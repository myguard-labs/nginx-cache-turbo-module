#!/usr/bin/env bash
# ci/tools/precommit-tests.sh -- run ONLY the tests mapped to the changed paths.
#
# The pre-commit hook must stay fast, so it never runs a whole suite: no
# run_all(), no ci/tests/unit/run.sh, no test_runtime.py. Each changed path is
# looked up in the reviewed map ci/tools/precommit-test-map.tsv and only the
# commands that row names are run (CI-P4). CI keeps the full suites.
#
# Usage:
#   precommit-tests.sh --staged            changed = `git diff --cached` names
#   precommit-tests.sh --files F [F...]    changed = the listed repo paths
#   options: --dry-run   list what would run, run nothing
#            --map FILE  alternate map (default ci/tools/precommit-test-map.tsv)
#
# Map format (TSV, '#' comments): <glob[|glob...]> <TAB> <needs> <TAB> <command>
#   needs    none | build | clang
#              build  = a configured nginx build under .build/ (runtime tests)
#              clang  = clang on PATH (fuzz replay)
#   command  run with `bash -c` from the repo root. Helpers available:
#              ut NAME EXTRACT|- [cc flags]   extract + compile + run unit NAME
#              $ROOT $PCT_TMP $NGX_SRC $NGX_OBJS (+ NGINX_SRC/OBJS/VERSION)
#            or one of the selector built-ins:
#              @area A [A...]    run_named.py over every test in areas/A.py
#              @fuzz-replay      build ci/fuzz targets, replay regressions only
#              @make-check       make -C ci/tests/unit check (nginx tree)
#   An @area group is also SKIPPED (FAIL under require) when the build is older
#   than the module sources it exercises (stale build; rebuild first).
#   An unmatched src/ path falls back to @make-check; any other unmatched
#   path (docs, workflows, ...) selects nothing.
#
# Env:
#   PRECOMMIT_TESTS=auto|require|off   require: a missing build/tool FAILS
#                                      instead of printing a loud SKIP
#   PRECOMMIT_BUILD_DIR  (default $ROOT/.build)
#   PRECOMMIT_TEST_PORT  (default 19400; outside CI's 18870-18999 band)
#   PRECOMMIT_REDIS_SERVER / PRECOMMIT_MEMCACHED_SERVER
#                        L2 server binaries handed to run_named.py when a
#                        selected @area test takes a redis*/mc fixture
#                        (default: redis-server / memcached on PATH; missing =
#                        loud SKIP, FAIL under require)
#   PRECOMMIT_ROOT       (default: repo containing this script; for tests)
#
# Exit: 0 all selected tests passed (or none selected / loud SKIP),
#       1 a test failed or require-mode could not run, 2 usage.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${PRECOMMIT_ROOT:-$(cd "$HERE/../.." && pwd)}"
MAP="$ROOT/ci/tools/precommit-test-map.tsv"
MODE="${PRECOMMIT_TESTS:-auto}"
BUILD_DIR="${PRECOMMIT_BUILD_DIR:-$ROOT/.build}"
PORT="${PRECOMMIT_TEST_PORT:-19400}"
DRY=0
SRC_MODE=""
FILES=()

usage() { sed -n '2,/^set -uo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//' >&2; exit 2; }

while (($# > 0)); do
    case "$1" in
        --staged) SRC_MODE=staged ;;
        --files) SRC_MODE=files ;;
        --dry-run) DRY=1 ;;
        --map) shift; (($# > 0)) || usage; MAP="$1" ;;
        -h|--help) usage ;;
        -*) echo "precommit-tests: unknown option $1" >&2; usage ;;
        *) if [ "$SRC_MODE" = files ]; then FILES+=("$1"); else usage; fi ;;
    esac
    shift
done
[ -n "$SRC_MODE" ] || usage

case "$MODE" in
    auto|require) ;;
    off) echo "precommit-tests: PRECOMMIT_TESTS=off -- no tests run" >&2; exit 0 ;;
    *) echo "precommit-tests: PRECOMMIT_TESTS must be auto|require|off" >&2; exit 2 ;;
esac

PCT_TMP="$(mktemp -d "${TMPDIR:-/tmp}/precommit-tests.XXXXXX")"
trap 'rm -rf "$PCT_TMP"' EXIT

if [ "$SRC_MODE" = staged ]; then
    # Materialise first so a failing git is an error, not a silently empty list.
    git -C "$ROOT" diff --cached --name-only --diff-filter=ACMR >"$PCT_TMP/staged" \
        || { echo "precommit-tests: git diff --cached failed" >&2; exit 2; }
    mapfile -t FILES <"$PCT_TMP/staged"
fi
[ -r "$MAP" ] || { echo "precommit-tests: map not readable: $MAP" >&2; exit 2; }

# --- select: ordered, de-duplicated "needs<TAB>command" rows -----------------
SEL=()
declare -A SEEN=()
add() {
    local key="$1"$'\t'"$2"
    [ -n "${SEEN[$key]:-}" ] && return
    SEEN[$key]=1
    SEL+=("$key")
}

for f in "${FILES[@]}"; do
    hit=0
    while IFS=$'\t' read -r globs needs cmd || [ -n "$globs" ]; do
        case "$globs" in ''|'#'*) continue ;; esac
        IFS='|' read -ra gl <<<"$globs"
        for g in "${gl[@]}"; do
            # $g is a reviewed glob from the map; unquoted on purpose.
            # shellcheck disable=SC2254
            case "$f" in
                $g) add "$needs" "$cmd"; hit=1; break ;;
            esac
        done
    done <"$MAP"
    if [ "$hit" = 0 ]; then
        case "$f" in
            src/*) add build "@make-check" ;;
        esac
    fi
done

if [ "${#SEL[@]}" -eq 0 ]; then
    echo "precommit-tests: no tests mapped for ${#FILES[@]} changed path(s); nothing to run"
    exit 0
fi

# --- build discovery ---------------------------------------------------------
NGX_DIR=""
if [ -d "$BUILD_DIR" ]; then
    find -L "$BUILD_DIR" -maxdepth 1 -type d -name 'nginx-*' >"$PCT_TMP/builds" 2>/dev/null
    sort -V "$PCT_TMP/builds" >"$PCT_TMP/builds.sorted"
    while IFS= read -r d; do
        if [ -x "$d/objs/nginx" ]; then NGX_DIR="$d"; fi
    done <"$PCT_TMP/builds.sorted"
fi
NGX_SRC="${NGX_DIR:+$NGX_DIR/src}"
NGX_OBJS="${NGX_DIR:+$NGX_DIR/objs}"
MODULE=""
if [ -n "$NGX_DIR" ]; then
    MODULE="$(find "$NGX_DIR/objs" -maxdepth 1 -name 'ngx_http_cache_turbo*module.so' 2>/dev/null | head -1)"
fi

# The unit scripts/Makefile read these names (see ci/tests/unit/run.sh).
NGINX_SRC="$NGX_SRC"
NGINX_OBJS="$NGX_OBJS"
NGINX_VERSION="$(basename "${NGX_DIR:-nginx-}")"
NGINX_VERSION="${NGINX_VERSION#nginx-}"
export ROOT PCT_TMP NGX_SRC NGX_OBJS NGINX_SRC NGINX_OBJS NGINX_VERSION

# Compile + run one pure unit test from ci/tests/unit (flags as in run.sh).
# Invoked from map commands via `bash -c` (export -f), hence the SC2317 and SC2329 waivers.
# shellcheck disable=SC2317,SC2329
ut() {
    local name="$1" ext="$2"
    shift 2
    local d="$ROOT/ci/tests/unit"
    [ "$ext" = "-" ] || bash "$d/extract_$ext.sh" || return 1
    "${CC:-cc}" -g -O0 -Wall -Wextra -Werror -I"$d" "$d/test_$name.c" \
        -o "$PCT_TMP/test_$name" "$@" || return 1
    "$PCT_TMP/test_$name"
}
export -f ut

area_tests() {
    sed -n 's/^def \(test_[A-Za-z0-9_]*\)(.*/\1/p' "$ROOT/ci/tools/areas/$1.py"
}

# Tests of an area file whose signature takes an L2 fixture (redis*, mc). The
# signature may span lines, so collect from `def test_` up to the closing `)`.
area_l2_tests() {
    awk '
        /^def test_/ { name = $0; sub(/^def /, "", name); sub(/\(.*/, "", name); sig = ""; open = 1 }
        open { sig = sig $0 }
        open && /\)[ ]*(->.*)?:[ ]*$/ {
            open = 0
            if (sig ~ /[(, ](mc|redis|redis_auth|redis_tls|redis_tls_untrusted|redis_tls_expired)[:,) =]/) print name
        }' "$ROOT/ci/tools/areas/$1.py"
}

REDIS_BIN="${PRECOMMIT_REDIS_SERVER:-$(command -v redis-server 2>/dev/null || true)}"
MC_BIN="${PRECOMMIT_MEMCACHED_SERVER:-$(command -v memcached 2>/dev/null || true)}"

# Echo a reason and return 1 when an @area group cannot give a truthful result.
# Stale build: a build older than the sources it tests fails on the NEW
# behaviour (a pre-preset build 404s `servarr`), which reads as a test failure
# when it is a missing rebuild.
area_ok() {
    local a ref stale l2=0
    ref="${MODULE:-$NGX_OBJS/nginx}"
    for a in ${1#@area }; do
        [ -n "$(area_l2_tests "$a" | head -1)" ] && l2=1
    done
    stale="$(find "$ROOT/src" -maxdepth 1 \( -name '*.c' -o -name '*.h' \) -newer "$ref" 2>/dev/null | head -1)"
    if [ -n "$stale" ]; then
        echo "stale build: ${stale#"$ROOT"/} is newer than ${ref#"$ROOT"/}; rebuild with ci/tools/ci-build.sh"
        return 1
    fi
    if [ "$l2" = 1 ]; then
        [ -x "$REDIS_BIN" ] || { echo "an L2 test is selected but redis-server is not available (set PRECOMMIT_REDIS_SERVER)"; return 1; }
        [ -x "$MC_BIN" ] || { echo "an L2 test is selected but memcached is not available (set PRECOMMIT_MEMCACHED_SERVER)"; return 1; }
    fi
    return 0
}

fuzz_replay() {
    local fz="$ROOT/ci/fuzz" t rc=0 files
    bash "$fz/build.sh" "$PCT_TMP" >/dev/null || return 1
    for t in fuzz_resp_parser fuzz_norm_args fuzz_mc_parser fuzz_auto_classify fuzz_blob; do
        # shellcheck disable=SC2207
        files=($(find "$fz/regressions/$t" -maxdepth 1 -type f ! -name README.md 2>/dev/null))
        if [ "${#files[@]}" -eq 0 ]; then echo "fuzz replay: $t: no regressions"; continue; fi
        "$PCT_TMP/$t" "${files[@]}" >/dev/null 2>"$PCT_TMP/$t.err" \
            || { echo "fuzz replay FAILED: $t" >&2; tail -5 "$PCT_TMP/$t.err" >&2; rc=1; }
    done
    return "$rc"
}

# Preflight a `needs` value; echo a reason and return 1 when unmet.
need_ok() {
    case "$1" in
        none) return 0 ;;
        build) [ -n "$NGX_DIR" ] || { echo "no configured nginx build under $BUILD_DIR (build with ci/tools/ci-build.sh)"; return 1; } ;;
        clang) command -v clang >/dev/null 2>&1 || { echo "clang not on PATH"; return 1; } ;;
        *) echo "unknown needs value '$1' in map"; return 1 ;;
    esac
}

run_one() {
    local cmd="$1" a names=() all=() l2=() srv=()
    cd "$ROOT" || return 1
    case "$cmd" in
        "@area "*)
            for a in ${cmd#@area }; do
                area_tests "$a" >"$PCT_TMP/names" || return 1
                mapfile -t names <"$PCT_TMP/names"
                [ "${#names[@]}" -gt 0 ] || { echo "area $a has no tests" >&2; return 1; }
                all+=("${names[@]}")
                area_l2_tests "$a" >"$PCT_TMP/l2names" || return 1
                mapfile -t names <"$PCT_TMP/l2names"
                [ "${#names[@]}" -eq 0 ] || l2+=("${names[@]}")
            done
            # L2-needing tests take redis*/mc fixtures that run_named.py only
            # builds when told where the servers are; without them the fixture
            # is None and the test crashes on it. Same flags CI passes.
            [ "${#l2[@]}" -eq 0 ] || srv=(--redis-server "$REDIS_BIN" --memcached-server "$MC_BIN")
            python3 ci/tools/run_named.py --nginx-binary "$NGX_OBJS/nginx" \
                ${MODULE:+--module "$MODULE"} --port "$PORT" ${srv[@]+"${srv[@]}"} "${all[@]}" ;;
        "@fuzz-replay") fuzz_replay ;;
        "@make-check")
            make -C ci/tests/unit --no-print-directory check \
                NGINX_SRC="$NGX_SRC" NGINX_OBJS="$NGX_OBJS" ;;
        *) # The command is reviewed map text; run it as a script file, not as
           # an interpolated string for a nested shell.
           printf '%s\n' "$cmd" >"$PCT_TMP/cmd.sh"
           bash "$PCT_TMP/cmd.sh" ;;
    esac
}

dry_describe() {
    local cmd="$1" a n
    case "$cmd" in
        "@area "*)
            for a in ${cmd#@area }; do
                n=$(area_tests "$a" | wc -l)
                echo "run_named.py ci/tools/areas/$a.py ($n tests)"
            done ;;
        *) echo "$cmd" ;;
    esac
}

rc=0
skipped=0
for row in "${SEL[@]}"; do
    needs="${row%%$'\t'*}"
    cmd="${row#*$'\t'}"
    if [ "$DRY" = 1 ]; then
        printf 'PLAN [%s] %s\n' "$needs" "$(dry_describe "$cmd")"
        continue
    fi
    if ! why="$(need_ok "$needs")"; then
        if [ "$MODE" = require ]; then
            echo "precommit-tests: FAIL (PRECOMMIT_TESTS=require): $why; needed by: $cmd" >&2
            rc=1
        else
            echo "precommit-tests: *** SKIP *** (NOT RUN): $why; needed by: $cmd" >&2
            skipped=$((skipped + 1))
        fi
        continue
    fi
    case "$cmd" in
        "@area "*)
            if ! why="$(area_ok "$cmd")"; then
                if [ "$MODE" = require ]; then
                    echo "precommit-tests: FAIL (PRECOMMIT_TESTS=require): $why; needed by: $cmd" >&2
                    rc=1
                else
                    echo "precommit-tests: *** SKIP *** (NOT RUN): $why; needed by: $cmd" >&2
                    skipped=$((skipped + 1))
                fi
                continue
            fi ;;
    esac
    echo "precommit-tests: RUN $cmd"
    if ! run_one "$cmd"; then
        echo "precommit-tests: FAIL: $cmd" >&2
        rc=1
    fi
done

[ "$skipped" -eq 0 ] || echo "precommit-tests: *** $skipped selected test group(s) SKIPPED -- coverage NOT provided ***" >&2
exit "$rc"
