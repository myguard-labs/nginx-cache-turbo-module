#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# testkit-run.sh -- run nginx-module-testkit's prober scenarios against a tree
# staged by ci/tools/testkit-stage.sh.
#
# WHAT THIS BUYS US
#   testkit's ci/prober/scenarios/consumer-cache-turbo is a finished per-request
#   allocation-neutrality oracle for THIS module: two post-drain quiescent
#   snapshots taken around one extra served request, comparing cycle-pool
#   counters (cycle_used, cycle_blocks, cycle_large), worker fd count and MASTER
#   fd count. Equal means the HIT path frees everything it allocates per
#   request. It also asserts a genuine `X-Cache: HIT` occurred first, so the
#   neutrality claim cannot pass vacuously against a pass-through filter.
#
#   That scenario has existed, finished, for a month and has never run: nobody
#   staged the .so its ./requires gate demands, so it emitted `1..0 # SKIP`
#   forever. `1..0 # SKIP` is a PASSING TAP plan -- indistinguishable from a
#   green leg in a job summary. This script plus testkit-stage.sh is the
#   connection that makes it real.
#
# WHY EVERY ENV VAR BELOW IS MANDATORY, NOT DEFAULTED
#   The scenario ships no `env` file (its directory is exactly driver.sh,
#   nginx.conf, requires), so nothing scenario-side supplies these. testkit's
#   prober_resolve hard-bails -- `Bail out!`, not a skip -- when PROBER_MODULE
#   or PROBER_DIRECTIVE is unset, and prober_render_conf bails when a conf uses
#   @PROBE@ with PROBER_PROBE unset. This scenario's conf uses @PROBE@ at its
#   /__probe location, and the driver reads cycle_used/cycle_blocks/
#   cycle_large/fds back out of that probe's JSON -- so the ref probe is
#   load-bearing for every oracle, not decoration.
#
# ⚠ PROBER_BUILD MUST BE ABSOLUTE -- THIS IS THE SUBTLE ONE
#   Two independent pieces of testkit resolve the build tree, and they disagree
#   about their fallbacks:
#
#     lib.sh    PROBER_BUILD, else ${PROBER_ROOT:-<testkit repo root, derived
#               from lib.sh's own BASH_SOURCE>}/.build/<flavor>-<version>
#     requires  PROBER_BUILD, else ${PROBER_ROOT:-.}/.build/<flavor>-<version>
#
#   run-scenario.sh has already cd'd into ci/prober/ before the gate runs, so
#   with NEITHER variable set the gate looks in ci/prober/.build/... while
#   lib.sh looks in <testkit>/.build/... . The gate then reports "module .so not
#   found" and SKIPs a perfectly good tree -- the exact silent-pass this whole
#   effort exists to remove, reintroduced by a path default.
#
#   PROBER_BUILD is the only variable BOTH consult FIRST, so setting it
#   absolutely is what makes the two agree. Our stage lives under THIS repo's
#   .build/, not testkit's, which neither fallback would ever find. Do not
#   replace it with PROBER_ROOT and do not make it relative.
#
# THE VERSION ARGUMENT IS THE STAGE NAME
#   run-scenario.sh takes flavor and version as argv and composes
#   .build/<flavor>-<version>. Our stage dir is <flavor>-<version>-testkit, so
#   the whole string "<version>-testkit" is what gets passed as VERSION. That
#   looks wrong and is correct; it is the same convention testkit's own
#   build-consumers.sh documents for its "-consumers" stage.
#
# USAGE
#   ci/tools/testkit-run.sh [OPTIONS] [-- scenario ...]
#
#     --flavor NAME     nginx | angie      (default: nginx)
#     --version VER     upstream version   (default: $NGINX_VERSION)
#     --testkit DIR     testkit checkout   (default: autodetected)
#     --port N          base listen port   (default: $TEST_BASE_PORT, else 19392)
#     --stage           run testkit-stage.sh first
#     --sanitizer       select (and with --stage, build) the ASan/UBSan tree
#                       .build/<flavor>-<version>-testkit-asan. The tree is
#                       verified to actually carry the sanitizer runtime, not
#                       trusted from the flag. detect_leaks stays OFF -- see
#                       the block by the check for why that is deliberate.
#     --expect-skip     invert the verdict: PASS only if the scenario SKIPs.
#                       The negative control for the whole adoption -- see below.
#     --list            print the scenarios that would run, exit
#     -h, --help        this header
#
#   With no `-- scenario` list, runs consumer-cache-turbo.
#
# --expect-skip, AND WHY IT EXISTS
#   The entire value of this integration is that the scenario stopped SKIPping.
#   Asserting the pass direction alone cannot prove that: a green run and a
#   permanently-skipping run both exit 0. So the gate is checked in BOTH
#   directions -- a staged tree must produce real assertions, and an UNSTAGED
#   tree must still SKIP cleanly rather than fail. --expect-skip is the second
#   half, used by the S3 check and by ci.yml.
#
# PORT BAND
#   Defaults to 19392, this job's band under ci/tools/lint-ci-ports.sh
#   (18880/18944/19008/19072/19136/19200/19264/19328 are taken). Verified
#   against ci/tools/max-port.sh, which checks the band against the kernel
#   ephemeral floor.
#
# EXIT
#   0  every scenario met its expectation (assertions passed, or SKIPped under
#      --expect-skip)
#   1  precondition failure (no testkit, no staged tree, bad option)
#   2  usage error
#   3  a scenario FAILED, or SKIPped when it was expected to assert, or
#      asserted when --expect-skip required a skip

set -euo pipefail

cd "$(dirname "$0")/../.."
ROOT="$PWD"

if [ -f .github/versions.env ]; then
    # shellcheck disable=SC1091
    source .github/versions.env
fi

FLAVOR=nginx
VERSION="${NGINX_VERSION:-1.31.3}"
TESTKIT="${TESTKIT_ROOT:-}"
PORT="${TEST_BASE_PORT:-19392}"
DO_STAGE=0
EXPECT_SKIP=0
SANITIZE=0
LIST=0
SCENARIOS=()

die()   { echo "testkit-run: $*" >&2; exit 1; }
usage() { echo "testkit-run: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
    case "$1" in
        --flavor)      FLAVOR="${2:?--flavor needs a value}"; shift 2 ;;
        --version)     VERSION="${2:?--version needs a value}"; shift 2 ;;
        --testkit)     TESTKIT="${2:?--testkit needs a value}"; shift 2 ;;
        --port)        PORT="${2:?--port needs a value}"; shift 2 ;;
        --stage)       DO_STAGE=1; shift ;;
        --sanitizer)   SANITIZE=1; shift ;;
        --expect-skip) EXPECT_SKIP=1; shift ;;
        --list)        LIST=1; shift ;;
        -h|--help)     sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        --)            shift; SCENARIOS=("$@"); break ;;
        *)             usage "unknown option: $1 (try --help)" ;;
    esac
done

case "$PORT" in
    ''|*[!0-9]*) usage "--port must be numeric, got '$PORT'" ;;
esac

[ "${#SCENARIOS[@]}" -gt 0 ] || SCENARIOS=(consumer-cache-turbo)

if [ -z "$TESTKIT" ]; then
    TESTKIT="$ROOT/../nginx-module-testkit"
fi
[ -d "$TESTKIT" ] || die "testkit checkout not found at '$TESTKIT' (set --testkit or \$TESTKIT_ROOT)"
TESTKIT="$(cd "$TESTKIT" && pwd)"
[ -x "$TESTKIT/ci/prober/run-scenario.sh" ] || \
    die "'$TESTKIT' has no ci/prober/run-scenario.sh -- that is not an nginx-module-testkit checkout"

if [ "$LIST" -eq 1 ]; then
    printf '%s\n' "${SCENARIOS[@]}"
    exit 0
fi

STAGE_SUFFIX=testkit
[ "$SANITIZE" -eq 1 ] && STAGE_SUFFIX=testkit-asan
STAGE_DIR="${BUILD_ROOT:-$ROOT/.build}/${FLAVOR}-${VERSION}-${STAGE_SUFFIX}"

if [ "$DO_STAGE" -eq 1 ]; then
    stage_args=(--flavor "$FLAVOR" --version "$VERSION" --testkit "$TESTKIT")
    [ "$SANITIZE" -eq 1 ] && stage_args+=(--sanitizer)
    ci/tools/testkit-stage.sh "${stage_args[@]}" || die "staging failed"
fi

# ---- the sanitizer contract -------------------------------------------------
# --sanitizer is a claim about the tree, so it is VERIFIED here rather than
# assumed from the flag. Selecting a different directory name is what makes an
# unsanitized tree impossible to pick up by accident; this grep is what makes a
# tree that merely LIVES under the -asan name and was built without the flags
# impossible to run silently. Both are needed: the name is chosen by the
# caller, the runtime is a property of the bytes.
#
# Same detection as testkit's lib.sh:244 (PROBER_SANITIZED) and as
# testkit-stage.sh's own gate. Three places agreeing is deliberate -- the one
# that must never be the odd one out is the harness, because it decides at
# RUNTIME which oracles apply.
if [ "$SANITIZE" -eq 1 ] && [ "$EXPECT_SKIP" -eq 0 ]; then
    if [ ! -f "$STAGE_DIR/objs/nginx" ] && [ ! -f "$STAGE_DIR/objs/angie" ]; then
        die "no sanitized tree at $STAGE_DIR/objs -- run ci/tools/testkit-stage.sh --sanitizer (or pass --stage)"
    fi
    for _obj in "$STAGE_DIR/objs/nginx" "$STAGE_DIR/objs/angie" \
                "$STAGE_DIR/objs/ngx_http_cache_turbo_module.so"; do
        [ -f "$_obj" ] || continue
        grep -qa '__asan_\|__ubsan_' "$_obj" || \
            die "--sanitizer given but $_obj carries no ASan/UBSan runtime -- restage with --sanitizer"
    done
fi

# ---- detect_leaks: a deliberate decision, not an omission -------------------
# LEFT OFF. testkit's prober_heap_env (lib.sh:242) sets detect_leaks=0 and this
# leg does not override it. The reasoning, so nobody "fixes" it later:
#
#   * nginx NEVER frees its configuration pool. LSan therefore reports the
#     entire config parse as leaked on `nginx -t` and on every clean shutdown.
#     That is upstream process-lifetime allocation, not a module defect.
#   * With detect_leaks=1 the FIRST thing that aborts is `nginx -t`, before a
#     single oracle runs -- so the leg would turn into a Bail out! and observe
#     strictly less than it does today, not more.
#   * The obvious workaround -- an LSan suppression file -- is BANNED here.
#     This repo carried `leak:ngx_create_pool` and `leak:main`, and cycle 8
#     DISPROVED both by negative control: they suppress REAL module leaks, not
#     just the config pool. A suppression that hides the class you are hunting
#     is worse than no leak detection at all, because it reports green.
#   * What this leg IS for is the class LSan cannot see anyway: the SERVER-side
#     use-after-free / overflow / UB that ASan and UBSan catch at the moment it
#     happens, with a stack, in a log the harness is structurally unable to
#     delete (lib.sh:1225-1314 keeps both the redirected error_log and the
#     pre-redirect server.err; lib.sh:1424 treats a sanitizer report as fatal
#     and never exemptable).
#
# Leak hunting is a separate instrument and needs a suppression story that
# survives a negative control. It is not this leg's job, and pretending
# otherwise by flipping one env var would cost the leg its actual coverage.

# The prober CLIENT is a compiled C binary, separate from the staged modules,
# and run-scenario.sh invokes ./prober directly rather than building it. Build
# it if it is missing so a caller does not have to know that; rebuilding when
# present is testkit's business, not ours.
if [ ! -x "$TESTKIT/ci/prober/prober" ]; then
    echo "==> building testkit prober client"
    ( cd "$TESTKIT" && ci/prober/build.sh ) >/dev/null \
        || die "testkit prober build failed (needs openssl + zlib headers)"
fi

# Under --expect-skip the staged tree is SUPPOSED to be absent, so demanding it
# here would make the negative control impossible to run.
if [ "$EXPECT_SKIP" -eq 0 ] && [ ! -d "$STAGE_DIR/objs" ]; then
    die "no staged tree at $STAGE_DIR/objs -- run ci/tools/testkit-stage.sh (or pass --stage)"
fi

status=0

for name in "${SCENARIOS[@]}"; do
    # A scenario may live in EITHER repo. testkit ships the generic ones and
    # the consumer-cache-turbo oracle; this repo authors the ones that encode
    # cache-turbo-specific knowledge (an L2 topology, a Redis fixture, a
    # second instance) and have no place in a generic harness. run-scenario.sh
    # takes an absolute scenario DIRECTORY, so a locally-authored scenario
    # needs no testkit change whatsoever -- which is the point: this repo can
    # add oracles without a cross-repo PR.
    #
    # Local FIRST. If a name exists in both, the local one wins, and that is
    # the safe precedence: a consumer overriding a harness scenario is
    # deliberate, whereas a harness upgrade silently shadowing a local oracle
    # would remove coverage without a diff in this repo.
    dir=""
    for cand in "$ROOT/ci/prober-scenarios/$name" "$TESTKIT/ci/prober/scenarios/$name"; do
        if [ -d "$cand" ]; then dir="$cand"; break; fi
    done
    [ -n "$dir" ] || die "no such scenario: $name (looked in $ROOT/ci/prober-scenarios/ and $TESTKIT/ci/prober/scenarios/)"

    echo "== scenario: $name (port $PORT, expect $([ "$EXPECT_SKIP" -eq 1 ] && echo SKIP || echo ASSERTIONS))"

    out="$(mktemp)"
    rc=0
    # PROBER_BUILD absolute -- see the header. PROBER_PROBE carries its own
    # trailing ';' because it is substituted directly into a conf location body.
    PROBER_BUILD="$STAGE_DIR" \
    PROBER_ROOT="$ROOT" \
    PROBER_PORT="$PORT" \
    PROBER_MODULE=ngx_http_test_ref_module.so \
    PROBER_DIRECTIVE=test_ref_probe \
    PROBER_PROBE='test_ref_probe;' \
        "$TESTKIT/ci/prober/run-scenario.sh" "$dir" "$FLAVOR" "${VERSION}-testkit" \
        >"$out" 2>&1 || rc=$?

    cat "$out"

    # A TAP plan of `1..0` with a SKIP directive is the skip shape. Matching the
    # plan line specifically, not a bare grep for "SKIP", because individual
    # oracles inside a RUNNING scenario legitimately emit `ok N - ... # SKIP`
    # for an unobservable reading (e.g. /proc not readable for master fds), and
    # counting that as "the scenario skipped" would report the connection dead
    # while it is in fact working.
    if grep -qE '^1\.\.0 # SKIP' "$out"; then
        skipped=1
    else
        skipped=0
    fi

    if [ "$EXPECT_SKIP" -eq 1 ]; then
        if [ "$skipped" -eq 1 ] && [ "$rc" -eq 0 ]; then
            echo "-- ok: scenario SKIPped cleanly on an unstaged tree, as required"
        else
            echo "-- FAIL: expected a clean '1..0 # SKIP' on an unstaged tree (rc=$rc skipped=$skipped)" >&2
            echo "   an unstaged tree must SKIP, never fail: a missing consumer .so is an" >&2
            echo "   environment fact, and turning it into a red teaches people to ignore this leg" >&2
            status=3
        fi
    else
        if [ "$skipped" -eq 1 ]; then
            echo "-- FAIL: scenario SKIPped on a STAGED tree -- the connection is broken" >&2
            echo "   '1..0 # SKIP' is a PASSING TAP plan, so this would otherwise read as green" >&2
            status=3
        elif [ "$rc" -ne 0 ]; then
            echo "-- FAIL: scenario reported failures (rc=$rc)" >&2
            status=3
        else
            echo "-- ok: scenario ran its assertions and passed"
        fi
    fi

    rm -f "$out"
done

exit "$status"
