#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# testkit-stage.sh -- build cache-turbo AND nginx-module-testkit's reference
# probe as dynamic modules into ONE objs/ dir, staged where the testkit
# prober's scenario runner looks for them.
#
# THE PROBLEM THIS SOLVES
#   labs/nginx-module-testkit ships a finished scenario for this module,
#   ci/prober/scenarios/consumer-cache-turbo -- a per-request allocation-
#   neutrality oracle (two post-drain quiescent snapshots around one extra
#   served request; cycle-pool counters, worker fds, master fds). It has never
#   once run. Its ./requires gate demands
#       $BUILD/objs/ngx_http_cache_turbo_module.so
#   and nobody stages that .so, so the scenario emits `1..0 # SKIP` forever.
#
#   `1..0 # SKIP` is a PASSING TAP plan. A permanently-skipping leg and a green
#   leg are indistinguishable in a job summary, which is why the integration
#   could be designed, merged and then silently never connected. This script is
#   the missing connection.
#
# WHY IT CANNOT REUSE ci-build.sh
#   ci-build.sh configures with `--add-dynamic-module=$MODULE_DIR` -- this
#   module and nothing else. The scenario's nginx.conf load_module's TWO .so
#   out of the SAME objs/: the harness's ref probe (which provides the
#   /__probe endpoint every oracle reads) and cache-turbo itself.
#
#   nginx binds its dynamic-module list at CONFIGURE time. There is no adding a
#   module to an already-built tree. So "ref probe + cache-turbo" is necessarily
#   ONE configure and ONE make -- a second configure into the same tree would
#   discard the first module set, not extend it. Hence a separate script rather
#   than a flag on ci-build.sh, whose single-module contract is depended on by
#   six other callers.
#
# WHY IT POINTS AT A REAL TESTKIT CHECKOUT, NEVER A COPY
#   testkit's t/module/config compiles sources reached by RELATIVE CLIMB out of
#   the addon dir:
#       $ngx_addon_dir/../../src/ngx_test_probe.c
#       $ngx_addon_dir/../../src/ngx_test_probe_arm.c
#   so --add-dynamic-module must name testkit's actual tree. Vendoring t/module
#   into this repo would break those climbs, and a vendored copy drifts from
#   upstream while the port-back never happens -- which is exactly how
#   testkit's own untracked consumers/ snapshot rotted a month stale. The
#   testkit checkout is located, not copied.
#
#   That config also appends -DNGX_TEST_HARNESS to the GLOBAL CFLAGS, and the
#   ref probe carries an #error guard that fails the build without it. That is
#   deliberate upstream: the alternative is a probe that builds, loads, and
#   answers with an empty document -- passing by testing nothing. It means the
#   whole staged tree is a test build by construction. Never ship it.
#
# STALENESS IS A HARD FAILURE, NOT A SKIP
#   A stale .so is the defect class this script exists to avoid, in both
#   repos' lessons: [[feedback-stale-so-fakes-negative-control]] and
#   [[feedback-stale-binary-fakes-a-hang]]. A scenario that loads a month-old
#   .so and reports its oracles green is worse than a red -- it is a false
#   negative wearing a pass. So the post-build check compares the staged .so
#   mtime against the newest src/*.c|h and EXITS NONZERO when it loses. It does
#   not warn, and it does not skip: both degrade to "green anyway".
#
# USAGE
#   ci/tools/testkit-stage.sh [OPTIONS]
#
#     --flavor NAME     nginx | angie        (default: nginx)
#     --version VER     upstream version     (default: $NGINX_VERSION from
#                                             .github/versions.env)
#     --testkit DIR     testkit checkout     (default: autodetected, see below)
#     --jobs N          make -j N            (default: nproc)
#     --src DIR         reuse an unpacked source tree instead of fetching
#     --keep-src        do not delete a fetched source tree on success
#     --dry-run         print the configure/make it WOULD run, touch nothing
#     -h, --help        this header
#
# TESTKIT AUTODETECTION
#   $TESTKIT_ROOT, else ../nginx-module-testkit relative to this repo (the
#   superrepo's labs/ layout). Explicit --testkit always wins. The path is
#   validated by the presence of t/module/config, not by name.
#
# OUTPUT
#   .build/<flavor>-<version>-testkit/objs/ containing both .so, plus the
#   configured nginx BINARY (testkit's prober_resolve requires an executable at
#   $BUILD/objs/nginx and bails without one -- lib.sh:96-101).
#
#   The stage directory name is NOT cosmetic: testkit's run-scenario.sh takes
#   flavor and version as argv and composes .build/<flavor>-<version>, and the
#   scenario's ./requires gate recomputes that same string independently. So
#   the whole string "<version>-testkit" is what a caller passes as the VERSION
#   argument. ci/tools/testkit-run.sh does that; if you invoke run-scenario.sh
#   by hand, pass `nginx 1.31.3-testkit`, not `1.31.3`.
#
#   A distinct suffix (rather than staging into .build/<flavor>-<version>) is
#   required because this script wipes objs/ before building, and that plain
#   name is the tree ci-build.sh produces for the runtime suite. Sharing it
#   would silently destroy the suite's tree on every stage.
#
#   ⚠ THE STAGE LIVES UNDER THIS REPO'S .build/, NOT TESTKIT'S. testkit's
#   prober_resolve (lib.sh:81-82) defaults its search root to the TESTKIT repo
#   root, derived from lib.sh's own BASH_SOURCE -- not to cwd. So a tree staged
#   here is invisible to it unless the caller exports an absolute PROBER_BUILD.
#   Worse, the scenario's ./requires gate (requires:26) falls back to `.` where
#   lib.sh falls back to the testkit root, and run-scenario.sh has already
#   cd'd to ci/prober/ by then -- so with neither variable set the two disagree
#   about where to look and the gate SKIPs a correctly staged tree. Exporting
#   an absolute PROBER_BUILD is the only setting BOTH consult first, which is
#   why testkit-run.sh always sets it. Do not "simplify" that away.
#
# EXIT
#   0  both .so present, and both newer than the newest module source
#   1  precondition failure (no testkit checkout, bad flavor, fetch/checksum)
#   2  usage error
#   3  the build ran but a required .so is MISSING or STALE -- a result, and
#      the one this script most exists to report

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
JOBS=""
SRC=""
KEEP_SRC=0
DRY=0

die()   { echo "testkit-stage: $*" >&2; exit 1; }
usage() { echo "testkit-stage: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
    case "$1" in
        --flavor)   FLAVOR="${2:?--flavor needs a value}"; shift 2 ;;
        --version)  VERSION="${2:?--version needs a value}"; shift 2 ;;
        --testkit)  TESTKIT="${2:?--testkit needs a value}"; shift 2 ;;
        --jobs)     JOBS="${2:?--jobs needs a value}"; shift 2 ;;
        --src)      SRC="${2:?--src needs a value}"; shift 2 ;;
        --keep-src) KEEP_SRC=1; shift ;;
        --dry-run)  DRY=1; shift ;;
        -h|--help)  sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)          usage "unknown option: $1 (try --help)" ;;
    esac
done

case "$JOBS" in
    '')            JOBS="$(nproc 2>/dev/null || echo 4)" ;;
    *[!0-9]*|0)    usage "--jobs must be a positive integer, got '$JOBS'" ;;
esac

# ---- locate the testkit checkout -------------------------------------------
# Validated by content (t/module/config), not by directory name: a caller may
# legitimately keep the checkout anywhere, and a wrong path must fail HERE with
# a readable message rather than 200 lines into a configure run.
if [ -z "$TESTKIT" ]; then
    TESTKIT="$ROOT/../nginx-module-testkit"
fi
[ -d "$TESTKIT" ] || die "testkit checkout not found at '$TESTKIT' (set --testkit or \$TESTKIT_ROOT)"
TESTKIT="$(cd "$TESTKIT" && pwd)"
[ -f "$TESTKIT/t/module/config" ] || \
    die "'$TESTKIT' has no t/module/config -- that is not an nginx-module-testkit checkout"

# The ref probe's sources are reached by relative climb out of t/module. If the
# climb targets are absent the configure still succeeds and the MAKE dies with
# a bare "no rule to make target", which reads like a testkit bug and is not
# one -- it means the checkout is partial (a sparse clone, an interrupted
# submodule init). Check the two files the config actually names.
for probe_src in src/ngx_test_probe.c src/ngx_test_probe_arm.c; do
    [ -f "$TESTKIT/$probe_src" ] || \
        die "testkit checkout '$TESTKIT' is missing $probe_src, which t/module/config compiles by relative path -- partial checkout?"
done

# ---- resolve the upstream tarball ------------------------------------------
# Version/digest pairs come from .github/versions.env, the repo's single source
# of truth, so this script can never fetch a tarball the rest of CI would
# refuse. An unpinned version is a hard error rather than an unverified
# download: a tampered tarball here would be compiled AND executed.
case "$FLAVOR" in
    nginx)
        URL="https://nginx.org/download/nginx-${VERSION}.tar.gz"
        DIR="nginx-${VERSION}"
        case "$VERSION" in
            "${NGINX_MAINLINE:-}")        EXPECTED_SHA256="${NGINX_MAINLINE_SHA256:-}" ;;
            "${NGINX_STABLE:-}")          EXPECTED_SHA256="${NGINX_STABLE_SHA256:-}" ;;
            "${LEGACY_NGINX_VERSION:-}")  EXPECTED_SHA256="${LEGACY_NGINX_VERSION_SHA256:-}" ;;
            *) die "no sha256 pin for nginx $VERSION in .github/versions.env" ;;
        esac
        ;;
    angie)
        URL="https://download.angie.software/files/angie-${VERSION}.tar.gz"
        DIR="angie-${VERSION}"
        EXPECTED_SHA256="${ANGIE_SHA256:-}"
        [ "$VERSION" = "${ANGIE_VERSION:-}" ] || \
            die "no sha256 pin for angie $VERSION (versions.env pins ${ANGIE_VERSION:-none})"
        ;;
    *)
        usage "unsupported flavor: $FLAVOR (expected nginx or angie)"
        ;;
esac
[ -n "$EXPECTED_SHA256" ] || die "empty sha256 pin for ${FLAVOR} ${VERSION}"

STAGE="${FLAVOR}-${VERSION}-testkit"
BUILD_ROOT="${BUILD_ROOT:-$ROOT/.build}"
STAGE_DIR="$BUILD_ROOT/$STAGE"

CT_SO=ngx_http_cache_turbo_module.so
TK_SO=ngx_http_test_ref_module.so

# ---- the configure argv ----------------------------------------------------
# --with-compat: required for dynamic modules generally, and already what
# ci-build.sh passes.
#
# The ref probe is listed FIRST so that a truncated argv loses cache-turbo (a
# visibly missing .so, caught by the staleness gate below) rather than the
# probe (whose absence makes every oracle SKIP -- a silent pass).
#
# Deliberately NOT passed, unlike testkit's own tools/build-consumers.sh:
#   --with-http_ssl_module --with-stream --with-stream_ssl_module
# Those exist there for OTHER consumers (autocert needs ngx_ssl_t; label-
# autoconf has a STREAM half). The consumer-cache-turbo scenario's nginx.conf
# speaks plain HTTP on 127.0.0.1 with no `ssl` on its listen and no stream
# block, and this module needs none of them. Adding them would only lengthen
# an already-expensive build.
#
# Equally deliberate: nothing here DISABLES a default module. The scenario's
# conf needs http_proxy (its `location /` proxy_pass'es to /origin on its own
# port) and http_rewrite (`return 200` in /origin). Both are on by default, so
# the requirement is invisible until someone "trims" the configure line -- at
# which point nginx -t fails on an unknown directive and it reads like a
# scenario bug. Stated here so it is not discovered the hard way.
CONFIGURE_ARGS=(
    --with-compat
    "--add-dynamic-module=$TESTKIT/t/module"
    "--add-dynamic-module=$ROOT"
)

if [ "$DRY" -eq 1 ]; then
    echo "would fetch    : $URL"
    echo "would verify   : $EXPECTED_SHA256"
    echo "would stage    : $STAGE_DIR/objs"
    echo "would configure: ./configure ${CONFIGURE_ARGS[*]}"
    echo "would build    : make -j$JOBS   (server binary + both modules)"
    echo "would require  : objs/$TK_SO newer than $TESTKIT/src"
    echo "                 objs/$CT_SO newer than $ROOT/src"
    echo "                 objs/nginx executable"
    exit 0
fi

# ---- host rule: one build at a time ----------------------------------------
# A concurrent nginx/pbuilder build on this box thrashes and has produced stale
# artifacts before. Refuse rather than race.
if pgrep -f 'pbuilder|dpkg-buildpackage' >/dev/null 2>&1; then
    die "another package build is running on this host -- refusing to start (one build at a time)"
fi

mkdir -p "$BUILD_ROOT"

TMP=""
cleanup() {
    if [ -n "$TMP" ] && [ "$KEEP_SRC" -eq 0 ]; then
        rm -rf "$TMP" 2>/dev/null || true
    fi
}
trap cleanup EXIT

if [ -n "$SRC" ]; then
    [ -f "$SRC/configure" ] || die "--src '$SRC' has no ./configure"
    BUILDDIR="$(cd "$SRC" && pwd)"
    echo "==> reusing source tree $BUILDDIR"
else
    TMP="$(mktemp -d "${TMPDIR:-/tmp}/testkit-stage.XXXXXX")"
    BUILDDIR="$TMP/$DIR"
    echo "==> fetching $URL"
    bash "$ROOT/.github/scripts/fetch-verify.sh" \
        "$URL" "$EXPECTED_SHA256" "$TMP/${DIR}.tar.gz" \
        || die "fetch/verify failed for $URL"
    tar -xzf "$TMP/${DIR}.tar.gz" -C "$TMP"
    [ -d "$BUILDDIR" ] || die "tarball did not unpack to expected dir $DIR"
fi

# WIPE objs/ BEFORE configuring. nginx's ./configure does not clear it -- the
# only `rm -rf $NGX_OBJS` in auto/init is the TEXT of the Makefile's clean:
# target being written out, not a command configure runs. A reused tree
# therefore keeps every .so from its previous build, and the staging copy below
# would carry a STALE .so forward as if it were fresh: the scenario's requires
# gate finds it, passes, and probes a module that was never rebuilt. That is
# precisely [[feedback-stale-so-fakes-negative-control]].
if [ -d "$BUILDDIR/objs" ]; then
    echo "==> wiping $BUILDDIR/objs (a reused tree's old .so would be staged as if fresh)"
    rm -rf "$BUILDDIR/objs"
fi

# ccache, mirroring ci-build.sh: keyed by compiler CONTENT so a cache restored
# onto a different runner is reusable. A content mismatch only ever MISSES.
CC="${CC:-cc}"
if command -v ccache >/dev/null 2>&1; then
    WITH_CC="ccache $CC"
    export CCACHE_COMPILERCHECK=content
else
    WITH_CC="$CC"
fi

MAKE="make"
if command -v eatmydata >/dev/null 2>&1; then
    MAKE="eatmydata make"
fi

echo "==> configuring ($FLAVOR $VERSION, ref probe + cache_turbo)"
(
    cd "$BUILDDIR"
    ./configure --with-cc="$WITH_CC" "${CONFIGURE_ARGS[@]}"
) || die "configure failed"

# Full build, not just `make modules`. The prober needs BOTH:
#   * objs/*.so                -- the two dynamic modules, and
#   * objs/nginx (or objs/angie) -- an EXECUTABLE server binary, which
#     prober_resolve checks for explicitly and bails on when absent
#     (lib.sh:85-86 composes the path, :96-101 `Bail out! no server binary`).
# `make modules` produces only the former, so a modules-only build stages a
# tree that configures fine and then refuses to run every scenario.
echo "==> building server + modules (-j$JOBS)"
(
    cd "$BUILDDIR"
    # shellcheck disable=SC2086  # MAKE may be "eatmydata make"; must word-split
    $MAKE -j"$JOBS"
) || die "make failed"

# ---- stage ------------------------------------------------------------------
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"
cp -r "$BUILDDIR/objs" "$STAGE_DIR/objs"

# ---- the staleness gate -- the reason this script is trustworthy ------------
# Both .so must EXIST and must be newer than the newest module source. A
# missing .so is exit 3; a stale one is exit 3 too. Neither warns and continues:
# the whole failure mode being defended against is a scenario that loads an old
# object and reports green.
#
# Each .so is compared against the sources it is actually BUILT FROM -- they
# are different trees, and using one reference for both is wrong in both
# directions. cache_turbo comes from this repo's src/; the ref probe comes from
# testkit's src/ngx_test_probe*.c plus t/module/. Checking the probe against
# OUR sources would fire spuriously every time we edit this module (the probe
# is legitimately older), and would miss the case that matters -- a probe left
# behind by an older testkit checkout. testkit's own prober_resolve enforces
# the second comparison too (lib.sh:105-163); doing it here means a stale probe
# is reported by the staging step that can fix it, rather than as a `Bail out!`
# from a scenario run that looks like a harness fault.
status=0

# newest_of DEPTH DIR... -> prints "<mtime> <path>" for the newest *.c|*.h.
# Exits nonzero on an EMPTY scan rather than printing 0: a staleness gate whose
# reference is "nothing" passes everything, which is the silent-green failure
# this whole block exists to prevent. A missing dir is skipped by find's
# stderr suppression but still cannot yield a false pass, because an all-empty
# scan returns 1.
newest_of() {
    local depth="$1"; shift
    local newest_mtime=0 newest_src="" f m
    while IFS= read -r f; do
        m="$(stat -c %Y "$f")"
        if [ "$m" -gt "$newest_mtime" ]; then
            newest_mtime="$m"
            newest_src="$f"
        fi
    done < <(find "$@" -maxdepth "$depth" -type f \( -name '*.c' -o -name '*.h' \) 2>/dev/null)
    [ -n "$newest_src" ] || return 1
    printf '%s %s\n' "$newest_mtime" "$newest_src"
}

ct_ref="$(newest_of 1 "$ROOT/src")" \
    || die "no sources found under $ROOT/src -- refusing to report a fresh build on an empty scan"
CT_MTIME="${ct_ref%% *}"; CT_NEWEST="${ct_ref#* }"

tk_ref="$(newest_of 2 "$TESTKIT/src" "$TESTKIT/t/module")" \
    || die "no sources found under $TESTKIT/src or $TESTKIT/t/module -- refusing to report a fresh build on an empty scan"
TK_MTIME="${tk_ref%% *}"; TK_NEWEST="${tk_ref#* }"

# The server binary is checked for existence and executability only -- its
# mtime is not compared against this module's sources, because nginx core does
# not rebuild when only src/*.c here changes, and demanding it would fail every
# incremental stage for no safety gain. prober_resolve makes the same
# distinction (lib.sh:96 tests -x, not mtime).
SERVER_BIN=nginx
[ "$FLAVOR" = "angie" ] && SERVER_BIN=angie
if [ ! -x "$STAGE_DIR/objs/$SERVER_BIN" ]; then
    echo "testkit-stage: MISSING or non-executable $STAGE_DIR/objs/$SERVER_BIN" >&2
    echo "  the prober bails without it (lib.sh 'Bail out! no server binary')" >&2
    status=3
fi

check_so() {   # check_so SO_NAME REF_MTIME REF_PATH
    local so="$1" ref_mtime="$2" ref_path="$3"
    local path="$STAGE_DIR/objs/$so" so_mtime
    if [ ! -f "$path" ]; then
        echo "testkit-stage: MISSING $path -- the build produced no such module" >&2
        status=3
        return
    fi
    so_mtime="$(stat -c %Y "$path")"
    if [ "$so_mtime" -lt "$ref_mtime" ]; then
        echo "testkit-stage: STALE $so" >&2
        echo "  $so$(printf '%*s' 4 '')$(date -d "@$so_mtime" '+%F %T')" >&2
        echo "  newest source $ref_path  $(date -d "@$ref_mtime" '+%F %T')" >&2
        echo "  a scenario loading this .so would report oracles green against code that was never built" >&2
        status=3
    fi
}

check_so "$TK_SO" "$TK_MTIME" "$TK_NEWEST"
check_so "$CT_SO" "$CT_MTIME" "$CT_NEWEST"

if [ "$status" -ne 0 ]; then
    exit "$status"
fi

# The three lines a caller actually needs, in `key=value` form matching
# ci-build.sh's convention. prober_build is the ABSOLUTE path that must reach
# the prober as $PROBER_BUILD -- see the OUTPUT note above on why an absolute
# value is the only thing both the requires gate and lib.sh agree on. version
# is the whole "<ver>-testkit" string to pass as run-scenario.sh's VERSION argv.
echo "==> staged $STAGE_DIR/objs"
printf 'stage=%s\n'        "$STAGE"
printf 'version=%s\n'      "${VERSION}-testkit"
printf 'prober_build=%s\n' "$STAGE_DIR"
printf 'objs=%s\n'         "$STAGE_DIR/objs"
