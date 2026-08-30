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
#     --sanitizer       build the server + both modules under ASan/UBSan
#     --coverage        build the server + both modules under gcov
#                       instrumentation (mutually exclusive with --sanitizer;
#                       the two modes are separate purposes and a build cannot
#                       usefully be both -- ASan's shadow bookkeeping moves the
#                       allocation counters gcov timing does not care about,
#                       and gcov's -O0 defeats nothing ASan needs, so stacking
#                       them would only spend build time proving neither number)
#     --valgrind        build the server + both modules DEBUG, explicitly
#                       WITHOUT a sanitizer (mutually exclusive with both
#                       --sanitizer and --coverage). Valgrind memcheck and
#                       ASan both intercept malloc/free and both instrument
#                       the same shadow-adjacent bookkeeping; running one
#                       inside the other is unsupported upstream and produces
#                       noise, not signal (this is the same reason the S21
#                       weekly job's own consumer template insists on "DEBUG,
#                       not ASan"). Flags mirror ci-build.sh's `debug` mode
#                       (-DNGX_DEBUG_PALLOC=1 -g3 -O0), not re-derived here,
#                       for the same one-spelling-per-mode reason the
#                       --sanitizer and --coverage blocks below already give.
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
#   --sanitizer stages into <version>-testkit-asan, a SEPARATE tree. It is not
#   a variant of the same directory: this script wipes objs/ before building,
#   so one name for both would mean each stage destroys the other leg's tree,
#   and whichever ran last would silently decide whether "the testkit leg"
#   was sanitized. Two names means both legs can be staged and run in one
#   session, and `testkit-run.sh --sanitizer` selects a tree that is either
#   present and sanitized or absent -- never present and quietly unsanitized.
#
#   --coverage stages into <version>-testkit-coverage, same reasoning: a
#   coverage build's .gcno/.gcda live inside objs/, so sharing a directory with
#   the plain or sanitized stage would mean the LAST stage run silently decides
#   whether "the testkit leg" carries instrumentation data at all.
#
#   --valgrind stages into <version>-testkit-valgrind, same reasoning again,
#   plus a second one specific to this mode: sharing the plain tree would mean
#   an ordinary `testkit-stage.sh` run (no flags) silently overwrites a
#   DEBUG-built valgrind tree with an optimized one, or vice versa, and
#   sharing the `-asan` tree would produce a build that is BOTH DEBUG and
#   sanitized -- exactly the "unsupported, noise not signal" combination the
#   flag's help text above warns about. A dedicated name makes "the valgrind
#   leg's tree" either present-and-plain-debug or absent, never silently
#   co-opted by whichever other mode staged last.
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
SANITIZE=0
COVERAGE=0
VALGRIND=0

die()   { echo "testkit-stage: $*" >&2; exit 1; }
usage() { echo "testkit-stage: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
    case "$1" in
        --flavor)   FLAVOR="${2:?--flavor needs a value}"; shift 2 ;;
        --version)  VERSION="${2:?--version needs a value}"; shift 2 ;;
        --testkit)  TESTKIT="${2:?--testkit needs a value}"; shift 2 ;;
        --jobs)     JOBS="${2:?--jobs needs a value}"; shift 2 ;;
        --src)      SRC="${2:?--src needs a value}"; shift 2 ;;
        --sanitizer) SANITIZE=1; shift ;;
        --coverage) COVERAGE=1; shift ;;
        --valgrind) VALGRIND=1; shift ;;
        --keep-src) KEEP_SRC=1; shift ;;
        --dry-run)  DRY=1; shift ;;
        -h|--help)  sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)          usage "unknown option: $1 (try --help)" ;;
    esac
done

_modes=$((SANITIZE + COVERAGE + VALGRIND))
[ "$_modes" -gt 1 ] && \
    usage "--sanitizer, --coverage and --valgrind are mutually exclusive (separate purposes, separate stage trees)"

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
[ "$SANITIZE" -eq 1 ] && STAGE="${STAGE}-asan"
[ "$COVERAGE" -eq 1 ] && STAGE="${STAGE}-coverage"
[ "$VALGRIND" -eq 1 ] && STAGE="${STAGE}-valgrind"
BUILD_ROOT="${BUILD_ROOT:-$ROOT/.build}"
STAGE_DIR="$BUILD_ROOT/$STAGE"

CT_SO=ngx_http_cache_turbo_module.so
TK_SO=ngx_http_test_ref_module.so
SERVER_BIN=nginx
[ "$FLAVOR" = "angie" ] && SERVER_BIN=angie

# ---- the configure argv ----------------------------------------------------
# --with-compat: required for dynamic modules generally, and already what
# ci-build.sh passes.
#
# The ref probe is listed FIRST so that a truncated argv loses cache-turbo (a
# visibly missing .so, caught by the staleness gate below) rather than the
# probe (whose absence makes every oracle SKIP -- a silent pass).
#
# Deliberately NOT passed, unlike testkit's own tools/build-consumers.sh:
#   --with-stream --with-stream_ssl_module
# Those exist there for OTHER consumers.  http_ssl IS compiled because the
# TEST_FAULTS build's digest-failure seam lives in the SSL implementation;
# without it the guarded test variable has no reader and nginx's -Werror build
# correctly rejects the staged artifact as internally inconsistent.
#
# Every staged tree is a test artifact, so it carries the same TEST_FAULTS
# define as ci-build.sh.  Several prober scenarios use the module's guarded
# observability headers as their non-vacuous oracle; NGX_TEST_HARNESS alone
# only registers probe hooks and does not compile those counters in.
#
# Equally deliberate: nothing here DISABLES a default module. The scenario's
# conf needs http_proxy (its `location /` proxy_pass'es to /origin on its own
# port) and http_rewrite (`return 200` in /origin). Both are on by default, so
# the requirement is invisible until someone "trims" the configure line -- at
# which point nginx -t fails on an unknown directive and it reads like a
# scenario bug. Stated here so it is not discovered the hard way.
CONFIGURE_ARGS=(
    --with-compat
    --with-threads
    --with-http_ssl_module
    "--with-cc-opt=-DNGX_HTTP_CACHE_TURBO_TEST_FAULTS=1"
    "--add-dynamic-module=$TESTKIT/t/module"
    "--add-dynamic-module=$ROOT"
)

# ---- the sanitizer argv ----------------------------------------------------
# Flag derivation is DELIBERATELY the same spelling ci-build.sh's `asan` mode
# uses (ci-build.sh:96-113), not a second one invented here. Two spellings of
# "the ASan build" in one repo is how a leg ends up sanitized differently from
# the leg it is supposed to corroborate, and the difference is invisible until
# one of them fails to reproduce what the other saw.
#
# WHY THE FLAGS MUST GO ON THE *SERVER*, NOT ONLY THE PROBER
#   testkit's ci/prober/build.sh SAN=1 sanitizes the PROBER CLIENT -- a
#   separate process that speaks HTTP to nginx. It cannot observe anything
#   inside the server's address space. The finding this leg exists to read is
#   a SERVER-side abort, so the sanitizer has to be compiled into nginx and
#   both modules. nginx applies --with-cc-opt to every object including the
#   addon sources and --with-ld-opt to the final link, so one pair of flags
#   covers core, the ref probe and cache_turbo alike.
#
# -fno-sanitize-recover=undefined is what makes a UBSan finding FATAL, and it
# is a compile-time property: it survives a caller that runs the binary
# without carrying UBSAN_OPTIONS through. Without it every UBSan report is
# advisory and the scenario still exits 0 -- a green leg over a real defect.
if [ "$SANITIZE" -eq 1 ]; then
    SAN_FLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g3 -O1"
    # clang trips three known false positives on nginx core that gcc does not;
    # ci-build.sh:108-110 makes exactly this distinction and the reasons are
    # documented there. Mirrored rather than re-litigated.
    if "${CC:-cc}" --version 2>/dev/null | grep -qi clang; then
        SAN_FLAGS="-fsanitize=address,undefined -fno-sanitize=function,nonnull-attribute,pointer-overflow -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g3 -O1"
    fi
    CONFIGURE_ARGS+=(
        "--with-cc-opt=-DNGX_HTTP_CACHE_TURBO_TEST_FAULTS=1 $SAN_FLAGS"
        "--with-ld-opt=$SAN_FLAGS"
    )
fi

# ---- the coverage argv ------------------------------------------------------
# Flag derivation is DELIBERATELY the same spelling ci-build.sh's `coverage`
# mode uses (ci-build.sh:117-131), not a second one invented here -- the same
# reason the sanitizer block above mirrors ci-build.sh's `asan` mode instead of
# re-deriving it: two spellings of "the coverage build" in one repo is how a
# leg ends up instrumented differently from the one it is supposed to
# corroborate, and gcov is exactly the tool where that difference is invisible
# until someone diffs two .gcda files that do not agree on line/branch mapping.
#
# -O0 keeps arcs mapped 1:1 to source lines (ci-build.sh's own comment: any
# optimization folds branches and gcov starts lying). --coverage must reach
# BOTH the compile (-ftest-coverage emits .gcno) and the link (-fprofile-arcs
# needs libgcov linked into the .so) -- nginx's --with-cc-opt/--with-ld-opt
# split covers exactly that, same as the plain coverage.sh path.
if [ "$COVERAGE" -eq 1 ]; then
    COV_FLAGS="--coverage -g -O0 -fno-omit-frame-pointer"
    CONFIGURE_ARGS+=(
        "--with-cc-opt=-DNGX_HTTP_CACHE_TURBO_TEST_FAULTS=1 $COV_FLAGS"
        "--with-ld-opt=--coverage"
    )
fi

# ---- the valgrind argv ------------------------------------------------------
# Flag derivation is DELIBERATELY the same spelling ci-build.sh's `debug` mode
# uses (ci-build.sh:91, the MODE default), not a second one invented here --
# same one-spelling-per-mode reason as the sanitizer and coverage blocks
# above. This is also the exact build ci-deep.yml's existing memcheck/helgrind
# soaks already run under valgrind (`ci-build.sh nginx "$NGINX_VERSION"
# debug`), so a finding here and a finding there are the same build, not two
# builds that merely sound alike.
#
# NGX_DEBUG_PALLOC=1 turns on nginx's own pool poisoner/logging, which is
# orthogonal to valgrind's own instrumentation and stays on for the same
# reason the existing memcheck soak keeps it on: a module bug that corrupts
# pool bookkeeping is easier to place with both signals than with either
# alone. -O0 -g3 -fno-omit-frame-pointer keeps valgrind's stack unwinder
# accurate -- the same reasoning ci-build.sh's own debug-mode comment gives.
# Explicitly NO --with-cc-opt/--with-ld-opt sanitizer flags: see the
# --valgrind help text above for why stacking ASan under memcheck is
# unsupported and produces noise, not signal.
if [ "$VALGRIND" -eq 1 ]; then
    DBG_FLAGS="-DNGX_DEBUG_PALLOC=1 -g3 -O0 -fno-omit-frame-pointer -funwind-tables"
    CONFIGURE_ARGS+=(
        --with-debug
        "--with-cc-opt=-DNGX_HTTP_CACHE_TURBO_TEST_FAULTS=1 $DBG_FLAGS"
    )
fi

if [ "$DRY" -eq 1 ]; then
    echo "would fetch    : $URL"
    echo "would verify   : $EXPECTED_SHA256"
    echo "would stage    : $STAGE_DIR/objs"
    echo "would configure: ./configure ${CONFIGURE_ARGS[*]}"
    echo "would build    : make -j$JOBS   (server binary + both modules)"
    [ "$SANITIZE" -eq 1 ] && echo "would require  : __asan_ present in objs/nginx and both .so"
    [ "$COVERAGE" -eq 1 ] && echo "would require  : .gcno present next to both modules' objects"
    [ "$VALGRIND" -eq 1 ] && echo "would require  : a DEBUG build with NO ASan/UBSan runtime present"
    echo "would require  : objs/$TK_SO newer than $TESTKIT/src"
    echo "                 objs/$CT_SO newer than $ROOT/src"
    echo "                 objs/$SERVER_BIN executable"
    exit 0
fi

# ---- host rule: one build at a time ----------------------------------------
# A concurrent nginx/pbuilder build on this box thrashes and has produced stale
# artifacts before. Refuse rather than race.
# Match the executable identity (or a shebang interpreter's script argv), not
# arbitrary command-line prose. A watcher or shell command that merely names
# pbuilder must not block every testkit build on the host.
# shellcheck disable=SC1091
source "$ROOT/ci/tools/testkit-host-guard.sh"
BUILD_GUARD_RC=0
testkit_package_build_running || BUILD_GUARD_RC=$?
case "$BUILD_GUARD_RC" in
    0) die "another package build is running on this host -- refusing to start (one build at a time)" ;;
    1) ;;
    *) die "cannot inspect host processes for concurrent package builds -- refusing to fail open" ;;
esac

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
elif [ "$COVERAGE" -eq 1 ]; then
    # Coverage CANNOT use the mktemp-then-cp-r path below. gcc's --coverage
    # bakes the OBJECT file's compile-time cwd + relative path into the
    # .gcno (verified with gcov-dump -p: a `cwd:` line plus each FUNCTION
    # record's source path) -- not a portable path resolved from the
    # binary's own location, and not one `cp -r`ing objs/ afterward can fix.
    # gcov looks for that exact path at runtime to write the matching
    # .gcda; a `cp -r "$BUILDDIR/objs" "$STAGE_DIR/objs"` into a directory
    # that then gets `rm -rf`'d by the `cleanup` trap leaves gcov trying to
    # create .gcda under a deleted /tmp path, which fails silently -- gcov
    # has no error message for this, gcda counters just never appear (and
    # nginx exits 0, the scenario TAP passes, so a run against a tree bad
    # this way reads as "the prober legs add nothing", not as broken
    # instrumentation).
    #
    # The fix: build coverage mode IN PLACE under STAGE_DIR itself, the same
    # arrangement ci-build.sh's `coverage` mode already relies on (it builds
    # in $ROOT/$DIR, never a scratch dir) -- so the cwd gcc records at
    # compile time is the same path the staged tree lives at forever after,
    # and the stage step below becomes a no-op (BUILDDIR IS STAGE_DIR/src,
    # objs/ is already where it needs to be).
    BUILDDIR="$STAGE_DIR/src"
    if [ -f "$BUILDDIR/configure" ]; then
        echo "==> reusing in-place coverage source tree $BUILDDIR"
    else
        rm -rf "$BUILDDIR"
        mkdir -p "$BUILDDIR"
        echo "==> fetching $URL"
        # TMP, not a separate FETCH_TMP -- TMP is the variable `cleanup`'s
        # EXIT trap already tracks (declared above, before this fetch could
        # possibly run), so an interrupt mid-fetch still reaps this scratch
        # dir instead of leaking it under /tmp the way a second untracked
        # variable would. KEEP_SRC does not apply to it: that flag means
        # "keep the tree actually being built" (already $STAGE_DIR/src for
        # coverage, permanent regardless), not "keep this fetch scratch
        # space too" -- so it is removed unconditionally on every path below,
        # matching the plain (non-coverage) fetch further down which has no
        # KEEP_SRC-conditional scratch step of its own either.
        TMP="$(mktemp -d "${TMPDIR:-/tmp}/testkit-stage-fetch.XXXXXX")"
        bash "$ROOT/.github/scripts/fetch-verify.sh" \
            "$URL" "$EXPECTED_SHA256" "$TMP/${DIR}.tar.gz" \
            || die "fetch/verify failed for $URL"
        tar -xzf "$TMP/${DIR}.tar.gz" -C "$TMP"
        [ -d "$TMP/$DIR" ] || die "tarball did not unpack to expected dir $DIR"
        # rsync/cp the unpacked tree's CONTENTS into BUILDDIR rather than
        # renaming $TMP/$DIR itself -- BUILDDIR's path (under STAGE_DIR) is
        # what must be stable across runs, not the fetch tmpdir's randomized
        # name.
        cp -r "$TMP/$DIR/." "$BUILDDIR/"
        rm -rf "$TMP" 2>/dev/null || true
        TMP=""
    fi
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
# Coverage built IN PLACE (see above) -- objs/ already lives under $BUILDDIR,
# which is normally $STAGE_DIR/src but can also be an external --src tree, so
# `rm -rf "$STAGE_DIR"` here would delete the source tree (and the objs/ this
# build just produced) before the copy below ever ran, and a symlink target
# hardcoded to the STAGE_DIR/src layout would dangle under --src. Wipe and
# relink just objs/, pointed at $BUILDDIR/objs directly (absolute, so it is
# correct in both layouts): everything downstream (the staleness gate, the
# coverage gate, testkit-run.sh) only ever reads $STAGE_DIR/objs, so a symlink
# is exactly as good as a copy and avoids doubling disk use for a tree gcov
# needs to keep matching its .gcno forever.
if [ "$COVERAGE" -eq 1 ]; then
    rm -rf "$STAGE_DIR/objs"
    ln -s "$BUILDDIR/objs" "$STAGE_DIR/objs"
else
    rm -rf "$STAGE_DIR"
    mkdir -p "$STAGE_DIR"
    cp -r "$BUILDDIR/objs" "$STAGE_DIR/objs"
fi

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
    local newest_mtime=0 newest_src="" f m inventory
    inventory="$(mktemp)" || return 2
    # A process substitution would return read's status and hide find failing
    # after emitting a real source. Materialise the NUL-delimited discovery
    # first: a partial source list must never certify a staged object as fresh.
    if ! find "$@" -maxdepth "$depth" -type f \
        \( -name '*.c' -o -name '*.h' \) -print0 >"$inventory" 2>/dev/null; then
        rm -f "$inventory"
        return 2
    fi
    while IFS= read -r -d '' f; do
        m="$(stat -c %Y "$f")"
        if [ "$m" -gt "$newest_mtime" ]; then
            newest_mtime="$m"
            newest_src="$f"
        fi
    done <"$inventory"
    rm -f "$inventory"
    [ -n "$newest_src" ] || return 1
    printf '%s %s\n' "$newest_mtime" "$newest_src"
}

unset newest_rc
ct_ref="$(newest_of 1 "$ROOT/src")" || newest_rc=$?
if [ "${newest_rc:-0}" -eq 2 ]; then
    usage "source inventory failed under $ROOT/src -- refusing partial freshness check"
elif [ "${newest_rc:-0}" -ne 0 ]; then
    die "no sources found under $ROOT/src -- refusing to report a fresh build on an empty scan"
fi
CT_MTIME="${ct_ref%% *}"; CT_NEWEST="${ct_ref#* }"

unset newest_rc
tk_ref="$(newest_of 2 "$TESTKIT/src" "$TESTKIT/t/module")" || newest_rc=$?
if [ "${newest_rc:-0}" -eq 2 ]; then
    usage "source inventory failed under $TESTKIT/src or $TESTKIT/t/module -- refusing partial freshness check"
elif [ "${newest_rc:-0}" -ne 0 ]; then
    die "no sources found under $TESTKIT/src or $TESTKIT/t/module -- refusing to report a fresh build on an empty scan"
fi
TK_MTIME="${tk_ref%% *}"; TK_NEWEST="${tk_ref#* }"

# The server binary is checked for existence and executability only -- its
# mtime is not compared against this module's sources, because nginx core does
# not rebuild when only src/*.c here changes, and demanding it would fail every
# incremental stage for no safety gain. prober_resolve makes the same
# distinction (lib.sh:96 tests -x, not mtime).
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

# ---- the sanitizer gate -----------------------------------------------------
# A staged tree that was ASKED for a sanitizer and did not get one is the
# worst outcome this script can produce, and it is SILENT by construction:
# every oracle still runs, the scenario still passes, and the leg reports
# green while observing nothing a plain build would not have observed. That is
# indistinguishable in a job summary from a sanitizer leg that found no
# defect -- exactly the `1..0 # SKIP` shape this whole integration was built
# to eliminate, one level deeper.
#
# It is not hypothetical. The flags travel through --with-cc-opt, which nginx
# will happily accept and pass to a compiler that does not support them (the
# failure then lands in the MAKE, which is caught) -- but also through a
# ./configure that silently drops them if a future auto/ script rewrites
# CC_OPT, and through a --src reuse where a previously-configured tree's
# objs/Makefile is regenerated but a stale binary survives a partial make.
#
# The check is the SAME detection testkit's lib.sh:244 uses to decide
# PROBER_SANITIZED, deliberately: if this gate and the harness disagree, the
# harness wins at runtime and this script's verdict was a lie. Matching it
# means a tree that passes here is a tree the harness will also call
# sanitized. All three objects are checked, not just the server -- nginx core
# and the two dynamic modules are separate link units, and a .so built
# without the flags loads into a sanitized server without complaint while
# leaving this module's own code entirely uninstrumented.
if [ "$SANITIZE" -eq 1 ]; then
    for obj in "$SERVER_BIN" "$TK_SO" "$CT_SO"; do
        path="$STAGE_DIR/objs/$obj"
        [ -f "$path" ] || continue   # already reported MISSING above
        if ! grep -qa '__asan_\|__ubsan_' "$path"; then
            echo "testkit-stage: NOT SANITIZED $obj" >&2
            echo "  --sanitizer was requested but $path carries no ASan/UBSan runtime" >&2
            echo "  (same detection testkit's lib.sh:244 uses for PROBER_SANITIZED)" >&2
            echo "  a scenario run against this tree would report green while observing nothing" >&2
            status=3
        fi
    done
fi

# The converse also matters, and costs one grep: an UNsanitized stage that
# picked up the runtime anyway means CFLAGS leaked in from the environment,
# and the "unsanitized leg" is quietly measuring a sanitized process. The
# consumer-cache-turbo oracles are allocation-neutrality assertions; ASan's
# quarantine and shadow bookkeeping move exactly the numbers they read (the
# harness documents a master that grows 21 pages unsanitized and 402 under
# ASan). A leg mislabelled in this direction does not fail -- it reports
# different numbers and invites someone to "fix" the oracle.
if [ "$SANITIZE" -eq 0 ] && [ -f "$STAGE_DIR/objs/$SERVER_BIN" ]; then
    if grep -qa '__asan_\|__ubsan_' "$STAGE_DIR/objs/$SERVER_BIN"; then
        echo "testkit-stage: UNEXPECTEDLY SANITIZED $SERVER_BIN" >&2
        echo "  --sanitizer was NOT requested, but the binary carries an ASan/UBSan runtime" >&2
        echo "  a sanitizer almost certainly leaked in via CFLAGS/CC in the environment" >&2
        echo "  the allocation-neutrality oracles read numbers the sanitizer itself moves" >&2
        status=3
    fi
fi

# ---- the coverage gate ------------------------------------------------------
# Same failure shape as the sanitizer gate above, one level removed: a staged
# tree that was ASKED for coverage and did not get it runs every scenario,
# reports every oracle result correctly, and produces zero .gcda -- which
# reads exactly like "the prober legs add nothing" instead of "instrumentation
# never happened". gcov instrumentation has no runtime symbol to grep for the
# way __asan_/__ubsan_ mark a sanitized binary; the proof is that the COMPILER
# emitted a .gcno next to each object, one per translation unit, at compile
# time -- so that is what is checked. Both --add-dynamic-module trees share
# ONE objs/addon/ (nginx namespaces by each module's own source directory
# basename, not by module): cache_turbo's objects (and, because t/module's
# config reaches them by relative climb, the ref probe's ngx_test_probe*.o
# support files) land under objs/addon/src, while the ref module's own single
# translation unit lands under objs/addon/module (named after testkit's
# t/module dir). Verified against an actual staged tree -- there is no
# "addon2"-shaped second path. nginx core's own .gcno are not this script's
# concern; coverage.sh already filters to src/ downstream.
if [ "$COVERAGE" -eq 1 ]; then
    for addon in "$STAGE_DIR/objs/addon/src" "$STAGE_DIR/objs/addon/module"; do
        [ -d "$addon" ] || continue
        if ! find "$addon" -maxdepth 1 -name '*.gcno' -print -quit | grep -q .; then
            echo "testkit-stage: NO .gcno UNDER $addon" >&2
            echo "  --coverage was requested but no gcov notes file was emitted there" >&2
            echo "  a scenario run against this tree would report green while measuring nothing" >&2
            status=3
        fi
    done
fi

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
