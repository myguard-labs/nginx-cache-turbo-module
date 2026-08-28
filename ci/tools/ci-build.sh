#!/usr/bin/env bash
#
# Build nginx (or angie) with http-cache-turbo for CI.
#   ci-build.sh <flavor> <version> <mode>
#     flavor : nginx | angie         (default nginx)
#     version: upstream version      (default 1.31.1)
#     mode   : debug | nginx | asan | module | coverage | profile
#              debug    - debug build + module (default)
#              nginx    - release-ish build + module
#              asan     - static --add-module build with ASan+UBSan (no .so)
#              module   - build only the .so, skip the binary
#              coverage - gcov-instrumented .so + binary; run the runtime suite
#                         against it, then gcov/lcov the module objects.
#                         .gcno files land under objs/addon/src/; the matching
#                         .gcda are written when the instrumented nginx exits.
#                         ci/tools/coverage.sh drives build -> run -> report.
#              configure - run ./configure ONLY and stop. Produces
#                         objs/Makefile (and so ALL_INCS) without compiling
#                         anything, which is all ci/tools/lint-carve-init.sh
#                         needs to parse the module against nginx's real
#                         include set. Seconds rather than minutes, so the
#                         validation job can have a parseable tree without
#                         waiting on a build.
#              profile  - optimized (-O2) dynamic module + binary with debug
#                         symbols and frame pointers kept, for `perf record`.
#                         Same optimization level as a real release build
#                         (unlike `nginx` mode's -O1), so the profile reflects
#                         the shipped code path, not a slower unoptimized one.
#                         See ci/tools/perf-profile.sh.
#
# No hiredis: cache-turbo's L2 Redis driver is native nginx, so the build has
# no -lhiredis dependency (see memory/.../cache-turbo-module-design.md).

set -euo pipefail

if [ -f .github/versions.env ]; then
    # shellcheck disable=SC1091
    source .github/versions.env
fi
FLAVOR="${1:-nginx}"
VERSION="${2:-${NGINX_VERSION:-1.31.1}}"
MODE="${3:-debug}"
ROOT="${BUILD_ROOT:-$PWD/.build}"
MODULE_DIR="$PWD"
TEST_OPT="-DNGX_HTTP_CACHE_TURBO_TEST_FAULTS=1"

case "$FLAVOR" in
    nginx)
        URL="https://nginx.org/download/nginx-${VERSION}.tar.gz"
        DIR="nginx-${VERSION}"
        BINARY="nginx"
        case "$VERSION" in
            "${NGINX_MAINLINE:-}") EXPECTED_SHA256="${NGINX_MAINLINE_SHA256:-}" ;;
            "${NGINX_STABLE:-}") EXPECTED_SHA256="${NGINX_STABLE_SHA256:-}" ;;
            "${LEGACY_NGINX_VERSION:-}") EXPECTED_SHA256="${LEGACY_NGINX_VERSION_SHA256:-}" ;;
            *) echo "no sha256 pin for nginx $VERSION" >&2; exit 2 ;;
        esac
        ;;
    angie)
        URL="https://download.angie.software/files/angie-${VERSION}.tar.gz"
        DIR="angie-${VERSION}"
        BINARY="angie"
        EXPECTED_SHA256="${ANGIE_SHA256:-}"
        ;;
    *)
        echo "unsupported flavor: $FLAVOR" >&2
        exit 2
        ;;
esac

mkdir -p "$ROOT"
bash "$MODULE_DIR/.github/scripts/fetch-verify.sh" \
    "$URL" "$EXPECTED_SHA256" "$ROOT/${DIR}.tar.gz"
if [ ! -d "$ROOT/$DIR" ]; then
    tar -xzf "$ROOT/${DIR}.tar.gz" -C "$ROOT"
fi

# ccache: cache object compiles across CI runs (50-80% compile cut on a warm
# cache). Auto-detected on PATH so a local build without ccache still works.
# nginx honors --with-cc; the base build uses the default `cc`, the asan/coverage
# branches below set a clang-specific CC, so wrap whichever compiler is in play.
# ASan/coverage flags are already in the compile hash (they live in --with-cc-opt),
# so those branches get their own cache namespace for free — no manual split.
CC="${CC:-cc}"
if command -v ccache >/dev/null 2>&1; then
    WITH_CC="ccache $CC"
    # Key ccache objects by compiler CONTENT, not mtime/size. Without this a
    # cache restored onto a different runner (or after a toolchain reinstall
    # that changed the compiler mtime) is treated as stale and wholesale-missed;
    # content hashing makes the cross-run/cross-runner ~/.cache/ccache that the
    # build-cache action persists actually reusable. Safe: a content mismatch
    # only ever MISSES, never serves a wrong object.
    export CCACHE_COMPILERCHECK=content
else
    WITH_CC="$CC"
fi

CC_OPT="$TEST_OPT -DNGX_DEBUG_PALLOC=1 -g3 -O0 -fno-omit-frame-pointer -funwind-tables"
LD_OPT=""
ADD_MODULE="--add-dynamic-module=$MODULE_DIR"
WITH_DEBUG="--with-debug"
case "$MODE" in
    asan)
        # Disable the UBSan sub-checks that nginx CORE trips as benign false
        # positives (so a soak under sanitizers doesn't abort on them):
        #   function          - core calls filters through a generic
        #                        ngx_*_filter_pt with a slightly different proto.
        #   nonnull-attribute - core passes NULL + len 0 to memcpy in the
        #                        proxy/upstream path.
        #   pointer-overflow  - core p +/- n arithmetic UBSan flags on buffers.
        # ASan and the rest of UBSan stay on. These -fno-sanitize sub-check
        # names are clang-specific; gcc's configure rejects nonnull-attribute/
        # pointer-overflow. Only add them under clang (the local soak path);
        # gcc keeps plain -fsanitize (CI was green, gcc doesn't trip these FPs).
        SAN="$TEST_OPT -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g3 -O1"
        if "${CC:-cc}" --version 2>/dev/null | grep -qi clang; then
            SAN="$TEST_OPT -fsanitize=address,undefined -fno-sanitize=function,nonnull-attribute,pointer-overflow -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g3 -O1"
        fi
        CC_OPT="$SAN"
        LD_OPT="$SAN"
        # ASan needs the module linked into the binary (static), not dlopen'd.
        ADD_MODULE="--add-module=$MODULE_DIR"
        ;;
    coverage)
        # gcov instrumentation on the MODULE only. --coverage =
        # -fprofile-arcs -ftest-coverage; -O0 keeps arcs mapped 1:1 to source
        # lines (optimization folds branches and makes gcov lie). No
        # NGX_DEBUG_PALLOC / --with-debug: the pool poisoner and debug logging
        # are irrelevant to coverage and only slow the suite. TEST_FAULTS stays
        # on so the fault-injection tests (and their code paths) are counted.
        #
        # --coverage must reach BOTH the compile and link of the module's
        # objects: -ftest-coverage emits .gcno at compile, -fprofile-arcs needs
        # libgcov linked into the .so. nginx applies --with-cc-opt to every
        # object including addon/src, and --with-ld-opt to the final link, so
        # both land where they must. WITH_DEBUG cleared so the run is faster.
        CC_OPT="$TEST_OPT --coverage -g -O0 -fno-omit-frame-pointer"
        LD_OPT="--coverage"
        WITH_DEBUG=""
        ;;
    nginx)
        # Stock nginx defaults for benchmarking (ci/tools/bench.sh): the only
        # --with-cc-opt is the inert CI fault-test hook, so nginx keeps its own
        # optimization defaults (-O, i.e. -O1), with no NGX_DEBUG_PALLOC
        # poisoning and no --with-debug logging. This is not the distro's
        # hardened -O2 set — it is a neutral upstream baseline. The module stays
        # a dynamic .so; bench it with MODULE=<.so> ci/tools/bench.sh.
        #
        # -flto=auto -ffat-lto-objects: the module's 15 src/*.c are compiled
        # as separate TUs, so every cross-TU accessor (get_u16/u32/u64, put_*,
        # blob_acquire, digest_update — 2-3 instructions each) is a real call
        # on the hit path instead of inlining. Measured on 59d30b5f: .text
        # 113535 -> 112116 bytes, intra-module calls 451 -> 325 (-28%), and all
        # 48 cross-TU accessor call sites inline to zero. -ffat-lto-objects
        # keeps a non-LTO fallback object alongside the IR in each .o (a real
        # compile-time cost) but nginx's ./configure probe-compiles a handful
        # of throwaway .c files outside the LTO link graph, and the shared
        # dynamic module link mixes module objects with nginx core objects
        # built by the same --with-cc-opt/--with-ld-opt — fat objects keep
        # those non-LTO consumers linkable without a second build mode.
        CC_OPT="$TEST_OPT -flto=auto -ffat-lto-objects"
        LD_OPT="-flto=auto"
        WITH_DEBUG=""
        ;;
    profile)
        # -O2 to match a real release build (bench.sh's `nginx` mode is only
        # -O1), plus -g and an explicit -fno-omit-frame-pointer so `perf
        # record`'s frame-pointer unwinder resolves the hit-path call stack
        # instead of dropping into '[unknown]'. No NGX_DEBUG_PALLOC / --with-debug
        # so nothing extra runs on the profiled path. The module stays a
        # dynamic .so; profile it with MODULE=<.so> ci/tools/perf-profile.sh.
        #
        # -flto=auto -ffat-lto-objects: same cross-TU inlining as `nginx`
        # mode above (see that comment) — the profiled build should reflect
        # the shipped code path, not a slower non-LTO one.
        CC_OPT="$TEST_OPT -g -O2 -fno-omit-frame-pointer -flto=auto -ffat-lto-objects"
        LD_OPT="-flto=auto"
        WITH_DEBUG=""
        ;;
esac

# mold: faster linker, auto-detected on PATH. Appended (never clobbering) so the
# asan/coverage LD_OPT flags set in the case above are preserved. -fuse-ld=mold
# is understood by both gcc and clang.
#
# SKIPPED under asan (and coverage, which links the same sanitizer-adjacent
# runtime): the sanitizer runtimes want the toolchain's own linker, and asan.yml
# installs mold for the other layers, so without this guard the ASan binary is
# silently linked by mold. Speed on a job whose whole purpose is instrumentation
# fidelity is the wrong trade -- keep the default linker there.
case "$MODE" in
    asan|coverage) ;;
    *)
        if command -v mold >/dev/null 2>&1; then
            LD_OPT="${LD_OPT:+$LD_OPT }-fuse-ld=mold"
        fi
        ;;
esac

# eatmydata: drop fsync/fdatasync on the many small object + intermediate writes
# make performs. Marginal but free; auto-detected so a local build without it is
# unaffected. Wraps only the build (make), not configure — configure is I/O-light.
MAKE="make"
if command -v eatmydata >/dev/null 2>&1; then
    MAKE="eatmydata make"
fi

cd "$ROOT/$DIR"
./configure \
    --with-compat \
    $WITH_DEBUG \
    --with-cc="$WITH_CC" \
    --with-http_realip_module \
    --with-http_ssl_module \
    --with-cc-opt="$CC_OPT" \
    --with-ld-opt="$LD_OPT" \
    "$ADD_MODULE"

# configure mode stops here: objs/Makefile now exists, which is everything the
# carve-init parser needs. Compiling would add minutes and change nothing it
# reads.
if [ "$MODE" = "configure" ]; then
    printf 'tree=%s\n' "$ROOT/$DIR"
    exit 0
fi

if [ "$MODE" != "asan" ]; then
    # MAKE may be "eatmydata make" — must word-split.
    # shellcheck disable=SC2086
    $MAKE -j"$(nproc)" modules
fi

if [ "$MODE" != "module" ]; then
    # shellcheck disable=SC2086
    $MAKE -j"$(nproc)"
    printf 'binary=%s\n' "$ROOT/$DIR/objs/$BINARY"
fi

if [ "$MODE" != "asan" ]; then
    printf 'module=%s\n' "$ROOT/$DIR/objs/ngx_http_cache_turbo_module.so"
fi
