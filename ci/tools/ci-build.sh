#!/usr/bin/env bash
#
# Build nginx (or angie) with http-cache-turbo for CI.
#   ci-build.sh <flavor> <version> <mode>
#     flavor : nginx | angie         (default nginx)
#     version: upstream version      (default 1.31.1)
#     mode   : debug | nginx | asan | module | coverage
#              debug    - debug build + module (default)
#              nginx    - release-ish build + module
#              asan     - static --add-module build with ASan+UBSan (no .so)
#              module   - build only the .so, skip the binary
#              coverage - gcov-instrumented .so + binary; run the runtime suite
#                         against it, then gcov/lcov the module objects.
#                         .gcno files land under objs/addon/src/; the matching
#                         .gcda are written when the instrumented nginx exits.
#                         ci/tools/coverage.sh drives build -> run -> report.
#
# No hiredis: cache-turbo's L2 Redis driver is native nginx, so the build has
# no -lhiredis dependency (see memory/.../cache-turbo-module-design.md).

set -euo pipefail

FLAVOR="${1:-nginx}"
VERSION="${2:-1.31.1}"
MODE="${3:-debug}"
ROOT="${BUILD_ROOT:-$PWD/.build}"
MODULE_DIR="$PWD"
TEST_OPT="-DNGX_HTTP_CACHE_TURBO_TEST_FAULTS=1"

case "$FLAVOR" in
    nginx)
        URL="https://nginx.org/download/nginx-${VERSION}.tar.gz"
        DIR="nginx-${VERSION}"
        BINARY="nginx"
        ;;
    angie)
        URL="https://download.angie.software/files/angie-${VERSION}.tar.gz"
        DIR="angie-${VERSION}"
        BINARY="angie"
        ;;
    *)
        echo "unsupported flavor: $FLAVOR" >&2
        exit 2
        ;;
esac

mkdir -p "$ROOT"
if [ ! -f "$ROOT/${DIR}.tar.gz" ]; then
    curl -fsSL "$URL" -o "$ROOT/${DIR}.tar.gz"
fi
bash "$MODULE_DIR/ci/tools/verify-download.sh" "$ROOT/${DIR}.tar.gz"
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
        CC_OPT="$TEST_OPT"
        WITH_DEBUG=""
        ;;
esac

# mold: faster linker, auto-detected on PATH. Appended (never clobbering) so the
# asan/coverage LD_OPT flags set in the case above are preserved. -fuse-ld=mold
# is understood by both gcc and clang.
if command -v mold >/dev/null 2>&1; then
    LD_OPT="${LD_OPT:+$LD_OPT }-fuse-ld=mold"
fi

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
    --without-http_rewrite_module \
    --with-cc-opt="$CC_OPT" \
    --with-ld-opt="$LD_OPT" \
    "$ADD_MODULE"

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
