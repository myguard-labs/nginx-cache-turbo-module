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
#                         tools/coverage.sh drives build -> run -> report.
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
bash "$MODULE_DIR/tools/verify-download.sh" "$ROOT/${DIR}.tar.gz"
if [ ! -d "$ROOT/$DIR" ]; then
    tar -xzf "$ROOT/${DIR}.tar.gz" -C "$ROOT"
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
        # Stock nginx defaults for benchmarking (tools/bench.sh): the only
        # --with-cc-opt is the inert CI fault-test hook, so nginx keeps its own
        # optimization defaults (-O, i.e. -O1), with no NGX_DEBUG_PALLOC
        # poisoning and no --with-debug logging. This is not the distro's
        # hardened -O2 set — it is a neutral upstream baseline. The module stays
        # a dynamic .so; bench it with MODULE=<.so> tools/bench.sh.
        CC_OPT="$TEST_OPT"
        WITH_DEBUG=""
        ;;
esac

# TEST_HARNESS=1 compiles the CI-only cache_turbo_probe introspection endpoint
# (t/harness, zero-hook mode) into the module. Never set for a packaged build:
# the probe scans /proc and exposes internal state unauthenticated. Appended
# AFTER the mode case so the asan leg (which replaces CC_OPT wholesale) keeps
# the define too.
if [ "${TEST_HARNESS:-0}" = "1" ]; then
    CC_OPT="$CC_OPT -DNGX_TEST_HARNESS"
fi

cd "$ROOT/$DIR"
./configure \
    --with-compat \
    $WITH_DEBUG \
    --with-http_realip_module \
    --with-http_ssl_module \
    --without-http_rewrite_module \
    --with-cc-opt="$CC_OPT" \
    --with-ld-opt="$LD_OPT" \
    "$ADD_MODULE"

if [ "$MODE" != "asan" ]; then
    make -j"$(nproc)" modules
fi

if [ "$MODE" != "module" ]; then
    make -j"$(nproc)"
    printf 'binary=%s\n' "$ROOT/$DIR/objs/$BINARY"
fi

if [ "$MODE" != "asan" ]; then
    printf 'module=%s\n' "$ROOT/$DIR/objs/ngx_http_cache_turbo_module.so"
fi
