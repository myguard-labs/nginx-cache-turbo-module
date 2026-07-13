#!/usr/bin/env bash
#
# Build nginx (or angie) with http-cache-turbo for CI.
#   ci-build.sh <flavor> <version> <mode>
#     flavor : nginx | angie         (default nginx)
#     version: upstream version      (default 1.31.1)
#     mode   : debug | nginx | asan | module
#              debug  - debug build + module (default)
#              nginx  - release-ish build + module
#              asan   - static --add-module build with ASan+UBSan (no .so)
#              module - build only the .so, skip the binary
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
