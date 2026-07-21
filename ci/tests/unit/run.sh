#!/usr/bin/env bash
#
# Build + run the cache-turbo pure-math unit tests. Fast, hermetic, no nginx.
#
#   ci/tests/unit/run.sh            # build with warnings-as-errors + run
#   COVERAGE=1 ci/tests/unit/run.sh # also instrument (--coverage) so a caller can
#                                # gcov ../../src/ngx_http_cache_turbo_{swr,
#                                # autotune}.c afterwards
#
# The driver #includes the shipped src units verbatim, so a prod change to the
# math flows straight into the test. check_constants.sh guards the one thing the
# shim duplicates (the fixed-point constants) against drift from module.h.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CC="${CC:-cc}"
CFLAGS="-g -O0 -Wall -Wextra -Werror -I$DIR"

bash "$DIR/check_constants.sh"

if [ "${COVERAGE:-0}" = 1 ]; then
    CFLAGS="$CFLAGS --coverage"
fi

# shellcheck disable=SC2086
"$CC" $CFLAGS "$DIR/test_math.c" -o "$DIR/test_math"
"$DIR/test_math"

# --- shm node state machine (CR-A / CR-B guards) --------------------------
# Unlike the pure-math tests these link nginx's real ngx_rbtree.c, so they need
# a CONFIGURED nginx source tree (objs/ngx_auto_config.h exists only after
# ./configure). Where there isn't one, skip with a notice rather than fail --
# the Validation job runs before any nginx build.
#
# ⚠ SKIPPING IS ONLY SAFE BECAUSE A JOB THAT HAS THE TREE ALSO RUNS THIS.
# If the only caller were a tree-less job this would silently test nothing,
# which is the exact failure mode these tests exist to prevent. Keep the
# build-test "Runtime" job (which has the configured tree) calling run.sh.
NGINX_VERSION="${NGINX_VERSION:-1.31.1}"
NGX_SRC="${NGX_SRC:-$DIR/../../../.build/nginx-$NGINX_VERSION}"

# Honour the Makefile's own variable names if the caller set them. These are
# passed to make as command-line args below, which override the environment --
# so without reading them here a caller pointing this script at a custom tree
# (following the Makefile, or the pattern in build-test.yml) would be silently
# ignored in favour of the .build default.
NGINX_SRC="${NGINX_SRC:-$NGX_SRC/src}"
NGINX_OBJS="${NGINX_OBJS:-$NGX_SRC/objs}"

if [ -f "$NGINX_OBJS/ngx_auto_config.h" ]; then
    echo "--- shm node state machine (ASan/UBSan) ---"
    make -C "$DIR" --no-print-directory check \
        NGINX_VERSION="$NGINX_VERSION" \
        NGINX_SRC="$NGINX_SRC" \
        NGINX_OBJS="$NGINX_OBJS"
else
    echo "--- shm node state machine: SKIPPED (no configured nginx tree at" \
         "$NGINX_OBJS) ---"
    echo "    build one with ci/tools/ci-build.sh, or run ci/tests/unit/make check" \
         "with NGINX_SRC/NGINX_OBJS set."
fi
