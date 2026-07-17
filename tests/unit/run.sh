#!/usr/bin/env bash
#
# Build + run the cache-turbo pure-math unit tests. Fast, hermetic, no nginx.
#
#   tests/unit/run.sh            # build with warnings-as-errors + run
#   COVERAGE=1 tests/unit/run.sh # also instrument (--coverage) so a caller can
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
