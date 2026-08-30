#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
# Compile the production TTL_MAX definition at the active ABI width.  The math
# unit uses a shim, so without this extractor a matching shim edit could leave
# the shipped header's 32-bit cast bug completely untested.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
CC="${CC:-cc}"
FLAGS="${UNIT_CFLAGS:-}"
EXPECT_TIME_T_BYTES="${EXPECT_TIME_T_BYTES:-}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

definition="$(grep -E '^#define[[:space:]]+NGX_HTTP_CACHE_TURBO_TTL_MAX[[:space:]]' \
    "$ROOT/src/ngx_http_cache_turbo_module.h")"
[ "$(printf '%s\n' "$definition" | grep -c .)" -eq 1 ] || {
    echo "TTL width: expected one single-line production definition" >&2
    exit 1
}

{
    printf '#include <stdint.h>\n#include <time.h>\n%s\n' "$definition"
    printf '_Static_assert(NGX_HTTP_CACHE_TURBO_TTL_MAX > 0, "TTL_MAX must be positive");\n'
    printf '_Static_assert(NGX_HTTP_CACHE_TURBO_TTL_MAX == (sizeof(time_t) < 8 ? 0x7FFFFFFFLL : 0xFFFFFFFFLL), "TTL_MAX width drift");\n'
} > "$TMP/positive.c"
case "$EXPECT_TIME_T_BYTES" in
    '') ;;
    4 | 8)
        printf '_Static_assert(sizeof(time_t) == %s, "unexpected time_t width");\n' \
            "$EXPECT_TIME_T_BYTES" >> "$TMP/positive.c"
        ;;
    *)
        echo "TTL width: EXPECT_TIME_T_BYTES must be 4 or 8" >&2
        exit 1
        ;;
esac
# shellcheck disable=SC2086
"$CC" $FLAGS -Wall -Wextra -Werror -fsyntax-only "$TMP/positive.c"

if [ -n "$EXPECT_TIME_T_BYTES" ]; then
    if [ "$EXPECT_TIME_T_BYTES" -eq 4 ]; then
        wrong_time_t_bytes=8
    else
        wrong_time_t_bytes=4
    fi
    printf '#include <time.h>\n_Static_assert(sizeof(time_t) == %s, "width mutant");\n' \
        "$wrong_time_t_bytes" > "$TMP/width_mutant.c"
    # shellcheck disable=SC2086
    if "$CC" $FLAGS -fsyntax-only "$TMP/width_mutant.c" >/dev/null 2>&1; then
        echo "TTL width: opposite time_t-width mutant survived" >&2
        exit 1
    fi
fi

printf '#include <time.h>\nint main(void) { return sizeof(time_t) < 8 ? 0 : 1; }\n' \
    > "$TMP/time_width.c"
# shellcheck disable=SC2086
"$CC" $FLAGS -Wall -Wextra -Werror "$TMP/time_width.c" -o "$TMP/time_width"
if "$TMP/time_width"; then
    printf '#include <time.h>\n#define NGX_HTTP_CACHE_TURBO_TTL_MAX ((time_t) 0xFFFFFFFF)\n_Static_assert(NGX_HTTP_CACHE_TURBO_TTL_MAX > 0, "mutant survived");\n' \
        > "$TMP/mutant.c"
    # shellcheck disable=SC2086
    if "$CC" $FLAGS -fsyntax-only "$TMP/mutant.c" >/dev/null 2>&1; then
        echo "TTL width: old UINT32_MAX cast mutant survived 32-bit time_t" >&2
        exit 1
    fi
    echo "TTL width: production definition is positive; 32-bit cast mutant rejected"
else
    echo "TTL width: production definition matches 64-bit time_t ceiling"
fi
