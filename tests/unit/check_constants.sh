#!/usr/bin/env bash
#
# The unit-test shim (ngx_shim_math.h) re-defines the fixed-point constants the
# math units use, because it deliberately does NOT include the real module.h.
# If those drift from src/ngx_http_cache_turbo_module.h the tests would assert
# against stale numbers and pass while production changed. This guard extracts
# each constant's value from BOTH files and fails on any mismatch.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HDR="$DIR/../../src/ngx_http_cache_turbo_module.h"
SHIM="$DIR/ngx_shim_math.h"

CONSTS=(
    NGX_HTTP_CACHE_TURBO_STALE_MULTIPLIER
    NGX_HTTP_CACHE_TURBO_TTL_MAX
    NGX_HTTP_CACHE_TURBO_BETA_MIN
    NGX_HTTP_CACHE_TURBO_BETA_MAX
    NGX_HTTP_CACHE_TURBO_BETA_COST_DIVISOR
    NGX_HTTP_CACHE_TURBO_AT_COST_STRONG_MS
    NGX_HTTP_CACHE_TURBO_AT_COST_MOD_MS
    NGX_HTTP_CACHE_TURBO_AT_MISSES_FLOOR
    NGX_HTTP_CACHE_TURBO_AT_HIT_RATE_CAP
    NGX_HTTP_CACHE_TURBO_AT_CHURN_CAP
    NGX_HTTP_CACHE_TURBO_AT_LOAD_BASE
    NGX_HTTP_CACHE_TURBO_AT_LOAD_MAX
    NGX_HTTP_CACHE_TURBO_AT_LOAD_PER_MS
    NGX_HTTP_CACHE_TURBO_AT_INTERVAL
)

# Pull the value token(s) after `#define <NAME>`, strip trailing block comments
# and surrounding whitespace, and collapse internal spaces so `((time_t)
# 0xFFFFFFFF)` compares equal regardless of spacing.
value_of() {
    local file="$1" name="$2"
    grep -E "^#define[[:space:]]+${name}[[:space:]]" "$file" \
        | head -1 \
        | sed -E "s/^#define[[:space:]]+${name}[[:space:]]+//; s|/\*.*\*/||; s|/\*.*||; s/[[:space:]]+/ /g; s/^ //; s/ $//"
}

rc=0
for c in "${CONSTS[@]}"; do
    h="$(value_of "$HDR" "$c")"
    s="$(value_of "$SHIM" "$c")"
    if [ -z "$h" ]; then
        echo "✗ $c not found in module.h" >&2; rc=1; continue
    fi
    if [ -z "$s" ]; then
        echo "✗ $c not found in shim" >&2; rc=1; continue
    fi
    if [ "$h" != "$s" ]; then
        echo "✗ $c drift: module.h='$h' shim='$s'" >&2; rc=1
    fi
done

if [ "$rc" -ne 0 ]; then
    echo "unit-test shim constants drifted from module.h — update ngx_shim_math.h" >&2
    exit 1
fi
echo "✓ unit-test shim constants match module.h (${#CONSTS[@]} checked)"
