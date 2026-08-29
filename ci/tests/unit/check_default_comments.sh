#!/usr/bin/env bash
set -euo pipefail
root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
grep -q 'cache_turbo_scan_resistant.*on by' "$root/src/ngx_http_cache_turbo_module.h"
grep -q 'off (an explicit opt-out)' "$root/src/ngx_http_cache_turbo_module.h"
grep -q 'merges to on (1) by default' "$root/src/ngx_http_cache_turbo_module.h"
grep -q 'shipped defaults are threshold 5 and window 10s' "$root/src/ngx_http_cache_turbo_module.h"
grep -q 'breaker_count_retries in the .h for why this remains opt-in' "$root/src/ngx_http_cache_turbo_module.c"
echo 'OK: default comments match merge-time contracts'
