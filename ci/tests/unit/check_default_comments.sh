#!/usr/bin/env bash
set -euo pipefail
root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
python3 - "$root" <<'PY'
import re, sys
root = sys.argv[1]
conf = open(root + '/src/ngx_http_cache_turbo_conf.c').read()
header = open(root + '/src/ngx_http_cache_turbo_module.h').read()
contracts = {
    'scan_resistant_pct': r'conf->scan_resistant_pct = NGX_HTTP_CACHE_TURBO_PROTECTED_PCT_DEFAULT',
    'vary_marker_revalidate': r'ngx_conf_merge_sec_value\(conf->vary_marker_revalidate,\s*prev->vary_marker_revalidate, 2\)',
    'breaker_enable': r'ngx_conf_merge_value\(conf->breaker_enable, prev->breaker_enable, 1\)',
    'breaker_threshold': r'ngx_conf_merge_uint_value\(conf->breaker_threshold,\s*prev->breaker_threshold, 5\)',
    'breaker_window': r'ngx_conf_merge_sec_value\(conf->breaker_window, prev->breaker_window, 10\)',
}
for name, pattern in contracts.items():
    if not re.search(pattern, conf):
        raise SystemExit(f'merge default missing for {name}')
if not re.search(r'#define NGX_HTTP_CACHE_TURBO_PROTECTED_PCT_DEFAULT\s+80\b', header):
    raise SystemExit('protected percentage constant drifted from documented 80')
comments = {
    'scan_resistant_pct': r'on by\s+default.*default 80',
    'vary_marker_revalidate': r'Shipped ON by default at 2s',
    'breaker_enable': r'Shipped ON by default',
    'breaker_threshold': r'5 failures within a 10s window',
    'breaker_window': r'5 failures within a 10s window',
}
for name, pattern in comments.items():
    if not re.search(pattern, header + conf, re.S):
        raise SystemExit(f'default comment missing for {name}')
print('OK: default comments match extracted merge-time contracts')
PY
