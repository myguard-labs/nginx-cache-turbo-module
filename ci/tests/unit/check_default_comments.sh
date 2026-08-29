#!/usr/bin/env bash
set -euo pipefail
root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
python3 - "$root" <<'PY'
import re, sys
root = sys.argv[1]
conf = open(root + '/src/ngx_http_cache_turbo_conf.c').read()
header = open(root + '/src/ngx_http_cache_turbo_module.h').read()
module = open(root + '/src/ngx_http_cache_turbo_module.c').read()
contracts = {
    'scan_resistant_pct': r'conf->scan_resistant_pct = NGX_HTTP_CACHE_TURBO_PROTECTED_PCT_DEFAULT',
    'vary_marker_revalidate': r'ngx_conf_merge_sec_value\(conf->vary_marker_revalidate,\s*prev->vary_marker_revalidate, 2\)',
}
for name, pattern in contracts.items():
    if not re.search(pattern, conf):
        raise SystemExit(f'merge default missing for {name}')
if not re.search(r'#define NGX_HTTP_CACHE_TURBO_PROTECTED_PCT_DEFAULT\s+80\b', header):
    raise SystemExit('protected percentage constant drifted from documented 80')
comments = {
    'scan_resistant_pct': r'on by\s+default.*default 80',
    'vary_marker_revalidate': r'Shipped ON by default at 2s',
}
for name, pattern in comments.items():
    if not re.search(pattern, header + conf, re.S):
        raise SystemExit(f'default comment missing for {name}')

# Keep the breaker field comments mechanically tied to the values used by the
# real merge calls.  Searching header+conf for generic prose allowed all three
# comments to disappear from the declarations while conf.c satisfied its own
# documentation gate.
breaker_merges = {
    'breaker_enable':
        r'ngx_conf_merge_value\(conf->breaker_enable, prev->breaker_enable, (\d+)\)',
    'breaker_threshold':
        r'ngx_conf_merge_uint_value\(conf->breaker_threshold,\s*prev->breaker_threshold, (\d+)\)',
    'breaker_window':
        r'ngx_conf_merge_sec_value\(conf->breaker_window, prev->breaker_window, (\d+)\)',
}
defaults = {}
for name, pattern in breaker_merges.items():
    match = re.search(pattern, conf)
    if not match:
        raise SystemExit(f'merge default missing for {name}')
    defaults[name] = match.group(1)

if defaults != {
    'breaker_enable': '1',
    'breaker_threshold': '5',
    'breaker_window': '10',
}:
    raise SystemExit(f'approved breaker defaults drifted: {defaults}')

field_comments = {
    'breaker_enable':
        rf'breaker_enable;\s*/\*\s*merge default {defaults["breaker_enable"]} \(on\)',
    'breaker_threshold':
        rf'breaker_threshold;\s*/\*\s*merge default {defaults["breaker_threshold"]}; 0 = off',
    'breaker_window':
        rf'breaker_window;\s*/\*\s*merge default {defaults["breaker_window"]}s; 0 = off',
}
for name, pattern in field_comments.items():
    if not re.search(pattern, header):
        raise SystemExit(f'field comment does not match conf.c merge for {name}')
if not re.search(r'keep_stale = NGX_CONF_UNSET;\s*/\* S2\.1; merges to 24h \*/', module):
    raise SystemExit('module lifecycle comment does not match keep_stale merge default')
if not re.search(r'breaker_enable = NGX_CONF_UNSET;\s*/\* O4\.4; merges to 1 = on \*/', module):
    raise SystemExit('module lifecycle comment does not match breaker_enable merge default')
if not re.search(r'breaker_threshold = NGX_CONF_UNSET_UINT;\s*/\* O4\.2; merges to 5 \*/', module):
    raise SystemExit('module lifecycle comment does not match breaker_threshold merge default')
if not re.search(r'breaker_window = NGX_CONF_UNSET;\s*/\* O4\.2; merges to 10s \*/', module):
    raise SystemExit('module lifecycle comment does not match breaker_window merge default')
print('OK: default comments match extracted merge-time contracts')
PY
