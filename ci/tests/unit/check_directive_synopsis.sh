#!/usr/bin/env bash
set -euo pipefail

root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
python3 - "$root" <<'PY'
import re, sys
root = sys.argv[1]
source = open(root + '/src/ngx_http_cache_turbo_module.c').read()
readme = open(root + '/README.md').read()
registered = list(dict.fromkeys(re.findall(r'ngx_string\("(cache_turbo_[^"]+)"\)', source)))
internal = {'cache_turbo_probe', 'cache_turbo_normalized_args', 'cache_turbo_active',
            'cache_turbo_status', 'cache_turbo_serve_reason'}
registered = [n for n in registered if not n.startswith('cache_turbo_test_') and n not in internal]
section = readme.split('## Directive synopsis', 1)[1].split('\n## ', 1)[0]
missing = [n for n in registered if not re.search(r'\|\s*`' + re.escape(n) + r'(?:\s|`)', section)]
if missing:
    raise SystemExit('directive synopsis missing: ' + ', '.join(missing))
for line in section.splitlines():
    if line.startswith('| `cache_turbo_') and len(line.split('|')) < 5:
        raise SystemExit('directive synopsis row has no default: ' + line)
print(f'OK: {len(registered)} registered production directives have synopsis rows and defaults')
PY
