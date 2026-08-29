#!/usr/bin/env bash
set -euo pipefail

root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
python3 - "$root" <<'PY'
import re, sys
root = sys.argv[1]
source = open(root + '/src/ngx_http_cache_turbo_module.c').read()
readme = open(root + '/README.md').read()
registered = list(dict.fromkeys(re.findall(r'ngx_string\("(cache_turbo(?:_[^"]+)?)"\)', source)))
internal = {'cache_turbo_probe', 'cache_turbo_normalized_args', 'cache_turbo_active',
            'cache_turbo_status', 'cache_turbo_serve_reason'}
registered = [n for n in registered if not n.startswith('cache_turbo_test_') and n not in internal]
section = readme.split('## Directive synopsis', 1)[1].split('\n## ', 1)[0]
reference = readme.split('## Every directive in one place (full syntax)', 1)[1]
reference = reference.split('```nginx', 1)[1].split('```', 1)[0]
rows = {}
def split_unescaped_pipes(line):
    cells, start, escaped = [], 0, False
    for i, char in enumerate(line):
        if char == '|' and not escaped:
            cells.append(line[start:i])
            start = i + 1
        escaped = (char == '\\' and not escaped)
        if char != '\\':
            escaped = False
    cells.append(line[start:])
    return cells

for line in section.splitlines():
    if not line.startswith('| `'):
        continue
    cells = [cell.strip() for cell in split_unescaped_pipes(line)]
    name = cells[1].strip('`').split()[0]
    rows[name] = cells
missing = [n for n in registered if not any(name == n or name.startswith(n + ' ') for name in rows)]
if missing:
    raise SystemExit('directive synopsis missing: ' + ', '.join(missing))
for n in registered:
    cells = next(c for name, c in rows.items() if name == n or name.startswith(n + ' '))
    if len(cells) < 5 or not cells[3]:
        raise SystemExit('directive synopsis row has empty Default cell: ' + n)
missing_reference = [n for n in registered
                     if not re.search(r'^\s*#?\s*' + re.escape(n) + r'(?:\s|$)',
                                     reference, re.M)]
if missing_reference:
    raise SystemExit('full-reference config missing: ' + ', '.join(missing_reference))
if not re.search(r'^\s*cache_turbo_keep_stale\s+24h\s*;', reference, re.M):
    raise SystemExit('full-reference default drift: cache_turbo_keep_stale must be 24h')
print(f'OK: {len(registered)} registered production directives have synopsis rows and defaults')
PY
