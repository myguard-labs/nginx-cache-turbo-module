#!/usr/bin/env bash
# Exercise the extractor's real owner check with a body larger than a pipe.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
extractor="${EXTRACTOR:-$DIR/extract_shm.sh}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
awk '/^# PERF-AUD2-10: store_locked\(\) is in this slice/{copy=1} /^if \[ "\$\(tail -n1/{copy=0} copy' "$extractor" > "$tmp/check.sh"
[ -s "$tmp/check.sh" ]
python3 - "$tmp/source.c" <<'PY'
import sys
owners = ('store_locked', 'claim_locked', 'count_miss_locked', 'l2_neg_set')
with open(sys.argv[1], 'w') as out:
    for owner in owners:
        out.write(f'ngx_http_cache_turbo_shm_{owner}(\n')
        out.write('test_hash_crc32_mismatch\n')
        out.write('padding\n' * 20000)
        out.write('}\n')
PY
run_check() {
    SRC="$tmp/source.c" OUT="$tmp/out" bash -euo pipefail "$tmp/check.sh"
}
run_check >"$tmp/log" 2>&1 || { cat "$tmp/log" >&2; exit 1; }
sed -i '/test_hash_crc32_mismatch/d' "$tmp/source.c"
if run_check >"$tmp/log" 2>&1; then
    echo 'missing hash diagnostic was accepted' >&2
    exit 1
fi
grep -qF 'ngx_http_cache_turbo_shm_store_locked lost its hash mismatch diagnostic' "$tmp/log"
echo 'hash diagnostic check handles large bodies and rejects missing diagnostics'
