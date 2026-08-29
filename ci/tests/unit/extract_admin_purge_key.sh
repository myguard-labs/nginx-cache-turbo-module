#!/usr/bin/env bash
# Extract the real admin single-key purge helper so digest failure propagation
# is executable unit coverage, not a source-text assertion.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$DIR/../../../src/ngx_http_cache_turbo_admin.c"
OUT="$DIR/generated_admin_purge_key.inc"

awk '
    /^static ngx_int_t$/ { pending = 1; buf = $0 ORS; next }
    pending && /^ngx_http_cache_turbo_admin_purge_key\(/ {
        capture = 1; pending = 0; printf "%s", buf; print; next
    }
    pending { pending = 0; buf = "" }
    capture {
        print
        if ($0 == "}") { capture = 0; exit }
    }
' "$SRC" >"$OUT"

if ! grep -qF 'ngx_http_cache_turbo_admin_purge_key(' "$OUT"; then
	echo "✗ failed to extract admin purge-key helper from $SRC" >&2
	rm -f "$OUT"
	exit 1
fi

echo "✓ extracted admin purge-key helper → $(basename "$OUT")"
