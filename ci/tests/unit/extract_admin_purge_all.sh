#!/usr/bin/env bash
# Extract the real admin whole-zone purge helper so the user-visible
# L1-incomplete response and L2 short-circuit are executable contracts.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$DIR/../../../src/ngx_http_cache_turbo_admin.c"
OUT="$DIR/generated_admin_purge_all.inc"

awk '
    /^static ngx_int_t$/ { pending = 1; buf = $0 ORS; next }
    pending && /^ngx_http_cache_turbo_admin_purge_all\(/ {
        capture = 1; pending = 0; printf "%s", buf; print; next
    }
    pending { pending = 0; buf = "" }
    capture {
        print
        if ($0 == "}") { capture = 0; exit }
    }
' "$SRC" > "$OUT"

if ! grep -qF 'ngx_http_cache_turbo_admin_purge_all(' "$OUT"; then
    echo "✗ failed to extract admin purge-all helper from $SRC" >&2
    rm -f "$OUT"
    exit 1
fi

echo "✓ extracted admin purge-all helper → $(basename "$OUT")"
