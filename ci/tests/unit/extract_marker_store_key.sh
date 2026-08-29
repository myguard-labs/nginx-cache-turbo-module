#!/usr/bin/env bash
# Extract the real marker-store helper so an L1 write failure cannot be hidden
# by a successful-looking L2 write-through.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$DIR/../../../src/ngx_http_cache_turbo_vary.c"
OUT="$DIR/generated_marker_store_key.inc"

awk '
    /^ngx_int_t$/ { pending = 1; buf = $0 ORS; next }
    pending && /^ngx_http_cache_turbo_marker_store_key\(/ {
        capture = 1; pending = 0; printf "%s", buf; print; next
    }
    pending { pending = 0; buf = "" }
    capture {
        print
        if ($0 == "}") { capture = 0; exit }
    }
' "$SRC" >"$OUT"

if ! grep -qF 'ngx_http_cache_turbo_marker_store_key(' "$OUT"; then
	echo "✗ failed to extract marker-store helper from $SRC" >&2
	rm -f "$OUT"
	exit 1
fi

echo "✓ extracted marker-store helper → $(basename "$OUT")"
