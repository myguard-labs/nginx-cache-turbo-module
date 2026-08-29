#!/usr/bin/env bash
# Extract the real L2 marker-resolution helper so marker self-heal failure is
# executable policy coverage rather than a source-text assertion.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$DIR/../../../src/ngx_http_cache_turbo_access.c"
OUT="$DIR/generated_access_marker_resolve.inc"

awk '
    /^static ngx_int_t$/ { pending = 1; buf = $0 ORS; next }
    pending && /^ngx_http_cache_turbo_access_l2_marker_resolve\(/ {
        capture = 1; pending = 0; printf "%s", buf; print; next
    }
    pending { pending = 0; buf = "" }
    capture {
        print
        if ($0 == "}") { capture = 0; exit }
    }
' "$SRC" >"$OUT"

if ! grep -qF 'ngx_http_cache_turbo_access_l2_marker_resolve(' "$OUT"; then
	echo "✗ failed to extract L2 marker-resolution helper from $SRC" >&2
	rm -f "$OUT"
	exit 1
fi

echo "✓ extracted L2 marker-resolution helper → $(basename "$OUT")"
