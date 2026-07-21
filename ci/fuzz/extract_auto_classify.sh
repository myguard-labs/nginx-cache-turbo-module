#!/usr/bin/env bash
#
# Slice the verbatim auto-classify block (preset registry + cookie_has +
# auto_skip) out of ../src/ngx_http_cache_turbo_module.c into
# generated_auto_classify.inc, delimited by the FUZZ-EXTRACT markers in the
# source. This keeps the fuzz target locked to production code — no hand copy.
# If the markers move or vanish, fail loudly rather than fuzz nothing.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$FUZZ_DIR/../../src/ngx_http_cache_turbo_module.c"
OUT="$FUZZ_DIR/generated_auto_classify.inc"

if [ ! -f "$SRC" ]; then
    echo "✗ cannot find $SRC" >&2
    exit 1
fi

awk '
    /FUZZ-EXTRACT auto-classify BEGIN/ { cap = 1; next }
    /FUZZ-EXTRACT auto-classify END/   { cap = 0 }
    cap { print }
' "$SRC" > "$OUT"

if ! grep -qF 'ngx_http_cache_turbo_auto_skip(' "$OUT"; then
    echo "✗ failed to extract auto_skip from $SRC (markers moved?)" >&2
    rm -f "$OUT"
    exit 1
fi
if ! grep -qF 'ngx_http_cache_turbo_cookie_has(' "$OUT"; then
    echo "✗ failed to extract cookie_has from $SRC (markers moved?)" >&2
    rm -f "$OUT"
    exit 1
fi

LINES=$(wc -l < "$OUT")
echo "✓ extracted auto-classify block — $LINES lines -> $OUT"
