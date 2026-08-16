#!/usr/bin/env bash
#
# Slice the verbatim auto-classify block (preset registry + bounded Cookie
# helpers + auto_skip) out of ../src/ngx_http_cache_turbo_module.c into
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

required_helpers=(
    ngx_http_cache_turbo_cookie_byteset_build
    ngx_http_cache_turbo_cookie_contains
    ngx_http_cache_turbo_cookie_has
    ngx_http_cache_turbo_auto_skip
)
for helper in "${required_helpers[@]}"; do
    if ! grep -qF "$helper(" "$OUT"; then
        echo "✗ failed to extract $helper from $SRC (markers moved?)" >&2
        rm -f "$OUT"
        exit 1
    fi
done

LINES=$(wc -l < "$OUT")
echo "✓ extracted auto-classify block — $LINES lines -> $OUT"
