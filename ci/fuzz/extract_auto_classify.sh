#!/usr/bin/env bash
#
# Slice the verbatim auto-classify block (preset registry + bounded Cookie
# helpers + auto_skip) into generated_auto_classify.inc, delimited by the
# FUZZ-EXTRACT markers in the source. This keeps the fuzz target locked to
# production code — no hand copy. If the markers move or vanish, fail loudly
# rather than fuzz nothing.
#
# MAINT-SPLIT: the block is now spread over TWO non-module.c TUs, each with its
# own FUZZ-EXTRACT BEGIN/END pair:
#
#   ../../src/ngx_http_cache_turbo_presets.c  preset registry data
#                                             (ngx_http_cache_turbo_preset_t
#                                             and the ct_* tables)
#   ../../src/ngx_http_cache_turbo_match.c    the cookie/query-arg/URI matching
#                                             group that consumes it
#                                             (cookie_byteset_build, cookie_has,
#                                             the qs/argparse decoders, auto_skip)
#
# module.c no longer carries a marker pair at all. Both slices are concatenated
# in source order (presets.c first, since ngx_http_cache_turbo_preset_t / the
# ct_* tables are referenced by the code that follows) so the .inc is
# byte-for-byte the same shape the fuzz target has always compiled — verified
# by md5 against the pre-split output.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$FUZZ_DIR/../../src/ngx_http_cache_turbo_match.c"
SRC_PRESETS="$FUZZ_DIR/../../src/ngx_http_cache_turbo_presets.c"
OUT="$FUZZ_DIR/generated_auto_classify.inc"

if [ ! -f "$SRC" ]; then
    echo "✗ cannot find $SRC" >&2
    exit 1
fi

if [ ! -f "$SRC_PRESETS" ]; then
    echo "✗ cannot find $SRC_PRESETS" >&2
    exit 1
fi

slice() {
    awk '
        /FUZZ-EXTRACT auto-classify BEGIN/ { cap = 1; next }
        /FUZZ-EXTRACT auto-classify END/   { cap = 0 }
        cap { print }
    ' "$1"
}

slice "$SRC_PRESETS" > "$OUT"
slice "$SRC" >> "$OUT"

if ! grep -qF 'ngx_http_cache_turbo_presets[]' "$OUT"; then
    echo "✗ failed to extract ngx_http_cache_turbo_presets[] from $SRC_PRESETS" \
         "(markers moved?)" >&2
    rm -f "$OUT"
    exit 1
fi

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
