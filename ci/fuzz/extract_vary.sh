#!/usr/bin/env bash
#
# Slice the verbatim bodies of the origin Vary classifier out of the shipped
# ../../src/ngx_http_cache_turbo_vary.c into generated_vary.inc, in source order:
#
#   ngx_http_cache_turbo_classify_vary_next_token()     - comma/ws tokeniser
#   ngx_http_cache_turbo_classify_vary_classify_token() - per-axis verdict
#   ngx_http_cache_turbo_vary_ignore_match()            - vary_ignore lookup
#
# Every function is `static <type>` on one line, the name on the next, and
# closes on a bare `}` in column 1 (nginx style). No hand-maintained copy: if a
# signature or body changes upstream the next build picks it up; if a function
# vanishes, or the slice is not exactly one definition each, we fail loudly.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$FUZZ_DIR/../../src/ngx_http_cache_turbo_vary.c"
OUT="$FUZZ_DIR/generated_vary.inc"
FUNCS="classify_vary_next_token classify_vary_classify_token vary_ignore_match"

if [ ! -f "$SRC" ]; then
    echo "✗ cannot find $SRC" >&2
    exit 1
fi

fail() {
    echo "✗ failed to extract the Vary classifier from $SRC" >&2
    echo "  ($1; source layout changed? update extract_vary.sh)" >&2
    rm -f "$OUT"
    exit 1
}

: > "$OUT"
for f in $FUNCS; do
    awk -v want="ngx_http_cache_turbo_${f}(" '
        /^static / { pending = 1; buf = $0 ORS; next }
        pending && index($0, want) == 1 {
            capture = 1; pending = 0; printf "%s", buf; print; next
        }
        pending { pending = 0; buf = "" }
        capture {
            print
            if ($0 == "}") { capture = 0; print "" }
        }
    ' "$SRC" > "$OUT.part"
    n=$(grep -c "^ngx_http_cache_turbo_${f}(" "$OUT.part" || true)
    if [ "$n" -ne 1 ] || [ "$(tail -n2 "$OUT.part" | head -n1)" != "}" ]; then
        rm -f "$OUT.part"
        fail "ngx_http_cache_turbo_${f}: expected exactly one complete definition, got $n"
    fi
    cat "$OUT.part" >> "$OUT"
    rm -f "$OUT.part"
done

LINES=$(wc -l < "$OUT")
echo "✓ extracted classify_vary next_token/classify_token/vary_ignore_match — $LINES lines -> $OUT"
