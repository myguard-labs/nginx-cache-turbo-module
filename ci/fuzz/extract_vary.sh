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
# shellcheck source=ci/fuzz/atomic_out.sh
. "$FUZZ_DIR/atomic_out.sh"
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

fuzz_atomic_begin
: > "$TMP_OUT"
for f in $FUNCS; do
    awk -v want="ngx_http_cache_turbo_${f}(" '
        # An open capture must close on a bare "}". A top-level declaration
        # reached first (e.g. the closing brace gained a trailing comment) means
        # the slice would swallow the next function: reject it.
        capture && ($0 ~ /^static / || $0 ~ /^[a-z_][a-z_0-9 ]*$/) { exit 3 }
        /^static / { pending = 1; buf = $0 ORS; next }
        pending && index($0, want) == 1 {
            capture = 1; pending = 0; printf "%s", buf; print; next
        }
        pending { pending = 0; buf = "" }
        capture {
            print
            if ($0 == "}") { capture = 0; print "" }
        }
    ' "$SRC" > "$TMP_PART" || {
        rm -f "$TMP_PART"
        fail "ngx_http_cache_turbo_${f}: slice reached the next top-level declaration before the closing brace"
    }
    n=$(grep -c "^ngx_http_cache_turbo_${f}(" "$TMP_PART" || true)
    if [ "$n" -ne 1 ] || [ "$(tail -n2 "$TMP_PART" | head -n1)" != "}" ]; then
        rm -f "$TMP_PART"
        fail "ngx_http_cache_turbo_${f}: expected exactly one complete definition, got $n"
    fi
    cat "$TMP_PART" >> "$TMP_OUT"
done

LINES=$(wc -l < "$TMP_OUT")
fuzz_atomic_publish
echo "✓ extracted classify_vary next_token/classify_token/vary_ignore_match — $LINES lines -> $OUT"
