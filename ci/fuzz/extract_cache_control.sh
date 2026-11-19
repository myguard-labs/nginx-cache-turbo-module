#!/usr/bin/env bash
#
# Slice the verbatim bodies of the origin Cache-Control / Surrogate-Control
# parser out of the shipped ../../src/ngx_http_cache_turbo_module.c into
# generated_cache_control.inc, in source order:
#
#   ngx_http_cache_turbo_cc_token()       - quoted-string aware directive scan
#   ngx_http_cache_turbo_cc_has()         - directive presence
#   ngx_http_cache_turbo_cc_parse_delta() - delta-seconds, saturating
#   ngx_http_cache_turbo_cc_delta()       - "<name>=N" lookup
#   ngx_http_cache_turbo_cc_delta_all()   - every field-line walk
#
# Every function is `static <type>` on one line, the name on the next, and
# closes on a bare `}` in column 1 (nginx style). No hand-maintained copy: if a
# signature or body changes upstream the next build picks it up; if a function
# vanishes, or the slice is not exactly one definition each, we fail loudly.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$FUZZ_DIR/../../src/ngx_http_cache_turbo_module.c"
OUT="$FUZZ_DIR/generated_cache_control.inc"
# shellcheck source=ci/fuzz/atomic_out.sh
. "$FUZZ_DIR/atomic_out.sh"
FUNCS="cc_token cc_has cc_parse_delta cc_delta cc_delta_all"

if [ ! -f "$SRC" ]; then
    echo "✗ cannot find $SRC" >&2
    exit 1
fi

fail() {
    echo "✗ failed to extract the Cache-Control parser from $SRC" >&2
    echo "  ($1; source layout changed? update extract_cache_control.sh)" >&2
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
echo "✓ extracted cc_token/has/parse_delta/delta/delta_all — $LINES lines -> $OUT"
