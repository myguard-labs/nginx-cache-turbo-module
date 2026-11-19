#!/usr/bin/env bash
#
# Slice the verbatim control-input code out of the shipped sources into
# generated_control_inputs.inc, in this order:
#
#   ../../src/ngx_http_cache_turbo_module.h
#     NGX_HTTP_CACHE_TURBO_MAX_TAGS / _MAX_TAG_LEN / _WARM_MAX_CEILING defines
#   ../../src/ngx_http_cache_turbo_admin.c
#     NGX_HTTP_CACHE_TURBO_WARM_FILE_MAX_SIZE / _WARM_LINE_MAX_LEN defines
#   ../../src/ngx_http_cache_turbo_match.c
#     hexval()                      - helper of purge hexdecode
#   ../../src/ngx_http_cache_turbo_purge.c
#     hexdecode()                   - tag-purge member hex -> bytes
#   ../../src/ngx_http_cache_turbo_filters.c
#     body_filter_tag_split()       - origin Surrogate-Key/Cache-Tag tokeniser
#   ../../src/ngx_http_cache_turbo_admin.c
#     warm_uri_is_safe(), warm_raw_is_safe(), warm()  - warm list splitter
#     warm_file_finish()            - warm-file line-length gate
#
# Function definitions are `static <type>` (or bare `<type>` for the exported
# hexval) on one line, the name on the next, closing on a bare `}` in column 1
# (nginx style). No hand-maintained copy: if a function or define vanishes or is
# not exactly one definition, fail closed (exit nonzero, no .inc left behind).

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRCDIR="$FUZZ_DIR/../../src"
HDR="$SRCDIR/ngx_http_cache_turbo_module.h"
ADMIN="$SRCDIR/ngx_http_cache_turbo_admin.c"
MATCH="$SRCDIR/ngx_http_cache_turbo_match.c"
PURGE="$SRCDIR/ngx_http_cache_turbo_purge.c"
FILTERS="$SRCDIR/ngx_http_cache_turbo_filters.c"
OUT="$FUZZ_DIR/generated_control_inputs.inc"
# shellcheck source=ci/fuzz/atomic_out.sh
. "$FUZZ_DIR/atomic_out.sh"

for f in "$HDR" "$ADMIN" "$MATCH" "$PURGE" "$FILTERS"; do
    if [ ! -f "$f" ]; then
        echo "✗ cannot find $f" >&2
        rm -f "$OUT"
        exit 1
    fi
done

fail() {
    echo "✗ failed to extract the control-input code from $SRCDIR" >&2
    echo "  ($1; source layout changed? update extract_control_inputs.sh)" >&2
    rm -f "$OUT"
    exit 1
}

fuzz_atomic_begin
: > "$TMP_OUT"

# One single-line `#define NAME value` from a file, exactly once.
slice_define() {
    local file="$1" name="$2" n
    grep "^#define $name " "$file" > "$TMP_PART" || true
    n=$(wc -l < "$TMP_PART")
    if [ "$n" -ne 1 ]; then
        fail "$name: expected exactly one #define in $(basename "$file"), got $n"
    fi
    # A continued definition would splice the next line into this macro.
    if grep -q '\\$' "$TMP_PART"; then
        fail "$name: #define in $(basename "$file") is continued with a backslash"
    fi
    cat "$TMP_PART" >> "$TMP_OUT"
}

slice_define "$HDR" NGX_HTTP_CACHE_TURBO_MAX_TAGS
slice_define "$HDR" NGX_HTTP_CACHE_TURBO_MAX_TAG_LEN
slice_define "$HDR" NGX_HTTP_CACHE_TURBO_WARM_MAX_CEILING
slice_define "$ADMIN" NGX_HTTP_CACHE_TURBO_WARM_FILE_MAX_SIZE
slice_define "$ADMIN" NGX_HTTP_CACHE_TURBO_WARM_LINE_MAX_LEN
echo >> "$TMP_OUT"

# One function definition from a file, exactly once, complete.
slice_func() {
    local file="$1" name="$2" n
    awk -v want="ngx_http_cache_turbo_${name}(" '
        # A capture must close on a bare "}". A top-level declaration reached
        # first (e.g. the closing brace gained a trailing comment) would swallow
        # the next function: reject the slice.
        capture && ($0 ~ /^static / || $0 ~ /^[a-z_][a-z_0-9 ]*$/) { exit 3 }
        capture {
            print
            if ($0 == "}") { capture = 0; print "" }
            next
        }
        pending && index($0, want) == 1 {
            capture = 1; pending = 0; printf "%s", buf; print; next
        }
        /^(static )?[a-z_][a-z_0-9 ]*$/ { pending = 1; buf = $0 ORS; next }
        { pending = 0; buf = "" }
    ' "$file" > "$TMP_PART" || {
        fail "ngx_http_cache_turbo_${name}: slice reached the next top-level declaration before the closing brace"
    }
    n=$(grep -c "^ngx_http_cache_turbo_${name}(" "$TMP_PART" || true)
    if [ "$n" -ne 1 ] || [ "$(tail -n2 "$TMP_PART" | head -n1)" != "}" ]; then
        fail "ngx_http_cache_turbo_${name}: expected exactly one complete definition in $(basename "$file"), got $n"
    fi
    cat "$TMP_PART" >> "$TMP_OUT"
}

slice_func "$MATCH" hexval
slice_func "$PURGE" hexdecode
slice_func "$FILTERS" body_filter_tag_split
slice_func "$ADMIN" warm_uri_is_safe
slice_func "$ADMIN" warm_raw_is_safe
slice_func "$ADMIN" warm
slice_func "$ADMIN" warm_file_finish
rm -f "$TMP_PART"

LINES=$(wc -l < "$TMP_OUT")
fuzz_atomic_publish
echo "✓ extracted hexdecode/tag_split/warm-list code — $LINES lines -> $OUT"
