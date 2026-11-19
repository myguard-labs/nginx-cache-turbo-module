#!/usr/bin/env bash
#
# Slice the verbatim Cookie-index / Cookie-AC / query-argparse code out of the
# shipped sources into generated_cookie_args.inc, in this order:
#
#   ../../src/ngx_http_cache_turbo_module.h  (type blocks, verbatim)
#     ngx_http_cache_turbo_cookie_ac_node_t / _cookie_ac_t
#     ngx_http_cache_turbo_cookie_pair_t / _cookie_index_t
#   ../../src/ngx_http_cache_turbo_match.c
#     NGX_HTTP_CACHE_TURBO_ARGS_MAX + argspan_t / argparse_t typedef block
#     cookie_index_add()          - helper of index_parse_one
#     cookie_index_parse_one()    - request Cookie header -> name/value index
#     cookie_ac_scan_one()        - Aho-Corasick scan of one Cookie value
#     hexval(), qs_first_mangled() - helpers of argparse_build
#     argparse_tail_count()       - exact remaining-span count
#     argparse_build()            - query string -> span array
#
# Function definitions are `static <type>` (or bare `<type>` for the exported
# hexval) on one line, the name on the next, closing on a bare `}` in column 1
# (nginx style). No hand-maintained copy: if a function, typedef or the
# ARGS_MAX define vanishes or is not exactly one definition, fail closed (exit
# nonzero, no .inc left behind).

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$FUZZ_DIR/../../src/ngx_http_cache_turbo_match.c"
HDR="$FUZZ_DIR/../../src/ngx_http_cache_turbo_module.h"
OUT="$FUZZ_DIR/generated_cookie_args.inc"
# shellcheck source=ci/fuzz/atomic_out.sh
. "$FUZZ_DIR/atomic_out.sh"
TYPES="cookie_ac_node_t cookie_ac_t cookie_pair_t cookie_index_t"
FUNCS="cookie_index_add cookie_index_parse_one cookie_ac_scan_one hexval qs_first_mangled argparse_tail_count argparse_build"

for f in "$SRC" "$HDR"; do
    if [ ! -f "$f" ]; then
        echo "✗ cannot find $f" >&2
        rm -f "$OUT"
        exit 1
    fi
done

fail() {
    echo "✗ failed to extract the Cookie/args code from $SRC" >&2
    echo "  ($1; source layout changed? update extract_cookie_args.sh)" >&2
    rm -f "$OUT"
    exit 1
}

fuzz_atomic_begin
: > "$TMP_OUT"

# Anonymous `typedef struct { ... } NAME;` blocks, each exactly once.
slice_typedef() {
    local file="$1" t="$2" n
    awk -v want="} ngx_http_cache_turbo_${t};" '
        /^typedef struct \{$/ { buf = $0 ORS; next }
        buf != "" {
            buf = buf $0 ORS
            if ($0 == want) { printf "%s\n", buf; buf = "" }
            else if ($0 ~ /^\} /) { buf = "" }
        }
    ' "$file" > "$TMP_PART"
    n=$(grep -c "^} ngx_http_cache_turbo_${t};" "$TMP_PART" || true)
    if [ "$n" -ne 1 ]; then
        fail "ngx_http_cache_turbo_${t}: expected exactly one typedef block in $(basename "$file"), got $n"
    fi
    cat "$TMP_PART" >> "$TMP_OUT"
}

# Type blocks from the module header.
for t in $TYPES; do
    slice_typedef "$HDR" "$t"
done

# ARGS_MAX define (one line, needed by argparse_t), then argspan_t before
# argparse_t, each validated on its own so a reordered source cannot drop one.
grep '^#define NGX_HTTP_CACHE_TURBO_ARGS_MAX ' "$SRC" > "$TMP_PART" || true
if [ "$(wc -l < "$TMP_PART")" -ne 1 ] || grep -q '\\$' "$TMP_PART"; then
    fail "ARGS_MAX define not found exactly once as a single line"
fi
{ cat "$TMP_PART"; echo; } >> "$TMP_OUT"
slice_typedef "$SRC" argspan_t
slice_typedef "$SRC" argparse_t

for f in $FUNCS; do
    awk -v want="ngx_http_cache_turbo_${f}(" '
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
    ' "$SRC" > "$TMP_PART" || {
        fail "ngx_http_cache_turbo_${f}: slice reached the next top-level declaration before the closing brace"
    }
    n=$(grep -c "^ngx_http_cache_turbo_${f}(" "$TMP_PART" || true)
    if [ "$n" -ne 1 ] || [ "$(tail -n2 "$TMP_PART" | head -n1)" != "}" ]; then
        fail "ngx_http_cache_turbo_${f}: expected exactly one complete definition, got $n"
    fi
    cat "$TMP_PART" >> "$TMP_OUT"
done
rm -f "$TMP_PART"

LINES=$(wc -l < "$TMP_OUT")
fuzz_atomic_publish
echo "✓ extracted cookie_index/cookie_ac/argparse code — $LINES lines -> $OUT"
