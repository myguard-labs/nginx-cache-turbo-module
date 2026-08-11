#!/usr/bin/env bash
#
# Slice the verbatim bodies of the three RESP reply parsers out of the shipped
# ../src/ngx_http_cache_turbo_redis.c into generated_parser.inc:
#
#   ngx_http_cache_turbo_redis_parse()        - bulk-string GET reply
#   ngx_http_cache_turbo_redis_parse_array()  - SMEMBERS array reply
#   ngx_http_cache_turbo_redis_parse_scan()   - SCAN [cursor, keys] 2-tuple
#
#   ngx_http_cache_turbo_redis_frame()        - STAB-3 pre-framer (recursive)
#
# plus the MAX_MEMBERS #define that sits among them (FRAME_MAX_DEPTH comes from
# ngx_shim.h instead — see the awk rule below). They are captured in source order. _frame() is directly recursive, so the .inc emits a
# forward declaration for it ahead of the bodies; the other three call nothing
# but _resp_len(), which precedes them in source order.
#
# This keeps the fuzz target locked to production code: there is no hand-copied
# parser. If a signature or body changes upstream, the next fuzz build picks it
# up automatically. If a function can no longer be found, we fail loudly rather
# than silently fuzz nothing.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$FUZZ_DIR/../../src/ngx_http_cache_turbo_redis.c"
SHIM="$FUZZ_DIR/ngx_shim.h"
OUT="$FUZZ_DIR/generated_parser.inc"

if [ ! -f "$SRC" ]; then
    echo "✗ cannot find $SRC" >&2
    exit 1
fi

# --- guard: the size constants the shim hard-codes must still match the source.
# The parsers compare against these; a drift would make the fuzzer exercise a
# different control flow than production. Fail the build if they diverge.
check_define() {
    name="$1"
    got=$(grep -E "^#define[[:space:]]+${name}[[:space:]]" "$SRC" \
          | head -n1 | sed -E "s/^#define[[:space:]]+${name}[[:space:]]+//; s/[[:space:]]*$//")
    shim=$(grep -E "^#define[[:space:]]+${name}[[:space:]]" "$SHIM" \
          | head -n1 | sed -E "s/^#define[[:space:]]+${name}[[:space:]]+//; s/[[:space:]]*$//")
    if [ -z "$got" ]; then
        echo "✗ $name not found in $SRC (renamed? update extract_parser.sh)" >&2
        exit 1
    fi
    if [ "$got" != "$shim" ]; then
        echo "✗ $name drifted: source='$got' shim='$shim'" >&2
        echo "  update ci/fuzz/ngx_shim.h to match src/ngx_http_cache_turbo_redis.c" >&2
        exit 1
    fi
}
check_define NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY
check_define NGX_HTTP_CACHE_TURBO_REDIS_MAX_MEMBERS
check_define NGX_HTTP_CACHE_TURBO_REDIS_FRAME_MAX_DEPTH

# --- slice the four parser bodies + the MAX_MEMBERS / FRAME_MAX_DEPTH defines,
# in source order. Each opens with a bare `static ngx_int_t` line immediately
# followed by its definition line, and closes with a bare `}` in column 0 (nginx
# style). The interleaved read handlers are `static void`, so matching on
# `static ngx_int_t` + the name regex picks out exactly the four we want (and not
# _fill / _launch, which are ngx_int_t but differently named).
#
# _frame() is directly recursive: its body calls itself before the definition is
# complete, so the slice needs a prototype up front. Emitted here rather than in
# ngx_shim.h so it stays adjacent to the extraction that requires it.
cat > "$OUT" <<'PROTO'
/* forward declaration — ngx_http_cache_turbo_redis_frame() is recursive */
static ngx_int_t ngx_http_cache_turbo_redis_frame(u_char *p, u_char *end,
    ngx_uint_t depth, u_char **next);

PROTO

awk '
    /^#define[[:space:]]+NGX_HTTP_CACHE_TURBO_REDIS_MAX_MEMBERS[[:space:]]/ {
        print; next
    }
    # FRAME_MAX_DEPTH is deliberately NOT copied: ngx_shim.h defines it, and
    # check_define above already fails the build if the two ever drift. Copying
    # it here as well would be a macro redefinition under -Werror.
    /^#define[[:space:]]+NGX_HTTP_CACHE_TURBO_REDIS_FRAME_MAX_DEPTH[[:space:]]/ {
        next
    }
    /^static ngx_int_t$/ { pending = 1; buf = $0 ORS; next }
    pending && /^ngx_http_cache_turbo_redis_(parse(_array|_scan)?|resp_len|frame)\(/ {
        capture = 1; pending = 0; printf "%s", buf; print; next
    }
    pending { pending = 0; buf = "" }
    capture {
        print
        if ($0 == "}") { capture = 0 }
    }
' "$SRC" >> "$OUT"

# --- sanity: all three must be present and the file must end on a closing brace.
for fn in \
    'ngx_http_cache_turbo_redis_resp_len(' \
    'ngx_http_cache_turbo_redis_parse(' \
    'ngx_http_cache_turbo_redis_parse_array(' \
    'ngx_http_cache_turbo_redis_parse_scan(' \
    'ngx_http_cache_turbo_redis_frame('
do
    # Anchored at column 0: this matches the DEFINITION line only. A bare -F
    # match would also hit the forward declaration this script emits for
    # _frame(), turning a failed body slice into a silent pass.
    if ! grep -qE "^${fn//(/\\(}" "$OUT"; then
        echo "✗ failed to extract $fn from $SRC" >&2
        echo "  (source layout changed? update extract_parser.sh)" >&2
        rm -f "$OUT"
        exit 1
    fi
done
if [ "$(tail -n1 "$OUT")" != "}" ]; then
    echo "✗ generated_parser.inc does not end on a closing brace (bad slice)" >&2
    rm -f "$OUT"
    exit 1
fi

LINES=$(wc -l < "$OUT")
echo "✓ extracted redis_parse() + _parse_array() + _parse_scan() + _frame() — $LINES lines -> $OUT"
