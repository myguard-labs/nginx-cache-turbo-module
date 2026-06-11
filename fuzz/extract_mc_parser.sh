#!/usr/bin/env bash
#
# Slice the verbatim body of the memcached GET reply parser out of the shipped
# ../src/ngx_http_cache_turbo_memcached.c into generated_mc_parser.inc:
#
#   ngx_http_cache_turbo_mc_parse()  - VALUE <key> <flags> <bytes> ... reply
#
# This keeps the fuzz target locked to production code: there is no hand-copied
# parser. If the signature or body changes upstream, the next fuzz build picks
# it up automatically. If the function can no longer be found, we fail loudly
# rather than silently fuzz nothing.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$FUZZ_DIR/../src/ngx_http_cache_turbo_memcached.c"
SHIM="$FUZZ_DIR/ngx_shim_mc.h"
OUT="$FUZZ_DIR/generated_mc_parser.inc"

if [ ! -f "$SRC" ]; then
    echo "✗ cannot find $SRC" >&2
    exit 1
fi

# --- guard: the 1 MiB value ceiling the parser enforces must still match the
# shim. A drift would make the fuzzer exercise a different control flow than
# production. Fail the build if they diverge.
name=NGX_HTTP_CACHE_TURBO_MC_MAX_VALUE
got=$(grep -E "^#define[[:space:]]+$name[[:space:]]" "$SRC" \
      | head -n1 | sed -E "s/^#define[[:space:]]+$name[[:space:]]+//; s/[[:space:]]*$//")
shim=$(grep -E "^#define[[:space:]]+$name[[:space:]]" "$SHIM" \
      | head -n1 | sed -E "s/^#define[[:space:]]+$name[[:space:]]+//; s/[[:space:]]*$//")
if [ -z "$got" ]; then
    echo "✗ $name not found in $SRC (renamed? update extract_mc_parser.sh)" >&2
    exit 1
fi
if [ "$got" != "$shim" ]; then
    echo "✗ $name drifted: source='$got' shim='$shim'" >&2
    echo "  update fuzz/ngx_shim_mc.h to match the source" >&2
    exit 1
fi

# --- slice the single parser body. It opens with a bare `static ngx_int_t` line
# immediately followed by its `ngx_http_cache_turbo_mc_parse(` definition line,
# and closes with a bare `}` in column 0 (nginx style).
awk '
    /^static ngx_int_t$/ { pending = 1; buf = $0 ORS; next }
    pending && /^ngx_http_cache_turbo_mc_parse\(/ {
        capture = 1; pending = 0; printf "%s", buf; print; next
    }
    pending { pending = 0; buf = "" }
    capture {
        print
        if ($0 == "}") { capture = 0 }
    }
' "$SRC" > "$OUT"

if ! grep -qF 'ngx_http_cache_turbo_mc_parse(' "$OUT"; then
    echo "✗ failed to extract ngx_http_cache_turbo_mc_parse from $SRC" >&2
    echo "  (source layout changed? update extract_mc_parser.sh)" >&2
    rm -f "$OUT"
    exit 1
fi
if [ "$(tail -n1 "$OUT")" != "}" ]; then
    echo "✗ generated_mc_parser.inc does not end on a closing brace (bad slice)" >&2
    rm -f "$OUT"
    exit 1
fi

LINES=$(wc -l < "$OUT")
echo "✓ extracted mc_parse() — $LINES lines -> $OUT"
