#!/usr/bin/env bash
#
# Slice the verbatim bodies of the query-string normaliser out of the
# shipped ../src/ngx_http_cache_turbo_module.c into
# generated_norm_args.inc:
#
#   ngx_http_cache_turbo_tok_cmp()                 - the sort comparator
#   ngx_http_cache_turbo_normalized_args_variable() - $cache_turbo_normalized_args:
#       splits the attacker-controlled query string on '&'/'=', drops denied
#       params, sorts, then builds a '?'-prefixed buffer sized by a computed
#       `total`. The size-vs-write consistency + the '&'/'=' pointer walk are
#       an OOB-WRITE / OOB-READ surface on fully attacker-controlled bytes.
#
# Captured in source order (tok_cmp precedes the variable handler that uses
# it as the ngx_sort comparator). The other helpers it calls
# (vary_suffix / var_set / name_denied) are NOT sliced — the harness stubs
# them, because the write bound is computed from the same kept-token set it
# writes, so it is independent of which tokens name_denied removes.
#
# No hand-maintained copy: if a signature or body changes upstream, the
# next build picks it up; if a function vanishes, we fail loudly.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$FUZZ_DIR/../../src/ngx_http_cache_turbo_module.c"
OUT="$FUZZ_DIR/generated_norm_args.inc"

if [ ! -f "$SRC" ]; then
    echo "✗ cannot find $SRC" >&2
    exit 1
fi

# tok_cmp opens `static ngx_int_t` + its name line; normalized_args_variable
# likewise. Both close on a bare `}` in column 1 (nginx style). Match on the
# definition line that follows the return-type line.
awk '
    /^static ngx_int_t$/ { pending = 1; buf = $0 ORS; next }
    pending && /^ngx_http_cache_turbo_(tok_cmp|normalized_args_variable)\(/ {
        capture = 1; pending = 0; printf "%s", buf; print; next
    }
    pending { pending = 0; buf = "" }
    capture {
        print
        if ($0 == "}") { capture = 0 }
    }
' "$SRC" > "$OUT"

if ! grep -q 'ngx_http_cache_turbo_tok_cmp' "$OUT" \
   || ! grep -q 'ngx_http_cache_turbo_normalized_args_variable' "$OUT" \
   || [ "$(tail -n1 "$OUT")" != "}" ]; then
    echo "✗ failed to extract the normaliser from $SRC" >&2
    echo "  (source layout changed? update extract_norm_args.sh)" >&2
    rm -f "$OUT"
    exit 1
fi

LINES=$(wc -l < "$OUT")
echo "✓ extracted tok_cmp() + normalized_args_variable() — $LINES lines -> $OUT"
