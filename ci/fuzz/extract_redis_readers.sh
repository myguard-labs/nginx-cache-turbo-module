#!/usr/bin/env bash
#
# Slice the verbatim bodies of the two Redis reply readers that parse straight
# out of the op's fixed recv[] scratch (not through op->rbuf) from the shipped
# ../src/ngx_http_cache_turbo_redis.c into generated_redis_readers.inc:
#
#   ngx_http_cache_turbo_redis_read_preamble() - AUTH/SELECT one-line replies
#   ngx_http_cache_turbo_redis_read_lock()     - SET NX PX lock reply
#
# Both are event handlers (`static void`, an ngx_event_t argument). The fuzz
# target compiles them against ngx_shim_redis_readers.h, whose connection
# recv() hands the reply over in the chunks the fuzzer chose, so the handlers'
# own accumulate-and-rescan loop is what gets fuzzed. read_lock() calls
# ngx_http_cache_turbo_redis_frame(), which extract_parser.sh slices into
# generated_parser.inc; include that file first.
#
# Called by extract_parser.sh (the registry slicer for fuzz_resp_parser), so
# every build of that target regenerates both files. Fails closed: a renamed or
# reshaped reader, or a recv[] scratch size that no longer matches the shim,
# stops the build naming what is missing rather than fuzzing nothing.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${FUZZ_REDIS_READERS_SRC:-$FUZZ_DIR/../../src/ngx_http_cache_turbo_redis.c}"
SHIM="$FUZZ_DIR/ngx_shim.h"
OUT="${FUZZ_REDIS_READERS_OUT:-$FUZZ_DIR/generated_redis_readers.inc}"

if [ ! -f "$SRC" ]; then
    echo "✗ cannot find $SRC" >&2
    exit 1
fi

# --- guard: the recv[] scratch size. Both readers bound their accumulation by
# sizeof(op->recv); a drift would fuzz a different cap than production.
recv_decl() {
    grep -E '^[[:space:]]+u_char[[:space:]]+recv\[[0-9]+\];' "$1" \
        | head -n1 | sed -E 's/.*recv\[([0-9]+)\].*/\1/'
}
got=$(recv_decl "$SRC")
shim=$(recv_decl "$SHIM")
if [ -z "$got" ]; then
    echo "✗ op->recv[] scratch not found in $SRC (update extract_redis_readers.sh)" >&2
    exit 1
fi
if [ "$got" != "$shim" ]; then
    echo "✗ op->recv[] drifted: source=$got shim=$shim" >&2
    echo "  update ci/fuzz/ngx_shim.h to match src/ngx_http_cache_turbo_redis.c" >&2
    exit 1
fi

# --- slice: a bare `static void` line, then the definition line, then the body
# up to the first column-0 `}` (nginx style). The forward declarations at the
# top of the source are one-liners (`static void name(...);`) and never match
# the bare `static void` line.
awk '
    /^static void$/ { pending = 1; buf = $0 ORS; next }
    pending && /^ngx_http_cache_turbo_redis_read_(preamble|lock)\(/ {
        capture = 1; pending = 0; printf "%s", buf; print; next
    }
    pending { pending = 0; buf = "" }
    capture {
        print
        if ($0 == "}") { capture = 0 }
    }
' "$SRC" > "$OUT"

for fn in \
    'ngx_http_cache_turbo_redis_read_preamble(' \
    'ngx_http_cache_turbo_redis_read_lock('
do
    if ! grep -qE "^${fn//(/\\(}" "$OUT"; then
        echo "✗ failed to extract $fn from $SRC" >&2
        echo "  (source layout changed? update extract_redis_readers.sh)" >&2
        rm -f "$OUT"
        exit 1
    fi
done
if [ "$(tail -n1 "$OUT")" != "}" ]; then
    echo "✗ generated_redis_readers.inc does not end on a closing brace (bad slice)" >&2
    rm -f "$OUT"
    exit 1
fi

LINES=$(wc -l < "$OUT")
echo "✓ extracted redis read_preamble() + read_lock() — $LINES lines -> $OUT"
