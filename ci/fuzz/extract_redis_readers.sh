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
if ! got=$(recv_decl "$SRC") || [ -z "$got" ]; then
    echo "✗ op->recv[] scratch not found in $SRC (update extract_redis_readers.sh)" >&2
    exit 1
fi
if ! shim=$(recv_decl "$SHIM") || [ -z "$shim" ]; then
    echo "✗ op->recv[] scratch not found in shim $SHIM (update ci/fuzz/ngx_shim.h)" >&2
    exit 1
fi
if [ "$got" != "$shim" ]; then
    echo "✗ op->recv[] drifted: source=$got shim=$shim" >&2
    echo "  update ci/fuzz/ngx_shim.h to match src/ngx_http_cache_turbo_redis.c" >&2
    exit 1
fi

fail() {
    echo "✗ failed to extract $1 from $SRC" >&2
    echo "  (source layout changed? update extract_redis_readers.sh)" >&2
    rm -f "$OUT" "$OUT.part"
    exit 1
}

# --- slice: a bare `static void` line, then the definition line, then the body
# up to the first column-0 `}` (nginx style). The forward declarations at the
# top of the source are one-liners (`static void name(...);`) and never match
# the bare `static void` line. Each reader is sliced and validated on its own:
# exactly one definition, closing on its own bare `}`, never running into
# another top-level declaration first.
: > "$OUT"
for fn in read_preamble read_lock; do
    name="ngx_http_cache_turbo_redis_${fn}("
    awk -v want="$name" '
        # An open capture must close on a bare "}"; reaching another top-level
        # declaration first (closing brace gained a trailing comment) is a bad slice.
        capture && ($0 ~ /^static / || $0 ~ /^[a-z_][a-z_0-9 ]*$/) { exit 3 }
        /^static void$/ { pending = 1; buf = $0 ORS; next }
        pending && index($0, want) == 1 {
            capture = 1; pending = 0; printf "%s", buf; print; next
        }
        pending { pending = 0; buf = "" }
        capture {
            print
            if ($0 == "}") { capture = 0 }
        }
    ' "$SRC" > "$OUT.part" || fail "$name (slice reached the next top-level declaration before its closing brace)"
    n=$(grep -c "^ngx_http_cache_turbo_redis_${fn}[(]" "$OUT.part" || true)
    if [ "$n" -ne 1 ]; then
        fail "$name (expected exactly one definition, got $n)"
    fi
    if [ "$(tail -n1 "$OUT.part")" != "}" ]; then
        fail "$name (slice does not end on a closing brace)"
    fi
    cat "$OUT.part" >> "$OUT"
done
rm -f "$OUT.part"

LINES=$(wc -l < "$OUT")
echo "✓ extracted redis read_preamble() + read_lock() — $LINES lines -> $OUT"
