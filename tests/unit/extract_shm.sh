#!/usr/bin/env bash
#
# Slice the verbatim bodies of the shared-memory node state machine out of the
# shipped ../../src/ngx_http_cache_turbo_shm.c into generated_shm.inc:
#
#   ngx_http_cache_turbo_shm_lookup()        - rbtree lookup by hash + key
#   ngx_http_cache_turbo_shm_evict_one()     - LRU tail reclaim
#   ngx_http_cache_turbo_shm_alloc_evict()   - alloc, evicting until it fits
#   ngx_http_cache_turbo_shm_claim()         - single-flight winner/loser/fresh
#   ngx_http_cache_turbo_shm_unstub()        - release stub, reclaim if empty
#   ngx_http_cache_turbo_shm_count_miss()    - min_uses miss counter
#   ngx_http_cache_turbo_shm_l2_neg_check()  - read the L13 negative memo
#   ngx_http_cache_turbo_shm_l2_neg_set()    - arm the L13 negative memo
#
# Same no-drift discipline as fuzz/extract_parser.sh: the test binary always
# exercises PRODUCTION code. Nothing here is hand-copied, so a body that
# changes upstream is picked up on the next build, and a body that can no
# longer be found fails the build loudly rather than silently testing nothing.
#
# Functions deliberately NOT sliced (they pull in the blob refcount layer,
# response serialisation and the config surface, none of which this harness is
# about): _init_zone, _store, _stats, _purge_key, _purge_all, _drop_locked.
# The two that the sliced set calls into are stubbed in test_shm_state.c.

set -euo pipefail

UNIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$UNIT_DIR/../../src/ngx_http_cache_turbo_shm.c"
HDR="$UNIT_DIR/../../src/ngx_http_cache_turbo_module.h"
OUT="$UNIT_DIR/generated_shm.inc"

if [ ! -f "$SRC" ]; then
    echo "✗ cannot find $SRC" >&2
    exit 1
fi

# --- guard: the node-kind constants the tests assert on must still mean what
# the tests think they mean. ENTRY == 0 is load-bearing (a node zeroed by
# accident must read as ENTRY, the safe direction), so a silent flip of these
# values would invert several assertions while leaving them green.
check_define() {
    name="$1"; want="$2"
    got=$(grep -E "^#define[[:space:]]+${name}[[:space:]]" "$HDR" \
          | head -n1 | sed -E "s/^#define[[:space:]]+${name}[[:space:]]+//" \
          | sed -E 's;/\*.*;;' | tr -d '[:space:]')
    if [ -z "$got" ]; then
        echo "✗ $name not found in $HDR (renamed? update extract_shm.sh)" >&2
        exit 1
    fi
    if [ "$got" != "$want" ]; then
        echo "✗ $name drifted: source='$got' expected='$want'" >&2
        echo "  tests/unit/test_shm_state.c asserts on these values" >&2
        exit 1
    fi
}
check_define NGX_HTTP_CACHE_TURBO_NODE_ENTRY   0
check_define NGX_HTTP_CACHE_TURBO_NODE_COUNTER 1

# --- slice the function bodies in source order.
# nginx style: a definition is a bare return-type line (`void`, `ngx_int_t`,
# `static void *`, `ngx_http_cache_turbo_node_t *`, ...) immediately followed
# by the `name(` line, and the body closes on a bare `}` in column 0. Matching
# the type line + the name regex picks out exactly the wanted set.
awk '
    /^(static )?(void|ngx_int_t|ngx_uint_t|time_t|u_char|ngx_http_cache_turbo_node_t)[[:space:]]*\**$/ {
        pending = 1; buf = $0 ORS; next
    }
    pending && /^ngx_http_cache_turbo_shm_(lookup|evict_one|alloc_evict|claim|unstub|count_miss|l2_neg_check|l2_neg_set)\(/ {
        capture = 1; pending = 0; printf "%s", buf; print; next
    }
    pending { pending = 0; buf = "" }
    capture {
        print
        if ($0 == "}") { capture = 0 }
    }
' "$SRC" > "$OUT"

# --- sanity: every wanted function must be present, and the file must end on a
# closing brace (a truncated slice would otherwise fail to compile in a
# confusing place, or worse, compile with a body silently cut short).
for fn in \
    'ngx_http_cache_turbo_shm_lookup(' \
    'ngx_http_cache_turbo_shm_evict_one(' \
    'ngx_http_cache_turbo_shm_alloc_evict(' \
    'ngx_http_cache_turbo_shm_claim(' \
    'ngx_http_cache_turbo_shm_unstub(' \
    'ngx_http_cache_turbo_shm_count_miss(' \
    'ngx_http_cache_turbo_shm_l2_neg_check(' \
    'ngx_http_cache_turbo_shm_l2_neg_set('
do
    if ! grep -qF "$fn" "$OUT"; then
        echo "✗ failed to extract $fn from $SRC" >&2
        echo "  (source layout changed? update extract_shm.sh)" >&2
        rm -f "$OUT"
        exit 1
    fi
done

if [ "$(tail -n1 "$OUT")" != "}" ]; then
    echo "✗ generated_shm.inc does not end on a closing brace (bad slice)" >&2
    rm -f "$OUT"
    exit 1
fi

# --- guard: the two invariants this harness exists to protect must still be
# absent-as-bugs in the sliced text. These are grep-level canaries for the
# exact regressions CR-A and CR-B describe; the real proof is the runnable
# negative control (`make control`), but a canary here fails faster and points
# straight at the line.
# Scope: only the TAKEOVER branch of claim() -- from the start of the function
# down to the CLAIM_WINNER return that follows `ctn->refreshing = 1`. Clearing
# l2_neg_until there is the CR-A bug. The new-node path further down legitimately
# zeroes it (a brand-new node has no memo to preserve), so the whole-function
# grep this used to do was a false positive on correct code.
if sed -n '/^ngx_http_cache_turbo_shm_claim(/,/return NGX_HTTP_CACHE_TURBO_CLAIM_WINNER;/p' "$OUT" \
   | grep -qE 'l2_neg_until[[:space:]]*=[[:space:]]*0;'; then
    echo "✗ CR-A regression: claim() clears l2_neg_until on stub takeover." >&2
    echo "  The memo must survive the claim that turns its node into a stub." >&2
    rm -f "$OUT"
    exit 1
fi
# ⚠ Comment lines are stripped before the grep. The in-tree unstub() comment
# also contains the string `miss_count == 0`, so a naive grep matched the PROSE
# and stayed green while the actual predicate had been removed -- verified by
# injecting the bug. A canary a comment can satisfy is not a canary.
if ! sed -n '/^ngx_http_cache_turbo_shm_unstub(/,/^}/p' "$OUT" \
   | sed -E 's;/\*.*;;; s;^[[:space:]]*\*.*;;' \
   | grep -q 'miss_count == 0'; then
    echo "✗ CR-B regression: unstub() no longer checks miss_count." >&2
    echo "  Freeing a COUNTER mid-count silently resets min_uses progress." >&2
    rm -f "$OUT"
    exit 1
fi

LINES=$(wc -l < "$OUT")
echo "✓ extracted 8 shm state functions — $LINES lines -> $OUT"
