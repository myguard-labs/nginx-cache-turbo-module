#!/usr/bin/env bash
#
# Slice the verbatim bodies of the shared-memory node state machine out of the
# shipped ../../src/ngx_http_cache_turbo_shm.c into generated_shm.inc:
#
#   ngx_http_cache_turbo_lru_*()             - S8 segment linkage helpers
#   ngx_http_cache_turbo_shm_touch_lru()     - S8 promote-on-second-hit
#   ngx_http_cache_turbo_shm_lookup()        - rbtree lookup by hash + key
#   ngx_http_cache_turbo_shm_evict_one()     - LRU tail reclaim
#   ngx_http_cache_turbo_shm_alloc_evict()   - alloc, evicting until it fits
#   ngx_http_cache_turbo_shm_claim()         - single-flight winner/loser/fresh
#   ngx_http_cache_turbo_shm_unstub()        - release stub, reclaim if empty
#   ngx_http_cache_turbo_shm_count_miss()    - min_uses miss counter
#   ngx_http_cache_turbo_shm_l2_neg_check()  - read the L13 negative memo
#   ngx_http_cache_turbo_shm_l2_neg_set()    - arm the L13 negative memo
#
# Same no-drift discipline as ci/fuzz/extract_parser.sh: the test binary always
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
SRC="$UNIT_DIR/../../../src/ngx_http_cache_turbo_shm.c"
HDR="$UNIT_DIR/../../../src/ngx_http_cache_turbo_module.h"
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
        echo "  ci/tests/unit/test_shm_state.c asserts on these values" >&2
        exit 1
    fi
}
check_define NGX_HTTP_CACHE_TURBO_NODE_ENTRY   0
check_define NGX_HTTP_CACHE_TURBO_NODE_COUNTER 1
# S8: PROBATION == 0 is load-bearing for the same reason ENTRY == 0 is -- a node
# zeroed by accident must read as the EVICTABLE segment. A silent flip would
# invert the promotion assertions while leaving them green.
check_define NGX_HTTP_CACHE_TURBO_SEG_PROBATION 0
check_define NGX_HTTP_CACHE_TURBO_SEG_PROTECTED 1
# P6/O4.1: CLOSED == 0 is load-bearing for the third time in this file -- a
# zeroed zone must come up with the breaker NOT tripped (traffic flows to origin
# as if the feature were off). A silent flip would bring every fresh worker up
# OPEN, serving stale bodies and 503s until the first probe, and the state tests
# below would stay green while doing it.
check_define NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED    0
check_define NGX_HTTP_CACHE_TURBO_BREAKER_OPEN      1
check_define NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN 2
# P6/O4.3: and a fourth time for the serve-path actions. PASS == 0 is the safe
# direction (a zeroed or defaulted verdict must not divert the request). The
# test file redeclares these locally, so an unpinned drift would leave the
# mapping tests asserting against the wrong numbers while staying green.
check_define NGX_HTTP_CACHE_TURBO_BRK_ACT_PASS  0
check_define NGX_HTTP_CACHE_TURBO_BRK_ACT_SERVE 1
check_define NGX_HTTP_CACHE_TURBO_BRK_ACT_FAIL  2

# --- slice the function bodies in source order.
# nginx style: a definition is a bare return-type line (`void`, `ngx_int_t`,
# `static void *`, `ngx_http_cache_turbo_node_t *`, ...) immediately followed
# by the `name(` line, and the body closes on a bare `}` in column 0. Matching
# the type line + the name regex picks out exactly the wanted set.
awk '
    /^(static )?(void|ngx_int_t|ngx_uint_t|time_t|u_char|const char|ngx_http_cache_turbo_node_t)[[:space:]]*\**$/ {
        pending = 1; buf = $0 ORS; next
    }
    pending && /^ngx_http_cache_turbo_(shm_(lookup|evict_one|alloc_evict|claim|unstub|count_miss|l2_neg_check|l2_neg_set|touch_lru|breaker_state|breaker_record|breaker_state_str)|lru_(link_head|unlink|insert_new|enforce_cap))\(/ {
        capture = 1; pending = 0; printf "%s", buf; print; next
    }
    pending { pending = 0; buf = "" }
    capture {
        print
        if ($0 == "}") { capture = 0 }
    }
' "$SRC" > "$OUT"

# --- P6/O4.2: the breaker's origin-failure predicate lives in module.c, not
# shm.c, because it is about the RESPONSE (a status code) rather than about the
# zone. Sliced by marker like the fuzz targets do it, for the same no-drift
# reason as everything above: the test must exercise production code, and a
# marker that moves or vanishes has to fail the build loudly rather than
# silently test a hand-copied stale duplicate.
MODSRC="$UNIT_DIR/../../../src/ngx_http_cache_turbo_module.c"
if [ ! -f "$MODSRC" ]; then
    echo "✗ cannot find $MODSRC" >&2
    rm -f "$OUT"
    exit 1
fi

{
    echo ""
    awk '
        /UNIT-EXTRACT breaker-failure BEGIN/ { cap = 1; next }
        /UNIT-EXTRACT breaker-failure END/   { cap = 0 }
        cap { print }
    ' "$MODSRC"
} >> "$OUT"

for fn in 'ngx_http_cache_turbo_breaker_is_origin_failure(' \
          'ngx_http_cache_turbo_breaker_should_record(' \
          'ngx_http_cache_turbo_breaker_from_origin(' \
          'ngx_http_cache_turbo_breaker_should_consult(' \
          'ngx_http_cache_turbo_breaker_action('; do
    if ! grep -qF "$fn" "$OUT"; then
        echo "✗ failed to extract ${fn%(} from $MODSRC" >&2
        echo "  (UNIT-EXTRACT breaker-failure markers moved or vanished?)" >&2
        rm -f "$OUT"
        exit 1
    fi
done

# ⚠ The admission rule must keep its from_origin arm. Without it a locally
# generated 5xx -- an only-if-cached miss is answered 504 by the module itself,
# no upstream contacted -- counts as an origin failure, and a client can trip a
# HEALTHY zone's breaker just by repeating a request header.
if ! sed -n '/^ngx_http_cache_turbo_breaker_should_record(/,/^}/p' "$OUT" \
   | sed -E 's;/\*.*;;; s;^[[:space:]]*\*.*;;' \
   | grep -q 'from_origin'; then
    echo "✗ O4.2 regression: the breaker admission rule dropped from_origin." >&2
    echo "  Locally generated 5xx (only-if-cached 504) would then count as" >&2
    echo "  origin failures — a client could trip a healthy breaker." >&2
    rm -f "$OUT"
    exit 1
fi

# ⚠ The CALL SITE must compute from_origin as "upstream exists AND this is not
# somebody else's cache hit". r->upstream != NULL alone only proves the upstream
# subsystem was initialised: with cache-turbo stacked in front of proxy_cache,
# ngx_http_upstream_cache_send() sets r->cached = 1 and serves from nginx's disk
# cache with r->upstream already allocated. Those hits would then clear a real
# failure run, or close a HALF_OPEN breaker with no probe reaching the origin.
#
# Checked against module.c rather than the slice: the call site is in the header
# filter, which is not extracted. Comments stripped first, as everywhere here.
if ! sed -n '/ngx_http_cache_turbo_breaker_should_record($/,/^    {$/p' "$MODSRC" \
   | sed -E 's;/\*.*;;; s;^[[:space:]]*\*.*;;' \
   | grep -q 'r->cached'; then
    echo "✗ O4.2 regression: the breaker call site no longer excludes" >&2
    echo "  r->cached. Native proxy_cache/fastcgi_cache HITs would count as" >&2
    echo "  origin outcomes and blind the breaker during an outage." >&2
    rm -f "$OUT"
    exit 1
fi

# ⚠ The whole point of this predicate is that it is NOT the use_stale trigger:
# use_stale may name 403/404/429, which are a healthy origin answering
# correctly, and feeding those to the breaker lets a 404-heavy site trip its own
# breaker and 503 everything. If somebody "deduplicates" the two, catch it here
# rather than in production. Comments are stripped first -- the prose above the
# function names use_stale deliberately, and a grep that matched the COMMENT
# would stay green exactly when the code had been broken.
if sed -n '/^ngx_http_cache_turbo_breaker_is_origin_failure(/,/^}/p' "$OUT" \
   | sed -E 's;/\*.*;;; s;^[[:space:]]*\*.*;;' \
   | grep -q 'use_stale'; then
    echo "✗ O4.2 regression: the breaker failure test now consults use_stale." >&2
    echo "  403/404/429 are a HEALTHY origin; counting them trips the breaker" >&2
    echo "  against a working backend. Keep the two predicates separate." >&2
    rm -f "$OUT"
    exit 1
fi

# ⚠ O4.3: the HALF_OPEN probe must PASS to the origin. A HALF_OPEN verdict goes
# to exactly one request per open window and that promotion is a lease which
# only _breaker_record() releases, so if the serve path answers the probe from
# cache (or 503s it) nothing ever reaches the origin, no outcome is recorded,
# and the breaker re-promotes one doomed probe per window forever.
#
# The property is structural: only the OPEN state may divert a request, so the
# mapping must key on OPEN and treat everything else as pass-through. A rewrite
# to "if (state != CLOSED) divert" reads as a harmless tidy-up and silently
# wedges the breaker, which is why this is pinned here and not left to review.
# Comments stripped first, for the same reason as every check above.
if ! sed -n '/^ngx_http_cache_turbo_breaker_action(/,/^}/p' "$OUT" \
   | sed -E 's;/\*.*;;; s;^[[:space:]]*\*.*;;' \
   | grep -q 'state != NGX_HTTP_CACHE_TURBO_BREAKER_OPEN'; then
    echo "✗ O4.3 regression: the serve-path action no longer keys on OPEN." >&2
    echo "  Only OPEN may divert a request. If HALF_OPEN stops passing to the" >&2
    echo "  origin the probe is answered locally, no outcome is ever recorded," >&2
    echo "  and the breaker wedges OPEN until reload." >&2
    rm -f "$OUT"
    exit 1
fi

# ⚠ O4.3: the OPEN arm must decide purely on whether a body exists, with NO age
# test. Serving a body of any age is the entire premise -- past stale, past
# stale-if-error, past keep_stale. Reintroducing a freshness condition here
# silently downgrades the breaker back into stale-if-error, and every test above
# would stay green because they only ever pass "has_body".
if sed -n '/^ngx_http_cache_turbo_breaker_action(/,/^}/p' "$OUT" \
   | sed -E 's;/\*.*;;; s;^[[:space:]]*\*.*;;' \
   | grep -qE 'ngx_time|fresh|stale_until|sie_ttl|created'; then
    echo "✗ O4.3 regression: the serve-path action grew an age/freshness test." >&2
    echo "  The breaker serves a cached body of ANY age once the origin is" >&2
    echo "  known down; an age condition turns it back into stale-if-error." >&2
    rm -f "$OUT"
    exit 1
fi

# --- sanity: every wanted function must be present, and the file must end on a
# closing brace (a truncated slice would otherwise fail to compile in a
# confusing place, or worse, compile with a body silently cut short).
for fn in \
    'ngx_http_cache_turbo_lru_link_head(' \
    'ngx_http_cache_turbo_lru_unlink(' \
    'ngx_http_cache_turbo_lru_insert_new(' \
    'ngx_http_cache_turbo_lru_enforce_cap(' \
    'ngx_http_cache_turbo_shm_touch_lru(' \
    'ngx_http_cache_turbo_shm_lookup(' \
    'ngx_http_cache_turbo_shm_evict_one(' \
    'ngx_http_cache_turbo_shm_alloc_evict(' \
    'ngx_http_cache_turbo_shm_claim(' \
    'ngx_http_cache_turbo_shm_unstub(' \
    'ngx_http_cache_turbo_shm_count_miss(' \
    'ngx_http_cache_turbo_shm_l2_neg_check(' \
    'ngx_http_cache_turbo_shm_l2_neg_set(' \
    'ngx_http_cache_turbo_shm_breaker_state(' \
    'ngx_http_cache_turbo_shm_breaker_record(' \
    'ngx_http_cache_turbo_shm_breaker_state_str('
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
# Derive the count rather than hardcoding it: a literal here goes stale the
# moment the slice list grows and then reports a number that is simply wrong.
FNS=$(grep -cE '^ngx_http_cache_turbo_[a-z_]+\(' "$OUT")
echo "✓ extracted $FNS shm state functions — $LINES lines -> $OUT"
