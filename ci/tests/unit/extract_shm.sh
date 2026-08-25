#!/usr/bin/env bash
#
# Slice the verbatim bodies of the shared-memory node state machine out of the
# shipped ../../src/ngx_http_cache_turbo_shm.c into generated_shm.inc:
#
#   ngx_http_cache_turbo_lru_*()             - S8 segment linkage helpers
#   ngx_http_cache_turbo_shm_touch_lru()     - S8 promote-on-second-hit
#   ngx_http_cache_turbo_shm_lookup()        - rbtree lookup by hash + key
#   ngx_http_cache_turbo_shm_admit()         - P4-1b W-TinyLFU admission test
#   ngx_http_cache_turbo_shm_evict_one()     - LRU tail reclaim
#   ngx_http_cache_turbo_shm_alloc_evict()   - alloc, evicting until it fits
#   ngx_http_cache_turbo_shm_free_locked()   - P4-2-s3a used-bytes discharge
#   ngx_http_cache_turbo_shm_claim()         - single-flight winner/loser/fresh
#   ngx_http_cache_turbo_shm_unstub()        - release stub, reclaim if empty
#   ngx_http_cache_turbo_shm_owns()          - is this token the live lease holder
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
# ⚠ The declarations this script mirrors are split across TWO headers as of
# MAINT-C3b, so there is no single $HDR:
#   _internal.h -- shm.c-private: the NODE_/SEG_ kind and segment values,
#                  CT_BLOBREF() and ngx_http_cache_turbo_blobref_t
#   module.h    -- cross-file: the BREAKER_* state and BREAKER_PROBE_* widths
# This extractor is a NON-COMPILER consumer of those declarations. Moving one
# between headers does not break any build -- it breaks this script's greps,
# and the drift checks below then fail with an empty `got=`. If a mirrored
# declaration moves again, repoint its check at the header that now holds it.
HDR="$UNIT_DIR/../../../src/ngx_http_cache_turbo_module.h"
HDR_INT="$UNIT_DIR/../../../src/ngx_http_cache_turbo_internal.h"
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
    name="$1"; want="$2"; where="${3:-$HDR}"
    got=$(grep -E "^#define[[:space:]]+${name}[[:space:]]" "$where" \
          | head -n1 | sed -E "s/^#define[[:space:]]+${name}[[:space:]]+//" \
          | sed -E 's;/\*.*;;' | tr -d '[:space:]')
    if [ -z "$got" ]; then
        echo "✗ $name not found in $where (renamed? update extract_shm.sh)" >&2
        exit 1
    fi
    if [ "$got" != "$want" ]; then
        echo "✗ $name drifted: source='$got' expected='$want'" >&2
        echo "  ci/tests/unit/test_shm_state.c asserts on these values" >&2
        exit 1
    fi
}
check_define NGX_HTTP_CACHE_TURBO_NODE_ENTRY   0 "$HDR_INT"
check_define NGX_HTTP_CACHE_TURBO_NODE_COUNTER 1 "$HDR_INT"
check_define NGX_HTTP_CACHE_TURBO_NODE_MARKER  2 "$HDR_INT"
# S8: PROBATION == 0 is load-bearing for the same reason ENTRY == 0 is -- a node
# zeroed by accident must read as the EVICTABLE segment. A silent flip would
# invert the promotion assertions while leaving them green.
check_define NGX_HTTP_CACHE_TURBO_SEG_PROBATION 0 "$HDR_INT"
check_define NGX_HTTP_CACHE_TURBO_SEG_PROTECTED 1 "$HDR_INT"
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
# P6/O4.4-a: the probe lease. Mirrored into test_shm_state.c because the sliced
# breaker_state() references it, so a drift between the two copies would move
# the reclaim deadline in production while the test kept measuring the old one.
# The test asserts only the ORDERING against open_for, but it cannot notice a
# value that silently drops below it -- this pin is what does.
check_define NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_LEASE 300
check_define NGX_HTTP_CACHE_TURBO_BRK_ACT_PASS  0
check_define NGX_HTTP_CACHE_TURBO_BRK_ACT_SERVE 1
check_define NGX_HTTP_CACHE_TURBO_BRK_ACT_FAIL  2
# S231-PERF-LRUCAP: the per-call demotion bound. Mirrored into
# test_shm_state.c, and test_s231_lru_enforce_cap_is_bounded() asserts the
# EXACT number demoted (== the bound, not merely <=), so a silent change to
# the value in shm.c would leave the test asserting the old number against
# the new behaviour and failing for a reason that looks unrelated -- or, if
# the test copy were changed to match, passing while measuring nothing.
# Lives in the .c, not the header, hence the third argument.
check_define NGX_HTTP_CACHE_TURBO_LRU_CAP_MAX_EVICT 8 "$SRC"

# P4-1a: the W-TinyLFU sketch constants. Also in the .c rather than a header,
# and also hand-mirrored into test_shm_state.c, so they get the same treatment.
# SKETCH_MAX == 15 and ROWS == 4 are both asserted on directly by the
# saturation and min-across-rows tests; MIN_WIDTH is what those tests size
# their fixture sketch to, so a silent widening would leave the fixture
# allocating less memory than the sliced code indexes into -- an ASan heap
# overflow rather than a clean failure, which is worse than a red assert.
check_define NGX_HTTP_CACHE_TURBO_SKETCH_ROWS      4 "$HDR"
check_define NGX_HTTP_CACHE_TURBO_SKETCH_MAX       15 "$SRC"
check_define NGX_HTTP_CACHE_TURBO_SKETCH_SAMPLE    10 "$SRC"
check_define NGX_HTTP_CACHE_TURBO_SKETCH_MIN_WIDTH 1024 "$SRC"
check_define NGX_HTTP_CACHE_TURBO_SKETCH_MAX_WIDTH '(1<<20)' "$SRC"

# H-4: the packed-probe layout macros are hand-mirrored into test_shm_state.c
# (NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_WORD_BITS / _STAMP_BITS / _GEN_BITS /
# _STAMP_MASK / _GEN_MASK and the pack/unpack macros built from them). Two
# comments used to CLAIM this was already pinned by this script -- it was not,
# and that is exactly how the wrong-layout bug in H-1 stayed invisible: the
# unit build silently compiled a different layout than production with
# nothing to fail loudly on the drift. check_define() only compares a single
# literal value, and NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_WORD_BITS is an
# expression (sizeof(ngx_atomic_t) * 8), not a literal, so it is verified
# structurally instead: assert both copies of the expression are textually
# identical. The STAMP_BITS/GEN_BITS split is width-conditional
# (#if NGX_PTR_SIZE >= 8); only the >= 8 arm ships (H-2/O4.4-j rejects the
# narrow layout at compile time -- see the layout comment in module.h), so
# only that arm's literal is pinned here.
extract_define() {
    # Extract the full value of a #define, following backslash line
    # continuations rather than assuming a fixed line count -- a macro
    # reflowed onto one line (or across N lines) must still be captured
    # in full. Strips the trailing '\' and all whitespace, concatenates
    # the continuation lines, and drops the macro name from the first
    # line so only the value remains.
    name="$1"
    file="$2"
    awk -v name="$name" '
        $0 ~ "^#define[[:space:]]+" name "([[:space:]]|\\\\|$)" {
            line = $0
            sub("^#define[[:space:]]+" name, "", line)
            cont = (line ~ /\\[[:space:]]*$/)
            sub(/\\[[:space:]]*$/, "", line)
            val = val line
            if (!cont) { print val; exit }
            getline line
            while (1) {
                cont = (line ~ /\\[[:space:]]*$/)
                sub(/\\[[:space:]]*$/, "", line)
                val = val line
                if (!cont) { print val; exit }
                getline line
            }
        }
    ' "$file" | tr -d '[:space:]'
}

check_probe_layout() {
    hdr_expr=$(extract_define \
        'NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_WORD_BITS' "$HDR")
    test_expr=$(extract_define \
        'NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_WORD_BITS' \
        "$UNIT_DIR/test_shm_state.c")
    if [ -z "$hdr_expr" ] || [ -z "$test_expr" ]; then
        echo "✗ NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_WORD_BITS not found in both" \
             "$HDR and test_shm_state.c" >&2
        exit 1
    fi
    if [ "$hdr_expr" != "$test_expr" ]; then
        echo "✗ NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_WORD_BITS drifted between" \
             "module.h ('$hdr_expr') and test_shm_state.c ('$test_expr')" >&2
        exit 1
    fi

    # Only the 32-bit STAMP_BITS arm ships (the narrow layout is rejected at
    # compile time -- see the width note above), so this is a single check, not
    # a loop over widths. It was written as `for bits in 32` for a second arm
    # that never arrived; shellcheck SC2043 flags that correctly.
    bits=32
    hdr_n=$(grep -c \
        "NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_STAMP_BITS  $bits\$" "$HDR" \
        || true)
    test_n=$(grep -c \
        "NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_STAMP_BITS  $bits\$" \
        "$UNIT_DIR/test_shm_state.c" || true)
    if [ "$hdr_n" -lt 1 ] || [ "$test_n" -lt 1 ]; then
        echo "✗ NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_STAMP_BITS $bits arm" \
             "missing from module.h ($hdr_n) or test_shm_state.c" \
             "($test_n) -- the width-conditional mirror drifted" >&2
        exit 1
    fi
}
check_probe_layout

# P2-3: pin the size of ngx_http_cache_turbo_node_t so it does not silently grow
# or shrink and change which slab class it lands in. The node must remain in the
# 256B slab class (nginx slab sizes are powers of 2: 128, 256, 512, ...).
# Measured with pahole; currently 200 bytes. The bounds check (128 < size <= 256)
# is portable across architectures and toolchains, while the exact size is not
# (padding, alignment, and type widths vary). If the struct grows past 256B or
# shrinks below 128B, the check fails loudly. Adding fields that change the size
# within the 256B class is permitted; leaving this check as-is (it will now cover
# a wider range) is the right behaviour.
check_node_size() {
    # pahole (dwarves package) is a required CI dependency -- see the
    # "Install build dependencies" step in .github/workflows/build-test.yml.
    # Skipping this check when the tool is missing would make the P2-3
    # assertion silently vacuous instead of failing loudly on the exact
    # regression it exists to catch, so a missing tool is itself a failure.
    if ! command -v pahole >/dev/null 2>&1; then
        echo "✗ pahole not found; required to measure" \
             "ngx_http_cache_turbo_node_t (P2-3 slab-class check)" >&2
        return 1
    fi

    # Find the struct size from pahole output in one of the compiled objects.
    # The struct is only in one TU at most, so try a few.
    # REPO-relative, not cwd-relative: this script runs under `make -C
    # ci/tests/unit`, whose cwd is ci/tests/unit, not the repo root where
    # ci-build.sh writes .build/. A ./.build/... glob from that cwd matches
    # nothing and the loop falls straight through to the "not found" error.
    for obj in "$UNIT_DIR"/../../../.build/nginx-*/objs/addon/src/ngx_http_cache_turbo_module.o; do
        if [ ! -f "$obj" ]; then
            continue
        fi
        # -F dwarf: this object has no .BTF section (only clang/pahole's BTF
        # encoder emits one), so the default BTF-first probe exits non-zero
        # with no size line and the loop silently tries the next object.
        # DWARF is always present from a normal -g compile, so pin the
        # source format explicitly rather than relying on pahole's fallback.
        size=$(pahole -F dwarf -C ngx_http_cache_turbo_node_t "$obj" 2>/dev/null \
               | grep "/\* size:" | head -1 \
               | sed -E 's/.*size:[[:space:]]*([0-9]+).*/\1/')
        if [ -n "$size" ]; then
            # Ensure the node fits in the 256B slab class (>128, <=256).
            # A node that grows past 256B moves to the 512B class and is a
            # significant memory-efficiency regression.
            if [ "$size" -le 128 ] || [ "$size" -gt 256 ]; then
                echo "✗ ngx_http_cache_turbo_node_t size is $size bytes;" \
                     "must be in the 256B slab class (128 < size <= 256)" >&2
                echo "  If the struct grew past 256B, this is a P4-3 blocker." \
                     "Update memory/PLAN-optimize.md with the new size and" \
                     "slab class, and justify the change." >&2
                return 1
            fi
            return 0
        fi
    done
    # If the struct size could not be measured (pahole ran but found nothing),
    # that is unexpected and should fail.
    echo "✗ could not measure ngx_http_cache_turbo_node_t size with pahole" >&2
    return 1
}
check_node_size || exit 1

# PERF-7: the blob refcount header is hand-mirrored into test_shm_state.c (the
# harness declares its own structs rather than including module.h). CT_BLOBREF()
# steps BACK by sizeof(that struct) from the blob pointer, so if the mirror ever
# has a different size or field order than production, the sliced bodies read a
# header at the wrong offset -- and every blob test would still pass, because
# the mirror and the tests would agree with each other while both disagreed with
# the shipped layout. That is precisely how the H-1 wrong-layout bug survived, so
# the mirror is pinned structurally here rather than trusted.
check_blobref_mirror() {
    # extract_define() anchors on the macro name followed by whitespace, a
    # continuation or EOL -- a function-like macro is followed by '(', so the
    # parameter list is part of the name we match on.
    hdr_macro=$(extract_define 'CT_BLOBREF\\(data\\)' "$HDR_INT")
    test_macro=$(extract_define 'CT_BLOBREF\\(data\\)' "$UNIT_DIR/test_shm_state.c")
    if [ -z "$hdr_macro" ] || [ -z "$test_macro" ]; then
        echo "✗ CT_BLOBREF not found in both $HDR_INT and test_shm_state.c" >&2
        exit 1
    fi
    if [ "$hdr_macro" != "$test_macro" ]; then
        echo "✗ CT_BLOBREF drifted between _internal.h ('$hdr_macro') and" \
             "test_shm_state.c ('$test_macro')" >&2
        exit 1
    fi

    # Field list + order of ngx_http_cache_turbo_blobref_t, normalised to
    # "type name;" tokens. Compares the struct BODY in both files: a reordered,
    # added, removed or retyped field changes the size or the offsets and must
    # fail the build rather than silently shift the header.
    blobref_fields() {
        awk '
            /^typedef struct \{/ { buf = ""; cap = 1; next }
            cap && /^\} ngx_http_cache_turbo_blobref_t;/ { print buf; exit }
            cap { line = $0
                  # Drop whole-line and trailing comments, and any line that is
                  # purely a comment continuation (" * text" or " */"), so only
                  # "type name;" survives. Without the continuation rule a
                  # comment REFLOWED across lines in one file but not the other
                  # would diverge the two field lists and fail the build on
                  # cosmetic drift alone.
                  gsub(/\/\*[^*]*\*+([^\/*][^*]*\*+)*\//, "", line)
                  sub(/\/\*.*/, "", line)
                  if (line ~ /^[[:space:]]*\*/) next
                  gsub(/[[:space:]]+/, " ", line)
                  gsub(/^ | $/, "", line)
                  if (line != "") buf = buf line "|"
                }
        ' "$1"
    }
    hdr_fields=$(blobref_fields "$HDR_INT")
    test_fields=$(blobref_fields "$UNIT_DIR/test_shm_state.c")
    if [ -z "$hdr_fields" ] || [ -z "$test_fields" ]; then
        echo "✗ ngx_http_cache_turbo_blobref_t body not found in both" \
             "$HDR_INT and test_shm_state.c" >&2
        exit 1
    fi
    if [ "$hdr_fields" != "$test_fields" ]; then
        echo "✗ ngx_http_cache_turbo_blobref_t drifted between module.h" \
             "('$hdr_fields') and test_shm_state.c ('$test_fields')" >&2
        echo "  the mirrored header size/offsets no longer match production" >&2
        exit 1
    fi
}
check_blobref_mirror

# --- slice the function bodies in source order.
# nginx style: a definition is a bare return-type line (`void`, `ngx_int_t`,
# `static void *`, `ngx_http_cache_turbo_node_t *`, ...) immediately followed
# by the `name(` line, and the body closes on a bare `}` in column 0. Matching
# the type line + the name regex picks out exactly the wanted set.
awk '
    /^(static )?(void|ngx_int_t|ngx_uint_t|ngx_flag_t|time_t|u_char|const char|uint32_t|uint64_t|ngx_http_cache_turbo_node_t)[[:space:]]*\**$/ {
        pending = 1; buf = $0 ORS; next
    }
    /^static ngx_inline (uint32_t|uint64_t|ngx_uint_t|void)$/ {
        pending = 1; buf = $0 ORS; next
    }
    pending && /^ngx_http_cache_turbo_(shm_(key64|sketch_bump|sketch_estimate|admit|lookup|evict_one|alloc_evict|free_locked|claim_locked|claim|resolve_miss|unstub|owns|count_miss_locked|count_miss|l2_neg_check|l2_neg_set|touch_lru|brk_probe_age|breaker_state|breaker_record|breaker_state_str|get_u32|get_u64|node_sie_live)|lru_(link_head|unlink|insert_new|enforce_cap)|sketch_(row_hash|rows|get|inc|halve)|blob_(alloc|node_release|acquire|release))\(/ {
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

# The header/body filter group lives in its own TU since MAINT-SPLIT step E.
# Call-site invariants that used to be checked against module.c and are stated
# inside a filter are checked against this file instead.
FILTERSRC="$UNIT_DIR/../../../src/ngx_http_cache_turbo_filters.c"
if [ ! -f "$FILTERSRC" ]; then
    echo "✗ cannot find $FILTERSRC" >&2
    rm -f "$OUT"
    exit 1
fi

# The access/precontent handler group lives in its own TU since MAINT-SPLIT
# step F. The O4.3 pre-origin gate canary below is a CALL-SITE invariant stated
# inside the access handler, so it follows that handler to this file. The
# breaker predicates it calls still live in module.c's UNIT-EXTRACT block and
# are still sliced from there, unchanged.
ACCESSSRC="$UNIT_DIR/../../../src/ngx_http_cache_turbo_access.c"
if [ ! -f "$ACCESSSRC" ]; then
    echo "✗ cannot find $ACCESSSRC" >&2
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
# Checked against filters.c rather than the slice: the call site is in the
# header filter, which is not extracted -- and which MAINT-SPLIT step E moved
# out of module.c into src/ngx_http_cache_turbo_filters.c. The predicate itself
# still lives in module.c's UNIT-EXTRACT block, so only this call-site check
# follows the filter. Comments stripped first, as everywhere here.
if ! sed -n '/ngx_http_cache_turbo_breaker_should_record($/,/^    {$/p' "$FILTERSRC" \
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

# ⚠ O4.5: the rolling-window re-anchor must stay a CAS on breaker_window_start.
# The bare check-then-write it replaced let every worker observing the expiry
# store both the new anchor AND a zeroed counter, so a burst of concurrent
# failures erased its own evidence and the breaker never reached threshold --
# it stayed CLOSED against a dead origin, the exact outage it exists to catch.
#
# Reverting the CAS reads as a simplification ("why cmp_set for a counter?") and
# leaves every breaker test green: the single-threaded ones never race, and only
# the concurrent-arrival test notices. Pinned structurally so the build fails
# instead. Comments stripped first, for the same reason as every check above --
# the prose around the fix names cmp_set repeatedly, so a naive grep would match
# the explanation rather than the code.
if ! sed -n '/^ngx_http_cache_turbo_shm_breaker_record(/,/^}/p' "$OUT" \
   | sed -E 's;/\*.*;;; s;^[[:space:]]*\*.*;;' \
   | grep -q 'ngx_atomic_cmp_set(&ngx_http_cache_turbo_zone_sh(z)->breaker_window_start'; then
    echo "✗ O4.5 regression: the rolling-window re-anchor is no longer a CAS" >&2
    echo "  on breaker_window_start. Concurrent failures then clear each" >&2
    echo "  other's count and the breaker cannot trip during a real burst." >&2
    rm -f "$OUT"
    exit 1
fi

# --- sanity: every wanted function must be present, and the file must end on a
# closing brace (a truncated slice would otherwise fail to compile in a
# confusing place, or worse, compile with a body silently cut short).
for fn in \
    'ngx_http_cache_turbo_shm_key64(' \
    'ngx_http_cache_turbo_lru_link_head(' \
    'ngx_http_cache_turbo_lru_unlink(' \
    'ngx_http_cache_turbo_lru_insert_new(' \
    'ngx_http_cache_turbo_lru_enforce_cap(' \
    'ngx_http_cache_turbo_shm_touch_lru(' \
    'ngx_http_cache_turbo_sketch_row_hash(' \
    'ngx_http_cache_turbo_sketch_rows(' \
    'ngx_http_cache_turbo_sketch_get(' \
    'ngx_http_cache_turbo_sketch_inc(' \
    'ngx_http_cache_turbo_sketch_halve(' \
    'ngx_http_cache_turbo_shm_sketch_bump(' \
    'ngx_http_cache_turbo_shm_sketch_estimate(' \
    'ngx_http_cache_turbo_shm_lookup(' \
    'ngx_http_cache_turbo_shm_admit(' \
    'ngx_http_cache_turbo_shm_evict_one(' \
    'ngx_http_cache_turbo_shm_alloc_evict(' \
    'ngx_http_cache_turbo_shm_free_locked(' \
    'ngx_http_cache_turbo_shm_claim_locked(' \
    'ngx_http_cache_turbo_shm_claim(' \
    'ngx_http_cache_turbo_shm_resolve_miss(' \
    'ngx_http_cache_turbo_shm_unstub(' \
    'ngx_http_cache_turbo_shm_owns(' \
    'ngx_http_cache_turbo_shm_count_miss_locked(' \
    'ngx_http_cache_turbo_shm_count_miss(' \
    'ngx_http_cache_turbo_shm_l2_neg_check(' \
    'ngx_http_cache_turbo_shm_l2_neg_set(' \
    'ngx_http_cache_turbo_shm_breaker_state(' \
    'ngx_http_cache_turbo_shm_breaker_record(' \
    'ngx_http_cache_turbo_shm_breaker_state_str(' \
    'ngx_http_cache_turbo_blob_alloc(' \
    'ngx_http_cache_turbo_blob_node_release(' \
    'ngx_http_cache_turbo_blob_acquire(' \
    'ngx_http_cache_turbo_blob_release('
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
# S231-PERF-MISSLOCKS: the mutation this canary guards moved into
# claim_locked() when claim() was split into a lock+lookup wrapper around a
# LOCK-HELD core (shared with count_miss() via resolve_miss()). The public
# claim() wrapper's body no longer contains the takeover branch at all, so the
# canary must scope to claim_locked() to keep testing the real code instead of
# vacuously passing against a thin pass-through.
if sed -n '/^ngx_http_cache_turbo_shm_claim_locked(/,/return NGX_HTTP_CACHE_TURBO_CLAIM_WINNER;/p' "$OUT" \
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

# ⚠ CTXRDR-ADOPT-LEASE: unstub() must gate on the LEASE IDENTITY, not just on
# the stub's shape. claim() re-leases an expired stub to a new winner, so an
# unstub() that matches kind + refreshing alone lets a stale, slow loser clear
# the CURRENT holder's live lease -- single-flight broken and the origin
# stampeded, exactly during the origin slowness that opens the window.
# Comments stripped first, for the same reason as the CR-B canary above: the
# prose around this predicate names the field, so a naive grep would match the
# explanation of the check rather than the check.
if ! sed -n '/^ngx_http_cache_turbo_shm_unstub(/,/^}/p' "$OUT" \
   | sed -E 's;/\*.*;;; s;^[[:space:]]*\*.*;;' \
   | grep -q 'refresh_owner == owner'; then
    echo "✗ CTXRDR-ADOPT-LEASE regression: unstub() no longer compares the" >&2
    echo "  owner token. A stale holder can now clear the live winner's lease." >&2
    rm -f "$OUT"
    exit 1
fi

# ⚠ P4-1a-ORDER: the sketch bump must stay BEFORE touch_lru()'s coarse
# `now - last_access < 1` gate. The gate returns early for a key touched within
# the last second, so a bump moved AFTER it counts at most one access per key
# per second -- undercounting hot keys by exactly the factor that makes them
# hot, and leaving the estimate unable to separate a key served 500 times a
# second from one served once.
#
# It reads as a natural tidy-up ("do the cheap early-out first"), it changes no
# observable behaviour in stage 1 at all, and even in stage 2 it degrades the
# admission decision silently rather than breaking anything. Nothing else in
# this harness can notice it, so it is pinned structurally here. Comments are
# stripped first, for the same reason as every canary above: the prose beside
# the bump names both the call and the gate, so a naive grep would match the
# explanation rather than the code.
if ! sed -n '/^ngx_http_cache_turbo_shm_touch_lru(/,/^}/p' "$OUT" \
   | sed -E 's;/\*.*;;; s;^[[:space:]]*\*.*;;' \
   | grep -nE 'sketch_bump|last_access < 1' \
   | head -n2 \
   | awk -F: 'NR==1 && $2 !~ /sketch_bump/ { bad=1 }
              NR==2 && $2 !~ /last_access < 1/ { bad=1 }
              END { exit (bad || NR < 2) }'; then
    echo "✗ P4-1a-ORDER regression: touch_lru()'s sketch bump is no longer" >&2
    echo "  the first statement before the last_access early-out gate." >&2
    echo "  After the gate it undercounts hot keys by their hotness." >&2
    rm -f "$OUT"
    exit 1
fi

# ⚠ P4-1b-ADMIT-ORDER: the admission test must stay in store_locked()'s
# NEW-ENTRY path, and STRICTLY BEFORE the alloc_evict() call there. That
# ordering is the whole termination argument: called before the loop, a refusal
# REMOVES an alloc_evict() call; called inside or after it, a refusal that
# undoes a store after eviction has already run turns "evict then decide" into
# a policy that can burn victims for a candidate it then rejects, and a caller
# that retried would drive evict_one() repeatedly on the same decision.
#
# store_locked() is deliberately NOT sliced (it pulls in the blob refcount
# layer), so this is checked against the SOURCE, scoped to that one function.
# Comments stripped first, exactly as above: the prose beside the call names
# both alloc_evict and shm_admit.
admit_order=$(sed -n '/^ngx_http_cache_turbo_shm_store_locked(/,/^}/p' "$SRC" \
   | sed -E 's;/\*.*;;; s;^[[:space:]]*\*.*;;' \
   | grep -nE 'ngx_http_cache_turbo_shm_admit\(|ngx_http_cache_turbo_shm_alloc_evict\(' \
   | head -n2)
if ! printf '%s\n' "$admit_order" \
   | awk -F: 'NR==1 && $2 !~ /shm_admit\(/ { bad=1 }
              NR==2 && $2 !~ /alloc_evict\(/ { bad=1 }
              END { exit (bad || NR < 2) }'; then
    echo "✗ P4-1b-ADMIT-ORDER regression: store_locked()'s admission test is" >&2
    echo "  no longer the first of the pair (admit, alloc_evict). Got:" >&2
    printf '%s\n' "$admit_order" >&2
    echo "  The termination argument in shm_admit() depends on the refusal" >&2
    echo "  happening BEFORE any eviction loop is entered." >&2
    rm -f "$OUT"
    exit 1
fi

# ⚠ P4-1b-FAIL-OPEN: shm_admit() must keep all three fail-open early-outs.
# Each one alone is enough to turn a refusal into a permanent silent cache
# miss if it goes: without the `!admission` test the policy ships ON; without
# the NULL-sketch test a zone whose sketch failed to allocate refuses on no
# evidence; without the empty-probation test a cold zone refuses to fill
# itself. All three are single `return 1;` lines that read as redundant, which
# is exactly why they are pinned here rather than left to review.
admit_body=$(sed -n '/^ngx_http_cache_turbo_shm_admit(/,/^}/p' "$OUT" \
   | sed -E 's;/\*.*;;; s;^[[:space:]]*\*.*;;')
# P4-2-s3b: `z->sh` is now spelled ngx_http_cache_turbo_zone_sh(z) -- the
# stripe resolver. Same three guards, same strength; only the accessor changed.
for guard in '!ngx_http_cache_turbo_zone_sh(z)->admission' \
             'ngx_http_cache_turbo_zone_sh(z)->sketch == NULL' \
             'ngx_queue_empty(&ngx_http_cache_turbo_zone_sh(z)->lru)'; do
    if ! printf '%s\n' "$admit_body" | grep -qF "$guard"; then
        echo "✗ P4-1b-FAIL-OPEN regression: shm_admit() no longer guards on" >&2
        echo "  '$guard' -- admission can now refuse on no evidence." >&2
        rm -f "$OUT"
        exit 1
    fi
done

LINES=$(wc -l < "$OUT")
# Derive the count rather than hardcoding it: a literal here goes stale the
# moment the slice list grows and then reports a number that is simply wrong.
FNS=$(grep -cE '^ngx_http_cache_turbo_[a-z_]+\(' "$OUT")
# ⚠ O4.3: the pre-origin gate must consult the breaker AT MOST ONCE per request.
# The access handler is re-entered from the top on every park/resume (L2 GET,
# the v4-2 NX lock, each cold_wait re-poll), and _breaker_state() promotes only
# one caller per open window and returns HALF_OPEN only to that promoter. An
# unlatched gate therefore hands a request that WAS the probe an OPEN verdict on
# its resume, answers it locally, and leaves nobody to close the breaker -- one
# burnt probe per window, indefinitely.
#
# Checked against access.c rather than the slice: the gate lives in the access
# handler, which is not extracted -- and which MAINT-SPLIT step F moved out of
# module.c into src/ngx_http_cache_turbo_access.c. The predicate it calls still
# lives in module.c's UNIT-EXTRACT block, so only this call-site check follows
# the handler. Comments stripped first, as everywhere here.
#
# ⚠ The block is delimited by BRACE DEPTH, not by a `^    }$` line. The previous
# form anchored on exact 4-space indentation and an exactly-indented closing
# brace, so a pure reformat -- moving the opening brace up onto the `if` line,
# no semantic change at all, latch fully intact -- made this fire a false build
# failure (#135). Depth counting cares about the code, not its layout, which is
# the whole point of a canary: it must fail when the LATCH goes, and only then.
#
# The gate is located by the should_consult(clcf) call rather than by a function
# definition (every sibling check here anchors on a definition) because it lives
# mid-function in the access handler, which has no extractable boundary of its
# own. If a second bare `should_consult(clcf)` gate block is ever added, this
# picks the FIRST and the invariant would need re-scoping -- hence the count
# guard below, which fails loudly instead of silently checking the wrong block.
GATES=$(grep -cE '^[[:space:]]*if \(ngx_http_cache_turbo_breaker_should_consult\(clcf\)\)[[:space:]]*\{?$' "$ACCESSSRC")
if [ "$GATES" -ne 1 ]; then
    echo "✗ O4.3 canary cannot scope itself: expected exactly 1 bare" >&2
    echo "  'if (breaker_should_consult(clcf))' gate in $ACCESSSRC, found $GATES." >&2
    echo "  Re-scope this check (it verifies the FIRST such block only)." >&2
    rm -f "$OUT"
    exit 1
fi

if ! awk '
    # Enter the gate block at the bare should_consult(clcf) if-statement.
    !inblk && $0 ~ /^[[:space:]]*if \(ngx_http_cache_turbo_breaker_should_consult\(clcf\)\)[[:space:]]*\{?$/ {
        inblk = 1
        depth = 0
        seen_open = 0
    }
    inblk {
        print
        # Count braces to find the real end of the block, whatever the layout.
        n = gsub(/\{/, "{"); depth += n; if (n) seen_open = 1
        depth -= gsub(/\}/, "}")
        if (seen_open && depth <= 0) { exit }
    }
' "$ACCESSSRC" \
   | sed -E 's;/\*.*;;; s;^[[:space:]]*\*.*;;' \
   | grep -q 'brk_consulted'; then
    echo "✗ O4.3 regression: the pre-origin breaker gate lost its" >&2
    echo "  ctx->brk_consulted latch. The handler is re-entered on every" >&2
    echo "  park/resume, so the promoted probe would be re-consulted, told" >&2
    echo "  OPEN, and answered from cache -- wedging the breaker." >&2
    rm -f "$OUT"
    exit 1
fi

echo "✓ extracted $FNS shm state functions — $LINES lines -> $OUT"
