#!/usr/bin/env bash
#
# Enforce the stripe seam (P4-2-s3b).
#
# A zone's shared state lives in an ARRAY of stripes, each with its own
# ngx_slab_pool_t and therefore its own mutex. The whole point of the seam is
# that no code picks a pool by hand: everything goes through
# ngx_http_cache_turbo_stripe_of() (key-directed) or
# ngx_http_cache_turbo_zone_stripe() (zone-wide), which are the only two
# functions allowed to index ->stripes[].
#
# The failure this guards against is not cosmetic. A site that keeps a bare
# `z->shpool` picks stripe 0 unconditionally while a neighbouring site asks the
# resolver -- so once N > 1 the module locks pool A's mutex and frees into pool
# B's arena. That is heap corruption under the wrong lock: silent, delayed, and
# unattributable to the commit that caused it. At N == 1 both spellings are
# identical, which is exactly why a stray site cannot be caught by any test and
# has to be caught structurally, here, while the two are still equivalent.
#
# Permitted exceptions, and why each is safe:
#   - src/ngx_http_cache_turbo_module.h -- defines the resolvers themselves.
#   - shm_init_zone() in src/ngx_http_cache_turbo_shm.c -- ESTABLISHES the
#     stripe. It writes through a local `st` obtained from the resolver, so it
#     names ->sh / ->shpool on a STRIPE pointer, never on a zone.
#
# SECOND CHECK (s3c prerequisite): the resolver-choice check above accepts
# EITHER resolver, so it cannot tell a KEY-DIRECTED site that wrongly took the
# zone-wide spelling from a genuinely zone-wide one. Both compile, and at
# N == 1 both behave identically -- so the gate could report ok while
# ngx_http_cache_turbo_stripe_of() had ZERO call sites in the entire module,
# which is exactly the state s3b left behind. A key-directed site pinned to
# stripe 0 is the same cross-pool free the first check guards against, just
# spelled legally.
#
# Because "which sites are key-directed" is a judgement call and not a grep,
# this is enforced as an EXPECTATION LEDGER rather than an inference: the
# functions known to be key-directed are listed in KEY_DIRECTED below with the
# state of their conversion. The lint fails when reality and the ledger
# disagree in EITHER direction --
#
#   - a ledger entry marked `converted` whose function does not call
#     stripe_of()  ->  the conversion was reverted or never landed;
#   - a ledger entry marked `pending` whose function DOES call stripe_of()
#     ->  good news, but the ledger (and docs/stripe-seam.md, and the s3c debt
#         list) must be updated in the same commit, or the next reader trusts
#         a stale map;
#   - zero stripe_of() call sites while any entry is `converted`  ->  the
#     vacuous-green state described above.
#
# So the gate cannot sit green on an unchanged, unstriped module while
# claiming the seam is ready for N > 1. It reports the pending count out loud
# on every run.
#
# Usage: ci/tools/lint-stripe-seam.sh [src-file ...]   (defaults to src/*.c)

set -euo pipefail

# ../.. -- repo root. This script lives in ci/tools/. Getting this climb wrong
# is how lint-shm-lock.sh spent months vacuously green; the empty-selection
# guard below is the second half of that lesson.
cd "$(dirname "$0")/../.."

if [ "$#" -gt 0 ]; then
    files=("$@")
else
    files=(src/*.c)
fi

if [ "${#files[@]}" -eq 0 ] || [ ! -f "${files[0]}" ]; then
    echo "lint-stripe-seam: no source files matched (${files[*]}) -- refusing to report ok on an empty scan" >&2
    exit 2
fi

status=0

for f in "${files[@]}"; do
    [ -f "$f" ] || continue

    awk -v file="$f" '
        # Drop comments: the sources discuss "z->shpool->mutex" in prose all
        # over, and a lint that fires on the explanation of an invariant is a
        # lint people delete.
        { line = $0; sub(/\/\/.*/, "", line) }
        line ~ /^[[:space:]]*\*/   { next }
        line ~ /^[[:space:]]*\/\*/ { next }

        # Track whether we are inside shm_init_zone(), the one function that is
        # allowed to name ->sh / ->shpool -- and only on its resolver-derived
        # `st`, which the second pattern below still holds it to.
        /^ngx_http_cache_turbo_shm_init_zone\(/ { in_init = 1 }
        in_init && /^}/                         { in_init = 0; next }

        # A bare zone dereference: <ident>->sh or <ident>->shpool where the
        # identifier is NOT a stripe pointer. Inside init, `st->` is the
        # sanctioned spelling and is skipped; everywhere else nothing is.
        # NOTE: no \b anywhere below. POSIX awk (and mawk) have no word-boundary
        # escape -- gawk silently treats \b as a backspace, so a pattern written
        # with it matches nothing and the lint reports ok having detected
        # nothing. That is precisely the vacuous-gate class the header of this file
        # warns about, and it was caught here by planting all three violations
        # and watching two of them sail through. Word edges are spelled with
        # explicit character classes, and the string is padded so a match at the
        # very start or end of the line still has a neighbour to test.
        {
            probe = " " line " "
            # Inside init the sanctioned spelling is `st->sh` / `st->shpool` on
            # the resolver-derived stripe pointer. Blank exactly that out (with
            # its left word edge, so `dst->sh` is NOT excused) and judge what is
            # left.
            if (in_init) { gsub(/([^A-Za-z0-9_])st->(sh|shpool)([^A-Za-z0-9_])/, " X ", probe) }

            if (probe ~ /[A-Za-z_][A-Za-z0-9_]*->shpool[^A-Za-z0-9_]/ ||
                probe ~ /[A-Za-z_][A-Za-z0-9_]*->sh[^A-Za-z0-9_]/) {
                trimmed = line
                sub(/^[[:space:]]+/, "", trimmed)
                printf "%s:%d: bare zone shm dereference outside the stripe resolver: %s\n", \
                       file, FNR, trimmed
                bad = 1
            }
        }

        # Only the resolvers may index the stripe array, and they live in the
        # header -- so any ->stripes[ in a .c file is a hand-picked pool.
        line ~ /->stripes\[/ {
            trimmed = line
            sub(/^[[:space:]]+/, "", trimmed)
            printf "%s:%d: direct ->stripes[] index outside the resolver: %s\n", \
                   file, FNR, trimmed
            bad = 1
        }

        END { exit bad ? 1 : 0 }
    ' "$f" || status=1
done

if [ "$status" -ne 0 ]; then
    echo "FAIL: a site reaches a stripe's pool without going through the resolver (P4-2-s3b)." >&2
    echo "      Use ngx_http_cache_turbo_zone_sh(z) / _zone_pool(z) / _zone_mutex(z)," >&2
    echo "      or ngx_http_cache_turbo_stripe_of(z, key) when the site is key-directed." >&2
    exit 1
fi


# ---------------------------------------------------------------------------
# The key-directed expectation ledger (see the SECOND CHECK note in the header).
#
# One row per function that operates on a SINGLE cache key's node and therefore
# must resolve its stripe from that key's hash once N > 1. Format:
#
#     <state>:<function-name>
#
#   converted -- must contain a stripe_of() call. Reverting it fails the lint.
#   pending   -- must NOT yet contain one; it still takes the zone-wide
#                spelling and is blocked on the s3c pool carving (a stripe-K
#                mutex cannot guard stripe-0's rbtree/LRU/used_bytes, so these
#                cannot be converted one at a time -- see docs/stripe-seam.md).
#                Converting one flips its row to `converted` IN THE SAME COMMIT.
#
# Adding a new key-directed function without a row here is not detectable by
# this lint; docs/stripe-seam.md § Maintaining the ledger says to add the row.
# ---------------------------------------------------------------------------
KEY_DIRECTED="
pending:ngx_http_cache_turbo_shm_lookup
pending:ngx_http_cache_turbo_shm_store_locked
pending:ngx_http_cache_turbo_shm_store
pending:ngx_http_cache_turbo_shm_store_if
pending:ngx_http_cache_turbo_shm_store_marker
pending:ngx_http_cache_turbo_shm_purge_key
pending:ngx_http_cache_turbo_shm_freshen
pending:ngx_http_cache_turbo_shm_drop_locked
pending:ngx_http_cache_turbo_shm_admit
pending:ngx_http_cache_turbo_shm_claim
pending:ngx_http_cache_turbo_shm_claim_locked
pending:ngx_http_cache_turbo_shm_unstub
pending:ngx_http_cache_turbo_shm_owns
pending:ngx_http_cache_turbo_shm_resolve_miss
pending:ngx_http_cache_turbo_shm_l2_neg_check
pending:ngx_http_cache_turbo_shm_l2_neg_set
pending:ngx_http_cache_turbo_shm_varidx_pending_set
pending:ngx_http_cache_turbo_shm_touch_lru
"

# Does function $1 (definition through its column-0 closing brace) call
# stripe_of()? Comments are stripped so the prose about the resolver in these
# functions' headers cannot be mistaken for a call. Prints "yes"/"no"; exits 2
# if the function cannot be found at all, which is a moved/renamed function and
# a stale ledger, not a pass.
fn_calls_stripe_of() {
    awk -v fn="$1" '
        { line = $0; sub(/\/\/.*/, "", line) }
        line ~ /^[[:space:]]*\*/   { next }
        line ~ /^[[:space:]]*\/\*/ { next }

        !on && index(line, fn "(") == 1 { on = 1; found = 1 }
        on && index(line, "ngx_http_cache_turbo_stripe_of(") > 0 { calls = 1 }
        on && line ~ /^}/ { on = 0 }

        END {
            if (!found) { exit 2 }
            print calls ? "yes" : "no"
        }
    ' src/*.c
}

# A whole-tree floor, independent of the per-function rows: if ANY row claims
# `converted`, the module must contain at least one real stripe_of() call site.
# grep -c over the sources with comments left in would count the prose, so the
# count is derived from the per-function answers below instead.
ledger_status=0
pending=0
converted=0

while IFS= read -r row; do
    [ -n "$row" ] || continue
    state="${row%%:*}"
    fn="${row#*:}"

    if ! answer="$(fn_calls_stripe_of "$fn")"; then
        echo "$fn: listed in the key-directed ledger but not found in src/*.c" >&2
        echo "    -- it was moved or renamed; update KEY_DIRECTED in $0." >&2
        ledger_status=1
        continue
    fi

    case "$state:$answer" in
        converted:yes) converted=$((converted + 1)) ;;
        pending:no)    pending=$((pending + 1)) ;;

        converted:no)
            echo "$fn: ledgered as 'converted' but calls no stripe_of()." >&2
            echo "    -- the key-directed conversion was reverted; it now pins" >&2
            echo "       stripe 0 while its ledger row claims otherwise." >&2
            ledger_status=1
            ;;

        pending:yes)
            echo "$fn: calls stripe_of() but is ledgered as 'pending'." >&2
            echo "    -- flip its row to 'converted' in $0 and update" >&2
            echo "       docs/stripe-seam.md in the SAME commit, so the s3c" >&2
            echo "       debt list does not go stale." >&2
            ledger_status=1
            ;;
    esac
done <<EOF
$KEY_DIRECTED
EOF

if [ "$ledger_status" -ne 0 ]; then
    echo "FAIL: the key-directed ledger and the code disagree (P4-2-s3c)." >&2
    exit 1
fi

echo "ok: stripe seam holds (no pool reached outside the resolver)"
echo "ok: key-directed ledger agrees with the code" \
     "($converted converted, $pending pending the s3c pool carving)"
