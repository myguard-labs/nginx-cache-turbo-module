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

echo "ok: stripe seam holds (no pool reached outside the resolver)"
