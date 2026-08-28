#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Enforce that every ngx_http_cache_turbo_shctx_t member is explicitly
# initialised at zone carve (CARVE-INIT).
#
# WHY THIS CANNOT BE A RUNTIME TEST. The shctx is carved once per zone by a
# single ngx_slab_alloc() in ngx_http_cache_turbo_shm_init_zone(), which
# does NOT zero
# its return -- but on the fresh-carve path the slab arena is backed by freshly
# mapped anonymous memory, which the kernel hands over already zeroed. So an
# omitted initialiser reads 0 anyway, every test passes, and the omission is
# invisible from the outside. The correctness of ~70 counters, gauges and
# token sources therefore rests on an allocator property that nothing in the
# module asserts and that one ngx_slab_calloc free-list reuse would end. That
# is a structural invariant, so it needs a structural gate -- the same shape of
# argument as lint-stripe-seam.sh, which is likewise invisible at today's N==1.
#
# The audit that prompted this (2026-08) was performed by eye and named five
# missing fields. Re-running it mechanically found EIGHT: markers, bg_inflight
# and owner_seq had been missed by the same reading that produced the list.
# owner_seq is the one that would have hurt -- claim() issues ++owner_seq as a
# never-reused single-flight token, and a garbage start can collide with a
# recycled node's stale refresh_owner. That miss rate is the case for this
# file existing: the manual pass is not reliable at this member count.
#
# WHAT IT CHECKS. Every member declared in ngx_http_cache_turbo_shctx_t must
# appear as an `sh->NAME =` assignment inside the carve block of
# ngx_http_cache_turbo_shm_init_zone().
# Explicit padding members (_pad*) are exempt: they are layout, never read.
#
# Usage: ci/tools/lint-carve-init.sh   (no arguments; the invariant spans a
#                                       fixed pair of files)
# Exit:  0 clean, 1 a member has no initialiser, 2 could not run.

set -euo pipefail

# ../.. -- the REPO ROOT. This script lives in ci/tools/, so one climb lands in
# ci/, where the paths below match nothing. lint-shm-lock.sh spent months
# vacuously green on exactly that mistake; the guards below make an empty scan
# exit 2 rather than report ok.
cd "$(dirname "$0")/../.."

HDR=src/ngx_http_cache_turbo_module.h
SRC=src/ngx_http_cache_turbo_shm.c

for f in "$HDR" "$SRC"; do
    [ -f "$f" ] || {
        echo "lint-carve-init: $f missing -- refusing to report ok on an empty scan" >&2
        exit 2
    }
done

# --- 1. the declared members -------------------------------------------------
#
# Delimited by the struct's own opening and closing lines rather than fixed line
# numbers, so the check follows the struct as the header is edited. Comment
# bodies are dropped first (a `*`-prefixed continuation line can otherwise end
# in `;` and read as a declaration), then any line ending in `;` at one level of
# brace nesting is a member and its name is the last identifier before the `;`,
# past any array bound or __attribute__.
#
# Both delimiters are REQUIRED to have matched. An awk that only sets `inside`
# on the opener runs to end-of-file when the closing line changes spelling, and
# harvests the members of every struct that follows -- reporting a screenful of
# bogus names as "uninitialised" (exit 1) instead of admitting it could not
# parse (exit 2). Caught by mutation: renaming the closing typedef produced a
# 190-name failure list naming fields of unrelated structs.
members="$(awk '
    /^typedef struct ngx_http_cache_turbo_shctx_s \{/ { inside = 1; opened = 1; next }
    inside && /^\} ngx_http_cache_turbo_shctx_t;/     { inside = 0; closed = 1 }
    /^\}/ && inside && !closed                        { unterminated = 1 }
    !inside { next }
    /^[[:space:]]*\*/  { next }        # block-comment continuation
    /^[[:space:]]*\/\*/ { next }       # block-comment opener
    /^[[:space:]]*#/   { next }        # preprocessor
    {
        line = $0
        sub(/\/\*.*/, "", line)        # trailing comment
        sub(/\/\/.*/, "", line)
        if (line !~ /;/) next
        sub(/;.*/, "", line)
        sub(/__attribute__.*/, "", line)
        # Capture the base type of the declaration BEFORE the array bound is
        # stripped: the _pad* exemption below must be able to prove a member is
        # genuinely `u_char NAME[...]` layout filler and not merely named like
        # it. `raw` keeps the array bracket the name-parse discards.
        raw = line
        gsub(/^[[:space:]]+/, "", raw)
        is_uchar_array = (raw ~ /^u_char[[:space:]]/ && raw ~ /\[[^]]*\]/)
        sub(/\[[^]]*\]/, "", line)     # array bound
        gsub(/[[:space:]]+$/, "", line)
        # A declaration may carry several declarators: `ngx_uint_t a, b;`.
        # Taking only the last identifier would hide every earlier name from
        # the gate permanently, so split on ',' and take the last identifier of
        # EACH declarator. Latent when written (the struct has no comma
        # declarators today); fixed so adding one cannot silently open a hole.
        ndecl = split(line, decls, /,/)
        for (d = 1; d <= ndecl; d++) {
            piece = decls[d]
            sub(/\[[^]]*\]/, "", piece)      # per-declarator array bound
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", piece)
            if (piece == "") continue
            n = split(piece, parts, /[[:space:]*]+/)
            if (n == 0) continue
            name = parts[n]
            if (name ~ /^[A-Za-z_][A-Za-z0-9_]*$/) {
                # Tag pad-eligibility onto the name so the exemption is a
                # TYPE decision, not a name-prefix one.
                if (is_uchar_array) print name "\tpadok"
                else               print name "\t-"
            }
        }
    }
    END {
        if (!opened) { print "ERR:no-opening-line" > "/dev/stderr"; exit 3 }
        if (!closed) { print "ERR:no-closing-line" > "/dev/stderr"; exit 3 }
        if (unterminated) { print "ERR:unterminated" > "/dev/stderr"; exit 3 }
    }
' "$HDR" | sort -u)" || {
    echo "lint-carve-init: could not delimit ngx_http_cache_turbo_shctx_t in $HDR -- its opening 'typedef struct ngx_http_cache_turbo_shctx_s {' or closing '} ngx_http_cache_turbo_shctx_t;' line has changed. Refusing to guess at the member set." >&2
    exit 2
}

if [ -z "$members" ]; then
    echo "lint-carve-init: parsed ZERO members from $HDR -- refusing to report ok on an empty scan" >&2
    exit 2
fi

# $members rows are "NAME<TAB>padok|-". Keep the tagged list for the exemption
# decision below and derive a bare-name list for counting.
member_names="$(printf '%s\n' "$members" | cut -f1)"

# --- 2. the members the carve block initialises ------------------------------
#
# Bounded to the CARVE BLOCK, not the whole function: an `sh->x = ...` store
# anywhere else in the file -- and, critically, anywhere else in this same
# function -- must not count as carve initialisation.
#
# The window opens at the `st->sh = ngx_slab_alloc(` line and closes at the
# first column-0 `}`. It deliberately does NOT open at the function's opening
# line, because ngx_http_cache_turbo_shm_init_zone() has two early-return
# branches ABOVE the slab alloc -- the `octx` reload inherit and the
# `shm.exists` branch -- each of which legitimately stores `st->sh->admission`.
# A window starting at the function opener swallows both, so a member
# initialised ONLY in a reload branch would satisfy the gate. That placement is
# exactly what the FAIL message below tells the developer not to do: it never
# runs on a fresh carve, and on reload it overwrites inherited live state.
# Caught by the agent review of this commit, reproduced by mutation.
#
# TWO accepted forms, because the block legitimately uses both:
#   assignment       st->sh->hits = 0;
#   initialiser call ngx_rbtree_init(&st->sh->rbtree, ...) / ngx_queue_init(&st->sh->lru)
# The second is matched on `&...sh->NAME` -- passing a member's address to an
# init helper is how the rbtree, its sentinel and the two queue heads are set
# up, and treating those as uninitialised would make the gate unsatisfiable.
# Note this deliberately does not try to prove the callee initialises what it
# is handed; that is beyond a textual gate. It proves the member was not
# FORGOTTEN, which is the failure class here.
inits="$(awk '
    # the carve block starts at the slab alloc, NOT at the function opener --
    # see the comment above. Track the function too, so a same-named store in
    # a LATER function cannot reopen the window.
    /^ngx_http_cache_turbo_shm_init_zone\(/ { infn = 1 }
    infn && /st->sh[[:space:]]*=[[:space:]]*ngx_slab_alloc\(/ { inside = 1 }
    /^\}/ { if (inside) { inside = 0 } ; infn = 0 }
    !inside { next }
    {
        line = $0
        # assignment form
        rest = line
        # `[^-+*/%&|^<>!=]=[^=]` so a compound assignment (+=, |=, &=, ...) is
        # NOT read as carve initialisation -- it mutates a value that must
        # already exist. Latent when written: zero compound assigns in the
        # carve block today.
        while (match(rest, /sh->[A-Za-z_][A-Za-z0-9_]*[[:space:]]*[^-+*\/%&|^<>!=[:space:]]?=[^=]/)) {
            s = substr(rest, RSTART + 4, RLENGTH - 4)
            sub(/[[:space:]]*=.*/, "", s)
            print s
            rest = substr(rest, RSTART + RLENGTH)
        }
        # Address-of form (initialiser call). Restricted to a KNOWN
        # INITIALISER allowlist: taking the address of a member proves nothing
        # on its own -- `memcmp(&st->sh->misses, ...)` is a pure READ and used
        # to satisfy this gate, which is a silent-green false negative. Only a
        # call that actually initialises what it is handed counts.
        if (line ~ /(ngx_rbtree_init|ngx_queue_init|ngx_memzero|ngx_rbtree_sentinel_init)[[:space:]]*\(/) {
        rest = line
        while (match(rest, /&[A-Za-z_][A-Za-z0-9_.>-]*sh->[A-Za-z_][A-Za-z0-9_]*/)) {
            s = substr(rest, RSTART, RLENGTH)
            sub(/.*sh->/, "", s)
            print s
            rest = substr(rest, RSTART + RLENGTH)
        }
        }
    }
' "$SRC" | sort -u)"

if [ -z "$inits" ]; then
    echo "lint-carve-init: parsed ZERO initialisers from $SRC -- shm_init_zone's signature or brace style must have changed; this checker cannot report ok on an empty scan" >&2
    exit 2
fi

# --- 3. the difference -------------------------------------------------------
#
# _pad* members are explicit layout filler. Nothing reads them, so they are the
# one class that legitimately needs no store.
#
# The exemption is a TYPE decision, not a name-prefix one. A member is exempt
# only when it is BOTH named _pad* AND declared `u_char NAME[...]` -- the
# harvest above tags that as "padok". Prefix alone was a silent-green hole: an
# `ngx_uint_t _pad_but_real` that something actually reads was exempted and the
# gate reported ok, which is the exact failure class this checker exists to
# catch. A _pad*-named member of any other type is now a FAIL, not an exemption.
missing=""
mistyped_pad=""
while IFS="$(printf '\t')" read -r m tag; do
    [ -n "$m" ] || continue
    case "$m" in
        _pad*)
            if [ "$tag" = "padok" ]; then
                continue
            fi
            mistyped_pad="$mistyped_pad $m"
            ;;
    esac
    printf '%s\n' "$inits" | grep -qx -- "$m" || missing="$missing $m"
done <<EOF
$members
EOF

if [ -n "$mistyped_pad" ]; then
    echo "FAIL: member(s) named _pad* but NOT declared 'u_char NAME[...]':" >&2
    for m in $mistyped_pad; do
        echo "        $m" >&2
    done
    echo "      The _pad* exemption covers layout filler only. Either declare it" >&2
    echo "      as a u_char array, or rename it and initialise it at the carve." >&2
    exit 1
fi

if [ -n "$missing" ]; then
    echo "FAIL: ngx_http_cache_turbo_shctx_t member(s) never initialised at zone carve:" >&2
    for m in $missing; do
        echo "        $m" >&2
    done
    echo "      ngx_slab_alloc() does not zero. Add an 'st->sh->NAME = ...;' to the" >&2
    echo "      carve block in ngx_http_cache_turbo_shm_init_zone() ($SRC)." >&2
    echo "      Do NOT add it to the shm.exists reload branch: that path deliberately" >&2
    echo "      inherits live state across a SIGHUP and zeroing there would wipe it." >&2
    exit 1
fi

n_checked="$(printf '%s\n' "$member_names" | grep -vc '^_pad' || true)"
echo "ok: all $n_checked shctx members initialised at zone carve (CARVE-INIT)"
