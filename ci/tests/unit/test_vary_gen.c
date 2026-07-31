/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * AUD-GEN1: the auto-Vary purge generation is a ONE-BYTE counter
 * (marker_store's body byte, module.c ~11268: `blob[HDR_WIRE+1] =
 * (u_char)(gen & 0xFF)`), incremented on every base PURGE (module.c ~1856:
 * `marker_store(..., mgen + 1, mttl)`) and folded into the variant digest by
 * `ngx_http_cache_turbo_variant_hash` (module.c ~11150) UNLESS `gen == 0`, in
 * which case the fold is skipped entirely -- gen 0 is documented as the
 * "never purged" sentinel that intentionally reproduces the pre-COR-5,
 * un-generationed variant key (upgrade compatibility).
 *
 * The 256th purge computes mgen+1 == 256, which the one-byte store truncates
 * to 0 -- the SAME value as "never purged". Because gen==0 also means "skip
 * the fold", a base purged exactly 256 times computes the IDENTICAL variant
 * key material as a base that was never purged at all: any variant still
 * resident under that untagged key (routine given L1 LRU / long TTL /
 * `keep_stale forever`) resurrects as a live HIT.
 *
 * This file mirrors (does not include -- variant_hash needs a full
 * ngx_http_request_t + md5 digest we don't want to drag in here) the two
 * functions' OBSERVABLE byte behaviour:
 *
 *   mirror_next_gen()   -- the purge-handler write-site arithmetic
 *   mirror_store_byte() -- marker_store's one-byte truncation
 *   mirror_fold()       -- variant_hash's gen-fold segment: returns the byte
 *                          LENGTH of the "\x1Fgen=<n>" tag fed to the digest,
 *                          or 0 if the fold was skipped.
 *
 * We test byte-length/emptiness of the fold segment rather than reproducing
 * the real md5: two different (gen) inputs collide in the real digest iff
 * they produce byte-identical fold segments (same base, same axis bits, only
 * the gen segment varies) -- so "the fold segment is empty" is exactly the
 * collision-with-the-untagged-keyspace condition AUD-GEN1 describes, and is
 * provable without the real digest.
 *
 * Two mutation macros each REVERT one half of the two-part fix, and are the
 * negative controls for it. An unguarded build is the shipped (fixed)
 * behaviour and passes.
 *
 *   GEN_CTRL_NOSKIPZERO  -- reverts the write-site skip-0-on-wrap
 *                           (module.c ~1856). Fails the "must never fold to
 *                           the SAME key as the genesis state" assertion.
 *   GEN_CTRL_NOFOLDFIX   -- reintroduces the fold-site `gen > 0` guard
 *                           (module.c ~11150). Fails the "genesis key must
 *                           carry an explicit generation tag" assertion.
 *
 * Defining BOTH reproduces the pre-fix code exactly, and is the AUD-GEN1
 * repro: 3 failures, plus the reported counter "empty fold at purge #256
 * ... = 1" -- the 256th purge folding to the same empty segment as the
 * never-purged base. Verified 2026-07-31; each macro also fails alone, so
 * neither half is carried by the other.
 *
 *   cc -DGEN_CTRL_NOSKIPZERO -DGEN_CTRL_NOFOLDFIX test_vary_gen.c -o t && ./t
 */

#include <stdio.h>
#include <string.h>

typedef unsigned long ngx_uint_t;
typedef unsigned char u_char;

/* mirrors the purge-handler write-site call, module.c ~1856.
 * GEN_PRE_FIX: `mgen + 1`, unmasked ngx_uint_t (the pre-fix code as it reads
 * today). Fixed: `(mgen + 1) & 0xFF`, explicit -- store already truncates to
 * one byte internally either way, so this half is self-documentation / a
 * belt-and-braces guard rather than an independent behavioural fix; see the
 * report for why it has no standalone mutation red. */
static ngx_uint_t
mirror_next_gen(ngx_uint_t mgen)
{
    ngx_uint_t next = (mgen + 1) & 0xFF;
#ifndef GEN_CTRL_NOSKIPZERO
    /* AUD-GEN1: 0 is permanently reserved for "never purged" -- once a base
     * has been purged at all, its generation must never again equal the
     * identity a fresh, unpurged base uses (module.c ~1856-1874). Without
     * this, dropping the fold-site `gen > 0` guard alone still lets a
     * 256-purge sequence resolve back to the SAME key as the base's own
     * pre-first-purge state (proven by a real runtime round trip, not just
     * reasoned about -- see the report on this ledger item). */
    if (next == 0) {
        next = 1;
    }
#endif
    return next;
}

/* mirrors marker_store's body-byte write, module.c ~11268. Unconditional in
 * both pre- and post-fix code -- this is the one-byte storage width itself,
 * not part of the AUD-GEN1 pair fix (widening it is the optional, NOT
 * required, follow-up the ledger row flags). */
static u_char
mirror_store_byte(ngx_uint_t gen)
{
    return (u_char) (gen & 0xFF);
}

/* mirrors variant_hash's gen-fold segment, module.c ~11150. Returns the
 * number of bytes that would be fed to the digest for this generation value;
 * 0 == the fold was skipped == the input is byte-identical to the untagged /
 * no-marker keyspace.
 *
 * GEN_CTRL_NOFOLDFIX reintroduces the reverted-independently `if (gen > 0)`
 * guard (mutation check #2); unguarded build = the shipped fix (fold always
 * runs). */
static size_t
mirror_fold(ngx_uint_t gen, char *out, size_t outsz)
{
#ifdef GEN_CTRL_NOFOLDFIX
    if (gen == 0) {
        return 0;
    }
#endif
    {
        int n = snprintf(out, outsz, "\x1Fgen=%lu", (unsigned long) gen);
        if (n < 0) {
            return 0;
        }
        return (size_t) n;
    }
}

static int checks   = 0;
static int failures = 0;

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        checks++;                                                            \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (msg));  \
        }                                                                    \
    } while (0)

/* Round trip: simulate a fresh base (marker starts absent -> mgen=0) taken
 * through 257 real purges the same way the purge handler does -- read the
 * marker's current gen, compute next, store it, and let the NEXT iteration's
 * "read" be exactly what was stored. Records the stored byte at every step,
 * and the fold-segment length variant_hash would compute for a request that
 * resolves the marker RIGHT AFTER that purge (the resurrection window: a
 * request between the purge and the next real store). */
static void
test_purge_sequence_257(void)
{
    ngx_uint_t mgen = 0;   /* never-purged marker; matches vary_resolve's
                             * default when no marker exists yet (module.c
                             * ~11329: `ctx->vary_gen = gen;` with gen==0). */
    char        buf[64];
    char        genesis_buf[64];
    size_t      genesis_len;
    size_t      empty_at_256 = 0, empty_at_0 = 0;
    ngx_uint_t  i;

    /* gen==0, pre-any-purge: the key material a fresh, never-purged base's
     * FIRST classified response is stored under (module.c ~8137-8139: the
     * store path reuses ctx->vary_gen, left at 0 by vary_resolve when no
     * marker existed yet). This is the exact bucket AUD-GEN1 says a
     * 256-purge wrap resurrects -- kept for the collision check below, not
     * only the emptiness check (which only holds pre-fix). */
    genesis_len = mirror_fold(mgen, genesis_buf, sizeof(genesis_buf));
    if (genesis_len == 0) {
        empty_at_0 = 1;
    }

    /* HEADLINE ASSERTION #0 (AUD-GEN1, the fold-guard half in isolation):
     * even the genesis (gen==0, never-purged) key must carry an explicit
     * "gen=0" tag -- fold must never skip, for ANY generation, including 0.
     * This is what closes the collision with the pre-COR-5 / no-marker
     * untagged keyspace (a marker-absent request never calls variant_hash at
     * all, so its base-key bytes can never match a tagged fold output). Red
     * ON ITS OWN under GEN_CTRL_NOFOLDFIX regardless of skip-zero, which is
     * the fold-guard mutation's independent proof (skip-zero alone hides
     * this half's regression from assertion #2 below, since it stops any
     * PURGED generation from ever reading back as 0 -- but genesis itself is
     * gen==0 by definition and always exercises the fold-guard). */
    CHECK(genesis_len > 0, "the genesis (never-purged) key must carry an "
                           "explicit generation tag, not fold to empty");

    for (i = 1; i <= 257; i++) {
        ngx_uint_t next  = mirror_next_gen(mgen);
        u_char     stored = mirror_store_byte(next);
        ngx_uint_t read_back = stored;   /* mirrors vary_resolve reading the
                                            * one byte back, module.c ~11321. */
        size_t     flen;

        flen = mirror_fold(read_back, buf, sizeof(buf));
        if (flen == 0 && i == 256) {
            empty_at_256 = 1;
        }

        /* HEADLINE ASSERTION #1 (AUD-GEN1): no generation that has gone
         * through at least one real purge may compute the EMPTY fold segment
         * -- an empty segment there is byte-identical to the
         * untagged/never-purged keyspace. PRE-FIX this fires at i == 256
         * (the truncation wrap); dropping the fold-site `gen > 0` guard
         * closes it for every i in 1..257. */
        CHECK(flen > 0, "purged generation must never fold to empty "
                        "(collides with the untagged/never-purged keyspace)");

        /* HEADLINE ASSERTION #2 (AUD-GEN1, the actual resurrection): a
         * purged generation's key material must differ from GENESIS (the
         * never-purged state) -- otherwise a request right after this purge
         * resolves to whatever is still resident under the base's
         * pre-first-purge slot and serves it as a live HIT. A REAL 256-purge
         * runtime round trip caught this failing when only the fold-site
         * guard was dropped (mask + unconditional fold, no write-side
         * skip-zero): i==256 truncates the stored byte back to 0, and
         * post-fold(0) == genesis-fold(0) byte-for-byte -- both are the SAME
         * numeric identity once stored in one byte, unconditional folding or
         * not. Skipping 0 on wrap (GEN_CTRL_NOSKIPZERO reverts this) is what
         * actually closes it: 0 becomes permanently exclusive to "never
         * purged", so no purge sequence can ever reproduce it again. */
        CHECK(!(flen == genesis_len && memcmp(buf, genesis_buf, flen) == 0),
              "a purged generation must never fold to the SAME key as the "
              "genesis (never-purged) state -- resurrection");

        mgen = read_back;
    }

    if (failures > 0) {
        fprintf(stderr,
            "AUD-GEN1: empty fold at gen=0 (pristine, expected under the "
            "current sentinel contract)=%zu; empty fold at purge #256 "
            "(wrap onto the pristine keyspace -- THE BUG)=%zu\n",
            empty_at_0, empty_at_256);
    }
}

/* Sanity: every non-wrapped generation 1..255 must produce a DISTINCT fold
 * segment (no two different purge counts should ever compute the same
 * variant key for the same base+axes). Guards against a careless fix that
 * folds a constant instead of the actual value. */
static void
test_fold_distinct_within_one_cycle(void)
{
    char    bufs[256][64];
    size_t  lens[256];
    ngx_uint_t g, h;

    for (g = 0; g < 256; g++) {
        lens[g] = mirror_fold(g, bufs[g], sizeof(bufs[g]));
    }

    for (g = 0; g < 256; g++) {
        for (h = g + 1; h < 256; h++) {
            int same = (lens[g] == lens[h]
                        && memcmp(bufs[g], bufs[h], lens[g]) == 0);
            CHECK(!same, "two distinct generations in 0..255 must not "
                         "fold to the same digest input");
        }
    }
}

int
main(void)
{
    test_purge_sequence_257();
    test_fold_distinct_within_one_cycle();

    printf("test_vary_gen: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
