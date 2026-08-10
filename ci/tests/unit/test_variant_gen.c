/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * AUD-GEN1, asserted against the REAL ngx_http_cache_turbo_variant_hash()
 * rather than a mirror of it. The function body is sliced verbatim from
 * src/ngx_http_cache_turbo_module.c by extract_variant_hash.sh into
 * generated_variant.inc; the digest is the real EVP/SHA-256. Only nginx's
 * scalar surface is shimmed (ngx_shim_variant.h).
 *
 * This exists because test_vary_gen.c -- which is kept, and tests something
 * else -- MIRRORS the arithmetic instead of linking it. A mirror cannot catch
 * drift between itself and production (rejected-test item 5): both could be
 * wrong in the same way. These assertions run production's own bytes.
 *
 * The claim under test
 * --------------------
 * The auto-Vary purge generation is a ONE-BYTE counter: marker_store writes
 * `blob[HDR_WIRE+1] = (u_char)(gen & 0xFF)`, so the 256th purge on a base
 * truncates back to 0 -- the same stored byte as a base that was NEVER purged.
 *
 * Historically variant_hash SKIPPED the generation fold when gen == 0 (a
 * "never purged" sentinel kept for pre-COR-5 upgrade compatibility). That made
 * the wrap land exactly on the untagged keyspace, so a base purged 256 times
 * computed the IDENTICAL variant key as one never purged, and a still-resident
 * sibling could resurrect as a live HIT.
 *
 * The fix folds the generation UNCONDITIONALLY, including gen == 0. What that
 * does and does not close:
 *
 *   - closed:   the wrapped 256th purge no longer computes the PRE-COR-5
 *               untagged key. gen 0 now folds "gen=0" instead of nothing, so
 *               the legacy un-generationed keyspace is vacated and a stale
 *               sibling sitting in it can no longer be hit.
 *   - NOT closed: gen N vs gen N+256 on the same base. The read path loads gen
 *               as ONE byte (module.c ~11816), so variant_hash only ever sees
 *               0..255 and the two are literally the same input. AUD-GEN1
 *               records this as an accepted limit with a byte-widening
 *               follow-up left open.
 *
 * Both are asserted. The second is asserted as a COLLISION on purpose: it pins
 * the accepted trade-off, so if the counter is ever widened this test flips to
 * red and forces the follow-up to update it deliberately rather than silently.
 *
 * Mutation (step 24 negative control), verified 2026-08-10
 * -------------------------------------------------------
 * Reintroducing the old sentinel guard around the fold in
 * src/ngx_http_cache_turbo_module.c:
 *
 *     if (gen > 0) {                      <-- the pre-COR-5 behaviour
 *         u_char gbuf[NGX_INT_T_LEN];
 *         ...
 *     }
 *
 * makes never_purged_folds_its_generation() FAIL: with the guard, gen 0 folds
 * nothing, so its digest becomes byte-identical to the untagged pre-COR-5
 * digest. Restored after the run.
 *
 * An EARLIER version of this test asserted that gen 0 and gen 256 produce
 * different digests, and the mutation SURVIVED it: 256 is > 0, so the guard
 * still folded "gen=256" and the two differed for the wrong reason. That is
 * rejected-test item 8, and it is why the assertion is now written against the
 * untagged digest -- the state production can actually reach.
 *
 * Note extract_variant_hash.sh ALSO rejects the guarded shape at build time --
 * to observe the test failing rather than the extractor, the mutation must be
 * run with the extractor's fold guard temporarily bypassed (rejected-test item
 * 10: confirm the mutated build actually compiled and ran).
 */

#include "ngx_shim_variant.h"

#include <stdarg.h>

#include "generated_variant.inc"

/* One base key for every assertion, so a digest difference is always the
 * generation and never the base. */
#define VARIANT_TEST_BASE  "https://example.test/asset.css"

static int  failures;

#define CHECK(cond, msg)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (msg));   \
            failures++;                                                       \
        }                                                                     \
    } while (0)

/* The one-byte store marker_store performs, as an explicit step: the tests
 * feed variant_hash what the WIRE would carry, not what the caller intended. */
static ngx_uint_t
stored_gen(ngx_uint_t gen)
{
    return (ngx_uint_t) ((u_char) (gen & 0xFF));
}

/* The pre-COR-5 / un-generationed variant key for the same base: base bytes
 * only, no "\x1Fgen=" segment. Built from the SAME real digest primitives the
 * sliced function uses, not from a recorded constant -- a hardcoded expected
 * digest would be rejected-test item 2.
 *
 * This models the keyspace the old sentinel produced for gen == 0. It is the
 * thing gen 0 must no longer collide with. */
static void
digest_of_untagged(u_char out[32])
{
    ngx_http_cache_turbo_digest_t  d;
    ngx_str_t                      base;

    base.data = (u_char *) VARIANT_TEST_BASE;
    base.len  = strlen(VARIANT_TEST_BASE);

    ngx_http_cache_turbo_digest_init(&d);
    ngx_http_cache_turbo_digest_update(&d, base.data, base.len);
    ngx_http_cache_turbo_digest_final(&d, out);
}

static void
digest_of(ngx_uint_t gen, u_char out[32])
{
    ngx_str_t  base;

    base.data = (u_char *) VARIANT_TEST_BASE;
    base.len  = strlen(VARIANT_TEST_BASE);

    /* bits == 0: no vary axis, so `r` is never dereferenced. r == NULL is
     * deliberate -- if a future edit reaches a classifier on this path the
     * shim aborts instead of returning a shimmed value. */
    ngx_http_cache_turbo_variant_hash(NULL, &base, 0, gen, out);
}


/* The collision AUD-GEN1 closed: a base that was never purged must not compute
 * the same variant key as one purged 256 times, even though both store the
 * byte 0.
 *
 * This is the assertion the old `if (gen > 0)` sentinel breaks. */
static void
never_purged_folds_its_generation(void)
{
    u_char  never[32], tagged[32];

    /* The read path (module.c ~11816) loads `gen` as ONE byte out of the
     * marker, so variant_hash only ever sees 0..255: the 256th purge arrives
     * as gen == 0, byte-identical to never-purged. The two states are
     * therefore NOT separable by the digest, and asserting that they differ
     * would be asserting something production cannot do.
     *
     * What the fix actually changed is that gen == 0 is folded at all. Before
     * it, gen 0 fed NOTHING to the digest, so the wrapped 256th purge computed
     * the pre-COR-5 untagged key and collided with the whole legacy keyspace.
     * After it, gen 0 folds "gen=0" like any other value -- the untagged
     * keyspace is vacated, which is what stops the resurrection.
     *
     * So the assertion is: the gen-0 digest must NOT equal the digest of the
     * same base with no generation folded at all. That is exactly what the
     * sentinel guard reintroduces, and it is what the mutation must break. */
    CHECK(stored_gen(256) == 0,
          "precondition: the 256th generation must truncate to byte 0");

    digest_of(0, never);
    digest_of_untagged(tagged);

    CHECK(memcmp(never, tagged, 32) != 0,
          "gen 0 must fold \"gen=0\" rather than nothing (AUD-GEN1); equal to "
          "the untagged digest means the fold is guarded on gen != 0 again and "
          "the wrapped 256th purge collides with the pre-COR-5 keyspace");
}


/* The residual limit AUD-GEN1 accepts: N and N+256 are indistinguishable once
 * stored, because only one byte survives. Asserted so the accepted trade-off is
 * pinned rather than assumed. */
static void
same_stored_byte_collides_by_design(void)
{
    u_char  a[32], b[32];

    CHECK(stored_gen(3) == stored_gen(259),
          "precondition: gen 3 and gen 259 must store the same byte");

    digest_of(stored_gen(3), a);
    digest_of(stored_gen(259), b);

    CHECK(memcmp(a, b, 32) == 0,
          "generations sharing a stored byte collide by design; a DIFFERENCE "
          "here means the counter was widened -- update AUD-GEN1 and this test");
}


/* Distinct generations that do NOT share a stored byte must produce distinct
 * keys. Without this, a fold that ignored `gen` entirely would still satisfy
 * the two tests above (rejected-test item 1: an assertion that holds in both
 * the pass and the fail state). */
static void
distinct_generations_differ(void)
{
    u_char  g1[32], g2[32], g255[32];

    digest_of(1, g1);
    digest_of(2, g2);
    digest_of(255, g255);

    CHECK(memcmp(g1, g2, 32) != 0, "gen 1 and gen 2 must differ");
    CHECK(memcmp(g2, g255, 32) != 0, "gen 2 and gen 255 must differ");
    CHECK(memcmp(g1, g255, 32) != 0, "gen 1 and gen 255 must differ");
}


/* The digest must actually depend on the base key too -- a fold that hashed
 * only the generation would pass everything above. */
static void
base_key_still_folded(void)
{
    u_char     one[32], two[32];
    ngx_str_t  base;

    base.data = (u_char *) "https://example.test/a";
    base.len  = strlen("https://example.test/a");
    ngx_http_cache_turbo_variant_hash(NULL, &base, 0, 7, one);

    base.data = (u_char *) "https://example.test/b";
    base.len  = strlen("https://example.test/b");
    ngx_http_cache_turbo_variant_hash(NULL, &base, 0, 7, two);

    CHECK(memcmp(one, two, 32) != 0,
          "different base keys must produce different variant keys");
}


int
main(void)
{
    never_purged_folds_its_generation();
    same_stored_byte_collides_by_design();
    distinct_generations_differ();
    base_key_still_folded();

    if (failures) {
        fprintf(stderr, "test_variant_gen: %d failure(s)\n", failures);
        return 1;
    }

    printf("test_variant_gen: all assertions passed\n");
    return 0;
}
