/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * P4-2-s3b/s3c: prove the STRIPE RESOLVERS are correct at N > 1 WITHOUT
 * shipping N > 1.
 *
 * The problem this test exists to solve. Production pins
 * NGX_HTTP_CACHE_TURBO_STRIPES at 1, and at N == 1 `anything % 1 == 0`, so
 * ngx_http_cache_turbo_stripe_of() returns &stripes[0] for every possible
 * input. That makes it INDISTINGUISHABLE from a resolver that ignores the key
 * entirely, from one whose modulo is inverted, and from one that is a verbatim
 * copy of the zone-wide resolver. No runtime test on the shipped module can
 * tell those apart -- every one of them is green. The arithmetic only becomes
 * observable at N > 1, so the resolver is compiled here at a FORCED N > 1
 * against a local zone struct: no shm, no slab pool, no nginx tree.
 *
 * What this does NOT claim. It proves the resolver ARITHMETIC only. It does
 * not stand up a real N > 1 zone, because one cannot exist yet: carving N real
 * (sh, shpool) pairs and deciding, per zone-wide field, whether it fans out or
 * pins stripe 0 is s3c's work, and every key-directed call site in src/ still
 * takes the zone-wide spelling (see the classification in docs/stripe-seam.md).
 * This is the arithmetic half of that prerequisite; the lint
 * (ci/tools/lint-stripe-seam.sh) is the call-site half.
 *
 * Hermetic: no nginx headers, no shm, part of ci/tests/unit/run.sh's pure-math
 * lane. The resolver bodies are SLICED FROM PRODUCTION by
 * extract_stripe_resolver.sh, never mirrored.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* Minimal surface the sliced resolvers need. `ngx_inline` is nginx's own
 * spelling; the slice carries it verbatim, so define it rather than edit the
 * slice. */
#define ngx_inline  inline
typedef unsigned long  ngx_uint_t;

/* The forced stripe count. Deliberately NOT NGX_HTTP_CACHE_TURBO_STRIPES: the
 * whole point is to compile the production resolver at a count production does
 * not ship. 8 is a power of two (so a modulo bug that is really a mask still
 * has to distribute) and 7 is co-prime with it (so the odd-N path is covered
 * too, where mask-vs-modulo genuinely differ). */
#define TEST_STRIPES      8u
#define TEST_STRIPES_ODD  7u

typedef struct {
    void  *sh;
    void  *shpool;
} ngx_http_cache_turbo_stripe_t;

typedef struct {
    ngx_http_cache_turbo_stripe_t  stripes[TEST_STRIPES];
    ngx_uint_t                     nstripes;
} ngx_http_cache_turbo_zone_t;

#include "generated_stripe_resolver.inc"

static int failures;

#define CHECK(cond, ...)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);                       \
            printf(__VA_ARGS__);                                              \
            printf("\n");                                                     \
            failures++;                                                       \
        }                                                                     \
    } while (0)

/* Index of the stripe the resolver picked, so assertions read in stripe
 * numbers rather than pointer arithmetic at every call site. */
static long
idx_of(ngx_http_cache_turbo_zone_t *z, ngx_http_cache_turbo_stripe_t *st)
{
    return (long) (st - &z->stripes[0]);
}


/* (1) The fail-safe. A zone whose init has not run has nstripes == 0; the
 * modulo would be a division by zero. Both 0 and 1 must short-circuit. */
static void
test_uninitialised_zone_is_safe(void)
{
    ngx_http_cache_turbo_zone_t  z;

    memset(&z, 0, sizeof(z));

    z.nstripes = 0;
    CHECK(idx_of(&z, ngx_http_cache_turbo_stripe_of(&z, 0)) == 0,
          "nstripes==0 must fail safe to stripe 0");
    CHECK(idx_of(&z, ngx_http_cache_turbo_stripe_of(&z, 0xffffffffu)) == 0,
          "nstripes==0 must fail safe to stripe 0 for any key");

    z.nstripes = 1;
    CHECK(idx_of(&z, ngx_http_cache_turbo_stripe_of(&z, 0xdeadbeefu)) == 0,
          "nstripes==1 must resolve to stripe 0");
}


/* (2) THE SAFETY ARGUMENT FOR THE SHIPPED MODULE. At N == 1 every possible
 * 32-bit key resolves to stripe 0, so converting a call site from the
 * zone-wide spelling to stripe_of() is provably behaviour-identical today.
 * Exhaustive over the whole u32 domain is 4G iterations; the boundaries plus a
 * deterministic spread is the practical equivalent, and the `% 1` identity is
 * total by construction. */
static void
test_n1_is_identity(void)
{
    ngx_http_cache_turbo_zone_t  z;
    uint32_t                     k;
    unsigned                     i;

    static const uint32_t  edge[] = {
        0u, 1u, 2u, 0x7fffffffu, 0x80000000u, 0xfffffffeu, 0xffffffffu
    };

    memset(&z, 0, sizeof(z));
    z.nstripes = 1;

    for (i = 0; i < sizeof(edge) / sizeof(edge[0]); i++) {
        CHECK(idx_of(&z, ngx_http_cache_turbo_stripe_of(&z, edge[i])) == 0,
              "N==1: key 0x%08lx must resolve to stripe 0",
              (unsigned long) edge[i]);
    }

    /* A wide deterministic sweep (LCG, no rand() so the run is reproducible). */
    k = 0x12345678u;
    for (i = 0; i < 200000; i++) {
        k = k * 1103515245u + 12345u;
        CHECK(idx_of(&z, ngx_http_cache_turbo_stripe_of(&z, k)) == 0,
              "N==1: key 0x%08lx must resolve to stripe 0", (unsigned long) k);
        if (failures) {
            return;         /* one counter-example is the whole result */
        }
    }
}


/* (3) Determinism: the SAME key must always land on the SAME stripe. If this
 * failed, a store and its lookup could take different mutexes for one key --
 * the exact heap-corruption class the seam exists to prevent. */
static void
test_same_key_same_stripe(void)
{
    ngx_http_cache_turbo_zone_t  z;
    uint32_t                     k;
    unsigned                     i;
    long                         first;

    memset(&z, 0, sizeof(z));
    z.nstripes = TEST_STRIPES;

    k = 0xa5a5a5a5u;
    for (i = 0; i < 64; i++) {
        k = k * 1103515245u + 12345u;
        first = idx_of(&z, ngx_http_cache_turbo_stripe_of(&z, k));
        CHECK(idx_of(&z, ngx_http_cache_turbo_stripe_of(&z, k)) == first,
              "key 0x%08lx resolved to two different stripes",
              (unsigned long) k);
        CHECK(idx_of(&z, ngx_http_cache_turbo_stripe_of(&z, k)) == first,
              "key 0x%08lx resolved to two different stripes (3rd call)",
              (unsigned long) k);
    }
}


/* (4) THE CLAIM N == 1 CANNOT MAKE: distinct keys reach distinct stripes, and
 * the mapping is exactly `key % nstripes`. This is what falsifies a resolver
 * that ignores its key. */
static void
test_distinct_keys_distinct_stripes(void)
{
    ngx_http_cache_turbo_zone_t  z;
    unsigned                     i;

    memset(&z, 0, sizeof(z));
    z.nstripes = TEST_STRIPES;

    /* Keys 0..N-1 must land on stripes 0..N-1 respectively -- a bijection, so
     * every stripe is reachable and none is aliased. */
    for (i = 0; i < TEST_STRIPES; i++) {
        CHECK(idx_of(&z, ngx_http_cache_turbo_stripe_of(&z, (uint32_t) i))
                  == (long) i,
              "key %u must map to stripe %u", i, i);
    }

    /* And the modulo wraps, rather than saturating or clamping at the top. */
    for (i = 0; i < 4 * TEST_STRIPES; i++) {
        CHECK(idx_of(&z, ngx_http_cache_turbo_stripe_of(&z, (uint32_t) i))
                  == (long) (i % TEST_STRIPES),
              "key %u must map to stripe %u", i, i % TEST_STRIPES);
    }

    /* The u32 top end must not sign-extend or overflow into a negative index:
     * 0xffffffff % 8 == 7. A resolver that let the key go through a signed
     * type would index out of bounds here. */
    CHECK(idx_of(&z, ngx_http_cache_turbo_stripe_of(&z, 0xffffffffu))
              == (long) (0xffffffffu % TEST_STRIPES),
          "top-of-range key must map to stripe %lu",
          (unsigned long) (0xffffffffu % TEST_STRIPES));
}


/* (5) An ODD stripe count. A resolver "optimised" into a bitmask (key & (N-1))
 * agrees with the modulo for every power-of-two N and is wrong for every other
 * N -- so a mask bug is invisible unless an odd count is tested. */
static void
test_odd_stripe_count(void)
{
    ngx_http_cache_turbo_zone_t  z;
    unsigned                     i;

    memset(&z, 0, sizeof(z));
    z.nstripes = TEST_STRIPES_ODD;

    for (i = 0; i < 3 * TEST_STRIPES_ODD; i++) {
        CHECK(idx_of(&z, ngx_http_cache_turbo_stripe_of(&z, (uint32_t) i))
                  == (long) (i % TEST_STRIPES_ODD),
              "odd N: key %u must map to stripe %u", i,
              i % TEST_STRIPES_ODD);
    }

    /* The discriminator itself: at N == 7, key 8 is stripe 1 under a modulo
     * and stripe 0 under a (key & 7) mask. Assert the modulo answer
     * explicitly so the intent survives a future reader. */
    CHECK(idx_of(&z, ngx_http_cache_turbo_stripe_of(&z, 8u)) == 1,
          "odd N: key 8 must be stripe 1 (modulo), not 0 (mask)");
}


/* (6) Every stripe is reachable and the spread is not degenerate. A resolver
 * that returned, say, `key % 2` at N == 8 would satisfy determinism and pass
 * (3) while using only a quarter of the pools -- which at s3c would be a
 * silent 4x contention regression, not a crash. */
static void
test_all_stripes_reachable(void)
{
    ngx_http_cache_turbo_zone_t  z;
    unsigned                     hit[TEST_STRIPES];
    uint32_t                     k;
    unsigned                     i;

    memset(&z, 0, sizeof(z));
    memset(hit, 0, sizeof(hit));
    z.nstripes = TEST_STRIPES;

    k = 0x1u;
    for (i = 0; i < 100000; i++) {
        k = k * 1103515245u + 12345u;
        hit[idx_of(&z, ngx_http_cache_turbo_stripe_of(&z, k))]++;
    }

    for (i = 0; i < TEST_STRIPES; i++) {
        CHECK(hit[i] > 0, "stripe %u was never selected over 100k keys", i);
        /* Uniform would be 12500 each. A floor of 1000 catches a resolver that
         * technically reaches every stripe but concentrates on a few, without
         * making the test a statistics flake -- the LCG is deterministic, so
         * this threshold is a fixed pass/fail, not a probability. */
        CHECK(hit[i] > 1000,
              "stripe %u got only %u of 100k keys -- spread is degenerate",
              i, hit[i]);
    }
}


/* (7) The ZONE-WIDE resolver must stay zone-wide -- it takes no key and must
 * pin stripe 0 whatever nstripes says. If someone made it key-directed, every
 * zone-global counter would scatter across pools. */
static void
test_zone_wide_resolver_pins_stripe_zero(void)
{
    ngx_http_cache_turbo_zone_t  z;

    memset(&z, 0, sizeof(z));

    z.nstripes = 0;
    CHECK(idx_of(&z, ngx_http_cache_turbo_zone_stripe(&z)) == 0,
          "zone_stripe() must pin stripe 0 (nstripes==0)");

    z.nstripes = 1;
    CHECK(idx_of(&z, ngx_http_cache_turbo_zone_stripe(&z)) == 0,
          "zone_stripe() must pin stripe 0 (nstripes==1)");

    z.nstripes = TEST_STRIPES;
    CHECK(idx_of(&z, ngx_http_cache_turbo_zone_stripe(&z)) == 0,
          "zone_stripe() must pin stripe 0 (nstripes==N)");
}


/* (8) The two resolvers must NOT be interchangeable at N > 1. This is the
 * property the lint enforces structurally at every call site; asserting it
 * here documents WHY a key-directed site taking the zone-wide spelling is a
 * bug rather than a style preference. */
static void
test_resolvers_diverge_at_n_gt_1(void)
{
    ngx_http_cache_turbo_zone_t  z;
    uint32_t                     k;
    unsigned                     i, diverged = 0;

    memset(&z, 0, sizeof(z));
    z.nstripes = TEST_STRIPES;

    for (i = 1; i < TEST_STRIPES; i++) {
        if (ngx_http_cache_turbo_stripe_of(&z, (uint32_t) i)
            != ngx_http_cache_turbo_zone_stripe(&z))
        {
            diverged++;
        }
    }

    CHECK(diverged == TEST_STRIPES - 1,
          "at N=%u, keys 1..%u must all resolve away from the zone-wide "
          "stripe; only %u did", TEST_STRIPES, TEST_STRIPES - 1, diverged);

    /* ...and at N == 1 they must agree for every key, which is precisely the
     * licence to convert call sites today. */
    z.nstripes = 1;
    k = 0x77777777u;
    for (i = 0; i < 1000; i++) {
        k = k * 1103515245u + 12345u;
        CHECK(ngx_http_cache_turbo_stripe_of(&z, k)
                  == ngx_http_cache_turbo_zone_stripe(&z),
              "at N==1 the two resolvers must agree (key 0x%08lx)",
              (unsigned long) k);
        if (failures) {
            return;
        }
    }
}


int
main(void)
{
    test_uninitialised_zone_is_safe();
    test_n1_is_identity();
    test_same_key_same_stripe();
    test_distinct_keys_distinct_stripes();
    test_odd_stripe_count();
    test_all_stripes_reachable();
    test_zone_wide_resolver_pins_stripe_zero();
    test_resolvers_diverge_at_n_gt_1();

    if (failures) {
        printf("test_stripe_resolver: %d FAILURE(S)\n", failures);
        return 1;
    }

    printf("test_stripe_resolver: ok (resolver arithmetic sound at N=%u "
           "and N=%u; identity at N=1)\n", TEST_STRIPES, TEST_STRIPES_ODD);
    return 0;
}
