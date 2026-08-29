/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * R3-2: $cache_turbo_normalized_args used to sort its kept query-param tokens
 * with nginx's ngx_sort() (src/core/ngx_string.c). ngx_sort() is an insertion
 * sort that ngx_alloc()s and ngx_free()s a `size`-byte scratch slot on EVERY
 * call -- here 16 bytes, sizeof(ngx_str_t) -- i.e. a real malloc/free pair per
 * request on a cache-key path nginx otherwise keeps allocation-free. It also
 * silently returns the array UNSORTED if that allocation fails, which under
 * memory pressure would have produced an order-dependent (inconsistent) cache
 * key. The fix open-codes the same insertion sort with a stack temp.
 *
 * The order this sort produces IS the cache key. Any divergence from
 * ngx_sort()'s order silently splits or merges cache entries for every
 * deployment that upgrades. So the property under test is BYTE-IDENTITY, not
 * merely "is sorted":
 *
 *     for every input, ct_tok_sort(a) and ngx_sort(a) must agree
 *     element-for-element -- same tokens in the same positions.
 *
 * "Is sorted" is deliberately NOT the oracle. Both a stable and an unstable
 * sort produce a "sorted" array; they differ only in where EQUAL-COMPARING
 * elements land, and the comparator here can compare two distinct tokens
 * equal only when they are byte-identical -- so the corpus below includes
 * duplicate tokens whose ngx_str_t.data pointers differ, making a stability
 * regression observable as a pointer mismatch that a value-only or
 * "is-sorted" check would sail straight past.
 *
 * ct_tok_sort() and the comparator are SLICED VERBATIM out of src/ by
 * extract_tok_sort.sh, so this exercises production's own loop rather than a
 * mirror that could stay correct while src/ drifted. The reference side is
 * ngx_sort() copied verbatim from the vendored nginx tree.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef intptr_t   ngx_int_t;
typedef uintptr_t  ngx_uint_t;
typedef unsigned char u_char;

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

#define ngx_min(a, b)        ((a) < (b) ? (a) : (b))
#define ngx_memcmp(s1, s2, n) memcmp((const char *) s1, (const char *) s2, n)
#define ngx_memcpy(d, s, n)  memcpy(d, s, n)

/* The production comparator + the production sort loop, sliced from src/. */
#include "generated_tok_sort.inc"

/*
 * REFERENCE: nginx's own ngx_sort(), src/core/ngx_string.c, verbatim except
 * for ngx_alloc()->malloc()/ngx_free()->free() (no ngx_cycle->log here). This
 * is the behaviour R3-2 must reproduce exactly.
 */
static void
ref_ngx_sort(void *base, size_t n, size_t size,
    ngx_int_t (*cmp)(const void *, const void *))
{
    u_char  *p1, *p2, *p;

    p = malloc(size);
    if (p == NULL) {
        return;
    }

    for (p1 = (u_char *) base + size;
         p1 < (u_char *) base + n * size;
         p1 += size)
    {
        ngx_memcpy(p, p1, size);

        for (p2 = p1;
             p2 > (u_char *) base && cmp(p2 - size, p) > 0;
             p2 -= size)
        {
            ngx_memcpy(p2, p2 - size, size);
        }

        ngx_memcpy(p2, p, size);
    }

    free(p);
}

static int checks;
static int failures;
static int alloc_fail_after = -1;
static int outstanding_allocs;
static int expected_alloc_failure;

static void *
test_malloc(size_t size)
{
    void *p;

    if (alloc_fail_after == 0) {
        return NULL;
    }
    if (alloc_fail_after > 0) {
        alloc_fail_after--;
    }
    p = malloc(size);
    if (p != NULL) {
        outstanding_allocs++;
    }
    return p;
}

static void
test_free(void *p)
{
    if (p != NULL) {
        outstanding_allocs--;
        free(p);
    }
}

static void
check_identical(const char *what, ngx_str_t *got, ngx_str_t *want, ngx_uint_t n)
{
    ngx_uint_t  i;

    checks++;

    for (i = 0; i < n; i++) {
        /* Compare the ngx_str_t FIELDS, not the bytes: two tokens can carry
         * identical bytes from different source offsets, and a stability
         * regression shows up only as a swapped .data pointer. */
        if (got[i].len != want[i].len || got[i].data != want[i].data) {
            failures++;
            fprintf(stderr,
                    "✗ %s: element %lu diverges from ngx_sort()\n"
                    "    got  len=%lu \"%.*s\" (data=%p)\n"
                    "    want len=%lu \"%.*s\" (data=%p)\n",
                    what, (unsigned long) i,
                    (unsigned long) got[i].len, (int) got[i].len, got[i].data,
                    (void *) got[i].data,
                    (unsigned long) want[i].len, (int) want[i].len, want[i].data,
                    (void *) want[i].data);
            return;
        }
    }
}

/* Run one input through both implementations and require agreement. */
static void
both(const char *what, ngx_str_t *in, ngx_uint_t n)
{
    ngx_str_t  *a = test_malloc(n * sizeof(ngx_str_t) + 1);
    ngx_str_t  *b;

    if (a == NULL) {
        if (expected_alloc_failure) {
            fprintf(stderr, "✓ %s: first comparison allocation handled\n",
                    what);
        } else {
            failures++;
            fprintf(stderr, "✗ %s: unexpected first comparison allocation "
                    "failure\n", what);
        }
        return;
    }

    b = test_malloc(n * sizeof(ngx_str_t) + 1);
    if (b == NULL) {
        if (expected_alloc_failure) {
            fprintf(stderr, "✓ %s: second comparison allocation handled\n",
                    what);
        } else {
            failures++;
            fprintf(stderr, "✗ %s: unexpected second comparison allocation "
                    "failure\n", what);
        }
        test_free(a);
        return;
    }

    memcpy(a, in, n * sizeof(ngx_str_t));
    memcpy(b, in, n * sizeof(ngx_str_t));

    ct_tok_sort(a, n);
    ref_ngx_sort(b, n, sizeof(ngx_str_t), ngx_http_cache_turbo_tok_cmp);

    check_identical(what, a, b, n);

    test_free(a);
    test_free(b);
}

static void
allocation_fault_checks(ngx_str_t *in)
{
    alloc_fail_after = 0;
    expected_alloc_failure = 1;
    both("first allocation fault", in, 1);
    if (outstanding_allocs != 0) {
        failures++;
        fprintf(stderr, "✗ first allocation fault leaked comparison storage\n");
    }

    alloc_fail_after = 1;
    both("second allocation fault", in, 1);
    if (outstanding_allocs != 0) {
        failures++;
        fprintf(stderr, "✗ second allocation fault leaked comparison storage\n");
    }
    alloc_fail_after = -1;
    expected_alloc_failure = 0;
}

/* Deterministic PRNG so a failure is reproducible from the printed seed. */
static uint32_t rng_state;

static uint32_t
rnd(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}


int
main(void)
{
    ngx_uint_t  i, n, round;

    /* ---- 1. n = 0 and n = 1: the loop must not touch anything ---------- */
    {
        ngx_str_t  one[1] = { { 3, (u_char *) "a=1" } };

        allocation_fault_checks(one);
        both("n=0", one, 0);
        both("n=1", one, 1);
    }

    /* ---- 2. hand-picked adversarial shapes ----------------------------- */
    {
        /* Shared prefixes force the comparator past ngx_memcmp into its
         * `a->len - b->len` length tiebreak; the bare "a" / "aa" pair is the
         * min(len) truncation case. */
        static u_char  *literals[] = {
            (u_char *) "a", (u_char *) "aa", (u_char *) "a=1",
            (u_char *) "a=10", (u_char *) "a=2", (u_char *) "b=1",
            (u_char *) "", (u_char *) "z=9", (u_char *) "aaa",
            (u_char *) "a=1"           /* duplicate VALUE, distinct pointer */
        };
        ngx_uint_t  nl = sizeof(literals) / sizeof(literals[0]);
        ngx_str_t   in[16];

        /* ascending, descending and rotated presentations of the same set */
        for (i = 0; i < nl; i++) {
            in[i].data = literals[i];
            in[i].len = strlen((char *) literals[i]);
        }
        both("literals as-given", in, nl);

        for (i = 0; i < nl; i++) {
            in[i].data = literals[nl - 1 - i];
            in[i].len = strlen((char *) literals[nl - 1 - i]);
        }
        both("literals reversed", in, nl);

        /* all-equal input: nothing may move, and stability must hold, so
         * every .data pointer must come back in its original slot. */
        for (i = 0; i < nl; i++) {
            in[i].data = (u_char *) "same=1";
            in[i].len = 6;
        }
        both("all tokens compare equal", in, nl);
    }

    /* ---- 3. randomized differential, incl. the empty-token edge -------- */
    {
        /* A pool of distinct backing buffers: duplicates in the token list
         * therefore have DIFFERENT .data pointers, which is what makes a
         * stability regression visible. */
        enum { POOL = 64, MAXTOK = 40 };
        static u_char  pool[POOL][8];
        ngx_str_t      in[MAXTOK];

        for (i = 0; i < POOL; i++) {
            /* short, heavily-colliding alphabet -> many equal comparisons */
            snprintf((char *) pool[i], sizeof(pool[i]), "%c%c=%c",
                     'a' + (int) (i % 3), 'a' + (int) ((i / 3) % 3),
                     '0' + (int) (i % 2));
        }

        rng_state = 0x5eed1234u;

        for (round = 0; round < 20000; round++) {
            n = 1 + (rnd() % MAXTOK);

            for (i = 0; i < n; i++) {
                ngx_uint_t  k = rnd() % POOL;

                in[i].data = pool[k];
                in[i].len = strlen((char *) pool[k]);

                /* ~1 in 16 tokens is zero-length: len==0 makes ngx_memcmp's
                 * n zero, so the comparator falls straight to the length
                 * tiebreak -- the path a non-empty corpus never reaches. */
                if ((rnd() & 15) == 0) {
                    in[i].len = 0;
                }
            }

            both("randomized differential", in, n);

            if (failures) {
                fprintf(stderr, "  (seed 0x5eed1234, round %lu, n=%lu)\n",
                        (unsigned long) round, (unsigned long) n);
                break;
            }
        }
    }

    printf("test_tok_sort: %d checks, %d failures\n", checks, failures);

    if (failures) {
        fprintf(stderr,
                "✗ the open-coded sort diverges from ngx_sort() -- this CHANGES "
                "THE CACHE KEY\n");
        return 1;
    }

    printf("OK: open-coded token sort is byte-identical to ngx_sort() "
           "(stack temp, no malloc/free per request)\n");
    return 0;
}
