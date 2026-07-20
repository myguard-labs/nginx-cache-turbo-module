/*
 * Unit tests for the cache-turbo shared-memory node state machine.
 *
 * These exist because two correct fixes on PR #77 had no guarding test:
 *
 *   CR-A  the L13 negative memo must SURVIVE the claim() that turns its
 *         COUNTER node into a single-flight stub. It used to be cleared there,
 *         which collapsed the memo window to ~1 request.
 *   CR-B  unstub() must NOT free a COUNTER that still carries min_uses
 *         progress (miss_count > 0) or a live memo. Freeing it silently reset
 *         the min_uses threshold.
 *
 * Neither is reachable through the HTTP surface -- see the header comment in
 * ngx_shim_shm.h for why, and do not re-attempt a black-box test for CR-A.
 * From C they are three calls each.
 *
 * ⚠ NEGATIVE CONTROL. A test that passes with the bug restored guards nothing
 * ([[feedback-negative-control-or-it-isnt-a-test]] -- 3 of 4 plausible tests
 * for this very module passed with the bug put back). Every invariant test
 * below is therefore paired with a control: build with -DCTRL_CR_A or
 * -DCTRL_CR_B and the harness re-introduces that specific bug in a copy of the
 * logic and asserts the test's own assertion FAILS. `make control` runs both
 * and fails if either survives. That target is part of `make check`.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ngx_shim_shm.h"

/* --- shim state ---------------------------------------------------------- */
time_t      ngx_test_now        = 1000000;
long        ngx_test_slab_budget = -1;
ngx_uint_t  ngx_test_slab_live   = 0;
ngx_uint_t  ngx_test_lock_depth  = 0;
ngx_uint_t  ngx_test_lock_count  = 0;

/* --- the node/zone types under test.
 * Sliced from the shipped header so the layout cannot drift from production;
 * see extract_shm.sh, which also pins the two NODE_* constants. */
#define NGX_HTTP_CACHE_TURBO_NODE_ENTRY    0
#define NGX_HTTP_CACHE_TURBO_NODE_COUNTER  1

typedef struct {
    ngx_rbtree_node_t   node;
    u_char              key[32];
    ngx_uint_t          kind;
    u_char             *data;
    size_t              len;
    time_t              fresh_until;
    time_t              stale_until;
    ngx_uint_t          refreshing;
    time_t              refresh_lock_until;
    ngx_uint_t          miss_count;
    time_t              l2_neg_until;
    time_t              last_access;
    ngx_queue_t         lru;
} ngx_http_cache_turbo_node_t;

typedef struct {
    ngx_rbtree_t        rbtree;
    ngx_rbtree_node_t   sentinel;
    ngx_queue_t         lru;
    ngx_atomic_t        hits, misses, stale_serves, refreshes, evictions;
    ngx_atomic_t        l2_hits, l2_misses, lock_waits;
    ngx_atomic_t        min_uses_skips, l2_neg_skips, bypasses;
} ngx_http_cache_turbo_shctx_t;

typedef struct {
    ngx_http_cache_turbo_shctx_t  *sh;
    ngx_slab_pool_t               *shpool;
} ngx_http_cache_turbo_zone_t;

/* claim() verdicts -- values are not asserted on, only distinctness matters. */
#define NGX_HTTP_CACHE_TURBO_CLAIM_FRESH    0
#define NGX_HTTP_CACHE_TURBO_CLAIM_WINNER   1
#define NGX_HTTP_CACHE_TURBO_CLAIM_LOSER    2

/* The sliced set calls this on eviction of a node that holds a body. No node
 * in these tests holds one (they are all COUNTERs), so reaching it means a
 * test built the wrong fixture -- fail loudly rather than silently no-op. */
static void
ngx_http_cache_turbo_blob_node_release(ngx_http_cache_turbo_zone_t *z, u_char *p)
{
    (void) z; (void) p;
    fprintf(stderr, "blob_node_release called: fixture built an ENTRY, not a COUNTER\n");
    abort();
}

#include "generated_shm.inc"

/* --- test scaffolding ---------------------------------------------------- */
static int tests_run, tests_failed;

#define CHECK(cond, msg)                                                      \
    do {                                                                      \
        tests_run++;                                                          \
        if (!(cond)) {                                                        \
            tests_failed++;                                                   \
            fprintf(stderr, "  ✗ %s\n    at %s:%d: %s\n",                     \
                    (msg), __FILE__, __LINE__, #cond);                        \
        }                                                                     \
    } while (0)

static ngx_http_cache_turbo_shctx_t  g_sh;
static ngx_slab_pool_t               g_pool;
static ngx_http_cache_turbo_zone_t   g_zone;

/* Whether g_sh currently holds an initialised LRU list. A zeroed g_sh has
 * lru.prev == NULL, and ngx_queue_empty() (h == h->prev) reads FALSE against
 * NULL -- so draining before the first ngx_queue_init() would walk a null
 * sentinel. UBSan caught exactly that; this flag is the fix. */
static int g_zone_live;

static void
zone_reset(void)
{
    /* Drain any nodes a previous test left behind so each test starts on an
     * empty zone AND so ngx_test_slab_live is a real leak check afterwards. */
    while (g_zone_live && !ngx_queue_empty(&g_sh.lru)) {
        ngx_queue_t                  *q   = ngx_queue_last(&g_sh.lru);
        ngx_http_cache_turbo_node_t  *ctn =
            ngx_queue_data(q, ngx_http_cache_turbo_node_t, lru);
        ngx_queue_remove(&ctn->lru);
        ngx_rbtree_delete(&g_sh.rbtree, &ctn->node);
        ngx_slab_free_locked(&g_pool, ctn);
    }

    memset(&g_sh, 0, sizeof(g_sh));
    ngx_rbtree_init(&g_sh.rbtree, &g_sh.sentinel, ngx_rbtree_insert_value);
    ngx_queue_init(&g_sh.lru);
    g_zone_live = 1;

    g_zone.sh     = &g_sh;
    g_zone.shpool = &g_pool;

    ngx_test_now         = 1000000;
    ngx_test_slab_budget = -1;
    ngx_test_lock_depth  = 0;
    ngx_test_lock_count  = 0;
}

/* Distinct 32-byte key material per logical key; hash is the rbtree key. */
static u_char *
mkkey(int n)
{
    static u_char buf[8][32];
    memset(buf[n], 0, 32);
    buf[n][0] = (u_char) ('A' + n);
    return buf[n];
}
#define KEY(n)  mkkey(n), (uint32_t) (0x1000 + (n))

static ngx_http_cache_turbo_node_t *
find(int n)
{
    return ngx_http_cache_turbo_shm_lookup(&g_zone, KEY(n));
}

/* =====================================================================
 * CR-A: the negative memo must survive claim()
 * ===================================================================== */
static void
test_cr_a_memo_survives_claim(void)
{
    ngx_http_cache_turbo_node_t  *ctn;
    ngx_int_t                     rc;

    printf("CR-A: negative memo survives the claim that stubs its node\n");
    zone_reset();

    /* Request 1: an L2 GET definitively missed, so it arms a 60s memo. This is
     * l2_neg_set() creating the COUNTER node. */
    ngx_http_cache_turbo_shm_l2_neg_set(&g_zone, KEY(0), 60);
    CHECK(ngx_test_lock_balanced(), "l2_neg_set left the zone mutex held");

    ctn = find(0);
    CHECK(ctn != NULL, "l2_neg_set did not create a node");
    CHECK(ctn->kind == NGX_HTTP_CACHE_TURBO_NODE_COUNTER,
          "memo node is not a COUNTER");
    CHECK(ctn->l2_neg_until == ngx_test_now + 60, "memo TTL not stamped");

    /* Request 1 continues into the cold-miss single-flight and wins, which
     * turns the SAME node into a stub. This is the exact transition CR-A is
     * about: before the fix, claim() cleared l2_neg_until here. */
    rc = ngx_http_cache_turbo_shm_claim(&g_zone, KEY(0), 5);
    CHECK(rc == NGX_HTTP_CACHE_TURBO_CLAIM_WINNER, "first claim should win");
    CHECK(ngx_test_lock_balanced(), "claim left the zone mutex held");

    ctn = find(0);
    CHECK(ctn != NULL, "claim destroyed the memo node");
    CHECK(ctn->refreshing == 1, "winner did not mark the node refreshing");

    /* THE INVARIANT. The node is now a stub, and the memo must still be on it. */
    CHECK(ctn->l2_neg_until == ngx_test_now + 60,
          "CR-A: claim() cleared the negative memo (window collapses to 1 req)");

    /* And it must be READABLE -- request 2 skips its L2 round-trip. This is the
     * observable payoff, and it is what the black-box suite could never reach:
     * l2_neg_check deliberately ignores `refreshing`. */
    rc = ngx_http_cache_turbo_shm_l2_neg_check(&g_zone, KEY(0));
    CHECK(rc == NGX_DECLINED,
          "CR-A: memo unreadable while the node is refreshing");

    /* Still live just before expiry, gone just after -- the window is the TTL,
     * not the claim. */
    ngx_test_advance_time(59);
    CHECK(ngx_http_cache_turbo_shm_l2_neg_check(&g_zone, KEY(0)) == NGX_DECLINED,
          "memo expired early (before its TTL)");
    ngx_test_advance_time(2);
    CHECK(ngx_http_cache_turbo_shm_l2_neg_check(&g_zone, KEY(0)) == NGX_OK,
          "memo outlived its TTL");
}

/* =====================================================================
 * CR-B: unstub() must not discard state the caller never asked to drop
 * ===================================================================== */
static void
test_cr_b_unstub_preserves_counter(void)
{
    ngx_http_cache_turbo_node_t  *ctn;

    printf("CR-B: unstub() preserves min_uses progress and live memos\n");
    zone_reset();

    /* Three cold misses under min_uses 4: the key is at 3/4, not yet cacheable. */
    CHECK(ngx_http_cache_turbo_shm_count_miss(&g_zone, KEY(0), 4) == NGX_DECLINED,
          "miss 1 should be below the min_uses threshold");
    CHECK(ngx_http_cache_turbo_shm_count_miss(&g_zone, KEY(0), 4) == NGX_DECLINED,
          "miss 2 should be below the min_uses threshold");
    CHECK(ngx_http_cache_turbo_shm_count_miss(&g_zone, KEY(0), 4) == NGX_DECLINED,
          "miss 3 should be below the min_uses threshold");
    CHECK(ngx_test_lock_balanced(), "count_miss left the zone mutex held");

    ctn = find(0);
    CHECK(ctn != NULL && ctn->miss_count == 3, "miss_count should be 3");

    /* That node becomes a stub, then the winner's response turns out to be
     * non-cacheable, so unstub() runs. */
    ctn->refreshing         = 1;
    ctn->refresh_lock_until = ngx_test_now + 5;

    ngx_http_cache_turbo_shm_unstub(&g_zone, KEY(0));
    CHECK(ngx_test_lock_balanced(), "unstub left the zone mutex held");

    /* Job 1, unconditional: the single-flight is released. Skipping this is the
     * variant that wedged every later request on a stub nobody would fill --
     * a hang, not a slowdown. */
    ctn = find(0);
    CHECK(ctn != NULL, "CR-B: unstub() freed a COUNTER still holding miss_count");
    CHECK(ctn->refreshing == 0, "unstub did not release the single-flight");
    CHECK(ctn->refresh_lock_until == 0, "unstub did not clear the lock deadline");

    /* Job 2, conditional: min_uses progress is intact, so the 4th miss still
     * crosses the threshold. If unstub() had freed the node this returns
     * NGX_DECLINED (count restarts at 1) and the key needs 4 more misses. */
    CHECK(ctn->miss_count == 3, "CR-B: unstub() reset min_uses progress");
    CHECK(ngx_http_cache_turbo_shm_count_miss(&g_zone, KEY(0), 4) == NGX_OK,
          "CR-B: 4th miss did not cross the threshold after unstub");

    /* Same guard for a live memo on an otherwise-empty counter. */
    zone_reset();
    ngx_http_cache_turbo_shm_l2_neg_set(&g_zone, KEY(1), 60);
    ctn = find(1);
    CHECK(ctn != NULL && ctn->miss_count == 0, "memo node should have no misses");
    ctn->refreshing         = 1;
    ctn->refresh_lock_until = ngx_test_now + 5;

    ngx_http_cache_turbo_shm_unstub(&g_zone, KEY(1));
    ctn = find(1);
    CHECK(ctn != NULL, "CR-B: unstub() freed a COUNTER holding a live memo");
    CHECK(ctn->refreshing == 0, "unstub did not release the single-flight");
    CHECK(ngx_http_cache_turbo_shm_l2_neg_check(&g_zone, KEY(1)) == NGX_DECLINED,
          "memo lost across unstub");

    /* The disposable case must still be reclaimed, or unstub() leaks stubs:
     * a bare stub with no miss_count and no live memo goes away entirely. */
    zone_reset();
    CHECK(ngx_http_cache_turbo_shm_claim(&g_zone, KEY(2), 5)
              == NGX_HTTP_CACHE_TURBO_CLAIM_WINNER, "claim should win");
    ngx_http_cache_turbo_shm_unstub(&g_zone, KEY(2));
    CHECK(find(2) == NULL, "unstub() failed to reclaim a disposable stub");

    /* An expired memo does not count as state worth keeping. */
    zone_reset();
    ngx_http_cache_turbo_shm_l2_neg_set(&g_zone, KEY(3), 10);
    ctn = find(3);
    ctn->refreshing         = 1;
    ctn->refresh_lock_until = ngx_test_now + 5;
    ngx_test_advance_time(11);                  /* memo now expired */
    ngx_http_cache_turbo_shm_unstub(&g_zone, KEY(3));
    CHECK(find(3) == NULL,
          "unstub() kept a stub whose memo had already expired");
}

/* =====================================================================
 * Surrounding state machine -- the invariants the two fixes rest on
 * ===================================================================== */
static void
test_claim_single_flight(void)
{
    ngx_int_t  rc;

    printf("claim(): single-flight winner/loser/self-heal\n");
    zone_reset();

    rc = ngx_http_cache_turbo_shm_claim(&g_zone, KEY(0), 5);
    CHECK(rc == NGX_HTTP_CACHE_TURBO_CLAIM_WINNER, "first claim should win");

    /* Second claim while the lock is live: park, do not stampede the origin. */
    rc = ngx_http_cache_turbo_shm_claim(&g_zone, KEY(0), 5);
    CHECK(rc == NGX_HTTP_CACHE_TURBO_CLAIM_LOSER,
          "second claim should lose while the lock is live");

    /* Past refresh_lock_until the previous winner is presumed dead and the
     * next arrival takes over -- otherwise a crashed worker blocks a key
     * forever. */
    ngx_test_advance_time(6);
    rc = ngx_http_cache_turbo_shm_claim(&g_zone, KEY(0), 5);
    CHECK(rc == NGX_HTTP_CACHE_TURBO_CLAIM_WINNER,
          "claim did not self-heal past an expired lock");
    CHECK(ngx_test_lock_balanced(), "claim left the zone mutex held");
}

static void
test_count_miss_semantics(void)
{
    ngx_http_cache_turbo_node_t  *ctn;

    printf("count_miss(): threshold, stub pass-through, ENTRY exemption\n");
    zone_reset();

    /* min_uses 1 is the default: never defer. */
    CHECK(ngx_http_cache_turbo_shm_count_miss(&g_zone, KEY(0), 1) == NGX_OK,
          "min_uses 1 should be store-eligible on the first miss");

    /* A live stub returns NGX_OK so the caller's claim() makes it a waiter --
     * this is NOT an un-coalesced miss and must not be counted. It is also the
     * reason a park is reachable with no concurrency at all. */
    zone_reset();
    ngx_http_cache_turbo_shm_count_miss(&g_zone, KEY(1), 4);
    ctn = find(1);
    ctn->refreshing         = 1;
    ctn->refresh_lock_until = ngx_test_now + 5;
    CHECK(ngx_http_cache_turbo_shm_count_miss(&g_zone, KEY(1), 4) == NGX_OK,
          "a live stub should pass through as NGX_OK");
    CHECK(find(1)->miss_count == 1, "a live stub must not be counted");

    /* A proven-cacheable ENTRY is never re-gated. */
    zone_reset();
    ngx_http_cache_turbo_shm_count_miss(&g_zone, KEY(2), 4);
    ctn = find(2);
    ctn->kind = NGX_HTTP_CACHE_TURBO_NODE_ENTRY;
    ctn->len  = 128;
    CHECK(ngx_http_cache_turbo_shm_count_miss(&g_zone, KEY(2), 4) == NGX_OK,
          "an ENTRY must never be re-gated by min_uses");
    CHECK(find(2)->miss_count == 1, "an ENTRY's counter must not be touched");
    ctn->len = 0;   /* keep zone_reset()'s drain off the blob path */
    ctn->kind = NGX_HTTP_CACHE_TURBO_NODE_COUNTER;
}

static void
test_l2_neg_never_on_entry(void)
{
    ngx_http_cache_turbo_node_t  *ctn;

    printf("l2_neg: an ENTRY is never memoed, and never reads one\n");
    zone_reset();

    ngx_http_cache_turbo_shm_count_miss(&g_zone, KEY(0), 4);
    ctn = find(0);
    ctn->kind = NGX_HTTP_CACHE_TURBO_NODE_ENTRY;
    ctn->len  = 64;

    ngx_http_cache_turbo_shm_l2_neg_set(&g_zone, KEY(0), 60);
    CHECK(find(0)->l2_neg_until == 0, "an ENTRY must never be memoed");
    CHECK(ngx_http_cache_turbo_shm_l2_neg_check(&g_zone, KEY(0)) == NGX_OK,
          "an ENTRY must never report a memo hit");

    ctn->len  = 0;
    ctn->kind = NGX_HTTP_CACHE_TURBO_NODE_COUNTER;
}

static void
test_out_of_slab_fails_open(void)
{
    printf("out-of-slab: both entry points fail OPEN, never wedge\n");
    zone_reset();

    /* No slab left. count_miss() cannot track the count, so it must let the
     * request cache now (less selective, still correct) rather than refuse. */
    ngx_test_slab_fail_after(0);
    CHECK(ngx_http_cache_turbo_shm_count_miss(&g_zone, KEY(0), 4) == NGX_OK,
          "count_miss must fail open when the slab is exhausted");
    CHECK(find(0) == NULL, "no node should exist after a failed alloc");

    /* claim() likewise: regenerate without a single-flight marker rather than
     * park a request on a stub that can never be created. */
    CHECK(ngx_http_cache_turbo_shm_claim(&g_zone, KEY(1), 5)
              == NGX_HTTP_CACHE_TURBO_CLAIM_WINNER,
          "claim must fail open (winner) when the slab is exhausted");
    CHECK(ngx_test_lock_balanced(), "a failed alloc leaked the zone mutex");

    ngx_test_slab_fail_after(-1);
}

/* =====================================================================
 * NEGATIVE CONTROL
 *
 * Re-implements each bug against the same fixture and asserts the test's own
 * assertion would FAIL. If a control ever "passes" (i.e. the buggy version
 * satisfies the assertion), the corresponding test proves nothing and this
 * binary exits non-zero.
 * ===================================================================== */
static void
run_negative_controls(void)
{
    ngx_http_cache_turbo_node_t  *ctn;
    int                           caught;

    printf("negative controls (each bug must break its own test)\n");

    /* CR-A restored: clear l2_neg_until at the claim() takeover point. */
    zone_reset();
    ngx_http_cache_turbo_shm_l2_neg_set(&g_zone, KEY(0), 60);
    ngx_http_cache_turbo_shm_claim(&g_zone, KEY(0), 5);
    ctn = find(0);
    ctn->l2_neg_until = 0;                     /* <-- the bug */

    caught = (ngx_http_cache_turbo_shm_l2_neg_check(&g_zone, KEY(0)) != NGX_DECLINED);
    tests_run++;
    if (!caught) {
        tests_failed++;
        fprintf(stderr, "  ✗ CONTROL CR-A: memo still readable with the bug "
                        "restored — test_cr_a_memo_survives_claim guards nothing\n");
    }

    /* CR-B restored: free any body-less node with no live memo, ignoring
     * miss_count (the exact predicate that discarded min_uses progress). */
    zone_reset();
    ngx_http_cache_turbo_shm_count_miss(&g_zone, KEY(1), 4);
    ngx_http_cache_turbo_shm_count_miss(&g_zone, KEY(1), 4);
    ngx_http_cache_turbo_shm_count_miss(&g_zone, KEY(1), 4);
    ctn = find(1);
    ctn->refreshing = 1;
    if (ctn->kind == NGX_HTTP_CACHE_TURBO_NODE_COUNTER
        && ctn->l2_neg_until <= ngx_time())     /* <-- the bug: no miss_count test */
    {
        ngx_queue_remove(&ctn->lru);
        ngx_rbtree_delete(&g_sh.rbtree, &ctn->node);
        ngx_slab_free_locked(&g_pool, ctn);
    }

    caught = (ngx_http_cache_turbo_shm_count_miss(&g_zone, KEY(1), 4) != NGX_OK);
    tests_run++;
    if (!caught) {
        tests_failed++;
        fprintf(stderr, "  ✗ CONTROL CR-B: min_uses progress survived the bug — "
                        "test_cr_b_unstub_preserves_counter guards nothing\n");
    }
}

int
main(void)
{
    memset(&g_sh, 0, sizeof(g_sh));
    zone_reset();

    test_cr_a_memo_survives_claim();
    test_cr_b_unstub_preserves_counter();
    test_claim_single_flight();
    test_count_miss_semantics();
    test_l2_neg_never_on_entry();
    test_out_of_slab_fails_open();
    run_negative_controls();

    /* Every node this run allocated must be accounted for. Under ASan a real
     * leak also trips the leak checker; this catches it in a plain build too. */
    zone_reset();
    tests_run++;
    if (ngx_test_slab_live != 0) {
        tests_failed++;
        fprintf(stderr, "  ✗ %lu slab allocation(s) leaked\n",
                (unsigned long) ngx_test_slab_live);
    }

    printf("\n%d checks, %d failed\n", tests_run, tests_failed);
    if (tests_failed == 0) {
        printf("OK: shm node state machine (CR-A memo survival, CR-B counter "
               "preservation, single-flight, min_uses, fail-open)\n");
    }
    return tests_failed == 0 ? 0 : 1;
}
