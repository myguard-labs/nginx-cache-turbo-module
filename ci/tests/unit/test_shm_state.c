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
#include <signal.h>
#include <unistd.h>

#include "ngx_shim_shm.h"

/* MIRROR side of the layout guard. layout_check.c asserts the REAL nginx
 * headers against the same literals; the two views cannot meet in one TU, so
 * agreeing with layout_expect.h separately is what proves they agree with each
 * other. Without this half, a hand edit to the mirror in ngx_shim_shm.h would
 * compile clean and corrupt memory at run time. */
#include "layout_expect.h"

NGX_CT_ASSERT_LAYOUTS("mirrored decl (ngx_shim_shm.h):");

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
    ngx_uint_t          seg;
    ngx_uint_t          promotable;
    ngx_queue_t         lru;
} ngx_http_cache_turbo_node_t;

/* S8 segment ids. PROBATION == 0 is load-bearing: a node zeroed by accident
 * reads as probation, i.e. the EVICTABLE (safe) direction -- same rationale as
 * NODE_ENTRY == 0. extract_shm.sh pins both values against the header. */
#define NGX_HTTP_CACHE_TURBO_SEG_PROBATION  0
#define NGX_HTTP_CACHE_TURBO_SEG_PROTECTED  1
#define NGX_HTTP_CACHE_TURBO_PROTECTED_PCT_DEFAULT 80

/* P6/O4.1 breaker states. CLOSED == 0 is load-bearing for the same reason
 * NODE_ENTRY == 0 and SEG_PROBATION == 0 are -- a zeroed zone must read as "not
 * tripped", the direction that sends traffic to the origin as if the feature
 * were off. extract_shm.sh pins all three against the header. */
#define NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED     0
#define NGX_HTTP_CACHE_TURBO_BREAKER_OPEN       1
#define NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN  2

/* P6/O4.3-c: breaker_state is a packed [ generation | state ] word, so that a
 * lease can be identified by a generation that every transition CASes as part
 * of the same atomic value. Mirrored from the header; extract_shm.sh pins the
 * two copies against each other. Rationale lives on the header definition. */
#define NGX_HTTP_CACHE_TURBO_BREAKER_STATE_BITS  2
#define NGX_HTTP_CACHE_TURBO_BREAKER_STATE_MASK \
    ((ngx_uint_t) ((1U << NGX_HTTP_CACHE_TURBO_BREAKER_STATE_BITS) - 1))

#define ngx_http_cache_turbo_brk_state(w) \
    ((ngx_uint_t) (w) & NGX_HTTP_CACHE_TURBO_BREAKER_STATE_MASK)
#define ngx_http_cache_turbo_brk_gen(w) \
    ((ngx_uint_t) (w) >> NGX_HTTP_CACHE_TURBO_BREAKER_STATE_BITS)
#define ngx_http_cache_turbo_brk_pack(gen, st)                                \
    (((ngx_uint_t) (gen) << NGX_HTTP_CACHE_TURBO_BREAKER_STATE_BITS)          \
     | ((ngx_uint_t) (st) & NGX_HTTP_CACHE_TURBO_BREAKER_STATE_MASK))

/* P6/O4.3 serve-path actions. PASS == 0 is load-bearing for the same reason
 * CLOSED == 0 is: the safe direction for a zeroed value is "the breaker does
 * not interfere". extract_shm.sh pins these against the header too. */
/* P6/O4.3 probe lease sentinel. 0 doubles as breaker_probe_at's zeroed value,
 * so a token that was never stamped can never match a live lease. */
#define NGX_HTTP_CACHE_TURBO_BREAKER_NO_PROBE  0

/* P6/O4.4-a: how long a promoted probe owns its lease, deliberately NOT
 * breaker_open -- rationale on the header definition. Mirrored here because the
 * sliced breaker_state() references it; extract_shm.sh pins the two copies. */
#define NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_LEASE  300

#define NGX_HTTP_CACHE_TURBO_BRK_ACT_PASS   0
#define NGX_HTTP_CACHE_TURBO_BRK_ACT_SERVE  1
#define NGX_HTTP_CACHE_TURBO_BRK_ACT_FAIL   2
/* O4.3-c: the promoted probe. Terminal and DISTINCT from PASS -- see header. */
#define NGX_HTTP_CACHE_TURBO_BRK_ACT_PROBE  3

/* P6/O4.2: the only nginx status constant the sliced origin-failure predicate
 * needs. Same value as nginx's own; check_constants.sh is not involved because
 * this one is nginx's, not ours. */
#define NGX_HTTP_INTERNAL_SERVER_ERROR      500

/* ⚠ MIRRORED, not included. The trailing autotune fields of the real shctx are
 * deliberately omitted -- no sliced function touches them. The breaker fields
 * below ARE touched by the sliced breaker functions, so they must stay in the
 * same relative order as the header's declaration. */
typedef struct {
    ngx_rbtree_t        rbtree;
    ngx_rbtree_node_t   sentinel;
    ngx_queue_t         lru;
    ngx_queue_t         lru_protected;
    ngx_uint_t          n_protected;
    ngx_uint_t          n_entries;
    ngx_atomic_t        hits, misses, stale_serves, refreshes, evictions;
    ngx_atomic_t        l2_hits, l2_misses, lock_waits;
    ngx_atomic_t        min_uses_skips, l2_neg_skips, bypasses;
    ngx_atomic_t        breaker_state, breaker_fails, breaker_window_start;
    ngx_atomic_t        breaker_opened_at, breaker_probe_at, breaker_opens;
} ngx_http_cache_turbo_shctx_t;

typedef struct {
    ngx_http_cache_turbo_shctx_t  *sh;
    ngx_slab_pool_t               *shpool;
} ngx_http_cache_turbo_zone_t;

/* O4.4: minimal loc_conf shim for ngx_http_cache_turbo_breaker_should_consult().
 * Only the four fields the predicate reads need to exist, and only by NAME --
 * the sliced function is compiled against THIS struct, not the real one, so
 * field ORDER/offsets don't need to match, just the names the predicate
 * dereferences (clcf->enable, clcf->breaker_enable, clcf->breaker_threshold,
 * clcf->breaker_window). Kept deliberately tiny rather than mirroring the full
 * ~1300-line production loc_conf. */
typedef struct {
    ngx_int_t    enable;         /* ngx_flag_t in the real loc_conf; the shim
                                   * doesn't pull in ngx_conf_file.h, and the
                                   * predicate only tests truthiness. */
    ngx_int_t    breaker_enable;
    ngx_uint_t   breaker_threshold;
    time_t       breaker_window;
} ngx_http_cache_turbo_loc_conf_t;

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

/* evict_one/alloc_evict are `static` in the sliced production source. Forward-
 * declare them so the S8 hang test can drive the eviction path directly --
 * that path is only reachable indirectly otherwise (through a slab failure),
 * which is far too blunt to pin which queue was consulted. */
static ngx_int_t ngx_http_cache_turbo_shm_evict_one(
    ngx_http_cache_turbo_zone_t *z);
static void *ngx_http_cache_turbo_shm_alloc_evict(
    ngx_http_cache_turbo_zone_t *z, size_t size);
static void ngx_http_cache_turbo_lru_link_head(
    ngx_http_cache_turbo_zone_t *z, ngx_http_cache_turbo_node_t *ctn);
static void ngx_http_cache_turbo_lru_unlink(
    ngx_http_cache_turbo_zone_t *z, ngx_http_cache_turbo_node_t *ctn);
static void ngx_http_cache_turbo_lru_insert_new(
    ngx_http_cache_turbo_zone_t *z, ngx_http_cache_turbo_node_t *ctn);
static void ngx_http_cache_turbo_lru_enforce_cap(
    ngx_http_cache_turbo_zone_t *z, ngx_uint_t protected_pct);

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

/* Fatal variant of CHECK for fixture-setup invariants whose failure would make
 * the FOLLOWING lines dereference a NULL/garbage pointer. It records the failure
 * exactly like CHECK, then RETURNS from the (void) test -- so a broken fixture
 * reports its own assertion instead of SIGSEGV-ing on the next deref and masking
 * which assertion actually failed. Use it only for a guard the rest of the test
 * body derefs (a find() result, a node pointer); keep CHECK for independent
 * asserts a later line does not depend on. */
#define REQUIRE(cond, msg)                                                    \
    do {                                                                      \
        tests_run++;                                                          \
        if (!(cond)) {                                                        \
            tests_failed++;                                                   \
            fprintf(stderr, "  ✗ %s (fatal)\n    at %s:%d: %s\n",             \
                    (msg), __FILE__, __LINE__, #cond);                        \
            return;                                                           \
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

    /* S8: the protected queue must be drained too, or the leak check below
     * misses every promoted node -- the same fan-out miss purge_all has to
     * avoid in production. */
    while (g_zone_live && !ngx_queue_empty(&g_sh.lru_protected)) {
        ngx_queue_t                  *q   = ngx_queue_last(&g_sh.lru_protected);
        ngx_http_cache_turbo_node_t  *ctn =
            ngx_queue_data(q, ngx_http_cache_turbo_node_t, lru);
        ngx_queue_remove(&ctn->lru);
        ngx_rbtree_delete(&g_sh.rbtree, &ctn->node);
        ngx_slab_free_locked(&g_pool, ctn);
    }

    memset(&g_sh, 0, sizeof(g_sh));
    ngx_rbtree_init(&g_sh.rbtree, &g_sh.sentinel, ngx_rbtree_insert_value);
    ngx_queue_init(&g_sh.lru);
    ngx_queue_init(&g_sh.lru_protected);
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
 * S8 HANG HAZARD -- the single most dangerous line in the segmented LRU.
 *
 * evict_one() used to answer "is there anything to evict?" with
 * ngx_queue_empty(&sh->lru). With TWO queues that test is no longer
 * sufficient IN EITHER DIRECTION, and the two directions fail differently:
 *
 *   a) It must not return 0 while the OTHER queue still holds a victim, or
 *      alloc_evict() gives up early and a store fails on a zone that still
 *      had reclaimable entries. Merely wrong, and visible as a test failure.
 *
 *   b) It must return 0 when BOTH are empty. If it ever returns non-zero
 *      without actually evicting, alloc_evict()'s
 *          while (p == NULL && evict_one(z))
 *      spins FOREVER -- while holding shpool->mutex. That is not a crash and
 *      not a wrong number: it is a wedged worker plus every other worker
 *      blocked behind the mutex it never releases. Nothing in a black-box
 *      HTTP suite reports that as anything but a timeout.
 *
 * A spin cannot be caught by an assertion, because control never comes back
 * to make one. So this test arms a real SIGALRM watchdog: if the call does
 * not return within the budget, the handler reports the hazard by name and
 * exits non-zero. A regression therefore FAILS the suite in bounded time
 * instead of hanging CI until the job timeout kills it with no diagnosis.
 * ===================================================================== */

static const char *g_watchdog_what;

static void
watchdog_fired(int sig)
{
    (void) sig;
    /* async-signal-safe only: write(2) + _exit(2). No printf, no abort. */
    static const char msg[] =
        "\n  x HANG: evict_one/alloc_evict did not return within the watchdog "
        "budget.\n"
        "    alloc_evict() spins while holding shpool->mutex when evict_one()\n"
        "    reports progress it did not make. This wedges a worker.\n"
        "    test: ";
    ssize_t rc;
    rc = write(2, msg, sizeof(msg) - 1);
    if (g_watchdog_what != NULL) {
        rc = write(2, g_watchdog_what, strlen(g_watchdog_what));
    }
    rc = write(2, "\n", 1);
    (void) rc;
    _exit(1);
}

/* Arm/disarm around any call that could spin. The budget is generous in
 * wall-clock terms (a correct call returns in microseconds) but finite, which
 * is the whole point: bounded failure beats an unbounded hang. */
static void
watchdog_arm(const char *what)
{
    g_watchdog_what = what;
    signal(SIGALRM, watchdog_fired);
    alarm(10);
}

static void
watchdog_disarm(void)
{
    alarm(0);
    g_watchdog_what = NULL;
}

static void
test_s8_evict_terminates_on_empty_queues(void)
{
    void  *p;

    printf("S8 hang hazard: eviction terminates when both queues are empty\n");
    zone_reset();

    /* (b) THE HANG. Both queues empty and the slab refuses every allocation:
     * alloc_evict() must conclude there is nothing to reclaim and return NULL.
     * If evict_one() ever claims progress on an empty pair, this never
     * returns and the watchdog fires. */
    ngx_test_slab_fail_after(0);

    watchdog_arm("both queues empty must terminate, not spin");
    p = ngx_http_cache_turbo_shm_alloc_evict(&g_zone, 128);
    watchdog_disarm();

    CHECK(p == NULL, "alloc_evict must fail (not spin) on an empty zone");
    CHECK(ngx_http_cache_turbo_shm_evict_one(&g_zone) == 0,
          "evict_one must report 0 when BOTH queues are empty");

    ngx_test_slab_fail_after(-1);

    /* (b') The same hazard with only the PROBATION queue empty. This is the
     * state a scan-resistant zone actually reaches: everything hot has been
     * promoted, probation has drained, and a new store still needs room. The
     * flat `ngx_queue_empty(&lru)` test answers "empty, give up" here, so a
     * naive port either wedges or refuses to evict a full-but-all-protected
     * zone. Assert it evicts the protected tail instead. */
    zone_reset();
    ngx_http_cache_turbo_shm_count_miss(&g_zone, KEY(0), 4);
    REQUIRE(find(0) != NULL, "fixture: count_miss did not create the node");
    find(0)->seg = NGX_HTTP_CACHE_TURBO_SEG_PROTECTED;
    ngx_queue_remove(&find(0)->lru);
    ngx_queue_insert_head(&g_sh.lru_protected, &find(0)->lru);
    g_sh.n_protected = 1;

    CHECK(ngx_queue_empty(&g_sh.lru), "fixture: probation should be empty");

    watchdog_arm("probation empty, protected non-empty must evict, not spin");
    CHECK(ngx_http_cache_turbo_shm_evict_one(&g_zone) == 1,
          "evict_one must fall through to the protected tail");
    watchdog_disarm();

    CHECK(find(0) == NULL, "the protected victim was not actually evicted");
    CHECK(g_sh.evictions == 1, "eviction was not counted");

    /* And now that it drained the protected queue too, the zone is genuinely
     * empty again -- so the terminating answer must still be 0. */
    watchdog_arm("post-drain empty must terminate");
    CHECK(ngx_http_cache_turbo_shm_evict_one(&g_zone) == 0,
          "evict_one must report 0 after draining the protected queue");
    watchdog_disarm();

    /* (a) The opposite direction: a victim in probation must be found even
     * though a segmented implementation might consult the wrong head. */
    zone_reset();
    ngx_http_cache_turbo_shm_count_miss(&g_zone, KEY(1), 4);
    CHECK(ngx_http_cache_turbo_shm_evict_one(&g_zone) == 1,
          "evict_one must evict a probation victim");
    CHECK(find(1) == NULL, "the probation victim was not evicted");

    CHECK(ngx_test_lock_balanced(), "eviction path left the zone mutex held");
}

/* =====================================================================
 * S8 promote-on-second-hit.
 *
 * The re-splice sites live in module.c (the request path), not in the sliced
 * shm set, so the shared decision is factored into ONE production helper --
 * ngx_http_cache_turbo_shm_touch_lru() in shm.c -- which all three sites call
 * and which extract_shm.sh slices here. That is deliberate: a rule duplicated
 * at three call sites is a rule that drifts at one of them, and this test
 * would still pass while the drifted site quietly never promoted.
 *
 * The invariants:
 *   1. first touch  -> stays in PROBATION (a one-hit crawler URL never gets
 *      protection; that is the entire scan resistance)
 *   2. second touch -> moves to PROTECTED head
 *   3. a COUNTER never promotes, however often it is touched -- it holds no
 *      body, and letting a miss-storm pin the protected segment with bodyless
 *      bookkeeping nodes would invert the feature
 *   4. the 1s coarse gate from P1 still applies; no second clock is added
 * ===================================================================== */
/* protected_pct as an ENABLED location would supply it. */
#define PCT_ON  NGX_HTTP_CACHE_TURBO_PROTECTED_PCT_DEFAULT

static void
test_s8_promote_on_second_hit(void)
{
    ngx_http_cache_turbo_node_t  *ctn;

    printf("S8: promote on second hit, and never promote a COUNTER\n");
    zone_reset();

    /* Build a real ENTRY the way store() would leave one: in probation. */
    ngx_http_cache_turbo_shm_count_miss(&g_zone, KEY(0), 1);
    ctn = find(0);
    REQUIRE(ctn != NULL, "S8 fixture: count_miss did not create the ENTRY");
    ctn->kind = NGX_HTTP_CACHE_TURBO_NODE_ENTRY;
    ctn->len  = 128;
    ctn->seg  = NGX_HTTP_CACHE_TURBO_SEG_PROBATION;
    ctn->last_access = ngx_test_now;

    /* (1) First hit. The P1 coarse gate must have elapsed for any splice to
     * happen at all, so advance past it. A first touch re-heads within
     * probation but must NOT promote. */
    ngx_test_advance_time(2);
    ngx_http_cache_turbo_shm_touch_lru(&g_zone, ctn, ngx_test_now, PCT_ON);
    CHECK(ctn->seg == NGX_HTTP_CACHE_TURBO_SEG_PROBATION,
          "S8: a FIRST hit must not promote (one-hit keys stay evictable)");
    CHECK(g_sh.n_protected == 0, "protected count moved on a first hit");

    /* (2) Second hit -> PROTECTED. This is the actual promotion rule. */
    ngx_test_advance_time(2);
    ngx_http_cache_turbo_shm_touch_lru(&g_zone, ctn, ngx_test_now, PCT_ON);
    CHECK(ctn->seg == NGX_HTTP_CACHE_TURBO_SEG_PROTECTED,
          "S8: a SECOND hit must promote the node to PROTECTED");
    CHECK(g_sh.n_protected == 1, "protected count not maintained on promote");
    CHECK(!ngx_queue_empty(&g_sh.lru_protected),
          "promoted node is not on the protected queue");
    CHECK(ngx_queue_empty(&g_sh.lru),
          "promoted node was left on the probation queue too (both-queue "
          "consistency broken -- a node must be on exactly one)");

    /* (4) The P1 coarse gate still governs: a touch inside the same second is
     * a no-op. The node is already PROTECTED here, so what this pins is that
     * an immediate re-touch does not run the promote/cap machinery again --
     * n_protected must not move. (No manual demote is involved; an earlier
     * version of this comment claimed one. CodeRabbit, PR #81.) */
    ngx_http_cache_turbo_shm_touch_lru(&g_zone, ctn, ngx_test_now, PCT_ON);
    CHECK(g_sh.n_protected == 1,
          "a within-1s touch must be a no-op, not a second promotion");

    /* (3) A COUNTER must never promote, no matter how many times it is
     * touched. l2_neg_check() touches memo nodes on every consult; if that
     * promoted them, an L2 miss storm would evict real bodies to make room
     * for nodes that hold none. */
    zone_reset();
    ngx_http_cache_turbo_shm_l2_neg_set(&g_zone, KEY(1), 600);
    ctn = find(1);
    REQUIRE(ctn != NULL, "S8 fixture: l2_neg_set did not create the COUNTER");
    CHECK(ctn->kind == NGX_HTTP_CACHE_TURBO_NODE_COUNTER, "fixture: COUNTER");

    ngx_test_advance_time(2);
    ngx_http_cache_turbo_shm_touch_lru(&g_zone, ctn, ngx_test_now, PCT_ON);
    ngx_test_advance_time(2);
    ngx_http_cache_turbo_shm_touch_lru(&g_zone, ctn, ngx_test_now, PCT_ON);
    ngx_test_advance_time(2);
    ngx_http_cache_turbo_shm_touch_lru(&g_zone, ctn, ngx_test_now, PCT_ON);

    CHECK(ctn->seg == NGX_HTTP_CACHE_TURBO_SEG_PROBATION,
          "S8: a COUNTER promoted -- a miss storm can now pin the protected "
          "segment with bodyless nodes");
    CHECK(g_sh.n_protected == 0, "a COUNTER was counted as protected");

    /* Same via the real l2_neg_check path, which is how a memo is touched in
     * production -- proves the gate is in the shared helper, not bolted onto
     * one call site. */
    ngx_test_advance_time(2);
    CHECK(ngx_http_cache_turbo_shm_l2_neg_check(&g_zone, KEY(1)) == NGX_DECLINED,
          "fixture: memo should still be live");
    CHECK(ctn->seg == NGX_HTTP_CACHE_TURBO_SEG_PROBATION,
          "S8: l2_neg_check promoted a memo COUNTER");

    CHECK(ngx_test_lock_balanced(), "touch path left the zone mutex held");
}

/* =====================================================================
 * S8: turning the feature OFF must DEMOTE, not merely stop promoting.
 *
 * A zone survives a reload -- init_zone() inherits the live `sh` -- so an
 * `on` -> `off` config change is handed nodes that are already PROTECTED.
 * If touch_lru() only declined to promote, unlink/link_head would keep
 * relinking those nodes onto lru_protected forever: `off` would stop future
 * promotions but never restore the flat single-queue LRU, and everything
 * promoted while it was on would stay preferentially un-evictable for the
 * life of the zone.
 *
 * Found by CodeRabbit on PR #81, not by CI -- the original tests only ever
 * exercised a FRESH zone, where nothing is protected to begin with.
 * ===================================================================== */
static void
test_s8_off_demotes_inherited_protected_nodes(void)
{
    ngx_http_cache_turbo_node_t  *ctn;

    printf("S8: `off` demotes nodes a previous `on` had promoted\n");
    zone_reset();

    /* Build the post-reload state: an ENTRY promoted while the feature was on. */
    ngx_http_cache_turbo_shm_count_miss(&g_zone, KEY(0), 1);
    ctn = find(0);
    REQUIRE(ctn != NULL, "S8-off fixture: count_miss did not create the ENTRY");
    ctn->kind = NGX_HTTP_CACHE_TURBO_NODE_ENTRY;
    ctn->len  = 128;
    ctn->last_access = ngx_test_now;

    ngx_test_advance_time(2);
    ngx_http_cache_turbo_shm_touch_lru(&g_zone, ctn, ngx_test_now, PCT_ON);
    ngx_test_advance_time(2);
    ngx_http_cache_turbo_shm_touch_lru(&g_zone, ctn, ngx_test_now, PCT_ON);
    CHECK(ctn->seg == NGX_HTTP_CACHE_TURBO_SEG_PROTECTED,
          "fixture: node should be PROTECTED before the reload");
    CHECK(g_sh.n_protected == 1, "fixture: n_protected should be 1");

    /* Config reloaded with the directive removed/off => pct 0 from here on. */
    ngx_test_advance_time(2);
    ngx_http_cache_turbo_shm_touch_lru(&g_zone, ctn, ngx_test_now, 0);

    CHECK(ctn->seg == NGX_HTTP_CACHE_TURBO_SEG_PROBATION,
          "S8: `off` left an inherited node PROTECTED -- the zone never "
          "returns to the flat LRU after an on->off reload");
    CHECK(g_sh.n_protected == 0,
          "S8: n_protected not decremented when `off` demoted the node");
    CHECK(ngx_queue_empty(&g_sh.lru_protected),
          "S8: protected queue still non-empty after `off` touched its "
          "only member");
    CHECK(!ngx_queue_empty(&g_sh.lru),
          "S8: demoted node did not land on the probation queue");

    /* And it must not creep back: with the feature off, further touches keep
     * it in probation however many times it is hit. */
    ngx_test_advance_time(2);
    ngx_http_cache_turbo_shm_touch_lru(&g_zone, ctn, ngx_test_now, 0);
    ngx_test_advance_time(2);
    ngx_http_cache_turbo_shm_touch_lru(&g_zone, ctn, ngx_test_now, 0);
    CHECK(ctn->seg == NGX_HTTP_CACHE_TURBO_SEG_PROBATION,
          "S8: a node re-promoted itself while the feature was off");
    CHECK(g_sh.n_protected == 0, "S8: n_protected rose while off");

    ctn->len = 0;   /* keep zone_reset()'s drain off the blob path */
    ctn->kind = NGX_HTTP_CACHE_TURBO_NODE_COUNTER;

    CHECK(ngx_test_lock_balanced(), "touch path left the zone mutex held");
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
    REQUIRE(ctn != NULL, "l2_neg_set did not create a node");
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
    REQUIRE(ctn != NULL, "claim destroyed the memo node");
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
    REQUIRE(ctn != NULL, "count_miss did not create a node");
    CHECK(ctn->miss_count == 3, "miss_count should be 3");

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
    REQUIRE(ctn != NULL, "CR-B: unstub() freed a COUNTER still holding miss_count");
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
    REQUIRE(ctn != NULL, "l2_neg_set did not create the memo node");
    CHECK(ctn->miss_count == 0, "memo node should have no misses");
    ctn->refreshing         = 1;
    ctn->refresh_lock_until = ngx_test_now + 5;

    ngx_http_cache_turbo_shm_unstub(&g_zone, KEY(1));
    ctn = find(1);
    REQUIRE(ctn != NULL, "CR-B: unstub() freed a COUNTER holding a live memo");
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
    REQUIRE(ctn != NULL, "l2_neg_set did not create the expiring memo node");
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
    REQUIRE(ctn != NULL, "count_miss fixture: live-stub node missing");
    ctn->refreshing         = 1;
    ctn->refresh_lock_until = ngx_test_now + 5;
    CHECK(ngx_http_cache_turbo_shm_count_miss(&g_zone, KEY(1), 4) == NGX_OK,
          "a live stub should pass through as NGX_OK");
    CHECK(ctn->miss_count == 1, "a live stub must not be counted");

    /* A proven-cacheable ENTRY is never re-gated. */
    zone_reset();
    ngx_http_cache_turbo_shm_count_miss(&g_zone, KEY(2), 4);
    ctn = find(2);
    REQUIRE(ctn != NULL, "count_miss fixture: ENTRY node missing");
    ctn->kind = NGX_HTTP_CACHE_TURBO_NODE_ENTRY;
    ctn->len  = 128;
    CHECK(ngx_http_cache_turbo_shm_count_miss(&g_zone, KEY(2), 4) == NGX_OK,
          "an ENTRY must never be re-gated by min_uses");
    CHECK(ctn->miss_count == 1, "an ENTRY's counter must not be touched");
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
    REQUIRE(ctn != NULL, "ENTRY-never-memoed fixture: node missing");
    ctn->kind = NGX_HTTP_CACHE_TURBO_NODE_ENTRY;
    ctn->len  = 64;

    ngx_http_cache_turbo_shm_l2_neg_set(&g_zone, KEY(0), 60);
    CHECK(ctn->l2_neg_until == 0, "an ENTRY must never be memoed");
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
 * P6/O4.1 -- circuit-breaker state machine
 *
 * ⚠ Single-threaded by construction: see the ngx_atomic_cmp_set note in
 * ngx_shim_shm.h. These tests pin the TRANSITION LOGIC (which precondition
 * guards which edge, and that a stale precondition is a no-op). They do NOT
 * prove the lock-free design is race-free -- that is the ASan multi-worker
 * runtime arm's job.
 * ===================================================================== */

/* A zeroed zone must read CLOSED. This is the fail-safe direction: traffic goes
 * to the origin exactly as if the feature were off. */
/* P6/O4.3 shims. Most breaker tests do not care about the probe LEASE TOKEN --
 * they assert state transitions -- so these keep those call sites readable while
 * still driving the real production signatures. brk_state() discards the token;
 * brk_probe_state() hands it back for the tests that DO care (only the promoted
 * request may resolve HALF_OPEN); brk_record() reports without a token, which is
 * what every non-probe request in the module passes. */
static ngx_uint_t
brk_state(time_t open_for)
{
    ngx_uint_t  probe;

    return ngx_http_cache_turbo_shm_breaker_state(&g_zone, open_for, &probe);
}

static ngx_uint_t
brk_probe_state(time_t open_for, ngx_uint_t *probe)
{
    return ngx_http_cache_turbo_shm_breaker_state(&g_zone, open_for, probe);
}

static void
brk_record(ngx_uint_t success, ngx_uint_t threshold, time_t window)
{
    ngx_http_cache_turbo_shm_breaker_record(&g_zone, success, threshold, window,
        NGX_HTTP_CACHE_TURBO_BREAKER_NO_PROBE);
}


/* O4.4-b: ngx_parse_time() accepts durations up to NGX_MAX_INT_T_VALUE, so a
 * deadline written as `now >= stamp + duration` overflows signed time_t once an
 * epoch stamp is added and the comparison INVERTS -- an effectively infinite
 * window reads as already elapsed. The shipped form subtracts two epoch stamps
 * instead, which cannot overflow for any duration the parser can produce.
 *
 * Both breaker deadlines are covered:
 *
 *  - the rolling failure window in _record(). With the overflowing form,
 *    `now >= window_start + window` is true for every failure, so each failure
 *    re-anchors the window and resets the counter to 1 -- the breaker can never
 *    accumulate to a threshold above 1 and NEVER TRIPS. The elapsed form keeps
 *    the anchor, so two failures inside a huge window trip it.
 *
 *  - the open duration in _breaker_state(). With the overflowing form,
 *    `now < opened_at + open_for` is false immediately, so an effectively
 *    infinite OPEN promotes a probe on the very next request -- the herd this
 *    breaker exists to hold back is released a second after it trips.
 *
 * Negative control: restore either `+` form and the matching CHECK below fails.
 */
static void
test_breaker_huge_durations_do_not_overflow(void)
{
    time_t  huge;

    printf("breaker: a near-max duration does not overflow the deadline\n");

    /* The largest duration ngx_parse_time() can hand the state machine that is
     * also representable in time_t (see ngx_shim_shm.h). Hardcoding a 64-bit
     * literal instead would be an out-of-range conversion wherever time_t is
     * narrower, and the test would quietly stop reaching the overflow. */
    huge = NGX_TEST_MAX_DURATION;

    zone_reset();
    ngx_test_set_time(1000);

    /* Window arm: two failures a second apart, threshold 2, effectively
     * infinite window. They are unquestionably inside it, so they must trip.
     *
     * The anchor is seeded explicitly rather than left at the zeroed-zone 0:
     * `0 + huge` does not overflow, so a fresh zone would exercise the safe
     * side of the comparison and the test would pass either way. A real epoch
     * anchor is what makes `anchor + huge` wrap. */
    g_sh.breaker_window_start = (ngx_atomic_t) 1000;
    brk_record(0, 2, huge);
    ngx_test_set_time(1001);
    brk_record(0, 2, huge);

    CHECK(brk_state(huge) == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
          "a near-max breaker window overflowed: every failure re-anchored the "
          "rolling window, so the breaker never reached its threshold");

    /* Open arm: the breaker just opened, and open_for is effectively infinite.
     * No probe may be promoted -- not now, and not a second later. */
    ngx_test_set_time(1002);
    CHECK(brk_state(huge) == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
          "a near-max breaker_open overflowed: the open window read as already "
          "elapsed and a probe was promoted immediately");
    CHECK(ngx_http_cache_turbo_brk_state((ngx_uint_t) g_sh.breaker_state)
              == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
          "a near-max breaker_open promoted the state out of OPEN");

    /* Reclaim arm: the probe LEASE deadline is the third site with the same
     * arithmetic.
     *
     * ⚠ O4.4-a moved this site off open_for and onto the fixed
     * BREAKER_PROBE_LEASE, which changes what it takes to overflow it. Seeding
     * `probe_at = 1000` and passing a near-max open_for no longer reaches the
     * addition form at all -- `1000 + 300` is not near TIME_MAX, so the arm
     * would stay green with the forbidden `now >= probe_at + lease` restored.
     * The stamp itself must sit STRICTLY INSIDE one lease of TIME_MAX instead;
     * that is where `probe_at + lease` wraps and reads a lease stamped THIS
     * INSTANT as long expired, handing a second concurrent probe to the origin.
     *
     * ⚠ `MAX - lease + 1` is NOT inside that band -- the sum lands exactly on
     * MAX, does not wrap, and both forms agree, so the arm silently stops
     * guarding anything. Verified by mutation, not by reading: the offset below
     * is deliberately well inside the band rather than on its edge.
     *
     * open_for is now irrelevant to this arm and is passed as an ordinary 30 to
     * make that explicit. */
    zone_reset();
    ngx_test_set_time(NGX_TEST_TIME_T_MAX - 100);
    g_sh.breaker_state    = ngx_http_cache_turbo_brk_pack(
                                1, NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN);
    g_sh.breaker_probe_at = (ngx_atomic_t) ngx_time();

    {
        ngx_uint_t  probe_b;
        CHECK(brk_probe_state(30, &probe_b)
                  == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
              "a lease stamped within one PROBE_LEASE of TIME_MAX overflowed "
              "its deadline and was reclaimed while live");
        CHECK(probe_b == NGX_HTTP_CACHE_TURBO_BREAKER_NO_PROBE,
              "a live lease near TIME_MAX was reclaimed and a second probe was "
              "issued a token");
    }
}


static void
test_breaker_zeroed_zone_is_closed(void)
{
    printf("breaker: a zeroed zone comes up CLOSED (fail-safe)\n");
    zone_reset();

    CHECK(brk_state(30)
              == NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED,
          "a zeroed zone did not read CLOSED");
    CHECK(g_sh.breaker_opens == 0, "a zeroed zone reported prior opens");
}


/* threshold consecutive failures inside the window trip CLOSED -> OPEN, and not
 * one failure earlier. */
static void
test_breaker_trips_at_threshold(void)
{
    printf("breaker: trips at the Nth failure, not the (N-1)th\n");
    zone_reset();
    ngx_test_set_time(1000);

    brk_record(0, 3, 60);
    brk_record(0, 3, 60);

    CHECK(brk_state(30)
              == NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED,
          "breaker opened one failure early");

    brk_record(0, 3, 60);

    CHECK(brk_state(30)
              == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
          "breaker did not open at the threshold");
    CHECK(g_sh.breaker_opens == 1, "breaker_opens was not bumped on the trip");
}


/* The window is a ROLLING anchor: failures spread wider than `window` must
 * re-anchor and never accumulate into an open. This is what stops a slow
 * trickle of unrelated 5xx from tripping a healthy origin. */
static void
test_breaker_window_rolls(void)
{
    ngx_uint_t  i;

    printf("breaker: failures spread past the window never accumulate\n");
    zone_reset();
    ngx_test_set_time(1000);

    /* Ten failures, each a full window apart. Threshold is 3, so a
     * non-rolling implementation would have opened on the third. */
    for (i = 0; i < 10; i++) {
        brk_record(0, 3, 60);
        ngx_test_advance_time(61);
    }

    CHECK(brk_state(30)
              == NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED,
          "a trickle of failures a window apart tripped the breaker");
    CHECK(g_sh.breaker_opens == 0, "breaker opened on a rolled window");
}


/* OPEN -> HALF_OPEN happens on time, and promotes EXACTLY ONE request. Every
 * other caller keeps seeing OPEN until the probe reports back -- that single
 * winner is what stops a herd from all probing a dead origin at once. */
static void
test_breaker_half_open_admits_one_probe(void)
{
    printf("breaker: one probe per open window, the rest stay OPEN\n");
    zone_reset();
    ngx_test_set_time(1000);

    brk_record(0, 1, 60);
    REQUIRE(brk_state(30)
                == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
            "breaker fixture: expected OPEN after a threshold-1 failure");

    /* Still inside the open window: no probe yet. */
    ngx_test_advance_time(29);
    CHECK(brk_state(30)
              == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
          "breaker probed before the open window elapsed");

    /* Window elapsed: the FIRST caller is promoted, the second is NOT.
     *
     * ⚠ The second assertion is the whole anti-herd property. An earlier
     * revision asserted the second caller ALSO received HALF_OPEN, which is
     * what the code did at the time -- the promotion CAS controlled who
     * TRANSITIONED, not who was ADMITTED, so every request after the winner
     * was handed the probe's verdict and walked into the dead origin. The
     * test certified the bug. Do not "restore" it. */
    ngx_test_advance_time(2);
    CHECK(brk_state(30)
              == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN,
          "breaker did not promote a probe after the open window");
    CHECK(brk_state(30)
              == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
          "a second caller was also admitted as a probe (herd)");
    CHECK(brk_state(30)
              == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
          "a third caller was also admitted as a probe (herd)");

    /* A failed probe returns to OPEN and re-arms a FULL window -- the next
     * probe must wait open_for again, not fire immediately. */
    brk_record(0, 1, 60);
    CHECK(brk_state(30)
              == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
          "a failed probe did not return the breaker to OPEN");

    ngx_test_advance_time(29);
    CHECK(brk_state(30)
              == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
          "a failed probe did not re-arm the full open window");
}


/* A promoted probe that never reports back must not wedge the breaker in
 * HALF_OPEN forever. Its request can be aborted, or its worker killed, between
 * promotion and _record() -- ordinary lifecycle events, not exotic ones. The
 * promotion is therefore a time-bounded LEASE: once stale, one replacement
 * probe is admitted. */
static void
test_breaker_abandoned_probe_lease_recovers(void)
{
    printf("breaker: an abandoned probe lease is reclaimed, once\n");
    zone_reset();
    ngx_test_set_time(1000);

    brk_record(0, 1, 60);
    ngx_test_advance_time(31);
    REQUIRE(brk_state(30)
                == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN,
            "breaker fixture: expected a promoted probe");

    /* The probe vanishes -- no _record() ever arrives. Inside the lease the
     * breaker must keep refusing everyone.
     *
     * ⚠ O4.4-a: these steps are sized from BREAKER_PROBE_LEASE, NOT from the
     * open_for passed to brk_state(). An earlier revision reclaimed on open_for
     * and this test walked the clock 29s then 2s across that 30s boundary; the
     * arithmetic looked like it was testing the lease while actually pinning
     * the coupling that made a slow-but-healthy probe unreclaimable in flight. */
    ngx_test_advance_time(
        (time_t) NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_LEASE - 1);
    CHECK(brk_state(30)
              == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
          "the probe lease was reclaimed before it went stale");

    /* Lease stale: exactly one replacement probe, and no more. */
    ngx_test_advance_time(2);
    CHECK(brk_state(30)
              == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN,
          "an abandoned probe lease was never reclaimed (wedged HALF_OPEN)");
    CHECK(brk_state(30)
              == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
          "the reclaimed lease admitted a second probe");
}


/* A success that predates the trip must not close a breaker it knows nothing
 * about. While OPEN nobody is talking to the origin, so the only success
 * carrying current information is the probe's. */
static void
test_breaker_stale_success_does_not_close(void)
{
    printf("breaker: a pre-trip success cannot close the breaker\n");
    zone_reset();
    ngx_test_set_time(1000);

    brk_record(0, 1, 60);
    REQUIRE(brk_state(30)
                == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
            "breaker fixture: expected OPEN");

    /* A request that started while the breaker was still CLOSED finally
     * completes and reports success. It must be ignored. */
    brk_record(1, 1, 60);
    CHECK(brk_state(30)
              == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
          "a stale pre-trip success closed the breaker");
}


/* A successful probe closes the breaker; open_for == 0 pins it OPEN until one
 * arrives (no timed reopen). */
static void
test_breaker_probe_success_closes(void)
{
    ngx_uint_t  probe;

    printf("breaker: a successful probe closes; open_for 0 pins OPEN\n");
    zone_reset();
    ngx_test_set_time(1000);

    brk_record(0, 1, 60);
    ngx_test_advance_time(31);
    /* O4.3: hold the lease token -- only its owner may close the breaker. */
    REQUIRE(brk_probe_state(30, &probe)
                == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN,
            "breaker fixture: expected a promoted probe");

    ngx_http_cache_turbo_shm_breaker_record(&g_zone, 1, 1, 60, probe);
    CHECK(brk_state(30)
              == NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED,
          "a successful probe did not close the breaker");

    /* Having closed, the failure run must be CLEAR. Proving that needs a run
     * long enough to cross the threshold if the old count were retained:
     * threshold 3 with 2 failures banked before the open, then 2 after the
     * close. Cleared -> 2 < 3, still CLOSED. Retained -> 2 + 2 >= 3, OPEN.
     *
     * ⚠ A SINGLE post-close failure cannot observe this (1 retained + 1 = 2,
     * under the threshold either way) -- that formulation was tried first and
     * passed with the bug restored. */
    zone_reset();
    ngx_test_set_time(1000);
    brk_record(0, 3, 60);
    brk_record(0, 3, 60);
    brk_record(1, 3, 60);   /* success */
    brk_record(0, 3, 60);
    brk_record(0, 3, 60);
    CHECK(brk_state(30)
              == NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED,
          "the failure counter survived a success");

    /* open_for == 0 disables the timed reopen. */
    zone_reset();
    ngx_test_set_time(1000);
    brk_record(0, 1, 60);
    ngx_test_advance_time(100000);
    CHECK(brk_state(0)
              == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
          "open_for 0 still performed a timed reopen");
}


/* O4.3-c/F1 -- the lease token must be bound to the GENERATION it was issued
 * for, not merely to "some HALF_OPEN". Codex review of PR #135.
 *
 * ⚠ WHY THIS TEST CONSTRUCTS THE STATE INSTEAD OF DRIVING IT. Both F1 schedules
 * are windows INSIDE one function -- the gap between the promotion CAS and the
 * probe_at store, and a state-only CAS that carries no generation. A
 * single-threaded harness calls those functions atomically and can never
 * observe either window by ordinary driving. The first formulation of this test
 * tried exactly that (promote A, let its lease go stale, promote B, then record
 * A) and PASSED against the unfixed code: every promotion overwrites probe_at,
 * so with the clock advanced between A and B the existing stamp comparison
 * already rejects A. It certified a case the shipped token handles and said
 * nothing about F1.
 *
 * So the fixture below writes the shm fields directly to construct the exact
 * inconsistent state a concurrent worker WOULD observe, then asks the real
 * function for its verdict -- the same technique the O4.1-a negative control
 * already uses. The state is reachable in production; only the schedule that
 * produces it is unreachable here.
 *
 * Schedule 1 (unsafe publication): worker A wins OPEN -> HALF_OPEN and is
 * descheduled BEFORE `breaker_probe_at = now`. Worker B now observes HALF_OPEN
 * paired with the PREVIOUS lease's stamp -- necessarily old, and zero on the
 * very first lease. B computes that lease as long expired, reclaims it, and is
 * promoted itself. Two live probes against a dead origin, which is the precise
 * herd this breaker exists to prevent. */
static void
test_breaker_unpublished_lease_is_not_reclaimable(void)
{
    ngx_uint_t  probe_b;

    printf("breaker: a lease whose stamp is not yet published is not stale\n");
    zone_reset();
    ngx_test_set_time(1000);

    /* Construct A's half-published promotion: HALF_OPEN is visible, the stamp
     * still holds the zeroed-zone value it had before the CAS. */
    g_sh.breaker_state    = NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN;
    g_sh.breaker_probe_at = 0;

    /* B arrives. It must NOT read this as an abandoned lease: A holds a live
     * probe and is simply between two stores. */
    CHECK(brk_probe_state(30, &probe_b)
              == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
          "a half-published lease was reclaimed as stale, admitting a second "
          "concurrent probe");
    CHECK(probe_b == NGX_HTTP_CACHE_TURBO_BREAKER_NO_PROBE,
          "a second probe was issued a lease token while the first was still "
          "live");
}


/* O4.4-a: the probe lease is bounded by BREAKER_PROBE_LEASE, not by open_for.
 *
 * The defect this pins wedged the breaker permanently OPEN against an origin
 * that was merely SLOW. With the lease reclaimed on open_for, a probe taking
 * longer than open_for lost its lease in flight; its healthy response then
 * arrived holding a superseded generation and was discarded (correctly), so
 * nothing could ever record the success that closes the breaker.
 *
 * Two arms, because either alone is satisfiable by a wrong constant: the lease
 * must OUTLIVE open_for, and it must still EXPIRE -- a lease that never expires
 * re-introduces the wedge the reclaim path exists to prevent, just at the other
 * end. The elapsed times are expressed relative to the constant so the test
 * follows it if the value is ever re-tuned, with one deliberate exception: the
 * upper bound is an ABSOLUTE ceiling, because a relative one scales with the
 * constant and would accept any value at all. */
static void
test_breaker_probe_lease_is_independent_of_open(void)
{
    ngx_uint_t  probe_a, probe_b;
    time_t      lease = (time_t) NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_LEASE;

    printf("breaker: the probe lease is independent of breaker_open\n");

    /* The hazard only exists when a probe can outlast open_for, which is what
     * the shipped 30s default against a 60s proxy_read_timeout looks like. */
    REQUIRE(lease > 30,
            "breaker fixture: probe lease must exceed the open_for used here, "
            "or this test cannot reach the coupling it pins");

    zone_reset();
    ngx_test_set_time(1000);

    brk_record(0, 1, 60);
    ngx_test_advance_time(31);
    REQUIRE(brk_probe_state(30, &probe_a)
                == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN,
            "breaker fixture: expected probe A to be promoted");
    REQUIRE(probe_a != NGX_HTTP_CACHE_TURBO_BREAKER_NO_PROBE,
            "breaker fixture: probe A was issued no token");

    /* Arm 1 -- A is slower than open_for but well inside its lease. This is the
     * slow-but-healthy origin. A's lease must still be its own. */
    ngx_test_advance_time(31);
    CHECK(brk_probe_state(30, &probe_b) == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
          "a probe slower than breaker_open had its lease reclaimed in flight; "
          "its response will carry a superseded generation and the breaker can "
          "never close");
    CHECK(probe_b == NGX_HTTP_CACHE_TURBO_BREAKER_NO_PROBE,
          "a second probe was promoted while the first was still inside its "
          "lease");

    /* A now reports success on the token it still holds -- the raw call, since
     * brk_record() hardcodes NO_PROBE and could never resolve a lease. With the
     * lease coupled to open_for this token is stale and the breaker stays OPEN
     * forever; that is the user-visible consequence, asserted not inferred. */
    ngx_http_cache_turbo_shm_breaker_record(&g_zone, 1, 1, 60, probe_a);
    CHECK(brk_probe_state(30, &probe_b) == NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED,
          "a slow-but-healthy probe reported success and the breaker did not "
          "close");

    /* ⚠ The lease must also be BOUNDED, and that cannot be asserted by stepping
     * `lease + 1` -- such a step scales with the constant, so an absurd lease
     * still passes and the arm certifies nothing. The bound is asserted here as
     * an absolute ceiling instead: an abandoned probe diverts every affected
     * origin-bound MISS to a stale body or a 503 until it is reclaimed (fresh
     * hits never reach the breaker), so a lease measured in hours is an outage,
     * not a backstop. 15 minutes is far above any real origin timeout and far
     * below "operationally indistinguishable from wedged". */
    CHECK(lease <= 900,
          "the probe lease exceeds 15 minutes; an abandoned probe would divert "
          "origin-bound misses for that long before a replacement is admitted");

    /* Arm 2 -- the lease still expires. Promote a fresh probe, abandon it, and
     * step just past the lease: the slot must be reclaimable, or an aborted
     * probe wedges the breaker in HALF_OPEN permanently. */
    zone_reset();
    ngx_test_set_time(1000);

    brk_record(0, 1, 60);
    ngx_test_advance_time(31);
    REQUIRE(brk_probe_state(30, &probe_a)
                == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN,
            "breaker fixture: expected the second probe to be promoted");

    ngx_test_advance_time((time_t) (lease + 1));
    CHECK(brk_probe_state(30, &probe_b)
              == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN,
          "an abandoned lease was not reclaimed after the probe lease elapsed; "
          "the breaker is wedged in HALF_OPEN");
    CHECK(probe_b != NGX_HTTP_CACHE_TURBO_BREAKER_NO_PROBE,
          "the reclaiming caller was not issued a replacement lease token");
}


/* O4.3-c/F1 schedule 2 (state-only CAS -> ABA): probe A validates its token and
 * is descheduled. Its lease is reclaimed, a replacement probe B is promoted,
 * and only then does A's CAS land. The CAS tests HALF_OPEN -> CLOSED and
 * nothing else, so it succeeds against B's generation.
 *
 * A's success closes a breaker that only A -- whose evidence predates the
 * replacement lease entirely -- ever tested, releasing the herd toward an
 * origin the current probe has not answered for.
 *
 * Constructed the same way and for the same reason as the test above: the
 * fixture rebuilds the state in which A's token is stale-but-equal, which is
 * what a bare stamp comparison cannot distinguish. Both leases are stamped in
 * the SAME second on purpose -- that is the collision the shipped comparison
 * misses, and advancing the clock between them is what made the first version
 * of this test vacuous. */
static void
test_breaker_stale_probe_cannot_resolve_new_lease(void)
{
    ngx_uint_t  probe_a;

    printf("breaker: a stale probe cannot resolve a later lease (ABA)\n");
    zone_reset();
    ngx_test_set_time(1000);

    brk_record(0, 1, 60);
    ngx_test_advance_time(31);
    REQUIRE(brk_probe_state(30, &probe_a)
                == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN,
            "breaker fixture: expected probe A to be promoted");
    REQUIRE(probe_a != NGX_HTTP_CACHE_TURBO_BREAKER_NO_PROBE,
            "breaker fixture: probe A was issued no token");

    /* A's lease is reclaimed and a replacement probe is promoted while A is
     * still in flight. Constructed directly: a NEW generation, stamped in the
     * SAME wall-clock second A was. The stamp is therefore identical, so a
     * comparison against breaker_probe_at cannot tell the two leases apart --
     * only a generation carried by the resolving CAS can. */
    g_sh.breaker_state    = (ngx_atomic_t) ngx_http_cache_turbo_brk_pack(
                                ngx_http_cache_turbo_brk_gen(
                                    g_sh.breaker_state) + 1,
                                NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN);

    /* ⚠ The two preconditions this test rests on. Without them it passes for
     * the wrong reason: an unequal stamp would let the OLD stamp comparison
     * reject A on its own, and an equal generation would mean no replacement
     * lease was actually constructed. */
    REQUIRE((ngx_uint_t) g_sh.breaker_probe_at == (ngx_uint_t) ngx_test_now,
            "breaker fixture: the replacement lease is not stamp-equal to A's, "
            "so this test cannot distinguish a generation from a stamp check");
    REQUIRE(ngx_http_cache_turbo_brk_gen(g_sh.breaker_state) != probe_a,
            "breaker fixture: the replacement lease reuses A's generation, so "
            "there is no superseded lease to test");

    /* A's success finally lands, naming a lease that has since been replaced. */
    ngx_http_cache_turbo_shm_breaker_record(&g_zone, 1, 1, 60, probe_a);

    CHECK(brk_state(30)
              == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
          "a stale probe's success closed a replacement lease it did not own");

    /* Symmetric: a stale FAILURE must not cancel the replacement lease either,
     * which would push recovery out by another full window on evidence that
     * belongs to a lease nobody is waiting on. */
    zone_reset();
    ngx_test_set_time(1000);
    brk_record(0, 1, 60);
    ngx_test_advance_time(31);
    REQUIRE(brk_probe_state(30, &probe_a)
                == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN,
            "breaker fixture: expected probe A to be promoted");

    g_sh.breaker_state     = (ngx_atomic_t) ngx_http_cache_turbo_brk_pack(
                                 ngx_http_cache_turbo_brk_gen(
                                     g_sh.breaker_state) + 1,
                                 NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN);
    g_sh.breaker_probe_at  = (ngx_atomic_t) ngx_test_now;
    g_sh.breaker_opened_at = (ngx_atomic_t) ngx_test_now;

    ngx_http_cache_turbo_shm_breaker_record(&g_zone, 0, 1, 60, probe_a);

    CHECK(ngx_http_cache_turbo_brk_state(g_sh.breaker_state)
              == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN,
          "a stale probe's failure re-opened a replacement lease it did not "
          "own");
}


/* threshold == 0 disables tripping entirely (the off switch O4.4's default
 * relies on). */
static void
test_breaker_threshold_zero_never_trips(void)
{
    ngx_uint_t  i;

    printf("breaker: threshold 0 never trips\n");
    zone_reset();
    ngx_test_set_time(1000);

    for (i = 0; i < 50; i++) {
        brk_record(0, 0, 60);
    }

    CHECK(brk_state(30)
              == NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED,
          "threshold 0 tripped the breaker");
    CHECK(g_sh.breaker_opens == 0, "threshold 0 recorded an open");
}


/* window == 0 is INERT, not "accumulate forever". O4.4 feeds this from a
 * directive, so an unset window is a plausible arrival and must fail towards
 * "breaker does nothing" the same way threshold == 0 does. */
static void
test_breaker_zero_window_never_trips(void)
{
    ngx_uint_t  i;

    printf("breaker: window 0 is inert, not cumulative\n");
    zone_reset();
    ngx_test_set_time(1000);

    /* Fifty failures, days apart. A cumulative reading would have tripped at
     * the third. */
    for (i = 0; i < 50; i++) {
        brk_record(0, 3, 0);
        ngx_test_advance_time(86400);
    }

    CHECK(brk_state(30)
              == NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED,
          "window 0 accumulated failures and tripped the breaker");
    CHECK(g_sh.breaker_opens == 0, "window 0 recorded an open");
}


/* The rendered state strings are what the admin JSON exposes; an unknown id
 * must render, not crash. */
static void
test_breaker_state_strings(void)
{
    printf("breaker: state ids render as stable strings\n");

    CHECK(strcmp(ngx_http_cache_turbo_shm_breaker_state_str(
                     NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED), "closed") == 0,
          "CLOSED did not render as \"closed\"");
    CHECK(strcmp(ngx_http_cache_turbo_shm_breaker_state_str(
                     NGX_HTTP_CACHE_TURBO_BREAKER_OPEN), "open") == 0,
          "OPEN did not render as \"open\"");
    CHECK(strcmp(ngx_http_cache_turbo_shm_breaker_state_str(
                     NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN), "half-open") == 0,
          "HALF_OPEN did not render as \"half-open\"");
    CHECK(strcmp(ngx_http_cache_turbo_shm_breaker_state_str(99),
                 "unknown") == 0,
          "an out-of-range state did not render as \"unknown\"");
}


/* =====================================================================
 * P6/O4.2 -- which origin outcomes feed the breaker
 * ===================================================================== */

/* Every 5xx means "the origin is down", including the ones no config token can
 * name individually. 599 is the inclusive upper bound; 600 is not a 5xx. */
static void
test_breaker_failure_counts_every_5xx(void)
{
    printf("breaker/O4.2: every 5xx counts as an origin failure\n");

    CHECK(ngx_http_cache_turbo_breaker_is_origin_failure(500),
          "500 was not counted as an origin failure");
    CHECK(ngx_http_cache_turbo_breaker_is_origin_failure(502),
          "502 was not counted as an origin failure");
    CHECK(ngx_http_cache_turbo_breaker_is_origin_failure(503),
          "503 was not counted as an origin failure");
    CHECK(ngx_http_cache_turbo_breaker_is_origin_failure(504),
          "504 was not counted as an origin failure");

    /* The statuses only ANY_5XX covers -- a breaker that missed these would
     * ignore real outages from origins that answer 507/508/511. */
    CHECK(ngx_http_cache_turbo_breaker_is_origin_failure(507),
          "507 was not counted as an origin failure");
    CHECK(ngx_http_cache_turbo_breaker_is_origin_failure(599),
          "599 (inclusive upper bound) was not counted as a failure");
}


/* ⚠ The load-bearing test of O4.2. The breaker's failure predicate must NOT be
 * the use_stale trigger: use_stale legitimately names 403/404/429, every one of
 * which is a HEALTHY origin answering correctly. If those ever start counting,
 * a 404-heavy site trips its own breaker and 503s everything while the backend
 * is fine -- an outage caused by switching on an unrelated stale-serve option.
 *
 * 200 is here for the obvious reason; 3xx/4xx because they are what the
 * use_stale mask can be configured to include. */
static void
test_breaker_failure_ignores_healthy_statuses(void)
{
    printf("breaker/O4.2: healthy statuses never count as origin failures\n");

    CHECK(!ngx_http_cache_turbo_breaker_is_origin_failure(200),
          "200 was counted as an origin failure");
    CHECK(!ngx_http_cache_turbo_breaker_is_origin_failure(301),
          "301 was counted as an origin failure");
    CHECK(!ngx_http_cache_turbo_breaker_is_origin_failure(304),
          "304 was counted as an origin failure");

    /* The three use_stale can name. These are the regression that matters. */
    CHECK(!ngx_http_cache_turbo_breaker_is_origin_failure(403),
          "403 counted as an origin failure — use_stale leaked into the "
          "breaker; a healthy origin can now trip it");
    CHECK(!ngx_http_cache_turbo_breaker_is_origin_failure(404),
          "404 counted as an origin failure — use_stale leaked into the "
          "breaker; a 404-heavy site will trip its own breaker");
    CHECK(!ngx_http_cache_turbo_breaker_is_origin_failure(429),
          "429 counted as an origin failure — use_stale leaked into the "
          "breaker");

    /* Below the 5xx floor by one, and above the ceiling by one. */
    CHECK(!ngx_http_cache_turbo_breaker_is_origin_failure(499),
          "499 was counted as an origin failure");
    CHECK(!ngx_http_cache_turbo_breaker_is_origin_failure(600),
          "600 was counted as an origin failure");
}


/* The two conditions that together mean "this came off the wire". Tested as a
 * pair because the dangerous case is the one where only half holds. */
static void
test_breaker_from_origin(void)
{
    printf("breaker/O4.2: upstream present AND not a native cache hit\n");

    CHECK(ngx_http_cache_turbo_breaker_from_origin(1, 0),
          "a real upstream response was not treated as coming from the origin");

    /* No upstream at all: the only-if-cached 504 the module generates itself. */
    CHECK(!ngx_http_cache_turbo_breaker_from_origin(0, 0),
          "a response with no upstream was treated as coming from the origin");

    /* ⚠ upstream allocated, but nginx served it from its OWN disk cache.
     * ngx_http_upstream_cache_send() sets r->cached = 1 with r->upstream
     * already in place, so the upstream check alone passes here. */
    CHECK(!ngx_http_cache_turbo_breaker_from_origin(1, 1),
          "a native proxy_cache HIT was treated as an origin response — the "
          "disk cache could close a breaker no probe ever tested");

    CHECK(!ngx_http_cache_turbo_breaker_from_origin(0, 1),
          "a cached response with no upstream was treated as an origin "
          "response");
}


/* The bug O4.2-a and O4.2-b model: the use_stale trigger reused as the
 * breaker's failure test (what this step's original spec called for). Written
 * out explicitly and kept local so the controls can assert that the REAL
 * predicate DISAGREES with it — a control that hardcodes its verdict never
 * touches the production function and would survive any mutation of it.
 *
 * Mirrors USE_STALE_DEFAULT plus the three healthy statuses an operator can
 * add: 403, 404, 429. */
static ngx_uint_t
buggy_use_stale_is_failure(ngx_uint_t status)
{
    return status == 403 || status == 404 || status == 429
           || (status >= 500 && status <= 504);
}


/* ⚠ The admission rule, driven directly rather than restated. Each argument is
 * withheld in turn; every one of them must be able to veto on its own. */
static void
test_breaker_should_record_admission(void)
{
    printf("breaker/O4.2: only a real origin response feeds the breaker\n");

    /* served=0, from_origin=1, main=1, threshold=3 -- the one admitted case. */
    CHECK(ngx_http_cache_turbo_breaker_should_record(0, 1, 1, 3),
          "a genuine origin response was not admitted");

    /* Our own cache serve says nothing about the origin. */
    CHECK(!ngx_http_cache_turbo_breaker_should_record(1, 1, 1, 3),
          "a cache serve was fed to the breaker — it would read a dead origin "
          "as healthy for as long as the cache kept serving");

    /* ⚠ Not from the origin. Two distinct real cases collapse onto this arm,
     * and the call site must exclude both:
     *   - an only-if-cached miss, answered 504 locally with no upstream at
     *     all. Client-triggerable: if it counts, a visitor trips a healthy
     *     zone's breaker just by repeating a request header.
     *   - a native proxy_cache/fastcgi_cache HIT, where r->upstream IS
     *     allocated but ngx_http_upstream_cache_send() served from disk and
     *     set r->cached. Somebody else's cache hit; counting it lets the disk
     *     cache close a breaker no probe ever tested. */
    CHECK(!ngx_http_cache_turbo_breaker_should_record(0, 0, 1, 3),
          "a response that did not come from the origin was fed to the "
          "breaker — either a client can trip a healthy origin's breaker, or "
          "a native cache HIT can close one without probing");

    /* Not the origin conversation we track. */
    CHECK(!ngx_http_cache_turbo_breaker_should_record(0, 1, 0, 3),
          "a foreign subrequest was fed to the breaker");

    /* threshold 0 = breaker off: skip the call entirely, because
     * _breaker_record()'s success path writes breaker_fails before it ever
     * consults the threshold. */
    CHECK(!ngx_http_cache_turbo_breaker_should_record(0, 1, 1, 0),
          "the breaker was recorded into while disabled — 'off' must not put "
          "a shared-memory write on every successful response");
}


/* P6/O4.3-O4.4: the pre-origin gate's admission rule. Same shape and same
 * reason as the O4.2 recording admission above -- the serve path must drive
 * the real predicate, not a restatement of it.
 *
 * O4.4 regression pin: this is the ONLY test that calls the real
 * ngx_http_cache_turbo_breaker_should_consult() function directly rather than
 * through a config-parse test. Config-parse tests can prove a directive is
 * ACCEPTED; they cannot prove the predicate a config value feeds is correct,
 * nor that a call site was wired to it at all -- see extract_shm.sh's
 * brk_consulted latch guard for the complementary "was it wired" check on the
 * pre-origin gate specifically. Each CHECK below independently zeroes exactly
 * one of the four required conditions to prove the predicate is a genuine AND
 * of all four, not e.g. an OR, or a predicate that silently ignores one
 * input. */
static void
test_breaker_should_consult_admission(void)
{
    ngx_http_cache_turbo_loc_conf_t  clcf;

    printf("breaker/O4.3-O4.4: the serve path consults the breaker only "
           "when ALL FOUR of enable/breaker_enable/threshold/window hold\n");

    /* All four true -> consult. */
    clcf.enable = 1;
    clcf.breaker_enable = 1;
    clcf.breaker_threshold = 3;
    clcf.breaker_window = 60;
    CHECK(ngx_http_cache_turbo_breaker_should_consult(&clcf),
          "an enabled breaker (all four conditions true) was not consulted "
          "on the pre-origin path");

    /* clcf->enable off (module disabled here) -> never consult, even if every
     * breaker-specific field says on. */
    clcf.enable = 0;
    clcf.breaker_enable = 1;
    clcf.breaker_threshold = 3;
    clcf.breaker_window = 60;
    CHECK(!ngx_http_cache_turbo_breaker_should_consult(&clcf),
          "the breaker was consulted in a location where cache_turbo itself "
          "is off");

    /* cache_turbo_breaker off -> never consult, even with a configured
     * threshold/window (an operator who left the breaker off but set the
     * tuning knobs must NOT get it silently switched on). */
    clcf.enable = 1;
    clcf.breaker_enable = 0;
    clcf.breaker_threshold = 3;
    clcf.breaker_window = 60;
    CHECK(!ngx_http_cache_turbo_breaker_should_consult(&clcf),
          "the breaker was consulted with cache_turbo_breaker off — "
          "breaker_enable must be an independent off-switch");

    /* ⚠ Not merely an optimisation. _breaker_state() PERFORMS the due
     * OPEN -> HALF_OPEN promotion, and the O4.2/O4.4 recording site is gated
     * on this same predicate, so consulting it while disabled would promote a
     * probe that nothing can ever report an outcome for. */
    clcf.enable = 1;
    clcf.breaker_enable = 1;
    clcf.breaker_threshold = 0;
    clcf.breaker_window = 60;
    CHECK(!ngx_http_cache_turbo_breaker_should_consult(&clcf),
          "a disabled breaker (threshold 0) was consulted — the state call "
          "is not a pure getter, so this drives a state machine nothing "
          "feeds");

    /* window 0 -> never consult, even with a real threshold: a trip count
     * with no rolling window to count it over is a meaningless config, and
     * must be as inert as threshold 0. */
    clcf.enable = 1;
    clcf.breaker_enable = 1;
    clcf.breaker_threshold = 3;
    clcf.breaker_window = 0;
    CHECK(!ngx_http_cache_turbo_breaker_should_consult(&clcf),
          "a disabled breaker (window 0) was consulted — window is one of "
          "the three independent off-switches, not a pure tuning knob");
}


/* P6/O4.3: state + body availability -> serve-path action. */
static void
test_breaker_action_mapping(void)
{
    printf("breaker/O4.3: OPEN serves any-age body, else 503; probe passes\n");

    /* CLOSED is normal service regardless of what is cached. */
    CHECK(ngx_http_cache_turbo_breaker_action(
              NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED, 1)
              == NGX_HTTP_CACHE_TURBO_BRK_ACT_PASS,
          "a CLOSED breaker interfered with a normal request");
    CHECK(ngx_http_cache_turbo_breaker_action(
              NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED, 0)
              == NGX_HTTP_CACHE_TURBO_BRK_ACT_PASS,
          "a CLOSED breaker interfered with a normal cold request");

    /* ⚠ THE probe assertion. HALF_OPEN is returned to exactly one request per
     * open window, and that promotion is a lease only _record() releases.
     * Answering it from cache means no origin contact, so no outcome is ever
     * recorded and the breaker cannot close -- it re-promotes one doomed probe
     * per window forever. A body being available must not change that, which is
     * what makes this a different rule from the OPEN arm below.
     *
     * ⚠ O4.3-c: this must be PROBE, not PASS. PASS states only "the breaker did
     * not interfere" and lets the request fall through into min_uses, claim(),
     * the NX lock and cold_wait() -- all of which can park it and let it return
     * from a pre-gate cache serve on resume, which is the very outcome the
     * paragraph above forbids. PROBE is terminal: the gate returns to the
     * origin immediately. Restoring PASS here reinstates Codex F2. */
    CHECK(ngx_http_cache_turbo_breaker_action(
              NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN, 1)
              == NGX_HTTP_CACHE_TURBO_BRK_ACT_PROBE,
          "the HALF_OPEN probe was served from cache — nothing would reach the "
          "origin, so no outcome is recorded and the breaker wedges OPEN");
    CHECK(ngx_http_cache_turbo_breaker_action(
              NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN, 0)
              == NGX_HTTP_CACHE_TURBO_BRK_ACT_PROBE,
          "the HALF_OPEN probe was 503'd instead of probing the origin");

    /* OPEN: a body of ANY age beats a 503, and only its presence decides. */
    CHECK(ngx_http_cache_turbo_breaker_action(
              NGX_HTTP_CACHE_TURBO_BREAKER_OPEN, 1)
              == NGX_HTTP_CACHE_TURBO_BRK_ACT_SERVE,
          "an OPEN breaker did not serve the cached body it had");
    CHECK(ngx_http_cache_turbo_breaker_action(
              NGX_HTTP_CACHE_TURBO_BREAKER_OPEN, 0)
              == NGX_HTTP_CACHE_TURBO_BRK_ACT_FAIL,
          "an OPEN breaker with nothing cached did not answer 503");
}


/* P6/O4.3: the probe mapping and the state machine, driven together.
 *
 * The pure mapping test above cannot see whether the value it maps is the one
 * the state machine actually hands out. This drives the real pair: trip the
 * breaker, let the open window elapse, and confirm the promoted request is told
 * to PASS and that reporting its success then CLOSES the breaker -- i.e. that
 * the O4.3 serve path can actually complete an O4.1 recovery cycle. A serve-path
 * change that swallowed the probe would leave this breaker OPEN forever. */
static void
test_breaker_probe_passes_and_recovery_completes(void)
{
    ngx_uint_t  i, state, act, probe;

    printf("breaker/O4.3: the promoted probe reaches origin and closes it\n");

    zone_reset();
    ngx_test_set_time(1000);

    for (i = 0; i < 3; i++) {
        brk_record(!ngx_http_cache_turbo_breaker_is_origin_failure(503),
            3, 60);
    }

    /* While OPEN, a request holding a stale body serves it and never leaves. */
    state = brk_state(30);
    CHECK(state == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
          "three 503s did not open the breaker");
    CHECK(ngx_http_cache_turbo_breaker_action(state, 1)
              == NGX_HTTP_CACHE_TURBO_BRK_ACT_SERVE,
          "an OPEN breaker sent a request to a dead origin");

    /* The open window elapses: exactly one request is promoted, and it must be
     * told to go to the origin. */
    ngx_test_set_time(1031);
    /* O4.3: keep the lease token; only its owner may close the breaker. */
    state = brk_probe_state(30, &probe);
    CHECK(state == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN,
          "no probe was promoted after the open window elapsed");
    act = ngx_http_cache_turbo_breaker_action(state, 1);
    CHECK(act == NGX_HTTP_CACHE_TURBO_BRK_ACT_PROBE,
          "the promoted probe did not reach the origin — with a body cached "
          "the serve path would answer it locally and the breaker would wedge");

    /* Everyone else still sees OPEN while the probe is out (anti-herd). */
    CHECK(brk_state(30)
              == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
          "a second request was also promoted — the herd walks into the origin");

    /* The probe reports success through the header filter, under ITS lease
     * token: breaker closes. */
    ngx_http_cache_turbo_shm_breaker_record(&g_zone,
        !ngx_http_cache_turbo_breaker_is_origin_failure(200), 3, 60, probe);
    state = brk_state(30);
    CHECK(state == NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED,
          "a successful probe did not close the breaker");
    CHECK(ngx_http_cache_turbo_breaker_action(state, 1)
              == NGX_HTTP_CACHE_TURBO_BRK_ACT_PASS,
          "the recovered breaker still refused to pass traffic");
}


/* P6/O4.3 (F1): only the request holding the lease token may resolve HALF_OPEN.
 *
 * Without the token, ANY origin outcome completing during the open window
 * resolves the lease: a request that started before the trip reports "origin
 * fine" and closes a breaker it never tested, releasing the herd onto a still
 * dead origin. The promoted probe, meanwhile, may never reach the origin at all
 * (it can lose the Redis NX and be served from a peer's L2 fill), leaving the
 * lease with no outcome. Both halves are asserted here. */
static void
test_breaker_only_the_probe_token_closes(void)
{
    ngx_uint_t  i, state, probe, other;

    printf("breaker/O4.3: only the lease owner's outcome resolves HALF_OPEN\n");

    zone_reset();
    ngx_test_set_time(1000);
    for (i = 0; i < 3; i++) {
        brk_record(!ngx_http_cache_turbo_breaker_is_origin_failure(503), 3, 60);
    }

    ngx_test_set_time(1031);
    state = brk_probe_state(30, &probe);
    CHECK(state == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN,
          "no probe was promoted after the open window elapsed");
    CHECK(probe != NGX_HTTP_CACHE_TURBO_BREAKER_NO_PROBE,
          "the promoted probe was not given a lease token");

    /* A non-probe success -- an older in-flight request, or one served from a
     * peer's fill -- must NOT close the breaker. */
    brk_record(1, 3, 60);
    CHECK(ngx_http_cache_turbo_brk_state(g_zone.sh->breaker_state)
              == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN,
          "a success WITHOUT the lease token closed the breaker — an outcome "
          "from a request that never probed would release the herd onto a "
          "still-dead origin");

    /* A non-probe FAILURE must not re-stamp the window either. */
    brk_record(0, 3, 60);
    CHECK(ngx_http_cache_turbo_brk_state(g_zone.sh->breaker_state)
              == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN,
          "a failure WITHOUT the lease token resolved the lease");

    /* A stale token from no lease at all is still refused. */
    other = probe + 12345;
    ngx_http_cache_turbo_shm_breaker_record(&g_zone, 1, 3, 60, other);
    CHECK(ngx_http_cache_turbo_brk_state(g_zone.sh->breaker_state)
              == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN,
          "a WRONG lease token closed the breaker");

    /* The real owner closes it. */
    ngx_http_cache_turbo_shm_breaker_record(&g_zone, 1, 3, 60, probe);
    CHECK(ngx_http_cache_turbo_brk_state(g_zone.sh->breaker_state)
              == NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED,
          "the lease owner's success did not close the breaker");
}


/* P6/O4.3 (F1): a failed probe re-opens only for its own lease owner. */
static void
test_breaker_probe_token_reopens(void)
{
    ngx_uint_t  i, state, probe;

    printf("breaker/O4.3: the lease owner's failure re-opens a fresh window\n");

    zone_reset();
    ngx_test_set_time(1000);
    for (i = 0; i < 3; i++) {
        brk_record(!ngx_http_cache_turbo_breaker_is_origin_failure(503), 3, 60);
    }

    ngx_test_set_time(1031);
    state = brk_probe_state(30, &probe);
    CHECK(state == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN,
          "no probe was promoted");

    ngx_http_cache_turbo_shm_breaker_record(
        &g_zone, !ngx_http_cache_turbo_breaker_is_origin_failure(502), 3, 60,
        probe);
    CHECK(ngx_http_cache_turbo_brk_state(g_zone.sh->breaker_state)
              == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
          "the probe's failure did not re-open the breaker");

    /* And the fresh window really is fresh: no immediate re-promotion. */
    CHECK(brk_state(30) == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
          "a probe was promoted again immediately after a failed probe — the "
          "open window was skipped");
}


/* P6/O4.3: consulting the breaker TWICE for one request wedges it.
 *
 * The access handler is re-entered from the top on every park/resume (L2 GET,
 * the v4-2 NX lock, each cold_wait re-poll). _breaker_state() promotes exactly
 * one caller per open window and returns HALF_OPEN only to that promoter, so a
 * request that was promoted and then parked is handed OPEN on its resume --
 * answered from cache, never reaching the origin, leaving nobody to report an
 * outcome. The production fix is the ctx->brk_consulted latch; this pins the
 * shm-level behaviour that makes the latch necessary, so a future "simplify"
 * that drops it fails here rather than in an outage.
 *
 * ⚠ This test asserts the SECOND call returns OPEN. That is not the desired
 * behaviour of the request path -- it is the trap the request path must avoid. */
static void
test_breaker_second_consult_loses_the_probe(void)
{
    ngx_uint_t  i, first, second;

    printf("breaker/O4.3: a second consult in one request loses the probe\n");

    zone_reset();
    ngx_test_set_time(1000);

    for (i = 0; i < 3; i++) {
        brk_record(!ngx_http_cache_turbo_breaker_is_origin_failure(503),
            3, 60);
    }

    ngx_test_set_time(1031);

    first = brk_state(30);
    CHECK(first == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN,
          "the first consult was not promoted to probe");
    CHECK(ngx_http_cache_turbo_breaker_action(first, 1)
              == NGX_HTTP_CACHE_TURBO_BRK_ACT_PROBE,
          "the promoted probe was not sent to the origin");

    /* The SAME request consulting again -- what an unlatched gate does on a
     * park/resume. It is no longer the promoter, so it is told OPEN. */
    second = brk_state(30);
    CHECK(second == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
          "a second consult did not return OPEN — if this ever changes, the "
          "brk_consulted latch's rationale needs rechecking");
    CHECK(ngx_http_cache_turbo_breaker_action(second, 1)
              == NGX_HTTP_CACHE_TURBO_BRK_ACT_SERVE,
          "the re-consulted request was not diverted — this is the wedge: it "
          "holds the probe lease but is answered from cache, so no outcome is "
          "ever recorded and the breaker cannot close");

    /* Nothing closed the breaker, because the probe never reported. */
    CHECK(ngx_http_cache_turbo_brk_state(g_zone.sh->breaker_state)
              == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN,
          "the breaker left the half-open lease unexpectedly");
}


/* The predicate is what the request path actually feeds to _record(), so drive
 * the real pair end to end: a run of 5xx trips the breaker, and the same number
 * of 404s does not. This is the assertion that would catch the two being wired
 * up backwards -- the pure-predicate tests above cannot see the call site. */
static void
test_breaker_record_driven_by_predicate(void)
{
    ngx_uint_t  i;

    printf("breaker/O4.2: 5xx runs trip the breaker, 404 runs do not\n");

    /* Three 503s at threshold 3 -> OPEN. */
    zone_reset();
    ngx_test_set_time(1000);
    for (i = 0; i < 3; i++) {
        brk_record(!ngx_http_cache_turbo_breaker_is_origin_failure(503),
            3, 60);
    }
    CHECK(brk_state(30)
              == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN,
          "three origin 503s did not trip the breaker");

    /* The same run of 404s must leave it CLOSED, and record no failures. */
    zone_reset();
    ngx_test_set_time(1000);
    for (i = 0; i < 3; i++) {
        brk_record(!ngx_http_cache_turbo_breaker_is_origin_failure(404),
            3, 60);
    }
    CHECK(brk_state(30)
              == NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED,
          "a run of 404s tripped the breaker against a healthy origin");
    CHECK(g_sh.breaker_opens == 0,
          "a run of 404s recorded a breaker trip");
    CHECK(g_sh.breaker_fails == 0,
          "a run of 404s accumulated failures");
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
    REQUIRE(ctn != NULL, "CR-A control fixture: memo node missing after claim");
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
    REQUIRE(ctn != NULL, "CR-B control fixture: COUNTER node missing");
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

    /* --- P6/O4.1 breaker controls ------------------------------------- */

    /* O4.1-a restored: a NON-rolling window (never re-anchor). The trickle in
     * test_breaker_window_rolls must then accumulate and trip. */
    zone_reset();
    ngx_test_set_time(1000);
    g_sh.breaker_window_start = 1000;
    {
        ngx_uint_t  i;

        /* The bug injected into REAL shared state: bump breaker_fails without
         * ever re-anchoring the window, which is what dropping the re-anchor
         * branch would do. Then ask the REAL function for its verdict. */
        for (i = 0; i < 10; i++) {
            g_sh.breaker_fails++;               /* <-- the bug: no re-anchor */
            ngx_test_advance_time(61);
        }

        if (g_sh.breaker_fails >= 3) {
            g_sh.breaker_opened_at = (ngx_atomic_t) ngx_test_now;
            g_sh.breaker_state = NGX_HTTP_CACHE_TURBO_BREAKER_OPEN;
        }

        caught = (brk_state(30)
                      == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN);
        tests_run++;
        if (!caught) {
            fprintf(stderr, "  ✗ CONTROL O4.1-a: a non-rolling window did not "
                            "reach the threshold — test_breaker_window_rolls "
                            "guards nothing\n");
            tests_failed++;
        }
    }

    /* O4.1-b restored: return the STORED state instead of reserving HALF_OPEN
     * for the CAS winner. That is what the first revision of this code did, and
     * it is the herd bug: once one caller is promoted, every subsequent caller
     * loads HALF_OPEN and is handed the probe's verdict.
     *
     * test_breaker_half_open_admits_one_probe's second-caller assertion is the
     * one that must break, so the control asks what a stored-state read would
     * return to the second caller. */
    zone_reset();
    ngx_test_set_time(1000);
    brk_record(0, 1, 60);
    ngx_test_advance_time(31);
    {
        ngx_uint_t  first, second;

        first = brk_state(30);

        /* the bug: hand back whatever is stored, with no winner check. */
        second = ngx_http_cache_turbo_brk_state(g_sh.breaker_state);

        caught = (first == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN
                  && second == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN);
        tests_run++;
        if (!caught) {
            fprintf(stderr, "  ✗ CONTROL O4.1-b: reading the stored state did "
                            "not admit a second probe — the single-winner "
                            "assertion guards nothing\n");
            tests_failed++;
        }
    }

    /* O4.1-c restored: a success that does NOT clear breaker_fails. The
     * "failure counter survived a close" assertion in
     * test_breaker_probe_success_closes must then break. */
    zone_reset();
    ngx_test_set_time(1000);
    brk_record(0, 3, 60);
    brk_record(0, 3, 60);
    {
        ngx_atomic_uint_t  kept = g_sh.breaker_fails;

        /* The bug: a success that does NOT clear the run. Restore the retained
         * count by hand, then drive the REAL record()/state() pair with the
         * same two post-success failures the test uses. With the run retained,
         * 2 + 2 crosses threshold 3 and the breaker opens. */
        brk_record(1, 3, 60);
        g_sh.breaker_fails = kept;              /* <-- bug: not cleared */

        brk_record(0, 3, 60);
        brk_record(0, 3, 60);

        caught = (brk_state(30)
                      == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN);
        tests_run++;
        if (!caught) {
            fprintf(stderr, "  ✗ CONTROL O4.1-c: a retained failure run did not "
                            "reach the threshold — the post-success assertion "
                            "guards nothing\n");
            tests_failed++;
        }
    }

    /* O4.2-a: the breaker's failure predicate reverted to the use_stale
     * trigger, i.e. the plan's literal wording. Model a use_stale mask with
     * `http_404` in it -- the exact configuration that makes the two predicates
     * disagree -- and confirm test_breaker_failure_ignores_healthy_statuses's
     * 404 assertion would then break.
     *
     * Asserted as a real state transition rather than on the boolean alone: a
     * bare `is_failure(404) == 1` control would pass even if _record() ignored
     * the value entirely, which is the vacuous shape the CodeRabbit round
     * flagged on O4.1. Here the run of 404s must actually OPEN the breaker. */
    zone_reset();
    ngx_test_set_time(1000);
    {
        ngx_uint_t  i, buggy_is_failure;

        /* Drive the buggy predicate for real, and REQUIRE that the production
         * one disagrees with it here. Without this the control hardcodes its
         * own verdict, never calls _breaker_is_origin_failure(), and stays
         * green through any mutation of it — vacuous in exactly the way the
         * comment above O4.1-a warns about. */
        buggy_is_failure = buggy_use_stale_is_failure(404);
        REQUIRE(buggy_is_failure
                && !ngx_http_cache_turbo_breaker_is_origin_failure(404),
                "O4.2-a fixture: the real predicate already agrees with the "
                "buggy one on 404 — the control models nothing");

        for (i = 0; i < 3; i++) {
            brk_record(!buggy_is_failure,
                                                    3, 60);
        }

        caught = (brk_state(30)
                      == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN
                  && g_sh.breaker_opens == 1);
        tests_run++;
        if (!caught) {
            fprintf(stderr, "  ✗ CONTROL O4.2-a: counting 404 as an origin "
                            "failure did not trip the breaker — the "
                            "healthy-status assertions guard nothing\n");
            tests_failed++;
        }
    }

    /* O4.2-b: the predicate narrowed to the four use_stale-nameable 5xx, losing
     * the ANY_5XX-only statuses (507/508/511/...). Those origins would then
     * never trip the breaker no matter how long they stayed down.
     * test_breaker_failure_counts_every_5xx's 507 assertion must break. */
    zone_reset();
    ngx_test_set_time(1000);
    {
        ngx_uint_t  i, buggy_is_failure;

        /* Same anchoring as O4.2-a, mirrored: the buggy predicate misses 507
         * (only ANY_5XX covers it), the real one must catch it. */
        buggy_is_failure = buggy_use_stale_is_failure(507);
        REQUIRE(!buggy_is_failure
                && ngx_http_cache_turbo_breaker_is_origin_failure(507),
                "O4.2-b fixture: the real predicate already agrees with the "
                "buggy one on 507 — the control models nothing");

        for (i = 0; i < 3; i++) {
            brk_record(!buggy_is_failure,
                                                    3, 60);
        }

        caught = (brk_state(30)
                      == NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED
                  && g_sh.breaker_opens == 0);
        tests_run++;
        if (!caught) {
            fprintf(stderr, "  ✗ CONTROL O4.2-b: ignoring 507 still tripped "
                            "the breaker — the every-5xx assertions guard "
                            "nothing\n");
            tests_failed++;
        }
    }

    /* O4.2-c: the admission rule loses its from_origin arm, so a response the
     * origin never sent counts as an origin outcome. Model the only-if-cached
     * miss exactly: no upstream was contacted, and the module answered 504
     * itself. Drive the REAL admission rule with from_origin forced on (the
     * bug's effect) and the REAL record()/state() pair with the 504.
     *
     * Three of those trip the breaker on threshold 3 -- against an origin
     * nobody spoke to. test_breaker_should_record_admission's no-upstream
     * assertion is the one that must break. */
    zone_reset();
    ngx_test_set_time(1000);
    {
        ngx_uint_t  i;

        for (i = 0; i < 3; i++) {
            /* the bug: from_origin forced to 1 for a response that wasn't */
            if (ngx_http_cache_turbo_breaker_should_record(0, 1, 1, 3)) {
                brk_record(!ngx_http_cache_turbo_breaker_is_origin_failure(504),
                    3, 60);
            }
        }

        caught = (brk_state(30)
                      == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN
                  && g_sh.breaker_opens == 1);
        tests_run++;
        if (!caught) {
            fprintf(stderr, "  ✗ CONTROL O4.2-c: admitting a response that "
                            "did not come from the origin did not trip the "
                            "breaker — the from_origin assertion guards "
                            "nothing\n");
            tests_failed++;
        }
    }

    /* O4.2-d: the admission rule loses its threshold arm, so a disabled
     * breaker is still recorded into. Prove that reaches shared memory: seed a
     * failure run, then feed one success with the breaker OFF. With the arm
     * present the call is skipped and the run survives; without it,
     * _breaker_record()'s success path clears breaker_fails before it ever
     * looks at the threshold (shm.c:1266 vs :1297). */
    zone_reset();
    ngx_test_set_time(1000);
    brk_record(0, 3, 60);
    brk_record(0, 3, 60);
    {
        ngx_atomic_uint_t  before = g_sh.breaker_fails;

        /* the bug: threshold 0 no longer vetoes, so the call goes through */
        brk_record(1, 0, 60);

        caught = (before == 2 && g_sh.breaker_fails == 0);
        tests_run++;
        if (!caught) {
            fprintf(stderr, "  ✗ CONTROL O4.2-d: recording into a DISABLED "
                            "breaker did not touch shared state — the "
                            "'off is free' assertion guards nothing\n");
            tests_failed++;
        }
    }
}

int
main(void)
{
    memset(&g_sh, 0, sizeof(g_sh));
    zone_reset();

    test_s8_evict_terminates_on_empty_queues();
    test_s8_promote_on_second_hit();
    test_s8_off_demotes_inherited_protected_nodes();
    test_cr_a_memo_survives_claim();
    test_cr_b_unstub_preserves_counter();
    test_claim_single_flight();
    test_count_miss_semantics();
    test_l2_neg_never_on_entry();
    test_out_of_slab_fails_open();
    test_breaker_zeroed_zone_is_closed();
    test_breaker_trips_at_threshold();
    test_breaker_window_rolls();
    test_breaker_half_open_admits_one_probe();
    test_breaker_probe_success_closes();
    test_breaker_abandoned_probe_lease_recovers();
    test_breaker_stale_success_does_not_close();
    test_breaker_unpublished_lease_is_not_reclaimable();
    test_breaker_probe_lease_is_independent_of_open();
    test_breaker_stale_probe_cannot_resolve_new_lease();
    test_breaker_huge_durations_do_not_overflow();
    test_breaker_threshold_zero_never_trips();
    test_breaker_zero_window_never_trips();
    test_breaker_state_strings();
    test_breaker_failure_counts_every_5xx();
    test_breaker_failure_ignores_healthy_statuses();
    test_breaker_record_driven_by_predicate();
    test_breaker_from_origin();
    test_breaker_should_record_admission();
    test_breaker_should_consult_admission();
    test_breaker_action_mapping();
    test_breaker_probe_passes_and_recovery_completes();
    test_breaker_second_consult_loses_the_probe();
    test_breaker_only_the_probe_token_closes();
    test_breaker_probe_token_reopens();
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
               "preservation, single-flight, min_uses, fail-open, P6 breaker)\n");
    }
    return tests_failed == 0 ? 0 : 1;
}
