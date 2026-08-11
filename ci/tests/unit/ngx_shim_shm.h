/*
 * Minimal nginx surface for UNIT-TESTING the cache-turbo shared-memory node
 * state machine (claim / unstub / count_miss / l2_neg_set / l2_neg_check).
 *
 * WHY THIS EXISTS
 * ---------------
 * Two fixes on PR #77 -- CodeRabbit CR-A (the negative memo must survive the
 * claim() that turns its node into a stub) and CR-B (unstub() must not free a
 * COUNTER carrying min_uses progress) -- are CORRECT but UNGUARDED: every
 * black-box runtime test still passes with either bug restored.
 *
 *   CR-A is unreachable through the HTTP surface by construction. The memo is
 *   consulted once per request BEFORE the cold-miss single-flight, and a
 *   request that arrives while a claim is held becomes a waiter whose re-poll
 *   sets l2_neg_force and bypasses the memo by design. Six formulations were
 *   tried (serial and 12-way concurrent; min_uses 1/4/32; lock on and off) and
 *   all six passed with the coupling deliberately restored. Do NOT re-attempt
 *   a black-box test for it.
 *
 *   CR-B is latent: a counter node mid-count cannot currently reach unstub()
 *   because every call site is gated on cold_winner. The guard is correct for
 *   the day that changes, but nothing exercises it.
 *
 * Both are reachable trivially from C, by calling the shm entry points directly
 * in the order the request path would. That is what this harness enables. Per
 * [[feedback-negative-control-or-it-isnt-a-test]], each test here is required
 * to FAIL with its bug restored -- see the NEGATIVE CONTROL block in
 * test_shm_state.c, which is runnable (`make control`), not merely asserted.
 *
 * WHAT IS REAL AND WHAT IS FAKE
 * -----------------------------
 * The functions under test are NOT copied. extract_shm.sh slices them verbatim
 * out of the shipped ../../../src/ngx_http_cache_turbo_shm.c at build time, the
 * same no-drift discipline ci/fuzz/extract_parser.sh already uses. If a body
 * changes upstream, the next build picks it up; if one cannot be found, the
 * build fails loudly rather than silently testing nothing.
 *
 *   REAL (compiled from the nginx tree, not reimplemented):
 *     ngx_rbtree_insert / _delete / _init  -- src/core/ngx_rbtree.c
 *     ngx_queue_*                          -- src/core/ngx_queue.h (header-only)
 *   Using the real rbtree matters: node lifetime and the sentinel/rebalance
 *   behaviour are part of what these functions manipulate, and a fake tree
 *   could hide a use-after-free that the real one exposes under ASan.
 *
 *   FAKE (this file):
 *     ngx_slab_*  -- malloc/free with an optional forced-failure budget, so the
 *                    out-of-slab branches are reachable on demand.
 *     ngx_shmtx_* -- single-threaded no-ops that COUNT lock/unlock, so a missed
 *                    unlock (the bug class that hangs a worker) is assertable.
 *     ngx_time()  -- settable clock. Real time would make TTL expiry tests
 *                    either sleep or flake; here it is a variable we advance.
 *
 * The fake slab deliberately does NOT emulate slab fragmentation or size
 * classes. These tests are about node STATE TRANSITIONS, not allocator
 * behaviour; alloc failure is modelled as a budget because that is the only
 * property the code under test actually branches on.
 */

#ifndef NGX_CACHE_TURBO_UNIT_SHM_SHIM_H
#define NGX_CACHE_TURBO_UNIT_SHM_SHIM_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* H-1: the real nginx build derives NGX_PTR_SIZE from objs/ngx_auto_config.h,
 * which this harness never sees -- test_shm_state.c used to leave the macro
 * entirely undefined, so `#if (NGX_PTR_SIZE >= 8)` at the packed-probe layout
 * select silently evaluated to 0 and every unit build compiled the 32-bit
 * (20/12-bit) layout regardless of host width, while shipped x86-64 uses the
 * 64-bit (32/32-bit) layout. `-Wundef` catches this ("not defined, evaluates
 * to 0") but -Wundef is not in -Wall/-Wextra, so plain -Werror never did.
 *
 * Fix: define it here from the portable predefined `__SIZEOF_POINTER__`
 * (the actual host pointer width in BYTES -- NGX_PTR_SIZE is 8 or 4 in real
 * nginx, matching sizeof(void *), not a bit count), never a hardcoded 8 --
 * hardcoding 8 would just move the same silent-wrong-layout bug from
 * "undefined" to "wrong on a 32-bit host". Both the real header and this
 * mirror now also #error outright if NGX_PTR_SIZE is somehow still
 * undefined at the layout-select site, so this can never again pick a
 * layout silently. */
#define NGX_PTR_SIZE  __SIZEOF_POINTER__

/* H-2/O4.4-j: this harness always builds the TEST_FAULTS-gated diagnostic
 * paths (breaker_wedge_observed here; test_brk_armings is exercised by a
 * different, black-box test instead and is not referenced by this file).
 * Defined here, once, ahead of generated_shm.inc's #include, rather than as
 * a Makefile -D so `make check`/`make run` need no flag threading and stay
 * the single source of truth for "this harness always compiles the
 * TEST_FAULTS arms". Production and package builds never define this. */
#define NGX_HTTP_CACHE_TURBO_TEST_FAULTS  1

/* --- core types (nginx ngx_config.h / ngx_core.h) --- */
typedef intptr_t    ngx_int_t;
typedef uintptr_t   ngx_uint_t;
typedef unsigned char u_char;
typedef intptr_t    ngx_atomic_int_t;
typedef uintptr_t   ngx_atomic_uint_t;
typedef volatile ngx_atomic_uint_t ngx_atomic_t;

#define NGX_OK        0
#define NGX_ERROR    -1
#define NGX_AGAIN    -2
#define NGX_DECLINED -5

#define ngx_memcpy(dst, src, n)   (void) memcpy(dst, src, n)
#define ngx_memcmp(a, b, n)       memcmp(a, b, n)
#define ngx_memzero(buf, n)       (void) memset(buf, 0, n)

/* Single-threaded harness: a plain read-modify-write is sufficient and keeps
 * the counters observable. */
#define ngx_atomic_fetch_add(p, n)  ((*(p)) += (n), (*(p)) - (n))

/* Compare-and-set, matching nginx's contract: set *p to `set` and return 1 iff
 * *p currently equals `old`, else return 0 and leave *p alone.
 *
 * ⚠ This harness is SINGLE-THREADED, so this models only the sequential
 * semantics of the real CAS -- it cannot exercise the interleavings that make
 * the breaker's lock-free design interesting (two workers racing the same
 * OPEN -> HALF_OPEN promotion). What it DOES cover is that each transition is
 * guarded by the right precondition, that a CAS whose precondition no longer
 * holds is a no-op, and that no path leaves the state machine in an
 * unreachable state. The multi-worker interleaving is covered by the ASan
 * multi-worker runtime arm, not here -- do not read a green run of this file
 * as proof the breaker is race-free. */
/* --- O4.5: a CAS the test can make LOSE ----------------------------------
 * The sequential shim above can never produce a losing CAS: nothing else
 * mutates the word between the caller's read and its compare-and-set, so every
 * CAS in this harness wins and the loser branches are dead code under test.
 * That is not a cosmetic gap. The breaker's rolling-window re-anchor is
 * correct precisely BECAUSE the loser skips the counter clear, so a harness in
 * which nobody ever loses cannot tell the CAS version apart from the unguarded
 * read-modify-write it replaced -- verified by reverting the fix, at which
 * point every test here stayed green.
 *
 * ct_cas_steal_arm() models the one event the sequential shim cannot: another
 * worker wins the race. When armed for an address, the next CAS on it stores
 * the value that "other worker" committed and reports FAILURE to the caller,
 * which is exactly what the caller observes in production when it loses. The
 * production code is unmodified and unaware; only the primitive's outcome is
 * driven, the same way ngx_time() is driven above.
 *
 * Scoped to one address and one shot: an armed steal that is never consumed is
 * a fixture bug, so ct_cas_steal_assert_used() must be called at the end of any
 * test that arms one. */
extern ngx_atomic_t      *ct_cas_steal_addr;
extern ngx_atomic_uint_t  ct_cas_steal_value;
extern int                ct_cas_steal_fired;

static inline void
ct_cas_steal_arm(ngx_atomic_t *p, ngx_atomic_uint_t committed_by_other)
{
    ct_cas_steal_addr  = p;
    ct_cas_steal_value = committed_by_other;
    ct_cas_steal_fired = 0;
}

static inline int
ct_cas_steal_consume(ngx_atomic_t *p)
{
    if (ct_cas_steal_addr != p) {
        return 0;
    }
    /* The rival's write lands, then our CAS reports the loss. */
    *p = ct_cas_steal_value;
    ct_cas_steal_addr  = NULL;
    ct_cas_steal_fired = 1;
    return 1;
}

#define ngx_atomic_cmp_set(p, old, set)                                       \
    (ct_cas_steal_consume((ngx_atomic_t *) (p))                               \
     ? 0                                                                      \
     : ((*(p)) == (ngx_atomic_uint_t) (old)                                   \
        ? ((*(p)) = (ngx_atomic_uint_t) (set), 1) : 0))

/* --- settable clock ------------------------------------------------------
 * The code under test stamps and compares TTL deadlines (refresh_lock_until,
 * l2_neg_until, last_access). Driving those from the real clock would force
 * every expiry test to sleep, which is both slow and flaky. Tests call
 * ngx_test_set_time() / ngx_test_advance_time() instead, so a 60-second memo
 * window expires in zero wall-clock time and deterministically. */
extern time_t ngx_test_now;

#define ngx_time()  (ngx_test_now)

static inline void ngx_test_set_time(time_t t)     { ngx_test_now = t; }
static inline void ngx_test_advance_time(time_t d) { ngx_test_now += d; }

/* The ceiling ngx_parse_time() accepts, gated exactly as ci/fuzz/ngx_shim.h
 * gates it. Tests that drive the breaker's overflow guards (O4.4-b) need the
 * largest duration the real parser can hand the state machine, and spelling it
 * as a 64-bit literal would be an out-of-range conversion wherever ngx_int_t is
 * 32 bits -- the test would stop exercising the path it exists for. */
#if (UINTPTR_MAX > 0xffffffffUL)
#define NGX_MAX_INT_T_VALUE  9223372036854775807LL
#else
#define NGX_MAX_INT_T_VALUE  2147483647
#endif

/* ...and the largest duration that also fits the local time_t, which is what
 * the deadline arithmetic actually overflows. On the usual 64-bit build this is
 * NGX_MAX_INT_T_VALUE itself; where time_t is narrower it is time_t's own
 * maximum, which still makes `stamp + duration` wrap. TIME_T_MAX is derived
 * from the unsigned counterpart rather than hardcoded, so it holds for any
 * width without assuming one. */
#define NGX_TEST_TIME_T_MAX                                                   \
    ((time_t) (((uintmax_t) 1 << (8 * sizeof(time_t) - 1)) - 1))

#define NGX_TEST_MAX_DURATION                                                 \
    ((time_t) (((uintmax_t) NGX_MAX_INT_T_VALUE                               \
                    <= (uintmax_t) NGX_TEST_TIME_T_MAX)                       \
                   ? (time_t) NGX_MAX_INT_T_VALUE                             \
                   : NGX_TEST_TIME_T_MAX))

/* --- real nginx rbtree + queue -------------------------------------------
 * ngx_rbtree.h and ngx_queue.h cannot be included directly here: both open with
 * `#include <ngx_config.h> / <ngx_core.h>`, which drags in the entire nginx
 * type universe and collides with the reduced surface above.
 *
 * So the DECLARATIONS are mirrored below (verbatim from src/core/ngx_rbtree.h
 * and ngx_queue.h -- layout is load-bearing and must match exactly), while the
 * IMPLEMENTATION is the real ngx_rbtree.c, compiled as its own translation unit
 * against the genuine nginx headers and linked in by the Makefile. The linker
 * is what pairs them, so the tree that runs during a test is nginx's own
 * insert/delete/rebalance, not a reimplementation.
 *
 * ngx_queue is header-only upstream and entirely macro-based, so mirroring it
 * is complete by construction -- there is no queue .c to link.
 *
 * ⚠ If these structs ever drift from upstream the two TUs disagree on layout
 * and the result is memory corruption, not a compile error. The Makefile's
 * `layout-check` target static-asserts sizeof/offsetof against the real headers
 * on every build to make that failure loud. */

typedef ngx_uint_t  ngx_rbtree_key_t;
typedef ngx_int_t   ngx_rbtree_key_int_t;

typedef struct ngx_rbtree_node_s  ngx_rbtree_node_t;

struct ngx_rbtree_node_s {
    ngx_rbtree_key_t       key;
    ngx_rbtree_node_t     *left;
    ngx_rbtree_node_t     *right;
    ngx_rbtree_node_t     *parent;
    u_char                 color;
    u_char                 data;
};

typedef struct ngx_rbtree_s  ngx_rbtree_t;

typedef void (*ngx_rbtree_insert_pt) (ngx_rbtree_node_t *root,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

struct ngx_rbtree_s {
    ngx_rbtree_node_t     *root;
    ngx_rbtree_node_t     *sentinel;
    ngx_rbtree_insert_pt   insert;
};

#define ngx_rbtree_init(tree, s, i)                                           \
    ngx_rbtree_sentinel_init(s);                                              \
    (tree)->root = s;                                                         \
    (tree)->sentinel = s;                                                     \
    (tree)->insert = i

#define ngx_rbtree_black(node)       ((node)->color = 0)
#define ngx_rbtree_sentinel_init(node)  ngx_rbtree_black(node)

void ngx_rbtree_insert(ngx_rbtree_t *tree, ngx_rbtree_node_t *node);
void ngx_rbtree_delete(ngx_rbtree_t *tree, ngx_rbtree_node_t *node);
void ngx_rbtree_insert_value(ngx_rbtree_node_t *root, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel);

/* --- ngx_queue.h (header-only upstream; mirrored verbatim) --- */
typedef struct ngx_queue_s  ngx_queue_t;

struct ngx_queue_s {
    ngx_queue_t  *prev;
    ngx_queue_t  *next;
};

#define ngx_queue_init(q)                                                     \
    (q)->prev = q;                                                            \
    (q)->next = q

#define ngx_queue_empty(h)                                                    \
    (h == (h)->prev)

#define ngx_queue_insert_head(h, x)                                           \
    (x)->next = (h)->next;                                                    \
    (x)->next->prev = x;                                                      \
    (x)->prev = h;                                                            \
    (h)->next = x

#define ngx_queue_head(h)   (h)->next
#define ngx_queue_last(h)   (h)->prev

#define ngx_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next;                                              \
    (x)->prev = NULL;                                                         \
    (x)->next = NULL

#define ngx_queue_data(q, type, link)                                         \
    (type *) ((u_char *) q - offsetof(type, link))

/* --- fake slab pool ------------------------------------------------------
 * Backed by malloc so ASan/valgrind see real allocation lifetimes: a
 * use-after-free or double-free in the node state machine is then a hard
 * failure, not silent reuse of a still-mapped arena.
 *
 * ngx_test_slab_fail_after(n) makes the NEXT n allocations succeed and every
 * one after that return NULL, which is how the out-of-slab branches in
 * claim() and count_miss() are reached. -1 (the default) means never fail. */
/* Declared before ngx_slab_pool_t because the pool embeds one by value, exactly
 * as the real ngx_slab_pool_t does (the code under test writes
 * `&z->shpool->mutex`). */
typedef struct {
    ngx_uint_t  lock;
} ngx_shmtx_t;

typedef struct {
    ngx_shmtx_t  mutex;
} ngx_slab_pool_t;

extern long        ngx_test_slab_budget;   /* -1 = unlimited */
extern ngx_uint_t  ngx_test_slab_live;     /* outstanding allocations */
extern ngx_uint_t  ngx_test_lock_depth;    /* must be 0 between entry points */
extern ngx_uint_t  ngx_test_lock_count;

static inline void
ngx_test_slab_fail_after(long n) { ngx_test_slab_budget = n; }

static inline void *
ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size)
{
    void *p;

    (void) pool;

    if (ngx_test_slab_budget == 0) {
        return NULL;
    }
    if (ngx_test_slab_budget > 0) {
        ngx_test_slab_budget--;
    }

    p = malloc(size);
    if (p != NULL) {
        /* Real slab memory is uninitialised too. Poison it so a field the code
         * forgets to initialise reads as garbage here rather than as a
         * convenient zero -- that is precisely the class of bug where a node
         * zeroed by accident would read as ENTRY. */
        memset(p, 0xA5, size);
        ngx_test_slab_live++;
    }
    return p;
}

static inline void *
ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size)
{
    return ngx_slab_alloc_locked(pool, size);
}

static inline void
ngx_slab_free_locked(ngx_slab_pool_t *pool, void *p)
{
    (void) pool;
    if (p != NULL) {
        ngx_test_slab_live--;
        free(p);
    }
}

/* --- fake shared-memory mutex -------------------------------------------
 * Single-threaded, so these cannot deadlock -- but they COUNT. An entry point
 * that returns while still holding the lock is the bug that wedges a whole
 * worker (exactly the failure mode the in-tree unstub() comment describes as
 * "a hang, not a slowdown"), so every test asserts the depth is back to 0
 * afterwards via ngx_test_lock_balanced(). ngx_shmtx_t itself is declared above,
 * next to ngx_slab_pool_t, which embeds one. */
static inline void
ngx_shmtx_lock(ngx_shmtx_t *mtx)
{
    (void) mtx;
    ngx_test_lock_depth++;
    ngx_test_lock_count++;
}

static inline void
ngx_shmtx_unlock(ngx_shmtx_t *mtx)
{
    (void) mtx;
    ngx_test_lock_depth--;
}

static inline int
ngx_test_lock_balanced(void) { return ngx_test_lock_depth == 0; }

#endif /* NGX_CACHE_TURBO_UNIT_SHM_SHIM_H */
