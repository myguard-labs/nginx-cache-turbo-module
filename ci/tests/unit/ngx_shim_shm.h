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
