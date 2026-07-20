/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * L1 shared-memory page cache: rbtree of cached objects keyed by the 32-byte
 * hash of the cache key, an LRU queue for eviction, and atomic stat counters.
 * Modelled on ngx_http_limit_req_module's slab+rbtree zone.
 */

#include "ngx_http_cache_turbo_module.h"


static void
ngx_http_cache_turbo_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t            **p;
    ngx_http_cache_turbo_node_t   *ctn, *ctnt;

    for ( ;; ) {
        if (node->key < temp->key) {
            p = &temp->left;

        } else if (node->key > temp->key) {
            p = &temp->right;

        } else {
            /* node->key == temp->key — disambiguate by full hash */
            ctn  = (ngx_http_cache_turbo_node_t *) node;
            ctnt = (ngx_http_cache_turbo_node_t *) temp;

            p = (ngx_memcmp(ctn->key, ctnt->key, 32) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


ngx_int_t
ngx_http_cache_turbo_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_cache_turbo_zone_t  *octx = data;
    ngx_http_cache_turbo_zone_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {
        /* reused zone after reload: inherit the live shm */
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;
        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;
        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(ctx->shpool,
                             sizeof(ngx_http_cache_turbo_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_http_cache_turbo_rbtree_insert_value);
    ngx_queue_init(&ctx->sh->lru);

    /* S8: the protected queue MUST be initialised even when scan resistance is
     * off. ngx_queue_empty() on a zeroed head reads h == h->prev as false
     * against NULL, so an uninitialised head would make evict_one() believe it
     * had a protected victim and walk a null sentinel. */
    ngx_queue_init(&ctx->sh->lru_protected);
    ctx->sh->n_protected = 0;
    ctx->sh->n_entries = 0;

    ctx->sh->hits = 0;
    ctx->sh->misses = 0;
    ctx->sh->stale_serves = 0;
    ctx->sh->refreshes = 0;
    ctx->sh->evictions = 0;
    ctx->sh->l2_hits = 0;
    ctx->sh->l2_misses = 0;
    ctx->sh->lock_waits = 0;
    ctx->sh->min_uses_skips = 0;
    ctx->sh->l2_neg_skips = 0;
    ctx->sh->bypasses = 0;

    /* Autotune state (v4-3): everything zeroed. autotune_next = 0 makes the first
     * recompute fire immediately; the snapshots being 0 means the first window is
     * "since worker start". autotuned_beta = 0 means "no verdict → use preset". */
    ctx->sh->cost_sum_ms = 0;
    ctx->sh->cost_count = 0;
    ctx->sh->autotuned_beta = 0;
    ctx->sh->autotuned_load = 0;   /* v4-4: 0 = baseline (no stale/lock widen) */
    ctx->sh->autotune_next = 0;
    ctx->sh->snap_hits = 0;
    ctx->sh->snap_misses = 0;
    ctx->sh->snap_refreshes = 0;
    ctx->sh->snap_cost_sum = 0;
    ctx->sh->snap_cost_count = 0;

    ctx->shpool->log_nomem = 0;

    return NGX_OK;
}


ngx_http_cache_turbo_node_t *
ngx_http_cache_turbo_shm_lookup(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash)
{
    ngx_int_t                     rc;
    ngx_rbtree_node_t            *node, *sentinel;
    ngx_http_cache_turbo_node_t  *ctn;

    node = z->sh->rbtree.root;
    sentinel = z->sh->rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */
        ctn = (ngx_http_cache_turbo_node_t *) node;

        rc = ngx_memcmp(key_hash, ctn->key, 32);

        if (rc == 0) {
            return ctn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static void *ngx_http_cache_turbo_shm_alloc_evict(
    ngx_http_cache_turbo_zone_t *z, size_t size);


/* PERF-7: allocate a response blob with an ngx_http_cache_turbo_blobref_t header
 * prefixed, so a HIT can be served zero-copy out of shm under refcount. Returns
 * the BLOB pointer (== node->data; the header sits immediately before it), or
 * NULL on slab exhaustion. Caller holds the shpool mutex. The header starts at
 * refs == 0 / detached == 0 (only the owning node references it). */
static u_char *
ngx_http_cache_turbo_blob_alloc(ngx_http_cache_turbo_zone_t *z, size_t len)
{
    u_char                          *base;
    ngx_http_cache_turbo_blobref_t  *ref;

    base = ngx_http_cache_turbo_shm_alloc_evict(z,
               sizeof(ngx_http_cache_turbo_blobref_t) + len);
    if (base == NULL) {
        return NULL;
    }

    ref = (ngx_http_cache_turbo_blobref_t *) base;
    ref->refs = 0;
    ref->detached = 0;

    return base + sizeof(ngx_http_cache_turbo_blobref_t);
}


/* PERF-7: the owning node drops its reference to a blob (evict / refresh / purge).
 * Caller holds the shpool mutex and `data` is non-NULL (node->data of a real
 * entry). If no serve is in flight (refs == 0) the slab is freed now; otherwise
 * it is marked detached and the last in-flight server frees it in its request-
 * pool cleanup (ngx_http_cache_turbo_blob_release). */
static void
ngx_http_cache_turbo_blob_node_release(ngx_http_cache_turbo_zone_t *z,
    u_char *data)
{
    ngx_http_cache_turbo_blobref_t  *ref = CT_BLOBREF(data);

    if (ref->refs == 0) {
        ngx_slab_free_locked(z->shpool, ref);
        return;
    }
    ref->detached = 1;
}


/* PERF-7 exported helpers (see header). acquire under the caller's held mutex;
 * release takes the mutex itself from a request-pool cleanup. */
void
ngx_http_cache_turbo_blob_acquire(u_char *data)
{
    CT_BLOBREF(data)->refs++;
}


void
ngx_http_cache_turbo_blob_release(ngx_http_cache_turbo_zone_t *z, u_char *data)
{
    ngx_http_cache_turbo_blobref_t  *ref = CT_BLOBREF(data);

    ngx_shmtx_lock(&z->shpool->mutex);
    ref->refs--;
    if (ref->refs == 0 && ref->detached) {
        ngx_slab_free_locked(z->shpool, ref);
    }
    ngx_shmtx_unlock(&z->shpool->mutex);
}


/* --- S8 segmented-LRU linkage helpers ------------------------------------
 *
 * EVERY insert/detach in this file goes through these three, so a node's `seg`
 * field and the queue it is actually threaded on can never disagree. That
 * invariant is what eviction depends on: evict_one() takes a node off the tail
 * of one queue and must be certain the node believed it was there.
 *
 * Caller holds the shpool mutex throughout.
 */

/* Link a node onto the head of the queue its `seg` names. `seg` must already
 * be set; this does not choose a segment. */
static void
ngx_http_cache_turbo_lru_link_head(ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_node_t *ctn)
{
    if (ctn->seg == NGX_HTTP_CACHE_TURBO_SEG_PROTECTED) {
        ngx_queue_insert_head(&z->sh->lru_protected, &ctn->lru);
        z->sh->n_protected++;

    } else {
        ngx_queue_insert_head(&z->sh->lru, &ctn->lru);
    }
}


/* Unlink a node from whichever queue it is on, keeping n_protected in step.
 * Leaves `seg` alone: callers either free the node or re-link it. */
static void
ngx_http_cache_turbo_lru_unlink(ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_node_t *ctn)
{
    ngx_queue_remove(&ctn->lru);

    if (ctn->seg == NGX_HTTP_CACHE_TURBO_SEG_PROTECTED) {
        z->sh->n_protected--;
    }
}


/* A brand-new node always enters PROBATION, whatever the feature setting. A
 * first store is an unproven key -- that is precisely what makes a scan
 * unable to evict the hot set. */
static void
ngx_http_cache_turbo_lru_insert_new(ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_node_t *ctn)
{
    ctn->seg = NGX_HTTP_CACHE_TURBO_SEG_PROBATION;
    ngx_queue_insert_head(&z->sh->lru, &ctn->lru);
    z->sh->n_entries++;
}


/* Enforce the protected-segment cap by demoting protected tails to the
 * PROBATION HEAD (not tail -- a demoted-but-hot entry deserves a second
 * chance before a cold probation entry). Caller holds the shpool mutex.
 *
 * A loop, not an `if`: protected_pct can shrink across a reload while entries
 * are already resident, so more than one demotion may be owed. It is bounded
 * by n_protected and each pass strictly decrements it, so it terminates. */
static void
ngx_http_cache_turbo_lru_enforce_cap(ngx_http_cache_turbo_zone_t *z,
    ngx_uint_t protected_pct)
{
    ngx_uint_t                    cap;
    ngx_queue_t                  *q;
    ngx_http_cache_turbo_node_t  *victim;

    /* Round UP, and floor the result at 1.
     *
     * Truncating division would make the cap 0 for any zone with fewer than
     * 100/pct entries -- at the default 80 that is a zone of ONE entry, whose
     * single node would be promoted and instantly demoted again on every hit,
     * churning the queues forever and never actually protecting anything. The
     * floor guarantees a non-empty zone can always protect at least one entry,
     * which is what makes the segment meaningful on small zones. */
    cap = (z->sh->n_entries * protected_pct + 99) / 100;

    if (cap == 0) {
        cap = 1;
    }

    while (z->sh->n_protected > cap
           && !ngx_queue_empty(&z->sh->lru_protected))
    {
        q = ngx_queue_last(&z->sh->lru_protected);
        victim = ngx_queue_data(q, ngx_http_cache_turbo_node_t, lru);

        ngx_http_cache_turbo_lru_unlink(z, victim);
        victim->seg = NGX_HTTP_CACHE_TURBO_SEG_PROBATION;
        ngx_http_cache_turbo_lru_link_head(z, victim);
    }
}


/* Re-splice a node on access, and promote it on its second touch (S8).
 *
 * Shared by all three re-splice sites (fresh HIT, stale HIT, memo consult) so
 * the promotion rule cannot drift between them -- a rule duplicated three
 * times is a rule that is wrong at one of them.
 *
 * `protected_pct` of 0 means the feature is OFF: the node then simply re-heads
 * within probation, which is byte-for-byte the pre-S8 behaviour.
 *
 * Returns with the node re-headed on whichever queue it now belongs to.
 * Caller holds the shpool mutex.
 */
void
ngx_http_cache_turbo_shm_touch_lru(ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_node_t *ctn, time_t now, ngx_uint_t protected_pct)
{
    /* P1 coarse gate: at most one LRU write per node per second. Deliberately
     * the SAME gate that governed the flat re-splice -- S8 adds no second
     * clock, so a hot key still serializes readers at most once/second. */
    if (now - ctn->last_access < 1) {
        return;
    }

    ctn->last_access = now;

    ngx_http_cache_turbo_lru_unlink(z, ctn);

    /* Promote on the SECOND touch, and only ever an ENTRY.
     *
     * ⚠ COUNTER nodes (min_uses counters, L13 negative memos, cold-miss stubs)
     * must stay in probation permanently. They hold bookkeeping, not content;
     * promoting one would let an L2 miss storm pin the protected segment with
     * nodes that carry no body at all -- inverting the feature. The kind gate
     * is load-bearing, not defensive.
     *
     * "Second touch" is read off `seg`: a node still in probation that is being
     * touched has been accessed at least once since it was stored (the store
     * itself does not touch), so this touch is the promoting one. That reuses
     * the existing state instead of adding a hit counter to the node. */
    if (protected_pct == 0) {
        /* Feature OFF: DEMOTE, do not merely decline to promote.
         *
         * ⚠ A zone survives a reload (init_zone inherits the live `sh` when
         * `octx` is set, or `shm.exists`), so an `on` -> `off` config change
         * hands us nodes that are already PROTECTED. Leaving `seg` alone here
         * would relink them onto lru_protected forever -- `off` would stop
         * future promotions but never restore the flat single-queue LRU, and
         * the entries promoted while it was on would stay preferentially
         * un-evictable for the life of the zone. Demoting on touch drains the
         * protected queue back into probation as those nodes are used, so
         * `off` genuinely converges on the pre-S8 behaviour. Untouched nodes
         * are reached by eviction instead, which drains lru_protected once
         * probation empties. (CodeRabbit, PR #81.) */
        ctn->seg = NGX_HTTP_CACHE_TURBO_SEG_PROBATION;

    } else if (ctn->kind == NGX_HTTP_CACHE_TURBO_NODE_ENTRY
               && ctn->seg == NGX_HTTP_CACHE_TURBO_SEG_PROBATION
               && ctn->promotable)
    {
        ctn->seg = NGX_HTTP_CACHE_TURBO_SEG_PROTECTED;
    }

    ctn->promotable = 1;

    ngx_http_cache_turbo_lru_link_head(z, ctn);

    if (protected_pct > 0) {
        ngx_http_cache_turbo_lru_enforce_cap(z, protected_pct);
    }
}


/* Evict the least-recently-used entry. Caller holds the shpool mutex. Returns 1
 * if an entry was evicted, 0 if BOTH queues were already empty (no candidate).
 *
 * ⚠ THE HANG HAZARD. With two queues, `ngx_queue_empty(&z->sh->lru)` is no
 * longer the "nothing to evict" test in either direction:
 *
 *   - Returning 0 while lru_protected still holds a victim makes alloc_evict()
 *     give up on a zone that still had reclaimable entries (a store fails for
 *     no reason).
 *   - Returning non-zero WITHOUT evicting makes alloc_evict()'s
 *     `while (p == NULL && evict_one(z))` spin forever -- while holding
 *     shpool->mutex. That wedges the worker and every other worker behind it.
 *     It is not a crash and not a wrong number; a black-box suite sees only a
 *     timeout.
 *
 * So: probation tail first (that ordering IS the scan resistance), fall
 * through to the protected tail, and return 0 only when BOTH are empty.
 * Pinned by test_s8_evict_terminates_on_empty_queues() under a SIGALRM
 * watchdog, so a regression fails in bounded time instead of hanging CI.
 */
static ngx_int_t
ngx_http_cache_turbo_shm_evict_one(ngx_http_cache_turbo_zone_t *z)
{
    ngx_queue_t                  *q;
    ngx_http_cache_turbo_node_t  *ctn;

    if (!ngx_queue_empty(&z->sh->lru)) {
        q = ngx_queue_last(&z->sh->lru);

    } else if (!ngx_queue_empty(&z->sh->lru_protected)) {
        /* Probation drained: a full-but-all-protected zone must still be
         * reclaimable, or the loop in alloc_evict() never terminates. */
        q = ngx_queue_last(&z->sh->lru_protected);

    } else {
        return 0;                    /* genuinely nothing to evict */
    }

    ctn = ngx_queue_data(q, ngx_http_cache_turbo_node_t, lru);

    ngx_http_cache_turbo_lru_unlink(z, ctn);
    z->sh->n_entries--;
    ngx_rbtree_delete(&z->sh->rbtree, &ctn->node);

    if (ctn->data) {
        ngx_http_cache_turbo_blob_node_release(z, ctn->data);
    }
    ngx_slab_free_locked(z->shpool, ctn);

    (void) ngx_atomic_fetch_add(&z->sh->evictions, 1);
    return 1;
}


/* Slab-alloc `size` bytes, evicting LRU entries one at a time until the
 * allocation succeeds or no candidate remains (PERF-6). A single fragmented
 * allocation could previously fail even when several reclaimable entries would
 * together free enough space; this drains as many as needed. Caller holds the
 * shpool mutex; any node that must NOT be evicted (e.g. the one being refreshed)
 * must be detached from the LRU before calling. */
static void *
ngx_http_cache_turbo_shm_alloc_evict(ngx_http_cache_turbo_zone_t *z, size_t size)
{
    void  *p = ngx_slab_alloc_locked(z->shpool, size);

    while (p == NULL && ngx_http_cache_turbo_shm_evict_one(z)) {
        p = ngx_slab_alloc_locked(z->shpool, size);
    }
    return p;
}


/* Remove one node from rbtree + LRU and free its slab memory. Caller holds the
 * shpool mutex. */
static void
ngx_http_cache_turbo_shm_drop_locked(ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_node_t *ctn)
{
    ngx_http_cache_turbo_lru_unlink(z, ctn);
    z->sh->n_entries--;
    ngx_rbtree_delete(&z->sh->rbtree, &ctn->node);
    if (ctn->data) {
        ngx_http_cache_turbo_blob_node_release(z, ctn->data);
    }
    ngx_slab_free_locked(z->shpool, ctn);
}


ngx_int_t
ngx_http_cache_turbo_shm_purge_key(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash)
{
    ngx_http_cache_turbo_node_t  *ctn;

    ngx_shmtx_lock(&z->shpool->mutex);
    ctn = ngx_http_cache_turbo_shm_lookup(z, key_hash, hash);
    if (ctn == NULL) {
        ngx_shmtx_unlock(&z->shpool->mutex);
        return 0;
    }
    ngx_http_cache_turbo_shm_drop_locked(z, ctn);
    ngx_shmtx_unlock(&z->shpool->mutex);
    return 1;
}


/* PERF-3: how many nodes to drop per lock acquisition during a purge-all walk.
 * Holding the zone mutex for the ENTIRE LRU (which can be millions of entries)
 * blocks every other worker's cache lookups/stores for the whole walk. Dropping
 * in bounded batches and releasing the mutex between them keeps each critical
 * section short, so a concurrent request waits at most one batch, not the whole
 * purge. The total is still reported. */
#define NGX_HTTP_CACHE_TURBO_PURGE_BATCH  512

ngx_uint_t
ngx_http_cache_turbo_shm_purge_all(ngx_http_cache_turbo_zone_t *z)
{
    ngx_uint_t                    n = 0, batch;
    ngx_queue_t                  *q;
    ngx_http_cache_turbo_node_t  *ctn;

    for ( ;; ) {
        ngx_shmtx_lock(&z->shpool->mutex);

        batch = 0;

        /* ⚠ S8: BOTH queues must drain. Walking only &z->sh->lru would leave
         * the entire protected set resident and a purge would silently keep
         * serving the objects it claimed to remove -- the classic fan-out
         * miss. Probation first, then protected; the batch cap spans the two
         * so the mutex is still released every PURGE_BATCH drops however the
         * entries are distributed. */
        while (batch < NGX_HTTP_CACHE_TURBO_PURGE_BATCH
               && !ngx_queue_empty(&z->sh->lru))
        {
            q = ngx_queue_head(&z->sh->lru);
            ctn = ngx_queue_data(q, ngx_http_cache_turbo_node_t, lru);
            ngx_http_cache_turbo_shm_drop_locked(z, ctn);
            batch++;
        }

        while (batch < NGX_HTTP_CACHE_TURBO_PURGE_BATCH
               && !ngx_queue_empty(&z->sh->lru_protected))
        {
            q = ngx_queue_head(&z->sh->lru_protected);
            ctn = ngx_queue_data(q, ngx_http_cache_turbo_node_t, lru);
            ngx_http_cache_turbo_shm_drop_locked(z, ctn);
            batch++;
        }

        n += batch;
        ngx_shmtx_unlock(&z->shpool->mutex);

        /* Drained, or this batch hit the cap with more to go: loop and let any
         * waiter take the mutex before we grab the next batch. */
        if (batch < NGX_HTTP_CACHE_TURBO_PURGE_BATCH) {
            break;
        }
    }

    return n;
}


ngx_int_t
ngx_http_cache_turbo_shm_store(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, u_char *data, size_t len,
    time_t fresh_ttl, time_t stale_ttl)
{
    u_char                       *body;
    time_t                        now;
    ngx_http_cache_turbo_node_t  *ctn;

    /* fresh_ttl may be <= 0 (object already stale on an L2 fill) — fresh_until
     * then lands in the past and the node is served via the stale path. stale_ttl
     * is the absolute serveable window from now (0 = no stale serving). */
    now = ngx_time();

    ngx_shmtx_lock(&z->shpool->mutex);

    /* Already present? Update in place (refresh path). */
    ctn = ngx_http_cache_turbo_shm_lookup(z, key_hash, hash);

    if (ctn) {
        /* Detach ctn from the LRU *before* any eviction. shm_evict_one() frees
         * the LRU tail, and on a stale refresh ctn may itself be that tail;
         * evicting it here would free the very node we go on to write to
         * (use-after-free + double-free of ctn->data). Detaching guarantees the
         * retry-evict frees some OTHER node (or none, if ctn was the only one).
         * Re-inserted at the LRU head on success, restored on alloc fail.
         *
         * ⚠ S8: unlink/relink both go through the helpers so n_protected stays
         * in step with the linkage on BOTH exits. `seg` is left untouched
         * across the detach, so the restore path below puts the node back on
         * exactly the queue it came off -- a protected entry whose refresh
         * fails must not silently demote itself. */
        ngx_http_cache_turbo_lru_unlink(z, ctn);

        body = ngx_http_cache_turbo_blob_alloc(z, len);
        if (body == NULL) {
            /* Refresh failed: keep the existing (stale) entry reachable, on
             * its original segment. */
            ngx_http_cache_turbo_lru_link_head(z, ctn);
            ngx_shmtx_unlock(&z->shpool->mutex);
            return NGX_ERROR;
        }

        ngx_memcpy(body, data, len);
        if (ctn->data) {
            /* PERF-7: the old blob may have an in-flight zero-copy server; this
             * detaches it and frees only if no serve holds it (else the server's
             * cleanup frees it). The new blob is independent, so a concurrent
             * serve of the old one is unaffected. */
            ngx_http_cache_turbo_blob_node_release(z, ctn->data);
        }
        ctn->kind = NGX_HTTP_CACHE_TURBO_NODE_ENTRY;  /* now holds a body */
        ctn->data = body;
        ctn->len = len;
        ctn->fresh_until = now + fresh_ttl;
        ctn->stale_until = stale_ttl ? now + stale_ttl : 0;
        ctn->refreshing = 0;
        ctn->refresh_lock_until = 0;
        ctn->l2_neg_until = 0;       /* L13: node now holds a body; any memo it
                                      * carried as a COUNTER is moot */
        ctn->last_access = now;      /* P1: store re-heads the LRU, sync stamp */

        /* S8: a refresh installs a NEW representation, so it re-earns
         * protection rather than inheriting the old body's. The node is
         * ALREADY unlinked (detached above, before the alloc), so this only
         * re-labels it and links it back onto probation. Two further hits
         * protect it again. This also stops the refresh path being a way to
         * hold protected residency indefinitely without ever being read. */
        ctn->seg = NGX_HTTP_CACHE_TURBO_SEG_PROBATION;
        ctn->promotable = 0;
        ngx_http_cache_turbo_lru_link_head(z, ctn);

        ngx_shmtx_unlock(&z->shpool->mutex);
        return NGX_OK;
    }

    /* New entry. */
    ctn = ngx_http_cache_turbo_shm_alloc_evict(z,
              sizeof(ngx_http_cache_turbo_node_t));
    if (ctn == NULL) {
        ngx_shmtx_unlock(&z->shpool->mutex);
        return NGX_ERROR;
    }

    body = ngx_http_cache_turbo_blob_alloc(z, len);
    if (body == NULL) {
        ngx_slab_free_locked(z->shpool, ctn);
        ngx_shmtx_unlock(&z->shpool->mutex);
        return NGX_ERROR;
    }

    ngx_memcpy(body, data, len);

    ctn->node.key = hash;
    ngx_memcpy(ctn->key, key_hash, 32);
    ctn->kind = NGX_HTTP_CACHE_TURBO_NODE_ENTRY;
    ctn->data = body;
    ctn->len = len;
    ctn->fresh_until = now + fresh_ttl;
    ctn->stale_until = stale_ttl ? now + stale_ttl : 0;
    ctn->refreshing = 0;
    ctn->refresh_lock_until = 0;
    ctn->miss_count = 0;
    ctn->l2_neg_until = 0;       /* L13: no memo on an ENTRY */
    ctn->last_access = now;      /* P1: fresh at LRU head */
    ctn->promotable = 0;         /* S8: unproven; second touch promotes */

    ngx_rbtree_insert(&z->sh->rbtree, &ctn->node);
    /* S8: every new node enters PROBATION (see lru_insert_new). */
    ngx_http_cache_turbo_lru_insert_new(z, ctn);

    ngx_shmtx_unlock(&z->shpool->mutex);
    return NGX_OK;
}


void
ngx_http_cache_turbo_shm_stats(ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_stats_t *out)
{
    ngx_atomic_uint_t  cnt;

    out->hits         = z->sh->hits;
    out->misses       = z->sh->misses;
    out->stale_serves = z->sh->stale_serves;
    out->refreshes    = z->sh->refreshes;
    out->evictions    = z->sh->evictions;
    out->l2_hits      = z->sh->l2_hits;
    out->l2_misses    = z->sh->l2_misses;
    out->lock_waits   = z->sh->lock_waits;
    out->min_uses_skips = z->sh->min_uses_skips;
    out->l2_neg_skips = z->sh->l2_neg_skips;
    out->bypasses     = z->sh->bypasses;

    /* Autotune introspection (v4-3): average origin-regen cost and the live beta
     * verdict, so the admin GET can render the tuning without an internal probe. */
    cnt = z->sh->cost_count;
    out->cost_ms        = cnt ? (z->sh->cost_sum_ms / cnt) : 0;
    out->autotuned_beta = z->sh->autotuned_beta;
    out->autotuned_load = z->sh->autotuned_load;   /* v4-4 load factor ×1000 */
}


/* Cold-miss single-flight claim (v10). Atomically decide, under the zone mutex,
 * whether this request becomes the single regenerator for a cold key or waits.
 * See the L1 vtable `claim` comment in the header. */
ngx_int_t
ngx_http_cache_turbo_shm_claim(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, time_t lock_ttl)
{
    time_t                        now;
    ngx_http_cache_turbo_node_t  *ctn;

    now = ngx_time();

    ngx_shmtx_lock(&z->shpool->mutex);

    ctn = ngx_http_cache_turbo_shm_lookup(z, key_hash, hash);

    if (ctn != NULL) {
        /* A real fresh entry raced in while we were on the cold path: re-serve
         * it, do NOT regenerate. */
        if (ctn->len > 0 && now < ctn->fresh_until) {
            ngx_shmtx_unlock(&z->shpool->mutex);
            return NGX_HTTP_CACHE_TURBO_CLAIM_FRESH;
        }

        /* Someone is already regenerating and the lock has not expired: wait. */
        if (ctn->refreshing && now < ctn->refresh_lock_until) {
            ngx_shmtx_unlock(&z->shpool->mutex);
            return NGX_HTTP_CACHE_TURBO_CLAIM_LOSER;
        }

        /* Expired entry or a dead in-flight stub (the previous winner died):
         * take it over as the new single regenerator. Any stale data left in
         * place is past its stale window so no one serves it; the winner
         * overwrites it on store().
         *
         * ⚠ The node's KIND is deliberately left alone. An expired ENTRY keeps its
         * (past-stale, unservable) blob until store() replaces it -- that is the
         * pre-existing contract and the blob's lifetime is not this fix's business.
         * `refreshing` alone marks the single-flight; for a COUNTER that is
         * precisely what makes it a stub.
         *
         * ⚠ l2_neg_until is deliberately NOT cleared. A COUNTER may carry a live
         * memo armed moments ago by l2_neg_set() on THIS request; clearing it here
         * destroyed the memo before any later request could read it, collapsing
         * the window to ~1 request (CodeRabbit CR-A on PR #77). The memo describes
         * L2's contents, which a local single-flight does not change, so it
         * legitimately outlives the regen. unstub() no longer depends on this
         * reset -- it identifies a stub by kind + refreshing, not by shape. */
        ctn->refreshing = 1;
        ctn->refresh_lock_until = now + lock_ttl;
        ngx_shmtx_unlock(&z->shpool->mutex);
        return NGX_HTTP_CACHE_TURBO_CLAIM_WINNER;
    }

    /* No node at all: create a stub (data == NULL, len == 0) marking the key as
     * in flight so concurrent first-hits wait instead of stampeding the origin.
     * The winner's store() finds it via lookup and overwrites it into a real
     * node (clearing refreshing). LRU eviction may reclaim a stub under memory
     * pressure — harmless, it just costs an extra origin hit. */
    ctn = ngx_http_cache_turbo_shm_alloc_evict(z,
              sizeof(ngx_http_cache_turbo_node_t));
    if (ctn == NULL) {
        /* Out of slab: cannot mark the key in flight, so just regenerate
         * (winner, no single-flight this time — correct, only less efficient). */
        ngx_shmtx_unlock(&z->shpool->mutex);
        return NGX_HTTP_CACHE_TURBO_CLAIM_WINNER;
    }

    ctn->node.key = hash;
    ngx_memcpy(ctn->key, key_hash, 32);
    ctn->kind = NGX_HTTP_CACHE_TURBO_NODE_COUNTER;  /* + refreshing = a stub */
    ctn->data = NULL;
    ctn->len = 0;
    ctn->fresh_until = 0;
    ctn->stale_until = 0;
    ctn->refreshing = 1;
    ctn->refresh_lock_until = now + lock_ttl;
    ctn->miss_count = 0;
    ctn->l2_neg_until = 0;       /* brand-new node: no memo to preserve */
    ctn->last_access = now;      /* P1: init the coarse LRU stamp */
    ctn->promotable = 0;         /* S8: unproven; second touch promotes */

    ngx_rbtree_insert(&z->sh->rbtree, &ctn->node);
    /* S8: every new node enters PROBATION (see lru_insert_new). */
    ngx_http_cache_turbo_lru_insert_new(z, ctn);

    ngx_shmtx_unlock(&z->shpool->mutex);
    return NGX_HTTP_CACHE_TURBO_CLAIM_WINNER;
}


/* Remove a leftover cold-miss stub (v10). Only acts if the node is still a stub
 * (data == NULL / len == 0) — a real entry stored in the meantime is left
 * intact. Called when a cold-miss winner's response was non-cacheable so the
 * in-flight marker would otherwise block waiters until refresh_lock_until. */
void
ngx_http_cache_turbo_shm_unstub(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash)
{
    ngx_http_cache_turbo_node_t  *ctn;

    ngx_shmtx_lock(&z->shpool->mutex);

    ctn = ngx_http_cache_turbo_shm_lookup(z, key_hash, hash);

    /* Two separate jobs, and conflating them is what made this function a bug
     * factory:
     *
     *   1. ALWAYS clear the single-flight on a claimed COUNTER. That is what
     *      unblocks waiters, and it must happen whatever else the node carries.
     *   2. Free the node only if it then carries NOTHING worth keeping.
     *
     * ⚠ Do NOT gate step 1 on what the node carries. A previous version required
     * `l2_neg_until <= now`, so a node holding a LIVE memo kept its `refreshing`
     * flag after its winner's response turned out non-cacheable -- every later
     * request for that key then parked on a stub nobody would ever fill, until
     * refresh_lock_until expired. That is a hang, not a slowdown: measured
     * 2026-07-19, it timed out the runtime suite outright.
     *
     * ⚠ Do NOT reduce the free test to a shape check (`len == 0 && data == NULL`).
     * That shape is shared by the stub, the min_uses counter and the L13 memo --
     * the overloading that produced this whole defect class. When only
     * l2_neg_until guarded it, a counter node mid-count was freed outright and its
     * min_uses progress silently reset (CR-B); the in-tree justification for that
     * ("the suite logs miss_count == 0 on all 68 calls") was measured under
     * min_uses 4, a config where counters never reach here at all. Evidence of
     * absence, mistaken for absence of the path.
     *
     * An ENTRY is never touched: it holds a body someone may still serve. */
    if (ctn != NULL
        && ctn->kind == NGX_HTTP_CACHE_TURBO_NODE_COUNTER
        && ctn->refreshing)
    {
        /* (1) release the single-flight -- unconditional */
        ctn->refreshing = 0;
        ctn->refresh_lock_until = 0;

        /* (2) reclaim only if nothing else lives on this node: no min_uses
         * progress and no live negative memo. Either one means the node still
         * carries state the caller never asked to discard, so it stays as a plain
         * COUNTER and expires on its own terms. */
        if (ctn->miss_count == 0 && ctn->l2_neg_until <= ngx_time()) {
            ngx_http_cache_turbo_lru_unlink(z, ctn);
            z->sh->n_entries--;
            ngx_rbtree_delete(&z->sh->rbtree, &ctn->node);
            ngx_slab_free_locked(z->shpool, ctn);
        }
    }

    ngx_shmtx_unlock(&z->shpool->mutex);
}


/* min_uses miss counter (v15). Count one cold miss for the key and decide
 * whether it has been requested enough times to be worth caching. See the L1
 * vtable `count_miss` comment in the header. Only called when min_uses > 1. */
ngx_int_t
ngx_http_cache_turbo_shm_count_miss(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, ngx_int_t min_uses)
{
    time_t                        now;
    ngx_http_cache_turbo_node_t  *ctn;

    now = ngx_time();

    ngx_shmtx_lock(&z->shpool->mutex);

    ctn = ngx_http_cache_turbo_shm_lookup(z, key_hash, hash);

    if (ctn != NULL) {
        /* A real entry (even expired/stale being refreshed) is already proven
         * cacheable — never re-gate it, and do not touch its counter. */
        if (ctn->kind == NGX_HTTP_CACHE_TURBO_NODE_ENTRY && ctn->len > 0) {
            ngx_shmtx_unlock(&z->shpool->mutex);
            return NGX_OK;
        }

        /* A live single-flight stub: another request already crossed the
         * threshold and is regenerating. Proceed so the caller's claim() makes
         * this request a waiter; don't count (this is not an un-coalesced miss). */
        if (ctn->refreshing && now < ctn->refresh_lock_until) {
            ngx_shmtx_unlock(&z->shpool->mutex);
            return NGX_OK;
        }

        /* A counter node (or a dead stub): this is a genuine cold miss for a key
         * not yet cached. Count it; cross the threshold => store-eligible. */
        ctn->miss_count++;
        if ((ngx_int_t) ctn->miss_count >= min_uses) {
            ngx_shmtx_unlock(&z->shpool->mutex);
            return NGX_OK;
        }
        ngx_shmtx_unlock(&z->shpool->mutex);
        return NGX_DECLINED;
    }

    /* No node yet: create a counter node (data == NULL / len == 0 /
     * refreshing == 0) recording this first miss. It is invisible to the serve
     * branches (their len > 0 guards skip it) and converts into the cold-miss
     * winner's stub via claim() once the threshold is reached. LRU eviction may
     * reclaim a cold counter node — harmless, it just resets the count. */
    ctn = ngx_http_cache_turbo_shm_alloc_evict(z,
              sizeof(ngx_http_cache_turbo_node_t));
    if (ctn == NULL) {
        /* Out of slab: cannot track the count, so just let it cache now
         * (correct, only less selective than min_uses would like). */
        ngx_shmtx_unlock(&z->shpool->mutex);
        return NGX_OK;
    }

    ctn->node.key = hash;
    ngx_memcpy(ctn->key, key_hash, 32);
    ctn->kind = NGX_HTTP_CACHE_TURBO_NODE_COUNTER;
    ctn->data = NULL;
    ctn->len = 0;
    ctn->fresh_until = 0;
    ctn->stale_until = 0;
    ctn->refreshing = 0;
    ctn->refresh_lock_until = 0;
    ctn->miss_count = 1;
    ctn->l2_neg_until = 0;       /* L13: no memo yet; l2_neg_set stamps it */
    ctn->last_access = now;      /* P1: init the coarse LRU stamp */
    ctn->promotable = 0;         /* S8: unproven; second touch promotes */

    ngx_rbtree_insert(&z->sh->rbtree, &ctn->node);
    /* S8: every new node enters PROBATION (see lru_insert_new). */
    ngx_http_cache_turbo_lru_insert_new(z, ctn);

    ngx_shmtx_unlock(&z->shpool->mutex);

    /* First miss: below threshold unless min_uses == 1 (caller guards that). */
    return (min_uses <= 1) ? NGX_OK : NGX_DECLINED;
}


/* L2 negative memo (L13). Is there a live "L2 missed this key recently" memo?
 * Returns NGX_DECLINED to SKIP the L2 GET, NGX_OK to consult L2 as usual.
 * See the L1 vtable `l2_neg_check` comment. Only called when
 * l2_negative_ttl > 0. */
ngx_int_t
ngx_http_cache_turbo_shm_l2_neg_check(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash)
{
    time_t                        now;
    ngx_int_t                     rc;
    ngx_http_cache_turbo_node_t  *ctn;

    now = ngx_time();
    rc = NGX_OK;

    ngx_shmtx_lock(&z->shpool->mutex);

    ctn = ngx_http_cache_turbo_shm_lookup(z, key_hash, hash);

    /* Only a COUNTER can carry a memo, and only while it has not expired.
     *
     * ⚠ `refreshing` is deliberately NOT consulted. It used to be, and that is
     * what limited the memo to ~1 request: l2_neg_check runs BEFORE claim() in the
     * request path (module.c), so req1 armed the memo and req1's own claim() then
     * marked the very same node refreshing, masking the memo from req2 onward. At
     * the default min_uses 1 that made the whole feature a near no-op (Codex #4).
     *
     * Consulting it is also wrong on the merits: `refreshing` says a LOCAL regen
     * is in the air, which tells us nothing about whether L2 holds the key. The
     * memo is a statement about L2's contents; a local single-flight does not
     * change them. Skipping the L2 GET while a regen is in flight is exactly as
     * safe as skipping it otherwise -- the memo holds no body and can never cause
     * a stale serve. */
    if (ctn != NULL
        && ctn->kind == NGX_HTTP_CACHE_TURBO_NODE_COUNTER
        && ctn->l2_neg_until > now)
    {
        rc = NGX_DECLINED;

        /* P1/Codex #2: a consulted memo is in USE -- re-head it on the same 1s
         * granularity as a served ENTRY. Without this a memo node keeps the
         * last_access it was created with and sinks to the LRU tail no matter how
         * often it is read, making it a PREFERRED eviction victim ahead of colder
         * entries. Eviction of a memo is legitimate under real slab pressure (a
         * body is worth more than a memo, and losing one only costs an RTT), but
         * it should be evicted on its true recency. */
        /* S8: routed through the shared helper so the memo re-splice cannot
         * drift from the two HIT sites. The pct argument is 0 because a memo is
         * a COUNTER and the helper's kind gate would refuse to promote it
         * anyway -- passing 0 states that intent locally, and means this site
         * needs no access to the location config. If the kind gate were ever
         * dropped, the promote-on-second-hit test asserts BOTH this path and
         * the gate, so the regression is caught either way. */
        ngx_http_cache_turbo_shm_touch_lru(z, ctn, now, 0);
    }

    ngx_shmtx_unlock(&z->shpool->mutex);

    return rc;
}


/* L2 negative memo (L13). Record that an L2 GET just missed this key, so the
 * next cold request skips the round-trip for `ttl` seconds. Best-effort: a full
 * slab simply means no memo (one extra RTT, never a correctness problem).
 * See the L1 vtable `l2_neg_set` comment. */
void
ngx_http_cache_turbo_shm_l2_neg_set(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, time_t ttl)
{
    time_t                        now;
    ngx_http_cache_turbo_node_t  *ctn;

    now = ngx_time();

    ngx_shmtx_lock(&z->shpool->mutex);

    ctn = ngx_http_cache_turbo_shm_lookup(z, key_hash, hash);

    if (ctn != NULL) {
        /* Never memo an ENTRY: it holds a body, so it does not consult L2 at all
         * and a memo on it could never be read.
         *
         * ⚠ `refreshing` is deliberately NOT consulted here either. The old guard
         * rejected a refreshing node because "stamping a stub would make the memo
         * outlive the single-flight it belongs to" -- but outliving it is now the
         * INTENDED behaviour (see l2_neg_check and the claim() takeover branch):
         * the memo describes L2's contents and a local regen does not change them.
         * Keeping the guard would also re-create the ~1-request window from the
         * other side, since a cold request's own claim() marks the node before the
         * miss is recorded on some paths. */
        if (ctn->kind == NGX_HTTP_CACHE_TURBO_NODE_ENTRY) {
            ngx_shmtx_unlock(&z->shpool->mutex);
            return;
        }

        ctn->l2_neg_until = now + ttl;
        ngx_shmtx_unlock(&z->shpool->mutex);
        return;
    }

    /* No node yet: create a COUNTER carrying only the memo. Invisible to every
     * serve branch (they require an ENTRY with a body). miss_count stays 0 --
     * this path counts nothing; if min_uses is also on it will do its own
     * counting through count_miss on the same node. */
    ctn = ngx_http_cache_turbo_shm_alloc_evict(z,
              sizeof(ngx_http_cache_turbo_node_t));
    if (ctn == NULL) {
        ngx_shmtx_unlock(&z->shpool->mutex);   /* out of slab: no memo */
        return;
    }

    ctn->node.key = hash;
    ngx_memcpy(ctn->key, key_hash, 32);
    ctn->kind = NGX_HTTP_CACHE_TURBO_NODE_COUNTER;
    ctn->data = NULL;
    ctn->len = 0;
    ctn->fresh_until = 0;
    ctn->stale_until = 0;
    ctn->refreshing = 0;
    ctn->refresh_lock_until = 0;
    ctn->miss_count = 0;
    ctn->l2_neg_until = now + ttl;
    ctn->last_access = now;      /* P1: init the coarse LRU stamp */
    ctn->promotable = 0;         /* S8: unproven; second touch promotes */

    ngx_rbtree_insert(&z->sh->rbtree, &ctn->node);
    /* S8: every new node enters PROBATION (see lru_insert_new). */
    ngx_http_cache_turbo_lru_insert_new(z, ctn);

    ngx_shmtx_unlock(&z->shpool->mutex);
}


/* L1 backend instance (v4-1). Stateless dispatch table over the shm functions
 * above; the zone is always passed in as an argument.
 *
 * ⚠ POSITIONAL: fields are brace-initialised in declaration order. A new slot
 * must be APPENDED here in the same order it was appended to
 * ngx_cache_turbo_l1_backend_t, or every entry after it silently shifts. */
ngx_cache_turbo_l1_backend_t  ngx_http_cache_turbo_shm_backend = {
    ngx_string("shm"),
    ngx_http_cache_turbo_shm_lookup,
    ngx_http_cache_turbo_shm_store,
    ngx_http_cache_turbo_shm_purge_key,
    ngx_http_cache_turbo_shm_purge_all,
    ngx_http_cache_turbo_shm_stats,
    ngx_http_cache_turbo_shm_claim,
    ngx_http_cache_turbo_shm_count_miss,
    ngx_http_cache_turbo_shm_l2_neg_check,
    ngx_http_cache_turbo_shm_l2_neg_set,
};
