/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
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

    ctx->sh->hits = 0;
    ctx->sh->misses = 0;
    ctx->sh->stale_serves = 0;
    ctx->sh->refreshes = 0;
    ctx->sh->evictions = 0;
    ctx->sh->l2_hits = 0;
    ctx->sh->l2_misses = 0;
    ctx->sh->lock_waits = 0;
    ctx->sh->min_uses_skips = 0;

    /* Autotune state (v4-3): everything zeroed. autotune_next = 0 makes the first
     * recompute fire immediately; the snapshots being 0 means the first window is
     * "since worker start". autotuned_beta = 0 means "no verdict → use preset". */
    ctx->sh->cost_sum_ms = 0;
    ctx->sh->cost_count = 0;
    ctx->sh->autotuned_beta = 0;
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


/* Evict the least-recently-used entry. Caller holds the shpool mutex. */
static void
ngx_http_cache_turbo_shm_evict_one(ngx_http_cache_turbo_zone_t *z)
{
    ngx_queue_t                  *q;
    ngx_http_cache_turbo_node_t  *ctn;

    if (ngx_queue_empty(&z->sh->lru)) {
        return;
    }

    q = ngx_queue_last(&z->sh->lru);
    ctn = ngx_queue_data(q, ngx_http_cache_turbo_node_t, lru);

    ngx_queue_remove(&ctn->lru);
    ngx_rbtree_delete(&z->sh->rbtree, &ctn->node);

    if (ctn->data) {
        ngx_slab_free_locked(z->shpool, ctn->data);
    }
    ngx_slab_free_locked(z->shpool, ctn);

    (void) ngx_atomic_fetch_add(&z->sh->evictions, 1);
}


/* Remove one node from rbtree + LRU and free its slab memory. Caller holds the
 * shpool mutex. */
static void
ngx_http_cache_turbo_shm_drop_locked(ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_node_t *ctn)
{
    ngx_queue_remove(&ctn->lru);
    ngx_rbtree_delete(&z->sh->rbtree, &ctn->node);
    if (ctn->data) {
        ngx_slab_free_locked(z->shpool, ctn->data);
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


ngx_uint_t
ngx_http_cache_turbo_shm_purge_all(ngx_http_cache_turbo_zone_t *z)
{
    ngx_uint_t                    n = 0;
    ngx_queue_t                  *q;
    ngx_http_cache_turbo_node_t  *ctn;

    ngx_shmtx_lock(&z->shpool->mutex);
    while (!ngx_queue_empty(&z->sh->lru)) {
        q = ngx_queue_head(&z->sh->lru);
        ctn = ngx_queue_data(q, ngx_http_cache_turbo_node_t, lru);
        ngx_http_cache_turbo_shm_drop_locked(z, ctn);
        n++;
    }
    ngx_shmtx_unlock(&z->shpool->mutex);
    return n;
}


ngx_int_t
ngx_http_cache_turbo_shm_store(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, u_char *data, size_t len,
    ngx_uint_t status, time_t fresh_ttl, ngx_int_t stale_mult)
{
    u_char                       *body;
    time_t                        now, stale_ttl;
    ngx_http_cache_turbo_node_t  *ctn;

    now = ngx_time();
    stale_ttl = ngx_http_cache_turbo_stale_ttl(fresh_ttl, stale_mult);

    ngx_shmtx_lock(&z->shpool->mutex);

    /* Already present? Update in place (refresh path). */
    ctn = ngx_http_cache_turbo_shm_lookup(z, key_hash, hash);

    if (ctn) {
        body = ngx_slab_alloc_locked(z->shpool, len);
        if (body == NULL) {
            ngx_http_cache_turbo_shm_evict_one(z);
            body = ngx_slab_alloc_locked(z->shpool, len);
        }
        if (body == NULL) {
            ngx_shmtx_unlock(&z->shpool->mutex);
            return NGX_ERROR;
        }

        ngx_memcpy(body, data, len);
        if (ctn->data) {
            ngx_slab_free_locked(z->shpool, ctn->data);
        }
        ctn->data = body;
        ctn->len = len;
        ctn->status = status;
        ctn->fresh_until = now + fresh_ttl;
        ctn->stale_until = stale_ttl ? now + stale_ttl : 0;
        ctn->refreshing = 0;
        ctn->refresh_lock_until = 0;

        ngx_queue_remove(&ctn->lru);
        ngx_queue_insert_head(&z->sh->lru, &ctn->lru);

        ngx_shmtx_unlock(&z->shpool->mutex);
        return NGX_OK;
    }

    /* New entry. */
    ctn = ngx_slab_alloc_locked(z->shpool,
                                sizeof(ngx_http_cache_turbo_node_t));
    if (ctn == NULL) {
        ngx_http_cache_turbo_shm_evict_one(z);
        ctn = ngx_slab_alloc_locked(z->shpool,
                                    sizeof(ngx_http_cache_turbo_node_t));
    }
    if (ctn == NULL) {
        ngx_shmtx_unlock(&z->shpool->mutex);
        return NGX_ERROR;
    }

    body = ngx_slab_alloc_locked(z->shpool, len);
    if (body == NULL) {
        ngx_http_cache_turbo_shm_evict_one(z);
        body = ngx_slab_alloc_locked(z->shpool, len);
    }
    if (body == NULL) {
        ngx_slab_free_locked(z->shpool, ctn);
        ngx_shmtx_unlock(&z->shpool->mutex);
        return NGX_ERROR;
    }

    ngx_memcpy(body, data, len);

    ctn->node.key = hash;
    ngx_memcpy(ctn->key, key_hash, 32);
    ctn->data = body;
    ctn->len = len;
    ctn->status = status;
    ctn->fresh_until = now + fresh_ttl;
    ctn->stale_until = stale_ttl ? now + stale_ttl : 0;
    ctn->refreshing = 0;
    ctn->refresh_lock_until = 0;
    ctn->miss_count = 0;

    ngx_rbtree_insert(&z->sh->rbtree, &ctn->node);
    ngx_queue_insert_head(&z->sh->lru, &ctn->lru);

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

    /* Autotune introspection (v4-3): average origin-regen cost and the live beta
     * verdict, so the admin GET can render the tuning without an internal probe. */
    cnt = z->sh->cost_count;
    out->cost_ms        = cnt ? (z->sh->cost_sum_ms / cnt) : 0;
    out->autotuned_beta = z->sh->autotuned_beta;
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
         * overwrites it on store(). */
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
    ctn = ngx_slab_alloc_locked(z->shpool,
                                sizeof(ngx_http_cache_turbo_node_t));
    if (ctn == NULL) {
        ngx_http_cache_turbo_shm_evict_one(z);
        ctn = ngx_slab_alloc_locked(z->shpool,
                                    sizeof(ngx_http_cache_turbo_node_t));
    }
    if (ctn == NULL) {
        /* Out of slab: cannot mark the key in flight, so just regenerate
         * (winner, no single-flight this time — correct, only less efficient). */
        ngx_shmtx_unlock(&z->shpool->mutex);
        return NGX_HTTP_CACHE_TURBO_CLAIM_WINNER;
    }

    ctn->node.key = hash;
    ngx_memcpy(ctn->key, key_hash, 32);
    ctn->data = NULL;
    ctn->len = 0;
    ctn->status = 0;
    ctn->fresh_until = 0;
    ctn->stale_until = 0;
    ctn->refreshing = 1;
    ctn->refresh_lock_until = now + lock_ttl;
    ctn->miss_count = 0;

    ngx_rbtree_insert(&z->sh->rbtree, &ctn->node);
    ngx_queue_insert_head(&z->sh->lru, &ctn->lru);

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
    if (ctn != NULL && ctn->len == 0 && ctn->data == NULL) {
        ngx_queue_remove(&ctn->lru);
        ngx_rbtree_delete(&z->sh->rbtree, &ctn->node);
        ngx_slab_free_locked(z->shpool, ctn);
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
        if (ctn->len > 0) {
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
    ctn = ngx_slab_alloc_locked(z->shpool,
                                sizeof(ngx_http_cache_turbo_node_t));
    if (ctn == NULL) {
        ngx_http_cache_turbo_shm_evict_one(z);
        ctn = ngx_slab_alloc_locked(z->shpool,
                                    sizeof(ngx_http_cache_turbo_node_t));
    }
    if (ctn == NULL) {
        /* Out of slab: cannot track the count, so just let it cache now
         * (correct, only less selective than min_uses would like). */
        ngx_shmtx_unlock(&z->shpool->mutex);
        return NGX_OK;
    }

    ctn->node.key = hash;
    ngx_memcpy(ctn->key, key_hash, 32);
    ctn->data = NULL;
    ctn->len = 0;
    ctn->status = 0;
    ctn->fresh_until = 0;
    ctn->stale_until = 0;
    ctn->refreshing = 0;
    ctn->refresh_lock_until = 0;
    ctn->miss_count = 1;

    ngx_rbtree_insert(&z->sh->rbtree, &ctn->node);
    ngx_queue_insert_head(&z->sh->lru, &ctn->lru);

    ngx_shmtx_unlock(&z->shpool->mutex);

    /* First miss: below threshold unless min_uses == 1 (caller guards that). */
    return (min_uses <= 1) ? NGX_OK : NGX_DECLINED;
}


/* L1 backend instance (v4-1). Stateless dispatch table over the shm functions
 * above; the zone is always passed in as an argument. */
ngx_cache_turbo_l1_backend_t  ngx_http_cache_turbo_shm_backend = {
    ngx_string("shm"),
    ngx_http_cache_turbo_shm_lookup,
    ngx_http_cache_turbo_shm_store,
    ngx_http_cache_turbo_shm_purge_key,
    ngx_http_cache_turbo_shm_purge_all,
    ngx_http_cache_turbo_shm_stats,
    ngx_http_cache_turbo_shm_claim,
    ngx_http_cache_turbo_shm_count_miss,
};
