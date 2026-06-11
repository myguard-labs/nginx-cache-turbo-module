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
        ctn->generated_at = now;
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
    ctn->generated_at = now;
    ctn->fresh_until = now + fresh_ttl;
    ctn->stale_until = stale_ttl ? now + stale_ttl : 0;
    ctn->refreshing = 0;
    ctn->refresh_lock_until = 0;

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

    /* Autotune introspection (v4-3): average origin-regen cost and the live beta
     * verdict, so the admin GET can render the tuning without an internal probe. */
    cnt = z->sh->cost_count;
    out->cost_ms        = cnt ? (z->sh->cost_sum_ms / cnt) : 0;
    out->autotuned_beta = z->sh->autotuned_beta;
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
};
