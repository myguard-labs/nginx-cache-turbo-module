/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * http-cache-turbo — Varnish-grade edge cache for nginx.
 *
 * v1 vertical slice: L1 shared-memory page cache with stale-while-revalidate
 * and probabilistic single-flight refresh (the "XFetch dice" ported from the
 * wp-redis SWR implementation: eilandert/wp-redis/includes/class-swr.php).
 * No Redis L2, no tags, no REST admin, no presets yet — those land in later
 * versions. See memory/nginx+angie/cache-turbo-module-design.md.
 */

#ifndef NGX_HTTP_CACHE_TURBO_MODULE_H_INCLUDED_
#define NGX_HTTP_CACHE_TURBO_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>


/* Stale window = fresh TTL * (STALE_MULTIPLIER - 1), matching wp-redis. */
#define NGX_HTTP_CACHE_TURBO_STALE_MULTIPLIER  4

/* Default SWR aggressiveness (beta). 1.0 = refresh probability tracks the
 * elapsed fraction of the stale window directly. */
#define NGX_HTTP_CACHE_TURBO_DEFAULT_BETA      1000   /* fixed-point /1000 */


/*
 * One cached object living in the shared-memory slab. The node key is the
 * 32-byte hash of the cache key; the variable-length body (headers + payload,
 * serialised) is slab-allocated separately and pointed to by data/len.
 */
typedef struct {
    ngx_rbtree_node_t        node;       /* node.key = crc32 of cache key  */
    u_char                   key[32];    /* full key hash, collision guard */

    u_char                  *data;       /* serialised response, slab alloc */
    size_t                   len;

    time_t                   fresh_until;   /* < now  => stale              */
    time_t                   stale_until;   /* < now  => expired/evict      */
    time_t                   generated_at;

    ngx_uint_t               refreshing;    /* a single-flight regen in air */
    time_t                   refresh_lock_until; /* hard single-flight guard:
                                              * while now < this, ALL readers
                                              * serve stale and skip the dice;
                                              * only the claimer regenerates.
                                              * Self-heals if a refresh dies. */
    ngx_uint_t               status;        /* cached HTTP status           */

    ngx_queue_t              lru;           /* LRU list linkage             */
} ngx_http_cache_turbo_node_t;


/* Shared-memory zone state: rbtree of cached objects + LRU + stats. */
typedef struct {
    ngx_rbtree_t             rbtree;
    ngx_rbtree_node_t        sentinel;
    ngx_queue_t              lru;

    ngx_atomic_t             hits;
    ngx_atomic_t             misses;
    ngx_atomic_t             stale_serves;
    ngx_atomic_t             refreshes;
    ngx_atomic_t             evictions;
} ngx_http_cache_turbo_shctx_t;


typedef struct {
    ngx_http_cache_turbo_shctx_t  *sh;
    ngx_slab_pool_t               *shpool;
} ngx_http_cache_turbo_zone_t;


/* location-level configuration */
typedef struct {
    ngx_flag_t               enable;
    ngx_shm_zone_t          *shm_zone;
    ngx_http_complex_value_t *key;        /* cache key expression           */
    time_t                   valid;       /* fresh TTL (seconds)            */
    ngx_int_t                beta;        /* SWR aggressiveness, /1000       */
    time_t                   lock_ttl;    /* hard single-flight lock window */
    size_t                   max_size;    /* max single response to cache   */
    ngx_flag_t               admin;       /* this location is an admin endpoint */
    ngx_shm_zone_t          *admin_zone;  /* zone the admin endpoint manages */

    /* L2 Redis (v2b). Native async client, no hiredis. The L2 store is touched
     * only on an L1 miss (sync GET) and on store (async write-through); it is
     * never on the L1-hit hot path. */
    ngx_flag_t               redis_enable; /* cache_turbo_redis configured     */
    ngx_addr_t               redis_addr;   /* resolved host:port               */
    ngx_str_t                redis_prefix; /* key prefix, default "ct:"        */
    ngx_msec_t               redis_timeout;/* connect/read timeout             */
} ngx_http_cache_turbo_loc_conf_t;


/* per-request context */
typedef struct {
    unsigned                 captured:1;  /* response captured for store    */
    unsigned                 served:1;    /* we served from cache           */
    unsigned                 stale_hit:1; /* served stale (for X-Cache)      */
    unsigned                 l2_pending:1;/* L2 GET parked, awaiting reply   */
    unsigned                 l2_done:1;   /* L2 GET finished (hit or miss)   */
    ngx_int_t                l2_result;   /* NGX_OK = L2 hit; else miss      */
    u_char                  *l2_blob;     /* L2-hit blob, copied to r->pool  */
    size_t                   l2_blob_len;
    ngx_chain_t             *body;        /* buffered response chain        */
    size_t                   body_len;
    ngx_str_t                cache_key;
    u_char                   key_hash[32];
} ngx_http_cache_turbo_ctx_t;


/*
 * Serialised cache blob layout (one contiguous slab allocation):
 *
 *   [ ngx_http_cache_turbo_blob_hdr_t header ]
 *   [ nheaders * { u32 name_len, name, u32 val_len, value } ]
 *   [ body bytes ]
 *
 * The header block lets us restore Content-Type and any other response
 * headers on a cache hit, so cached responses are byte-identical to origin.
 */
typedef struct {
    uint32_t                 magic;       /* 0x43544231 = "CTB1"            */
    uint32_t                 nheaders;
    uint32_t                 headers_len; /* bytes of the header block      */
    uint32_t                 body_len;
    uint32_t                 status;
} ngx_http_cache_turbo_blob_hdr_t;

#define NGX_HTTP_CACHE_TURBO_BLOB_MAGIC  0x43544231


extern ngx_module_t  ngx_http_cache_turbo_module;


/* ---- shm.c ---- */
ngx_int_t ngx_http_cache_turbo_shm_init_zone(ngx_shm_zone_t *zone, void *data);

ngx_http_cache_turbo_node_t *
    ngx_http_cache_turbo_shm_lookup(ngx_http_cache_turbo_zone_t *z,
        u_char *key_hash, uint32_t hash);

ngx_int_t ngx_http_cache_turbo_shm_store(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, u_char *data, size_t len,
    ngx_uint_t status, time_t fresh_ttl);

/* Purge a single entry by key hash. Returns 1 if an entry was removed, 0 if
 * not present. */
ngx_int_t ngx_http_cache_turbo_shm_purge_key(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash);

/* Purge every entry in the zone. Returns the number removed. */
ngx_uint_t ngx_http_cache_turbo_shm_purge_all(ngx_http_cache_turbo_zone_t *z);


/* ---- swr.c ---- */
time_t    ngx_http_cache_turbo_stale_ttl(time_t fresh_ttl);
ngx_int_t ngx_http_cache_turbo_should_refresh(u_char *key_hash,
    time_t fresh_until, time_t stale_window, ngx_int_t beta_milli);


/* ---- redis.c (L2, v2b) ---- */

/* Default key prefix for L2 entries (overridable with prefix=). */
#define NGX_HTTP_CACHE_TURBO_REDIS_PREFIX  "ct:"

/* Build the L2 redis key for a cache entry into buf (must hold prefix.len +
 * 64). Returns the byte length written. Key = prefix + lowercase hex of the
 * 32-byte key hash, so it is stable and shareable across nodes. */
size_t ngx_http_cache_turbo_redis_key(ngx_str_t *prefix, u_char *key_hash,
    u_char *buf);

/* Async write-through: fire-and-forget SET <key> <blob> PX <ms>. Copies
 * everything it needs into its own pool, never blocks the worker, and survives
 * the request being finalised. Best-effort: failures are logged, not fatal. */
void ngx_http_cache_turbo_redis_set(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, u_char *key_hash,
    u_char *blob, size_t blob_len, time_t fresh_ttl);

/* Async fire-and-forget DEL <key>: drop an entry from L2 so a purge that
 * cleared L1 cannot be refilled from Redis (issue P6). Own pool, never blocks,
 * survives the request. No-op when L2 is disabled. */
void ngx_http_cache_turbo_redis_del(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *key_hash);

/* Sync-on-L1-miss GET. Issues GET <key> and parks the request (count++,
 * NGX_AGAIN) until the reply arrives; the read handler stores the result in
 * ctx (l2_done + l2_result + l2_blob) and resumes the phase engine. Returns:
 *   NGX_AGAIN    - parked, caller must return NGX_AGAIN to suspend the request
 *   NGX_DECLINED - L2 disabled or could not start; caller proceeds to origin
 * On re-entry after the reply, the caller inspects ctx->l2_result. */
ngx_int_t ngx_http_cache_turbo_redis_get(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx);


#endif /* NGX_HTTP_CACHE_TURBO_MODULE_H_INCLUDED_ */
