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


/* Stale window = fresh TTL * (STALE_MULTIPLIER - 1), matching wp-redis. This is
 * the BALANCED-preset stale multiplier; presets override it per-band (v3-2) via
 * the runtime ngx_http_cache_turbo_loc_conf_t.stale_mult field. */
#define NGX_HTTP_CACHE_TURBO_STALE_MULTIPLIER  4

/* Default SWR aggressiveness (beta). 1.0 = refresh probability tracks the
 * elapsed fraction of the stale window directly. */
#define NGX_HTTP_CACHE_TURBO_DEFAULT_BETA      1000   /* fixed-point /1000 */


/*
 * Autotune presets (#10, v3-2). One directive `cache_turbo_preset
 * conservative|balanced|aggressive` sets the default tuning bundle; an explicit
 * knob directive still wins. Vocab matches wp-redis (BALANCED, not "normal").
 * Values are 1-based so they index ngx_http_cache_turbo_bands[] directly; 0 is
 * unused so a zeroed/UNSET field is never a valid preset.
 */
#define NGX_HTTP_CACHE_TURBO_PRESET_CONSERVATIVE  1
#define NGX_HTTP_CACHE_TURBO_PRESET_BALANCED      2
#define NGX_HTTP_CACHE_TURBO_PRESET_AGGRESSIVE    3

/* Default-of-defaults: an unconfigured location resolves to BALANCED, whose band
 * values equal the historical hardcoded merge fallbacks (valid 60s, beta 1000,
 * lock_ttl 5s, stale_mult 4). */
#define NGX_HTTP_CACHE_TURBO_PRESET_DEFAULT  NGX_HTTP_CACHE_TURBO_PRESET_BALANCED

/* A preset band: the default value for each preset-controlled knob. */
typedef struct {
    time_t      valid;       /* fresh TTL (seconds)        */
    ngx_int_t   beta;        /* SWR aggressiveness, /1000  */
    time_t      lock_ttl;    /* single-flight lock window  */
    ngx_int_t   stale_mult;  /* stale window multiplier    */
} ngx_http_cache_turbo_band_t;


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

    /*
     * Preset + the knobs it controls (v3-2). The *_raw fields hold the explicit
     * directive value (or NGX_CONF_UNSET); they are what the directive slots
     * write and what merge inherits down the tree WITHOUT a literal default, so
     * a knob stays UNSET until a real directive sets it at some level. The
     * non-raw fields (valid/beta/lock_ttl/stale_mult) are the EFFECTIVE values
     * the request path reads: in merge_loc_conf each resolves to its *_raw value
     * if set, else the resolved preset's band value. Keeping raw separate from
     * effective is what lets a location's preset still win when an ancestor only
     * resolved the effective default — see the note in merge_loc_conf.
     */
    ngx_int_t                preset;      /* one of PRESET_* or UNSET       */
    time_t                   valid_raw;   /* explicit cache_turbo_valid      */
    ngx_int_t                beta_raw;    /* explicit cache_turbo_beta       */
    time_t                   lock_ttl_raw;/* explicit cache_turbo_lock_ttl   */

    time_t                   valid;       /* fresh TTL (seconds), effective */
    ngx_int_t                beta;        /* SWR aggressiveness /1000, eff  */
    time_t                   lock_ttl;    /* single-flight lock window, eff */
    ngx_int_t                stale_mult;  /* stale window multiplier, eff   */
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

    /* Tag index (v2c). cache_turbo_tag evaluates to a whitespace/comma list of
     * tags; on store each tag set "<prefix>tag:<name>" gets the object's L2 key
     * SADD'ed (+EXPIRE), so a purge-by-tag can drop every keyed object across
     * both tiers. Tags live only in L2, so this needs cache_turbo_redis. */
    ngx_http_complex_value_t *tag;        /* tag list expression, or NULL     */

    /* Key normalize (v3-1). The $cache_turbo_normalized_args variable rebuilds
     * r->args dropping tracking params and sorting the rest, so requests that
     * differ only in arg order or carry junk (utm_*, fbclid, ...) hash to one
     * cache slot. Orthogonal to keying: the user composes the key from the
     * variable, e.g. cache_turbo_key $uri$cache_turbo_normalized_args. */
    ngx_flag_t               normalize_strip_all; /* drop EVERY arg            */
    ngx_array_t             *normalize_strip;     /* extra ngx_str_t patterns to
                                                   * deny, added to the built-in
                                                   * defaults; trailing '*' is a
                                                   * prefix match. NULL = none. */
} ngx_http_cache_turbo_loc_conf_t;


/* per-request context */
typedef struct {
    unsigned                 captured:1;  /* response captured for store    */
    unsigned                 served:1;    /* we served from cache           */
    unsigned                 stale_hit:1; /* served stale (for X-Cache)      */
    unsigned                 warm:1;      /* warm subrequest: force a miss,  */
                                          /* capture + store though !r->main */
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
    ngx_uint_t status, time_t fresh_ttl, ngx_int_t stale_mult);

/* Purge a single entry by key hash. Returns 1 if an entry was removed, 0 if
 * not present. */
ngx_int_t ngx_http_cache_turbo_shm_purge_key(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash);

/* Purge every entry in the zone. Returns the number removed. */
ngx_uint_t ngx_http_cache_turbo_shm_purge_all(ngx_http_cache_turbo_zone_t *z);


/* ---- swr.c ---- */
time_t    ngx_http_cache_turbo_stale_ttl(time_t fresh_ttl, ngx_int_t stale_mult);
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

/* Fire-and-forget DEL of an arbitrary raw key (e.g. an emptied tag set). The
 * key bytes are copied immediately, so the caller's buffer need not outlive the
 * call. No-op when L2 is disabled. */
void ngx_http_cache_turbo_redis_del_raw(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *key, size_t key_len);

/* Build the tag-set key "<prefix>tag:<name>" into buf (must hold
 * prefix.len + sizeof("tag:")-1 + name_len). Returns bytes written. */
size_t ngx_http_cache_turbo_redis_tagkey(ngx_str_t *prefix, u_char *name,
    size_t name_len, u_char *buf);

/* Tag index store: SADD "<prefix>tag:<name>" "<object L2 key>" + EXPIRE the tag
 * set to ttl seconds (refreshed each store). Async fire-and-forget. No-op when
 * L2 is disabled. */
void ngx_http_cache_turbo_redis_tag_add(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *key_hash, u_char *name, size_t name_len, time_t ttl);

/* Completion callback for a SMEMBERS fetch: invoked once with the set members
 * (pointing into transient buffers — copy what must outlive the call) BEFORE
 * the request is finalized. Must produce the HTTP response and return the rc to
 * finalize with. Called with nmembers==0 on an empty/missing set or any error,
 * so the response path is uniform. */
typedef ngx_int_t (*ngx_http_cache_turbo_redis_members_pt)(
    ngx_http_request_t *r, void *data, ngx_str_t *members,
    ngx_uint_t nmembers);

/* Sync-park SMEMBERS "<prefix>tag:<name>": parks the request (count++) and,
 * when the array reply lands, invokes cb(r, data, members, n) then finalizes
 * with the rc cb returned. Returns:
 *   NGX_DONE  - parked; caller must return NGX_DONE
 *   NGX_ERROR - could not start (L2 disabled or connect failed); caller
 *               produces its own response. */
ngx_int_t ngx_http_cache_turbo_redis_smembers(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, u_char *name, size_t name_len,
    ngx_http_cache_turbo_redis_members_pt cb, void *data);

/* Sync-on-L1-miss GET. Issues GET <key> and parks the request (count++,
 * NGX_AGAIN) until the reply arrives; the read handler stores the result in
 * ctx (l2_done + l2_result + l2_blob) and resumes the phase engine. Returns:
 *   NGX_AGAIN    - parked, caller must return NGX_AGAIN to suspend the request
 *   NGX_DECLINED - L2 disabled or could not start; caller proceeds to origin
 * On re-entry after the reply, the caller inspects ctx->l2_result. */
ngx_int_t ngx_http_cache_turbo_redis_get(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx);


#endif /* NGX_HTTP_CACHE_TURBO_MODULE_H_INCLUDED_ */
