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


/*
 * Live autotune within preset bands (#10, v4-3). Ported from the wp-redis PHP
 * implementation (eilandert/wp-redis/includes/class-swr-autotune.php) so the edge
 * cache and the object cache tune the same way with the same constants. When
 * cache_turbo_autotune is on, a throttled per-zone recompute reads the L1 shm
 * stats over the last window (delta-snapshot), derives a target beta from the
 * average origin-regen cost, and writes it to the zone (z->sh->autotuned_beta).
 * The request path then uses that beta clamped to the location's preset band
 * instead of the static preset/explicit beta. See history.md v4-3.
 *
 * All values are integer fixed-point to keep floats off the request path, exactly
 * like swr.c: beta is ×1000, hit-rate is a percentage, the cost divisor and churn
 * cap are plain integers. The PHP source uses 0.5/3.0/20/30ms/10ms/100/0.95/2.0.
 */
#define NGX_HTTP_CACHE_TURBO_BETA_MIN          500    /* 0.5 ×1000 (global floor) */
#define NGX_HTTP_CACHE_TURBO_BETA_MAX          3000   /* 3.0 ×1000 (global ceil)  */
#define NGX_HTTP_CACHE_TURBO_BETA_COST_DIVISOR 20     /* beta = cost_ms / 20      */

#define NGX_HTTP_CACHE_TURBO_AT_COST_STRONG_MS 30     /* expensive-regen gate     */
#define NGX_HTTP_CACHE_TURBO_AT_COST_MOD_MS    10     /* moderate-regen gate      */
#define NGX_HTTP_CACHE_TURBO_AT_MISSES_FLOOR   100    /* min misses/window + the
                                                       * min hits+misses to decide */
#define NGX_HTTP_CACHE_TURBO_AT_HIT_RATE_CAP   95     /* hit-rate < 95% (percent) */
#define NGX_HTTP_CACHE_TURBO_AT_CHURN_CAP      2      /* refreshes/misses > 2 → no */

/* Default recompute cadence (seconds) when cache_turbo_autotune is on but no
 * cache_turbo_autotune_interval is given. */
#define NGX_HTTP_CACHE_TURBO_AT_INTERVAL       30


/*
 * Vary-aware normalize suffix (v3-4). Bitmask in loc_conf.normalize_vary chosen
 * by `cache_turbo_normalize_vary encoding device`. ENCODING appends an
 * Accept-Encoding class (br/gzip/identity); DEVICE appends a User-Agent device
 * class (mobile/desktop). Off by default so v3-1 keys are unchanged.
 */
#define NGX_HTTP_CACHE_TURBO_VARY_ENCODING  0x1
#define NGX_HTTP_CACHE_TURBO_VARY_DEVICE    0x2
/* auto-Vary (v11 other half): the same bits also drive the automatic variant
 * key derived from a response `Vary:` header (cache_turbo_auto_vary). LANG keys
 * on the raw Accept-Language value; ORIGIN on the raw Origin value. Only this
 * safe whitelist is honoured — Vary: * / Cookie / Authorization make the
 * response uncacheable instead (cross-user poisoning/leak guard). */
#define NGX_HTTP_CACHE_TURBO_VARY_LANG      0x4
#define NGX_HTTP_CACHE_TURBO_VARY_ORIGIN    0x8

/* Worst-case suffix bytes: "\x1Fae=identity" (12) + "\x1Fdev=desktop" (12). The
 * delimiter is the raw 0x1F (US) byte, which a query string can never contain
 * (clients percent-encode control bytes), so the suffix cannot collide with a
 * real arg value. */
#define NGX_HTTP_CACHE_TURBO_VARY_SUFFIX_MAX  32

/* A preset band: the default value for each preset-controlled knob, plus the
 * [beta_min, beta_max] window the live autotune (v4-3) may move beta within for
 * this preset. The autotune computes a cost-derived target clamped to the global
 * [BETA_MIN, BETA_MAX]; the request path then re-clamps it to this band so e.g. a
 * conservative location never autotunes as hot as an aggressive one. */
typedef struct {
    time_t      valid;       /* fresh TTL (seconds)        */
    ngx_int_t   beta;        /* SWR aggressiveness, /1000  */
    time_t      lock_ttl;    /* single-flight lock window  */
    ngx_int_t   stale_mult;  /* stale window multiplier    */
    ngx_int_t   beta_min;    /* autotune lower clamp /1000 */
    ngx_int_t   beta_max;    /* autotune upper clamp /1000 */
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

    ngx_uint_t               refreshing;    /* a single-flight regen in air */
    time_t                   refresh_lock_until; /* hard single-flight guard:
                                              * while now < this, ALL readers
                                              * serve stale and skip the dice;
                                              * only the claimer regenerates.
                                              * Self-heals if a refresh dies. */
    ngx_uint_t               status;        /* cached HTTP status           */

    /* min_uses (v15) miss counter. A "counter node" (data == NULL / len == 0,
     * refreshing == 0) tracks how many times a key has cold-missed without yet
     * being cached, so cache_turbo_min_uses N can defer the first store until the
     * key has been requested N times (don't cache one-hit-wonders). Distinct from
     * a v10 single-flight STUB, which is also len == 0 but has refreshing == 1.
     * Irrelevant once the node holds a real body (len > 0); left untouched then. */
    ngx_uint_t               miss_count;

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

    /* L2 (Redis) outcome counters (v12): incremented on an L1 miss that
     * consulted L2 — l2_hits when L2 held the object (filled L1), l2_misses when
     * it did not (went to origin). Zero when no L2 is configured. */
    ngx_atomic_t             l2_hits;
    ngx_atomic_t             l2_misses;

    /* Cold-miss single-flight (v10): bumped once when a request first enters the
     * wait loop (a coalesced cold-miss that did NOT go to origin). Zero when
     * cache_turbo_lock is off. Observability for the single-flight working. */
    ngx_atomic_t             lock_waits;

    /* min_uses (v15): bumped once per cold miss that was sent to the origin
     * WITHOUT storing because the key is still below cache_turbo_min_uses. Zero
     * when min_uses is 1 (the default — feature off). Observability for the
     * "don't cache one-hit-wonders" gate. */
    ngx_atomic_t             min_uses_skips;

    /*
     * Live autotune state (v4-3). cost_sum_ms / cost_count accumulate the
     * wall-clock cost of every origin regeneration (request_time at the
     * origin→cache store), so their ratio is the average miss-cost the autotune
     * feeds on. autotuned_beta is the verdict the request path reads (×1000;
     * 0 = no verdict yet → fall back to the preset/explicit beta). autotune_next
     * throttles the recompute to once per interval per worker. The snap_* fields
     * are the counter values at the previous recompute so each tick works on the
     * delta over the last window (windowed, not lifetime-cumulative → it adapts
     * down as well as up). All mutated under shpool->mutex in the recompute.
     */
    ngx_atomic_t             cost_sum_ms;   /* Σ origin-regen request_time (ms) */
    ngx_atomic_t             cost_count;    /* number of origin regens measured */
    ngx_atomic_t             autotuned_beta;/* live verdict ×1000, 0 = none     */
    ngx_atomic_t             autotune_next; /* next recompute (epoch seconds)   */
    ngx_atomic_uint_t        snap_hits;
    ngx_atomic_uint_t        snap_misses;
    ngx_atomic_uint_t        snap_refreshes;
    ngx_atomic_uint_t        snap_cost_sum;
    ngx_atomic_uint_t        snap_cost_count;
} ngx_http_cache_turbo_shctx_t;


typedef struct {
    ngx_http_cache_turbo_shctx_t  *sh;
    ngx_slab_pool_t               *shpool;
} ngx_http_cache_turbo_zone_t;


/* Snapshot of the L1 zone's atomic counters. Filled by the l1 backend's stats
 * op and rendered by the admin GET handler, so the JSON formatting never touches
 * the live shctx directly. */
typedef struct {
    ngx_atomic_uint_t   hits;
    ngx_atomic_uint_t   misses;
    ngx_atomic_uint_t   stale_serves;
    ngx_atomic_uint_t   refreshes;
    ngx_atomic_uint_t   evictions;
    ngx_atomic_uint_t   l2_hits;
    ngx_atomic_uint_t   l2_misses;
    ngx_atomic_uint_t   lock_waits;   /* v10 coalesced cold-misses (waited)   */
    ngx_atomic_uint_t   min_uses_skips; /* v15 cold misses below min_uses     */
    /* Autotune introspection (v4-3): cost_ms = the measured average origin-regen
     * cost (cost_sum_ms / cost_count, 0 when nothing measured); autotuned_beta =
     * the live verdict ×1000 (0 = none). Rendered by the admin GET so a test (or
     * an operator) can see the live tuning without an internal probe. */
    ngx_atomic_uint_t   cost_ms;
    ngx_atomic_uint_t   autotuned_beta;
} ngx_http_cache_turbo_stats_t;


/*
 * Backend vtables (v4-1, #6). Two tiers, two interfaces: the local L1 store
 * (synchronous, in-process shm) and the remote L2 driver (asynchronous, parks
 * the request). They are deliberately NOT fused behind one get() — the SWR dice
 * / serve-stale branching lives between the L1 lookup and the L2 consult in the
 * access handler (see history.md v4-1). Forward-declared here so loc_conf can
 * hold pointers; the full definitions are at the foot of this header (after the
 * request ctx + members callback typedef they reference).
 */
typedef struct ngx_cache_turbo_l1_backend_s  ngx_cache_turbo_l1_backend_t;
typedef struct ngx_cache_turbo_backend_s     ngx_cache_turbo_backend_t;


/* One per-status fresh-TTL rule (v6): "cache this status for this long". */
typedef struct {
    ngx_uint_t   status;     /* HTTP status code (e.g. 301, 404)  */
    time_t       valid;      /* fresh TTL in seconds (0 = forever) */
} ngx_http_cache_turbo_valid_t;


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

    /* Per-status TTLs (v6). cache_turbo_valid with leading status codes, e.g.
     * `cache_turbo_valid 301 302 1h; cache_turbo_valid 404 410 1m;`. Lets the
     * cache store redirects and negative responses, each with its own fresh TTL.
     * Array of ngx_http_cache_turbo_valid_t; NULL = only 200 is cacheable (at
     * clcf->valid). 200's TTL stays the bare `cache_turbo_valid TIME` value. */
    ngx_array_t             *valid_status;

    /* Bypass / no-store predicates (v9), like proxy_cache_bypass / proxy_no_cache.
     * Each is an array of complex values; a request "trips" the predicate when any
     * evaluates to a non-empty string other than "0". bypass => don't serve from
     * cache (still store the fresh response); no_store => don't store. Both NULL
     * by default. */
    ngx_array_t             *bypass;
    ngx_array_t             *no_store;

    /* Live autotune (v4-3). When on, the request path uses the zone's live
     * autotuned beta (clamped to this location's preset band) in place of the
     * static effective beta above; autotune_interval throttles the per-zone
     * recompute. Off by default — beta then resolves purely from preset/explicit
     * as before. The clamp band is ngx_http_cache_turbo_bands[preset]. */
    ngx_flag_t               autotune;       /* cache_turbo_autotune on|off    */
    time_t                   autotune_interval; /* recompute cadence (seconds) */

    /* Honor upstream freshness (v7). When on, the fresh TTL for a stored response
     * is taken from its own Cache-Control s-maxage / max-age (s-maxage wins), or
     * else its Expires header, instead of the static per-status TTL. Falls back to
     * the configured TTL when the response carries no freshness info. Off by
     * default so existing fixed-TTL configs are unchanged. */
    ngx_flag_t               honor_cc;
    size_t                   max_size;    /* max single response to cache   */
    ngx_flag_t               admin;       /* this location is an admin endpoint */
    ngx_shm_zone_t          *admin_zone;  /* zone the admin endpoint manages */

    /* PURGE method (v14). When on, a `PURGE <uri>` request to this caching
     * location drops that URI's entry from L1 (+ L2). Gate the location with
     * allow/deny. Off by default. */
    ngx_flag_t               purge;

    /* Background update / stale-while-revalidate (v8). When on (default), the
     * SWR dice-winner does NOT regenerate inline: it fires a background refresh
     * subrequest for its own URI and serves the stale copy immediately, so no
     * foreground request ever blocks on the origin. A failed bg refresh (origin
     * 5xx/timeout) never overwrites the entry, so the stale copy persists =
     * stale-if-error for free. Off restores the old block-and-serve-fresh
     * winner. Mirrors proxy_cache_background_update (but default on here). */
    ngx_flag_t               background_update;

    /* Cold-miss single-flight (v10). When on (default), the FIRST request to
     * cold-miss a key (no L1 node, L2 also misses) becomes the single
     * regenerator (per box via a stub shm node, cross-node via the v4-2 Redis
     * NX lock); concurrent first-hits for the same key WAIT (park + re-check)
     * up to lock_timeout for the winner to fill the cache, then serve it,
     * instead of all stampeding the origin. off restores the old behaviour
     * (every cold-miss goes straight to origin). Mirrors proxy_cache_lock /
     * proxy_cache_lock_timeout (but default on here). lock_ttl bounds the
     * winner's hold (self-heal). */
    ngx_flag_t               lock;          /* cache_turbo_lock on|off          */
    ngx_msec_t               lock_timeout;  /* max a loser waits, then origin   */

    /* Minimum uses before caching (v15). cache_turbo_min_uses N stores a
     * response only after its key has cold-missed N times, so one-hit-wonder
     * URLs never occupy the cache. A per-key miss counter lives in a lightweight
     * L1 "counter node" (see ngx_http_cache_turbo_node_t.miss_count); the Nth
     * miss converts that node into the normal cold-miss winner that stores.
     * Default 1 = store on the first miss (feature off, zero behaviour change).
     * Below the threshold a request goes to the origin but is not captured, and
     * a popular key already present in L2 is served from L2 regardless (the gate
     * sits after the L2 consult). */
    ngx_int_t                min_uses;

    /* L2 Redis (v2b). Native async client, no hiredis. The L2 store is touched
     * only on an L1 miss (sync GET) and on store (async write-through); it is
     * never on the L1-hit hot path. */
    ngx_flag_t               redis_enable; /* cache_turbo_redis configured     */
    ngx_addr_t               redis_addr;   /* resolved host:port               */
    ngx_str_t                redis_prefix; /* key prefix, default "ct:"        */
    ngx_msec_t               redis_timeout;/* connect/read timeout             */

    /* Keepalive pool (v15). cache_turbo_redis keepalive=N caches up to N idle
     * L2 connections per worker, keyed by peer addr, so an L2 op reuses a live
     * TCP connection instead of connect()+close per op. 0 = off (default).
     * keepalive_timeout= closes an idle pooled connection after this long.
     * Plain TCP only: TLS connections are never pooled (c->ssl borrows the op
     * pool, which is torn down per op — see redis op_done). */
    ngx_int_t                redis_keepalive;        /* max idle conns, 0=off  */
    ngx_msec_t               redis_keepalive_timeout;/* idle close timeout     */

    /* Full DSN (v5): cache_turbo_redis accepts redis://[user:pass@]host:port/db
     * (rediss:// = TLS), with prefix=/timeout=/password=/user=/db=/tls=/
     * tls_verify=/tls_ca=/tls_name= overrides. On each connection the driver
     * pipelines AUTH (+ optional ACL user) and SELECT <db> before the command;
     * rediss wraps the socket in TLS and (by default) verifies the server cert
     * against the system CA + the host name. */
    ngx_str_t                redis_user;    /* ACL username, "" = legacy AUTH   */
    ngx_str_t                redis_password;/* AUTH password, "" = no AUTH      */
    ngx_int_t                redis_db;      /* SELECT db index, 0 = no SELECT   */
    ngx_flag_t               redis_tls;     /* rediss:// or tls=on              */
    ngx_flag_t               redis_tls_verify; /* verify cert+host (default on) */
    ngx_str_t                redis_tls_ca;  /* CA bundle file, "" = system CAs  */
    ngx_str_t                redis_tls_name;/* verify/SNI name, "" = DSN host   */
    ngx_str_t                redis_host;    /* DSN host (default SNI/verify name)*/
#if (NGX_SSL)
    ngx_ssl_t               *redis_ssl;     /* per-location client SSL context  */
#endif

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

    /* Vary-aware suffix (v3-4). Bitmask of NGX_HTTP_CACHE_TURBO_VARY_* selecting
     * which buckets are appended to $cache_turbo_normalized_args so responses
     * that legitimately differ by encoding (br/gzip/identity) or device
     * (mobile/desktop) get separate cache slots. NGX_CONF_UNSET / 0 = off, so
     * v3-1 keys are unchanged unless cache_turbo_normalize_vary opts in. */
    ngx_int_t                normalize_vary;

    /* auto-Vary (v11 other half). When on, the response `Vary:` header is read
     * at store time and the named request headers (safe whitelist only:
     * Accept-Encoding, User-Agent->device, Accept-Language, Origin) are folded
     * into a SECONDARY variant key so distinct representations get distinct
     * slots automatically — no operator config of the axes. Two-level keying is
     * node-local: a tiny "vary marker" (the active axis bitmask) is stored in L1
     * under a dedicated marker key; a request probes the marker (L1 only) and,
     * if present, recomputes its key to the variant before the normal lookup.
     * The base slot stays empty for varied URLs, so a missing marker just misses
     * to origin (never serves the wrong variant). Vary: * / Cookie /
     * Authorization make the response uncacheable. Off by default. */
    ngx_flag_t               auto_vary;

    /* Backend vtables (v4-1). l1 = the local store (shm); it is a stateless
     * dispatch table (the zone is passed as an argument), so it is set
     * unconditionally and is never NULL. backend = the remote L2 driver (redis),
     * set when cache_turbo_redis is configured, else NULL — call sites guard on
     * it. Both are resolved in merge_loc_conf. */
    ngx_cache_turbo_l1_backend_t  *l1;
    ngx_cache_turbo_backend_t     *backend;
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
    /* Cross-node dogpile (v4-2). On a stale L1 dice win the request parks for a
     * Redis SET NX PX reply: lock_result == NGX_OK means this node holds the
     * cluster-wide regen lock (go to origin); anything else means another node
     * owns it (serve stale, skip origin). Mirrors the l2_* park/resume trio. */
    unsigned                 lock_pending:1;/* NX parked, awaiting reply      */
    unsigned                 lock_done:1; /* NX reply landed                 */
    ngx_int_t                lock_result; /* NGX_OK = we hold the lock        */
    /* Cold-miss single-flight (v10). A cold-miss LOSER parks on a short timer
     * and re-checks L1/L2 until the winner fills the entry or lock_timeout
     * elapses. waiting marks this request as already in the wait loop (re-entry
     * must not re-claim); wait_deadline is the give-up time (ngx_current_msec
     * clock); cold_wait_ev is the per-request poll timer (data = r). */
    unsigned                 waiting:1;   /* in the cold-miss wait loop       */
    ngx_msec_t               wait_deadline;/* give up + go to origin at this   */
    ngx_event_t              cold_wait_ev; /* poll timer for the wait loop     */
    /* This request is the cold-miss WINNER that owns the in-flight stub: it
     * went to origin and must leave a real entry OR clear the stub so waiters
     * don't block on a key that turned out non-cacheable. cold_stored = the
     * stub was resolved (a real blob was stored, or the stub was cleared); when
     * it is still 0 at request teardown the pool cleanup removes the leftover
     * stub. cold_zone is the zone to clear it in (cleanup has only the ctx). */
    unsigned                 cold_winner:1;
    unsigned                 cold_stored:1;
    ngx_http_cache_turbo_zone_t *cold_zone;
    ngx_chain_t             *body;        /* buffered response chain        */
    size_t                   body_len;
    ngx_str_t                cache_key;
    u_char                   key_hash[32];
    /* auto-Vary (v11 other half). varied = the request was re-keyed to a variant
     * via an L1 vary marker (key_hash already holds the variant). vary_bits = the
     * safe-axis bitmask classified from the response Vary header in the header
     * filter (>0 => store under a variant key + write/refresh the marker; the
     * body filter reads it). vary_nocache = the response carried a Vary the
     * whitelist refuses (*, Cookie, Authorization) => do not capture/store. */
    unsigned                 varied:1;
    unsigned                 vary_nocache:1;
    ngx_int_t                vary_bits;
    /* min_uses (v15). min_uses_skip = this request is below the threshold, so the
     * header filter must NOT capture it (no store) and it runs to the origin.
     * min_uses_passed = the gate already counted this request and let it through
     * (it reached the threshold); it guards against re-counting on a park/resume
     * re-entry of the access handler (L2/NX-lock/cold-wait wake). */
    unsigned                 min_uses_skip:1;
    unsigned                 min_uses_passed:1;
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

/* Snapshot the zone's atomic stat counters into out (admin stats endpoint). */
void ngx_http_cache_turbo_shm_stats(ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_stats_t *out);

/* Cold-miss single-flight claim (v10). See the L1 vtable `claim` comment.
 * Returns NGX_HTTP_CACHE_TURBO_CLAIM_{WINNER,LOSER,FRESH}. */
ngx_int_t ngx_http_cache_turbo_shm_claim(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, time_t lock_ttl);

/* Remove a leftover cold-miss STUB (v10): drops the node ONLY if it is still a
 * stub (len == 0), so a real entry stored by someone else is never touched.
 * Used when a cold-miss winner's response turned out non-cacheable. */
void ngx_http_cache_turbo_shm_unstub(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash);

/* min_uses miss counter (v15). See the L1 vtable `count_miss` comment. Returns
 * NGX_OK when the key has reached min_uses (store-eligible — proceed to the
 * normal cold path) or NGX_DECLINED when it is still below the threshold (go to
 * the origin without storing). A real entry (len > 0) or an in-flight stub
 * always returns NGX_OK without counting — refreshes are never re-gated. */
ngx_int_t ngx_http_cache_turbo_shm_count_miss(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, ngx_int_t min_uses);


/* ---- swr.c ---- */
time_t    ngx_http_cache_turbo_stale_ttl(time_t fresh_ttl, ngx_int_t stale_mult);
ngx_int_t ngx_http_cache_turbo_should_refresh(u_char *key_hash,
    time_t fresh_until, time_t stale_window, ngx_int_t beta_milli);


/* ---- autotune.c (live autotune within preset bands, v4-3) ---- */

/* Record one origin-regeneration cost sample (request_time in ms) into the zone's
 * running cost accumulator. Called on the origin→cache store path only (never the
 * cheap L2→L1 fill), so the average reflects real origin latency. Lock-free
 * (two atomic adds); ms < 0 is clamped to 0. */
void ngx_http_cache_turbo_autotune_record_cost(ngx_http_cache_turbo_zone_t *z,
    ngx_msec_int_t ms);

/* Throttled per-zone recompute. At most once per `interval` seconds per worker
 * (guarded by z->sh->autotune_next): reads the L1 stats delta since the last
 * tick, derives a target beta from the average miss-cost, applies the qualify /
 * churn gates, and publishes the global-clamped verdict to z->sh->autotuned_beta
 * (0 when the zone doesn't qualify or there is too little data). The request path
 * re-clamps that verdict to the location's preset band. Cheap to call every
 * request — the heavy path runs at most once per interval. */
void ngx_http_cache_turbo_autotune_maybe(ngx_http_cache_turbo_zone_t *z,
    time_t interval);

/* Force an immediate recompute over the window since the last snapshot, ignoring
 * the interval throttle (does not disturb the throttle schedule). Backs the admin
 * "recompute now" command (`?autotune=1`) — an operator escape hatch, and what
 * makes the autotune tests deterministic without waiting on the interval. */
void ngx_http_cache_turbo_autotune_force(ngx_http_cache_turbo_zone_t *z);


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

/* Build the cross-node lock key "<prefix>lock:<64 hex of key hash>" into buf
 * (must hold prefix.len + sizeof("lock:")-1 + 64). Returns bytes written. */
size_t ngx_http_cache_turbo_redis_lockkey(ngx_str_t *prefix, u_char *key_hash,
    u_char *buf);

/* Cross-node single-flight (v4-2): async SET <lockkey> <owner> NX PX <ttl*1000>.
 * Parks the request (count++, NGX_AGAIN) until the reply lands, then sets
 * ctx->lock_done + ctx->lock_result (NGX_OK = acquired) and resumes the phase
 * engine. Returns NGX_AGAIN (parked) or NGX_DECLINED (L2 off / could not start;
 * caller proceeds as single-box). */
ngx_int_t ngx_http_cache_turbo_redis_lock(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    time_t ttl);

/* Clear the whole L2 keyspace for this prefix (v4-2): parked SCAN MATCH
 * <prefix>* cursor loop, DEL each match, then cb(r, data, NULL, 0) emits the
 * response. Returns NGX_DONE (parked) or NGX_ERROR (L2 off / could not start). */
ngx_int_t ngx_http_cache_turbo_redis_scan_del(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_http_cache_turbo_redis_members_pt cb, void *data);


/* ---- backend vtables (v4-1, #6) ---- */

/*
 * L1 local-store backend. Synchronous in-process tier. `lookup` returns the live
 * node so the caller (holding the zone mutex) can read its fields and run the SWR
 * dice itself — that is why the stale/serve-stale control flow stays in the
 * access handler rather than being hidden inside a fused get(). Today's only
 * driver is shm; a future disk/mmap local tier would slot in behind this struct.
 */
struct ngx_cache_turbo_l1_backend_s {
    ngx_str_t   name;

    ngx_http_cache_turbo_node_t *(*lookup)(ngx_http_cache_turbo_zone_t *z,
        u_char *key_hash, uint32_t hash);
    ngx_int_t  (*store)(ngx_http_cache_turbo_zone_t *z, u_char *key_hash,
        uint32_t hash, u_char *data, size_t len, ngx_uint_t status,
        time_t fresh_ttl, ngx_int_t stale_mult);
    ngx_int_t  (*purge_key)(ngx_http_cache_turbo_zone_t *z, u_char *key_hash,
        uint32_t hash);
    ngx_uint_t (*purge_all)(ngx_http_cache_turbo_zone_t *z);
    void       (*stats)(ngx_http_cache_turbo_zone_t *z,
        ngx_http_cache_turbo_stats_t *out);

    /* Cold-miss single-flight claim (v10). Atomically (under the zone mutex)
     * decide whether this request regenerates the key or waits for someone else.
     * Returns CLAIM_WINNER (took/created the in-flight stub — go to origin),
     * CLAIM_LOSER (someone else is in flight — wait), or CLAIM_FRESH (a real
     * fresh entry raced in — re-serve via lookup). lock_ttl bounds the stub. */
    ngx_int_t  (*claim)(ngx_http_cache_turbo_zone_t *z, u_char *key_hash,
        uint32_t hash, time_t lock_ttl);

    /* min_uses miss counter (v15). Atomically (under the zone mutex) count one
     * cold miss for the key and decide whether it has now been requested enough
     * times to be worth caching. Returns NGX_OK (>= min_uses — proceed to the
     * cold-miss/store path) or NGX_DECLINED (still below — go to origin, do not
     * store). A node holding a real body (len > 0) or an in-flight stub returns
     * NGX_OK without counting (a refresh of an already-cached key is never
     * re-gated). Only called when min_uses > 1. */
    ngx_int_t  (*count_miss)(ngx_http_cache_turbo_zone_t *z, u_char *key_hash,
        uint32_t hash, ngx_int_t min_uses);
};

#define NGX_HTTP_CACHE_TURBO_CLAIM_WINNER  0
#define NGX_HTTP_CACHE_TURBO_CLAIM_LOSER   1
#define NGX_HTTP_CACHE_TURBO_CLAIM_FRESH   2

/* Cold-miss wait-loop poll interval (ms): a loser re-checks L1/L2 this often
 * until the winner fills the entry or cache_turbo_lock_timeout elapses (v10). */
#define NGX_HTTP_CACHE_TURBO_LOCK_POLL_MS  100

extern ngx_cache_turbo_l1_backend_t  ngx_http_cache_turbo_shm_backend;


/*
 * L2 remote-driver backend. Asynchronous — `get` and `purge_tag` park the
 * request (count++, NGX_AGAIN) and resume it when the reply lands. redis is the
 * only driver today; memcached / disk slot in behind the same struct later. A
 * driver that cannot perform an op leaves that member NULL (e.g. memcached has
 * no atomic tag set, so its `purge_tag`/`tag_add` would be NULL). `lock`/
 * `unlock` are the v4-2 multi-node single-flight slots (SET NX PX); NULL until
 * then so v4-2 only fills the functions, never re-touches this struct.
 */
struct ngx_cache_turbo_backend_s {
    ngx_str_t   name;

    ngx_int_t  (*get)(ngx_http_request_t *r,
        ngx_http_cache_turbo_loc_conf_t *clcf,
        ngx_http_cache_turbo_ctx_t *ctx);
    void       (*set)(ngx_http_request_t *r,
        ngx_http_cache_turbo_loc_conf_t *clcf, u_char *key_hash,
        u_char *blob, size_t blob_len, time_t fresh_ttl);
    void       (*del)(ngx_http_cache_turbo_loc_conf_t *clcf, u_char *key_hash);
    void       (*del_raw)(ngx_http_cache_turbo_loc_conf_t *clcf, u_char *key,
        size_t key_len);
    size_t     (*tagkey)(ngx_str_t *prefix, u_char *name, size_t name_len,
        u_char *buf);
    void       (*tag_add)(ngx_http_cache_turbo_loc_conf_t *clcf,
        u_char *key_hash, u_char *name, size_t name_len, time_t ttl);
    ngx_int_t  (*purge_tag)(ngx_http_request_t *r,
        ngx_http_cache_turbo_loc_conf_t *clcf, u_char *name, size_t name_len,
        ngx_http_cache_turbo_redis_members_pt cb, void *data);

    /* Purge the whole L2 keyspace (v4-2): SCAN MATCH <prefix>* + DEL each, then
     * invoke cb(r, data, NULL, 0) to emit the response. Parks the request. */
    ngx_int_t  (*scan_del)(ngx_http_request_t *r,
        ngx_http_cache_turbo_loc_conf_t *clcf,
        ngx_http_cache_turbo_redis_members_pt cb, void *data);

    /* Cross-node dogpile (v4-2): async SET <prefix>lock:<hex> <owner> NX PX
     * <ttl*1000>. Parks the request (count++, NGX_AGAIN); on reply ctx->lock_*
     * is set (NGX_OK = acquired). NGX_DECLINED synchronously if it could not
     * start (L2 down) — caller falls back to single-box regen. `unlock` stays
     * NULL: the lock is released by PX expiry, never by owner (see history.md
     * v4-2 — early unlock would re-open the single-flight window). */
    ngx_int_t  (*lock)(ngx_http_request_t *r,
        ngx_http_cache_turbo_loc_conf_t *clcf,
        ngx_http_cache_turbo_ctx_t *ctx, time_t ttl);
    ngx_int_t  (*unlock)(ngx_http_cache_turbo_loc_conf_t *clcf, u_char *key_hash,
        ngx_str_t *owner);
};

extern ngx_cache_turbo_backend_t  ngx_http_cache_turbo_redis_backend;


#endif /* NGX_HTTP_CACHE_TURBO_MODULE_H_INCLUDED_ */
