/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
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

/* "Forever" fresh TTL. `cache_turbo_valid 0` ("cache forever", per the code's
 * long-standing contract) resolves to this long-but-finite TTL rather than a
 * literal 0 — a literal 0 made the object instantly+permanently STALE and
 * skipped L2 (the L2 blob's stale_ttl was 0 => every L2 hit read as expired).
 * 10 years keeps all the freshness arithmetic (fresh_until, stale window, L2
 * EXPIRE, blob created+age) on the normal path while behaving as "never
 * expires". Bounded so FOREVER * max-preset-stale_mult (8) still fits the uint32
 * blob stale_ttl field (2.5e9 < 4.29e9). */
#define NGX_HTTP_CACHE_TURBO_FOREVER_TTL  ((time_t) 315360000)   /* 10 years */

/* Hard ceiling for any fresh/stale TTL that reaches the wire (STAB-5). The blob
 * fresh_ttl/stale_ttl are uint32 and the redis PX is `<ttl> * 1000`; an
 * unbounded honor_cc max-age or `cache_turbo_valid <huge>` could overflow the
 * uint32 cast or the *1000. Clamp every TTL to UINT32_MAX seconds (~136 yr,
 * itself well past FOREVER): the cast is lossless and `<= 4.29e9 * 1000` (4.29e12)
 * stays inside int64 %T. ngx_http_cache_turbo_stale_ttl clamps its product here;
 * the store path clamps the fresh TTL before the uint32 cast. */
#define NGX_HTTP_CACHE_TURBO_TTL_MAX  ((time_t) 0xFFFFFFFF)

/* Upper bound on cache_turbo_redis keepalive=N (STAB-5). The per-worker pool is
 * `ngx_palloc(N * sizeof(item))`; an unbounded N overflows the size_t multiply
 * into a short allocation that the init loop then writes N items past. 65535
 * idle L2 conns/worker is already absurd; reject anything larger at parse. */
#define NGX_HTTP_CACHE_TURBO_KEEPALIVE_MAX  65535

/* PERF-2: bounds on the upstream-controlled cache_turbo_tag value, so one
 * response cannot fan out into an unbounded number of SADD connections. At most
 * MAX_TAGS distinct tags are indexed per store; a token longer than MAX_TAG_LEN
 * is ignored (a real tag name is short). */
#define NGX_HTTP_CACHE_TURBO_MAX_TAGS     16
#define NGX_HTTP_CACHE_TURBO_MAX_TAG_LEN  128

/* Default SWR aggressiveness (beta). 1.0 = refresh probability tracks the
 * elapsed fraction of the stale window directly. */
#define NGX_HTTP_CACHE_TURBO_DEFAULT_BETA      1000   /* fixed-point /1000 */


/*
 * Autotune presets (#10, v3-2). One directive `cache_turbo_preset
 * micro|conservative|balanced|aggressive` sets the default tuning bundle; an
 * explicit knob directive still wins. Vocab matches wp-redis (BALANCED, not
 * "normal"). Values are 1-based so they index ngx_http_cache_turbo_bands[]
 * directly; 0 is unused so a zeroed/UNSET field is never a valid preset.
 */
#define NGX_HTTP_CACHE_TURBO_PRESET_CONSERVATIVE  1
#define NGX_HTTP_CACHE_TURBO_PRESET_BALANCED      2
#define NGX_HTTP_CACHE_TURBO_PRESET_AGGRESSIVE    3
#define NGX_HTTP_CACHE_TURBO_PRESET_MICRO         4

/* Default-of-defaults: an unconfigured location resolves to BALANCED, whose band
 * values equal the historical hardcoded merge fallbacks (valid 60s, beta 1000,
 * lock_ttl 5s, stale_mult 4). */
#define NGX_HTTP_CACHE_TURBO_PRESET_DEFAULT  NGX_HTTP_CACHE_TURBO_PRESET_BALANCED


/*
 * Auto-classify CMS backend presets (distinct from the stale-window PRESET_*
 * above). A bitmask in loc_conf->backend_presets; each bit pulls in one row of
 * the preset registry (cookie/URI/arg dynamic-surface rules).
 *
 * EVERY preset is opt-in — you name the backends you actually run. There is no
 * `generic` / `auto` union, and deliberately so. It used to mean
 * WORDPRESS|WOOCOMMERCE|JOOMLA, and it was never a safe default:
 *
 *   - it never covered every backend, so `auto` on a Drupal or XenForo site
 *     silently enabled no rules for it at all;
 *   - WOOCOMMERCE inside it leaves /wp-admin/ cacheable unless stacked with
 *     WORDPRESS — a union whose members you must know how to combine is not a
 *     default;
 *   - JOOMLA inside it ships no cookie rule, so `auto` on a Joomla site LOOKED
 *     like it protected logged-in users and did not.
 *
 * Both spellings are now rejected at config parse (see cache_turbo_backend).
 *
 * The other reason no union is safe: most of these presets have generic-English
 * dynamic URIs — /login, /register, /contact, /misc (xenforo), /login, /signup,
 * /posts (discourse), /user, /admin, /node (drupal), /index.php (mediawiki) —
 * which an unrelated site may legitimately serve as perfectly cacheable pages.
 * Enabling one you do not run punches holes in your own cache.
 */
#define NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS    0x0001
#define NGX_HTTP_CACHE_TURBO_BACKEND_WOOCOMMERCE  0x0002
#define NGX_HTTP_CACHE_TURBO_BACKEND_JOOMLA       0x0004
#define NGX_HTTP_CACHE_TURBO_BACKEND_XENFORO      0x0008
#define NGX_HTTP_CACHE_TURBO_BACKEND_DISCOURSE    0x0010
#define NGX_HTTP_CACHE_TURBO_BACKEND_PHPBB        0x0020
#define NGX_HTTP_CACHE_TURBO_BACKEND_DRUPAL       0x0040
#define NGX_HTTP_CACHE_TURBO_BACKEND_MEDIAWIKI    0x0080
#define NGX_HTTP_CACHE_TURBO_BACKEND_MAGENTO      0x0100
#define NGX_HTTP_CACHE_TURBO_BACKEND_GHOST        0x0200
#define NGX_HTTP_CACHE_TURBO_BACKEND_WAGTAIL      0x0400
#define NGX_HTTP_CACHE_TURBO_BACKEND_KIRBY        0x0800
#define NGX_HTTP_CACHE_TURBO_BACKEND_SHOPWARE6    0x1000
#define NGX_HTTP_CACHE_TURBO_BACKEND_TYPO3        0x2000
#define NGX_HTTP_CACHE_TURBO_BACKEND_INVISION     0x4000
#define NGX_HTTP_CACHE_TURBO_BACKEND_SMF          0x8000
#define NGX_HTTP_CACHE_TURBO_BACKEND_VANILLA      0x10000
#define NGX_HTTP_CACHE_TURBO_BACKEND_PUNBB        0x20000
#define NGX_HTTP_CACHE_TURBO_BACKEND_PHORUM       0x40000
#define NGX_HTTP_CACHE_TURBO_BACKEND_YABB         0x80000
#define NGX_HTTP_CACHE_TURBO_BACKEND_MYBB         0x100000
#define NGX_HTTP_CACHE_TURBO_BACKEND_VBULLETIN    0x200000
/* NOTE: BACKEND_NONE below was moved from 0x8000 to 0x400000 to make room for
 * the bits above (SMF used to collide with it) — see BACKEND_NONE comment. */

/*
 * "cache_turbo_backend none;" — explicitly NO preset here.
 *
 * This is a sentinel, not a registry row: it matches no backend and pulls in no
 * cookie/URI/arg rules. It exists because backend_presets uses 0 to mean "this
 * location named no backend", which the loc-conf merge treats as "inherit the
 * parent's". So a server-level `cache_turbo_backend wordpress;` is inherited by
 * every location under it, and before `none` there was no way to switch that off
 * for one location — leaving the mask at 0 is indistinguishable from silence.
 *
 * NONE occupies a bit so that backend_presets != 0 and inheritance is defeated,
 * while matching nothing in the registry (whose rows all have a real backend
 * bit). It is deliberately OUTSIDE the contiguous preset run so BACKEND_ALL —
 * and the fuzzer's gapless-bits assert — is unaffected.
 *
 * It also does NOT imply cache_turbo_cache_control honor, unlike a real preset:
 * asking for no CMS classification should not quietly change how the response's
 * Cache-Control is treated.
 */
#define NGX_HTTP_CACHE_TURBO_BACKEND_NONE         0x400000

/* True when a REAL preset is active — i.e. at least one registry row is armed.
 * Use this, never a bare `backend_presets != 0`: the NONE sentinel is non-zero
 * (deliberately, to defeat loc-conf inheritance) but must not count as a preset,
 * or it would imply cache_control honor and enter the auto-classify walk. */
#define NGX_HTTP_CACHE_TURBO_HAS_BACKEND(m)                                    \
    (((m) & ~NGX_HTTP_CACHE_TURBO_BACKEND_NONE) != 0)

/* cache_turbo_cache_control modes (loc_conf.cc_mode). */
#define NGX_HTTP_CACHE_TURBO_CC_RESPECT  0
#define NGX_HTTP_CACHE_TURBO_CC_HONOR    1
#define NGX_HTTP_CACHE_TURBO_CC_IGNORE   2

/* Per-request serve outcome (ctx.status), surfaced by $cache_turbo_status.
 * Tokens mirror nginx $upstream_cache_status (HIT/MISS/EXPIRED/STALE/BYPASS).
 * MISS is 0 so a pcalloc'd ctx defaults to it; the serve/bypass/expired paths
 * override. EXPIRED = a cached entry was found past its serveable window and
 * refetched (NOT a cold miss, NOT only-if-cached-504 which stays MISS).
 * Keep ngx_http_cache_turbo_status_str() in the .c in sync with these. */
#define NGX_HTTP_CACHE_TURBO_ST_MISS     0
#define NGX_HTTP_CACHE_TURBO_ST_HIT      1
#define NGX_HTTP_CACHE_TURBO_ST_STALE    2
#define NGX_HTTP_CACHE_TURBO_ST_BYPASS   3
#define NGX_HTTP_CACHE_TURBO_ST_EXPIRED  4


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

/* Load-adaptive autotune (v4-4). Folded into cache_turbo_autotune on: when the
 * same cost/hit-rate verdict that drives beta says the backend is under load,
 * the zone also publishes a LOAD FACTOR (×1000, 1000 = baseline). The request
 * path widens two knobs by it — the serveable STALE window (not the fresh
 * window: the freshness contract is unchanged) and the single-flight lock_ttl —
 * so a slow/overwhelmed origin is shielded by serving stale longer and
 * collapsing more requests onto one regen. Snaps back to 1000 the first window
 * load clears. The factor is mapped from avg regen cost: AT_LOAD_PER_MS per ms
 * (so 1× at AT_COST_MOD_MS, the same moderate-load gate beta uses) and capped at
 * AT_LOAD_MAX (= a hard ≤4× ceiling on both widenings). */
#define NGX_HTTP_CACHE_TURBO_AT_LOAD_BASE      1000   /* 1.0 ×1000 (no widening)  */
#define NGX_HTTP_CACHE_TURBO_AT_LOAD_MAX       4000   /* 4.0 ×1000 (widening cap) */
#define NGX_HTTP_CACHE_TURBO_AT_LOAD_PER_MS    100    /* load = cost_ms × 100     */

/* Fixed autotune recompute cadence (seconds) when cache_turbo_autotune is on. */
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


/* PERF-7: reference header prefixed to every slab-allocated response body so a
 * cache HIT can serve the blob DIRECTLY out of shm (zero-copy) instead of
 * memcpy'ing it into r->pool under the zone mutex. `data` (below) points at the
 * blob bytes that follow this header; the header is recovered with CT_BLOBREF().
 *
 * Lifetime: while a request serves a blob its output buffer points into the
 * slab, so the buffer must outlive eviction/refresh by another worker. `refs`
 * counts the in-flight zero-copy servers; `detached` is set when the owning node
 * has dropped this buffer (evict / refresh / purge). The slab is freed only when
 * refs == 0 AND detached — i.e. by whichever side is last (the evicting worker if
 * no serve is in flight, otherwise the last server's request-pool cleanup).
 * ALL fields are mutated only under shpool->mutex, so plain ints suffice (the
 * mutex is the barrier); no atomics. */
typedef struct {
    ngx_uint_t               refs;       /* in-flight zero-copy servers      */
    ngx_uint_t               detached;   /* owning node dropped this buffer  */
} ngx_http_cache_turbo_blobref_t;

#define CT_BLOBREF(data)                                                       \
    ((ngx_http_cache_turbo_blobref_t *)                                        \
        ((u_char *) (data) - sizeof(ngx_http_cache_turbo_blobref_t)))


/*
 * One cached object living in the shared-memory slab. The node key is the
 * 32-byte hash of the cache key; the variable-length body (headers + payload,
 * serialised) is slab-allocated separately and pointed to by data/len.
 */
typedef struct {
    ngx_rbtree_node_t        node;       /* node.key = crc32 of cache key  */
    u_char                   key[32];    /* full key hash, collision guard */

    u_char                  *data;       /* blob bytes; CT_BLOBREF() header
                                          * sits immediately before, slab alloc */
    size_t                   len;

    time_t                   fresh_until;   /* < now  => stale              */
    time_t                   stale_until;   /* < now  => expired/evict      */

    ngx_uint_t               refreshing;    /* a single-flight regen in air */
    time_t                   refresh_lock_until; /* hard single-flight guard:
                                              * while now < this, ALL readers
                                              * serve stale and skip the dice;
                                              * only the claimer regenerates.
                                              * Self-heals if a refresh dies. */

    /* min_uses (v15) miss counter. A "counter node" (data == NULL / len == 0,
     * refreshing == 0) tracks how many times a key has cold-missed without yet
     * being cached, so cache_turbo_min_uses N can defer the first store until the
     * key has been requested N times (don't cache one-hit-wonders). Distinct from
     * a v10 single-flight STUB, which is also len == 0 but has refreshing == 1.
     * Irrelevant once the node holds a real body (len > 0); left untouched then. */
    ngx_uint_t               miss_count;

    /* PERF (P1): coarse last-access stamp (1s granularity, ngx_time). The true-LRU
     * head-splice on every HIT is a WRITE to the shared LRU list under
     * shpool->mutex — on a hot key that serializes all readers on the same cache
     * lines. We re-splice only when now - last_access >= 1, so a key hammered many
     * times per second splices at most once/second. Eviction is best-effort/
     * approximate anyway (shm.c), so an LRU that is at most ~1s stale is harmless.
     * 0 = never spliced (fresh node); the first HIT always splices. */
    time_t                   last_access;

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

    /* Requests sent to origin because a cache_turbo_bypass predicate tripped or
     * a CMS backend preset auto-classified them as dynamic. Also counted in
     * misses (they reached origin); bypasses isolates the "skipped on purpose"
     * subset for $cache_turbo_status / Prometheus. */
    ngx_atomic_t             bypasses;

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
    ngx_atomic_t             autotuned_load;/* v4-4 load factor ×1000, 0/1000   *
                                             * = baseline (no stale/lock widen) */
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
    ngx_atomic_uint_t   bypasses;     /* bypass / auto-classify skips to origin */
    /* Autotune introspection (v4-3): cost_ms = the measured average origin-regen
     * cost (cost_sum_ms / cost_count, 0 when nothing measured); autotuned_beta =
     * the live verdict ×1000 (0 = none). Rendered by the admin GET so a test (or
     * an operator) can see the live tuning without an internal probe. */
    ngx_atomic_uint_t   cost_ms;
    ngx_atomic_uint_t   autotuned_beta;
    ngx_atomic_uint_t   autotuned_load;   /* v4-4 load factor ×1000 (1000 = none) */
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

    /* Manual DIY equivalents of the preset URI-bypass and key-cookie engines
     * (v15), for an app we ship no preset for.
     *
     * bypass_uri: array of ngx_str_t URI prefixes. A request whose r->uri
     * matches any prefix on a path-segment boundary ('/' or '.') skips the
     * cache entirely — the same origin-and-never-capture semantics as a preset
     * URI rule (ngx_http_cache_turbo_auto_skip), evaluated by the SAME
     * ngx_http_cache_turbo_uri_prefix() matcher, but WITHOUT needing a preset.
     * This is what nginx `location` prefixes cannot express: they anchor at
     * position 0 and have no segment-boundary semantics, so mounting the app in
     * a subdirectory silently mis-matches.
     *
     * key_cookies: array of ngx_str_t cookie names whose VALUE is folded into
     * the cache key (tier-3 value-keying) via the same unforgeable
     * length-prefixed framing the presets use in build_key. EXACT name match,
     * ALL Cookie headers scanned. KEY, never bypass, never presence — see the
     * key_cookies field on ngx_http_cache_turbo_preset_t and the fold in
     * ngx_http_cache_turbo_build_key for the full rationale (a value-key is for
     * a SEGMENT FINGERPRINT the app shares across many visitors, not an
     * identity; presence-keying leaks). Both NGX_CONF_UNSET_PTR until set. */
    ngx_array_t             *bypass_uri;
    ngx_array_t             *key_cookies;

    /* Auto-classify (cache_turbo <zone> auto / cache_turbo_backend <name>...).
     * A bitmask of CMS cacheability presets; 0 = manual mode (off). Each set
     * bit applies a curated set of "this request is dynamic, never cache it"
     * heuristics (login/session cookie prefixes, backend URI prefixes, dynamic
     * query args) evaluated in the access handler. `auto` and `backend generic`
     * set the union of all presets; naming specific backends composes only
     * those. Sits UNDER manual bypass/no_store overrides. See the preset
     * registry and ngx_http_cache_turbo_auto_skip() in the .c. */
    ngx_uint_t               backend_presets;

    /* Live autotune (v4-3). When on, the request path uses the zone's live
     * autotuned beta (clamped to this location's preset band) in place of the
     * static effective beta above; the per-zone recompute is throttled to a
     * fixed NGX_HTTP_CACHE_TURBO_AT_INTERVAL (30s) cadence. Off by default —
     * beta then resolves purely from preset as before. The clamp band is
     * ngx_http_cache_turbo_bands[preset]. */
    ngx_flag_t               autotune;       /* cache_turbo_autotune on|off    */

    /* Response Cache-Control handling, set by `cache_turbo_cache_control
     * respect|honor|ignore`. cc_mode is the raw tri-state (UNSET until set, so
     * a CMS preset can default it to "honor"); honor_cc/ignore_cc are derived
     * from it at merge and are what the request path reads — the runtime logic
     * is unchanged from when these were two separate directives.
     *
     *   respect (default): the response Cache-Control gates storage + reshapes
     *     the stale window as written; the fresh TTL comes from cache_turbo_valid.
     *   honor: also take the fresh TTL from the response's own s-maxage / max-age
     *     (s-maxage wins) or Expires; fall back to cache_turbo_valid when absent.
     *   ignore: discard the response Cache-Control entirely (mirrors nginx
     *     `proxy_ignore_headers Cache-Control`) — no-store / no-cache / private /
     *     max-age=0 / s-maxage=0 no longer forbid storage, must-revalidate / swr /
     *     sie no longer reshape the window, and the TTL is cache_turbo_valid.
     *     The Set-Cookie and request-Authorization safety floors are NOT affected
     *     (a per-user response is still never cached). */
    ngx_uint_t               cc_mode;     /* CT_CC_* ; UNSET until configured */
    ngx_flag_t               honor_cc;    /* derived: cc_mode == CT_CC_HONOR  */
    ngx_flag_t               ignore_cc;   /* derived: cc_mode == CT_CC_IGNORE */
    size_t                   max_size;    /* max single response to cache   */

    /* Suppress native cache when stacked (Q1). When on, the $cache_turbo_active
     * variable reads "1" for a request cache-turbo is handling (enabled,
     * cacheable method, not bypassed/no_store), else "0". The operator wires
     * `proxy_no_cache $cache_turbo_active; proxy_cache_bypass $cache_turbo_active;`
     * so a stacked native proxy_cache/fastcgi_cache defers to us instead of
     * double-caching. Off by default => the variable is always "0", so the
     * wiring can stay in place permanently and be toggled by this one knob. */
    ngx_flag_t               suppress_native;
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

    /* L2 memcached (v13). A second, simpler L2 backend selected by
     * cache_turbo_memcached HOST:PORT (mutually exclusive with cache_turbo_redis
     * — both reuse redis_addr/redis_prefix/redis_timeout/redis_enable; the flag
     * below picks the vtable). Text protocol, plain TCP, get/set/del/del_raw
     * only: tag/scan/lock vtable slots stay NULL (no SADD/SCAN/atomic-lock), so
     * tag-purge / purge?all / cross-node single-flight are unavailable on it.
     * 1 MB value cap (memcached's default item ceiling): oversized SET skipped. */
    ngx_flag_t               memcached;    /* cache_turbo_memcached configured  */

    /* Keepalive pool (v15; per-profile buckets v16). cache_turbo_redis
     * keepalive=N caches up to N idle L2 connections per worker, so an L2 op
     * reuses a live connection instead of connect()+close per op. 0 = off
     * (default). keepalive_timeout= closes an idle pooled connection after this
     * long. Each distinct connection profile (peer addr + db + credentials + TLS
     * context) gets its OWN bucket with its OWN N and timeout, taken from the
     * location that opens it — so per-location values are honoured and profiles
     * cannot starve each other (see ka_bucket() in the redis driver). TLS conns
     * are pooled too (v15-2): the persistent channel is reused, handshake +
     * preamble skipped on reuse. */
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

    /* Explicit upstream store opt-in (cache_turbo_require_header <name>).
     * When set, a response is captured ONLY if it carries <name> with an
     * affirmative value ("yes"/"1"/"on", case-insensitive). Everything else --
     * header absent, "no", empty, unparseable -- refuses the store.
     *
     * This inverts the module's usual "cacheable unless something vetoes it"
     * default into "uncacheable unless the origin says otherwise", for origins
     * where only the application can decide: a GraphQL endpoint answers a query
     * and a mutation on the same URI+method, and returns errors as HTTP 200
     * with an `errors` member in the body. No amount of HTTP-level inspection
     * separates those, and the module deliberately does not parse the body
     * (it stays an opaque blob), so the decision has to come from upstream.
     *
     * Fails CLOSED by construction: any doubt = no store = a cache miss, never
     * a wrong serve. The name is stripped before store (like Age / the RFC 9213
     * targeted directives) -- this cache is its intended consumer, and a HIT
     * must not replay it downstream. len == 0 = unset (default). */
    ngx_str_t                require_header;

    /* Key normalize (v3-1). The $cache_turbo_normalized_args variable rebuilds
     * r->args dropping tracking params and sorting the rest, so requests that
     * differ only in arg order or carry junk (utm_*, fbclid, ...) hash to one
     * cache slot. Orthogonal to keying: the user composes the key from the
     * variable, e.g. cache_turbo_key $uri$cache_turbo_normalized_args. */
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

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    /* CI-only fault injection; production/package builds do not define the
     * feature macro and therefore expose neither this field nor its directive. */
    ngx_flag_t               test_restore_alloc_fail;
    /* Force the body filter onto the file-backed delegate path even when the
     * incoming buffers are in memory, so the sendfile-abort branch (which is
     * fs/directio-alignment dependent and non-deterministic in the harness) is
     * exercised deterministically. Delegates the UNMODIFIED in-memory chain
     * downstream and abandons capture; it does NOT forge b->in_file. */
    ngx_flag_t               test_force_file_buf;
#endif


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
    unsigned                 ct_active:1; /* Q1: cache-turbo engaged for this
                                           * request (enabled, cacheable method,
                                           * not bypassed/no_store) -> the
                                           * $cache_turbo_active var reads 1     */
    unsigned                 auto_skip:1; /* auto-classify ruled this request
                                           * dynamic -> origin, never capture    */
    unsigned                 captured:1;  /* response captured for store    */
    unsigned                 served:1;    /* we served from cache           */
    unsigned                 stale_hit:1; /* served stale (for X-Cache)      */
    unsigned                 warm:1;      /* warm subrequest: force a miss,  */
                                          /* capture + store though !r->main */
    unsigned                 l2_done:1;   /* L2 GET finished (hit or miss)   */
    ngx_int_t                l2_result;   /* NGX_OK = L2 hit; else miss      */
    u_char                  *l2_blob;     /* L2-hit blob, copied to r->pool  */
    size_t                   l2_blob_len;
    unsigned                 l2_miss_counted:1;/* l2_misses stat already bumped*/
    /* Cross-node dogpile (v4-2). On a stale L1 dice win the request parks for a
     * Redis SET NX PX reply: lock_result == NGX_OK means this node holds the
     * cluster-wide regen lock (go to origin); anything else means another node
     * owns it (serve stale, skip origin). Mirrors the l2_* park/resume trio.
     * lock_result == NGX_ERROR is a THIRD outcome (v16): the L2 lock channel
     * itself failed (timeout / connect error / EOF), distinct from a genuine
     * peer-holds-lock decline — the caller degrades to per-box single-flight
     * (regenerate locally) instead of suppressing the refresh, so a Redis
     * outage cannot freeze every node on serve-stale / cold-wait. */
    unsigned                 lock_done:1; /* NX reply landed                 */
    ngx_int_t                lock_result; /* NGX_OK=hold; NGX_ERROR=L2 down   */
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
    ngx_chain_t             *body_last;   /* tail of body, O(1) append      */
    size_t                   body_len;
    ngx_str_t                cache_key;
    u_char                   key_hash[32];
    /* auto-Vary (v11 other half). vary_bits = the safe-axis bitmask classified
     * from the response Vary header in the header filter (>0 => store under a
     * variant key + write/refresh the marker; the body filter reads it). When a
     * request resolves to a variant via an L1 vary marker, key_hash already holds
     * the variant key. vary_nocache = the response carried a Vary the whitelist
     * refuses (*, Cookie, Authorization) => do not capture/store. */
    unsigned                 vary_nocache:1;
    ngx_int_t                vary_bits;
    /* auto-Vary PURGE generation (COR-5). Resolved from the L1 marker by
     * vary_resolve and reused at store so the variant key + marker agree. Stays
     * 0 for the backend-backed purge path (variants are physically removed +
     * the marker deleted, so the keyspace resets cleanly to gen 0); only the
     * L1-only / memcached purge path bumps it (no enumerable L2 index, so an
     * old generation's variants are orphaned and age out while new requests
     * key on gen+1). variant_hash folds it ONLY when >0, so gen 0 keeps the
     * pre-COR-5 variant keys (no keyspace turnover on upgrade). */
    ngx_uint_t               vary_gen;
    /* min_uses (v15). min_uses_skip = this request is below the threshold, so the
     * header filter must NOT capture it (no store) and it runs to the origin.
     * min_uses_passed = the gate already counted this request and let it through
     * (it reached the threshold); it guards against re-counting on a park/resume
     * re-entry of the access handler (L2/NX-lock/cold-wait wake). */
    unsigned                 min_uses_skip:1;
    unsigned                 min_uses_passed:1;
    /* RFC-1 request Cache-Control (parsed once in the prologue). only_if_cached
     * (RFC 9111 §5.2.1.7): the client refuses origin contact, so a request that
     * cannot be served from L1/L2 returns 504 instead of going to the origin.
     * no_store (§5.2.1.5): do not store this request's response (the header
     * filter skips capture). Request no-cache / max-age=0 are folded into
     * ngx_http_cache_turbo_request_revalidate() and handled inline. */
    unsigned                 req_only_if_cached:1;
    unsigned                 req_no_store:1;
    /* P4: request Cache-Control + Pragma header values, resolved ONCE by
     * ngx_http_cache_turbo_resolve_req_cc() with a single walk of the request
     * header list, then read by each RFC-1 predicate (revalidate / only-if-cached
     * / no-store / freshness-bounds) instead of each re-walking the whole list
     * (the old path did that 5x per hit). data == NULL means the header is absent.
     * req_cc_resolved guards against double-resolve. nginx does NOT pre-parse a
     * request Cache-Control field (unlike cookies), so this fold is the win. */
    ngx_str_t                req_cc;
    ngx_str_t                req_pragma;
    unsigned                 req_cc_resolved:1;
    /* RFC-1 request freshness bounds (parsed once in the prologue). max_age /
     * min_fresh = -1 when absent (§5.2.1.1/§5.2.1.3). max_stale: max_stale_set
     * marks presence, max_stale_any a bare "max-stale" (accept any staleness),
     * else req_max_stale carries the value (§5.2.1.2). req_reval is set when an
     * existing entry failed the client's bounds (or no-cache/max-age=0), so the
     * cold-miss CLAIM_FRESH path must NOT re-serve the raced-in fresh entry. */
    time_t                   req_max_age;
    time_t                   req_min_fresh;
    time_t                   req_max_stale;
    unsigned                 req_max_stale_set:1;
    unsigned                 req_max_stale_any:1;
    unsigned                 req_reval:1;
    /* PERF (P2): set iff the client sent ANY of max-age/min-fresh/max-stale, i.e.
     * the freshness bounds can actually change the serve verdict. When unset the
     * per-hit req_serve_verdict/bounds block on the lookup fast path is dead work
     * (all three bounds are -1/absent => fresh serves, stale serves) and is
     * skipped. only-if-cached is NOT folded here: it is handled at :2998/:3511. */
    unsigned                 has_req_bounds:1;
    /* RFC 5861 §4 / RFC-2 stale-if-error serve-on-error (CTB4). On a lookup that
     * finds the entry EXPIRED (past its stale window) but still inside the blob's
     * serve-on-error window (created + sie_ttl), we DECLINE to origin yet stash a
     * snapshot of the stale blob here (sie_snap, r->pool). If the origin
     * revalidation then returns 5xx, the header+body filters REPLACE the error
     * response with this snapshot (X-Cache: STALE-IF-ERROR) instead of surfacing
     * the failure. No node field is needed: eviction is pure-LRU (no TTL reaper),
     * so the expired node survives on its own; arming at access time is enough. */
    unsigned                 sie_armed:1;     /* a within-SIE snapshot is stashed */
    unsigned                 sie_serving:1;   /* filters replacing error w/ snap  */
    unsigned                 sie_body_sent:1; /* snapshot last_buf already emitted */
    u_char                  *sie_snap;        /* stale blob copy (r->pool)         */
    size_t                   sie_snap_len;
    u_char                  *sie_body;        /* body slice inside sie_snap        */
    size_t                   sie_body_len;
    /* Per-request serve outcome for $cache_turbo_status / access logging. One of
     * NGX_HTTP_CACHE_TURBO_ST_*; defaults to ST_MISS (0) via pcalloc and is
     * overridden to HIT/STALE at the X-Cache emit site, BYPASS on the
     * auto-classify / cache_turbo_bypass paths, EXPIRED when a cached entry is
     * found past its serveable window (L1 or L2) and refetched from origin. */
    ngx_uint_t               status;
} ngx_http_cache_turbo_ctx_t;


/*
 * Serialised cache blob layout (one contiguous slab allocation):
 *
 *   [ 44-byte fixed wire header (see ngx_http_cache_turbo_blob_hdr_write) ]
 *   [ nheaders * { u32 name_len, name, u32 val_len, value } ]   (all u32 LE)
 *   [ body bytes ]
 *
 * The header block lets us restore Content-Type and any other response
 * headers on a cache hit, so cached responses are byte-identical to origin.
 *
 * created/fresh_ttl/stale_ttl/sie_ttl carry the object's ORIGINAL freshness so
 * an L2 hit can rebuild L1 with the remaining lifetime instead of resetting it
 * to the location default — without these, every L2 hit would re-promote a stale
 * object as fresh and it could live forever (and per-status/upstream TTLs would
 * be lost across the L2 round-trip). sie_ttl (RFC-2 stale-if-error, CTB4) is the
 * absolute serve-on-origin-error window from creation (fresh + stale-if-error N);
 * 0 = no serve-on-error past the normal stale window.
 *
 * STAB-4: the wire header is a FIXED little-endian, 44-byte, padding-free layout
 * (NOT this struct's native ABI) written/read only via the blob_hdr_write/
 * blob_validate helpers in module.c — so the on-disk format is independent of
 * compiler struct padding and host endianness. This struct is the in-memory
 * PARSED form; its field order/size is irrelevant to the wire. A single
 * ngx_http_cache_turbo_blob_validate() fully validates magic+version+all length
 * fields+the TLV header walk in one place, so a malformed L2 blob is rejected
 * BEFORE it is inserted into L1 (the old inline parse stored first, then serve()
 * failed = a poisoned L1 slot).
 *
 * Wire offsets (little-endian):
 *   0  u32 magic     ("CTB4")    16  u32 headers_len   32  u32 fresh_ttl
 *   4  u16 version   (= 4)       20  u32 body_len      36  u32 stale_ttl
 *   6  u16 flags     (reserved)  24  i64 created       40  u32 sie_ttl
 *   8  u32 status    12 u32 nheaders                   44  = header size
 */
typedef struct {
    uint32_t                 magic;       /* 0x43544234 = "CTB4"            */
    uint32_t                 version;
    uint32_t                 nheaders;
    uint32_t                 headers_len; /* bytes of the header block      */
    uint32_t                 body_len;
    uint32_t                 status;
    int64_t                  created;     /* unix time (s) the blob was made */
    uint32_t                 fresh_ttl;   /* freshness seconds from created  */
    uint32_t                 stale_ttl;   /* total serveable window (>=fresh) */
    uint32_t                 sie_ttl;     /* abs serve-on-error window; 0=none */
} ngx_http_cache_turbo_blob_hdr_t;

/* CTB4 (RFC-2 stale-if-error): fixed-endian versioned wire format. CTB4 adds the
 * sie_ttl u32 after stale_ttl (44-byte header). Old CTB1/CTB2/CTB3 blobs in L2
 * fail the magic/version check and are treated as a miss (cache self-heals), so
 * no migration is needed — the keyspace turns over once on upgrade.
 *
 * NOTE: the magic/version are bumped ONLY for an actual wire-LAYOUT change. A
 * purely semantic shift in already-laid-out bytes (e.g. the 2bcb914 switch from
 * storing a compressed body to an identity one) does NOT bump it — a reload
 * clears L1 shm and short TTLs age out any L2 copy, so a global keyspace
 * turnover would be unwarranted churn for a not-yet-in-production module. */
#define NGX_HTTP_CACHE_TURBO_BLOB_MAGIC    0x43544234
#define NGX_HTTP_CACHE_TURBO_BLOB_VERSION  4
/* Fixed wire size of the blob header (NOT sizeof the struct — that carries
 * native padding). All blob offsets derive from this constant. */
#define NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE 44


extern ngx_module_t  ngx_http_cache_turbo_module;


/* ---- shm.c ---- */
ngx_int_t ngx_http_cache_turbo_shm_init_zone(ngx_shm_zone_t *zone, void *data);

/* PERF-7 zero-copy serve refcount. acquire() pins a blob for an in-flight serve
 * and MUST be called with shpool->mutex held (same critical section as the
 * lookup that produced `data`). release() is the request-pool cleanup: it takes
 * the mutex itself, drops the ref, and frees the slab if the owning node has
 * already detached it. `data` is ngx_http_cache_turbo_node_t.data (the blob ptr,
 * never NULL). */
void ngx_http_cache_turbo_blob_acquire(u_char *data);
void ngx_http_cache_turbo_blob_release(ngx_http_cache_turbo_zone_t *z,
    u_char *data);

ngx_http_cache_turbo_node_t *
    ngx_http_cache_turbo_shm_lookup(ngx_http_cache_turbo_zone_t *z,
        u_char *key_hash, uint32_t hash);

ngx_int_t ngx_http_cache_turbo_shm_store(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, u_char *data, size_t len,
    time_t fresh_ttl, time_t stale_ttl);

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

/* PERF-1/2: drop many L2 keys in ONE connection. Pipelines chunked variadic
 * UNLINK commands (each UNLINK deletes up to a fixed cap of keys and returns a
 * single integer reply) instead of one fire-and-forget connection per key, so a
 * large tag/all purge can no longer open thousands of sockets at once. Key
 * bytes are copied into the op pool, so the caller's array need not outlive the
 * call. No-op when L2 is disabled or nkeys == 0. */
void ngx_http_cache_turbo_redis_del_many(ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_str_t *keys, ngx_uint_t nkeys);

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
        uint32_t hash, u_char *data, size_t len,
        time_t fresh_ttl, time_t stale_ttl);
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
extern ngx_cache_turbo_backend_t  ngx_http_cache_turbo_memcached_backend;


#endif /* NGX_HTTP_CACHE_TURBO_MODULE_H_INCLUDED_ */
