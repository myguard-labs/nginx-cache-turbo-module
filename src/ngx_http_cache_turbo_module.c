/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * http-cache-turbo — v1 vertical slice.
 *
 *   - ACCESS phase: hash the cache key, look it up in the L1 shm zone.
 *       * fresh hit          -> serve from shm, skip upstream
 *       * stale hit + dice   -> THIS request regenerates synchronously (goes to
 *                               origin, serves the fresh copy); concurrent
 *                               readers serve stale meanwhile
 *       * stale hit, no dice -> serve stale now; someone else regenerates
 *       * miss               -> let the request run, capture + store
 *   - header/body filters: capture the upstream response and store it.
 *
 * Single-flight is probabilistic (the SWR dice in swr.c), so the read path is
 * lock-free. See memory/nginx+angie/cache-turbo-module-design.md.
 */

#include "ngx_http_cache_turbo_module.h"

#if (NGX_SSL)
#include <ngx_event_openssl.h>
#endif


static ngx_int_t ngx_http_cache_turbo_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_cache_turbo_precontent_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_cache_turbo_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_cache_turbo_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);

static ngx_int_t ngx_http_cache_turbo_serve(ngx_http_request_t *r,
    u_char *copy, size_t len, ngx_uint_t stale,
    ngx_http_cache_turbo_zone_t *z, u_char *ref_data, const char *xcache);
/* P6/O4.3: the breaker's 503 path needs the shared small-body sender, which is
 * defined with the other response helpers far below the access handler. */
static ngx_int_t ngx_http_cache_turbo_send_body(ngx_http_request_t *r,
    ngx_uint_t status, ngx_str_t *body, const char *ctype, size_t ctype_len);
/* P6/O4.3: the serve-path breaker predicates. Defined beside the O4.2 recording
 * rule inside the UNIT-EXTRACT block (so the unit suite slices all of the
 * breaker's decision logic from one place), which is below the access handler
 * that calls them. */
static ngx_int_t ngx_http_cache_turbo_add_header(ngx_http_request_t *r,
    u_char *name, size_t nlen, u_char *val, size_t vlen);
static ngx_uint_t ngx_http_cache_turbo_breaker_should_consult(
    ngx_http_cache_turbo_loc_conf_t *clcf);
static char *ngx_http_cache_turbo_breaker_open_conf(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_uint_t ngx_http_cache_turbo_breaker_action(ngx_uint_t state,
    ngx_uint_t has_body);
static ngx_int_t ngx_http_cache_turbo_restore_response(ngx_http_request_t *r,
    u_char *copy, size_t len, ngx_uint_t stale, const char *xcache,
    u_char **bodyp, size_t *body_lenp);
static ngx_uint_t ngx_http_cache_turbo_restore_alloc_fails(
    ngx_http_request_t *r);
static ngx_int_t ngx_http_cache_turbo_cold_wait(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_ctx_t *ctx);
static void ngx_http_cache_turbo_cold_wait_timeout(ngx_event_t *ev);
static void ngx_http_cache_turbo_cold_wait_cleanup(void *data);
static void ngx_http_cache_turbo_cold_mark_winner(ngx_http_request_t *r,
    ngx_http_cache_turbo_ctx_t *ctx, ngx_http_cache_turbo_zone_t *z,
    uint64_t owner);
static void ngx_http_cache_turbo_cold_cleanup(void *data);
static ngx_int_t ngx_http_cache_turbo_cold_adopt_own_stub(
    ngx_http_request_t *r, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_cache_turbo_zone_t *z);
static ngx_int_t ngx_http_cache_turbo_send_json(ngx_http_request_t *r,
    ngx_uint_t status, ngx_str_t *body);

static void *ngx_http_cache_turbo_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_cache_turbo_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_http_cache_turbo_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cache_turbo(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cache_turbo_backend(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cache_turbo_cache_control(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_cache_turbo_auto_skip(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf);
static ngx_int_t ngx_http_cache_turbo_key_cookie(ngx_http_request_t *r,
    ngx_uint_t backend_presets, ngx_uint_t *cursor, ngx_str_t *name_out,
    ngx_str_t *val_out);
static ngx_int_t ngx_http_cache_turbo_cookie_lookup(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *val_out);
static ngx_int_t ngx_http_cache_turbo_bypass_uri_match(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf);
static char *ngx_http_cache_turbo_key(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cache_turbo_valid_conf(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cache_turbo_admin(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cache_turbo_redis_conf(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_cache_turbo_memcached_conf(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_cache_turbo_tag(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cache_turbo_require_header(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_cache_turbo_require_hdr_ok(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf);
static char *ngx_http_cache_turbo_stale_mult(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_cache_turbo_min_uses(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_cache_turbo_scan_resistant(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_cache_turbo_l2_negative_ttl(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_cache_turbo_keep_stale(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_cache_turbo_use_stale(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_cache_turbo_preset(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_cache_turbo_admin_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_cache_turbo_warm(ngx_http_request_t *r,
    ngx_str_t *urls);
static ngx_int_t ngx_http_cache_turbo_warm_one(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args);
/* State carried through an async tag purge from the admin handler to the
 * SMEMBERS completion callback. Also reused for the COR-5 variant-index purge
 * (the index is a per-base tag set), so it is defined up here for
 * purge_request near the top of the file. */
typedef struct {
    ngx_http_cache_turbo_loc_conf_t  *clcf;
    ngx_http_cache_turbo_zone_t      *zone;
    ngx_str_t                         tag;    /* copied into r->pool */
} ngx_http_cache_turbo_tagpurge_t;
static ngx_int_t ngx_http_cache_turbo_tag_purge_complete(ngx_http_request_t *r,
    void *data, ngx_str_t *members, ngx_uint_t nmembers,
    const ngx_http_cache_turbo_redis_walk_t *walk);
static ngx_int_t ngx_http_cache_turbo_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_cache_turbo_normalized_args_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static char *ngx_http_cache_turbo_normalize_strip(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_cache_turbo_normalize_vary(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_cache_turbo_backend_prefix(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_cache_turbo_bypass_uri(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_cache_turbo_key_cookie_conf(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
/* auto-Vary (v11 other half) — defined near the v3-4 vary helpers but called
 * from the access/header/body paths above them, so forward-declared here. */
static void ngx_http_cache_turbo_vary_resolve(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_ctx_t *ctx, uint32_t *hash);
static void ngx_http_cache_turbo_variant_hash(ngx_http_request_t *r,
    ngx_str_t *base, ngx_int_t bits, ngx_uint_t gen, u_char out[32]);
static void ngx_http_cache_turbo_marker_hash(ngx_str_t *base, u_char out[32]);
/* AUD-HDR1: the single store/restore header gate. Declared here because
 * restore_response() (above its definition) is one of the two callers — the
 * point of the helper is that there is exactly ONE. */
static ngx_int_t ngx_http_cache_turbo_header_admissible(
    ngx_http_cache_turbo_loc_conf_t *clcf, u_char *name, size_t nlen,
    u_char *val, size_t vlen);
static void ngx_http_cache_turbo_marker_store(ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_http_cache_turbo_zone_t *z, ngx_str_t *base, ngx_int_t bits,
    ngx_uint_t gen, time_t ttl);
/* COR-5: the per-base variant-index set name (space-framed so no user tag token
 * can collide) + the L1-only generation bump. */
static size_t ngx_http_cache_turbo_variant_index_name(ngx_str_t *base,
    u_char *buf);
static void ngx_http_cache_turbo_classify_vary(ngx_http_request_t *r,
    ngx_int_t *bits_out, ngx_uint_t *nocache_out);
static ngx_uint_t ngx_http_cache_turbo_response_encoded(ngx_http_request_t *r);
static ngx_int_t ngx_http_cache_turbo_init(ngx_conf_t *cf);


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


/*
 * Preset bands (v3-2). Indexed by NGX_HTTP_CACHE_TURBO_PRESET_* (1-based; slot 0
 * is a never-used placeholder so an UNSET/zero preset can't silently index a
 * real band). BALANCED equals the historical hardcoded merge fallbacks. Tune by
 * feel; the chosen values are documented in
 * memory/labs/nginx-cache-turbo-module/history.md.
 */
/* Fields: valid, beta, lock_ttl, stale_mult, beta_min, beta_max, min_uses.
 * beta_min/beta_max are the v4-3 autotune clamp window for the preset (×1000);
 * the autotune verdict is re-clamped to them so a conservative location never
 * tunes as hot as aggressive (see history.md v4-3). Centres match the static
 * beta; bands subset global [500,3000] with overlapping edges.
 *
 * min_uses (H3c): cold misses required before a key is stored. 1 = store on the
 * first miss. ONLY AGGRESSIVE raises it to 2, deliberately: the gate trades one
 * extra origin fetch per genuine repeat key for never spending a response blob
 * on a one-hit-wonder URL, which is the bargain an operator asking for max
 * hit-rate on a long-tail site wants. Every other band — including BALANCED,
 * the default — stays 1, so the default preset's caching behaviour is unchanged
 * (a key is stored on its first request, as it always has been). Note a counter
 * node still costs a full node_t: min_uses 2 saves the BLOB on one-hit keys, not
 * the node, so raising it on a normal-cardinality site is a pure origin-load
 * increase with no offsetting saving. See history.md H3c. */
static const ngx_http_cache_turbo_band_t  ngx_http_cache_turbo_bands[] = {
    /* [0] unused placeholder        */ {   0,    0,  0, 0,    0,    0, 0 },
    /* [1] CONSERVATIVE: correctness */ {  30,  500, 10, 2,  500, 1000, 1 },
    /* [2] BALANCED: current defaults*/ {  60, 1000,  5, 4,  500, 2000, 1 },
    /* [3] AGGRESSIVE: max hit-rate  */ { 300, 3000,  3, 8, 1000, 3000, 2 },
    /* [4] MICRO: 1s microcaching    */ {   1, 1000,  1, 2,  500, 2000, 1 },
};


static ngx_command_t  ngx_http_cache_turbo_commands[] = {

    { ngx_string("cache_turbo_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_cache_turbo_zone,
      0,
      0,
      NULL },

    { ngx_string("cache_turbo"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
      ngx_http_cache_turbo,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_backend"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_http_cache_turbo_backend,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_key"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_cache_turbo_key,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_valid"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_http_cache_turbo_valid_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_beta"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, beta_raw),
      NULL },

    { ngx_string("cache_turbo_max_size"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, max_size),
      NULL },

    { ngx_string("cache_turbo_suppress_native"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, suppress_native),
      NULL },

    { ngx_string("cache_turbo_lock_ttl"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, lock_ttl_raw),
      NULL },

    { ngx_string("cache_turbo_stale_mult"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_cache_turbo_stale_mult,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_preset"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_cache_turbo_preset,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_autotune"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, autotune),
      NULL },

    { ngx_string("cache_turbo_cache_control"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_cache_turbo_cache_control,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_auto_vary"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, auto_vary),
      NULL },

    { ngx_string("cache_turbo_purge"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, purge),
      NULL },

    { ngx_string("cache_turbo_background_update"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, background_update),
      NULL },

    { ngx_string("cache_turbo_lock"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, lock),
      NULL },

    { ngx_string("cache_turbo_lock_timeout"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, lock_timeout),
      NULL },

    { ngx_string("cache_turbo_min_uses"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_cache_turbo_min_uses,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_scan_resistant"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
      ngx_http_cache_turbo_scan_resistant,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_l2_negative_ttl"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_cache_turbo_l2_negative_ttl,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_keep_stale"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_cache_turbo_keep_stale,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_use_stale"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_http_cache_turbo_use_stale,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* O4.4: the circuit-breaker directives. Three independent ways to turn
     * the breaker off: this flag, `cache_turbo_breaker_threshold 0`, or
     * `cache_turbo_breaker_window 0` -- see
     * ngx_http_cache_turbo_breaker_should_consult(). Deliberately no
     * cache_turbo_breaker_probe directive: the probe lease is the internal
     * constant NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_LEASE, not operator-tunable
     * (see its header comment for why). */
    { ngx_string("cache_turbo_breaker"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, breaker_enable),
      NULL },

    { ngx_string("cache_turbo_breaker_threshold"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, breaker_threshold),
      NULL },

    { ngx_string("cache_turbo_breaker_window"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, breaker_window),
      NULL },

    /* ⚠ NOT ngx_conf_set_sec_slot: 0 must be a hard config error here, not a
     * silent disable. See ngx_http_cache_turbo_breaker_open_conf() and the
     * O4.3-a note on the breaker_open field in the .h. */
    { ngx_string("cache_turbo_breaker_open"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_cache_turbo_breaker_open_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_breaker_retry_after"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, breaker_retry_after),
      NULL },

    { ngx_string("cache_turbo_admin"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_cache_turbo_admin,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_redis"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_cache_turbo_redis_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_memcached"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_cache_turbo_memcached_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_tag"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_cache_turbo_tag,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_require_header"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_cache_turbo_require_header,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_surrogate_key"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, surrogate_key),
      NULL },

    { ngx_string("cache_turbo_bypass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_http_set_predicate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, bypass),
      NULL },

    { ngx_string("cache_turbo_no_store"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_http_set_predicate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, no_store),
      NULL },

    { ngx_string("cache_turbo_normalize_strip"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_http_cache_turbo_normalize_strip,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_normalize_vary"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_http_cache_turbo_normalize_vary,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_bypass_uri"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_http_cache_turbo_bypass_uri,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_backend_prefix"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_cache_turbo_backend_prefix,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_key_cookie"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_http_cache_turbo_key_cookie_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    { ngx_string("cache_turbo_test_restore_alloc_fail"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, test_restore_alloc_fail),
      NULL },

    { ngx_string("cache_turbo_test_force_file_buf"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, test_force_file_buf),
      NULL },

    { ngx_string("cache_turbo_test_store_fail"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, test_store_fail),
      NULL },

    /* AUD-SCAN1: lower the SCAN-del page cap so the "abandon the walk and
     * report INCOMPLETE" branch is reachable without a 268M-key keyspace. */
    { ngx_string("cache_turbo_test_scan_max_pages"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, test_scan_max_pages),
      NULL },

    /* AUD-L2-PROMOTE-RACE: the gap between the resumed L2-hit handler's own
     * (already-unlocked) L1 re-check and its store_if() call is pure CPU with
     * no I/O or yield point in between -- unreachable from a black-box HTTP
     * timing race. This blocks the CURRENT WORKER for up to N ms, right
     * before the promote call, so a test can land a concurrent write from a
     * DIFFERENT worker into that exact window. ngx_msleep is a plain
     * usleep(): it stalls only this worker's event loop, not the others, so
     * with >1 worker configured the concurrent write is unaffected. 0/unset
     * = no hold (production default; the directive does not exist outside
     * TEST_FAULTS builds at all). */
    { ngx_string("cache_turbo_test_l2_promote_hold_ms"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, test_l2_promote_hold_ms),
      NULL },
#endif

      ngx_null_command
};


static void ngx_http_cache_turbo_exit_process(ngx_cycle_t *cycle);


static ngx_http_module_t  ngx_http_cache_turbo_module_ctx = {
    ngx_http_cache_turbo_add_variables,    /* preconfiguration */
    ngx_http_cache_turbo_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_cache_turbo_create_loc_conf,  /* create location configuration */
    ngx_http_cache_turbo_merge_loc_conf    /* merge location configuration */
};


ngx_module_t  ngx_http_cache_turbo_module = {
    NGX_MODULE_V1,
    &ngx_http_cache_turbo_module_ctx,      /* module context */
    ngx_http_cache_turbo_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_cache_turbo_exit_process,     /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


/* ------------------------------------------------------------------------- *
 * SEC-2: 256-bit content digest.
 *
 * The cache key hash is a 32-byte slot (the redis key is hex(slot[32]) = 64
 * chars). MD5 alone filled only the low 16 bytes (the high 16 stayed zero) =>
 * a 128-bit identity with no second-preimage/collision margin beyond MD5's
 * (broken) one. We now fill the whole slot with a real 256-bit digest:
 *
 *   - SHA-256 when built with SSL (libcrypto is linked — the shipped build uses
 *     --with-http_ssl_module). EVP one-shot/streaming API (not the deprecated
 *     SHA256_* low-level calls, which warn under -Werror on OpenSSL 3).
 *   - a double independent MD5 fold otherwise, so a no-SSL build still fills the
 *     full 32-byte slot with no OpenSSL dependency: low 16 = MD5(data),
 *     high 16 = MD5(domain-tag . data). Weaker than true SHA-256 but strictly
 *     wider than the old single-MD5-with-zero-pad.
 *
 * Either way the on-wire key is hex(slot[32]); the digest choice only changes
 * which bytes, so the keyspace turnover self-heals (old keys just miss). All
 * key-derivation sites (build_key, the variant/marker hashes, the admin
 * ?key= purge) MUST go through this one helper so they agree.
 * ------------------------------------------------------------------------- */

typedef struct {
#if (NGX_SSL)
    EVP_MD_CTX  *md;
    ngx_int_t    ok;
#else
    ngx_md5_t    lo;
    ngx_md5_t    hi;
#endif
} ngx_http_cache_turbo_digest_t;


#if (NGX_SSL)
/* P6: one EVP_MD_CTX per worker, reused across every digest.
 *
 * nginx workers are single-threaded and a digest never spans an event-handler
 * return (init/update/final all run within one call), so there is no window in
 * which two digests are live at once and a single shared ctx is safe. Each
 * digest_init() does EVP_DigestInit_ex() on it, which resets the hash state —
 * so no residue carries between callers.
 *
 * Created lazily on first use rather than from an init_process hook, so a
 * digest issued before worker fork (config-time key derivation) still works.
 * Freed in exit_process; leaking it at shutdown would be harmless but shows up
 * under valgrind/ASan and the suite treats that as a failure.
 */
static EVP_MD_CTX  *ngx_http_cache_turbo_worker_md;
#endif

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
static ngx_uint_t  ngx_http_cache_turbo_test_digest_fail = 0;
#endif


static void
ngx_http_cache_turbo_digest_init(ngx_http_cache_turbo_digest_t *d)
{
#if (NGX_SSL)
    if (ngx_http_cache_turbo_worker_md == NULL) {
        ngx_http_cache_turbo_worker_md = EVP_MD_CTX_new();
    }

    d->md = ngx_http_cache_turbo_worker_md;
    d->ok = (d->md != NULL
             && EVP_DigestInit_ex(d->md, EVP_sha256(), NULL) == 1) ? 1 : 0;
#else
    static const u_char  tag[] = "ngx_http_cache_turbo\x1Fhi";

    ngx_md5_init(&d->lo);
    ngx_md5_init(&d->hi);
    ngx_md5_update(&d->hi, tag, sizeof(tag) - 1);
#endif
}


static void
ngx_http_cache_turbo_digest_update(ngx_http_cache_turbo_digest_t *d,
    const void *data, size_t len)
{
#if (NGX_SSL)
    if (d->ok) {
        (void) EVP_DigestUpdate(d->md, data, len);
    }
#else
    ngx_md5_update(&d->lo, data, len);
    ngx_md5_update(&d->hi, data, len);
#endif
}


/* Finalise into the 32-byte slot. Returns NGX_OK on success, NGX_ERROR on failure. */
static ngx_int_t
ngx_http_cache_turbo_digest_final(ngx_http_cache_turbo_digest_t *d,
    u_char out[32])
{
#if (NGX_SSL)
    unsigned int  n = 0;

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    if (ngx_http_cache_turbo_test_digest_fail) {
        d->md = NULL;
        return NGX_ERROR;
    }
#endif

    if (d->ok && EVP_DigestFinal_ex(d->md, out, &n) == 1 && n == 32) {
        /* P6: the ctx is worker-persistent — do NOT free it here. The next
         * digest_init() re-keys it via EVP_DigestInit_ex(); exit_process frees it. */
        d->md = NULL;
        return NGX_OK;
    } else {
        /* EVP_MD_CTX alloc/finalise failure (OOM) — fail closed: return error
         * so the caller skips caching rather than storing under an all-zero key. */
        d->md = NULL;
        return NGX_ERROR;
    }
#else
    ngx_md5_final(out, &d->lo);          /* low 16 */
    ngx_md5_final(out + 16, &d->hi);     /* high 16 */
    return NGX_OK;
#endif
}


/* One-shot convenience for a single contiguous input. Returns NGX_OK on success, NGX_ERROR on failure. */
static ngx_int_t
ngx_http_cache_turbo_digest(const void *data, size_t len, u_char out[32])
{
    ngx_http_cache_turbo_digest_t  d;

    ngx_http_cache_turbo_digest_init(&d);
    ngx_http_cache_turbo_digest_update(&d, data, len);
    return ngx_http_cache_turbo_digest_final(&d, out);
}


/* P6: release the worker-persistent digest ctx (see digest_init). */
static void
ngx_http_cache_turbo_exit_process(ngx_cycle_t *cycle)
{
    (void) cycle;

#if (NGX_SSL)
    if (ngx_http_cache_turbo_worker_md != NULL) {
        EVP_MD_CTX_free(ngx_http_cache_turbo_worker_md);
        ngx_http_cache_turbo_worker_md = NULL;
    }
#endif
}


/* ------------------------------------------------------------------------- *
 * STAB-4: fixed little-endian, padding-free blob wire header (44 bytes, CTB4).
 * Written/read only through these helpers so the on-disk format is independent
 * of struct padding and host endianness. See the layout comment on
 * ngx_http_cache_turbo_blob_hdr_t in the header.
 * ------------------------------------------------------------------------- */

static ngx_inline void
ngx_http_cache_turbo_put_u16(u_char *p, uint16_t v)
{
    p[0] = (u_char) (v & 0xff);
    p[1] = (u_char) ((v >> 8) & 0xff);
}

static ngx_inline void
ngx_http_cache_turbo_put_u32(u_char *p, uint32_t v)
{
    p[0] = (u_char) (v & 0xff);
    p[1] = (u_char) ((v >> 8) & 0xff);
    p[2] = (u_char) ((v >> 16) & 0xff);
    p[3] = (u_char) ((v >> 24) & 0xff);
}

static ngx_inline void
ngx_http_cache_turbo_put_u64(u_char *p, uint64_t v)
{
    ngx_http_cache_turbo_put_u32(p, (uint32_t) (v & 0xffffffffULL));
    ngx_http_cache_turbo_put_u32(p + 4, (uint32_t) ((v >> 32) & 0xffffffffULL));
}

static ngx_inline uint16_t
ngx_http_cache_turbo_get_u16(const u_char *p)
{
    return (uint16_t) (p[0] | ((uint16_t) p[1] << 8));
}

static ngx_inline uint32_t
ngx_http_cache_turbo_get_u32(const u_char *p)
{
    return (uint32_t) p[0]
         | ((uint32_t) p[1] << 8)
         | ((uint32_t) p[2] << 16)
         | ((uint32_t) p[3] << 24);
}

static ngx_inline uint64_t
ngx_http_cache_turbo_get_u64(const u_char *p)
{
    return (uint64_t) ngx_http_cache_turbo_get_u32(p)
         | ((uint64_t) ngx_http_cache_turbo_get_u32(p + 4) << 32);
}


/* Serialise the parsed header into NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE bytes. */
static void
ngx_http_cache_turbo_blob_hdr_write(u_char *dst,
    const ngx_http_cache_turbo_blob_hdr_t *h)
{
    ngx_http_cache_turbo_put_u32(dst + 0,  NGX_HTTP_CACHE_TURBO_BLOB_MAGIC);
    ngx_http_cache_turbo_put_u16(dst + 4,  NGX_HTTP_CACHE_TURBO_BLOB_VERSION);
    ngx_http_cache_turbo_put_u16(dst + 6,  0);            /* flags reserved */
    ngx_http_cache_turbo_put_u32(dst + 8,  h->status);
    ngx_http_cache_turbo_put_u32(dst + 12, h->nheaders);
    ngx_http_cache_turbo_put_u32(dst + 16, h->headers_len);
    ngx_http_cache_turbo_put_u32(dst + 20, h->body_len);
    ngx_http_cache_turbo_put_u64(dst + 24, (uint64_t) h->created);
    ngx_http_cache_turbo_put_u32(dst + 32, h->fresh_ttl);
    ngx_http_cache_turbo_put_u32(dst + 36, h->stale_ttl);
    ngx_http_cache_turbo_put_u32(dst + 40, h->sie_ttl);   /* CTB4 (RFC-2 SIE) */
}


/*
 * Parse AND fully validate a stored blob in one place (STAB-4). On NGX_OK *out
 * holds the parsed header and (when non-NULL) *hdr_block / *body point at the
 * interior header block and body. Validates: minimum length, magic, version,
 * that the header block and body fit inside the buffer, AND that every TLV
 * header entry lies within the header block (a full walk). Doing the walk here
 * lets the L2-fill path reject a malformed blob BEFORE inserting it into L1 —
 * the old code stored first and only failed later in serve(), poisoning the L1
 * slot with a node that could never be served.
 */
static ngx_int_t
ngx_http_cache_turbo_blob_validate(const u_char *blob, size_t len,
    ngx_http_cache_turbo_blob_hdr_t *out, const u_char **hdr_block,
    const u_char **body)
{
    const u_char  *p, *end;
    uint32_t       i;

    if (blob == NULL || len < NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE) {
        return NGX_ERROR;
    }
    if (ngx_http_cache_turbo_get_u32(blob) != NGX_HTTP_CACHE_TURBO_BLOB_MAGIC
        || ngx_http_cache_turbo_get_u16(blob + 4)
               != NGX_HTTP_CACHE_TURBO_BLOB_VERSION)
    {
        return NGX_ERROR;
    }

    out->magic       = NGX_HTTP_CACHE_TURBO_BLOB_MAGIC;
    out->version     = NGX_HTTP_CACHE_TURBO_BLOB_VERSION;
    out->status      = ngx_http_cache_turbo_get_u32(blob + 8);
    out->nheaders    = ngx_http_cache_turbo_get_u32(blob + 12);
    out->headers_len = ngx_http_cache_turbo_get_u32(blob + 16);
    out->body_len    = ngx_http_cache_turbo_get_u32(blob + 20);
    out->created     = (int64_t) ngx_http_cache_turbo_get_u64(blob + 24);
    out->fresh_ttl   = ngx_http_cache_turbo_get_u32(blob + 32);
    out->stale_ttl   = ngx_http_cache_turbo_get_u32(blob + 36);
    out->sie_ttl     = ngx_http_cache_turbo_get_u32(blob + 40);   /* CTB4 */

    /*
     * AUD-HDR1: RANGE validation, not just framing. Everything below this point
     * is inherited by every consumer — restore_response() writes `status`
     * straight into r->headers_out.status, and the L2-fill path computes the
     * L1 lifetime from fresh_ttl/stale_ttl — so bounding the fields HERE is
     * what makes "the blob passed validation" mean something. Rejecting rather
     * than clamping is deliberate: these values are not degraded, they are
     * impossible, and a blob carrying them was not written by this module.
     *
     * NOTE on the TTLs: a bare "clamp to NGX_HTTP_CACHE_TURBO_TTL_MAX" would be
     * VACUOUS here — TTL_MAX is 0xFFFFFFFF and these are u32 wire fields, so it
     * can never fire. The invariant that does bite is stale_ttl >= fresh_ttl:
     * stale_ttl is the TOTAL serveable window (see the blob_hdr layout comment),
     * and every store-path shape satisfies it — stale_ttl() multiplies by
     * stale_mult >= 1, the stale-while-revalidate branch adds to ttl, and the
     * must-revalidate branch collapses it to exactly ttl. A forged blob claiming
     * a 136-year fresh_ttl under an ordinary stale window does not.
     */
    if (out->status < 100 || out->status > 599) {
        return NGX_ERROR;
    }
    if (out->stale_ttl < out->fresh_ttl) {
        return NGX_ERROR;
    }

    /*
     * AUD-BLOB-CREATED: bound `created` for the same reason status/stale_ttl
     * are bounded above — every downstream consumer computes
     * `now - created` (signed time_t subtraction) with no overflow check
     * before it, so an out-of-range `created` (e.g. INT64_MIN from a hostile
     * or corrupt L2 blob) is undefined behaviour before any later `age < 0`
     * clamp can run. See the NGX_HTTP_CACHE_TURBO_BLOB_CREATED_MIN comment in
     * the header for the range rationale. Reject, do not clamp: a `created`
     * outside this window was not written by this module's store path.
     */
    if (out->created < NGX_HTTP_CACHE_TURBO_BLOB_CREATED_MIN
        || out->created > (int64_t) ngx_time()
                               + (int64_t) NGX_HTTP_CACHE_TURBO_FOREVER_TTL)
    {
        return NGX_ERROR;
    }

    /* header block + body must fit (subtract on the remaining len — no overflow) */
    if (out->headers_len > len - NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE
        || out->body_len
               > len - NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE - out->headers_len)
    {
        return NGX_ERROR;
    }

    p   = blob + NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE;
    end = p + out->headers_len;

    for (i = 0; i < out->nheaders; i++) {
        uint32_t  nl, vl;

        if ((size_t) (end - p) < 4) { return NGX_ERROR; }
        nl = ngx_http_cache_turbo_get_u32(p); p += 4;
        if ((size_t) (end - p) < nl) { return NGX_ERROR; }
        p += nl;
        if ((size_t) (end - p) < 4) { return NGX_ERROR; }
        vl = ngx_http_cache_turbo_get_u32(p); p += 4;
        if ((size_t) (end - p) < vl) { return NGX_ERROR; }
        p += vl;
    }

    if (hdr_block) { *hdr_block = blob + NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE; }
    if (body)      { *body = end; }
    return NGX_OK;
}


/*
 * Decode ONE `u32 nlen | name | u32 vlen | value` TLV entry at *pp and advance
 * *pp past it. Returns NGX_OK with the four out-params pointing INTO the caller's
 * buffer, or NGX_DONE when the header block is exhausted or the next entry does
 * not fit (the walk stops, it never runs off `end`).
 *
 * AUD-FUZZ1: this is the ONE walk. blob_validate() above pre-walks the block to
 * reject a malformed blob before it reaches L1, restore_response() re-walks it to
 * rebuild headers_out, and ci/fuzz/fuzz_blob.c drives this exact function — so
 * the three can no longer disagree about where an entry ends. The previous
 * open-coded copy in restore_response() was the only reader of the blob's TLV
 * framing that nothing tested.
 */
static ngx_int_t
ngx_http_cache_turbo_blob_next_header(const u_char **pp, const u_char *end,
    const u_char **name, uint32_t *nlen, const u_char **val, uint32_t *vlen)
{
    const u_char  *p = *pp;
    uint32_t       nl, vl;

    if ((size_t) (end - p) < 8) { return NGX_DONE; }

    nl = ngx_http_cache_turbo_get_u32(p); p += 4;
    if ((size_t) (end - p) < nl) { return NGX_DONE; }
    *name = p; p += nl;

    if ((size_t) (end - p) < 4) { return NGX_DONE; }
    vl = ngx_http_cache_turbo_get_u32(p); p += 4;
    if ((size_t) (end - p) < vl) { return NGX_DONE; }
    *val = p; p += vl;

    *nlen = nl;
    *vlen = vl;
    *pp = p;
    return NGX_OK;
}


/*
 * Longest key-cookie VALUE folded verbatim. Every legitimate segment
 * fingerprint is far shorter: X-Magento-Vary is a base64'd hash, xf_style_id /
 * xf_language_id are small integers, ips4_theme and mybbtheme are theme ids.
 * A value past this length is not a fingerprint any application issued.
 */
#define NGX_HTTP_CACHE_TURBO_KEY_COOKIE_MAX       256

/*
 * Value-length field written for an over-long value. A real value can never
 * reach this, since it is capped at _MAX above, so the marker is unforgeable
 * from the request — the same property the length-prefixed framing relies on.
 */
#define NGX_HTTP_CACHE_TURBO_KEY_COOKIE_OVERSIZE  0xffffffffu


/*
 * Append ONE key cookie to the key under construction, with the unforgeable
 * length-prefixed framing both the preset and the DIY path use: 0x1f tag, then
 * the name length and the value length as fixed 4-byte fields, then the name
 * and value bytes. See the call sites for why a length prefix and not a
 * delimiter (a delimiter would be forgeable from a request header).
 *
 * Folding is append-only, so calling this once per present cookie yields a key
 * that depends on every one of them. Order is the caller's iteration order,
 * which is fixed by the preset table / the config, so the key is deterministic.
 *
 * A value longer than _KEY_COOKIE_MAX is NOT folded verbatim. All such values
 * collapse to ONE bucket, marked by the reserved _OVERSIZE length field and no
 * value bytes. That bucket is distinct from the absent-cookie (anonymous) key
 * and from every in-range value, so an over-long value can neither poison the
 * anonymous entry nor land on a legitimate segment's entry — the only requests
 * that share it are other over-long ones.
 *
 * WHAT THIS DOES AND DOES NOT FIX. It bounds the key size a single request can
 * force, and it collapses the over-long case to one entry. It does NOT bound
 * cardinality in general, and no length cap can: 256 bytes still spans 2^2048
 * values, so an attacker sending short random values mints an entry per request
 * exactly as before. That is a real exposure — it is finding 3's class (the
 * vbulletin bb_lastvisit timestamp) — and the controls for it are
 * cache_turbo_min_uses, which refuses to store a once-seen key at all, plus
 * max_size and LRU. The remaining shipped key cookies are all low-cardinality
 * by design, which is the property that makes them keyable in the first place;
 * a high-cardinality one gets DROPPED from the list rather than capped, which
 * is what happened to bb_lastvisit.
 *
 * The value is deliberately NOT hashed here and NOT charset-filtered. The whole
 * key is SHA-256'd into ctx->key_hash before it reaches L1 or the L2 wire
 * (SEC-2), so hashing a component adds nothing, and no raw byte of it is ever
 * transmitted or used as a memcached/Redis key — which is what a charset filter
 * would be protecting against. The framing above already makes arbitrary bytes
 * unambiguous.
 */
static ngx_int_t
ngx_http_cache_turbo_key_fold_cookie(ngx_http_request_t *r,
    ngx_http_cache_turbo_ctx_t *ctx, ngx_str_t *name, ngx_str_t *val)
{
    u_char    *k, *p;
    size_t     klen, vlen;
    uint32_t   vfield;

    if (val->len > NGX_HTTP_CACHE_TURBO_KEY_COOKIE_MAX) {
        vlen = 0;
        vfield = NGX_HTTP_CACHE_TURBO_KEY_COOKIE_OVERSIZE;

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "cache_turbo: key cookie \"%V\" value of %uz bytes "
                      "exceeds %d, folded as oversize",
                      name, val->len,
                      NGX_HTTP_CACHE_TURBO_KEY_COOKIE_MAX);

    } else {
        vlen = val->len;
        vfield = (uint32_t) val->len;
    }

    klen = ctx->cache_key.len + 1 + 4 + 4 + name->len + vlen;

    k = ngx_pnalloc(r->pool, klen);
    if (k == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(k, ctx->cache_key.data, ctx->cache_key.len);
    *p++ = '\x1f';
    ngx_http_cache_turbo_put_u32(p, (uint32_t) name->len);
    p += 4;
    ngx_http_cache_turbo_put_u32(p, vfield);
    p += 4;
    p = ngx_cpymem(p, name->data, name->len);
    if (vlen) {
        ngx_memcpy(p, val->data, vlen);
    }

    ctx->cache_key.data = k;
    ctx->cache_key.len = klen;

    return NGX_OK;
}


/* Build the cache key string and its hash into the request ctx. */
static ngx_int_t
ngx_http_cache_turbo_build_key(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx)
{
    if (clcf->key) {
        if (ngx_http_complex_value(r, clcf->key, &ctx->cache_key) != NGX_OK) {
            return NGX_ERROR;
        }
    } else {
        /*
         * Default key: Host + request URI. The Host MUST be in the key — without
         * it, two server blocks that share one zone collide (cross-vhost cache
         * poisoning). r->headers_in.server is the validated Host (or matched
         * server_name); r->unparsed_uri carries the path + raw query string.
         */
        u_char     *k, *p;
        ngx_str_t   host = r->headers_in.server;
        size_t      klen = host.len + r->unparsed_uri.len;

        k = ngx_pnalloc(r->pool, klen ? klen : 1);
        if (k == NULL) {
            return NGX_ERROR;
        }
        p = ngx_cpymem(k, host.data, host.len);
        ngx_memcpy(p, r->unparsed_uri.data, r->unparsed_uri.len);
        ctx->cache_key.data = k;
        ctx->cache_key.len = klen;
    }

    /*
     * Preset key cookies (tier 3): fold the VALUE of a preset's key cookie into
     * the key, so segment variants (Magento's customer group / currency / store
     * view) get their own entries instead of bypassing. Absent cookie => key
     * unchanged, i.e. the plain anonymous entry, which is what the application
     * itself assumes (Magento emits no cookie for an all-default context).
     *
     * The framing is LENGTH-PREFIXED, not delimited: a 0x1f tag byte, then the
     * name length and value length as fixed 4-byte fields, then the name and
     * value bytes. Length-prefixing makes the fold UNAMBIGUOUS regardless of the
     * bytes involved — no separator exists that a cookie value or the base key
     * could contain to splice into a neighbouring field, so no (base, name,
     * value) triple can serialize to another triple's bytes. This matters
     * because the base key can be an operator-configured complex value
     * (cache_turbo_key) that folds in a raw request header, and nginx permits
     * 0x1f inside header field values (only SP/CR/LF/NUL are special in
     * ngx_http_parse_header_line) — so a plain delimiter WOULD be forgeable from
     * the request. The 4-byte lengths are memcpy'd, not text, so they are not
     * confusable with content either. Including the name keeps two presets'
     * key cookies from ever producing the same fold from different cookies.
     */
    if (NGX_HTTP_CACHE_TURBO_HAS_BACKEND(clcf->backend_presets)) {
        ngx_str_t   kcname, kcval;
        ngx_uint_t  cursor = 0;

        /* EVERY present key cookie is folded, not just the first: a preset may
         * declare several, and a cookie the key ignores is one two different
         * users can differ in while sharing an entry. */
        while (ngx_http_cache_turbo_key_cookie(r, clcf->backend_presets,
                                               &cursor, &kcname, &kcval))
        {
            if (ngx_http_cache_turbo_key_fold_cookie(r, ctx, &kcname, &kcval)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

    /*
     * DIY key cookies (cache_turbo_key_cookie): the same tier-3 value-keying as
     * a preset key cookie, for an app we ship no preset for. Each configured
     * cookie's VALUE is folded into the key with the IDENTICAL unforgeable
     * length-prefixed framing (0x1f tag + 4B namelen + 4B vallen + name +
     * value) — see the preset block above for why length-prefixing (not a
     * delimiter) is required. Cookies are folded in config order, which is
     * stable, so the key is deterministic. EXACT name match, ALL Cookie headers
     * scanned (an attacker must not be able to hide the real cookie in a second
     * header and pick the bucket). An absent cookie leaves the key unchanged
     * (the anonymous entry), matching the preset semantics.
     *
     * SAFETY: like the presets, this DEPENDS on the unconditional Set-Cookie
     * store floor in ngx_http_cache_turbo_response_cacheable() to refuse the
     * transition race (request without the cookie keys to the anon entry, the
     * response then SETS the cookie -> storing under the anon key would poison
     * it). Do not relax that floor.
     */
    if (clcf->key_cookies != NULL
        && clcf->key_cookies != NGX_CONF_UNSET_PTR)
    {
        ngx_str_t   *nm = clcf->key_cookies->elts;
        ngx_uint_t   i;

        for (i = 0; i < clcf->key_cookies->nelts; i++) {
            ngx_str_t  kcval;

            if (!ngx_http_cache_turbo_cookie_lookup(r, &nm[i], &kcval)) {
                continue;
            }

            if (ngx_http_cache_turbo_key_fold_cookie(r, ctx, &nm[i], &kcval)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

    /*
     * key_hash is a 32-byte slot filled with a 256-bit digest (SEC-2): the
     * redis hex key/lockkey encode the full slot, so the on-wire layout is
     * stable and the whole 256 bits are the collision guard (was MD5 in the low
     * 16 with the high 16 zeroed = effectively 128-bit). ctx is pcalloc'd, but
     * the digest fills all 32 bytes regardless.
     */
    if (ngx_http_cache_turbo_digest(ctx->cache_key.data, ctx->cache_key.len,
                                    ctx->key_hash) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * Resolve the beta the SWR dice should use for this request. With autotune off
 * (default) it is the static preset/explicit effective beta. With autotune on and
 * a live verdict published (z->sh->autotuned_beta > 0), it is that verdict
 * re-clamped to THIS location's preset band — so a conservative location can't be
 * autotuned as hot as an aggressive one even though they may share a zone and
 * thus a single global verdict. No verdict yet → fall back to the static beta.
 */
static ngx_int_t
ngx_http_cache_turbo_effective_beta(ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_http_cache_turbo_zone_t *z)
{
    ngx_int_t                           ab, p;
    const ngx_http_cache_turbo_band_t  *band;

    if (!clcf->autotune) {
        return clcf->beta;
    }

    ab = (ngx_int_t) z->sh->autotuned_beta;
    if (ab <= 0) {
        return clcf->beta;
    }

    p = (clcf->preset == NGX_CONF_UNSET)
            ? NGX_HTTP_CACHE_TURBO_PRESET_DEFAULT : clcf->preset;
    band = &ngx_http_cache_turbo_bands[p];

    if (ab < band->beta_min) {
        ab = band->beta_min;

    } else if (ab > band->beta_max) {
        ab = band->beta_max;
    }

    return ab;
}


/*
 * v4-4: resolve the load factor (×1000) the request path uses to widen the
 * serveable stale window and the single-flight lock_ttl under sustained backend
 * load. Baseline AT_LOAD_BASE (1000 = no widening) when autotune is off, no
 * verdict is published yet, or the last window was not under load. Unlike beta
 * this is NOT re-clamped to the location's preset band — it is a zone-global
 * load signal, not a per-location eagerness dial — but it is hard-capped at
 * AT_LOAD_MAX so a pathological cost can never extend stale/lock past ≤4×.
 */
static ngx_int_t
ngx_http_cache_turbo_effective_load(ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_http_cache_turbo_zone_t *z)
{
    ngx_int_t  ld;

    if (!clcf->autotune) {
        return NGX_HTTP_CACHE_TURBO_AT_LOAD_BASE;
    }

    ld = (ngx_int_t) z->sh->autotuned_load;
    if (ld <= NGX_HTTP_CACHE_TURBO_AT_LOAD_BASE) {
        return NGX_HTTP_CACHE_TURBO_AT_LOAD_BASE;
    }
    if (ld > NGX_HTTP_CACHE_TURBO_AT_LOAD_MAX) {
        ld = NGX_HTTP_CACHE_TURBO_AT_LOAD_MAX;
    }
    return ld;
}


/*
 * Fresh TTL (seconds) to cache a response with this status, or -1 if the status
 * is not cacheable here (v6). 200 always caches at clcf->valid; any other status
 * caches only if a `cache_turbo_valid <code> <time>` rule named it. A configured
 * "forever" (`cache_turbo_valid 0`) is already resolved to FOREVER_TTL at parse
 * time, so a literal 0 never reaches here; the not-cacheable sentinel is -1.
 */
static time_t
ngx_http_cache_turbo_status_ttl(ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_uint_t status)
{
    ngx_http_cache_turbo_valid_t  *v;
    ngx_uint_t                     i;

    /* Never cache 206 Partial Content: the cache key does not include the Range,
     * so a stored partial would be served for a different (or full) range. Refuse
     * even if an operator listed 206 in cache_turbo_valid. */
    if (status == NGX_HTTP_PARTIAL_CONTENT) {
        return -1;
    }

    if (status == NGX_HTTP_OK) {
        return clcf->valid;
    }

    if (clcf->valid_status != NULL) {
        v = clcf->valid_status->elts;
        for (i = 0; i < clcf->valid_status->nelts; i++) {
            if (v[i].status == status) {
                return v[i].valid;
            }
        }
    }

    return -1;
}


/*
 * Locate a Cache-Control directive by FULL-TOKEN match in a comma-separated
 * value [v,last). Each token is "<name>" or "<name>=<value>" with optional
 * surrounding LWS. Returns a pointer to the value (after '=') with *vlen set
 * when the directive is present with a value, the token start with *vlen == 0
 * when present bare, or NULL when absent. A full-token match (not a substring)
 * is what keeps `s-maxage` from matching inside `max-age` parsing and
 * `max-age=0` from matching inside `max-age=01000` (see the codex follow-ups).
 */
static u_char *
ngx_http_cache_turbo_cc_token(u_char *v, u_char *last, const char *name,
    size_t nlen, size_t *vlen)
{
    u_char  *s = v, *tok, *e, *eq;
    size_t   tn;

    while (s < last) {
        while (s < last && (*s == ' ' || *s == '\t' || *s == ',')) {
            s++;
        }
        tok = s;
        while (s < last && *s != ',') {
            s++;
        }
        e = s;                                  /* [tok, e) is one token */
        while (e > tok && (e[-1] == ' ' || e[-1] == '\t')) {
            e--;                                /* right-trim LWS */
        }

        eq = ngx_strlchr(tok, e, '=');
        tn = eq ? (size_t) (eq - tok) : (size_t) (e - tok);

        if (tn == nlen && ngx_strncasecmp(tok, (u_char *) name, nlen) == 0) {
            if (eq) {
                *vlen = (size_t) (e - (eq + 1));
                return eq + 1;
            }
            *vlen = 0;
            return tok;
        }
    }

    return NULL;
}


/* True if the named Cache-Control directive is present (bare or with a value),
 * full-token match. */
static ngx_int_t
ngx_http_cache_turbo_cc_has(u_char *v, u_char *last, const char *name,
    size_t nlen)
{
    size_t  vlen;

    return ngx_http_cache_turbo_cc_token(v, last, name, nlen, &vlen) != NULL;
}


/* Parse the integer delta-seconds of a Cache-Control "<name>=N" directive in
 * [p,last). Returns -1 if the directive is absent or carries no numeric value.
 * `name` is the bare directive (e.g. "max-age"), NOT including the '='. */
static time_t
ngx_http_cache_turbo_cc_delta(u_char *p, u_char *last, const char *name,
    size_t nlen)
{
    u_char  *q, *e, *vend;
    size_t   vlen;

    q = ngx_http_cache_turbo_cc_token(p, last, name, nlen, &vlen);
    if (q == NULL || vlen == 0) {
        return -1;
    }
    vend = q + vlen;
    for (e = q; e < vend && *e >= '0' && *e <= '9'; e++) { /* void */ }
    if (e == q) {
        return -1;
    }
    return (time_t) ngx_atoi(q, e - q);
}


/*
 * CQ-3: find the first header named `name` (case-insensitive) in an ngx_list_t
 * (works for both r->headers_in.headers and r->headers_out.headers), returning
 * its value or a NULL ngx_str_t when absent. Replaces the open-coded
 * ngx_list_part walk that was copy-pasted across the header-policy helpers. The
 * header lists are short, so a separate walk per looked-up name is cheap.
 */
static ngx_str_t
ngx_http_cache_turbo_header_find(ngx_list_t *headers, const char *name,
    size_t name_len)
{
    ngx_list_part_t  *part = &headers->part;
    ngx_table_elt_t  *h = part->elts;
    ngx_uint_t        i;
    ngx_str_t         v = ngx_null_string;

    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (h[i].hash == 0 || h[i].key.len != name_len) {
            continue;
        }
        if (ngx_strncasecmp(h[i].key.data, (u_char *) name, name_len) == 0) {
            return h[i].value;
        }
    }

    return v;
}


/*
 * HTTP allows a field to be split across multiple field-lines with the same
 * name (RFC 9110 §5.3), semantically equivalent to one line with the values
 * comma-joined in order. header_find() above only returns the FIRST
 * occurrence, which is fine for headers we treat as singular, but
 * Cache-Control is combinable: a directive on a LATER line is just as
 * binding as one on the first. ngx_http_cache_turbo_response_cacheable()
 * already walks every line explicitly (it needs the raw ngx_table_elt_t to
 * also check the header name and Set-Cookie); these two helpers give the
 * same guarantee to callers that only need a directive lookup on the
 * response Cache-Control header, folding the list walk in once instead of
 * being copy-pasted per caller.
 *
 * cc_has_all: true if the named directive appears on ANY Cache-Control line.
 * cc_delta_all: numeric value of the named directive from the FIRST line
 * that carries it (document order), matching the precedence a single
 * comma-joined line would give under cc_delta's existing first-match rule.
 */
static ngx_int_t
ngx_http_cache_turbo_cc_has_all(ngx_list_t *headers, const char *hname,
    size_t hnlen, const char *name, size_t nlen)
{
    ngx_list_part_t  *part = &headers->part;
    ngx_table_elt_t  *h = part->elts;
    ngx_uint_t         i;

    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (h[i].hash == 0 || h[i].key.len != hnlen) {
            continue;
        }
        if (ngx_strncasecmp(h[i].key.data, (u_char *) hname, hnlen) != 0) {
            continue;
        }
        if (ngx_http_cache_turbo_cc_has(h[i].value.data,
                h[i].value.data + h[i].value.len, name, nlen))
        {
            return 1;
        }
    }

    return 0;
}


/*
 * Generalized over the header NAME (CQ-3 follow-up, AUD2-CC-TARGETED): the
 * targeted freshness headers Surrogate-Control / CDN-Cache-Control share the
 * same combinable-field-line semantics as Cache-Control (RFC 9110 §5.3), so
 * their TTL selection needs the same every-line walk that response_cacheable()
 * already applies to all three names on the veto path. Single-line lookup via
 * header_find() only sees the FIRST field-line; a later line carrying the
 * authoritative max-age/s-maxage was silently ignored.
 */
static time_t
ngx_http_cache_turbo_cc_delta_all(ngx_list_t *headers, const char *hname,
    size_t hnlen, const char *name, size_t nlen)
{
    ngx_list_part_t  *part = &headers->part;
    ngx_table_elt_t  *h = part->elts;
    ngx_uint_t         i;
    time_t             t;

    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (h[i].hash == 0 || h[i].key.len != hnlen) {
            continue;
        }
        if (ngx_strncasecmp(h[i].key.data, (u_char *) hname, hnlen) != 0) {
            continue;
        }
        t = ngx_http_cache_turbo_cc_delta(h[i].value.data,
                h[i].value.data + h[i].value.len, name, nlen);
        if (t >= 0) {
            return t;
        }
    }

    return -1;
}


/*
 * Fresh TTL derived from the response's own freshness headers (v7), or -1 if it
 * carries none. Priority ladder (highest first):
 *   1. Surrogate-Control: max-age    (Fastly/Akamai, RFC 9213)
 *   2. CDN-Cache-Control: s-maxage/max-age   (Cloudflare, RFC 9213 §2)
 *   3. Cache-Control: s-maxage > max-age
 *   4. Expires (absolute) minus now.
 * The targeted headers (1,2) exist precisely so an origin can hand the edge /
 * shared cache a DIFFERENT TTL than the browser's Cache-Control — we are that
 * shared cache, so they outrank plain Cache-Control here. They share the same
 * "<token>=<delta>" grammar as Cache-Control, so cc_delta parses them directly.
 * A past Expires / a parse miss clamps to 0 (store but immediately stale).
 * no-store/private/max-age=0 (incl. the targeted variants) are already refused
 * upstream by response_cacheable, so they never reach here. Only called under
 * honor_cc && !ignore_cc, so honouring the targeted variants needs no new knob.
 */
static time_t
ngx_http_cache_turbo_upstream_ttl(ngx_http_request_t *r)
{
    ngx_str_t  expires;
    time_t     t;

    expires = ngx_http_cache_turbo_header_find(&r->headers_out.headers,
             "Expires", sizeof("Expires") - 1);

    /*
     * 1. Surrogate-Control: only max-age is defined for freshness (no
     * s-maxage). Multi-line-safe (AUD2-CC-TARGETED): a later field-line
     * carrying max-age is just as binding as the first (RFC 9110 §5.3), so
     * this walks every Surrogate-Control line rather than only the first.
     */
    t = ngx_http_cache_turbo_cc_delta_all(&r->headers_out.headers,
            "Surrogate-Control", sizeof("Surrogate-Control") - 1,
            "max-age", sizeof("max-age") - 1);
    if (t >= 0) {
        return t;
    }

    /*
     * 2. CDN-Cache-Control: s-maxage wins over max-age, same as
     * Cache-Control. Multi-line-safe for the same reason as arm 1.
     */
    t = ngx_http_cache_turbo_cc_delta_all(&r->headers_out.headers,
            "CDN-Cache-Control", sizeof("CDN-Cache-Control") - 1,
            "s-maxage", sizeof("s-maxage") - 1);
    if (t < 0) {
        t = ngx_http_cache_turbo_cc_delta_all(&r->headers_out.headers,
                "CDN-Cache-Control", sizeof("CDN-Cache-Control") - 1,
                "max-age", sizeof("max-age") - 1);
    }
    if (t >= 0) {
        return t;
    }

    t = ngx_http_cache_turbo_cc_delta_all(&r->headers_out.headers,
            "Cache-Control", sizeof("Cache-Control") - 1,
            "s-maxage", sizeof("s-maxage") - 1);
    if (t < 0) {
        t = ngx_http_cache_turbo_cc_delta_all(&r->headers_out.headers,
                "Cache-Control", sizeof("Cache-Control") - 1,
                "max-age", sizeof("max-age") - 1);
    }
    if (t >= 0) {
        return t;
    }

    if (expires.len) {
        time_t  exp = ngx_parse_http_time(expires.data, expires.len);
        if (exp != NGX_ERROR) {
            exp -= ngx_time();
            return (exp > 0) ? exp : 0;
        }
    }

    return -1;
}


/*
 * True when the response forbids serving stale once expired (RFC 9111 §5.2.2.2 /
 * §5.2.2.8): Cache-Control: must-revalidate or proxy-revalidate. We honour it by
 * collapsing the stale window to zero at store, so the object is served fresh
 * until its deadline and then re-fetched rather than stale-served. Walks the
 * (small) response header list once on the store path only.
 */
static ngx_int_t
ngx_http_cache_turbo_response_must_revalidate(ngx_http_request_t *r)
{
    return (ngx_http_cache_turbo_cc_has_all(&r->headers_out.headers,
                "Cache-Control", sizeof("Cache-Control") - 1,
                "must-revalidate", sizeof("must-revalidate") - 1)
            || ngx_http_cache_turbo_cc_has_all(&r->headers_out.headers,
                "Cache-Control", sizeof("Cache-Control") - 1,
                "proxy-revalidate", sizeof("proxy-revalidate") - 1)) ? 1 : 0;
}


/*
 * RFC 5861 §3 / RFC 9111: response Cache-Control: stale-while-revalidate=N — the
 * origin tells the cache how long past freshness it may serve a stale copy while
 * a refresh runs. Returns N (>=0) or -1 when absent / no numeric value. Honoured
 * at store by sizing the stale window to N instead of the cache_turbo_stale_mult
 * default (RFC-2). Walks the (small) response header list once on the store path.
 */
static time_t
ngx_http_cache_turbo_response_swr(ngx_http_request_t *r)
{
    return ngx_http_cache_turbo_cc_delta_all(&r->headers_out.headers,
               "Cache-Control", sizeof("Cache-Control") - 1,
               "stale-while-revalidate", sizeof("stale-while-revalidate") - 1);
}


/*
 * RFC 5861 §4 / RFC 9111: response Cache-Control: stale-if-error=N — the origin
 * tells the cache how long past freshness it may serve a stale copy when a
 * revalidation to the origin fails (5xx / timeout / connect error). Returns N
 * (>=0) or -1 when absent / no numeric value. Honoured at store by recording the
 * absolute serve-on-error window (fresh + N) in the blob's sie_ttl (CTB4); the
 * serve-on-error path consumes it. Walks the (small) response header list once.
 */
static time_t
ngx_http_cache_turbo_response_sie(ngx_http_request_t *r)
{
    return ngx_http_cache_turbo_cc_delta_all(&r->headers_out.headers,
               "Cache-Control", sizeof("Cache-Control") - 1,
               "stale-if-error", sizeof("stale-if-error") - 1);
}


/*
 * P4: resolve the request Cache-Control and Pragma header values ONCE with a
 * single walk of the request header list, caching them in the ctx. nginx does
 * NOT pre-parse request Cache-Control into a discrete headers_in field (it does
 * for cookies, not for CC), so the four RFC-1 predicates below used to each call
 * header_find and re-walk the whole list — five full scans per hit. This folds
 * them to one. ctx->req_cc / ctx->req_pragma carry data == NULL when the header
 * is absent. Idempotent via req_cc_resolved.
 */
static void
ngx_http_cache_turbo_resolve_req_cc(ngx_http_request_t *r,
    ngx_http_cache_turbo_ctx_t *ctx)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;
    ngx_uint_t        i;

    if (ctx->req_cc_resolved) {
        return;
    }
    ngx_str_null(&ctx->req_cc);
    ngx_str_null(&ctx->req_pragma);
    ctx->req_cc_resolved = 1;

    /* One traversal of the request header list, capturing the first Cache-Control
     * and first Pragma (first-occurrence-wins, matching the old per-predicate
     * header_find). Stop early once both are found. */
    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (h[i].hash == 0) {
            continue;
        }
        if (ctx->req_cc.data == NULL
            && h[i].key.len == sizeof("Cache-Control") - 1
            && ngx_strncasecmp(h[i].key.data, (u_char *) "Cache-Control",
                               sizeof("Cache-Control") - 1) == 0)
        {
            ctx->req_cc = h[i].value;
        } else if (ctx->req_pragma.data == NULL
            && h[i].key.len == sizeof("Pragma") - 1
            && ngx_strncasecmp(h[i].key.data, (u_char *) "Pragma",
                               sizeof("Pragma") - 1) == 0)
        {
            ctx->req_pragma = h[i].value;
        }
        if (ctx->req_cc.data != NULL && ctx->req_pragma.data != NULL) {
            break;
        }
    }
}


/*
 * RFC 9111 §5.2.1.4 / §5.2.1.1: a request Cache-Control: no-cache (or the
 * legacy Pragma: no-cache), or a request max-age=0, means "do not reuse a
 * stored response without successful validation". max-age=0 is what browsers
 * send on a force-refresh (Ctrl-Shift-R), so honouring it is the dominant case.
 * We have no upstream validation channel for a cache hit, so the conservative-
 * correct behaviour is to skip the cache lookup and go to the origin (the fresh
 * response is still stored, refreshing the entry). max-age=N>0 / min-fresh /
 * max-stale are NOT honoured here — they need an entry-serve restructure that
 * collides with the cold-miss claim race (see audit RFC-1). Reads the CC/Pragma
 * values resolved once by resolve_req_cc(); the headers are rare so first-match
 * is fine.
 */
static ngx_int_t
ngx_http_cache_turbo_request_revalidate(ngx_http_request_t *r,
    ngx_http_cache_turbo_ctx_t *ctx)
{
    ngx_http_cache_turbo_resolve_req_cc(r, ctx);

    if (ctx->req_cc.data != NULL) {
        u_char  *v = ctx->req_cc.data, *e = ctx->req_cc.data + ctx->req_cc.len;

        if (ngx_http_cache_turbo_cc_has(v, e, "no-cache",
                sizeof("no-cache") - 1)
            || ngx_http_cache_turbo_cc_delta(v, e, "max-age",
                sizeof("max-age") - 1) == 0)
        {
            return 1;
        }
    }

    if (ctx->req_pragma.data != NULL
        && ngx_http_cache_turbo_cc_has(ctx->req_pragma.data,
               ctx->req_pragma.data + ctx->req_pragma.len,
               "no-cache", sizeof("no-cache") - 1))
    {
        return 1;
    }

    return 0;
}


/* RFC 9111 §5.2.1.7: request Cache-Control: only-if-cached — the client refuses
 * any origin contact. We may answer from L1/L2 (both are caches), but if neither
 * holds a serveable response the request gets 504 Gateway Timeout instead of
 * reaching the origin. */
static ngx_int_t
ngx_http_cache_turbo_request_only_if_cached(ngx_http_request_t *r,
    ngx_http_cache_turbo_ctx_t *ctx)
{
    ngx_http_cache_turbo_resolve_req_cc(r, ctx);
    return (ctx->req_cc.data != NULL
            && ngx_http_cache_turbo_cc_has(ctx->req_cc.data,
                   ctx->req_cc.data + ctx->req_cc.len,
                   "only-if-cached", sizeof("only-if-cached") - 1)) ? 1 : 0;
}


/* RFC 9111 §5.2.1.5: request Cache-Control: no-store — do not store this
 * request's response (the header-filter capture gate checks the flag). */
static ngx_int_t
ngx_http_cache_turbo_request_no_store(ngx_http_request_t *r,
    ngx_http_cache_turbo_ctx_t *ctx)
{
    ngx_http_cache_turbo_resolve_req_cc(r, ctx);
    return (ctx->req_cc.data != NULL
            && ngx_http_cache_turbo_cc_has(ctx->req_cc.data,
                   ctx->req_cc.data + ctx->req_cc.len,
                   "no-store", sizeof("no-store") - 1)) ? 1 : 0;
}


/*
 * RFC 9111 §5.2.1: parse the request freshness bounds once into the ctx.
 *   max-age=N   (§5.2.1.1) the client won't accept a response older than N.
 *   min-fresh=N (§5.2.1.3) it must stay fresh for at least N more seconds.
 *   max-stale[=N] (§5.2.1.2) it WILL accept a stale response, up to N seconds
 *                 past expiry (bare = any staleness).
 * Sentinels: -1 = absent. max-stale presence/bare tracked by the two bits.
 */
static void
ngx_http_cache_turbo_request_freshness_bounds(ngx_http_request_t *r,
    ngx_http_cache_turbo_ctx_t *ctx)
{
    u_char    *v, *e, *q;
    size_t     vlen;

    ctx->req_max_age = -1;
    ctx->req_min_fresh = -1;
    ctx->req_max_stale = -1;

    ngx_http_cache_turbo_resolve_req_cc(r, ctx);
    if (ctx->req_cc.data == NULL) {
        return;
    }
    v = ctx->req_cc.data;
    e = ctx->req_cc.data + ctx->req_cc.len;

    ctx->req_max_age = ngx_http_cache_turbo_cc_delta(v, e, "max-age",
                           sizeof("max-age") - 1);
    ctx->req_min_fresh = ngx_http_cache_turbo_cc_delta(v, e, "min-fresh",
                             sizeof("min-fresh") - 1);
    if (ctx->req_max_age >= 0 || ctx->req_min_fresh >= 0) {
        ctx->has_req_bounds = 1;    /* P2: a bound that can change the verdict */
    }

    q = ngx_http_cache_turbo_cc_token(v, e, "max-stale",
            sizeof("max-stale") - 1, &vlen);
    if (q != NULL) {
        ctx->req_max_stale_set = 1;
        ctx->has_req_bounds = 1;    /* P2 */
        if (vlen == 0) {
            ctx->req_max_stale_any = 1;          /* bare: accept any staleness */
        } else {
            time_t  d = ngx_http_cache_turbo_cc_delta(v, e, "max-stale",
                            sizeof("max-stale") - 1);
            if (d >= 0) {
                ctx->req_max_stale = d;
            } else {
                ctx->req_max_stale_any = 1;      /* unparseable value: be lenient */
            }
        }
    }
}


/*
 * RFC-1 serve verdict for an EXISTING entry vs the request freshness bounds.
 * fresh_ok: a fresh entry (now < fresh_until) is acceptable to this client.
 * stale_ok: a stale entry (within the serveable window) may be served.
 * `created` is read from the blob header so age is exact. The default (client
 * sent none of these directives) preserves the pre-RFC-1 behaviour: fresh hits
 * serve, stale hits serve (a cache MAY serve stale by its own policy). A client
 * that sends max-age/min-fresh (wants fresh) but NO max-stale gets no stale
 * tolerance; max-stale explicitly re-permits (and loosens) stale serving.
 */
static void
ngx_http_cache_turbo_req_serve_verdict(ngx_http_cache_turbo_ctx_t *ctx,
    time_t created, time_t now, time_t fresh_until,
    ngx_int_t *fresh_ok, ngx_int_t *stale_ok)
{
    time_t  age = now - created;

    if (age < 0) {
        age = 0;
    }

    *fresh_ok = 1;
    if (ctx->req_max_age >= 0 && age > ctx->req_max_age) {
        *fresh_ok = 0;
    }
    if (ctx->req_min_fresh >= 0 && (fresh_until - now) < ctx->req_min_fresh) {
        *fresh_ok = 0;
    }

    if (ctx->req_max_stale_set) {
        time_t  staleness = now - fresh_until;
        if (staleness < 0) {
            staleness = 0;
        }
        *stale_ok = (ctx->req_max_stale_any || staleness <= ctx->req_max_stale)
                    ? 1 : 0;
    } else if (ctx->req_max_age >= 0 || ctx->req_min_fresh >= 0) {
        *stale_ok = 0;          /* client asked for fresh, no stale tolerance */
    } else {
        *stale_ok = 1;          /* default: serve stale per cache policy */
    }
}


/* PURGE <uri> (v14): drop this URI's entry from L1 (+ L2) and answer
 * {"purged":N}. Reuses the request's own key (built via the configured
 * cache_turbo_key), so the purged slot matches what a GET would look up. The
 * location must be gated with allow/deny. */
static ngx_int_t
ngx_http_cache_turbo_purge_request(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf)
{
    uint32_t                      hash;
    ngx_int_t                     drc;
    ngx_uint_t                    purged;
    ngx_str_t                     body;
    u_char                       *p;
    ngx_http_cache_turbo_ctx_t   *ctx;
    ngx_http_cache_turbo_zone_t  *z;

    drc = ngx_http_discard_request_body(r);
    if (drc != NGX_OK) {
        return drc;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_cache_turbo_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (ngx_http_cache_turbo_build_key(r, clcf, ctx) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    z = clcf->shm_zone->data;
    hash = ngx_crc32_short(ctx->key_hash, 32);

    purged = (ngx_uint_t) clcf->l1->purge_key(z, ctx->key_hash, hash);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cache_turbo: PURGE \"%V\" key=%ui purged=%ui",
                   &r->uri, (ngx_uint_t) hash, purged);

    /* Drop from L2 too, so a purge can't be silently refilled from Redis. */
    if (clcf->backend) {
        clcf->backend->del(clcf, ctx->key_hash);
    }

    /* COR-5: a PURGE of the base URI must also invalidate every auto-Vary
     * variant. Variants are stored under variant keys (base material + the
     * folded axis values), not the base key, so the base purge above never
     * touches them. Two strategies by L2 capability:
     *   - Redis (purge_tag): the variants were SADD'd into a per-base index set
     *     at store time. SMEMBERS it and drop every variant from L1 + L2 + the
     *     set (async). Delete the node-local marker so this node stops resolving
     *     to the now-removed variants; the keyspace resets cleanly to gen 0.
     *   - L1-only / memcached (no enumerable index): bump the marker generation
     *     so old-generation variants are orphaned (new requests key on gen+1;
     *     orphans age out via L1 LRU + TTL / memcached value TTL). */
    if (clcf->auto_vary) {
        u_char                        mk[32];
        ngx_int_t                     bits = 0;
        ngx_uint_t                    mgen = 0;
        ngx_uint_t                    next_gen;
        time_t                        mttl = 0;
        ngx_uint_t                    have_marker = 0;
        ngx_http_cache_turbo_node_t  *m;

        ngx_http_cache_turbo_marker_hash(&ctx->cache_key, mk);
        ngx_shmtx_lock(&z->shpool->mutex);
        m = clcf->l1->lookup(z, mk, ngx_crc32_short(mk, 32));
        if (m != NULL && m->data != NULL
            && m->len >= NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 1)
        {
            ngx_http_cache_turbo_blob_hdr_t  mh;
            if (ngx_http_cache_turbo_blob_validate(m->data, m->len, &mh,
                    NULL, NULL) == NGX_OK)
            {
                have_marker = 1;
                bits = m->data[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE];
                if (m->len >= NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 2) {
                    mgen = m->data[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 1];
                }
                mttl = (time_t) mh.fresh_ttl;
            }
        }
        ngx_shmtx_unlock(&z->shpool->mutex);

        if (clcf->backend && clcf->backend->purge_tag) {
            u_char                            vname[1 + 64];
            size_t                            vlen;
            ngx_http_cache_turbo_tagpurge_t  *tp;
            ngx_int_t                         prc;

            (void) clcf->l1->purge_key(z, mk, ngx_crc32_short(mk, 32));

            tp = ngx_pcalloc(r->pool, sizeof(*tp));
            if (tp != NULL) {
                vlen = ngx_http_cache_turbo_variant_index_name(&ctx->cache_key,
                                                               vname);
                tp->clcf = clcf;
                tp->zone = z;
                tp->tag.data = ngx_pnalloc(r->pool, vlen);
                if (tp->tag.data != NULL) {
                    ngx_memcpy(tp->tag.data, vname, vlen);
                    tp->tag.len = vlen;
                    prc = clcf->backend->purge_tag(r, clcf, vname, vlen,
                              ngx_http_cache_turbo_tag_purge_complete, tp);
                    if (prc == NGX_DONE) {
                        /* parked; the completion drops every variant + the index
                         * set and sends {"purged":N}. */
                        return NGX_DONE;
                    }
                }
            }
            /* could not launch (alloc / L2 down): fall through to the sync
             * base-only reply below. */

        } else if (have_marker) {
            /* AUD-GEN1: wrap explicitly, and NEVER land back on 0. gen 0 is
             * the permanent "never purged" identity (default when no marker
             * exists yet); folding it unconditionally (see variant_hash)
             * stops it colliding with the pre-COR-5 untagged keyspace, but
             * that alone does not stop THIS purge sequence from reproducing
             * its OWN gen-0 identity every 256 purges -- 256 & 0xFF == 0,
             * numerically indistinguishable from "never purged" once stored
             * in one byte, so a request racing the wrap would resolve back to
             * whatever is still resident under the base's original,
             * pre-first-purge key (proven by a real 256-purge round trip
             * against the unpatched arithmetic, not just reasoned about).
             * Skipping 0 on wrap makes 0 permanently exclusive to "never
             * purged": once a base has been purged at all, its generation can
             * never again equal the identity a fresh, unpurged base uses.
             * The residual (generation N colliding with N+255, still a
             * 1-byte counter) is the accepted trade-off the ledger row
             * documents; this closes the specific, highest-risk collision --
             * the one with the longest-lived, most-likely-still-resident
             * data. */
            next_gen = (mgen + 1) & 0xFF;
            if (next_gen == 0) {
                next_gen = 1;
            }
            ngx_http_cache_turbo_marker_store(clcf, z, &ctx->cache_key, bits,
                                              next_gen, mttl);
            purged++;
        }
    }

    p = ngx_pnalloc(r->pool, sizeof("{\"purged\":4294967295}\n"));
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    body.data = p;
    body.len = ngx_sprintf(p, "{\"purged\":%ui}\n", purged) - p;

    /* PRECONTENT phase (after ACCESS/allow-deny): send the reply, finalize, and
     * return NGX_DONE so the phase engine stops here instead of falling through
     * to the content handler / proxy_pass (same pattern as serve()). */
    drc = ngx_http_cache_turbo_send_json(r, NGX_HTTP_OK, &body);
    ngx_http_finalize_request(r, drc);
    return NGX_DONE;
}


/* >>> FUZZ-EXTRACT auto-classify BEGIN (ci/fuzz/extract_auto_classify.sh) <<< */
/*
 * Auto-classify preset registry. Each row is one CMS backend: NULL-terminated
 * lists of request-Cookie name substrings, r->uri prefixes, and query args
 * that mark a request as a dynamic surface that must NOT be cached. A query-arg
 * entry is either a bare "name" (presence alone is the signal) or "name=value"
 * (the argument must carry exactly that value) — the single-entry-script forums
 * route every page through one `action`/`do` argument, so for them only the
 * VALUE separates a login from an ordinary read. Adding a
 * backend is one row here — no new code path. A row is active when
 * (clcf->backend_presets & row->bit). `generic` (bare `auto`) is the union of
 * WP/Woo/Joomla, whose cookie/URI namespaces are disjoint, so stacking them
 * cannot collide. A backend with generic-English URIs (xenforo, discourse,
 * drupal, ...) stays out of that union and must be named explicitly. Curated
 * heuristic, not a CMS fingerprint.
 *
 * `cookies` is matched as a SUBSTRING of the request Cookie header — presence
 * only, no value predicate. Two consequences the rows below turn on: a cookie
 * an application also issues to GUESTS can never be a bypass rule (it would
 * match most traffic and take the hit rate to zero), and an application whose
 * cookie NAME is per-install (a hash, or an operator-set prefix) cannot be
 * matched at all. Where either applies the row ships no cookie rule and says
 * so, rather than shipping one that does not work; docs/<app>.md then tells the
 * operator to add their own cache_turbo_bypass.
 */
typedef struct ngx_http_cache_turbo_cookie_pred_s
               ngx_http_cache_turbo_cookie_pred_t;

#define NGX_HTTP_CACHE_TURBO_CVOP_NE        0   /* bypass when value != literal */
#define NGX_HTTP_CACHE_TURBO_CVOP_EQ        1   /* bypass when value == literal */
#define NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY  2   /* bypass when value is non-empty */

struct ngx_http_cache_turbo_cookie_pred_s {
    const char  *name_suffix;  /* cookie NAME must END with this (prefix-agnostic) */
    ngx_uint_t   op;           /* NGX_HTTP_CACHE_TURBO_CVOP_*                       */
    const char  *value;        /* literal compared against, NULL for NONEMPTY       */
};

typedef struct {
    ngx_uint_t           bit;
    const char *const   *cookies;  /* substrings in the request Cookie header */
    const char *const   *uris;     /* r->uri prefixes                         */
    const char *const   *args;     /* "name" (presence) or "name=value"       */

    /* Cookie VALUE predicates (tier 2). NULL for presets that classify on name
     * presence alone. An application that issues the SAME cookie to guests and
     * members, and encodes the difference in the value, is unclassifiable by the
     * `cookies` list above and needs a row here instead. See the predicate
     * engine below for why the name is matched by SUFFIX and why an unparseable
     * cookie fails closed to bypass. */
    const ngx_http_cache_turbo_cookie_pred_t  *cookie_preds;

    /*
     * Cookie VALUE KEYING (tier 3). NULL-terminated list of cookie names whose
     * VALUE is folded into the cache key, so visitors carrying different values
     * get different cache entries instead of bypassing the cache altogether.
     *
     * This is for a cookie that is a SEGMENT FINGERPRINT, not an identity: it
     * marks which shared variant of a page the visitor should see (customer
     * group / currency / store view), and many visitors legitimately share one
     * value. Magento's X-Magento-Vary is the type case, and Magento's own
     * reference Varnish VCL keys on exactly this value (vcl_hash: hash_data of
     * the regsub'd cookie) rather than passing.
     *
     * KEY, never BYPASS, and never PRESENCE. Keying on PRESENCE would collapse
     * every non-default visitor into one bucket and is a cross-user leak; that
     * is a different mistake from keying on the VALUE, and the two must not be
     * confused. Bypassing on presence is safe but throws away the hit rate for
     * every non-default ANONYMOUS visitor (guest in a second currency, second
     * store view), who has no private data at all.
     *
     * A preset that lists a key cookie DEPENDS on the Set-Cookie floor in
     * ngx_http_cache_turbo_response_cacheable(): a request with no key cookie
     * hashes to the ANONYMOUS entry, and if the response ESTABLISHES the segment
     * (Set-Cookie: <keycookie>=...) then storing that body under the anonymous
     * key poisons it for every anonymous visitor. The floor refuses to store ANY
     * Set-Cookie response, unconditionally, which covers that case exactly.
     * DO NOT relax that floor without adding a preset-level veto here first.
     */
    const char *const  *key_cookies;
} ngx_http_cache_turbo_preset_t;

/*
 * WordPress. The cookie tier is the load-bearing one: wordpress_logged_in_ is
 * the login cookie, wp-postpass_ unlocks a password-protected post, and
 * comment_author_ marks a commenter who must see their own pending comment.
 * All three are matched as PREFIXES because the wire names carry a site-hash
 * suffix (wordpress_logged_in_<sitehash>) — which is also why the
 * `$cookie_wordpress_logged_in_` form seen in a lot of third-party configs is a
 * permanent no-op: nginx's $cookie_NAME is an EXACT lookup.
 *
 * `preview` renders an UNPUBLISHED revision for an author who holds a valid
 * nonce, so it must never be stored.
 *
 * `rest_route` IS THE REST API, and listing /wp-json/ without it covered only
 * half the surface. The two are not a path and a fallback — the path is sugar
 * over the argument. wp-includes/rest-api.php registers
 *
 *     add_rewrite_rule( '^' . rest_get_url_prefix() . '/(.*)?',
 *                       'index.php?rest_route=/$matches[1]', 'top' );
 *
 * so /wp-json/wp/v2/users/me is REWRITTEN to index.php?rest_route=/wp/v2/users/me,
 * and rest_api_loaded() dispatches only when that query var is set:
 *
 *     if ( empty( $GLOBALS['wp']->query_vars['rest_route'] ) ) { return; }
 *
 * With plain permalinks — or from any client that calls get_rest_url() while
 * they are off, which emits the add_query_arg( 'rest_route', ... ) form — the
 * request never has a /wp-json/ path at all. The URI rule saw nothing and
 * `GET /?rest_route=/wp/v2/users/me` was cacheable. This is the same surface
 * addressed two ways with only one way guarded: a parser differential, not a
 * missing corner case.
 *
 * Matched as a bare NAME, so the whole REST API bypasses, public endpoints
 * included. That is deliberate and matches how /wp-json/ is already treated
 * (docs/wordpress.md calls the wholesale bypass out as a known hit-rate cost).
 * An operator who wants a public endpoint cached gives it its own location.
 *
 * `s` — SITE SEARCH — IS DELIBERATELY ABSENT, and it used to be here. Every
 * logged-out visitor searching "foo" gets the same page: search results are
 * dynamic but ANONYMOUS-IDENTICAL, which is shared, hot, and exactly what a
 * cache is for. A logged-in editor whose results include drafts and private
 * posts is already bypassed by wordpress_logged_in_ on the cookie tier, so the
 * arg rule bought no safety at all — only hit-rate loss.
 *
 * It was also actively harmful. A bypass returns NGX_DECLINED BEFORE the
 * single-flight lock, so miss-collapsing does not apply to a bypassed request:
 * with `s` listed, a flood of `?s=<anything>` put 100% of its load on the
 * origin, uncollapsed, on the single most expensive query WordPress runs (a
 * full-text LIKE scan of wp_posts). Caching search at least collapses repeats.
 *
 * The objection to caching it is unbounded keyspace — `?s=<random>` mints a new
 * entry each time and can LRU-evict the zone. That objection is real, and it
 * has a directive: `cache_turbo_min_uses N` stores an entry only after N
 * misses, so a flood of once-seen search terms never mints one while the terms
 * real visitors repeat still cache. That is the control to reach for, and it is
 * strictly better than the arg rule was — it bounds cardinality WITHOUT handing
 * the origin an uncollapsed flood.
 *
 * It is also not specific to search: the default key includes unparsed_uri, so
 * EVERY query-bearing URL has the same shape. Singling out search did not close
 * that hole; it just moved the cost onto the database.
 *
 * This now matches ct_wagtail_* (/search/ deliberately absent, same reasoning)
 * and the mediawiki registry's refusal of a blanket action= rule. Those two
 * comments argue this case at length; the WordPress row was the outlier and it
 * carried no comment explaining why.
 */
static const char *const  ct_wp_cookies[] = {
    "wordpress_logged_in_", "wp-postpass_", "comment_author_", NULL };
static const char *const  ct_wp_uris[] = {
    "/wp-admin/", "/wp-login.php", "/wp-cron.php", "/xmlrpc.php",
    "/wp-json/", NULL };
static const char *const  ct_wp_args[] = { "preview", "rest_route", NULL };

static const char *const  ct_woo_cookies[] = {
    "woocommerce_items_in_cart", "woocommerce_cart_hash",
    "wp_woocommerce_session_", NULL };
/*
 * THESE THREE SLUGS ARE ENGLISH DEFAULTS, NOT CONSTANTS, and on a non-English
 * store they match NOTHING. WC_Install::create_pages() declares them as
 * TRANSLATABLE strings — _x( 'cart', 'Page slug', 'woocommerce' ) — and wraps
 * the whole page-creation block in wc_switch_to_site_locale() precisely so that
 * "pages are created in the correct language". So a German store gets
 * /warenkorb, /kasse, /mein-konto AT INSTALL TIME, by design. This is not admin
 * drift that a careful operator avoids; it is the shipped behaviour for every
 * locale but one. An admin can also rename the pages afterwards, and the
 * `woocommerce_create_pages` filter can replace the set outright.
 *
 * So DO NOT TREAT THE URI TIER AS THE GUARD HERE. It is a convenience for the
 * default-locale majority. What actually holds on a translated store is the
 * cookie tier above plus the STACKED wordpress preset — a logged-in customer
 * carries wordpress_logged_in_, and a shopper with a cart carries
 * woocommerce_items_in_cart / wp_woocommerce_session_.
 *
 * That stacking is not optional, and this is the case that proves it: a
 * `cache_turbo_backend woocommerce;` used ALONE on a translated store serves a
 * logged-in customer with an EMPTY cart — no woo cookie, no URI match, no
 * wordpress preset — a CACHED /mein-konto. Every WooCommerce doc says to stack
 * `wordpress woocommerce`; this is why.
 *
 * Locale slugs are deliberately NOT enumerated here. The set is unbounded (one
 * per WooCommerce translation, plus whatever the operator typed), so an
 * operator on a translated store adds their own:
 *     cache_turbo_bypass_uri /warenkorb /kasse /mein-konto;
 * See docs/woocommerce.md.
 */
static const char *const  ct_woo_uris[] = {
    "/cart", "/checkout", "/my-account", NULL };
/*
 * wc-ajax is LOAD-BEARING, not decoration — it is the one WooCommerce rule that
 * no URI prefix can substitute for. WC's AJAX endpoints do not live under a path
 * of their own: they ride on WHATEVER page the shopper is on, as a query arg
 * (includes/class-wc-ajax.php::get_endpoint() -> "currentpageurl?wc-ajax=name").
 * So `/?wc-ajax=get_refreshed_fragments` is a request to the CACHED HOME PAGE,
 * and none of /cart, /checkout, /my-account match it.
 *
 * The response is that shopper's cart-fragment HTML. Store it and the next
 * visitor is served someone else's cart. This is the only cross-customer leak
 * path the URI rules cannot close, which is why it is an ARG rule.
 */
static const char *const  ct_woo_args[] = { "wc-ajax", NULL };

/*
 * Joomla. One cookie, and it is a PARTIAL guard — read the caveat.
 *
 * `joomla_remember_me_` is a real fixed prefix ('joomla_remember_me_' .
 * UserHelper::getShortHashedUserAgent()), set only for an authenticated user and
 * cleared on logout. The per-install part is the SUFFIX, so the prefix is
 * matchable — this is the one Joomla cookie that passes both tests.
 *
 * WHAT IT DOES NOT COVER, and this is the important half: it is only present for
 * users who ticked "Remember Me". A normally-logged-in frontend user carries only
 * the SESSION cookie, whose NAME is md5($secret . $session_name) — a per-install
 * hash with no fixed substring anywhere in it. That user is invisible to this
 * matcher. So joomla_remember_me_ raises the floor; it does not make the preset
 * safe on its own.
 *
 * The real guard for a logged-in Joomla user therefore remains Joomla's own
 * Cache-Control (core's page cache plugin itself gates on
 * !$app->getIdentity()->guest), plus the /administrator/ URI rule. An operator
 * running a site with frontend logins MUST add their own cache_turbo_bypass on
 * their install's session-cookie name — docs/joomla.md shows how to find it.
 * Do not read the presence of a cookie rule here as "joomla is now handled".
 */
static const char *const  ct_joomla_cookies[] = { "joomla_remember_me_", NULL };
static const char *const  ct_joomla_uris[] = { "/administrator/", NULL };
static const char *const  ct_joomla_args[] = { NULL };

/*
 * XenForo (XF2). READ THIS BEFORE TOUCHING THE COOKIE LIST.
 *
 * STOCK XF2 HAS NO LOGIN-ONLY COOKIE. This is the central, awkward fact about
 * this preset, and an earlier version of it got this wrong and LEAKED.
 *
 * The trap: `xf_user` looks like the login cookie. It is not — it is the
 * REMEMBER-ME cookie. ControllerPlugin/Login.php calls completeLogin($user,
 * $remember) and only mints `xf_user` inside `if ($remember)`. "Stay logged in"
 * is UNTICKED BY DEFAULT, so an ordinary member who just types their password
 * carries NO xf_user at all. Matching only xf_user + xf_session_admin therefore
 * misses the common login entirely: that member's authenticated page matched no
 * bypass rule, got stored, and was served to strangers.
 *
 * So `xf_session` is in the list, and it has to be, even though XF issues it to
 * guests. That is the whole trade:
 *
 *   - XF2's session IS lazy (Pub/App.php only saves when hasData() is true), so
 *     a clean first-time guest who stores nothing gets NO cookie and still
 *     caches. This is why the rule is not an instant hit-rate zero.
 *   - BUT guests acquire a session routinely: LOGGING OUT writes userId=0 into
 *     the session, a pending 2FA login writes tfaLoginUserId, captcha and spam
 *     state write too. Any of those, and that guest is uncacheable from then on.
 *
 * Net: correct, with an unpredictable and possibly poor hit rate. That is the
 * only cookie-only option that is not a leak. Do not "optimise" xf_session back
 * out of this list — that is the leak, and it is how this preset shipped before.
 *
 * `xf_lscxf_logged_in` is the LiteSpeed XF2 plugin's cookie (its Login.php
 * override sets it IGNORING $remember, with the verbatim comment "Set custom
 * cookie to better track logged in state when 'Stay logged in' is unchecked").
 * A vendor writing PHP to create this cookie is the proof that stock XF has
 * none. On a forum running that plugin it is the precise login signal, and the
 * operator can then narrow the preset by dropping xf_session with their own
 * config. Harmless when the plugin is absent (the cookie simply never appears).
 * The DigitalPoint Cloudflare app sets an equivalent <prefix>logged_in cookie
 * (xf_logged_in on the stock prefix) for the same purpose; an operator running
 * that instead can add it to their own bypass the same way.
 *
 * PRESENTATION VARIANTS ARE KEY COOKIES, NOT BYPASS (tier 3). These are shared
 * across everyone who picked the same value, so folding the VALUE into the key
 * gives one cache entry per variant instead of dropping the visitor from cache
 * (bypassing on them would zero caching for anyone on a dark theme):
 *   - xf_style_id       — selected style on a MULTI-STYLE board. This is the one
 *                         LiteSpeed's own addon varies on (E=...,xf_style_id,...).
 *   - xf_style_variation — light/dark/system VARIATION within a style. NEW in XF
 *                         2.3's dark mode; set client-side by JS when the visitor
 *                         picks a scheme. Distinct cookie from xf_style_id — a 2.3
 *                         board with dark mode needs BOTH keyed.
 *   - xf_language_id    — selected language on a multi-language board.
 * A single-style, single-language, no-dark-mode board shares one value for each
 * and loses nothing by keying on them (one bucket). xf_consent (guest-set, and
 * it DOES change embed HTML: XF renders a consent placeholder in place of a
 * third-party embed until accepted) is deliberately NOT keyed here — it would
 * fragment the cache two ways on every embed-bearing page. docs/xenforo.md tells
 * an operator who needs it to add xf_consent with their own cache_turbo_key_cookie.
 *
 * `/api/` is the XF REST API (docs.xenforo.com/manual/reference/rest-api). It
 * authenticates on the XF-Api-Key REQUEST HEADER, never a cookie or the standard
 * Authorization header — so an API client's private response carries NONE of the
 * bypass cookies above, and a shared cache keyed on URL alone would store one
 * client's data and serve it to the next. The header is invisible to the cookie
 * rules, so /api/ must bypass on the URI. (This is the same class of bug as the
 * xf_session leak: a real cross-CLIENT leak, closed here on the URI.)
 *
 * `_xfToken` is XF's CSRF token as a QUERY ARG (stock XF hangs it off GET links
 * such as the logout link and the style-variation switcher). Its value is
 * per-session, so any GET carrying it is per-user and must never be cached or
 * served across visitors. The bare `t` alias XF also accepts is NOT matched: it
 * is too generic (tracking params, timestamps) to bypass safely on a preset, and
 * the surfaces that use it (logout, misc/style-variation) are already covered by
 * the /logout and /misc URI rules. An operator with a custom GET route that
 * takes `t` adds it with their own cache_turbo_bypass.
 *
 * All names honour $config['cookie']['prefix'] (default "xf_"); a forum that
 * changed the prefix needs its own cache_turbo_bypass. URIs are the XF2 dynamic
 * surfaces: auth flows, the admin and installer entry scripts, /api/ (REST), and
 * /misc (the style/language picker + inline dispatch endpoints). /contact is NOT
 * a stock XF2 route — the real one is misc/contact, already covered by /misc.
 * /conversations is the pre-2.3 DM route; XF 2.3 renamed it to /direct-messages
 * and permanently redirects the old path, so BOTH are listed (the redirect is a
 * cacheable object we do not want captured under a member's session either).
 */
static const char *const  ct_xf_cookies[] = {
    "xf_session", "xf_user", "xf_session_admin", "xf_lscxf_logged_in", NULL };
static const char *const  ct_xf_uris[] = {
    "/admin.php", "/install/", "/api/", "/login", "/logout", "/lost-password",
    "/register", "/account", "/conversations", "/direct-messages",
    "/misc", NULL };
static const char *const  ct_xf_args[] = { "_xfToken", NULL };
static const char *const  ct_xf_key_cookies[] = {
    "xf_style_id", "xf_style_variation", "xf_language_id", NULL };

/*
 * Discourse. One cookie: `_t`, the auth token (lib/auth/default_current_user_
 * provider.rb — TOKEN_COOKIE, deleted outright for anonymous requests, and the
 * exact test Discourse's own anon cache uses). `_forum_session` is the Rails
 * session cookie and is issued to EVERY visitor including guests, so it is the
 * xf_session trap wearing a different hat: bypassing on it would drop all guest
 * traffic out of the cache. `theme_ids` / `forced_color_mode` are presentation
 * variants (Discourse folds them into its own cache KEY) — they belong in
 * cache_turbo_key, not here. `_t` is renameable via DISCOURSE_TOKEN_COOKIE; a
 * site that renamed it needs its own cache_turbo_bypass.
 *
 * Note Discourse ships its own anonymous page cache and already sends
 * Cache-Control: no-store on authenticated responses, so this preset is mostly
 * defence-in-depth. The api_key/api_username args mark API calls.
 *
 * The rule is "_t=", not "_t": a two-character substring would match inside
 * unrelated names and values (_gat, utm_term=...). Keeping the "=" pins it to a
 * name/value boundary. It can still over-match a cookie literally named
 * "<something>_t" (e.g. "list_t"), which costs a needless bypass but never
 * leaks; a substring matcher cannot do better, and "; _t=" would miss the case
 * where _t is the first cookie in the header.
 *
 * `/u/` (public user profiles) is deliberately ABSENT: profiles are anonymous-
 * identical and Discourse's own anon cache caches them, so bypassing was a pure
 * hit-rate loss. The route is `/drafts` (plural — resources :drafts in
 * config/routes.rb); the singular `/draft` shipped earlier matched only via the
 * old boundary-less prefix test and stops matching `/drafts.json` under the
 * segment-boundary matcher, so it is corrected to the real name here.
 */
static const char *const  ct_discourse_cookies[] = { "_t=", NULL };
static const char *const  ct_discourse_uris[] = {
    "/admin", "/session", "/auth/", "/login", "/logout", "/signup",
    "/my/", "/message-bus/", "/drafts", "/presence/", "/notifications",
    "/user_actions", NULL };
static const char *const  ct_discourse_args[] = {
    "api_key", "api_username", NULL };

/*
 * phpBB 3.x. NO COOKIE RULE — and that is deliberate, not an omission.
 *
 * phpBB's cookie names are <cookie_name>_u / _k / _sid where the prefix is set
 * in the ACP and randomised by many installers, so no substring is shippable
 * (the joomla problem). Worse, session_create() sets all three for every
 * non-bot visitor INCLUDING guests (phpbb/session.php — the set_cookie() block
 * is guarded on $bot, not on login state; an anonymous visitor gets _u=1, the
 * ANONYMOUS user id, plus a real _sid). Telling a logged-in user apart from a
 * guest therefore requires a VALUE test (_u != 1, or _k non-empty), and this
 * registry matches cookie-name substrings only — presence, never value. A _u or
 * _sid rule here would match every anonymous visitor and take the hit rate to
 * zero while still not identifying an authenticated one.
 *
 * So: ship the URI rules (phpBB's dynamic surface is .php entry scripts, which
 * are at least distinctive), ship no cookie rule, and document loudly that the
 * operator MUST add their own cache_turbo_bypass. See docs/phpbb.md.
 */
static const char *const  ct_phpbb_cookies[] = { NULL };
static const char *const  ct_phpbb_uris[] = {
    "/ucp.php", "/mcp.php", "/adm/", "/posting.php", "/memberlist.php",
    "/search.php", "/report.php", NULL };
static const char *const  ct_phpbb_args[] = { "sid", NULL };

/*
 * phpBB VALUE predicate — the cookie rule the comment above says cannot exist as
 * a NAME rule. Verified against phpbb/phpbb source, not inferred:
 *
 *   includes/constants.php            define('ANONYMOUS', 1);
 *   phpbb/session.php  session_create()
 *       guest:  $this->cookie_data['u'] = ($bot) ? $bot : ANONYMOUS;   // => 1
 *       member: $this->cookie_data['u'] = $this->data['user_id'];      // never 1
 *   phpbb/session.php  set_cookie()
 *       $name_data = rawurlencode($config['cookie_name'] . '_' . $name) . '=' ...
 *
 * So EVERY non-bot visitor carries <cookie_name>_u; a guest's holds the literal
 * 1 (ANONYMOUS is a reserved user row, so a real account never has user_id 1),
 * and a member's holds their id. NE against "1" separates them exactly, which a
 * presence rule cannot do — that is why this preset shipped with no cookie rule
 * and told the operator to hand-write a bypass.
 *
 * THE NAME IS MATCHED BY SUFFIX because the prefix is an ACP setting
 * (config 'cookie_name', default "phpbb", so the wire name is "phpbb_u").
 * Installers randomise it and any admin hosting two boards on one domain changes
 * it. A literal-name rule silently stops matching on such a board — and a bypass
 * rule that stops matching caches the member's page and serves it to strangers.
 * Suffix "_u" is prefix-agnostic. It can over-match an unrelated cookie ending
 * in _u (a needless bypass, never a leak): the safe direction.
 *
 * Absent _u => no opinion => cacheable. Correct: a visitor with no phpBB cookie
 * has no session and is a guest.
 *
 * Known, accepted: _u is attacker-supplied, so anyone can send <x>_u=999 and
 * force their own request to bypass. That is a self-inflicted cache miss, not a
 * leak. It is also a cache-flooding lever, but bounded — bypassed requests are
 * never stored, so it costs origin traffic, not cache keyspace.
 */
static const ngx_http_cache_turbo_cookie_pred_t  ct_phpbb_preds[] = {
    { "_u", NGX_HTTP_CACHE_TURBO_CVOP_NE, "1" },
    { NULL, 0, NULL }
};

/*
 * Drupal 9/10/11. Cookie rule: the "SESS" substring, which covers BOTH
 * SESS<hash> and SSESS<hash> (the TLS variant) in one entry.
 *
 * THIS USED TO SHIP NO COOKIE RULE. That was a LEAK, and the reasoning behind it
 * was factually wrong. The old comment claimed "anonymous readers get no session
 * cookie at all", so the Cache-Control floor alone was enough. Drupal does not
 * work that way: it opens a session for an ANONYMOUS user as soon as anything
 * writes to $_SESSION, and core's own NoSessionOpen docblock names the everyday
 * cases — a status message queued by a form submission, and cart contents. Once
 * that happens the visitor holds SESS<hash>, and a logged-IN user holds the same
 * cookie shape. With no cookie rule, an authenticated response could be stored
 * and served to a stranger the moment the Cache-Control floor was not there to
 * catch it (`cache_turbo_cache_control ignore` removes it, and the README
 * recommends that mode for some origins). Correctness cannot rest on that floor.
 *
 * THE KNOWN COST, accepted deliberately: "SESS" is a substring of PHPSESSID and
 * JSESSIONID, so on a box that co-hosts another PHP or Java app under the same
 * server block, this rule also bypasses on THAT app's session cookie. That is a
 * hit-rate loss, never a leak — and a hit-rate loss on a co-hosted app is not a
 * reason to keep leaking on the Drupal one. An operator who cares can narrow it
 * with their own cache_turbo_bypass $cookie_SESS<their-hash>; see docs/drupal.md.
 *
 * The hash is per-install (derived from the hostname — Core/Session/
 * SessionConfiguration.php), so "SESS" is the ONLY shippable literal; matching
 * the full name is impossible.
 *
 * NOT NO_CACHE. It looks like the obvious addition — it is a fixed literal and it
 * appears in every canonical Drupal VCL — but it is CONTRIB, not core (zero hits
 * in the Drupal 11 core tree; it is Pressflow/Varnish heritage carried by modules
 * like cookie_cache_bypass_adv), and it is set FOR LOGGED-OUT visitors by design
 * (that is its whole purpose: force a cache bypass for a guest who must see fresh
 * content). Matching it costs hits and buys no safety.
 *
 * Drupal still defends itself — `private, must-revalidate` on every authenticated
 * response (EventSubscriber/FinishResponseSubscriber.php) — but that is now
 * defence-in-depth behind the cookie rule, which is the correct ordering.
 */
static const char *const  ct_drupal_cookies[] = { "SESS", NULL };
/*
 * /jsonapi and /oauth are the HEADER-AUTHENTICATED surfaces. The cookie tier
 * cannot see them at all: an API client sends `Authorization: Bearer ...` and
 * no SESS cookie, so every cookie rule above is structurally blind to it.
 *
 *   /jsonapi  core's JSON:API module. The prefix is a container parameter,
 *             `jsonapi.base_path: /jsonapi` (core/modules/jsonapi/
 *             jsonapi.services.yml). It exposes every entity type the site has,
 *             filtered by the requesting account's permissions.
 *   /oauth    simple_oauth, which is contrib rather than core but is the
 *             de-facto OAuth2/OIDC provider for Drupal. Its routes are
 *             /oauth/token, /oauth/authorize, /oauth/userinfo, /oauth/debug,
 *             /oauth/jwks (simple_oauth.routing.yml).
 *
 * /oauth/userinfo is the one that makes this a leak rather than a nicety: it is
 * a GET, authenticated purely by the bearer token, and it returns the token
 * holder's profile. Store that response and the next caller is handed someone
 * else's identity. /oauth/debug has the same shape for token metadata. The
 * token endpoint itself is a POST and RFC 6749 §5.1 requires `no-store` on it,
 * so it was never the interesting one.
 *
 * Core REST (?_format=json on an arbitrary entity path) is NOT coverable by a
 * prefix — it rides on ordinary node URLs. The cookie tier catches the
 * session-authenticated case; a bearer-authenticated core-REST client is not
 * catchable here and is called out in docs/drupal.md.
 */
static const char *const  ct_drupal_uris[] = {
    "/user", "/admin", "/node/add", "/system/", "/core/install.php",
    "/jsonapi", "/oauth", NULL };
static const char *const  ct_drupal_args[] = { NULL };

/*
 * MediaWiki. Cookie prefix is $wgCookiePrefix, which DEFAULTS TO THE DATABASE
 * NAME — so, as with joomla, there is no shippable prefix. What is shippable is
 * the SUFFIX: the identity cookies are <prefix>UserID / <prefix>UserName /
 * <prefix>Token / <prefix>_session, and those tails are distinctive enough to
 * match on.
 *
 * MATCH WHAT UPSTREAM MATCHES. MediaWiki's own getVaryCookies() says it plainly:
 *
 *     "Vary on token and session because those are the real authn determiners.
 *      UserID and UserName don't matter without those."
 *
 * So `Token=` and `_session=` are the load-bearing pair, and they are what is
 * shipped. `UserID=` is kept as a cheap belt-and-braces (it is cleared for an
 * anonymous user, so it costs nothing).
 *
 * `UserName=` IS DELIBERATELY NOT MATCHED, and this is not an oversight —
 * unpersistSession() deliberately does NOT clear it on logout, because it
 * pre-fills the login form. So EVERY visitor who has ever logged in keeps
 * sending <prefix>UserName forever, long after they are anonymous again.
 * Bypassing on it is a permanent hit-rate loss for that visitor with zero safety
 * gain — they are, by then, exactly the shared anonymous reader the cache exists
 * for. It used to be in this list; removing it is a pure win.
 *
 * `_session=` is matched even though an anonymous visitor who merely interacts
 * (edit preview, CSRF token) can acquire one. That is the xf_session trade in
 * miniature and it is the right side of it: upstream names it a real authn
 * determiner, and a bypassed guest costs hits while a cached member leaks.
 *
 * MediaWiki's dynamic surface is in the QUERY ARGS, not the path: /wiki/<Title>
 * is the cacheable read path and /index.php?action=... is the dynamic one. Only
 * the MUTATING actions are listed, enumerated from ActionFactory::CORE_ACTIONS.
 * action=view, =history, =raw, =render, =info, =credits, diff= and oldid= are
 * all deliberately absent — they are deterministic, shared, hot, and perfectly
 * cacheable; bypassing them is a measurable hit-rate loss. veaction= is the
 * VisualEditor entry point and is always dynamic. printable= is a presentation
 * variant and belongs in cache_turbo_key.
 *
 * THIS LIST USED TO BE EMPTY while the comment above claimed it was populated.
 * The rows are new; what follows is why the floor that covered for them is not
 * sufficient on its own.
 *
 * MediaWiki's non-view Cache-Control floor is DEFAULT-DENY, and much stronger
 * than "mutating actions are marked private". OutputPage::$mCdnMaxage starts at
 * 0 (Output/OutputPage.php), and core raises it in exactly one place —
 * Actions/ActionEntryPoint.php::performAction():
 *
 *     if ( UseCdn ) {
 *         if ( $request->matchURLForCDN( $htmlCacheUpdater->getUrls( $title ) ) )
 *             $output->setCdnMaxage( CdnMaxAge );
 *         elseif ( $action instanceof ViewAction )
 *             $output->setCdnMaxage( 3600 );
 *     }
 *
 * So a nonzero s-maxage requires a ViewAction or an exact match against the
 * title's PURGEABLE canonical URLs — an ?action= URL is neither. Every other
 * action falls to `$privateReason = 'no-maxage'` in sendCacheControl() and gets
 * `private, must-revalidate, max-age=0`. None of those conditions is
 * identity-dependent, so this holds for ANONYMOUS requesters too — that was the
 * untested half of the claim, and it checks out. With UseCdn off, the same
 * function takes `$privateReason = 'config'` and everything is private anyway.
 *
 * THE ROWS ARE STILL SHIPPED, for the drupal reason (see ct_drupal_cookies):
 * `cache_turbo_cache_control ignore` switches that floor off, and correctness
 * cannot rest on a floor an operator can remove. The cost of carrying them is
 * ~zero — the read path is /wiki/<Title> with no action argument at all, and
 * every hot ?action= value is deliberately NOT listed.
 *
 * Upstream's own recommended Varnish VCL does lean purely on cookies plus
 * Cache-Control with no path rules — and that remains true of the PATH tier
 * here, which is empty. These are argument rules, not path rules.
 *
 * THERE ARE NO URI RULES, and that is the whole point — it is what "no path
 * rules" above actually means. Three used to be here; all three were wrong:
 *
 *   /index.php  On a STOCK wiki $wgArticlePath is /index.php?title=Foo (or
 *               /index.php/Foo) — i.e. /index.php IS the article read path. This
 *               rule bypassed 100% of article reads on any wiki without short-URL
 *               rewrites. It was the single worst rule in the registry.
 *   /load.php   ResourceLoader: versioned, long-TTL JS/CSS bundles — the hottest
 *               cacheable objects on the site.
 *   /api.php    Same class.
 *
 * Wikimedia's production VCL does not merely cache the latter two, it RING-FENCES
 * them, by ticket number, against a rule that would have made them private:
 *   // Only apply to pages. Don't steal cachability of api.php, load.php, etc.
 *   // (T102898, T113007)
 *   if (req.url ~ "^/wiki/" || req.url ~ "^/w/index\.php" || ...)
 * Their frontend has NO path-based pass rule at all — identity is handled purely
 * by folding the session/Token cookies into the hash. The cookies below plus the
 * Cache-Control floor are the entire mechanism, upstream and here. Do not
 * re-add a path rule without a source that says MediaWiki cannot cache it.
 */
static const char *const  ct_mw_cookies[] = {
    "Token=", "_session=", "UserID=", NULL };
static const char *const  ct_mw_uris[] = { NULL };
static const char *const  ct_mw_args[] = {
    "veaction", "returnto",
    /* ActionFactory::CORE_ACTIONS, mutating half only. The read half
     * (view/history/raw/render/info/credits) is deliberately absent. */
    "action=edit", "action=submit", "action=delete", "action=protect",
    "action=unprotect", "action=purge", "action=rollback", "action=revert",
    "action=watch", "action=unwatch", "action=markpatrolled",
    "action=mcrundo", "action=mcrrestore", NULL };

/*
 * Magento 2 (2.4.x). ONE cookie: X-Magento-Vary. Magento is built to sit behind a
 * shared cache and ships its own reference Varnish VCL
 * (app/code/Magento/PageCache/etc/varnish7.vcl) — this preset is that VCL,
 * translated, with one deliberate and important deviation.
 *
 * X-Magento-Vary is the "this visitor is not the shared anonymous case" signal
 * (Framework/App/Http/Context.php::getVaryString): it is a salted hash of the
 * vary context — customer group, auth flag, currency, store view — and it is
 * computed ONLY from values that differ from their defaults. A plain anonymous
 * visitor on the default store has an all-default context, so getVaryString()
 * returns null and the cookie is not set (it is actively deleted if stale). A
 * logged-in customer, a non-default customer group, or a switched
 * currency/store gets the cookie.
 *
 * WE KEY ON THE VALUE, exactly as Magento's VCL does (vcl_hash: hash_data of the
 * regsub'd cookie), via the preset `key_cookies` list. vcl_recv never passes on
 * this cookie; it passes on URL and method only. Magento's OWN built-in PHP full-
 * page cache agrees — Framework/App/PageCache/Identifier.php folds
 * COOKIE_VARY_STRING into the sha1 cache id. Two independent upstream
 * implementations, one call: the vary value is a cache-key component.
 *
 * WHY NOT BYPASS (what this preset used to do). The cookie is a SEGMENT
 * FINGERPRINT, not an identity: sha256 over the SORTED tuple {customer_group,
 * customer_logged_in, store, currency} (App/Http/Context.php::getVaryString), and
 * getData() drops every value equal to its default. So a plain anonymous visitor
 * has NO cookie, and a guest who merely switched currency or store view has one
 * while holding zero private data. Bypassing sent all of them to the origin. The
 * "it prevents a cart leak" premise was false besides: the cart is NOT in the
 * cached HTML — Magento's private-content/sections JS fetches it client-side, and
 * two logged-in shoppers in the same group/store/currency are DESIGNED to receive
 * byte-identical cached HTML.
 *
 * WHY NOT PRESENCE-KEY. Keying on mere presence would collapse a EUR guest, a
 * wholesale customer and a logged-in retail customer into ONE bucket — that IS
 * the cross-user leak. Presence-keying and value-keying are different things;
 * rejecting the first does not justify bypassing.
 *
 * THE TRANSITION RACE (the one genuine leak, invisible from the request side):
 * a request with NO vary cookie hashes to the anonymous bucket, and the RESPONSE
 * sets X-Magento-Vary. Storing that segmented body under the anonymous key
 * poisons it for everyone. Upstream refuses to cache exactly this
 * (vcl_backend_response: beresp.uncacheable when the request had no vary cookie
 * and the response sets one). We inherit the identical refusal from the
 * UNCONDITIONAL Set-Cookie floor in ngx_http_cache_turbo_response_cacheable():
 * the response that establishes the segment carries a Set-Cookie, so it is never
 * stored, under any key. A dedicated preset veto would be dead code today — but
 * this preset DEPENDS on that floor, and the floor says so.
 *
 * The raw Cookie header is parsed directly because nginx does NOT expose a
 * hyphenated cookie via $cookie_ (there is no '-' -> '_' translation for cookie
 * names, unlike headers), so `$cookie_X_Magento_Vary` silently never matches — a
 * `map` on $http_cookie is the only variable-level workaround, and the module's
 * own parser makes it unnecessary.
 *
 * COOKIES DELIBERATELY NOT LISTED — every one of these is set for ANONYMOUS
 * visitors, and bypassing on any of them takes the hit rate to ~0:
 *   PHPSESSID              sessions are site-wide; everyone gets one
 *   form_key               CSRF token, set client-side for everyone
 *   private_content_version set on ANY POST by anyone (guest add-to-cart,
 *                          newsletter) and then persists for TEN YEARS —
 *                          a slow-motion hit-rate collapse
 *   mage-cache-sessid      set by JS for everyone
 *   section_data_ids       set by JS for everyone
 *   mage-messages          flash queue; anons get these too
 *   mage-cache-storage     not a cookie at all — a localStorage namespace
 *   mage-customer-login    presence != logged-in (it stores a true/false VALUE)
 *
 * Most of the safety here is NOT these rules: cart, checkout, checkout success
 * and the customer-account layouts are all cacheable="false", so Magento emits
 * `no-store, no-cache, must-revalidate` (Framework/App/Response/Http.php
 * ::setNoCacheHeaders) and the implied cache_control honor already refuses to
 * store them. The URI list is defence-in-depth.
 *
 * /admin is deliberately ABSENT: the admin path is randomised per install
 * ("admin_" + 7 random base36 chars — Framework/Setup/BackendFrontnameGenerator),
 * so no shippable prefix matches it. It does not need one: admin always sends
 * no-store. /cart and /onepage are absent because they are not stock routes (the
 * real paths are /checkout/cart and /checkout/onepage) — as position-0 prefixes
 * they would match nothing, while /cart could false-positive on a catalog URL key
 * like /cartridge-refill.
 */
static const char *const  ct_magento_cookies[] = { NULL };
/*
 * /rest and /soap are the Web API front names, and they are the HEADER-
 * AUTHENTICATED surface the cookie tier is structurally blind to. Magento
 * declares all three in app/code/Magento/Webapi/etc/di.xml:
 *
 *     <item name="webapi_rest" ...><item name="frontName">rest</item>
 *     <item name="webapi_soap" ...><item name="frontName">soap</item>
 *
 * `GET /rest/V1/customers/me` with `Authorization: Bearer <customer token>`
 * returns that customer's name, e-mail and address book. No cookie is involved,
 * so no cookie rule can see it; the request carries its identity in a header.
 * /graphql was already listed and is the same class — /rest and /soap were the
 * missing twins, not a new idea.
 *
 * The Authorization storage floor does refuse to store these, but that floor is
 * the same defence-in-depth argument the comment above makes for the rest of
 * this list, and the URI rule is what stops the LOOKUP as well as the store.
 */
static const char *const  ct_magento_uris[] = {
    "/checkout", "/customer", "/graphql", "/rest", "/soap", "/sales",
    "/newsletter", "/wishlist", "/paypal", "/review",
    "/page_cache/block/esi", "/health_check.php", NULL };
static const char *const  ct_magento_args[] = { NULL };
/* Value-keyed, never bypassed. Exact name — see ngx_http_cache_turbo_cookie_value. */
static const char *const  ct_magento_key_cookies[] = { "X-Magento-Vary", NULL };

/*
 * Ghost (5.x/6.x). The public blog is a large, genuinely shared anonymous surface,
 * which is what makes it worth caching at all.
 *
 * DO NOT reason "a member sees the same HTML as a guest on a public post." It is
 * FALSE, and an earlier version of this comment said it. checkPostAccess()
 * (services/members/content-gating.js) does early-return on visibility ===
 * 'public' — but `@member` is injected into the template context UNCONDITIONALLY
 * whenever req.member exists (update-local-template-options.js), so a stock
 * {{#if @member}} in the theme changes the markup of a FULLY PUBLIC post. Ghost
 * itself agrees: frontend-caching.js sets `Cache-Control: private` for ANY member
 * request without ever consulting visibility. The cookie bypass below is what
 * keeps this correct — it is load-bearing, not defence-in-depth.
 *
 * ghost-members-ssr is the members session cookie (services/members/service.js),
 * set ONLY on login — an anonymous reader gets no cookie at all, which is the
 * property Moodle and the PHP shops lack. The substring also covers the
 * ghost-members-ssr.sig signature cookie, so one entry does both.
 *
 * THE ARGS ARE LOAD-BEARING, not decoration — each one authenticates or unlocks
 * WITHOUT A COOKIE, so the cookie rule above cannot catch them:
 *   uuid + key  authMemberByUuid() (services/members/middleware.js) authenticates
 *               a member purely from the QUERY STRING, HMAC-verifying key against
 *               uuid. No cookie is involved at any point.
 *   token       the magic-link signin.
 *   gift        a ?gift render serves UNLOCKED GATED CONTENT with no member
 *               cookie present. Ghost's own cache middleware refuses to store it
 *               for exactly this reason (isGiftRequest()).
 * Store any of these and the paid/gated body is replayed to strangers. Do not
 * drop them, and do not assume the Cache-Control floor covers you: an operator
 * running `cache_turbo_cache_control ignore` (which the README recommends for
 * some origins) has switched that floor off.
 *
 * /p/ is unpublished post previews (must never be cached) and /r/ is the
 * link-redirect tracker.
 */
static const char *const  ct_ghost_cookies[] = {
    "ghost-members-ssr", "ghost-admin-api-session", NULL };
static const char *const  ct_ghost_uris[] = {
    "/ghost/", "/members/", "/p/", "/r/", NULL };
static const char *const  ct_ghost_args[] = {
    "uuid", "key", "token", "gift", NULL };

/*
 * Wagtail (Django CMS). The first preset for an app whose auth cookie belongs to
 * its FRAMEWORK, not to itself — Wagtail ships no cookie of its own, it rides
 * Django's `sessionid`. That is only shippable because of a specific Django
 * property: SessionMiddleware saves the session cookie ONLY when the session is
 * non-empty AND modified, so a logged-out reader of a public page is issued no
 * cookie at all. Contrast Laravel, whose StartSession has no such check and
 * cookies every guest — which is why there is no statamic/october preset, and no
 * `laravel` preset, and never will be. See docs/frameworks.md.
 *
 * THE CONDITION IS REAL AND IT IS THE APP'S TO BREAK. `sessionid` stops being a
 * logged-in signal the moment the site writes to the session for anonymous
 * visitors: an anonymous cart (request.session['cart']=…), a large guest flash
 * message (contrib.messages overflows cookie storage and falls back to the
 * SESSION), or CSRF_USE_SESSIONS=True. Each turns the bypass into a 100% bypass —
 * hit rate 0, no error, nothing in the log. This FAILS SAFE (lost hits, never a
 * leak), which is the only reason it is shippable at all; docs/wagtail.md tells
 * the operator to re-check with curl after any deploy that touches sessions.
 *
 * NOT csrftoken. Django hands it to every anonymous visitor that renders a form
 * (a search box in the header is enough), so bypassing it would bypass everything
 * and find no logged-in user. Same class as WooCommerce's guest cookies.
 *
 * URIs come from Wagtail's own project template (project_template/project_name/
 * urls.py), so all three are what a stock install actually serves:
 *   /admin/         wagtailadmin_urls — relocatable (the docs suggest /cms/ when
 *                   it clashes with Django admin). An install that moves it loses
 *                   the URI shortcut but stays CORRECT, because `sessionid` is the
 *                   real guard. Cookie guards, URI optimises — that ordering is
 *                   deliberate.
 *   /django-admin/  admin.site.urls — also in the stock template.
 *   /documents/     LOAD-BEARING, not decoration. WAGTAILDOCS_SERVE_METHOD
 *                   defaults to serve_view under FileSystemStorage: a Django view
 *                   that enforces per-collection PRIVACY checks. A private
 *                   document fetched by an authorised user must never be stored
 *                   and replayed to a stranger. Bypass on the prefix rather than
 *                   trusting a no-store header we have not verified.
 *
 * /search/ is deliberately ABSENT. It is dynamic but ANONYMOUS-IDENTICAL — every
 * logged-out visitor searching "foo" gets the same page — so it is shared, hot,
 * and exactly what a cache is for. Bypassing it would be a pure hit-rate loss with
 * no safety gain. Same reasoning that keeps a blanket `action=` out of mediawiki.
 */
static const char *const  ct_wagtail_cookies[] = { "sessionid", NULL };
static const char *const  ct_wagtail_uris[] = {
    "/admin/", "/django-admin/", "/documents/", NULL };
static const char *const  ct_wagtail_args[] = { NULL };

/*
 * Kirby (flat-file PHP CMS). The best-shaped traffic of any preset here: a
 * flat-file site is almost entirely public pages that are byte-identical for every
 * logged-out visitor, which is the whole business case for a page cache.
 *
 * kirby_session is a STABLE literal (session.cookieName default) — no hash, no
 * APP_NAME, no admin-settable prefix — and Kirby creates a session only when
 * something is actually stored in it, so a plain anonymous GET of a public page is
 * issued NO cookie. Stable + not-guest-issued is the pair every rejected candidate
 * failed: Grav's grav-site-<hash> is both guest-issued AND per-install, Craft's
 * CraftSessionId is stable but handed to every visitor, Statamic's is APP_NAME-
 * derived AND guest-issued.
 *
 * THE ONE CONDITION, and it fails SAFE: Kirby's csrf() helper creates a session
 * cookie ("When you use the csrf() helper, Kirby will create a session cookie" —
 * the privacy guide). So a template with a contact/search/comment form issues
 * kirby_session TO GUESTS on that page, and those pages stop caching. That costs
 * HITS on form pages; it never leaks, because the direction of the error is
 * bypass-a-guest, not serve-a-member's-page. Precisely inverted from Flarum, which
 * is why Flarum is rejected and this ships. docs/kirby.md says which pages to
 * expect it on.
 *
 * /panel is the admin (panel.slug, rarely moved). /media is NOT listed: Kirby
 * serves assets from /media/<hash>/ with no per-request permission view, so it is
 * static content that SHOULD cache — bypassing it would be a self-inflicted wound.
 */
static const char *const  ct_kirby_cookies[] = { "kirby_session", NULL };
static const char *const  ct_kirby_uris[] = { "/panel", NULL };
static const char *const  ct_kirby_args[] = { NULL };

/*
 * Shopware 6. VALUE-KEYED, NOT BYPASSED — the same shape as magento, and for the
 * same reason. Read that comment first; this one only records what differs.
 *
 * sw-cache-hash is a purpose-built cache-variant cookie, not an identity.
 * CacheHeadersService::buildCacheHash() folds a SET of fields into it —
 * {rule_ids, version_id, currency_id, tax_state, logged_in_state} — where
 * logged_in_state is literally 'logged-in' | 'not-logged-in' (CacheHeadersService
 * .php:104). The logged-in bit is INSIDE the value, alongside currency and price
 * rules. Shopware's own reverse proxy treats it exactly as a key and never as a
 * bypass (shopware/varnish-shopware default.vcl: hash_data("+context=" +
 * cookie.get("sw-cache-hash"))), which is the behaviour we are matching.
 *
 * WHY A BYPASS WOULD BE WRONG, precisely: isCacheHashRequired() (:125) returns
 * true for a logged-in customer OR a guest with a filled cart OR a guest on a
 * non-default currency. So bypass-on-presence would send cart-holding GUESTS and
 * non-default-currency GUESTS to the origin — anonymous visitors whose private
 * data is not in the cached HTML at all (the cart is fetched client-side, as in
 * magento). That is the exact bypass #28 removed from magento; do not reintroduce
 * it here. Presence is not identity; the value is a segment fingerprint.
 *
 * LAZY, and actively so — this is the (b) half of the screening question, and
 * Shopware enforces it harder than any other preset here. When the hash is NOT
 * required, applyCacheHash() (:62) does not merely omit the cookie, it DELETES a
 * stale one (removeCookie + clearCookie). A default anonymous visitor is
 * guaranteed cookieless, so the anonymous bucket is the common case.
 *
 * sw-states IS DELIBERATELY NOT MATCHED, and matching it would be a LEAK on a
 * current shop. It was REMOVED in 6.8 (UPGRADE-6.8.md: "Removed `sw-states` and
 * `sw-currency` cache cookie handling ... The complete caching behaviour is now
 * controlled by the `sw-cache-hash` cookie"); HttpCacheKeyGenerator::
 * SYSTEM_STATE_COOKIE is @deprecated tag:v6.8.0 and CacheResponseSubscriber gates
 * the whole path off under Feature::isActive('v6.8.0.0'), so 6.8 never sets it. A
 * preset keyed on sw-states alone would silently stop firing on an upgraded shop
 * — the classic "matcher stops matching => logged-in pages get cached" failure.
 * sw-cache-hash spans 6.4..6.8, so one exact literal covers every supported line.
 *
 * The name is a stable literal (HttpCacheKeyGenerator::CONTEXT_CACHE_COOKIE =
 * 'sw-cache-hash', :27) — no per-install hash, no APP_NAME, not admin-settable.
 * It is hyphenated, so $cookie_sw_cache_hash would never match; the module's raw
 * Cookie parser is what makes it usable (see the magento note).
 *
 * /account and /checkout are stock Storefront routes and stay bypassed as
 * defence-in-depth (Shopware sends no-store on them anyway). /admin is the API +
 * Administration SPA. /store-api is the headless JSON API: it is context-sensitive
 * per sw-context-token and must never be shared.
 */
static const char *const  ct_shopware6_cookies[] = { NULL };
static const char *const  ct_shopware6_uris[] = {
    "/account", "/checkout", "/admin", "/api", "/store-api", NULL };
static const char *const  ct_shopware6_args[] = { NULL };
/* Value-keyed, never bypassed. Exact name — see ngx_http_cache_turbo_cookie_value. */
static const char *const  ct_shopware6_key_cookies[] = { "sw-cache-hash", NULL };

/*
 * TYPO3 (v11..v13). Lazy sessions, confirmed at the strongest possible place: the
 * frontend authentication object opts OUT of cookies by default.
 * FrontendUserAuthentication::$dontSetCookie = true (:155) OVERRIDES the base
 * class default of false (AbstractUserAuthentication:199), and it is flipped back
 * to false in exactly two places, both on the login path — createUserSession()
 * (:242) and regenerateSessionId() (:407). shallSetSessionCookie() (:344) is the
 * gate. So an anonymous visitor reading public pages is issued NO cookie: this is
 * a deliberate upstream design decision in favour of caching, not an accident we
 * are relying on.
 *
 * THE ONE CAVEAT, and it is a real one: the name is admin-overridable, NOT a hard
 * literal. FrontendUserAuthentication::getCookieName() (:167) reads
 * $GLOBALS['TYPO3_CONF_VARS']['FE']['cookieName'] and falls back to 'fe_typo_user'.
 * It is a plain default rather than a per-install hash (unlike Drupal's SESS<hash>
 * or Grav's grav-site-<hash>), and overriding it is rare — but a site that DOES
 * override it silently loses the match, and a lost match on a bypass rule means
 * logged-in pages get cached. docs/typo3.md says: if you set FE/cookieName, add
 * your name with cache_turbo_bypass_cookie. We match the default exactly; we
 * cannot match a name we cannot know.
 *
 * be_typo_user is matched too, and is a genuine stable literal. It is not
 * redundant with the FE cookie: an editor previewing the frontend, or any backend
 * user hitting a FE page, carries only the BE cookie, and TYPO3 renders
 * hidden/scheduled records and preview versions for them. Caching that response
 * would publish unpublished content to strangers. Same class as xenforo's
 * xf_session_admin — a second cookie, a second table, an independent lifetime.
 *
 * /typo3 is the backend entry point (stable; TYPO3 does not randomise it the way
 * magento randomises /admin).
 */
static const char *const  ct_typo3_cookies[] = {
    "fe_typo_user", "be_typo_user", NULL };
static const char *const  ct_typo3_uris[] = { "/typo3", NULL };
static const char *const  ct_typo3_args[] = { NULL };

/*
 * Invision Community (IPS4). Closed-source, vendor-attested rather than
 * source-verified — IPS's own developer docs document ips4_loggedIn as
 * existing FOR THIS EXACT PURPOSE: "set after login, used by caching systems
 * to identify if you are logged in" (Common Cookies Set By The Suite / the
 * Caching developer guide, which tells a page-cache integrator to check it
 * before initialising other classes). This is a stronger, purpose-built signal
 * than most platforms in this registry ship — most forums leave you to reverse
 * engineer a remember-me cookie; IPS names the caching cookie for you.
 *
 * `ips4_IPSSessionFront` is issued to EVERY visitor, guests included (ordinary
 * session tracking) — the same xf_session/_forum_session shape, and it is
 * deliberately NOT in this list.
 *
 * The `ips4_` prefix is admin-configurable (Overriding Default Cookie Options),
 * so the rule matches the SUFFIX `_loggedIn`, not the literal `ips4_loggedIn`
 * — the same prefix-agnostic technique phpBB's `_u` and Drupal's `SESS` use.
 *
 * IPS routes through app=core&module=...&do=... controller dispatch rather
 * than one stable posting URI, so posting/messaging/moderation surfaces are
 * matched as `do=` query args, not URI prefixes, alongside the fixed
 * front-controller paths (/login, /register, /lostpassword, /messenger, and
 * /admin — the ACP).
 *
 * key_cookies are cosmetic (theme, language, JS detection), shared by everyone
 * who picked the same value — never an identity signal.
 *
 * `ips4_device_key` is deliberately NOT keyed, and it is the counter-example
 * that defines the rule: it is a PER-DEVICE fingerprint, so it is neither
 * cosmetic nor shared. Keying on it gives every visitor a private entry nobody
 * else can ever hit, and because the value comes straight from the client it
 * also lets one attacker mint unlimited distinct keys and push the zone into
 * eviction. Same reasoning as ct_vbulletin_key_cookies. It carries no variant
 * information either: IPS sets it on the login POST for the remember-me device
 * list, so its bearer is a MEMBER, and those requests the _loggedIn predicate
 * has already bypassed. (It is httpOnly, but that is irrelevant here — httpOnly
 * only hides a cookie from browser script; it is still sent in the Cookie
 * header and this module sees it like any other.)
 */
static const ngx_http_cache_turbo_cookie_pred_t  ct_invision_preds[] = {
    { "_loggedIn", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { NULL, 0, NULL }
};
static const char *const  ct_invision_cookies[] = { NULL };
static const char *const  ct_invision_uris[] = {
    "/admin", "/login", "/register", "/lostpassword", "/messenger", NULL };
static const char *const  ct_invision_args[] = {
    "do=compose", "do=post", "do=reply", "do=report", "module=messaging", NULL };
static const char *const  ct_invision_key_cookies[] = {
    "ips4_hasJS", "ips4_theme", "ips4_language", NULL };

/*
 * Simple Machines Forum (SMF). SMFCookie (name is `$cookiename` from
 * Settings.php, default "SMFCookie" + version suffix e.g. SMFCookie20/21, so
 * the rule matches the SUBSTRING "SMFCookie" not a full literal) is issued to
 * EVERY visitor, guests included — the phpBB shape exactly. loadUserSettings()
 * in SMF's own core only treats it as authenticated when the embedded
 * password-hash element is non-empty; a guest's value carries id_member=0 and
 * an empty password field.
 *
 * A general-purpose nginx cookie matcher cannot safely JSON/PHP-serialize
 * decode the structured value and validate hash shape, so the pragmatic proxy
 * (same class of compromise as phpBB's presence-of-suffix rule) is: bypass
 * whenever the cookie is present AT ALL. This is presence-only despite the
 * cookie being guest-issued, and it is NOT free — it costs hit rate on guests
 * who have merely started a session (viewed the login page, tripped 2FA).
 * That is the accepted XenForo-style trade: correct, not maximally fast. Do
 * not "optimise" this into a value predicate without actually parsing the
 * cookie's array/JSON structure — an approximate string-prefix guess against
 * a guest-canonical value is not a safe substitute for a real decode, and
 * shipping one un-decoded risks the opposite failure (misclassifying an
 * authenticated cookie as guest-shaped).
 *
 * The 2FA companion cookie `<cookiename>_tfa` only exists mid-login and is
 * folded into the same presence rule for completeness.
 */
static const char *const  ct_smf_cookies[] = { "SMFCookie", NULL };
static const char *const  ct_smf_uris[] = { NULL };
static const char *const  ct_smf_args[] = {
    "action=admin", "action=login", "action=login2", "action=logintfa",
    "action=logout", "action=profile", "action=pm", "action=post",
    "action=post2", "action=moderate", "action=reporttm", "action=xmlhttp",
    NULL };

/*
 * Vanilla Forums. The `Vanilla` identity cookie (Gdn_CookieIdentity::
 * SetIdentity()) is written ONLY at login/SSO time — a true guest never
 * receives it at all, unlike the phpBB/SMF/XenForo shape. No value predicate
 * is needed or available (the value is an HMAC-signed opaque payload).
 *
 * CAVEAT: this is corroborated via Vanilla's own KB article and community
 * threads describing SetIdentity/GetIdentity, not a direct line-cited GitHub
 * source read (the exact file could not be fetched at research time — it may
 * have moved in the TypeScript/PHP8 rewrite of newer Vanilla). Ship it, but
 * verify empirically against your own install (curl anonymously, confirm no
 * `Set-Cookie: Vanilla=...` appears) before relying on it in production.
 *
 * The rule matches "Vanilla=" — the identity cookie's name followed by its
 * delimiter — NOT the bare substring "Vanilla". Vanilla derives several
 * GUEST-issued cookie names from the same `Garden.Cookie.Name` prefix
 * (`Vanilla-tk`, the CSRF transient key, and `Vanilla-Vv`, the visit
 * tracker), so a bare-prefix match would fire on ordinary anonymous traffic
 * and collapse the hit rate to cookieless first hits and crawlers — the
 * guest-issued-cookie trap this registry's header comment forbids. The
 * trailing '=' is what separates the identity cookie from its siblings.
 *
 * Renaming `Garden.Cookie.Name` therefore defeats this rule; docs/vanilla.md
 * tells the operator to add their own cache_turbo_bypass in that case.
 */
/*
 * NO /api ROW, DELIBERATELY, and this is an unresolved gap rather than a
 * decision. Vanilla's API v2 is Bearer-authenticated, so it is exactly the
 * header-auth surface the cookie tier cannot see — the same class as magento
 * /rest, drupal /jsonapi and xenforo /api/, all of which ARE listed.
 *
 * It is not listed here because it cannot be verified: github.com/vanilla/vanilla
 * now 404s (repo, raw and API alike; the org survives), so there is no upstream
 * tree left to check the prefix against, and every surviving reference is a
 * Garden-era fork last pushed in 2013. Adding a row from recollection is exactly
 * what produced the dead /admin.php and /message_send.php rows in punbb, so it
 * is not being done. An operator running Vanilla's API adds their own:
 *     cache_turbo_bypass_uri /api;
 * See docs/vanilla.md.
 */
static const char *const  ct_vanilla_cookies[] = { "Vanilla=", NULL };
static const char *const  ct_vanilla_uris[] = {
    "/dashboard", "/entry/", "/messages/", "/post/", NULL };
static const char *const  ct_vanilla_args[] = { NULL };

/*
 * PunBB. The session cookie is issued EAGERLY to every guest too
 * (set_default_user(), unless
 * FORUM_QUIET_VISIT), so this needs the phpBB-shaped value predicate, not
 * presence. Unlike phpBB's derived `_u` flag, PunBB's cookie value is a
 * base64'd, pipe-delimited string whose FIRST field IS the numeric user_id
 * directly — a guest's is the hardcoded literal "1" (login.php: logout path
 * writes `base64_encode('1|'.random_key(...))`; a real login writes the
 * actual user_id, which by the same ANONYMOUS-reserved-row convention as
 * phpBB is never 1). The registry's cookie_preds engine tests the request
 * Cookie header directly (not decoded base64), so the predicate here matches
 * against the cookie's RAW value with the NE-vs-guest-literal test applied to
 * the same base64'd guest string PunBB itself always writes for a logged-out
 * visitor — see the predicate below.
 *
 * Fixed literal URI prefixes for admin/login/posting/editing/moderation bypass
 * unconditionally. There is no private-messaging row: PunBB core ships no PM
 * (an earlier version of this comment claimed it did) -- see the URI list.
 *
 * IMPLEMENTATION NOTE: the ideal rule (base64-decode, split on '|', compare
 * field[0] against the guest literal "1") is NOT expressible by this engine's
 * cookie_preds — it compares the RAW cookie value against a fixed literal
 * (EQ/NE) or tests non-emptiness, and PunBB's base64'd guest value carries a
 * random per-request key suffix after the "1|" (`base64_encode('1|'.
 * random_key(...))`), so it is never one fixed string an EQ/NE test can
 * anchor on. A prefix-of-decoded-value predicate would require actually
 * decoding base64 in the hot classify path, which this registry does not do
 * anywhere else (all other value predicates compare the wire bytes directly).
 * So this preset degrades to PRESENCE-only, same shape as SMF's SMFCookie —
 * safe (bypass is the correct-direction failure), but costs hit rate on
 * guests who merely touched a session-starting action. docs/punbb.md notes
 * this rather than claiming the sharper rule the research suggested.
 *
 * COOKIE NAME: PunBB 1.4.x defaults to `forum_cookie`, and its installer
 * offers a randomised `forum_cookie_<rand>`; `punbb_cookie` was the 1.2-era
 * default and still appears on upgraded boards. Both are matched as
 * substrings, so the randomised 1.4 variant is covered by the `forum_cookie`
 * entry. Matching only `punbb_cookie` (as this row originally did) never
 * fired on a stock 1.4 install, which served cached guest pages to logged-in
 * members. An operator who renames `$cookie_name` to anything else must add
 * their own cache_turbo_bypass — docs/punbb.md says so.
 */
static const char *const  ct_punbb_cookies[] = {
    "forum_cookie", "punbb_cookie", NULL };
/*
 * URI list, verified against the punbb/punbb tree at tag v1.4.4. Every entry
 * below is a script that exists at the document root of a stock install.
 *
 * Three rows were removed because NO PunBB release ships them:
 *   - "/admin.php": 1.4.x keeps the admin under the "/admin/" DIRECTORY
 *     (admin/index.php, admin/users.php, admin/settings.php, ...), and the
 *     1.2-era layout used admin_index.php / admin_users.php at the docroot.
 *     Neither is "/admin.php". The 1.2 layout is also NOT expressible here:
 *     uri_prefix() requires the byte after the needle to be '/' or '.', so a
 *     partial-filename needle like "/admin_" can never match "/admin_index.php"
 *     -- listing every 1.2 admin script individually would be the only way, and
 *     1.2 has been EOL since 2013. Losing it costs nothing anyway: an admin is
 *     by definition logged in, so the cookie tier bypasses them already, and
 *     the admin scripts re-check g_id server-side.
 *   - "/message_send.php", "/message_delete.php": private messaging is NOT a
 *     PunBB core feature (the comment above previously claimed it was). Core
 *     has no PM at all -- misc.php carries the email-a-user and report-a-post
 *     forms instead -- and the third-party PM extensions route through their
 *     own extension paths, not these two names.
 *
 * Five real member/mutating scripts were missing and are now listed: edit.php,
 * delete.php, moderate.php, profile.php, register.php. search.php and
 * userlist.php are deliberately absent -- both are guest-reachable read
 * surfaces that cache correctly.
 */
static const char *const  ct_punbb_uris[] = {
    "/admin/", "/login.php", "/post.php", "/edit.php", "/delete.php",
    "/moderate.php", "/profile.php", "/register.php", "/misc.php", NULL };
static const char *const  ct_punbb_args[] = { NULL };

/*
 * Phorum. Fixed, version-pinned literal session-cookie constants
 * (phorum_session_v5, phorum_session_st, phorum_admin_session — PHP
 * constants in include/api/user.php, not per-install hashes or
 * admin-configurable prefixes) written ONLY by
 * phorum_api_user_session_create(), which is called ONLY from a successful
 * login — never for anonymous page rendering. This is the inverse of the
 * XenForo/Discourse/phpBB/Flarum trap: presence alone is a safe, sufficient
 * signal because guests never receive any of these three cookies. No value
 * predicate needed.
 *
 * `phorum_tmp_cookie` is a guest-received cookie-support PROBE with no
 * identity value (destroyed once logged in) — deliberately absent from the
 * list; matching it would be a pure hit-rate loss for zero safety gain.
 *
 * Phorum is a flat top-level-script app (admin.php, login.php, ... — no path
 * hierarchy), so the dynamic surface is expressed as URI prefixes against
 * those script names directly.
 */
static const char *const  ct_phorum_cookies[] = {
    "phorum_session_v5", "phorum_session_st", "phorum_admin_session", NULL };
/*
 * Verified against Phorum/Core master. "/file.php" is the row that matters
 * most and was missing: it is the ATTACHMENT DOWNLOAD script, and it authorises
 * per request through the file_storage API (a file attached to a private-forum
 * message is refused to anyone without read access to that forum). Serving it
 * from the cache hands the first requester's attachment body to every later
 * requester of the same file id, permission check skipped -- the same shape as
 * the phpBB download/file.php hazard.
 *
 * "/post.php" is kept even though Phorum 5 replaced it with posting.php: the
 * file still ships, as a stub whose entire body is a die() that exists to
 * overwrite the 5.0 script on upgrade so spammers cannot POST to it. Bypassing
 * a die() page costs nothing and the row is one byte of table.
 */
static const char *const  ct_phorum_uris[] = {
    "/admin.php", "/login.php", "/register.php", "/pm.php", "/posting.php",
    "/post.php", "/moderation.php", "/control.php", "/ajax.php", "/report.php",
    "/follow.php", "/file.php", NULL };
static const char *const  ct_phorum_args[] = { NULL };
static const char *const  ct_phorum_key_cookies[] = { "list_style", NULL };

/*
 * YaBB (the Perl forum). The three session/login cookies (`Y2User-<rand>`,
 * `Y2Pass-<rand>`, `Y2Sess-<rand>`) get a RANDOM per-install numeric suffix
 * generated once by Setup.pl — the Joomla-shaped naming problem — but the
 * FIXED PREFIXES (`Y2User-`, `Y2Pass-`, `Y2Sess-`) survive it, so the rule
 * matches those substrings, not a full name.
 *
 * More importantly: presence alone is safe regardless of the prefix, because
 * the single write path (UpdateCookie("write", ...)) is called ONLY from the
 * post-login-form-POST success branch in LogInOut.pl. Every guest / logged-out
 * / failed-login path calls UpdateCookie("delete") instead, which clears these
 * three cookies (or, in guest-language-cookie mode, repurposes only the
 * Y2Pass- slot to hold a plaintext "guestlanguage" string — cosmetic, not an
 * auth artifact). YaBB also always cookies on login regardless of a
 * remember-me checkbox (UpdateCookie("write") on LogInOut.pl:101 fires for
 * ANY successful login; only the expiry varies) — so this has none of the
 * XenForo/Flarum "ordinary login leaves no cookie" trap either.
 *
 * A site that hand-renames the three Y2*-prefixed cookie vars away from the
 * convention breaks this preset silently — same caveat class as any other
 * admin-configurable cookie name in this registry (document, don't code
 * around what can't be discovered).
 *
 * YaBB is a single-script CGI app (YaBB.pl?action=X), so the dynamic surface
 * lives in query args, not URI prefixes.
 *
 * `action=logout` is in the args list for the same reason `action=login` is,
 * and it is the more dangerous of the pair to omit: a cached logout response
 * is served without the request ever reaching LogInOut.pl, so the
 * UpdateCookie("delete") that terminates the session never runs and the member
 * stays logged in while being told they are not.
 */
static const char *const  ct_yabb_cookies[] = {
    "Y2User-", "Y2Pass-", "Y2Sess-", NULL };
static const char *const  ct_yabb_uris[] = { NULL };
static const char *const  ct_yabb_args[] = {
    "action=post", "action=post2", "action=login", "action=login2",
    "action=logout", "action=register", "action=register2", "action=admin",
    "action=pm", "action=imsend", "action=imsend2", NULL };

/*
 * MyBB. The login cookie is `mybbuser` — the whole of that is MyBB's own
 * hardcoded base name (my_setcookie("mybbuser", ...)); the ACP `cookieprefix`
 * setting is PREPENDED to it and defaults to EMPTY. An earlier version of this
 * comment had it backwards ("COOKIE_PREFIX default mybb_"), which matters
 * because it makes the prefix look like a fixed, known string when it is
 * operator-chosen and undiscoverable from the request.
 *
 * It is written ONLY inside the login success path (inc/datahandlers/login.php
 * via member.php do_login) — a guest structurally cannot receive it, so
 * presence alone is sufficient with no value predicate. Because the prefix is
 * operator-set, the rule matches the SUFFIX "user", the same prefix-agnostic
 * technique phpBB's "_u" uses; a predicate can afford that because its failure
 * direction is a needless bypass (`coppauser`, a real MyBB cookie, also ends in
 * "user" and costs a registrant's hit rate — nothing worse).
 *
 * `sid` (session id) is issued to EVERY visitor including guests and bots —
 * deliberately NOT in this list; it is the same xf_session/SMFCookie trap. The
 * various `mybb[lastvisit]`, `[threadread]`, `[forumread]`, `[readallforums]`,
 * `[announcements]` array-cookies are guest read-tracking, not auth — also
 * excluded. `mybbtheme` / `mybblang` are presentation cookies, folded into the
 * key instead of bypassed.
 *
 * THE KEY COOKIES DO NOT GET THE SUFFIX TREATMENT, deliberately. On a board
 * that sets a `cookieprefix` the wire names become `<prefix>mybbtheme` /
 * `<prefix>mybblang`, the exact match below folds nothing, and every guest
 * shares one bucket — whichever theme rendered first is served to all of them.
 * That is a hit-QUALITY bug, and it is the better of the two failures: keying
 * on a suffix would let any client fold a cookie of its own choosing
 * (`evilmybbtheme=dark`) into the key, landing on the same bucket a real
 * `mybbtheme=dark` reader uses while the origin — which ignores the unknown
 * name — returns the DEFAULT theme to be stored there. See the threat model on
 * ngx_http_cache_turbo_cookie_value(): a predicate's loose match costs a
 * bypass, a key's loose match hands out bucket selection.
 *
 * The remedy is operator-side and already exists: a prefixed board declares
 * `cache_turbo_key_cookie <prefix>mybbtheme <prefix>mybblang;`, which folds
 * with the identical framing. docs/mybb.md carries this.
 */
static const ngx_http_cache_turbo_cookie_pred_t  ct_mybb_preds[] = {
    { "user", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { NULL, 0, NULL }
};
static const char *const  ct_mybb_cookies[] = { NULL };
static const char *const  ct_mybb_uris[] = {
    "/member.php", "/usercp.php", "/private.php", "/modcp.php",
    "/newthread.php", "/newreply.php", "/editpost.php", "/polls.php",
    "/admin/", "/xmlhttp.php", NULL };
static const char *const  ct_mybb_args[] = {
    "action=login", "action=do_login", "action=logout", "action=do_logout",
    "action=register", "action=do_register", "action=activate",
    "action=lostpw", "action=do_lostpw", "action=resetpassword", NULL };
static const char *const  ct_mybb_key_cookies[] = {
    "mybbtheme", "mybblang", NULL };

/*
 * vBulletin (3.x/4.x "bb_" cookie-prefix era). `bb_userid` / `bb_password`
 * (or `bbimloggedin=yes` on some builds, confirmed as the real signal ops use
 * in production LiteSpeed vBulletin caching configs) are set ONLY on login
 * and removed on logout — never issued to guests. Presence/non-empty-value
 * alone is sufficient; no value-split trick needed.
 *
 * `bb_sessionhash` is issued to guests too (session tracking for everyone) —
 * deliberately excluded, the xf_session shape again. The `bb_` prefix is
 * admin-configurable (Cookie and HTTP Header Options), so this matches the
 * SUFFIX "userid" / "password", not a hardcoded "bb_" literal — a rare manual
 * full-rename still evades it (documented gap, same class as any other
 * admin-configurable-name caveat in this registry).
 *
 * The style-and-language-selection cookie is presentation, folded into the key
 * rather than bypassed. `bb_lastvisit` / `bb_lastactivity` are presentation too
 * but are NOT key cookies -- see ct_vbulletin_key_cookies below for why keying
 * on a per-request timestamp is both useless and hostile.
 */
static const ngx_http_cache_turbo_cookie_pred_t  ct_vbulletin_preds[] = {
    { "userid", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { "password", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { "imloggedin", NGX_HTTP_CACHE_TURBO_CVOP_EQ, "yes" },
    { NULL, 0, NULL }
};
static const char *const  ct_vbulletin_cookies[] = { NULL };
static const char *const  ct_vbulletin_uris[] = {
    "/login.php", "/register.php", "/usercp.php", "/private.php",
    "/profile.php", "/cron.php", "/admincp/", NULL };
static const char *const  ct_vbulletin_args[] = { NULL };
/* Only bb_language. bb_lastvisit and bb_lastactivity are per-visit timestamps
 * that change on essentially every request, so keying on them gave each visitor
 * a private bucket the next request already invalidated -- a hit rate near zero
 * on a board that otherwise caches well. They were also a free remote memory
 * attack: the values come straight from the client, so anyone could mint
 * unlimited distinct keys and push the zone into eviction. */
static const char *const  ct_vbulletin_key_cookies[] = {
    "bb_language", NULL };

/*
 * Textpattern. Both login cookies are written after every successful login;
 * `txp_login_public` is the frontend signal and `txp_login` protects the admin
 * side. Anonymous public requests do not receive either one. The admin folder
 * defaults to /textpattern but can be renamed, so the guide requires an
 * operator rule when it is moved.
 */
static const char *const  ct_textpattern_cookies[] = {
    "txp_login_public=", "txp_login=", NULL };
static const char *const  ct_textpattern_uris[] = { "/textpattern", NULL };
static const char *const  ct_textpattern_args[] = { NULL };

/*
 * Bludit. Only the admin bootstrap starts the BLUDIT-KEY session; the public
 * bootstrap is session-free. The __Secure- spelling still contains BLUDIT-KEY,
 * and the two remember-me names are stable literals. /install.php is dynamic
 * setup state and must never be replayed from the page cache.
 */
static const char *const  ct_bludit_cookies[] = {
    "BLUDIT-KEY", "BLUDITREMEMBERUSERNAME=", "BLUDITREMEMBERTOKEN=", NULL };
static const char *const  ct_bludit_uris[] = {
    "/admin", "/install.php", NULL };
static const char *const  ct_bludit_args[] = { NULL };

/*
 * SPIP prefixes all of its spip_* cookies with an operator-selected cookie
 * prefix. Suffix predicates preserve the meaningful half of each name and fail
 * toward a bypass if another cookie happens to collide. Language and Ajax-mode
 * cookies are presentation state; bypassing them avoids serving the wrong
 * variant without allowing arbitrary client values into the cache key.
 * `?action=` dispatches action handlers and `?var_mode=` forces preview/debug/
 * recalculation modes, neither of which is a shared page render.
 */
static const ngx_http_cache_turbo_cookie_pred_t  ct_spip_preds[] = {
    { "_session", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { "_admin", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { "_lang", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { "_lang_ecrire", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { "_accepte_ajax", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { NULL, 0, NULL }
};
static const char *const  ct_spip_cookies[] = { NULL };
static const char *const  ct_spip_uris[] = { "/ecrire", NULL };
static const char *const  ct_spip_args[] = { "action", "var_mode", NULL };

/*
 * Bugzilla. Bugzilla_login and Bugzilla_logincookie are both issued on every
 * successful cookie login (remember-me changes only expiry), so they are clean
 * member-only signals. API keys and tokens can authenticate entirely through
 * the query string. The URI list keeps login/account/mutation/admin/API entry
 * points out before a cookie exists while leaving show_bug.cgi, buglist.cgi
 * and reports cacheable for anonymous readers.
 */
static const char *const  ct_bugzilla_cookies[] = {
    "Bugzilla_login=", "Bugzilla_logincookie=", NULL };
static const char *const  ct_bugzilla_uris[] = {
    "/admin.cgi", "/createaccount.cgi", "/relogin.cgi", "/token.cgi",
    "/userprefs.cgi", "/enter_bug.cgi", "/post_bug.cgi",
    "/process_bug.cgi", "/request.cgi", "/quips.cgi", "/votes.cgi",
    "/colchange.cgi", "/summarize_time.cgi", "/sanitycheck.cgi",
    "/page.cgi", "/search_plugin.cgi", "/jsonrpc.cgi", "/xmlrpc.cgi",
    "/rest", "/rest.cgi", "/editclassifications.cgi", "/editcomponents.cgi",
    "/editfields.cgi", "/editflagtypes.cgi", "/editgroups.cgi",
    "/editkeywords.cgi", "/editmilestones.cgi", "/editparams.cgi",
    "/editproducts.cgi", "/editsettings.cgi", "/editusers.cgi",
    "/editvalues.cgi", "/editversions.cgi", "/editwhines.cgi",
    "/editworkflow.cgi", NULL };
static const char *const  ct_bugzilla_args[] = {
    "Bugzilla_api_key", "api_key", "Bugzilla_api_token", "Bugzilla_token",
    "Bugzilla_login", "Bugzilla_password", "Bugzilla_login_token", "token",
    NULL };

/*
 * MantisBT. The install-selected cookie prefix is prepended to every symbolic
 * cookie name, so predicates match the invariant suffix. STRING_COOKIE is the
 * login token; the project/list/collapse cookies change a public render and are
 * conservatively bypassed instead of keyed. Mantis form tokens lazily start a
 * native PHP session for anonymous form pages; PHPSESSID is therefore included
 * too (session.name overrides need an operator rule, documented in the guide).
 */
static const ngx_http_cache_turbo_cookie_pred_t  ct_mantisbt_preds[] = {
    { "_STRING_COOKIE", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { "_PROJECT_COOKIE", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { "_VIEW_ALL_COOKIE", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { "_BUG_LIST_COOKIE", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { "_collapse_settings", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { NULL, 0, NULL }
};
static const char *const  ct_mantisbt_cookies[] = { "PHPSESSID=", NULL };
static const char *const  ct_mantisbt_uris[] = {
    "/admin/", "/api/", "/login.php", "/login_page.php",
    "/login_password_page.php", "/logout_page.php", "/signup.php",
    "/signup_page.php", "/lost_pwd.php", "/lost_pwd_page.php",
    "/verify.php", "/verify_email.php", "/my_view_page.php",
    "/account_page.php", "/account_prefs_page.php",
    "/account_prof_edit_page.php", "/account_manage_columns_page.php",
    "/api_tokens_page.php", "/bug_report.php", "/bug_report_page.php",
    "/bug_update.php", "/bug_update_page.php",
    "/bug_change_status_page.php", "/bug_actiongroup_page.php",
    "/bug_actiongroup_ext_page.php", "/bug_reminder_page.php",
    "/bugnote_add.php", "/bugnote_edit_page.php", "/proj_doc_add_page.php",
    "/proj_doc_edit_page.php", "/news_edit_page.php", "/query_store.php",
    NULL };
static const char *const  ct_mantisbt_args[] = { NULL };

/*
 * Plone. __ac is the stable frontend authentication cookie. Zope sessions,
 * status messages and the language override are user-specific state too. Plone
 * itself marks login/reset responses private; the URI tier is still valuable
 * when an operator weakens origin Cache-Control. Traversal views below content
 * (folder/@@edit) remain protected by the auth cookie.
 */
static const char *const  ct_plone_cookies[] = {
    "__ac=", "_ZopeId=", "statusmessages=", "I18N_LANGUAGE=", NULL };
static const char *const  ct_plone_uris[] = {
    "/login", "/logout", "/register", "/passwordreset", "/mail_password",
    "/manage", "/@@login", NULL };
static const char *const  ct_plone_args[] = { NULL };

/*
 * Umbraco. Verified current identity channels include the configurable
 * back-office cookie (default UMB_UCONTEXT), v17+ token cookies, preview/XSRF
 * cookies, and ASP.NET Identity's member cookie. UMB_EXTLOGIN and UMB_SESSION
 * remain conservative compatibility guards for legacy/optional integrations.
 * /umbraco contains the back office and management API; ordinary content and
 * the public Delivery API are left available for caching. Sites that rename
 * the member/back-office cookies must add their configured names explicitly
 * (see docs/umbraco.md).
 */
static const char *const  ct_umbraco_cookies[] = {
    "UMB_UCONTEXT=", "UMB_EXTLOGIN=", "UMB_PREVIEW=",
    "UMB-WEBSITE-PREVIEW-ACCEPT=", "UMB-XSRF-V=", "UMB_SESSION=",
    "umbAccessToken", "umbRefreshToken", "umbPkceCode",
    ".AspNetCore.Identity.Application=", NULL };
static const char *const  ct_umbraco_uris[] = { "/umbraco", NULL };
static const char *const  ct_umbraco_args[] = { NULL };

/*
 * Dotclear. The public frontend does not start the configured PHP session by
 * default; the backend does. `dcxd` is DC_SESSION_NAME's stock value and also
 * prefixes per-blog frontend sessions. dc_admin is the fixed remember-cookie,
 * while dc_passwd grants access to password-protected posts/pages. Preview
 * routes expose unpublished content on the public host. DC_SESSION_NAME and
 * DC_ADMIN_URL are configurable, so non-default deployments need matching
 * operator rules (see docs/dotclear.md).
 */
static const char *const  ct_dotclear_cookies[] = {
    "dcxd", "dc_admin=", "dc_passwd=", NULL };
static const char *const  ct_dotclear_uris[] = {
    "/admin", "/preview", "/pagespreview", NULL };
static const char *const  ct_dotclear_args[] = { NULL };

/*
 * Wiki.js 2.x. Authentication is a fixed `jwt` cookie. Express-session is
 * installed globally but saveUninitialized=false leaves ordinary guests
 * cookie-free; OAuth strategies can create the default connect.sid session.
 * loginRedirect carries a private target across login. The URI tier keeps
 * identity, editor/history/source, upload and GraphQL surfaces out even before
 * a cookie exists. Published arbitrary-path pages remain available for shared
 * guest caching; their ACL/navigation view is guest-group-specific, while all
 * authenticated group variants carry jwt and bypass.
 */
static const char *const  ct_wikijs_cookies[] = {
    "jwt=", "connect.sid=", "loginRedirect=", NULL };
static const char *const  ct_wikijs_uris[] = {
    "/a", "/d", "/e", "/h", "/p", "/s", "/u",
    "/login", "/logout", "/register", "/verify", "/login-reset",
    "/graphql", "/graphql-subscriptions", NULL };
static const char *const  ct_wikijs_args[] = { NULL };

/*
 * Redmine. `_redmine_session` is a hardcoded string literal in
 * config/application.rb (config.session_store :cookie_store, :key =>
 * '_redmine_session') — not derived from config, unlike most of the apps
 * researched alongside it. `autologin` is the remember-me cookie; its name is
 * config-settable (Redmine::Configuration['autologin_cookie_name']) but falls
 * back to the literal, so the stock name is matched and a renamed one degrades
 * to "session cookie still catches an active login" rather than to nothing.
 *
 * The ARG tier is load-bearing here and is NOT optional. `key` authenticates
 * with NO cookie at all: application_controller.rb accepts it as an Atom key
 * (params[:format] == 'atom' && params[:key] -> User.find_by_atom_key) and as
 * an API key (api_key_from_request when Setting.rest_api_enabled?). A
 * cookie-only rule would therefore cache a private issue list fetched via
 * ?key=<atom key> under the public cache key and serve it to everyone. This is
 * the same class of hole the ghost preset's ?uuid=/?key=/?gift= rows close.
 *
 * The URI tier deliberately does NOT list /projects, /issues, /news, /wiki or
 * /repository. On an open tracker those are the main public content and the
 * entire reason to cache it; public-vs-private there is a per-project ACL that
 * nginx cannot see, and the cookie rule is what protects a logged-in view of
 * them. Verified against redmine/redmine master (7.0.0 current 2026-07-26).
 */
static const char *const  ct_redmine_cookies[] = {
    "_redmine_session=", "autologin=", NULL };
static const char *const  ct_redmine_uris[] = {
    "/admin", "/my", "/login", "/logout", "/account",
    "/settings", "/enumerations", "/roles", "/trackers", "/custom_fields",
    "/auth_sources", "/mail_handler", NULL };
static const char *const  ct_redmine_args[] = { "key", NULL };

/*
 * Flarum. The cookie tier matches ONLY `flarum_remember`, never
 * `flarum_session` — and that distinction is the whole preset.
 * Http/Middleware/StartSession.php applies withSessionCookie() unconditionally
 * after $session->save(), on every response, before any auth check, so
 * `flarum_session` is issued to ANONYMOUS GUESTS. A rule matching it would fire
 * on ~100% of traffic and silently disable the cache — the guest-issued-cookie
 * trap this registry's header comment forbids. `flarum_remember` is written
 * only by Http/Rememberer.php (COOKIE_NAME = 'remember'), i.e. at login.
 *
 * KNOWN GAP, documented rather than papered over: a user who logs in WITHOUT
 * "remember me" carries only `flarum_session`, whose guest and member forms are
 * distinguishable solely by the session id's server-side mapping. nginx cannot
 * tell them apart, so such a login is invisible to the cookie tier. /api is in
 * the URI tier partly to contain that — the SPA fetches its content through it —
 * but a non-remembered login browsing plain discussion URLs is genuinely
 * unprotected by this preset alone. docs/flarum.md prescribes the map-based
 * rule for sites that need to close it.
 *
 * Both names carry the `cookie.name` prefix from config.php (CookieFactory.php:
 * $prefix = $config['cookie.name'] ?? 'flarum', getName() returns
 * "{$prefix}_{$name}"), and `paths.admin`/`paths.api` are renameable the same
 * way; all three are matched at their stock values only. Verified against
 * flarum/framework main (2.0.0-rc.5; identical mechanics in the 1.8.x stable
 * line).
 */
static const char *const  ct_flarum_cookies[] = {
    "flarum_remember=", NULL };
static const char *const  ct_flarum_uris[] = {
    "/admin", "/api", "/login", "/logout", "/global-logout", "/register",
    "/reset", "/confirm", "/settings", "/notifications", NULL };
static const char *const  ct_flarum_args[] = { NULL };

/*
 * OpenCart. This preset is ARG-tier, not URI-tier, and that is forced by the
 * application: OpenCart routes everything through index.php?route=<controller>,
 * so every private page shares the single path /index.php. A URI-prefix rule
 * catches NOTHING here — it would look correct, match nothing, and leave carts
 * and account pages cacheable. The `route=account/` and `route=checkout/`
 * prefixes cover the whole private surface (verified against
 * upload/catalog/controller/{account,checkout}/ on opencart/opencart master,
 * 4.1.0.3 current 2026-07-26). `user_token` is the admin-panel auth arg and
 * `customer_token` the login-validation token.
 *
 * NO COOKIE ROW, deliberately. `OCSESSID` (upload/system/config/default.php,
 * $_['session_name']) is issued to guests — a shop has to track an anonymous
 * cart — and login state lives in $this->session->data['customer'], SERVER-SIDE
 * ONLY. The cookie value is an opaque session id whose guest and customer forms
 * are identical on the wire, so there is nothing for nginx to test. Adding
 * `OCSESSID` here would bypass every visitor and disable the cache. The
 * /admin/ path is renameable at install and is therefore left to the operator.
 *
 * The route values are ENUMERATED, not prefix-matched. The arg tier compares
 * NAME=VALUE by exact bytes (see the NAME=VALUE branch in auto_skip: "no case
 * folding, no prefix match"), so a `route=account/` row would match only the
 * literal ?route=account/ and never ?route=account/login — i.e. it would look
 * right and protect nothing. Every private route is therefore listed in full.
 * ADDING A ROUTE MEANS ADDING A ROW; a new private controller under
 * account/ or checkout/ is NOT covered automatically.
 *
 * No key_cookies: OpenCart 4.x drives language and currency through the URL
 * (catalog/controller/common/language.php only reads request/config and
 * redirects with the arg — it sets no cookie), so there is no rendering cookie
 * to vary on. The 3.x-era `language`/`currency` cookies were checked for and
 * are NOT set by 4.x; do not add them back without re-verifying.
 */
static const char *const  ct_opencart_cookies[] = { NULL };
static const char *const  ct_opencart_uris[] = { NULL };
static const char *const  ct_opencart_args[] = {
    "route=checkout/cart", "route=checkout/checkout", "route=checkout/confirm",
    "route=checkout/success", "route=checkout/failure",
    "route=checkout/payment_address", "route=checkout/payment_method",
    "route=checkout/shipping_address", "route=checkout/shipping_method",
    "route=checkout/register",
    "route=account/account", "route=account/login", "route=account/logout",
    "route=account/register", "route=account/forgotten", "route=account/edit",
    "route=account/password", "route=account/address", "route=account/order",
    "route=account/wishlist", "route=account/download", "route=account/returns",
    "route=account/reward", "route=account/transaction",
    "route=account/subscription", "route=account/newsletter",
    "route=account/affiliate", "route=account/custom_field",
    "route=account/tracking", "route=account/payment_method",
    "route=account/authorize", "route=account/success",
    "user_token", "customer_token", NULL };

static const ngx_http_cache_turbo_preset_t  ngx_http_cache_turbo_presets[] = {
    { NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS,
      ct_wp_cookies, ct_wp_uris, ct_wp_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_WOOCOMMERCE,
      ct_woo_cookies, ct_woo_uris, ct_woo_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_JOOMLA,
      ct_joomla_cookies, ct_joomla_uris, ct_joomla_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_XENFORO,
      ct_xf_cookies, ct_xf_uris, ct_xf_args, NULL, ct_xf_key_cookies },
    { NGX_HTTP_CACHE_TURBO_BACKEND_DISCOURSE,
      ct_discourse_cookies, ct_discourse_uris, ct_discourse_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_PHPBB,
      ct_phpbb_cookies, ct_phpbb_uris, ct_phpbb_args, ct_phpbb_preds, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_DRUPAL,
      ct_drupal_cookies, ct_drupal_uris, ct_drupal_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_MEDIAWIKI,
      ct_mw_cookies, ct_mw_uris, ct_mw_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_MAGENTO,
      ct_magento_cookies, ct_magento_uris, ct_magento_args, NULL,
      ct_magento_key_cookies },
    { NGX_HTTP_CACHE_TURBO_BACKEND_GHOST,
      ct_ghost_cookies, ct_ghost_uris, ct_ghost_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_WAGTAIL,
      ct_wagtail_cookies, ct_wagtail_uris, ct_wagtail_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_KIRBY,
      ct_kirby_cookies, ct_kirby_uris, ct_kirby_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_SHOPWARE6,
      ct_shopware6_cookies, ct_shopware6_uris, ct_shopware6_args, NULL,
      ct_shopware6_key_cookies },
    { NGX_HTTP_CACHE_TURBO_BACKEND_TYPO3,
      ct_typo3_cookies, ct_typo3_uris, ct_typo3_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_INVISION,
      ct_invision_cookies, ct_invision_uris, ct_invision_args,
      ct_invision_preds, ct_invision_key_cookies },
    { NGX_HTTP_CACHE_TURBO_BACKEND_SMF,
      ct_smf_cookies, ct_smf_uris, ct_smf_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_VANILLA,
      ct_vanilla_cookies, ct_vanilla_uris, ct_vanilla_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_PUNBB,
      ct_punbb_cookies, ct_punbb_uris, ct_punbb_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_PHORUM,
      ct_phorum_cookies, ct_phorum_uris, ct_phorum_args, NULL,
      ct_phorum_key_cookies },
    { NGX_HTTP_CACHE_TURBO_BACKEND_YABB,
      ct_yabb_cookies, ct_yabb_uris, ct_yabb_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_MYBB,
      ct_mybb_cookies, ct_mybb_uris, ct_mybb_args, ct_mybb_preds,
      ct_mybb_key_cookies },
    { NGX_HTTP_CACHE_TURBO_BACKEND_VBULLETIN,
      ct_vbulletin_cookies, ct_vbulletin_uris, ct_vbulletin_args,
      ct_vbulletin_preds, ct_vbulletin_key_cookies },
    { NGX_HTTP_CACHE_TURBO_BACKEND_TEXTPATTERN,
      ct_textpattern_cookies, ct_textpattern_uris, ct_textpattern_args,
      NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_BLUDIT,
      ct_bludit_cookies, ct_bludit_uris, ct_bludit_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_SPIP,
      ct_spip_cookies, ct_spip_uris, ct_spip_args, ct_spip_preds, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_BUGZILLA,
      ct_bugzilla_cookies, ct_bugzilla_uris, ct_bugzilla_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_MANTISBT,
      ct_mantisbt_cookies, ct_mantisbt_uris, ct_mantisbt_args,
      ct_mantisbt_preds, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_PLONE,
      ct_plone_cookies, ct_plone_uris, ct_plone_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_UMBRACO,
      ct_umbraco_cookies, ct_umbraco_uris, ct_umbraco_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_DOTCLEAR,
      ct_dotclear_cookies, ct_dotclear_uris, ct_dotclear_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_WIKIJS,
      ct_wikijs_cookies, ct_wikijs_uris, ct_wikijs_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_REDMINE,
      ct_redmine_cookies, ct_redmine_uris, ct_redmine_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_FLARUM,
      ct_flarum_cookies, ct_flarum_uris, ct_flarum_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_OPENCART,
      ct_opencart_cookies, ct_opencart_uris, ct_opencart_args, NULL, NULL },
    { 0, NULL, NULL, NULL, NULL, NULL }
};


/* True if any request Cookie header contains one of the NULL-terminated name
 * substrings (the login/session cookies carry dynamic suffixes, so a substring
 * match on the distinctive prefix is the right test, not an exact-name lookup). */
static ngx_int_t
ngx_http_cache_turbo_cookie_has(ngx_http_request_t *r,
    const char *const *subs)
{
    const char *const  *pp;
#if (nginx_version >= 1023000)
    ngx_table_elt_t    *ck;

    for (ck = r->headers_in.cookie; ck; ck = ck->next) {
        for (pp = subs; *pp; pp++) {
            if (ngx_strnstr(ck->value.data, (char *) *pp, ck->value.len)
                != NULL)
            {
                return 1;
            }
        }
    }
#else
    ngx_table_elt_t   **ckp;
    ngx_uint_t          i;

    ckp = r->headers_in.cookies.elts;
    for (i = 0; i < r->headers_in.cookies.nelts; i++) {
        for (pp = subs; *pp; pp++) {
            if (ngx_strnstr(ckp[i]->value.data, (char *) *pp,
                            ckp[i]->value.len) != NULL)
            {
                return 1;
            }
        }
    }
#endif
    return 0;
}


/*
 * Cookie VALUE predicates (tier 2). The substring matcher above tests only that
 * a cookie NAME appears somewhere in the header. Some applications cannot be
 * classified that way at all: they issue the same cookie to guests and members
 * and encode the distinction in its VALUE. phpBB is the type case — every
 * non-bot visitor gets <prefix>_u, a guest's holds ANONYMOUS (the literal 1) and
 * a member's holds their user_id (never 1, ANONYMOUS is a reserved row). A
 * presence rule there matches all traffic and identifies nobody; a value rule
 * separates them exactly.
 *
 * TWO PROPERTIES OF THIS PARSER ARE LOAD-BEARING. Both were derived from the
 * upstream source, not assumed:
 *
 * 1. NAME-SUFFIX MATCHING, not exact names. phpBB's cookie is
 *    $config['cookie_name'] . '_u' (phpbb/session.php, set_cookie()), and
 *    cookie_name is an ACP setting — it defaults to "phpbb" (so the wire name is
 *    "phpbb_u") but installers randomise it and any admin running two boards on
 *    one domain changes it. A rule keyed on a literal name silently STOPS
 *    MATCHING on such a board, and a bypass rule that stops matching means the
 *    member's page is cached and served to strangers. Matching the name SUFFIX
 *    ("_u") is prefix-agnostic and therefore safe. It can over-match an
 *    unrelated cookie that happens to end in _u, which costs a needless bypass
 *    and never leaks — the correct direction to err.
 *
 * 2. UNPARSEABLE => BYPASS (fail closed to the cache, open to the origin). If
 *    the header is malformed, truncated, or the name matches with no '=' , we
 *    return "dynamic" rather than "cacheable". A false bypass costs one cache
 *    miss; a false hit costs somebody else's authenticated page. Every ambiguous
 *    path below returns 1.
 *
 * The value is compared against a literal (op EQ/NE) or merely required to be
 * non-empty (op NONEMPTY). Comparison is exact and length-checked: a cookie
 * "_u=10" must NOT satisfy "_u == 1".
 *
 * Cookie header grammar (RFC 6265 §4.2.1): cookie-pair *( ";" SP cookie-pair ).
 * We tolerate the sloppiness real clients emit — arbitrary OWS around ';' and
 * '=', missing SP, empty pairs — because a parser that only accepts well-formed
 * input would treat a malformed header as "no match" and, under a presence-only
 * reading, silently cache it. r->headers_in cookie values are NOT
 * NUL-terminated: every scan below is bounded by ck->value.len. (The fuzz
 * harness drives this function with arbitrary non-NUL-terminated bytes under
 * ASan for exactly this reason — ci/fuzz/ngx_shim_auto.h.)
 */


/* True if the cookie name [n, n+nlen) ends with the NUL-terminated suffix. */
static ngx_int_t
ngx_http_cache_turbo_name_has_suffix(u_char *n, size_t nlen, const char *suffix)
{
    size_t  slen;

    slen = ngx_strlen(suffix);

    if (slen == 0 || nlen < slen) {
        return 0;
    }

    return ngx_strncmp(n + (nlen - slen), suffix, slen) == 0;
}


/*
 * Evaluate one predicate against one Cookie header value (which may itself hold
 * several ';'-separated pairs). Returns 1 = request is dynamic (bypass), 0 = no
 * opinion. "No opinion" is NOT "cacheable": the caller ORs the results of every
 * predicate of every active preset, and a request nothing objects to is cached.
 * A predicate whose cookie is ABSENT must therefore return 0 — for phpBB that is
 * correct, since a visitor with no _u at all has no session and is a guest.
 */
static ngx_int_t
ngx_http_cache_turbo_cookie_pred_one(u_char *data, size_t len,
    const ngx_http_cache_turbo_cookie_pred_t *pr)
{
    u_char  *p, *end, *name, *eq, *val;
    size_t   nlen, vlen, plen, cmplen;

    /* An empty (or absent) Cookie value: nothing to match, and no opinion. The
     * explicit guard is required, not cosmetic — a header can carry data == NULL
     * with len == 0, and computing `data + len` on a NULL pointer is undefined
     * behaviour even when the offset is zero (UBSan: "applying zero offset to
     * null pointer"). The fuzzer hit this on its first empty input. */
    if (data == NULL || len == 0) {
        return 0;
    }

    p = data;
    end = data + len;

    while (p < end) {

        /* Skip leading OWS and stray ';' before this pair. */
        while (p < end && (*p == ' ' || *p == '\t' || *p == ';')) {
            p++;
        }
        if (p >= end) {
            break;
        }

        /* The pair runs to the next ';' or to the end of the header value. */
        name = p;
        while (p < end && *p != ';') {
            p++;
        }
        plen = (size_t) (p - name);

        /* Trim trailing OWS off the pair. */
        while (plen > 0
               && (name[plen - 1] == ' ' || name[plen - 1] == '\t'))
        {
            plen--;
        }
        if (plen == 0) {
            continue;                       /* empty pair ("; ;") — ignore */
        }

        /* Split name '=' value, bounded by plen (no NUL to lean on). */
        eq = ngx_strlchr(name, name + plen, '=');

        if (eq == NULL) {
            /* A bare cookie with no '='. If its NAME is the one we key on, we
             * cannot read a value and must not guess: fail closed to bypass. */
            nlen = plen;
            while (nlen > 0 && (name[nlen - 1] == ' ' || name[nlen - 1] == '\t')) {
                nlen--;
            }
            if (ngx_http_cache_turbo_name_has_suffix(name, nlen,
                                                     pr->name_suffix))
            {
                return 1;                   /* unparseable => bypass */
            }
            continue;
        }

        nlen = (size_t) (eq - name);
        while (nlen > 0 && (name[nlen - 1] == ' ' || name[nlen - 1] == '\t')) {
            nlen--;                          /* OWS before '=' */
        }

        if (!ngx_http_cache_turbo_name_has_suffix(name, nlen,
                                                  pr->name_suffix))
        {
            continue;                        /* different cookie */
        }

        /* Value = everything after '=' to the end of the pair, OWS-trimmed. */
        val = eq + 1;
        while (val < name + plen && (*val == ' ' || *val == '\t')) {
            val++;
        }
        vlen = (size_t) ((name + plen) - val);

        /* A "this pair says cacheable" answer must NOT end the scan: the header
         * can carry several cookies whose names all end in the suffix (phpBB
         * keys on `_u`, and `phpbb3_<hash>_u` is per-board, so one browser
         * visiting two boards on the same host sends two of them). Whichever
         * one comes first would otherwise decide for the whole request, and a
         * leading guest `_u=1` would mask a member `_u=42` behind it — serving
         * and storing that member's page. So only `continue` here; bypass (1)
         * still returns immediately, and "no pair objected" is the loop's exit
         * value below.
         *
         * cmplen is deliberately NOT plen: plen is this pair's length and is
         * still what bounds `val` above. Reusing it for the predicate value's
         * length is safe only for as long as every arm returns. */
        cmplen = (pr->value != NULL) ? ngx_strlen(pr->value) : 0;

        switch (pr->op) {

        case NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY:
            if (vlen > 0) {
                return 1;
            }
            continue;

        case NGX_HTTP_CACHE_TURBO_CVOP_EQ:
            /* A value-comparing op with no literal cannot match anything.
             * Guard it: the registry never ships such a row, but the compare
             * below passes pr->value to a nonnull parameter. */
            if (pr->value != NULL
                && vlen == cmplen
                && ngx_strncmp(val, pr->value, cmplen) == 0)
            {
                return 1;
            }
            continue;

        case NGX_HTTP_CACHE_TURBO_CVOP_NE:
        default:
            /* The phpBB case. An EMPTY value ("_u=") is not the guest literal
             * "1", so by the letter of != it is a member — but it is really a
             * malformed/cleared cookie. Bypass either way: both readings agree,
             * and bypass is the safe direction. */
            if (pr->value != NULL
                && vlen == cmplen
                && ngx_strncmp(val, pr->value, cmplen) == 0)
            {
                continue;                    /* == the guest literal: cacheable */
            }
            return 1;                        /* anything else (incl. a row with
                                              * no literal): bypass, the safe
                                              * direction */
        }
    }

    return 0;                                /* cookie absent: no opinion */
}


/* True if any predicate in the NULL-terminated list fires against any Cookie
 * header on the request. */
static ngx_int_t
ngx_http_cache_turbo_cookie_pred(ngx_http_request_t *r,
    const ngx_http_cache_turbo_cookie_pred_t *preds)
{
    const ngx_http_cache_turbo_cookie_pred_t  *pr;
#if (nginx_version >= 1023000)
    ngx_table_elt_t                           *ck;

    for (pr = preds; pr->name_suffix; pr++) {
        for (ck = r->headers_in.cookie; ck; ck = ck->next) {
            if (ngx_http_cache_turbo_cookie_pred_one(ck->value.data,
                                                     ck->value.len, pr))
            {
                return 1;
            }
        }
    }
#else
    ngx_table_elt_t                          **ckp;
    ngx_uint_t                                 i;

    ckp = r->headers_in.cookies.elts;
    for (pr = preds; pr->name_suffix; pr++) {
        for (i = 0; i < r->headers_in.cookies.nelts; i++) {
            if (ngx_http_cache_turbo_cookie_pred_one(ckp[i]->value.data,
                                                     ckp[i]->value.len, pr))
            {
                return 1;
            }
        }
    }
#endif
    return 0;
}


/*
 * Extract the VALUE of one cookie from one Cookie header value, by EXACT name.
 * Returns 1 and fills *val when the cookie is present, 0 otherwise. A present
 * cookie with an empty or absent value yields a zero-length *val and still
 * returns 1 — "present but empty" is a distinct key from "absent", and both are
 * distinct from any real value.
 *
 * EXACT name, not the suffix rule the predicate engine uses. A key cookie is
 * shipped by the application under a fixed name (X-Magento-Vary), and the name
 * bounds a value that goes into the CACHE KEY: a loose match would let an
 * attacker-chosen cookie ("NOT-X-Magento-Vary") select which bucket a victim's
 * request lands in. The predicate engine can afford suffix matching because its
 * failure direction is a needless bypass; keying cannot.
 */
static ngx_int_t
ngx_http_cache_turbo_cookie_value(u_char *data, size_t len, const char *name,
    size_t nmlen, ngx_str_t *val)
{
    u_char  *p, *end, *pair, *eq, *v;
    size_t   plen, nlen;

    /* NULL data with len == 0: `data + len` is UB even at zero offset. */
    if (data == NULL || len == 0) {
        return 0;
    }

    p = data;
    end = data + len;

    while (p < end) {

        while (p < end && (*p == ' ' || *p == '\t' || *p == ';')) {
            p++;
        }
        if (p >= end) {
            break;
        }

        pair = p;
        while (p < end && *p != ';') {
            p++;
        }
        plen = (size_t) (p - pair);

        while (plen > 0 && (pair[plen - 1] == ' ' || pair[plen - 1] == '\t')) {
            plen--;
        }
        if (plen == 0) {
            continue;
        }

        eq = ngx_strlchr(pair, pair + plen, '=');

        if (eq == NULL) {
            /* Bare cookie, no '='. If it is ours, it is present with no value. */
            nlen = plen;
            while (nlen > 0 && (pair[nlen - 1] == ' ' || pair[nlen - 1] == '\t')) {
                nlen--;
            }
            if (nlen == nmlen && ngx_strncmp(pair, name, nmlen) == 0) {
                val->data = pair;
                val->len = 0;
                return 1;
            }
            continue;
        }

        nlen = (size_t) (eq - pair);
        while (nlen > 0 && (pair[nlen - 1] == ' ' || pair[nlen - 1] == '\t')) {
            nlen--;
        }

        if (nlen != nmlen || ngx_strncmp(pair, name, nmlen) != 0) {
            continue;
        }

        v = eq + 1;
        while (v < pair + plen && (*v == ' ' || *v == '\t')) {
            v++;
        }
        val->data = v;
        val->len = (size_t) ((pair + plen) - v);
        return 1;
    }

    return 0;
}


/*
 * URI prefix match with a PATH-SEGMENT BOUNDARY. A preset URI rule like "/user"
 * must bypass "/user" and "/user/settings" but NOT "/users-guide" — a bare
 * ngx_strncmp prefix test matches all three and silently over-bypasses (a
 * hit-rate loss) or, worse for a slash-less rule that is a genuine prefix of an
 * unrelated public path, un-caches real content.
 *
 * A match requires the prefix, and then the URI must either END or continue with
 * a boundary byte. Boundary bytes are '/' AND '.': '.' matters because Rails-
 * style backends serve the same controller action with a format suffix appended
 * directly to the path ("/notifications" -> "/notifications.json"), and those
 * suffixed variants are the DYNAMIC endpoint we must keep bypassing. Requiring
 * only '/' would un-bypass "/notifications.json" and leak it. Note r->uri never
 * contains the query string (nginx splits it into r->args), so '/' and '.' are
 * the only boundaries that occur.
 *
 * Rules that already carry their own boundary (a trailing '/' like "/wp-admin/",
 * or a file suffix like "/xmlrpc.php") are unaffected: the byte after the prefix
 * is fixed by the needle itself, so the extra check is always satisfied.
 */
static ngx_int_t
ngx_http_cache_turbo_uri_prefix(ngx_str_t *uri, const char *pfx, size_t l)
{
    u_char  next;

    if (uri->len < l || ngx_strncmp(uri->data, pfx, l) != 0) {
        return 0;
    }

    if (uri->len == l) {
        return 1;                       /* exact match: "/panel" == "/panel" */
    }

    /* A needle that already ends in a boundary ("/wp-admin/") carries its own
     * segment terminator: any continuation is inside the matched subtree, so a
     * plain prefix is the whole test. Only slash-less needles ("/panel") need
     * the trailing byte checked. */
    if (pfx[l - 1] == '/') {
        return 1;
    }

    next = uri->data[l];
    return (next == '/' || next == '.');
}


/* One hex nibble -> 0..15, or -1 on a non-hex char. Lives inside the
 * FUZZ-EXTRACT region because the query-string decoder below needs it; the
 * hex-decode helpers further down share it. */
static ngx_int_t
ngx_http_cache_turbo_hexval(u_char c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
}


/*
 * Compare one raw query-string span against a plain needle, percent-DECODING
 * the span as it goes.
 *
 * The backend routes on the decoded query string: PHP's $_GET turns "%61ction"
 * into "action" and "log%69n" into "login", and every forum family in the
 * preset table routes that way. Comparing the raw bytes therefore misses a
 * request the backend treats as identical to one the classifier does catch, so
 * an over-encoded (or deliberately encoded) login/logout/PM URL is classified
 * cacheable and gets stored. Decoding as we compare needs no buffer and no
 * length cap, so a megabyte-long value costs one walk and nothing else.
 *
 * Malformed escapes ("%", "%A", "%GG") compare as a literal '%' followed by
 * whatever follows it, which is how PHP's parser leaves them.
 *
 * `name` selects PHP's key mangling, and only argument NAMES get it. PHP builds
 * $_GET keys through php_register_variable_ex(), which rewrites '.' and ' ' to
 * '_' — a habit inherited from register_globals, where a key had to be a legal
 * variable name. So "%2ExfToken", "xf+Token" and "ips4.hasJS" all arrive at the
 * application as "_xfToken" / "xf_Token" / "ips4_hasJS", and a matcher that
 * only percent-decodes misses every one of them. Underscores are common in the
 * needles (_xfToken, api_key, ips4_theme, woocommerce_cart_hash), so this is
 * the same fail-open as the encoding case, one alphabet further out.
 *
 * A LITERAL '+' is a space here (form encoding), so it mangles to '_' too; a
 * percent-escaped one ("%2B") decodes to a real '+' and PHP leaves it alone, so
 * the two are tracked apart. PHP additionally strips leading spaces from a key,
 * which this does not — a leading space folds to '_' instead. That direction
 * over-matches (an unnecessary bypass, hit rate only) where the alternative
 * would under-match, which is a cached private page.
 *
 * VALUES are never mangled by PHP and are not mangled here. A '+' in a value
 * stays a '+': every needle value is a fixed route token with no space in it,
 * so no treatment of '+' can create or destroy a match.
 */
static ngx_int_t
ngx_http_cache_turbo_qs_eq(u_char *p, u_char *end, const char *needle,
    size_t nlen, ngx_uint_t name)
{
    size_t     i;
    u_char     c;
    ngx_int_t  hi, lo, decoded;

    for (i = 0; p < end; i++) {

        c = *p++;
        decoded = 0;

        if (c == '%' && (size_t) (end - p) >= 2
            && (hi = ngx_http_cache_turbo_hexval(p[0])) >= 0
            && (lo = ngx_http_cache_turbo_hexval(p[1])) >= 0)
        {
            c = (u_char) ((hi << 4) | lo);
            p += 2;
            decoded = 1;
        }

        if (name) {
            if (c == '+' && !decoded) {
                c = '_';                /* literal '+' is a space, and mangles */

            } else if (c == '.' || c == ' ') {
                c = '_';
            }
        }

        if (i >= nlen || c != (u_char) needle[i]) {
            return 0;
        }
    }

    return i == nlen;
}


/*
 * Scan the query string for an argument, and keep scanning past a non-match.
 *
 * Replaces ngx_http_arg() for preset classification. ngx_http_arg has two
 * properties that are wrong here:
 *
 *   1. It returns the FIRST occurrence of the name and stops. A query string
 *      may legally repeat a name ("?action=profile&action=logout"), and the
 *      backend decides which one wins — PHP's $_GET keeps the LAST. Stopping on
 *      the first meant an attacker prefixed a harmless value and the real
 *      dynamic route behind it was never seen, so the private page was cached.
 *      Every occurrence is checked here; any match is a match.
 *   2. It does not percent-decode, and it splits only on '&'. SMF and YaBB
 *      build nearly every multi-argument URL with ';' as the separator
 *      ("?action=profile;u=42"), a form PHP's arg_separator.input has accepted
 *      for its whole life — so with '&'-only splitting, only the first argument
 *      of such a URL was ever visible and the rest of those presets' arg rows
 *      matched nothing at all.
 *
 * `value == NULL` means the rule is a bare NAME and presence alone is the
 * signal (an empty "sid=" counts as present, matching ngx_http_arg). Otherwise
 * the decoded value must equal `value` exactly.
 *
 * Splitting on ';' can also split a value that carries an unescaped ';'
 * ("?next=/a;b"), which can only ever manufacture an EXTRA apparent argument.
 * That direction fails safe: the worst case is an unnecessary bypass (hit-rate
 * loss), never a cached private page.
 */
static ngx_int_t
ngx_http_cache_turbo_arg_match(ngx_http_request_t *r, const char *name,
    size_t nlen, const char *value, size_t vlen)
{
    u_char  *p, *end, *pair, *pend, *eq;

    if (r->args.data == NULL || r->args.len == 0) {
        return 0;
    }

    p = r->args.data;
    end = p + r->args.len;

    while (p < end) {

        pair = p;
        while (p < end && *p != '&' && *p != ';') {
            p++;
        }
        pend = p;

        if (p < end) {
            p++;                        /* step over the separator */
        }

        if (pend == pair) {
            continue;                   /* "&&", leading '&', trailing '&' */
        }

        eq = ngx_strlchr(pair, pend, '=');

        if (eq == NULL) {
            /* Valueless argument ("?...&sid&..."). Only a bare-NAME rule can
             * match it; a NAME=VALUE rule has nothing to compare against. */
            if (value == NULL
                && ngx_http_cache_turbo_qs_eq(pair, pend, name, nlen, 1))
            {
                return 1;
            }
            continue;
        }

        if (!ngx_http_cache_turbo_qs_eq(pair, eq, name, nlen, 1)) {
            continue;
        }

        if (value == NULL) {
            return 1;
        }

        if (ngx_http_cache_turbo_qs_eq(eq + 1, pend, value, vlen, 0)) {
            return 1;
        }
    }

    return 0;
}


/*
 * Auto-classify gate. Returns 1 when the request matches a dynamic surface of
 * any active preset (login/session cookie, backend URI prefix, dynamic query
 * arg) and must therefore skip the cache entirely (origin, never capture). 0 =
 * treat as cacheable and continue. Runs only when backend_presets != 0; sits
 * UNDER the manual bypass/no_store overrides (those are checked separately).
 */
static ngx_int_t
ngx_http_cache_turbo_auto_skip(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf)
{
    const ngx_http_cache_turbo_preset_t  *ps;
    const char *const                    *pp;
    const char                           *eq;
    size_t                                l, nlen, vlen;
    ngx_str_t                             uri;

    /* Preset uris[] are literals anchored at byte 0 ("/wp-admin/"), so a
     * subdirectory install matches nothing unless we rebase the URI onto the
     * configured mount point. Loop-invariant, so computed once.
     *
     * The mount's trailing '/' is RETAINED as the rebased URI's leading '/':
     * "/shop/" over "/shop/wp-admin/" yields "/wp-admin/", which is the shape
     * every needle is written in. A URI outside the mount is left alone rather
     * than force-matched, so "/other/wp-admin/" on a "/shop/"-mounted site does
     * not inherit the mounted app's rules. */
    uri = r->uri;

    if (clcf->backend_prefix != NULL
        && clcf->backend_prefix != NGX_CONF_UNSET_PTR)
    {
        l = clcf->backend_prefix->len;

        if (uri.len >= l
            && ngx_strncmp(uri.data, clcf->backend_prefix->data, l) == 0)
        {
            uri.data += l - 1;          /* keep the mount's trailing '/' */
            uri.len  -= l - 1;
        }
    }

    for (ps = ngx_http_cache_turbo_presets; ps->bit; ps++) {
        if (!(clcf->backend_presets & ps->bit)) {
            continue;
        }

        for (pp = ps->uris; *pp; pp++) {
            l = ngx_strlen(*pp);
            if (ngx_http_cache_turbo_uri_prefix(&uri, *pp, l)) {
                return 1;
            }
        }

        if (r->args.len) {
            for (pp = ps->args; *pp; pp++) {
                eq = ngx_strchr(*pp, '=');

                if (eq == NULL) {
                    /* Bare NAME: presence of the argument is the signal,
                     * whatever its value ("_xfToken", "sid"). */
                    if (ngx_http_cache_turbo_arg_match(r, *pp,
                                                       ngx_strlen(*pp), NULL, 0))
                    {
                        return 1;
                    }
                    continue;
                }

                /* NAME=VALUE: the forum families that route everything through
                 * one script ("index.php?action=login", "?do=compose") cannot
                 * be classified on the argument NAME — `action` and `do` also
                 * carry the ordinary read routes, so matching the bare name
                 * would bypass the whole board. Match the exact value instead.
                 * Values are fixed route tokens, so an exact byte compare is
                 * the whole test; no case folding, no prefix match. */
                nlen = (size_t) (eq - *pp);
                vlen = ngx_strlen(eq + 1);

                if (ngx_http_cache_turbo_arg_match(r, *pp, nlen,
                                                   eq + 1, vlen))
                {
                    return 1;
                }
            }
        }

        if (ngx_http_cache_turbo_cookie_has(r, ps->cookies)) {
            return 1;
        }

        /* Tier-2 value predicates. Only presets that cannot be classified by
         * cookie-name presence carry these (phpbb: <prefix>_u != ANONYMOUS). */
        if (ps->cookie_preds != NULL
            && ngx_http_cache_turbo_cookie_pred(r, ps->cookie_preds))
        {
            return 1;
        }
    }

    return 0;
}


/*
 * Look the request's key cookie up across EVERY Cookie header. A client may
 * legally split its cookies over several Cookie headers, and Magento's own VCL
 * runs std.collect(req.http.Cookie) before it looks — without that, a request
 * that carries a decoy in the first header and the real cookie in the second
 * would key on the decoy, i.e. an attacker could CHOOSE which cache bucket to
 * read from or write to. Every header is scanned; the FIRST occurrence of the
 * name wins, which is the same rule a browser's own single header would give.
 *
 * This is an ITERATOR, not a single lookup. A preset may declare several key
 * cookies (and several presets may be enabled at once); returning only the
 * first present one made every cookie behind it dead — the key ignored it, so
 * two requests that differ only in that cookie shared an entry, which is the
 * cache leak the key cookie exists to prevent. The caller drives it to
 * exhaustion and folds EVERY present cookie into the key.
 *
 * *cursor must be 0 on the first call and is carried unchanged between calls;
 * it is the index (over the flattened enabled-preset x key-cookie sequence) of
 * the next candidate to examine. The sequence is walked from the start each
 * call — it is at most a dozen entries, and this keeps the iterator a pure
 * function of (request, presets, cursor).
 *
 * *name_out is set to the matched preset name so the key can record WHICH cookie
 * produced the value (two presets with key cookies must not produce the same key
 * suffix from different cookies). Returns 1 when a key cookie was found.
 */
static ngx_int_t
ngx_http_cache_turbo_key_cookie(ngx_http_request_t *r,
    ngx_uint_t backend_presets, ngx_uint_t *cursor, ngx_str_t *name_out,
    ngx_str_t *val_out)
{
    const ngx_http_cache_turbo_preset_t  *ps;
    const char *const                    *pp;
    size_t                                nmlen;
    ngx_uint_t                            idx = 0;
#if (nginx_version >= 1023000)
    ngx_table_elt_t                      *ck;
#else
    ngx_table_elt_t                     **ckp;
    ngx_uint_t                            i;
#endif

    for (ps = ngx_http_cache_turbo_presets; ps->bit; ps++) {
        if (!(backend_presets & ps->bit) || ps->key_cookies == NULL) {
            continue;
        }

        for (pp = ps->key_cookies; *pp; pp++, idx++) {

            if (idx < *cursor) {         /* already returned by an earlier call */
                continue;
            }

            nmlen = ngx_strlen(*pp);

#if (nginx_version >= 1023000)
            for (ck = r->headers_in.cookie; ck; ck = ck->next) {
                if (ngx_http_cache_turbo_cookie_value(ck->value.data,
                                                      ck->value.len,
                                                      *pp, nmlen, val_out))
                {
                    name_out->data = (u_char *) *pp;
                    name_out->len = nmlen;
                    *cursor = idx + 1;
                    return 1;
                }
            }
#else
            ckp = r->headers_in.cookies.elts;
            for (i = 0; i < r->headers_in.cookies.nelts; i++) {
                if (ngx_http_cache_turbo_cookie_value(ckp[i]->value.data,
                                                      ckp[i]->value.len,
                                                      *pp, nmlen, val_out))
                {
                    name_out->data = (u_char *) *pp;
                    name_out->len = nmlen;
                    *cursor = idx + 1;
                    return 1;
                }
            }
#endif
        }
    }

    *cursor = idx;                       /* sequence exhausted */
    return 0;
}
/* >>> FUZZ-EXTRACT auto-classify END <<< */


/*
 * DIY manual URI bypass (cache_turbo_bypass_uri). Returns 1 when r->uri matches
 * any configured prefix on a path-segment boundary, using the SAME matcher the
 * presets use (ngx_http_cache_turbo_uri_prefix) — so an app we ship no preset
 * for gets the identical subdirectory-safe bypass a preset URI rule would give,
 * with the same origin-and-never-capture treatment (the caller sets
 * ctx->auto_skip). Runs independently of backend_presets, so it works in pure
 * manual mode. Config-driven, so it lives OUTSIDE the fuzz-extracted preset
 * classifier. NULL / empty list => 0 (no cost when unused).
 */
static ngx_int_t
ngx_http_cache_turbo_bypass_uri_match(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf)
{
    ngx_str_t   *pfx;
    ngx_uint_t   i;

    if (clcf->bypass_uri == NULL
        || clcf->bypass_uri == NGX_CONF_UNSET_PTR)
    {
        return 0;
    }

    pfx = clcf->bypass_uri->elts;
    for (i = 0; i < clcf->bypass_uri->nelts; i++) {
        if (ngx_http_cache_turbo_uri_prefix(&r->uri, (char *) pfx[i].data,
                                            pfx[i].len))
        {
            return 1;
        }
    }

    return 0;
}


/*
 * Config-driven cookie lookup for cache_turbo_key_cookie: find NAME's value
 * across EVERY Cookie header (same all-headers scan and first-occurrence-wins
 * rule as ngx_http_cache_turbo_key_cookie for the presets, and the same reason
 * — an attacker must not hide the real cookie in a second header to pick a
 * bucket). NAME comes from config (an ngx_str_t) rather than the preset's
 * NUL-terminated C string, so it is matched by explicit length. Returns 1 and
 * fills *val_out when found.
 */
static ngx_int_t
ngx_http_cache_turbo_cookie_lookup(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *val_out)
{
#if (nginx_version >= 1023000)
    ngx_table_elt_t  *ck;

    for (ck = r->headers_in.cookie; ck; ck = ck->next) {
        if (ngx_http_cache_turbo_cookie_value(ck->value.data, ck->value.len,
                                              (char *) name->data, name->len,
                                              val_out))
        {
            return 1;
        }
    }
#else
    ngx_table_elt_t  **ckp;
    ngx_uint_t          i;

    ckp = r->headers_in.cookies.elts;
    for (i = 0; i < r->headers_in.cookies.nelts; i++) {
        if (ngx_http_cache_turbo_cookie_value(ckp[i]->value.data,
                                              ckp[i]->value.len,
                                              (char *) name->data, name->len,
                                              val_out))
        {
            return 1;
        }
    }
#endif

    return 0;
}


/* PURGE (v14) runs in the PRECONTENT phase, NOT the ACCESS phase. The ACCESS
 * phase (allow/deny, auth_basic, …) must complete first: handling PURGE in
 * ACCESS and returning NGX_DONE would short-circuit the phase engine and let an
 * unauthorized client purge the cache despite the documented allow/deny gate.
 * Precontent runs after access, so a 403 from allow/deny fires before we get
 * here. */
static ngx_int_t
ngx_http_cache_turbo_precontent_handler(ngx_http_request_t *r)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);

    if (!clcf->enable || clcf->shm_zone == NULL || !clcf->purge) {
        return NGX_DECLINED;
    }

    if (r != r->main
        || r->method_name.len != sizeof("PURGE") - 1
        || ngx_strncmp(r->method_name.data, "PURGE", sizeof("PURGE") - 1) != 0)
    {
        return NGX_DECLINED;
    }

    return ngx_http_cache_turbo_purge_request(r, clcf);
}


/*
 * CQ-2: prologue gates + per-request setup shared by every (re)entry of the
 * access handler (a parked L2/lock resume re-enters the handler, so this runs
 * again — build_key/auto-classify/no-cache/vary/bypass all re-evaluate, exactly
 * as before the extraction). Returns NGX_OK with ctxp/zp/hashp populated when
 * the caller should proceed to the L1 lookup; any other value is what the
 * handler must return (NGX_DECLINED for the not-cacheable/skip/bypass gates,
 * NGX_ERROR on ctx alloc / key build failure).
 */
static ngx_int_t
ngx_http_cache_turbo_access_prologue(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_http_cache_turbo_ctx_t **ctxp, ngx_http_cache_turbo_zone_t **zp,
    uint32_t *hashp)
{
    uint32_t                      hash;
    ngx_http_cache_turbo_ctx_t   *ctx;
    ngx_http_cache_turbo_zone_t  *z;

    if (!clcf->enable || clcf->shm_zone == NULL) {
        return NGX_DECLINED;
    }

    /* PURGE is handled by the preceding PRECONTENT handler. Both handlers run
     * after ACCESS so cache hits cannot bypass allow/deny or auth modules. */

    /* Only cache safe idempotent reads for v1. */
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }

    if (r != r->main) {
        /* subrequest (e.g. our own background refresh) — never serve from
         * cache, let it hit the origin and repopulate. A warm subrequest (v3-3)
         * builds its key + captures in the header/body filters. */
        return NGX_DECLINED;
    }

    /* RFC 9111 shared-cache safety: do not reuse a public representation for a
     * request carrying credentials. response_cacheable() already prevents the
     * resulting response from being stored; this is the matching lookup gate. */
    if (r->headers_in.authorization != NULL) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_cache_turbo_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_cache_turbo_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_cache_turbo_module);
    }

    if (ngx_http_cache_turbo_build_key(r, clcf, ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Q1: cache-turbo is engaged for this request (enabled, cacheable method,
     * main request). The $cache_turbo_active variable reads this (gated by
     * cache_turbo_suppress_native) so a stacked native proxy_cache can defer.
     * Set before the bypass check on purpose: a bypassing request still stores
     * the fresh response, so native should defer to us on that path too. */
    ctx->ct_active = 1;

    z = clcf->shm_zone->data;
    hash = ngx_crc32_short(ctx->key_hash, 32);

    /* Auto-classify (cache_turbo auto / cache_turbo_backend): a curated union of
     * CMS cacheability heuristics. When the request matches a dynamic surface of
     * an active preset (login/session cookie, backend URI, dynamic arg) skip the
     * cache entirely — go to the origin and never capture (ctx->auto_skip vetoes
     * the body filter). Sits under the manual bypass/no_store overrides below.
     * honor_cc is auto-enabled with a preset so a plugin's own Cache-Control:
     * no-cache on an anon page self-excludes at store time. */
    if ((NGX_HTTP_CACHE_TURBO_HAS_BACKEND(clcf->backend_presets)
         && ngx_http_cache_turbo_auto_skip(r, clcf))
        || ngx_http_cache_turbo_bypass_uri_match(r, clcf))
    {
        ctx->auto_skip = 1;
        /* cache-turbo neither serves nor stores an auto-classified dynamic
         * request, so it is NOT "engaged": leave $cache_turbo_active = 0 so a
         * stacked native cache is free to handle the URL itself. */
        ctx->ct_active = 0;
        ctx->status = NGX_HTTP_CACHE_TURBO_ST_BYPASS;
        (void) ngx_atomic_fetch_add(&z->sh->misses, 1);
        (void) ngx_atomic_fetch_add(&z->sh->bypasses, 1);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: auto-classify dynamic \"%V\" -> origin",
                       &r->uri);
        return NGX_DECLINED;
    }

    /* RFC-1 request Cache-Control, parsed once here for the whole request:
     * only-if-cached gates the origin-bound miss paths below (-> 504), no-store
     * vetoes capture in the header filter. */
    ctx->req_only_if_cached = ngx_http_cache_turbo_request_only_if_cached(r, ctx);
    ctx->req_no_store = ngx_http_cache_turbo_request_no_store(r, ctx);
    ngx_http_cache_turbo_request_freshness_bounds(r, ctx);

    /* Request Cache-Control: no-cache / Pragma: no-cache / max-age=0 (RFC 9111
     * §5.2.1.1/§5.2.1.4): do not reuse a stored response without validation.
     * With no validation channel for a hit, skip the lookup and go to the
     * origin — the fresh response still stores (refreshing the entry), like a
     * bypass. With only-if-cached the client refuses origin contact and we
     * cannot validate, so the answer is 504 (RFC 9111 §5.2.1.7). */
    if (ngx_http_cache_turbo_request_revalidate(r, ctx)) {
        (void) ngx_atomic_fetch_add(&z->sh->misses, 1);
        if (ctx->req_only_if_cached) {
            /* Nothing serveable without origin contact the client forbids:
             * a cache miss from the client's view ($cache_turbo_status MISS,
             * the pcalloc default). EXPIRED is reserved for the case where we
             * DID find a cached entry but it was past its serveable window. */
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: request revalidate + only-if-cached "
                           "\"%V\" -> 504", &r->uri);
            return NGX_HTTP_GATEWAY_TIME_OUT;
        }
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: request no-cache \"%V\" -> origin (revalidate)",
                       &r->uri);
        return NGX_DECLINED;
    }

    /* auto-Vary (v11 other half): probe the L1 vary marker for this base key and,
     * if a previous store told us this URL varies, recompute key_hash to the
     * variant (folding the named request headers) BEFORE the lookup below, so the
     * whole single-flight/serve flow runs unchanged on the variant key. No marker
     * (or auto_vary off) => key_hash stays the base key. */
    if (clcf->auto_vary) {
        ngx_http_cache_turbo_vary_resolve(r, clcf, z, ctx, &hash);
    }

    /* Bypass (v9): when a cache_turbo_bypass predicate trips, skip the cache
     * lookup entirely and go to the origin — but still let the filters store the
     * fresh response (so a bypassing request refreshes the entry). The key was
     * built above so the body filter stores under the right slot. */
    if (clcf->bypass != NULL
        && !ctx->l2_done && !ctx->lock_done
        && ngx_http_test_predicates(r, clcf->bypass) != NGX_OK)
    {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: bypass \"%V\" key=%ui -> origin",
                       &r->uri, (ngx_uint_t) hash);
        (void) ngx_atomic_fetch_add(&z->sh->misses, 1);
        (void) ngx_atomic_fetch_add(&z->sh->bypasses, 1);
        ctx->status = NGX_HTTP_CACHE_TURBO_ST_BYPASS;
        return NGX_DECLINED;
    }

    /* Live autotune (v4-3): throttled per-zone recompute of the beta verdict from
     * the window's stats. Cheap to call every request (one time compare on the
     * fast path); the heavy recompute runs at most once per interval per worker.
     * Takes the zone mutex itself, so call it before we lock below. */
    if (clcf->autotune) {
        ngx_http_cache_turbo_autotune_maybe(z,
            NGX_HTTP_CACHE_TURBO_AT_INTERVAL);
    }

    *ctxp = ctx;
    *zp = z;
    *hashp = hash;
    return NGX_OK;
}


/* PERF-7: request-pool cleanup that drops a zero-copy serve's blob reference once
 * the response has been fully sent (pool destroy happens after the output chain
 * drains). `z` + `data` identify the blob; the slab is freed here only if the
 * owning node already detached it (evict/refresh/purge raced the serve). */
typedef struct {
    ngx_http_cache_turbo_zone_t  *z;
    u_char                       *data;
} ngx_http_cache_turbo_blob_cln_t;

static void
ngx_http_cache_turbo_blob_cleanup(void *data)
{
    ngx_http_cache_turbo_blob_cln_t  *c = data;

    /* O4.3-c: c->data == NULL means the reference was already dropped early --
     * see the breaker gate, which releases a fallback nothing can consume once
     * its verdict is known. Pool cleanups cannot be unregistered, so disarming
     * one is exactly this: clear the payload and let it run as a no-op. */
    if (c->data == NULL) {
        return;
    }

    ngx_http_cache_turbo_blob_release(c->z, c->data);
    c->data = NULL;
}


/* P6/O4.3, S231-PERF-SIEARM: register the pool cleanup that drops an armed
 * blob's slab reference. Shared by the circuit-breaker arm and the SIE arm --
 * both pin a blob under the zone mutex (PERF-7 style) instead of copying it,
 * but UNLIKE the serve paths neither yet knows whether the blob will ever be
 * sent: most armed requests never consume their fallback (breaker: the gate
 * stays CLOSED; SIE: the origin revalidation does not come back 5xx). So the
 * reference is dropped by a cleanup tied to the REQUEST POOL rather than to a
 * serve call, which covers both outcomes with one drop.
 *
 * ⚠ That is also why the breaker's and SIE's own _serve()/restore call sites
 * never pass this same data as a second ref_data. A second cleanup for the
 * same blob would double-drop the refcount and free a slab still in use
 * elsewhere.
 *
 * Returns NGX_ERROR when the cleanup cannot be registered. Both callers run
 * this BEFORE ngx_http_cache_turbo_blob_acquire() precisely so that failure
 * path owns nothing: no reference has been taken yet, so the caller arms
 * nothing and releases nothing. A future caller that acquires first would have
 * to release here -- and could not, because blob_release() takes the zone mutex
 * the arming sites already hold. Keep the order.
 */
static ngx_int_t
ngx_http_cache_turbo_blob_ref_cleanup(ngx_http_request_t *r,
    ngx_http_cache_turbo_zone_t *z, u_char *data,
    ngx_http_cache_turbo_blob_cln_t **out)
{
    ngx_pool_cleanup_t               *cln;
    ngx_http_cache_turbo_blob_cln_t  *cc;

    cln = ngx_pool_cleanup_add(r->pool,
              sizeof(ngx_http_cache_turbo_blob_cln_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_cache_turbo_blob_cleanup;
    cc = cln->data;
    cc->z = z;
    cc->data = data;

    /* O4.3-c: hand the record back so the caller can drop the reference early
     * (see ngx_http_cache_turbo_brk_ref_drop). Optional -- pass NULL when the
     * pool-lifetime drop is all that is wanted (the SIE arm does this). */
    if (out != NULL) {
        *out = cc;
    }

    return NGX_OK;
}


/*
 * O4.3-c: drop a breaker fallback's slab reference NOW rather than at request
 * teardown, and disarm the pool cleanup that would otherwise drop it again.
 *
 * Called once the gate's verdict rules out a fallback serve. Idempotent, and
 * safe to call with nothing armed. See ctx->brk_cln for why holding the pin to
 * pool destruction is a reclamation hazard.
 */
static void
ngx_http_cache_turbo_brk_ref_drop(ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_cache_turbo_zone_t *z)
{
    ngx_http_cache_turbo_blob_cln_t  *cc = ctx->brk_cln;

    /* Only an L1 arming holds a slab reference. An L2 arming points at
     * ctx->l2_blob, which lives in r->pool and needs no release -- but it must
     * still be disarmed below, or this function is idempotent for one arming
     * source and not the other. */
    if (cc != NULL && cc->data != NULL) {
        ngx_http_cache_turbo_blob_release(z, cc->data);

        /* Disarm: the cleanup still runs at pool destruction, as a no-op. */
        cc->data = NULL;
    }

    ctx->brk_cln  = NULL;
    ctx->brk_ref  = NULL;
    ctx->brk_snap = NULL;
    ctx->brk_snap_len = 0;
    ctx->brk_armed = 0;
}


/*
 * P6/O4.3: answer a request the OPEN breaker refuses to forward and for which
 * no cached body of any age exists. 503 + Retry-After, generated locally with
 * no origin contact.
 *
 * ⚠ Finalizes and returns NGX_DONE, exactly like ngx_http_cache_turbo_serve().
 * This runs in the ACCESS phase, so returning the output filter's rc (or a bare
 * NGX_HTTP_SERVICE_UNAVAILABLE) would let the phase engine finalize a second
 * time on a request this function has already sent a body for. NGX_DONE is what
 * stops the engine here.
 *
 * On a HEAD the shared sender returns after ngx_http_send_header() via
 * r->header_only, so the headers -- Content-Length included -- are emitted with
 * no body. That is the correct HEAD representation per RFC 9110 §9.3.2
 * (identical fields to the GET, body omitted), not a framing bug; nginx knows
 * the response is body-less and keeps the connection in sync.
 *
 * Retry-After is advisory to the client and deliberately does NOT feed back
 * into the breaker's own timing: the breaker reopens on ITS schedule
 * (breaker_open), and a client that ignores the hint simply gets another 503.
 * Emitting the operator's configured value rather than the breaker's remaining
 * open time also avoids leaking the zone's internal state to every visitor.
 */
static ngx_int_t
ngx_http_cache_turbo_breaker_unavailable(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf)
{
    ngx_int_t                    rc;
    u_char                      *ra;
    size_t                       ra_len;
    time_t                       retry_after;
    ngx_http_cache_turbo_ctx_t  *ctx;
    ngx_str_t                    body = ngx_string("503 Service Unavailable\n");

    static u_char  ra_name[] = "Retry-After";
    static u_char  xc_name[] = "X-Cache";
    static u_char  xc_val[]  = "BREAKER-503";

    /* BRK-RA1: breaker_retry_after can now legitimately be NGX_CONF_UNSET
     * (nobody set it anywhere, at any level) because the config-time merge
     * no longer defaults it to breaker_open -- see the merge note above.
     * Resolve the effective value here instead: an explicit, set value
     * (!= NGX_CONF_UNSET) always wins, including an explicit 0 (which means
     * "send no Retry-After"); otherwise fall back to this location's fully
     * merged, request-scoped breaker_open. clcf is complete by request time,
     * so this lazy resolution needs no merge-order care at all. */
    retry_after = (clcf->breaker_retry_after != NGX_CONF_UNSET)
                  ? clcf->breaker_retry_after
                  : clcf->breaker_open;

    /* ⚠ Both headers go through ngx_http_cache_turbo_add_header() rather than a
     * bare ngx_list_push(). The helper also sets h->next = NULL on nginx 1.23+,
     * where repeated response headers form a linked chain rather than being
     * merged: a ngx_list_push() slot comes back with whatever the pool last
     * held, so an unset `next` is a dangling pointer that a downstream module
     * walking the chain will follow. */
    if (retry_after > 0) {
        ra = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
        if (ra == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ra_len = ngx_sprintf(ra, "%T", retry_after) - ra;

        if (ngx_http_cache_turbo_add_header(r, ra_name,
                sizeof("Retry-After") - 1, ra, ra_len) != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* Flag the reason the same way every other serve path does, so a log format
     * carrying X-Cache can tell a breaker 503 from an origin one. */
    if (ngx_http_cache_turbo_add_header(r, xc_name, sizeof("X-Cache") - 1,
            xc_val, sizeof("BREAKER-503") - 1) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* ⚠ Mark the request served BEFORE sending. Two things depend on it:
     *
     * 1. The body filter must not try to CAPTURE this 503 into the cache. It is
     *    our own locally generated response, not an origin body.
     * 2. The O4.2 recording site in the header filter early-returns on
     *    ctx->served, which is exactly right here: a breaker 503 never touched
     *    the origin, so counting it would let the breaker feed its OWN refusals
     *    back in as origin failures and hold itself open forever. (The
     *    r->upstream == NULL arm of _breaker_from_origin() already excludes it
     *    independently -- this is the second of the two guards, not the only
     *    one.)
     *
     * $cache_turbo_status is deliberately left at its default (MISS): the
     * existing status ids have no value meaning "refused without contacting the
     * origin", so this path leaves it alone. $cache_turbo_serve_reason (S7.2)
     * DOES record it, as SR_BREAKER_503 -- that variable exists precisely for
     * outcomes status's HIT/STALE/BYPASS/EXPIRED/MISS enum has no slot for. */
    ctx = ngx_http_get_module_ctx(r, ngx_http_cache_turbo_module);
    if (ctx != NULL) {
        ctx->served = 1;
        ctx->serve_reason = NGX_HTTP_CACHE_TURBO_SR_BREAKER_503;
    }

    rc = ngx_http_cache_turbo_send_body(r, NGX_HTTP_SERVICE_UNAVAILABLE, &body,
             "text/plain", sizeof("text/plain") - 1);

    ngx_http_finalize_request(r, rc);
    return NGX_DONE;
}


static ngx_int_t
ngx_http_cache_turbo_access_handler(ngx_http_request_t *r)
{
    uint32_t                          hash;
    ngx_int_t                         prc;
    ngx_http_cache_turbo_ctx_t       *ctx;
    ngx_http_cache_turbo_node_t      *ctn;
    ngx_http_cache_turbo_zone_t      *z;
    ngx_http_cache_turbo_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);

    /* Prologue: enablement, method/subrequest/auth vetoes, ctx + key, auto-
     * classify, request no-cache, auto-Vary, bypass, autotune. NGX_OK => proceed
     * with ctx/z/hash set; otherwise that is our return value. */
    prc = ngx_http_cache_turbo_access_prologue(r, clcf, &ctx, &z, &hash);
    if (prc != NGX_OK) {
        return prc;
    }

    ngx_shmtx_lock(&z->shpool->mutex);

    ctn = clcf->l1->lookup(z, ctx->key_hash, hash);

    if (ctn != NULL) {
        time_t     now = ngx_time();
        time_t     fresh_until = ctn->fresh_until;
        time_t     stale_until = ctn->stale_until;
        time_t     stale_window;
        ngx_int_t  refresh;
        ngx_int_t  fresh_ok = 1, stale_ok = 1;

        /* v4-4 load-adaptive stale window. Under sustained backend load
         * autotune publishes a load factor (>BASE); widen ONLY the serveable
         * stale deadline by it, so a slow origin is shielded by serving stale
         * longer before a hard miss. The FRESH deadline (fresh_until) is left
         * untouched — the freshness contract the operator configured is never
         * relaxed, only the best-effort stale grace is. stale_until == 0 means
         * "no stale deadline" (e.g. cache-forever) and is left as-is. The widen
         * applies to the local `stale_until` only; the refresh-dice window below
         * still reads ctn->stale_until (the STORED window), so beta keeps owning
         * refresh timing while the load factor owns serve-stale reach. */
        if (stale_until != 0 && clcf->autotune) {
            ngx_int_t  load = ngx_http_cache_turbo_effective_load(clcf, z);

            if (load > NGX_HTTP_CACHE_TURBO_AT_LOAD_BASE) {
                time_t  win = stale_until - fresh_until;   /* stored stale span */

                if (win > 0) {
                    stale_until += win
                        * (load - NGX_HTTP_CACHE_TURBO_AT_LOAD_BASE)
                        / NGX_HTTP_CACHE_TURBO_AT_LOAD_BASE;
                }
            }
        }

        /* RFC-1 request freshness bounds (max-age / min-fresh / max-stale): an
         * existing entry may be unacceptable to THIS client even when the cache
         * would serve it. Read the blob's created stamp (offset 24) for an exact
         * age; the verdict gates the two serve blocks below. When a serveable
         * entry is blocked by the bounds, req_reval makes this a revalidation:
         * the cold-miss CLAIM_FRESH path must not re-serve the raced-in fresh
         * entry, and only-if-cached still 504s at the post-L2 chokepoint. */
        if (ctx->has_req_bounds && ctn->len > 0) {
            /* P2: only run the request-freshness-bounds verdict when the client
             * actually sent max-age/min-fresh/max-stale. With none set,
             * req_serve_verdict returns fresh_ok=stale_ok=1 unconditionally, so
             * the block below can never set req_reval — pure dead work on the
             * common (no request CC) hot path. only-if-cached is unaffected: it
             * is gated at :2998/:3511, not here.
             * len > 0 implies data != NULL (a real entry always has both; a
             * stub/counter node is len == 0) — the serve blocks below already
             * rely on this when they memcpy ctn->data. */
            time_t  created = (time_t)
                ngx_http_cache_turbo_get_u64(ctn->data + 24);
            ngx_int_t  in_window = (now < fresh_until)
                || (stale_until == 0 || now < stale_until);

            ngx_http_cache_turbo_req_serve_verdict(ctx, created, now,
                fresh_until, &fresh_ok, &stale_ok);

            if (in_window
                && !((now < fresh_until) && fresh_ok)
                && !(((stale_until == 0) || now < stale_until) && stale_ok))
            {
                ctx->req_reval = 1;
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "cache_turbo: entry fails request freshness bounds "
                    "\"%V\" -> revalidate", &r->uri);
            }
        }

        if (now < fresh_until && fresh_ok) {
            /* PERF-7 fresh hit: serve the blob DIRECTLY out of shm (zero-copy).
             * Pin it with a reference under the mutex we already hold; the serve
             * path registers a pool cleanup that drops the ref once the response
             * has drained, so eviction/refresh by any worker is safe meanwhile. */
            u_char *body = ctn->data;
            size_t  body_len = ctn->len;
            ngx_http_cache_turbo_blob_acquire(body);
            /* True LRU: promote this node to the head on access, so eviction
             * targets the genuinely least-recently-used entry (not the oldest by
             * insertion/refresh). P1: coarse-gate the splice — skip the LRU WRITE
             * when this node was already spliced within the last second, so a
             * hot key serializes readers on the mutex at most once/second. */
            /* S8: shared promote-on-second-hit helper; also applies the P1
             * 1s coarse gate internally. clcf->scan_resistant_pct == 0 (the
             * default) makes this a plain probation re-head. */
            ngx_http_cache_turbo_shm_touch_lru(z, ctn, now,
                                               clcf->scan_resistant_pct);
            ngx_shmtx_unlock(&z->shpool->mutex);
            (void) ngx_atomic_fetch_add(&z->sh->hits, 1);
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: L1 HIT (fresh) \"%V\" key=%ui len=%uz",
                           &r->uri, (ngx_uint_t) hash, body_len);
            return ngx_http_cache_turbo_serve(r, body, body_len, 0, z, body,
                                              NULL);
        }

        if ((stale_until == 0 || now < stale_until) && ctn->len > 0 && stale_ok) {
            /* stale-but-serveable. The `len > 0` guard skips a cold-miss
             * single-flight STUB (v10: data == NULL, len == 0, stale_until == 0)
             * — a stub is an in-flight marker, never serveable; it falls through
             * to the cold path below where the waiter/claim logic handles it. */

            /* True LRU: promote on access (still a live, serveable entry).
             * P1: coarse-gate the splice (see the fresh-HIT site above). */
            /* S8: shared promote-on-second-hit helper; also applies the P1
             * 1s coarse gate internally. clcf->scan_resistant_pct == 0 (the
             * default) makes this a plain probation re-head. */
            ngx_http_cache_turbo_shm_touch_lru(z, ctn, now,
                                               clcf->scan_resistant_pct);

            /* Cross-node single-flight resolved (v4-2): we parked for the Redis
             * NX and the phase engine re-entered. If we won (NGX_OK), we own the
             * cluster-wide regen → go to origin. If the lock channel FAILED
             * (NGX_ERROR: Redis timeout/outage), there is no cross-node
             * coordination to honour, so degrade to per-box single-flight and
             * regenerate locally — `refreshing` is already claimed, so this box
             * still single-flights while a peer with a live Redis can win the NX.
             * Only a genuine peer-holds (NGX_DECLINED) falls through to serve
             * stale: the dice is skipped (refreshing claimed) and the tail below
             * serves stale — no extra state needed. */
            if (ctx->lock_done
                && (ctx->lock_result == NGX_OK || ctx->lock_result == NGX_ERROR))
            {
                /* We own the (cluster-wide, or per-box on L2 failure) regen. With
                 * background_update (v8,
                 * default) refresh in the background and serve stale now; else
                 * fall through to the origin and regenerate inline. */
                if (clcf->background_update) {
                    u_char *snap = ngx_pnalloc(r->pool, ctn->len);
                    size_t  snap_len = ctn->len;
                    if (snap == NULL) {
                        ngx_shmtx_unlock(&z->shpool->mutex);
                        return NGX_ERROR;
                    }
                    ngx_memcpy(snap, ctn->data, snap_len);
                    ngx_shmtx_unlock(&z->shpool->mutex);
                    (void) ngx_http_cache_turbo_warm_one(r, &r->uri, &r->args);
                    (void) ngx_atomic_fetch_add(&z->sh->stale_serves, 1);
                    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "cache_turbo: cross-node WON bg-refresh + STALE "
                                   "serve \"%V\" key=%ui len=%uz",
                                   &r->uri, (ngx_uint_t) hash, snap_len);
                    return ngx_http_cache_turbo_serve(r, snap, snap_len, 1,
                                                      z, NULL, NULL);
                }
                ngx_shmtx_unlock(&z->shpool->mutex);
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: cross-node lock WON \"%V\" key=%ui "
                               "-> regenerate", &r->uri, (ngx_uint_t) hash);
                return NGX_DECLINED;
            }

            /* Refresh-dice window from the OBJECT's own deadlines, not the
             * location default (COR-3): a per-status TTL or an honor_cc upstream
             * max-age gives this node a different fresh/stale span than
             * clcf->valid, so using clcf->valid here mis-scaled the dice and such
             * objects could expire cold. stale_until == 0 (no stale deadline)
             * falls back to the location-derived window. */
            if (ctn->stale_until != 0) {
                stale_window = ctn->stale_until - fresh_until;
            } else {
                stale_window = ngx_http_cache_turbo_stale_ttl(clcf->valid,
                                   clcf->stale_mult)
                               - clcf->valid;
            }
            if (stale_window <= 0) {
                stale_window = 1;
            }

            /* Hard single-flight: if a refresh is already claimed and its lock
             * window hasn't expired, every reader serves stale and skips the
             * dice entirely. Only when no lock is held (or it has expired, i.e.
             * the previous refresh died) does anyone roll to become the single
             * regenerator. This caps origin regens at ~one per stale cycle even
             * with many workers and aggressive beta. */
            refresh = NGX_DECLINED;
            if (!ctx->lock_done
                && (!ctn->refreshing || now >= ctn->refresh_lock_until))
            {
                refresh = ngx_http_cache_turbo_should_refresh(ctx->key_hash,
                              fresh_until, stale_window,
                              ngx_http_cache_turbo_effective_beta(clcf, z));
            }

            if (refresh == NGX_OK) {
                /* We win the per-box dice: claim the refresh under lock (atomic
                 * with the check above). With background_update on (v8, default)
                 * this request serves STALE and refreshes in the background — it
                 * never blocks on origin; the bg subrequest restores a fresh copy
                 * and a failed origin (5xx/timeout) leaves the stale entry intact
                 * (stale-if-error). With background_update off it falls through to
                 * the origin and regenerates SYNCHRONOUSLY (serving fresh). Either
                 * way the OTHER concurrent readers serve stale. We count a
                 * `refresh` here (the regen we triggered) plus a `stale_serve` on
                 * the bg path (the stale response we hand back). The lock
                 * self-heals after lock_ttl if the refresh never completes. */
                time_t  lock_ttl = clcf->lock_ttl;
                u_char *snap;
                size_t  snap_len;

                if (lock_ttl <= 0) {
                    lock_ttl = 5;
                }

                /* v4-4: a slow origin (the load case) takes longer to regen, so
                 * widen the single-flight window by the load factor — hold the
                 * claim long enough that a still-running slow refresh isn't
                 * re-claimed, collapsing more requests onto the one regen. */
                lock_ttl = lock_ttl
                    * ngx_http_cache_turbo_effective_load(clcf, z)
                    / NGX_HTTP_CACHE_TURBO_AT_LOAD_BASE;

                /* snapshot the stale copy under the lock — used to serve stale on
                 * the single-box background-update path below. */
                snap_len = ctn->len;
                snap = ngx_pnalloc(r->pool, snap_len);
                if (snap == NULL) {
                    ngx_shmtx_unlock(&z->shpool->mutex);
                    return NGX_ERROR;
                }
                ngx_memcpy(snap, ctn->data, snap_len);

                /* CTXRDR-ADOPT-LEASE: deliberately NO refresh_owner here. This is
                 * the v8 background-update lease on an ENTRY that still has a
                 * body, not the cold-miss stub lease. It is resolved by store()
                 * overwriting the node, never by unstub() -- which ignores an
                 * ENTRY (kind == COUNTER is required) -- and it is never adopted
                 * across a redirect, because a request holding it is serving
                 * stale rather than parking in cold_wait(). The two leases share
                 * the `refreshing` flag and nothing else. */
                ctn->refreshing = 1;
                ctn->refresh_lock_until = now + lock_ttl;
                ngx_shmtx_unlock(&z->shpool->mutex);
                (void) ngx_atomic_fetch_add(&z->sh->refreshes, 1);
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: stale, refresh dice WON \"%V\" "
                               "key=%ui", &r->uri, (ngx_uint_t) hash);

                /* Cross-node gate (v4-2): the per-box L1 dice win is necessary
                 * but not sufficient — only the node that ALSO wins the Redis
                 * SET NX PX regenerates; the rest serve stale. lock() parks for
                 * the NX reply and re-enters this handler (ctx->lock_done set,
                 * resolved at the top of this block — bg or inline). NGX_DECLINED
                 * = L2 off / could not start → single-box fallback below. */
                if (clcf->backend && clcf->backend->lock) {
                    ngx_int_t  lrc = clcf->backend->lock(r, clcf, ctx, lock_ttl);
                    if (lrc == NGX_AGAIN) {
                        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                       "cache_turbo: parked on L2 lock NX \"%V\" "
                                       "key=%ui", &r->uri, (ngx_uint_t) hash);
                        return NGX_AGAIN;       /* parked; resume re-enters */
                    }
                }

                /* single-box winner (no L2 lock, or it could not start). */
                if (clcf->background_update) {
                    /* v8: fire a background refresh of this URI, serve stale. */
                    (void) ngx_http_cache_turbo_warm_one(r, &r->uri, &r->args);
                    (void) ngx_atomic_fetch_add(&z->sh->stale_serves, 1);
                    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "cache_turbo: bg-refresh + STALE serve \"%V\" "
                                   "key=%ui len=%uz", &r->uri, (ngx_uint_t) hash,
                                   snap_len);
                    return ngx_http_cache_turbo_serve(r, snap, snap_len, 1,
                                                      z, NULL, NULL);
                }

                return NGX_DECLINED;       /* inline regen (serves fresh) */
            }

            /* serve stale, no regeneration on this request */
            {
                /* PERF-7: zero-copy stale serve (see the fresh-hit path). */
                u_char *body = ctn->data;
                size_t  body_len = ctn->len;
                ngx_http_cache_turbo_blob_acquire(body);
                ngx_shmtx_unlock(&z->shpool->mutex);
                (void) ngx_atomic_fetch_add(&z->sh->stale_serves, 1);
                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: STALE serve \"%V\" key=%ui len=%uz",
                               &r->uri, (ngx_uint_t) hash, body_len);
                return ngx_http_cache_turbo_serve(r, body, body_len, 1, z, body,
                                                  NULL);
            }
        }

        /* expired: the L1 copy is past its stale window. Fall through to the
         * shared L2-consult/miss path below — another node may hold a fresher
         * copy in Redis, so we must check L2 before the origin (issue P6).
         *
         * $cache_turbo_status: a cached entry WAS found but is past its
         * serveable window -> EXPIRED (matches nginx $upstream_cache_status:
         * expired-and-refetched, distinct from a true cold MISS). Overwritten
         * to HIT/STALE below if L2 holds a serveable copy.
         *
         * RFC 5861 §4 / RFC-2 stale-if-error (CTB4): before going to origin,
         * arm a serve-on-error snapshot if this blob still carries a window
         * (created + sie_ttl) that covers now. If the origin revalidation then
         * fails (5xx/timeout), the header/body filters replay this snapshot
         * instead of surfacing the error. Arming only STASHES — the L2 consult
         * below still runs first (a peer may hold a fresh copy). len > 0 skips a
         * stub; the !sie_armed guard makes the park/resume re-entries idempotent. */
        ctx->status = NGX_HTTP_CACHE_TURBO_ST_EXPIRED;

        /* P6/O4.3: arm the circuit-breaker fallback from this expired L1 entry.
         *
         * Unconditional on age, unlike the SIE arming below: the breaker's
         * contract is "any body beats a 503 once the origin is known down". The
         * entry has already fallen past its stale window here, so nothing on the
         * NORMAL path will ever serve it -- only the pre-origin breaker gate
         * can, and only while the breaker is OPEN.
         *
         * ⚠ Gated on breaker_should_consult() so this costs nothing when the
         * breaker is off by ANY of its off-switches: it is a full-blob memcpy
         * on the expired-entry path, which is every request to a cold-ish
         * key. Same predicate the pre-origin gate below uses.
         *
         * The !brk_armed guard makes the park/resume re-entries idempotent (the
         * L2 GET and the cold-wait both re-enter this handler from the top),
         * exactly as !sie_armed does below. */
        if (ctn->len > 0 && !ctx->brk_arm_done
            && ngx_http_cache_turbo_breaker_should_consult(clcf))
        {
            /* PERF-7 style zero-copy arm: pin the blob in the slab under the
             * mutex we already hold instead of copying it. A full-blob memcpy
             * here would run on EVERY enabled request that finds an expired
             * entry, inside the cross-worker zone lock, on objects up to
             * cache_turbo_max_object (1 MiB by default, configurable higher) --
             * a lock convoy on precisely the outage path this feature is meant
             * to smooth. The reference is released by the pool cleanup that
             * ngx_http_cache_turbo_serve() registers for ref_data.
             *
             * ⚠ Arming does not mean serving: most armed requests fall through
             * to the origin with a CLOSED breaker and never call _serve(). The
             * ref must therefore be dropped when nobody consumes it, which is
             * what the explicit cleanup below is for -- see brk_ref. */
            /* Register the drop BEFORE acquiring. ngx_pool_cleanup_add() is
             * the only thing here that can fail, and it touches r->pool only
             * -- no slab, no zone mutex -- so failing first costs nothing to
             * undo. Acquiring first would force the failure arm to call
             * blob_release(), which takes the zone mutex itself (shm.c) and so
             * requires unlocking here; ngx_shmtx is not recursive. That unlock
             * would invalidate `ctn` -- it was resolved at the lookup and is
             * only valid while the mutex is held -- letting a concurrent
             * evict/refresh/purge detach the blob and our own release then free
             * it, leaving the SIE block below dereferencing freed slab. */
            ngx_http_cache_turbo_blob_cln_t  *bcc = NULL;

            if (ngx_http_cache_turbo_blob_ref_cleanup(r, z, ctn->data, &bcc)
                == NGX_OK)
            {
                ctx->brk_arm_done = 1;
                ngx_http_cache_turbo_blob_acquire(ctn->data);
                ctx->brk_snap = ctn->data;
                ctx->brk_snap_len = ctn->len;
                ctx->brk_ref = ctn->data;
                ctx->brk_cln = bcc;
                ctx->brk_armed = 1;

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
                /* O4.4-i negative control for THIS site. Inside the
                 * should_consult() branch on purpose -- see the field comment.
                 * Bumps the L1 field only: a shared counter would let an L2
                 * assertion pass on this site's bump. */
                (void) ngx_atomic_fetch_add(&z->sh->test_brk_armings_l1, 1);
#endif

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: breaker fallback armed from L1 "
                               "\"%V\" key=%ui", &r->uri, (ngx_uint_t) hash);
            }
        }

        if (ctn->len > 0 && !ctx->sie_armed) {
            time_t    created = (time_t)
                ngx_http_cache_turbo_get_u64(ctn->data + 24);
            uint32_t  sie_ttl = ngx_http_cache_turbo_get_u32(ctn->data + 40);

            if (sie_ttl > 0 && now < created + (time_t) sie_ttl) {
                /* S231-PERF-SIEARM: PERF-7 style zero-copy arm, same reasoning
                 * as the breaker arm just above -- see its comment for the
                 * full rationale; this is the identical hazard on the SAME
                 * `ctn`, still under the SAME mutex hold.
                 *
                 * Register the drop BEFORE acquiring. ngx_pool_cleanup_add()
                 * is the only thing here that can fail, and it touches
                 * r->pool only -- no slab, no zone mutex -- so failing first
                 * costs nothing to undo. Acquiring first would force the
                 * failure arm to call blob_release(), which takes the zone
                 * mutex itself (shm.c) and so requires unlocking here;
                 * ngx_shmtx is not recursive. That unlock would invalidate
                 * `ctn` -- it was resolved at the lookup and is only valid
                 * while the mutex is held -- letting a concurrent
                 * evict/refresh/purge detach the blob and our own release
                 * then free it, leaving the L2-consult code below
                 * dereferencing freed slab. */
                /* No early-drop caller for the SIE arm (unlike the breaker's
                 * brk_ref_drop), so nothing needs the cleanup record back --
                 * pass NULL and let the pool-lifetime drop be the only
                 * owner. */
                if (ngx_http_cache_turbo_blob_ref_cleanup(r, z, ctn->data,
                        NULL) == NGX_OK)
                {
                    ngx_http_cache_turbo_blob_acquire(ctn->data);
                    ctx->sie_snap = ctn->data;
                    ctx->sie_snap_len = ctn->len;
                    ctx->sie_armed = 1;
                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "cache_turbo: SIE armed from L1 \"%V\" key=%ui",
                                   &r->uri, (ngx_uint_t) hash);
                }
            }
        }
    }

    /* L1 absent (miss) or expired. Consult L2 (Redis or memcached -- the
     * backend is a vtable) before falling through to the origin: another node
     * may already hold this object. The L2 GET is
     * async but logically synchronous — it parks the request and resumes it
     * when the reply lands (see ngx_http_cache_turbo_redis_get). */
    ngx_shmtx_unlock(&z->shpool->mutex);

    /* L13: a live negative memo says an L2 GET for this key missed within the
     * last cache_turbo_l2_negative_ttl seconds. Skip the round-trip and treat
     * it as an L2 miss directly. Marking l2_done keeps the rest of the handler
     * (and the l2_misses metric below) on exactly the path a real miss takes,
     * so a memoed miss and a fetched miss are indistinguishable downstream. */
    if (clcf->backend && !ctx->l2_done && !ctx->l2_neg_force
        && clcf->l2_negative_ttl > 0
        && clcf->l1->l2_neg_check(z, ctx->key_hash, hash) == NGX_DECLINED)
    {
        ctx->l2_done = 1;
        /* NGX_DECLINED is right HERE (unlike the cold-wait re-poll seed, which
         * uses NGX_ERROR): the memo asserts L2 definitively lacks the key, and
         * downstream must not be able to tell a memoed miss from a fetched one.
         * l2_neg_skipped on the next line is what stops this from re-arming. */
        ctx->l2_result = NGX_DECLINED;
        ctx->l2_neg_skipped = 1;
        (void) ngx_atomic_fetch_add(&z->sh->l2_neg_skips, 1);
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: L2 GET skipped by negative memo \"%V\" "
                       "key=%ui", &r->uri, (ngx_uint_t) hash);
    }

    if (clcf->backend && !ctx->l2_done) {
        ngx_int_t  rc = clcf->backend->get(r, clcf, ctx);
        if (rc == NGX_AGAIN) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: parked on L2 GET \"%V\" key=%ui",
                           &r->uri, (ngx_uint_t) hash);
            return NGX_AGAIN;           /* parked; redis read handler resumes */
        }
        /* NGX_DECLINED: L2 disabled or could not start; go to origin */
    }

    if (ctx->l2_done && ctx->l2_result == NGX_OK && ctx->l2_blob) {
        /* L2 hit: FULLY validate the blob (STAB-4) before touching L1, populate
         * L1 so later reads hit shm, then serve it as a normal HIT. */
        ngx_http_cache_turbo_blob_hdr_t  bh;

        if (ngx_http_cache_turbo_blob_validate(ctx->l2_blob, ctx->l2_blob_len,
                                               &bh, NULL, NULL) == NGX_OK)
        {
            time_t  age, rem_fresh, rem_stale;

            /* Restore the object's REMAINING lifetime, not the location
             * default — otherwise every L2 hit re-promotes a stale object as
             * fresh and it never expires (and per-status/upstream TTLs are
             * lost across the L2 round-trip). */
            age = ngx_time() - (time_t) bh.created;
            if (age < 0) {                 /* clock skew between writers */
                age = 0;
            }
            rem_fresh = (time_t) bh.fresh_ttl - age;   /* <=0 => stale */
            rem_stale = (time_t) bh.stale_ttl - age;   /* total window left */

            if (rem_stale <= 0) {
                /* Object outlived its serveable window in L2 (Redis TTL
                 * slack): treat as a miss and go to origin.
                 *
                 * NOTE (v4-4 asymmetry, intentional): the load-adaptive stale
                 * widening is applied to the L1 serve decision only (it widens
                 * the local stale_until without rewriting the stored window).
                 * It is deliberately NOT applied here: this branch both SERVES
                 * and STORES the L2 blob into L1 (rem_stale below feeds
                 * l1->store), so widening rem_stale would PERSIST a stretched
                 * window into L1 and diverge from the serve-only L1 semantics.
                 * An L2-restored entry past its stored window is conservatively
                 * a miss; the origin single-flight bounds the refetch.
                 *
                 * RFC-2 stale-if-error (CTB4): if the L1 path did not already arm
                 * a snapshot (L1 evicted, or this is a peer's fresher-but-expired
                 * copy) and this L2 blob still carries a serve-on-error window
                 * (created + sie_ttl) covering now, arm from it so a failing
                 * origin below replays it instead of erroring. */
                /* P6/O4.3: arm the breaker fallback from the L2 blob too. This
                 * is the L1-absent / L1-evicted case -- a peer's copy that is
                 * past its serveable window. Same any-age rule and same
                 * breaker_should_consult() off-switch as the L1 site above. */
                if (!ctx->brk_arm_done
                    && ngx_http_cache_turbo_breaker_should_consult(clcf))
                {
                    /* No copy: ctx->l2_blob already lives in r->pool with the
                     * same lifetime as this request, so pointing at it is both
                     * correct and free. brk_ref stays NULL -- there is no shm
                     * slab reference to drop. */
                    ctx->brk_snap = ctx->l2_blob;
                    ctx->brk_snap_len = ctx->l2_blob_len;
                    ctx->brk_ref = NULL;
                    ctx->brk_arm_done = 1;
                    ctx->brk_armed = 1;
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
                    /* O4.4-i negative control for THIS site. Inside the
                     * should_consult() branch on purpose -- see field comment.
                     * Bumps the L2 field only, so a delta here cannot have come
                     * from the L1 site above. */
                    (void) ngx_atomic_fetch_add(&z->sh->test_brk_armings_l2, 1);
#endif
                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "cache_turbo: breaker fallback armed from "
                                   "L2 \"%V\" key=%ui", &r->uri,
                                   (ngx_uint_t) hash);
                }

                if (!ctx->sie_armed && bh.sie_ttl > 0
                    && ngx_time() < (time_t) bh.created + (time_t) bh.sie_ttl)
                {
                    u_char *snap = ngx_pnalloc(r->pool, ctx->l2_blob_len);
                    if (snap != NULL) {
                        ngx_memcpy(snap, ctx->l2_blob, ctx->l2_blob_len);
                        ctx->sie_snap = snap;
                        ctx->sie_snap_len = ctx->l2_blob_len;
                        ctx->sie_armed = 1;
                        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                       "cache_turbo: SIE armed from L2 \"%V\" "
                                       "key=%ui", &r->uri, (ngx_uint_t) hash);
                    }
                }
                /* L2 held this object but it is past its serveable window:
                 * EXPIRED (a cached entry was found and refetched), not a cold
                 * MISS. Covers the L1-absent / L1-evicted case where the L1
                 * fall-through above never ran. */
                ctx->status = NGX_HTTP_CACHE_TURBO_ST_EXPIRED;
                /* V-HANG-2: L2 HAS the key, we just cannot serve it. If we are
                 * a cold-miss waiter, the fill we are parked for has already
                 * landed — every further poll re-fetches this same unserveable
                 * blob, so waiting out lock_timeout adds pure latency. Record
                 * it; the wait loop gives up on the next re-entry. */
                ctx->l2_present_unserveable = 1;
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: L2 blob expired \"%V\" key=%ui "
                               "-> origin", &r->uri, (ngx_uint_t) hash);
            } else {
                /* RFC-1: the L2 copy must also satisfy the request freshness
                 * bounds. An L2 entry can be younger than the L1 one (a peer
                 * refreshed it), so evaluate it on its own age, not the L1
                 * verdict. If it fails, revalidate at origin instead of serving
                 * the rejected copy (req_reval blocks the cold-claim re-serve). */
                ngx_int_t  l2_fresh_ok = 1, l2_stale_ok = 1;
                ngx_int_t  promote_rc;

                /* P2: same gate as the L1 verdict above — only run the bounds
                 * check when the client actually sent one. With none set the
                 * verdict leaves l2_fresh_ok/l2_stale_ok at 1 and the block below
                 * can never set req_reval, so it is pure dead work on the L2 hot
                 * path. The defaults are the no-bounds answer. */
                if (ctx->has_req_bounds) {
                    ngx_http_cache_turbo_req_serve_verdict(ctx,
                        (time_t) bh.created, ngx_time(),
                        (time_t) bh.created + (time_t) bh.fresh_ttl,
                        &l2_fresh_ok, &l2_stale_ok);
                }

                if ((rem_fresh > 0 && !l2_fresh_ok)
                    || (rem_fresh <= 0 && !l2_stale_ok))
                {
                    ctx->req_reval = 1;
                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "cache_turbo: L2 blob fails request freshness bounds "
                        "\"%V\" key=%ui -> origin", &r->uri, (ngx_uint_t) hash);
                } else {
                    /* The blob passed blob_validate() above: framing, the full
                     * TLV walk, AND the status/TTL range checks — so the slot we
                     * put in L1 cannot be structurally unserveable.
                     *
                     * AUD-HDR1: this comment used to claim "full validation",
                     * which was read as licence to promote an L2 blob into shm
                     * where every worker serves it. It was not true of the
                     * CONTENT: blob_validate inspects no header bytes. The
                     * content guarantee comes from header_admissible(), applied
                     * on the way OUT in restore_response(), so a poisoned header
                     * in this blob is dropped at serve time rather than
                     * prevented from entering L1. Keep the two claims separate;
                     * conflating them is what let AUD-HDR1 survive to HEAD. */
                    /* AUD-L2-PROMOTE-RACE: this GET unlocked before the
                     * request parked; on resume it used to promote
                     * unconditionally, so a slow L2 reply could overwrite a
                     * NEWER origin response that landed while parked.
                     * store_if() decides "is the resident entry newer?" and
                     * writes under ONE lock hold, closing that window.
                     * NGX_DECLINED means the promotion did not happen -- that
                     * is CORRECT, not an error: the blob we hold is still
                     * valid and gets served below exactly as before, we
                     * simply declined to displace a fresher L1 entry. */
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
                    /* AUD-L2-PROMOTE-RACE test hook: the gap this fix closes
                     * is pure CPU between the unlock above and store_if()'s
                     * own lock -- no I/O, no yield point, unreachable from a
                     * black-box HTTP timing race. Blocking THIS worker here
                     * (ngx_msleep = plain usleep, stalls only its own event
                     * loop) gives a test a deterministic window to land a
                     * concurrent write from a DIFFERENT worker before the
                     * decide-and-store below runs. 0/unset = no hold. */
                    if (clcf->test_l2_promote_hold_ms > 0) {
                        ngx_msleep((ngx_msec_t) clcf->test_l2_promote_hold_ms);
                    }
#endif
                    promote_rc = clcf->l1->store_if(z,
                               ctx->key_hash, hash,
                               ctx->l2_blob, ctx->l2_blob_len,
                               rem_fresh, rem_stale,
                               NGX_HTTP_CACHE_TURBO_STORE_IF_NEWER);

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
                    /* AUD-L2-PROMOTE-RACE oracle: NOTICE (not debug) so it is
                     * readable at the harness's default log level -- same
                     * reasoning as test_sie_unconsumed (AUD-SIE-BODY). Two
                     * DISTINCT values so a test can tell "declined" from
                     * "stored" apart, never inferring one from the other's
                     * absence: an absent line must fail the test, not read
                     * as either. */
                    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                                  "cache_turbo: test_l2_promote_rc=%i",
                                  promote_rc);
#endif

                    if (promote_rc == NGX_DECLINED) {
                        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                       "cache_turbo: L2 promote skipped, "
                                       "newer entry resident \"%V\" key=%ui",
                                       &r->uri, (ngx_uint_t) hash);
                    }

                    (void) ngx_atomic_fetch_add(&z->sh->hits, 1);
                    (void) ngx_atomic_fetch_add(&z->sh->l2_hits, 1);
                    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "cache_turbo: L2 HIT \"%V\" key=%ui len=%uz "
                                   "(filled L1)", &r->uri, (ngx_uint_t) hash,
                                   ctx->l2_blob_len);
                    return ngx_http_cache_turbo_serve(r, ctx->l2_blob,
                               ctx->l2_blob_len, rem_fresh <= 0 ? 1 : 0,
                               z, NULL, NULL);
                                          /* L2 blob lives in r->pool, no ref */
                }
            }
        }
        /* corrupt/short/expired blob: treat as a miss, fall through to origin */
    }

    /* L2 was consulted but did not satisfy the request (v12 metric). Count it
     * at most once per request: a cold miss parks on the L2 GET and then parks
     * AGAIN on the v4-2 NX lock / v10 cold-wait, re-entering this handler from
     * the top each resume — l2_miss_counted guards the double/triple count. */
    if (clcf->backend && ctx->l2_done && !ctx->l2_miss_counted) {
        ctx->l2_miss_counted = 1;
        (void) ngx_atomic_fetch_add(&z->sh->l2_misses, 1);

        /* L13: remember this miss so the next cold request skips the GET.
         *
         * ⚠ Guarded on !l2_neg_skipped: re-stamping a miss we only "knew about"
         * BECAUSE of a memo would slide the window forward on every request and
         * keep L2 switched off indefinitely for a hot-but-absent key. Only a
         * miss learned from a REAL round-trip may arm the memo, so the window
         * is bounded at l2_negative_ttl from the last actual L2 answer.
         *
         * ⚠ Guarded on l2_result == NGX_DECLINED: ONLY a definitive miss arms it.
         * l2_result is tri-state (see the ctx field) and NGX_ERROR means L2's
         * answer is unknown -- a timeout, a dropped connection, a malformed or
         * error reply, or a local alloc failure on a real HIT. Arming on those
         * turned an L2 OUTAGE into self-inflicted amplification: every failed GET
         * armed a memo, the memos then suppressed the GETs that would have noticed
         * L2 coming back, and the cache stayed switched off for up to
         * l2_negative_ttl past recovery. The alloc-failure sub-case was worse
         * still -- it armed "key is absent" immediately after L2 said it HAS the
         * key. (Codex #5 on PR #77.) */
        if (clcf->l2_negative_ttl > 0 && !ctx->l2_neg_skipped
            && ctx->l2_result == NGX_DECLINED)
        {
            clcf->l1->l2_neg_set(z, ctx->key_hash, hash,
                                 clcf->l2_negative_ttl);
        }
    }

    /* only-if-cached (RFC 9111 §5.2.1.7): L1 missed/expired and L2 (if any) did
     * not satisfy it either — both caches are exhausted. The client refuses
     * origin contact, so answer 504 rather than engaging the cold-miss
     * single-flight / origin path below. A fresh or stale HIT above already
     * returned (only-if-cached is satisfied by any cache serve). */
    if (ctx->req_only_if_cached) {

        /* P6/O4.3: the breaker's any-age snapshot is still a CACHE serve with
         * zero origin contact, so it satisfies only-if-cached in full -- but
         * only when the breaker is already OPEN. Read the state RAW rather than
         * through _breaker_state(), which is not a pure getter: it would
         * promote this request to probe, and an only-if-cached request can
         * never be a probe (it will not contact the origin by definition), so
         * the lease would be burnt and the recovery window lost. The admin
         * stats path reads raw for the same reason.
         *
         * A CLOSED or HALF_OPEN breaker falls through to the 504 below: with
         * the origin believed reachable, serving a body past every configured
         * window is the operator's outage policy, not this client's to invoke. */
        if (ngx_http_cache_turbo_breaker_should_consult(clcf)
            && ctx->brk_armed
            && ngx_http_cache_turbo_brk_state(z->sh->breaker_state)
                   == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN)
        {
            (void) ngx_atomic_fetch_add(&z->sh->stale_serves, 1);
            /* S7.1: a genuine breaker-fallback SERVE (this is the
             * only-if-cached twin of the pre-origin-gate ACT_SERVE site
             * below; both deliver a STALE-BREAKER response). */
            (void) ngx_atomic_fetch_add(&z->sh->breaker_serves, 1);
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: only-if-cached + breaker OPEN -> "
                           "STALE-BREAKER serve \"%V\" key=%ui len=%uz",
                           &r->uri, (ngx_uint_t) hash, ctx->brk_snap_len);
            /* ref_data = NULL: the arming site owns the reference drop. */
            return ngx_http_cache_turbo_serve(r, ctx->brk_snap,
                       ctx->brk_snap_len, 1, z, NULL, "STALE-BREAKER");
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: only-if-cached miss \"%V\" key=%ui -> 504",
                       &r->uri, (ngx_uint_t) hash);
        return NGX_HTTP_GATEWAY_TIME_OUT;
    }

    /* ------------------------------------------------------------------
     * P6/O4.3: the pre-origin circuit-breaker gate.
     *
     * The chokepoint every ORIGIN-BOUND request passes exactly once: L1 has
     * missed or fallen past its stale window, L2 has been consulted and did not
     * satisfy us, and only-if-cached has already had its say. Everything below
     * this line (min_uses, the cold-miss single-flight, the plain miss) either
     * answers locally or returns NGX_DECLINED into the upstream.
     *
     * ⚠ SCOPE. This gate governs the requests this module can actually serve
     * from cache: anonymous, cacheable, main GET/HEAD. The prologue turns away
     * non-GET/HEAD, subrequests, Authorization-bearing requests, request
     * no-cache, auto-classified dynamic URIs and configured bypasses BEFORE the
     * handler ever gets here, and those still reach the origin while the
     * breaker is OPEN. That is not an oversight to be "fixed" by 503-ing them:
     * the breaker's whole mechanism is answering from a cached representation,
     * and for a request the module never caches there is nothing to answer
     * with. Refusing them would mean 503-ing authenticated and non-idempotent
     * traffic on the strength of a breaker that never observed it.
     *
     * ⚠ Placed AFTER the only-if-cached 504. RFC 9111 §5.2.1.7 makes 504 the
     * required answer when the cache cannot satisfy such a request, so the
     * breaker must not preempt it with a 503 -- and, more importantly, an
     * only-if-cached request must never become the origin PROBE, because by
     * definition it will not contact the origin. It would win the promotion and
     * then exit locally, burning one recovery lease per open window. A request
     * that CAN be satisfied from the breaker's snapshot returned above.
     *
     * ⚠ Placed BEFORE the cold-miss single-flight. A stampede onto a dead
     * origin must not first claim a stub and park every loser in cold_wait()
     * for a fill that can never arrive -- that turns an outage into lock_timeout
     * of latency on every request plus a parked worker for each.
     *
     * Three verdicts, from ngx_http_cache_turbo_shm_breaker_state():
     *
     *   CLOSED     -- normal service. Fall through untouched.
     *   HALF_OPEN  -- ⚠ WE ARE THE PROBE, and we hold the lease token in
     *                 ctx->brk_probe. This request MUST reach the origin so the
     *                 header filter can report the outcome back under that
     *                 token; serving it from cache would leave the breaker with
     *                 nobody to close it. Falling through is mandatory.
     *   OPEN       -- serve the fallback body if one was armed, else 503 +
     *                 Retry-After. Either way: no origin contact.
     *
     * ⚠ The state call is skipped entirely when breaker_should_consult() is
     * false (any of: not enabled, breaker off, threshold == 0, window == 0).
     * It is not a pure getter -- it performs the due OPEN -> HALF_OPEN
     * transition -- so calling it with the breaker disabled would drive a
     * state machine nothing can feed, and pay an shm read on every miss.
     */
    if (ngx_http_cache_turbo_breaker_should_consult(clcf))
    {
        ngx_uint_t  bact;

        /* ⚠ Consult at most ONCE per request; latch the verdict AND the lease
         * token. This handler is re-entered from the top on every park/resume
         * (L2 GET, the v4-2 NX lock, each cold_wait re-poll), and
         * _breaker_state() is not a pure getter -- it promotes exactly one
         * caller per open window and returns HALF_OPEN only to that promoter.
         * Consulting twice therefore hands a request that WAS the probe an OPEN
         * verdict on its resume, answers it locally, and leaves nobody to close
         * the breaker. See the brk_consulted field comment. */
        if (!ctx->brk_consulted) {
            ctx->brk_consulted = 1;
            ctx->brk_state = ngx_http_cache_turbo_shm_breaker_state(
                z, clcf->breaker_open, &ctx->brk_probe);
            ctx->brk_action = ngx_http_cache_turbo_breaker_action(
                ctx->brk_state, ctx->brk_armed);

            if (ctx->brk_state == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN) {
                /* Logged only on the consult that actually won the promotion.
                 * This line means "this request owes the breaker an outcome". */
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: breaker HALF_OPEN, this request is "
                               "the probe \"%V\" key=%ui -> origin",
                               &r->uri, (ngx_uint_t) hash);
            }
        }

        bact = ctx->brk_action;

        /* ⚠ O4.3-c (Codex F2): the probe leaves for the origin HERE, before
         * min_uses, claim(), the cross-node NX lock and cold_wait() -- every
         * one of which can park this request and resume it at the top of the
         * handler, where the L1 and L2 serve paths return BEFORE this gate and
         * brk_consulted stops the gate re-running. A parked probe answered from
         * a peer's fill never touches the origin, records no outcome, and
         * leaves the breaker HALF_OPEN until its lease expires -- the recovery
         * window is spent on a request that learned nothing.
         *
         * NGX_DECLINED is the handler's ordinary "carry on to the upstream"
         * return, the same one the fall-through below reaches; taking it early
         * simply skips the machinery that could divert us. */
        if (bact == NGX_HTTP_CACHE_TURBO_BRK_ACT_PROBE) {
            /* O4.3-c (F3): this request is going to the origin and can never
             * consume its armed fallback, so release the slab pin now instead
             * of holding it for the whole upstream round trip. */
            ngx_http_cache_turbo_brk_ref_drop(ctx, z);
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: breaker probe bypasses single-flight "
                           "\"%V\" key=%ui -> origin",
                           &r->uri, (ngx_uint_t) hash);
            return NGX_DECLINED;
        }

        /* O4.3-c (F3): same for an ordinary CLOSED-breaker request -- it falls
         * through to the origin below and will not serve the fallback either.
         * Only ACT_SERVE consumes it, and ACT_FAIL has nothing armed by
         * definition (it is the no-body verdict). Holding these pins across a
         * slow upstream is what lets an evictor drain the zone's LRU without
         * reclaiming any blob storage. */
        if (bact == NGX_HTTP_CACHE_TURBO_BRK_ACT_PASS) {
            ngx_http_cache_turbo_brk_ref_drop(ctx, z);
        }

        if (bact != NGX_HTTP_CACHE_TURBO_BRK_ACT_PASS) {

            if (bact == NGX_HTTP_CACHE_TURBO_BRK_ACT_SERVE) {
                /* Serve the stale body. ngx_http_cache_turbo_serve() is correct
                 * here and there is NO double-finalize hazard: we are in the
                 * ACCESS phase with no upstream in flight, the same position as
                 * every other _serve() call site. The hazard documented on
                 * ngx_http_cache_turbo_sie_rewrite() is specific to the HEADER
                 * FILTER, where a send_header + finalize would land inside
                 * ngx_http_special_response_handler on an already-finalizing
                 * request. Do not "unify" the two.
                 *
                 * stale = 1 suppresses the conditional-GET 304 shortcut: this
                 * copy is past its window and has NOT been revalidated, so a
                 * 304 would tell the client its cached copy is still good on
                 * the authority of an origin we cannot reach. */
                (void) ngx_atomic_fetch_add(&z->sh->stale_serves, 1);
                /* S7.1: the pre-origin-gate breaker-fallback SERVE. Bumped
                 * here (the delivery site), not at breaker_action()/
                 * ACT_SERVE classification, so this counts responses actually
                 * served, matching sie_serves/origin_failures discipline. */
                (void) ngx_atomic_fetch_add(&z->sh->breaker_serves, 1);
                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: breaker OPEN -> STALE-BREAKER serve "
                               "\"%V\" key=%ui len=%uz",
                               &r->uri, (ngx_uint_t) hash, ctx->brk_snap_len);
                /* ref_data = NULL on purpose: when brk_snap points into the
                 * slab, the ARMING site already registered the pool cleanup
                 * that drops that reference. Passing ctx->brk_ref here would
                 * register a SECOND cleanup for the same blob and double-drop
                 * the refcount, freeing a slab another worker may still be
                 * serving. The single cleanup covers both outcomes -- served
                 * and not served -- because it is tied to the request pool, not
                 * to this call. */
                return ngx_http_cache_turbo_serve(r, ctx->brk_snap,
                           ctx->brk_snap_len, 1, z, NULL, "STALE-BREAKER");
            }

            /* Nothing cached at any age: answer immediately rather than
             * spending a full connect/read timeout on a corpse. This is the
             * worker-exhaustion case the breaker exists for -- the 503 is the
             * feature, not a failure.
             *
             * Counted as a MISS so the zone totals stay reconcilable: every
             * other terminal branch in this handler bumps one of hits /
             * stale_serves / misses, and a branch that bumps nothing makes
             * hits+stale_serves+misses silently undercount once O4.4 makes the
             * breaker reachable. A miss is also what this is -- nothing was
             * served from cache. This is the ACT_FAIL branch (no body armed),
             * so it does not touch breaker_serves (S7.1) -- that counter is
             * bumped only at the two ACT_SERVE delivery sites above. */
            (void) ngx_atomic_fetch_add(&z->sh->misses, 1);
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: breaker OPEN, no body \"%V\" key=%ui "
                           "-> 503", &r->uri, (ngx_uint_t) hash);
            return ngx_http_cache_turbo_breaker_unavailable(r, clcf);
        }
    }

    /* min_uses (v15): defer caching until the key has cold-missed min_uses times,
     * so one-hit-wonder URLs never occupy the cache. The gate sits AFTER the L2
     * consult (a popular key already held in L2 was served above, never blocked
     * by min_uses) and BEFORE the v10 lock path (no point single-flighting a key
     * we are not going to store yet). Run once per request — min_uses_passed
     * guards the park/resume re-entries (the L2 GET / NX lock / cold-wait wakes
     * all re-enter this handler from the top). */
    if (clcf->min_uses > 1 && !ctx->min_uses_passed && !ctx->lock_done) {
        if (clcf->l1->count_miss(z, ctx->key_hash, hash, clcf->min_uses)
            == NGX_DECLINED)
        {
            /* Still below the threshold: run to the origin but do NOT store (the
             * header filter checks min_uses_skip before capturing). */
            ctx->min_uses_skip = 1;
            (void) ngx_atomic_fetch_add(&z->sh->misses, 1);
            (void) ngx_atomic_fetch_add(&z->sh->min_uses_skips, 1);
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: below min_uses \"%V\" key=%ui -> origin "
                           "(no store)", &r->uri, (ngx_uint_t) hash);
            return NGX_DECLINED;
        }
        /* Threshold reached: this request stores via the normal cold path below. */
        ctx->min_uses_passed = 1;
    }

    /* Cold-miss single-flight (v10). L1 absent/expired and L2 missed: rather than
     * let every concurrent first-hit stampede the origin, the first request
     * becomes the single regenerator (per box via a stub shm node, cross-node via
     * the v4-2 Redis NX lock) and the rest WAIT for it to fill the cache, then
     * serve it. cache_turbo_lock off restores the old straight-to-origin path. */
    if (clcf->lock) {
        time_t     lock_ttl = clcf->lock_ttl;
        ngx_int_t  cl;
        uint64_t   claim_owner = 0;   /* CTXRDR-ADOPT-LEASE: set on CLAIM_WINNER */

        if (lock_ttl <= 0) {
            lock_ttl = 5;
        }

        /* v4-4: widen the cold-miss single-flight window by the load factor too,
         * so a stampede onto an uncached key during a slow-origin spell collapses
         * onto one regen for longer (same rationale as the stale-refresh claim). */
        lock_ttl = lock_ttl
            * ngx_http_cache_turbo_effective_load(clcf, z)
            / NGX_HTTP_CACHE_TURBO_AT_LOAD_BASE;

        /* Resume after the cross-node NX park (we are the per-box claim winner
         * that fired the lock): won -> we own the fleet-wide regen, go to origin;
         * lost -> another node is filling, wait for its L2 write-through. An
         * NGX_ERROR (Redis outage: lock channel failed) is NOT a peer holding the
         * lock — going to origin would stampede, but cold-waiting would add a full
         * lock_timeout of dead latency for a fill that will never arrive. Treat it
         * as a win: the per-box stub we already hold still single-flights this box,
         * so degrade to per-box single-flight and regenerate now (codex). */
        if (ctx->lock_done) {
            if (ctx->lock_result == NGX_OK || ctx->lock_result == NGX_ERROR) {
                (void) ngx_atomic_fetch_add(&z->sh->misses, 1);
                /* This resume always follows a CLAIM_WINNER below that fired
                 * the cross-node NX lock and parked: an L1 lease WAS taken
                 * (CTXRDR-ADOPT-LEASE) and its token is stashed in
                 * ctx->pending_l1_owner since the claim_owner stack local
                 * that carried it does not survive the park/resume. Hand it
                 * to the winner so the lease is cleared by shm_unstub()
                 * instead of leaking. */
                ngx_http_cache_turbo_cold_mark_winner(r, ctx, z,
                                                       ctx->pending_l1_owner);
                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: cold-miss cross-node WON%s \"%V\" "
                               "key=%ui -> origin",
                               ctx->lock_result == NGX_ERROR ? " (L2 down)" : "",
                               &r->uri, (ngx_uint_t) hash);
                return NGX_DECLINED;
            }
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: cold-miss cross-node LOST \"%V\" key=%ui "
                           "-> wait for L2 fill", &r->uri, (ngx_uint_t) hash);
            return ngx_http_cache_turbo_cold_wait(r, clcf, z, ctx);
        }

        cl = clcf->l1->claim(z, ctx->key_hash, hash, lock_ttl, &claim_owner);
        /* Stash the lease token now: if this claim is a CLAIM_WINNER that
         * goes on to fire the cross-node NX lock below, the request parks
         * (NGX_AGAIN) and resumes at the top of this block on a fresh call
         * where claim_owner (a stack local) no longer holds it. */
        ctx->pending_l1_owner = claim_owner;

        if (cl == NGX_HTTP_CACHE_TURBO_CLAIM_FRESH) {
            /* A real fresh entry raced in while we were on the cold path
             * (another local winner finished): re-serve it from L1. */
            ngx_http_cache_turbo_node_t  *fresh;
            size_t                        snap_len;

            ngx_shmtx_lock(&z->shpool->mutex);
            fresh = clcf->l1->lookup(z, ctx->key_hash, hash);
            /* RFC-1: do NOT re-serve the raced-in fresh entry when this request
             * is a revalidation forced by its own freshness bounds (max-age /
             * min-fresh) — that entry is exactly what the client rejected. Fall
             * through to the origin instead. */
            if (fresh != NULL && fresh->len > 0
                && ngx_time() < fresh->fresh_until
                && !ctx->req_reval)
            {
                /* PERF-7: zero-copy serve of the raced-in fresh entry. */
                u_char *body = fresh->data;
                snap_len = fresh->len;
                ngx_http_cache_turbo_blob_acquire(body);
                ngx_shmtx_unlock(&z->shpool->mutex);
                (void) ngx_atomic_fetch_add(&z->sh->hits, 1);
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: cold-miss raced to FRESH \"%V\" "
                               "key=%ui -> serve", &r->uri, (ngx_uint_t) hash);
                return ngx_http_cache_turbo_serve(r, body, snap_len, 0, z, body,
                                                  NULL);
            }
            ngx_shmtx_unlock(&z->shpool->mutex);
            /* vanished again (evicted/expired in the race): go to origin */
            (void) ngx_atomic_fetch_add(&z->sh->misses, 1);
            return NGX_DECLINED;
        }

        if (cl == NGX_HTTP_CACHE_TURBO_CLAIM_LOSER) {
            /* CTXRDR: we may have LOST to ourselves. An internal redirect
             * (error_page / X-Accel-Redirect) memzeros r->ctx mid-request, so a
             * second pass over a key that is stable across the redirect finds
             * the stub its own first pass planted and would otherwise park on
             * it for the full lock_timeout. Adopt it and proceed as the winner
             * we already are. */
            if (ngx_http_cache_turbo_cold_adopt_own_stub(r, ctx, z) == NGX_OK) {
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: cold-miss adopted OWN stub across "
                               "internal redirect \"%V\" key=%ui",
                               &r->uri, (ngx_uint_t) hash);
                return NGX_DECLINED;      /* go to origin as the winner */
            }

            return ngx_http_cache_turbo_cold_wait(r, clcf, z, ctx);
        }

        /* CLAIM_WINNER: we created/took over the in-flight stub. Fire the
         * cross-node NX lock (v4-2) so the whole fleet single-flights too; park
         * for the reply (resolved at the top of this block on resume).
         * NGX_DECLINED = no L2 / could not start -> single-box winner now. */
        if (clcf->backend && clcf->backend->lock) {
            ngx_int_t  lrc = clcf->backend->lock(r, clcf, ctx, lock_ttl);
            if (lrc == NGX_AGAIN) {
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: cold-miss parked on L2 lock NX \"%V\" "
                               "key=%ui", &r->uri, (ngx_uint_t) hash);
                return NGX_AGAIN;
            }
        }

        (void) ngx_atomic_fetch_add(&z->sh->misses, 1);
        ngx_http_cache_turbo_cold_mark_winner(r, ctx, z, claim_owner);
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: cold-miss single-box WON \"%V\" key=%ui "
                       "-> origin", &r->uri, (ngx_uint_t) hash);
        return NGX_DECLINED;
    }

    /* true miss (cache_turbo_lock off): mark for capture, run to the origin */
    (void) ngx_atomic_fetch_add(&z->sh->misses, 1);
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cache_turbo: MISS \"%V\" key=%ui -> origin",
                   &r->uri, (ngx_uint_t) hash);
    return NGX_DECLINED;
}


/* Cold-miss single-flight waiter (v10). A request that lost the cold-miss claim
 * (or the cross-node NX) parks on a short timer and re-checks L1/L2 until the
 * winner fills the entry (a later re-entry then serves it) or lock_timeout
 * elapses, at which point it falls through to the origin itself. Mirrors the
 * redis park/resume dance: count++ here, finalize(NGX_DONE) in the timer handler. */
static ngx_int_t
ngx_http_cache_turbo_cold_wait(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_ctx_t *ctx)
{
    ngx_msec_t       now = ngx_current_msec;
    ngx_msec_int_t   remaining;
    ngx_msec_t       delay;

    if (!ctx->waiting) {
        ctx->waiting = 1;
        ctx->wait_deadline = now + clcf->lock_timeout;
        (void) ngx_atomic_fetch_add(&z->sh->lock_waits, 1);
    }

    /* V-HANG-2: a previous re-poll already found the key PRESENT in L2 but past
     * its stored stale window. The winner's fill has landed; it is simply not
     * serveable to us. Polling again can only re-read the same blob, so stop
     * waiting and regenerate now instead of burning the rest of lock_timeout.
     *
     * ⚠ This is NOT an early `unlock`. The cross-node NX lock is still held by
     * its owner and still expires only by PX (module.h: unlock stays NULL, and
     * releasing it here would re-open the dogpile window). We only stop THIS
     * waiter from parking for a fill that has demonstrably already happened —
     * the per-box stub still single-flights this box.
     *
     * Bites whenever the stored stale window is shorter than lock_ttl: e.g.
     * cache_turbo_stale_mult 1 makes stale_window == fresh_ttl, so the entry is
     * unserveable ~1s after it is written while the lock lives 5s. Every
     * request in that gap stalled the full lock_timeout (~5s) before this.
     *
     * ⚠ Gated on wait_polled, NOT on ctx->waiting: waiting is set unconditionally
     * a few lines above, so it is always 1 by the time we read it here and tests
     * nothing. The inference "the fill has already landed" is only valid AFTER we
     * have actually parked once — on the first pass a CLAIM_LOSER can reach this
     * with the flag set by its own initial L2 lookup, before the winner has
     * written anything, and giving up there stampedes the origin with every
     * loser. Do not relax this back to ctx->waiting. */
    if (ctx->wait_polled && ctx->l2_present_unserveable) {
        ctx->waiting = 0;
        (void) ngx_atomic_fetch_add(&z->sh->misses, 1);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: cold-wait sees L2 filled-but-unserveable "
                       "\"%V\" -> origin", &r->uri);
        return NGX_DECLINED;
    }

    remaining = (ngx_msec_int_t) (ctx->wait_deadline - now);
    if (remaining <= 0) {
        /* Waited long enough: give up and regenerate ourselves. Our store ends
         * the wait for any remaining readers. Bounded by lock_timeout. */
        ctx->waiting = 0;
        (void) ngx_atomic_fetch_add(&z->sh->misses, 1);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: cold-miss wait timeout \"%V\" -> origin",
                       &r->uri);
        return NGX_DECLINED;
    }

    /* Re-consult L2 on the next re-entry so a cross-node winner's write-through
     * is picked up (per-box fills are caught by the L1 lookup itself).
     *
     * L13: that cross-node pickup is the ONE thing the negative memo would
     * wrongly suppress -- we are here precisely because we expect a peer to
     * publish the key mid-wait, which is the memo's blind spot. So force a real
     * L2 GET on every cold-wait re-poll (l2_neg_force) and clear the
     * skipped-flag, rather than letting a memo armed moments ago short-circuit
     * the wait into a guaranteed origin fetch. */
    ctx->l2_done = 0;
    ctx->l2_neg_skipped = 0;
    ctx->l2_neg_force = 1;
    /* ⚠ NGX_ERROR ("no L2 answer yet"), NOT NGX_DECLINED. Since L13-fix,
     * NGX_DECLINED means "L2 definitively does not have this key" and is what
     * licenses arming the negative memo. Seeding a pre-GET placeholder with it
     * makes every cold-wait re-poll look like a fresh definitive miss: combined
     * with the l2_neg_skipped reset above, that re-arms the memo on each poll and
     * slides l2_neg_until forward indefinitely, so a hot-but-absent key never
     * re-consults L2. The real result overwrites this when the GET completes. */
    ctx->l2_result = NGX_ERROR;
    ctx->l2_blob = NULL;
    ctx->l2_blob_len = 0;

    delay = NGX_HTTP_CACHE_TURBO_LOCK_POLL_MS;
    if (delay > (ngx_msec_t) remaining) {
        delay = (ngx_msec_t) remaining;
    }

    if (ctx->cold_wait_ev.handler == NULL) {
        ngx_pool_cleanup_t  *cln;

        ctx->cold_wait_ev.handler = ngx_http_cache_turbo_cold_wait_timeout;
        ctx->cold_wait_ev.data = r;
        ctx->cold_wait_ev.log = r->connection->log;

        /* Cancel a still-pending poll timer at request teardown. Without this,
         * a request torn down while parked here (client abort, or worker exit
         * under cold-key churn) leaves cold_wait_ev armed on a freed r and the
         * count++ below unbalanced -- the connection cannot close, surfacing as
         * "open socket left in connection" at shutdown. Registered once, on the
         * same one-shot path that first arms the timer; the timeout handler runs
         * ngx_del_timer implicitly via its finalize, so a normal wake leaves
         * timer_set == 0 and the cleanup is a no-op. */
        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            /* Never arm the timer without its teardown cancellation: under the
             * memory exhaustion that makes this fail, a subsequent teardown is
             * exactly when the orphaned-timer socket leak would bite. Fail
             * closed (the access handler finalizes 500) instead. */
            return NGX_ERROR;
        }
        cln->handler = ngx_http_cache_turbo_cold_wait_cleanup;
        cln->data = ctx;
    }

    ngx_add_timer(&ctx->cold_wait_ev, delay);
    r->main->count++;
    /* We are now genuinely parked: any subsequent re-entry is a re-poll, so the
     * V-HANG-2 give-up at the top of this function may trust an
     * l2_present_unserveable observed from here on. Never cleared. */
    ctx->wait_polled = 1;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cache_turbo: cold-miss WAIT \"%V\" poll=%M ms",
                   &r->uri, delay);
    return NGX_AGAIN;
}


/* Timer fired: re-drive the parked waiter through the phase engine (re-enters the
 * access handler, which re-checks L1/L2). Same teardown as the redis get_finish
 * resume — run_phases, run_posted_requests, then release the parked reference. */
static void
ngx_http_cache_turbo_cold_wait_timeout(ngx_event_t *ev)
{
    ngx_http_request_t  *r = ev->data;
    ngx_connection_t    *c = r->connection;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "cache_turbo: cold-miss wait wake \"%V\"", &r->uri);

    ngx_http_core_run_phases(r);
    ngx_http_run_posted_requests(c);
    ngx_http_finalize_request(r, NGX_DONE);
}


/* Pool cleanup: delete a still-armed cold-wait poll timer at request teardown.
 * The timer's ev.data points at r; once the request pool is being destroyed that
 * pointer is dangling, so a timer left in the event tree would fire the handler
 * on freed memory. Deleting it here makes teardown safe on every path that
 * bypasses the normal timer wake (worker exit under cold-key churn, connection
 * reset). A normal wake already ran ngx_del_timer, so timer_set is 0 and this
 * is a no-op. */
static void
ngx_http_cache_turbo_cold_wait_cleanup(void *data)
{
    ngx_http_cache_turbo_ctx_t  *ctx = data;

    if (ctx->cold_wait_ev.timer_set) {
        ngx_del_timer(&ctx->cold_wait_ev);
    }
}


/* Mark this request as the cold-miss winner that owns the in-flight stub, and
 * register a pool cleanup so the stub is removed at request teardown if the
 * winner never stored a real entry (non-cacheable response, oversized body,
 * upstream error, client abort). The header filter clears it earlier for the
 * common non-cacheable case; this is the backstop for every other non-store
 * exit. Registered once per request (the winner-DECLINED sites are reached at
 * most once). */
static void
ngx_http_cache_turbo_cold_mark_winner(ngx_http_request_t *r,
    ngx_http_cache_turbo_ctx_t *ctx, ngx_http_cache_turbo_zone_t *z,
    uint64_t owner)
{
    ngx_pool_cleanup_t  *cln;

    if (ctx->cold_winner) {
        return;
    }

    ctx->cold_winner = 1;
    ctx->cold_zone = z;
    /* CTXRDR-ADOPT-LEASE: the lease token claim() issued to us, or 0 when this
     * win did not come with an L1 lease (the cross-node L2 path, and the
     * out-of-slab claim that could not create a node). 0 is inert everywhere:
     * such a winner stores normally but never clears anyone's lease. */
    ctx->cold_owner = owner;

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return;
    }
    cln->handler = ngx_http_cache_turbo_cold_cleanup;
    cln->data = ctx;
}


/*
 * CTXRDR: find a cold-miss stub that an EARLIER ctx of THIS SAME REQUEST is
 * still holding for `key_hash`, and hand its ownership to `ctx`.
 *
 * An internal redirect (error_page, X-Accel-Redirect, a rewrite that reaches a
 * new location) memzeros r->ctx unconditionally -- ngx_http_core_module.c:2614,
 * and the one-module-preserving variant at special_response.c:547 is the
 * filter_finalize path, not this one. r->pool is NOT reset, so a ctx that won a
 * claim before the redirect keeps its pool cleanup and its cold_winner/cold_zone
 * state, but the access handler on the second pass sees r->ctx == NULL, pcallocs
 * a FRESH ctx (cold_winner = 0), and no longer knows the request owns the stub.
 *
 * With a key that is stable across the redirect -- $request_uri, the form every
 * doc here recommends precisely because it survives one -- both passes hash to
 * the same key, so the second pass finds its OWN stub, reads it as another
 * request's in-flight fill, and parks in cold_wait() until lock_timeout (5s by
 * default) before giving up and re-winning. The request answers correctly but
 * pays the full timeout, and none of the three header/body-filter unstub sites
 * can prevent it: an intercepted error is finalized by
 * ngx_http_upstream_intercept_errors() without traversing the output filter
 * chain at all, so only the pool cleanup remains and that runs at teardown --
 * long after the second pass has already parked.
 *
 * The cleanup list is the authority for WHICH ctx of this request last held a
 * stub for the key: it is already the request-lifetime record of "this ctx owns
 * an unresolved stub", it is exactly what the redirect leaves intact, and
 * reusing it keeps one source of truth instead of two that can disagree. The
 * list is short (a handful of entries per request) and this runs only on the
 * CLAIM_LOSER path.
 *
 * ⚠ CTXRDR-ADOPT-LEASE -- the cleanup list is NOT sufficient on its own, and an
 * earlier version of this function that stopped there was wrong. cold_winner +
 * !cold_stored + zone + key prove only that this request owned a stub for this
 * key at SOME point. They cannot prove it owns the live one, because claim()
 * deliberately re-leases a stub whose refresh_lock_until has passed to a
 * different request, and CLAIM_LOSER is the zone telling us authoritatively that
 * someone else holds it NOW. Overriding that on stale request-local state let
 * two requests regenerate concurrently and let the loser's unstub() clear the
 * winner's live lease -- single-flight broken and the origin stampeded, exactly
 * during the origin slowness that opened the window.
 *
 * So the cleanup list only nominates a candidate; shm_owns() adjudicates it
 * against the zone under the mutex. Both must agree before we adopt.
 */
static ngx_int_t
ngx_http_cache_turbo_cold_adopt_own_stub(ngx_http_request_t *r,
    ngx_http_cache_turbo_ctx_t *ctx, ngx_http_cache_turbo_zone_t *z)
{
    ngx_pool_cleanup_t          *c;
    ngx_http_cache_turbo_ctx_t  *prev;

    for (c = r->pool->cleanup; c; c = c->next) {
        if (c->handler != ngx_http_cache_turbo_cold_cleanup) {
            continue;
        }

        prev = c->data;

        if (prev == NULL || prev == ctx) {
            continue;
        }

        /* Same key, same zone, and the stub is still unresolved: this request
         * already owns it. Compare the full 32-byte key -- the rbtree's crc32
         * is collision-prone by design, and adopting on a collision would clear
         * a DIFFERENT key's stub. */
        if (prev->cold_winner
            && !prev->cold_stored
            && prev->cold_zone == z
            && ngx_memcmp(prev->key_hash, ctx->key_hash, 32) == 0)
        {
            /* The candidate held a stub for this key. Now ask the ZONE whether
             * that lease is still ours, rather than assuming it from the above.
             * A mismatch means claim() re-leased it (or store()/unstub() already
             * resolved it) and CLAIM_LOSER was right: fall through, keep
             * searching, and ultimately wait like any other loser. */
            if (ngx_http_cache_turbo_shm_owns(z, ctx->key_hash,
                    ngx_crc32_short(ctx->key_hash, 32),
                    prev->cold_owner) != NGX_OK)
            {
                continue;
            }

            /* Transfer ownership to the live ctx, INCLUDING the lease token --
             * without it the adopting ctx could not prove ownership to unstub()
             * and would leave the stub to expire on its own. Retarget this very
             * cleanup instead of registering a second one: the entry is already
             * in the list, so ownership moves with a single store that cannot
             * fail, and there is exactly one cleanup per live stub. The earlier
             * shape (mark inert + ngx_pool_cleanup_add) could fail its
             * allocation AFTER disarming the old entry and still return NGX_OK,
             * leaving an adopted stub with no teardown owner at all. */
            ctx->cold_winner = 1;
            ctx->cold_zone = z;
            ctx->cold_owner = prev->cold_owner;

            prev->cold_stored = 1;   /* the old ctx no longer owns anything */
            c->data = ctx;           /* ...and this cleanup now speaks for us */

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


/* Pool cleanup: if the cold-miss winner never resolved its stub (no real entry
 * stored, stub not already cleared), remove the leftover stub so waiters for
 * this key stop blocking. unstub only drops a node that is still a stub. */
static void
ngx_http_cache_turbo_cold_cleanup(void *data)
{
    ngx_http_cache_turbo_ctx_t  *ctx = data;
    uint32_t                     hash;

    if (!ctx->cold_winner || ctx->cold_stored || ctx->cold_zone == NULL) {
        return;
    }

    hash = ngx_crc32_short(ctx->key_hash, 32);
    ngx_http_cache_turbo_shm_unstub(ctx->cold_zone, ctx->key_hash, hash,
                                    ctx->cold_owner);
}


/* Add a simple response header (name/value already in a stable buffer). */
static ngx_int_t
ngx_http_cache_turbo_add_header(ngx_http_request_t *r,
    u_char *name, size_t nlen, u_char *val, size_t vlen)
{
    ngx_table_elt_t  *h;

    h = ngx_http_cache_turbo_restore_alloc_fails(r)
            ? NULL : ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    h->key.len = nlen;
    h->key.data = name;
    h->value.len = vlen;
    h->value.data = val;
#if (nginx_version >= 1023000)
    h->next = NULL;
#endif

    return NGX_OK;
}


#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
/*
 * O4.4-i: emit the zone's lifetime breaker-arming count as
 * X-Cache-Turbo-Test-Armings so a runtime test can assert that a `breaker off`
 * location armed NOTHING, which is the negative control the black-box shape
 * cannot provide (the pre-origin gate masks the two arming sites).
 *
 * TEST_FAULTS-only: production and package builds define neither the counter
 * nor this function, so no public surface is added to serve a test.
 *
 * ⚠ Uses ngx_list_push() directly rather than the add_header() helper, because
 * that helper is deliberately suppressed by cache_turbo_test_restore_alloc_fail.
 * An oracle that vanishes under an unrelated fault flag would read as "armed 0"
 * -- the exact vacuous pass this control exists to prevent.
 *
 * ⚠ ADDING ANOTHER TEST/DIAGNOSTIC HEADER? It must be re-stamped on the
 * STALE-IF-ERROR path too (OBS-1). sie_rewrite() calls ngx_list_init() on
 * headers_out.headers (see :7079) to make the stored snapshot authoritative,
 * which wipes everything the header filter has already stamped. A header added
 * only in the filter therefore reports the SNAPSHOT's stored value -- normally
 * 0 -- on every serve-on-error response, while the live counter has moved. It
 * does not error; it silently reports a stale number, which is strictly worse
 * for an oracle. This is a known constraint of the SIE path, not a bug to
 * rediscover: re-stamp after restore_response() the way :7117 does, or teach
 * the wipe to preserve module-added headers.
 */
static ngx_int_t
ngx_http_cache_turbo_test_armings_header(ngx_http_request_t *r)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf;
    ngx_http_cache_turbo_zone_t      *z;
    ngx_table_elt_t                  *h;
    u_char                           *v;
    size_t                            vlen;

    static u_char  name[] = "X-Cache-Turbo-Test-Armings";

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);

    if (clcf->shm_zone == NULL) {
        return NGX_DECLINED;
    }

    z = clcf->shm_zone->data;
    if (z == NULL || z->sh == NULL) {
        return NGX_DECLINED;
    }

    /* "l1=<n>,l2=<n>" -- the two arming sites are reported separately so a
     * test can attribute a delta to ONE of them. A single total cannot: the L1
     * site runs first on every request, so an L2 assertion against a shared
     * counter passes on L1's bump and the L2 mutation stays green (measured).
     * Room for both values plus the "l1=" / ",l2=" literals. */
    v = ngx_pnalloc(r->pool, sizeof("l1=,l2=") - 1 + 2 * NGX_ATOMIC_T_LEN);
    if (v == NULL) {
        return NGX_ERROR;
    }

    vlen = ngx_sprintf(v, "l1=%uA,l2=%uA",
                       ngx_atomic_fetch_add(&z->sh->test_brk_armings_l1, 0),
                       ngx_atomic_fetch_add(&z->sh->test_brk_armings_l2, 0)) - v;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    h->key.len = sizeof("X-Cache-Turbo-Test-Armings") - 1;
    h->key.data = name;
    h->value.len = vlen;
    h->value.data = v;
#if (nginx_version >= 1023000)
    h->next = NULL;
#endif

    return NGX_OK;
}
#endif


/*
 * cache_turbo_surrogate_key emit. Evaluate the cache_turbo_tag expression,
 * tokenise it with the SAME whitespace/comma split, per-tag length cap
 * (MAX_TAG_LEN) and count cap + dedup (MAX_TAGS) the L2 tag-index store uses,
 * then join the surviving tags into ONE space-separated Surrogate-Key response
 * header (Fastly / RFC edge-arch surrogate spec) so a CDN fronting this cache
 * keys the edge object on the same tags. Space is the surrogate-key separator;
 * the tokeniser splits on it, so a single tag never itself contains a space.
 *
 * Called from the HEADER filter on the capture (MISS/store) path BEFORE headers
 * are sent (the body-filter store runs after the header filter, far too late to
 * add a response header), AND from restore_response() on every HIT/STALE serve
 * (SK-A1): a CDN POP that lost its own copy refills from one of our hits, so a
 * hit without the key produces an untagged, unpurgeable edge object. Independent
 * of cache_turbo_redis -- emitting the CDN header needs no turbo L2 tag index.
 *
 * Best-effort: empty tag value, zero surviving tags, or any allocation failure
 * simply skips the header. A missing CDN purge-key is a degraded-but-correct
 * edge (still cached, just not CDN-tag-purgeable), never a response failure. */
static void
ngx_http_cache_turbo_emit_surrogate_key(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf)
{
    ngx_str_t    tagval, seen[NGX_HTTP_CACHE_TURBO_MAX_TAGS];
    u_char      *s, *e, *tok, *buf, *p;
    size_t       toklen, len = 0;
    ngx_uint_t   ntags = 0, i, k;

    if (clcf->tag == NULL) {
        return;
    }
    if (ngx_http_complex_value(r, clcf->tag, &tagval) != NGX_OK
        || tagval.len == 0)
    {
        return;
    }

    s = tagval.data;
    e = tagval.data + tagval.len;

    while (s < e && ntags < NGX_HTTP_CACHE_TURBO_MAX_TAGS) {
        while (s < e && (*s == ' ' || *s == '\t' || *s == ','
                         || *s == '\r' || *s == '\n'))
        {
            s++;
        }
        tok = s;
        while (s < e && *s != ' ' && *s != '\t' && *s != ','
               && *s != '\r' && *s != '\n')
        {
            s++;
        }
        toklen = (size_t) (s - tok);
        if (toklen == 0 || toklen > NGX_HTTP_CACHE_TURBO_MAX_TAG_LEN) {
            continue;
        }

        for (k = 0; k < ntags; k++) {          /* dedup within value */
            if (seen[k].len == toklen
                && ngx_memcmp(seen[k].data, tok, toklen) == 0)
            {
                break;
            }
        }
        if (k < ntags) {
            continue;
        }

        seen[ntags].data = tok;
        seen[ntags].len = toklen;
        ntags++;
    }

    if (ntags == 0) {
        return;
    }

    for (i = 0; i < ntags; i++) {
        len += seen[i].len + 1;                /* +1 for a separating space */
    }

    buf = ngx_pnalloc(r->pool, len);
    if (buf == NULL) {
        return;                                /* degrade: no CDN key, still cached */
    }

    p = buf;
    for (i = 0; i < ntags; i++) {
        if (i != 0) {
            *p++ = ' ';
        }
        p = ngx_cpymem(p, seen[i].data, seen[i].len);
    }

    (void) ngx_http_cache_turbo_add_header(r,
               (u_char *) "Surrogate-Key", sizeof("Surrogate-Key") - 1,
               buf, (size_t) (p - buf));
}


/* CI builds can fail every allocation in cached-response reconstruction. The
 * directive and field do not exist in production/package builds; keeping the
 * hook at the allocation sink lets runtime tests exercise both live HIT and
 * stale-if-error fail-closed behaviour without weakening ngx_alloc globally. */
static ngx_uint_t
ngx_http_cache_turbo_restore_alloc_fails(ngx_http_request_t *r)
{
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    ngx_http_cache_turbo_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);
    return clcf->test_restore_alloc_fail ? 1 : 0;
#else
    (void) r;
    return 0;
#endif
}


/*
 * RFC 7232 conditional evaluation for a cache HIT (v11). Returns 1 when the
 * client's validators match the stored representation and we should reply 304
 * instead of the body. If-None-Match takes precedence; If-Modified-Since is
 * only consulted when If-None-Match is absent (RFC 7232 §6). etag/lm are the
 * raw stored validator values (including ETag's surrounding quotes), captured
 * out of the blob; either may be empty when the response carried no such
 * header. The If-None-Match walk mirrors core's ngx_http_test_if_match with the
 * weak comparator (correct for GET/HEAD): strip an optional "W/" from both the
 * stored tag and each list entry, then octet-compare the quoted opaque tag.
 */
static ngx_uint_t
ngx_http_cache_turbo_not_modified(ngx_http_request_t *r,
    u_char *etag, size_t etag_len, u_char *lm, size_t lm_len)
{
    ngx_table_elt_t  *inm = r->headers_in.if_none_match;
    ngx_table_elt_t  *ims = r->headers_in.if_modified_since;

    if (inm != NULL) {
        u_char  *start = inm->value.data;
        u_char  *end = start + inm->value.len;
        u_char   ch;

        /* "*" matches any current representation (we have one cached). */
        if (inm->value.len == 1 && start[0] == '*') {
            return 1;
        }

        if (etag_len == 0) {
            return 0;
        }

        if (etag_len > 2 && etag[0] == 'W' && etag[1] == '/') {
            etag += 2;
            etag_len -= 2;
        }

        while (start < end) {

            if (end - start > 2 && start[0] == 'W' && start[1] == '/') {
                start += 2;
            }

            if (etag_len > (size_t) (end - start)) {
                return 0;
            }

            if (ngx_strncmp(start, etag, etag_len) != 0) {
                goto skip;
            }

            start += etag_len;

            while (start < end) {
                ch = *start;
                if (ch == ' ' || ch == '\t') { start++; continue; }
                break;
            }

            if (start == end || *start == ',') {
                return 1;
            }

        skip:
            while (start < end && *start != ',') { start++; }
            while (start < end) {
                ch = *start;
                if (ch == ' ' || ch == '\t' || ch == ',') { start++; continue; }
                break;
            }
        }

        return 0;
    }

    if (ims != NULL && lm_len) {
        time_t  ims_t, lm_t;

        ims_t = ngx_parse_http_time(ims->value.data, ims->value.len);
        lm_t  = ngx_parse_http_time(lm, lm_len);

        if (ims_t != NGX_ERROR && lm_t != NGX_ERROR && lm_t <= ims_t) {
            return 1;
        }
    }

    return 0;
}


/* Rebuild r->headers_out from a validated, pool-owned cache blob (caller already
 * copied it out of shm and released the zone lock): set status / Content-Type /
 * Content-Length, replay the stored headers, answer a conditional 200 with 304
 * (live serves only), and stamp Date / Age / X-Cache. Returns the body slice via
 * *bodyp / *body_lenp. Does NOT send the header or body — ngx_http_cache_turbo_
 * serve() does that for a live HIT, while the RFC-2 serve-on-error path calls
 * this from the header filter and lets the filter chain carry the response. */
static ngx_int_t
ngx_http_cache_turbo_restore_response(ngx_http_request_t *r, u_char *copy,
    size_t len, ngx_uint_t stale, const char *xcache,
    u_char **bodyp, size_t *body_lenp)
{
    u_char                           *p, *end, *body;
    size_t                            body_len;
    ngx_http_cache_turbo_blob_hdr_t   hdr;
    ngx_http_cache_turbo_blob_hdr_t  *bh;
    uint32_t                          i;
    u_char                           *etag = NULL, *lastmod = NULL;
    size_t                            etag_len = 0, lastmod_len = 0;
    ngx_uint_t                        dropped = 0;
    ngx_http_cache_turbo_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);

    /* A NULL blob is never produced by a live caller (every HIT/L2 path holds a
     * real buffer), but guard at the deref site so the static analyzer can prove
     * the header walk below never reads through a null `p`. */
    if (copy == NULL || clcf == NULL) {
        return NGX_ERROR;
    }

    /* STAB-4: one validated parse. blob_validate checks magic+version, that the
     * header block and body fit, AND walks every TLV header entry — so the
     * restore loop below cannot run off the end. The blob is byte-aligned
     * (ngx_pnalloc); the validator reads the wire header with fixed-endian
     * getters, no misaligned struct cast. */
    if (ngx_http_cache_turbo_blob_validate(copy, len, &hdr, NULL, NULL)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    bh = &hdr;

    p   = copy + NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE;
    end = p + bh->headers_len;
    body = end;
    body_len = bh->body_len;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cache_turbo: serve status=%ui body=%uz stale=%ui",
                   (ngx_uint_t) bh->status, body_len, stale);

    r->headers_out.status = bh->status;
    r->headers_out.content_length_n = body_len;

    /* Restore each stored header. Content-Type is mapped to the typed field;
     * the rest go onto the headers list. */
    for (i = 0; i < bh->nheaders; i++) {
        uint32_t       nl, vl;
        u_char        *nm, *vv;
        const u_char  *cp = p, *cnm, *cvv;

        if (ngx_http_cache_turbo_blob_next_header(&cp, end, &cnm, &nl,
                                                  &cvv, &vl) != NGX_OK)
        {
            break;
        }
        p = (u_char *) cp;
        nm = (u_char *) cnm;
        vv = (u_char *) cvv;

        /* AUD-HDR1: the restore-side mirror of the store-side filter. This runs
         * BEFORE the Content-Type / validator branches below, because those
         * also put the bytes into the response (content_type is serialised by
         * core just like a list header) — a gate placed after them would leave
         * exactly the typed fields unguarded. Drop, don't fail: one poisoned
         * header must not cost the client the whole cached response. */
        if (!ngx_http_cache_turbo_header_admissible(clcf, nm, nl, vv, vl)) {
            dropped++;
            continue;
        }

        if (nl == sizeof("Content-Type") - 1
            && ngx_strncasecmp(nm, (u_char *) "Content-Type", nl) == 0)
        {
            r->headers_out.content_type.len = vl;
            r->headers_out.content_type.data = vv;
            r->headers_out.content_type_len = vl;
            continue;
        }

        /* v11: remember the stored validators so we can answer a conditional
         * request with 304 below. They are still emitted as normal headers. */
        if (nl == sizeof("ETag") - 1
            && ngx_strncasecmp(nm, (u_char *) "ETag", nl) == 0)
        {
            etag = vv;
            etag_len = vl;

        } else if (nl == sizeof("Last-Modified") - 1
                   && ngx_strncasecmp(nm, (u_char *) "Last-Modified", nl) == 0)
        {
            lastmod = vv;
            lastmod_len = vl;
        }

        if (ngx_http_cache_turbo_add_header(r, nm, nl, vv, vl) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /* AUD-HDR1: report ONCE per restore, not once per header. A poisoned entry is
     * served repeatedly, and an attacker who controls the header count would
     * otherwise pick the log-amplification factor. WARN (not INFO) because a
     * cached copy written by this module never trips the gate: reaching here at
     * all means the L2 copy did not come from us. */
    if (dropped) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "cache_turbo: dropped %ui inadmissible stored header(s) "
                      "while restoring \"%V\" — the cached copy may be forged",
                      dropped, &r->uri);
    }

    /* SK-A1: re-emit the CDN purge key on every HIT/STALE serve, not only on the
     * MISS that stored the entry. A fronting surrogate-key CDN refills a POP from
     * one of OUR hits whenever its own copy expired or was evicted; without the
     * key that edge object is untagged and survives a later tag purge, leaving
     * stale content publicly served. Generated live from the same cache_turbo_tag
     * expression (the header is skipped at store while the directive is on, so
     * there is no duplicate), and best-effort like the MISS-path emit. */
    if (clcf->surrogate_key) {
        ngx_http_cache_turbo_emit_surrogate_key(r, clcf);
    }

    /* Conditional request (v11): a 200 HIT whose stored ETag / Last-Modified
     * satisfy the client's If-None-Match / If-Modified-Since is answered 304
     * with no body. Only 200 is validated this way (redirects and other cached
     * statuses serve normally); GET/HEAD only. Pre-converting the status keeps
     * core's not-modified header filter a no-op (it bails unless status == 200),
     * so there is no double handling. (Core's own ngx_http_test_if_match /
     * ngx_http_test_if_modified are static in the not-modified filter module and
     * cannot be linked; ngx_http_cache_turbo_not_modified mirrors them with the
     * weak comparator.)
     *
     * RFC-6: gate the 304 behind freshness — a 304 means "your cached copy is
     * still good", which we may only assert for a response we know is fresh.
     * A STALE entry has not been revalidated against the origin, so answering
     * 304 from it would tell the client its copy is current when it is not;
     * serve the full (stale) body instead and let the next request revalidate. */
    if (!stale
        && bh->status == NGX_HTTP_OK
        && (r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))
        && ngx_http_cache_turbo_not_modified(r, etag, etag_len,
                                             lastmod, lastmod_len))
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: conditional HIT -> 304");

        r->headers_out.status = NGX_HTTP_NOT_MODIFIED;
        r->headers_out.status_line.len = 0;
        r->headers_out.content_length_n = -1;
        r->headers_out.content_type.len = 0;
        r->headers_out.content_type.data = NULL;
        r->header_only = 1;        /* serve() short-circuits the body below */
        body_len = 0;
    }

    /* AUD-RANGE1: tell core's range filter this response may be range-served.
     * Upstream sets r->allow_ranges on every MISS (ngx_http_upstream.c), so a
     * client asking for the same URL twice got 206 on MISS and 200 on HIT/STALE
     * — a correctness regression, not just a missed optimisation (a client that
     * requested a partial fetch by Range and got the whole body back can
     * misinterpret it as the slice it asked for). Restrict to the plain 200
     * serve with a known length: not the 304 branch just above (no body to
     * range over), and not other cached statuses (redirects etc. never carry
     * Range semantics). ngx_http_range_header_filter re-checks the request's
     * own Range header and r->headers_out.status itself, so this only *permits*
     * ranged replies; it does not force one. */
    if (r->headers_out.status == NGX_HTTP_OK
        && r->headers_out.content_length_n >= 0)
    {
        r->allow_ranges = 1;
    }

    /* Date header (RFC 9111 §5.6.7, §4.2.3 — RFC-3): emit a STABLE Date for the
     * cached representation instead of letting core stamp the current time on
     * every hit. Core's header filter generates its own Date line only when
     * r->headers_out.date == NULL, so pushing a Date into the list AND pointing
     * headers_out.date at it makes ours authoritative (exactly one Date line).
     * Without this a cached response looks freshly generated each hit and its
     * Date drifts ahead of the Age we report. We replay the blob's creation
     * timestamp; Age = now - created below is then exactly consistent with it.
     * NOTE: created is our store time, not the upstream's original Date (which
     * is stripped at store and has no blob field yet); true origin-Date
     * preservation rides the deferred RFC-2 blob-format bump. */
    {
        u_char           *db;
        ngx_table_elt_t  *dh;

        db = ngx_http_cache_turbo_restore_alloc_fails(r) ? NULL
             : ngx_pnalloc(r->pool,
                           sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1);
        if (db == NULL) {
            return NGX_ERROR;
        }
        dh = ngx_http_cache_turbo_restore_alloc_fails(r)
                 ? NULL : ngx_list_push(&r->headers_out.headers);
        if (dh == NULL) {
            return NGX_ERROR;
        }

        {
            static u_char  date_name[] = "Date";
            dh->hash = 1;
            dh->key.len = sizeof("Date") - 1;
            dh->key.data = date_name;
            dh->value.len = (size_t) (ngx_http_time(db,
                                (time_t) bh->created) - db);
            dh->value.data = db;
#if (nginx_version >= 1023000)
            dh->next = NULL;
#endif
            r->headers_out.date = dh;
        }
    }

    /* Age header (RFC 9111 §5.1): seconds since this representation was stored
     * at the origin. created is the blob's own timestamp (survives the L2
     * round-trip), so Age is correct whether served from L1 or after an L2
     * fill. Clamp negative (writer/reader clock skew) to 0. */
    {
        time_t   age = ngx_time() - (time_t) bh->created;
        u_char  *ab;

        if (age < 0) {
            age = 0;
        }
        ab = ngx_http_cache_turbo_restore_alloc_fails(r)
                 ? NULL : ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
        if (ab == NULL) {
            return NGX_ERROR;
        }
        {
            static u_char  age_name[] = "Age";
            size_t         al = (size_t) (ngx_sprintf(ab, "%T", age) - ab);

            if (ngx_http_cache_turbo_add_header(r, age_name,
                    sizeof("Age") - 1, ab, al) != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

    /* X-Cache debug header. The caller chooses the value (HIT / STALE for a live
     * serve, STALE-IF-ERROR for the RFC-2 serve-on-error replacement). Always
     * emitted; the Age above is too (RFC 9111). To suppress it on the wire,
     * clear it downstream with the standard nginx header tooling. */
    {
        ngx_http_cache_turbo_ctx_t  *sctx;
        static u_char  xc_name[] = "X-Cache";
        if (ngx_http_cache_turbo_add_header(r, xc_name,
                sizeof("X-Cache") - 1, (u_char *) xcache,
                ngx_strlen(xcache)) != NGX_OK)
        {
            return NGX_ERROR;
        }

        /* Record the served outcome for $cache_turbo_status. Match the reason
         * EXACTLY rather than switching on xcache[0]: O4.3 made this parameter
         * caller-supplied ("STALE-BREAKER"), so a first-byte test silently
         * turns every future reason beginning with 'H' into a fresh HIT. Any
         * non-HIT reason -- "STALE", "STALE-IF-ERROR", "STALE-BREAKER" -- folds
         * to STALE, which is what $upstream_cache_status compatibility wants. */
        sctx = ngx_http_get_module_ctx(r, ngx_http_cache_turbo_module);
        if (sctx != NULL) {
            sctx->status = (ngx_strcmp(xcache, "HIT") == 0)
                ? NGX_HTTP_CACHE_TURBO_ST_HIT
                : NGX_HTTP_CACHE_TURBO_ST_STALE;

            /* S7.2: unfolded reason for $cache_turbo_serve_reason. Same
             * exact-match discipline as the fold above -- never switch on
             * xcache[0]. FRESH is the S7.2 spec's name for what `status`
             * calls HIT; the other three values pass through as-is. */
            if (ngx_strcmp(xcache, "HIT") == 0) {
                sctx->serve_reason = NGX_HTTP_CACHE_TURBO_SR_FRESH;

            } else if (ngx_strcmp(xcache, "STALE") == 0) {
                sctx->serve_reason = NGX_HTTP_CACHE_TURBO_SR_STALE;

            } else if (ngx_strcmp(xcache, "STALE-IF-ERROR") == 0) {
                sctx->serve_reason = NGX_HTTP_CACHE_TURBO_SR_STALE_IF_ERROR;

            } else if (ngx_strcmp(xcache, "STALE-BREAKER") == 0) {
                sctx->serve_reason = NGX_HTTP_CACHE_TURBO_SR_STALE_BREAKER;
            }
        }
    }

    *bodyp = body;
    *body_lenp = body_len;
    return NGX_OK;
}


/*
 * Send a fully validated cache blob as the response: rebuild r->headers_out
 * from it (ngx_http_cache_turbo_restore_response), then send the header and the
 * body and finalize. Used for every live HIT / STALE serve from the access
 * handler. The RFC-2 serve-on-error path does NOT use this — it reuses only the
 * restore step from the header filter (a send_header + finalize here would
 * double-finalize the in-flight upstream-error request); see the header filter.
 *
 * PERF-7: when ref_data is non-NULL, `copy` is the blob still living in the shm
 * slab (zero-copy serve); the caller has already taken a reference under the zone
 * mutex (ngx_http_cache_turbo_blob_acquire) and we register a pool cleanup to
 * drop it after the response drains. When ref_data is NULL, `copy` is a private
 * r->pool buffer (an L2 blob or a copied snapshot) and no reference is held.
 */
static ngx_int_t
ngx_http_cache_turbo_serve(ngx_http_request_t *r, u_char *copy, size_t len,
    ngx_uint_t stale, ngx_http_cache_turbo_zone_t *z, u_char *ref_data,
    const char *xcache)
{
    u_char                           *body;
    size_t                            body_len;
    ngx_int_t                         rc;
    ngx_buf_t                        *b;
    ngx_chain_t                       out;
    ngx_http_cache_turbo_ctx_t       *ctx;
    ngx_pool_cleanup_t               *cln;
    ngx_http_cache_turbo_blob_cln_t  *cc;

    /* PERF-7: arm the reference drop FIRST, before any early return below, so the
     * acquired ref is released exactly once on every exit path (the cleanup fires
     * at request-pool destroy, after the output chain has drained). If the
     * cleanup cannot be registered we must drop the ref now or the detached blob
     * would leak forever. */
    if (ref_data != NULL) {
        cln = ngx_pool_cleanup_add(r->pool,
                  sizeof(ngx_http_cache_turbo_blob_cln_t));
        if (cln == NULL) {
            ngx_http_cache_turbo_blob_release(z, ref_data);
            return NGX_ERROR;
        }
        cln->handler = ngx_http_cache_turbo_blob_cleanup;
        cc = cln->data;
        cc->z = z;
        cc->data = ref_data;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_cache_turbo_module);
    if (ctx) {
        ctx->served = 1;           /* stop our filters re-capturing */
    }

    /* P6/O4.3: `xcache` lets a caller name the serve reason (the breaker's
     * STALE-BREAKER). NULL keeps the original HIT/STALE choice, which is what
     * every pre-O4.3 call site passes.
     *
     * The $cache_turbo_status mapping in restore_response() compares the
     * reason EXACTLY against "HIT", so any override is safe -- including one
     * that starts with 'H'. An earlier revision folded on the first byte, which
     * would have logged such a value as a fresh HIT. */
    if (ngx_http_cache_turbo_restore_response(r, copy, len, stale,
            xcache != NULL ? xcache : (stale ? "STALE" : "HIT"),
            &body, &body_len) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* A header filter may return a STATUS CODE rather than NGX_OK/NGX_ERROR,
     * and that is not an error: ngx_http_range_header_filter answers an
     * unsatisfiable Range with NGX_HTTP_RANGE_NOT_SATISFIABLE (416), which it
     * expects the caller to finalize into a real 416 response. Collapsing every
     * non-NGX_OK into NGX_ERROR turned that into ngx_http_finalize_request(-1)
     * -- the connection was closed with NO response at all, while the SAME
     * request against a MISS got a well-formed answer from upstream. Mirrors
     * the core contract at ngx_http_upstream.c: `rc == NGX_ERROR || rc >
     * NGX_OK` finalizes with rc. `rc > NGX_OK` is the status-code case (NGX_OK
     * is 0 and every HTTP status is positive); NGX_AGAIN/NGX_DONE are negative
     * and fall through to the body send, as they do for a normal serve. */
    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK) {
        ngx_http_finalize_request(r, rc);
        return NGX_DONE;
    }

    /* HEAD / conditional-304: header already sent, no body expected — done. */
    if (r->header_only) {
        ngx_http_finalize_request(r, NGX_OK);
        return NGX_DONE;
    }

    /* For a GET we must still push a terminating last_buf through the output
     * filter, even when the body is empty (a cached 301/302/308/204, v6): just
     * finalizing without a last buffer leaves the response chain unterminated
     * and the client hangs. An empty memory buffer with last_buf set is the
     * standard end-of-response signal. */
    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->pos = body;
    b->last = body + body_len;
    b->memory = (body_len > 0) ? 1 : 0;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;
    if (body_len == 0) {
        b->sync = 1;                 /* zero-size control buffer */
    }

    out.buf = b;
    out.next = NULL;

    rc = ngx_http_output_filter(r, &out);

    /* Finalize and return NGX_DONE so the ACCESS phase engine stops here and
     * does NOT fall through to the location's content handler (proxy_pass).
     * Returning the output-filter's NGX_OK would let nginx continue to the
     * upstream, hitting the origin on every cache HIT. */
    ngx_http_finalize_request(r, rc);
    return NGX_DONE;
}


/*
 * RFC 9111 shared-cache safety floor: decide whether THIS response may be stored
 * and replayed to other clients. Refuses when
 *   - the request carried Authorization (the response is per-user), or
 *   - the response sets a cookie (Set-Cookie => per-client state), or
 *   - Cache-Control forbids shared/any caching
 *     (private / no-store / no-cache / max-age=0 / s-maxage=0).
 * Without this the module would store an authenticated 200 under its URL key and
 * serve it to everyone — a cache-poisoning / data-leak hole. Cheap: one walk of
 * the (small) response header list, only on the store path.
 */
static ngx_int_t
ngx_http_cache_turbo_response_cacheable(ngx_http_request_t *r)
{
    ngx_list_part_t                  *part;
    ngx_table_elt_t                  *h;
    ngx_uint_t                        i;
    ngx_http_cache_turbo_loc_conf_t  *clcf;

    if (r->headers_in.authorization != NULL) {
        return 0;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);

    part = &r->headers_out.headers.part;
    h = part->elts;
    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (h[i].hash == 0 || h[i].key.len == 0) {
            continue;
        }

        /*
         * The Set-Cookie floor. Unconditional on purpose — NOT gated by
         * ignore_cc, because relaxing it does more than staple one visitor's
         * session cookie into a shared body.
         *
         * PRESET KEY COOKIES DEPEND ON THIS. A request that carries no key
         * cookie (Magento's X-Magento-Vary) hashes to the ANONYMOUS entry, and
         * the response that FIRST establishes the segment arrives with exactly
         * one distinguishing mark: a Set-Cookie. Store it and the anonymous
         * entry now serves segmented content to every anonymous visitor —
         * upstream Magento's own VCL refuses the identical case
         * (vcl_backend_response: beresp.uncacheable). Anyone adding a knob that
         * caches Set-Cookie responses must add a preset-level veto in the header
         * filter FIRST (request had no key cookie && response sets one => do not
         * capture), or reintroduce a cross-user leak.
         */
        if (h[i].key.len == sizeof("Set-Cookie") - 1
            && ngx_strncasecmp(h[i].key.data, (u_char *) "Set-Cookie",
                               sizeof("Set-Cookie") - 1) == 0)
        {
            return 0;
        }

        /* Cache-Control plus the RFC 9213 targeted variants (CDN-Cache-Control,
         * Surrogate-Control): all three carry the same no-store/private/max-age=0
         * grammar, so a targeted directive must veto the shared store the same way
         * plain Cache-Control does — otherwise an origin that says
         * "CDN-Cache-Control: no-store" (edge must not cache) would still be
         * stored by us. Gated by honor_cc (via ignore_cc): if the operator ignores
         * Cache-Control, we ignore the targeted variants too. Surrogate-Control
         * has no "private" token (Fastly uses "no-store"/"private" loosely, so we
         * still honour both). */
        if (!clcf->ignore_cc
            && ((h[i].key.len == sizeof("Cache-Control") - 1
                 && ngx_strncasecmp(h[i].key.data, (u_char *) "Cache-Control",
                                    sizeof("Cache-Control") - 1) == 0)
                || (h[i].key.len == sizeof("CDN-Cache-Control") - 1
                    && ngx_strncasecmp(h[i].key.data,
                                       (u_char *) "CDN-Cache-Control",
                                       sizeof("CDN-Cache-Control") - 1) == 0)
                || (h[i].key.len == sizeof("Surrogate-Control") - 1
                    && ngx_strncasecmp(h[i].key.data,
                                       (u_char *) "Surrogate-Control",
                                       sizeof("Surrogate-Control") - 1) == 0)))
        {
            u_char  *v = h[i].value.data;
            u_char  *e = v + h[i].value.len;

            /* Full-token match (not substring): no-store / no-cache / private
             * forbid shared storage; max-age=0 / s-maxage=0 mean already-stale,
             * not cacheable. cc_delta returns 0 only for an exact "=0" value, so
             * "max-age=01000" no longer trips this (it is a 1000s freshness). */
            if (ngx_http_cache_turbo_cc_has(v, e, "no-store",
                    sizeof("no-store") - 1)
                || ngx_http_cache_turbo_cc_has(v, e, "no-cache",
                    sizeof("no-cache") - 1)
                || ngx_http_cache_turbo_cc_has(v, e, "private",
                    sizeof("private") - 1)
                || ngx_http_cache_turbo_cc_delta(v, e, "max-age",
                    sizeof("max-age") - 1) == 0
                || ngx_http_cache_turbo_cc_delta(v, e, "s-maxage",
                    sizeof("s-maxage") - 1) == 0)
            {
                return 0;
            }
        }
    }

    return 1;
}


/*
 * Headers that must NOT be captured into the cache blob. Hop-by-hop (RFC 9110
 * §7.6.1) plus headers serve() / nginx's own header filter regenerate:
 * Content-Length is re-derived from the stored body, Date/Server are re-emitted
 * by the header filter, so replaying any of these would duplicate or conflict
 * (e.g. two Content-Length lines, or chunked framing against a fixed length).
 * Set-Cookie is dropped defensively too, though response_cacheable already
 * refuses to store a Set-Cookie response at all. Age and the X-Cache* status
 * headers are dropped so that when a NATIVE nginx cache (proxy_cache / fastcgi_
 * cache) sits behind us, we don't freeze and replay its per-response age/status
 * on every L1 hit (see "Mixing with nginx's native cache" in the README).
 *
 * Content-Encoding is dropped because we are the TOP-most output filter: our
 * body filter captures the IDENTITY body, BEFORE gzip/zstd/brotli compress it,
 * but the compression filter's header filter runs downstream of ours and has
 * already stamped Content-Encoding on r->headers_out by the time we serialise
 * the headers at store. Storing that coding against an uncompressed body would
 * replay e.g. "Content-Encoding: gzip" with a plain body (browser "Content
 * Encoding Error"). Dropping it lets the downstream compression filter re-add
 * the correct coding per client on every MISS and HIT (the proxy_cache model).
 * A genuinely origin-pre-compressed response is refused earlier by the
 * response_encoded() guard (its Content-Encoding is set BEFORE our header
 * filter runs), so it never reaches this serialiser.
 */
static ngx_int_t
ngx_http_cache_turbo_header_skip(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *name, size_t nlen)
{
    static const ngx_str_t  skip[] = {
        ngx_string("Connection"), ngx_string("Keep-Alive"),
        ngx_string("Proxy-Authenticate"), ngx_string("Proxy-Authorization"),
        ngx_string("TE"), ngx_string("Trailer"),
        ngx_string("Transfer-Encoding"), ngx_string("Upgrade"),
        ngx_string("Content-Length"), ngx_string("Content-Encoding"),
        ngx_string("Set-Cookie"), ngx_string("Date"), ngx_string("Server"),
        ngx_string("Age"), ngx_string("X-Cache"), ngx_string("X-Cache-Status"),
        /* RFC 9213 targeted cache directives: we (the shared cache / edge) are
         * their intended consumer, so strip them before store — replaying them
         * downstream would wrongly steer the browser or a next cache tier with a
         * TTL meant for us. Same rationale as the Age strip above. */
        ngx_string("CDN-Cache-Control"), ngx_string("Surrogate-Control"),
        ngx_null_string
    };
    ngx_uint_t  i;

    /* SK-A1: Surrogate-Key describes the representation, so it must travel WITH
     * it. A CDN POP whose copy expired refills from OUR hit; if that hit carries
     * no key the edge object is untagged and a later tag purge misses it.
     *
     * When cache_turbo_surrogate_key is ON we generate the header live on both
     * MISS and HIT from the same cache_turbo_tag expression, so storing the
     * miss-time copy would only duplicate it -> skip at store.
     * When the directive is OFF the header is purely origin-supplied metadata
     * about this response: store and replay it like any other header. */
    if (clcf->surrogate_key
        && nlen == sizeof("Surrogate-Key") - 1
        && ngx_strncasecmp(name, (u_char *) "Surrogate-Key", nlen) == 0)
    {
        return 1;
    }

    for (i = 0; skip[i].len != 0; i++) {
        if (nlen == skip[i].len
            && ngx_strncasecmp(name, skip[i].data, skip[i].len) == 0)
        {
            return 1;
        }
    }

    /* The configured store opt-in header (cache_turbo_require_header) is for
     * this cache to read, exactly like the RFC 9213 targeted directives above:
     * strip it so a HIT never replays the origin's internal store signal. */
    if (clcf->require_header.len == nlen
        && nlen != 0
        && ngx_strncasecmp(name, clcf->require_header.data, nlen) == 0)
    {
        return 1;
    }

    return 0;
}


/*
 * AUD-HDR1: the ONE gate both cache directions ask "may this header cross?".
 * Returns 1 to let the pair through, 0 to drop it.
 *
 * Why one helper rather than a check on each side: header_skip() above used to
 * be called only on the STORE path. The RESTORE path re-materialised whatever
 * bytes were in the blob and handed them straight to add_header() ->
 * ngx_list_push(), which validates nothing, after which nginx serialises
 * "name: value\r\n" verbatim. That asymmetry is only invisible while the L2 is
 * trusted: a writer who reaches Redis directly (compromised, or MITM'd — see
 * AUD-TLS1) never runs the store path, so every store-side check was optional
 * from the attacker's point of view. Concretely that bought
 *
 *   - CR/LF in a value            -> response splitting
 *   - Transfer-Encoding, or a 2nd Content-Length beside the one restore sets
 *                                 -> request smuggling vs a downstream proxy/CDN
 *   - Set-Cookie                  -> session fixation (it is on the skip list
 *                                    precisely because it is dangerous)
 *
 * Routing BOTH directions through this function is what stops them drifting
 * again; ci/fuzz/fuzz_blob.c asserts they have not (it fails the build's
 * fixture suite if a restored header would bypass header_skip()).
 *
 * The name test is RFC 9110 §5.6.2 tchar, i.e. what can legally be serialised
 * as a field name at all. The value test is CR/LF/NUL only: HTAB and the rest
 * of the printable range are legal field-content, and rejecting more would drop
 * legitimate origin headers on a HIT that were served fine on the MISS.
 */
static ngx_int_t
ngx_http_cache_turbo_header_admissible(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *name, size_t nlen, u_char *val, size_t vlen)
{
    size_t  i;

    if (nlen == 0) {
        return 0;
    }

    for (i = 0; i < nlen; i++) {
        u_char  c = name[i];

        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9'))
        {
            continue;
        }
        switch (c) {
        case '!': case '#': case '$': case '%': case '&': case '\'':
        case '*': case '+': case '-': case '.': case '^': case '_':
        case '`': case '|': case '~':
            continue;
        default:
            return 0;                      /* not a token: unserialisable */
        }
    }

    for (i = 0; i < vlen; i++) {
        if (val[i] == CR || val[i] == LF || val[i] == '\0') {
            return 0;                      /* header injection primitive */
        }
    }

    if (ngx_http_cache_turbo_header_skip(clcf, name, nlen)) {
        return 0;
    }

    return 1;
}


/*
 * RFC-2 stale-if-error serve-on-error, header half. The origin revalidation of an
 * EXPIRED entry returned a 5xx (or nginx synthesised a 502/504 for a transport
 * failure) and a within-SIE snapshot is armed: REPLACE the error response with
 * the stale snapshot. We cannot call ngx_http_cache_turbo_serve() here — it runs
 * ngx_http_send_header + ngx_http_finalize_request, and on the upstream-error
 * path we are already inside ngx_http_special_response_handler; a second
 * finalize is a double-finalize / use-after-free. Instead we rewrite
 * r->headers_out in place and let the filter chain carry the response: drop the
 * error's header list + typed Content-Type/Length, then replay the snapshot via
 * the shared restore step (X-Cache: STALE-IF-ERROR), stashing the body slice for
 * the body filter. Returns NGX_OK on a successful rewrite and NGX_ERROR on any
 * allocation failure: once list reconstruction starts, falling through would
 * emit a partially rebuilt response.
 */
static ngx_int_t
ngx_http_cache_turbo_sie_rewrite(ngx_http_request_t *r,
    ngx_http_cache_turbo_ctx_t *ctx)
{
    u_char  *body;
    size_t   body_len;

    /* Drop the error response's headers and the typed fields it set (Content-Type
     * / Content-Length) so the snapshot's own headers are authoritative. The
     * special-response path has already cleared ETag/Last-Modified/Accept-Ranges,
     * so a fresh list + these two typed fields is a clean slate; restore_response
     * sets status / Content-Type / Content-Length / status_line from the blob. */
    if (ngx_list_init(&r->headers_out.headers, r->pool, 8,
                      sizeof(ngx_table_elt_t)) != NGX_OK)
    {
        return NGX_ERROR;
    }
    r->headers_out.content_type.len = 0;
    r->headers_out.content_type.data = NULL;
    r->headers_out.content_type_len = 0;
    r->headers_out.content_length_n = -1;
    r->headers_out.content_length = NULL;
    r->headers_out.status_line.len = 0;

    /* stale = 1: never answer 304 from a serve-on-error copy (it has not been
     * revalidated), and the X-Cache value flags the replacement. */
    if (ngx_http_cache_turbo_restore_response(r, ctx->sie_snap,
            ctx->sie_snap_len, 1, "STALE-IF-ERROR", &body, &body_len) != NGX_OK)
    {
        return NGX_ERROR;
    }

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    /* O4.4-i: RE-STAMP the arming counter header.
     *
     * The ngx_list_init() above wipes headers_out.headers, and the header
     * filter has ALREADY stamped X-Cache-Turbo-Test-Armings by the time this
     * runs -- so without this the client sees the snapshot's stored value
     * (whatever the counter read at store time, normally 0) on every
     * STALE-IF-ERROR response, while the live zone counter has moved. That is
     * not a cosmetic loss: it silently disarms the O4.4-i L2 control, whose
     * `breaker off` fixture is served exactly this way. Measured: the header
     * filter logged l2=3/l2=4 for the two /brkil2off/ requests while the
     * client received l1=0,l2=0.
     *
     * Failure is deliberately ignored -- a test-only header must never turn a
     * successful serve-on-error into a 500. A MISSING header is a hard failure
     * in the test's own oracle (_armings), so a silent drop cannot read as
     * "armed 0". */
    (void) ngx_http_cache_turbo_test_armings_header(r);
#endif

    ctx->sie_body = body;
    ctx->sie_body_len = body_len;
    return NGX_OK;
}


/* S4.2: does `status` trigger a stale serve under the configured use_stale mask?
 *
 * The mask is the operator's `cache_turbo_use_stale` set (S4.1); the default
 * (USE_STALE_DEFAULT) reproduces the pre-S4.2 hardcoded "every 5xx" condition
 * byte-for-byte via the four named 5xx bits plus ANY_5XX.
 *
 * ERROR/TIMEOUT are folded onto 502/504 here, NOT honoured as distinct
 * conditions: this site sees only r->headers_out.status, so a refused
 * connection and a genuine upstream 502 are the same value by the time we run
 * (see the USE_STALE_* comment block in the header for why the bits stay
 * separate anyway). Do not "fix" this into a distinction without first giving
 * the trigger access to upstream provenance.
 */
static ngx_uint_t
ngx_http_cache_turbo_use_stale_triggers(ngx_uint_t mask, ngx_uint_t status)
{
    ngx_uint_t  bit;

    switch (status) {
    case NGX_HTTP_FORBIDDEN:
        bit = NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_403;
        break;
    case NGX_HTTP_NOT_FOUND:
        bit = NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_404;
        break;
    case 429:
        bit = NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_429;
        break;
    case NGX_HTTP_INTERNAL_SERVER_ERROR:
        bit = NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_500;
        break;
    case NGX_HTTP_BAD_GATEWAY:
        bit = NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_502
              | NGX_HTTP_CACHE_TURBO_USE_STALE_ERROR;
        break;
    case NGX_HTTP_SERVICE_UNAVAILABLE:
        bit = NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_503;
        break;
    case NGX_HTTP_GATEWAY_TIME_OUT:
        bit = NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_504
              | NGX_HTTP_CACHE_TURBO_USE_STALE_TIMEOUT;
        break;
    default:
        /* Every other 5xx (506, 507, 508, 510, 511, ...) is covered only by
         * ANY_5XX, which the default sets and no config token can set alone. */
        bit = (status >= NGX_HTTP_INTERNAL_SERVER_ERROR && status <= 599)
              ? NGX_HTTP_CACHE_TURBO_USE_STALE_ANY_5XX
              : 0;
        break;
    }

    return (mask & bit) != 0;
}


/* P6/O4.2: does `status` mean "the origin is down" for circuit-breaker
 * purposes?
 *
 * ⚠ Deliberately NOT ngx_http_cache_turbo_use_stale_triggers(). The two
 * questions look alike and are not: use_stale answers "may I serve a stale
 * copy instead of this response?", and its mask may legitimately name 403,
 * 404 and 429 -- every one of which is a perfectly HEALTHY origin answering
 * correctly. Feeding those into the breaker would let a 404-heavy site trip
 * its own breaker and start 503-ing everything while the origin was fine: an
 * outage caused by enabling an unrelated stale-serving option. So the breaker
 * has its own, narrower test.
 *
 * 5xx-only, all of them, matching what "origin is down" means at this site.
 * As at the use_stale trigger, a refused connection and a genuine upstream 502
 * are indistinguishable here -- the header filter sees r->headers_out.status
 * and nothing else -- so transport failures arrive as 502/504 and are counted
 * by the same test. */
/* UNIT-EXTRACT breaker-failure BEGIN */
static ngx_uint_t
ngx_http_cache_turbo_breaker_is_origin_failure(ngx_uint_t status)
{
    return status >= NGX_HTTP_INTERNAL_SERVER_ERROR && status <= 599;
}


/* P6/O4.2: may this response feed the breaker at all?
 *
 * Factored out of the header filter so the unit suite can drive the REAL
 * admission rule instead of restating it -- a test that re-implements its
 * subject passes whatever the subject does (that is how O4.1's herd bug got
 * certified by its own test). The header filter passes the four facts it has;
 * every argument here is a genuine reason to refuse.
 *
 *   served       -- OUR cache serve. Replaying our own body says nothing about
 *                   the origin, and feeding it back would read a dead origin
 *                   as healthy for as long as the cache kept serving.
 *   from_origin  -- the response really came off the wire. TWO conditions, and
 *                   both are needed:
 *
 *                   r->upstream != NULL, because !served does NOT mean the
 *                   origin was contacted -- an only-if-cached miss is answered
 *                   504 locally (module.c:4422, :5002) with no upstream at
 *                   all, and counting those lets a client trip a healthy
 *                   breaker with a request header.
 *
 *                   !r->cached, because r->upstream being non-NULL only means
 *                   the upstream subsystem was initialised, NOT that it spoke
 *                   to anyone. When cache-turbo is stacked in front of
 *                   proxy_cache / fastcgi_cache (a documented setup, see the
 *                   README), ngx_http_upstream_cache_send() sets r->cached = 1
 *                   and serves from nginx's OWN disk cache with r->upstream
 *                   already allocated. Those responses are somebody else's
 *                   cache hits: counting them lets nginx's disk cache clear a
 *                   real failure run, or close a HALF_OPEN breaker without any
 *                   probe ever reaching the origin -- the breaker would go
 *                   blind for exactly as long as the disk cache kept serving.
 *   is_main      -- subrequests other than our own warm fetch have their own
 *                   lifecycle and are not the origin conversation we track.
 *   threshold    -- the breaker's off-switch. _breaker_record()'s success path
 *                   returns before the threshold check and writes
 *                   breaker_fails = 0 regardless, so "off" is only free if the
 *                   call is skipped here.
 */
static ngx_uint_t
ngx_http_cache_turbo_breaker_should_record(ngx_uint_t served,
    ngx_uint_t from_origin, ngx_uint_t is_main, ngx_uint_t threshold)
{
    return !served && from_origin && is_main && threshold > 0;
}


/* Did this response actually come off the wire? Split out so the two
 * conditions are testable together rather than assembled inline at the call
 * site: an inline expression is invisible to the unit slice, so reversing or
 * dropping half of it would leave every test green.
 *
 * `upstream` is r->upstream != NULL, `native_cached` is r->cached (always 0
 * where NGX_HTTP_CACHE is off, hence no #if here -- the caller resolves that).
 * See the argument notes on _breaker_should_record() for why both are needed.
 */
static ngx_uint_t
ngx_http_cache_turbo_breaker_from_origin(ngx_uint_t upstream,
    ngx_uint_t native_cached)
{
    return upstream && !native_cached;
}
/* P6/O4.3-O4.4: may the pre-origin gate (or the outcome-recording site)
 * consult/feed the breaker for this request?
 *
 * Factored out for the same reason _breaker_should_record() was: the unit suite
 * must drive the REAL admission rule rather than restate it. Restated rules
 * pass whatever the subject does, which is precisely how O4.1's herd bug got
 * certified green by its own test.
 *
 * Full predicate, O4.4: clcf->enable && clcf->breaker_enable &&
 * breaker_threshold > 0 && breaker_window > 0. Three independent off-switches
 * on top of the module's own enable flag -- cache_turbo_breaker off,
 * cache_turbo_breaker_threshold 0, or cache_turbo_breaker_window 0 -- any one
 * of which must make this false. breaker_window matters here even though the
 * pre-origin gate itself never reads it: a threshold with no window is a
 * meaningless "trip after N failures ever", and admitting that config to the
 * state machine would let a handful of failures over the server's entire
 * uptime eventually trip a breaker nobody configured a trip window for.
 *
 * ⚠ None of these fields are tuning knobs once false is reached here --
 * together they are the off-switch, and skipping the call matters beyond
 * saving an shm read: _breaker_state() is NOT a pure getter -- it performs
 * the due OPEN -> HALF_OPEN promotion. Consulting it while the breaker is
 * disabled would drive a state machine that nothing is feeding outcomes into
 * (the O4.2 recording site is gated on this same predicate), so a zone could
 * be promoted to probe with no probe ever reporting back.
 *
 * Takes clcf directly rather than individual fields: every call site already
 * has clcf in scope, and a struct pointer can't drift out of sync with a
 * field the way four positional scalar arguments could. */
static ngx_uint_t
ngx_http_cache_turbo_breaker_should_consult(
    ngx_http_cache_turbo_loc_conf_t *clcf)
{
    return clcf->enable && clcf->breaker_enable
           && clcf->breaker_threshold > 0
           && clcf->breaker_window > 0;
}


/* P6/O4.3: turn a breaker state into the serve-path verdict.
 *
 * Returns one of the BRK_ACT_* actions below. Split from the handler so the
 * three-way mapping is testable without an nginx request: the handler keeps
 * only the mechanics (which body to send, which counter to bump).
 *
 * ⚠ HALF_OPEN maps to PASS, and that is load-bearing rather than a fallback for
 * "not OPEN". A HALF_OPEN verdict is only ever returned to the single request
 * that WON the promotion CAS, and that promotion is a lease which only
 * _breaker_record() releases. Mapping it to SERVE (or to a 503) would answer
 * that request from cache, so nothing would ever reach the origin, no outcome
 * would ever be recorded, and the breaker would sit OPEN until the lease
 * expired -- re-promoting one doomed probe per window, forever. The probe MUST
 * go to the origin.
 *
 * ⚠ has_body is the ONLY input that separates SERVE from FAIL, deliberately
 * without any age test. Past the stale window, past stale-if-error, past
 * keep_stale -- the breaker's whole premise is that once the origin is known
 * down, a body of any age beats a 503, and the operator opted into that by
 * enabling the breaker. Adding a freshness condition here would silently turn
 * the feature back into stale-if-error.
 */
static ngx_uint_t
ngx_http_cache_turbo_breaker_action(ngx_uint_t state, ngx_uint_t has_body)
{
    /* ⚠ O4.3-c: HALF_OPEN is returned ONLY to the request that won the
     * promotion, and it is terminal -- that request owes the breaker an origin
     * outcome, so it must reach the origin directly rather than falling through
     * into the single-flight machinery, which can park it and answer it from
     * cache on resume. See BRK_ACT_PROBE. */
    if (state == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN) {
        return NGX_HTTP_CACHE_TURBO_BRK_ACT_PROBE;
    }

    if (state != NGX_HTTP_CACHE_TURBO_BREAKER_OPEN) {
        return NGX_HTTP_CACHE_TURBO_BRK_ACT_PASS;
    }

    return has_body ? NGX_HTTP_CACHE_TURBO_BRK_ACT_SERVE
                    : NGX_HTTP_CACHE_TURBO_BRK_ACT_FAIL;
}
/* UNIT-EXTRACT breaker-failure END */


static ngx_int_t
ngx_http_cache_turbo_header_filter(ngx_http_request_t *r)
{
    ngx_http_cache_turbo_ctx_t       *ctx;
    ngx_http_cache_turbo_loc_conf_t  *clcf;
    ngx_int_t                         rc;

    ctx = ngx_http_get_module_ctx(r, ngx_http_cache_turbo_module);

    if (ctx == NULL || ctx->served) {
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
        /* O4.4-i: report the zone's arming count on cache-serve responses too.
         * Stamped BEFORE this early-return because a request that armed from L1
         * is frequently the one that then serves the snapshot, and the test must
         * be able to read the counter off any response it makes. */
        if (ctx != NULL) {
            (void) ngx_http_cache_turbo_test_armings_header(r);
        }
#endif
        return ngx_http_next_header_filter(r);
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    (void) ngx_http_cache_turbo_test_armings_header(r);
#endif

    /* P6/O4.2: feed this origin outcome into the per-zone circuit breaker.
     *
     * Placement matters in three ways:
     *
     * 1. AFTER the ctx->served early-return above, so only responses that
     *    really came from the origin are recorded. A cache serve never reaches
     *    here, and must not -- a breaker fed by its own cache hits would read a
     *    dead origin as healthy for as long as the cache kept serving.
     * 2. BEFORE the stale-if-error rewrite below, which overwrites
     *    r->headers_out.status with the snapshot's 200. Recorded after it, the
     *    origin's 502 would be counted as a success and the breaker could never
     *    trip on exactly the outage it exists to handle.
     * 3. OUTSIDE the `ctx->sie_armed` guard the SIE trigger sits behind. A cold
     *    URL with no armed snapshot is precisely the case where the breaker
     *    matters most, and those failures must count even though nothing
     *    stale-serves them.
     *
     * O4.4: gated on breaker_should_consult() rather than the bare
     * clcf->enable this used before the breaker had its own directives.
     * threshold/window at their 0 defaults (or breaker_enable off, or the
     * module itself disabled) make _breaker_record() inert (it returns before
     * touching any window state), so this predicate simply makes that "no
     * config can trip it" state explicit and skips the shm read entirely
     * rather than paying it every response. Successes are recorded just as
     * broadly as failures -- a breaker that only ever hears about failures
     * can never close again.
     *
     * ⚠ NOT recorded at the autotune_record_cost() site the plan first named.
     * That call lives inside the store block, behind ~10 cacheability gates
     * (enable, not-HEAD, status_ttl >= 0, response_cacheable, require_hdr_ok,
     * not-encoded, no_store predicates, ...). A healthy origin serving an
     * uncacheable 200 would never record a success there, so a breaker tripped
     * by a transient outage could never close. Success recording has to be at
     * least as broad as failure recording, which is why both live here.
     *
     * ⚠ r->upstream is the load-bearing part of this condition, not decoration.
     * !ctx->served proves we are not replaying a cached body; it does NOT prove
     * the origin was ever contacted. This module generates 5xx locally: a
     * request carrying `Cache-Control: only-if-cached` that finds nothing
     * serveable is answered NGX_HTTP_GATEWAY_TIME_OUT straight from the access
     * handler (module.c:4422 and :5002), with ctx allocated and ctx->served
     * unset, having spoken to no upstream at all. Counting those would let a
     * client trip a HEALTHY zone's breaker on demand simply by repeating a
     * request header -- a remote denial of service against the origin's own
     * traffic. Only a response with an upstream behind it carries information
     * about whether the origin is up.
     *
     * ⚠ The threshold/window off-switch is now enforced entirely by
     * should_consult(clcf) above -- should_record()'s own `threshold` argument
     * is a legacy positional parameter kept for the unit slice, not a second
     * independent gate. The reason this call must still be SKIPPED outright
     * (rather than trusting _breaker_record() to be inert when off) is that
     * _breaker_record() only checks the off-switch on its FAILURE path
     * (shm.c:1297); the success path returns earlier at :1266 having already
     * written breaker_fails = 0. Calling it unconditionally would therefore
     * put a shared-memory write on every successful response even with the
     * breaker disabled -- not the no-op this step is supposed to be.
     * Skipping the call outright keeps "breaker off" genuinely free. */
    if (ngx_http_cache_turbo_breaker_should_consult(clcf)
        && clcf->shm_zone != NULL
        && ngx_http_cache_turbo_breaker_should_record(
               0,                      /* ctx->served: excluded above already */
               ngx_http_cache_turbo_breaker_from_origin(
                   r->upstream != NULL,
#if (NGX_HTTP_CACHE)
                   r->cached),
#else
                   0),
#endif
               r == r->main || ctx->warm,
               clcf->breaker_threshold))
    {
        /* ⚠ ctx->brk_probe is the lease token, non-zero only when THIS request
         * won the promotion. Passing it is what stops an unrelated origin
         * response -- one that started before the trip, or one this module
         * served from a peer's L2 fill -- from closing a HALF_OPEN breaker no
         * probe actually tested. Non-probe requests pass 0 (NO_PROBE) and can
         * still count failures toward a CLOSED breaker's threshold, which is
         * the one thing they legitimately observe. */
        ngx_http_cache_turbo_zone_t  *bz = clcf->shm_zone->data;
        ngx_uint_t  is_failure = ngx_http_cache_turbo_breaker_is_origin_failure(
                                      r->headers_out.status);

        /* S7.1: count the origin request as a failure right where the
         * breaker itself is fed that verdict, so this counter and the
         * breaker's own fail/window accounting can never disagree about what
         * counts as a failure. Bumped before the record() call (not after)
         * only as a matter of local ordering -- record() cannot fail and
         * there is no early-return between the two, so the order is not
         * load-bearing. */
        if (is_failure) {
            (void) ngx_atomic_fetch_add(&bz->sh->origin_failures, 1);
        }

        ngx_http_cache_turbo_shm_breaker_record(
            clcf->shm_zone->data,
            !is_failure,
            clcf->breaker_threshold,
            clcf->breaker_window,
            ctx->brk_probe);
    }

    /* RFC-2 stale-if-error: an armed serve-on-error snapshot + a status the
     * configured `cache_turbo_use_stale` set names means replace the error with
     * the stale copy. Do this BEFORE the capture gate so the (replaced) error is
     * never captured, and clear any cold-miss stub we own so waiters do not
     * block on a key we will not store. */
    if (ctx->sie_armed && !ctx->sie_serving
        && ngx_http_cache_turbo_use_stale_triggers(clcf->use_stale,
                                                   r->headers_out.status))
    {
        rc = ngx_http_cache_turbo_sie_rewrite(r, ctx);
        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }
        if (rc == NGX_OK) {
            ctx->served = 1;      /* block capture of the replaced error */
            ctx->sie_serving = 1; /* body filter emits the snapshot body */

            /* S7.1: this IS the SIE serve -- sie_rewrite() returning NGX_OK
             * means the error response was actually replaced with the stale
             * snapshot and will be delivered. Bumped here rather than inside
             * sie_rewrite() itself so the counter lives beside sie_serving,
             * the other "this response is now the SIE snapshot" flag. */
            if (clcf->shm_zone != NULL) {
                ngx_http_cache_turbo_zone_t  *sz = clcf->shm_zone->data;
                (void) ngx_atomic_fetch_add(&sz->sh->sie_serves, 1);
            }

            if (ctx->cold_winner && !ctx->cold_stored
                && ctx->cold_zone != NULL)
            {
                uint32_t  h = ngx_crc32_short(ctx->key_hash, 32);
                ngx_http_cache_turbo_shm_unstub(ctx->cold_zone,
                                                ctx->key_hash, h,
                                                ctx->cold_owner);
                ctx->cold_stored = 1;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: STALE-IF-ERROR serve \"%V\" len=%uz",
                           &r->uri, ctx->sie_body_len);
            return ngx_http_next_header_filter(r);
        }
    }

    /* auto-Vary (v11 other half): classify the response Vary header once. bits =
     * the safe-axis bitmask the body filter folds into the variant key + marker;
     * vary_nocache vetoes caching when the response varies on something the
     * whitelist refuses (*, Cookie, Authorization). Done before the capture gate
     * so vary_nocache can suppress capture (and the cold-stub clear below fires). */
    if (clcf->auto_vary) {
        ngx_uint_t  nocache = 0;
        ngx_http_cache_turbo_classify_vary(r, &ctx->vary_bits, &nocache);
        ctx->vary_nocache = nocache ? 1 : 0;
    }

    /* Only capture cacheable responses. 200 always, plus any status named by a
     * cache_turbo_valid <code> rule (redirects / negative caching, v6). Never a
     * HEAD — its empty body must not overwrite the GET entry. Normally the main
     * request only; a warm subrequest (ctx->warm) is the deliberate exception. */
    if (clcf->enable && (r == r->main || ctx->warm)
        && !(r->method & NGX_HTTP_HEAD)
        && !ctx->vary_nocache
        && !ctx->min_uses_skip
        && !ctx->auto_skip
        && !ctx->req_no_store
        && ngx_http_cache_turbo_status_ttl(clcf, r->headers_out.status) >= 0
        && ngx_http_cache_turbo_response_cacheable(r)
        && ngx_http_cache_turbo_require_hdr_ok(r, clcf)
        && !ngx_http_cache_turbo_response_encoded(r)
        && (clcf->no_store == NULL
            || ngx_http_test_predicates(r, clcf->no_store) == NGX_OK))
    {
        /* A warm subrequest is deliberately excluded from lookup, so its key
         * was never built. Build it here from the subrequest URI before flagging
         * capture, so the body filter stores under the same key a later real
         * request will look up. */
        if (ctx->warm
            && ngx_http_cache_turbo_build_key(r, clcf, ctx) != NGX_OK)
        {
            return ngx_http_next_header_filter(r);
        }
        ctx->captured = 1;

        /* cache_turbo_surrogate_key: this response is a MISS being stored, so
         * emit the tag list downstream as a Surrogate-Key header for a fronting
         * CDN NOW, while headers are still mutable (the body-filter store runs
         * after headers are sent). Capture-path only -- a HIT returns earlier via
         * ctx->served and never re-emits. */
        if (clcf->surrogate_key) {
            ngx_http_cache_turbo_emit_surrogate_key(r, clcf);
        }
    }

    /* Cold-miss single-flight (v10): if we are the winner but this response is
     * NOT cacheable, the body filter will never store, so clear our in-flight
     * stub now rather than make waiters block on it until lock_ttl. The pool
     * cleanup is the backstop for the remaining non-store paths. */
    if (ctx->cold_winner && !ctx->cold_stored && !ctx->captured
        && ctx->cold_zone != NULL)
    {
        uint32_t  hash = ngx_crc32_short(ctx->key_hash, 32);
        ngx_http_cache_turbo_shm_unstub(ctx->cold_zone, ctx->key_hash, hash,
                                        ctx->cold_owner);
        ctx->cold_stored = 1;
    }

    return ngx_http_next_header_filter(r);
}


/* Downstream forward for the body filter. For a normal (main or SIE) request
 * this is the real next body filter. For a background WARM subrequest it
 * SWALLOWS the chain instead: a warm sr has no client, and forwarding its body
 * into the postpone/write chain accrues r->buffered on the shared main
 * connection. ngx_http_finalize_request then parks the subrequest on
 * ngx_http_writer (the `r != r->main && r->buffered` branch) instead of taking
 * the r->background count-drop, so the warm sr's r->main->count++ is never
 * balanced. If the worker enters graceful exit while parked, the parent
 * stale-serve client connection can never close -> "open socket left in
 * connection" at shutdown (proven via gdb core dump, s84). The body is already
 * captured into ctx->body above; nothing downstream needs it. Consuming the
 * buffers (pos=last, mark consumed) lets the upstream see the output as fully
 * written so the sr finalizes with r->buffered == 0. */
static ngx_int_t
ngx_http_cache_turbo_forward_body(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_chain_t                 *cl;
    ngx_http_cache_turbo_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_cache_turbo_module);

    if (ctx == NULL || !ctx->warm) {
        return ngx_http_next_body_filter(r, in);
    }

    for (cl = in; cl; cl = cl->next) {
        cl->buf->pos = cl->buf->last;
        cl->buf->file_pos = cl->buf->file_last;
        cl->buf->sync = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_cache_turbo_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    uint32_t                          hash;
    u_char                           *p;
    size_t                            n;
    ngx_buf_t                        *b;
    ngx_chain_t                      *cl, **ll;
    ngx_http_cache_turbo_ctx_t       *ctx;
    ngx_http_cache_turbo_zone_t      *z;
    ngx_http_cache_turbo_loc_conf_t  *clcf;
    ngx_uint_t                        last = 0;

    ctx = ngx_http_get_module_ctx(r, ngx_http_cache_turbo_module);

    /* RFC-2 stale-if-error, body half. The header filter replaced an origin error
     * with the stale snapshot; discard the upstream error body and emit the
     * snapshot body ONCE with last_buf. Checked before the served/captured gate
     * (the header filter set ctx->served to stop capture). sie_body_sent swallows
     * any trailing error buffers the upstream still streams after the last_buf.
     * The discarded upstream chain (`in`) is marked consumed (pos=last, buffers
     * released back to the upstream) on both exits below: with proxy_buffering
     * off, nothing else ever advances those buffers, so skipping this leaves
     * them stuck on the upstream's busy_bufs forever and the request hangs. */
    if (ctx != NULL && ctx->sie_serving) {
        ngx_buf_t    *eb;
        ngx_chain_t   eout;

        if (ctx->sie_body_sent) {
            for (cl = in; cl; cl = cl->next) {
                cl->buf->pos = cl->buf->last;
                cl->buf->file_pos = cl->buf->file_last;
                cl->buf->sync = 1;
            }
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
            /* AUD-SIE-BODY: observe the chain AFTER the consume loop above --
             * this is the postcondition the fix is supposed to establish
             * (every buffer in `in` fully consumed), not a pre-count of how
             * much data arrived. With the fix present the loop always leaves
             * pos == last, so this is always 0; reverting ONLY the consume
             * loop (this counter/log stays) leaves the buffers exactly as the
             * upstream delivered them, so this counts them > 0. Logged (not a
             * response header): by the time this block runs,
             * ngx_http_next_header_filter() has already returned for this
             * request -- nginx's header filter chain serializes
             * r->headers_out.headers into the wire buffer synchronously and
             * has no postponement contract, so a header added here would be
             * invisible to the client and would always read 0 (verified). The
             * greppable "cache_turbo: test_sie_unconsumed=" token is the
             * oracle the runtime test reads out of logs/error.log instead. */
            for (cl = in; cl; cl = cl->next) {
                if (cl->buf->pos != cl->buf->last) {
                    ctx->test_sie_unconsumed++;
                }
            }
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                          "cache_turbo: test_sie_unconsumed=%ui",
                          ctx->test_sie_unconsumed);
#endif
            return NGX_OK;
        }
        ctx->sie_body_sent = 1;

        eb = ngx_calloc_buf(r->pool);
        if (eb == NULL) {
            return NGX_ERROR;
        }
        eb->pos = ctx->sie_body;
        eb->last = ctx->sie_body + ctx->sie_body_len;
        eb->memory = (ctx->sie_body_len > 0) ? 1 : 0;
        eb->last_buf = (r == r->main) ? 1 : 0;
        eb->last_in_chain = 1;
        if (ctx->sie_body_len == 0) {
            eb->sync = 1;
        }

        for (cl = in; cl; cl = cl->next) {
            cl->buf->pos = cl->buf->last;
            cl->buf->file_pos = cl->buf->file_last;
            cl->buf->sync = 1;
        }

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
        /* AUD-SIE-BODY: same observe-AFTER-consume ordering and logged oracle
         * as the sie_body_sent exit above, for the main snapshot-emitting exit. */
        for (cl = in; cl; cl = cl->next) {
            if (cl->buf->pos != cl->buf->last) {
                ctx->test_sie_unconsumed++;
            }
        }
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                      "cache_turbo: test_sie_unconsumed=%ui",
                      ctx->test_sie_unconsumed);
#endif

        eout.buf = eb;
        eout.next = NULL;
        return ngx_http_next_body_filter(r, &eout);
    }

    if (ctx == NULL || !ctx->captured || ctx->served) {
        return ngx_http_cache_turbo_forward_body(r, in);
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    /* CI-only: deterministically drive the file-backed delegate path. The real
     * trigger (an in_file && !in_memory buffer) is fs/directio dependent and
     * cannot be produced reliably in the harness. Take the SAME abort-capture +
     * delegate-unmodified-chain action here, without forging b->in_file (which
     * would make downstream sendfile garbage). */
    if (clcf->test_force_file_buf) {
        ctx->captured = 0;
        ctx->body = NULL;
        ctx->body_last = NULL;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: test_force_file_buf \"%V\" -> delegate to "
                       "native (capture abandoned)", &r->uri);
        return ngx_http_cache_turbo_forward_body(r, in);
    }
#endif

    /* Append the incoming buffers to our captured chain (copying the bytes
     * into the request pool so they survive past this filter call). Seed the
     * append cursor from the cached tail so a multi-call streamed body does not
     * re-walk the whole chain every filter invocation (was O(n²)). */
    ll = ctx->body_last ? &ctx->body_last->next : &ctx->body;

    for (cl = in; cl; cl = cl->next) {
        ngx_buf_t    *nb;
        ngx_chain_t  *ncl;

        b = cl->buf;

        /* Only in-memory bytes are capturable. A file-backed buffer (sendfile
         * path) carries no valid b->pos for its declared ngx_buf_size(), so
         * copying from b->pos would read out of bounds. Abort capture and
         * delegate the whole response downstream rather than store garbage. */
        if (b->in_file && !ngx_buf_in_memory(b)
            && b->file_last > b->file_pos)
        {
            ctx->captured = 0;
            ctx->body = NULL;
            ctx->body_last = NULL;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: file-backed body \"%V\" -> delegate to "
                           "native (cannot capture from memory)", &r->uri);
            return ngx_http_cache_turbo_forward_body(r, in);
        }

        n = ngx_buf_in_memory(b) ? (size_t) (b->last - b->pos) : 0;

        if (n > 0) {
            /* Q2: oversize early-abort, BEFORE the alloc+memcpy. Once the body
             * would cross max_size we will never store this response (the store
             * gate below refuses it), so a single huge buffer must not be fully
             * copied into the request pool just to be discarded at last_buf.
             * Drop the partial capture, mark the request non-capturing, and
             * forward downstream untouched. A stacked native proxy_cache (README
             * pattern B) keeps the object on disk; cache-turbo delegates oversize
             * media with ~zero shm/pool overhead. Any cold-miss stub is cleared
             * by the pool-cleanup backstop at request end. */
            if (clcf->max_size > 0 && ctx->body_len + n > clcf->max_size) {
                ctx->captured = 0;
                ctx->body = NULL;
                ctx->body_last = NULL;
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: oversize capture aborted \"%V\" "
                               "body>%uz -> delegate to native",
                               &r->uri, clcf->max_size);
                return ngx_http_cache_turbo_forward_body(r, in);
            }

            p = ngx_pnalloc(r->pool, n);
            if (p == NULL) {
                return NGX_ERROR;
            }
            ngx_memcpy(p, b->pos, n);

            nb = ngx_calloc_buf(r->pool);
            if (nb == NULL) {
                return NGX_ERROR;
            }
            nb->pos = p;
            nb->last = p + n;
            nb->memory = 1;

            ncl = ngx_alloc_chain_link(r->pool);
            if (ncl == NULL) {
                return NGX_ERROR;
            }
            ncl->buf = nb;
            ncl->next = NULL;

            *ll = ncl;
            ll = &ncl->next;
            ctx->body_last = ncl;

            ctx->body_len += n;
        }

        if (b->last_buf || b->last_in_chain) {
            last = 1;
        }
    }

    /* Store once the response is complete and within max_size. A zero-length
     * body is allowed (v6): a 301/302/308 redirect or a 204 has no body but is
     * worth caching for its headers. (HEAD is already excluded at capture.) */
    if (last
        && (clcf->max_size == 0 || ctx->body_len <= clcf->max_size))
    {
        ngx_list_part_t                  *part;
        ngx_table_elt_t                  *h;
        ngx_str_t                         ct;
        size_t                            hdr_bytes = 0, blob_len = 0;
        uint32_t                          nheaders = 0;
        u_char                           *blob, *w;
        ngx_uint_t                        i;
        time_t                            ttl, stale_window, sie_window = 0;
        time_t                            retain_ttl;

        ttl = ngx_http_cache_turbo_status_ttl(clcf, r->headers_out.status);
        if (ttl < 0) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: not cacheable \"%V\" status=%ui",
                           &r->uri, r->headers_out.status);
            return ngx_http_cache_turbo_forward_body(r, in);   /* not cacheable */
        }

        /* O6/S3.1: a negative-cached error (e.g. "cache_turbo_valid 503 1m")
         * must never overwrite a body that is still worth serving. The guard
         * itself lives at the store site below (search "refusing to overwrite
         * cached body"), which is the single source of truth for the predicate
         * and why it looks the way it does -- including why the blob's sie_ttl
         * is deliberately NOT consulted. Do not restate the predicate here; an
         * earlier copy of it in this comment went stale the moment the
         * implementation changed. */
        /* Honor upstream freshness (v7): let the response's own
         * Cache-Control/Expires set the fresh TTL when enabled. ignore_cc wins:
         * if the operator told us to ignore Cache-Control, the TTL is the static
         * cache_turbo_valid, never the (ignored) upstream max-age/Expires. */
        if (clcf->honor_cc && !clcf->ignore_cc) {
            time_t  up = ngx_http_cache_turbo_upstream_ttl(r);
            if (up >= 0) {
                ttl = up;
            }
        }

        /* STAB-5: clamp the fresh TTL to the uint32 ceiling before it feeds the
         * blob fresh_ttl cast, the stale-window multiply, and the L2 PX. An
         * unbounded upstream max-age (honor_cc) is the realistic source. */
        if (ttl > NGX_HTTP_CACHE_TURBO_TTL_MAX) {
            ttl = NGX_HTTP_CACHE_TURBO_TTL_MAX;
        }

        /* Absolute serveable window (fresh + stale) from now, reused by the blob
         * metadata, the L1 store, and the L2 EXPIRE so all three agree. */
        stale_window = ngx_http_cache_turbo_stale_ttl(ttl, clcf->stale_mult);

        /* RFC 5861 / RFC-2: a response stale-while-revalidate=N sets the stale
         * window explicitly (fresh + N), overriding the cache_turbo_stale_mult
         * default. The existing SWR machinery (background_update) then serves
         * stale + refreshes within it. must-revalidate below still wins (it
         * collapses the window). Only meaningful for a finite TTL.
         *
         * ignore_cc skips ALL three response-Cache-Control window adjustments
         * (swr here, must-revalidate + stale-if-error below): the operator told
         * us to ignore the upstream Cache-Control, so an upstream max-age=0 /
         * must-revalidate / stale-while|if-* must NOT reshape the window built
         * from cache_turbo_valid + cache_turbo_stale_mult. Matches the
         * proxy_ignore_headers Cache-Control contract (the whole header is
         * inert), not just the cacheability floor. */
        if (ttl > 0 && !clcf->ignore_cc) {
            time_t  swr = ngx_http_cache_turbo_response_swr(r);
            if (swr >= 0) {
                /* AUD-CC-DELTA-OVF: swr is parsed straight off the wire and can
                 * be up to NGX_MAX_INT_T_VALUE (e.g. stale-while-revalidate=
                 * 9223372036854775807) -- clamp the delta BEFORE the add, not
                 * the sum after, or ttl + swr overflows signed time_t (UB). */
                stale_window = ngx_http_cache_turbo_add_ttl_clamped(ttl, swr);
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: stale-while-revalidate=%T \"%V\"",
                               swr, &r->uri);
            }
        }

        /* RFC 9111 must-revalidate / proxy-revalidate: once stale, the response
         * must NOT be served without revalidation. We have no validation channel
         * for a hit, so collapse the stale window to the fresh TTL — the object
         * is served fresh until its deadline, then re-fetched (no stale serve,
         * no stale-if-error). Only meaningful for a finite TTL. Skipped under
         * ignore_cc (see the swr block above — the whole upstream Cache-Control
         * is inert, so an upstream must-revalidate must not collapse the
         * operator-configured stale window). */
        if (ttl > 0 && !clcf->ignore_cc
            && ngx_http_cache_turbo_response_must_revalidate(r))
        {
            stale_window = ttl;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: must-revalidate \"%V\" -> no stale window",
                           &r->uri);

        } else if (ttl > 0 && !clcf->ignore_cc) {
            /* RFC 5861 §4 / RFC-2: a response stale-if-error=N records an absolute
             * serve-on-error window (fresh + N) in the blob's sie_ttl (CTB4), so a
             * later origin failure may serve this copy PAST the normal stale
             * window. 0 = absent => no serve-on-error beyond the stale window.
             * Gated behind !must-revalidate above (must-revalidate forbids any
             * stale serve, stale-if-error included). The serve-on-error path that
             * consumes sie_ttl lands in a follow-up; the field is carried now so
             * the wire format turns over once (single cold-cache event). */
            time_t  sie = ngx_http_cache_turbo_response_sie(r);
            if (sie >= 0) {
                /* AUD-CC-DELTA-OVF: same wire-controlled overflow as the swr
                 * clamp above -- clamp the delta before the add. */
                sie_window = ngx_http_cache_turbo_add_ttl_clamped(ttl, sie);
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: stale-if-error=%T \"%V\"",
                               sie, &r->uri);

            } else if (ttl > 0 && clcf->keep_stale > 0) {
                /* S2.2 / D-1: no response stale-if-error to honor here, so fall
                 * back to the operator's cache_turbo_keep_stale baseline (fresh +
                 * keep_stale). This branch only runs when a response SIE was
                 * absent -- a HONORED response stale-if-error above already took
                 * this window and we must NOT also apply keep_stale on top of it
                 * (that would be max(), which the plan explicitly rejects: an
                 * origin that states its own error window is making a statement,
                 * not setting a floor). Still gated behind the outer
                 * !must-revalidate branch above, so a honored must-revalidate
                 * still collapses the window to `ttl` and suppresses keep_stale
                 * too -- must-revalidate forbids ANY stale serve. */
                sie_window = ttl + clcf->keep_stale;
                if (sie_window > NGX_HTTP_CACHE_TURBO_TTL_MAX) {
                    sie_window = NGX_HTTP_CACHE_TURBO_TTL_MAX;
                }
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: keep_stale=%T \"%V\"",
                               clcf->keep_stale, &r->uri);
            }

        } else if (ttl > 0 && clcf->ignore_cc && clcf->keep_stale > 0) {
            /* D-1: under ignore_cc the response-derived swr/must-revalidate/sie
             * branches above never run (the whole upstream Cache-Control is
             * inert), so this location's stale window is untouched by the
             * response and sie_window is still 0 here. keep_stale is OPERATOR
             * config, not upstream config -- ignore_cc only makes the upstream
             * header inert, it does not disable operator-configured retention.
             * Apply the keep_stale baseline unconditionally in this case (no
             * response SIE to compare against, and no honored must-revalidate
             * to suppress it -- must-revalidate is itself response-derived and
             * therefore inert under ignore_cc). */
            sie_window = ttl + clcf->keep_stale;
            if (sie_window > NGX_HTTP_CACHE_TURBO_TTL_MAX) {
                sie_window = NGX_HTTP_CACHE_TURBO_TTL_MAX;
            }
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: keep_stale=%T (ignore_cc) \"%V\"",
                           clcf->keep_stale, &r->uri);
        }

        /* Synthesise a Content-Type entry from the typed field (it is not in
         * the headers list). Everything else comes from headers_out.headers. */
        ct = r->headers_out.content_type;

        /* First pass: measure the header block. */
        if (ct.len) {
            hdr_bytes += sizeof(uint32_t) + sizeof("Content-Type") - 1
                         + sizeof(uint32_t) + ct.len;
            nheaders++;
        }

        part = &r->headers_out.headers.part;
        h = part->elts;
        for (i = 0; /* void */ ; i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }
                part = part->next;
                h = part->elts;
                i = 0;
            }
            /* AUD-HDR1: the same gate the restore path uses. This loop and the
             * emit loop below MUST make identical decisions or headers_len
             * would lie about the block that follows — one helper, called
             * twice, is what guarantees that. */
            if (h[i].hash == 0
                || !ngx_http_cache_turbo_header_admissible(clcf,
                        h[i].key.data, h[i].key.len,
                        h[i].value.data, h[i].value.len))
            {
                continue;
            }
            hdr_bytes += sizeof(uint32_t) + h[i].key.len
                         + sizeof(uint32_t) + h[i].value.len;
            nheaders++;
        }

        /* STAB-5: headers_len and body_len are uint32 in the blob header. Refuse
         * to store (rather than write a header that lies about the layout) if a
         * pathological response would truncate either. body_len is already
         * bounded by max_size on the capture path; this also covers a max_size
         * configured above 4 GiB and an unbounded header block. Reuse the
         * blob==NULL skip below (same as an alloc failure: silently don't cache). */
        if (hdr_bytes > 0xFFFFFFFFUL || ctx->body_len > 0xFFFFFFFFUL) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "cache_turbo: \"%V\" not cached: header/body block "
                          "exceeds the 4 GiB blob field limit", &r->uri);
            blob = NULL;
        } else {
            blob_len = NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE
                       + hdr_bytes + ctx->body_len;
            blob = ngx_pnalloc(r->pool, blob_len);
        }

        if (blob != NULL) {
            ngx_http_cache_turbo_blob_hdr_t  bhw;
            u_char                           store_key[32];

            /* STAB-4: serialise the header into the fixed 44-byte LE wire form. */
            bhw.nheaders = nheaders;
            bhw.headers_len = (uint32_t) hdr_bytes;
            bhw.body_len = (uint32_t) ctx->body_len;
            bhw.status = (uint32_t) r->headers_out.status;
            /* Freshness metadata so an L2 hit restores the remaining lifetime
             * (not the location default). stale_ttl is the absolute serveable
             * window from creation (fresh + stale), matching shm_store. */
            bhw.created = (int64_t) ngx_time();
            bhw.fresh_ttl = (uint32_t) (ttl > 0 ? ttl : 0);
            bhw.stale_ttl = (uint32_t) stale_window;
            bhw.sie_ttl = (uint32_t) sie_window;   /* CTB4 (RFC-2 SIE) */
            ngx_http_cache_turbo_blob_hdr_write(blob, &bhw);

            /* The L2 retention window, used for the object key AND for every L2
             * index that points at it (variant index, tag index). stale_window
             * already carries any stale-while-revalidate widening; sie_window is
             * the RFC-2 stale-if-error deadline and can extend past it entirely.
             * Both are absolute windows off the same base ttl and are already
             * clamped to TTL_MAX, so max() needs no further bounding.
             *
             * The indexes MUST NOT outlive-mismatch the object: if an index
             * expired at the stale window while the object survived into the
             * SIE-only interval, a tag or base purge in that interval could no
             * longer find the object and would leave it undeletable in L2. */
            retain_ttl = stale_window;
            if (sie_window > retain_ttl) {
                retain_ttl = sie_window;
            }

            w = blob + NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE;

            /* write a single name/value pair (lengths fixed-endian, STAB-4) */
            #define CT_PUT(np, nl, vp, vl)                                     \
                do {                                                          \
                    ngx_http_cache_turbo_put_u32(w, (uint32_t) (nl)); w += 4; \
                    ngx_memcpy(w, (np), (nl)); w += (nl);                     \
                    ngx_http_cache_turbo_put_u32(w, (uint32_t) (vl)); w += 4; \
                    ngx_memcpy(w, (vp), (vl)); w += (vl);                     \
                } while (0)

            if (ct.len) {
                CT_PUT("Content-Type", sizeof("Content-Type") - 1,
                       ct.data, ct.len);
            }

            part = &r->headers_out.headers.part;
            h = part->elts;
            for (i = 0; /* void */ ; i++) {
                if (i >= part->nelts) {
                    if (part->next == NULL) {
                        break;
                    }
                    part = part->next;
                    h = part->elts;
                    i = 0;
                }
                if (h[i].hash == 0
                    || !ngx_http_cache_turbo_header_admissible(clcf,
                            h[i].key.data, h[i].key.len,
                            h[i].value.data, h[i].value.len))
                {
                    continue;
                }
                CT_PUT(h[i].key.data, h[i].key.len,
                       h[i].value.data, h[i].value.len);
            }
            #undef CT_PUT

            /* append body */
            for (cl = ctx->body; cl; cl = cl->next) {
                size_t bn = ngx_buf_size(cl->buf);
                ngx_memcpy(w, cl->buf->pos, bn);
                w += bn;
            }

            z = clcf->shm_zone->data;

            /* auto-Vary (v11 other half): when the response varies on a safe
             * axis, store the object under the SECONDARY variant key (folding the
             * named request headers) instead of the base key, so distinct
             * representations never collide. store_key == key_hash otherwise (no
             * auto_vary, no/whitelist-only Vary, or key_hash was already the
             * variant via the request-time marker). */
            ngx_memcpy(store_key, ctx->key_hash, 32);
            if (clcf->auto_vary && ctx->vary_bits > 0) {
                ngx_http_cache_turbo_variant_hash(r, &ctx->cache_key,
                                                  ctx->vary_bits, ctx->vary_gen,
                                                  store_key);
            }
            hash = ngx_crc32_short(store_key, 32);

            /* O6/S3.1: a negative-cached error (e.g. "cache_turbo_valid 503 1m")
             * must never overwrite a body that is still worth serving -- that is
             * the exact inverse of outage resilience.
             *
             * AUD-5XX-CTA: this used to be a separate check-then-act -- lock,
             * lookup, decide `protect`, unlock, THEN store re-locked later.
             * Reachable under cache_turbo_bypass (skips lookup AND
             * single-flight, still permits storing), another worker could
             * change the node in the gap between the two critical sections.
             * Folded into a single store_if() call below: the predicate
             * (search "refusing to overwrite cached body") and the write now
             * share ONE lock hold, via
             * NGX_HTTP_CACHE_TURBO_STORE_IF_ABSENT_OR_DEAD, which is exactly
             * the old `protect` predicate --
             *   kind == ENTRY && ctn->len > 0 && (stale_until == 0
             *                                     || now < stale_until)
             * -- moved inside shm_store_if(). stale_until == 0 means FOREVER,
             * not expired.
             *
             * ⚠ D-4 ("does this also cover a body alive ONLY via
             * cache_turbo_keep_stale, i.e. past stale_until?") is YES, and it is
             * ALREADY SATISFIED UPSTREAM -- deliberately NOT by a second branch
             * on the blob's sie_ttl here. A keep-stale-only body arms an SIE
             * snapshot at access time (see the `sie_ttl > 0 && now < created +
             * sie_ttl` arming test in the access handler), and the header filter
             * then rewrites the origin's 5xx into that snapshot and sets
             * ctx->served = 1 BEFORE the capture gate -- so the 5xx never
             * reaches this body filter at all and there is nothing here to
             * guard. An earlier revision of this guard did test
             * `now < created + sie_ttl` as a fallback arm; it was UNREACHABLE
             * (identical predicate to the arming test, evaluated on the same
             * fields) and was removed rather than shipped as dead weight. The
             * only way past the arming test is its ngx_pnalloc() for the
             * snapshot failing under memory pressure -- not worth a branch.
             * Do not "restore" the sie_ttl arm without first writing a test
             * that reaches it.
             *
             * ⚠ store_if() MUST probe the key this store will actually write,
             * and `store_key` only diverges from ctx->key_hash above (auto-Vary
             * variant relocation). Probing ctx->key_hash instead would check
             * the BASE key while the store overwrites the VARIANT --
             * protecting on an unrelated body and still clobbering the variant
             * this guard exists to save. store_if() is called with store_key,
             * below, preserving that property. */

            /* If we relocated the key away from the base (cold-miss winner that
             * only learned the Vary now), the cold-miss stub the access handler
             * left under the base key would never be overwritten by this store →
             * clear it so waiters on the base key stop blocking. unstub only drops
             * a still-stub node, so a real base entry (if any) is untouched. */
            if (ctx->cold_winner && !ctx->cold_stored
                && ngx_memcmp(store_key, ctx->key_hash, 32) != 0)
            {
                ngx_http_cache_turbo_shm_unstub(z, ctx->key_hash,
                                   ngx_crc32_short(ctx->key_hash, 32),
                                   ctx->cold_owner);
            }

            {
            ngx_int_t  store_rc;
            ngx_uint_t is_5xx = (r->headers_out.status
                                  >= NGX_HTTP_INTERNAL_SERVER_ERROR);

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
            /* AUD-STORE-ERR-STUB: deterministically simulate a failed store
             * without depending on real slab exhaustion timing.
             *
             * The store is SKIPPED, not called-then-overridden. Masking the
             * return value of a store that actually succeeded is not the same
             * fault: the entry lands in L1 anyway, the next request is a plain
             * L1 HIT, and no cold-miss stub is ever orphaned -- so the test
             * built on it passed identically with and without the fix. The
             * defect under test is "no entry was written, so the stub must be
             * cleaned up", which requires no entry to be written. */
            if (clcf->test_store_fail) {
                store_rc = NGX_ERROR;

            } else if (is_5xx) {
                store_rc = clcf->l1->store_if(z, store_key, hash,
                           blob, blob_len, ttl, stale_window,
                           NGX_HTTP_CACHE_TURBO_STORE_IF_ABSENT_OR_DEAD);

            } else {
                store_rc = clcf->l1->store(z, store_key, hash,
                           blob, blob_len, ttl,
                           stale_window);
            }
#else
            if (is_5xx) {
                store_rc = clcf->l1->store_if(z, store_key, hash,
                           blob, blob_len, ttl, stale_window,
                           NGX_HTTP_CACHE_TURBO_STORE_IF_ABSENT_OR_DEAD);

            } else {
                store_rc = clcf->l1->store(z, store_key, hash,
                           blob, blob_len, ttl,
                           stale_window);
            }
#endif

            /* AUD-5XX-CTA: NGX_DECLINED means store_if() refused the write
             * because a still-servable good body is resident under
             * store_key -- equivalent to the old `protect` branch. Return
             * BEFORE touching ctx->cold_stored, same as before: nothing was
             * written, so the cold-miss stub cleanup (AUD-STORE-ERR-STUB,
             * just below) must still run. */
            if (store_rc == NGX_DECLINED) {
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: refusing to overwrite cached "
                               "body \"%V\" with error status=%ui",
                               &r->uri, r->headers_out.status);
                return ngx_http_cache_turbo_forward_body(r, in);
            }

            if (store_rc == NGX_OK) {
                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: stored \"%V\" len=%uz ttl=%T",
                               &r->uri, blob_len, ttl);

                /* v10: store overwrote any cold-miss stub into a real entry (or
                 * we cleared the relocated base stub above), so the cleanup
                 * must not remove it. */
                ctx->cold_stored = 1;

            } else {
                /* AUD-STORE-ERR-STUB: a failed store leaves whatever was under
                 * store_key untouched -- no real entry was written, so the
                 * cold-miss stub (if any) still needs the pool cleanup to run
                 * and unstub it. Leaving ctx->cold_stored at 0 here is what
                 * arms that cleanup; setting it unconditionally (the bug) told
                 * the cleanup a real entry existed and left the stub to block
                 * every waiter until lock_ttl. */
                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: store failed \"%V\" len=%uz "
                               "ttl=%T", &r->uri, blob_len, ttl);
            }
            }

            /* auto-Vary: persist the active-axis bitmask as an L1 marker under
             * the base key so the next request resolves straight to this variant
             * (node-local; self-heals if evicted). */
            if (clcf->auto_vary && ctx->vary_bits > 0) {
                ngx_http_cache_turbo_marker_store(clcf, z, &ctx->cache_key,
                                                  ctx->vary_bits, ctx->vary_gen,
                                                  ttl);

                /* COR-5 variant index: SADD this variant's L2 key into the
                 * per-base index set so a later PURGE of the base URI can
                 * enumerate + drop every variant from L1+L2. Redis only
                 * (memcached has no sets => tag_add NULL; its variants are
                 * invalidated by the L1-only generation bump + TTL instead). */
                if (clcf->backend && clcf->backend->tag_add) {
                    u_char  vname[1 + 64];
                    size_t  vlen;

                    vlen = ngx_http_cache_turbo_variant_index_name(
                               &ctx->cache_key, vname);
                    clcf->backend->tag_add(clcf, store_key, vname, vlen,
                                           retain_ttl);
                }
            }

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: STORE \"%V\" key=%ui len=%uz ttl=%T",
                           &r->uri, (ngx_uint_t) hash, blob_len, ttl);

            /* Record this origin regeneration's cost for the autotune (v4-3).
             * This store site is the origin→cache path only (the L2→L1 fill in
             * the access handler is a separate store call), so request_time here
             * is real origin latency — exactly the miss-cost the autotune feeds
             * on. Recorded unconditionally so the admin cost_ms is meaningful and
             * autotune has history the moment it is enabled; just two atomics. */
            {
                ngx_time_t      *tp = ngx_timeofday();
                ngx_msec_int_t   ms;

                ms = (ngx_msec_int_t)
                     ((tp->sec - r->start_sec) * 1000
                      + (tp->msec - r->start_msec));
                ngx_http_cache_turbo_autotune_record_cost(z, ms);
            }

            /* L2 write-through (async, fire-and-forget). Copies the blob into
             * its own pool, so it is safe even though `blob` lives in r->pool.
             * The caller owns the L2 key's retention window: retain_ttl (computed
             * above, shared with the L2 index writes) is max(stale_window,
             * sie_window). Passing stale_window alone here would silently
             * truncate the L2 key's PX/EXPIRE to the stale deadline, so an
             * SIE-armed object's L2 copy is already gone by the time an origin
             * failure needs it — the access handler's SIE-from-L2 path would
             * then always miss. */
            if (clcf->backend) {
                clcf->backend->set(r, clcf, store_key,
                                   blob, blob_len, ttl, retain_ttl);
            }

            /* Tag index (v2c): for each tag in the cache_turbo_tag expression,
             * SADD this object's L2 key to the tag set so it can be purged by
             * tag later. Tags live only in L2; skip when Redis is off. The
             * memcached backend has no tag support (tag_add == NULL, v13).
             *
             * cache_turbo_surrogate_key (emit the same tags downstream for a
             * fronting CDN) is handled separately in the HEADER filter -- headers
             * are already sent by the time this body-filter store runs, so the
             * emit MUST happen before next_header_filter, not here. */
            if (clcf->backend && clcf->backend->tag_add && clcf->tag) {
                ngx_str_t  tagval;

                if (ngx_http_complex_value(r, clcf->tag, &tagval) == NGX_OK
                    && tagval.len)
                {
                    u_char    *s, *e, *tok;
                    size_t     toklen;
                    ngx_uint_t ntags = 0, k;
                    /* PERF-2: the tag value is upstream-controlled (e.g. an
                     * X-Cache-Tags header), so without bounds a hostile/buggy
                     * origin could name thousands of tags and make ONE response
                     * fire thousands of SADD connections. Cap the count, cap
                     * each tag's length, and dedup so the same tag in one value
                     * is SADD'd once. */
                    ngx_str_t  seen[NGX_HTTP_CACHE_TURBO_MAX_TAGS];

                    s = tagval.data;
                    e = tagval.data + tagval.len;

                    while (s < e && ntags < NGX_HTTP_CACHE_TURBO_MAX_TAGS) {
                        while (s < e && (*s == ' ' || *s == '\t' || *s == ','
                                         || *s == '\r' || *s == '\n'))
                        {
                            s++;
                        }
                        tok = s;
                        while (s < e && *s != ' ' && *s != '\t' && *s != ','
                               && *s != '\r' && *s != '\n')
                        {
                            s++;
                        }
                        toklen = (size_t) (s - tok);
                        if (toklen == 0
                            || toklen > NGX_HTTP_CACHE_TURBO_MAX_TAG_LEN)
                        {
                            continue;          /* empty or over-long: skip */
                        }

                        for (k = 0; k < ntags; k++) {   /* dedup within value */
                            if (seen[k].len == toklen
                                && ngx_memcmp(seen[k].data, tok, toklen) == 0)
                            {
                                break;
                            }
                        }
                        if (k < ntags) {
                            continue;          /* already added this tag */
                        }

                        seen[ntags].data = tok;
                        seen[ntags].len = toklen;
                        ntags++;
                    }

                    /* L9: index the whole deduped set in ONE pipelined op
                     * (one pool, one connection, one round trip) rather than
                     * one op per tag -- a MAX_TAGS response fired up to 16.
                     * seen[] is already deduped and cap-bound by the loop
                     * above, which is exactly tag_add_many's contract. Fall
                     * back to per-tag calls on a backend that predates the
                     * batched slot. */
                    if (ntags > 0) {
                        if (clcf->backend->tag_add_many) {
                            clcf->backend->tag_add_many(clcf, store_key, seen,
                                                        ntags, retain_ttl);
                        } else {
                            for (k = 0; k < ntags; k++) {
                                clcf->backend->tag_add(clcf, store_key,
                                                       seen[k].data,
                                                       seen[k].len, retain_ttl);
                            }
                        }
                    }

                    /* The MAX_TAGS cap is a DoS bound (above), not a hint -- but
                     * hitting it SILENTLY is a correctness trap: the tags past the
                     * cap are never indexed, so a later purge of one of them does
                     * NOT invalidate this page and the operator sees stale content
                     * with no signal anywhere. Real origins hit this: a Magento
                     * category page emits one cat_p_<id> tag PER PRODUCT, so a
                     * 40-product page overflows a 16-tag cap and quietly stops
                     * being purgeable on the dropped tags.
                     *
                     * Warn, once per affected response, only when tags were
                     * actually dropped -- s < e means the tokeniser stopped early
                     * because the cap was reached, not because the value ran out.
                     * Skip trailing separators first so a value ending in ", "
                     * does not report a phantom drop. */
                    while (s < e && (*s == ' ' || *s == '\t' || *s == ','
                                     || *s == '\r' || *s == '\n'))
                    {
                        s++;
                    }
                    if (s < e) {
                        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                            "cache_turbo: tag list truncated at %ui tags for "
                            "\"%V\" -- the remaining tags are NOT indexed and a "
                            "purge of them will NOT invalidate this entry "
                            "(raise NGX_HTTP_CACHE_TURBO_MAX_TAGS or emit fewer "
                            "tags)", (ngx_uint_t) NGX_HTTP_CACHE_TURBO_MAX_TAGS,
                            &r->uri);
                    }
                }
            }
        }
    }

    return ngx_http_cache_turbo_forward_body(r, in);
}


static char *
ngx_http_cache_turbo_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                       *p;
    ssize_t                       size;
    ngx_str_t                    *value, name, s;
    ngx_shm_zone_t               *shm_zone;
    ngx_http_cache_turbo_zone_t  *ctx;

    value = cf->args->elts;

    /* arg 1: name=NNN, arg 2: size */
    name.len = 0;
    name.data = NULL;

    p = (u_char *) ngx_strchr(value[1].data, '=');
    if (p && ngx_strncmp(value[1].data, "name=", 5) == 0) {
        name.data = value[1].data + 5;
        name.len = value[1].len - 5;
    } else {
        name = value[1];
    }

    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid cache_turbo_zone name");
        return NGX_CONF_ERROR;
    }

    s = value[2];
    size = ngx_parse_size(&s);
    if (size == NGX_ERROR || size < (ssize_t) (8 * ngx_pagesize)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid cache_turbo_zone size \"%V\"", &s);
        return NGX_CONF_ERROR;
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_cache_turbo_zone_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_cache_turbo_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate cache_turbo_zone \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_cache_turbo_shm_init_zone;
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}


static char *
ngx_http_cache_turbo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t       *value;
    ngx_shm_zone_t  *shm_zone;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        clcf->enable = 0;
        return NGX_CONF_OK;
    }

    /* "cache_turbo <zone>;" enables and binds the zone */
    shm_zone = ngx_shared_memory_add(cf, &value[1], 0,
                                     &ngx_http_cache_turbo_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    clcf->enable = 1;
    clcf->shm_zone = shm_zone;

    /*
     * "cache_turbo <zone> auto;" used to be shorthand for the `generic` preset.
     * Both are GONE — see the cache_turbo_backend comment for why. The directive
     * now takes the zone and nothing else.
     *
     * The command is deliberately still NGX_CONF_TAKE12 rather than TAKE1: that
     * lets us catch the dead token here and name its replacement, instead of
     * letting nginx emit a bare "invalid number of arguments" at someone whose
     * config worked yesterday. It is a hard config error either way — nginx will
     * not start — which is the point. Silently ignoring `auto` would leave a
     * WordPress site with NO preset active and quietly start caching /wp-admin/.
     */
    if (cf->args->nelts == 3) {
        if (ngx_strcmp(value[2].data, "auto") == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "\"cache_turbo %V auto\" is no longer supported: the `auto` / "
                "`generic` preset union has been removed because it was not a "
                "safe default (it never covered every backend, and `joomla` in "
                "it ships no cookie rule at all). Name the backends you actually "
                "run, e.g. \"cache_turbo %V; cache_turbo_backend wordpress;\"",
                &value[1], &value[1]);
            return NGX_CONF_ERROR;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid cache_turbo mode \"%V\" (cache_turbo takes a zone name "
            "only; use cache_turbo_backend to enable a CMS preset)",
            &value[2]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * cache_turbo_backend <name>... — compose one or more CMS auto-classify presets.
 * EVERY preset is opt-in: you name the backends you actually run. All backends
 * stack, and spaces and '|' are interchangeable separators:
 *
 *     cache_turbo_backend wordpress woocommerce;
 *     cache_turbo_backend wordpress|woocommerce;
 *     cache_turbo_backend wordpress | woocommerce;
 *
 * `none` is the odd one out: it means "no preset in this location" and overrides
 * a preset inherited from the server block (see BACKEND_NONE in the header). It
 * is exclusive — combining it with a real backend is a config error.
 *
 * Sets bits in clcf->backend_presets consumed by ngx_http_cache_turbo_auto_skip.
 *
 * There is deliberately no `generic` / `auto` union any more. It used to mean
 * wordpress+woocommerce+joomla, and it was never a safe default:
 *
 *   - it never covered every backend (after xenforo/discourse/phpbb/drupal/
 *     mediawiki it named 3 of 9), so `auto` on a Drupal site silently enabled
 *     no Drupal rules at all;
 *   - `woocommerce` inside it leaves /wp-admin/ cacheable unless it is stacked
 *     with `wordpress` — a union whose members you must know how to combine is
 *     not a default;
 *   - `joomla` inside it ships NO cookie rule, so `auto` on a Joomla site LOOKED
 *     like it protected logged-in users and did not.
 *
 * A default that is only correct if you already know which parts of it are wrong
 * is a footgun with a friendly name. Both spellings are now rejected at config
 * parse with a message naming the replacement — a hard error, never a silent
 * no-op, because silently enabling nothing would start caching /wp-admin/ on an
 * existing WordPress config.
 */
/* Backend name -> preset bit. One row per preset; adding a backend is a row here
 * and a row in the registry, nothing else. Order is the order shown in the
 * "unknown backend" diagnostic.
 *
 * `implies` names other preset bits that this backend REQUIRES to be safe — an
 * add-on that layers dynamic surfaces on top of another CMS without repeating
 * that CMS's own login/admin rules. `woocommerce` is the type case: its rows add
 * only cart/checkout/account cookies and URIs and ship NO /wp-admin/ rule and NO
 * wordpress_logged_in_ cookie rule, because it IS WordPress and those belong to
 * the wordpress preset. `cache_turbo_backend woocommerce;` used alone therefore
 * leaves /wp-admin/ cacheable and — on a store whose account page is at a
 * translated slug the woo uris[] cannot know — caches a logged-in customer's
 * account page (no woo cookie on an empty cart, no wordpress preset to catch the
 * login cookie). The implication is resolved to a fixpoint at parse time
 * (ngx_http_cache_turbo_backend), so naming the add-on silently enables the base
 * too; auto_skip then fires the base's rules unchanged. 0 = no implication. */
static const struct {
    const char  *name;
    ngx_uint_t   bit;
    ngx_uint_t   implies;
} ngx_http_cache_turbo_backend_names[] = {
    { "wordpress",   NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS,   0 },
    { "woocommerce", NGX_HTTP_CACHE_TURBO_BACKEND_WOOCOMMERCE,
      NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS },
    { "joomla",      NGX_HTTP_CACHE_TURBO_BACKEND_JOOMLA,      0 },
    { "xenforo",     NGX_HTTP_CACHE_TURBO_BACKEND_XENFORO,     0 },
    { "discourse",   NGX_HTTP_CACHE_TURBO_BACKEND_DISCOURSE,   0 },
    { "phpbb",       NGX_HTTP_CACHE_TURBO_BACKEND_PHPBB,       0 },
    { "drupal",      NGX_HTTP_CACHE_TURBO_BACKEND_DRUPAL,      0 },
    { "mediawiki",   NGX_HTTP_CACHE_TURBO_BACKEND_MEDIAWIKI,   0 },
    { "magento",     NGX_HTTP_CACHE_TURBO_BACKEND_MAGENTO,     0 },
    { "ghost",       NGX_HTTP_CACHE_TURBO_BACKEND_GHOST,       0 },
    { "wagtail",     NGX_HTTP_CACHE_TURBO_BACKEND_WAGTAIL,     0 },
    { "kirby",       NGX_HTTP_CACHE_TURBO_BACKEND_KIRBY,       0 },
    { "shopware6",   NGX_HTTP_CACHE_TURBO_BACKEND_SHOPWARE6,   0 },
    { "typo3",       NGX_HTTP_CACHE_TURBO_BACKEND_TYPO3,       0 },
    { "invision",    NGX_HTTP_CACHE_TURBO_BACKEND_INVISION,    0 },
    { "smf",         NGX_HTTP_CACHE_TURBO_BACKEND_SMF,         0 },
    { "vanilla",     NGX_HTTP_CACHE_TURBO_BACKEND_VANILLA,     0 },
    { "punbb",       NGX_HTTP_CACHE_TURBO_BACKEND_PUNBB,       0 },
    { "phorum",      NGX_HTTP_CACHE_TURBO_BACKEND_PHORUM,      0 },
    { "yabb",        NGX_HTTP_CACHE_TURBO_BACKEND_YABB,        0 },
    { "mybb",        NGX_HTTP_CACHE_TURBO_BACKEND_MYBB,        0 },
    { "vbulletin",   NGX_HTTP_CACHE_TURBO_BACKEND_VBULLETIN,   0 },
    { "textpattern", NGX_HTTP_CACHE_TURBO_BACKEND_TEXTPATTERN, 0 },
    { "bludit",      NGX_HTTP_CACHE_TURBO_BACKEND_BLUDIT,      0 },
    { "spip",        NGX_HTTP_CACHE_TURBO_BACKEND_SPIP,        0 },
    { "bugzilla",    NGX_HTTP_CACHE_TURBO_BACKEND_BUGZILLA,    0 },
    { "mantisbt",    NGX_HTTP_CACHE_TURBO_BACKEND_MANTISBT,    0 },
    { "mantis",      NGX_HTTP_CACHE_TURBO_BACKEND_MANTISBT,    0 },
    { "plone",       NGX_HTTP_CACHE_TURBO_BACKEND_PLONE,       0 },
    { "umbraco",     NGX_HTTP_CACHE_TURBO_BACKEND_UMBRACO,     0 },
    { "dotclear",    NGX_HTTP_CACHE_TURBO_BACKEND_DOTCLEAR,    0 },
    { "wikijs",      NGX_HTTP_CACHE_TURBO_BACKEND_WIKIJS,      0 },
    { "redmine",     NGX_HTTP_CACHE_TURBO_BACKEND_REDMINE,     0 },
    { "flarum",      NGX_HTTP_CACHE_TURBO_BACKEND_FLARUM,      0 },
    { "opencart",    NGX_HTTP_CACHE_TURBO_BACKEND_OPENCART,    0 },
    { "classicpress", NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS,  0 },
    { "backdrop",    NGX_HTTP_CACHE_TURBO_BACKEND_DRUPAL,      0 },
    { "none",        NGX_HTTP_CACHE_TURBO_BACKEND_NONE,        0 },
    { NULL,          0,                                        0 }
};


/* Expand every implied backend bit into `mask` to a fixpoint. An add-on preset
 * (woocommerce -> wordpress) is unsafe without its base, so naming it must
 * enable the base too. The loop repeats until a pass adds nothing, so a chain
 * (a -> b -> c) resolves fully however the table is ordered; the table is small
 * and implications are shallow, so the cost is negligible. Returns the expanded
 * mask. */
static ngx_uint_t
ngx_http_cache_turbo_expand_implies(ngx_uint_t mask)
{
    ngx_uint_t  i, added;

    do {
        added = 0;

        for (i = 0; ngx_http_cache_turbo_backend_names[i].name; i++) {
            if ((mask & ngx_http_cache_turbo_backend_names[i].bit)
                && ngx_http_cache_turbo_backend_names[i].implies)
            {
                ngx_uint_t  imp = ngx_http_cache_turbo_backend_names[i].implies;

                if ((mask & imp) != imp) {
                    mask |= imp;
                    added = 1;
                }
            }
        }
    } while (added);

    return mask;
}


/* Resolve one backend name (already split off a token) to its bit. Returns 0 for
 * an unknown name — 0 is not a valid bit, so the caller uses it as "not found".
 * `len` is explicit because names arrive as slices of a `a|b|c` token and are
 * NOT NUL-terminated at the boundary. */
static ngx_uint_t
ngx_http_cache_turbo_backend_bit(u_char *name, size_t len)
{
    ngx_uint_t  i;
    size_t      nlen;

    for (i = 0; ngx_http_cache_turbo_backend_names[i].name; i++) {
        nlen = ngx_strlen(ngx_http_cache_turbo_backend_names[i].name);

        if (nlen == len
            && ngx_strncmp(name, ngx_http_cache_turbo_backend_names[i].name,
                           len) == 0)
        {
            return ngx_http_cache_turbo_backend_names[i].bit;
        }
    }

    return 0;
}


static char *
ngx_http_cache_turbo_backend(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;
    ngx_str_t                        *value;
    ngx_uint_t                        i, bit, mask;
    u_char                           *p, *end, *tok;
    ngx_str_t                         bad;

    value = cf->args->elts;
    mask = 0;

    /*
     * Backends stack, and both separators mean the same thing:
     *
     *     cache_turbo_backend wordpress woocommerce;      (spaces)
     *     cache_turbo_backend wordpress|woocommerce;      (pipe)
     *     cache_turbo_backend wordpress | woocommerce;    (both)
     *
     * nginx's config lexer splits on whitespace, so `a|b` reaches us as ONE
     * token containing a '|', while `a | b` reaches us as THREE tokens (the
     * middle one a bare "|"). Hence two levels: walk the argv tokens, and split
     * each one on '|'. A bare "|" token contributes no names and is skipped.
     * Empty slices (`a||b`, a trailing `a|`) are rejected rather than ignored —
     * they are a typo, and silently accepting them hides it.
     */
    for (i = 1; i < cf->args->nelts; i++) {
        p = value[i].data;
        end = p + value[i].len;

        /* a bare "|" used as a standalone separator token */
        if (value[i].len == 1 && *p == '|') {
            continue;
        }

        while (p < end) {
            tok = p;
            while (p < end && *p != '|') {
                p++;
            }

            if (p == tok) {          /* empty slice: "||", leading/trailing "|" */
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "empty backend name in cache_turbo_backend \"%V\" "
                    "(stray '|')", &value[i]);
                return NGX_CONF_ERROR;
            }

            bit = ngx_http_cache_turbo_backend_bit(tok, (size_t) (p - tok));

            if (bit == 0) {
                bad.data = tok;
                bad.len  = (size_t) (p - tok);

                /* The two removed spellings get their own diagnostic — a bare
                 * "unknown backend" would leave an operator whose config worked
                 * yesterday with no idea what to do. This is a HARD error, not a
                 * silent no-op: accepting the name and enabling nothing would
                 * leave an existing WordPress config with no preset active and
                 * quietly start caching /wp-admin/, which is the exact failure
                 * the removal exists to prevent. Refusing to start makes the
                 * operator look. */
                if ((bad.len == sizeof("generic") - 1
                     && ngx_strncmp(bad.data, "generic", bad.len) == 0)
                    || (bad.len == sizeof("auto") - 1
                        && ngx_strncmp(bad.data, "auto", bad.len) == 0))
                {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "cache_turbo_backend \"%V\" has been removed: it was a "
                        "union of wordpress+woocommerce+joomla, which was never "
                        "a safe default — it did not cover every backend, "
                        "`woocommerce` in it left /wp-admin/ cacheable unless "
                        "stacked with `wordpress`, and `joomla` in it ships no "
                        "cookie rule at all. Name the backends you actually run, "
                        "e.g. \"cache_turbo_backend wordpress|woocommerce;\"",
                        &bad);
                    return NGX_CONF_ERROR;
                }

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "unknown cache_turbo_backend \"%V\" (want wordpress, "
                    "woocommerce, joomla, xenforo, discourse, phpbb, drupal, "
                    "mediawiki, magento, ghost, wagtail, kirby, shopware6, "
                    "typo3, invision, smf, vanilla, punbb, phorum, yabb, mybb, "
                    "vbulletin, textpattern, bludit, spip, bugzilla, mantisbt, "
                    "mantis, plone, umbraco, dotclear, wikijs, redmine, "
                    "flarum, opencart, "
                    "classicpress, backdrop, or none — "
                    "separated by spaces or '|')", &bad);
                return NGX_CONF_ERROR;
            }

            mask |= bit;

            if (p < end) {
                p++;                 /* step over the '|' */

                /* A '|' promises another name. If it was the last character of
                 * the token ("wordpress|"), there is none — and the outer
                 * `while (p < end)` would simply exit, silently accepting the
                 * typo. Catch it here; the empty-slice check above only fires
                 * for a leading or doubled pipe. */
                if (p == end) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "empty backend name in cache_turbo_backend \"%V\" "
                        "(trailing '|')", &value[i]);
                    return NGX_CONF_ERROR;
                }
            }
        }
    }

    /* Every argument was a bare '|' separator, so no backend was actually named
     * ("cache_turbo_backend |;"). Leaving the mask at 0 would mean "unset", which
     * the loc-conf merge reads as "inherit the parent's" — a directive that looks
     * like it says something and silently does nothing. NGX_CONF_1MORE already
     * guarantees at least one argument; this catches the degenerate one. */
    if (mask == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_backend names no backend (want wordpress, woocommerce, "
            "joomla, xenforo, discourse, phpbb, drupal, mediawiki, magento, "
            "ghost, wagtail, kirby, shopware6, typo3, invision, smf, vanilla, "
            "punbb, phorum, yabb, mybb, vbulletin, textpattern, bludit, spip, "
            "bugzilla, mantisbt, mantis, plone, umbraco, dotclear, wikijs, "
            "redmine, flarum, opencart, "
            "classicpress, backdrop, or none)");
        return NGX_CONF_ERROR;
    }

    /* Resolve add-on implications (woocommerce -> wordpress) to a fixpoint.
     * Silent by design — an add-on that needed its base spelled out would be the
     * same footgun cache_turbo_backend "auto" was removed for. "none" carries no
     * implication (implies == 0 in the name table), so folding it through here is
     * a no-op and safe to do before the exclusivity check below. */
    mask = ngx_http_cache_turbo_expand_implies(mask);

    /* Fold in any earlier cache_turbo_backend in the SAME context before the
     * "none" exclusivity check. backend_presets accumulates per context (0 =
     * unset), so this makes the check see the combined value rather than only this
     * one invocation's args — otherwise `cache_turbo_backend none;` and
     * `cache_turbo_backend wordpress;` on two lines each pass alone and silently
     * leave NONE|WORDPRESS set. */
    mask |= clcf->backend_presets;

    /* "none" is exclusive: `none|wordpress` is a contradiction, not a merge, and
     * silently letting one win would be the quiet surprise this directive exists
     * to avoid. Checked on the combined mask so it catches the mix however it was
     * spelled (spaces, pipes, or across several directives). */
    if ((mask & NGX_HTTP_CACHE_TURBO_BACKEND_NONE)
        && NGX_HTTP_CACHE_TURBO_HAS_BACKEND(mask))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_backend \"none\" cannot be combined with other backends "
            "— it means \"no preset in this location\" (and overrides one "
            "inherited from the server block). Use it alone.");
        return NGX_CONF_ERROR;
    }

    clcf->backend_presets = mask;

    return NGX_CONF_OK;
}


/* "cache_turbo_cache_control respect|honor|ignore;" — how the response
 * Cache-Control is treated. Sets the tri-state cc_mode; honor_cc/ignore_cc are
 * derived from it at merge (see merge_loc_conf). Replaces the former
 * cache_turbo_honor_cache_control / cache_turbo_ignore_cache_control flags. */
static char *
ngx_http_cache_turbo_cache_control(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;
    ngx_str_t                        *value = cf->args->elts;

    if (clcf->cc_mode != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    if (ngx_strcmp(value[1].data, "respect") == 0) {
        clcf->cc_mode = NGX_HTTP_CACHE_TURBO_CC_RESPECT;
    } else if (ngx_strcmp(value[1].data, "honor") == 0) {
        clcf->cc_mode = NGX_HTTP_CACHE_TURBO_CC_HONOR;
    } else if (ngx_strcmp(value[1].data, "ignore") == 0) {
        clcf->cc_mode = NGX_HTTP_CACHE_TURBO_CC_IGNORE;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid cache_turbo_cache_control \"%V\" "
            "(want respect|honor|ignore)", &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_cache_turbo_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    clcf->key = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (clcf->key == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = clcf->key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * "cache_turbo_valid [code ...] time;"
 *   - bare `cache_turbo_valid 30s;`  => the default/200 fresh TTL (valid_raw),
 *     which also drives the stale window + autotune (back-compatible).
 *   - `cache_turbo_valid 301 302 1h;` / `cache_turbo_valid 404 1m;` => per-status
 *     fresh TTLs, so redirects and negative responses get cached too.
 * Last arg is always the time; any leading args are HTTP status codes.
 */
static char *
ngx_http_cache_turbo_valid_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t                     *value;
    time_t                         valid;
    ngx_uint_t                     i;
    ngx_int_t                      code;
    ngx_http_cache_turbo_valid_t  *v;

    value = cf->args->elts;

    valid = ngx_parse_time(&value[cf->args->nelts - 1], 1);   /* seconds */
    if (valid == (time_t) NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "cache_turbo_valid: bad time \"%V\"",
                           &value[cf->args->nelts - 1]);
        return NGX_CONF_ERROR;
    }

    /* "0" means "cache forever" (the documented contract). Resolve it to a long
     * finite TTL so the object stays FRESH (not instantly-stale) and L2 works —
     * a literal 0 fresh TTL produced an L2 blob with stale_ttl 0, which every L2
     * hit re-read as already-expired. Covers both the bare default TTL and any
     * per-status `cache_turbo_valid <code> 0` rule (same parsed `valid`). */
    if (valid == 0) {
        valid = NGX_HTTP_CACHE_TURBO_FOREVER_TTL;
    }

    if (cf->args->nelts == 2) {
        clcf->valid_raw = valid;           /* default / 200 TTL */
        return NGX_CONF_OK;
    }

    if (clcf->valid_status == NULL) {
        clcf->valid_status = ngx_array_create(cf->pool, 4,
                                 sizeof(ngx_http_cache_turbo_valid_t));
        if (clcf->valid_status == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts - 1; i++) {
        code = ngx_atoi(value[i].data, value[i].len);
        if (code < 100 || code > 599) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_valid: bad status code \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
        /* Reject statuses that must not stand alone as a cached representation
         * (COR-12): 1xx informational are not final responses; 206 has no Range
         * in the key (a stored partial would be replayed for another range); 304
         * is a conditional answer that must never be served to an unconditional
         * request. The body filter also refuses 206 at store time, but rejecting
         * here turns a meaningless config into a clear error. */
        if (code < 200 || code == NGX_HTTP_PARTIAL_CONTENT
            || code == NGX_HTTP_NOT_MODIFIED)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_valid: status %V cannot be cached standalone "
                "(1xx/206/304 refused)", &value[i]);
            return NGX_CONF_ERROR;
        }
        /* COR-9: status_ttl() returns the FIRST matching rule, so a second rule
         * for the same code is dead. Warn rather than silently ignore it. */
        {
            ngx_http_cache_turbo_valid_t  *ev = clcf->valid_status->elts;
            ngx_uint_t                     j;

            for (j = 0; j < clcf->valid_status->nelts; j++) {
                if (ev[j].status == (ngx_uint_t) code) {
                    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                        "cache_turbo_valid: duplicate rule for status %V "
                        "ignored (the first rule for a code wins)", &value[i]);
                    break;
                }
            }
        }

        v = ngx_array_push(clcf->valid_status);
        if (v == NULL) {
            return NGX_CONF_ERROR;
        }
        v->status = (ngx_uint_t) code;
        v->valid = valid;
    }

    return NGX_CONF_OK;
}


/* "cache_turbo_tag <expr>;" sets the tag-list expression. On store the result
 * is split on whitespace/commas and each tag set gets the object's L2 key. */
static char *
ngx_http_cache_turbo_tag(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    clcf->tag = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (clcf->tag == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = clcf->tag;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * cache_turbo_require_header <name>: the explicit upstream store opt-in.
 * A plain header NAME, not a complex value -- the module reads the RESPONSE
 * header of that name, and a $variable here would be evaluated against the
 * request, quietly gating on the wrong thing.
 */
static char *
ngx_http_cache_turbo_require_header(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t  *value = cf->args->elts;
    ngx_uint_t  i;

    if (clcf->require_header.len) {
        return "is duplicate";
    }

    if (value[1].len == 0) {
        return "requires a header name";
    }

    /* A header name is a token (RFC 9110 5.6.2). Reject anything else at config
     * time rather than compare a name that can never match at runtime -- a
     * store gate that silently never passes reads as "the cache is broken",
     * and one that silently never fires would be worse. */
    for (i = 0; i < value[1].len; i++) {
        u_char  c = value[1].data[i];

        if (c <= 0x20 || c >= 0x7f || c == ':' || c == ',' || c == ';'
            || c == '(' || c == ')' || c == '<' || c == '>' || c == '@'
            || c == '\\' || c == '"' || c == '/' || c == '[' || c == ']'
            || c == '?' || c == '=' || c == '{' || c == '}')
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid header name \"%V\" in "
                               "\"cache_turbo_require_header\"", &value[1]);
            return NGX_CONF_ERROR;
        }
    }

    clcf->require_header = value[1];

    return NGX_CONF_OK;
}


/*
 * The store gate itself. Unset (len == 0) => 1, so every existing config keeps
 * the module's normal "cacheable unless vetoed" behaviour untouched.
 *
 * Set => the named response header must be present AND affirmative. Scans the
 * whole headers_out list rather than stopping at the first match: an upstream
 * that emits the header twice ("yes" and "no") is ambiguous, and the only safe
 * reading of an ambiguous store signal is "do not store" -- so ANY
 * non-affirmative occurrence vetoes, whatever order they arrive in.
 */
static ngx_int_t
ngx_http_cache_turbo_require_hdr_ok(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;
    ngx_uint_t        i, found = 0;

    if (clcf->require_header.len == 0) {
        return 1;
    }

    part = &r->headers_out.headers.part;
    h = part->elts;

    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (h[i].hash == 0 || h[i].key.len != clcf->require_header.len) {
            continue;
        }
        if (ngx_strncasecmp(h[i].key.data, clcf->require_header.data,
                            clcf->require_header.len) != 0)
        {
            continue;
        }

        /* Affirmative values only, matched whole: "yes" / "1" / "on". A prefix
         * compare would read "note" as "no"-negative and, worse, "yes-but-not-
         * really" as affirmative. */
        if (!((h[i].value.len == 3
               && ngx_strncasecmp(h[i].value.data, (u_char *) "yes", 3) == 0)
              || (h[i].value.len == 2
                  && ngx_strncasecmp(h[i].value.data, (u_char *) "on", 2) == 0)
              || (h[i].value.len == 1 && h[i].value.data[0] == '1')))
        {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: \"%V\" not cached: %V is not "
                           "affirmative", &r->uri, &clcf->require_header);
            return 0;
        }

        found = 1;
    }

    if (!found) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: \"%V\" not cached: no %V header",
                       &r->uri, &clcf->require_header);
    }

    return found ? 1 : 0;
}


/* cache_turbo_stale_mult N (H5). Range-checked rather than a bare
 * ngx_conf_set_num_slot: ngx_http_cache_turbo_stale_ttl() coerces <= 0 back to
 * the BALANCED default, so an explicit `0` would silently behave as `4` instead
 * of the "no stale window" the operator wrote. Reject it at parse instead. */
static char *
ngx_http_cache_turbo_stale_mult(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t  *value = cf->args->elts;
    ngx_int_t   n;

    if (clcf->stale_mult_raw != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    n = ngx_atoi(value[1].data, value[1].len);
    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_stale_mult: bad value \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (n < NGX_HTTP_CACHE_TURBO_STALE_MULT_MIN
        || n > NGX_HTTP_CACHE_TURBO_STALE_MULT_MAX)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_stale_mult \"%V\" is out of range: expected %d..%d",
            &value[1], NGX_HTTP_CACHE_TURBO_STALE_MULT_MIN,
            NGX_HTTP_CACHE_TURBO_STALE_MULT_MAX);
        return NGX_CONF_ERROR;
    }

    clcf->stale_mult_raw = n;

    return NGX_CONF_OK;
}


/* cache_turbo_min_uses N (H3c). Range-checked rather than a bare
 * ngx_conf_set_num_slot for the same reason as stale_mult above: merge_loc_conf
 * coerces a value < 1 up to 1, so an explicit `0` or a negative would silently
 * behave as `1` ("store on the first miss") instead of whatever the operator
 * meant by it. Reject at parse so the config cannot lie. */
static char *
ngx_http_cache_turbo_min_uses(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t  *value = cf->args->elts;
    ngx_int_t   n;

    if (clcf->min_uses_raw != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    /* ngx_atoi has no sign handling, so a negative fails here as NGX_ERROR and
     * surfaces as "bad value" rather than reaching the range check below. The
     * two diagnostics are deliberately distinct — see the H5 lesson. */
    n = ngx_atoi(value[1].data, value[1].len);
    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_min_uses: bad value \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (n < NGX_HTTP_CACHE_TURBO_MIN_USES_MIN
        || n > NGX_HTTP_CACHE_TURBO_MIN_USES_MAX)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_min_uses \"%V\" is out of range: expected %d..%d",
            &value[1], NGX_HTTP_CACHE_TURBO_MIN_USES_MIN,
            NGX_HTTP_CACHE_TURBO_MIN_USES_MAX);
        return NGX_CONF_ERROR;
    }

    clcf->min_uses_raw = n;

    return NGX_CONF_OK;
}


/* cache_turbo_breaker_open T (O4.4). Hand-rolled rather than
 * ngx_conf_set_sec_slot for the same class of reason as min_uses/stale_mult
 * above, but inverted: those reject 0 because merge_loc_conf would silently
 * COERCE it to a non-zero default, masking the operator's intent. This one
 * rejects 0 because a literal 0 would NOT be inert here the way it is for
 * every sibling breaker field -- _breaker_state()'s timed reopen is guarded
 * on `open_for > 0` (see the field comment in the .h and O4.3-a in memory
 * issues.md), so `cache_turbo_breaker_open 0` would WEDGE an OPEN breaker
 * permanently: it would never promote a probe, and with nobody talking to
 * the origin while OPEN, no success could ever be recorded to close it
 * either. That is materially worse than the "off" the operator likely
 * intended, so it is refused outright -- "off" for the breaker is expressed
 * via cache_turbo_breaker, cache_turbo_breaker_threshold 0, or
 * cache_turbo_breaker_window 0 instead. */
static char *
ngx_http_cache_turbo_breaker_open_conf(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t   *value = cf->args->elts;
    ngx_int_t    n;

    if (clcf->breaker_open != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    n = ngx_parse_time(&value[1], 1);
    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_breaker_open: invalid value \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (n == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_breaker_open \"%V\" must be greater than 0 "
            "(0 wedges the breaker OPEN forever: it never reopens and, with "
            "no origin contact while OPEN, never closes either -- use "
            "cache_turbo_breaker off, cache_turbo_breaker_threshold 0, or "
            "cache_turbo_breaker_window 0 to disable the breaker instead)",
            &value[1]);
        return NGX_CONF_ERROR;
    }

    clcf->breaker_open = (time_t) n;

    return NGX_CONF_OK;
}


/* cache_turbo_scan_resistant on|off [protected_pct=N]   (S8)
 *
 * Segmented (probation/protected) LRU. OFF BY DEFAULT: when absent, or set to
 * `off`, scan_resistant_pct is 0 and every LRU path behaves exactly as the flat
 * single-queue LRU did before S8 -- no node is ever promoted, the protected
 * queue stays empty, and eviction always finds its victim on probation.
 *
 * `on` stores the protected-segment cap (1..99, default 80) in the same field,
 * so "on" and the tuning cannot disagree and there is no representable
 * "on with pct 0" state.
 *
 * Range-checked by hand rather than via ngx_conf_set_num_slot for the reason
 * H5/stale_mult and H3c/min_uses both re-learned the hard way: a bare num_slot
 * would accept `protected_pct=0` and let it be silently coerced to the default,
 * so the config would quietly mean something other than what it says. A value
 * outside the band is a config ERROR here.
 */
static char *
ngx_http_cache_turbo_scan_resistant(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t  *value = cf->args->elts;
    ngx_int_t   pct;
    ngx_uint_t  i;
    ngx_uint_t  on;

    if (clcf->scan_resistant_pct != (ngx_uint_t) NGX_CONF_UNSET) {
        return "is duplicate";
    }

    if (value[1].len == 2 && ngx_strncmp(value[1].data, "on", 2) == 0) {
        on = 1;

    } else if (value[1].len == 3
               && ngx_strncmp(value[1].data, "off", 3) == 0)
    {
        on = 0;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_scan_resistant: bad value \"%V\": expected "
            "\"on\" or \"off\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    pct = NGX_HTTP_CACHE_TURBO_PROTECTED_PCT_DEFAULT;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "protected_pct=", 14) == 0) {

            /* ngx_atoi has no sign handling, so a negative fails as NGX_ERROR
             * and surfaces as "bad protected_pct" rather than reaching the
             * range check. The two diagnostics are deliberately distinct --
             * same split as cache_turbo_stale_mult (the H5 lesson). */
            pct = ngx_atoi(value[i].data + 14, value[i].len - 14);
            if (pct == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_scan_resistant: bad protected_pct \"%V\"",
                    &value[i]);
                return NGX_CONF_ERROR;
            }

            if (pct < NGX_HTTP_CACHE_TURBO_PROTECTED_PCT_MIN
                || pct > NGX_HTTP_CACHE_TURBO_PROTECTED_PCT_MAX)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_scan_resistant: protected_pct \"%V\" is out "
                    "of range: expected %d..%d", &value[i],
                    NGX_HTTP_CACHE_TURBO_PROTECTED_PCT_MIN,
                    NGX_HTTP_CACHE_TURBO_PROTECTED_PCT_MAX);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_scan_resistant: unknown parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    /* protected_pct on an `off` directive is accepted-but-inert config: reject
     * it rather than store a value that will never be read. */
    if (!on && cf->args->nelts > 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_scan_resistant: protected_pct is meaningless with "
            "\"off\"");
        return NGX_CONF_ERROR;
    }

    clcf->scan_resistant_pct = on ? (ngx_uint_t) pct : 0;

    return NGX_CONF_OK;
}


/* cache_turbo_l2_negative_ttl N (L13). Seconds to remember an L2 miss so the
 * next cold request for the same key skips the L2 round-trip.
 *
 * Range-checked like stale_mult/min_uses above, but with one deliberate
 * difference: 0 is ACCEPTED here and means OFF (the default). For those two
 * directives a literal 0 was a config lie -- merge coerced it back up to 1 --
 * so it had to be rejected. Here 0 is the honest, and default, way to say "no
 * memo", and merge_loc_conf leaves it at 0. A NEGATIVE still fails as
 * NGX_ERROR out of ngx_atoi (no sign handling) and surfaces as "bad value". */
static char *
ngx_http_cache_turbo_l2_negative_ttl(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t  *value = cf->args->elts;
    ngx_int_t   n;

    if (clcf->l2_negative_ttl != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    n = ngx_atoi(value[1].data, value[1].len);
    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_l2_negative_ttl: bad value \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (n != 0
        && (n < NGX_HTTP_CACHE_TURBO_L2_NEG_TTL_MIN
            || n > NGX_HTTP_CACHE_TURBO_L2_NEG_TTL_MAX))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_l2_negative_ttl \"%V\" is out of range: expected 0 "
            "(off) or %d..%d",
            &value[1], NGX_HTTP_CACHE_TURBO_L2_NEG_TTL_MIN,
            NGX_HTTP_CACHE_TURBO_L2_NEG_TTL_MAX);
        return NGX_CONF_ERROR;
    }

    clcf->l2_negative_ttl = (time_t) n;

    return NGX_CONF_OK;
}


/* cache_turbo_keep_stale <off|time|forever> (S2.1). Origin-independent
 * last-resort retention: when a response carries no `stale-if-error` window of
 * its own, this value becomes the effective stale-if-error window instead of
 * leaving the object with no fallback. The store path reads clcf->keep_stale
 * into sie_window in the two branches at the `ttl > 0 && clcf->keep_stale > 0`
 * and `ttl > 0 && clcf->ignore_cc && clcf->keep_stale > 0` gates (S2.2).
 *
 * cache_turbo_cache_control ignore does NOT suppress this directive (decision
 * D-1; clcf->ignore_cc is the internal flag it sets). Every
 * !clcf->ignore_cc gate in the store path guards a RESPONSE-derived value --
 * upstream max-age, stale-while-revalidate, must-revalidate, stale-if-error --
 * because ignore_cc means "the upstream Cache-Control header is inert", not
 * "operator retention config is inert". stale_window is likewise built from
 * cache_turbo_valid + cache_turbo_stale_mult regardless of ignore_cc; keep_stale
 * is the sie_window analogue of stale_mult. Under ignore_cc the response
 * stale-if-error branch never runs, so keep_stale simply applies unconditionally.
 * Precedence when both are available: a HONORED response stale-if-error WINS over
 * keep_stale (same shape as response swr beating stale_mult) -- deliberately not
 * max(), which would make keep_stale a silent floor overriding an origin that
 * explicitly stated its own error window.
 *
 * Argument forms:
 *   off      -> 0 (the default; today's behaviour, unchanged)
 *   forever  -> NGX_HTTP_CACHE_TURBO_FOREVER_TTL
 *   <time>   -> ngx_parse_time(..., 1), clamped to NGX_HTTP_CACHE_TURBO_TTL_MAX
 *
 * A bare "0" is accepted as a synonym for `off`, NOT for "forever" --
 * ngx_parse_time("0", 1) already returns 0 with no error, so this falls out
 * naturally rather than needing a special case. This is a DELIBERATE
 * departure from cache_turbo_valid's contract, where `cache_turbo_valid 0`
 * means "cache forever" (see the FOREVER_TTL resolution above
 * ngx_http_cache_turbo_valid_conf). The two directives read the same digit
 * with opposite meaning: cache_turbo_valid's forever-TTL and this directive's
 * off both had to spell as "reset the field to a value that switches the
 * feature off"; but cache_turbo_valid's field can never mean "no TTL" (a
 * cached object always has SOME fresh window), so 0 there was repurposed as
 * an alias for forever. keep_stale, by contrast, has an honest OFF state (no
 * last-resort retention at all), and OFF is what an operator who writes a
 * bare 0 -- or omits the directive -- means. Do not "fix" this to match
 * cache_turbo_valid; a future reader who reconciles the two will silently
 * turn every un-configured location into permanent stale retention. */
static char *
ngx_http_cache_turbo_keep_stale(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t  *value = cf->args->elts;
    time_t      t;

    if (clcf->keep_stale != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    if (value[1].len == 3 && ngx_strncmp(value[1].data, "off", 3) == 0) {
        clcf->keep_stale = 0;
        return NGX_CONF_OK;
    }

    if (value[1].len == 7 && ngx_strncmp(value[1].data, "forever", 7) == 0) {
        clcf->keep_stale = NGX_HTTP_CACHE_TURBO_FOREVER_TTL;
        return NGX_CONF_OK;
    }

    t = ngx_parse_time(&value[1], 1);   /* seconds, matches cache_turbo_valid */
    if (t == (time_t) NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_keep_stale: bad value \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    /* Clamp rather than reject (matches the store path's own TTL_MAX clamp,
     * see the header comment on NGX_HTTP_CACHE_TURBO_TTL_MAX): an operator
     * writing an oversized-but-well-formed time is asking for "as long as
     * possible", not making a typo the way an out-of-range l2_negative_ttl
     * is -- there is no bounded-blindness cost here to make a large value a
     * footgun, only a wire-format ceiling. */
    if (t > NGX_HTTP_CACHE_TURBO_TTL_MAX) {
        t = NGX_HTTP_CACHE_TURBO_TTL_MAX;
    }

    clcf->keep_stale = t;

    return NGX_CONF_OK;
}


/* cache_turbo_use_stale <off | error | timeout | http_403 | http_404 |
 *                         http_429 | http_500 | http_502 | http_503 |
 *                         http_504> ... (S4.1). Read on the request path by
 * the stale-if-error gate in ngx_http_cache_turbo_header_filter (S4.2). See the
 * NGX_HTTP_CACHE_TURBO_USE_STALE_* block in the header for the full mask
 * contract, the error/timeout aliasing rationale, and why the merge default
 * includes the ANY_5XX bit.
 *
 * `off` must appear alone: mixing it with any other token is rejected, same
 * shape as nginx's own proxy_cache_use_stale (`off` there is likewise not
 * combinable). Any unrecognised token is rejected by name. Hand-written
 * NGX_CONF_1MORE parser -- this module has zero uses of
 * ngx_conf_set_bitmask_slot anywhere, by established convention (see
 * cache_turbo_scan_resistant, cache_turbo_normalize_strip, and the directive
 * this one is modelled on, cache_turbo_keep_stale, immediately above). */
static char *
ngx_http_cache_turbo_use_stale(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t   *value;
    ngx_uint_t   i, mask, saw_off;

    if (clcf->use_stale != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;
    mask = 0;
    saw_off = 0;

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].len == 3
            && ngx_strncmp(value[i].data, "off", 3) == 0)
        {
            saw_off = 1;
            continue;
        }

        if (value[i].len == 5
            && ngx_strncmp(value[i].data, "error", 5) == 0)
        {
            mask |= NGX_HTTP_CACHE_TURBO_USE_STALE_ERROR;

        } else if (value[i].len == 7
            && ngx_strncmp(value[i].data, "timeout", 7) == 0)
        {
            mask |= NGX_HTTP_CACHE_TURBO_USE_STALE_TIMEOUT;

        } else if (value[i].len == 8
            && ngx_strncmp(value[i].data, "http_403", 8) == 0)
        {
            mask |= NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_403;

        } else if (value[i].len == 8
            && ngx_strncmp(value[i].data, "http_404", 8) == 0)
        {
            mask |= NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_404;

        } else if (value[i].len == 8
            && ngx_strncmp(value[i].data, "http_429", 8) == 0)
        {
            mask |= NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_429;

        } else if (value[i].len == 8
            && ngx_strncmp(value[i].data, "http_500", 8) == 0)
        {
            mask |= NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_500;

        } else if (value[i].len == 8
            && ngx_strncmp(value[i].data, "http_502", 8) == 0)
        {
            mask |= NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_502;

        } else if (value[i].len == 8
            && ngx_strncmp(value[i].data, "http_503", 8) == 0)
        {
            mask |= NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_503;

        } else if (value[i].len == 8
            && ngx_strncmp(value[i].data, "http_504", 8) == 0)
        {
            mask |= NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_504;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid value \"%V\" in \"%V\" directive",
                &value[i], &cmd->name);
            return NGX_CONF_ERROR;
        }
    }

    if (saw_off && mask != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid value \"off\" in \"%V\" directive: "
            "\"off\" cannot be combined with other tokens", &cmd->name);
        return NGX_CONF_ERROR;
    }

    /* saw_off with mask == 0 -> empty mask (off). Any other combination of
     * real tokens -> their OR. Note this never sets ANY_5XX: that bit is a
     * merge-default-only construct (see header comment), not reachable from
     * the config vocabulary. */
    clcf->use_stale = mask;

    return NGX_CONF_OK;
}


/* "cache_turbo_preset micro|conservative|balanced|aggressive;" stores the enum
 * (and validates the name here, at config time). The enum only selects the band
 * of default knob values used in merge_loc_conf; an explicit knob directive
 * (cache_turbo_valid/_beta/_lock_ttl) still wins because those write the *_raw
 * fields, which take precedence over the band in the merge. */
static char *
ngx_http_cache_turbo_preset(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t  *value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "conservative") == 0) {
        clcf->preset = NGX_HTTP_CACHE_TURBO_PRESET_CONSERVATIVE;

    } else if (ngx_strcmp(value[1].data, "balanced") == 0) {
        clcf->preset = NGX_HTTP_CACHE_TURBO_PRESET_BALANCED;

    } else if (ngx_strcmp(value[1].data, "aggressive") == 0) {
        clcf->preset = NGX_HTTP_CACHE_TURBO_PRESET_AGGRESSIVE;

    } else if (ngx_strcmp(value[1].data, "micro") == 0) {
        clcf->preset = NGX_HTTP_CACHE_TURBO_PRESET_MICRO;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid cache_turbo_preset \"%V\": "
            "expected micro, conservative, balanced, or aggressive",
            &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/* "cache_turbo_admin <zone>;" turns this location into a control endpoint for
 * the named zone. Gate it with the usual allow/deny. */
static char *
ngx_http_cache_turbo_admin(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t                 *value;
    ngx_http_core_loc_conf_t  *core;

    value = cf->args->elts;

    clcf->admin_zone = ngx_shared_memory_add(cf, &value[1], 0,
                                             &ngx_http_cache_turbo_module);
    if (clcf->admin_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    clcf->admin = 1;

    core = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    core->handler = ngx_http_cache_turbo_admin_handler;

    return NGX_CONF_OK;
}


#if (NGX_SSL)
/* Build the per-location client SSL context for a rediss:// (TLS) backend.
 * Verification is on unless tls_verify=off: trust the system CA store, or the
 * file named by tls_ca=. The cert+hostname are checked post-handshake in the
 * driver (ngx_ssl_check_host + SSL_get_verify_result). */
static char *
ngx_http_cache_turbo_redis_build_ssl(ngx_conf_t *cf,
    ngx_http_cache_turbo_loc_conf_t *clcf)
{
    ngx_ssl_t           *ssl;
    ngx_pool_cleanup_t  *cln;

    ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
    if (ssl == NULL) {
        return NGX_CONF_ERROR;
    }
    ssl->log = cf->log;

    if (ngx_ssl_create(ssl, NGX_SSL_TLSv1_2|NGX_SSL_TLSv1_3, NULL) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        ngx_ssl_cleanup_ctx(ssl);
        return NGX_CONF_ERROR;
    }
    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = ssl;

    /* Called post-merge (COR-6): redis_tls_verify is resolved to 0 or 1 here.
     * 0 = verify off (tls_verify=off); 1 = verify on (the default). */
    if (clcf->redis_tls_verify != 0) {
        if (clcf->redis_tls_ca.len) {
            if (ngx_ssl_trusted_certificate(cf, ssl, &clcf->redis_tls_ca, 2)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
        } else if (SSL_CTX_set_default_verify_paths(ssl->ctx) != 1) {
            ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                          "cache_turbo_redis: "
                          "SSL_CTX_set_default_verify_paths() failed");
            return NGX_CONF_ERROR;
        }
    }

    clcf->redis_ssl = ssl;
    return NGX_CONF_OK;
}
#endif


/* AUD-MC1: validate an operator-supplied L2 key prefix at config time, for both
 * backends. The composed key is prefix + a hex digest, and the module documents
 * it as printable, space-free and <=250 bytes -- an invariant only the digest
 * half ever honoured. On memcached a space or CRLF in the prefix splits the
 * delimiter-framed command outright; on Redis it merely makes keys that no
 * operator can type back into redis-cli. There is no attacker path (every
 * request-controlled byte terminates at the digest), so this is a config typo
 * that used to fail silently, degrading the location to L1-only.
 *
 * `name` is the directive, so the error names the line the operator wrote. */
static char *
ngx_http_cache_turbo_check_l2_prefix(ngx_conf_t *cf, ngx_str_t *prefix,
    const char *name)
{
    size_t  i;

    if (prefix->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo: empty prefix= is not allowed "
            "(an all-purge would match the whole L2 keyspace)");
        return NGX_CONF_ERROR;
    }

    for (i = 0; i < prefix->len; i++) {
        if (prefix->data[i] <= 0x20 || prefix->data[i] >= 0x7f) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "%s: prefix= contains byte 0x%02Xd at offset %uz; the L2 key "
                "must be printable and free of spaces and control characters",
                name, prefix->data[i], i);
            return NGX_CONF_ERROR;
        }
    }

    if (prefix->len + NGX_HTTP_CACHE_TURBO_L2_KEY_SUFFIX_MAX
        > NGX_HTTP_CACHE_TURBO_L2_KEY_MAX)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "%s: prefix= is %uz bytes; at most %uz are usable, because the "
            "module appends up to %d bytes of key and an L2 key may not "
            "exceed %d bytes",
            name, prefix->len,
            (size_t) (NGX_HTTP_CACHE_TURBO_L2_KEY_MAX
                      - NGX_HTTP_CACHE_TURBO_L2_KEY_SUFFIX_MAX),
            NGX_HTTP_CACHE_TURBO_L2_KEY_SUFFIX_MAX,
            NGX_HTTP_CACHE_TURBO_L2_KEY_MAX);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * "cache_turbo_redis <dsn|host:port> [prefix=] [timeout=] [password=] [user=]
 *  [db=] [tls=on|off] [tls_verify=on|off] [tls_ca=<file>] [tls_name=<host>];"
 *
 * The DSN is redis://[user:pass@]host:port/db ; rediss:// selects TLS. Bare
 * host:port still works (legacy). Trailing params override whatever the DSN
 * carried. The address is resolved at config time; settable at http/server/
 * location level and merged down, so a whole http{} block can share one L2.
 */
static char *
ngx_http_cache_turbo_redis_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t   *value, s, hostport, arg1;
    ngx_url_t    u;
    ngx_uint_t   i;
    ngx_int_t    t;
    u_char      *rest, *last, *at, *slash, *colon;

    value = cf->args->elts;
    arg1 = value[1];

    if (clcf->memcached == 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_redis: an L2 backend (cache_turbo_memcached) is already "
            "configured in this block; the two are mutually exclusive");
        return NGX_CONF_ERROR;
    }

    /* --- 1. split the DSN (scheme / userinfo / host:port / db) ------------- */
    hostport = arg1;

    if (arg1.len > sizeof("rediss://") - 1
        && ngx_strncasecmp(arg1.data, (u_char *) "rediss://",
                           sizeof("rediss://") - 1) == 0)
    {
        clcf->redis_tls = 1;
        rest = arg1.data + sizeof("rediss://") - 1;

    } else if (arg1.len > sizeof("redis://") - 1
               && ngx_strncasecmp(arg1.data, (u_char *) "redis://",
                                  sizeof("redis://") - 1) == 0)
    {
        rest = arg1.data + sizeof("redis://") - 1;

    } else {
        rest = NULL;        /* bare host:port */
    }

    if (rest != NULL) {
        last = arg1.data + arg1.len;

        at = ngx_strlchr(rest, last, '@');
        if (at != NULL) {
            colon = ngx_strlchr(rest, at, ':');
            if (colon != NULL) {
                clcf->redis_user.data = rest;
                clcf->redis_user.len = colon - rest;
                clcf->redis_password.data = colon + 1;
                clcf->redis_password.len = at - (colon + 1);
            } else {
                clcf->redis_user.data = rest;
                clcf->redis_user.len = at - rest;
            }
            rest = at + 1;
        }

        slash = ngx_strlchr(rest, last, '/');
        if (slash != NULL) {
            if (last - (slash + 1) > 0) {
                clcf->redis_db = ngx_atoi(slash + 1,
                                          last - (slash + 1));
                if (clcf->redis_db == NGX_ERROR || clcf->redis_db < 0) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "cache_turbo_redis: bad db in DSN \"%V\"", &arg1);
                    return NGX_CONF_ERROR;
                }
                if (clcf->redis_db > NGX_HTTP_CACHE_TURBO_REDIS_DB_MAX) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "cache_turbo_redis: db in DSN \"%V\" exceeds the "
                        "maximum %d", &arg1,
                        NGX_HTTP_CACHE_TURBO_REDIS_DB_MAX);
                    return NGX_CONF_ERROR;
                }
            }
            hostport.data = rest;
            hostport.len = slash - rest;
        } else {
            hostport.data = rest;
            hostport.len = last - rest;
        }
    }

    /* --- 2. resolve the host:port ----------------------------------------- */
    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = hostport;
    u.default_port = 6379;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "cache_turbo_redis: %s in \"%V\"", u.err, &u.url);
        }
        return NGX_CONF_ERROR;
    }
    if (u.naddrs == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "cache_turbo_redis: no addresses for \"%V\"", &u.url);
        return NGX_CONF_ERROR;
    }

    clcf->redis_addr = u.addrs[0];
    clcf->redis_host = u.host;        /* default SNI / verify name */

    /* --- 3. trailing params override the DSN ------------------------------ */
    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "prefix=", 7) == 0) {
            clcf->redis_prefix.data = value[i].data + 7;
            clcf->redis_prefix.len = value[i].len - 7;
            if (ngx_http_cache_turbo_check_l2_prefix(cf, &clcf->redis_prefix,
                                                     "cache_turbo_redis")
                != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }

        } else if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
            s.data = value[i].data + 8;
            s.len = value[i].len - 8;
            t = ngx_parse_time(&s, 0);   /* milliseconds */
            if (t == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "cache_turbo_redis: bad timeout \"%V\"", &s);
                return NGX_CONF_ERROR;
            }
            if (t == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "cache_turbo_redis: timeout must be > 0");
                return NGX_CONF_ERROR;
            }
            clcf->redis_timeout = (ngx_msec_t) t;

        } else if (ngx_strncmp(value[i].data, "keepalive=", 10) == 0) {
            clcf->redis_keepalive = ngx_atoi(value[i].data + 10,
                                             value[i].len - 10);
            if (clcf->redis_keepalive == NGX_ERROR
                || clcf->redis_keepalive < 0)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_redis: bad keepalive \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }
            /* STAB-5: bound N so the pool's N*sizeof(item) alloc can't overflow. */
            if (clcf->redis_keepalive > NGX_HTTP_CACHE_TURBO_KEEPALIVE_MAX) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_redis: keepalive %V exceeds the maximum %d",
                    &value[i], NGX_HTTP_CACHE_TURBO_KEEPALIVE_MAX);
                return NGX_CONF_ERROR;
            }

        } else if (ngx_strncmp(value[i].data, "keepalive_timeout=", 18) == 0) {
            s.data = value[i].data + 18;
            s.len = value[i].len - 18;
            t = ngx_parse_time(&s, 0);   /* milliseconds */
            if (t == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_redis: bad keepalive_timeout \"%V\"", &s);
                return NGX_CONF_ERROR;
            }
            clcf->redis_keepalive_timeout = (ngx_msec_t) t;

        } else if (ngx_strncmp(value[i].data, "password=", 9) == 0) {
            clcf->redis_password.data = value[i].data + 9;
            clcf->redis_password.len = value[i].len - 9;

        } else if (ngx_strncmp(value[i].data, "user=", 5) == 0) {
            clcf->redis_user.data = value[i].data + 5;
            clcf->redis_user.len = value[i].len - 5;

        } else if (ngx_strncmp(value[i].data, "db=", 3) == 0) {
            clcf->redis_db = ngx_atoi(value[i].data + 3, value[i].len - 3);
            if (clcf->redis_db == NGX_ERROR || clcf->redis_db < 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "cache_turbo_redis: bad db \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }
            if (clcf->redis_db > NGX_HTTP_CACHE_TURBO_REDIS_DB_MAX) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "cache_turbo_redis: db \"%V\" exceeds the "
                                   "maximum %d", &value[i],
                                   NGX_HTTP_CACHE_TURBO_REDIS_DB_MAX);
                return NGX_CONF_ERROR;
            }

        } else if (ngx_strncmp(value[i].data, "tls=", 4) == 0) {
            s.data = value[i].data + 4;
            s.len = value[i].len - 4;
            if (s.len == 2 && ngx_strncmp(s.data, "on", 2) == 0) {
                clcf->redis_tls = 1;
            } else if (s.len == 3 && ngx_strncmp(s.data, "off", 3) == 0) {
                clcf->redis_tls = 0;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "cache_turbo_redis: tls must be on|off");
                return NGX_CONF_ERROR;
            }

        } else if (ngx_strncmp(value[i].data, "tls_verify=", 11) == 0) {
            s.data = value[i].data + 11;
            s.len = value[i].len - 11;
            if (s.len == 2 && ngx_strncmp(s.data, "on", 2) == 0) {
                clcf->redis_tls_verify = 1;
            } else if (s.len == 3 && ngx_strncmp(s.data, "off", 3) == 0) {
                clcf->redis_tls_verify = 0;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "cache_turbo_redis: tls_verify must be on|off");
                return NGX_CONF_ERROR;
            }

        } else if (ngx_strncmp(value[i].data, "tls_ca=", 7) == 0) {
            clcf->redis_tls_ca.data = value[i].data + 7;
            clcf->redis_tls_ca.len = value[i].len - 7;

        } else if (ngx_strncmp(value[i].data, "tls_name=", 9) == 0) {
            clcf->redis_tls_name.data = value[i].data + 9;
            clcf->redis_tls_name.len = value[i].len - 9;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "cache_turbo_redis: invalid parameter \"%V\"",
                               &value[i]);
            return NGX_CONF_ERROR;
        }
    }

    /* The client TLS context is built in merge_loc_conf (COR-6), once
     * redis_tls / tls_verify / tls_ca are resolved — not here, where an
     * inherited verify flag or CA would not yet be visible. */

    clcf->redis_enable = 1;
    /* Pin the backend choice for this block to Redis. Without this the flag
     * stays UNSET and merge_loc_conf would inherit a parent's memcached=1,
     * selecting the memcached driver for this block's redis:// address. */
    clcf->memcached = 0;

    return NGX_CONF_OK;
}


/*
 * "cache_turbo_memcached <host:port> [prefix=] [timeout=];"  (v13)
 *
 * Selects the memcached L2 backend instead of Redis. Reuses the redis_addr/
 * redis_prefix/redis_timeout/redis_enable fields (the two backends are mutually
 * exclusive — one L2 per location) and sets clcf->memcached so the merge step
 * wires the memcached vtable. No DSN/auth/db/TLS: memcached's text protocol has
 * no AUTH/SELECT and we keep the driver plain-TCP.
 */
static char *
ngx_http_cache_turbo_memcached_conf(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t   *value, s;
    ngx_url_t    u;
    ngx_uint_t   i;
    ngx_int_t    t;

    value = cf->args->elts;

    if (clcf->redis_enable == 1 && clcf->memcached != 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_memcached: an L2 backend (cache_turbo_redis) is already "
            "configured in this block; the two are mutually exclusive");
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = value[1];
    u.default_port = 11211;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_memcached: %s in \"%V\"", u.err, &u.url);
        }
        return NGX_CONF_ERROR;
    }
    if (u.naddrs == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_memcached: no addresses for \"%V\"", &u.url);
        return NGX_CONF_ERROR;
    }

    clcf->redis_addr = u.addrs[0];

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "prefix=", 7) == 0) {
            clcf->redis_prefix.data = value[i].data + 7;
            clcf->redis_prefix.len = value[i].len - 7;
            if (ngx_http_cache_turbo_check_l2_prefix(cf, &clcf->redis_prefix,
                                                     "cache_turbo_memcached")
                != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }

        } else if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
            s.data = value[i].data + 8;
            s.len = value[i].len - 8;
            t = ngx_parse_time(&s, 0);   /* milliseconds */
            if (t == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_memcached: bad timeout \"%V\"", &s);
                return NGX_CONF_ERROR;
            }
            if (t == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_memcached: timeout must be > 0");
                return NGX_CONF_ERROR;
            }
            clcf->redis_timeout = (ngx_msec_t) t;

        } else if (ngx_strncmp(value[i].data, "keepalive=", 10) == 0) {
            s.data = value[i].data + 10;
            s.len = value[i].len - 10;
            clcf->memcached_keepalive = ngx_atoi(s.data, s.len);
            if (clcf->memcached_keepalive == NGX_ERROR
                || clcf->memcached_keepalive < 0)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_memcached: bad keepalive \"%V\"", &s);
                return NGX_CONF_ERROR;
            }
            if (clcf->memcached_keepalive > NGX_HTTP_CACHE_TURBO_KEEPALIVE_MAX) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_memcached: keepalive must be <= %d",
                    NGX_HTTP_CACHE_TURBO_KEEPALIVE_MAX);
                return NGX_CONF_ERROR;
            }

        } else if (ngx_strncmp(value[i].data, "keepalive_timeout=", 18) == 0) {
            s.data = value[i].data + 18;
            s.len = value[i].len - 18;
            t = ngx_parse_time(&s, 0);
            if (t == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_memcached: bad keepalive_timeout \"%V\"", &s);
                return NGX_CONF_ERROR;
            }
            clcf->memcached_keepalive_timeout = (ngx_msec_t) t;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_memcached: invalid parameter \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
    }

    clcf->redis_enable = 1;
    clcf->memcached = 1;

    return NGX_CONF_OK;
}


/* Send a small body with the given status and content-type. Returns the rc to
 * propagate/finalize with. */
static ngx_int_t
ngx_http_cache_turbo_send_body(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t *body, const char *ctype, size_t ctype_len)
{
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t   out;

    r->headers_out.status = status;
    r->headers_out.content_type.data = (u_char *) ctype;
    r->headers_out.content_type.len = ctype_len;
    r->headers_out.content_type_len = ctype_len;
    r->headers_out.content_length_n = body->len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b = ngx_create_temp_buf(r->pool, body->len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(b->pos, body->data, body->len);
    b->last = b->pos + body->len;
    b->last_buf = 1;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}


/* Send a small JSON body. Shared by the admin handler and the async tag-purge
 * completion. */
static ngx_int_t
ngx_http_cache_turbo_send_json(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t *body)
{
    return ngx_http_cache_turbo_send_body(r, status, body,
               "application/json", sizeof("application/json") - 1);
}


/* Decode len hex chars at src into len/2 bytes at dst. NGX_ERROR on odd length
 * or any non-hex char. */
static ngx_int_t
ngx_http_cache_turbo_hexdecode(u_char *src, size_t len, u_char *dst)
{
    size_t     i;
    ngx_int_t  hi, lo;

    if (len & 1) {
        return NGX_ERROR;
    }
    for (i = 0; i < len; i += 2) {
        hi = ngx_http_cache_turbo_hexval(src[i]);
        lo = ngx_http_cache_turbo_hexval(src[i + 1]);
        if (hi < 0 || lo < 0) {
            return NGX_ERROR;
        }
        dst[i / 2] = (u_char) ((hi << 4) | lo);
    }
    return NGX_OK;
}


/* ngx_http_cache_turbo_tagpurge_t is defined near the top of the file (shared
 * with the COR-5 variant-index purge launched from purge_request). */


/* SMEMBERS completion: drop every member object from L1 + L2, delete the now-
 * empty tag set, and answer {"purged":N}. Runs while `members` (which point
 * into the redis op buffer) are still valid; everything it keeps is copied or
 * acted on synchronously here. */
static ngx_int_t
ngx_http_cache_turbo_tag_purge_complete(ngx_http_request_t *r, void *data,
    ngx_str_t *members, ngx_uint_t nmembers,
    const ngx_http_cache_turbo_redis_walk_t *walk)
{
    ngx_http_cache_turbo_tagpurge_t  *tp = data;
    ngx_uint_t                        i, purged = 0, ndel = 0;
    size_t                            plen, n;
    u_char                           *tagkey, *p;
    ngx_str_t                        *delkeys, body;

    (void) walk;                 /* SMEMBERS walks no keyspace: always NULL */

    plen = tp->clcf->redis_prefix.len;

    /* PERF-2: collect every L2 key to drop (each member's object key + its
     * cross-node lock key + the tag set itself) and issue ONE pipelined UNLINK
     * connection, instead of two fire-and-forget connections per member plus
     * one for the set. A tag with thousands of members previously opened
     * thousands of sockets at once (worker_connections exhaustion); now it is a
     * single bounded connection. L1 eviction stays inline (no socket). */
    delkeys = ngx_palloc(r->pool, (nmembers * 2 + 1) * sizeof(ngx_str_t));
    if (delkeys == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    for (i = 0; i < nmembers; i++) {
        if (members[i].len == 0) {
            continue;
        }

        /* The member IS the object's L2 key. */
        delkeys[ndel++] = members[i];

        /* member = <prefix><64 hex of the 32-byte key hash>: drop from L1, and
         * also drop the object's cross-node single-flight lock (v4-2 SET NX PX)
         * — otherwise a stale lock outlives the purged object and stalls the
         * next cold-miss winner for lock_timeout (the V-HANG; see redis_del). */
        if (members[i].len == plen + 64) {
            u_char    key_hash[32];
            uint32_t  hash;

            if (ngx_http_cache_turbo_hexdecode(members[i].data + plen, 64,
                                               key_hash) == NGX_OK)
            {
                u_char  *lockbuf;

                hash = ngx_crc32_short(key_hash, 32);
                (void) tp->clcf->l1->purge_key(tp->zone, key_hash, hash);

                lockbuf = ngx_pnalloc(r->pool,
                              plen + sizeof("lock:") - 1 + 64);
                if (lockbuf != NULL) {
                    delkeys[ndel].data = lockbuf;
                    delkeys[ndel].len = ngx_http_cache_turbo_redis_lockkey(
                                  &tp->clcf->redis_prefix, key_hash, lockbuf);
                    ndel++;
                }
            }
        }

        purged++;
    }

    /* Remove the (now-emptied) tag set itself in the same pipeline. */
    tagkey = ngx_pnalloc(r->pool, plen + sizeof("tag:") - 1 + tp->tag.len);
    if (tagkey != NULL) {
        n = tp->clcf->backend->tagkey(&tp->clcf->redis_prefix,
                 tp->tag.data, tp->tag.len, tagkey);
        delkeys[ndel].data = tagkey;
        delkeys[ndel].len = n;
        ndel++;
    }

    ngx_http_cache_turbo_redis_del_many(tp->clcf, delkeys, ndel);

    p = ngx_pnalloc(r->pool, sizeof("{\"purged\":4294967295}\n"));
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    body.data = p;
    body.len = ngx_sprintf(p, "{\"purged\":%ui}\n", purged) - p;

    return ngx_http_cache_turbo_send_json(r, NGX_HTTP_OK, &body);
}


/* State carried through an async all-purge (?all=1) from the admin handler to
 * the SCAN-del completion callback. Holds the L1 count purged synchronously so
 * the reply can report it after the parked L2 SCAN finishes. */
typedef struct {
    ngx_uint_t  purged;        /* L1 entries dropped (reported as "purged") */
} ngx_http_cache_turbo_allpurge_t;


/* SCAN-del completion (?all=1): the L2 keyspace walk has ended; emit
 * {"purged":N} where N is the L1 count (L2 deletions are fire-and-forget and not
 * separately counted). members/nmembers are unused (always 0 here).
 *
 * AUD-SCAN1: the walk does NOT always finish. It ends early on a read timeout,
 * a malformed reply, an allocation failure, or the SCAN page cap — and in every
 * one of those cases part of the L2 keyspace still holds entries the caller was
 * told were gone. That is worse than an outright error: an operator who purged
 * before a config rollout believes L2 is empty when it is not. So a walk that
 * did not reach cursor 0 is reported as a FAILURE (500) carrying
 * "l2":"incomplete" plus the reason, never as a 200. AUD-PURGE-HONESTY1
 * refines that: a walk that consumed ZERO pages never ran at all (L2 refused
 * the connection), so it reports "l2":"unavailable" — L2 is intact, not partly
 * purged. `walk == NULL` cannot
 * happen on this path (the SCAN backend always supplies it); it is treated as
 * complete only so the callback stays total. */
static ngx_int_t
ngx_http_cache_turbo_all_purge_complete(ngx_http_request_t *r, void *data,
    ngx_str_t *members, ngx_uint_t nmembers,
    const ngx_http_cache_turbo_redis_walk_t *walk)
{
    ngx_http_cache_turbo_allpurge_t  *ap = data;
    u_char                           *p;
    ngx_str_t                         body;
    ngx_uint_t                        status;
    const char                       *reason;
    const char                       *state;

    (void) members;
    (void) nmembers;

    if (walk == NULL || walk->status == NGX_OK) {
        status = NGX_HTTP_OK;
        state = NULL;
        reason = NULL;
    } else {
        status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        reason = (walk->status == NGX_ABORT) ? "page-cap" : "error";

        /* AUD-PURGE-HONESTY1: separate "the walk ran and stopped early" from
         * "the walk never happened". Zero pages consumed means no SCAN reply
         * was ever parsed -- L2 refused the connection, or died before the
         * first page -- so the whole keyspace is intact rather than partly
         * purged. Both are 500; the field tells the operator which state L2 is
         * actually in, and "incomplete" would overstate what was done. */
        state = (walk->pages == 0) ? "unavailable" : "incomplete";
    }

    p = ngx_pnalloc(r->pool,
                    sizeof("{\"purged\":4294967295,"
                           "\"l2\":\"unavailable\",\"reason\":\"page-cap\","
                           "\"scan_pages\":4294967295,"
                           "\"scan_pool_blocks\":4294967295}\n"));
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    body.data = p;
    p = ngx_sprintf(p, "{\"purged\":%ui", ap->purged);
    if (reason != NULL) {
        p = ngx_sprintf(p, ",\"l2\":\"%s\",\"reason\":\"%s\"", state, reason);
    }
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    /* Walk diagnostics, CI builds only: scan_pool_blocks is the oracle for the
     * per-page-pool release (constant in scan_pages when the walk is O(1) in
     * page count, linear in it when the whole walk shares one pool). Not a
     * permanent operator-facing field — same convention as the TEST_FAULTS
     * breaker counters. */
    if (walk != NULL) {
        p = ngx_sprintf(p, ",\"scan_pages\":%ui,\"scan_pool_blocks\":%ui",
                        walk->pages, walk->blocks);
    }
#endif
    p = ngx_sprintf(p, "}\n");
    body.len = p - body.data;

    return ngx_http_cache_turbo_send_json(r, status, &body);
}


/* GET  -> JSON stats for the zone.
 * POST -> purge: ?all=1 purges the whole zone; ?key=<string> purges one key
 *         (hashed the same way the cache hashes its key); ?tag=<name> purges
 *         every object tagged <name> across L1 + L2 (needs cache_turbo_redis).
 * Gating is the caller's responsibility (allow/deny in the location). */
static ngx_int_t
ngx_http_cache_turbo_admin_handler(ngx_http_request_t *r)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf;
    ngx_http_cache_turbo_zone_t      *z;
    ngx_str_t                         body;
    u_char                           *p;
    size_t                            len;
    ngx_int_t                         drc;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);
    if (!clcf->admin || clcf->admin_zone == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }

    /* Content handler must consume any request body (a purge/warm POST may carry
     * one) or the bytes desync a keepalive connection. */
    drc = ngx_http_discard_request_body(r);
    if (drc != NGX_OK) {
        return drc;
    }

    z = clcf->admin_zone->data;

    if (r->method & (NGX_HTTP_POST|NGX_HTTP_PUT|NGX_HTTP_DELETE)) {
        ngx_str_t  arg;
        ngx_uint_t purged = 0;

        /* Require all=1 explicitly (COR-10): mere presence of the arg used to
         * purge, so a typo like ?all=0 destroyed the whole zone. Only the exact
         * value "1" triggers the all-purge now. */
        if (r->args.len
            && ngx_http_arg(r, (u_char *) "all", 3, &arg) == NGX_OK
            && arg.len == 1 && arg.data[0] == '1')
        {
            purged = clcf->l1->purge_all(z);

            /* L2-aware all-purge (v4-2): also clear the whole L2 keyspace for
             * this prefix via a parked SCAN MATCH <prefix>* + DEL loop, so an
             * object cleared from L1 cannot be silently refilled from Redis on
             * the next miss. Needs cache_turbo_redis on this admin location.
             * The completion callback emits {"purged":<L1 count>}. */
            if (clcf->backend && clcf->backend->scan_del) {
                ngx_http_cache_turbo_allpurge_t  *ap;
                ngx_int_t                         rc;

                ap = ngx_palloc(r->pool,
                                sizeof(ngx_http_cache_turbo_allpurge_t));
                if (ap == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                ap->purged = purged;

                rc = clcf->backend->scan_del(r, clcf,
                         ngx_http_cache_turbo_all_purge_complete, ap);
                if (rc == NGX_DONE) {
                    return NGX_DONE;        /* parked; completion sends reply */
                }

                /* AUD-PURGE-HONESTY1: the walk did not even START — L2 is down,
                 * or the connection was never established — so the entire L2
                 * keyspace still holds entries the caller asked to be gone.
                 * This used to fall through to the synchronous
                 * 200 {"purged":<L1 count>} below, which reads as a complete
                 * purge. Same dishonesty class as AUD-SCAN1 (a walk that starts
                 * and ends early), so it gets the same answer shape: non-2xx
                 * plus an explicit L2 state. "unavailable" rather than
                 * "incomplete" — nothing was walked at all. L1 really was
                 * purged and "purged" still reports that count. */
                p = ngx_pnalloc(r->pool,
                                sizeof("{\"purged\":4294967295,"
                                       "\"l2\":\"unavailable\"}\n"));
                if (p == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                body.data = p;
                body.len = ngx_sprintf(p,
                               "{\"purged\":%ui,\"l2\":\"unavailable\"}\n",
                               purged) - p;
                return ngx_http_cache_turbo_send_json(r,
                           NGX_HTTP_INTERNAL_SERVER_ERROR, &body);
            }

        } else if (r->args.len
                   && ngx_http_arg(r, (u_char *) "key", 3, &arg) == NGX_OK)
        {
            u_char     key_hash[32];
            uint32_t   hash;

            /* SEC-2: must match build_key's digest so ?key=<rendered key>
             * resolves to the same slot. */
            ngx_http_cache_turbo_digest(arg.data, arg.len, key_hash);
            hash = ngx_crc32_short(key_hash, 32);

            purged = clcf->l1->purge_key(z, key_hash, hash);

            /* L2-aware purge (issue P6): also drop the entry from Redis, so a
             * purge that cleared L1 cannot be silently refilled from L2 on the
             * next miss. Fire-and-forget; needs cache_turbo_redis on this admin
             * location (inherit it from server/http level). Reported "purged"
             * still reflects the L1 removal only. */
            if (clcf->backend) {
                clcf->backend->del(clcf, key_hash);
            }

        } else if (r->args.len
                   && ngx_http_arg(r, (u_char *) "tag", 3, &arg) == NGX_OK)
        {
            /* Purge by tag. The tag index lives only in L2, so this needs
             * cache_turbo_redis. SMEMBERS parks the request; the completion
             * callback drops each object from L1 + L2, deletes the tag set, and
             * sends {"purged":N}. */
            ngx_http_cache_turbo_tagpurge_t  *tp;
            ngx_int_t                         rc;
            u_char                            ch;
            ngx_uint_t                        ti;

            if (clcf->backend == NULL || clcf->backend->purge_tag == NULL) {
                ngx_str_set(&body,
                    "{\"error\":\"tag purge requires cache_turbo_redis\"}\n");
                return ngx_http_cache_turbo_send_json(r,
                           NGX_HTTP_BAD_REQUEST, &body);
            }

            /* AUD-TAG1: mirror the surrogate-key tokeniser's own rules
             * (ngx_http_cache_turbo_emit_surrogate_key above) so a tag never
             * exceeds NGX_HTTP_CACHE_TURBO_MAX_TAG_LEN or contains one of the
             * tokeniser's separator bytes. Nothing downstream URL-decodes
             * ?tag=, so today this is belt-and-braces around a distant
             * parser (nginx rejects a raw space in the request line) rather
             * than a live bypass -- but the check should live locally, not
             * depend on that. */
            if (arg.len == 0 || arg.len > NGX_HTTP_CACHE_TURBO_MAX_TAG_LEN) {
                ngx_str_set(&body,
                    "{\"error\":\"invalid tag: empty or too long "
                    "(max 128 bytes)\"}\n");
                return ngx_http_cache_turbo_send_json(r,
                           NGX_HTTP_BAD_REQUEST, &body);
            }

            for (ti = 0; ti < arg.len; ti++) {
                ch = arg.data[ti];
                if (ch == ' ' || ch == '\t' || ch == ',' || ch == '\r'
                    || ch == '\n')
                {
                    ngx_str_set(&body,
                        "{\"error\":\"invalid tag: contains a "
                        "space/tab/comma/CR/LF\"}\n");
                    return ngx_http_cache_turbo_send_json(r,
                               NGX_HTTP_BAD_REQUEST, &body);
                }
            }

            tp = ngx_palloc(r->pool, sizeof(ngx_http_cache_turbo_tagpurge_t));
            if (tp == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            tp->clcf = clcf;
            tp->zone = z;
            tp->tag.len = arg.len;
            tp->tag.data = ngx_pnalloc(r->pool, arg.len);
            if (tp->tag.data == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            ngx_memcpy(tp->tag.data, arg.data, arg.len);

            rc = clcf->backend->purge_tag(r, clcf,
                     tp->tag.data, tp->tag.len,
                     ngx_http_cache_turbo_tag_purge_complete, tp);
            if (rc == NGX_DONE) {
                return NGX_DONE;            /* parked; completion sends reply */
            }

            ngx_str_set(&body,
                "{\"error\":\"tag purge backend unavailable\"}\n");
            return ngx_http_cache_turbo_send_json(r, NGX_HTTP_BAD_GATEWAY,
                       &body);

        } else if (r->args.len
                   && ngx_http_arg(r, (u_char *) "url", 3, &arg) == NGX_OK)
        {
            /* Warm (v3-3): pre-populate the cache for one or more comma-
             * separated site URLs by firing background subrequests that hit the
             * origin and store the result. Best-effort/async — the reply reports
             * how many warm subrequests were fired, not how many actually
             * stored. Sends its own JSON, so return its rc directly. */
            return ngx_http_cache_turbo_warm(r, &arg);

        } else {
            ngx_str_set(&body,
                "{\"error\":\"specify ?all=1, ?key=<string>, ?tag=<name> "
                "or ?url=<path[,path...]>\"}\n");
            return ngx_http_cache_turbo_send_json(r, NGX_HTTP_BAD_REQUEST,
                       &body);
        }

        p = ngx_pnalloc(r->pool, sizeof("{\"purged\":4294967295}\n"));
        if (p == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        body.data = p;
        body.len = ngx_sprintf(p, "{\"purged\":%ui}\n", purged) - p;
        return ngx_http_cache_turbo_send_json(r, NGX_HTTP_OK, &body);
    }

    /* GET / HEAD -> stats. `?autotune=1` first forces an immediate autotune
     * recompute over the window since the last tick (operator "recompute now"),
     * so the returned autotuned_beta reflects current stats without waiting on the
     * interval. `?format=prometheus` renders the Prometheus text exposition
     * format (for a scrape) instead of JSON. Snapshot the counters through the L1
     * backend rather than reading the live shctx here. */
    {
        ngx_http_cache_turbo_stats_t  st;
        ngx_str_t                     arg;

        if (r->args.len
            && ngx_http_arg(r, (u_char *) "autotune", 8, &arg) == NGX_OK)
        {
            ngx_http_cache_turbo_autotune_force(z);
        }

        clcf->l1->stats(z, &st);

        if (r->args.len
            && ngx_http_arg(r, (u_char *) "format", 6, &arg) == NGX_OK
            && arg.len == sizeof("prometheus") - 1
            && ngx_strncmp(arg.data, "prometheus", arg.len) == 0)
        {
            ngx_str_t  zname = clcf->admin_zone->shm.name;

            /* Fifteen counters (*_total) + four gauges, each labelled by zone
             * so one Prometheus job can scrape many zones. Exposition format
             * 0.0.4. The per-metric budget must track the emitted count (19):
             * every metric line renders one %V (zone) + one %uA (value), so a
             * short multiplier could truncate the last line under a long zone
             * name. The fixed term covers the HELP/TYPE prose, which grows
             * with every metric added -- bump BOTH when adding one (L13 added
             * the 14th and needed ~180 bytes of prose; a stale 13 truncated
             * the JSON arm's neighbour into invalid output; S7.1 added three
             * more, prose term bumped by ~450 bytes for their HELP/TYPE
             * lines; H7.3a added breaker_opens_total (counter) and
             * breaker_state (gauge), prose term bumped by ~350 bytes -- the
             * breaker_state HELP documents the numeric mapping since the
             * value itself is deliberately NOT a label, see the emit call
             * below). */
            len = 3900 + 19 * zname.len + 19 * NGX_ATOMIC_T_LEN;
            p = ngx_pnalloc(r->pool, len);
            if (p == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            body.data = p;
            body.len = ngx_snprintf(p, len,
                "# HELP cache_turbo_hits_total Fresh L1 cache hits served.\n"
                "# TYPE cache_turbo_hits_total counter\n"
                "cache_turbo_hits_total{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_misses_total Misses that went to the origin.\n"
                "# TYPE cache_turbo_misses_total counter\n"
                "cache_turbo_misses_total{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_stale_serves_total Stale copies served while a refresh ran.\n"
                "# TYPE cache_turbo_stale_serves_total counter\n"
                "cache_turbo_stale_serves_total{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_refreshes_total Background single-flight refreshes started.\n"
                "# TYPE cache_turbo_refreshes_total counter\n"
                "cache_turbo_refreshes_total{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_evictions_total Entries evicted under memory pressure (LRU).\n"
                "# TYPE cache_turbo_evictions_total counter\n"
                "cache_turbo_evictions_total{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_l2_hits_total L1 misses satisfied by the L2 tier (Redis or memcached).\n"
                "# TYPE cache_turbo_l2_hits_total counter\n"
                "cache_turbo_l2_hits_total{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_l2_misses_total L1 misses that L2 could not satisfy (went to origin).\n"
                "# TYPE cache_turbo_l2_misses_total counter\n"
                "cache_turbo_l2_misses_total{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_lock_waits_total Cold-miss requests that waited for a single-flight fill (v10).\n"
                "# TYPE cache_turbo_lock_waits_total counter\n"
                "cache_turbo_lock_waits_total{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_min_uses_skips_total Cold misses sent to origin without storing because the key is below cache_turbo_min_uses (v15).\n"
                "# TYPE cache_turbo_min_uses_skips_total counter\n"
                "cache_turbo_min_uses_skips_total{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_l2_neg_skips_total L2 GETs skipped because a negative memo already recorded a miss for the key (L13).\n"
                "# TYPE cache_turbo_l2_neg_skips_total counter\n"
                "cache_turbo_l2_neg_skips_total{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_bypasses_total Requests skipped straight to origin by a cache_turbo_bypass predicate or a CMS backend preset (subset of misses).\n"
                "# TYPE cache_turbo_bypasses_total counter\n"
                "cache_turbo_bypasses_total{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_regen_cost_ms Average origin regeneration cost in milliseconds.\n"
                "# TYPE cache_turbo_regen_cost_ms gauge\n"
                "cache_turbo_regen_cost_ms{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_autotuned_beta Live autotuned SWR beta (x1000; 0 = none).\n"
                "# TYPE cache_turbo_autotuned_beta gauge\n"
                "cache_turbo_autotuned_beta{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_autotuned_load Live load factor widening stale window + lock_ttl under load (x1000; 1000 = none).\n"
                "# TYPE cache_turbo_autotuned_load gauge\n"
                "cache_turbo_autotuned_load{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_sie_serves_total Responses served from a stale-if-error snapshot.\n"
                "# TYPE cache_turbo_sie_serves_total counter\n"
                "cache_turbo_sie_serves_total{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_breaker_serves_total Responses served from the circuit breaker's armed fallback while OPEN.\n"
                "# TYPE cache_turbo_breaker_serves_total counter\n"
                "cache_turbo_breaker_serves_total{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_origin_failures_total Origin responses recorded as a failure by the circuit breaker.\n"
                "# TYPE cache_turbo_origin_failures_total counter\n"
                "cache_turbo_origin_failures_total{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_breaker_opens_total Lifetime count of CLOSED->OPEN circuit breaker trips.\n"
                "# TYPE cache_turbo_breaker_opens_total counter\n"
                "cache_turbo_breaker_opens_total{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_breaker_state Circuit breaker state (0=closed, 1=open, 2=half-open).\n"
                "# TYPE cache_turbo_breaker_state gauge\n"
                "cache_turbo_breaker_state{zone=\"%V\"} %uA\n",
                &zname, st.hits, &zname, st.misses, &zname, st.stale_serves,
                &zname, st.refreshes, &zname, st.evictions,
                &zname, st.l2_hits, &zname, st.l2_misses, &zname, st.lock_waits,
                &zname, st.min_uses_skips, &zname, st.l2_neg_skips,
                &zname, st.bypasses,
                &zname, st.cost_ms, &zname, st.autotuned_beta,
                &zname, st.autotuned_load,
                &zname, st.sie_serves, &zname, st.breaker_serves,
                &zname, st.origin_failures,
                &zname, st.breaker_opens,
                &zname, (ngx_atomic_uint_t) ngx_http_cache_turbo_brk_state(
                    (ngx_uint_t) st.breaker_state)) - p;

            return ngx_http_cache_turbo_send_body(r, NGX_HTTP_OK, &body,
                "text/plain; version=0.0.4; charset=utf-8",
                sizeof("text/plain; version=0.0.4; charset=utf-8") - 1);
        }

        len = sizeof("{\"hits\":,\"misses\":,\"stale_serves\":,\"refreshes\":,"
                     "\"evictions\":,\"l2_hits\":,\"l2_misses\":,\"lock_waits\":,"
                     "\"min_uses_skips\":,\"l2_neg_skips\":,\"bypasses\":,"
                     "\"cost_ms\":,"
                     "\"autotuned_beta\":,\"autotuned_load\":,"
                     "\"breaker_state\":\"\",\"breaker_opens\":,"
                     "\"sie_serves\":,\"breaker_serves\":,"
                     "\"origin_failures\":}\n")
              + 18 * NGX_ATOMIC_T_LEN
              + sizeof("half-open") - 1;   /* longest _breaker_state_str value */
        p = ngx_pnalloc(r->pool, len);
        if (p == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        body.data = p;
        body.len = ngx_sprintf(p,
            "{\"hits\":%uA,\"misses\":%uA,\"stale_serves\":%uA,"
            "\"refreshes\":%uA,\"evictions\":%uA,\"l2_hits\":%uA,"
            "\"l2_misses\":%uA,\"lock_waits\":%uA,\"min_uses_skips\":%uA,"
            "\"l2_neg_skips\":%uA,"
            "\"bypasses\":%uA,\"cost_ms\":%uA,\"autotuned_beta\":%uA,"
            "\"autotuned_load\":%uA,"
            "\"breaker_state\":\"%s\",\"breaker_opens\":%uA,"
            "\"sie_serves\":%uA,\"breaker_serves\":%uA,"
            "\"origin_failures\":%uA}\n",
            st.hits, st.misses, st.stale_serves,
            st.refreshes, st.evictions, st.l2_hits, st.l2_misses,
            st.lock_waits, st.min_uses_skips, st.l2_neg_skips,
            st.bypasses, st.cost_ms,
            st.autotuned_beta, st.autotuned_load,
            ngx_http_cache_turbo_shm_breaker_state_str(
                (ngx_uint_t) st.breaker_state),
            st.breaker_opens,
            st.sie_serves, st.breaker_serves, st.origin_failures) - p;
    }
    return ngx_http_cache_turbo_send_json(r, NGX_HTTP_OK, &body);
}


/* ----- warm (v3-3) --------------------------------------------------------- */

/* Cap on URLs warmed per request. Keeps a single call well under nginx's
 * subrequest-depth limit and bounds the work one admin POST can schedule. */
#define NGX_HTTP_CACHE_TURBO_WARM_MAX  32


/*
 * Fire one background subrequest for `uri` (+ optional `args`) so the origin is
 * hit and the response stored. BACKGROUND (not IN_MEMORY): IN_MEMORY would make
 * the upstream accumulate into u->buffer via its input filter and bypass the
 * output body-filter chain, so our body filter would never see the bytes and
 * nothing would be cached. BACKGROUND alone lets the proxied response traverse
 * the output filters (our filter captures + stores) while the postpone/write
 * filter discards the client-facing output. See history.md (v3-3).
 *
 * The subrequest is pre-seeded with a ctx whose ->warm bit tells the access /
 * header / body filters to force a miss and capture-store despite r != r->main.
 */

/*
 * Make a warm subrequest fetch ANONYMOUSLY. ngx_http_subrequest sets
 * sr->headers_in = r->headers_in (a SHALLOW copy), so the warm sr inherits the
 * admin POST's Cookie header. If the operator's browser carried a segment/key
 * cookie (Magento's X-Magento-Vary, Shopware's sw-cache-hash, a configured
 * cache_turbo_key_cookie, ...), that inherited cookie would be wrong on BOTH
 * axes: (a) build_key folds every present preset/configured key cookie into the
 * key, so the warmed body lands under a SEGMENTED key no cookieless visitor ever
 * looks up -- wasted warm; and (b) the proxy forwards the headers_in list to the
 * origin verbatim, so the origin returns that segment's PRIVATE body -- which,
 * once (a) is corrected to the anonymous key, would be stored under the anon key
 * = a cross-visitor leak. Warm as a cookieless anonymous visitor: give the sr a
 * PRIVATE headers list with every Cookie header dropped, and clear the derived
 * cookie fields. The parent request's list and header elements are never mutated
 * (its own key/upstream handling is unaffected).
 */
static ngx_int_t
ngx_http_cache_turbo_warm_anonymize(ngx_http_request_t *sr)
{
    ngx_list_t        shared;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h, *nh;
    ngx_uint_t        i;

    /* Read from a COPY of the inherited (parent-shared) list header, then build
     * a fresh private list IN PLACE in sr->headers_in.headers. Initialising in
     * place (not into a local we assign out of) keeps the list's `last` pointer
     * self-referential: a local ngx_list_t copied into the struct would leave
     * `last` dangling at the out-of-scope local's embedded first part. The
     * parent's list data is only read; its elements are never mutated. */
    shared = sr->headers_in.headers;

    if (ngx_list_init(&sr->headers_in.headers, sr->pool, 8,
                      sizeof(ngx_table_elt_t)) != NGX_OK)
    {
        sr->headers_in.headers = shared;      /* restore on failure */
        return NGX_ERROR;
    }

    part = &shared.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }

        /* Drop every Cookie header; copy every other elt BY VALUE into the
         * private list (the parent's list/elts stay untouched). */
        if (h[i].key.len == sizeof("Cookie") - 1
            && ngx_strncasecmp(h[i].key.data, (u_char *) "Cookie",
                               sizeof("Cookie") - 1) == 0)
        {
            continue;
        }

        nh = ngx_list_push(&sr->headers_in.headers);
        if (nh == NULL) {
            sr->headers_in.headers = shared;  /* restore on failure */
            return NGX_ERROR;
        }
        *nh = h[i];
    }

#if (nginx_version >= 1023000)
    sr->headers_in.cookie = NULL;
#else
    sr->headers_in.cookies.nelts = 0;
#endif

    return NGX_OK;
}

static ngx_int_t
ngx_http_cache_turbo_warm_one(ngx_http_request_t *r, ngx_str_t *uri,
    ngx_str_t *args)
{
    ngx_http_request_t          *sr;
    ngx_http_cache_turbo_ctx_t  *wctx;

    if (ngx_http_subrequest(r, uri, args->len ? args : NULL, &sr, NULL,
                            NGX_HTTP_SUBREQUEST_BACKGROUND)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Seed the ctx FIRST, before anything below that can fail. A background
     * subrequest cannot be unwound once ngx_http_subrequest() has posted it, so
     * an early return here leaves `sr` live but ctx-less -- and the body filter
     * treats a NULL ctx as "not ours" and FORWARDS the body
     * (ngx_http_cache_turbo_body_filter, ctx == NULL arm). A warm subrequest
     * whose body is forwarded rather than captured is the documented s84
     * shutdown-hang condition. Allocating the ctx up front means every failure
     * arm below leaves a subrequest that is still recognisably ours. */
    wctx = ngx_pcalloc(sr->pool, sizeof(ngx_http_cache_turbo_ctx_t));
    if (wctx == NULL) {
        return NGX_ERROR;
    }
    wctx->warm = 1;
    ngx_http_set_ctx(sr, wctx, ngx_http_cache_turbo_module);

    /* Warm anonymously: strip inherited cookies so both the cache key and the
     * upstream request are the cookieless anonymous variant a visitor gets. */
    if (ngx_http_cache_turbo_warm_anonymize(sr) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Force a clean GET to the origin regardless of the admin request's method
     * (the admin POST is what triggered the warm). header_only stays 0: unlike
     * core SWR (which relies on the native file cache and can set header_only=1),
     * cache-turbo captures the body in its OWN body filter, so the full origin
     * body must stream through the filter chain to be stored. header_only=1
     * suppresses that streaming and the warm entry is never populated
     * (test_warm_populates). */
    sr->header_only = 0;

    return NGX_OK;
}


/*
 * ngx_http_subrequest() does NOT run ngx_http_parse_complex_uri() on the URI
 * we hand it -- that normalization only happens for a real client request
 * line, before any module sees it. A hand-built subrequest URI goes straight
 * into sr->uri and location matching verbatim, so a percent-decoded "?url="
 * value must be validated ourselves: reject an embedded NUL (truncates
 * downstream ngx_str_t-vs-C-string consumers, e.g. proxy_pass URI
 * construction or $uri in a log format) and reject any ".." path segment
 * (traversal past the intended location, e.g. "/%2e%2e/%2e%2e/etc/x").
 * Returns 1 if `uri` is safe to warm, 0 if it must be skipped.
 */
static ngx_uint_t
ngx_http_cache_turbo_warm_uri_is_safe(ngx_str_t *uri)
{
    u_char  *p, *last, *seg;

    last = uri->data + uri->len;

    for (p = uri->data; p < last; p++) {
        if (*p == '\0') {
            return 0;
        }
    }

    /* uri->data[0] == '/' is guaranteed by the caller, so every segment
     * starts right after a '/'. Walk segments delimited by '/' and reject
     * one that is exactly "..". */
    seg = uri->data + 1;
    for (p = seg; p <= last; p++) {
        if (p == last || *p == '/') {
            if (p - seg == 2 && seg[0] == '.' && seg[1] == '.') {
                return 0;
            }
            seg = p + 1;
        }
    }

    return 1;
}


/*
 * POST /_cache?url=<path[,path,...]> — warm each comma-separated path. Each path
 * is percent-decoded (so an encoded URL still resolves) and an optional "?query"
 * suffix is passed through as the subrequest args. Only absolute paths ('/'...)
 * are accepted; anything else is skipped. Replies {"warmed":N} with N = number
 * of warm subrequests actually fired. The bg subrequests outlive this reply:
 * each bumped r->main->count, so the connection survives admin finalize until
 * they complete.
 */
static ngx_int_t
ngx_http_cache_turbo_warm(ngx_http_request_t *r, ngx_str_t *urls)
{
    u_char     *p, *last, *comma, *q, *dst, *s;
    ngx_uint_t  warmed = 0;
    ngx_str_t   uri, args, body;
    u_char     *out;

    p = urls->data;
    last = p + urls->len;

    while (p < last && warmed < NGX_HTTP_CACHE_TURBO_WARM_MAX) {
        comma = ngx_strlchr(p, last, ',');
        if (comma == NULL) {
            comma = last;
        }

        if (comma > p) {
            uri.data = p;
            uri.len = comma - p;
            ngx_str_null(&args);

            /* split off a "?query" suffix; keep it as the subrequest args */
            q = ngx_strlchr(uri.data, uri.data + uri.len, '?');
            if (q != NULL) {
                args.data = q + 1;
                args.len = uri.data + uri.len - (q + 1);
                uri.len = q - uri.data;
            }

            /* percent-decode the path into a fresh buffer (subrequest expects an
             * unescaped uri); decoding never grows the string. */
            if (uri.len > 0 && uri.data[0] == '/') {
                dst = ngx_pnalloc(r->pool, uri.len);
                if (dst == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                s = uri.data;
                {
                    u_char  *d = dst;
                    ngx_unescape_uri(&d, &s, uri.len, 0);
                    uri.data = dst;
                    uri.len = d - dst;
                }

                if (uri.len > 0 && uri.data[0] == '/'
                    && ngx_http_cache_turbo_warm_uri_is_safe(&uri)
                    && ngx_http_cache_turbo_warm_one(r, &uri, &args) == NGX_OK)
                {
                    warmed++;
                }
            }
        }

        p = comma + 1;
    }

    out = ngx_pnalloc(r->pool, sizeof("{\"warmed\":4294967295}\n"));
    if (out == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    body.data = out;
    body.len = ngx_sprintf(out, "{\"warmed\":%ui}\n", warmed) - out;
    return ngx_http_cache_turbo_send_json(r, NGX_HTTP_OK, &body);
}


/* ----- key normalize (v3-1) ------------------------------------------------ */

/* Built-in denylist: query params dropped from $cache_turbo_normalized_args by
 * default. A trailing '*' is a prefix match (so utm_* covers utm_source etc.).
 * cache_turbo_normalize_strip adds to this; it never removes a default. */
static ngx_str_t  ngx_http_cache_turbo_default_strip[] = {
    ngx_string("utm_*"),
    ngx_string("fbclid"),
    ngx_string("gclid"),
    ngx_string("msclkid"),
    ngx_string("mc_eid"),
    ngx_string("_ga"),
    ngx_string("ref"),
    ngx_string("sid"),
    ngx_string("sessionid"),
    ngx_string("tmp_*"),
};


/* Does an arg name match a denylist pattern? Trailing '*' => prefix match. */
static ngx_int_t
ngx_http_cache_turbo_pat_match(ngx_str_t *pat, u_char *name, size_t nlen)
{
    if (pat->len > 0 && pat->data[pat->len - 1] == '*') {
        size_t  plen = pat->len - 1;
        return nlen >= plen && ngx_strncmp(name, pat->data, plen) == 0;
    }
    return nlen == pat->len && ngx_strncmp(name, pat->data, nlen) == 0;
}


/* Is this arg name on the denylist (built-in defaults + configured extras)? */
static ngx_int_t
ngx_http_cache_turbo_name_denied(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *name, size_t nlen)
{
    ngx_str_t   *pat;
    ngx_uint_t   i;

    for (i = 0;
         i < sizeof(ngx_http_cache_turbo_default_strip) / sizeof(ngx_str_t);
         i++)
    {
        if (ngx_http_cache_turbo_pat_match(
                &ngx_http_cache_turbo_default_strip[i], name, nlen))
        {
            return 1;
        }
    }

    if (clcf->normalize_strip != NULL
        && clcf->normalize_strip != NGX_CONF_UNSET_PTR)
    {
        pat = clcf->normalize_strip->elts;
        for (i = 0; i < clcf->normalize_strip->nelts; i++) {
            if (ngx_http_cache_turbo_pat_match(&pat[i], name, nlen)) {
                return 1;
            }
        }
    }

    return 0;
}


/* Stable byte-wise compare of two "name=value" tokens for the sort. */
static ngx_int_t
ngx_http_cache_turbo_tok_cmp(const void *one, const void *two)
{
    const ngx_str_t  *a = one;
    const ngx_str_t  *b = two;
    size_t            n = ngx_min(a->len, b->len);
    ngx_int_t         rc = ngx_memcmp(a->data, b->data, n);

    if (rc != 0) {
        return rc;
    }
    return (ngx_int_t) a->len - (ngx_int_t) b->len;
}


/* ----- Vary-aware suffix (v3-4) --------------------------------------------- */

/* Per-coding q-value check for the Accept-Encoding parser. `p` points at the
 * first ';' of a coding token's parameters, `last` is the token end. Returns 0
 * iff an explicit `q=0` (0, 0.0, 0.000, …) is present — i.e. the client REFUSES
 * this coding — else 1 (a missing q, or any q>0, is acceptable). A bare substring
 * match would treat `gzip;q=0` as gzip-capable and re-key a never-gzip client
 * onto a gzip body (codex follow-up). RFC 9110 §12.5.3. */
static ngx_uint_t
ngx_http_cache_turbo_ae_q_ok(u_char *p, u_char *last)
{
    while (p < last) {
        if (*p != ';') {
            p++;
            continue;
        }
        p++;                                   /* past ';' */
        while (p < last && (*p == ' ' || *p == '\t')) {
            p++;
        }
        if (p + 1 < last && (p[0] == 'q' || p[0] == 'Q') && p[1] == '=') {
            ngx_uint_t  nonzero = 0;
            p += 2;
            while (p < last && *p != ';' && *p != ' ' && *p != '\t') {
                if (*p >= '1' && *p <= '9') {
                    nonzero = 1;
                }
                p++;
            }
            return nonzero ? 1 : 0;            /* q=0(.0…) => refused */
        }
    }
    return 1;                                  /* no q parameter => acceptable */
}


/* Accept-Encoding collapsed to a small, stable enum so the cache shards by what
 * the response actually IS (zstd/br/gzip/identity), not by the per-browser raw
 * header. Priority zstd > br > gzip mirrors what our stack serves when the client
 * accepts several: the http-zstd filter emits zstd whenever the client advertises
 * zstd (ngx_http_zstd_ok), winning over brotli/gzip, and brotli wins over gzip.
 * We ship http-zstd, so zstd MUST be bucketed or a zstd-only client could read an
 * identity entry and a zstd+br client could collide a zstd body under ae=br
 * (issues V6). Absent/empty header => identity.
 *
 * The header is tokenised on commas into full codings (each `coding[;params]`)
 * rather than substring-scanned, so `br` no longer matches inside `Calibre`,
 * `x-gzip` no longer aliases `gzip`, and a `;q=0` parameter de-selects the coding
 * (codex follow-up: token boundaries + q-values). Coding names are matched
 * case-insensitively at exact length. */
static const char *
ngx_http_cache_turbo_ae_class(ngx_http_request_t *r)
{
    ngx_table_elt_t  *ae = r->headers_in.accept_encoding;
    u_char           *p, *last, *end, *tok, *semi, *ce;
    size_t            clen;
    ngx_uint_t        zstd = 0, br = 0, gzip = 0;

    if (ae == NULL || ae->value.len == 0) {
        return "identity";
    }

    p = ae->value.data;
    last = p + ae->value.len;

    while (p < last) {
        end = p;                               /* split on the next comma */
        while (end < last && *end != ',') {
            end++;
        }

        semi = p;                              /* coding name = [tok, semi) */
        while (semi < end && *semi != ';') {
            semi++;
        }

        tok = p;
        while (tok < semi && (*tok == ' ' || *tok == '\t')) {
            tok++;
        }
        ce = semi;
        while (ce > tok && (ce[-1] == ' ' || ce[-1] == '\t')) {
            ce--;
        }
        clen = (size_t) (ce - tok);

        if (clen > 0 && ngx_http_cache_turbo_ae_q_ok(semi, end)) {
            if (clen == 4 && ngx_strncasecmp(tok, (u_char *) "zstd", 4) == 0) {
                zstd = 1;
            } else if (clen == 2
                       && ngx_strncasecmp(tok, (u_char *) "br", 2) == 0) {
                br = 1;
            } else if (clen == 4
                       && ngx_strncasecmp(tok, (u_char *) "gzip", 4) == 0) {
                gzip = 1;
            }
        }

        p = (end < last) ? end + 1 : end;
    }

    if (zstd) {
        return "zstd";
    }
    if (br) {
        return "br";
    }
    if (gzip) {
        return "gzip";
    }
    return "identity";
}


/* Device class from the User-Agent, coarse two-way bucket. Minimal substring
 * match for the standard mobile UA tokens (no regex: the module builds
 * --without-http_rewrite_module, no PCRE). Case-insensitive — core only ships a
 * bounded case-insensitive search (ngx_strlcasestrn); case-folding mobile tokens
 * is harmless. Tablets fall in desktop by design. */
static const char *
ngx_http_cache_turbo_device_class(ngx_http_request_t *r)
{
    ngx_table_elt_t  *ua = r->headers_in.user_agent;
    u_char           *s, *last;

    if (ua == NULL || ua->value.len == 0) {
        return "desktop";
    }

    s = ua->value.data;
    last = s + ua->value.len;

    if (ngx_strlcasestrn(s, last, (u_char *) "mobi", 4 - 1) != NULL
        || ngx_strlcasestrn(s, last, (u_char *) "android", 7 - 1) != NULL
        || ngx_strlcasestrn(s, last, (u_char *) "iphone", 6 - 1) != NULL)
    {
        return "mobile";
    }
    return "desktop";
}


/* Write the Vary suffix selected by the loc_conf bitmask into buf (>= MAX) and
 * return its byte length. Buckets are emitted in a FIXED order (ae then dev)
 * regardless of the directive's token order, so the key is deterministic. The
 * 0x1F (US) delimiter can never appear in a query string, so the suffix cannot
 * collide with a real arg value. Returns 0 when vary is UNSET/off. */
static size_t
ngx_http_cache_turbo_vary_suffix(ngx_http_request_t *r, ngx_int_t vary,
    u_char *buf)
{
    const char  *cls;
    u_char      *w = buf;

    if (vary == NGX_CONF_UNSET || vary == 0) {
        return 0;
    }

    if (vary & NGX_HTTP_CACHE_TURBO_VARY_ENCODING) {
        cls = ngx_http_cache_turbo_ae_class(r);
        *w++ = 0x1F;
        w = ngx_cpymem(w, "ae=", 3);
        w = ngx_cpymem(w, cls, ngx_strlen(cls));
    }

    if (vary & NGX_HTTP_CACHE_TURBO_VARY_DEVICE) {
        cls = ngx_http_cache_turbo_device_class(r);
        *w++ = 0x1F;
        w = ngx_cpymem(w, "dev=", 4);
        w = ngx_cpymem(w, cls, ngx_strlen(cls));
    }

    return w - buf;
}


/* Set the variable to a pool-owned copy of len bytes of src, or the empty string
 * when len == 0. Shared "emit these bytes or nothing" tail for the argless output
 * paths (no args / strip_all / everything denied), where the suffix stands alone
 * with no leading '?'. */
static ngx_int_t
ngx_http_cache_turbo_var_set(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, u_char *src, size_t len)
{
    u_char  *out;

    if (len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    out = ngx_pnalloc(r->pool, len);
    if (out == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(out, src, len);
    v->len = len;
    v->data = out;

    return NGX_OK;
}


/* --- auto-Vary (v11 other half) helpers --- */

/* Find a request header by (case-insensitive) name; returns its value or an
 * empty string when absent. Used for the raw-valued auto-Vary axes (Accept-
 * Language, Origin) that core does not expose as a typed field. */
static ngx_str_t
ngx_http_cache_turbo_req_header(ngx_http_request_t *r, const char *name,
    size_t nlen)
{
    ngx_list_part_t  *part = &r->headers_in.headers.part;
    ngx_table_elt_t  *h = part->elts;
    ngx_str_t         out = ngx_null_string;
    ngx_uint_t        i;

    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (h[i].hash == 0 || h[i].key.len != nlen) {
            continue;
        }
        if (ngx_strncasecmp(h[i].key.data, (u_char *) name, nlen) == 0) {
            return h[i].value;
        }
    }

    return out;
}


/* Accept-Language collapsed to the PRIMARY SUBTAG only, lowercased, so
 * `en-US,en;q=0.9` and `en-GB,en;q=0.8` fold to the same "en" class instead of
 * spawning a distinct variant per raw header string (i18n keyspace blowup).
 * Policy: take the first language-range of the header, cut at '-', drop any
 * ';q=' parameter, lowercase. Absent/empty/malformed header folds to the empty
 * class "" (NOT skipped — skipping the axis would collide with a genuinely
 * empty-but-present header). Result is capped at LANG_CLASS_MAX bytes; a
 * longer primary subtag is truncated, not rejected.
 *
 * Unlike ae_class/device_class this returns into a caller buffer rather than a
 * static string: the class is a truncated, lowercased slice of the raw header,
 * not a fixed enum member. len (out) is 0..LANG_CLASS_MAX.
 *
 * Unlike the COR-5 purge generation (folded ONLY when bumped, so an unpurged
 * base keeps its pre-upgrade variant key), this fold applies unconditionally:
 * every LANG-varying entry's variant key changes on upgrade (base keys are
 * unaffected — only the auto-Vary variant suffix moves). That one-time
 * keyspace turnover is the accepted, expected cost of collapsing the
 * raw-header keyspace to primary-subtag classes. */
#define NGX_HTTP_CACHE_TURBO_LANG_CLASS_MAX  8

static size_t
ngx_http_cache_turbo_lang_class(ngx_http_request_t *r, u_char *buf)
{
    ngx_str_t   v;
    u_char     *s, *last;
    size_t      len;

    v = ngx_http_cache_turbo_req_header(r, "Accept-Language",
                                        sizeof("Accept-Language") - 1);

    if (v.len == 0) {
        return 0;
    }

    s = v.data;
    last = v.data + v.len;

    /* first language-range = up to the first ',' */
    while (s < last && *s != ',') {
        s++;
    }
    last = s;
    s = v.data;

    /* primary subtag = up to the first '-' (also stops at ';q=' since ';'
     * terminates the range the same way '-' does for subtags) */
    while (s < last && *s != '-' && *s != ';') {
        s++;
    }

    len = (size_t) (s - v.data);
    if (len > NGX_HTTP_CACHE_TURBO_LANG_CLASS_MAX) {
        len = NGX_HTTP_CACHE_TURBO_LANG_CLASS_MAX;
    }

    ngx_strlow(buf, v.data, len);

    return len;
}


/* Derive the secondary VARIANT key from the base key material plus the request
 * values of the named (whitelisted) Vary axes. Axes are folded in a FIXED order
 * (ae, dev, lang, origin) regardless of the response Vary token order, so two
 * nodes / two requests with the same axis values compute the same key. Encoding,
 * device, and language (S7: primary-subtag class) are all bucketed to a class;
 * origin alone folds its raw value (CORS security boundary — see lang_class's
 * docstring for why LANG is classed but ORIGIN is not). The 0x1F (US) delimiter
 * can never appear in a URI or these header values, so the suffix cannot
 * collide with the base material. md5 fills the low 16 bytes; the high 16 are
 * zeroed first (the slot layout matches build_key, so a base and a variant
 * only ever differ by the folded bytes). */
static void
ngx_http_cache_turbo_variant_hash(ngx_http_request_t *r, ngx_str_t *base,
    ngx_int_t bits, ngx_uint_t gen, u_char out[32])
{
    ngx_http_cache_turbo_digest_t  d;
    const char                    *cls;
    ngx_str_t                      v;
    static const u_char            us = 0x1F;

    ngx_http_cache_turbo_digest_init(&d);
    ngx_http_cache_turbo_digest_update(&d, base->data, base->len);

    /* PURGE generation (COR-5 / AUD-GEN1): folded UNCONDITIONALLY, including
     * gen == 0. The generation lives in one marker byte (marker_store truncates
     * to gen & 0xFF), so the 256th purge on a base wraps back to the SAME byte
     * value as a base that was never purged. Folding was previously skipped
     * for gen == 0 (treated as a "never purged" sentinel, kept for pre-COR-5
     * upgrade compatibility) -- that made the wrap land EXACTLY on the
     * untagged/never-purged variant keyspace, so a variant purged 256 times
     * could resurrect as a live HIT if its pre-purge/never-purged sibling was
     * still resident (long TTL / keep_stale forever / L1 LRU). Folding gen=0
     * too closes that specific collision at the cost of a one-time keyspace
     * turnover on upgrade (existing warm untagged entries stop matching and
     * are refetched once). A residual collision between generation N and
     * N+256 on the SAME base is NOT eliminated by this alone -- it is an
     * inherent limit of a one-byte counter, not the sentinel-vs-legacy
     * collision this fix closes; see AUD-GEN1 for the accepted trade-off and
     * the byte-widening follow-up it leaves open. */
    {
        u_char  gbuf[NGX_INT_T_LEN];
        size_t  glen;

        glen = (size_t) (ngx_sprintf(gbuf, "%ui", gen) - gbuf);
        ngx_http_cache_turbo_digest_update(&d, &us, 1);
        ngx_http_cache_turbo_digest_update(&d, "gen=", 4);
        ngx_http_cache_turbo_digest_update(&d, gbuf, glen);
    }

    if (bits & NGX_HTTP_CACHE_TURBO_VARY_ENCODING) {
        cls = ngx_http_cache_turbo_ae_class(r);
        ngx_http_cache_turbo_digest_update(&d, &us, 1);
        ngx_http_cache_turbo_digest_update(&d, "ae=", 3);
        ngx_http_cache_turbo_digest_update(&d, cls, ngx_strlen(cls));
    }
    if (bits & NGX_HTTP_CACHE_TURBO_VARY_DEVICE) {
        cls = ngx_http_cache_turbo_device_class(r);
        ngx_http_cache_turbo_digest_update(&d, &us, 1);
        ngx_http_cache_turbo_digest_update(&d, "dev=", 4);
        ngx_http_cache_turbo_digest_update(&d, cls, ngx_strlen(cls));
    }
    if (bits & NGX_HTTP_CACHE_TURBO_VARY_LANG) {
        u_char  lbuf[NGX_HTTP_CACHE_TURBO_LANG_CLASS_MAX];
        size_t  llen;

        llen = ngx_http_cache_turbo_lang_class(r, lbuf);
        ngx_http_cache_turbo_digest_update(&d, &us, 1);
        ngx_http_cache_turbo_digest_update(&d, "lang=", 5);
        ngx_http_cache_turbo_digest_update(&d, lbuf, llen);
    }
    if (bits & NGX_HTTP_CACHE_TURBO_VARY_ORIGIN) {
        v = ngx_http_cache_turbo_req_header(r, "Origin", sizeof("Origin") - 1);
        ngx_http_cache_turbo_digest_update(&d, &us, 1);
        ngx_http_cache_turbo_digest_update(&d, "org=", 4);
        ngx_http_cache_turbo_digest_update(&d, v.data, v.len);
    }

    ngx_http_cache_turbo_digest_final(&d, out);
}


/* The dedicated L1 slot key for the vary marker of a base key. Distinct from the
 * object key (it folds a "varymark" tag) so the marker never collides with an
 * object slot or a cold-miss stub. */
static void
ngx_http_cache_turbo_marker_hash(ngx_str_t *base, u_char out[32])
{
    ngx_http_cache_turbo_digest_t  d;
    static const u_char            us = 0x1F;

    ngx_http_cache_turbo_digest_init(&d);
    ngx_http_cache_turbo_digest_update(&d, base->data, base->len);
    ngx_http_cache_turbo_digest_update(&d, &us, 1);
    ngx_http_cache_turbo_digest_update(&d, "varymark", sizeof("varymark") - 1);
    ngx_http_cache_turbo_digest_final(&d, out);
}


/* COR-5: build the per-base variant-index "tag name" into buf (>= 1 + 64). The
 * index reuses the L2 tag set machinery (SADD member + EXPIRE NX/GT, purge via
 * SMEMBERS); this name lands the set under <prefix>tag:<name>. A LEADING SPACE
 * frames it so no user `cache_turbo_tag` token can ever equal it: tag tokens are
 * split on whitespace, so a token can never contain a space. The body is the
 * 64-hex of a "varidx"-tagged digest of the base key material (deterministic
 * across nodes, like the variant/marker hashes). Returns the byte length. */
static size_t
ngx_http_cache_turbo_variant_index_name(ngx_str_t *base, u_char *buf)
{
    ngx_http_cache_turbo_digest_t  d;
    u_char                         h[32];
    u_char                        *p;
    static const u_char            us = 0x1F;

    ngx_http_cache_turbo_digest_init(&d);
    ngx_http_cache_turbo_digest_update(&d, base->data, base->len);
    ngx_http_cache_turbo_digest_update(&d, &us, 1);
    ngx_http_cache_turbo_digest_update(&d, "varidx", sizeof("varidx") - 1);
    ngx_http_cache_turbo_digest_final(&d, h);

    buf[0] = ' ';
    p = ngx_hex_dump(buf + 1, h, 32);
    return (size_t) (p - buf);
}


/* Store/refresh the L1 vary marker for a base key: a one-byte body carrying the
 * active-axis bitmask, wrapped in the standard blob header so a later read can
 * validate the magic before trusting the byte. L1-only and node-local by design
 * (see the loc_conf auto_vary comment); shm store copies the stack blob in. */
static void
ngx_http_cache_turbo_marker_store(ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_http_cache_turbo_zone_t *z, ngx_str_t *base, ngx_int_t bits,
    ngx_uint_t gen, time_t ttl)
{
    u_char                           mk[32];
    u_char                           blob[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE
                                          + 2];
    ngx_http_cache_turbo_blob_hdr_t  bh;

    ngx_memzero(&bh, sizeof(bh));
    /* A marker is a blob, so it must satisfy the blob contract: since AUD-HDR1
     * blob_validate() rejects a status outside 100..599, a memzero'd status 0
     * would make every marker unreadable. 200 is the only honest choice (the
     * marker records a successful classification); the body is still the 2-byte
     * [bits][gen] pair, which is what the readers actually consume. Markers are
     * L1-only and node-local, so any warm pre-AUD-HDR1 marker simply fails
     * validation once and is re-stored. */
    bh.status = NGX_HTTP_OK;
    bh.body_len = 2;
    bh.created = (int64_t) ngx_time();
    bh.fresh_ttl = (uint32_t) (ttl > 0 ? ttl : 0);
    bh.stale_ttl = (uint32_t) ngx_http_cache_turbo_stale_ttl(ttl,
                       clcf->stale_mult);
    ngx_http_cache_turbo_blob_hdr_write(blob, &bh);
    /* body = [axis bitmask][purge generation] (COR-5). The generation lets the
     * L1-only purge path orphan an old generation's variants by bumping it. */
    blob[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE]     = (u_char) (bits & 0xFF);
    blob[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 1] = (u_char) (gen & 0xFF);

    ngx_http_cache_turbo_marker_hash(base, mk);

    (void) clcf->l1->store(z, mk, ngx_crc32_short(mk, 32),
               blob, sizeof(blob), ttl,
               ngx_http_cache_turbo_stale_ttl(ttl, clcf->stale_mult));
}


/* Probe the L1 vary marker for the request's base key. If a fresh marker exists,
 * recompute ctx->key_hash to the variant key (and the caller's crc32) so the
 * whole lookup/single-flight/serve flow below runs on the variant. No marker =>
 * key_hash unchanged (base key) => a miss to origin, never a wrong-variant
 * serve. L1-only: cross-node first-hit re-fetches once per node until its marker
 * warms (the safe, non-invasive trade documented on loc_conf.auto_vary). */
static void
ngx_http_cache_turbo_vary_resolve(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_ctx_t *ctx, uint32_t *hash)
{
    u_char                        mk[32];
    ngx_int_t                     bits = 0;
    ngx_uint_t                    gen = 0;
    ngx_http_cache_turbo_node_t  *m;

    ngx_http_cache_turbo_marker_hash(&ctx->cache_key, mk);

    ngx_shmtx_lock(&z->shpool->mutex);
    m = clcf->l1->lookup(z, mk, ngx_crc32_short(mk, 32));
    /* Accept a stale-but-serveable marker, not only a fresh one (codex
     * follow-up): the object variants it points at are themselves served stale
     * within their stale window, so gating the marker on fresh_until alone made
     * those stale variants unreachable (the request fell back to the base key
     * and re-fetched). The marker is refreshed on every variant store, so it
     * only goes stale alongside its objects. stale_until == 0 => forever. */
    if (m != NULL && m->data != NULL
        && m->len >= NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 1
        && (m->stale_until == 0 || ngx_time() < m->stale_until))
    {
        /* Validate the marker's blob magic+version before trusting the bits byte
         * (the marker key folds "varymark" so a real object can't normally land
         * here, but a hash collision must not be read as an axis bitmask). The
         * 1-byte body sits just past the fixed wire header. */
        ngx_http_cache_turbo_blob_hdr_t  mh;
        if (ngx_http_cache_turbo_blob_validate(m->data, m->len, &mh, NULL, NULL)
            == NGX_OK)
        {
            bits = m->data[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE];
            /* COR-5: the purge generation lives in the 2nd body byte. Older
             * 1-byte markers (pre-COR-5, still warm in L1 after upgrade) lack
             * it => treat as gen 0. */
            if (m->len >= NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 2) {
                gen = m->data[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 1];
            }
        }
    }
    ngx_shmtx_unlock(&z->shpool->mutex);

    /* Carry the generation to the store path so the variant key + the refreshed
     * marker agree on it (store reuses ctx->vary_gen). */
    ctx->vary_gen = gen;

    if (bits > 0) {
        ngx_http_cache_turbo_variant_hash(r, &ctx->cache_key, bits, gen,
                                          ctx->key_hash);
        *hash = ngx_crc32_short(ctx->key_hash, 32);
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: auto-Vary marker hit \"%V\" bits=0x%xi "
                       "-> variant key", &r->uri, bits);
    }
}


/* True if the response already carries a non-identity Content-Encoding.
 *
 * SEC: a coding-specific body must never be cached under our encoding-blind
 * key. The filter-order fix (no ngx_module_order in `config`, so a lone
 * --add-dynamic-module registers LAST = TOP-most output filter; cache_turbo is
 * also kept the last --add-dynamic-module in the angie/nginx package build)
 * puts our body filter ABOVE the gzip/zstd/brotli filters, so a normal
 * compressed page reaches this filter as IDENTITY (no Content-Encoding yet)
 * and is captured uncompressed — the
 * compression filter then re-encodes it per client on both MISS and HIT. A
 * Content-Encoding still present here therefore means either the ORIGIN
 * pre-compressed the response (we hold no identity copy to re-encode) or we
 * were mis-ordered below a compressor. In both cases the stored bytes are
 * specific to one coding; replaying them to a client that negotiated a
 * different Accept-Encoding yields a browser "Content Encoding Error". Refuse
 * to capture rather than corrupt — this is the defense-in-depth guard that
 * holds even if the filter order is ever wrong. (Walks the typed field, which
 * upstream/proxy and the compression filters both populate.) */
static ngx_uint_t
ngx_http_cache_turbo_response_encoded(ngx_http_request_t *r)
{
    ngx_table_elt_t  *ce = r->headers_out.content_encoding;

    if (ce == NULL || ce->hash == 0 || ce->value.len == 0) {
        return 0;
    }

    /* "identity" is the no-op coding — safe to cache as-is. */
    if (ce->value.len == sizeof("identity") - 1
        && ngx_strncasecmp(ce->value.data, (u_char *) "identity",
                           sizeof("identity") - 1) == 0)
    {
        return 0;
    }

    return 1;
}


/* Classify the response Vary header into a safe-axis bitmask (what we may key
 * on) and a nocache veto. Only the whitelist (Accept-Encoding, User-Agent,
 * Accept-Language, Origin) contributes to the key. Anything else — Vary: *,
 * Cookie, Authorization, OR any header we cannot key on — forces the response
 * uncacheable, because serving one stored representation for every value of an
 * un-split Vary axis would return the wrong representation (RFC 9110 12.5.5).
 * Walks every Vary header instance and tokenises on comma/whitespace. */
static void
ngx_http_cache_turbo_classify_vary(ngx_http_request_t *r,
    ngx_int_t *bits_out, ngx_uint_t *nocache_out)
{
    ngx_list_part_t  *part = &r->headers_out.headers.part;
    ngx_table_elt_t  *h = part->elts;
    ngx_int_t         bits = 0;
    ngx_uint_t        nocache = 0;
    ngx_uint_t        i;

    for (i = 0; /* void */ ; i++) {
        u_char  *s, *e, *tok;

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (h[i].hash == 0
            || h[i].key.len != sizeof("Vary") - 1
            || ngx_strncasecmp(h[i].key.data, (u_char *) "Vary",
                               sizeof("Vary") - 1) != 0)
        {
            continue;
        }

        s = h[i].value.data;
        e = s + h[i].value.len;

        while (s < e) {
            size_t  tl;

            while (s < e && (*s == ' ' || *s == '\t' || *s == ',')) {
                s++;
            }
            tok = s;
            while (s < e && *s != ' ' && *s != '\t' && *s != ',') {
                s++;
            }
            tl = (size_t) (s - tok);
            if (tl == 0) {
                continue;
            }

            if (tl == 1 && tok[0] == '*') {
                nocache = 1;
            } else if (tl == sizeof("Cookie") - 1
                && ngx_strncasecmp(tok, (u_char *) "Cookie", tl) == 0) {
                nocache = 1;
            } else if (tl == sizeof("Authorization") - 1
                && ngx_strncasecmp(tok, (u_char *) "Authorization", tl) == 0) {
                nocache = 1;
            } else if (tl == sizeof("Accept-Encoding") - 1
                && ngx_strncasecmp(tok, (u_char *) "Accept-Encoding", tl) == 0) {
                bits |= NGX_HTTP_CACHE_TURBO_VARY_ENCODING;
            } else if (tl == sizeof("User-Agent") - 1
                && ngx_strncasecmp(tok, (u_char *) "User-Agent", tl) == 0) {
                bits |= NGX_HTTP_CACHE_TURBO_VARY_DEVICE;
            } else if (tl == sizeof("Accept-Language") - 1
                && ngx_strncasecmp(tok, (u_char *) "Accept-Language", tl) == 0) {
                bits |= NGX_HTTP_CACHE_TURBO_VARY_LANG;
            } else if (tl == sizeof("Origin") - 1
                && ngx_strncasecmp(tok, (u_char *) "Origin", tl) == 0) {
                bits |= NGX_HTTP_CACHE_TURBO_VARY_ORIGIN;
            } else {
                /* A Vary axis we cannot key on. Caching anyway would serve one
                 * stored representation for every value of this header — i.e.
                 * the wrong representation (RFC 9110 12.5.5 / RFC 9111 4.1).
                 * Refuse to cache, same as Cookie/Authorization/"*". */
                nocache = 1;
            }
        }
    }

    /* A refused axis wins over any safe axis: don't cache a response that also
     * varies on Cookie, Authorization or "*", even if it also names a safe one. */
    if (nocache) {
        bits = 0;
    }

    *bits_out = bits;
    *nocache_out = nocache;
}


/*
 * $cache_turbo_normalized_args: rebuild r->args dropping denylisted params and
 * sorting what remains, prefixed with '?', then append the Vary-aware suffix
 * (v3-4) if enabled. Empty string when there is nothing to keep AND no suffix, so
 * the variable can be concatenated straight into a cache key. The suffix is
 * appended on every path — including the argless ones — so two requests that
 * differ only by encoding/device still split into separate slots. Computed in
 * r->pool; r->args is left untouched so application logic still sees the original
 * query string.
 */
static ngx_int_t
ngx_http_cache_turbo_normalized_args_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf;
    ngx_str_t                        *toks;
    u_char                           *p, *last, *amp, *eq, *out, *w;
    u_char                            vbuf[NGX_HTTP_CACHE_TURBO_VARY_SUFFIX_MAX];
    size_t                            nlen, total, vlen;
    ngx_uint_t                        n, i, kept;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    vlen = ngx_http_cache_turbo_vary_suffix(r, clcf->normalize_vary, vbuf);

    /* No args at all (or all stripped below): output is the Vary suffix alone
     * (no '?'). To drop every arg explicitly, use `cache_turbo_normalize_strip *`
     * — a bare '*' is a zero-length prefix that matches every name. */
    if (r->args.len == 0) {
        return ngx_http_cache_turbo_var_set(r, v, vbuf, vlen);
    }

    /* Upper bound on token count = number of '&' + 1. */
    n = 1;
    for (p = r->args.data, last = p + r->args.len; p < last; p++) {
        if (*p == '&') {
            n++;
        }
    }

    /* ngx_str_t array needs pointer alignment -> ngx_palloc, NEVER ngx_pnalloc
     * (byte-aligned -> UBSan misalign trap; same class as issues C3 / v2c). */
    toks = ngx_palloc(r->pool, n * sizeof(ngx_str_t));
    if (toks == NULL) {
        return NGX_ERROR;
    }

    /* Split on '&', keep the full "name=value" of each non-denied param. */
    kept = 0;
    total = 0;
    p = r->args.data;
    last = p + r->args.len;
    while (p < last) {
        amp = ngx_strlchr(p, last, '&');
        if (amp == NULL) {
            amp = last;
        }

        if (amp > p) {                       /* skip empty tokens ("&&", "&") */
            eq = ngx_strlchr(p, amp, '=');
            nlen = eq ? (size_t) (eq - p) : (size_t) (amp - p);

            if (!ngx_http_cache_turbo_name_denied(clcf, p, nlen)) {
                toks[kept].data = p;
                toks[kept].len = amp - p;
                total += toks[kept].len;
                kept++;
            }
        }

        p = amp + 1;
    }

    if (kept == 0) {
        /* every arg denied: output is the Vary suffix alone (no '?'). */
        return ngx_http_cache_turbo_var_set(r, v, vbuf, vlen);
    }

    /* Stable alpha sort so ?b=2&a=1 and ?a=1&b=2 normalize identically. */
    ngx_sort(toks, kept, sizeof(ngx_str_t), ngx_http_cache_turbo_tok_cmp);

    total += 1 + (kept - 1);                  /* leading '?' + '&' separators  */
    total += vlen;                            /* Vary suffix (v3-4)            */

    out = ngx_pnalloc(r->pool, total);        /* raw bytes -> pnalloc is fine  */
    if (out == NULL) {
        return NGX_ERROR;
    }

    w = out;
    *w++ = '?';
    for (i = 0; i < kept; i++) {
        if (i) {
            *w++ = '&';
        }
        w = ngx_cpymem(w, toks[i].data, toks[i].len);
    }
    if (vlen) {
        w = ngx_cpymem(w, vbuf, vlen);
    }

    v->len = w - out;
    v->data = out;

    return NGX_OK;
}


static ngx_str_t  ngx_http_cache_turbo_normalized_args_name =
    ngx_string("cache_turbo_normalized_args");


/*
 * $cache_turbo_beta — the beta the SWR dice would use for a request in this
 * location right now (×1000), i.e. the static preset/explicit beta, or, when
 * cache_turbo_autotune is on and a live verdict is published, that verdict
 * re-clamped to this location's preset band. Read-only introspection (v4-3): lets
 * an operator log the live tuning, and lets the test suite observe the per-location
 * band clamp (the zone-level verdict in the admin stats is pre-clamp). Not
 * cacheable — it tracks live autotune state. */
static ngx_str_t  ngx_http_cache_turbo_beta_name =
    ngx_string("cache_turbo_beta");


/*
 * $cache_turbo_active (Q1) — "1" when cache-turbo is engaged for this request
 * (enabled, cacheable method, main request) AND cache_turbo_suppress_native is
 * on for the location; "0" otherwise. Wire it into a stacked native cache as
 * `proxy_no_cache $cache_turbo_active; proxy_cache_bypass $cache_turbo_active;`
 * so proxy_cache/fastcgi_cache defers to cache-turbo instead of double-caching.
 * With suppress_native off (default) it is always "0", so the wiring is a safe
 * no-op until the operator opts in. Not cacheable — it is per-request state. */
static ngx_str_t  ngx_http_cache_turbo_active_name =
    ngx_string("cache_turbo_active");


/*
 * $cache_turbo_status — the per-request serve outcome, for access logging.
 * Tokens mirror nginx's $upstream_cache_status so the two can be graphed
 * together:
 *   HIT     served fresh from L1/L2
 *   STALE   served stale while a refresh runs (incl. stale-if-error)
 *   EXPIRED a cached entry was found past its serveable window and refetched
 *           from origin (distinct from a true cold miss)
 *   MISS    no serveable entry anywhere -> origin (cold miss / store path), or
 *           an only-if-cached request the cache could not satisfy (504)
 *   BYPASS  skipped to origin by cache_turbo_bypass or a CMS backend preset
 * A request cache-turbo never engaged (cache off / not a main GET) resolves to
 * "-" (not_found). Drop it in a log_format, e.g.
 *   log_format ct '$request "$cache_turbo_status" $upstream_response_time';
 */
static ngx_str_t  ngx_http_cache_turbo_status_name =
    ngx_string("cache_turbo_status");


/*
 * $cache_turbo_serve_reason (S7.2) -- the UNFOLDED per-request serve outcome,
 * for access logging. Unlike $cache_turbo_status (which folds every non-HIT
 * reason to STALE for $upstream_cache_status compatibility and MUST keep
 * doing so -- do not change that fold), this variable keeps the reason
 * distinct:
 *   FRESH            served fresh from L1/L2 ($cache_turbo_status: HIT)
 *   STALE            served stale while a refresh runs
 *   STALE-IF-ERROR   RFC 5861 serve-on-error replacement
 *   STALE-BREAKER    served stale because the breaker is OPEN/HALF_OPEN
 *   BREAKER-503      breaker OPEN, no serveable copy -> local 503, no origin
 * A request cache-turbo never engaged, or one that has not yet reached a
 * serve/503 decision, resolves to "-" (not_found) -- same convention as
 * $cache_turbo_status.
 */
static ngx_str_t  ngx_http_cache_turbo_serve_reason_name =
    ngx_string("cache_turbo_serve_reason");


static ngx_int_t
ngx_http_cache_turbo_beta_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf;
    ngx_http_cache_turbo_zone_t      *z;
    ngx_int_t                         beta;
    u_char                           *p;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);

    if (clcf->shm_zone == NULL) {
        beta = clcf->beta;            /* not a caching location: static beta */

    } else {
        z = clcf->shm_zone->data;
        beta = ngx_http_cache_turbo_effective_beta(clcf, z);
    }

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", beta) - p;
    v->data = p;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_cache_turbo_active_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf;
    ngx_http_cache_turbo_ctx_t       *ctx;
    ngx_uint_t                        active = 0;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_cache_turbo_module);

    if (clcf->enable && clcf->suppress_native && ctx && ctx->ct_active) {
        active = 1;
    }

    v->len = 1;
    v->data = (u_char *) (active ? "1" : "0");
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


/* Keep in sync with the NGX_HTTP_CACHE_TURBO_ST_* macros in the .h. */
static const char *
ngx_http_cache_turbo_status_str(ngx_uint_t st)
{
    switch (st) {
    case NGX_HTTP_CACHE_TURBO_ST_HIT:     return "HIT";
    case NGX_HTTP_CACHE_TURBO_ST_STALE:   return "STALE";
    case NGX_HTTP_CACHE_TURBO_ST_BYPASS:  return "BYPASS";
    case NGX_HTTP_CACHE_TURBO_ST_EXPIRED: return "EXPIRED";
    default:                              return "MISS";
    }
}


static ngx_int_t
ngx_http_cache_turbo_status_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_cache_turbo_ctx_t  *ctx;
    const char                  *s;

    ctx = ngx_http_get_module_ctx(r, ngx_http_cache_turbo_module);
    if (ctx == NULL) {
        /* cache-turbo never engaged for this request -> "-" in the access log. */
        v->not_found = 1;
        return NGX_OK;
    }

    s = ngx_http_cache_turbo_status_str(ctx->status);
    v->data = (u_char *) s;
    v->len = ngx_strlen(s);
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


/* Keep in sync with the NGX_HTTP_CACHE_TURBO_SR_* macros in the .h. */
static const char *
ngx_http_cache_turbo_serve_reason_str(ngx_uint_t sr)
{
    switch (sr) {
    case NGX_HTTP_CACHE_TURBO_SR_FRESH:           return "FRESH";
    case NGX_HTTP_CACHE_TURBO_SR_STALE:           return "STALE";
    case NGX_HTTP_CACHE_TURBO_SR_STALE_IF_ERROR:  return "STALE-IF-ERROR";
    case NGX_HTTP_CACHE_TURBO_SR_STALE_BREAKER:   return "STALE-BREAKER";
    case NGX_HTTP_CACHE_TURBO_SR_BREAKER_503:     return "BREAKER-503";
    default:                                      return NULL;
    }
}


static ngx_int_t
ngx_http_cache_turbo_serve_reason_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_cache_turbo_ctx_t  *ctx;
    const char                  *s;

    ctx = ngx_http_get_module_ctx(r, ngx_http_cache_turbo_module);
    if (ctx == NULL) {
        /* cache-turbo never engaged for this request -> "-" in the access log. */
        v->not_found = 1;
        return NGX_OK;
    }

    s = ngx_http_cache_turbo_serve_reason_str(ctx->serve_reason);
    if (s == NULL) {
        /* SR_NONE: engaged but no serve/503 decision recorded yet (e.g. a
         * MISS/BYPASS/EXPIRED path that $cache_turbo_status covers but S7.2
         * has no unfolded reason for) -> "-", same convention as above. */
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = (u_char *) s;
    v->len = ngx_strlen(s);
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_cache_turbo_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_cache_turbo_normalized_args_name,
                                0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_cache_turbo_normalized_args_variable;

    var = ngx_http_add_variable(cf, &ngx_http_cache_turbo_beta_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_cache_turbo_beta_variable;

    var = ngx_http_add_variable(cf, &ngx_http_cache_turbo_active_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_cache_turbo_active_variable;

    var = ngx_http_add_variable(cf, &ngx_http_cache_turbo_status_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_cache_turbo_status_variable;

    var = ngx_http_add_variable(cf, &ngx_http_cache_turbo_serve_reason_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_cache_turbo_serve_reason_variable;

    return NGX_OK;
}


/* cache_turbo_normalize_strip name...  — append extra denylist patterns. */
static char *
ngx_http_cache_turbo_normalize_strip(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;
    ngx_str_t                        *value, *s;
    ngx_uint_t                        i;

    if (clcf->normalize_strip == NGX_CONF_UNSET_PTR) {
        clcf->normalize_strip = ngx_array_create(cf->pool, 8,
                                                 sizeof(ngx_str_t));
        if (clcf->normalize_strip == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        s = ngx_array_push(clcf->normalize_strip);
        if (s == NULL) {
            return NGX_CONF_ERROR;
        }
        *s = value[i];
    }

    return NGX_CONF_OK;
}


/* "cache_turbo_normalize_vary encoding device;" — select which Vary buckets are
 * appended to $cache_turbo_normalized_args (v3-4). Tokens validated at config
 * time; an unknown token is rejected (like cache_turbo_preset). Default off. */
static char *
ngx_http_cache_turbo_normalize_vary(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;
    ngx_str_t                        *value;
    ngx_uint_t                        i;
    ngx_int_t                         vary = 0;

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strcmp(value[i].data, "encoding") == 0) {
            vary |= NGX_HTTP_CACHE_TURBO_VARY_ENCODING;

        } else if (ngx_strcmp(value[i].data, "device") == 0) {
            vary |= NGX_HTTP_CACHE_TURBO_VARY_DEVICE;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid cache_turbo_normalize_vary token \"%V\": "
                "expected encoding and/or device", &value[i]);
            return NGX_CONF_ERROR;
        }
    }

    clcf->normalize_vary = vary;

    return NGX_CONF_OK;
}


/*
 * "cache_turbo_backend_prefix /shop/;"
 *
 * Mount point of a subdirectory install. Rebases r->uri before the preset
 * uris[] tier runs, so "/shop/wp-admin/" matches the "/wp-admin/" needle.
 * See the backend_prefix field comment for why the scope stops there.
 *
 * Both slashes are REQUIRED rather than silently added. A value that does not
 * match the deployed mount produces zero URI-rule coverage — the exact silent
 * failure this directive exists to end — so a malformed one is rejected loudly
 * at config time instead of being coerced into something that merely looks
 * like it works.
 */
static char *
ngx_http_cache_turbo_backend_prefix(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;
    ngx_str_t                        *value;

    if (clcf->backend_prefix != NGX_CONF_UNSET_PTR
        && clcf->backend_prefix != NULL)
    {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].len < 2 || value[1].data[0] != '/'
        || value[1].data[value[1].len - 1] != '/')
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_backend_prefix \"%V\" must begin and end with \"/\" "
            "(e.g. \"/shop/\"); \"/\" alone is the root mount and is the "
            "default behaviour, so it is not a valid value", &value[1]);
        return NGX_CONF_ERROR;
    }

    clcf->backend_prefix = ngx_palloc(cf->pool, sizeof(ngx_str_t));
    if (clcf->backend_prefix == NULL) {
        return NGX_CONF_ERROR;
    }

    *clcf->backend_prefix = value[1];

    return NGX_CONF_OK;
}


/* cache_turbo_bypass_uri prefix...  — DIY equivalent of a preset URI rule. Each
 * prefix is stored verbatim; the request path matches it with the same
 * segment-boundary matcher the presets use. Appends across levels (a location
 * adds to the server-level set) rather than replacing. */
static char *
ngx_http_cache_turbo_bypass_uri(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;
    ngx_str_t                        *value, *s;
    ngx_uint_t                        i;

    if (clcf->bypass_uri == NGX_CONF_UNSET_PTR) {
        clcf->bypass_uri = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (clcf->bypass_uri == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len == 0 || value[i].data[0] != '/') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_bypass_uri prefix \"%V\" must begin with \"/\"",
                &value[i]);
            return NGX_CONF_ERROR;
        }
        s = ngx_array_push(clcf->bypass_uri);
        if (s == NULL) {
            return NGX_CONF_ERROR;
        }
        *s = value[i];
    }

    return NGX_CONF_OK;
}


/* cache_turbo_key_cookie name...  — DIY equivalent of a preset key cookie. The
 * VALUE of each named cookie is folded into the cache key (tier-3 value-keying)
 * so segment variants get their own entries instead of bypassing. EXACT name
 * match. See ngx_http_cache_turbo_build_key for the fold and its security
 * rationale (unforgeable length-prefixed framing, all Cookie headers scanned).
 * Appends across levels. */
static char *
ngx_http_cache_turbo_key_cookie_conf(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;
    ngx_str_t                        *value, *s;
    ngx_uint_t                        i;

    if (clcf->key_cookies == NGX_CONF_UNSET_PTR) {
        clcf->key_cookies = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (clcf->key_cookies == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_key_cookie name must not be empty");
            return NGX_CONF_ERROR;
        }
        s = ngx_array_push(clcf->key_cookies);
        if (s == NULL) {
            return NGX_CONF_ERROR;
        }
        *s = value[i];
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_cache_turbo_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_cache_turbo_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cache_turbo_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->preset = NGX_CONF_UNSET;
    conf->beta_raw = NGX_CONF_UNSET;
    conf->valid_raw = NGX_CONF_UNSET;
    conf->lock_ttl_raw = NGX_CONF_UNSET;
    conf->stale_mult_raw = NGX_CONF_UNSET;
    conf->autotune = NGX_CONF_UNSET;
    conf->cc_mode = NGX_CONF_UNSET_UINT;
    conf->auto_vary = NGX_CONF_UNSET;
    conf->purge = NGX_CONF_UNSET;
    conf->background_update = NGX_CONF_UNSET;
    conf->surrogate_key = NGX_CONF_UNSET;
    conf->lock = NGX_CONF_UNSET;
    conf->lock_timeout = NGX_CONF_UNSET_MSEC;
    conf->min_uses_raw = NGX_CONF_UNSET;
    /* S8: NGX_CONF_UNSET (not 0) so merge can tell "never set here" from an
     * explicit `off`, and an explicit off in a location still beats an
     * inherited `on`. Resolved to 0 (off) or 1..99 in merge_loc_conf. */
    conf->scan_resistant_pct = (ngx_uint_t) NGX_CONF_UNSET;
    conf->min_uses = NGX_CONF_UNSET;
    conf->l2_negative_ttl = NGX_CONF_UNSET;   /* L13; merges to 0 = off */
    conf->keep_stale = NGX_CONF_UNSET;   /* S2.1; merges to 0 = off */
    conf->use_stale = NGX_CONF_UNSET_UINT;   /* S4.1; merges to USE_STALE_DEFAULT */
    conf->breaker_enable = NGX_CONF_UNSET;         /* O4.4; merges to 0 = off */
    conf->breaker_threshold = NGX_CONF_UNSET_UINT; /* O4.2; merges to 0 = off */
    conf->breaker_window = NGX_CONF_UNSET;         /* O4.2; merges to 0 = off */
    conf->breaker_open = NGX_CONF_UNSET;           /* O4.3; see the merge note */
    conf->breaker_retry_after = NGX_CONF_UNSET;    /* BRK-RA1; stays UNSET if
                                                     * never set anywhere,
                                                     * resolved lazily at
                                                     * request time */
    conf->max_size = NGX_CONF_UNSET_SIZE;
    conf->suppress_native = NGX_CONF_UNSET;
    conf->redis_enable = NGX_CONF_UNSET;
    conf->memcached = NGX_CONF_UNSET;
    conf->redis_timeout = NGX_CONF_UNSET_MSEC;
    conf->redis_keepalive = NGX_CONF_UNSET;
    conf->redis_keepalive_timeout = NGX_CONF_UNSET_MSEC;
    conf->memcached_keepalive = NGX_CONF_UNSET;
    conf->memcached_keepalive_timeout = NGX_CONF_UNSET_MSEC;
    conf->redis_db = NGX_CONF_UNSET;
    conf->redis_tls = NGX_CONF_UNSET;
    conf->redis_tls_verify = NGX_CONF_UNSET;
    conf->normalize_strip = NGX_CONF_UNSET_PTR;
    conf->normalize_vary = NGX_CONF_UNSET;
    conf->bypass = NGX_CONF_UNSET_PTR;
    conf->no_store = NGX_CONF_UNSET_PTR;
    conf->bypass_uri = NGX_CONF_UNSET_PTR;
    conf->key_cookies = NGX_CONF_UNSET_PTR;
    conf->backend_prefix = NGX_CONF_UNSET_PTR;
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    conf->test_restore_alloc_fail = NGX_CONF_UNSET;
    conf->test_force_file_buf = NGX_CONF_UNSET;
    conf->test_store_fail = NGX_CONF_UNSET;
    conf->test_scan_max_pages = NGX_CONF_UNSET;
    conf->test_l2_promote_hold_ms = NGX_CONF_UNSET;
#endif
    /* shm_zone, key, redis_addr, redis_prefix default NULL via pcalloc */

    return conf;
}


static char *
ngx_http_cache_turbo_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_cache_turbo_loc_conf_t  *prev = parent;
    ngx_http_cache_turbo_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_size_value(conf->max_size, prev->max_size, 1024 * 1024);
    ngx_conf_merge_value(conf->suppress_native, prev->suppress_native, 0);

    /* backend_presets is an accumulated bitmask (0 = unset), so the standard
     * UNSET-sentinel merge can't be used; inherit the parent's set when this
     * location named no backend of its own (an explicit backend fully
     * overrides, it does not OR with the parent's).
     *
     * `cache_turbo_backend none;` is what makes that overridable downward: it
     * sets the NONE sentinel bit, so the mask is non-zero, so we do NOT inherit
     * — and since NONE matches no registry row, the location ends up with no
     * preset at all. Without it, a server-level preset could never be switched
     * off for a single location. */
    if (conf->backend_presets == 0) {
        conf->backend_presets = prev->backend_presets;
    }

    /*
     * Presets (v3-2). Two-stage so a location's preset can still set the band
     * defaults even when an ANCESTOR already resolved its own effective knobs:
     *
     *  1. Inherit the preset enum down the tree.
     *  2. Inherit the *explicit* (raw) knob values with NGX_CONF_UNSET as the
     *     fallback — NOT a literal. A knob therefore stays UNSET unless a real
     *     cache_turbo_valid/_beta/_lock_ttl directive set it at some level. This
     *     is the crucial bit: if we filled a literal/band default here, that
     *     value would no longer look UNSET to a descendant, so the descendant's
     *     own preset could never override it (the classic merge-poisoning trap).
     *  3. Resolve the effective knob: explicit raw value if set, else this
     *     level's resolved-preset band value. All four knobs (valid, beta,
     *     lock_ttl, stale_mult) follow this same raw/effective split.
     *
     * Net effect: an explicit directive beats a preset; a nearer preset beats a
     * farther one; nothing leaks a band default into the inheritance chain.
     */
    if (conf->preset == NGX_CONF_UNSET) {
        conf->preset = prev->preset;
    }

    /* S8: deliberately NOT band-resolved. No preset enables scan resistance --
     * it is a behaviour change with a keyspace-shape trade-off, so it is opt-in
     * per location and nothing else. Plain inherit, then default to 0 = OFF.
     * An explicit `off` stores 0 (not UNSET), so it correctly overrides an
     * inherited `on` rather than re-inheriting it here. */
    if (conf->scan_resistant_pct == (ngx_uint_t) NGX_CONF_UNSET) {
        conf->scan_resistant_pct = prev->scan_resistant_pct;
    }
    if (conf->scan_resistant_pct == (ngx_uint_t) NGX_CONF_UNSET) {
        conf->scan_resistant_pct = 0;
    }

    {
        ngx_int_t                          p;
        const ngx_http_cache_turbo_band_t  *band;

        p = (conf->preset == NGX_CONF_UNSET)
                ? NGX_HTTP_CACHE_TURBO_PRESET_DEFAULT : conf->preset;
        band = &ngx_http_cache_turbo_bands[p];

        ngx_conf_merge_sec_value(conf->valid_raw, prev->valid_raw,
                                 NGX_CONF_UNSET);
        ngx_conf_merge_value(conf->beta_raw, prev->beta_raw, NGX_CONF_UNSET);
        ngx_conf_merge_sec_value(conf->lock_ttl_raw, prev->lock_ttl_raw,
                                 NGX_CONF_UNSET);
        ngx_conf_merge_value(conf->stale_mult_raw, prev->stale_mult_raw,
                             NGX_CONF_UNSET);
        ngx_conf_merge_value(conf->min_uses_raw, prev->min_uses_raw,
                             NGX_CONF_UNSET);

        conf->valid = (conf->valid_raw == NGX_CONF_UNSET)
                          ? band->valid : conf->valid_raw;
        conf->beta = (conf->beta_raw == NGX_CONF_UNSET)
                          ? band->beta : conf->beta_raw;
        conf->lock_ttl = (conf->lock_ttl_raw == NGX_CONF_UNSET)
                          ? band->lock_ttl : conf->lock_ttl_raw;
        conf->stale_mult = (conf->stale_mult_raw == NGX_CONF_UNSET)
                          ? band->stale_mult : conf->stale_mult_raw;
        conf->min_uses = (conf->min_uses_raw == NGX_CONF_UNSET)
                          ? band->min_uses : conf->min_uses_raw;
    }

    /* L2 negative memo (L13). Deliberately NOT a preset band column: the memo
     * trades L2 coherence for a saved round-trip, and that must be opted into
     * per location rather than inherited from a preset name. Defaults to 0
     * (off) at every preset, so this is inert unless explicitly configured. */
    ngx_conf_merge_sec_value(conf->l2_negative_ttl, prev->l2_negative_ttl, 0);

    /* cache_turbo_keep_stale (S2.1). Plain inherit/default-0, same shape as
     * l2_negative_ttl above -- not a preset band column, and off unless an
     * operator opts in. Consulted on the store path, where a non-zero value
     * widens sie_window (S2.2). */
    ngx_conf_merge_sec_value(conf->keep_stale, prev->keep_stale, 0);

    /* cache_turbo_use_stale (S4.1). Plain inherit/default, same shape as
     * keep_stale above. Default is USE_STALE_DEFAULT (HTTP_500|502|503|504 +
     * ANY_5XX), which reproduces today's unconditional "any 5xx" trigger at
     * ngx_http_cache_turbo_header_filter byte-for-byte -- see the header
     * comment on NGX_HTTP_CACHE_TURBO_USE_STALE_DEFAULT for why the ANY_5XX
     * bit is required to make that true. Consulted on the request path by the
     * stale-if-error gate in ngx_http_cache_turbo_header_filter (S4.2). */
    ngx_conf_merge_uint_value(conf->use_stale, prev->use_stale,
                              NGX_HTTP_CACHE_TURBO_USE_STALE_DEFAULT);

    /* O4.4: the breaker's own on/off switch, independent of clcf->enable and
     * of the threshold/window off-switches below -- see
     * ngx_http_cache_turbo_breaker_should_consult(). */
    ngx_conf_merge_value(conf->breaker_enable, prev->breaker_enable, 0);

    /* P6/O4.2 breaker tuning. Both default to 0, which _breaker_record()
     * treats as INERT (no tripping, no window accounting) -- these are two
     * more of the three independent off-switches alongside breaker_enable
     * above. */
    ngx_conf_merge_uint_value(conf->breaker_threshold,
                              prev->breaker_threshold, 0);
    ngx_conf_merge_sec_value(conf->breaker_window, prev->breaker_window, 0);

    /* P6/O4.3. ⚠ breaker_open merges to a NON-ZERO default, unlike every other
     * breaker field. 0 is not "off" for this one -- it is the one value that
     * WEDGES the breaker: _breaker_state() guards its timed reopen on
     * `open_for > 0`, so with 0 an OPEN breaker never promotes a probe, and
     * since nobody contacts the origin while OPEN no success can ever be
     * recorded to close it either. The breaker would stay open until reload.
     *
     * The whole feature is still off by default via breaker_threshold == 0
     * (which skips the state call outright), so this default only takes effect
     * once an operator switches the breaker on. cache_turbo_breaker_open's
     * custom handler REJECTS an explicit 0 at parse time rather than accept
     * it as a disable -- tracked as O4.3-a -- so 0 can never reach this merge
     * from an explicit directive; NGX_CONF_UNSET is the only way through.
     *
     * 30s is the usual circuit-breaker recovery probe interval: long enough
     * that a dead origin is not re-probed hard, short enough that a recovered
     * one is picked up quickly. */
    ngx_conf_merge_sec_value(conf->breaker_open, prev->breaker_open, 30);

    /* Advisory only; 0 = send no Retry-After at all. cache_turbo_breaker_open
     * is rejected at 0 (see above) but the fully-merged breaker_open here can
     * still legitimately be a small operator-chosen value, so the effective
     * value should track the EFFECTIVE (post-merge) breaker_open rather than
     * a hardcoded constant, keeping the hint in sync with the actual probe
     * interval by default. A `cache_turbo_breaker_retry_after` directive, if
     * given explicitly, always wins -- the auto-track fallback applies only
     * when it was left unset everywhere.
     *
     * BRK-RA1: this merge must NOT default to conf->breaker_open here. nginx
     * merges the enclosing server{} block against http FIRST, before any
     * location merge runs. If nothing sets breaker_retry_after at server
     * scope, that level would resolve to http's breaker_open default (30)
     * -- not NGX_CONF_UNSET -- and every child location leaving it unset
     * would then inherit prev->breaker_retry_after == 30 instead of UNSET,
     * so the location's own breaker_open (e.g. 2s) would never be consulted.
     * Keep this merge plain (prev, else UNSET) so breaker_retry_after stays
     * NGX_CONF_UNSET when nobody set it anywhere; the actual fallback to the
     * effective breaker_open is resolved lazily at request time in
     * ngx_http_cache_turbo_breaker_unavailable(), where clcf is fully merged
     * and request-scoped, so merge order can no longer poison it. */
    ngx_conf_merge_sec_value(conf->breaker_retry_after,
                             prev->breaker_retry_after, NGX_CONF_UNSET);

    /* Per-status TTLs (v6): inherit the rule list if this level set none. */
    if (conf->valid_status == NULL) {
        conf->valid_status = prev->valid_status;
    }

    /* Bypass / no-store predicates (v9). */
    ngx_conf_merge_ptr_value(conf->bypass, prev->bypass, NULL);
    ngx_conf_merge_ptr_value(conf->no_store, prev->no_store, NULL);

    /* Response Cache-Control mode (cache_turbo_cache_control). Default respect.
     * Auto-classify defaults it to "honor" (unless explicitly set in this block)
     * so a backend plugin's own Cache-Control: no-cache on an anon page
     * self-excludes at store time. Done before the merge so an explicit
     * `cache_turbo_cache_control respect;` still wins. honor_cc/ignore_cc are
     * derived from the resolved mode and are what the request path reads. */
    if (NGX_HTTP_CACHE_TURBO_HAS_BACKEND(conf->backend_presets)
        && conf->cc_mode == NGX_CONF_UNSET_UINT)
    {
        conf->cc_mode = NGX_HTTP_CACHE_TURBO_CC_HONOR;
    }
    ngx_conf_merge_uint_value(conf->cc_mode, prev->cc_mode,
                              NGX_HTTP_CACHE_TURBO_CC_RESPECT);
    conf->honor_cc  = (conf->cc_mode == NGX_HTTP_CACHE_TURBO_CC_HONOR);
    conf->ignore_cc = (conf->cc_mode == NGX_HTTP_CACHE_TURBO_CC_IGNORE);
    ngx_conf_merge_value(conf->auto_vary, prev->auto_vary, 0);
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    ngx_conf_merge_value(conf->test_restore_alloc_fail,
                         prev->test_restore_alloc_fail, 0);
    ngx_conf_merge_value(conf->test_force_file_buf,
                         prev->test_force_file_buf, 0);
    ngx_conf_merge_value(conf->test_store_fail,
                         prev->test_store_fail, 0);
    ngx_conf_merge_value(conf->test_scan_max_pages,
                         prev->test_scan_max_pages, 0);
    ngx_conf_merge_value(conf->test_l2_promote_hold_ms,
                         prev->test_l2_promote_hold_ms, 0);
#endif

    /* PURGE method (v14): off by default. */
    ngx_conf_merge_value(conf->purge, prev->purge, 0);
    ngx_conf_merge_value(conf->surrogate_key, prev->surrogate_key, 0);

    /* v8: background update / SWR defaults ON — the dice-winner serves stale and
     * refreshes in the background rather than blocking on origin. */
    ngx_conf_merge_value(conf->background_update, prev->background_update, 1);

    /* v10: cold-miss single-flight defaults ON — concurrent first-hits for one
     * cold key collapse to a single origin fetch; the rest wait up to
     * lock_timeout (default 5s) and serve the filled entry. */
    ngx_conf_merge_value(conf->lock, prev->lock, 1);
    ngx_conf_merge_msec_value(conf->lock_timeout, prev->lock_timeout, 5000);

    /* min_uses (v15) is resolved in the preset block above (H3c): it inherits as
     * min_uses_raw with an UNSET fallback and resolves against the band, exactly
     * like valid/beta/lock_ttl/stale_mult. Do NOT merge it to a literal here —
     * that would overwrite the band-resolved value and re-poison the inheritance
     * chain the raw/effective split exists to keep clean. The old `< 1` clamp is
     * gone too: ngx_http_cache_turbo_min_uses() range-checks at parse, and every
     * band value is >= 1, so the gate's `> 1` test cannot see a stray 0. */

    /* Live autotune (v4-3): off by default; default recompute cadence when on. */
    ngx_conf_merge_value(conf->autotune, prev->autotune, 0);
    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }
    if (conf->key == NULL) {
        conf->key = prev->key;
    }

    /* O4.4-d: the breaker's STATE and counters live in the ZONE (shared
     * across every location bound to it), but breaker_enable/threshold/
     * window/open/retry_after above are all per-LOCATION. Sibling locations
     * sharing one zone can therefore feed one state machine different
     * policies -- reopen timing becomes "whichever location last called
     * _breaker_state() decides". This is legal (nothing rejects it) and
     * already documented in the README; this block only detects it at
     * config time and warns -- see the O4.4-d ledger entry for the
     * rejected alternatives (main_conf sees unmerged sentinels; a
     * postconfiguration location-tree walk misses named/regex locations,
     * which ngx_http_init_locations() queue_splits off before any walk
     * could reach them).
     *
     * Guarded the same way the request path decides the breaker is live
     * for this location, to avoid a false positive from a server{} block
     * that binds the zone but whose own effective tuple no request ever
     * consults (every location under it overrides the breaker itself). */
    if (conf->shm_zone != NULL
        && ngx_http_cache_turbo_breaker_should_consult(conf))
    {
        ngx_http_cache_turbo_zone_t  *zctx = conf->shm_zone->data;

        /* NULL when the zone is referenced before its cache_turbo_zone
         * directive appears textually -- skip rather than dereference. */
        if (zctx != NULL) {
            /* BRK-RA1: conf->breaker_retry_after can now be NGX_CONF_UNSET
             * (auto-track: nobody set it anywhere). Compare/store/print the
             * EFFECTIVE value -- resolved the same way the request path
             * resolves it, unset falling back to this location's own
             * breaker_open -- not the raw field. Otherwise two locations
             * that both auto-track but have different breaker_open would
             * compare UNSET == UNSET and wrongly look identical, while a
             * spurious -1 could reach the log format string. */
            time_t  eff_retry_after =
                (conf->breaker_retry_after != NGX_CONF_UNSET)
                ? conf->breaker_retry_after
                : conf->breaker_open;

            if (!zctx->policy_seen) {
                zctx->policy_seen         = 1;
                zctx->policy_threshold    = conf->breaker_threshold;
                zctx->policy_window       = conf->breaker_window;
                zctx->policy_open         = conf->breaker_open;
                zctx->policy_retry_after  = eff_retry_after;
            } else if (zctx->policy_threshold != conf->breaker_threshold
                       || zctx->policy_window != conf->breaker_window
                       || zctx->policy_open != conf->breaker_open
                       || zctx->policy_retry_after != eff_retry_after)
            {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                    "cache_turbo circuit breaker: this location's effective "
                    "policy (threshold=%ui window=%T open=%T "
                    "retry_after=%T) diverges from another location sharing "
                    "the same cache_turbo_zone (threshold=%ui window=%T "
                    "open=%T retry_after=%T); breaker STATE is per-zone but "
                    "policy is per-location, so whichever location last "
                    "calls the state machine decides effective reopen "
                    "timing for the whole zone",
                    conf->breaker_threshold, conf->breaker_window,
                    conf->breaker_open, eff_retry_after,
                    zctx->policy_threshold, zctx->policy_window,
                    zctx->policy_open, zctx->policy_retry_after);
            }
        }
    }

    /* Default cache key (no explicit cache_turbo_key) for an enabled location:
     * $host$uri$cache_turbo_normalized_args — tracking params stripped + args
     * sorted out of the box. Compiled lazily here; the normalized_args variable
     * was registered in preconfiguration. For a raw, no-strip/sort key (e.g. an
     * origin that does not reliably mark per-user responses private), set it
     * explicitly: cache_turbo_key $scheme$host$request_uri; */
    if (conf->key == NULL && conf->enable) {
        ngx_str_t                         defkey =
            ngx_string("$host$uri$cache_turbo_normalized_args");
        ngx_http_compile_complex_value_t  ccv;

        conf->key = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (conf->key == NULL) {
            return NGX_CONF_ERROR;
        }
        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &defkey;
        ccv.complex_value = conf->key;
        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    if (conf->tag == NULL) {
        conf->tag = prev->tag;
    }

    ngx_conf_merge_str_value(conf->require_header, prev->require_header,
                             "");

    /* L2 backend selection + connection knobs. These are behavioural tunables,
     * not backend identity, so they inherit independently as before. */
    ngx_conf_merge_value(conf->redis_enable, prev->redis_enable, 0);
    ngx_conf_merge_value(conf->memcached, prev->memcached, 0);
    ngx_conf_merge_msec_value(conf->redis_timeout, prev->redis_timeout, 250);
    ngx_conf_merge_value(conf->redis_keepalive, prev->redis_keepalive, 0);
    ngx_conf_merge_msec_value(conf->redis_keepalive_timeout,
                              prev->redis_keepalive_timeout, 60000);
    ngx_conf_merge_value(conf->memcached_keepalive, prev->memcached_keepalive, 0);
    ngx_conf_merge_msec_value(conf->memcached_keepalive_timeout,
                              prev->memcached_keepalive_timeout, 60000);

    if (conf->redis_addr.sockaddr != NULL) {
        /* COR-6: this block ran its own cache_turbo_redis — a complete backend
         * in its own right (address set at parse). Treat its identity /
         * credential / db / TLS fields as a FULL REPLACEMENT of the parent's:
         * never inherit them field-by-field, or a child pointed at a different
         * server would silently reuse the parent's password, database, and CA.
         * Anything this directive left unset takes the built-in default. */
        if (conf->redis_prefix.data == NULL) {
            ngx_str_set(&conf->redis_prefix,
                        NGX_HTTP_CACHE_TURBO_REDIS_PREFIX);
        }
        /* nginx has no ngx_conf_init_str_value; self-merge applies the default
         * when unset without consulting the parent. */
        ngx_conf_merge_str_value(conf->redis_user, conf->redis_user, "");
        ngx_conf_merge_str_value(conf->redis_password, conf->redis_password, "");
        ngx_conf_init_value(conf->redis_db, 0);
        ngx_conf_init_value(conf->redis_tls, 0);
        ngx_conf_init_value(conf->redis_tls_verify, 1);
        ngx_conf_merge_str_value(conf->redis_tls_ca, conf->redis_tls_ca, "");
        ngx_conf_merge_str_value(conf->redis_tls_name, conf->redis_tls_name, "");
        /* redis_host was set from the DSN at parse; redis_ssl is built below,
         * post-merge, so it can never carry the parent's TLS context. */

    } else {
        /* No own backend: inherit the parent's entire profile (address + all
         * identity/credential/TLS fields + the already-built TLS context) so an
         * http/server-level backend applies to every nested location. */
        conf->redis_addr = prev->redis_addr;
        if (conf->redis_prefix.data == NULL) {
            if (prev->redis_prefix.data) {
                conf->redis_prefix = prev->redis_prefix;
            } else {
                ngx_str_set(&conf->redis_prefix,
                            NGX_HTTP_CACHE_TURBO_REDIS_PREFIX);
            }
        }
        ngx_conf_merge_str_value(conf->redis_user, prev->redis_user, "");
        ngx_conf_merge_str_value(conf->redis_password, prev->redis_password, "");
        ngx_conf_merge_value(conf->redis_db, prev->redis_db, 0);
        ngx_conf_merge_value(conf->redis_tls, prev->redis_tls, 0);
        ngx_conf_merge_value(conf->redis_tls_verify, prev->redis_tls_verify, 1);
        ngx_conf_merge_str_value(conf->redis_tls_ca, prev->redis_tls_ca, "");
        ngx_conf_merge_str_value(conf->redis_tls_name, prev->redis_tls_name, "");
        ngx_conf_merge_str_value(conf->redis_host, prev->redis_host, "");
#if (NGX_SSL)
        conf->redis_ssl = prev->redis_ssl;   /* reuse parent's built context */
#endif
    }

#if (NGX_SSL)
    /* COR-6: build the client TLS context HERE, after redis_tls / tls_verify /
     * tls_ca are fully resolved — not at directive-parse time, when a tls=on
     * backend that inherits its verify flag or CA would build the context from
     * unmerged (default) values. Own backends build a fresh context; inherited
     * backends already copied prev->redis_ssl above (guard skips the rebuild). */
    if (conf->redis_enable && conf->redis_tls == 1 && conf->redis_ssl == NULL) {
        if (ngx_http_cache_turbo_redis_build_ssl(cf, conf) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
    }
#else
    if (conf->redis_enable && conf->redis_tls == 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_redis: TLS (rediss:// / tls=on) requires nginx built "
            "with --with-http_ssl_module");
        return NGX_CONF_ERROR;
    }
#endif

    /* Resolve the backend vtables (v4-1). l1 is a stateless dispatch table, so
     * it is always wired (the zone is an argument, not driver state). backend is
     * the remote L2 driver, present only when cache_turbo_redis was configured;
     * call sites guard on it being non-NULL. */
    conf->l1 = &ngx_http_cache_turbo_shm_backend;
    conf->backend = conf->redis_enable
                        ? (conf->memcached
                               ? &ngx_http_cache_turbo_memcached_backend
                               : &ngx_http_cache_turbo_redis_backend)
                        : NULL;

    /* COR-0: the tag INDEX (purge-by-tag) lives only in a Redis L2 (the memcached
     * backend has no atomic tag set: tag_add == NULL). A cache_turbo_tag with no L2,
     * or with the memcached backend, cannot be purged by tag — warn at config time
     * rather than let the operator believe purge-by-tag will work. EXCEPTION:
     * cache_turbo_surrogate_key gives the tag list a SECOND, Redis-free consumer
     * (downstream Surrogate-Key emission for a fronting CDN), so the tag is NOT
     * inert then; only the local purge-by-tag index is unavailable, and that is a
     * deliberate, documented Redis-free mode — no warning. */
    if (conf->tag != NULL
        && !conf->surrogate_key
        && (conf->backend == NULL || conf->backend->tag_add == NULL))
    {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "cache_turbo_tag has no effect here: tag indexing requires a Redis "
            "L2 (cache_turbo_redis); it is unavailable with %s "
            "(cache_turbo_surrogate_key still emits the tags downstream)",
            conf->backend == NULL ? "no L2 backend" : "the memcached backend");
    }

    /* Key normalize: inherit the extra-pattern list. */
    if (conf->normalize_strip == NGX_CONF_UNSET_PTR) {
        conf->normalize_strip = prev->normalize_strip;
    }
    /* DIY bypass-URI and key-cookie lists: inherit UNSET-only, same as
     * normalize_strip (a location that sets its own fully replaces the parent's
     * — matching how the append happens within a level, not across). */
    if (conf->bypass_uri == NGX_CONF_UNSET_PTR) {
        conf->bypass_uri = prev->bypass_uri;
    }
    if (conf->backend_prefix == NGX_CONF_UNSET_PTR) {
        conf->backend_prefix = prev->backend_prefix;
    }
    if (conf->key_cookies == NGX_CONF_UNSET_PTR) {
        conf->key_cookies = prev->key_cookies;
    }
    /* Vary suffix bitmask: inherit UNSET-only; the variable handler reads UNSET
     * as 0 (off), so v3-1 keys are unchanged unless a directive opts in. */
    if (conf->normalize_vary == NGX_CONF_UNSET) {
        conf->normalize_vary = prev->normalize_vary;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_cache_turbo_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    /* Cache lookup/serve runs after ACCESS. Serving a HIT from ACCESS and
     * returning NGX_DONE would short-circuit allow/deny and auth handlers. */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_cache_turbo_access_handler;

    /* PURGE runs here, after the ACCESS phase, so allow/deny gates it. */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_cache_turbo_precontent_handler;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_cache_turbo_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_cache_turbo_body_filter;

    return NGX_OK;
}
