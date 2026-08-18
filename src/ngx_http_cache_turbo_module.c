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
#include "ngx_http_cache_turbo_internal.h"

#if (NGX_SSL)
#include <ngx_event_openssl.h>
#endif


/* The access/precontent handlers, the cold-miss single-flight machinery and
 * the blob-reference cleanups moved to ngx_http_cache_turbo_access.c
 * (MAINT-SPLIT step F). ngx_http_cache_turbo_init() below still pushes the two
 * handlers onto the PRECONTENT phase array; they and blob_cleanup are declared
 * in ngx_http_cache_turbo_internal.h. */

/* ngx_http_cache_turbo_serve, _add_header and _breaker_action are called from
 * access.c across the TU boundary and so are declared, non-static, in
 * ngx_http_cache_turbo_internal.h rather than here.
 *
 * P6/O4.3: the breaker's 503 path needs the shared small-body sender, which is
 * defined with the other response helpers far below. Declared non-static in
 * ngx_http_cache_turbo_module.h (shared with admin.c). */
ngx_uint_t ngx_http_cache_turbo_breaker_should_consult(
    ngx_http_cache_turbo_loc_conf_t *clcf);
static char *ngx_http_cache_turbo_breaker_open_conf(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_cache_turbo_restore_response(ngx_http_request_t *r,
    u_char *copy, size_t len, ngx_uint_t stale, const char *xcache,
    u_char **bodyp, size_t *body_lenp);
static ngx_int_t ngx_http_cache_turbo_restore_response_prologue(
    ngx_http_request_t *r, u_char *copy, size_t len, ngx_uint_t stale,
    ngx_http_cache_turbo_blob_hdr_t *bhp,
    ngx_http_cache_turbo_blob_href_t **refsp,
    u_char **bodyp, size_t *body_lenp);
static ngx_int_t ngx_http_cache_turbo_restore_response_headers(
    ngx_http_request_t *r, ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_http_cache_turbo_blob_hdr_t *bh,
    ngx_http_cache_turbo_blob_href_t *refs,
    u_char **etagp, size_t *etag_lenp,
    u_char **lastmodp, size_t *lastmod_lenp);
static ngx_int_t ngx_http_cache_turbo_restore_response_finalize(
    ngx_http_request_t *r, ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_http_cache_turbo_blob_hdr_t *bh, ngx_uint_t stale,
    const char *xcache, u_char *etag, size_t etag_len,
    u_char *lastmod, size_t lastmod_len, size_t *body_lenp);
static ngx_uint_t ngx_http_cache_turbo_restore_alloc_fails(
    ngx_http_request_t *r);
/* ngx_http_cache_turbo_send_json declared non-static in
 * ngx_http_cache_turbo_module.h (shared with admin.c). */

static void *ngx_http_cache_turbo_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_cache_turbo_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cache_turbo(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cache_turbo_backend(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cache_turbo_cache_control(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_cache_turbo_key(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cache_turbo_valid_conf(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cache_turbo_admin(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cache_turbo_tag(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cache_turbo_require_header(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
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
/* ngx_http_cache_turbo_admin_handler now lives in admin.c; declared in
 * ngx_http_cache_turbo_module.h (non-static, core->handler assigns it below). */
/* ngx_http_cache_turbo_warm_one declared non-static in
 * ngx_http_cache_turbo_module.h (shared with admin.c's warm dispatch). */
/* ngx_http_cache_turbo_tagpurge_t now lives in ngx_http_cache_turbo_module.h
 * (shared with admin.c); reused for the COR-5 variant-index purge below and
 * for the admin tag-purge path. ngx_http_cache_turbo_tag_purge_complete
 * declared non-static in ngx_http_cache_turbo_module.h (shared with admin.c). */
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
static char *ngx_http_cache_turbo_bypass_stale_uri(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_cache_turbo_key_cookie_conf(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
/* ngx_http_cache_turbo_vary_prepare/_vary_apply/_variant_hash/_marker_hash/
 * _marker_store/_variant_index_name/_classify_vary/_response_encoded now live
 * in ngx_http_cache_turbo_vary.c; declared non-static in
 * ngx_http_cache_turbo_internal.h (called from the access/header/body paths
 * above their old position in this file). */
/* AUD-HDR1: the single store/restore header gate. Declared here because
 * restore_response() (above its definition) is one of the two callers — the
 * point of the helper is that there is exactly ONE. */
static ngx_int_t ngx_http_cache_turbo_init(ngx_conf_t *cf);




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
const ngx_http_cache_turbo_band_t  ngx_http_cache_turbo_bands[] = {
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

    { ngx_string("cache_turbo_bypass_stale_uri"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_http_cache_turbo_bypass_stale_uri,
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

    /* S231-SIE-MIDBODY: deterministically simulate an upstream that dies
     * AFTER headers were sent but BEFORE last_buf, so the pre-flush SIE
     * body rescue can be exercised without racing real connection teardown.
     * See the loc_conf field comment and the body filter rescue site. */
    { ngx_string("cache_turbo_test_midbody_abort"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, test_midbody_abort),
      NULL },
#endif

      ngx_null_command
};


/* ngx_http_cache_turbo_exit_process() is declared in
 * ngx_http_cache_turbo_internal.h and defined in blob.c. */


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
 * One matched key cookie, queued for folding. Only the name/value POINTERS are
 * kept (name is either a preset's static C string or a config ngx_str_t, value
 * points into r->headers_in.cookie); nothing is copied here.
 */
typedef struct {
    ngx_str_t   name;
    ngx_str_t   val;
} ngx_http_cache_turbo_key_cookie_slot_t;


/*
 * Queue ONE matched key cookie for folding — no allocation, no copy, just an
 * array_push. Splitting "collect" from "append" (below) lets the caller size
 * ONE buffer for every fold up front instead of reallocating and re-copying
 * the whole growing key once per cookie (which was O(n^2) in the number of
 * folded cookies): every real deployment folds a handful, but a config or
 * preset list is not bounded, so the old per-cookie realloc was the thing that
 * scaled badly, not a byte count.
 */
static ngx_int_t
ngx_http_cache_turbo_key_cookie_queue(ngx_array_t *slots, ngx_str_t *name,
    ngx_str_t *val)
{
    ngx_http_cache_turbo_key_cookie_slot_t  *slot;

    slot = ngx_array_push(slots);
    if (slot == NULL) {
        return NGX_ERROR;
    }

    slot->name = *name;
    slot->val = *val;
    return NGX_OK;
}


/*
 * Append ONE queued key cookie into the key buffer under construction, with
 * the unforgeable length-prefixed framing both the preset and the DIY path
 * use: 0x1f tag, then the name length and the value length as fixed 4-byte
 * fields, then the name and value bytes. See the call sites for why a length
 * prefix and not a delimiter (a delimiter would be forgeable from a request
 * header). Returns the buffer position after the appended entry.
 *
 * Folding is append-only, so one call per queued cookie yields a key that
 * depends on every one of them. Order is the caller's iteration order, which
 * is fixed by the preset table / the config, so the key is deterministic.
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
static size_t
ngx_http_cache_turbo_key_fold_size(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *val, size_t *vlen_out, uint32_t *vfield_out)
{
    size_t     vlen;
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

    *vlen_out = vlen;
    *vfield_out = vfield;

    return 1 + 4 + 4 + name->len + vlen;
}


static u_char *
ngx_http_cache_turbo_key_fold_append(u_char *p, ngx_str_t *name,
    size_t vlen, uint32_t vfield, ngx_str_t *val)
{
    *p++ = '\x1f';
    ngx_http_cache_turbo_put_u32(p, (uint32_t) name->len);
    p += 4;
    ngx_http_cache_turbo_put_u32(p, vfield);
    p += 4;
    p = ngx_cpymem(p, name->data, name->len);
    if (vlen) {
        p = ngx_cpymem(p, val->data, vlen);
    }

    return p;
}


/*
 * Fold every QUEUED key cookie into ctx->cache_key in ONE pass: size every
 * entry first (this also resolves the oversize/vfield decision once per
 * cookie, before any byte is written), allocate a single buffer sized for the
 * base key plus all of them, then append the base key and every entry in
 * order. Replaces the previous per-cookie realloc-and-copy-the-whole-prefix,
 * which re-copied the growing key on every fold call (O(n^2) in the number of
 * folded cookies) — this is the SAME bytes in the SAME order, just written
 * once instead of n times.
 */
static ngx_int_t
ngx_http_cache_turbo_key_fold_all(ngx_http_request_t *r,
    ngx_http_cache_turbo_ctx_t *ctx, ngx_array_t *slots)
{
    ngx_http_cache_turbo_key_cookie_slot_t  *s = slots->elts;
    size_t                                   klen = ctx->cache_key.len;
    size_t                                  *vlen;
    uint32_t                                *vfield;
    u_char                                  *k, *p;
    ngx_uint_t                               i;

    if (slots->nelts == 0) {
        return NGX_OK;
    }

    vlen = ngx_palloc(r->pool, slots->nelts * sizeof(size_t));
    if (vlen == NULL) {
        return NGX_ERROR;
    }

    vfield = ngx_palloc(r->pool, slots->nelts * sizeof(uint32_t));
    if (vfield == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < slots->nelts; i++) {
        klen += ngx_http_cache_turbo_key_fold_size(r, &s[i].name, &s[i].val,
                                                    &vlen[i], &vfield[i]);
    }

    k = ngx_pnalloc(r->pool, klen);
    if (k == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(k, ctx->cache_key.data, ctx->cache_key.len);

    for (i = 0; i < slots->nelts; i++) {
        p = ngx_http_cache_turbo_key_fold_append(p, &s[i].name, vlen[i],
                                                  vfield[i], &s[i].val);
    }

    ctx->cache_key.data = k;
    ctx->cache_key.len = klen;

    return NGX_OK;
}


/* Build the cache key string and its hash into the request ctx. */
ngx_int_t
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
    {
    ngx_array_t  slots;

    /* Small typical case (0-2 folded cookies): a 4-element inline pool
     * allocation covers it without a second array_push growth. */
    if (ngx_array_init(&slots, r->pool, 4,
                        sizeof(ngx_http_cache_turbo_key_cookie_slot_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (NGX_HTTP_CACHE_TURBO_HAS_BACKEND(clcf->backend_presets)) {
        ngx_str_t   kcname, kcval;
        ngx_uint_t  cursor = 0;

        /* EVERY present key cookie is folded, not just the first: a preset may
         * declare several, and a cookie the key ignores is one two different
         * users can differ in while sharing an entry. */
        while (ngx_http_cache_turbo_key_cookie(r, clcf->backend_presets,
                                               &cursor, &kcname, &kcval))
        {
            if (ngx_http_cache_turbo_key_cookie_queue(&slots, &kcname, &kcval)
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

            if (ngx_http_cache_turbo_key_cookie_queue(&slots, &nm[i], &kcval)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
    }

    /* Fold every queued cookie in ONE pass: size all of them, allocate a
     * single buffer sized for the base key plus every entry, then append —
     * instead of the previous realloc-and-copy-the-whole-prefix per cookie. */
    if (ngx_http_cache_turbo_key_fold_all(r, ctx, &slots) != NGX_OK) {
        return NGX_ERROR;
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
ngx_int_t
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
ngx_int_t
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
time_t
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
time_t
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
ngx_int_t
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
time_t
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
time_t
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
ngx_int_t
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
ngx_int_t
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
ngx_int_t
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
void
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
void
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
ngx_int_t
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
                    NULL, NULL, NULL, NULL) == NGX_OK)
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

                        /* S231-VARY-LEAK: release the park's reference here,
                         * because THIS caller is the one that never gets a free
                         * drop. purge_request runs in the PRECONTENT phase, and
                         * ngx_http_core_generic_phase answers NGX_DONE with a
                         * bare `return NGX_OK` -- it never calls
                         * ngx_http_finalize_request at all. The completion's
                         * single finalize would therefore leave count at 1 with
                         * nothing left to drop it, orphaning the client
                         * connection with its fd open (visible only at worker
                         * shutdown as "open socket left in connection").
                         *
                         * The module's other two parked purge entry points --
                         * admin_handler's ?tag= (purge_tag) and its all-purge
                         * (scan_del) -- must NOT do this: they are reached
                         * through core->handler, and
                         * ngx_http_core_content_phase ALWAYS runs
                         * ngx_http_finalize_request(r, rc), where NGX_DONE goes
                         * to ngx_http_finalize_connection -> the count != 1
                         * branch -> ngx_http_close_request, which decrements.
                         * Their parks are already balanced; dropping again
                         * there trips "http request count is zero". The
                         * asymmetry is the CALLER'S PHASE, not the op kind, so
                         * the release belongs at each acquire site rather than
                         * in the shared completion. */
                        r->main->count--;

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




/* Add a simple response header (name/value already in a stable buffer). */
ngx_int_t
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
ngx_int_t
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


/* S231: per-worker counters bumped exactly once per request that hit the L2
 * connect backoff fail-fast path -- one counter per driver, defined in
 * ngx_http_cache_turbo_redis.c / ngx_http_cache_turbo_memcached.c next to the
 * backoff table each guards. Unlike X-Cache-Turbo-Test-Armings these are
 * process-global (not zone/shm), matching the backoff state itself being
 * per-worker, not per-zone -- so no shm_zone guard is needed here.
 *
 * Same re-stamp-on-SIE requirement as the armings header above: call this
 * everywhere ngx_http_cache_turbo_test_armings_header is called. */
extern ngx_atomic_uint_t  ngx_http_cache_turbo_redis_test_backoff_skips;
extern ngx_atomic_uint_t  ngx_http_cache_turbo_mc_test_backoff_skips;

ngx_int_t
ngx_http_cache_turbo_test_backoff_header(ngx_http_request_t *r)
{
    ngx_table_elt_t  *h;
    u_char           *v;
    size_t            vlen;

    static u_char  name[] = "X-Cache-Turbo-Test-L2-Backoff";

    /* "redis=<n>,memcached=<n>" -- split the same way the armings header
     * splits l1/l2, so a test asserting on ONE driver cannot be satisfied by
     * the other driver's counter moving. */
    v = ngx_pnalloc(r->pool,
                    sizeof("redis=,memcached=") - 1 + 2 * NGX_ATOMIC_T_LEN);
    if (v == NULL) {
        return NGX_ERROR;
    }

    vlen = ngx_sprintf(v, "redis=%uA,memcached=%uA",
                ngx_atomic_fetch_add(&ngx_http_cache_turbo_redis_test_backoff_skips, 0),
                ngx_atomic_fetch_add(&ngx_http_cache_turbo_mc_test_backoff_skips, 0))
           - v;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    h->key.len = sizeof("X-Cache-Turbo-Test-L2-Backoff") - 1;
    h->key.data = name;
    h->value.len = vlen;
    h->value.data = v;
#if (nginx_version >= 1023000)
    h->next = NULL;
#endif

    return NGX_OK;
}


/* S231-PERF-AUTOCLASSIFY: report the process-global qs_eq() NAME-comparison
 * count from arg_match()'s pre-parsed-span/first-byte prefilter, so a runtime
 * test can assert the prefilter is actually cutting scans (a COUNTER oracle,
 * never a wall-clock timing band) instead of just trusting that it compiles.
 * Same TEST_FAULTS-only / re-stamp-on-SIE discipline as the two headers
 * above. */
extern ngx_atomic_uint_t  ngx_http_cache_turbo_test_arg_scans;

ngx_int_t
ngx_http_cache_turbo_test_arg_scan_header(ngx_http_request_t *r)
{
    ngx_table_elt_t  *h;
    u_char           *v;
    size_t            vlen;

    static u_char  name[] = "X-Cache-Turbo-Test-Arg-Scans";

    v = ngx_pnalloc(r->pool, NGX_ATOMIC_T_LEN);
    if (v == NULL) {
        return NGX_ERROR;
    }

    vlen = ngx_sprintf(v, "%uA",
                ngx_atomic_fetch_add(&ngx_http_cache_turbo_test_arg_scans, 0))
           - v;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    h->key.len = sizeof("X-Cache-Turbo-Test-Arg-Scans") - 1;
    h->key.data = name;
    h->value.len = vlen;
    h->value.data = v;
#if (nginx_version >= 1023000)
    h->next = NULL;
#endif

    return NGX_OK;
}


/* S231-PERF-AUTOCLASSIFY: report the process-global substring-scan call count
 * from cookie_has()'s first-byte prefilter, so a runtime test can assert the
 * prefilter is actually cutting scans (a COUNTER oracle, never a wall-clock
 * timing band) instead of just trusting that it compiles. Same
 * TEST_FAULTS-only / re-stamp-on-SIE discipline as the two headers above. */
extern ngx_atomic_uint_t  ngx_http_cache_turbo_test_cookie_scans;

ngx_int_t
ngx_http_cache_turbo_test_cookie_scan_header(ngx_http_request_t *r)
{
    ngx_table_elt_t  *h;
    u_char           *v;
    size_t            vlen;

    static u_char  name[] = "X-Cache-Turbo-Test-Cookie-Scans";

    v = ngx_pnalloc(r->pool, NGX_ATOMIC_T_LEN);
    if (v == NULL) {
        return NGX_ERROR;
    }

    vlen = ngx_sprintf(v, "%uA",
                ngx_atomic_fetch_add(&ngx_http_cache_turbo_test_cookie_scans, 0))
           - v;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    h->key.len = sizeof("X-Cache-Turbo-Test-Cookie-Scans") - 1;
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

/* MAINT-H4f phase helper for ngx_http_cache_turbo_emit_surrogate_key().
 * PHASE 2 -- parse tag directive value, tokenize on space/tab/comma/CRLF,
 * deduplicate within value, and count unique tags. Stays WHOLE rather than
 * being split: the tokenizer walk operates on cached pointers within
 * tagval.data and cannot be fragmented across function boundaries. void:
 * this phase only populates an array and counter the caller inspects before
 * proceeding; there is nothing to branch on. */
static void
ngx_http_cache_turbo_emit_surrogate_key_parse(ngx_str_t *tagval,
    ngx_str_t *seen, ngx_uint_t *out_ntags)
{
    u_char      *s, *e, *tok;
    size_t       toklen;
    ngx_uint_t   ntags = 0, k;

    s = tagval->data;
    e = tagval->data + tagval->len;

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

    *out_ntags = ntags;
}


/* MAINT-H4f phase helper for ngx_http_cache_turbo_emit_surrogate_key().
 * PHASE 3 -- calculate buffer size, allocate, format space-separated tags,
 * and emit Surrogate-Key header. void: best-effort like the MISS-path emit.
 * Allocation failure is benign: response stays cached, just not CDN-tag-
 * purgeable. */
static void
ngx_http_cache_turbo_emit_surrogate_key_format(ngx_http_request_t *r,
    ngx_str_t *seen, ngx_uint_t ntags)
{
    u_char      *buf, *p;
    size_t       len = 0;
    ngx_uint_t   i;

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


void
ngx_http_cache_turbo_emit_surrogate_key(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf)
{
    ngx_str_t    tagval, seen[NGX_HTTP_CACHE_TURBO_MAX_TAGS];
    ngx_uint_t   ntags = 0;

    if (clcf->tag == NULL) {
        return;
    }
    if (ngx_http_complex_value(r, clcf->tag, &tagval) != NGX_OK
        || tagval.len == 0)
    {
        return;
    }

    ngx_http_cache_turbo_emit_surrogate_key_parse(&tagval, seen, &ntags);

    if (ntags == 0) {
        return;
    }

    ngx_http_cache_turbo_emit_surrogate_key_format(r, seen, ntags);
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

/* Phase 1 of ngx_http_cache_turbo_not_modified(): check If-None-Match header
 * (etag matching). Returns non-zero if a match is found (resource not modified).
 */
static ngx_uint_t
ngx_http_cache_turbo_not_modified_etag(ngx_http_request_t *r,
    u_char *etag, size_t etag_len)
{
    ngx_table_elt_t  *inm = r->headers_in.if_none_match;
    u_char           *start, *end, ch;

    if (inm == NULL) {
        return 0;
    }

    start = inm->value.data;
    end = start + inm->value.len;

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


/* Phase 2 of ngx_http_cache_turbo_not_modified(): check If-Modified-Since
 * header (time comparison). Returns non-zero if resource was not modified
 * (Last-Modified <= If-Modified-Since).
 */
static ngx_uint_t
ngx_http_cache_turbo_not_modified_time(ngx_http_request_t *r,
    u_char *lm, size_t lm_len)
{
    ngx_table_elt_t  *ims = r->headers_in.if_modified_since;
    time_t           ims_t, lm_t;

    if (ims == NULL || lm_len == 0) {
        return 0;
    }

    ims_t = ngx_parse_http_time(ims->value.data, ims->value.len);
    lm_t  = ngx_parse_http_time(lm, lm_len);

    if (ims_t != NGX_ERROR && lm_t != NGX_ERROR && lm_t <= ims_t) {
        return 1;
    }

    return 0;
}


static ngx_uint_t
ngx_http_cache_turbo_not_modified(ngx_http_request_t *r,
    u_char *etag, size_t etag_len, u_char *lm, size_t lm_len)
{
    if (ngx_http_cache_turbo_not_modified_etag(r, etag, etag_len)) {
        return 1;
    }

    return ngx_http_cache_turbo_not_modified_time(r, lm, lm_len);
}


/* Phase 1 of ngx_http_cache_turbo_restore_response(): validate the pool-owned
 * blob and set the two headers_out fields that only depend on the blob
 * envelope (status, Content-Length) before any per-header work starts.
 * Out-params: *bhp receives the decoded header (copied into the caller's own
 * ngx_http_cache_turbo_blob_hdr_t, so it stays valid once this stack frame
 * returns), *refsp the r->pool-owned per-header ref array from the single
 * validated walk, *bodyp / *body_lenp the body slice. Returns NGX_ERROR on a
 * NULL blob/loc-conf or a failed blob_validate(); the caller must not use any
 * out-param when this happens. */
static ngx_int_t
ngx_http_cache_turbo_restore_response_prologue(ngx_http_request_t *r,
    u_char *copy, size_t len, ngx_uint_t stale,
    ngx_http_cache_turbo_blob_hdr_t *bhp,
    ngx_http_cache_turbo_blob_href_t **refsp,
    u_char **bodyp, size_t *body_lenp)
{
    const u_char                      *body_start;
    ngx_http_cache_turbo_loc_conf_t   *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);

    /* A NULL blob is never produced by a live caller (every HIT/L2 path holds a
     * real buffer), but guard at the deref site so the static analyzer can prove
     * the header walk below never reads through a null `p`. */
    if (copy == NULL || clcf == NULL) {
        return NGX_ERROR;
    }

    /* S231-PERF-HDRWALK: ONE validated parse AND ONE header walk. blob_validate
     * checks magic+version, that the header block and body fit, walks every TLV
     * header entry to prove the restore loop below cannot run off the end, AND
     * (r->pool + &refs passed) records each entry's decoded name/value pointers
     * into `refs` in that same pass -- the loop below consumes `refs` directly
     * instead of re-deriving the same offsets with a second bounds-checked walk
     * (ngx_http_cache_turbo_blob_next_header). The blob is byte-aligned
     * (ngx_pnalloc); the validator reads the wire header with fixed-endian
     * getters, no misaligned struct cast. */
    if (ngx_http_cache_turbo_blob_validate(copy, len, bhp, NULL, &body_start,
                                           r->pool, refsp)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    *bodyp = (u_char *) body_start;
    *body_lenp = bhp->body_len;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cache_turbo: serve status=%ui body=%uz stale=%ui",
                   (ngx_uint_t) bhp->status, *body_lenp, stale);

    r->headers_out.status = bhp->status;
    r->headers_out.content_length_n = *body_lenp;

    return NGX_OK;
}


/* Phase 2 of ngx_http_cache_turbo_restore_response(): replay every stored
 * header off the ref array the prologue's single validated walk already
 * built. Content-Type is mapped onto the typed field; ETag / Last-Modified
 * are also captured (via *etagp / *etag_lenp / *lastmodp / *lastmod_lenp) for the
 * conditional-request phase that follows; everything else goes onto the
 * headers list. Returns NGX_ERROR the moment ngx_http_cache_turbo_add_header()
 * fails to allocate — the caller must return NGX_ERROR immediately, same as
 * the inline loop this replaces. */
static ngx_int_t
ngx_http_cache_turbo_restore_response_headers(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_http_cache_turbo_blob_hdr_t *bh,
    ngx_http_cache_turbo_blob_href_t *refs,
    u_char **etagp, size_t *etag_lenp,
    u_char **lastmodp, size_t *lastmod_lenp)
{
    uint32_t     i;
    ngx_uint_t   dropped = 0;

    /* Restore each stored header. Content-Type is mapped to the typed field;
     * the rest go onto the headers list. */
    for (i = 0; i < bh->nheaders; i++) {
        uint32_t       nl, vl;
        u_char        *nm, *vv;

        nl = refs[i].nlen;
        vl = refs[i].vlen;
        nm = (u_char *) refs[i].name;
        vv = (u_char *) refs[i].val;

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
            *etagp = vv;
            *etag_lenp = vl;

        } else if (nl == sizeof("Last-Modified") - 1
                   && ngx_strncasecmp(nm, (u_char *) "Last-Modified", nl) == 0)
        {
            *lastmodp = vv;
            *lastmod_lenp = vl;
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

    return NGX_OK;
}


/* Phase 3 of ngx_http_cache_turbo_restore_response(): everything after the
 * header-restore loop — surrogate-key re-emit, the conditional 200->304
 * rewrite, the range-filter permit, and the Date / Age / X-Cache trailer
 * headers (the last of which also records $cache_turbo_status /
 * $cache_turbo_serve_reason). *body_lenp is read (for the range permit,
 * folded into the 200 check by way of r->headers_out.content_length_n) and
 * conditionally zeroed by the 304 rewrite, matching the inline block this
 * replaces exactly. Returns NGX_ERROR on the first allocation failure in the
 * Date/Age/X-Cache trailer; the caller must return NGX_ERROR immediately. */
static ngx_int_t
ngx_http_cache_turbo_restore_response_finalize(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_http_cache_turbo_blob_hdr_t *bh,
    ngx_uint_t stale, const char *xcache,
    u_char *etag, size_t etag_len,
    u_char *lastmod, size_t lastmod_len,
    size_t *body_lenp)
{
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
        *body_lenp = 0;
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

    return NGX_OK;
}


/* Rebuild r->headers_out from a validated, pool-owned cache blob (caller already
 * copied it out of shm and released the zone lock): set status / Content-Type /
 * Content-Length, replay the stored headers, answer a conditional 200 with 304
 * (live serves only), and stamp Date / Age / X-Cache. Returns the body slice via
 * *bodyp / *body_lenp. Does NOT send the header or body — ngx_http_cache_turbo_
 * serve() does that for a live HIT, while the RFC-2 serve-on-error path calls
 * this from the header filter and lets the filter chain carry the response.
 *
 * Decomposed (MAINT-H4a) into prologue / headers / finalize phases above;
 * this orchestrator only owns the local state that crosses phase boundaries
 * (hdr/refs/etag/lastmod/body) and the downstream hand-off, unchanged from
 * before the split. */
static ngx_int_t
ngx_http_cache_turbo_restore_response(ngx_http_request_t *r, u_char *copy,
    size_t len, ngx_uint_t stale, const char *xcache,
    u_char **bodyp, size_t *body_lenp)
{
    u_char                            *body;
    size_t                             body_len;
    ngx_http_cache_turbo_blob_hdr_t    hdr;
    u_char                            *etag = NULL, *lastmod = NULL;
    size_t                             etag_len = 0, lastmod_len = 0;
    ngx_http_cache_turbo_loc_conf_t   *clcf;
    ngx_http_cache_turbo_blob_href_t  *refs;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);

    if (ngx_http_cache_turbo_restore_response_prologue(r, copy, len, stale,
                                                        &hdr, &refs,
                                                        &body, &body_len)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_cache_turbo_restore_response_headers(r, clcf, &hdr, refs,
                                                       &etag, &etag_len,
                                                       &lastmod, &lastmod_len)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_cache_turbo_restore_response_finalize(r, clcf, &hdr, stale,
                                                        xcache, etag, etag_len,
                                                        lastmod, lastmod_len,
                                                        &body_len)
        != NGX_OK)
    {
        return NGX_ERROR;
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
ngx_int_t
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
    /* S232-BYPASS-STALE: initialised because the breaker-only guard below
     * disarms this cleanup, and it reads `cc` under the same `ref_data != NULL`
     * condition that assigns it. gcc at -O1 cannot prove the two conditions
     * coincide and rejects the read under -Werror=maybe-uninitialized (-O0
     * builds do not warn, so this surfaces only in the sanitizer job). */
    ngx_http_cache_turbo_blob_cln_t  *cc = NULL;

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

    /*
     * S232-BYPASS-STALE: enforce BLOBF_BREAKER_ONLY at the ONE chokepoint every
     * serve passes through, rather than at each call site. A blob stamped
     * breaker-only may leave this function only as the breaker's fallback; on
     * any other path it is not a response, and we return NGX_DECLINED so the
     * caller proceeds to the origin exactly as if nothing were cached.
     *
     * ⚠ Placed here and keyed on the BLOB'S OWN BIT deliberately. The call
     * sites are numerous (L1 hit, L2 fill, stale-while-revalidate, SIE, cold
     * wait) and more get added; a per-site check would silently fail open the
     * day someone adds the tenth one, and the failure mode is a cross-user
     * disclosure on precisely the URLs an operator had excluded from the cache.
     * Fail CLOSED: the allowance is the narrow, explicit "STALE-BREAKER"
     * reason, so a new call site is refused until it opts in on purpose.
     *
     * The read is bounded by the same 44-byte header check blob_validate()
     * applies; a buffer too short to hold the header cannot be served at all,
     * so treat it as not-permitted rather than reading past it. The NULL check
     * is load-bearing, not defensive noise: this runs BEFORE restore_response()
     * (which is where a NULL copy used to be caught first), so without it a
     * caller passing copy == NULL faults here instead -- clang-analyzer
     * core.NullDereference flagged exactly that path.
     */
    if (copy != NULL && len >= NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE) {
        if ((ngx_http_cache_turbo_get_u16(copy + 6)
             & NGX_HTTP_CACHE_TURBO_BLOBF_BREAKER_ONLY)
            && (xcache == NULL || ngx_strcmp(xcache, "STALE-BREAKER") != 0))
        {
            if (ref_data != NULL && cc != NULL) {
                /* The cleanup registered above owns the ref; disarm it and drop
                 * the reference now, the same way the breaker gate releases a
                 * fallback nothing will consume (a pool cleanup cannot be
                 * unregistered, so clearing its payload is how one is voided).
                 * `cc != NULL` is implied by ref_data != NULL (the block above
                 * assigns both or returns), and is tested anyway so the
                 * initialiser cannot silently turn a future divergence into a
                 * NULL deref here. */
                cc->data = NULL;
                ngx_http_cache_turbo_blob_release(z, ref_data);
            }
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: breaker-only entry \"%V\" refused on "
                           "the normal path -> origin", &r->uri);
            return NGX_DECLINED;
        }
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
ngx_int_t
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


/* MAINT-H4f phase helper for ngx_http_cache_turbo_header_admissible().
 * PHASE 1 -- validate header name token characters per RFC 9110 §5.6.2 tchar.
 * Returns NGX_OK if name is a valid token (or empty), NGX_DECLINED otherwise.
 * The tokenizer walk stays WHOLE rather than being split: it operates on the
 * character stream sequentially and cannot be fragmented across function
 * boundaries. */
static ngx_int_t
ngx_http_cache_turbo_header_admissible_name(u_char *name, size_t nlen)
{
    size_t   i;
    u_char   c;

    if (nlen == 0) {
        return NGX_DECLINED;
    }

    for (i = 0; i < nlen; i++) {
        c = name[i];

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
            return NGX_DECLINED;               /* not a token: unserialisable */
        }
    }

    return NGX_OK;
}


/* MAINT-H4f phase helper for ngx_http_cache_turbo_header_admissible().
 * PHASE 2 -- validate header value for response-splitting primitives (CR/LF/NUL).
 * Returns NGX_OK if value is safe, NGX_DECLINED if any byte is CR/LF/NUL.
 * The bounds check stays WHOLE: it validates a flat byte span and cannot be
 * split across function boundaries. */
static ngx_int_t
ngx_http_cache_turbo_header_admissible_value(u_char *val, size_t vlen)
{
    size_t   i;

    for (i = 0; i < vlen; i++) {
        if (val[i] == CR || val[i] == LF || val[i] == '\0') {
            return NGX_DECLINED;               /* header injection primitive */
        }
    }

    return NGX_OK;
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
ngx_int_t
ngx_http_cache_turbo_header_admissible(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *name, size_t nlen, u_char *val, size_t vlen)
{
    if (ngx_http_cache_turbo_header_admissible_name(name, nlen) != NGX_OK) {
        return 0;
    }

    if (ngx_http_cache_turbo_header_admissible_value(val, vlen) != NGX_OK) {
        return 0;
    }

    if (ngx_http_cache_turbo_header_skip(clcf, name, nlen)) {
        return 0;
    }

    return 1;
}


/*
 * S231-SIE-MIDBODY: read the snapshot's body length WITHOUT touching
 * r->headers_out or the header list. ngx_http_cache_turbo_sie_rewrite() below
 * is destructive (ngx_list_init() wipes r->headers_out.headers, clears the
 * typed Content-Type/Length fields) — calling it just to inspect the length
 * and then backing out would leave the response half-rewritten with no way
 * to undo it. ngx_http_cache_turbo_blob_validate() is already the read-only,
 * fully-bounds-checked parse every other snapshot consumer trusts (see
 * STAB-4 above restore_response()); reuse it here instead of open-coding a
 * second TLV reader. Returns NGX_OK and sets *body_lenp on a structurally
 * valid blob, NGX_ERROR otherwise (caller must treat that as "cannot prove
 * the rescue is framing-safe" and decline).
 */
ngx_int_t
ngx_http_cache_turbo_sie_snap_body_len(ngx_http_cache_turbo_ctx_t *ctx,
    size_t *body_lenp)
{
    ngx_http_cache_turbo_blob_hdr_t  hdr;

    if (ctx->sie_snap == NULL
        || ngx_http_cache_turbo_blob_validate(ctx->sie_snap, ctx->sie_snap_len,
                                              &hdr, NULL, NULL, NULL, NULL)
           != NGX_OK)
    {
        return NGX_ERROR;
    }

    *body_lenp = hdr.body_len;
    return NGX_OK;
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
ngx_int_t
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
    (void) ngx_http_cache_turbo_test_backoff_header(r);
    (void) ngx_http_cache_turbo_test_arg_scan_header(r);
    (void) ngx_http_cache_turbo_test_cookie_scan_header(r);
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
ngx_uint_t
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
ngx_uint_t
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
ngx_uint_t
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
ngx_uint_t
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
ngx_uint_t
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
ngx_uint_t
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
ngx_int_t
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
/* MAINT-SEAM: the token vocabulary as data. The chain of length+strncmp arms
 * this replaces carried one branch pair per token, which is what put this
 * function at the top of the complexity list; adding a token now means adding
 * a row, not another arm. `off` stays a special case above the table -- it
 * sets no bit and is the only token that cannot be combined. Terminated by a
 * zero-length name. */
typedef struct {
    ngx_str_t   name;
    ngx_uint_t  bit;
} ngx_http_cache_turbo_use_stale_token_t;

static const ngx_http_cache_turbo_use_stale_token_t
    ngx_http_cache_turbo_use_stale_tokens[] = {
    { ngx_string("error"),    NGX_HTTP_CACHE_TURBO_USE_STALE_ERROR    },
    { ngx_string("timeout"),  NGX_HTTP_CACHE_TURBO_USE_STALE_TIMEOUT  },
    { ngx_string("http_403"), NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_403 },
    { ngx_string("http_404"), NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_404 },
    { ngx_string("http_429"), NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_429 },
    { ngx_string("http_500"), NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_500 },
    { ngx_string("http_502"), NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_502 },
    { ngx_string("http_503"), NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_503 },
    { ngx_string("http_504"), NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_504 },
    { ngx_null_string, 0 }
};


static char *
ngx_http_cache_turbo_use_stale(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t   *value;
    ngx_uint_t   i, mask, saw_off;

    const ngx_http_cache_turbo_use_stale_token_t  *t;

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

        for (t = ngx_http_cache_turbo_use_stale_tokens; t->name.len; t++) {
            if (value[i].len == t->name.len
                && ngx_strncmp(value[i].data, t->name.data, t->name.len) == 0)
            {
                mask |= t->bit;
                break;
            }
        }

        if (t->name.len == 0) {
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
char *
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


/* Send a small body with the given status and content-type. Returns the rc to
 * propagate/finalize with. Non-static: called from admin.c too. */
ngx_int_t
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
 * completion. Non-static: called from admin.c too. */
ngx_int_t
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


/* ngx_http_cache_turbo_tagpurge_t is defined in ngx_http_cache_turbo_module.h
 * (shared with the COR-5 variant-index purge launched from purge_request, and
 * with the admin tag-purge path in admin.c). */


/* SMEMBERS completion: drop every member object from L1 + L2, delete the now-
 * empty tag set, and answer {"purged":N}. Runs while `members` (which point
 * into the redis op buffer) are still valid; everything it keeps is copied or
 * acted on synchronously here. Non-static: called from admin.c too. */
ngx_int_t
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


/* ----- warm (v3-3) --------------------------------------------------------- */

/* NGX_HTTP_CACHE_TURBO_WARM_MAX (cap on URLs warmed per request) moved to
 * admin.c with the only caller, ngx_http_cache_turbo_warm. */


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

/* Non-static: called from admin.c's warm dispatch too. */
ngx_int_t
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


/* S232-BYPASS-STALE: cache_turbo_bypass_stale_uri <prefix>... -- same parsing
 * and same segment-boundary matcher as cache_turbo_bypass_uri above, but the
 * effect is the opposite: these prefixes are STORED (as breaker-only fallback)
 * rather than skipped. See the bypass_stale_uri field comment in module.h for
 * why this is a separate directive instead of a flag on the bypass rules. */
static char *
ngx_http_cache_turbo_bypass_stale_uri(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;
    ngx_str_t                        *value, *s;
    ngx_uint_t                        i;

    if (clcf->bypass_stale_uri == NGX_CONF_UNSET_PTR) {
        clcf->bypass_stale_uri = ngx_array_create(cf->pool, 4,
                                                  sizeof(ngx_str_t));
        if (clcf->bypass_stale_uri == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len == 0 || value[i].data[0] != '/') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_bypass_stale_uri prefix \"%V\" must begin "
                "with \"/\"", &value[i]);
            return NGX_CONF_ERROR;
        }
        s = ngx_array_push(clcf->bypass_stale_uri);
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
    conf->redis_scan_deadline = NGX_CONF_UNSET_MSEC;
    conf->redis_connect_backoff = NGX_CONF_UNSET_MSEC;
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
    conf->bypass_stale_uri = NGX_CONF_UNSET_PTR;
    conf->key_cookies = NGX_CONF_UNSET_PTR;
    conf->backend_prefix = NGX_CONF_UNSET_PTR;
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    conf->test_restore_alloc_fail = NGX_CONF_UNSET;
    conf->test_force_file_buf = NGX_CONF_UNSET;
    conf->test_store_fail = NGX_CONF_UNSET;
    conf->test_scan_max_pages = NGX_CONF_UNSET;
    conf->test_l2_promote_hold_ms = NGX_CONF_UNSET;
    conf->test_midbody_abort = NGX_CONF_UNSET;
#endif
    /* shm_zone, key, redis_addr, redis_prefix default NULL via pcalloc */

    return conf;
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

    if (ngx_http_cache_turbo_filter_chain_init() != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
