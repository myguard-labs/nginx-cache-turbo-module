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
/* ngx_http_cache_turbo_zone/_backend/_cache_control/_key/_valid_conf/_tag/
 * _require_header/_stale_mult/_min_uses/_breaker_open_conf/_scan_resistant/
 * _l2_negative_ttl/_keep_stale/_use_stale/_preset/_admin/_redis_build_ssl and
 * the ngx_http_cache_turbo(...) top-level directive, plus
 * _normalize_strip/_normalize_vary/_backend_prefix/_bypass_uri/
 * _bypass_stale_uri/_key_cookie_conf, moved to ngx_http_cache_turbo_conf.c
 * (MAINT-SPLIT step H). All are non-static now: ngx_http_cache_turbo_commands[]
 * below still references them as function pointers, so they are declared in
 * ngx_http_cache_turbo_internal.h. ngx_http_cache_turbo_require_hdr_ok was
 * already non-static (called from filters.c) and moved with the group. */
/* ngx_http_cache_turbo_admin_handler now lives in admin.c; declared in
 * ngx_http_cache_turbo_module.h (non-static, core->handler assigns it below). */
/* ngx_http_cache_turbo_warm_one declared non-static in
 * ngx_http_cache_turbo_module.h (shared with admin.c's warm dispatch). */
/* ngx_http_cache_turbo_tagpurge_t now lives in ngx_http_cache_turbo_module.h
 * (shared with admin.c); reused for the COR-5 variant-index purge and for the
 * admin tag-purge path. ngx_http_cache_turbo_purge_request and
 * ngx_http_cache_turbo_tag_purge_complete moved to
 * ngx_http_cache_turbo_purge.c (MAINT-SPLIT step G); both declared non-static
 * in ngx_http_cache_turbo_internal.h / ngx_http_cache_turbo_module.h
 * respectively (shared with access.c / admin.c). */
static ngx_int_t ngx_http_cache_turbo_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_cache_turbo_normalized_args_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
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
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE23,   /* P4-1b: optional admission=on|off */
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

    { ngx_string("cache_turbo_vary_ignore"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_http_cache_turbo_vary_ignore,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_key_encoded_origin"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, key_encoded_origin),
      NULL },

    { ngx_string("cache_turbo_serve_authorized"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, serve_authorized),
      NULL },

    { ngx_string("cache_turbo_store_head"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, store_head),
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

    /* P3-7: zone-wide cap on concurrent background-refresh subrequests.
     * 0 = unlimited (default; see conf->background_update_max init and the
     * merge below for why 0 rather than a nonzero default was chosen). */
    { ngx_string("cache_turbo_background_update_max"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, background_update_max),
      NULL },

    /* P5-2-p0: ceiling on URLs warmed per admin warm request (?url=... or
     * ?url_file=...). Default 32 (unchanged behaviour); range-checked by
     * hand in ngx_http_cache_turbo_warm_max() -- a bare ngx_conf_set_num_slot
     * would accept 0 or a negative value and silently disable warming rather
     * than erroring, the same H5/scan_resistant_pct lesson. */
    { ngx_string("cache_turbo_warm_max"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_cache_turbo_warm_max,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
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

    { ngx_string("cache_turbo_min_uses_window"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, min_uses_window),
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

    { ngx_string("cache_turbo_vary_marker_revalidate"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_cache_turbo_vary_marker_revalidate,
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

    /* P5-5r: OPT-IN, default off -- see the field comment on
     * breaker_count_retries in the .h for why this does not ship on. When
     * on, every proxy_next_upstream peer attempt that failed before the
     * final one also counts toward the breaker's failure run. */
    { ngx_string("cache_turbo_breaker_count_retries"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, breaker_count_retries),
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

    { ngx_string("cache_turbo_ignore_set_cookie"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_http_cache_turbo_ignore_set_cookie_conf,
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

    /* COR-5(b): arm the per-request variant-index drop. See the
     * test_varidx_fail field comment for why the trigger is a request header
     * and not "take Redis down". */
    { ngx_string("cache_turbo_test_varidx_fail"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, test_varidx_fail),
      NULL },

    { ngx_string("cache_turbo_test_store_fail"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, test_store_fail),
      NULL },

    /* P3-7: force warm_one()'s warm_anonymize() call to fail (posted
     * subrequest, ctx already seeded, early NGX_ERROR return) so the
     * bg_inflight leak scenario is testable on demand. */
    { ngx_string("cache_turbo_test_warm_ctx_fail"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, test_warm_ctx_fail),
      NULL },

    /* AUD-SCAN1: lower the SCAN-del page cap so the "abandon the walk and
     * report INCOMPLETE" branch is reachable without a 268M-key keyspace. */
    { ngx_string("cache_turbo_test_scan_max_pages"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, test_scan_max_pages),
      NULL },

    /* S231-L2-SCANTIME: hold the worker at every SCAN page boundary so the
     * walk's wall-clock deadline check is reachable without depending on how
     * fast the runner is. The completion check returns before the deadline
     * check, so a walk that finishes never evaluates the deadline; this makes
     * a non-final page boundary outlive any deadline under test. Blocking
     * ngx_msleep for the same reason as the promote hold below. 0/unset =
     * no hold. */
    { ngx_string("cache_turbo_test_scan_page_hold_ms"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, test_scan_page_hold_ms),
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

    /* Guard the unconditional pool allocation: slots is only needed if either
     * a backend preset has key_cookies OR DIY cache_turbo_key_cookie is
     * configured. The common case (no presets, no key_cookies) skips the 4-slot
     * allocation per request by zero-initializing the struct instead — the fold
     * loop below (ngx_http_cache_turbo_key_fold_all) checks nelts == 0 and
     * returns early. */
    ngx_memzero(&slots, sizeof(slots));

    if (NGX_HTTP_CACHE_TURBO_HAS_BACKEND(clcf->backend_presets) ||
        (clcf->key_cookies != NULL && clcf->key_cookies != NGX_CONF_UNSET_PTR))
    {
        /* Small typical case (0-2 folded cookies): a 4-element inline pool
         * allocation covers it without a second array_push growth. */
        if (ngx_array_init(&slots, r->pool, 4,
                            sizeof(ngx_http_cache_turbo_key_cookie_slot_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
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
     * SAFETY: like the presets, this DEPENDS on the Set-Cookie store floor in
     * ngx_http_cache_turbo_response_cacheable() to refuse the transition race
     * (request without the cookie keys to the anon entry, the response then
     * SETS the cookie -> storing under the anon key would poison it). The floor
     * is unconditional for THIS location by construction: P5-8's
     * cache_turbo_ignore_set_cookie relax is hard-vetoed whenever key_cookies
     * is non-empty, precisely so this dependency cannot be configured away.
     * Do not weaken that veto.
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

    ab = (ngx_int_t) ngx_http_cache_turbo_zone_sh(z)->autotuned_beta;
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

    ld = (ngx_int_t) ngx_http_cache_turbo_zone_sh(z)->autotuned_load;
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
 * P3-4 / RFC 9111 §3.5: may a stored response be REUSED for a request that
 * carried Authorization? A shared cache MUST NOT do so unless the response
 * explicitly authorises it, which §3.5 spells out as one of:
 *
 *   - Cache-Control: public
 *   - Cache-Control: s-maxage=<delta>   (any value; presence is the signal)
 *   - Cache-Control: must-revalidate    (proxy-revalidate is its shared-cache
 *                                        synonym, already folded into
 *                                        response_must_revalidate())
 *
 * Evaluated at STORE time and recorded as a blob flag bit, exactly like
 * BLOBF_ORIGIN_ENCODED: the serve path must not have to re-derive it from a
 * response it no longer has. Note s-maxage=0 still counts as "authorised" here
 * -- it is a freshness lifetime, not a permission, and response_cacheable()
 * has already refused to store an s-maxage=0 response at all, so no blob can
 * reach the serve path carrying it.
 *
 * ⚠ This is ONLY the §3.5 reuse authorisation. It says nothing about whether
 * the entry was stored anonymously; that is guaranteed separately and
 * unconditionally by response_cacheable()'s Authorization arm. Both hold.
 */
ngx_int_t
ngx_http_cache_turbo_response_auth_shareable(ngx_http_request_t *r)
{
    if (ngx_http_cache_turbo_cc_has_all(&r->headers_out.headers,
            "Cache-Control", sizeof("Cache-Control") - 1,
            "public", sizeof("public") - 1))
    {
        return 1;
    }

    if (ngx_http_cache_turbo_cc_delta_all(&r->headers_out.headers,
            "Cache-Control", sizeof("Cache-Control") - 1,
            "s-maxage", sizeof("s-maxage") - 1) >= 0)
    {
        return 1;
    }

    return ngx_http_cache_turbo_response_must_revalidate(r);
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
    if (z == NULL || ngx_http_cache_turbo_zone_sh(z) == NULL) {
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
                       ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->test_brk_armings_l1, 0),
                       ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->test_brk_armings_l2, 0)) - v;

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


/* COR-5(b): report the zone's auto-Vary variant-index self-heal counters as
 * "drops=<n>,reissues=<n>". See the sh->varidx_drops field comment for why
 * these are two ZONE-scoped counters rather than one process-global one.
 * Compiles to a no-op returning NGX_OK outside a TEST_FAULTS build. */
ngx_int_t
ngx_http_cache_turbo_test_varidx_header(ngx_http_request_t *r)
{
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    ngx_http_cache_turbo_loc_conf_t  *clcf;
    ngx_http_cache_turbo_zone_t      *z;
    ngx_table_elt_t                  *h;
    u_char                           *v;
    size_t                            vlen;

    static u_char  name[] = "X-Cache-Turbo-Test-Varidx";

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);

    if (clcf->shm_zone == NULL) {
        return NGX_DECLINED;
    }

    z = clcf->shm_zone->data;
    if (z == NULL || ngx_http_cache_turbo_zone_sh(z) == NULL) {
        return NGX_DECLINED;
    }

    v = ngx_pnalloc(r->pool,
                    sizeof("drops=,reissues=") - 1 + 2 * NGX_ATOMIC_T_LEN);
    if (v == NULL) {
        return NGX_ERROR;
    }

    vlen = ngx_sprintf(v, "drops=%uA,reissues=%uA",
                       ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->varidx_drops, 0),
                       ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->varidx_reissues, 0)) - v;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    h->key.len = sizeof("X-Cache-Turbo-Test-Varidx") - 1;
    h->key.data = name;
    h->value.len = vlen;
    h->value.data = v;
#if (nginx_version >= 1023000)
    h->next = NULL;
#endif

    return NGX_OK;
#else
    (void) r;
    return NGX_OK;
#endif
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
    ngx_uint_t   vetted;

    /*
     * P4-3: skip the per-header re-validation when the blob carries
     * BLOBF_HDRS_VETTED. That bit is set at store time (filters.c
     * body_filter_blob_write) only after this very gate has already accepted
     * every pair in the block, so on a fresh L1 hit the loop below would be
     * re-deriving an answer this worker computed when it serialised the
     * bytes: a tchar scan of the name, a CR/LF/NUL scan of the value, and a
     * linear walk of the 18-entry header_skip table, per header, per hit.
     *
     * ⚠ The bit is NOT trusted off the wire. Anything arriving from L2 has it
     * stripped at ingress (blob.c clear_vetted, called from redis.c and
     * memcached.c on the private r->pool copy), so `vetted` can only be true
     * for a blob this process serialised. A blob with the bit clear -- an L2
     * restore, a pre-P4-3 warm entry, or anything malformed -- takes the full
     * gate below, unchanged. Fail-safe direction: the bit only ever removes
     * work from a path whose input we produced.
     */
    vetted = (bh->flags & NGX_HTTP_CACHE_TURBO_BLOBF_HDRS_VETTED) ? 1 : 0;

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
        if (!vetted
            && !ngx_http_cache_turbo_header_admissible(clcf, nm, nl, vv, vl))
        {
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

        /*
         * P3-4 / RFC 9111 SS3.5: this request carries Authorization. It only
         * got past access_eligible() because cache_turbo_serve_authorized is
         * on for its location. Anonymity of the stored copy is already
         * guaranteed (response_cacheable()'s unconditional Authorization arm
         * gates ctx->captured, the sole store trigger), but SS3.5 also
         * requires the RESPONSE to have authorised reuse for an authenticated
         * request. Enforce that here, at the same chokepoint and with the same
         * fail-closed discipline as BLOBF_BREAKER_ONLY: an entry stored
         * WITHOUT public / s-maxage / must-revalidate is refused
         * (NGX_DECLINED -> caller proceeds to origin exactly as on a miss),
         * including every blob written before the bit existed, whose flags
         * word has the bit clear.
         *
         * Checked on the request's OWN Authorization header rather than on a
         * ctx flag, so it holds on every serve path (L1 hit, L2 fill, SWR,
         * SIE, cold wait) and cannot be bypassed by a call site that forgot
         * to thread the state through.
         *
         * Reads the SAME already-bounds-checked u16 the breaker check read;
         * `len >= BLOB_HDR_WIRE` from the outer `if` covers this offset.
         */
        if (r->headers_in.authorization != NULL
            && !(ngx_http_cache_turbo_get_u16(copy + 6)
                 & NGX_HTTP_CACHE_TURBO_BLOBF_AUTH_SHAREABLE))
        {
            if (ref_data != NULL && cc != NULL) {
                cc->data = NULL;
                ngx_http_cache_turbo_blob_release(z, ref_data);
            }
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: entry \"%V\" lacks RFC 9111 3.5 "
                           "reuse authorisation for a credentialed request "
                           "-> origin", &r->uri);
            return NGX_DECLINED;
        }

        /*
         * P5-6: enforce BLOBF_HEAD_DERIVED at this SAME chokepoint, beside
         * BLOBF_BREAKER_ONLY / BLOBF_AUTH_SHAREABLE / BLOBF_ORIGIN_ENCODED,
         * and for the identical reason -- every live serve (L1 hit, L2 fill,
         * SWR stale, SIE, cold wait, the breaker's own fallback) passes
         * through here, and a per-call-site check would fail open on the
         * next site added.
         *
         * THE INVARIANT: a HEAD-derived entry may answer a HEAD and MUST
         * NEVER answer a GET (or any other method that reached a lookup).
         * The blob's body is a real origin representation -- the warm
         * subrequest that produced it was a genuine GET -- but the traffic
         * that caused the fetch was HEAD-only, so nothing on this path has
         * ever established that a GET client here should receive it from
         * cache. Fail CLOSED: NGX_DECLINED, caller proceeds to the origin
         * exactly as on a miss, and the store it performs then replaces the
         * stamped entry with an ordinary one.
         *
         * Keyed on the REQUEST'S OWN METHOD rather than on r->header_only:
         * header_only is also set by the 304-conditional path
         * (module.c, the NOT_MODIFIED arm) and by core once headers are
         * sent, so it is true for requests that are NOT HEAD and would let a
         * conditional GET read a head-derived entry.
         *
         * Reads the SAME already-bounds-checked u16 the guards above read;
         * `len >= NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE` from the outer `if`
         * covers this offset.
         */
        if ((ngx_http_cache_turbo_get_u16(copy + 6)
             & NGX_HTTP_CACHE_TURBO_BLOBF_HEAD_DERIVED)
            && !(r->method & NGX_HTTP_HEAD))
        {
            if (ref_data != NULL && cc != NULL) {
                cc->data = NULL;
                ngx_http_cache_turbo_blob_release(z, ref_data);
            }
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: head-derived entry \"%V\" refused "
                           "for a non-HEAD request -> origin", &r->uri);
            return NGX_DECLINED;
        }

        /*
         * P3-2: enforce BLOBF_ORIGIN_ENCODED at this SAME chokepoint, right
         * beside BLOBF_BREAKER_ONLY, for the same reason -- every live serve
         * (L1 hit, L2 fill, stale-while-revalidate, cold wait, the breaker's
         * own fallback) passes through here, and a per-call-site check would
         * silently fail open on the next one added. This bit's whole point
         * is belt-and-braces on top of the ae-class variant key
         * (cache_turbo_key_encoded_origin, P3-2): vary.c:196-201 already
         * documents ONE real bug where the variant hash alone let a
         * zstd-only client read an identity entry, so the guard here must
         * NOT rely on the variant key having routed the request to the
         * right slot -- it independently re-checks the REQUEST's own
         * Accept-Encoding against the class the blob says it was stored
         * under, and fails closed (NGX_DECLINED -> caller proceeds to
         * origin exactly as on a miss) on any mismatch, including a
         * malformed/absent Accept-Encoding.
         *
         * (ngx_http_cache_turbo_get_u16(copy + 6) & BLOBF_ORIGIN_ENCODED)
         * reads the SAME already-bounds-checked u16 the breaker check above
         * just read -- no second length check needed, `len >=
         * NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE` from the outer `if` already
         * covers this offset. */
        if (ngx_http_cache_turbo_get_u16(copy + 6)
            & NGX_HTTP_CACHE_TURBO_BLOBF_ORIGIN_ENCODED)
        {
            ngx_uint_t  class = (ngx_http_cache_turbo_get_u16(copy + 6)
                                  & NGX_HTTP_CACHE_TURBO_BLOBF_AE_CLASS_MASK)
                                 >> NGX_HTTP_CACHE_TURBO_BLOBF_AE_CLASS_SHIFT;

            if (!ngx_http_cache_turbo_ae_class_accepted(r, class)) {
                if (ref_data != NULL && cc != NULL) {
                    cc->data = NULL;
                    ngx_http_cache_turbo_blob_release(z, ref_data);
                }
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: origin-encoded entry \"%V\" "
                               "class=%ui not accepted by request "
                               "Accept-Encoding -> origin", &r->uri, class);
                return NGX_DECLINED;
            }
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
     * standard end-of-response signal.
     *
     * P4-5: a large body is emitted as a CHAIN of bufs rather than one buf
     * spanning the whole thing. All of them point INTO THE SAME buffer
     * (`body`) -- there is no copy and the serve stays zero-copy -- they just
     * slice it so the writer has natural yield points instead of one
     * monolithic writev of the entire body.
     *
     * Why this matters at 4 MB: a single buf makes ngx_http_write_filter hand
     * the kernel the whole body in one shot and, more importantly, gives the
     * downstream filters and the event loop exactly one unit of work with no
     * intermediate progress. Slicing it lets a partial write retire whole
     * bufs, so a slow consumer no longer forces the whole body to be
     * re-offered as one indivisible piece on every write event.
     *
     * ⚠ REFCOUNT LIFETIME. On the PERF-7 zero-copy path `body` lives inside
     * the shm slab and is kept alive by exactly ONE reference, taken by the
     * caller under the zone mutex and dropped by the single
     * ngx_http_cache_turbo_blob_cleanup registered on r->pool at the top of
     * this function. Chaining does NOT change that: the cleanup is
     * POOL-lifetime, not buf-lifetime, and nginx destroys the request pool in
     * ngx_http_free_request() only after the writer has drained every buffer
     * of the response. So one acquire and one release still cover the whole
     * chain, no matter how many bufs slice it, and no buf can outlive the
     * cleanup. Taking a reference per buf (or dropping one per buf) would be
     * a refcount bug -- do not "balance" this per buf.
     *
     * Chunk size: nginx has no per-location `output_buffers` directive
     * (`output_buffers` is a field of ngx_http_upstream_conf_t, not of
     * ngx_http_core_loc_conf_t, so it is not reachable from a plain content
     * serve like this one), and inventing a new directive for a purely
     * internal slicing decision is not worth the config surface. We therefore
     * use a fixed 32 KB, which is nginx's own conventional output buffer size
     * (the `proxy_buffers`/`output_buffers` default is 32 KB pages) and keeps
     * the buf count bounded: even a 64 MB entry stays at 2048 bufs, and
     * ngx_writev_chain caps each writev at IOV_MAX and loops, so a long chain
     * is correct as well as cheap. */
    if (body_len == 0) {
        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->memory = 0;
        b->last_buf = (r == r->main) ? 1 : 0;
        b->last_in_chain = 1;
        b->sync = 1;                 /* zero-size control buffer */

        out.buf = b;
        out.next = NULL;
        rc = ngx_http_output_filter(r, &out);

    } else {
        ngx_chain_t  *cl, **ll;
        size_t        off;

        ll = &out.next;
        out.buf = NULL;
        b = NULL;
        off = 0;

        /* do/while, not for: body_len > 0 in this arm, so the body ALWAYS runs
         * at least once and `b` is non-NULL at the terminator below. Written
         * this way so that is structural rather than something a reader (or an
         * analyzer) has to derive from the loop condition -- cppcheck reads the
         * `for` form as "condition may be false on entry" and reports the
         * terminator as a NULL dereference. */
        do {
            size_t  n = body_len - off;

            if (n > NGX_HTTP_CACHE_TURBO_SERVE_CHUNK) {
                n = NGX_HTTP_CACHE_TURBO_SERVE_CHUNK;
            }

            b = ngx_calloc_buf(r->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

            b->pos = body + off;
            b->last = body + off + n;
            b->memory = 1;

            if (out.buf == NULL) {
                out.buf = b;

            } else {
                cl = ngx_alloc_chain_link(r->pool);
                if (cl == NULL) {
                    return NGX_ERROR;
                }
                cl->buf = b;
                *ll = cl;
                ll = &cl->next;
            }

            off += NGX_HTTP_CACHE_TURBO_SERVE_CHUNK;

        } while (off < body_len);

        *ll = NULL;

        /* Only the FINAL buf terminates the response: `b` is the last buf the
         * loop allocated. */
        b->last_buf = (r == r->main) ? 1 : 0;
        b->last_in_chain = 1;

        rc = ngx_http_output_filter(r, &out);
    }

    /* Finalize and return NGX_DONE so the ACCESS phase engine stops here and
     * does NOT fall through to the location's content handler (proxy_pass).
     * Returning the output-filter's NGX_OK would let nginx continue to the
     * upstream, hitting the origin on every cache HIT. */
    ngx_http_finalize_request(r, rc);
    return NGX_DONE;
}


/*
 * P5-8: extract the cookie NAME from one Set-Cookie field value, strictly.
 *
 * RFC 6265 SS4.1.1: set-cookie-string = cookie-pair *( ";" SP cookie-av ), and
 * cookie-pair = cookie-name "=" cookie-value. The NAME is therefore everything
 * before the FIRST '=', and only that -- the attributes after the first ';'
 * (Path, Domain, Secure, HttpOnly, Max-Age, an Expires date containing commas
 * and spaces) are NOT part of it and must never be matched against.
 *
 * This is deliberately NOT ngx_http_cache_turbo_cookie_value(): that parses the
 * REQUEST Cookie header, whose grammar is a ';'-separated list of pairs. Reusing
 * it here would read "Path=/" out of a Set-Cookie's ATTRIBUTES as though it were
 * a second cookie -- a name-confusion bug that turns an attribute an attacker
 * influences into a list match.
 *
 * FAIL-CLOSED. Returns 0 (and the caller refuses the store) for every value this
 * cannot resolve to exactly one unambiguous token name:
 *   - empty value, or no '=' at all (an attribute-only / malformed field);
 *   - an EMPTY name ("=v"), which RFC 6265 does not define and clients disagree
 *     on;
 *   - a name containing a byte outside the RFC 6265 token set -- CTLs, SP, '=',
 *     ';', ',', '"' and the RFC 9110 separators. A quoted name ("a"=v), a name
 *     with an embedded space, or one carrying a stray ',' (which some stacks use
 *     to fold two Set-Cookies into ONE field value -- a fold this parser
 *     explicitly refuses to guess at) all land here.
 * Leading OWS before the name is skipped (nginx keeps the value verbatim after
 * the ':' OWS, but a folded/re-emitted value can carry more); nothing else is
 * normalised.
 */
static ngx_int_t
ngx_http_cache_turbo_set_cookie_name(u_char *data, size_t len,
    ngx_str_t *name_out)
{
    u_char  *p, *end, *eq;
    size_t   i;

    if (data == NULL || len == 0) {
        return 0;
    }

    p = data;
    end = data + len;

    while (p < end && (*p == ' ' || *p == '\t')) {
        p++;
    }

    eq = ngx_strlchr(p, end, '=');
    if (eq == NULL || eq == p) {
        /* No cookie-pair at all, or an empty name. Fail closed. */
        return 0;
    }

    name_out->data = p;
    name_out->len = (size_t) (eq - p);

    for (i = 0; i < name_out->len; i++) {
        if (!ngx_http_cache_turbo_is_cookie_name_byte(name_out->data[i])) {
            return 0;
        }
    }

    return 1;
}


/*
 * P5-8: may THIS Set-Cookie field value be ignored for store purposes?
 *
 * 1 only when the operator configured cache_turbo_ignore_set_cookie AND the
 * value parses to exactly one token cookie name AND that name matches a
 * configured entry EXACTLY and CASE-SENSITIVELY. RFC 6265 cookie names are
 * case-sensitive on the wire, and a case-insensitive match here would only ever
 * ACCEPT MORE responses than the operator named -- the wrong direction for a
 * fail-closed gate. `_GA` therefore never satisfies a list entry of `_ga`.
 *
 * Every other outcome is 0 and the caller refuses the store exactly as it did
 * before this directive existed.
 */
static ngx_int_t
ngx_http_cache_turbo_set_cookie_ignorable(
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_table_elt_t *h)
{
    ngx_str_t   name;
    ngx_str_t  *nm;
    ngx_uint_t  i;

    if (clcf->ignore_set_cookie == NULL
        || clcf->ignore_set_cookie == NGX_CONF_UNSET_PTR
        || clcf->ignore_set_cookie->nelts == 0)
    {
        return 0;
    }

    if (!ngx_http_cache_turbo_set_cookie_name(h->value.data, h->value.len,
                                              &name))
    {
        return 0;
    }

    nm = clcf->ignore_set_cookie->elts;

    for (i = 0; i < clcf->ignore_set_cookie->nelts; i++) {
        if (name.len == nm[i].len
            && ngx_strncmp(name.data, nm[i].data, name.len) == 0)
        {
            return 1;
        }
    }

    return 0;
}


/*
 * P5-8: is the named-ignore relax permitted AT ALL for this location?
 *
 * HARD VETO on the key-cookie machinery, which is the precondition the Set-Cookie
 * floor's own comment names. A key cookie (a backend preset's, or a DIY
 * cache_turbo_key_cookie) folds a cookie VALUE into the cache key, so a request
 * arriving WITHOUT that cookie hashes to the ANONYMOUS entry. The response that
 * first establishes the segment is distinguishable by exactly one thing: it
 * carries a Set-Cookie. Storing it under the anonymous key poisons that entry
 * for every anonymous visitor -- upstream Magento's VCL refuses the identical
 * case (vcl_backend_response: beresp.uncacheable).
 *
 * The veto is on the CONFIGURATION, not on which cookies this particular
 * response happens to set, because the relax would otherwise depend on the
 * operator having listed every key cookie -- and a list that omits one silently
 * reopens the race. With any key cookie configured the location keeps the
 * original unconditional floor, whatever the ignore list says.
 */
static ngx_int_t
ngx_http_cache_turbo_set_cookie_relax_allowed(
    ngx_http_cache_turbo_loc_conf_t *clcf)
{
    if (clcf->ignore_set_cookie == NULL
        || clcf->ignore_set_cookie == NGX_CONF_UNSET_PTR
        || clcf->ignore_set_cookie->nelts == 0)
    {
        return 0;
    }

    /* DIY value-keying configured => transition race is live. */
    if (clcf->key_cookies != NULL
        && clcf->key_cookies != NGX_CONF_UNSET_PTR
        && clcf->key_cookies->nelts > 0)
    {
        return 0;
    }

    /* A backend preset is enabled. Vetoed whether or not the preset declares
     * key_cookies: presets gain key cookies over time, and a relax that silently
     * turns itself back on when a preset is extended is exactly the failure this
     * veto exists to prevent. */
    if (NGX_HTTP_CACHE_TURBO_HAS_BACKEND(clcf->backend_presets)) {
        return 0;
    }

    return 1;
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
 *
 * P0-1: reason_out (may be NULL) receives which arm vetoed, one of the
 * NGX_HTTP_CACHE_TURBO_REFUSE_* constants, so the header-filter capture gate
 * can attribute a refusal to a Prometheus counter without a second header
 * walk. Purely observational -- does not change which responses are refused.
 */
ngx_int_t
ngx_http_cache_turbo_response_cacheable(ngx_http_request_t *r,
    ngx_uint_t *reason_out)
{
    ngx_list_part_t                  *part;
    ngx_table_elt_t                  *h;
    ngx_uint_t                        i;
    ngx_http_cache_turbo_loc_conf_t  *clcf;

    if (reason_out != NULL) {
        *reason_out = NGX_HTTP_CACHE_TURBO_REFUSE_NONE;
    }

    if (r->headers_in.authorization != NULL) {
        if (reason_out != NULL) {
            *reason_out = NGX_HTTP_CACHE_TURBO_REFUSE_AUTHORIZATION;
        }
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
         * The Set-Cookie floor. NOT gated by ignore_cc, because relaxing it
         * does more than staple one visitor's session cookie into a shared
         * body. The ONE way to relax it is P5-8's
         * cache_turbo_ignore_set_cookie, off by default and carrying the
         * preset-level veto the paragraph below demands.
         *
         * PRESET KEY COOKIES DEPEND ON THIS. A request that carries no key
         * cookie (Magento's X-Magento-Vary) hashes to the ANONYMOUS entry, and
         * the response that FIRST establishes the segment arrives with exactly
         * one distinguishing mark: a Set-Cookie. Store it and the anonymous
         * entry now serves segmented content to every anonymous visitor —
         * upstream Magento's own VCL refuses the identical case
         * (vcl_backend_response: beresp.uncacheable). Anyone adding a knob that
         * caches Set-Cookie responses must add a preset-level veto FIRST
         * (request had no key cookie && response sets one => do not capture),
         * or reintroduce a cross-user leak.
         *
         * P5-8 SATISFIES THAT PRECONDITION, and more strictly than the
         * paragraph asks: instead of deciding per response whether a key cookie
         * was involved, ngx_http_cache_turbo_set_cookie_relax_allowed() vetoes
         * on the CONFIGURATION -- any active backend preset, or any
         * cache_turbo_key_cookie, disables the relax for the whole location
         * whatever the ignore list says. A per-response test would depend on
         * the operator having listed every key cookie, and a list that omits
         * one silently reopens the race; a per-location veto cannot.
         */
        if (h[i].key.len == sizeof("Set-Cookie") - 1
            && ngx_strncasecmp(h[i].key.data, (u_char *) "Set-Cookie",
                               sizeof("Set-Cookie") - 1) == 0)
        {
            /*
             * P5-8: the named relax. This `continue` is reached ONLY when the
             * operator listed this exact cookie name AND the location has no
             * key-cookie machinery at all -- the preset-level veto the comment
             * above demands, implemented in
             * ngx_http_cache_turbo_set_cookie_relax_allowed().
             *
             * It is a `continue`, NOT a `return 1`: the loop must keep walking,
             * because a response may carry SEVERAL Set-Cookie fields (nginx
             * hands them to us as separate entries in this very list) and ONE
             * unlisted or unparseable name among them must still refuse the
             * whole store. Every other veto arm below still applies too.
             *
             * What gets STORED is unaffected: "Set-Cookie" is on the
             * unconditional header_skip[] list, so no Set-Cookie is ever
             * serialised into a blob and none can replay to another client.
             */
            if (ngx_http_cache_turbo_set_cookie_relax_allowed(clcf)
                && ngx_http_cache_turbo_set_cookie_ignorable(clcf, &h[i]))
            {
                continue;
            }

            if (reason_out != NULL) {
                *reason_out = NGX_HTTP_CACHE_TURBO_REFUSE_SET_COOKIE;
            }
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
                if (reason_out != NULL) {
                    *reason_out = NGX_HTTP_CACHE_TURBO_REFUSE_CACHE_CONTROL;
                }
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

    /*
     * P3-2: this is the SECOND (and only other) call site of
     * ngx_http_cache_turbo_restore_response() -- see the identical guard in
     * ngx_http_cache_turbo_serve() for the full rationale (belt-and-braces
     * on top of the ae-class variant key, vary.c:196-201). Checked BEFORE
     * the destructive ngx_list_init() below (which wipes r->headers_out) so
     * a refusal can return cleanly without leaving the response half
     * rewritten; the caller (header_filter_try_sie()) treats NGX_DECLINED
     * as "no SIE serve happened, continue as before", i.e. the original
     * upstream error response is left to flow through the filter chain
     * untouched -- the same safe fallback the breaker-only style guard in
     * serve() gets via NGX_DECLINED.
     *
     * ctx->sie_snap is a private r->pool snapshot (never a live shm blob,
     * see its own comments), so there is no reference to release on
     * refusal, unlike the serve() call site.
     */
    if (ctx->sie_snap != NULL
        && ctx->sie_snap_len >= NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE)
    {
        uint16_t  snap_flags = ngx_http_cache_turbo_get_u16(ctx->sie_snap + 6);

        /* P3-4: the same RFC 9111 SS3.5 reuse gate serve() applies, for the
         * same reason -- this is the other path a stored body can reach a
         * client on, so leaving it out would serve a non-shareable entry to a
         * credentialed requester whenever the SIE window opened. Fail closed
         * on a missing bit, exactly as serve() does. */
        if (r->headers_in.authorization != NULL
            && !(snap_flags & NGX_HTTP_CACHE_TURBO_BLOBF_AUTH_SHAREABLE))
        {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: SIE snapshot \"%V\" lacks RFC 9111 "
                           "3.5 reuse authorisation for a credentialed "
                           "request -> no SIE serve", &r->uri);
            return NGX_DECLINED;
        }

        /* P5-6: the same HEAD-derived gate serve() applies, for the same
         * reason -- SIE is the other path a stored body can reach a client
         * on, so leaving it out would let a GET read a head-derived entry
         * for the whole stale-if-error window, which is precisely the
         * "serve site added without the flag check" failure the chokepoint
         * discipline exists to prevent. Fail closed on the bit being set for
         * a non-HEAD request, exactly as serve() does. */
        if ((snap_flags & NGX_HTTP_CACHE_TURBO_BLOBF_HEAD_DERIVED)
            && !(r->method & NGX_HTTP_HEAD))
        {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: head-derived SIE snapshot \"%V\" "
                           "refused for a non-HEAD request -> origin error "
                           "stands", &r->uri);
            return NGX_DECLINED;
        }

        if (snap_flags & NGX_HTTP_CACHE_TURBO_BLOBF_ORIGIN_ENCODED) {
            ngx_uint_t  class = (snap_flags
                                  & NGX_HTTP_CACHE_TURBO_BLOBF_AE_CLASS_MASK)
                                 >> NGX_HTTP_CACHE_TURBO_BLOBF_AE_CLASS_SHIFT;

            if (!ngx_http_cache_turbo_ae_class_accepted(r, class)) {
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: origin-encoded SIE snapshot "
                               "\"%V\" class=%ui not accepted by request "
                               "Accept-Encoding -> origin error stands",
                               &r->uri, class);
                return NGX_DECLINED;
            }
        }
    }

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
    (void) ngx_http_cache_turbo_test_varidx_header(r);
#endif

    ctx->sie_body = body;
    ctx->sie_body_len = body_len;
    return NGX_OK;
}


/* P5-5: does r->upstream carry a genuine TRANSPORT failure -- connect
 * refused, DNS failure, upstream timeout -- as opposed to a real response the
 * origin sent (even an origin-generated 502/504)?
 *
 * Discriminator: r->upstream->state->header_time. nginx sets it to
 * (ngx_msec_t) -1 the moment it opens a peer attempt and overwrites it with a
 * real elapsed-time value ONLY on the success path of
 * ngx_http_upstream_process_header(), immediately after a response header was
 * actually parsed (rc == NGX_OK) -- see ngx_http_upstream.c. Every failure
 * path that synthesizes a status (connect error, DNS failure,
 * next_upstream_timeout, proxy_next_upstream exhaustion) reaches
 * ngx_http_upstream_finalize_request() without ever executing that line, so
 * -1 survives unchanged to the point this module's header filter runs. A -1
 * therefore means "the last peer attempt never produced a parseable header",
 * true regardless of whether nginx folds that into a synthesized 502 or 504.
 *
 * r->upstream->state is nginx's own pointer to the CURRENT (last) attempt's
 * slot in r->upstream_states -- no walk needed, and it is populated before
 * ngx_http_send_header() ever reaches this module's filter chain, so this is
 * reliable at header-filter time. It is a DIFFERENT, earlier point than the
 * mid-body SIE rescue in ngx_http_cache_turbo_body_filter_midbody_rescue()
 * (filters.c), whose own comment rules out u->peer.connection and
 * r->upstream->length as unreliable there -- that timing is post-body-start,
 * with headers already serialised and the connection potentially closing
 * concurrently; this check runs before any byte of THIS response's headers
 * has left the filter chain, on the state nginx itself finished writing for
 * the attempt already selected as final. Do not reuse this helper from the
 * mid-body rescue: nothing there proves this same reliability. */
ngx_uint_t
ngx_http_cache_turbo_transport_failure(ngx_http_request_t *r)
{
    ngx_http_upstream_t  *u = r->upstream;

    if (u == NULL || u->state == NULL) {
        return 0;
    }

    return u->state->header_time == (ngx_msec_t) -1;
}


/* S4.2: does `status` trigger a stale serve under the configured use_stale
 * mask, given whether this response arrived via a transport failure (P5-5,
 * ngx_http_cache_turbo_transport_failure() above)?
 *
 * The mask is the operator's `cache_turbo_use_stale` set (S4.1); the default
 * (USE_STALE_DEFAULT) reproduces the pre-S4.2 hardcoded "every 5xx" condition
 * byte-for-byte via the four named 5xx bits plus ANY_5XX -- transport_failure
 * changes nothing about DEFAULT, because DEFAULT never sets the ERROR/TIMEOUT
 * bits in the first place.
 *
 * ERROR/TIMEOUT are folded onto 502/504 ONLY when transport_failure is true:
 * an operator running `cache_turbo_use_stale error timeout;` alone (no
 * http_502/http_504) now serves stale strictly for "nginx never heard back",
 * leaving a real origin-emitted 502/504 to surface as-is unless http_502 /
 * http_504 is also configured. HTTP_502/HTTP_504 are unaffected either way --
 * they still match the status alone, transport failure or not, so an
 * operator who wants "stale on any 502" keeps that from http_502 regardless.
 */
ngx_uint_t
ngx_http_cache_turbo_use_stale_triggers(ngx_uint_t mask, ngx_uint_t status,
    ngx_uint_t transport_failure)
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
        bit = NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_502;
        if (transport_failure) {
            bit |= NGX_HTTP_CACHE_TURBO_USE_STALE_ERROR;
        }
        break;
    case NGX_HTTP_SERVICE_UNAVAILABLE:
        bit = NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_503;
        break;
    case NGX_HTTP_GATEWAY_TIME_OUT:
        bit = NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_504;
        if (transport_failure) {
            bit |= NGX_HTTP_CACHE_TURBO_USE_STALE_TIMEOUT;
        }
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


/* P5-5r: count peer attempts that FAILED before the one whose status this
 * response reports, i.e. every ngx_http_upstream_state_t entry in
 * r->upstream_states except the last (r->upstream->state, already handled
 * by the caller via ngx_http_cache_turbo_breaker_is_origin_failure() /
 * ngx_http_cache_turbo_transport_failure()).
 *
 * Deliberately NOT part of the UNIT-EXTRACT breaker-failure block above:
 * every function there is a pure predicate the unit harness can drive with
 * scalars; this one walks a live ngx_http_request_t's upstream_states array,
 * which only exists inside a real request and cannot be sliced into that
 * harness. It is exercised by the Test::Nginx integration suite instead
 * (t/breaker-retry-count.t).
 *
 * WHY a prior attempt counts as a failure without re-deriving is_origin_failure
 * on its recorded `status`: a retried attempt's status field is only ever
 * meaningful when nginx itself decided to retry past it, and nginx retries
 * past 5xx (via proxy_next_upstream's default) or a transport failure (no
 * status at all, header_time == -1) -- see the same -1 sentinel
 * ngx_http_cache_turbo_transport_failure() reads on the CURRENT attempt.
 * Reusing breaker_is_origin_failure() on a retried entry's `status` handles
 * both: a transport failure leaves `status` at 0 (ngx_memzero at push time,
 * ngx_http_upstream_connect() above), which is outside the 500..599 range
 * and would go uncounted by is_origin_failure() alone -- so this function
 * treats header_time == -1 as an additional failure signal, exactly
 * mirroring ngx_http_cache_turbo_transport_failure()'s own test, rather than
 * inventing a second one.
 *
 * Only counts entries STRICTLY BEFORE the last: the last entry is the
 * response this filter is already handling via the existing single-status
 * path in the caller, and counting it again here would double-count that
 * exact outcome. A request with only one attempt (the common case, no
 * retry occurred) returns 0 -- this function changes nothing when
 * proxy_next_upstream never fired. */
ngx_uint_t
ngx_http_cache_turbo_breaker_retry_failures(ngx_http_request_t *r)
{
    ngx_http_upstream_state_t  *state;
    ngx_uint_t                  i, n, fails;

    if (r->upstream_states == NULL || r->upstream_states->nelts < 2) {
        return 0;
    }

    state = r->upstream_states->elts;
    n     = r->upstream_states->nelts - 1; /* exclude the final/current attempt */
    fails = 0;

    for (i = 0; i < n; i++) {
        if (state[i].header_time == (ngx_msec_t) -1
            || ngx_http_cache_turbo_breaker_is_origin_failure(state[i].status))
        {
            fails++;
        }
    }

    return fails;
}




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

/* P3-7: cleanup record for the zone-wide bg_inflight decrement. Lives in
 * sr->pool (the SUBREQUEST's own pool, not r->pool) so it runs exactly once
 * when the subrequest's request object is freed -- whether that happens
 * because the subrequest ran to completion or because one of warm_one()'s
 * own failure arms below tears it down early. This is deliberately NOT a
 * decrement keyed to warm_one()'s return value: ngx_http_subrequest()
 * already posted the subrequest by the time any of those arms can fail, so
 * a return-value decrement would never run on those paths and would leak
 * the counter -- see the bg_inflight field comment in module.h. */
typedef struct {
    ngx_http_cache_turbo_zone_t  *z;
} ngx_http_cache_turbo_bginflight_cln_t;

static void
ngx_http_cache_turbo_bginflight_cleanup(void *data)
{
    ngx_http_cache_turbo_bginflight_cln_t  *c = data;

    (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(c->z)->bg_inflight, -1);
}

/*
 * P1-4: push one validator header (If-None-Match from a stored ETag, or
 * If-Modified-Since from a stored Last-Modified) onto a warm/refresh
 * subrequest's private headers_in list, the same list warm_anonymize()
 * already builds in place. name/value are copied by VALUE (ngx_list_push +
 * struct assignment), matching warm_anonymize()'s existing elements -- no new
 * copy semantics introduced here.
 */
static ngx_int_t
ngx_http_cache_turbo_warm_add_validator(ngx_http_request_t *sr,
    const char *name, size_t name_len, u_char *value, size_t value_len)
{
    ngx_table_elt_t  *h;

    h = ngx_list_push(&sr->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    h->key.data = (u_char *) name;
    h->key.len = name_len;
    h->value.data = value;
    h->value.len = value_len;
    h->lowcase_key = (u_char *) name;   /* markers below are already lower */
#if (nginx_version >= 1023000)
    h->next = NULL;
#endif

    return NGX_OK;
}

/*
 * P1-4: inject If-None-Match / If-Modified-Since onto a background-refresh
 * subrequest from the entry's CURRENTLY STORED blob, so stale-while-revalidate
 * refreshes can be answered 304 by the origin instead of always paying a full
 * body -- see PLAN-optimize.md row P1-4. `snap`/`snap_len` is the pinned blob
 * copy the caller already holds (SWR callers only; the admin warm path passes
 * NULL/0 and gets today's unconditional GET). Only a validator the entry
 * ACTUALLY has is injected: an entry stored without an ETag and without a
 * Last-Modified must still produce an unconditional GET, exactly as before
 * this change -- so a failed/absent parse here is silently a no-op, never an
 * error that would abort the refresh. This is INJECTION ONLY: a 304 answer is
 * simply not cache_turbo_valid by default (ngx_http_cache_turbo_status_ttl()
 * returns -1 for any status the operator has not explicitly listed), so the
 * capture gate in the body filter declines it and the existing stale entry is
 * left exactly as it was -- 304-freshening (reusing the stored body) is the
 * deliberately separate row P5-4.
 */
static void
ngx_http_cache_turbo_warm_inject_validators(ngx_http_request_t *sr,
    u_char *snap, size_t snap_len)
{
    ngx_http_cache_turbo_blob_hdr_t    bh;
    ngx_http_cache_turbo_blob_href_t  *refs;
    const u_char                      *body_start;
    uint32_t                           i;
    u_char                             *etag = NULL, *lastmod = NULL;
    size_t                              etag_len = 0, lastmod_len = 0;

    if (snap == NULL || snap_len == 0) {
        return;
    }

    if (ngx_http_cache_turbo_blob_validate(snap, snap_len, &bh, NULL,
                                           &body_start, sr->pool, &refs)
        != NGX_OK)
    {
        return;
    }

    for (i = 0; i < bh.nheaders; i++) {
        uint32_t  nl = refs[i].nlen;

        if (nl == sizeof("ETag") - 1
            && ngx_strncasecmp((u_char *) refs[i].name, (u_char *) "ETag", nl)
               == 0)
        {
            etag = (u_char *) refs[i].val;
            etag_len = refs[i].vlen;

        } else if (nl == sizeof("Last-Modified") - 1
                   && ngx_strncasecmp((u_char *) refs[i].name,
                                     (u_char *) "Last-Modified", nl) == 0)
        {
            lastmod = (u_char *) refs[i].val;
            lastmod_len = refs[i].vlen;
        }
    }

    /* If-None-Match takes precedence over If-Modified-Since on the response
     * side (RFC 7232 SS6); mirror that here by preferring ETag when both are
     * present, matching ngx_http_cache_turbo_not_modified()'s own order. */
    if (etag != NULL && etag_len > 0) {
        (void) ngx_http_cache_turbo_warm_add_validator(sr,
                   "If-None-Match", sizeof("If-None-Match") - 1,
                   etag, etag_len);

    } else if (lastmod != NULL && lastmod_len > 0) {
        (void) ngx_http_cache_turbo_warm_add_validator(sr,
                   "If-Modified-Since", sizeof("If-Modified-Since") - 1,
                   lastmod, lastmod_len);
    }
}

/* Non-static: called from admin.c's warm dispatch too. */
ngx_int_t
ngx_http_cache_turbo_warm_one(ngx_http_request_t *r, ngx_str_t *uri,
    ngx_str_t *args, u_char *snap, size_t snap_len,
    ngx_http_cache_turbo_ctx_t **ctx_out, ngx_str_t *unparsed_uri_src)
{
    ngx_http_request_t                     *sr;
    ngx_http_cache_turbo_ctx_t             *wctx;
    ngx_http_cache_turbo_loc_conf_t        *clcf;
    ngx_http_cache_turbo_zone_t            *z;
    ngx_pool_cleanup_t                     *cln;
    ngx_http_cache_turbo_bginflight_cln_t  *cc;

    /* P3-7: `r` here is whichever request CALLED warm_one() -- the SWR
     * dice-winner itself (access.c, r is the caching location) OR the admin
     * warm endpoint (admin.c, r is the `cache_turbo_admin` location, which
     * sets admin_zone, never shm_zone). Both name the SAME shared-memory
     * zone in every real deployment (the admin endpoint manages the zone it
     * warms into), so fall back to admin_zone when shm_zone is unset rather
     * than silently treating an admin-triggered warm as capless. */
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);
    if (clcf->shm_zone != NULL) {
        z = clcf->shm_zone->data;
    } else if (clcf->admin_zone != NULL) {
        z = clcf->admin_zone->data;
    } else {
        z = NULL;
    }

    /* P3-7: zone-wide cap on concurrent background-refresh subrequests.
     * 0 (the default) is the "unlimited" sentinel -- preserves the ungated
     * behaviour that shipped before this directive existed, so an operator
     * who has not read about the new knob sees no change. A nonzero cap
     * checks-and-increments the atomic; if the zone is already at the cap
     * this call refuses to fire and the caller's stale copy is served
     * without a regen (the same outcome as a peer already holding the
     * per-key single-flight lock -- no new failure mode). Checked BEFORE
     * ngx_http_subrequest(): unlike the failure arms below, refusing here
     * costs nothing to unwind because nothing has been posted yet. */
    if (z != NULL && clcf->background_update_max != 0) {
        for ( ;; ) {
            ngx_atomic_uint_t  cur = *(volatile ngx_atomic_uint_t *)
                                          &ngx_http_cache_turbo_zone_sh(z)->bg_inflight;

            if (cur >= (ngx_atomic_uint_t) clcf->background_update_max) {
                return NGX_DECLINED;
            }
            if (ngx_atomic_cmp_set(&ngx_http_cache_turbo_zone_sh(z)->bg_inflight, cur, cur + 1)) {
                break;
            }
        }
    }

    if (ngx_http_subrequest(r, uri, args->len ? args : NULL, &sr, NULL,
                            NGX_HTTP_SUBREQUEST_BACKGROUND)
        != NGX_OK)
    {
        if (z != NULL && clcf->background_update_max != 0) {
            (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->bg_inflight, -1);
        }
        return NGX_ERROR;
    }

    /* Arm the bg_inflight decrement on the SUBREQUEST's pool, immediately
     * after the subrequest is posted and before anything else that can fail.
     * From this point on the subrequest is live and will eventually free
     * sr->pool no matter which return path below is taken, so the cleanup is
     * the only decrement site that cannot be skipped by an early return. */
    if (z != NULL && clcf->background_update_max != 0) {
        cln = ngx_pool_cleanup_add(sr->pool,
                  sizeof(ngx_http_cache_turbo_bginflight_cln_t));
        if (cln == NULL) {
            /* Cannot arm the cleanup: undo the increment now, since nothing
             * else will. The subrequest itself still runs (unthrottled by
             * this cap for its remaining lifetime) rather than being torn
             * down -- ngx_http_subrequest() has already posted it and it
             * cannot be unwound, same rationale as the ctx-alloc failure
             * below. */
            (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->bg_inflight, -1);
        } else {
            cln->handler = ngx_http_cache_turbo_bginflight_cleanup;
            cc = cln->data;
            cc->z = z;
        }
    }

    /* Seed the ctx FIRST, before anything below that can fail. A background
     * subrequest cannot be unwound once ngx_http_subrequest() has posted it, so
     * an early return here leaves `sr` live but ctx-less -- and the body filter
     * treats a NULL ctx as "not ours" and FORWARDS the body
     * (ngx_http_cache_turbo_body_filter, ctx == NULL arm). A warm subrequest
     * whose body is forwarded rather than captured is the documented s84
     * shutdown-hang condition. Allocating the ctx up front means every failure
     * arm below leaves a subrequest that is still recognisably ours.
     *
     * P3-7: NOTE this and the anonymize failure below are exactly the "return
     * before the subrequest completes" arms the bg_inflight decrement must
     * survive -- the cleanup armed above already covers them; nothing here
     * touches the counter. */
    wctx = ngx_pcalloc(sr->pool, sizeof(ngx_http_cache_turbo_ctx_t));
    if (wctx == NULL) {
        return NGX_ERROR;
    }
    wctx->warm = 1;
    ngx_http_set_ctx(sr, wctx, ngx_http_cache_turbo_module);

    /* P5-6: hand the caller the subrequest's ctx so a specialised warm (the
     * HEAD-triggered store) can stamp its own capture flags on it. Published
     * HERE -- immediately after the ctx exists and BEFORE the failure arms
     * below -- because a subrequest that has been posted cannot be unwound:
     * an arm returning NGX_ERROR below still leaves `sr` live and still
     * running through our body filter, so a caller that only learns the ctx
     * on NGX_OK would miss exactly those cases and the blob would be stored
     * WITHOUT its flag. Publishing early makes the stamp unconditional on
     * the subrequest's existence rather than on warm_one()'s return value. */
    if (ctx_out != NULL) {
        *ctx_out = wctx;
    }

    /* Warm anonymously: strip inherited cookies so both the cache key and the
     * upstream request are the cookieless anonymous variant a visitor gets.
     *
     * P3-7: this is the fault-injectable arm for the bg_inflight leak test,
     * deliberately NOT the ctx-alloc arm just above. ctx is already seeded by
     * this point, so a forced failure here still leaves the subrequest
     * recognisably ours to the body filter and finalizes normally -- unlike
     * forcing wctx == NULL, which reintroduces the ctx-less "body forwarded,
     * main->count never dropped" condition s84 already fixed (see the
     * comment on the ctx alloc above). Injecting THAT would test a
     * known-fixed hang, not this feature's own decrement. */
    if (ngx_http_cache_turbo_warm_anonymize(sr) != NGX_OK
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
        || clcf->test_warm_ctx_fail
#endif
       )
    {
        return NGX_ERROR;
    }

    /* P1-4: inject a conditional validator from the currently stored blob (if
     * any) AFTER anonymize has rebuilt the private headers list -- anonymize
     * allocates that list, so an injection before it would land in the OLD
     * (still shared-with-parent) list and be discarded when anonymize swaps
     * it out from under us. */
    ngx_http_cache_turbo_warm_inject_validators(sr, snap, snap_len);

    /* Force a clean GET to the origin regardless of the admin request's method
     * (the admin POST is what triggered the warm). header_only stays 0: unlike
     * core SWR (which relies on the native file cache and can set header_only=1),
     * cache-turbo captures the body in its OWN body filter, so the full origin
     * body must stream through the filter chain to be stored. header_only=1
     * suppresses that streaming and the warm entry is never populated
     * (test_warm_populates). */
    sr->header_only = 0;

    /*
     * ⚠ UB-PROXYNULLURI. A subrequest is `internal` and, unlike the client
     * request it was spawned from, ngx_http_subrequest() leaves
     * sr->valid_unparsed_uri at 0 (it is only copied under
     * NGX_HTTP_SUBREQUEST_CLONE). That single bit decides which branch
     * ngx_http_proxy_create_request() takes for a `proxy_pass` whose URL has
     * NO URI component (`proxy_pass http://host;` -- no trailing slash, no
     * path), where ctx->vars.uri is the zeroed {0, NULL}:
     *
     *   valid_unparsed_uri=1 -> the unparsed_uri branch; 1383 never runs.
     *   valid_unparsed_uri=0 -> the else branch, whose copy is guarded ONLY by
     *                           r->valid_location (1 for every subrequest)
     *                           and NOT by ctx->vars.uri.len -- unlike the
     *                           length pass a hundred lines above, which does
     *                           test both. So it reaches
     *                           ngx_copy(dst, NULL, 0) == memcpy(dst, NULL, 0),
     *                           which is undefined behaviour: passing NULL for
     *                           a parameter declared __attribute__((nonnull))
     *                           even with n == 0.
     *
     * Under -fsanitize=undefined with halt_on_error=1 that ABORTS THE WORKER
     * mid-request, so the client sees a connection closed with no response.
     * Reproduced deterministically (nginx 1.31.3, gcc 14.2.0):
     *
     *   src/http/modules/ngx_http_proxy_module.c:1383:23: runtime error:
     *   null pointer passed as argument 2, which is declared to never be null
     *       #0 ngx_http_proxy_create_request  ngx_http_proxy_module.c:1383
     *       #1 ngx_http_upstream_init_request ngx_http_upstream.c:669
     *       ...
     *       #8 ngx_http_run_posted_requests   ngx_http_request.c:2648
     *
     * frame #8 being this very subrequest running off the posted-request
     * queue. It is latent nginx-core UB -- an ordinary internal redirect into
     * the same location shape reaches it too -- but a warm subrequest is one
     * of the ways to get there, so fix it where we control the code.
     *
     * THE FIX, and why it is safe rather than a workaround: this subrequest's
     * URI is `uri`/`args` as handed to us. When those are byte-identical to
     * the parent's own r->uri/r->args -- which is the case for EVERY internal
     * warm (SWR background refresh, the cache_turbo_store_head HEAD warm):
     * they pass &r->uri and &r->args verbatim -- then r->unparsed_uri is by
     * construction the raw form of this exact request target, and the
     * unparsed_uri branch emits precisely what the parent's own proxy_pass
     * would emit for the same location. Inheriting the bit is therefore not a
     * behaviour change; it restores the branch the client request already
     * takes.
     *
     * The admin warm endpoint (admin.c) passes an OPERATOR-SUPPLIED uri that
     * has nothing to do with r->unparsed_uri, so the bit stays 0 there -- the
     * upstream request line must be built from OUR uri, never from the admin
     * POST's. Fail safe: the comparison below is the whole gate.
     *
     * When the inherit gate does not apply, the admin path still needs SOME
     * valid_unparsed_uri=1 text to avoid the same UB, so it hands us
     * `unparsed_uri_src` -- the still-percent-escaped request-target text as
     * it appeared in the operator's warm list, taken BEFORE admin.c's own
     * ngx_unescape_uri() decoded `uri` into r->pool. That text is exactly
     * what belongs on the wire (unparsed_uri is copied verbatim into the
     * upstream request line, so it must already be escaped -- passing the
     * decoded `uri` here would send an unescaped path upstream). Synthesise
     * a private copy in the SUBREQUEST's own pool (never the parent's, and
     * never reused across warms) so its lifetime matches sr and it cannot be
     * mutated out from under a concurrent warm sharing the same admin
     * request. */
    if (r->valid_unparsed_uri
        && uri->len == r->uri.len
        && (uri->len == 0
            || ngx_memcmp(uri->data, r->uri.data, uri->len) == 0)
        && args->len == r->args.len
        && (args->len == 0
            || ngx_memcmp(args->data, r->args.data, args->len) == 0))
    {
        sr->valid_unparsed_uri = 1;

    } else if (unparsed_uri_src != NULL) {
        u_char  *up;

        up = ngx_pnalloc(sr->pool, unparsed_uri_src->len);
        if (up == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(up, unparsed_uri_src->data, unparsed_uri_src->len);

        sr->unparsed_uri.data = up;
        sr->unparsed_uri.len = unparsed_uri_src->len;
        sr->valid_unparsed_uri = 1;
    }

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
    conf->key_encoded_origin = NGX_CONF_UNSET;
    conf->serve_authorized = NGX_CONF_UNSET;
    conf->store_head = NGX_CONF_UNSET;
    conf->purge = NGX_CONF_UNSET;
    conf->background_update = NGX_CONF_UNSET;
    conf->background_update_max = NGX_CONF_UNSET;  /* P3-7; merges to 0 = unlimited */
    conf->warm_max = NGX_CONF_UNSET;  /* P5-2-p0; merges to WARM_MAX_DEFAULT (32) */
    conf->surrogate_key = NGX_CONF_UNSET;
    conf->lock = NGX_CONF_UNSET;
    conf->lock_timeout = NGX_CONF_UNSET_MSEC;
    conf->min_uses_window = NGX_CONF_UNSET;  /* P3-6; merges to 0 = off */
    conf->min_uses_raw = NGX_CONF_UNSET;
    /* S8: NGX_CONF_UNSET (not 0) so merge can tell "never set here" from an
     * explicit `off`, and an explicit off in a location still beats an
     * inherited `on`. Resolved to 0 (off) or 1..99 in merge_loc_conf. */
    conf->scan_resistant_pct = (ngx_uint_t) NGX_CONF_UNSET;
    conf->min_uses = NGX_CONF_UNSET;
    conf->l2_negative_ttl = NGX_CONF_UNSET;   /* L13; merges to 0 = off */
    conf->vary_marker_revalidate = NGX_CONF_UNSET;  /* c-2; merges to 2s */
    conf->keep_stale = NGX_CONF_UNSET;   /* S2.1; merges to 0 = off */
    conf->use_stale = NGX_CONF_UNSET_UINT;   /* S4.1; merges to USE_STALE_DEFAULT */
    conf->breaker_enable = NGX_CONF_UNSET;         /* O4.4; merges to 0 = off */
    conf->breaker_threshold = NGX_CONF_UNSET_UINT; /* O4.2; merges to 0 = off */
    conf->breaker_window = NGX_CONF_UNSET;         /* O4.2; merges to 0 = off */
    conf->breaker_count_retries = NGX_CONF_UNSET;  /* P5-5r; merges to 0=off */
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
    conf->ignore_set_cookie = NGX_CONF_UNSET_PTR;
    conf->backend_prefix = NGX_CONF_UNSET_PTR;
    conf->vary_ignore = NGX_CONF_UNSET_PTR;
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    conf->test_restore_alloc_fail = NGX_CONF_UNSET;
    conf->test_force_file_buf = NGX_CONF_UNSET;
    conf->test_store_fail = NGX_CONF_UNSET;
    conf->test_varidx_fail = NGX_CONF_UNSET;
    conf->test_scan_max_pages = NGX_CONF_UNSET;
    conf->test_scan_page_hold_ms = NGX_CONF_UNSET;
    conf->test_l2_promote_hold_ms = NGX_CONF_UNSET;
    conf->test_midbody_abort = NGX_CONF_UNSET;
    conf->test_warm_ctx_fail = NGX_CONF_UNSET;
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
