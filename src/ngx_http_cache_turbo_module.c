/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
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
static ngx_int_t ngx_http_cache_turbo_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_cache_turbo_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);

static ngx_int_t ngx_http_cache_turbo_serve(ngx_http_request_t *r,
    u_char *copy, size_t len, ngx_uint_t stale);
static ngx_int_t ngx_http_cache_turbo_cold_wait(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_ctx_t *ctx);
static void ngx_http_cache_turbo_cold_wait_timeout(ngx_event_t *ev);
static void ngx_http_cache_turbo_cold_mark_winner(ngx_http_request_t *r,
    ngx_http_cache_turbo_ctx_t *ctx, ngx_http_cache_turbo_zone_t *z);
static void ngx_http_cache_turbo_cold_cleanup(void *data);
static ngx_int_t ngx_http_cache_turbo_send_json(ngx_http_request_t *r,
    ngx_uint_t status, ngx_str_t *body);

static void *ngx_http_cache_turbo_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_cache_turbo_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_http_cache_turbo_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cache_turbo(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cache_turbo_key(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cache_turbo_valid_conf(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cache_turbo_admin(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cache_turbo_redis_conf(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_cache_turbo_tag(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cache_turbo_preset(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_cache_turbo_admin_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_cache_turbo_warm(ngx_http_request_t *r,
    ngx_str_t *urls);
static ngx_int_t ngx_http_cache_turbo_warm_one(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args);
static ngx_int_t ngx_http_cache_turbo_tag_purge_complete(ngx_http_request_t *r,
    void *data, ngx_str_t *members, ngx_uint_t nmembers);
static ngx_int_t ngx_http_cache_turbo_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_cache_turbo_normalized_args_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static char *ngx_http_cache_turbo_normalize_strip(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_cache_turbo_normalize_vary(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
/* auto-Vary (v11 other half) — defined near the v3-4 vary helpers but called
 * from the access/header/body paths above them, so forward-declared here. */
static void ngx_http_cache_turbo_vary_resolve(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_ctx_t *ctx, uint32_t *hash);
static void ngx_http_cache_turbo_variant_hash(ngx_http_request_t *r,
    ngx_str_t *base, ngx_int_t bits, u_char out[32]);
static void ngx_http_cache_turbo_marker_hash(ngx_str_t *base, u_char out[32]);
static void ngx_http_cache_turbo_marker_store(ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_http_cache_turbo_zone_t *z, ngx_str_t *base, ngx_int_t bits, time_t ttl);
static void ngx_http_cache_turbo_classify_vary(ngx_http_request_t *r,
    ngx_int_t *bits_out, ngx_uint_t *nocache_out);
static ngx_int_t ngx_http_cache_turbo_init(ngx_conf_t *cf);


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


/*
 * Preset bands (v3-2). Indexed by NGX_HTTP_CACHE_TURBO_PRESET_* (1-based; slot 0
 * is a never-used placeholder so an UNSET/zero preset can't silently index a
 * real band). BALANCED equals the historical hardcoded merge fallbacks. Tune by
 * feel; the chosen values are documented in
 * memory/eilandert/nginx-cache-turbo-module/history.md.
 */
/* Fields: valid, beta, lock_ttl, stale_mult, beta_min, beta_max. The last two are
 * the v4-3 autotune clamp window for the preset (×1000); the autotune verdict is
 * re-clamped to them so a conservative location never tunes as hot as aggressive
 * (see history.md v4-3). Centres match the static beta; bands subset global
 * [500,3000] with overlapping edges. */
static const ngx_http_cache_turbo_band_t  ngx_http_cache_turbo_bands[] = {
    /* [0] unused placeholder        */ {   0,    0,  0, 0,    0,    0 },
    /* [1] CONSERVATIVE: correctness */ {  30,  500, 10, 2,  500, 1000 },
    /* [2] BALANCED: current defaults*/ {  60, 1000,  5, 4,  500, 2000 },
    /* [3] AGGRESSIVE: max hit-rate  */ { 300, 3000,  3, 8, 1000, 3000 },
};


static ngx_command_t  ngx_http_cache_turbo_commands[] = {

    { ngx_string("cache_turbo_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_cache_turbo_zone,
      0,
      0,
      NULL },

    { ngx_string("cache_turbo"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_cache_turbo,
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

    { ngx_string("cache_turbo_lock_ttl"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, lock_ttl_raw),
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

    { ngx_string("cache_turbo_autotune_interval"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, autotune_interval),
      NULL },

    { ngx_string("cache_turbo_honor_cache_control"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, honor_cc),
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

    { ngx_string("cache_turbo_tag"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_cache_turbo_tag,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
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

    { ngx_string("cache_turbo_normalize_strip_all"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, normalize_strip_all),
      NULL },

    { ngx_string("cache_turbo_normalize_vary"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_http_cache_turbo_normalize_vary,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


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
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


/* Build the cache key string and its hash into the request ctx. */
static ngx_int_t
ngx_http_cache_turbo_build_key(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx)
{
    ngx_md5_t  md5;

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
     * key_hash is a 32-byte slot; MD5 fills the low 16 and the high 16 stay
     * zero (ctx is pcalloc'd). The collision guard is therefore effectively
     * 128-bit — ample for cache keying, and the redis hex key/lockkey encode
     * the full 32-byte slot so the on-wire layout is stable.
     */
    ngx_md5_init(&md5);
    ngx_md5_update(&md5, ctx->cache_key.data, ctx->cache_key.len);
    ngx_md5_final(ctx->key_hash, &md5);

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
 * Fresh TTL (seconds) to cache a response with this status, or -1 if the status
 * is not cacheable here (v6). 200 always caches at clcf->valid; any other status
 * caches only if a `cache_turbo_valid <code> <time>` rule named it. A 0 TTL
 * ("forever") is a valid return, so the not-cacheable sentinel is -1.
 */
static time_t
ngx_http_cache_turbo_status_ttl(ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_uint_t status)
{
    ngx_http_cache_turbo_valid_t  *v;
    ngx_uint_t                     i;

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


/* Parse the integer delta-seconds after a Cache-Control "<dir>=" token in
 * [p,last). Returns -1 if the token is absent or has no numeric value. */
static time_t
ngx_http_cache_turbo_cc_delta(u_char *p, u_char *last, const char *dir,
    size_t dirlen)
{
    u_char  *q, *e;

    q = ngx_strlcasestrn(p, last, (u_char *) dir, dirlen - 1);
    if (q == NULL) {
        return -1;
    }
    q += dirlen;                       /* past "<dir>=" */
    for (e = q; e < last && *e >= '0' && *e <= '9'; e++) { /* void */ }
    if (e == q) {
        return -1;
    }
    return (time_t) ngx_atoi(q, e - q);
}


/*
 * Fresh TTL derived from the response's own freshness headers (v7), or -1 if it
 * carries none. Cache-Control s-maxage wins over max-age; otherwise Expires
 * (absolute) minus now. A past Expires / a parse miss clamps to 0 (store but
 * immediately stale). no-store/private/max-age=0 are already refused upstream by
 * response_cacheable, so they never reach here.
 */
static time_t
ngx_http_cache_turbo_upstream_ttl(ngx_http_request_t *r)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;
    ngx_uint_t        i;
    u_char           *cc = NULL, *cc_last = NULL;
    ngx_str_t         expires = ngx_null_string;
    time_t            t;

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
        if (h[i].key.len == sizeof("Cache-Control") - 1
            && ngx_strncasecmp(h[i].key.data, (u_char *) "Cache-Control",
                               sizeof("Cache-Control") - 1) == 0)
        {
            cc = h[i].value.data;
            cc_last = cc + h[i].value.len;
        } else if (h[i].key.len == sizeof("Expires") - 1
                   && ngx_strncasecmp(h[i].key.data, (u_char *) "Expires",
                                      sizeof("Expires") - 1) == 0)
        {
            expires = h[i].value;
        }
    }

    if (cc != NULL) {
        t = ngx_http_cache_turbo_cc_delta(cc, cc_last, "s-maxage=",
                                          sizeof("s-maxage=") - 1);
        if (t < 0) {
            t = ngx_http_cache_turbo_cc_delta(cc, cc_last, "max-age=",
                                              sizeof("max-age=") - 1);
        }
        if (t >= 0) {
            return t;
        }
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

    p = ngx_pnalloc(r->pool, sizeof("{\"purged\":4294967295}\n"));
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    body.data = p;
    body.len = ngx_sprintf(p, "{\"purged\":%ui}\n", purged) - p;

    /* We are in the ACCESS phase: send the reply, finalize, and return NGX_DONE
     * so the phase engine stops here instead of falling through to proxy_pass
     * (same pattern as serve()). */
    drc = ngx_http_cache_turbo_send_json(r, NGX_HTTP_OK, &body);
    ngx_http_finalize_request(r, drc);
    return NGX_DONE;
}


static ngx_int_t
ngx_http_cache_turbo_access_handler(ngx_http_request_t *r)
{
    uint32_t                          hash;
    ngx_http_cache_turbo_ctx_t       *ctx;
    ngx_http_cache_turbo_node_t      *ctn;
    ngx_http_cache_turbo_zone_t      *z;
    ngx_http_cache_turbo_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);

    if (!clcf->enable || clcf->shm_zone == NULL) {
        return NGX_DECLINED;
    }

    /* PURGE method (v14): purge this URI's entry, then answer directly. Checked
     * before the GET/HEAD gate since PURGE is a non-standard method. */
    if (clcf->purge && r == r->main
        && r->method_name.len == sizeof("PURGE") - 1
        && ngx_strncmp(r->method_name.data, "PURGE", sizeof("PURGE") - 1) == 0)
    {
        return ngx_http_cache_turbo_purge_request(r, clcf);
    }

    /* Only cache safe idempotent reads for v1. */
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }

    if (r != r->main) {
        /* subrequest (e.g. our own background refresh) — never serve from
         * cache, let it hit the origin and repopulate. NB: nginx's access-phase
         * checker skips subrequests entirely (ngx_http_core_access_phase:
         * r != r->main -> phase_handler = next), so in practice this handler
         * only ever runs for the main request. A warm subrequest (v3-3) builds
         * its key + captures in the header/body filters, which DO run for
         * subrequests. */
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

    z = clcf->shm_zone->data;
    hash = ngx_crc32_short(ctx->key_hash, 32);

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
        return NGX_DECLINED;
    }

    /* Live autotune (v4-3): throttled per-zone recompute of the beta verdict from
     * the window's stats. Cheap to call every request (one time compare on the
     * fast path); the heavy recompute runs at most once per interval per worker.
     * Takes the zone mutex itself, so call it before we lock below. */
    if (clcf->autotune) {
        ngx_http_cache_turbo_autotune_maybe(z, clcf->autotune_interval);
    }

    ngx_shmtx_lock(&z->shpool->mutex);

    ctn = clcf->l1->lookup(z, ctx->key_hash, hash);

    if (ctn != NULL) {
        time_t     now = ngx_time();
        time_t     fresh_until = ctn->fresh_until;
        time_t     stale_until = ctn->stale_until;
        time_t     stale_window;
        ngx_int_t  refresh;

        if (now < fresh_until) {
            /* fresh hit: copy out of shm under lock, send after unlocking */
            u_char *snap = ngx_pnalloc(r->pool, ctn->len);
            size_t  snap_len = ctn->len;
            if (snap == NULL) {
                ngx_shmtx_unlock(&z->shpool->mutex);
                return NGX_ERROR;
            }
            ngx_memcpy(snap, ctn->data, snap_len);
            ngx_shmtx_unlock(&z->shpool->mutex);
            (void) ngx_atomic_fetch_add(&z->sh->hits, 1);
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: L1 HIT (fresh) \"%V\" key=%ui len=%uz",
                           &r->uri, (ngx_uint_t) hash, snap_len);
            return ngx_http_cache_turbo_serve(r, snap, snap_len, 0);
        }

        if ((stale_until == 0 || now < stale_until) && ctn->len > 0) {
            /* stale-but-serveable. The `len > 0` guard skips a cold-miss
             * single-flight STUB (v10: data == NULL, len == 0, stale_until == 0)
             * — a stub is an in-flight marker, never serveable; it falls through
             * to the cold path below where the waiter/claim logic handles it. */

            /* Cross-node single-flight resolved (v4-2): we parked for the Redis
             * NX and the phase engine re-entered. If we won, we own the
             * cluster-wide regen → go to origin. If we lost, fall through:
             * `refreshing` is already claimed (set before we parked) so the dice
             * is skipped and we serve stale via the tail below — no extra state
             * needed. */
            if (ctx->lock_done && ctx->lock_result == NGX_OK) {
                /* We own the cluster-wide regen. With background_update (v8,
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
                    return ngx_http_cache_turbo_serve(r, snap, snap_len, 1);
                }
                ngx_shmtx_unlock(&z->shpool->mutex);
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: cross-node lock WON \"%V\" key=%ui "
                               "-> regenerate", &r->uri, (ngx_uint_t) hash);
                return NGX_DECLINED;
            }

            stale_window = ngx_http_cache_turbo_stale_ttl(clcf->valid,
                               clcf->stale_mult)
                           - clcf->valid;
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

                /* snapshot the stale copy under the lock — used to serve stale on
                 * the single-box background-update path below. */
                snap_len = ctn->len;
                snap = ngx_pnalloc(r->pool, snap_len);
                if (snap == NULL) {
                    ngx_shmtx_unlock(&z->shpool->mutex);
                    return NGX_ERROR;
                }
                ngx_memcpy(snap, ctn->data, snap_len);

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
                    return ngx_http_cache_turbo_serve(r, snap, snap_len, 1);
                }

                return NGX_DECLINED;       /* inline regen (serves fresh) */
            }

            /* serve stale, no regeneration on this request */
            {
                u_char *snap = ngx_pnalloc(r->pool, ctn->len);
                size_t  snap_len = ctn->len;
                if (snap == NULL) {
                    ngx_shmtx_unlock(&z->shpool->mutex);
                    return NGX_ERROR;
                }
                ngx_memcpy(snap, ctn->data, snap_len);
                ngx_shmtx_unlock(&z->shpool->mutex);
                (void) ngx_atomic_fetch_add(&z->sh->stale_serves, 1);
                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: STALE serve \"%V\" key=%ui len=%uz",
                               &r->uri, (ngx_uint_t) hash, snap_len);
                return ngx_http_cache_turbo_serve(r, snap, snap_len, 1);
            }
        }

        /* expired: the L1 copy is past its stale window. Fall through to the
         * shared L2-consult/miss path below — another node may hold a fresher
         * copy in Redis, so we must check L2 before the origin (issue P6). */
    }

    /* L1 absent (miss) or expired. Consult L2 (Redis) before falling through to
     * the origin: another node may already hold this object. The L2 GET is
     * async but logically synchronous — it parks the request and resumes it
     * when the reply lands (see ngx_http_cache_turbo_redis_get). */
    ngx_shmtx_unlock(&z->shpool->mutex);

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
        /* L2 hit: validate the blob, populate L1 so later reads hit shm,
         * then serve it as a normal HIT. */
        ngx_http_cache_turbo_blob_hdr_t  bh;

        if (ctx->l2_blob_len >= sizeof(bh)) {
            ngx_memcpy(&bh, ctx->l2_blob, sizeof(bh));
            if (bh.magic == NGX_HTTP_CACHE_TURBO_BLOB_MAGIC) {
                (void) clcf->l1->store(z, ctx->key_hash, hash,
                           ctx->l2_blob, ctx->l2_blob_len, bh.status,
                           clcf->valid, clcf->stale_mult);
                (void) ngx_atomic_fetch_add(&z->sh->hits, 1);
                (void) ngx_atomic_fetch_add(&z->sh->l2_hits, 1);
                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: L2 HIT \"%V\" key=%ui len=%uz "
                               "(filled L1)", &r->uri, (ngx_uint_t) hash,
                               ctx->l2_blob_len);
                return ngx_http_cache_turbo_serve(r, ctx->l2_blob,
                           ctx->l2_blob_len, 0);
            }
        }
        /* corrupt/short blob: treat as a miss, fall through to origin */
    }

    /* L2 was consulted but did not satisfy the request (v12 metric). */
    if (clcf->backend && ctx->l2_done) {
        (void) ngx_atomic_fetch_add(&z->sh->l2_misses, 1);
    }

    /* Cold-miss single-flight (v10). L1 absent/expired and L2 missed: rather than
     * let every concurrent first-hit stampede the origin, the first request
     * becomes the single regenerator (per box via a stub shm node, cross-node via
     * the v4-2 Redis NX lock) and the rest WAIT for it to fill the cache, then
     * serve it. cache_turbo_lock off restores the old straight-to-origin path. */
    if (clcf->lock) {
        time_t     lock_ttl = clcf->lock_ttl;
        ngx_int_t  cl;

        if (lock_ttl <= 0) {
            lock_ttl = 5;
        }

        /* Resume after the cross-node NX park (we are the per-box claim winner
         * that fired the lock): won -> we own the fleet-wide regen, go to origin;
         * lost -> another node is filling, wait for its L2 write-through. */
        if (ctx->lock_done) {
            if (ctx->lock_result == NGX_OK) {
                (void) ngx_atomic_fetch_add(&z->sh->misses, 1);
                ngx_http_cache_turbo_cold_mark_winner(r, ctx, z);
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: cold-miss cross-node WON \"%V\" "
                               "key=%ui -> origin", &r->uri, (ngx_uint_t) hash);
                return NGX_DECLINED;
            }
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: cold-miss cross-node LOST \"%V\" key=%ui "
                           "-> wait for L2 fill", &r->uri, (ngx_uint_t) hash);
            return ngx_http_cache_turbo_cold_wait(r, clcf, z, ctx);
        }

        cl = clcf->l1->claim(z, ctx->key_hash, hash, lock_ttl);

        if (cl == NGX_HTTP_CACHE_TURBO_CLAIM_FRESH) {
            /* A real fresh entry raced in while we were on the cold path
             * (another local winner finished): re-serve it from L1. */
            ngx_http_cache_turbo_node_t  *fresh;
            u_char                       *snap;
            size_t                        snap_len;

            ngx_shmtx_lock(&z->shpool->mutex);
            fresh = clcf->l1->lookup(z, ctx->key_hash, hash);
            if (fresh != NULL && fresh->len > 0
                && ngx_time() < fresh->fresh_until)
            {
                snap_len = fresh->len;
                snap = ngx_pnalloc(r->pool, snap_len);
                if (snap == NULL) {
                    ngx_shmtx_unlock(&z->shpool->mutex);
                    return NGX_ERROR;
                }
                ngx_memcpy(snap, fresh->data, snap_len);
                ngx_shmtx_unlock(&z->shpool->mutex);
                (void) ngx_atomic_fetch_add(&z->sh->hits, 1);
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: cold-miss raced to FRESH \"%V\" "
                               "key=%ui -> serve", &r->uri, (ngx_uint_t) hash);
                return ngx_http_cache_turbo_serve(r, snap, snap_len, 0);
            }
            ngx_shmtx_unlock(&z->shpool->mutex);
            /* vanished again (evicted/expired in the race): go to origin */
            (void) ngx_atomic_fetch_add(&z->sh->misses, 1);
            return NGX_DECLINED;
        }

        if (cl == NGX_HTTP_CACHE_TURBO_CLAIM_LOSER) {
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
        ngx_http_cache_turbo_cold_mark_winner(r, ctx, z);
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
     * is picked up (per-box fills are caught by the L1 lookup itself). */
    ctx->l2_done = 0;
    ctx->l2_result = NGX_DECLINED;
    ctx->l2_blob = NULL;
    ctx->l2_blob_len = 0;

    delay = NGX_HTTP_CACHE_TURBO_LOCK_POLL_MS;
    if (delay > (ngx_msec_t) remaining) {
        delay = (ngx_msec_t) remaining;
    }

    if (ctx->cold_wait_ev.handler == NULL) {
        ctx->cold_wait_ev.handler = ngx_http_cache_turbo_cold_wait_timeout;
        ctx->cold_wait_ev.data = r;
        ctx->cold_wait_ev.log = r->connection->log;
    }

    ngx_add_timer(&ctx->cold_wait_ev, delay);
    r->main->count++;

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


/* Mark this request as the cold-miss winner that owns the in-flight stub, and
 * register a pool cleanup so the stub is removed at request teardown if the
 * winner never stored a real entry (non-cacheable response, oversized body,
 * upstream error, client abort). The header filter clears it earlier for the
 * common non-cacheable case; this is the backstop for every other non-store
 * exit. Registered once per request (the winner-DECLINED sites are reached at
 * most once). */
static void
ngx_http_cache_turbo_cold_mark_winner(ngx_http_request_t *r,
    ngx_http_cache_turbo_ctx_t *ctx, ngx_http_cache_turbo_zone_t *z)
{
    ngx_pool_cleanup_t  *cln;

    if (ctx->cold_winner) {
        return;
    }

    ctx->cold_winner = 1;
    ctx->cold_zone = z;

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return;
    }
    cln->handler = ngx_http_cache_turbo_cold_cleanup;
    cln->data = ctx;
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
    ngx_http_cache_turbo_shm_unstub(ctx->cold_zone, ctx->key_hash, hash);
}


/* Add a simple response header (name/value already in a stable buffer). */
static ngx_int_t
ngx_http_cache_turbo_add_header(ngx_http_request_t *r,
    u_char *name, size_t nlen, u_char *val, size_t vlen)
{
    ngx_table_elt_t  *h;

    h = ngx_list_push(&r->headers_out.headers);
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


/* Serve a cached object from a pool-owned snapshot (caller already copied it
 * out of shm and released the zone lock). */
static ngx_int_t
ngx_http_cache_turbo_serve(ngx_http_request_t *r, u_char *copy, size_t len,
    ngx_uint_t stale)
{
    u_char                           *p, *end, *body;
    size_t                            body_len;
    ngx_int_t                         rc;
    ngx_buf_t                        *b;
    ngx_chain_t                       out;
    ngx_http_cache_turbo_blob_hdr_t   hdr;
    ngx_http_cache_turbo_blob_hdr_t  *bh;
    ngx_http_cache_turbo_ctx_t       *ctx;
    uint32_t                          i;
    u_char                           *etag = NULL, *lastmod = NULL;
    size_t                            etag_len = 0, lastmod_len = 0;

    ctx = ngx_http_get_module_ctx(r, ngx_http_cache_turbo_module);
    if (ctx) {
        ctx->served = 1;           /* stop our filters re-capturing */
    }

    /* Backward/safety: blob must carry our header. The blob is byte-aligned
     * (ngx_pnalloc), so copy the header into a properly-aligned local rather
     * than casting the buffer to the struct (which is misaligned UB). */
    if (len < sizeof(ngx_http_cache_turbo_blob_hdr_t)) {
        return NGX_ERROR;
    }

    ngx_memcpy(&hdr, copy, sizeof(hdr));
    bh = &hdr;
    if (bh->magic != NGX_HTTP_CACHE_TURBO_BLOB_MAGIC) {
        return NGX_ERROR;
    }

    p   = copy + sizeof(ngx_http_cache_turbo_blob_hdr_t);
    end = p + bh->headers_len;
    body = end;
    body_len = bh->body_len;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cache_turbo: serve status=%ui body=%uz stale=%ui",
                   (ngx_uint_t) bh->status, body_len, stale);

    /* guard: header block must fit inside the blob */
    if (bh->headers_len > len - sizeof(hdr)
        || body_len > len - sizeof(hdr) - bh->headers_len)
    {
        return NGX_ERROR;
    }

    r->headers_out.status = bh->status;
    r->headers_out.content_length_n = body_len;

    /* Restore each stored header. Content-Type is mapped to the typed field;
     * the rest go onto the headers list. */
    for (i = 0; i < bh->nheaders && p + 8 <= end; i++) {
        uint32_t  nl, vl;
        u_char   *nm, *vv;

        ngx_memcpy(&nl, p, 4); p += 4;
        if (p + nl > end) { break; }
        nm = p; p += nl;

        if (p + 4 > end) { break; }
        ngx_memcpy(&vl, p, 4); p += 4;
        if (p + vl > end) { break; }
        vv = p; p += vl;

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

        (void) ngx_http_cache_turbo_add_header(r, nm, nl, vv, vl);
    }

    /* Conditional request (v11): a fresh OR stale 200 HIT whose stored ETag /
     * Last-Modified satisfy the client's If-None-Match / If-Modified-Since is
     * answered 304 with no body. Only 200 is validated this way (redirects and
     * other cached statuses serve normally); GET/HEAD only. Pre-converting the
     * status keeps core's not-modified header filter a no-op (it bails unless
     * status == 200), so there is no double handling. */
    if (bh->status == NGX_HTTP_OK
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

    /* X-Cache debug header */
    {
        static u_char  xc_name[] = "X-Cache";
        u_char        *state = stale ? (u_char *) "STALE" : (u_char *) "HIT";
        (void) ngx_http_cache_turbo_add_header(r, xc_name,
                   sizeof("X-Cache") - 1, state, ngx_strlen(state));
    }

    if (ngx_http_send_header(r) != NGX_OK) {
        return NGX_ERROR;
    }

    /* HEAD: header already sent, no body expected — done. */
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
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;
    ngx_uint_t        i;

    if (r->headers_in.authorization != NULL) {
        return 0;
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
        if (h[i].hash == 0 || h[i].key.len == 0) {
            continue;
        }

        if (h[i].key.len == sizeof("Set-Cookie") - 1
            && ngx_strncasecmp(h[i].key.data, (u_char *) "Set-Cookie",
                               sizeof("Set-Cookie") - 1) == 0)
        {
            return 0;
        }

        if (h[i].key.len == sizeof("Cache-Control") - 1
            && ngx_strncasecmp(h[i].key.data, (u_char *) "Cache-Control",
                               sizeof("Cache-Control") - 1) == 0)
        {
            u_char  *v = h[i].value.data;
            u_char  *e = v + h[i].value.len;

            if (ngx_strlcasestrn(v, e, (u_char *) "no-store", 8 - 1) != NULL
                || ngx_strlcasestrn(v, e, (u_char *) "no-cache", 8 - 1) != NULL
                || ngx_strlcasestrn(v, e, (u_char *) "private", 7 - 1) != NULL
                || ngx_strlcasestrn(v, e, (u_char *) "max-age=0", 9 - 1) != NULL
                || ngx_strlcasestrn(v, e, (u_char *) "s-maxage=0", 10 - 1)
                       != NULL)
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
 */
static ngx_int_t
ngx_http_cache_turbo_header_skip(u_char *name, size_t nlen)
{
    static const char  *skip[] = {
        "Connection", "Keep-Alive", "Proxy-Authenticate",
        "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding",
        "Upgrade", "Content-Length", "Set-Cookie", "Date", "Server",
        "Age", "X-Cache", "X-Cache-Status", NULL
    };
    ngx_uint_t  i;
    size_t      sl;

    for (i = 0; skip[i] != NULL; i++) {
        sl = ngx_strlen(skip[i]);
        if (nlen == sl
            && ngx_strncasecmp(name, (u_char *) skip[i], sl) == 0)
        {
            return 1;
        }
    }

    return 0;
}


static ngx_int_t
ngx_http_cache_turbo_header_filter(ngx_http_request_t *r)
{
    ngx_http_cache_turbo_ctx_t       *ctx;
    ngx_http_cache_turbo_loc_conf_t  *clcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_cache_turbo_module);

    if (ctx == NULL || ctx->served) {
        return ngx_http_next_header_filter(r);
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);

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
        && ngx_http_cache_turbo_status_ttl(clcf, r->headers_out.status) >= 0
        && ngx_http_cache_turbo_response_cacheable(r)
        && (clcf->no_store == NULL
            || ngx_http_test_predicates(r, clcf->no_store) == NGX_OK))
    {
        /* A warm subrequest never ran the access phase (nginx skips it for
         * subrequests), so its key was never built. Build it here from the
         * subrequest URI before flagging capture, so the body filter stores
         * under the same key a later real request will look up. */
        if (ctx->warm
            && ngx_http_cache_turbo_build_key(r, clcf, ctx) != NGX_OK)
        {
            return ngx_http_next_header_filter(r);
        }
        ctx->captured = 1;
    }

    /* Cold-miss single-flight (v10): if we are the winner but this response is
     * NOT cacheable, the body filter will never store, so clear our in-flight
     * stub now rather than make waiters block on it until lock_ttl. The pool
     * cleanup is the backstop for the remaining non-store paths. */
    if (ctx->cold_winner && !ctx->cold_stored && !ctx->captured
        && ctx->cold_zone != NULL)
    {
        uint32_t  hash = ngx_crc32_short(ctx->key_hash, 32);
        ngx_http_cache_turbo_shm_unstub(ctx->cold_zone, ctx->key_hash, hash);
        ctx->cold_stored = 1;
    }

    return ngx_http_next_header_filter(r);
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

    if (ctx == NULL || !ctx->captured || ctx->served) {
        return ngx_http_next_body_filter(r, in);
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);

    /* Append the incoming buffers to our captured chain (copying the bytes
     * into the request pool so they survive past this filter call). */
    ll = &ctx->body;
    while (*ll) {
        ll = &(*ll)->next;
    }

    for (cl = in; cl; cl = cl->next) {
        ngx_buf_t    *nb;
        ngx_chain_t  *ncl;

        b = cl->buf;
        n = ngx_buf_size(b);

        if (n > 0) {
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
        size_t                            hdr_bytes = 0, blob_len;
        uint32_t                          nheaders = 0;
        u_char                           *blob, *w;
        ngx_uint_t                        i;
        time_t                            ttl;

        ttl = ngx_http_cache_turbo_status_ttl(clcf, r->headers_out.status);
        if (ttl < 0) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: not cacheable \"%V\" status=%ui",
                           &r->uri, r->headers_out.status);
            return ngx_http_next_body_filter(r, in);   /* not cacheable */
        }

        /* Honor upstream freshness (v7): let the response's own
         * Cache-Control/Expires set the fresh TTL when enabled. */
        if (clcf->honor_cc) {
            time_t  up = ngx_http_cache_turbo_upstream_ttl(r);
            if (up >= 0) {
                ttl = up;
            }
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
            if (h[i].hash == 0 || h[i].key.len == 0
                || ngx_http_cache_turbo_header_skip(h[i].key.data,
                                                    h[i].key.len))
            {
                continue;
            }
            hdr_bytes += sizeof(uint32_t) + h[i].key.len
                         + sizeof(uint32_t) + h[i].value.len;
            nheaders++;
        }

        blob_len = sizeof(ngx_http_cache_turbo_blob_hdr_t)
                   + hdr_bytes + ctx->body_len;

        blob = ngx_pnalloc(r->pool, blob_len);
        if (blob != NULL) {
            ngx_http_cache_turbo_blob_hdr_t  bhw;
            u_char                           store_key[32];

            /* blob is byte-aligned; build the header in an aligned local and
             * memcpy it in rather than writing through a misaligned cast. */
            bhw.magic = NGX_HTTP_CACHE_TURBO_BLOB_MAGIC;
            bhw.nheaders = nheaders;
            bhw.headers_len = (uint32_t) hdr_bytes;
            bhw.body_len = (uint32_t) ctx->body_len;
            bhw.status = (uint32_t) r->headers_out.status;
            ngx_memcpy(blob, &bhw, sizeof(bhw));

            w = blob + sizeof(ngx_http_cache_turbo_blob_hdr_t);

            /* write a single name/value pair */
            #define CT_PUT(np, nl, vp, vl)                                     \
                do {                                                          \
                    uint32_t _l;                                              \
                    _l = (uint32_t) (nl); ngx_memcpy(w, &_l, 4); w += 4;      \
                    ngx_memcpy(w, (np), (nl)); w += (nl);                     \
                    _l = (uint32_t) (vl); ngx_memcpy(w, &_l, 4); w += 4;      \
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
                if (h[i].hash == 0 || h[i].key.len == 0
                    || ngx_http_cache_turbo_header_skip(h[i].key.data,
                                                        h[i].key.len))
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
                                                  ctx->vary_bits, store_key);
            }
            hash = ngx_crc32_short(store_key, 32);

            /* If we relocated the key away from the base (cold-miss winner that
             * only learned the Vary now), the cold-miss stub the access handler
             * left under the base key would never be overwritten by this store →
             * clear it so waiters on the base key stop blocking. unstub only drops
             * a still-stub node, so a real base entry (if any) is untouched. */
            if (ctx->cold_winner && !ctx->cold_stored
                && ngx_memcmp(store_key, ctx->key_hash, 32) != 0)
            {
                ngx_http_cache_turbo_shm_unstub(z, ctx->key_hash,
                                   ngx_crc32_short(ctx->key_hash, 32));
            }

            (void) clcf->l1->store(z, store_key, hash,
                       blob, blob_len, r->headers_out.status, ttl,
                       clcf->stale_mult);

            /* v10: store overwrote any cold-miss stub into a real entry (or we
             * cleared the relocated base stub above), so the cleanup must not
             * remove it. */
            ctx->cold_stored = 1;

            /* auto-Vary: persist the active-axis bitmask as an L1 marker under
             * the base key so the next request resolves straight to this variant
             * (node-local; self-heals if evicted). */
            if (clcf->auto_vary && ctx->vary_bits > 0) {
                ngx_http_cache_turbo_marker_store(clcf, z, &ctx->cache_key,
                                                  ctx->vary_bits, ttl);
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
             * its own pool, so it is safe even though `blob` lives in r->pool. */
            if (clcf->backend) {
                clcf->backend->set(r, clcf, store_key,
                                   blob, blob_len, ttl);
            }

            /* Tag index (v2c): for each tag in the cache_turbo_tag expression,
             * SADD this object's L2 key to the tag set so it can be purged by
             * tag later. Tags live only in L2; skip when Redis is off. */
            if (clcf->backend && clcf->tag) {
                ngx_str_t  tagval;

                if (ngx_http_complex_value(r, clcf->tag, &tagval) == NGX_OK
                    && tagval.len)
                {
                    time_t   stale_ttl;
                    u_char  *s, *e, *tok;

                    stale_ttl = ngx_http_cache_turbo_stale_ttl(ttl,
                                    clcf->stale_mult);
                    s = tagval.data;
                    e = tagval.data + tagval.len;

                    while (s < e) {
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
                        if (s > tok) {
                            clcf->backend->tag_add(clcf,
                                store_key, tok, (size_t) (s - tok),
                                stale_ttl);
                        }
                    }
                }
            }
        }
    }

    return ngx_http_next_body_filter(r, in);
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


/* "cache_turbo_preset conservative|balanced|aggressive;" stores the preset enum
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

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid cache_turbo_preset \"%V\": "
            "expected conservative, balanced, or aggressive",
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

    /* redis_tls_verify is still NGX_CONF_UNSET (-1) here unless tls_verify=off
     * set it to 0; -1 and 1 both mean "verify on" (merge resolves -1 -> 1). */
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

        } else if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
            s.data = value[i].data + 8;
            s.len = value[i].len - 8;
            t = ngx_parse_time(&s, 0);   /* milliseconds */
            if (t == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "cache_turbo_redis: bad timeout \"%V\"", &s);
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

    /* --- 4. build the SSL context if this is a TLS backend ---------------- */
    if (clcf->redis_tls == 1) {
#if (NGX_SSL)
        if (ngx_http_cache_turbo_redis_build_ssl(cf, clcf) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_redis: TLS (rediss:// / tls=on) requires nginx built "
            "with --with-http_ssl_module");
        return NGX_CONF_ERROR;
#endif
    }

    clcf->redis_enable = 1;

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


/* One hex nibble -> 0..15, or -1 on a non-hex char. */
static ngx_int_t
ngx_http_cache_turbo_hexval(u_char c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
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


/* State carried through an async tag purge from the admin handler to the
 * SMEMBERS completion callback. */
typedef struct {
    ngx_http_cache_turbo_loc_conf_t  *clcf;
    ngx_http_cache_turbo_zone_t      *zone;
    ngx_str_t                         tag;    /* copied into r->pool */
} ngx_http_cache_turbo_tagpurge_t;


/* SMEMBERS completion: drop every member object from L1 + L2, delete the now-
 * empty tag set, and answer {"purged":N}. Runs while `members` (which point
 * into the redis op buffer) are still valid; everything it keeps is copied or
 * acted on synchronously here. */
static ngx_int_t
ngx_http_cache_turbo_tag_purge_complete(ngx_http_request_t *r, void *data,
    ngx_str_t *members, ngx_uint_t nmembers)
{
    ngx_http_cache_turbo_tagpurge_t  *tp = data;
    ngx_uint_t                        i, purged = 0;
    size_t                            plen, n;
    u_char                           *tagkey, *p;
    ngx_str_t                         body;

    plen = tp->clcf->redis_prefix.len;

    for (i = 0; i < nmembers; i++) {
        if (members[i].len == 0) {
            continue;
        }

        /* The member IS the object's L2 key: drop it from Redis. */
        tp->clcf->backend->del_raw(tp->clcf, members[i].data,
                                   members[i].len);

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
                    size_t  locklen;
                    locklen = ngx_http_cache_turbo_redis_lockkey(
                                  &tp->clcf->redis_prefix, key_hash, lockbuf);
                    tp->clcf->backend->del_raw(tp->clcf, lockbuf, locklen);
                }
            }
        }

        purged++;
    }

    /* Remove the (now-emptied) tag set itself. */
    tagkey = ngx_pnalloc(r->pool, plen + sizeof("tag:") - 1 + tp->tag.len);
    if (tagkey != NULL) {
        n = tp->clcf->backend->tagkey(&tp->clcf->redis_prefix,
                 tp->tag.data, tp->tag.len, tagkey);
        tp->clcf->backend->del_raw(tp->clcf, tagkey, n);
    }

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


/* SCAN-del completion (?all=1): the L2 keyspace has been walked + DEL'd; emit
 * {"purged":N} where N is the L1 count (L2 deletions are fire-and-forget and not
 * separately counted). members/nmembers are unused (always 0 here). */
static ngx_int_t
ngx_http_cache_turbo_all_purge_complete(ngx_http_request_t *r, void *data,
    ngx_str_t *members, ngx_uint_t nmembers)
{
    ngx_http_cache_turbo_allpurge_t  *ap = data;
    u_char                           *p;
    ngx_str_t                         body;

    (void) members;
    (void) nmembers;

    p = ngx_pnalloc(r->pool, sizeof("{\"purged\":4294967295}\n"));
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    body.data = p;
    body.len = ngx_sprintf(p, "{\"purged\":%ui}\n", ap->purged) - p;

    return ngx_http_cache_turbo_send_json(r, NGX_HTTP_OK, &body);
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

        if (r->args.len
            && ngx_http_arg(r, (u_char *) "all", 3, &arg) == NGX_OK)
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
                /* NGX_ERROR: L2 unavailable — fall through to the sync reply
                 * below with the L1 count (L2 left as-is). */
            }

        } else if (r->args.len
                   && ngx_http_arg(r, (u_char *) "key", 3, &arg) == NGX_OK)
        {
            ngx_md5_t  md5;
            u_char     key_hash[32];
            uint32_t   hash;

            ngx_memzero(key_hash, sizeof(key_hash));
            ngx_md5_init(&md5);
            ngx_md5_update(&md5, arg.data, arg.len);
            ngx_md5_final(key_hash, &md5);
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

            if (clcf->backend == NULL) {
                ngx_str_set(&body,
                    "{\"error\":\"tag purge requires cache_turbo_redis\"}\n");
                return ngx_http_cache_turbo_send_json(r,
                           NGX_HTTP_BAD_REQUEST, &body);
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

            /* Seven counters (*_total) + two gauges, each labelled by zone so one
             * Prometheus job can scrape many zones. Exposition format 0.0.4. */
            len = 2800 + 10 * zname.len + 10 * NGX_ATOMIC_T_LEN;
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
                "# HELP cache_turbo_l2_hits_total L1 misses satisfied by the L2 (Redis) tier.\n"
                "# TYPE cache_turbo_l2_hits_total counter\n"
                "cache_turbo_l2_hits_total{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_l2_misses_total L1 misses that L2 could not satisfy (went to origin).\n"
                "# TYPE cache_turbo_l2_misses_total counter\n"
                "cache_turbo_l2_misses_total{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_lock_waits_total Cold-miss requests that waited for a single-flight fill (v10).\n"
                "# TYPE cache_turbo_lock_waits_total counter\n"
                "cache_turbo_lock_waits_total{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_regen_cost_ms Average origin regeneration cost in milliseconds.\n"
                "# TYPE cache_turbo_regen_cost_ms gauge\n"
                "cache_turbo_regen_cost_ms{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_autotuned_beta Live autotuned SWR beta (x1000; 0 = none).\n"
                "# TYPE cache_turbo_autotuned_beta gauge\n"
                "cache_turbo_autotuned_beta{zone=\"%V\"} %uA\n",
                &zname, st.hits, &zname, st.misses, &zname, st.stale_serves,
                &zname, st.refreshes, &zname, st.evictions,
                &zname, st.l2_hits, &zname, st.l2_misses, &zname, st.lock_waits,
                &zname, st.cost_ms, &zname, st.autotuned_beta) - p;

            return ngx_http_cache_turbo_send_body(r, NGX_HTTP_OK, &body,
                "text/plain; version=0.0.4; charset=utf-8",
                sizeof("text/plain; version=0.0.4; charset=utf-8") - 1);
        }

        len = sizeof("{\"hits\":,\"misses\":,\"stale_serves\":,\"refreshes\":,"
                     "\"evictions\":,\"l2_hits\":,\"l2_misses\":,\"lock_waits\":,"
                     "\"cost_ms\":,\"autotuned_beta\":}\n")
              + 10 * NGX_ATOMIC_T_LEN;
        p = ngx_pnalloc(r->pool, len);
        if (p == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        body.data = p;
        body.len = ngx_sprintf(p,
            "{\"hits\":%uA,\"misses\":%uA,\"stale_serves\":%uA,"
            "\"refreshes\":%uA,\"evictions\":%uA,\"l2_hits\":%uA,"
            "\"l2_misses\":%uA,\"lock_waits\":%uA,\"cost_ms\":%uA,"
            "\"autotuned_beta\":%uA}\n",
            st.hits, st.misses, st.stale_serves,
            st.refreshes, st.evictions, st.l2_hits, st.l2_misses,
            st.lock_waits, st.cost_ms, st.autotuned_beta) - p;
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

    /* Force a clean GET to the origin regardless of the admin request's method
     * (the admin POST is what triggered the warm). */
    sr->method = NGX_HTTP_GET;
    ngx_str_set(&sr->method_name, "GET");
    sr->header_only = 0;

    wctx = ngx_pcalloc(sr->pool, sizeof(ngx_http_cache_turbo_ctx_t));
    if (wctx == NULL) {
        return NGX_ERROR;
    }
    wctx->warm = 1;
    ngx_http_set_ctx(sr, wctx, ngx_http_cache_turbo_module);

    return NGX_OK;
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

/* Accept-Encoding collapsed to a small, stable enum so the cache shards by what
 * the response actually IS (zstd/br/gzip/identity), not by the per-browser raw
 * header. Priority zstd > br > gzip mirrors what our stack serves when the client
 * accepts several: the http-zstd filter emits zstd whenever the client advertises
 * zstd (ngx_http_zstd_ok), winning over brotli/gzip, and brotli wins over gzip.
 * We ship http-zstd, so zstd MUST be bucketed or a zstd-only client could read an
 * identity entry and a zstd+br client could collide a zstd body under ae=br
 * (issues V6). Absent/empty header => identity. Case-insensitive substring. */
static const char *
ngx_http_cache_turbo_ae_class(ngx_http_request_t *r)
{
    ngx_table_elt_t  *ae = r->headers_in.accept_encoding;
    u_char           *s, *last;

    if (ae == NULL || ae->value.len == 0) {
        return "identity";
    }

    s = ae->value.data;
    last = s + ae->value.len;

    if (ngx_strlcasestrn(s, last, (u_char *) "zstd", 4 - 1) != NULL) {
        return "zstd";
    }
    if (ngx_strlcasestrn(s, last, (u_char *) "br", 2 - 1) != NULL) {
        return "br";
    }
    if (ngx_strlcasestrn(s, last, (u_char *) "gzip", 4 - 1) != NULL) {
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


/* Derive the secondary VARIANT key from the base key material plus the request
 * values of the named (whitelisted) Vary axes. Axes are folded in a FIXED order
 * (ae, dev, lang, origin) regardless of the response Vary token order, so two
 * nodes / two requests with the same axis values compute the same key. Encoding
 * and device are bucketed to a class (reusing the v3-4 helpers); language and
 * origin fold their raw values. The 0x1F (US) delimiter can never appear in a
 * URI or these header values, so the suffix cannot collide with the base
 * material. md5 fills the low 16 bytes; the high 16 are zeroed first (the slot
 * layout matches build_key, so a base and a variant only ever differ by the
 * folded bytes). */
static void
ngx_http_cache_turbo_variant_hash(ngx_http_request_t *r, ngx_str_t *base,
    ngx_int_t bits, u_char out[32])
{
    ngx_md5_t          md5;
    const char        *cls;
    ngx_str_t          v;
    static const u_char us = 0x1F;

    ngx_memzero(out, 32);
    ngx_md5_init(&md5);
    ngx_md5_update(&md5, base->data, base->len);

    if (bits & NGX_HTTP_CACHE_TURBO_VARY_ENCODING) {
        cls = ngx_http_cache_turbo_ae_class(r);
        ngx_md5_update(&md5, &us, 1);
        ngx_md5_update(&md5, "ae=", 3);
        ngx_md5_update(&md5, cls, ngx_strlen(cls));
    }
    if (bits & NGX_HTTP_CACHE_TURBO_VARY_DEVICE) {
        cls = ngx_http_cache_turbo_device_class(r);
        ngx_md5_update(&md5, &us, 1);
        ngx_md5_update(&md5, "dev=", 4);
        ngx_md5_update(&md5, cls, ngx_strlen(cls));
    }
    if (bits & NGX_HTTP_CACHE_TURBO_VARY_LANG) {
        v = ngx_http_cache_turbo_req_header(r, "Accept-Language",
                                            sizeof("Accept-Language") - 1);
        ngx_md5_update(&md5, &us, 1);
        ngx_md5_update(&md5, "lang=", 5);
        ngx_md5_update(&md5, v.data, v.len);
    }
    if (bits & NGX_HTTP_CACHE_TURBO_VARY_ORIGIN) {
        v = ngx_http_cache_turbo_req_header(r, "Origin", sizeof("Origin") - 1);
        ngx_md5_update(&md5, &us, 1);
        ngx_md5_update(&md5, "org=", 4);
        ngx_md5_update(&md5, v.data, v.len);
    }

    ngx_md5_final(out, &md5);
}


/* The dedicated L1 slot key for the vary marker of a base key. Distinct from the
 * object key (it folds a "varymark" tag) so the marker never collides with an
 * object slot or a cold-miss stub. */
static void
ngx_http_cache_turbo_marker_hash(ngx_str_t *base, u_char out[32])
{
    ngx_md5_t          md5;
    static const u_char us = 0x1F;

    ngx_memzero(out, 32);
    ngx_md5_init(&md5);
    ngx_md5_update(&md5, base->data, base->len);
    ngx_md5_update(&md5, &us, 1);
    ngx_md5_update(&md5, "varymark", sizeof("varymark") - 1);
    ngx_md5_final(out, &md5);
}


/* Store/refresh the L1 vary marker for a base key: a one-byte body carrying the
 * active-axis bitmask, wrapped in the standard blob header so a later read can
 * validate the magic before trusting the byte. L1-only and node-local by design
 * (see the loc_conf auto_vary comment); shm store copies the stack blob in. */
static void
ngx_http_cache_turbo_marker_store(ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_http_cache_turbo_zone_t *z, ngx_str_t *base, ngx_int_t bits, time_t ttl)
{
    u_char                           mk[32];
    u_char                           blob[sizeof(ngx_http_cache_turbo_blob_hdr_t)
                                          + 1];
    ngx_http_cache_turbo_blob_hdr_t  bh;

    bh.magic = NGX_HTTP_CACHE_TURBO_BLOB_MAGIC;
    bh.nheaders = 0;
    bh.headers_len = 0;
    bh.body_len = 1;
    bh.status = 0;
    ngx_memcpy(blob, &bh, sizeof(bh));
    blob[sizeof(bh)] = (u_char) (bits & 0xFF);

    ngx_http_cache_turbo_marker_hash(base, mk);

    (void) clcf->l1->store(z, mk, ngx_crc32_short(mk, 32),
               blob, sizeof(blob), 0, ttl, clcf->stale_mult);
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
    ngx_http_cache_turbo_node_t  *m;

    ngx_http_cache_turbo_marker_hash(&ctx->cache_key, mk);

    ngx_shmtx_lock(&z->shpool->mutex);
    m = clcf->l1->lookup(z, mk, ngx_crc32_short(mk, 32));
    if (m != NULL && m->data != NULL
        && m->len >= sizeof(ngx_http_cache_turbo_blob_hdr_t) + 1
        && ngx_time() < m->fresh_until)
    {
        bits = m->data[sizeof(ngx_http_cache_turbo_blob_hdr_t)];
    }
    ngx_shmtx_unlock(&z->shpool->mutex);

    if (bits > 0) {
        ngx_http_cache_turbo_variant_hash(r, &ctx->cache_key, bits,
                                          ctx->key_hash);
        *hash = ngx_crc32_short(ctx->key_hash, 32);
        ctx->varied = 1;
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: auto-Vary marker hit \"%V\" bits=0x%xi "
                       "-> variant key", &r->uri, bits);
    }
}


/* Classify the response Vary header into a safe-axis bitmask (what we may key
 * on) and a nocache veto. Only the whitelist (Accept-Encoding, User-Agent,
 * Accept-Language, Origin) contributes to the key; Vary: * or a Vary naming
 * Cookie / Authorization forces the response uncacheable (cross-user
 * poisoning/leak guard); any other named header is ignored (the response is
 * still cached, just not split on that header). Walks every Vary header instance
 * and tokenises on comma/whitespace. */
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
            }
            /* any other token: ignored (still cacheable, not split on it) */
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

    /* strip_all, or no args at all: output is the Vary suffix alone (no '?'). */
    if (clcf->normalize_strip_all || r->args.len == 0) {
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
    conf->valid_raw = NGX_CONF_UNSET;
    conf->beta_raw = NGX_CONF_UNSET;
    conf->lock_ttl_raw = NGX_CONF_UNSET;
    conf->autotune = NGX_CONF_UNSET;
    conf->autotune_interval = NGX_CONF_UNSET;
    conf->honor_cc = NGX_CONF_UNSET;
    conf->auto_vary = NGX_CONF_UNSET;
    conf->purge = NGX_CONF_UNSET;
    conf->background_update = NGX_CONF_UNSET;
    conf->lock = NGX_CONF_UNSET;
    conf->lock_timeout = NGX_CONF_UNSET_MSEC;
    conf->max_size = NGX_CONF_UNSET_SIZE;
    conf->redis_enable = NGX_CONF_UNSET;
    conf->redis_timeout = NGX_CONF_UNSET_MSEC;
    conf->redis_keepalive = NGX_CONF_UNSET;
    conf->redis_keepalive_timeout = NGX_CONF_UNSET_MSEC;
    conf->redis_db = NGX_CONF_UNSET;
    conf->redis_tls = NGX_CONF_UNSET;
    conf->redis_tls_verify = NGX_CONF_UNSET;
    conf->normalize_strip_all = NGX_CONF_UNSET;
    conf->normalize_strip = NGX_CONF_UNSET_PTR;
    conf->normalize_vary = NGX_CONF_UNSET;
    conf->bypass = NGX_CONF_UNSET_PTR;
    conf->no_store = NGX_CONF_UNSET_PTR;
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
     *     level's resolved-preset band value. stale_mult is preset-only (no
     *     directive yet), so it always takes the band value.
     *
     * Net effect: an explicit directive beats a preset; a nearer preset beats a
     * farther one; nothing leaks a band default into the inheritance chain.
     */
    if (conf->preset == NGX_CONF_UNSET) {
        conf->preset = prev->preset;
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

        conf->valid = (conf->valid_raw == NGX_CONF_UNSET)
                          ? band->valid : conf->valid_raw;
        conf->beta = (conf->beta_raw == NGX_CONF_UNSET)
                          ? band->beta : conf->beta_raw;
        conf->lock_ttl = (conf->lock_ttl_raw == NGX_CONF_UNSET)
                          ? band->lock_ttl : conf->lock_ttl_raw;
        conf->stale_mult = band->stale_mult;
    }

    /* Per-status TTLs (v6): inherit the rule list if this level set none. */
    if (conf->valid_status == NULL) {
        conf->valid_status = prev->valid_status;
    }

    /* Bypass / no-store predicates (v9). */
    ngx_conf_merge_ptr_value(conf->bypass, prev->bypass, NULL);
    ngx_conf_merge_ptr_value(conf->no_store, prev->no_store, NULL);

    /* Honor upstream Cache-Control/Expires (v7): off by default. */
    ngx_conf_merge_value(conf->honor_cc, prev->honor_cc, 0);
    ngx_conf_merge_value(conf->auto_vary, prev->auto_vary, 0);

    /* PURGE method (v14): off by default. */
    ngx_conf_merge_value(conf->purge, prev->purge, 0);

    /* v8: background update / SWR defaults ON — the dice-winner serves stale and
     * refreshes in the background rather than blocking on origin. */
    ngx_conf_merge_value(conf->background_update, prev->background_update, 1);

    /* v10: cold-miss single-flight defaults ON — concurrent first-hits for one
     * cold key collapse to a single origin fetch; the rest wait up to
     * lock_timeout (default 5s) and serve the filled entry. */
    ngx_conf_merge_value(conf->lock, prev->lock, 1);
    ngx_conf_merge_msec_value(conf->lock_timeout, prev->lock_timeout, 5000);

    /* Live autotune (v4-3): off by default; default recompute cadence when on. */
    ngx_conf_merge_value(conf->autotune, prev->autotune, 0);
    ngx_conf_merge_sec_value(conf->autotune_interval, prev->autotune_interval,
                             NGX_HTTP_CACHE_TURBO_AT_INTERVAL);

    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }
    if (conf->key == NULL) {
        conf->key = prev->key;
    }

    /* Default cache key (no explicit cache_turbo_key) for an enabled location:
     * $host$uri$cache_turbo_normalized_args — host so vhosts don't collide, $uri
     * for the path, and the normalized args so tracking params are stripped and
     * args are order-insensitive out of the box. Compiled lazily here; the
     * variable was registered in preconfiguration. */
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

    /* L2 Redis: inherit address/prefix/timeout, default prefix "ct:". */
    ngx_conf_merge_value(conf->redis_enable, prev->redis_enable, 0);
    ngx_conf_merge_msec_value(conf->redis_timeout, prev->redis_timeout, 250);
    ngx_conf_merge_value(conf->redis_keepalive, prev->redis_keepalive, 0);
    ngx_conf_merge_msec_value(conf->redis_keepalive_timeout,
                              prev->redis_keepalive_timeout, 60000);

    if (conf->redis_addr.sockaddr == NULL) {
        conf->redis_addr = prev->redis_addr;
    }
    if (conf->redis_prefix.data == NULL) {
        if (prev->redis_prefix.data) {
            conf->redis_prefix = prev->redis_prefix;
        } else {
            ngx_str_set(&conf->redis_prefix,
                        NGX_HTTP_CACHE_TURBO_REDIS_PREFIX);
        }
    }

    /* L2 auth/db/tls (v5 DSN). Inherit alongside the address. */
    ngx_conf_merge_str_value(conf->redis_user, prev->redis_user, "");
    ngx_conf_merge_str_value(conf->redis_password, prev->redis_password, "");
    ngx_conf_merge_value(conf->redis_db, prev->redis_db, 0);
    ngx_conf_merge_value(conf->redis_tls, prev->redis_tls, 0);
    ngx_conf_merge_value(conf->redis_tls_verify, prev->redis_tls_verify, 1);
    ngx_conf_merge_str_value(conf->redis_tls_ca, prev->redis_tls_ca, "");
    ngx_conf_merge_str_value(conf->redis_tls_name, prev->redis_tls_name, "");
    ngx_conf_merge_str_value(conf->redis_host, prev->redis_host, "");
#if (NGX_SSL)
    if (conf->redis_ssl == NULL) {
        conf->redis_ssl = prev->redis_ssl;
    }
#endif

    /* Resolve the backend vtables (v4-1). l1 is a stateless dispatch table, so
     * it is always wired (the zone is an argument, not driver state). backend is
     * the remote L2 driver, present only when cache_turbo_redis was configured;
     * call sites guard on it being non-NULL. */
    conf->l1 = &ngx_http_cache_turbo_shm_backend;
    conf->backend = conf->redis_enable
                        ? &ngx_http_cache_turbo_redis_backend : NULL;

    /* Key normalize: inherit strip_all + the extra-pattern list. */
    ngx_conf_merge_value(conf->normalize_strip_all, prev->normalize_strip_all,
                         0);
    if (conf->normalize_strip == NGX_CONF_UNSET_PTR) {
        conf->normalize_strip = prev->normalize_strip;
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

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_cache_turbo_access_handler;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_cache_turbo_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_cache_turbo_body_filter;

    return NGX_OK;
}
