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
static ngx_int_t ngx_http_cache_turbo_precontent_handler(ngx_http_request_t *r);
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
static char *ngx_http_cache_turbo_backend(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_cache_turbo_auto_skip(ngx_http_request_t *r,
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
    ngx_str_t *base, ngx_int_t bits, ngx_uint_t gen, u_char out[32]);
static void ngx_http_cache_turbo_marker_hash(ngx_str_t *base, u_char out[32]);
static void ngx_http_cache_turbo_marker_store(ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_http_cache_turbo_zone_t *z, ngx_str_t *base, ngx_int_t bits,
    ngx_uint_t gen, time_t ttl);
/* COR-5: the per-base variant-index set name (space-framed so no user tag token
 * can collide) + the L1-only generation bump. */
static size_t ngx_http_cache_turbo_variant_index_name(ngx_str_t *base,
    u_char *buf);
static void ngx_http_cache_turbo_classify_vary(ngx_http_request_t *r,
    ngx_int_t *bits_out, ngx_uint_t *nocache_out);
static ngx_uint_t ngx_http_cache_turbo_response_has_vary(ngx_http_request_t *r);
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

    { ngx_string("cache_turbo_safe_key"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, safe_key),
      NULL },

    { ngx_string("cache_turbo_vary_safe"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, vary_safe),
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
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, min_uses),
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


static void
ngx_http_cache_turbo_digest_init(ngx_http_cache_turbo_digest_t *d)
{
#if (NGX_SSL)
    d->md = EVP_MD_CTX_new();
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


/* Finalise into the 32-byte slot. */
static void
ngx_http_cache_turbo_digest_final(ngx_http_cache_turbo_digest_t *d,
    u_char out[32])
{
#if (NGX_SSL)
    unsigned int  n = 0;

    if (d->ok && EVP_DigestFinal_ex(d->md, out, &n) == 1 && n == 32) {
        /* ok */
    } else {
        /* EVP_MD_CTX alloc/finalise failure (OOM) — degrade to a fixed slot
         * rather than read uninitialised bytes. Practically unreachable. */
        ngx_memzero(out, 32);
    }
    if (d->md != NULL) {
        EVP_MD_CTX_free(d->md);
        d->md = NULL;
    }
#else
    ngx_md5_final(out, &d->lo);          /* low 16 */
    ngx_md5_final(out + 16, &d->hi);     /* high 16 */
#endif
}


/* One-shot convenience for a single contiguous input. */
static void
ngx_http_cache_turbo_digest(const void *data, size_t len, u_char out[32])
{
    ngx_http_cache_turbo_digest_t  d;

    ngx_http_cache_turbo_digest_init(&d);
    ngx_http_cache_turbo_digest_update(&d, data, len);
    ngx_http_cache_turbo_digest_final(&d, out);
}


/* ------------------------------------------------------------------------- *
 * STAB-4: fixed little-endian, padding-free blob wire header (40 bytes).
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

    if (len < NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE) {
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
     * key_hash is a 32-byte slot filled with a 256-bit digest (SEC-2): the
     * redis hex key/lockkey encode the full slot, so the on-wire layout is
     * stable and the whole 256 bits are the collision guard (was MD5 in the low
     * 16 with the high 16 zeroed = effectively 128-bit). ctx is pcalloc'd, but
     * the digest fills all 32 bytes regardless.
     */
    ngx_http_cache_turbo_digest(ctx->cache_key.data, ctx->cache_key.len,
                                ctx->key_hash);

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
        t = ngx_http_cache_turbo_cc_delta(cc, cc_last, "s-maxage",
                                          sizeof("s-maxage") - 1);
        if (t < 0) {
            t = ngx_http_cache_turbo_cc_delta(cc, cc_last, "max-age",
                                              sizeof("max-age") - 1);
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
    ngx_list_part_t  *part = &r->headers_out.headers.part;
    ngx_table_elt_t  *h = part->elts;
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
        if (h[i].hash == 0
            || h[i].key.len != sizeof("Cache-Control") - 1
            || ngx_strncasecmp(h[i].key.data, (u_char *) "Cache-Control",
                               sizeof("Cache-Control") - 1) != 0)
        {
            continue;
        }

        {
            u_char  *v = h[i].value.data;
            u_char  *e = v + h[i].value.len;

            if (ngx_http_cache_turbo_cc_has(v, e, "must-revalidate",
                    sizeof("must-revalidate") - 1)
                || ngx_http_cache_turbo_cc_has(v, e, "proxy-revalidate",
                    sizeof("proxy-revalidate") - 1))
            {
                return 1;
            }
        }
    }

    return 0;
}


/*
 * RFC 9111 §5.2.1.4: a request Cache-Control: no-cache (or the legacy
 * Pragma: no-cache) means "do not reuse a stored response without successful
 * validation". We have no upstream validation channel for a cache hit, so the
 * conservative-correct behaviour is to skip the cache lookup and go to the
 * origin (the fresh response is still stored, refreshing the entry). Walks the
 * request header list once; both headers are rare so first-match is fine.
 */
static ngx_int_t
ngx_http_cache_turbo_request_no_cache(ngx_http_request_t *r)
{
    ngx_list_part_t  *part = &r->headers_in.headers.part;
    ngx_table_elt_t  *h = part->elts;
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
        if (h[i].hash == 0) {
            continue;
        }

        if (h[i].key.len == sizeof("Cache-Control") - 1
            && ngx_strncasecmp(h[i].key.data, (u_char *) "Cache-Control",
                               sizeof("Cache-Control") - 1) == 0)
        {
            if (ngx_http_cache_turbo_cc_has(h[i].value.data,
                    h[i].value.data + h[i].value.len, "no-cache",
                    sizeof("no-cache") - 1))
            {
                return 1;
            }

        } else if (h[i].key.len == sizeof("Pragma") - 1
                   && ngx_strncasecmp(h[i].key.data, (u_char *) "Pragma",
                                      sizeof("Pragma") - 1) == 0)
        {
            if (ngx_http_cache_turbo_cc_has(h[i].value.data,
                    h[i].value.data + h[i].value.len, "no-cache",
                    sizeof("no-cache") - 1))
            {
                return 1;
            }
        }
    }

    return 0;
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
            ngx_http_cache_turbo_marker_store(clcf, z, &ctx->cache_key, bits,
                                              mgen + 1, mttl);
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


/* >>> FUZZ-EXTRACT auto-classify BEGIN (fuzz/extract_auto_classify.sh) <<< */
/*
 * Auto-classify preset registry. Each row is one CMS backend: NULL-terminated
 * lists of request-Cookie name substrings, r->uri prefixes, and query-arg keys
 * that mark a request as a dynamic surface that must NOT be cached. Adding a
 * backend is one row here — no new code path. `generic` (bare `auto`) is the
 * union: a row is active when (clcf->backend_presets & row->bit). These mirror
 * the disjoint cookie/URI namespaces WP/Woo/Joomla use, so the union does not
 * collide. Curated heuristic, not a CMS fingerprint.
 */
typedef struct {
    ngx_uint_t           bit;
    const char *const   *cookies;  /* substrings in the request Cookie header */
    const char *const   *uris;     /* r->uri prefixes                         */
    const char *const   *args;     /* query-arg keys (presence => dynamic)    */
} ngx_http_cache_turbo_preset_t;

static const char *const  ct_wp_cookies[] = {
    "wordpress_logged_in_", "wp-postpass_", "comment_author_", NULL };
static const char *const  ct_wp_uris[] = {
    "/wp-admin/", "/wp-login.php", "/wp-cron.php", "/xmlrpc.php",
    "/wp-json/", NULL };
static const char *const  ct_wp_args[] = { "preview", "s", NULL };

static const char *const  ct_woo_cookies[] = {
    "woocommerce_items_in_cart", "woocommerce_cart_hash",
    "wp_woocommerce_session_", NULL };
static const char *const  ct_woo_uris[] = {
    "/cart", "/checkout", "/my-account", NULL };
static const char *const  ct_woo_args[] = { NULL };

static const char *const  ct_joomla_cookies[] = { NULL };
static const char *const  ct_joomla_uris[] = { "/administrator/", NULL };
static const char *const  ct_joomla_args[] = { NULL };

static const ngx_http_cache_turbo_preset_t  ngx_http_cache_turbo_presets[] = {
    { NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS,
      ct_wp_cookies, ct_wp_uris, ct_wp_args },
    { NGX_HTTP_CACHE_TURBO_BACKEND_WOOCOMMERCE,
      ct_woo_cookies, ct_woo_uris, ct_woo_args },
    { NGX_HTTP_CACHE_TURBO_BACKEND_JOOMLA,
      ct_joomla_cookies, ct_joomla_uris, ct_joomla_args },
    { 0, NULL, NULL, NULL }
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
    ngx_str_t                             val;
    size_t                                l;

    for (ps = ngx_http_cache_turbo_presets; ps->bit; ps++) {
        if (!(clcf->backend_presets & ps->bit)) {
            continue;
        }

        for (pp = ps->uris; *pp; pp++) {
            l = ngx_strlen(*pp);
            if (r->uri.len >= l
                && ngx_strncmp(r->uri.data, *pp, l) == 0)
            {
                return 1;
            }
        }

        if (r->args.len) {
            for (pp = ps->args; *pp; pp++) {
                if (ngx_http_arg(r, (u_char *) *pp, ngx_strlen(*pp), &val)
                    == NGX_OK)
                {
                    return 1;
                }
            }
        }

        if (ngx_http_cache_turbo_cookie_has(r, ps->cookies)) {
            return 1;
        }
    }

    return 0;
}
/* >>> FUZZ-EXTRACT auto-classify END <<< */


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
    if (clcf->backend_presets && ngx_http_cache_turbo_auto_skip(r, clcf)) {
        ctx->auto_skip = 1;
        /* cache-turbo neither serves nor stores an auto-classified dynamic
         * request, so it is NOT "engaged": leave $cache_turbo_active = 0 so a
         * stacked native cache is free to handle the URL itself. */
        ctx->ct_active = 0;
        (void) ngx_atomic_fetch_add(&z->sh->misses, 1);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: auto-classify dynamic \"%V\" -> origin",
                       &r->uri);
        return NGX_DECLINED;
    }

    /* Request Cache-Control: no-cache / Pragma: no-cache (RFC 9111 §5.2.1.4):
     * do not reuse a stored response without validation. With no validation
     * channel for a hit, skip the lookup and go to the origin — the fresh
     * response still stores (refreshing the entry), like a bypass. */
    if (ngx_http_cache_turbo_request_no_cache(r)) {
        (void) ngx_atomic_fetch_add(&z->sh->misses, 1);
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
            /* True LRU: promote this node to the head on access, so eviction
             * targets the genuinely least-recently-used entry (not the oldest by
             * insertion/refresh). Cheap queue splice under the mutex we hold. */
            ngx_queue_remove(&ctn->lru);
            ngx_queue_insert_head(&z->sh->lru, &ctn->lru);
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

            /* True LRU: promote on access (still a live, serveable entry). */
            ngx_queue_remove(&ctn->lru);
            ngx_queue_insert_head(&z->sh->lru, &ctn->lru);

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
                    return ngx_http_cache_turbo_serve(r, snap, snap_len, 1);
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
                 * slack): treat as a miss and go to origin. */
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: L2 blob expired \"%V\" key=%ui "
                               "-> origin", &r->uri, (ngx_uint_t) hash);
            } else {
                /* The blob passed full validation above, so the slot we put in
                 * L1 is guaranteed serveable (no poisoned L1 node). */
                (void) clcf->l1->store(z, ctx->key_hash, hash,
                           ctx->l2_blob, ctx->l2_blob_len,
                           rem_fresh, rem_stale);
                (void) ngx_atomic_fetch_add(&z->sh->hits, 1);
                (void) ngx_atomic_fetch_add(&z->sh->l2_hits, 1);
                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: L2 HIT \"%V\" key=%ui len=%uz "
                               "(filled L1)", &r->uri, (ngx_uint_t) hash,
                               ctx->l2_blob_len);
                return ngx_http_cache_turbo_serve(r, ctx->l2_blob,
                           ctx->l2_blob_len, rem_fresh <= 0 ? 1 : 0);
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

        if (lock_ttl <= 0) {
            lock_ttl = 5;
        }

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
                ngx_http_cache_turbo_cold_mark_winner(r, ctx, z);
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
    for (i = 0; i < bh->nheaders && p + 8 <= end; i++) {
        uint32_t  nl, vl;
        u_char   *nm, *vv;

        nl = ngx_http_cache_turbo_get_u32(p); p += 4;
        if (p + nl > end) { break; }
        nm = p; p += nl;

        if (p + 4 > end) { break; }
        vl = ngx_http_cache_turbo_get_u32(p); p += 4;
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
        ab = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
        if (ab != NULL) {
            static u_char  age_name[] = "Age";
            size_t         al = (size_t) (ngx_sprintf(ab, "%T", age) - ab);
            (void) ngx_http_cache_turbo_add_header(r, age_name,
                       sizeof("Age") - 1, ab, al);
        }
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

    } else if (clcf->vary_safe
               && ngx_http_cache_turbo_response_has_vary(r))
    {
        /* Vary safety (SEC-4): auto_vary is off, so the key does NOT account for
         * any Vary field. Caching such a response would serve one representation
         * for every value of the varied axis (cache poisoning / cross-tenant
         * leak). Refuse to store it. (With auto_vary on, the classify step above
         * already refuses the un-keyable axes, so vary_safe is a no-op there.) */
        ctx->vary_nocache = 1;
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
        && ngx_http_cache_turbo_status_ttl(clcf, r->headers_out.status) >= 0
        && ngx_http_cache_turbo_response_cacheable(r)
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
            return ngx_http_next_body_filter(r, in);
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
                return ngx_http_next_body_filter(r, in);
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
        size_t                            hdr_bytes = 0, blob_len;
        uint32_t                          nheaders = 0;
        u_char                           *blob, *w;
        ngx_uint_t                        i;
        time_t                            ttl, stale_window;

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

        /* STAB-5: clamp the fresh TTL to the uint32 ceiling before it feeds the
         * blob fresh_ttl cast, the stale-window multiply, and the L2 PX. An
         * unbounded upstream max-age (honor_cc) is the realistic source. */
        if (ttl > NGX_HTTP_CACHE_TURBO_TTL_MAX) {
            ttl = NGX_HTTP_CACHE_TURBO_TTL_MAX;
        }

        /* Absolute serveable window (fresh + stale) from now, reused by the blob
         * metadata, the L1 store, and the L2 EXPIRE so all three agree. */
        stale_window = ngx_http_cache_turbo_stale_ttl(ttl, clcf->stale_mult);

        /* RFC 9111 must-revalidate / proxy-revalidate: once stale, the response
         * must NOT be served without revalidation. We have no validation channel
         * for a hit, so collapse the stale window to the fresh TTL — the object
         * is served fresh until its deadline, then re-fetched (no stale serve,
         * no stale-if-error). Only meaningful for a finite TTL. */
        if (ttl > 0 && ngx_http_cache_turbo_response_must_revalidate(r)) {
            stale_window = ttl;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: must-revalidate \"%V\" -> no stale window",
                           &r->uri);
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

            /* STAB-4: serialise the header into the fixed 40-byte LE wire form. */
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
            ngx_http_cache_turbo_blob_hdr_write(blob, &bhw);

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
                                                  ctx->vary_bits, ctx->vary_gen,
                                                  store_key);
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
                       blob, blob_len, ttl,
                       stale_window);

            /* v10: store overwrote any cold-miss stub into a real entry (or we
             * cleared the relocated base stub above), so the cleanup must not
             * remove it. */
            ctx->cold_stored = 1;

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
                        ngx_http_cache_turbo_stale_ttl(ttl, clcf->stale_mult));
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
             * set() takes the FRESH ttl and derives its own EXPIRE spanning the
             * full serveable window (fresh + stale), so the object can still be
             * stale-served from L2 after its fresh deadline; the blob's own
             * freshness metadata then bounds how it is restored into L1. */
            if (clcf->backend) {
                clcf->backend->set(r, clcf, store_key,
                                   blob, blob_len, ttl);
            }

            /* Tag index (v2c): for each tag in the cache_turbo_tag expression,
             * SADD this object's L2 key to the tag set so it can be purged by
             * tag later. Tags live only in L2; skip when Redis is off. The
             * memcached backend has no tag support (tag_add == NULL, v13). */
            if (clcf->backend && clcf->backend->tag_add && clcf->tag) {
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

    /* "cache_turbo <zone> auto;" — shorthand for the generic auto-classify
     * preset (the union of all CMS backends). Equivalent to also writing
     * `cache_turbo_backend generic;`. Any other 2nd token is rejected. */
    if (cf->args->nelts == 3) {
        if (ngx_strcmp(value[2].data, "auto") != 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid cache_turbo mode \"%V\" (expected \"auto\")",
                &value[2]);
            return NGX_CONF_ERROR;
        }
        clcf->backend_presets |= NGX_HTTP_CACHE_TURBO_BACKEND_GENERIC;
    }

    return NGX_CONF_OK;
}


/* cache_turbo_backend <name>... — compose one or more CMS auto-classify presets
 * (NGX_CONF_1MORE; listed names stack, e.g. `wordpress woocommerce`). "generic"
 * (or "auto") is the union of all backends; naming specific backends is tighter.
 * Sets bits in clcf->backend_presets consumed by ngx_http_cache_turbo_auto_skip. */
static char *
ngx_http_cache_turbo_backend(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;
    ngx_str_t                        *value;
    ngx_uint_t                        i;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strcmp(value[i].data, "generic") == 0
            || ngx_strcmp(value[i].data, "auto") == 0)
        {
            clcf->backend_presets |= NGX_HTTP_CACHE_TURBO_BACKEND_GENERIC;

        } else if (ngx_strcmp(value[i].data, "wordpress") == 0) {
            clcf->backend_presets |= NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS;

        } else if (ngx_strcmp(value[i].data, "woocommerce") == 0) {
            clcf->backend_presets |= NGX_HTTP_CACHE_TURBO_BACKEND_WOOCOMMERCE;

        } else if (ngx_strcmp(value[i].data, "joomla") == 0) {
            clcf->backend_presets |= NGX_HTTP_CACHE_TURBO_BACKEND_JOOMLA;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "unknown cache_turbo_backend \"%V\" (want "
                "generic|wordpress|woocommerce|joomla)", &value[i]);
            return NGX_CONF_ERROR;
        }
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
            if (clcf->redis_prefix.len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo: empty prefix= is not allowed "
                    "(an all-purge would match the whole L2 keyspace)");
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
            if (clcf->redis_prefix.len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo: empty prefix= is not allowed "
                    "(an all-purge would match the whole L2 keyspace)");
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
            clcf->redis_timeout = (ngx_msec_t) t;

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


/* ngx_http_cache_turbo_tagpurge_t is defined near the top of the file (shared
 * with the COR-5 variant-index purge launched from purge_request). */


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
                /* NGX_ERROR: L2 unavailable — fall through to the sync reply
                 * below with the L1 count (L2 left as-is). */
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

            if (clcf->backend == NULL || clcf->backend->purge_tag == NULL) {
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
                "# HELP cache_turbo_min_uses_skips_total Cold misses sent to origin without storing because the key is below cache_turbo_min_uses (v15).\n"
                "# TYPE cache_turbo_min_uses_skips_total counter\n"
                "cache_turbo_min_uses_skips_total{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_regen_cost_ms Average origin regeneration cost in milliseconds.\n"
                "# TYPE cache_turbo_regen_cost_ms gauge\n"
                "cache_turbo_regen_cost_ms{zone=\"%V\"} %uA\n"
                "# HELP cache_turbo_autotuned_beta Live autotuned SWR beta (x1000; 0 = none).\n"
                "# TYPE cache_turbo_autotuned_beta gauge\n"
                "cache_turbo_autotuned_beta{zone=\"%V\"} %uA\n",
                &zname, st.hits, &zname, st.misses, &zname, st.stale_serves,
                &zname, st.refreshes, &zname, st.evictions,
                &zname, st.l2_hits, &zname, st.l2_misses, &zname, st.lock_waits,
                &zname, st.min_uses_skips,
                &zname, st.cost_ms, &zname, st.autotuned_beta) - p;

            return ngx_http_cache_turbo_send_body(r, NGX_HTTP_OK, &body,
                "text/plain; version=0.0.4; charset=utf-8",
                sizeof("text/plain; version=0.0.4; charset=utf-8") - 1);
        }

        len = sizeof("{\"hits\":,\"misses\":,\"stale_serves\":,\"refreshes\":,"
                     "\"evictions\":,\"l2_hits\":,\"l2_misses\":,\"lock_waits\":,"
                     "\"min_uses_skips\":,\"cost_ms\":,\"autotuned_beta\":}\n")
              + 11 * NGX_ATOMIC_T_LEN;
        p = ngx_pnalloc(r->pool, len);
        if (p == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        body.data = p;
        body.len = ngx_sprintf(p,
            "{\"hits\":%uA,\"misses\":%uA,\"stale_serves\":%uA,"
            "\"refreshes\":%uA,\"evictions\":%uA,\"l2_hits\":%uA,"
            "\"l2_misses\":%uA,\"lock_waits\":%uA,\"min_uses_skips\":%uA,"
            "\"cost_ms\":%uA,\"autotuned_beta\":%uA}\n",
            st.hits, st.misses, st.stale_serves,
            st.refreshes, st.evictions, st.l2_hits, st.l2_misses,
            st.lock_waits, st.min_uses_skips, st.cost_ms,
            st.autotuned_beta) - p;
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
    ngx_int_t bits, ngx_uint_t gen, u_char out[32])
{
    ngx_http_cache_turbo_digest_t  d;
    const char                    *cls;
    ngx_str_t                      v;
    static const u_char            us = 0x1F;

    ngx_http_cache_turbo_digest_init(&d);
    ngx_http_cache_turbo_digest_update(&d, base->data, base->len);

    /* PURGE generation (COR-5): folded ONLY when bumped (>0) so an unpurged
     * base keeps the pre-COR-5 variant key (no keyspace turnover on upgrade).
     * The L1-only / memcached purge path bumps it to orphan an old generation's
     * variants; the backend-backed purge deletes them outright and leaves gen 0. */
    if (gen > 0) {
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
        v = ngx_http_cache_turbo_req_header(r, "Accept-Language",
                                            sizeof("Accept-Language") - 1);
        ngx_http_cache_turbo_digest_update(&d, &us, 1);
        ngx_http_cache_turbo_digest_update(&d, "lang=", 5);
        ngx_http_cache_turbo_digest_update(&d, v.data, v.len);
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


/* True if the response carries at least one non-empty Vary header. Used by the
 * vary_safe gate (SEC-4) to refuse caching a varied response when auto_vary is
 * off and the key therefore ignores every Vary field. Walks the header list
 * (not the typed r->headers_out.vary field, which only exists on nginx >= 1.23)
 * so the legacy header path is covered too. */
static ngx_uint_t
ngx_http_cache_turbo_response_has_vary(ngx_http_request_t *r)
{
    ngx_list_part_t  *part = &r->headers_out.headers.part;
    ngx_table_elt_t  *h = part->elts;
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
        if (h[i].hash == 0) {
            continue;
        }
        if (h[i].key.len == sizeof("Vary") - 1
            && ngx_strncasecmp(h[i].key.data, (u_char *) "Vary",
                               sizeof("Vary") - 1) == 0
            && h[i].value.len != 0)
        {
            return 1;
        }
    }

    return 0;
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
    conf->safe_key = NGX_CONF_UNSET;
    conf->vary_safe = NGX_CONF_UNSET;
    conf->purge = NGX_CONF_UNSET;
    conf->background_update = NGX_CONF_UNSET;
    conf->lock = NGX_CONF_UNSET;
    conf->lock_timeout = NGX_CONF_UNSET_MSEC;
    conf->min_uses = NGX_CONF_UNSET;
    conf->max_size = NGX_CONF_UNSET_SIZE;
    conf->suppress_native = NGX_CONF_UNSET;
    conf->redis_enable = NGX_CONF_UNSET;
    conf->memcached = NGX_CONF_UNSET;
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
    ngx_conf_merge_value(conf->suppress_native, prev->suppress_native, 0);

    /* backend_presets is an accumulated bitmask (0 = unset), so the standard
     * UNSET-sentinel merge can't be used; inherit the parent's set when this
     * location named no backend of its own (an explicit backend fully
     * overrides, it does not OR with the parent's). */
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
    /* Auto-classify auto-enables honor_cc (unless explicitly set), so a
     * backend plugin's own Cache-Control: no-cache on an anon page
     * self-excludes at store time. Done before the merge so an explicit
     * `cache_turbo_honor_cache_control off;` still wins. */
    if (conf->backend_presets != 0 && conf->honor_cc == NGX_CONF_UNSET) {
        conf->honor_cc = 1;
    }
    ngx_conf_merge_value(conf->honor_cc, prev->honor_cc, 0);
    ngx_conf_merge_value(conf->auto_vary, prev->auto_vary, 0);
    ngx_conf_merge_value(conf->safe_key, prev->safe_key, 0);
    ngx_conf_merge_value(conf->vary_safe, prev->vary_safe, 0);

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

    /* min_uses (v15): default 1 = store on the first miss (feature off). A value
     * below 1 is meaningless — clamp it so the gate's `> 1` test is the only
     * switch and a stray 0/negative never disables caching outright. */
    ngx_conf_merge_value(conf->min_uses, prev->min_uses, 1);
    if (conf->min_uses < 1) {
        conf->min_uses = 1;
    }

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

    /* Default cache key (no explicit cache_turbo_key) for an enabled location.
     * Normalized default: $host$uri$cache_turbo_normalized_args — tracking params
     * stripped + args sorted out of the box. With cache_turbo_safe_key on (COR-1)
     * the default instead becomes $scheme$host$request_uri — the full raw query,
     * no stripping/sorting — so distinct private URLs (e.g. two sessionid values)
     * can never alias onto one entry. Compiled lazily here; the normalized_args
     * variable was registered in preconfiguration. */
    if (conf->key == NULL && conf->enable) {
        ngx_str_t                         defkey = conf->safe_key
            ? (ngx_str_t) ngx_string("$scheme$host$request_uri")
            : (ngx_str_t) ngx_string("$host$uri$cache_turbo_normalized_args");
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

    /* L2 backend selection + connection knobs. These are behavioural tunables,
     * not backend identity, so they inherit independently as before. */
    ngx_conf_merge_value(conf->redis_enable, prev->redis_enable, 0);
    ngx_conf_merge_value(conf->memcached, prev->memcached, 0);
    ngx_conf_merge_msec_value(conf->redis_timeout, prev->redis_timeout, 250);
    ngx_conf_merge_value(conf->redis_keepalive, prev->redis_keepalive, 0);
    ngx_conf_merge_msec_value(conf->redis_keepalive_timeout,
                              prev->redis_keepalive_timeout, 60000);

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

    /* COR-0: tags live only in a Redis L2 (the memcached backend has no atomic
     * tag set: tag_add == NULL). A cache_turbo_tag with no L2, or with the
     * memcached backend, is silently inert — warn at config time rather than let
     * the operator believe purge-by-tag will work. */
    if (conf->tag != NULL
        && (conf->backend == NULL || conf->backend->tag_add == NULL))
    {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "cache_turbo_tag has no effect here: tag indexing requires a Redis "
            "L2 (cache_turbo_redis); it is unavailable with %s",
            conf->backend == NULL ? "no L2 backend" : "the memcached backend");
    }

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
