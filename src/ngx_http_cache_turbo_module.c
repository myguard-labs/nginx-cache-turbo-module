/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * http-cache-turbo — v1 vertical slice.
 *
 *   - ACCESS phase: hash the cache key, look it up in the L1 shm zone.
 *       * fresh hit          -> serve from shm, skip upstream
 *       * stale hit + dice   -> serve stale now; this request regenerates
 *       * stale hit, no dice -> serve stale now; someone else regenerates
 *       * miss               -> let the request run, capture + store
 *   - header/body filters: capture the upstream response and store it.
 *
 * Single-flight is probabilistic (the SWR dice in swr.c), so the read path is
 * lock-free. See memory/nginx+angie/cache-turbo-module-design.md.
 */

#include "ngx_http_cache_turbo_module.h"


static ngx_int_t ngx_http_cache_turbo_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_cache_turbo_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_cache_turbo_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);

static ngx_int_t ngx_http_cache_turbo_serve(ngx_http_request_t *r,
    u_char *copy, size_t len, ngx_uint_t stale);

static void *ngx_http_cache_turbo_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_cache_turbo_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_http_cache_turbo_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cache_turbo(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cache_turbo_key(ngx_conf_t *cf, ngx_command_t *cmd,
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
static const ngx_http_cache_turbo_band_t  ngx_http_cache_turbo_bands[] = {
    /* [0] unused placeholder           */ {   0,    0,  0, 0 },
    /* [1] CONSERVATIVE: correctness     */ {  30,  500, 10, 2 },
    /* [2] BALANCED: current defaults    */ {  60, 1000,  5, 4 },
    /* [3] AGGRESSIVE: max hit-rate      */ { 300, 3000,  3, 8 },
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
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cache_turbo_loc_conf_t, valid_raw),
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

    { ngx_string("cache_turbo_admin"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_cache_turbo_admin,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cache_turbo_redis"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
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


/* Build the cache key string and its 32-byte hash into the request ctx. */
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
        /* default key: scheme + host + request_uri */
        ctx->cache_key = r->unparsed_uri;
    }

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, ctx->cache_key.data, ctx->cache_key.len);
    ngx_md5_final(ctx->key_hash, &md5);

    /* md5 is 16 bytes; widen into the 32-byte slot (rest stays zero). */
    return NGX_OK;
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
            return ngx_http_cache_turbo_serve(r, snap, snap_len, 0);
        }

        if (stale_until == 0 || now < stale_until) {
            /* stale-but-serveable */
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
            if (!ctn->refreshing || now >= ctn->refresh_lock_until) {
                refresh = ngx_http_cache_turbo_should_refresh(ctx->key_hash,
                              fresh_until, stale_window, clcf->beta);
            }

            if (refresh == NGX_OK) {
                /* we win the dice: claim the refresh under lock (atomic with
                 * the check above), serve stale, and fall through to origin so
                 * the filters restore a fresh copy. The lock self-heals after
                 * lock_ttl if this refresh never completes. */
                time_t lock_ttl = clcf->lock_ttl;
                if (lock_ttl <= 0) {
                    lock_ttl = 5;
                }
                ctn->refreshing = 1;
                ctn->refresh_lock_until = now + lock_ttl;
                ngx_shmtx_unlock(&z->shpool->mutex);
                (void) ngx_atomic_fetch_add(&z->sh->stale_serves, 1);
                (void) ngx_atomic_fetch_add(&z->sh->refreshes, 1);
                return NGX_DECLINED;
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
                return ngx_http_cache_turbo_serve(r, ctx->l2_blob,
                           ctx->l2_blob_len, 0);
            }
        }
        /* corrupt/short blob: treat as a miss, fall through to origin */
    }

    /* true miss: mark for capture, let the request run to the origin */
    (void) ngx_atomic_fetch_add(&z->sh->misses, 1);
    return NGX_DECLINED;
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

        (void) ngx_http_cache_turbo_add_header(r, nm, nl, vv, vl);
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

    if (r->header_only || body_len == 0) {
        ngx_http_finalize_request(r, NGX_OK);
        return NGX_DONE;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->pos = body;
    b->last = body + body_len;
    b->memory = 1;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

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

    /* Only capture cacheable success responses. Normally the main request only;
     * a warm subrequest (ctx->warm) is the deliberate exception — we want its
     * origin response captured and stored even though r != r->main. */
    if (clcf->enable && (r == r->main || ctx->warm)
        && r->headers_out.status == NGX_HTTP_OK)
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
        b = cl->buf;
        n = ngx_buf_size(b);

        if (n > 0) {
            p = ngx_pnalloc(r->pool, n);
            if (p == NULL) {
                return NGX_ERROR;
            }
            ngx_memcpy(p, b->pos, n);

            ngx_buf_t *nb = ngx_calloc_buf(r->pool);
            if (nb == NULL) {
                return NGX_ERROR;
            }
            nb->pos = p;
            nb->last = p + n;
            nb->memory = 1;

            ngx_chain_t *ncl = ngx_alloc_chain_link(r->pool);
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

    if (last && ctx->body_len > 0
        && (clcf->max_size == 0 || ctx->body_len <= clcf->max_size))
    {
        ngx_list_part_t                  *part;
        ngx_table_elt_t                  *h;
        ngx_str_t                         ct;
        size_t                            hdr_bytes = 0, blob_len;
        uint32_t                          nheaders = 0;
        u_char                           *blob, *w;
        ngx_uint_t                        i;

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
            if (h[i].hash == 0 || h[i].key.len == 0) {
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
                if (h[i].hash == 0 || h[i].key.len == 0) {
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
            hash = ngx_crc32_short(ctx->key_hash, 32);

            (void) clcf->l1->store(z, ctx->key_hash, hash,
                       blob, blob_len, r->headers_out.status, clcf->valid,
                       clcf->stale_mult);

            /* L2 write-through (async, fire-and-forget). Copies the blob into
             * its own pool, so it is safe even though `blob` lives in r->pool. */
            if (clcf->backend) {
                clcf->backend->set(r, clcf, ctx->key_hash,
                                   blob, blob_len, clcf->valid);
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

                    stale_ttl = ngx_http_cache_turbo_stale_ttl(clcf->valid,
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
                                ctx->key_hash, tok, (size_t) (s - tok),
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


/* "cache_turbo_redis <host:port> [prefix=<str>] [timeout=<time>];" wires the
 * L2 backend. The address is resolved at config time. Settable at http/server/
 * location level and merged down, so a whole http{} block can share one L2. */
static char *
ngx_http_cache_turbo_redis_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t   *value, s;
    ngx_url_t    u;
    ngx_uint_t   i;
    ngx_int_t    t;

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = value[1];
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

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "prefix=", 7) == 0) {
            clcf->redis_prefix.data = value[i].data + 7;
            clcf->redis_prefix.len = value[i].len - 7;
            continue;
        }

        if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
            s.data = value[i].data + 8;
            s.len = value[i].len - 8;
            t = ngx_parse_time(&s, 0);   /* milliseconds */
            if (t == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "cache_turbo_redis: bad timeout \"%V\"", &s);
                return NGX_CONF_ERROR;
            }
            clcf->redis_timeout = (ngx_msec_t) t;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "cache_turbo_redis: invalid parameter \"%V\"",
                           &value[i]);
        return NGX_CONF_ERROR;
    }

    clcf->redis_enable = 1;

    return NGX_CONF_OK;
}


/* Send a small JSON body with the given status. Shared by the admin handler and
 * the async tag-purge completion. Returns the rc to propagate/finalize with. */
static ngx_int_t
ngx_http_cache_turbo_send_json(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t *body)
{
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t   out;

    r->headers_out.status = status;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_type_len = r->headers_out.content_type.len;
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

        /* member = <prefix><64 hex of the 32-byte key hash>: drop from L1. */
        if (members[i].len == plen + 64) {
            u_char    key_hash[32];
            uint32_t  hash;

            if (ngx_http_cache_turbo_hexdecode(members[i].data + plen, 64,
                                               key_hash) == NGX_OK)
            {
                hash = ngx_crc32_short(key_hash, 32);
                (void) tp->clcf->l1->purge_key(tp->zone, key_hash, hash);
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

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);
    if (!clcf->admin || clcf->admin_zone == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }

    z = clcf->admin_zone->data;

    if (r->method & (NGX_HTTP_POST|NGX_HTTP_PUT|NGX_HTTP_DELETE)) {
        ngx_str_t  arg;
        ngx_uint_t purged = 0;

        if (r->args.len
            && ngx_http_arg(r, (u_char *) "all", 3, &arg) == NGX_OK)
        {
            purged = clcf->l1->purge_all(z);

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

    /* GET / HEAD -> stats. Snapshot the counters through the L1 backend rather
     * than reading the live shctx here. */
    {
        ngx_http_cache_turbo_stats_t  st;

        clcf->l1->stats(z, &st);

        len = sizeof("{\"hits\":,\"misses\":,\"stale_serves\":,\"refreshes\":,"
                     "\"evictions\":}\n") + 6 * NGX_ATOMIC_T_LEN;
        p = ngx_pnalloc(r->pool, len);
        if (p == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        body.data = p;
        body.len = ngx_sprintf(p,
            "{\"hits\":%uA,\"misses\":%uA,\"stale_serves\":%uA,"
            "\"refreshes\":%uA,\"evictions\":%uA}\n",
            st.hits, st.misses, st.stale_serves,
            st.refreshes, st.evictions) - p;
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
 * the response actually IS (br/gzip/identity), not by the per-browser raw header.
 * Priority br > gzip: this mirrors what nginx+brotli/gzip serve when the client
 * accepts both. Absent/empty header => identity. Case-insensitive substring. */
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
    conf->max_size = NGX_CONF_UNSET_SIZE;
    conf->redis_enable = NGX_CONF_UNSET;
    conf->redis_timeout = NGX_CONF_UNSET_MSEC;
    conf->normalize_strip_all = NGX_CONF_UNSET;
    conf->normalize_strip = NGX_CONF_UNSET_PTR;
    conf->normalize_vary = NGX_CONF_UNSET;
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

    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }
    if (conf->key == NULL) {
        conf->key = prev->key;
    }
    if (conf->tag == NULL) {
        conf->tag = prev->tag;
    }

    /* L2 Redis: inherit address/prefix/timeout, default prefix "ct:". */
    ngx_conf_merge_value(conf->redis_enable, prev->redis_enable, 0);
    ngx_conf_merge_msec_value(conf->redis_timeout, prev->redis_timeout, 250);

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
