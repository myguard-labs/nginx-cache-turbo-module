/* Minimal nginx/module surface for the extracted PURGE digest-order path. */
#ifndef NGX_CACHE_TURBO_UNIT_SHIM_PURGE_DIGEST_ORDER_H
#define NGX_CACHE_TURBO_UNIT_SHIM_PURGE_DIGEST_ORDER_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

typedef intptr_t       ngx_int_t;
typedef uintptr_t      ngx_uint_t;
typedef uintptr_t      ngx_atomic_t;
typedef unsigned char  u_char;

#define NGX_OK                              0
#define NGX_ERROR                          -1
#define NGX_DONE                           -4
#define NGX_HTTP_OK                       200
#define NGX_HTTP_INTERNAL_SERVER_ERROR    500
#define NGX_LOG_DEBUG_HTTP                  0
#define NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE 76

#define ngx_memcpy  memcpy
#define ngx_memzero(buf, len)  memset((buf), 0, (len))
#define ngx_log_debug3(...)    ((void) 0)

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

typedef struct {
    u_char  storage[4096];
    size_t  used;
} ngx_pool_t;

typedef struct ngx_http_request_s ngx_http_request_t;
typedef struct ngx_http_cache_turbo_loc_conf_s
    ngx_http_cache_turbo_loc_conf_t;
typedef struct ngx_http_cache_turbo_zone_s ngx_http_cache_turbo_zone_t;
typedef struct ngx_http_cache_turbo_redis_walk_s
    ngx_http_cache_turbo_redis_walk_t;

typedef struct {
    void  *log;
} ngx_connection_t;

struct ngx_http_request_s {
    ngx_pool_t          *pool;
    ngx_http_request_t  *main;
    ngx_uint_t           count;
    ngx_str_t            uri;
    ngx_connection_t    *connection;
    ngx_uint_t           send_calls;
    ngx_uint_t           sent_status;
    ngx_str_t            sent_body;
    ngx_uint_t           finalize_calls;
    ngx_int_t            finalized_rc;
};

typedef struct {
    ngx_str_t  cache_key;
    u_char     key_hash[32];
} ngx_http_cache_turbo_ctx_t;

typedef struct {
    u_char  *data;
    size_t   len;
} ngx_http_cache_turbo_node_t;

typedef struct {
    uint32_t  fresh_ttl;
} ngx_http_cache_turbo_blob_hdr_t;

typedef struct { int unused; } ngx_http_cache_turbo_blob_href_t;

typedef struct {
    ngx_atomic_t  varidx_inflight;
    ngx_atomic_t  varidx_drops;
    ngx_atomic_t  varidx_reissues;
} ngx_http_cache_turbo_shctx_t;

struct ngx_http_cache_turbo_zone_s {
    ngx_http_cache_turbo_shctx_t  sh;
    int                           mutex;
};

typedef struct {
    void  *data;
} ngx_shm_zone_t;

typedef struct {
    u_char  marker[32];
    u_char  variant_index[1 + 64];
    size_t  variant_index_len;
} ngx_http_cache_turbo_purge_vary_keys_t;

typedef ngx_int_t (*ngx_http_cache_turbo_redis_members_pt)(
    ngx_http_request_t *r, void *data, ngx_str_t *members,
    ngx_uint_t nmembers, const ngx_http_cache_turbo_redis_walk_t *walk);

typedef struct {
    ngx_http_cache_turbo_node_t *(*lookup)(ngx_http_cache_turbo_zone_t *z,
        u_char *key_hash, uint32_t hash);
    ngx_int_t (*purge_key)(ngx_http_cache_turbo_zone_t *z, u_char *key_hash,
        uint32_t hash);
} ngx_cache_turbo_l1_backend_t;

typedef struct {
    void (*del)(ngx_http_cache_turbo_loc_conf_t *clcf, u_char *key_hash);
    ngx_int_t (*purge_tag)(ngx_http_request_t *r,
        ngx_http_cache_turbo_loc_conf_t *clcf, u_char *name, size_t name_len,
        ngx_http_cache_turbo_redis_members_pt cb, void *data);
} ngx_cache_turbo_backend_t;

struct ngx_http_cache_turbo_loc_conf_s {
    ngx_cache_turbo_l1_backend_t  *l1;
    ngx_cache_turbo_backend_t     *backend;
    ngx_shm_zone_t                *shm_zone;
    ngx_uint_t                     auto_vary;
    ngx_int_t                      stale_mult;
};

typedef struct {
    ngx_http_cache_turbo_loc_conf_t  *clcf;
    ngx_http_cache_turbo_zone_t      *zone;
    ngx_str_t                         tag;
    unsigned                          is_auto_vary:1;
    ngx_uint_t                        pending_at_launch;
} ngx_http_cache_turbo_tagpurge_t;

static int     ngx_test_digest_call;
static int     ngx_test_digest_fail_call;
static int     ngx_test_marker_store_calls;
static u_char  ngx_test_marker_store_key[32];

static void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    void  *p;

    if (size > sizeof(pool->storage) - pool->used) {
        return NULL;
    }
    p = pool->storage + pool->used;
    pool->used += size;
    return p;
}

static void *
ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    void  *p = ngx_pnalloc(pool, size);

    if (p != NULL) {
        memset(p, 0, size);
    }
    return p;
}

static uint32_t
ngx_crc32_short(const u_char *data, size_t len)
{
    uint32_t  hash = 2166136261u;

    while (len--) {
        hash = (hash ^ *data++) * 16777619u;
    }
    return hash;
}

static void *
ngx_http_cache_turbo_zone_mutex(ngx_http_cache_turbo_zone_t *z)
{
    return &z->mutex;
}

static ngx_http_cache_turbo_shctx_t *
ngx_http_cache_turbo_zone_sh(ngx_http_cache_turbo_zone_t *z)
{
    return &z->sh;
}

static void ngx_shmtx_lock(void *mutex) { (void) mutex; }
static void ngx_shmtx_unlock(void *mutex) { (void) mutex; }

static ngx_atomic_t
ngx_atomic_fetch_add(ngx_atomic_t *value, ngx_atomic_t add)
{
    ngx_atomic_t  old = *value;

    *value += add;
    return old;
}

static ngx_int_t
ngx_http_cache_turbo_blob_validate(const u_char *blob, size_t len,
    ngx_http_cache_turbo_blob_hdr_t *out, const u_char **hdr_block,
    const u_char **body, ngx_pool_t *pool,
    ngx_http_cache_turbo_blob_href_t **refs_out,
    ngx_http_cache_turbo_blob_href_t *refs_buf, ngx_uint_t refs_buf_cap)
{
    (void) blob;
    (void) len;
    (void) hdr_block;
    (void) body;
    (void) pool;
    (void) refs_out;
    (void) refs_buf;
    (void) refs_buf_cap;
    out->fresh_ttl = 30;
    return NGX_OK;
}

static ngx_int_t
ngx_http_cache_turbo_marker_hash(ngx_str_t *base, u_char out[32])
{
    ngx_uint_t  i;

    (void) base;
    ngx_test_digest_call++;
    if (ngx_test_digest_call == ngx_test_digest_fail_call) {
        return NGX_ERROR;
    }
    for (i = 0; i < 32; i++) {
        out[i] = (u_char) (i + 1);
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_cache_turbo_variant_index_name(ngx_str_t *base, u_char *buf,
    size_t *len)
{
    static const u_char hex[] = "0123456789abcdef";
    ngx_uint_t          i;

    (void) base;
    ngx_test_digest_call++;
    if (ngx_test_digest_call == ngx_test_digest_fail_call) {
        return NGX_ERROR;
    }
    buf[0] = ' ';
    for (i = 0; i < 64; i++) {
        buf[i + 1] = hex[i & 0x0f];
    }
    *len = 65;
    return NGX_OK;
}

static ngx_int_t
ngx_http_cache_turbo_marker_store_key(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_http_cache_turbo_zone_t *z, u_char marker_key[32], ngx_int_t bits,
    ngx_uint_t gen, time_t ttl, time_t retain_ttl)
{
    (void) r;
    (void) clcf;
    (void) z;
    (void) bits;
    (void) gen;
    (void) ttl;
    (void) retain_ttl;
    ngx_test_marker_store_calls++;
    memcpy(ngx_test_marker_store_key, marker_key, 32);
    return NGX_OK;
}

static time_t
ngx_http_cache_turbo_stale_ttl(time_t fresh_ttl, ngx_int_t stale_mult)
{
    return fresh_ttl * stale_mult;
}

static ngx_int_t
ngx_http_discard_request_body(ngx_http_request_t *r)
{
    (void) r;
    return NGX_OK;
}

static ngx_int_t
ngx_http_cache_turbo_build_key(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx)
{
    static u_char base[] = "https://example.test/asset.css";
    ngx_uint_t    i;

    (void) r;
    (void) clcf;
    ctx->cache_key.data = base;
    ctx->cache_key.len = sizeof(base) - 1;
    for (i = 0; i < 32; i++) {
        ctx->key_hash[i] = (u_char) (0x80 + i);
    }
    return NGX_OK;
}

static u_char *
ngx_sprintf(u_char *buf, const char *fmt, ...)
{
    va_list     ap;
    ngx_uint_t  purged;
    int         n;

    (void) fmt;
    va_start(ap, fmt);
    purged = va_arg(ap, ngx_uint_t);
    va_end(ap);
    n = snprintf((char *) buf, 64, "{\"purged\":%lu}\n",
                 (unsigned long) purged);
    return buf + n;
}

static ngx_int_t
ngx_http_cache_turbo_send_json(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t *body)
{
    r->send_calls++;
    r->sent_status = status;
    r->sent_body = *body;
    return NGX_OK;
}

static void
ngx_http_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    r->finalize_calls++;
    r->finalized_rc = rc;
}

static ngx_int_t
ngx_http_cache_turbo_tag_purge_complete(ngx_http_request_t *r, void *data,
    ngx_str_t *members, ngx_uint_t nmembers,
    const ngx_http_cache_turbo_redis_walk_t *walk)
{
    (void) r;
    (void) data;
    (void) members;
    (void) nmembers;
    (void) walk;
    return NGX_OK;
}

#endif
