/* Minimal nginx/module surface for the extracted admin purge-all helper. */
#ifndef NGX_CACHE_TURBO_UNIT_SHIM_ADMIN_PURGE_ALL_H
#define NGX_CACHE_TURBO_UNIT_SHIM_ADMIN_PURGE_ALL_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef intptr_t       ngx_int_t;
typedef uintptr_t      ngx_uint_t;
typedef unsigned char  u_char;

#define NGX_OK                           0
#define NGX_ERROR                       -1
#define NGX_AGAIN                       -2
#define NGX_DONE                        -4
#define NGX_HTTP_INTERNAL_SERVER_ERROR 500

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

typedef struct {
    u_char  storage[256];
    size_t  used;
} ngx_pool_t;

typedef struct ngx_http_request_s ngx_http_request_t;
struct ngx_http_request_s {
    ngx_pool_t  *pool;
    ngx_uint_t   send_calls;
    ngx_uint_t   sent_status;
    ngx_str_t    sent_body;
};

typedef struct ngx_http_cache_turbo_zone_s ngx_http_cache_turbo_zone_t;
struct ngx_http_cache_turbo_zone_s { int unused; };

typedef struct ngx_http_cache_turbo_loc_conf_s ngx_http_cache_turbo_loc_conf_t;
typedef struct ngx_http_cache_turbo_redis_walk_s
    ngx_http_cache_turbo_redis_walk_t;

typedef ngx_int_t (*ngx_http_cache_turbo_walk_pt)(ngx_http_request_t *r,
    void *data, ngx_str_t *members, ngx_uint_t nmembers,
    const ngx_http_cache_turbo_redis_walk_t *walk);

typedef struct {
    ngx_uint_t  purged;
} ngx_http_cache_turbo_allpurge_t;

typedef struct {
    ngx_int_t (*purge_all)(ngx_http_cache_turbo_zone_t *z,
        ngx_uint_t *purged);
} ngx_cache_turbo_l1_backend_t;

typedef struct {
    ngx_int_t (*scan_del)(ngx_http_request_t *r,
        ngx_http_cache_turbo_loc_conf_t *clcf,
        ngx_http_cache_turbo_walk_pt callback, void *data);
} ngx_cache_turbo_backend_t;

struct ngx_http_cache_turbo_loc_conf_s {
    ngx_cache_turbo_l1_backend_t  *l1;
    ngx_cache_turbo_backend_t     *backend;
};

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
ngx_palloc(ngx_pool_t *pool, size_t size)
{
    return ngx_pnalloc(pool, size);
}

static u_char *
ngx_sprintf(u_char *buf, const char *fmt, ...)
{
    va_list     ap;
    ngx_uint_t  purged;
    char        converted[128];
    size_t      i, j;
    int         n;

    /* nginx's %ui is standard printf's %lu for this uintptr_t-backed shim.
     * Preserve every other source byte so the test observes JSON field/order
     * mutations instead of regenerating the expected body itself. */
    for (i = 0, j = 0; fmt[i] != '\0' && j + 1 < sizeof(converted); i++) {
        if (fmt[i] == '%' && fmt[i + 1] == 'u' && fmt[i + 2] == 'i'
            && j + 3 < sizeof(converted))
        {
            converted[j++] = '%';
            converted[j++] = 'l';
            converted[j++] = 'u';
            i += 2;
        } else {
            converted[j++] = fmt[i];
        }
    }
    converted[j] = '\0';

    va_start(ap, fmt);
    purged = va_arg(ap, ngx_uint_t);
    va_end(ap);

    n = snprintf((char *) buf, 128, converted, (unsigned long) purged);
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

static ngx_int_t
ngx_http_cache_turbo_all_purge_complete(ngx_http_request_t *r, void *data,
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
