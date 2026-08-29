/* Minimal nginx/module surface for the extracted admin purge-all helper. */
#ifndef NGX_CACHE_TURBO_UNIT_SHIM_ADMIN_PURGE_ALL_H
#define NGX_CACHE_TURBO_UNIT_SHIM_ADMIN_PURGE_ALL_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef intptr_t       ngx_int_t;
typedef uintptr_t      ngx_uint_t;
typedef ngx_int_t      ngx_flag_t;
typedef unsigned char  u_char;

#define NGX_OK                           0
#define NGX_ERROR                       -1
#define NGX_AGAIN                       -2
#define NGX_DONE                        -4
#define NGX_ABORT                       -6
#define NGX_HTTP_OK                    200
#define NGX_HTTP_BAD_REQUEST           400
#define NGX_HTTP_INTERNAL_SERVER_ERROR 500

/* Keep exact response fixtures independent of production fault diagnostics,
 * even when a caller supplies a target-wide test-faults compile flag. */
#ifdef NGX_HTTP_CACHE_TURBO_TEST_FAULTS
#undef NGX_HTTP_CACHE_TURBO_TEST_FAULTS
#endif
#define NGX_HTTP_CACHE_TURBO_TEST_FAULTS 0

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
    ngx_str_t    args;
    ngx_uint_t   send_calls;
    ngx_uint_t   sent_status;
    ngx_str_t    sent_body;
};

static u_char  *ngx_test_alloc_start;
static u_char  *ngx_test_alloc_end;

typedef struct ngx_http_cache_turbo_zone_s ngx_http_cache_turbo_zone_t;
struct ngx_http_cache_turbo_zone_s { int unused; };

typedef struct ngx_http_cache_turbo_loc_conf_s ngx_http_cache_turbo_loc_conf_t;
typedef struct ngx_http_cache_turbo_redis_walk_s
    ngx_http_cache_turbo_redis_walk_t;

struct ngx_http_cache_turbo_redis_walk_s {
    ngx_int_t   status;
    ngx_uint_t  pages;
    ngx_uint_t  blocks;
    unsigned    deadline:1;
};

typedef ngx_int_t (*ngx_http_cache_turbo_walk_pt)(ngx_http_request_t *r,
    void *data, ngx_str_t *members, ngx_uint_t nmembers,
    const ngx_http_cache_turbo_redis_walk_t *walk);

typedef struct {
    ngx_uint_t  purged;
    ngx_flag_t  l1_incomplete;
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
    ngx_int_t                      warm_max;
};

#define ngx_str_set(str, text)                                               \
    do {                                                                      \
        (str)->len = sizeof(text) - 1;                                         \
        (str)->data = (u_char *) (text);                                       \
    } while (0)

static ngx_int_t
ngx_http_arg(ngx_http_request_t *r, u_char *name, size_t len, ngx_str_t *value)
{
    if (len == 3 && memcmp(name, "all", 3) == 0 && r->args.len == 5
        && memcmp(r->args.data, "all=1", 5) == 0)
    {
        value->data = r->args.data + 4;
        value->len = 1;
        return NGX_OK;
    }

    return NGX_ERROR;
}

static ngx_int_t
ngx_http_cache_turbo_admin_purge_key(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_zone_t *z,
    ngx_str_t *arg, ngx_uint_t *purged)
{
    (void) r;
    (void) clcf;
    (void) z;
    (void) arg;
    (void) purged;
    abort();
}

static ngx_int_t
ngx_http_cache_turbo_admin_purge_tag(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_zone_t *z,
    ngx_str_t *arg)
{
    (void) r;
    (void) clcf;
    (void) z;
    (void) arg;
    abort();
}

static ngx_int_t
ngx_http_cache_turbo_warm(ngx_http_request_t *r, ngx_str_t *urls,
    ngx_int_t warm_max)
{
    (void) r;
    (void) urls;
    (void) warm_max;
    abort();
}

static ngx_int_t
ngx_http_cache_turbo_warm_file(ngx_http_request_t *r, ngx_str_t *path,
    ngx_int_t warm_max)
{
    (void) r;
    (void) path;
    (void) warm_max;
    abort();
}

static void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    void  *p;

    if (pool->used > sizeof(pool->storage)
        || size > sizeof(pool->storage) - pool->used)
    {
        return NULL;
    }
    p = pool->storage + pool->used;
    pool->used += size;
    ngx_test_alloc_start = p;
    ngx_test_alloc_end = (u_char *) p + size;
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
    enum { CONV_UI, CONV_STRING } conversions[2];
    va_list     ap;
    char        converted[256];
    size_t      available, i, j, nconv;
    int         n;

    /* nginx's %ui is standard printf's %lu for this uintptr_t-backed shim.
     * Preserve every other source byte so the test observes JSON field/order
     * mutations instead of regenerating the expected body itself. Abort on a
     * conversion the shim does not model instead of consuming the wrong vararg
     * type and accidentally blessing malformed production output. */
    nconv = 0;
    for (i = 0, j = 0; fmt[i] != '\0' && j + 1 < sizeof(converted); i++) {
        if (fmt[i] == '%' && fmt[i + 1] == 'u' && fmt[i + 2] == 'i'
            && j + 3 < sizeof(converted))
        {
            if (nconv == 2) {
                fprintf(stderr, "shim ngx_sprintf: too many conversions\n");
                abort();
            }
            conversions[nconv++] = CONV_UI;
            converted[j++] = '%';
            converted[j++] = 'l';
            converted[j++] = 'u';
            i += 2;
        } else if (fmt[i] == '%' && fmt[i + 1] == 's') {
            if (nconv == 2) {
                fprintf(stderr, "shim ngx_sprintf: too many conversions\n");
                abort();
            }
            conversions[nconv++] = CONV_STRING;
            converted[j++] = fmt[i];
            converted[j++] = fmt[++i];
        } else if (fmt[i] == '%') {
            fprintf(stderr, "shim ngx_sprintf: unsupported format \"%s\"\n",
                    fmt);
            abort();
        } else {
            converted[j++] = fmt[i];
        }
    }
    if (fmt[i] != '\0') {
        fprintf(stderr, "shim ngx_sprintf: converted format overflow\n");
        abort();
    }
    converted[j] = '\0';

    if (buf < ngx_test_alloc_start || buf >= ngx_test_alloc_end) {
        fprintf(stderr, "shim ngx_sprintf: destination outside allocation\n");
        abort();
    }
    available = (size_t) (ngx_test_alloc_end - buf);

    va_start(ap, fmt);
    if (nconv == 0) {
        n = snprintf((char *) buf, available, "%s", converted);
    } else if (nconv == 1 && conversions[0] == CONV_UI) {
        ngx_uint_t  value = va_arg(ap, ngx_uint_t);

        n = snprintf((char *) buf, available, converted,
                     (unsigned long) value);
    } else if (nconv == 1 && conversions[0] == CONV_STRING) {
        const char  *value = va_arg(ap, const char *);

        n = snprintf((char *) buf, available, converted, value);
    } else if (conversions[0] == CONV_UI
               && conversions[1] == CONV_UI)
    {
        ngx_uint_t  first = va_arg(ap, ngx_uint_t);
        ngx_uint_t  second = va_arg(ap, ngx_uint_t);

        n = snprintf((char *) buf, available, converted,
                     (unsigned long) first, (unsigned long) second);
    } else if (conversions[0] == CONV_STRING
               && conversions[1] == CONV_STRING)
    {
        const char  *first = va_arg(ap, const char *);
        const char  *second = va_arg(ap, const char *);

        n = snprintf((char *) buf, available, converted, first, second);
    } else {
        fprintf(stderr, "shim ngx_sprintf: unsupported conversion order\n");
        abort();
    }
    va_end(ap);

    if (n < 0 || (size_t) n >= available) {
        fprintf(stderr, "shim ngx_sprintf: destination allocation overflow\n");
        abort();
    }
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

#endif
