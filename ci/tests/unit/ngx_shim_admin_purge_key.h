/* Minimal nginx/module surface for the extracted admin purge-key helper. */
#ifndef NGX_CACHE_TURBO_UNIT_SHIM_ADMIN_PURGE_KEY_H
#define NGX_CACHE_TURBO_UNIT_SHIM_ADMIN_PURGE_KEY_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef intptr_t       ngx_int_t;
typedef uintptr_t      ngx_uint_t;
typedef unsigned char  u_char;

#define NGX_OK                           0
#define NGX_ERROR                       -1
#define NGX_HTTP_INTERNAL_SERVER_ERROR 500

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

typedef struct ngx_http_request_s ngx_http_request_t;
struct ngx_http_request_s { int unused; };

typedef struct ngx_http_cache_turbo_zone_s ngx_http_cache_turbo_zone_t;
struct ngx_http_cache_turbo_zone_s { int unused; };

typedef struct ngx_http_cache_turbo_loc_conf_s ngx_http_cache_turbo_loc_conf_t;

typedef struct {
    ngx_int_t (*purge_key)(ngx_http_cache_turbo_zone_t *z, u_char *key_hash,
        uint32_t hash);
} ngx_cache_turbo_l1_backend_t;

typedef struct {
    void (*del)(ngx_http_cache_turbo_loc_conf_t *clcf, u_char *key_hash);
} ngx_cache_turbo_backend_t;

struct ngx_http_cache_turbo_loc_conf_s {
    ngx_cache_turbo_l1_backend_t  *l1;
    ngx_cache_turbo_backend_t     *backend;
};

extern int ngx_test_digest_fail;

static ngx_int_t
ngx_http_cache_turbo_digest(const void *data, size_t len, u_char out[32])
{
    size_t  i;

    if (ngx_test_digest_fail) {
        return NGX_ERROR;
    }
    for (i = 0; i < 32; i++) {
        out[i] = len == 0 ? 0xA5 : ((const u_char *) data)[i % len];
    }
    return NGX_OK;
}

static uint32_t
ngx_crc32_short(u_char *data, size_t len)
{
    uint32_t  hash = 2166136261u;

    while (len--) {
        hash ^= *data++;
        hash *= 16777619u;
    }
    return hash;
}

#endif
