/* Minimal nginx/module surface for the extracted marker-store helper. */
#ifndef NGX_CACHE_TURBO_UNIT_SHIM_MARKER_STORE_KEY_H
#define NGX_CACHE_TURBO_UNIT_SHIM_MARKER_STORE_KEY_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

typedef intptr_t       ngx_int_t;
typedef uintptr_t      ngx_uint_t;
typedef unsigned char  u_char;

#define NGX_OK                                0
#define NGX_ERROR                            -1
#define NGX_HTTP_OK                         200
#define NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE   76
#define ngx_memzero(buf, n) memset((buf), 0, (n))

typedef struct ngx_http_request_s ngx_http_request_t;
struct ngx_http_request_s { int unused; };

typedef struct ngx_http_cache_turbo_zone_s ngx_http_cache_turbo_zone_t;
struct ngx_http_cache_turbo_zone_s { int unused; };

typedef struct ngx_http_cache_turbo_loc_conf_s ngx_http_cache_turbo_loc_conf_t;

typedef struct {
    uint16_t  status;
    uint32_t  body_len;
    int64_t   created;
    uint32_t  fresh_ttl;
    uint32_t  stale_ttl;
} ngx_http_cache_turbo_blob_hdr_t;

typedef struct {
    void (*set)(ngx_http_request_t *r,
        ngx_http_cache_turbo_loc_conf_t *clcf, u_char key[32],
        u_char *blob, size_t blob_len, time_t ttl, time_t retain_ttl);
} ngx_cache_turbo_backend_t;

struct ngx_http_cache_turbo_loc_conf_s {
    ngx_cache_turbo_backend_t  *backend;
};

extern ngx_int_t   ngx_test_shm_result;
extern ngx_uint_t  ngx_test_shm_calls;
extern ngx_uint_t  ngx_test_l2_calls;
extern u_char      ngx_test_shm_key[32];
extern u_char      ngx_test_l2_key[32];
extern u_char      ngx_test_shm_blob[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 2];
extern u_char      ngx_test_l2_blob[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 2];
extern time_t      ngx_test_shm_ttl;
extern time_t      ngx_test_shm_retain_ttl;

static time_t
ngx_time(void)
{
    return (time_t) 1700000000;
}

static void
ngx_http_cache_turbo_blob_hdr_write(u_char *dst,
    ngx_http_cache_turbo_blob_hdr_t *bh)
{
    memset(dst, 0, NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE);
    memcpy(dst, bh, sizeof(*bh));
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

static ngx_int_t
ngx_http_cache_turbo_shm_store_marker(ngx_http_cache_turbo_zone_t *z,
    u_char key[32], uint32_t hash, u_char *blob, size_t blob_len,
    time_t ttl, time_t retain_ttl)
{
    (void) z;
    (void) hash;
    ngx_test_shm_calls++;
    memcpy(ngx_test_shm_key, key, sizeof(ngx_test_shm_key));
    if (blob_len == sizeof(ngx_test_shm_blob)) {
        memcpy(ngx_test_shm_blob, blob, blob_len);
    }
    ngx_test_shm_ttl = ttl;
    ngx_test_shm_retain_ttl = retain_ttl;
    return ngx_test_shm_result;
}

#endif
