/* Minimal nginx/module surface for the extracted L2 marker-resolution helper. */
#ifndef NGX_CACHE_TURBO_UNIT_SHIM_ACCESS_MARKER_RESOLVE_H
#define NGX_CACHE_TURBO_UNIT_SHIM_ACCESS_MARKER_RESOLVE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

typedef intptr_t       ngx_int_t;
typedef uintptr_t      ngx_uint_t;
typedef unsigned char  u_char;

#define NGX_OK                0
#define NGX_ERROR            -1
#define NGX_LOG_WARN          4
#define NGX_LOG_DEBUG_HTTP    0

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

typedef struct {
    void  *log;
} ngx_connection_t;

typedef struct {
    ngx_connection_t  *connection;
    ngx_str_t           uri;
} ngx_http_request_t;

typedef struct {
    ngx_str_t   cache_key;
    u_char      key_hash[32];
    ngx_uint_t  vary_gen;
    ngx_int_t   vary_marker_l2_bits;
    ngx_uint_t  vary_marker_l2_gen;
} ngx_http_cache_turbo_ctx_t;

typedef struct { int unused; } ngx_http_cache_turbo_loc_conf_t;
typedef struct { int unused; } ngx_http_cache_turbo_zone_t;

extern ngx_int_t   ngx_test_variant_hash_result;
extern ngx_int_t   ngx_test_marker_store_result;
extern ngx_uint_t  ngx_test_variant_hash_calls;
extern ngx_uint_t  ngx_test_marker_store_calls;
extern ngx_uint_t  ngx_test_warning_calls;
extern ngx_uint_t  ngx_test_debug_calls;
extern ngx_uint_t  ngx_test_warning_level;
extern ngx_int_t   ngx_test_store_bits;
extern ngx_uint_t  ngx_test_store_gen;
extern time_t      ngx_test_store_ttl;
extern time_t      ngx_test_store_retain_ttl;

#define ngx_log_error(level, log, err, ...)                                  \
    do {                                                                     \
        (void) (log);                                                        \
        (void) (err);                                                        \
        ngx_test_warning_calls++;                                            \
        ngx_test_warning_level = (level);                                    \
    } while (0)

#define ngx_log_debug2(...)                                                  \
    do { ngx_test_debug_calls++; } while (0)

static ngx_int_t
ngx_http_cache_turbo_variant_hash(ngx_http_request_t *r, ngx_str_t *base,
    ngx_int_t bits, ngx_uint_t gen, u_char out[32])
{
    ngx_uint_t  i;

    (void) r;
    (void) base;
    (void) bits;
    (void) gen;
    ngx_test_variant_hash_calls++;
    if (ngx_test_variant_hash_result != NGX_OK) {
        return ngx_test_variant_hash_result;
    }
    for (i = 0; i < 32; i++) {
        out[i] = (u_char) (0x40 + i);
    }
    return NGX_OK;
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
ngx_http_cache_turbo_marker_store(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_zone_t *z,
    ngx_str_t *base, ngx_int_t bits, ngx_uint_t gen, time_t ttl,
    time_t retain_ttl)
{
    (void) r;
    (void) clcf;
    (void) z;
    (void) base;
    ngx_test_marker_store_calls++;
    ngx_test_store_bits = bits;
    ngx_test_store_gen = gen;
    ngx_test_store_ttl = ttl;
    ngx_test_store_retain_ttl = retain_ttl;
    return ngx_test_marker_store_result;
}

#endif
