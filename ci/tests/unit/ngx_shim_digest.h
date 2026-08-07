/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Minimal nginx surface for UNIT-TESTING the digest failure path. Provides
 * stub implementations of OpenSSL/EVP operations to allow testing digest
 * failure without requiring actual SSL/EVP library calls.
 */

#ifndef NGX_CACHE_TURBO_UNIT_SHIM_DIGEST_H
#define NGX_CACHE_TURBO_UNIT_SHIM_DIGEST_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/* Scalar types, faithful to nginx on LP64. */
typedef intptr_t        ngx_int_t;
typedef uintptr_t       ngx_uint_t;
typedef intptr_t        ngx_flag_t;
typedef unsigned char   u_char;

#define NGX_OK           0
#define NGX_ERROR       -1
#define NGX_DECLINED    -5

/* ---- Test fault injection flag ----------------------------------------- */
extern ngx_uint_t  ngx_http_cache_turbo_test_digest_fail;

/* ---- EVP stubs (we're not actually using OpenSSL) ---------------------- */
typedef struct { int _unused; } EVP_MD_CTX;

/* Stub implementations that either fake success or return error based on the
 * fault flag. For testing, we use a simple seeded hash. */

/* Simple hash buffer to track input data for deterministic output */
static u_char evp_hash_buffer[256] = {0};
static int evp_hash_len = 0;

static EVP_MD_CTX *EVP_MD_CTX_new(void) {
    evp_hash_len = 0;
    memset(evp_hash_buffer, 0, sizeof(evp_hash_buffer));
    return (EVP_MD_CTX *) 1;  /* non-NULL */
}

static void EVP_MD_CTX_free(EVP_MD_CTX *ctx) {
    (void) ctx;
}

static const void *EVP_sha256(void) {
    return (const void *) 1;
}

static int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const void *type, void *impl) {
    (void) ctx;
    (void) type;
    (void) impl;
    evp_hash_len = 0;
    memset(evp_hash_buffer, 0, sizeof(evp_hash_buffer));
    return 1;  /* success */
}

static int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt) {
    (void) ctx;
    if (evp_hash_len + cnt > (int)sizeof(evp_hash_buffer)) {
        cnt = sizeof(evp_hash_buffer) - evp_hash_len;
    }
    memcpy(evp_hash_buffer + evp_hash_len, d, cnt);
    evp_hash_len += cnt;
    return 1;  /* success */
}

static int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, u_char *md, unsigned int *s) {
    (void) ctx;
    if (ngx_http_cache_turbo_test_digest_fail) {
        return 0;  /* failure */
    }
    /* Simple deterministic hash: use first 32 bytes of buffer,
     * or repeat the pattern if buffer is smaller. */
    for (int i = 0; i < 32; i++) {
        if (evp_hash_len > 0) {
            md[i] = evp_hash_buffer[i % evp_hash_len];
        } else {
            md[i] = 0xAB;
        }
    }
    *s = 32;
    return 1;  /* success */
}

/* ---- nginx MD5 stubs (for non-SSL builds) ------------------------------ */
typedef struct {
    uint32_t state[4];
} ngx_md5_t;

static void ngx_md5_init(ngx_md5_t *ctx) {
    memset(ctx, 0, sizeof(*ctx));
}

static void ngx_md5_update(ngx_md5_t *ctx, const void *data, size_t len) {
    (void) ctx;
    (void) data;
    (void) len;
}

static void ngx_md5_final(u_char *result, ngx_md5_t *ctx) {
    (void) ctx;
    /* Deterministic output */
    memset(result, 0xCD, 16);
}

/* ---- Minimal request stub (if needed) --------------------------------- */
typedef struct { int _unused; } ngx_http_request_t;

/* ---- Pool allocator stub ------------------------------------------------ */
typedef struct { int _unused; } ngx_pool_t;

static void *ngx_pnalloc(ngx_pool_t *pool, size_t size) {
    (void) pool;
    return malloc(size);
}

#define ngx_memzero(p, n) memset((p), 0, (n))
#define ngx_cpymem(dst, src, n) (memcpy((dst), (src), (n)) + (n))
#define ngx_memcpy(dst, src, n) memcpy((dst), (src), (n))

/* ---- Typedef for digest context ---------------------------------------- */
typedef struct {
    EVP_MD_CTX  *md;
    ngx_uint_t   ok;
} ngx_http_cache_turbo_digest_t;

/* ---- Build key context stub --------------------------------------------- */
typedef struct {
    u_char *data;
    size_t  len;
} ngx_str_t;

typedef struct {
    ngx_str_t  cache_key;
    u_char     key_hash[32];
} ngx_http_cache_turbo_ctx_t;

typedef struct { int _unused; } ngx_http_cache_turbo_loc_conf_t;

/* Forward declarations for the functions we're testing */
static void ngx_http_cache_turbo_digest_init(ngx_http_cache_turbo_digest_t *d);
static void ngx_http_cache_turbo_digest_update(ngx_http_cache_turbo_digest_t *d,
    const void *data, size_t len);
static ngx_int_t ngx_http_cache_turbo_digest_final(ngx_http_cache_turbo_digest_t *d,
    u_char out[32]);
static ngx_int_t ngx_http_cache_turbo_digest(const void *data, size_t len,
    u_char out[32]);
static ngx_int_t ngx_http_cache_turbo_build_key(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx);

/* SSL support check */
#define NGX_SSL 1

#endif /* NGX_CACHE_TURBO_UNIT_SHIM_DIGEST_H */
