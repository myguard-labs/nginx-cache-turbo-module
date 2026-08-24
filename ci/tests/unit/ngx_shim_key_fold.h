/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Minimal nginx surface for UNIT-TESTING the REAL cache-turbo key-fold
 * functions (ngx_http_cache_turbo_key_fold_size/_append/_all and the queue
 * helper), sliced verbatim out of src/ngx_http_cache_turbo_module.c by
 * extract_key_fold.sh (S231-PERF-KEYFOLD).
 *
 * This is deliberately NOT a mirror of the folding logic: the functions under
 * test are production source, and only the nginx surface they need to compile
 * is shimmed here (pool alloc, ngx_array_t, ngx_log_error, the digest
 * wrapper). The digest is the REAL EVP/OpenSSL SHA-256, so the bytes asserted
 * on are the bytes production computes.
 *
 * The pool is a real (if trivial) bump allocator, not a stub that returns a
 * fixed buffer -- fold_all does multiple ngx_palloc/ngx_pnalloc calls per
 * build_key, and a stub that aliases them would hide a use-after-overwrite
 * that a real allocator's non-overlapping regions would catch.
 */

#ifndef NGX_CACHE_TURBO_UNIT_SHIM_KEY_FOLD_H
#define NGX_CACHE_TURBO_UNIT_SHIM_KEY_FOLD_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <openssl/evp.h>

/* Scalar types, faithful to nginx on LP64. */
typedef intptr_t        ngx_int_t;
typedef uintptr_t       ngx_uint_t;
typedef unsigned char   u_char;

#define NGX_OK      0
#define NGX_ERROR  -1

#define NGX_SSL     1

#define ngx_inline  inline
#define ngx_memcpy(dst, src, n)   memcpy((dst), (src), (n))
#define ngx_cpymem(dst, src, n)   (((u_char *) memcpy((dst), (src), (n))) + (n))

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

/* ---- trivial bump-allocator pool ----------------------------------------
 * Real, non-overlapping allocations (not a fixed shared buffer), so a fold
 * bug that overruns one allocation into the next is a real corruption an
 * ASan/UBSan-instrumented run of this test can catch. */

#define NGX_SHIM_POOL_SIZE  (1 << 20)

typedef struct {
    u_char  buf[NGX_SHIM_POOL_SIZE];
    size_t  used;
} ngx_pool_t;

static void *
ngx_shim_alloc(ngx_pool_t *pool, size_t size)
{
    void  *p;

    if (pool->used + size > NGX_SHIM_POOL_SIZE) {
        fprintf(stderr, "shim pool exhausted (%zu + %zu > %d)\n",
                pool->used, size, NGX_SHIM_POOL_SIZE);
        abort();
    }

    p = pool->buf + pool->used;
    pool->used += size;
    return p;
}

static void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    return ngx_shim_alloc(pool, size);
}

static void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
    return ngx_shim_alloc(pool, size);
}

/* ---- ngx_array_t: real growth semantics, not a fixed-size stand-in ------ */

typedef struct {
    void        *elts;
    ngx_uint_t   nelts;
    size_t       size;
    ngx_uint_t   nalloc;
    ngx_pool_t  *pool;
} ngx_array_t;

static ngx_int_t
ngx_array_init(ngx_array_t *array, ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    array->nelts = 0;
    array->size = size;
    array->nalloc = n;
    array->pool = pool;
    array->elts = ngx_palloc(pool, n * size);
    return array->elts ? NGX_OK : NGX_ERROR;
}

static void *
ngx_array_push(ngx_array_t *a)
{
    void    *new_elts;
    size_t   grown;

    if (a->nelts == a->nalloc) {
        grown = (a->nalloc == 0 ? 1 : a->nalloc * 2);
        new_elts = ngx_palloc(a->pool, grown * a->size);
        if (new_elts == NULL) {
            return NULL;
        }
        memcpy(new_elts, a->elts, a->nelts * a->size);
        a->elts = new_elts;
        a->nalloc = grown;
    }

    return (u_char *) a->elts + a->size * a->nelts++;
}

/* ---- logging: record the last message so a test can assert the oversize
 * path actually logged, without pulling in nginx's log machinery. */

static char  ngx_shim_last_log[512];

#define NGX_LOG_INFO  0

typedef struct { int _unused; } ngx_shim_log_t;
static ngx_shim_log_t  ngx_shim_conn_log;

typedef struct {
    ngx_shim_log_t  *log;
} ngx_shim_connection_t;
static ngx_shim_connection_t  ngx_shim_connection = { &ngx_shim_conn_log };

/* Request type: fold_size reaches r->connection->log, fold_all reaches
 * r->pool. */
typedef struct ngx_http_request_s {
    ngx_shim_connection_t  *connection;
    ngx_pool_t             *pool;
} ngx_http_request_t;

static ngx_pool_t  ngx_shim_request_pool;
static ngx_http_request_t  ngx_shim_request =
    { &ngx_shim_connection, &ngx_shim_request_pool };

/* Production calls ngx_log_error(level, log, err, fmt, ...) as a macro; the
 * sliced body's one call site passes %V (ngx_str_t*) and %uz (size_t) — the
 * shim only needs to swallow the varargs and record that it fired, since the
 * test asserts on the log FIRING, not nginx's %V/%uz rendering. `log` is
 * threaded through (not discarded) so -Wunused-parameter stays honest about
 * r->connection->log actually being used at the call site. */
#define ngx_log_error(level, log, err, fmt, ...) \
    ngx_shim_last_log_mark(log)

static void
ngx_shim_last_log_mark(ngx_shim_log_t *log)
{
    (void) log;
    snprintf(ngx_shim_last_log, sizeof(ngx_shim_last_log), "logged");
}

/* ---- the REAL digest, via EVP --------------------------------------------
 * Same shape as production's NGX_SSL branch. */

typedef struct {
    EVP_MD_CTX  *md;
    ngx_int_t    ok;
} ngx_http_cache_turbo_digest_t;

static EVP_MD_CTX  *ngx_http_cache_turbo_worker_md;

static void
ngx_http_cache_turbo_digest_init(ngx_http_cache_turbo_digest_t *d)
{
    if (ngx_http_cache_turbo_worker_md == NULL) {
        ngx_http_cache_turbo_worker_md = EVP_MD_CTX_new();
        if (ngx_http_cache_turbo_worker_md == NULL) {
            abort();
        }
    }

    d->md = ngx_http_cache_turbo_worker_md;
    d->ok = EVP_DigestInit_ex(d->md, EVP_sha256(), NULL) == 1 ? 1 : 0;
}

static void
ngx_http_cache_turbo_digest_update(ngx_http_cache_turbo_digest_t *d,
    const void *data, size_t len)
{
    if (d->ok && EVP_DigestUpdate(d->md, data, len) != 1) {
        d->ok = 0;
    }
}

static ngx_int_t
ngx_http_cache_turbo_digest_final(ngx_http_cache_turbo_digest_t *d,
    u_char out[32])
{
    unsigned int  n = 0;

    if (!d->ok || EVP_DigestFinal_ex(d->md, out, &n) != 1 || n != 32) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_cache_turbo_digest(const void *data, size_t len, u_char out[32])
{
    ngx_http_cache_turbo_digest_t  d;

    ngx_http_cache_turbo_digest_init(&d);
    ngx_http_cache_turbo_digest_update(&d, data, len);
    return ngx_http_cache_turbo_digest_final(&d, out);
}

/* ---- key-fold constants and ctx, mirrored from module.c ------------------
 * These live OUTSIDE the sliced function bodies (they are #defines and a
 * typedef at file scope in production), so the shim declares them here. The
 * VALUES are load-bearing: a drift between this 256 and module.c's would make
 * the byte-identity assertions below test a different framing than
 * production ships. */

#define NGX_HTTP_CACHE_TURBO_KEY_COOKIE_MAX       256
#define NGX_HTTP_CACHE_TURBO_KEY_COOKIE_OVERSIZE  0xffffffffu

typedef struct {
    ngx_str_t   name;
    ngx_str_t   val;
    uint32_t    vlen;
    uint32_t    vfield;
} ngx_http_cache_turbo_key_cookie_slot_t;

typedef struct {
    ngx_str_t  cache_key;
    u_char     key_hash[32];
} ngx_http_cache_turbo_ctx_t;

#endif /* NGX_CACHE_TURBO_UNIT_SHIM_KEY_FOLD_H */
