/*
 * Minimal nginx surface for fuzzing the cache-turbo Cookie index, Cookie
 * Aho-Corasick scan and query-string argument parser
 * (ngx_http_cache_turbo_cookie_index_parse_one, _cookie_ac_scan_one,
 * _argparse_tail_count, _argparse_build).
 *
 * Self-contained: only fuzz_cookie_args.c includes it. The function bodies and
 * the typedef blocks they use are sliced VERBATIM from the shipped src into
 * generated_cookie_args.inc; only the core types, string helpers and a
 * recording pool are redefined here, faithfully to src/core (ngx_str_t,
 * ngx_strlchr, ngx_strncmp, ngx_memcpy) and to the reduced request struct the
 * sliced code reads (r->args, r->pool).
 *
 * The pool is a malloc-per-allocation recorder: every ngx_palloc is an EXACT
 * heap block (so ASan sees a write past the computed size) and its byte size
 * is kept so the harness can assert the allocation equals the size the
 * counting pass computed. `fail` makes every ngx_palloc return NULL.
 */

#ifndef NGX_CACHE_TURBO_FUZZ_COOKIE_ARGS_SHIM_H
#define NGX_CACHE_TURBO_FUZZ_COOKIE_ARGS_SHIM_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef intptr_t      ngx_int_t;
typedef uintptr_t     ngx_uint_t;
typedef unsigned char u_char;

#define NGX_OK                 0
#define NGX_ERROR              -1
#define NGX_MAX_SIZE_T_VALUE   ((size_t) -1)

#define ngx_strncmp(s1, s2, n)  strncmp((char *) (s1), (char *) (s2), n)
#define ngx_memcpy(dst, src, n)  memcpy(dst, src, n)

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

#define NGX_FUZZ_POOL_MAX_ALLOCS  64

typedef struct {
    void    *allocs[NGX_FUZZ_POOL_MAX_ALLOCS];
    size_t   sizes[NGX_FUZZ_POOL_MAX_ALLOCS];
    size_t   nallocs;
    int      fail;
} ngx_pool_t;

static void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
    void  *p;

    if (pool->fail || pool->nallocs >= NGX_FUZZ_POOL_MAX_ALLOCS) {
        return NULL;
    }
    p = malloc(size ? size : 1);
    if (p == NULL) {
        return NULL;
    }
    pool->allocs[pool->nallocs] = p;
    pool->sizes[pool->nallocs] = size;
    pool->nallocs++;
    return p;
}

static void
ngx_fuzz_pool_reset(ngx_pool_t *pool)
{
    size_t  i;

    for (i = 0; i < pool->nallocs; i++) {
        free(pool->allocs[i]);
    }
    pool->nallocs = 0;
}

/* --- verbatim from nginx src/core/ngx_string.h --- */
static inline u_char *
ngx_strlchr(u_char *p, u_char *last, u_char c)
{
    while (p < last) {

        if (*p == c) {
            return p;
        }

        p++;
    }

    return NULL;
}

/* Work counter hook used by cookie_ac_scan_one; absent in production builds. */
#define ngx_http_cache_turbo_cookie_work_add(n)  ((void) 0)

/* Only the two fields the sliced code reads. */
typedef struct {
    ngx_str_t    args;
    ngx_pool_t  *pool;
} ngx_http_request_t;

#endif
