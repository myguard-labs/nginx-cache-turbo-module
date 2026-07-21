/*
 * Minimal nginx surface for fuzzing the cache-turbo query-string normaliser
 * (ngx_http_cache_turbo_normalized_args_variable + its tok_cmp comparator).
 *
 * Self-contained on purpose: only fuzz_norm_args.c includes it, so it can
 * redefine the same core types as ngx_shim.h without an ODR clash (different
 * translation unit). The normaliser body is sliced VERBATIM from the shipped
 * src into generated_norm_args.inc — not copied here — so the fuzzer always
 * exercises production code.
 *
 * Three helpers it calls are STUBBED rather than sliced (vary_suffix,
 * var_set, name_denied). That is sound for the bug class under test: the
 * output buffer is sized from a `total` computed over the SAME kept-token
 * set that is then written, so the size-vs-write bound is independent of
 * WHICH tokens name_denied drops or whether a Vary suffix is appended. The
 * stubs keep faithful shapes (var_set really copies; name_denied gives a
 * deterministic deny rule so the fuzzer explores both kept==n and kept<n).
 */

#ifndef NGX_CACHE_TURBO_FUZZ_ARGS_SHIM_H
#define NGX_CACHE_TURBO_FUZZ_ARGS_SHIM_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef intptr_t   ngx_int_t;
typedef uintptr_t  ngx_uint_t;
typedef ngx_int_t  ngx_flag_t;
typedef unsigned char u_char;

#define NGX_OK             0
#define NGX_ERROR         -1
#define NGX_CONF_UNSET    -1
#define NGX_CONF_UNSET_PTR  ((void *) -1)

#define NGX_HTTP_CACHE_TURBO_VARY_SUFFIX_MAX  32

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

/* nginx ngx_variable_value_t bitfield layout (src/core/ngx_string.h). */
typedef struct {
    unsigned    len:28;
    unsigned    valid:1;
    unsigned    no_cacheable:1;
    unsigned    not_found:1;
    unsigned    escape:1;
    u_char     *data;
} ngx_http_variable_value_t;

/* --- string helpers, verbatim/faithful upstream --- */
#define ngx_memcpy(dst, src, n)   (void) memcpy(dst, src, n)
#define ngx_cpymem(dst, src, n)   (((u_char *) memcpy(dst, src, n)) + (n))
#define ngx_memcmp(s1, s2, n)     memcmp((const char *) s1, (const char *) s2, n)
#define ngx_min(a, b)             ((a < b) ? (a) : (b))

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

/*
 * Pool shim: malloc-backed with a small free registry so libFuzzer's leak
 * check stays quiet. The normaliser does at most a few allocs per call
 * (toks[] + out[] + maybe var_set copy).
 */
#define NGX_FUZZ_POOL_MAX_ALLOCS  16
typedef struct {
    void    *allocs[NGX_FUZZ_POOL_MAX_ALLOCS];
    size_t   nallocs;
} ngx_pool_t;

static void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
    void *p;
    if (pool->nallocs >= NGX_FUZZ_POOL_MAX_ALLOCS) {
        return NULL;                  /* caller handles NULL -> NGX_ERROR */
    }
    p = malloc(size ? size : 1);
    if (p == NULL) {
        return NULL;
    }
    pool->allocs[pool->nallocs++] = p;
    return p;
}
#define ngx_pnalloc(pool, size)  ngx_palloc((pool), (size))

static void
ngx_fuzz_pool_reset(ngx_pool_t *pool)
{
    size_t  i;
    for (i = 0; i < pool->nallocs; i++) {
        free(pool->allocs[i]);
    }
    pool->nallocs = 0;
}

/*
 * ngx_sort() — faithful copy of nginx src/core/ngx_array.c (insertion sort
 * with a scratch element). The normaliser relies on a STABLE sort; this is
 * upstream's exact algorithm.
 */
static void
ngx_sort(void *base, size_t n, size_t size,
    ngx_int_t (*cmp)(const void *, const void *))
{
    u_char  *p1, *p2, *p;

    p = (u_char *) malloc(size ? size : 1);
    if (p == NULL) {
        return;
    }
    for (p1 = (u_char *) base + size;
         p1 < (u_char *) base + n * size;
         p1 += size)
    {
        memcpy(p, p1, size);
        for (p2 = p1 - size;
             p2 >= (u_char *) base && cmp(p2, p) > 0;
             p2 -= size)
        {
            memcpy(p2 + size, p2, size);
        }
        memcpy(p2 + size, p, size);
    }
    free(p);
}

/* --- request / loc-conf, reduced to the fields the sliced body reads --- */
typedef struct {
    ngx_str_t    args;
    ngx_pool_t  *pool;
} ngx_http_request_t;

typedef struct {
    ngx_int_t    normalize_vary;
    void        *normalize_strip;
} ngx_http_cache_turbo_loc_conf_t;

/* The handler fetches its loc-conf via this macro; route it to the global
 * the harness sets up. The module symbol only has to exist for the macro
 * argument to compile. */
static const int  ngx_http_cache_turbo_module = 0;
extern ngx_http_cache_turbo_loc_conf_t *g_fuzz_clcf;
#define ngx_http_get_module_loc_conf(r, mod)  ((void) (mod), g_fuzz_clcf)

/* --- STUBBED helpers (see header comment for why this is faithful) --- */

/* normalize_vary is driven to 0 by the harness, so this returns 0 without
 * touching buf; kept as a real symbol the sliced body can call. */
static size_t
ngx_http_cache_turbo_vary_suffix(ngx_http_request_t *r, ngx_int_t vary,
    u_char *buf)
{
    (void) r; (void) vary; (void) buf;
    return 0;
}

/* Faithful: copy len bytes into the pool (or emit the empty string). */
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

/* Deterministic deny rule (not production semantics): drop a param whose
 * name begins with '_'. Lets the fuzzer reach both the kept==n and kept<n
 * branches; the OOB-write bound is invariant to the exact rule. */
static ngx_int_t
ngx_http_cache_turbo_name_denied(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *name, size_t nlen)
{
    (void) clcf;
    return (nlen > 0 && name[0] == '_') ? 1 : 0;
}

#endif /* NGX_CACHE_TURBO_FUZZ_ARGS_SHIM_H */
