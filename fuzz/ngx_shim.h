/*
 * Minimal nginx surface for fuzzing the cache-turbo RESP reply parsers
 * (ngx_http_cache_turbo_redis_parse / _parse_array / _parse_scan).
 *
 * Those three functions read attacker-influenceable bytes — a Redis reply
 * from a shared, possibly-compromised or buggy L2 — out of op->rbuf doing
 * length-line + bulk-string pointer arithmetic against op->rbuf + op->rlen.
 * That is exactly the OOB-read / integer-handling bug class coverage-guided
 * fuzzing catches and the Perl/python runtime suite misses.
 *
 * Everything here is the *faithful* nginx surface the parsers touch, copied
 * verbatim from the nginx tree (ngx_atoi, ngx_strlchr) or reduced to the
 * exact fields/semantics the sliced parser bodies use (the op struct, the
 * pool allocator). The parser bodies themselves are NOT copied — they are
 * sliced from the shipped src/ngx_http_cache_turbo_redis.c at build time by
 * extract_parser.sh into generated_parser.inc, so the fuzzer always exercises
 * production code with no drift.
 */

#ifndef NGX_CACHE_TURBO_FUZZ_SHIM_H
#define NGX_CACHE_TURBO_FUZZ_SHIM_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* --- core types (nginx ngx_config.h) --- */
typedef intptr_t   ngx_int_t;
typedef uintptr_t  ngx_uint_t;
typedef unsigned char u_char;

/* nginx ngx_string.h: { len; data; } — order is load-bearing for nothing the
 * parser does, but matched to upstream anyway. */
typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

/* --- core constants (nginx ngx_core.h / ngx_config.h) --- */
#define NGX_OK            0
#define NGX_ERROR        -1
#define NGX_AGAIN        -2
#define NGX_DONE         -4
#define NGX_DECLINED     -5

#if (UINTPTR_MAX > 0xffffffffUL)
#define NGX_MAX_INT_T_VALUE  9223372036854775807LL
#else
#define NGX_MAX_INT_T_VALUE  2147483647
#endif

#define CR  (u_char) '\r'
#define LF  (u_char) '\n'

/* The two reply-size guards the parsers enforce. Kept in sync with the
 * #define ... lines in src/ngx_http_cache_turbo_redis.c — the build-time
 * grep_defines step (extract_parser.sh) FAILS if the shipped values change,
 * so these can never silently drift. */
#define NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY    (64 * 1024 * 1024)
#define NGX_HTTP_CACHE_TURBO_REDIS_MAX_MEMBERS  (1024 * 1024)

/*
 * Pool shim. The parsers allocate one ngx_str_t[] per call via ngx_palloc.
 * We back each alloc with malloc and register it so the harness can free the
 * lot after every input (otherwise libFuzzer's leak check fires). A request
 * makes at most one array alloc per parser, so a tiny fixed registry suffices.
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
        return NULL;                   /* parser handles NULL -> NGX_DECLINED */
    }
    /* malloc is at least max_align_t aligned, satisfying ngx_str_t alignment
     * (the parsers deliberately use ngx_palloc, not byte-aligned ngx_pnalloc). */
    p = malloc(size ? size : 1);
    if (p == NULL) {
        return NULL;
    }
    pool->allocs[pool->nallocs++] = p;
    return p;
}

/* Not used by the sliced parsers (they only ngx_palloc), provided for surface
 * completeness so the .inc compiles even if a future slice pulls in a pnalloc
 * caller. Byte-aligned like upstream. */
static void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    return ngx_palloc(pool, size);
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

/*
 * The op struct, reduced to exactly the three fields the parser bodies read:
 * the accumulated reply buffer (rbuf), how many bytes are in it (rlen), and
 * the pool the members/keys array is allocated from. The shipped struct has
 * many more fields (connection, events, callbacks); the parsers touch none of
 * them.
 */
typedef struct {
    u_char     *rbuf;
    size_t      rlen;
    ngx_pool_t *pool;
} ngx_http_cache_turbo_redis_op_t;

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

/* --- verbatim from nginx src/core/ngx_string.c --- */
static ngx_int_t
ngx_atoi(u_char *line, size_t n)
{
    ngx_int_t  value, cutoff, cutlim;

    if (n == 0) {
        return NGX_ERROR;
    }

    cutoff = NGX_MAX_INT_T_VALUE / 10;
    cutlim = NGX_MAX_INT_T_VALUE % 10;

    for (value = 0; n--; line++) {
        if (*line < '0' || *line > '9') {
            return NGX_ERROR;
        }

        if (value >= cutoff && (value > cutoff || *line - '0' > cutlim)) {
            return NGX_ERROR;
        }

        value = value * 10 + (*line - '0');
    }

    return value;
}

#endif /* NGX_CACHE_TURBO_FUZZ_SHIM_H */
