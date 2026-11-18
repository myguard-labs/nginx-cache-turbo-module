/*
 * Minimal nginx surface for fuzzing the cache-turbo control-input code: the
 * tag-purge hex decoder (ngx_http_cache_turbo_hexdecode), the origin
 * Surrogate-Key / Cache-Tag tokeniser (_body_filter_tag_split) and the admin
 * warm-list splitter (_warm, _warm_uri_is_safe, _warm_raw_is_safe,
 * _warm_file_finish).
 *
 * Self-contained: only fuzz_control_inputs.c includes it. The function bodies
 * and the cap defines are sliced VERBATIM from the shipped src into
 * generated_control_inputs.inc; only the core types, string helpers, a
 * recording pool and the two out-of-slice collaborators are redefined here:
 *
 *   - ngx_unescape_uri is copied verbatim from nginx src/core/ngx_string.c.
 *   - ngx_http_cache_turbo_warm_one (fires a background subrequest) is a stub
 *     that records every argument it is handed and fails on a schedule the
 *     harness chooses; ngx_http_cache_turbo_send_json records the reply.
 *   - ngx_log_error only counts warnings.
 *
 * The pool is a malloc-per-allocation recorder: every ngx_pnalloc is an EXACT
 * heap block (so ASan sees a write past the requested size) and `fail_at`
 * makes the Nth allocation and every later one return NULL.
 */

#ifndef NGX_CACHE_TURBO_FUZZ_CONTROL_INPUTS_SHIM_H
#define NGX_CACHE_TURBO_FUZZ_CONTROL_INPUTS_SHIM_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef intptr_t      ngx_int_t;
typedef uintptr_t     ngx_uint_t;
typedef unsigned char u_char;

#define NGX_OK                          0
#define NGX_ERROR                       -1
#define NGX_HTTP_OK                     200
#define NGX_HTTP_INTERNAL_SERVER_ERROR  500
#define NGX_LOG_WARN                    5

#define ngx_memcmp(s1, s2, n)  memcmp((char *) (s1), (char *) (s2), n)

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

#define ngx_str_set(str, text)                                               \
    (str)->len = sizeof(text) - 1; (str)->data = (u_char *) text
#define ngx_str_null(str)  (str)->len = 0; (str)->data = NULL

typedef struct {
    void   **allocs;
    size_t   nallocs;        /* blocks held */
    size_t   cap;
    size_t   nreq;           /* allocation requests so far */
    size_t   fail_at;        /* request index from which every one fails */
} ngx_pool_t;

static void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    void  *p;

    if (pool->nreq++ >= pool->fail_at) {
        return NULL;
    }
    if (pool->nallocs == pool->cap) {
        size_t  ncap = pool->cap ? pool->cap * 2 : 64;
        void  **na = realloc(pool->allocs, ncap * sizeof(void *));

        if (na == NULL) {
            abort();
        }
        pool->allocs = na;
        pool->cap = ncap;
    }
    p = malloc(size ? size : 1);
    if (p == NULL) {
        abort();
    }
    pool->allocs[pool->nallocs++] = p;
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
    pool->nreq = 0;
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

#define NGX_UNESCAPE_URI       1
#define NGX_UNESCAPE_REDIRECT  2

/* --- verbatim from nginx src/core/ngx_string.c --- */
static void
ngx_unescape_uri(u_char **dst, u_char **src, size_t size, ngx_uint_t type)
{
    u_char  *d, *s, ch, c, decoded;
    enum {
        sw_usual = 0,
        sw_quoted,
        sw_quoted_second
    } state;

    d = *dst;
    s = *src;

    state = 0;
    decoded = 0;

    while (size--) {

        ch = *s++;

        switch (state) {
        case sw_usual:
            if (ch == '?'
                && (type & (NGX_UNESCAPE_URI|NGX_UNESCAPE_REDIRECT)))
            {
                *d++ = ch;
                goto done;
            }

            if (ch == '%') {
                state = sw_quoted;
                break;
            }

            *d++ = ch;
            break;

        case sw_quoted:

            if (ch >= '0' && ch <= '9') {
                decoded = (u_char) (ch - '0');
                state = sw_quoted_second;
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                decoded = (u_char) (c - 'a' + 10);
                state = sw_quoted_second;
                break;
            }

            /* the invalid quoted character */

            state = sw_usual;

            *d++ = ch;

            break;

        case sw_quoted_second:

            state = sw_usual;

            if (ch >= '0' && ch <= '9') {
                ch = (u_char) ((decoded << 4) + (ch - '0'));

                if (type & NGX_UNESCAPE_REDIRECT) {
                    if (ch > '%' && ch < 0x7f) {
                        *d++ = ch;
                        break;
                    }

                    *d++ = '%'; *d++ = *(s - 2); *d++ = *(s - 1);

                    break;
                }

                *d++ = ch;

                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                ch = (u_char) ((decoded << 4) + (c - 'a') + 10);

                if (type & NGX_UNESCAPE_URI) {
                    if (ch == '?') {
                        *d++ = ch;
                        goto done;
                    }

                    *d++ = ch;
                    break;
                }

                if (type & NGX_UNESCAPE_REDIRECT) {
                    if (ch == '?') {
                        *d++ = ch;
                        goto done;
                    }

                    if (ch > '%' && ch < 0x7f) {
                        *d++ = ch;
                        break;
                    }

                    *d++ = '%'; *d++ = *(s - 2); *d++ = *(s - 1);
                    break;
                }

                *d++ = ch;

                break;
            }

            /* the invalid quoted character */

            break;
        }
    }

done:

    *dst = d;
    *src = s;
}

/* ---- ngx_log_error: warning counter only -------------------------------- */

static unsigned long  ngx_fuzz_warns;

#define ngx_log_error(level, log, err, ...)                                  \
    do {                                                                     \
        (void) (log);                                                        \
        ngx_fuzz_warns++;                                                    \
    } while (0)

typedef struct {
    void  *log;
} ngx_connection_t;

/* Only the fields the sliced code reads. */
typedef struct {
    ngx_str_t          uri;
    ngx_str_t          args;
    ngx_pool_t        *pool;
    ngx_connection_t  *connection;
} ngx_http_request_t;

/* ---- ngx_sprintf: the single "%ui" conversion warm() uses ---------------- */

/* Unbounded on purpose (like the real one): the exact-sized destination makes
 * ASan report a reply that outgrows its allocation. */
static u_char *
ngx_sprintf(u_char *buf, const char *fmt, ngx_uint_t v)
{
    char    f[64];
    size_t  n = strlen(fmt), i, o = 0;

    for (i = 0; i < n && o + 4 < sizeof(f); i++) {
        if (fmt[i] == '%' && fmt[i + 1] == 'u' && fmt[i + 2] == 'i') {
            f[o++] = '%';
            f[o++] = 'l';
            f[o++] = 'u';
            i += 2;
        } else {
            f[o++] = fmt[i];
        }
    }
    f[o] = '\0';
    return buf + sprintf((char *) buf, f, (unsigned long) v);
}

/* ---- out-of-slice collaborators: recorders ------------------------------- */

typedef struct {
    const u_char  *uri;
    size_t         uri_len;
    const u_char  *args;
    size_t         args_len;
    const u_char  *raw;
    size_t         raw_len;
} ngx_fuzz_warm_call_t;

static ngx_fuzz_warm_call_t  *ngx_fuzz_calls;
static size_t                 ngx_fuzz_ncalls, ngx_fuzz_calls_cap;
static unsigned               ngx_fuzz_warm_pattern;
static volatile unsigned char ngx_fuzz_sink;

/* Failure schedule shared with the harness's reference model. */
static int
ngx_fuzz_warm_fails(size_t idx, unsigned pattern)
{
    switch (pattern) {
    case 1:
        return 1;
    case 2:
        return idx % 2 == 0;
    case 3:
        return idx % 3 != 2;
    default:
        return 0;
    }
}

/* Reads every handed byte (ASan checks the ranges), records the call. */
static ngx_int_t
ngx_http_cache_turbo_warm_one(ngx_http_request_t *r, ngx_str_t *uri,
    ngx_str_t *args, u_char *snap, size_t snap_len, void **ctx_out,
    ngx_str_t *unparsed_uri_src)
{
    ngx_fuzz_warm_call_t  *c;
    size_t                 i;
    unsigned char          x = 0;

    (void) r;
    (void) snap;
    (void) snap_len;
    (void) ctx_out;

    if (ngx_fuzz_ncalls == ngx_fuzz_calls_cap) {
        size_t  ncap = ngx_fuzz_calls_cap ? ngx_fuzz_calls_cap * 2 : 256;

        ngx_fuzz_calls = realloc(ngx_fuzz_calls, ncap * sizeof(*c));
        if (ngx_fuzz_calls == NULL) {
            abort();
        }
        ngx_fuzz_calls_cap = ncap;
    }
    c = &ngx_fuzz_calls[ngx_fuzz_ncalls];
    c->uri = uri->data;
    c->uri_len = uri->len;
    c->args = args->data;
    c->args_len = args->len;
    c->raw = unparsed_uri_src->data;
    c->raw_len = unparsed_uri_src->len;

    for (i = 0; i < uri->len; i++) {
        x ^= uri->data[i];
    }
    for (i = 0; i < args->len; i++) {
        x ^= args->data[i];
    }
    for (i = 0; i < unparsed_uri_src->len; i++) {
        x ^= unparsed_uri_src->data[i];
    }
    ngx_fuzz_sink = x;

    return ngx_fuzz_warm_fails(ngx_fuzz_ncalls++, ngx_fuzz_warm_pattern)
           ? NGX_ERROR : NGX_OK;
}

static int         ngx_fuzz_replies;
static ngx_int_t   ngx_fuzz_reply_status;
static char        ngx_fuzz_reply_body[256];

static ngx_int_t
ngx_http_cache_turbo_send_json(ngx_http_request_t *r, ngx_int_t status,
    ngx_str_t *body)
{
    (void) r;
    ngx_fuzz_replies++;
    ngx_fuzz_reply_status = status;
    snprintf(ngx_fuzz_reply_body, sizeof(ngx_fuzz_reply_body), "%.*s",
             (int) body->len, (char *) body->data);
    return status;
}

#endif
