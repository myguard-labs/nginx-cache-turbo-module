/*
 * Minimal nginx surface for fuzzing the cache-turbo origin Vary classifier
 * (ngx_http_cache_turbo_classify_vary_next_token / _classify_token and
 * ngx_http_cache_turbo_vary_ignore_match).
 *
 * Self-contained: only fuzz_vary.c includes it. The function bodies are sliced
 * VERBATIM from the shipped src into generated_vary.inc; only the types,
 * constants and string helper they use are redefined here, faithfully to
 * src/core (ngx_str_t, ngx_array_t, ngx_strncasecmp, NGX_CONF_UNSET_PTR) and to
 * src/ngx_http_cache_turbo_internal.h (the VARY_* bits) and
 * ngx_http_cache_turbo_module.h (loc_conf->vary_ignore).
 */

#ifndef NGX_CACHE_TURBO_FUZZ_VARY_SHIM_H
#define NGX_CACHE_TURBO_FUZZ_VARY_SHIM_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef intptr_t      ngx_int_t;
typedef uintptr_t     ngx_uint_t;
typedef unsigned char u_char;

#define NGX_CONF_UNSET_PTR  ((void *) -1)

#define NGX_HTTP_CACHE_TURBO_VARY_ENCODING  0x1
#define NGX_HTTP_CACHE_TURBO_VARY_DEVICE    0x2
#define NGX_HTTP_CACHE_TURBO_VARY_LANG      0x4
#define NGX_HTTP_CACHE_TURBO_VARY_ORIGIN    0x8

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

typedef struct {
    void        *elts;
    ngx_uint_t   nelts;
} ngx_array_t;

/* Only the one field the sliced code reads. */
typedef struct {
    ngx_array_t  *vary_ignore;
} ngx_http_cache_turbo_loc_conf_t;

/* ngx_strncasecmp: byte-wise case-insensitive compare, stops at a NUL. */
static inline ngx_int_t
ngx_strncasecmp(u_char *s1, u_char *s2, size_t n)
{
    return (ngx_int_t) strncasecmp((const char *) s1, (const char *) s2, n);
}

#endif
