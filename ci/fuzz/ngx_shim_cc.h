/*
 * Minimal nginx surface for fuzzing the cache-turbo origin Cache-Control /
 * Surrogate-Control parser (ngx_http_cache_turbo_cc_token / cc_has /
 * cc_parse_delta / cc_delta / cc_delta_all).
 *
 * Self-contained: only fuzz_cache_control.c includes it. The parser bodies are
 * sliced VERBATIM from the shipped src into generated_cache_control.inc; only
 * the types and string helpers they use are redefined here, faithfully to
 * src/core (ngx_list_t, ngx_table_elt_t, ngx_strncasecmp, ngx_strlchr,
 * NGX_MAX_TIME_T_VALUE for a 64-bit time_t).
 */

#ifndef NGX_CACHE_TURBO_FUZZ_CC_SHIM_H
#define NGX_CACHE_TURBO_FUZZ_CC_SHIM_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

typedef intptr_t      ngx_int_t;
typedef uintptr_t     ngx_uint_t;
typedef unsigned char u_char;

/* nginx: sizeof(time_t) == 8 -> 9223372036854775807LL (ngx_config.h). */
#define NGX_MAX_TIME_T_VALUE  9223372036854775807LL

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

#define ngx_null_string  { 0, NULL }

typedef struct {
    ngx_uint_t  hash;
    ngx_str_t   key;
    ngx_str_t   value;
} ngx_table_elt_t;

typedef struct ngx_list_part_s ngx_list_part_t;
struct ngx_list_part_s {
    void             *elts;
    ngx_uint_t        nelts;
    ngx_list_part_t  *next;
};

typedef struct {
    ngx_list_part_t  *last;
    ngx_list_part_t   part;
} ngx_list_t;

/* ngx_strncasecmp: byte-wise case-insensitive compare, stops at a NUL. */
static inline ngx_int_t
ngx_strncasecmp(u_char *s1, u_char *s2, size_t n)
{
    return (ngx_int_t) strncasecmp((const char *) s1, (const char *) s2, n);
}

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

#endif
