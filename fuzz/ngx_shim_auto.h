/*
 * Minimal nginx surface for fuzzing the cache-turbo auto-classify gate
 * (ngx_http_cache_turbo_auto_skip + ngx_http_cache_turbo_cookie_has).
 *
 * auto_skip reads attacker-controlled request bytes — the URI and, via
 * cookie_has, every Cookie header value — doing manual length-bounded scanning
 * (ngx_strnstr over a non-NUL-terminated cookie value of length ck->value.len,
 * ngx_strncmp of a URI prefix guarded by r->uri.len). A reintroduced
 * NUL-bounded scan or an off-by-one in those bounds is a worker-crashing
 * OOB read the runtime suite can't reach. The fuzzer drives the SHIPPED code
 * (generated_auto_classify.inc, sliced at build time) against arbitrary URI +
 * cookie bytes with NO trailing NUL, so ASAN turns any over-read into an
 * immediate heap-buffer-overflow.
 *
 * The arg branch of auto_skip calls ngx_http_arg (core nginx, already robust);
 * the driver sets r->args.len = 0 so that branch is skipped — the ngx_http_arg
 * stub below exists only to satisfy the linker and is never called.
 */

#ifndef NGX_CACHE_TURBO_FUZZ_SHIM_AUTO_H
#define NGX_CACHE_TURBO_FUZZ_SHIM_AUTO_H

#include <string.h>

#include "ngx_shim.h"   /* ngx_int_t/ngx_uint_t/u_char/ngx_str_t, NGX_OK/DECLINED */

typedef ngx_int_t  ngx_flag_t;

/* Select the linked-list cookie path (nginx >= 1.23) in cookie_has. */
#define nginx_version  1031001

/* String primitives the block uses, faithful to nginx's ngx_string.h. */
#define ngx_strncmp(s1, s2, n)  strncmp((char *) (s1), (char *) (s2), n)
#define ngx_strlen(s)           strlen((const char *) (s))

/* ngx_strnstr: locate NUL-terminated s2 within the first n bytes of s1, never
 * reading past s1 + n. Mirrors src/core/ngx_string.c. */
static u_char *
ngx_strnstr(u_char *s1, char *s2, size_t n)
{
    u_char  c1, c2;
    size_t  len;

    c2 = *(u_char *) s2++;
    len = strlen(s2);

    do {
        do {
            if (n-- == 0) {
                return NULL;
            }
            c1 = *s1++;
            if (c1 == 0) {
                return NULL;
            }
        } while (c1 != c2);

        if (n < len) {
            return NULL;
        }
    } while (strncmp((const char *) s1, s2, len) != 0);

    return --s1;
}

/* Reduced request/loc-conf/table structs: exactly the fields the block reads. */
typedef struct ngx_table_elt_s  ngx_table_elt_t;
struct ngx_table_elt_s {
    ngx_str_t         value;
    ngx_table_elt_t  *next;
};

typedef struct {
    struct {
        ngx_table_elt_t  *cookie;
    } headers_in;
    ngx_str_t  uri;
    ngx_str_t  args;
} ngx_http_request_t;

typedef struct {
    ngx_uint_t  backend_presets;
} ngx_http_cache_turbo_loc_conf_t;

/* CMS preset bits (kept in sync with src/ngx_http_cache_turbo_module.h). */
#define NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS    0x0001
#define NGX_HTTP_CACHE_TURBO_BACKEND_WOOCOMMERCE  0x0002
#define NGX_HTTP_CACHE_TURBO_BACKEND_JOOMLA       0x0004
#define NGX_HTTP_CACHE_TURBO_BACKEND_GENERIC                                   \
    (NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS                                    \
     | NGX_HTTP_CACHE_TURBO_BACKEND_WOOCOMMERCE                                \
     | NGX_HTTP_CACHE_TURBO_BACKEND_JOOMLA)

/* Linker stub: never called (driver keeps r->args.len == 0). */
static ngx_int_t
ngx_http_arg(ngx_http_request_t *r, u_char *name, size_t len, ngx_str_t *value)
{
    (void) r; (void) name; (void) len; (void) value;
    return NGX_DECLINED;
}

#endif /* NGX_CACHE_TURBO_FUZZ_SHIM_AUTO_H */
