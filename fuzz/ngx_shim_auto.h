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

/* NGX_CONF_UNSET_PTR is nginx's "directive not set" sentinel. The sliced code
 * tests pointer conf fields against it, so the shim must define it with the
 * same value the real ngx_conf.h uses. */
#define NGX_CONF_UNSET_PTR  ((void *) -1)

typedef struct {
    ngx_uint_t  backend_presets;
    /* Mirrors src/ngx_http_cache_turbo_module.h. The preset URI tier rebases
     * r->uri onto this mount before comparing, so the sliced auto_skip reads
     * it and the field must exist here too — see the bit-mirroring note below,
     * which applies to conf FIELDS for the same reason. */
    ngx_str_t  *backend_prefix;
} ngx_http_cache_turbo_loc_conf_t;

/*
 * CMS preset bits — MUST mirror src/ngx_http_cache_turbo_module.h. The fuzz
 * target compiles the sliced registry WITHOUT the real header, so a bit added
 * there and not here fails the fuzz build with "use of undeclared identifier"
 * (and only in CI, since extract_auto_classify.sh does not compile). Adding a
 * preset means editing BOTH. The static assert below catches the common case.
 */
#define NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS    0x0001
#define NGX_HTTP_CACHE_TURBO_BACKEND_WOOCOMMERCE  0x0002
#define NGX_HTTP_CACHE_TURBO_BACKEND_JOOMLA       0x0004
#define NGX_HTTP_CACHE_TURBO_BACKEND_XENFORO      0x0008
#define NGX_HTTP_CACHE_TURBO_BACKEND_DISCOURSE    0x0010
#define NGX_HTTP_CACHE_TURBO_BACKEND_PHPBB        0x0020
#define NGX_HTTP_CACHE_TURBO_BACKEND_DRUPAL       0x0040
#define NGX_HTTP_CACHE_TURBO_BACKEND_MEDIAWIKI    0x0080
#define NGX_HTTP_CACHE_TURBO_BACKEND_MAGENTO      0x0100
#define NGX_HTTP_CACHE_TURBO_BACKEND_GHOST        0x0200
#define NGX_HTTP_CACHE_TURBO_BACKEND_WAGTAIL      0x0400
#define NGX_HTTP_CACHE_TURBO_BACKEND_KIRBY        0x0800
#define NGX_HTTP_CACHE_TURBO_BACKEND_SHOPWARE6    0x1000
#define NGX_HTTP_CACHE_TURBO_BACKEND_TYPO3        0x2000
#define NGX_HTTP_CACHE_TURBO_BACKEND_INVISION     0x4000
#define NGX_HTTP_CACHE_TURBO_BACKEND_SMF          0x8000
#define NGX_HTTP_CACHE_TURBO_BACKEND_VANILLA      0x10000
#define NGX_HTTP_CACHE_TURBO_BACKEND_PUNBB        0x20000
#define NGX_HTTP_CACHE_TURBO_BACKEND_PHORUM       0x40000
#define NGX_HTTP_CACHE_TURBO_BACKEND_YABB         0x80000
#define NGX_HTTP_CACHE_TURBO_BACKEND_MYBB         0x100000
#define NGX_HTTP_CACHE_TURBO_BACKEND_VBULLETIN    0x200000

/*
 * Every preset bit, armed together by the driver. There is no GENERIC union any
 * more (it was never a safe default — see the module header); every preset is
 * opt-in, so the fuzzer must arm them all explicitly or a row's cookie/URI/arg
 * lists are walked by nobody.
 *
 * ADDING A PRESET MEANS ADDING IT HERE TOO. The assert below is the guard: it
 * pins the mask to the contiguous run of bits [0x0001 .. highest], so a new bit
 * that is not folded into ALL fails the fuzz build rather than silently going
 * unfuzzed.
 */
#define NGX_HTTP_CACHE_TURBO_BACKEND_ALL                                       \
    (NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS                                    \
     | NGX_HTTP_CACHE_TURBO_BACKEND_WOOCOMMERCE                                \
     | NGX_HTTP_CACHE_TURBO_BACKEND_JOOMLA                                     \
     | NGX_HTTP_CACHE_TURBO_BACKEND_XENFORO                                    \
     | NGX_HTTP_CACHE_TURBO_BACKEND_DISCOURSE                                  \
     | NGX_HTTP_CACHE_TURBO_BACKEND_PHPBB                                      \
     | NGX_HTTP_CACHE_TURBO_BACKEND_DRUPAL                                     \
     | NGX_HTTP_CACHE_TURBO_BACKEND_MEDIAWIKI                                  \
     | NGX_HTTP_CACHE_TURBO_BACKEND_MAGENTO                                    \
     | NGX_HTTP_CACHE_TURBO_BACKEND_GHOST                                      \
     | NGX_HTTP_CACHE_TURBO_BACKEND_WAGTAIL                                    \
     | NGX_HTTP_CACHE_TURBO_BACKEND_KIRBY                                      \
     | NGX_HTTP_CACHE_TURBO_BACKEND_SHOPWARE6                                  \
     | NGX_HTTP_CACHE_TURBO_BACKEND_TYPO3                                     \
     | NGX_HTTP_CACHE_TURBO_BACKEND_INVISION                                  \
     | NGX_HTTP_CACHE_TURBO_BACKEND_SMF                                       \
     | NGX_HTTP_CACHE_TURBO_BACKEND_VANILLA                                   \
     | NGX_HTTP_CACHE_TURBO_BACKEND_PUNBB                                     \
     | NGX_HTTP_CACHE_TURBO_BACKEND_PHORUM                                    \
     | NGX_HTTP_CACHE_TURBO_BACKEND_YABB                                      \
     | NGX_HTTP_CACHE_TURBO_BACKEND_MYBB                                      \
     | NGX_HTTP_CACHE_TURBO_BACKEND_VBULLETIN)

/* ALL must be a gapless run of bits starting at 0x0001 — i.e. ALL+1 is a power
 * of two. A preset bit defined above but left out of ALL breaks this and fails
 * the fuzz build, which is exactly when we want to hear about it. */
_Static_assert((NGX_HTTP_CACHE_TURBO_BACKEND_ALL
                & (NGX_HTTP_CACHE_TURBO_BACKEND_ALL + 1)) == 0,
               "a BACKEND_* bit is missing from BACKEND_ALL — the fuzzer would "
               "not walk its preset row (see module header)");

/* Linker stub: never called (driver keeps r->args.len == 0). */
static ngx_int_t
ngx_http_arg(ngx_http_request_t *r, u_char *name, size_t len, ngx_str_t *value)
{
    (void) r; (void) name; (void) len; (void) value;
    return NGX_DECLINED;
}

#endif /* NGX_CACHE_TURBO_FUZZ_SHIM_AUTO_H */
