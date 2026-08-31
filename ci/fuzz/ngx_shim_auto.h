/*
 * Minimal nginx surface for fuzzing the cache-turbo auto-classify gate
 * (ngx_http_cache_turbo_auto_skip + ngx_http_cache_turbo_cookie_has).
 *
 * auto_skip reads attacker-controlled request bytes — the URI and, via
 * cookie_has, every Cookie header value — doing manual length-bounded scanning
 * (cookie_contains over a value of length ck->value.len, ngx_strncmp of a URI
 * prefix guarded by r->uri.len). A reintroduced unbounded scan or an off-by-one
 * in those bounds is a worker-crashing OOB read the runtime suite can't reach.
 * The fuzzer drives the SHIPPED code
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
#define NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO  1

/* String primitives the block uses, faithful to nginx's ngx_string.h. */
#define ngx_strncmp(s1, s2, n)  strncmp((char *) (s1), (char *) (s2), n)
#define ngx_strlen(s)           strlen((const char *) (s))

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
    ngx_pool_t *pool;
} ngx_http_request_t;

#ifndef NGX_MAX_SIZE_T_VALUE
#define NGX_MAX_SIZE_T_VALUE  ((size_t) -1)
#endif

#define ngx_memcpy(dst, src, n)  memcpy(dst, src, n)

/* NGX_CONF_UNSET_PTR is nginx's "directive not set" sentinel. The sliced code
 * tests pointer conf fields against it, so the shim must define it with the
 * same value the real ngx_conf.h uses. */
#define NGX_CONF_UNSET_PTR  ((void *) -1)

struct ngx_http_cache_turbo_loc_conf_s {
    ngx_uint_t  backend_presets;
    /* Mirrors src/ngx_http_cache_turbo_module.h. The preset URI tier rebases
     * r->uri onto this mount before comparing, so the sliced auto_skip reads
     * it and the field must exist here too — see the bit-mirroring note below,
     * which applies to conf FIELDS for the same reason. */
    ngx_str_t  *backend_prefix;
};

/*
 * Application preset bits — MUST mirror src/ngx_http_cache_turbo_module.h.
 * The fuzz target compiles the sliced registry WITHOUT the real header, so a
 * bit added there and not here fails the fuzz build with an
 * undeclared-identifier error (and only in CI, since
 * extract_auto_classify.sh does not compile). Adding a preset means editing
 * BOTH. The static assert below catches gaps in the mask.
 */
#define NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS    0x0001ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_WOOCOMMERCE  0x0002ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_JOOMLA       0x0004ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_XENFORO      0x0008ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_DISCOURSE    0x0010ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_PHPBB        0x0020ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_DRUPAL       0x0040ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_MEDIAWIKI    0x0080ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_MAGENTO      0x0100ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_GHOST        0x0200ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_WAGTAIL      0x0400ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_KIRBY        0x0800ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_SHOPWARE6    0x1000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_TYPO3        0x2000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_INVISION     0x4000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_SMF          0x8000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_VANILLA      0x10000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_PUNBB        0x20000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_PHORUM       0x40000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_YABB         0x80000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_MYBB         0x100000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_VBULLETIN    0x200000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_TEXTPATTERN  0x400000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_BLUDIT       0x800000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_SPIP         0x1000000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_BUGZILLA     0x2000000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_MANTISBT     0x4000000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_PLONE        0x8000000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_UMBRACO      0x10000000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_DOTCLEAR     0x20000000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_WIKIJS       0x40000000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_REDMINE      0x80000000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_FLARUM       0x100000000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_OPENCART     0x200000000ull

/*
 * Every preset bit, armed together by the driver. There is no GENERIC union any
 * more (it was never a safe default — see the module header); every preset is
 * opt-in, so the fuzzer must arm them all explicitly or a row's cookie/URI/arg
 * lists are walked by nobody.
 *
 * ADDING A PRESET MEANS ADDING IT HERE TOO. The assert below pins the mask to a
 * contiguous run of bits [0x0001 .. highest], so an omitted bit inside that run
 * fails the fuzz build. Review still has to update the highest bit explicitly;
 * C has no way to enumerate macro definitions.
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
     | NGX_HTTP_CACHE_TURBO_BACKEND_VBULLETIN                                 \
     | NGX_HTTP_CACHE_TURBO_BACKEND_TEXTPATTERN                               \
     | NGX_HTTP_CACHE_TURBO_BACKEND_BLUDIT                                    \
     | NGX_HTTP_CACHE_TURBO_BACKEND_SPIP                                      \
     | NGX_HTTP_CACHE_TURBO_BACKEND_BUGZILLA                                  \
     | NGX_HTTP_CACHE_TURBO_BACKEND_MANTISBT                                  \
     | NGX_HTTP_CACHE_TURBO_BACKEND_PLONE                                     \
     | NGX_HTTP_CACHE_TURBO_BACKEND_UMBRACO                                   \
     | NGX_HTTP_CACHE_TURBO_BACKEND_DOTCLEAR                                  \
     | NGX_HTTP_CACHE_TURBO_BACKEND_WIKIJS                                     \
     | NGX_HTTP_CACHE_TURBO_BACKEND_REDMINE                                    \
     | NGX_HTTP_CACHE_TURBO_BACKEND_FLARUM                                     \
     | NGX_HTTP_CACHE_TURBO_BACKEND_OPENCART)

/* ALL must be a gapless run of bits starting at 0x0001 — i.e. ALL+1 is a power
 * of two. An omitted bit inside the run breaks this and fails the fuzz build,
 * which is exactly when we want to hear about it.
 *
 * The bits are `ull`, which is what keeps `ALL + 1` meaningful as the run grows:
 * on a 32-bit literal type a full run would wrap to 0 and satisfy this assert
 * vacuously. See the WIDTH note in src/ngx_http_cache_turbo_module.h. */
_Static_assert((NGX_HTTP_CACHE_TURBO_BACKEND_ALL
                & (NGX_HTTP_CACHE_TURBO_BACKEND_ALL + 1)) == 0,
               "BACKEND_ALL has a bit gap — the fuzzer would not walk that "
               "preset row (see module header)");

/* Linker stub retained for compatibility with older extracted classifier code;
 * the current in-module query scanner does not call ngx_http_arg(). */
static ngx_int_t
ngx_http_arg(ngx_http_request_t *r, u_char *name, size_t len, ngx_str_t *value)
{
    (void) r; (void) name; (void) len; (void) value;
    return NGX_DECLINED;
}

#endif /* NGX_CACHE_TURBO_FUZZ_SHIM_AUTO_H */
