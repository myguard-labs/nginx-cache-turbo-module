/*
 * Minimal nginx surface for fuzzing the cache-turbo L2 BLOB deserializer
 * (ngx_http_cache_turbo_blob_validate + the TLV header walk + the header
 * admissibility filter).
 *
 * Why a shim at all: the sliced functions are pure byte-pushers — they take a
 * const u_char* and a length and hand back offsets into it. The only nginx
 * surface they touch is the scalar typedefs, NGX_OK/NGX_ERROR, the two string
 * primitives header_skip() uses, and two fields of the location conf. Mirroring
 * that here (rather than dragging in ngx_core.h) is what lets the harness build
 * standalone with no configured nginx tree, exactly like the other four targets.
 *
 * ⚠ ngx_strncasecmp is the security-relevant one: header_skip() decides whether
 * a header is dropped by case-insensitive compare, so a shim that folded case
 * differently from nginx would make the fuzzer exercise a DIFFERENT skip set
 * than production. It is mirrored byte-for-byte from src/core/ngx_string.c
 * below (tolower on both sides, no locale).
 */

#ifndef NGX_CACHE_TURBO_FUZZ_SHIM_BLOB_H
#define NGX_CACHE_TURBO_FUZZ_SHIM_BLOB_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>   /* NGX_HTTP_CACHE_TURBO_TTL_MAX is a (time_t) cast */

#include "ngx_shim.h"   /* u_char/ngx_int_t/ngx_uint_t/ngx_str_t, NGX_OK/ERROR */

typedef ngx_int_t  ngx_flag_t;

#define ngx_strlen(s)  strlen((const char *) (s))

/* nginx ngx_config.h picks the compiler's inline keyword; C99 `inline` is the
 * faithful choice for the two accessor helpers the slice pulls in. */
#define ngx_inline  inline

/* Mirrors src/core/ngx_string.c ngx_strncasecmp(): ASCII tolower on both
 * operands, stop at n bytes or at the first NUL in either. The skip[] entries
 * are C literals so their NUL terminates; `name` is length-bounded by nlen,
 * which every caller checks for equality with the literal's length FIRST — so
 * this never reads past the caller's buffer. */
static ngx_int_t
ngx_strncasecmp(u_char *s1, u_char *s2, size_t n)
{
    ngx_uint_t  c1, c2;

    while (n) {
        c1 = (ngx_uint_t) *s1++;
        c2 = (ngx_uint_t) *s2++;

        c1 = (c1 >= 'A' && c1 <= 'Z') ? (c1 | 0x20) : c1;
        c2 = (c2 >= 'A' && c2 <= 'Z') ? (c2 | 0x20) : c2;

        if (c1 == c2) {
            if (c1) {
                n--;
                continue;
            }
            return 0;
        }

        return (ngx_int_t) c1 - (ngx_int_t) c2;
    }

    return 0;
}

/*
 * Only the two fields header_skip() reads. Deliberately NOT the real
 * ngx_http_cache_turbo_loc_conf_t: the sliced code is compiled against THIS
 * declaration, so an added field it starts reading is a compile error here
 * rather than a silent read of uninitialised fuzz state.
 */
typedef struct {
    ngx_flag_t  surrogate_key;
    ngx_str_t   require_header;
} ngx_http_cache_turbo_loc_conf_t;

#endif /* NGX_CACHE_TURBO_FUZZ_SHIM_BLOB_H */
