/*
 * libFuzzer harness for the cache-turbo auto-classify gate:
 *   ngx_http_cache_turbo_auto_skip()  +  ngx_http_cache_turbo_cookie_has()
 *
 * Why this target: auto_skip decides whether to cache a request by scanning
 * attacker-controlled bytes — the request URI (prefix match) and every Cookie
 * header value (substring match via ngx_strnstr over a buffer bounded by
 * ck->value.len, NOT NUL-terminated). An off-by-one or a reintroduced
 * NUL-bounded scan would over-read a worker. The runtime suite only feeds
 * well-formed cookies; this fuzzes arbitrary URI + cookie bytes.
 *
 * The real code lives in ../src/ngx_http_cache_turbo_module.c between the
 * FUZZ-EXTRACT markers; fuzz/extract_auto_classify.sh slices it into
 * generated_auto_classify.inc at build time, so we fuzz the SHIPPED gate with
 * no copy drift. ngx_shim_auto.h supplies the tiny nginx surface.
 *
 * Input layout: bytes up to the first 0x00 are the URI; bytes after it are one
 * Cookie value (no NUL byte => empty cookie). Both buffers are sized EXACTLY,
 * with no trailing NUL, so ASAN flags any read at or past the end. All presets
 * are enabled (GENERIC) to exercise every cookie/URI rule each call.
 *
 * Build (see fuzz/build.sh):
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *       fuzz_auto_classify.c -o fuzz_auto_classify
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ngx_shim_auto.h"

/* Verbatim auto-classify block sliced from the shipped module. */
#include "generated_auto_classify.inc"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_http_request_t               r;
    ngx_http_cache_turbo_loc_conf_t  clcf;
    ngx_table_elt_t                  cookie;
    const uint8_t                   *sep;
    size_t                           uri_len, ck_len;
    u_char                          *uri_buf = NULL;
    u_char                          *ck_buf = NULL;

    /* Split input into URI (before the first NUL) and one cookie value (after). */
    sep = (const uint8_t *) memchr(data, 0x00, size);
    if (sep != NULL) {
        uri_len = (size_t) (sep - data);
        ck_len = size - uri_len - 1;       /* drop the separator byte */
    } else {
        uri_len = size;
        ck_len = 0;
    }

    /* Exact-sized, non-NUL-terminated buffers: an over-read trips ASAN. */
    if (uri_len) {
        uri_buf = (u_char *) malloc(uri_len);
        if (uri_buf == NULL) {
            return 0;
        }
        memcpy(uri_buf, data, uri_len);
    }
    if (ck_len) {
        ck_buf = (u_char *) malloc(ck_len);
        if (ck_buf == NULL) {
            free(uri_buf);
            return 0;
        }
        memcpy(ck_buf, sep + 1, ck_len);
    }

    memset(&r, 0, sizeof(r));
    memset(&cookie, 0, sizeof(cookie));

    r.uri.data = uri_buf;
    r.uri.len = uri_len;
    r.args.len = 0;                        /* skip the ngx_http_arg branch */
    r.args.data = NULL;

    cookie.value.data = ck_buf;
    cookie.value.len = ck_len;
    cookie.next = NULL;
    r.headers_in.cookie = &cookie;

    /* Arm EVERY preset row, not just GENERIC — xenforo is deliberately outside
     * the GENERIC union, so arming GENERIC alone would leave its cookie/URI
     * lists unfuzzed. The bug class here is an OOB read while walking those
     * lists, so every row must be walked. */
    clcf.backend_presets = NGX_HTTP_CACHE_TURBO_BACKEND_GENERIC
                           | NGX_HTTP_CACHE_TURBO_BACKEND_XENFORO;

    /* Return is 0/1; the bug class is an OOB read inside, which ASAN catches. */
    (void) ngx_http_cache_turbo_auto_skip(&r, &clcf);

    free(uri_buf);
    free(ck_buf);
    return 0;
}
