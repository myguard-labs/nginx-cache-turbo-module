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
 * FUZZ-EXTRACT markers; ci/fuzz/extract_auto_classify.sh slices it into
 * generated_auto_classify.inc at build time, so we fuzz the SHIPPED gate with
 * no copy drift. ngx_shim_auto.h supplies the tiny nginx surface.
 *
 * Input layout: bytes up to the first 0x00 are the URI; bytes between the first
 * and second 0x00 are one Cookie value; bytes after the second 0x00 are the
 * query string (a missing separator => that field is empty). The query string
 * is last so every pre-existing one-NUL corpus entry keeps its exact old
 * meaning. All three buffers are sized EXACTLY, with no trailing NUL, so ASAN
 * flags any read at or past the end. All presets are enabled to exercise every
 * cookie/URI/arg rule each call.
 *
 * Build (see ci/fuzz/build.sh):
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
    const uint8_t                   *sep, *ck_src, *sep2, *arg_src;
    size_t                           uri_len, ck_len, arg_len;
    u_char                          *uri_buf = NULL;
    u_char                          *ck_buf = NULL;
    u_char                          *arg_buf = NULL;

    /* URI = before the first NUL, cookie = up to the second, args = the rest. */
    sep = (const uint8_t *) memchr(data, 0x00, size);
    if (sep != NULL) {
        uri_len = (size_t) (sep - data);
        ck_src = sep + 1;
        ck_len = size - uri_len - 1;       /* drop the separator byte */

        sep2 = (const uint8_t *) memchr(ck_src, 0x00, ck_len);
        if (sep2 != NULL) {
            arg_src = sep2 + 1;
            arg_len = ck_len - (size_t) (sep2 - ck_src) - 1;
            ck_len = (size_t) (sep2 - ck_src);
        } else {
            arg_src = NULL;
            arg_len = 0;
        }
    } else {
        uri_len = size;
        ck_src = NULL;
        ck_len = 0;
        arg_src = NULL;
        arg_len = 0;
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
        memcpy(ck_buf, ck_src, ck_len);
    }
    if (arg_len) {
        arg_buf = (u_char *) malloc(arg_len);
        if (arg_buf == NULL) {
            free(uri_buf);
            free(ck_buf);
            return 0;
        }
        memcpy(arg_buf, arg_src, arg_len);
    }

    memset(&r, 0, sizeof(r));
    memset(&cookie, 0, sizeof(cookie));

    r.uri.data = uri_buf;
    r.uri.len = uri_len;
    /* The arg branch no longer calls core nginx's ngx_http_arg — the module
     * carries its own percent-decoding, ';'-splitting, all-occurrences scanner,
     * so those bytes are now OUR parser's problem and must be fuzzed. */
    r.args.data = arg_buf;
    r.args.len = arg_len;

    cookie.value.data = ck_buf;
    cookie.value.len = ck_len;
    cookie.next = NULL;
    r.headers_in.cookie = &cookie;

    /* Arm EVERY preset row. There is no GENERIC union any more — every preset is
     * opt-in — so the fuzzer must name them all or a row's cookie/URI/arg lists
     * are walked by nobody. The bug class here is an OOB read while walking those
     * lists, so every row must be walked. BACKEND_ALL is defined in
     * ngx_shim_auto.h next to the bits, with a static assert that catches a bit
     * left out of it. */
    clcf.backend_presets = NGX_HTTP_CACHE_TURBO_BACKEND_ALL;

    /* Subdirectory mount (cache_turbo_backend_prefix). clcf is NOT memset, so
     * this field must be assigned on every path or auto_skip dereferences stack
     * garbage. Alternate between unset and a fixed "/shop/" mount, keyed off a
     * byte of the input, so BOTH the rebased and the un-rebased comparison get
     * fuzzed: the rebase shortens the URI it hands to the prefix matcher, which
     * is exactly where a length underflow would show up. A real mount is always
     * well-formed ('/'-delimited, validated at config time), so fuzzing the
     * mount VALUE itself would test a state the config parser cannot produce. */
    static ngx_str_t  mount = { 6, (u_char *) "/shop/" };

    clcf.backend_prefix = (uri_len && (uri_buf[0] & 1)) ? &mount : NULL;

    /* Return is 0/1; the bug class is an OOB read inside, which ASAN catches. */
    (void) ngx_http_cache_turbo_auto_skip(&r, &clcf);

    /* Key cookies (tier 3) have their own raw-Cookie parser, and it is the one
     * whose output reaches the CACHE KEY — an OOB read here is worse than in
     * auto_skip, so drive it over the same arbitrary cookie bytes. The returned
     * ngx_str_t points INTO the cookie buffer, so touch it: an off-by-one in the
     * value bounds only shows up when the bytes are read. */
    {
        ngx_str_t   kcname, kcval;
        volatile u_char  sink = 0;
        ngx_uint_t  cursor = 0;
        size_t      j;

        /* Drive the iterator to exhaustion: every declared key cookie is a
         * separate raw-Cookie scan, so each one needs the fuzzed bytes. */
        while (ngx_http_cache_turbo_key_cookie(&r, clcf.backend_presets,
                                               &cursor, &kcname, &kcval))
        {
            for (j = 0; j < kcval.len; j++) {
                sink = (u_char) (sink ^ kcval.data[j]);
            }
            (void) sink;
        }
    }

    free(uri_buf);
    free(ck_buf);
    free(arg_buf);
    return 0;
}
