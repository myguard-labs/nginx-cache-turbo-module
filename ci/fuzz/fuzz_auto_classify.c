/*
 * libFuzzer harness for the cache-turbo auto-classify gate:
 *   ngx_http_cache_turbo_auto_skip()  +  ngx_http_cache_turbo_cookie_has()
 *
 * Why this target: auto_skip decides whether to cache a request by scanning
 * attacker-controlled bytes — the request URI (prefix match) and every Cookie
 * header value (manual substring match over a buffer bounded by ck->value.len,
 * NOT NUL-terminated). An off-by-one or a reintroduced unbounded scan would
 * over-read a worker. The runtime suite only feeds
 * well-formed cookies; this fuzzes arbitrary URI + cookie bytes.
 *
 * The real code lives in ../../src/ngx_http_cache_turbo_module.c between the
 * FUZZ-EXTRACT markers; ci/fuzz/extract_auto_classify.sh slices it into
 * generated_auto_classify.inc at build time, so we fuzz the SHIPPED gate with
 * no copy drift. ngx_shim_auto.h supplies the tiny nginx surface.
 *
 * Input layout: bytes up to the first 0x00 are the URI; bytes between the first
 * and second 0x00 are one Cookie value; bytes after the second 0x00 are the
 * query string. A missing first separator means no Cookie header; a first
 * separator followed immediately by EOF means a present-empty Cookie header.
 * The query string is last so every pre-existing one-NUL corpus entry keeps its
 * exact old meaning. All three buffers are sized EXACTLY, with no trailing NUL,
 * so ASAN flags any read at or past the end. All presets are enabled to exercise
 * every cookie/URI/arg rule each call.
 *
 * Build (see ci/fuzz/build.sh):
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *       fuzz_auto_classify.c -o fuzz_auto_classify
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ngx_shim_auto.h"

/* Verbatim auto-classify block sliced from the shipped module. */
#include "generated_auto_classify.inc"

#if defined(NGX_HTTP_CACHE_TURBO_AUTO_FIXTURES)
/* Deterministic fixtures against the extracted production classifier. */
static void
auto_fixture_request(ngx_http_request_t *r, ngx_pool_t *pool,
    ngx_table_elt_t *cookies)
{
    static u_char  root[] = "/";

    memset(r, 0, sizeof(*r));
    memset(pool, 0, sizeof(*pool));
    r->uri.data = root;
    r->uri.len = 1;
    r->headers_in.cookie = cookies;
    r->pool = pool;
}


static ngx_int_t
auto_fixture_classify(ngx_table_elt_t *cookies, ngx_uint_t preset)
{
    ngx_http_request_t               r;
    ngx_http_cache_turbo_loc_conf_t  clcf;
    ngx_pool_t                       pool;

    auto_fixture_request(&r, &pool, cookies);
    memset(&clcf, 0, sizeof(clcf));
    clcf.backend_presets = preset;

    return ngx_http_cache_turbo_auto_skip(&r, &clcf);
}


static size_t
auto_fixture_length_work(const char *const *subs)
{
    const char *const  *pp;
    size_t              work = 0;

    for (pp = subs; *pp; pp++) {
        work += strlen(*pp) + 1;
    }

    return work;
}


/* Filling the shim pool's allocation registry forces the arg parser's 65th-
 * pair extension allocation to fail. auto_skip must return private/bypass
 * rather than inspect the partial 64-span prefix. */
static int
auto_fixture_arg_allocation_failure(void)
{
    ngx_http_request_t               r;
    ngx_http_cache_turbo_loc_conf_t  clcf;
    ngx_pool_t                       pool;
    u_char                           args[65 * 2 - 1];
    ngx_uint_t                       i;

    memset(&r, 0, sizeof(r));
    memset(&clcf, 0, sizeof(clcf));
    memset(&pool, 0, sizeof(pool));

    for (i = 0; i < 65; i++) {
        args[i * 2] = 'z';
        if (i + 1 < 65) {
            args[i * 2 + 1] = '&';
        }
    }

    pool.nallocs = NGX_FUZZ_POOL_MAX_ALLOCS;
    r.args.data = args;
    r.args.len = sizeof(args);
    r.pool = &pool;
    clcf.backend_presets = NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS;

    if (ngx_http_cache_turbo_auto_skip(&r, &clcf) != 1) {
        fprintf(stderr, "allocation failure did not fail closed\n");
        return 1;
    }

    puts("auto-classify: overflow allocation failure fails closed");
    return 0;
}


/* Prove the Cookie-byte cap is inclusive, aggregate across header fields, and
 * fail-closed at cap+1 and on impossible sizing/null-backed shapes. The work
 * counter's exact boundary values prove the rejected tail is never scanned. */
static int
auto_fixture_cookie_boundaries(void)
{
    u_char           cookie[NGX_HTTP_CACHE_TURBO_COOKIE_BYTES_MAX + 1];
    ngx_table_elt_t  first, second;
    size_t           expected, half;

    memset(cookie, '~', sizeof(cookie));
    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));

    half = NGX_HTTP_CACHE_TURBO_COOKIE_BYTES_MAX / 2;
    first.value.data = cookie;
    first.value.len = half;
    first.next = &second;
    second.value.data = cookie + half;
    second.value.len = NGX_HTTP_CACHE_TURBO_COOKIE_BYTES_MAX - half;

    ngx_http_cache_turbo_cookie_work = 0;
    if (auto_fixture_classify(&first,
            NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS) != 0)
    {
        fprintf(stderr, "Cookie request at the inclusive cap bypassed\n");
        return 1;
    }
    expected = NGX_HTTP_CACHE_TURBO_COOKIE_BYTES_MAX
               + auto_fixture_length_work(ct_wp_cookies);
    if (ngx_http_cache_turbo_cookie_work != expected) {
        fprintf(stderr, "at-cap work mismatch: got %zu, expected %zu\n",
                ngx_http_cache_turbo_cookie_work, expected);
        return 1;
    }

    second.value.len++;
    ngx_http_cache_turbo_cookie_work = 0;
    if (auto_fixture_classify(&first,
            NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS) != 1)
    {
        fprintf(stderr, "Cookie request at cap+1 did not fail closed\n");
        return 1;
    }
    if (ngx_http_cache_turbo_cookie_work != half) {
        fprintf(stderr, "cap+1 inspected rejected tail: work=%zu, expected %zu\n",
                ngx_http_cache_turbo_cookie_work, half);
        return 1;
    }

    first.next = NULL;
    first.value.len = NGX_MAX_SIZE_T_VALUE;
    ngx_http_cache_turbo_cookie_work = 0;
    if (auto_fixture_classify(&first,
            NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS) != 1
        || ngx_http_cache_turbo_cookie_work != 0)
    {
        fprintf(stderr, "impossible Cookie size did not fail closed pre-scan\n");
        return 1;
    }

    first.value.data = NULL;
    first.value.len = 1;
    if (auto_fixture_classify(&first,
            NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS) != 1)
    {
        fprintf(stderr, "null-backed Cookie value did not fail closed\n");
        return 1;
    }

    printf("auto-classify: Cookie cap %d inclusive; cap+1/sizing fail closed\n",
           NGX_HTTP_CACHE_TURBO_COOKIE_BYTES_MAX);
    return 0;
}


/* Every populated registry family and every one of its current needles is
 * driven at the cap, at the final possible byte of the SECOND Cookie field.
 * The single-needle helper call prevents an earlier overlapping registry
 * literal from satisfying the assertion vacuously; auto_skip then proves the
 * owning preset row still maps that match to private/bypass. */
static int
auto_fixture_cookie_needles(void)
{
    const ngx_http_cache_turbo_preset_t  *ps;
    const char *const                    *pp;
    const char                           *single[2];
    ngx_http_cache_turbo_byteset_t        bs;
    ngx_http_request_t                    r;
    ngx_pool_t                            pool;
    ngx_table_elt_t                       first, second;
    u_char                                cookie[NGX_HTTP_CACHE_TURBO_COOKIE_BYTES_MAX];
    size_t                                bound, candidates, half, nlen;
    ngx_uint_t                            families = 0, needles = 0;

    half = NGX_HTTP_CACHE_TURBO_COOKIE_BYTES_MAX / 2;

    for (ps = ngx_http_cache_turbo_presets; ps->bit; ps++) {
        if (ps->cookies == NULL || ps->cookies[0] == NULL) {
            continue;
        }
        families++;

        for (pp = ps->cookies; *pp; pp++) {
            nlen = strlen(*pp);
            if (nlen == 0 || nlen > half) {
                fprintf(stderr, "invalid Cookie registry needle length: %s\n",
                        *pp);
                return 1;
            }
            needles++;

            memset(cookie, '~', sizeof(cookie));
            memcpy(cookie + sizeof(cookie) - nlen, *pp, nlen);
            memset(&first, 0, sizeof(first));
            memset(&second, 0, sizeof(second));
            first.value.data = cookie;
            first.value.len = half;
            first.next = &second;
            second.value.data = cookie + half;
            second.value.len = sizeof(cookie) - half;

            auto_fixture_request(&r, &pool, &first);
            ngx_http_cache_turbo_cookie_work = 0;
            if (ngx_http_cache_turbo_cookie_byteset_build(&r, &bs) != NGX_OK) {
                fprintf(stderr, "at-cap byteset rejected needle: %s\n", *pp);
                return 1;
            }

            single[0] = *pp;
            single[1] = NULL;
            if (!ngx_http_cache_turbo_cookie_has(&r, single, &bs)) {
                fprintf(stderr, "at-cap final-position needle unreachable: %s\n",
                        *pp);
                return 1;
            }

            candidates = 2 * (half - nlen + 1);
            bound = NGX_HTTP_CACHE_TURBO_COOKIE_BYTES_MAX + nlen + 1
                    + candidates * nlen;
            if (ngx_http_cache_turbo_cookie_work > bound) {
                fprintf(stderr, "needle work exceeded bound: %s (%zu > %zu)\n",
                        *pp, ngx_http_cache_turbo_cookie_work, bound);
                return 1;
            }

            if (auto_fixture_classify(&first, ps->bit) != 1) {
                fprintf(stderr, "preset did not bypass for Cookie needle: %s\n",
                        *pp);
                return 1;
            }
        }
    }

    if (families == 0 || needles == 0) {
        fprintf(stderr, "Cookie registry fixture reached no populated rows\n");
        return 1;
    }

    printf("auto-classify: %u Cookie families / %u needles reachable at cap\n",
           (unsigned) families, (unsigned) needles);
    return 0;
}


/* Exact operation oracle for the worst useful prefilter shape: the needle's
 * first byte occurs at every haystack position, its second byte never does,
 * so every candidate performs exactly two comparisons and no timing is used. */
static int
auto_fixture_cookie_work_oracle(void)
{
    const char       *needle = ct_wp_cookies[0];
    const char       *single[] = { NULL, NULL };
    ngx_http_cache_turbo_byteset_t  bs;
    ngx_http_request_t              r;
    ngx_pool_t                      pool;
    ngx_table_elt_t                 first, second;
    u_char                          cookie[NGX_HTTP_CACHE_TURBO_COOKIE_BYTES_MAX];
    size_t                          candidates, expected, half, nlen;

    nlen = strlen(needle);
    half = sizeof(cookie) / 2;
    memset(cookie, needle[0], sizeof(cookie));
    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    first.value.data = cookie;
    first.value.len = half;
    first.next = &second;
    second.value.data = cookie + half;
    second.value.len = sizeof(cookie) - half;
    single[0] = needle;

    auto_fixture_request(&r, &pool, &first);
    ngx_http_cache_turbo_cookie_work = 0;
    if (ngx_http_cache_turbo_cookie_byteset_build(&r, &bs) != NGX_OK
        || ngx_http_cache_turbo_cookie_has(&r, single, &bs) != 0)
    {
        fprintf(stderr, "work-oracle non-match classified as a match\n");
        return 1;
    }

    candidates = 2 * (half - nlen + 1);
    expected = sizeof(cookie) + nlen + 1 + candidates * 2;
    if (ngx_http_cache_turbo_cookie_work != expected) {
        fprintf(stderr, "Cookie work oracle mismatch: got %zu, expected %zu\n",
                ngx_http_cache_turbo_cookie_work, expected);
        return 1;
    }

    printf("auto-classify: Cookie work oracle exact at %zu operations\n",
           expected);
    return 0;
}


/* A needle split across Cookie fields must not be manufactured by the union
 * byteset. Each complete field is searched independently, as before. */
static int
auto_fixture_cookie_split_negative(void)
{
    const char       *needle = ct_wp_cookies[0];
    ngx_table_elt_t   first, second;
    size_t            split = strlen(needle) / 2;

    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    first.value.data = (u_char *) needle;
    first.value.len = split;
    first.next = &second;
    second.value.data = (u_char *) needle + split;
    second.value.len = strlen(needle) - split;

    if (auto_fixture_classify(&first,
            NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS) != 0)
    {
        fprintf(stderr, "split Cookie fields manufactured a substring match\n");
        return 1;
    }

    puts("auto-classify: split Cookie fields remain independent");
    return 0;
}


int
main(void)
{
    if (auto_fixture_arg_allocation_failure()
        || auto_fixture_cookie_boundaries()
        || auto_fixture_cookie_needles()
        || auto_fixture_cookie_work_oracle()
        || auto_fixture_cookie_split_negative())
    {
        return 1;
    }

    return 0;
}
#endif

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_http_request_t               r;
    ngx_http_cache_turbo_loc_conf_t  clcf;
    ngx_table_elt_t                  cookie;
    ngx_pool_t                       pool;
    const uint8_t                   *sep, *ck_src, *sep2, *arg_src;
    size_t                           uri_len, ck_len, arg_len;
    int                              has_cookie;
    u_char                          *uri_buf = NULL;
    u_char                          *ck_buf = NULL;
    u_char                          *arg_buf = NULL;

    /* URI = before the first NUL, cookie = up to the second, args = the rest. */
    sep = (const uint8_t *) memchr(data, 0x00, size);
    if (sep != NULL) {
        has_cookie = 1;
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
        has_cookie = 0;
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
    memset(&pool, 0, sizeof(pool));

    r.uri.data = uri_buf;
    r.uri.len = uri_len;
    /* The arg branch no longer calls core nginx's ngx_http_arg — the module
     * carries its own percent-decoding, ';'-splitting, all-occurrences scanner,
     * so those bytes are now OUR parser's problem and must be fuzzed. */
    r.args.data = arg_buf;
    r.args.len = arg_len;
    r.pool = &pool;

    cookie.value.data = ck_buf;
    cookie.value.len = ck_len;
    cookie.next = NULL;
    r.headers_in.cookie = has_cookie ? &cookie : NULL;

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
    ngx_fuzz_pool_reset(&pool);
    return 0;
}
