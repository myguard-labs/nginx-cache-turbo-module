/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * P3-2: pure-math mirror of ngx_http_cache_turbo_ae_class_accepted() (src/
 * ngx_http_cache_turbo_vary.c) -- the SERVE-SIDE GUARD that
 * cache_turbo_key_encoded_origin's safety argument rests on. The real
 * function needs a full ngx_http_request_t (r->headers_in.accept_encoding is
 * an ngx_table_elt_t inside the whole HTTP request machinery) -- same
 * reasoning test_vary_encoding_collapse.c's header comment already gives for
 * why classify_vary()'s Accept-Encoding arm is mirrored rather than linked
 * directly. This mirrors the tokeniser byte-for-byte (comma-split, semicolon
 * trim, leading/trailing whitespace strip, exact-length case-insensitive
 * name compare, q=0 exclusion) so a change to the REAL parsing logic that
 * silently drifts from this copy is the one thing this test cannot catch --
 * everything else (does a given Accept-Encoding header accept/refuse a given
 * stored class) it proves directly.
 *
 * WHY THIS TEST EXISTS AT ALL (not just the end-to-end runtime one):
 * ci/tools/areas/tune.py's test_key_encoded_origin_serve_guard_refuses_wrong_
 * ae_class proves the FEATURE end-to-end, but cannot reach the guard's own
 * refusal branch: the SAME request that resolves to a stored blob via the
 * auto-Vary variant key (ngx_http_cache_turbo_variant_hash(), which folds in
 * ae_class(r) from that SAME request's Accept-Encoding) can never disagree
 * with what ae_class_accepted() computes from that SAME header -- both derive
 * the class the same way, so a br-only client's variant hash routes it to
 * the br slot (a MISS, no stored blob at all) rather than ever reaching the
 * gzip slot's guard check. The guard is live production defense-in-depth for
 * the cross-node/stale-marker/hash-collision cases vary.c:196-201 documents
 * (a real prior bug: the variant hash ALONE let a zstd-only client read an
 * identity entry) -- exactly the scenario a single-node functional test
 * structurally cannot construct. This unit test is therefore the only place
 * that proves the guard's OWN logic is correct, independent of whether the
 * variant key ever lets a request reach it.
 *
 *   cc test_ae_class_guard.c -o t && ./t
 *   cc -DNGX_CTRL_ALWAYS_ACCEPT test_ae_class_guard.c -o t && ./t   (mutant: must fail)
 *
 * NGX_CTRL_ALWAYS_ACCEPT is the negative control for the mutation: it makes
 * every class "accepted" unconditionally (the exact fail-open bug the guard
 * exists to prevent) and must fail every REFUSE assertion below.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <strings.h>            /* strncasecmp (POSIX, not plain C99) */

typedef unsigned long ngx_uint_t;
typedef long           ngx_int_t;
typedef unsigned char  u_char;

#define NGX_HTTP_CACHE_TURBO_AE_CLASS_IDENTITY  0
#define NGX_HTTP_CACHE_TURBO_AE_CLASS_GZIP      1
#define NGX_HTTP_CACHE_TURBO_AE_CLASS_BR        2
#define NGX_HTTP_CACHE_TURBO_AE_CLASS_ZSTD      3

/* Mirrors ngx_http_cache_turbo_ae_q_ok() (src/ngx_http_cache_turbo_vary.c)
 * byte-for-byte: `p` at the token's first ';' (or == last if none), `last`
 * the token end. Returns 0 iff an explicit q=0(.0...) is present. */
static ngx_uint_t
mirror_ae_q_ok(const u_char *p, const u_char *last)
{
    while (p < last) {
        if (*p != ';') {
            p++;
            continue;
        }
        p++;
        while (p < last && (*p == ' ' || *p == '\t')) {
            p++;
        }
        if (p + 1 < last && (p[0] == 'q' || p[0] == 'Q') && p[1] == '=') {
            ngx_uint_t nonzero = 0;
            p += 2;
            while (p < last && *p != ';' && *p != ' ' && *p != '\t') {
                if (*p >= '1' && *p <= '9') {
                    nonzero = 1;
                }
                p++;
            }
            return nonzero ? 1 : 0;
        }
    }
    return 1;
}

/* Mirrors ngx_http_cache_turbo_ae_class_accepted() (src/ngx_http_cache_
 * turbo_vary.c): does `ae` (an Accept-Encoding header value, ae_data/ae_len;
 * ae_data == NULL mirrors a NULL/absent header) accept the coding named by
 * `class`? IDENTITY is always accepted. An unrecognised class refuses (0). */
static ngx_uint_t
mirror_ae_class_accepted(const u_char *ae_data, size_t ae_len,
    ngx_uint_t class)
{
    const u_char *p, *last, *end, *tok, *semi, *ce;
    size_t        clen;
    const char   *name;
    size_t        nlen;

    if (class == NGX_HTTP_CACHE_TURBO_AE_CLASS_IDENTITY) {
        return 1;
    }
#ifdef NGX_CTRL_ALWAYS_ACCEPT
    (void) ae_data; (void) ae_len; (void) class;
    return 1;
#endif
    if (class == NGX_HTTP_CACHE_TURBO_AE_CLASS_ZSTD) {
        name = "zstd"; nlen = 4;
    } else if (class == NGX_HTTP_CACHE_TURBO_AE_CLASS_BR) {
        name = "br"; nlen = 2;
    } else if (class == NGX_HTTP_CACHE_TURBO_AE_CLASS_GZIP) {
        name = "gzip"; nlen = 4;
    } else {
        return 0;
    }

    if (ae_data == NULL || ae_len == 0) {
        return 0;
    }

    p = ae_data;
    last = p + ae_len;

    while (p < last) {
        end = p;
        while (end < last && *end != ',') {
            end++;
        }

        semi = p;
        while (semi < end && *semi != ';') {
            semi++;
        }

        tok = p;
        while (tok < semi && (*tok == ' ' || *tok == '\t')) {
            tok++;
        }
        ce = semi;
        while (ce > tok && (ce[-1] == ' ' || ce[-1] == '\t')) {
            ce--;
        }
        clen = (size_t) (ce - tok);

        if (clen == nlen && strncasecmp((const char *) tok, name, nlen) == 0
            && mirror_ae_q_ok(semi, end))
        {
            return 1;
        }

        p = (end < last) ? end + 1 : end;
    }

    return 0;
}

static int checks   = 0;
static int failures = 0;

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        checks++;                                                            \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (msg));  \
        }                                                                    \
    } while (0)

#define AE(s) ((const u_char *) (s)), (sizeof(s) - 1)

int
main(void)
{
    /* IDENTITY is always accepted, absent/empty header included -- every
     * client accepts identity (RFC 9110 12.5.3). */
    CHECK(mirror_ae_class_accepted(NULL, 0, NGX_HTTP_CACHE_TURBO_AE_CLASS_IDENTITY),
          "IDENTITY must be accepted with no header at all");

    /* The exact-match cases each stored class needs. */
    CHECK(mirror_ae_class_accepted(AE("gzip"), NGX_HTTP_CACHE_TURBO_AE_CLASS_GZIP),
          "plain 'gzip' must accept the GZIP class");
    CHECK(mirror_ae_class_accepted(AE("br"), NGX_HTTP_CACHE_TURBO_AE_CLASS_BR),
          "plain 'br' must accept the BR class");
    CHECK(mirror_ae_class_accepted(AE("zstd"), NGX_HTTP_CACHE_TURBO_AE_CLASS_ZSTD),
          "plain 'zstd' must accept the ZSTD class");

    /* THE mandatory safety case: absent/no header, or a header that never
     * names the stored coding at all -- must REFUSE. This is exactly the
     * vary.c:196-201 failure mode (a client that cannot decode a coding
     * being served that coding anyway) if this ever returns 1. */
    CHECK(!mirror_ae_class_accepted(NULL, 0, NGX_HTTP_CACHE_TURBO_AE_CLASS_GZIP),
          "no Accept-Encoding header must REFUSE a gzip-class blob");
    CHECK(!mirror_ae_class_accepted(AE(""), NGX_HTTP_CACHE_TURBO_AE_CLASS_GZIP),
          "empty Accept-Encoding must REFUSE a gzip-class blob");
    CHECK(!mirror_ae_class_accepted(AE("br"), NGX_HTTP_CACHE_TURBO_AE_CLASS_GZIP),
          "'br' only must REFUSE a gzip-class blob");
    CHECK(!mirror_ae_class_accepted(AE("br, zstd"), NGX_HTTP_CACHE_TURBO_AE_CLASS_GZIP),
          "'br, zstd' must REFUSE a gzip-class blob (gzip absent entirely)");
    CHECK(!mirror_ae_class_accepted(AE("gzip"), NGX_HTTP_CACHE_TURBO_AE_CLASS_BR),
          "'gzip' only must REFUSE a br-class blob");
    CHECK(!mirror_ae_class_accepted(AE("gzip"), NGX_HTTP_CACHE_TURBO_AE_CLASS_ZSTD),
          "'gzip' only must REFUSE a zstd-class blob");

    /* q=0 explicitly refuses the coding even though the token is present --
     * a bare substring/membership check would wrongly accept this. */
    CHECK(!mirror_ae_class_accepted(AE("gzip;q=0"), NGX_HTTP_CACHE_TURBO_AE_CLASS_GZIP),
          "'gzip;q=0' must REFUSE the gzip class (explicit q=0)");
    CHECK(!mirror_ae_class_accepted(AE("gzip;q=0.0, br"), NGX_HTTP_CACHE_TURBO_AE_CLASS_GZIP),
          "'gzip;q=0.0, br' must REFUSE the gzip class");
    CHECK(mirror_ae_class_accepted(AE("gzip;q=0.5"), NGX_HTTP_CACHE_TURBO_AE_CLASS_GZIP),
          "'gzip;q=0.5' (nonzero q) must accept the gzip class");

    /* Token-boundary correctness: 'x-gzip' / 'Calibre' must not alias 'gzip'
     * / 'br' via a bare substring scan (same codex-follow-up guard
     * ae_class() itself already has to hold). */
    CHECK(!mirror_ae_class_accepted(AE("x-gzip"), NGX_HTTP_CACHE_TURBO_AE_CLASS_GZIP),
          "'x-gzip' must not alias the gzip class (token boundary)");
    CHECK(!mirror_ae_class_accepted(AE("Calibre"), NGX_HTTP_CACHE_TURBO_AE_CLASS_BR),
          "'Calibre' must not alias the br class (substring guard)");

    /* Case-insensitivity, whitespace tolerance, and finding gzip among
     * several codings (comma list). */
    CHECK(mirror_ae_class_accepted(AE("GZIP"), NGX_HTTP_CACHE_TURBO_AE_CLASS_GZIP),
          "'GZIP' (uppercase) must accept the gzip class");
    CHECK(mirror_ae_class_accepted(AE("br, gzip, zstd"), NGX_HTTP_CACHE_TURBO_AE_CLASS_GZIP),
          "gzip present among several codings must accept the gzip class");
    CHECK(mirror_ae_class_accepted(AE(" gzip ; q=0.8 , br"), NGX_HTTP_CACHE_TURBO_AE_CLASS_GZIP),
          "whitespace around the token/params must not defeat the match");

    /* An unrecognised packed class value (should never occur -- only
     * GZIP/BR/ZSTD are ever stamped -- but the function must fail closed,
     * not open, on anything else). */
    CHECK(!mirror_ae_class_accepted(AE("gzip, br, zstd"), 7 /* bogus class */),
          "an unrecognised class value must REFUSE, not accept, everything");

    printf("test_ae_class_guard: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
