/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * S231-PERF-KEYFOLD: the old ngx_http_cache_turbo_key_fold_cookie() reallocated
 * and copied the WHOLE growing key on every folded cookie (ngx_pnalloc sized
 * ctx->cache_key.len + entry, then ngx_cpymem the entire existing prefix back
 * in) -- O(n^2) in the number of folded key cookies. It was replaced by a
 * two-pass fold: queue every matched cookie (ngx_http_cache_turbo_key_cookie_
 * queue, no copy), size all of them (ngx_http_cache_turbo_key_fold_size),
 * allocate ONE buffer for the base key plus every entry, then append
 * (ngx_http_cache_turbo_key_fold_append) in order
 * (ngx_http_cache_turbo_key_fold_all).
 *
 * Because ctx->cache_key is the input to the cache-key digest (SEC-2), a
 * behaviour change here is not just a perf regression -- it silently
 * invalidates every stored entry (same request, different key, guaranteed
 * miss) or worse, collides two different requests onto the same key. This
 * test asserts BYTE-IDENTITY against the pre-change byte-framing contract
 * (0x1f tag + 4B name-len + 4B val-len + name + value, little-endian, using
 * NGX_HTTP_CACHE_TURBO_KEY_COOKIE_OVERSIZE=0xffffffffu for an over-256-byte
 * value), computed independently in this test and fed through the REAL
 * EVP/SHA-256 digest -- so a fold_all that reorders, mis-sizes, or drops a
 * byte relative to the OLD per-cookie fold produces a different digest and
 * this test goes red.
 *
 * Functions under test are sliced VERBATIM out of src/ by
 * extract_key_fold.sh, not mirrored, so drift between this test and shipped
 * code cannot pass unnoticed.
 */

#include "ngx_shim_key_fold.h"

#include "generated_key_fold.inc"

#include <stdio.h>
#include <string.h>

static int failures = 0;
static int checks   = 0;

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        checks++;                                                            \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (msg));  \
        }                                                                    \
    } while (0)

/* Independently compute the expected key bytes for a base key plus a list of
 * (name, value) pairs, using the SAME byte-framing contract the production
 * fold uses (0x1f tag, 4B little-endian name-len, 4B little-endian val-len,
 * name, value; over-256-byte values collapse to vfield ==
 * NGX_HTTP_CACHE_TURBO_KEY_COOKIE_OVERSIZE with zero value bytes). Written
 * independently of ngx_http_cache_turbo_key_fold_append so it is not just
 * calling the function under test on itself. */
static size_t
expected_key(const ngx_str_t *base, const ngx_str_t *names,
    const ngx_str_t *vals, size_t n, u_char *out)
{
    size_t    i, vlen;
    uint32_t  vfield;
    u_char   *p = out;

    memcpy(p, base->data, base->len);
    p += base->len;

    for (i = 0; i < n; i++) {
        if (vals[i].len > NGX_HTTP_CACHE_TURBO_KEY_COOKIE_MAX) {
            vlen = 0;
            vfield = NGX_HTTP_CACHE_TURBO_KEY_COOKIE_OVERSIZE;
        } else {
            vlen = vals[i].len;
            vfield = (uint32_t) vals[i].len;
        }

        *p++ = 0x1f;
        p[0] = (u_char) (names[i].len & 0xff);
        p[1] = (u_char) ((names[i].len >> 8) & 0xff);
        p[2] = (u_char) ((names[i].len >> 16) & 0xff);
        p[3] = (u_char) ((names[i].len >> 24) & 0xff);
        p += 4;
        p[0] = (u_char) (vfield & 0xff);
        p[1] = (u_char) ((vfield >> 8) & 0xff);
        p[2] = (u_char) ((vfield >> 16) & 0xff);
        p[3] = (u_char) ((vfield >> 24) & 0xff);
        p += 4;
        memcpy(p, names[i].data, names[i].len);
        p += names[i].len;
        if (vlen) {
            memcpy(p, vals[i].data, vlen);
            p += vlen;
        }
    }

    return (size_t) (p - out);
}

static ngx_str_t
S(const char *s)
{
    ngx_str_t  r;
    r.data = (u_char *) s;
    r.len = strlen(s);
    return r;
}

/* Drive ctx->cache_key through the REAL queue + fold_all path for `n` (name,
 * value) pairs on top of `base`, and return the resulting digest. */
static void
run_fold_ex(ngx_str_t *base, ngx_str_t *names, ngx_str_t *vals, size_t n,
    u_char digest_out[32], ngx_str_t *key_out)
{
    ngx_http_cache_turbo_ctx_t  ctx;
    ngx_array_t                 slots;
    size_t                      i;

    memset(&ctx, 0, sizeof(ctx));
    ctx.cache_key = *base;

    CHECK(ngx_array_init(&slots, ngx_shim_request.pool, 4,
                          sizeof(ngx_http_cache_turbo_key_cookie_slot_t))
              == NGX_OK,
          "array_init should succeed");

    for (i = 0; i < n; i++) {
        CHECK(ngx_http_cache_turbo_key_cookie_queue(&slots, &names[i],
                                                     &vals[i]) == NGX_OK,
              "queue should succeed");
    }

    CHECK(ngx_http_cache_turbo_key_fold_all(&ngx_shim_request, &ctx, &slots)
              == NGX_OK,
          "fold_all should succeed");

    CHECK(ngx_http_cache_turbo_digest(ctx.cache_key.data, ctx.cache_key.len,
                                       digest_out) == NGX_OK,
          "digest should succeed");

    if (key_out) {
        *key_out = ctx.cache_key;
    }
}

static void
run_fold(ngx_str_t *base, ngx_str_t *names, ngx_str_t *vals, size_t n,
    u_char digest_out[32])
{
    run_fold_ex(base, names, vals, n, digest_out, NULL);
}

/* --- case 1: multi-part key, all in-range values ------------------------- */
static void
test_multi_part_key(void)
{
    ngx_str_t  base = S("example.test/path?q=1");
    ngx_str_t  names[3] = { S("X-Magento-Vary"), S("theme"), S("lang") };
    ngx_str_t  vals[3]  = { S("abc123"), S("dark"), S("en") };
    u_char     got[32], want[32];
    u_char     expect_buf[1024];
    size_t     expect_len;

    run_fold(&base, names, vals, 3, got);

    expect_len = expected_key(&base, names, vals, 3, expect_buf);
    CHECK(ngx_http_cache_turbo_digest(expect_buf, expect_len, want) == NGX_OK,
          "expected digest should succeed");

    CHECK(memcmp(got, want, 32) == 0,
          "multi-part key digest must match the pinned byte-framing");
}

/* --- case 2: an EMPTY-value part (present cookie, zero-length value) ----- */
static void
test_empty_part(void)
{
    ngx_str_t  base = S("example.test/path");
    ngx_str_t  names[2] = { S("sw-cache-hash"), S("empty-cookie") };
    ngx_str_t  vals[2]  = { S("deadbeef"), S("") };
    u_char     got[32], want[32];
    u_char     expect_buf[1024];
    size_t     expect_len;

    run_fold(&base, names, vals, 2, got);

    expect_len = expected_key(&base, names, vals, 2, expect_buf);
    CHECK(ngx_http_cache_turbo_digest(expect_buf, expect_len, want) == NGX_OK,
          "expected digest should succeed");

    CHECK(memcmp(got, want, 32) == 0,
          "empty-part key digest must match the pinned byte-framing");

    /* And an empty value must be distinguishable from an absent cookie
     * (no fold at all) -- the whole point of the length-prefixed framing. */
    {
        u_char  no_fold[32];
        CHECK(ngx_http_cache_turbo_digest(base.data, base.len, no_fold)
                  == NGX_OK,
              "no-fold digest should succeed");
        CHECK(memcmp(got, no_fold, 32) != 0,
              "an empty-value cookie must NOT collide with no cookie at all");
    }
}

/* --- case 3: oversize value collapses to the OVERSIZE bucket, dropping the
 * value bytes but keeping the name -- pin this too, since it is a distinct
 * length field (0xffffffff) from every real length. */
static void
test_oversize_part(void)
{
    ngx_str_t   base = S("example.test/");
    ngx_str_t   name = S("bb_lastvisit");
    static char big[NGX_HTTP_CACHE_TURBO_KEY_COOKIE_MAX + 1 + 1];
    ngx_str_t   val;
    u_char      got[32], want[32];
    u_char      expect_buf[1024];
    size_t      expect_len;
    size_t      i;

    for (i = 0; i < sizeof(big) - 1; i++) {
        big[i] = 'a';
    }
    big[sizeof(big) - 1] = '\0';
    val = S(big);
    CHECK(val.len == NGX_HTTP_CACHE_TURBO_KEY_COOKIE_MAX + 1,
          "fixture value must exceed the oversize threshold by exactly one byte");

    run_fold(&base, &name, &val, 1, got);

    expect_len = expected_key(&base, &name, &val, 1, expect_buf);
    CHECK(ngx_http_cache_turbo_digest(expect_buf, expect_len, want) == NGX_OK,
          "expected digest should succeed");

    CHECK(memcmp(got, want, 32) == 0,
          "oversize-part key digest must match the pinned OVERSIZE framing");

    CHECK(ngx_shim_last_log[0] != '\0',
          "an oversize value must be logged");
}

/* --- case 4: fold order matters -- two cookies folded in reverse order must
 * NOT collide (the framing is order-dependent, matching config/iteration
 * order, which the old per-cookie append preserved and fold_all must too). */
static void
test_order_matters(void)
{
    ngx_str_t  base = S("example.test/");
    ngx_str_t  names[2]   = { S("a"), S("b") };
    ngx_str_t  vals[2]    = { S("1"), S("2") };
    ngx_str_t  rev_names[2] = { S("b"), S("a") };
    ngx_str_t  rev_vals[2]  = { S("2"), S("1") };
    u_char     fwd[32], rev[32];

    run_fold(&base, names, vals, 2, fwd);
    run_fold(&base, rev_names, rev_vals, 2, rev);

    CHECK(memcmp(fwd, rev, 32) != 0,
          "folding cookies in a different order must produce a different key");
}

/* --- case 5: zero queued cookies leaves the key untouched (base key alone),
 * matching the "absent cookie -> anonymous entry" contract. */
static void
test_zero_cookies_unchanged(void)
{
    ngx_http_cache_turbo_ctx_t  ctx;
    ngx_array_t                 slots;
    ngx_str_t                   base = S("example.test/anon");
    u_char                       before_digest[32], after_digest[32];

    memset(&ctx, 0, sizeof(ctx));
    ctx.cache_key = base;

    CHECK(ngx_http_cache_turbo_digest(base.data, base.len, before_digest)
              == NGX_OK, "base digest should succeed");

    CHECK(ngx_array_init(&slots, ngx_shim_request.pool, 4,
                          sizeof(ngx_http_cache_turbo_key_cookie_slot_t))
              == NGX_OK,
          "array_init should succeed");

    CHECK(ngx_http_cache_turbo_key_fold_all(&ngx_shim_request, &ctx, &slots)
              == NGX_OK,
          "fold_all with zero slots should succeed");

    CHECK(ctx.cache_key.len == base.len && ctx.cache_key.data == base.data,
          "fold_all with zero slots must leave cache_key untouched");

    CHECK(ngx_http_cache_turbo_digest(ctx.cache_key.data, ctx.cache_key.len,
                                       after_digest) == NGX_OK,
          "post-fold digest should succeed");

    CHECK(memcmp(before_digest, after_digest, 32) == 0,
          "zero folded cookies must not change the digest");
}

int
main(void)
{
    test_multi_part_key();
    test_empty_part();
    test_oversize_part();
    test_order_matters();
    test_zero_cookies_unchanged();

    fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
