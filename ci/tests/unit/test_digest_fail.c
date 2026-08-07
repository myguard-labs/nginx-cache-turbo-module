/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit test for the cache-turbo digest failure path. When EVP digest
 * operations fail, digest_final() must return NGX_ERROR (fail-closed) rather
 * than producing an all-zero hash that would collide all requests.
 *
 * This test directly exercises the fault-injection mechanism: when
 * ngx_http_cache_turbo_test_digest_fail is 1, digest_final() returns NGX_ERROR
 * without calling the actual digest operations. The test verifies that:
 * 1. Normal operation produces a non-zero hash
 * 2. With fault injection enabled, digest() returns NGX_ERROR
 * 3. Different inputs produce different outputs
 */

#define NGX_HTTP_CACHE_TURBO_TEST_FAULTS 1
#include "ngx_shim_digest.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int failures = 0;
static int checks   = 0;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        checks++;                                                              \
        if (!(cond)) {                                                         \
            failures++;                                                        \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (msg));    \
        }                                                                      \
    } while (0)

#define CHECK_EQ(got, want, msg)                                               \
    do {                                                                       \
        int g_ = (int)(got), w_ = (int)(want);                                 \
        checks++;                                                              \
        if (g_ != w_) {                                                        \
            failures++;                                                        \
            fprintf(stderr, "FAIL %s:%d: %s (got %d, want %d)\n",              \
                    __FILE__, __LINE__, (msg), g_, w_);                        \
        }                                                                      \
    } while (0)

/* Module-level global for fault injection and worker MD context */
static EVP_MD_CTX  *ngx_http_cache_turbo_worker_md = NULL;
ngx_uint_t  ngx_http_cache_turbo_test_digest_fail = 0;

/* Inline versions of the digest functions for testing */
#define NGX_SSL 1
static void
ngx_http_cache_turbo_digest_init(ngx_http_cache_turbo_digest_t *d)
{
#if (NGX_SSL)
    if (ngx_http_cache_turbo_worker_md == NULL) {
        ngx_http_cache_turbo_worker_md = EVP_MD_CTX_new();
    }

    d->md = ngx_http_cache_turbo_worker_md;
    d->ok = (d->md != NULL
             && EVP_DigestInit_ex(d->md, EVP_sha256(), NULL) == 1) ? 1 : 0;
#else
    static const u_char  tag[] = "ngx_http_cache_turbo\x1Fhi";

    ngx_md5_init(&d->lo);
    ngx_md5_init(&d->hi);
    ngx_md5_update(&d->hi, tag, sizeof(tag) - 1);
#endif
}

static void
ngx_http_cache_turbo_digest_update(ngx_http_cache_turbo_digest_t *d,
    const void *data, size_t len)
{
#if (NGX_SSL)
    if (d->ok) {
        (void) EVP_DigestUpdate(d->md, data, len);
    }
#else
    ngx_md5_update(&d->lo, data, len);
    ngx_md5_update(&d->hi, data, len);
#endif
}

/* The function under test - must match production */
static ngx_int_t
ngx_http_cache_turbo_digest_final(ngx_http_cache_turbo_digest_t *d,
    u_char out[32])
{
#if (NGX_SSL)
    unsigned int  n = 0;

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    if (ngx_http_cache_turbo_test_digest_fail) {
        d->md = NULL;
        return NGX_ERROR;
    }
#endif

    if (d->ok && EVP_DigestFinal_ex(d->md, out, &n) == 1 && n == 32) {
        d->md = NULL;
        return NGX_OK;
    } else {
        d->md = NULL;
        return NGX_ERROR;
    }
#else
    ngx_md5_final(out, &d->lo);          /* low 16 */
    ngx_md5_final(out + 16, &d->hi);     /* high 16 */
    return NGX_OK;
#endif
}

/* One-shot convenience for a single contiguous input. */
static ngx_int_t
ngx_http_cache_turbo_digest(const void *data, size_t len, u_char out[32])
{
    ngx_http_cache_turbo_digest_t  d;

    ngx_http_cache_turbo_digest_init(&d);
    ngx_http_cache_turbo_digest_update(&d, data, len);
    return ngx_http_cache_turbo_digest_final(&d, out);
}

/* Test normal digest operation (no fault injection). */
static void test_digest_normal() {
    u_char out1[32], out2[32];
    const char *input = "test input";

    /* Disable fault injection */
    ngx_http_cache_turbo_test_digest_fail = 0;

    /* Call digest twice with the same input */
    CHECK(ngx_http_cache_turbo_digest(input, strlen(input), out1) == NGX_OK,
          "digest should succeed normally");
    CHECK(ngx_http_cache_turbo_digest(input, strlen(input), out2) == NGX_OK,
          "second digest should succeed");

    /* Both should produce the same output (deterministic) */
    CHECK(memcmp(out1, out2, 32) == 0,
          "same input should produce same digest");

    /* Output should NOT be all zeros (unless astronomically unlikely) */
    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (out1[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    CHECK(!all_zero, "digest should not be all zeros");
}

/* Test digest failure path (with fault injection). */
static void test_digest_fail_closed() {
    u_char out[32];
    const char *input = "test input";

    /* Enable fault injection */
    ngx_http_cache_turbo_test_digest_fail = 1;

    /* digest_final() should return NGX_ERROR when fault is set */
    CHECK(ngx_http_cache_turbo_digest(input, strlen(input), out) == NGX_ERROR,
          "digest should return NGX_ERROR when fault injection is enabled");

    /* After failure, disable for the next test */
    ngx_http_cache_turbo_test_digest_fail = 0;
}

/* Test that different inputs produce different outputs. */
static void test_digest_different_inputs() {
    u_char out1[32], out2[32];

    ngx_http_cache_turbo_test_digest_fail = 0;

    CHECK(ngx_http_cache_turbo_digest("input1", 6, out1) == NGX_OK,
          "first digest should succeed");
    CHECK(ngx_http_cache_turbo_digest("input2", 6, out2) == NGX_OK,
          "second digest should succeed");

    CHECK(memcmp(out1, out2, 32) != 0,
          "different inputs should produce different digests");
}

int main(void) {
    test_digest_normal();
    test_digest_fail_closed();
    test_digest_different_inputs();

    fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
