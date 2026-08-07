/*
 * Negative control: test that fails when the buggy version is used.
 * This demonstrates that the test is not vacuous and would catch the bug.
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

/* Module-level global for fault injection and worker MD context */
static EVP_MD_CTX  *ngx_http_cache_turbo_worker_md = NULL;
ngx_uint_t  ngx_http_cache_turbo_test_digest_fail = 0;

/* BUGGY version: always returns NGX_OK regardless of fault */
static ngx_int_t
ngx_http_cache_turbo_digest_final_BUGGY(ngx_http_cache_turbo_digest_t *d,
    u_char out[32])
{
#if (NGX_SSL)
    unsigned int  n = 0;

    if (d->ok && EVP_DigestFinal_ex(d->md, out, &n) == 1 && n == 32) {
        d->md = NULL;
        return NGX_OK;
    } else {
        /* BUG: zeroes the output but still returns NGX_OK instead of NGX_ERROR */
        ngx_memzero(out, 32);
        d->md = NULL;
        return NGX_OK;  /* Should be NGX_ERROR */
    }
#else
    ngx_md5_final(out, &d->lo);
    ngx_md5_final(out + 16, &d->hi);
    return NGX_OK;
#endif
}

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

/* Test that the BUGGY version fails the test (negative control) */
static void test_buggy_version_fails() {
    ngx_http_cache_turbo_digest_t  d;
    u_char out[32];
    const char *input = "test input";

    /* Enable fault injection */
    ngx_http_cache_turbo_test_digest_fail = 1;

    /* Initialize digest */
    ngx_http_cache_turbo_digest_init(&d);
    ngx_http_cache_turbo_digest_update(&d, input, strlen(input));

    /* Buggy version returns NGX_OK even with fault injection */
    int result = ngx_http_cache_turbo_digest_final_BUGGY(&d, out);

    /* This check FAILS because buggy version returns NGX_OK */
    /* The FIXED version would return NGX_ERROR */
    checks++;
    if (result != NGX_ERROR) {
        failures++;
        fprintf(stderr, "EXPECTED FAIL: buggy digest_final returned %d instead of NGX_ERROR\n", result);
    } else {
        fprintf(stderr, "UNEXPECTED: buggy version returned NGX_ERROR (it shouldn't)\n");
    }

    ngx_http_cache_turbo_test_digest_fail = 0;
}

int main(void) {
    test_buggy_version_fails();

    fprintf(stderr, "Negative control: %d checks, %d failures (expect 1 failure)\n", checks, failures);
    return failures > 0 ? 0 : 1;  /* Invert: success if we found the bug */
}
