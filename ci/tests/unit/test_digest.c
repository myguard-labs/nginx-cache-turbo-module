/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * C0 (PLAN-hitpath-2026-08-23.md): ngx_http_cache_turbo_digest_init() now
 * fetches the SHA2-256 EVP_MD ONCE per worker via EVP_MD_fetch() and reuses
 * it, instead of passing the legacy EVP_sha256() handle to EVP_DigestInit_ex()
 * on every call (which forces an implicit OpenSSL 3.x provider FETCH each
 * time). The digest IS the cache key -- including the L2 wire key shared
 * across nodes -- so the fetched-EVP_MD path MUST produce byte-identical
 * output to the pre-C0 EVP_sha256() path for the same input. That is the
 * entire risk this test exists to retire.
 *
 * This links the REAL production ngx_http_cache_turbo_digest_init/_update/
 * _final/_digest, sliced verbatim out of src/ngx_http_cache_turbo_blob.c by
 * extract_digest.sh -- not a mirror -- against the REAL OpenSSL EVP/SHA-256
 * (ngx_shim_digest_evp.h includes <openssl/evp.h> for real, unlike
 * ngx_shim_digest.h's fully-faked EVP_* used by the pre-existing
 * test_digest_fail.c).
 *
 * 1. test_known_vector(): asserts digest("abc") equals the NIST SHA-256 test
 *    vector, computed independently via `printf '%s' abc | sha256sum` (NOT
 *    with this code), so a wrong algorithm/wrong bytes cannot pass by
 *    tautology.
 * 2. test_empty_vector(): same idea for the empty-string SHA-256 vector.
 * 3. test_fixed_vector(): a third fixed vector, used again by the fallback
 *    tests below so the SAME expected bytes prove both code paths agree.
 * 4. test_fetched_matches_fallback(): the cached-EVP_MD_fetch() path (default)
 *    and the EVP_sha256()-fallback path (ngx_http_cache_turbo_test_fetch_
 *    md_fail=1, C0's negative-control (b) knob -- see blob.c) produce
 *    byte-identical output for the same input, AND the fallback path's
 *    output still equals the independently-computed vector from (3).
 *
 * Guarded on OPENSSL_VERSION_NUMBER >= 0x30000000L && !LIBRESSL_VERSION_NUMBER,
 * same condition as production's cached-fetch code: on an older/LibreSSL
 * build there is no fetch path to compare against, only the always-taken
 * EVP_sha256() call that test_known_vector()/test_empty_vector() already
 * cover.
 *
 * Cached-fetch negative controls (one source mutation, one runtime knob):
 *   (a) temporarily change extract_digest.sh's/blob.c's fetched algorithm
 *       name to "SHA2-224" or "SHA2-512" and rebuild+rerun this test -- the
 *       digest length check (`n == 32`) in digest_final() rejects both
 *       (28 and 64 bytes respectively), so ngx_http_cache_turbo_digest()
 *       returns NGX_ERROR instead of NGX_OK and test_known_vector() goes RED.
 *   (b) ngx_http_cache_turbo_test_fetch_md_fail=1 forces digest_init() to
 *       treat the cached fetch as if it returned NULL for that call, without
 *       needing to fake OpenSSL -- test_fetched_matches_fallback() exercises
 *       exactly this and asserts the output is still correct.
 */

#define NGX_HTTP_CACHE_TURBO_TEST_FAULTS 1
#include "ngx_shim_digest_evp.h"

#include "generated_digest.inc"

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

/* Parse a 64-hex-char sha256sum(1) digest into 32 raw bytes. */
static void
hex_to_bytes(const char *hex, u_char out[32])
{
    int  i;
    unsigned int  byte;

    for (i = 0; i < 32; i++) {
        sscanf(hex + i * 2, "%2x", &byte);
        out[i] = (u_char) byte;
    }
}

/* $ printf '%s' "abc" | sha256sum */
#define VEC_ABC_HEX \
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

/* $ printf '%s' "" | sha256sum */
#define VEC_EMPTY_HEX \
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

/* $ printf '%s' "cache-turbo C0 fetched-md fixed vector" | sha256sum */
#define VEC_FIXED_INPUT "cache-turbo C0 fetched-md fixed vector"
#define VEC_FIXED_HEX \
    "0ee6431e88397290ea3ff6883195a8697550128e267efa0584ad412b3dbc8a9c"

static void
test_known_vector(void)
{
    u_char  out[32], want[32];

    hex_to_bytes(VEC_ABC_HEX, want);

    CHECK(ngx_http_cache_turbo_digest("abc", 3, out) == NGX_OK,
          "digest(\"abc\") should succeed");
    CHECK(memcmp(out, want, 32) == 0,
          "digest(\"abc\") must equal the independently-computed SHA-256 vector");
}

static void
test_empty_vector(void)
{
    u_char  out[32], want[32];

    hex_to_bytes(VEC_EMPTY_HEX, want);

    CHECK(ngx_http_cache_turbo_digest("", 0, out) == NGX_OK,
          "digest(\"\") should succeed");
    CHECK(memcmp(out, want, 32) == 0,
          "digest(\"\") must equal the independently-computed SHA-256 vector");
}

static void
test_fixed_vector(void)
{
    u_char  out[32], want[32];

    hex_to_bytes(VEC_FIXED_HEX, want);

    CHECK(ngx_http_cache_turbo_digest(VEC_FIXED_INPUT,
                                       strlen(VEC_FIXED_INPUT), out) == NGX_OK,
          "digest(fixed input) should succeed");
    CHECK(memcmp(out, want, 32) == 0,
          "digest(fixed input) must equal the independently-computed SHA-256 vector");
}

static void
test_update_failure_is_sticky(void)
{
    ngx_http_cache_turbo_digest_t  d;
    u_char                         out[32], unpublished[32];

    memset(out, 0xA5, sizeof(out));
    memset(unpublished, 0xA5, sizeof(unpublished));
    ngx_http_cache_turbo_digest_init(&d);
    ngx_http_cache_turbo_test_digest_update_fail = 1;
    ngx_http_cache_turbo_digest_update(&d, "discarded", 9);
    ngx_http_cache_turbo_test_digest_update_fail = 0;

    CHECK(ngx_http_cache_turbo_digest_final(&d, out) == NGX_ERROR,
          "a failed EVP_DigestUpdate must stay failed through final");
    CHECK(memcmp(out, unpublished, sizeof(out)) == 0,
          "failed update/final must not publish any digest byte");
}

static void
test_final_failure_propagates(void)
{
    u_char  out[32], unpublished[32];

    memset(out, 0x5A, sizeof(out));
    memset(unpublished, 0x5A, sizeof(unpublished));
    ngx_http_cache_turbo_test_digest_fail = 1;
    CHECK(ngx_http_cache_turbo_digest("final-fail", 10, out) == NGX_ERROR,
          "a failed EVP_DigestFinal_ex must propagate through digest()");
    ngx_http_cache_turbo_test_digest_fail = 0;
    CHECK(memcmp(out, unpublished, sizeof(out)) == 0,
          "failed final must not publish any digest byte");
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
static void
test_fetched_matches_fallback(void)
{
    u_char  fetched_out[32], fallback_out[32], want[32];

    hex_to_bytes(VEC_FIXED_HEX, want);

    /* Default: the cached EVP_MD_fetch() path (worker_sha256 populated by
     * the earlier tests already, but digest_init() re-derives d->ok/md_type
     * fresh on every call regardless). */
    ngx_http_cache_turbo_test_fetch_md_fail = 0;
    CHECK(ngx_http_cache_turbo_digest(VEC_FIXED_INPUT,
                                       strlen(VEC_FIXED_INPUT),
                                       fetched_out) == NGX_OK,
          "fetched-path digest should succeed");

    /* C0 negative control (b): force this call's md_type to fall back to
     * EVP_sha256() as if the cached fetch had returned NULL. */
    ngx_http_cache_turbo_test_fetch_md_fail = 1;
    CHECK(ngx_http_cache_turbo_digest(VEC_FIXED_INPUT,
                                       strlen(VEC_FIXED_INPUT),
                                       fallback_out) == NGX_OK,
          "fallback-path digest should succeed");
    ngx_http_cache_turbo_test_fetch_md_fail = 0;

    CHECK(memcmp(fetched_out, fallback_out, 32) == 0,
          "fetched-EVP_MD path and EVP_sha256() fallback path must be byte-identical");
    CHECK(memcmp(fallback_out, want, 32) == 0,
          "fallback-path output must equal the independently-computed SHA-256 vector");
}
#endif

int
main(void)
{
    test_known_vector();
    test_empty_vector();
    test_fixed_vector();
    test_update_failure_is_sticky();
    test_final_failure_propagates();
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
    test_fetched_matches_fallback();
#else
    fprintf(stderr,
            "(skipped test_fetched_matches_fallback: no EVP_MD_fetch on this "
            "OpenSSL/LibreSSL build, only the always-taken EVP_sha256() path "
            "exists here)\n");
#endif

    fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
