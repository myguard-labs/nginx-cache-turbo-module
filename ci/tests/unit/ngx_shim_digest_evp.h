/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Minimal nginx surface for UNIT-TESTING the REAL cache-turbo content-digest
 * functions (ngx_http_cache_turbo_digest_init/_update/_final/_digest),
 * sliced verbatim out of src/ngx_http_cache_turbo_blob.c by
 * extract_digest.sh (C0, PLAN-hitpath-2026-08-23.md).
 *
 * Unlike ngx_shim_digest.h (which fakes EVP_* entirely for the pre-existing
 * fail-closed test), this shim links the REAL OpenSSL EVP/SHA-256 via
 * <openssl/evp.h> -- the whole point of C0's test is that the cached
 * EVP_MD_fetch() path and the EVP_sha256() fallback path must produce
 * byte-identical output from the SAME production code, which only means
 * something against the real provider machinery, not a stub.
 *
 * The two worker-persistent globals and the TEST_FAULTS-gated fault flags
 * are declared here (not extracted) with the SAME guard conditions as
 * production, mirroring the existing ngx_shim_key_fold.h / test_digest_fail.c
 * convention of declaring the supporting globals in the shim/test file and
 * extracting only function BODIES.
 */

#ifndef NGX_CACHE_TURBO_UNIT_SHIM_DIGEST_EVP_H
#define NGX_CACHE_TURBO_UNIT_SHIM_DIGEST_EVP_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

/* Scalar types, faithful to nginx on LP64. */
typedef intptr_t        ngx_int_t;
typedef uintptr_t       ngx_uint_t;
typedef unsigned char   u_char;

#define NGX_OK      0
#define NGX_ERROR  -1

#define NGX_SSL     1

/* ---- ngx_http_cache_turbo_digest_t, verbatim from
 * ngx_http_cache_turbo_internal.h's NGX_SSL arm ------------------------- */

typedef struct {
    EVP_MD_CTX  *md;
    ngx_int_t    ok;
} ngx_http_cache_turbo_digest_t;

/* ---- worker-persistent globals, same guard as blob.c ------------------- */

EVP_MD_CTX  *ngx_http_cache_turbo_worker_md = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
EVP_MD  *ngx_http_cache_turbo_worker_sha256 = NULL;
#endif

/* ---- TEST_FAULTS-gated fault-injection flags, same guard as blob.c ----- */

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
ngx_uint_t  ngx_http_cache_turbo_test_digest_fail = 0;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
ngx_uint_t  ngx_http_cache_turbo_test_fetch_md_fail = 0;
#endif
#endif

#endif /* NGX_CACHE_TURBO_UNIT_SHIM_DIGEST_EVP_H */
