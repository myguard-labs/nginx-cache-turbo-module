/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Minimal nginx surface for UNIT-TESTING the REAL
 * ngx_http_cache_turbo_variant_hash(), which is sliced verbatim out of
 * src/ngx_http_cache_turbo_module.c by extract_variant_hash.sh.
 *
 * This is deliberately NOT a mirror of the decision logic: the function under
 * test is production source, and the only thing shimmed is the nginx scalar
 * surface it needs to compile (types, ngx_sprintf, the digest wrapper). The
 * digest is the REAL EVP/OpenSSL one, so the bytes asserted on are the bytes
 * production computes.
 *
 * variant_hash dereferences its ngx_http_request_t *r ONLY inside the four
 * `if (bits & ...)` branches. The tests pass bits == 0 and r == NULL, so the
 * vary-axis classifiers are never called and need no stub with behaviour --
 * the four declarations below exist purely to satisfy the compiler and abort
 * loudly if a future edit makes the gen path reach one of them.
 */

#ifndef NGX_CACHE_TURBO_UNIT_SHIM_VARIANT_H
#define NGX_CACHE_TURBO_UNIT_SHIM_VARIANT_H

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

#define NGX_SSL          1
#define NGX_OK           0
#define NGX_ERROR       -1
#define NGX_INT_T_LEN    (sizeof("-9223372036854775808") - 1)

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

/* Opaque: the tests never build one, and variant_hash never dereferences it
 * when bits == 0. */
typedef struct ngx_http_request_s  ngx_http_request_t;

/* The vary-axis bits. Values are irrelevant here (every test passes bits == 0);
 * they exist so the sliced function compiles. */
#define NGX_HTTP_CACHE_TURBO_VARY_ENCODING  0x01
#define NGX_HTTP_CACHE_TURBO_VARY_DEVICE    0x02
#define NGX_HTTP_CACHE_TURBO_VARY_LANG      0x04
#define NGX_HTTP_CACHE_TURBO_VARY_ORIGIN    0x08

#define NGX_HTTP_CACHE_TURBO_LANG_CLASS_MAX  64

#define ngx_strlen(s)  strlen((const char *) (s))

/* nginx's ngx_sprintf returns a pointer PAST the last byte written. Only the
 * "%ui" conversion is reachable from variant_hash's gen fold. */
static u_char *
ngx_sprintf(u_char *buf, const char *fmt, ...)
{
    va_list      ap;
    ngx_uint_t   ui;
    int          n;

    if (strcmp(fmt, "%ui") != 0) {
        fprintf(stderr, "shim ngx_sprintf: unexpected format \"%s\"\n", fmt);
        abort();
    }

    va_start(ap, fmt);
    ui = va_arg(ap, ngx_uint_t);
    va_end(ap);

    n = sprintf((char *) buf, "%lu", (unsigned long) ui);
    if (n < 0) {
        abort();
    }

    return buf + n;
}

/* ---- the REAL digest, via EVP -------------------------------------------
 * Same shape as production's NGX_SSL branch: one reused context, reset by
 * digest_init(). Kept here rather than sliced because production's copy is
 * entangled with worker lifecycle (lazy create, exit_process free) that has no
 * meaning in a unit test -- but the HASH is genuine, which is what the
 * assertions depend on. */

typedef struct {
    EVP_MD_CTX  *md;
    ngx_int_t    ok;
} ngx_http_cache_turbo_digest_t;

static EVP_MD_CTX  *ngx_http_cache_turbo_worker_md;
static ngx_uint_t    ngx_test_digest_update_fail;
static ngx_uint_t    ngx_test_digest_final_fail;

static void
ngx_http_cache_turbo_digest_init(ngx_http_cache_turbo_digest_t *d)
{
    if (ngx_http_cache_turbo_worker_md == NULL) {
        ngx_http_cache_turbo_worker_md = EVP_MD_CTX_new();
        if (ngx_http_cache_turbo_worker_md == NULL) {
            abort();
        }
    }

    d->md = ngx_http_cache_turbo_worker_md;
    d->ok = EVP_DigestInit_ex(d->md, EVP_sha256(), NULL) == 1 ? 1 : 0;
}

static void
ngx_http_cache_turbo_digest_update(ngx_http_cache_turbo_digest_t *d,
    const void *data, size_t len)
{
    if (d->ok && (ngx_test_digest_update_fail
                  || EVP_DigestUpdate(d->md, data, len) != 1))
    {
        d->ok = 0;
    }
}

static ngx_int_t
ngx_http_cache_turbo_digest_final(ngx_http_cache_turbo_digest_t *d,
    u_char out[32])
{
    unsigned int  n = 0;

    if (!d->ok || ngx_test_digest_final_fail
        || EVP_DigestFinal_ex(d->md, out, &n) != 1 || n != 32)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static u_char *
ngx_hex_dump(u_char *dst, u_char *src, size_t len)
{
    static const u_char  hex[] = "0123456789abcdef";

    while (len--) {
        *dst++ = hex[*src >> 4];
        *dst++ = hex[*src++ & 0x0f];
    }
    return dst;
}

/* ---- vary-axis classifiers: unreachable when bits == 0 ------------------
 * Each aborts rather than returning a plausible value, so a test that
 * accidentally sets a vary bit fails loudly instead of silently asserting on
 * shimmed behaviour (rejected-test item 2). */

static ngx_str_t
ngx_http_cache_turbo_ae_class(ngx_http_request_t *r)
{
    (void) r; fprintf(stderr, "ae_class reached with bits == 0\n"); abort();
}

static ngx_str_t
ngx_http_cache_turbo_device_class(ngx_http_request_t *r)
{
    (void) r; fprintf(stderr, "device_class reached with bits == 0\n"); abort();
}

static size_t
ngx_http_cache_turbo_lang_class(ngx_http_request_t *r, u_char *buf)
{
    (void) r; (void) buf;
    fprintf(stderr, "lang_class reached with bits == 0\n"); abort();
}

static ngx_str_t
ngx_http_cache_turbo_req_header(ngx_http_request_t *r, const char *name,
    size_t len)
{
    (void) r; (void) name; (void) len;
    fprintf(stderr, "req_header reached with bits == 0\n"); abort();
}

#endif /* NGX_CACHE_TURBO_UNIT_SHIM_VARIANT_H */
