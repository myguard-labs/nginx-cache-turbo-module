/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * P1-1: pure-math mirror of the Accept-Encoding arm inside
 * ngx_http_cache_turbo_classify_vary_classify_token() (src/ngx_http_cache_
 * turbo_vary.c ~847-870). That function needs a full ngx_http_request_t +
 * out-params we do not want to drag in here (same reasoning as
 * test_vary_gen.c's header comment), so this mirrors its OBSERVABLE decision
 * only: given a Vary: Accept-Encoding token and response_encoded()'s
 * boolean result, does the VARY_ENCODING bit get set?
 *
 * This is the one case a runtime Test::Nginx HIT/MISS assertion structurally
 * cannot observe for response_encoded()==1: a genuinely pre-encoded response
 * is refused by the capture gate's own unconditional `!response_encoded(r)`
 * leg BEFORE classify_vary()'s bit can ever influence storage or lookup (see
 * ngx_http_cache_turbo_filters.c's header_filter_capture and the module's own
 * README note: "an origin that pre-compresses its own response is refused
 * outright ... so encoding-keyed caching is never actually needed"). So the
 * end-to-end negative control in ci/tools/areas/tune.py
 * (test_auto_vary_encoding_precompressed_still_never_cached) can only prove
 * "never a HIT", not "the bit is set" -- this unit test proves the bit
 * itself, directly, for both response_encoded() states.
 *
 *   cc -DNGX_CTRL_NOCOLLAPSE test_vary_encoding_collapse.c -o t && ./t
 *
 * NGX_CTRL_NOCOLLAPSE reverts to the pre-P1-1 behaviour (bit always set,
 * ignoring response_encoded()) and is the negative control for the mutation:
 * it must fail the "unencoded body does not set the bit" assertion.
 */

#include <stdio.h>
#include <string.h>

typedef unsigned long ngx_uint_t;
typedef long           ngx_int_t;
typedef unsigned char  u_char;

#define NGX_HTTP_CACHE_TURBO_VARY_ENCODING 0x1

/* Mirrors ngx_http_cache_turbo_classify_vary_classify_token()'s
 * Accept-Encoding arm exactly (src/ngx_http_cache_turbo_vary.c): the token
 * is already known to be "Accept-Encoding" (that string match is untouched
 * by P1-1 and not re-tested here -- see classify_vary_classify_token's own
 * tl/ngx_strncasecmp checks), so this starts from "the axis IS
 * Accept-Encoding" and mirrors only the conditional OR this change added. */
static void
mirror_classify_encoding(ngx_int_t *bits, ngx_uint_t response_encoded)
{
#ifdef NGX_CTRL_NOCOLLAPSE
    (void) response_encoded;
    *bits |= NGX_HTTP_CACHE_TURBO_VARY_ENCODING;
#else
    if (response_encoded) {
        *bits |= NGX_HTTP_CACHE_TURBO_VARY_ENCODING;
    }
#endif
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

int
main(void)
{
    ngx_int_t  bits;

    /* response_encoded() == 0 (the identity/no-Content-Encoding case, which
     * is EVERY response the capture gate can ever store): the axis is inert
     * and must NOT set the bit -- this is the P1-1 collapse itself. */
    bits = 0;
    mirror_classify_encoding(&bits, 0);
    CHECK((bits & NGX_HTTP_CACHE_TURBO_VARY_ENCODING) == 0,
          "unencoded response must NOT set VARY_ENCODING (collapse)");

    /* response_encoded() == 1 (a genuinely pre-encoded body -- unreachable
     * through the capture gate today, but classify_vary() itself must still
     * be correct for it, both as documentation of intent and in case a
     * future caller ever asks it before the capture-gate refusal runs): the
     * bit must still be set, unchanged from before P1-1. */
    bits = 0;
    mirror_classify_encoding(&bits, 1);
    CHECK((bits & NGX_HTTP_CACHE_TURBO_VARY_ENCODING) != 0,
          "pre-encoded response must still set VARY_ENCODING");

    /* Bit composes correctly alongside another already-set axis bit in
     * either state, i.e. the collapse touches only its own bit. */
    bits = 0x2;                                     /* pretend VARY_DEVICE */
    mirror_classify_encoding(&bits, 0);
    CHECK(bits == 0x2,
          "collapse must not disturb an unrelated already-set axis bit");

    bits = 0x2;
    mirror_classify_encoding(&bits, 1);
    CHECK(bits == (0x2 | NGX_HTTP_CACHE_TURBO_VARY_ENCODING),
          "encoding bit must OR in cleanly alongside another axis bit");

    printf("test_vary_encoding_collapse: %d checks, %d failures\n",
           checks, failures);
    return failures ? 1 : 0;
}
