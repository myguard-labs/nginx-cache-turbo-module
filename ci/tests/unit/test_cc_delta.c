/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * CACHE-CONTROL-DELTA-GRAMMAR: token iteration, quoted-value boundaries, exact
 * delta grammar and overflow boundaries against the production helpers sliced
 * by extract_cc_delta.sh.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

typedef unsigned char  u_char;
typedef uintptr_t      ngx_uint_t;
typedef intptr_t       ngx_int_t;

#define NGX_MAX_INT_T_VALUE  ((intptr_t) (UINTPTR_MAX >> 1))

static u_char *
ngx_strlchr(u_char *p, u_char *last, u_char c)
{
    while (p < last) {
        if (*p == c) {
            return p;
        }
        p++;
    }
    return NULL;
}

static ngx_int_t
ngx_strncasecmp(u_char *s1, u_char *s2, size_t n)
{
    u_char  c1, c2;

    while (n != 0) {
        c1 = *s1++;
        c2 = *s2++;
        if (c1 >= 'A' && c1 <= 'Z') {
            c1 = (u_char) (c1 | 0x20);
        }
        if (c2 >= 'A' && c2 <= 'Z') {
            c2 = (u_char) (c2 | 0x20);
        }
        if (c1 != c2) {
            return c1 - c2;
        }
        n--;
    }
    return 0;
}

#include "generated_cc_delta.inc"

static int failures;

static void
expect(const char *name, const char *input, time_t want)
{
    time_t  got;

    got = ngx_http_cache_turbo_cc_parse_delta((u_char *) input, strlen(input));
    if (got != want) {
        fprintf(stderr, "FAIL test_cc_delta_%s: input=%s got=%lld want=%lld\n",
                name, input, (long long) got, (long long) want);
        failures++;
    }
}

static void
expect_directive(const char *name, const char *input, const char *directive,
    time_t want)
{
    time_t  got;

    got = ngx_http_cache_turbo_cc_delta((u_char *) input,
                                        (u_char *) input + strlen(input),
                                        directive, strlen(directive));
    if (got != want) {
        fprintf(stderr,
                "FAIL test_cc_delta_directive_%s: input=%s got=%lld want=%lld\n",
                name, input, (long long) got, (long long) want);
        failures++;
    }
}

static void
expect_has(const char *name, const char *input, const char *directive,
    ngx_int_t want)
{
    ngx_int_t  got;

    got = ngx_http_cache_turbo_cc_has((u_char *) input,
                                     (u_char *) input + strlen(input),
                                     directive, strlen(directive));
    if (got != want) {
        fprintf(stderr, "FAIL test_cc_token_has_%s: got=%ld want=%ld\n",
                name, (long) got, (long) want);
        failures++;
    }
}

static void
expect_tokens(const char *name, const char *input, const char *directive,
    const char **want, size_t nwant)
{
    u_char     *cursor, *last, *q;
    size_t      vlen, seen;
    ngx_int_t   valued;

    cursor = (u_char *) input;
    last = cursor + strlen(input);
    seen = 0;
    while ((q = ngx_http_cache_turbo_cc_token(&cursor, last, directive,
               strlen(directive), &vlen, &valued)) != NULL)
    {
        if (seen >= nwant) {
            fprintf(stderr, "FAIL test_cc_token_%s: unexpected extra match\n",
                    name);
            failures++;
            return;
        }
        if (want[seen] == NULL) {
            if (valued) {
                fprintf(stderr,
                        "FAIL test_cc_token_%s: match %zu should be bare\n",
                        name, seen);
                failures++;
            }
        } else if (!valued || vlen != strlen(want[seen])
                   || memcmp(q, want[seen], vlen) != 0)
        {
            fprintf(stderr,
                    "FAIL test_cc_token_%s: match %zu value mismatch\n",
                    name, seen);
            failures++;
        }
        seen++;
    }
    if (seen != nwant) {
        fprintf(stderr, "FAIL test_cc_token_%s: got=%zu matches want=%zu\n",
                name, seen, nwant);
        failures++;
    }
}

int
main(void)
{
    expect("zero", "0", 0);
    expect("unquoted", "42", 42);
    expect("quoted", "\"42\"", 42);
    expect("signed_boundary", "9223372036854775807",
           (time_t) NGX_MAX_INT_T_VALUE);
    expect("overflow_saturates", "9223372036854775808",
           (time_t) NGX_MAX_INT_T_VALUE);
    expect("long_overflow_saturates", "999999999999999999999999999999999",
           (time_t) NGX_MAX_INT_T_VALUE);
    expect("junk_suffix", "42x", -1);
    expect("quoted_junk_suffix", "\"42\"x", -1);
    expect("unterminated_quote", "\"42", -1);
    expect("empty_quote", "\"\"", -1);
    expect("sign", "+42", -1);
    expect("whitespace", " 42", -1);

    expect_tokens("duplicate_numeric",
                  "max-age=600, max-age=0", "max-age",
                  (const char *[]) {"600", "0"}, 2);
    expect_tokens("bare_then_numeric",
                  "max-stale, max-stale=0", "max-stale",
                  (const char *[]) {NULL, "0"}, 2);
    expect_tokens("quoted_comma_inert",
                  "ext=\"inert, max-age=0, tail\", max-age=600", "max-age",
                  (const char *[]) {"600"}, 1);
    expect_tokens("quoted_pair_inert",
                  "ext=\"inert, max-age=0, tail=\\\"x\", max-age=600",
                  "max-age", (const char *[]) {"600"}, 1);
    expect_tokens("unbalanced_quote_inert",
                  "ext=\"inert, max-age=0, tail", "max-age", NULL, 0);
    expect_tokens("directive_after_quote",
                  "ext=\"a,b\", max-age=0", "max-age",
                  (const char *[]) {"0"}, 1);
    expect_tokens("empty_valued", "max-stale=", "max-stale",
                  (const char *[]) {""}, 1);
    expect_has("quoted_no_cache_inert",
               "ext=\"inert, no-cache, tail\"", "no-cache", 0);
    expect_has("no_cache_after_quote",
               "ext=\"a,b\", no-cache", "no-cache", 1);
    expect_directive("response_first_preserved",
                     "max-age=600, max-age=0", "max-age", 600);

    if (failures != 0) {
        return 1;
    }
    puts("PASS test_cc_token_quote_iteration_and_delta_grammar");
    return 0;
}
