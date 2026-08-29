/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * CACHE-CONTROL-DELTA-GRAMMAR: exact grammar and overflow boundaries against
 * the production parser sliced by extract_cc_delta.sh.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

typedef unsigned char  u_char;
typedef uintptr_t      ngx_uint_t;

#define NGX_MAX_INT_T_VALUE  ((intptr_t) (UINTPTR_MAX >> 1))

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

    if (failures != 0) {
        return 1;
    }
    puts("PASS test_cc_delta_positive_boundary_malformed");
    return 0;
}
