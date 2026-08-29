/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit tests for the shipped memcached GET reply parser. The parser body is
 * extracted from src/ngx_http_cache_turbo_memcached.c via
 * ci/fuzz/generated_mc_parser.inc, so this exercises production code.
 */

#include "../../fuzz/ngx_shim_mc.h"
#include "../../fuzz/generated_mc_parser.inc"

#include <stdio.h>
#include <string.h>

static int failures = 0;
static int checks = 0;

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        checks++;                                                            \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (msg));  \
        }                                                                    \
    } while (0)

static ngx_int_t
parse_once(u_char *buf, size_t len, u_char **blob, size_t *blob_len,
    size_t *consumed)
{
    ngx_http_cache_turbo_mc_op_t  op;

    op.rbuf = buf;
    op.rlen = len;
    *blob = NULL;
    *blob_len = 0;
    *consumed = 0;

    return ngx_http_cache_turbo_mc_parse(&op, blob, blob_len, consumed);
}

static ngx_int_t
parse_dribbled(u_char *buf, size_t total, u_char **blob, size_t *blob_len,
    size_t *consumed)
{
    size_t     delivered;
    ngx_int_t  rc = NGX_AGAIN;

    for (delivered = 1; delivered <= total; delivered++) {
        rc = parse_once(buf, delivered, blob, blob_len, consumed);
        if (rc != NGX_AGAIN) {
            break;
        }
    }

    return rc;
}

static void
check_split_parity(const char *fixture, ngx_int_t expected,
    const char *label)
{
    u_char     buf[256];
    u_char    *blob_one, *blob_split;
    size_t     blob_len_one, blob_len_split, consumed_one, consumed_split;
    size_t     total;
    ngx_int_t  rc_one, rc_split;

    total = strlen(fixture);
    memcpy(buf, fixture, total);

    rc_one = parse_once(buf, total, &blob_one, &blob_len_one, &consumed_one);
    rc_split = parse_dribbled(buf, total, &blob_split, &blob_len_split,
                              &consumed_split);

    CHECK(rc_one == expected, label);
    CHECK(rc_split == expected,
          "memcached parser preserves verdict under every-byte delivery");
    CHECK(consumed_one == consumed_split,
          "memcached parser preserves consumed offset under every-byte delivery");
    CHECK(blob_len_one == blob_len_split,
          "memcached parser preserves blob length under every-byte delivery");
    if (expected == NGX_OK && rc_one == NGX_OK && rc_split == NGX_OK
        && blob_one != NULL && blob_split != NULL)
    {
        CHECK(blob_one - buf == blob_split - buf,
              "memcached parser preserves blob offset under every-byte delivery");
        CHECK(memcmp(blob_one, blob_split, blob_len_one) == 0,
              "memcached parser preserves blob bytes under every-byte delivery");
    } else {
        CHECK(blob_split == NULL && blob_len_split == 0,
              "non-hit memcached parser result hands back no blob");
    }
}

int
main(void)
{
    check_split_parity("VALUE ct:k 0 5\r\nhello\r\nEND\r\n", NGX_OK,
                       "complete VALUE reply parses as a hit");
    check_split_parity("VALUE ct:k 0 0\r\n\r\nEND\r\n", NGX_OK,
                       "empty VALUE reply parses as a hit");
    check_split_parity("VALUE ct:k 0 5 99\r\nhello\r\nEND\r\n", NGX_OK,
                       "VALUE reply with CAS parses as a hit");
    check_split_parity("END\r\n", NGX_DECLINED,
                       "complete END reply parses as a miss");
    check_split_parity("VALUE ct:k 0 5\r\nhello\r\nJUNK\r\n", NGX_ERROR,
                       "hostile VALUE trailer is rejected");
    check_split_parity("VALUE ct:k 0 -1\r\n\r\nEND\r\n", NGX_ERROR,
                       "negative VALUE length is rejected");
    check_split_parity("CLIENT_ERROR bad\r\n", NGX_ERROR,
                       "memcached error line is not mistaken for a miss");
    check_split_parity("SERVER_ERROR busy\r\n", NGX_ERROR,
                       "memcached server error is not mistaken for a miss");
    check_split_parity("STORED\r\n", NGX_ERROR,
                       "SET ack is not accepted as a GET reply");

    fprintf(stderr, "%d checks, %d failed\n", checks, failures);
    if (failures == 0) {
        fprintf(stderr, "OK: memcached parser split-boundary parity\n");
    }
    return failures == 0 ? 0 : 1;
}
