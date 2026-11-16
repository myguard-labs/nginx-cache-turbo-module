/* Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause */
#include "stats_test_types.h"
#include "ngx_http_cache_turbo_stats_schema.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char **argv)
{
    ngx_http_cache_turbo_stats_snapshot_t snapshot = {0};
    ngx_http_cache_turbo_stats_writer_t writer;
    ngx_str_t zone, text;
    size_t budget, length, short_length, i;
    u_char *buffer, escaped[64];
    ngx_atomic_uint_t value;
    ngx_flag_t prometheus;
    const u_char controls[] = {0, 1, 9, 10, 13, 31, '"', '\\', 'x'};
    const char expected[] = "\\u0000\\u0001\\u0009\\n\\u000d\\u001f\\\"\\\\x";

    assert(argc == 3);
    zone.data = (u_char *) argv[2];
    zone.len = strlen(argv[2]);
    /* Independent fixture assignment uses the real extracted struct members,
     * not descriptor offsets, so an incorrect offset cannot verify itself. */
    seed_stats(&snapshot.stats, strcmp(argv[1], "max") == 0);
    snapshot.lock_ttl = strcmp(argv[1], "min") == 0
                        ? (time_t) INT64_MIN : (time_t) INT64_MAX;
    if (strncmp(argv[1], "state", 5) == 0) {
        snapshot.stats.breaker_state = 0x100 | (argv[1][5] - '0');
    } else {
        snapshot.stats.breaker_state = 2;
    }
    /* Check the full atomic-width conversion independently of the schema. */
    value = (ngx_atomic_uint_t) -1;
    writer = (ngx_http_cache_turbo_stats_writer_t) {escaped, 0, sizeof(escaped), 0};
    ngx_http_cache_turbo_stats_number(&writer, value);
    assert(writer.error == NGX_OK && writer.len == NGX_ATOMIC_T_LEN);
    assert(memcmp(escaped, "18446744073709551615", writer.len) == 0);
    writer = (ngx_http_cache_turbo_stats_writer_t) {escaped, 0, sizeof(escaped), 0};
    text = (ngx_str_t) {sizeof(controls), (u_char *) controls};
    ngx_http_cache_turbo_stats_escape(&writer, text, 1);
    assert(writer.error == NGX_OK && writer.len == sizeof(expected) - 1);
    assert(memcmp(escaped, expected, sizeof(expected) - 1) == 0);
    writer = (ngx_http_cache_turbo_stats_writer_t) {NULL, SIZE_MAX - 1, SIZE_MAX, 0};
    ngx_http_cache_turbo_stats_write(&writer, "xx", 2);
    assert(writer.error == NGX_ERROR && writer.len == SIZE_MAX - 1);
    writer = (ngx_http_cache_turbo_stats_writer_t) {escaped, 0, 0, 0};
    ngx_http_cache_turbo_stats_write(&writer, "x", 1);
    assert(writer.error == NGX_ERROR && writer.len == 0);

    for (prometheus = 0; prometheus <= 1; prometheus++) {
        assert(ngx_http_cache_turbo_stats_render(&snapshot, zone, prometheus, 1,
                   NULL, SIZE_MAX, &budget) == NGX_OK);
        buffer = malloc(budget + 16);
        assert(buffer != NULL);
        memset(buffer, 0xa5, budget + 16);
        assert(ngx_http_cache_turbo_stats_render(&snapshot, zone, prometheus, 0,
                   buffer, budget, &length) == NGX_OK);
        assert(length <= budget);
        for (i = budget; i < budget + 16; i++) {
            assert(buffer[i] == 0xa5);
        }
        i = fwrite(buffer, 1, length, stdout);
        assert(i == length);
        /* One byte below ACTUAL size, independent of pessimistic budget slack. */
        memset(buffer, 0xa5, budget + 16);
        assert(ngx_http_cache_turbo_stats_render(&snapshot, zone, prometheus, 0,
                   buffer, length - 1, &short_length) == NGX_ERROR);
        for (i = length - 1; i < budget + 16; i++) {
            assert(buffer[i] == 0xa5);
        }
        assert(ngx_http_cache_turbo_stats_render(&snapshot, zone, prometheus, 1,
                   NULL, 0, &short_length) == NGX_ERROR);
        free(buffer);
    }
    return 0;
}
