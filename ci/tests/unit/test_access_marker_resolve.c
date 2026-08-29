/* L2 marker self-heal is best-effort once the request key is resolved. */
#include "ngx_shim_access_marker_resolve.h"

#include <stdio.h>

#include "generated_access_marker_resolve.inc"

ngx_int_t   ngx_test_variant_hash_result;
ngx_int_t   ngx_test_marker_store_result;
ngx_uint_t  ngx_test_variant_hash_calls;
ngx_uint_t  ngx_test_marker_store_calls;
ngx_uint_t  ngx_test_warning_calls;
ngx_uint_t  ngx_test_debug_calls;
ngx_uint_t  ngx_test_warning_level;
ngx_int_t   ngx_test_store_bits;
ngx_uint_t  ngx_test_store_gen;
time_t      ngx_test_store_ttl;
time_t      ngx_test_store_retain_ttl;

static int failures;

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, msg);   \
            failures++;                                                      \
        }                                                                    \
    } while (0)

static void
reset_faults(void)
{
    ngx_test_variant_hash_result = NGX_OK;
    ngx_test_marker_store_result = NGX_OK;
    ngx_test_variant_hash_calls = 0;
    ngx_test_marker_store_calls = 0;
    ngx_test_warning_calls = 0;
    ngx_test_debug_calls = 0;
    ngx_test_warning_level = 0;
    ngx_test_store_bits = 0;
    ngx_test_store_gen = 0;
    ngx_test_store_ttl = 0;
    ngx_test_store_retain_ttl = 0;
}

int
main(void)
{
    static u_char base[] = "https://example.test/asset.css";
    static u_char uri[] = "/asset.css";
    ngx_connection_t                 connection = { NULL };
    ngx_http_request_t               request = {
        &connection, { sizeof(uri) - 1, uri }
    };
    ngx_http_cache_turbo_loc_conf_t  clcf;
    ngx_http_cache_turbo_zone_t      zone;
    ngx_http_cache_turbo_ctx_t       ctx;
    uint32_t                         hash, expected_hash;
    u_char                           expected_key[32], key_before_failure[32];
    ngx_uint_t                       i;
    ngx_int_t                        rc;

    memset(&ctx, 0, sizeof(ctx));
    ctx.cache_key.data = base;
    ctx.cache_key.len = sizeof(base) - 1;
    for (i = 0; i < 32; i++) {
        expected_key[i] = (u_char) (0x40 + i);
    }
    expected_hash = ngx_crc32_short(expected_key, sizeof(expected_key));

    reset_faults();
    ngx_test_marker_store_result = NGX_ERROR;
    hash = 0;
    rc = ngx_http_cache_turbo_access_l2_marker_resolve(&request, &clcf, &ctx,
                                                        &zone, &hash, 5, 9,
                                                        -3, 120);
    CHECK(rc == NGX_OK,
          "marker self-heal failure must not fail a resolved L2 request");
    CHECK(ngx_test_variant_hash_calls == 1 && ngx_test_marker_store_calls == 1,
          "self-heal failure must occur after one successful key resolution");
    CHECK(memcmp(ctx.key_hash, expected_key, sizeof(expected_key)) == 0
              && hash == expected_hash,
          "self-heal failure must preserve the resolved variant key bytes");
    CHECK(ctx.vary_gen == 9 && ctx.vary_marker_l2_bits == 5
              && ctx.vary_marker_l2_gen == 9,
          "self-heal failure must preserve the resolved marker state");
    CHECK(ngx_test_store_bits == 5 && ngx_test_store_gen == 9
              && ngx_test_store_ttl == 1
              && ngx_test_store_retain_ttl == 120,
          "best-effort self-heal must preserve marker arguments and TTL floor");
    CHECK(ngx_test_warning_calls == 1
              && ngx_test_warning_level == NGX_LOG_WARN,
          "marker self-heal failure must emit one warning");
    CHECK(ngx_test_debug_calls == 0,
          "failed marker self-heal must not claim success in the debug log");

    reset_faults();
    rc = ngx_http_cache_turbo_access_l2_marker_resolve(&request, &clcf, &ctx,
                                                        &zone, &hash, 3, 7,
                                                        20, 80);
    CHECK(rc == NGX_OK && ngx_test_marker_store_calls == 1,
          "successful marker resolution must retain the ordinary path");
    CHECK(ngx_test_warning_calls == 0 && ngx_test_debug_calls == 1,
          "successful self-heal must emit only its success debug log");

    /* Negative control: only the post-resolution replication failure is
     * best-effort. A variant-key digest failure still rejects the request and
     * must not attempt marker replication with invalid key state. */
    reset_faults();
    ngx_test_variant_hash_result = NGX_ERROR;
    memset(ctx.key_hash, 0xC3, sizeof(ctx.key_hash));
    memcpy(key_before_failure, ctx.key_hash, sizeof(key_before_failure));
    hash = 0xdecafbadU;
    rc = ngx_http_cache_turbo_access_l2_marker_resolve(&request, &clcf, &ctx,
                                                        &zone, &hash, 1, 2,
                                                        10, 40);
    CHECK(rc == NGX_ERROR,
          "variant-key digest failure must remain fail-closed");
    CHECK(ngx_test_marker_store_calls == 0 && ngx_test_warning_calls == 0,
          "variant-key failure must stop before marker self-heal");
    CHECK(memcmp(ctx.key_hash, key_before_failure,
                 sizeof(key_before_failure)) == 0
              && hash == 0xdecafbadU,
          "variant-key failure must not publish key bytes or hash");

    fprintf(stderr, "access marker resolve policy: %d failures\n", failures);
    return failures ? 1 : 0;
}
