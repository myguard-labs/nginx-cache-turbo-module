/* L1 marker persistence is mandatory; L2 write-through is ordered after it. */
#include <stdio.h>

#include "ngx_shim_marker_store_key.h"
#include "generated_marker_store_key.inc"

static int         failures;
ngx_int_t          ngx_test_shm_result;
ngx_uint_t         ngx_test_shm_calls;
ngx_uint_t         ngx_test_l2_calls;
u_char             ngx_test_shm_key[32];
u_char             ngx_test_l2_key[32];
u_char             ngx_test_shm_blob[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 2];
u_char             ngx_test_l2_blob[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 2];
time_t             ngx_test_shm_ttl;
time_t             ngx_test_shm_retain_ttl;

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, msg); \
            failures++;                                                      \
        }                                                                    \
    } while (0)

static void
test_l2_set(ngx_http_request_t *r, ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char key[32], u_char *blob, size_t blob_len, time_t ttl,
    time_t retain_ttl)
{
    (void) r;
    (void) clcf;
    CHECK(blob_len == sizeof(ngx_test_l2_blob),
          "L2 marker wire length must remain byte-compatible");
    ngx_test_l2_calls++;
    memcpy(ngx_test_l2_key, key, sizeof(ngx_test_l2_key));
    if (blob_len == sizeof(ngx_test_l2_blob)) {
        memcpy(ngx_test_l2_blob, blob, blob_len);
    }
    CHECK(ttl == 37 && retain_ttl == 91,
          "L2 marker TTLs must remain unchanged");
}

static void
reset_case(void)
{
    ngx_test_shm_result = NGX_OK;
    ngx_test_shm_calls = 0;
    ngx_test_l2_calls = 0;
    memset(ngx_test_shm_key, 0, sizeof(ngx_test_shm_key));
    memset(ngx_test_l2_key, 0, sizeof(ngx_test_l2_key));
    memset(ngx_test_shm_blob, 0, sizeof(ngx_test_shm_blob));
    memset(ngx_test_l2_blob, 0, sizeof(ngx_test_l2_blob));
    ngx_test_shm_ttl = 0;
    ngx_test_shm_retain_ttl = 0;
}

int
main(void)
{
    ngx_cache_turbo_backend_t          backend = { test_l2_set };
    ngx_http_cache_turbo_loc_conf_t    clcf = { &backend };
    ngx_http_cache_turbo_zone_t        zone;
    ngx_http_request_t                 request;
    u_char                             marker_key[32];
    ngx_uint_t                         i;
    ngx_int_t                          rc;

    for (i = 0; i < 32; i++) {
        marker_key[i] = (u_char) (0x80 + i);
    }

    reset_case();
    ngx_test_shm_result = NGX_ERROR;
    rc = ngx_http_cache_turbo_marker_store_key(&request, &clcf, &zone,
                                                marker_key, 0x35, 0x4a,
                                                37, 91);
    CHECK(rc == NGX_ERROR,
          "failed mandatory L1 marker store must propagate NGX_ERROR");
    CHECK(ngx_test_shm_calls == 1,
          "failed L1 marker store must be attempted exactly once");
    CHECK(ngx_test_l2_calls == 0,
          "failed L1 marker store must stop before L2 write-through");

    reset_case();
    rc = ngx_http_cache_turbo_marker_store_key(&request, &clcf, &zone,
                                                marker_key, 0x35, 0x4a,
                                                37, 91);
    CHECK(rc == NGX_OK, "successful marker persistence must remain NGX_OK");
    CHECK(ngx_test_shm_calls == 1 && ngx_test_l2_calls == 1,
          "successful marker persistence must reach both tiers once");
    CHECK(memcmp(ngx_test_shm_key, marker_key, 32) == 0
          && memcmp(ngx_test_l2_key, marker_key, 32) == 0,
          "successful marker key bytes must remain unchanged in both tiers");
    CHECK(memcmp(ngx_test_shm_blob, ngx_test_l2_blob,
                 sizeof(ngx_test_shm_blob)) == 0,
          "successful L1/L2 marker blobs must remain byte-identical");
    CHECK(ngx_test_shm_blob[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE] == 0x35
          && ngx_test_shm_blob[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 1] == 0x4a,
          "successful marker body bytes must remain [bits][generation]");
    CHECK(ngx_test_shm_ttl == 37 && ngx_test_shm_retain_ttl == 91,
          "successful L1 marker TTLs must remain unchanged");

    fprintf(stderr, "marker store ordering: %d failures\n", failures);
    return failures ? 1 : 0;
}
