/* Digest failure must stop admin ?key= before either cache tier sees bytes. */
#include "ngx_shim_admin_purge_key.h"

#include <stdio.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include "generated_admin_purge_key.inc"
#pragma GCC diagnostic pop

int ngx_test_digest_fail;
static int failures;
static int l1_calls;
static int l2_calls;
static u_char l1_key[32];
static u_char l2_key[32];

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, msg);   \
            failures++;                                                      \
        }                                                                    \
    } while (0)

static ngx_int_t
test_purge_key(ngx_http_cache_turbo_zone_t *z, u_char *key_hash, uint32_t hash)
{
    (void) z;
    (void) hash;
    memcpy(l1_key, key_hash, sizeof(l1_key));
    l1_calls++;
    return 7;
}

static void
test_del(ngx_http_cache_turbo_loc_conf_t *clcf, u_char *key_hash)
{
    (void) clcf;
    memcpy(l2_key, key_hash, sizeof(l2_key));
    l2_calls++;
}

int
main(void)
{
    static const u_char expected[32] =
        "admin-keyadmin-keyadmin-keyadmin";
    ngx_cache_turbo_l1_backend_t  l1 = { test_purge_key };
    ngx_cache_turbo_backend_t     l2 = { test_del };
    ngx_http_cache_turbo_loc_conf_t clcf = { &l1, &l2 };
    ngx_http_cache_turbo_zone_t   zone;
    ngx_http_request_t            request;
    ngx_str_t                     key = { 9, (u_char *) "admin-key" };
    ngx_uint_t                    purged = 99;
    ngx_int_t                     rc;

    ngx_test_digest_fail = 1;
    rc = ngx_http_cache_turbo_admin_purge_key(&request, &clcf, &zone, &key,
                                               &purged);
    CHECK(rc == NGX_HTTP_INTERNAL_SERVER_ERROR,
          "digest failure must become an admin 500");
    CHECK(l1_calls == 0, "digest failure must not purge L1 with invalid bytes");
    CHECK(l2_calls == 0, "digest failure must not delete L2 with invalid bytes");
    CHECK(purged == 99, "digest failure must not publish a purge count");

    ngx_test_digest_fail = 0;
    rc = ngx_http_cache_turbo_admin_purge_key(&request, &clcf, &zone, &key,
                                               &purged);
    CHECK(rc == NGX_OK, "successful admin digest must preserve the old status");
    CHECK(l1_calls == 1 && l2_calls == 1,
          "successful admin purge must still reach both cache tiers once");
    CHECK(memcmp(l1_key, expected, sizeof(expected)) == 0,
          "successful admin purge must deliver exact digest bytes to L1");
    CHECK(memcmp(l2_key, expected, sizeof(expected)) == 0,
          "successful admin purge must deliver exact digest bytes to L2");
    CHECK(memcmp(l1_key, l2_key, sizeof(l1_key)) == 0,
          "successful admin purge must use identical bytes for both tiers");
    CHECK(purged == 7, "successful admin purge count must stay compatible");

    fprintf(stderr, "admin purge digest: %d failures\n", failures);
    return failures ? 1 : 0;
}
