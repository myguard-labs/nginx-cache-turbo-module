/* Digest failures must abort a PURGE before any base/marker/L2 mutation. */
#include "ngx_shim_purge_digest_order.h"

#include "generated_purge_digest_order.inc"

static int        failures;
static int        l1_lookup_calls;
static int        l1_purge_calls;
static int        l2_del_calls;
static int        l2_purge_tag_calls;
static ngx_int_t  l2_purge_tag_result;
static int        marker_present;
static u_char     purged_keys[2][32];
static u_char     deleted_keys[2][32];
static u_char     purged_tag[65];
static size_t     purged_tag_len;
static u_char     marker_blob[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 2];
static ngx_http_cache_turbo_node_t marker_node = {
    marker_blob, sizeof(marker_blob)
};

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
            failures++;                                                      \
        }                                                                    \
    } while (0)

static ngx_http_cache_turbo_node_t *
test_lookup(ngx_http_cache_turbo_zone_t *z, u_char *key_hash, uint32_t hash)
{
    (void) z;
    (void) key_hash;
    (void) hash;
    l1_lookup_calls++;
    return marker_present ? &marker_node : NULL;
}

static ngx_int_t
test_purge_key(ngx_http_cache_turbo_zone_t *z, u_char *key_hash, uint32_t hash)
{
    (void) z;
    (void) hash;
    if (l1_purge_calls < 2) {
        memcpy(purged_keys[l1_purge_calls], key_hash, 32);
    }
    l1_purge_calls++;
    return 1;
}

static void
test_del(ngx_http_cache_turbo_loc_conf_t *clcf, u_char *key_hash)
{
    (void) clcf;
    if (l2_del_calls < 2) {
        memcpy(deleted_keys[l2_del_calls], key_hash, 32);
    }
    l2_del_calls++;
}

static ngx_int_t
test_purge_tag(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, u_char *name, size_t name_len,
    ngx_http_cache_turbo_redis_members_pt cb, void *data)
{
    (void) r;
    (void) clcf;
    (void) data;
    CHECK(cb == ngx_http_cache_turbo_tag_purge_complete,
          "variant purge must preserve the completion callback");
    l2_purge_tag_calls++;
    purged_tag_len = name_len;
    if (name_len <= sizeof(purged_tag)) {
        memcpy(purged_tag, name, name_len);
    }
    return l2_purge_tag_result;
}

static void
reset_case(ngx_http_request_t *r, ngx_pool_t *pool,
    ngx_connection_t *connection, ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_cache_turbo_l1_backend_t *l1, ngx_cache_turbo_backend_t *backend,
    ngx_shm_zone_t *shm_zone)
{
    memset(pool, 0, sizeof(*pool));
    memset(r, 0, sizeof(*r));
    memset(connection, 0, sizeof(*connection));
    memset(clcf, 0, sizeof(*clcf));
    clcf->l1 = l1;
    clcf->backend = backend;
    clcf->shm_zone = shm_zone;
    clcf->auto_vary = 1;
    clcf->stale_mult = 4;
    memset(purged_keys, 0, sizeof(purged_keys));
    memset(deleted_keys, 0, sizeof(deleted_keys));
    memset(purged_tag, 0, sizeof(purged_tag));
    memset(ngx_test_marker_store_key, 0, sizeof(ngx_test_marker_store_key));
    memset(marker_blob, 0, sizeof(marker_blob));
    marker_blob[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE] = 3;
    marker_blob[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 1] = 7;
    r->pool = pool;
    r->main = r;
    r->count = 2;
    r->connection = connection;
    r->uri.data = (u_char *) "/asset.css";
    r->uri.len = sizeof("/asset.css") - 1;
    ngx_test_digest_call = 0;
    ngx_test_digest_fail_call = 0;
    ngx_test_marker_store_calls = 0;
    l1_lookup_calls = 0;
    l1_purge_calls = 0;
    l2_del_calls = 0;
    l2_purge_tag_calls = 0;
    l2_purge_tag_result = NGX_DONE;
    marker_present = 0;
    purged_tag_len = 0;
}

static void
check_no_mutation(ngx_http_request_t *r, const char *lookup_message)
{
    CHECK(l1_lookup_calls == 0, lookup_message);
    CHECK(l1_purge_calls == 0, "digest failure must not purge any L1 key");
    CHECK(l2_del_calls == 0, "digest failure must not delete any L2 key");
    CHECK(l2_purge_tag_calls == 0,
          "digest failure must not launch variant enumeration");
    CHECK(ngx_test_marker_store_calls == 0,
          "digest failure must not store a new marker generation");
    CHECK(r->send_calls == 0 && r->finalize_calls == 0,
          "digest failure must return 500 before sending a success body");
}

static void
expected_marker(u_char out[32])
{
    ngx_uint_t  i;

    for (i = 0; i < 32; i++) {
        out[i] = (u_char) (i + 1);
    }
}

static void
expected_index(u_char out[65])
{
    static const u_char hex[] = "0123456789abcdef";
    ngx_uint_t          i;

    out[0] = ' ';
    for (i = 0; i < 64; i++) {
        out[i + 1] = hex[i & 0x0f];
    }
}

int
main(void)
{
    ngx_cache_turbo_l1_backend_t    l1 = { test_lookup, test_purge_key };
    ngx_cache_turbo_backend_t       redis = { test_del, test_purge_tag };
    ngx_http_cache_turbo_zone_t     zone;
    ngx_shm_zone_t                  shm_zone = { &zone };
    ngx_http_cache_turbo_loc_conf_t clcf;
    ngx_http_request_t              request;
    ngx_connection_t                connection;
    ngx_pool_t                      pool;
    void                           *aligned_ptr;
    ngx_int_t                       rc;
    u_char                          marker[32], index[65];

    memset(&zone, 0, sizeof(zone));
    expected_marker(marker);
    expected_index(index);

    /* Faithfulness guard: ngx_pcalloc() uses nginx's aligned ngx_palloc(),
     * while byte buffers may use unaligned ngx_pnalloc().  Beginning at an
     * odd offset makes a collapsed implementation fail deterministically. */
    memset(&pool, 0, sizeof(pool));
    pool.used = 1;
    aligned_ptr = ngx_pcalloc(&pool, sizeof(ngx_http_cache_turbo_ctx_t));
    CHECK(aligned_ptr != NULL,
          "shim alignment fixture must fit in the test pool");
    CHECK(aligned_ptr != NULL
              && (uintptr_t) aligned_ptr % sizeof(uintptr_t) == 0,
          "shim struct allocations must preserve nginx pool alignment");

    reset_case(&request, &pool, &connection, &clcf, &l1, &redis, &shm_zone);
    ngx_test_digest_fail_call = 1;
    rc = ngx_http_cache_turbo_purge_request(&request, &clcf);
    CHECK(rc == NGX_HTTP_INTERNAL_SERVER_ERROR,
          "marker digest failure must return HTTP 500");
    CHECK(ngx_test_digest_call == 1,
          "marker digest failure must stop before index derivation");
    check_no_mutation(&request,
                      "marker digest failure must not enter auto-Vary lookup");

    reset_case(&request, &pool, &connection, &clcf, &l1, &redis, &shm_zone);
    ngx_test_digest_fail_call = 2;
    rc = ngx_http_cache_turbo_purge_request(&request, &clcf);
    CHECK(rc == NGX_HTTP_INTERNAL_SERVER_ERROR,
          "variant-index digest failure must return HTTP 500");
    CHECK(ngx_test_digest_call == 2,
          "variant-index fault must occur after marker preflight");
    check_no_mutation(&request,
                      "index digest failure must not enter auto-Vary lookup");

    reset_case(&request, &pool, &connection, &clcf, &l1, &redis, &shm_zone);
    rc = ngx_http_cache_turbo_purge_request(&request, &clcf);
    CHECK(rc == NGX_DONE, "successful Redis variant purge must park");
    CHECK(ngx_test_digest_call == 2,
          "Redis purge must derive marker and index exactly once before mutation");
    CHECK(l1_lookup_calls == 1 && l1_purge_calls == 2,
          "Redis purge must delete the base and marker from L1");
    CHECK(l2_del_calls == 2 && l2_purge_tag_calls == 1,
          "Redis purge must delete base/marker and enumerate variants in L2");
    CHECK(memcmp(purged_keys[1], marker, 32) == 0
              && memcmp(deleted_keys[1], marker, 32) == 0,
          "successful marker-key bytes must reach both tiers unchanged");
    CHECK(purged_tag_len == 65 && memcmp(purged_tag, index, 65) == 0,
          "successful variant-index bytes must reach purge_tag unchanged");
    CHECK(request.count == 1,
          "parked precontent purge must preserve request-count balancing");

    reset_case(&request, &pool, &connection, &clcf, &l1, NULL, &shm_zone);
    marker_present = 1;
    rc = ngx_http_cache_turbo_purge_request(&request, &clcf);
    CHECK(rc == NGX_DONE, "successful L1-only purge must send synchronously");
    CHECK(ngx_test_digest_call == 1,
          "L1-only purge must not re-digest inside marker_store");
    CHECK(l1_purge_calls == 1 && l1_lookup_calls == 1,
          "L1-only purge must delete the base and inspect the marker once");
    CHECK(ngx_test_marker_store_calls == 1,
          "L1-only purge must bump the marker generation once");
    CHECK(memcmp(ngx_test_marker_store_key, marker, 32) == 0,
          "preflighted marker bytes must reach marker_store unchanged");
    CHECK(request.send_calls == 1 && request.sent_status == NGX_HTTP_OK,
          "successful L1-only purge must retain its HTTP 200 response");

    /* Appended-case control: reset_case() must restore the configured backend
     * after the L1-only fixture above instead of leaking that case's mode. */
    reset_case(&request, &pool, &connection, &clcf, &l1, &redis, &shm_zone);
    CHECK(clcf.backend == &redis,
          "case reset must reseed the configured L2 backend");

    fprintf(stderr, "PURGE digest ordering: %d failures\n", failures);
    return failures ? 1 : 0;
}
