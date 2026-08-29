/* L1-incomplete purge-all must be an exact 500 and must not launch L2. */
#include "ngx_shim_admin_purge_all.h"

#include "generated_admin_purge_all.inc"

static int        failures;
static ngx_int_t  l1_result;
static ngx_uint_t l1_purged;
static int        l1_calls;
static int        l2_calls;
static ngx_uint_t l2_arg_purged;

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, msg);   \
            failures++;                                                      \
        }                                                                    \
    } while (0)

static ngx_int_t
test_purge_all(ngx_http_cache_turbo_zone_t *z, ngx_uint_t *purged)
{
    (void) z;
    l1_calls++;
    *purged = l1_purged;
    return l1_result;
}

static ngx_int_t
test_scan_del(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_http_cache_turbo_walk_pt callback, void *data)
{
    ngx_http_cache_turbo_allpurge_t  *ap = data;

    (void) r;
    (void) clcf;
    CHECK(callback != NULL, "complete L1 path must provide an L2 callback");
    l2_calls++;
    l2_arg_purged = ap->purged;
    return NGX_DONE;
}

static void
reset_request(ngx_http_request_t *r, ngx_pool_t *pool)
{
    memset(pool, 0, sizeof(*pool));
    memset(r, 0, sizeof(*r));
    r->pool = pool;
    l1_calls = 0;
    l2_calls = 0;
    l2_arg_purged = 0;
}

int
main(void)
{
    static const char expected[] =
        "{\"purged\":513,\"l1\":\"incomplete\"}\n";
    ngx_cache_turbo_l1_backend_t    l1 = { test_purge_all };
    ngx_cache_turbo_backend_t       l2 = { test_scan_del };
    ngx_http_cache_turbo_loc_conf_t clcf = { &l1, &l2 };
    ngx_http_cache_turbo_zone_t     zone;
    ngx_http_request_t              request;
    ngx_pool_t                      pool;
    ngx_uint_t                      purged = 0;
    ngx_int_t                       rc;

    reset_request(&request, &pool);
    l1_result = NGX_AGAIN;
    l1_purged = 513;
    rc = ngx_http_cache_turbo_admin_purge_all(&request, &clcf, &zone,
                                               &purged);

    CHECK(rc == NGX_OK, "the emitted incomplete response must propagate");
    CHECK(l1_calls == 1, "purge-all must query L1 exactly once");
    CHECK(purged == 513, "the incomplete response must preserve the exact count");
    CHECK(request.send_calls == 1, "L1 incompleteness must send one response");
    if (request.send_calls == 1) {
        CHECK(request.sent_status == NGX_HTTP_INTERNAL_SERVER_ERROR,
              "L1 incompleteness must send HTTP 500");
        CHECK(request.sent_body.len == sizeof(expected) - 1,
              "L1-incomplete JSON length must be exact");
        if (request.sent_body.len == sizeof(expected) - 1) {
            CHECK(memcmp(request.sent_body.data, expected,
                         sizeof(expected) - 1) == 0,
                  "L1-incomplete JSON fields and shape must be exact");
        }
    }
    CHECK(l2_calls == 0, "L1 incompleteness must not launch an L2 purge");

    /* Positive reachability control: the same configured backend must launch
     * exactly once when L1 reports complete.  Without this, l2_calls == 0 in
     * the failure case could pass because the shim never wired scan_del. */
    reset_request(&request, &pool);
    l1_result = NGX_OK;
    l1_purged = 7;
    purged = 0;
    rc = ngx_http_cache_turbo_admin_purge_all(&request, &clcf, &zone,
                                               &purged);
    CHECK(rc == NGX_DONE, "complete L1 must propagate the parked L2 status");
    CHECK(l1_calls == 1 && l2_calls == 1,
          "complete L1 must launch the configured L2 purge exactly once");
    CHECK(l2_arg_purged == 7,
          "the L2 completion state must preserve the exact L1 count");
    CHECK(request.send_calls == 0,
          "a parked L2 purge must not send a synchronous response");

    fprintf(stderr, "admin purge-all contract: %d failures\n", failures);
    return failures ? 1 : 0;
}
