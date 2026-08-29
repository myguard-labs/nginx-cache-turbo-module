/* Whole-zone purge must report combined L1/L2 completion truthfully. */
#include "ngx_shim_admin_purge_all.h"

#include "generated_admin_purge_all.inc"

static int                            failures;
static ngx_int_t                      l1_result;
static ngx_uint_t                     l1_purged;
static int                            l1_calls;
static int                            l2_calls;
static ngx_uint_t                     l2_arg_purged;
static ngx_flag_t                     l2_arg_l1_incomplete;
static ngx_int_t                      l2_result;
static ngx_http_cache_turbo_walk_pt   saved_callback;
static void                          *saved_data;

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
    CHECK(callback != NULL, "configured L2 path must provide its callback");
    l2_calls++;
    l2_arg_purged = ap->purged;
    l2_arg_l1_incomplete = ap->l1_incomplete;
    saved_callback = callback;
    saved_data = data;
    return l2_result;
}

static void
reset_request(ngx_http_request_t *r, ngx_pool_t *pool)
{
    memset(pool, 0, sizeof(*pool));
    memset(r, 0, sizeof(*r));
    r->pool = pool;
    r->args.data = (u_char *) "all=1";
    r->args.len = sizeof("all=1") - 1;
    ngx_test_alloc_start = NULL;
    ngx_test_alloc_end = NULL;
    l1_calls = 0;
    l2_calls = 0;
    l2_arg_purged = 0;
    l2_arg_l1_incomplete = 0;
    saved_callback = NULL;
    saved_data = NULL;
}

static void
check_response(ngx_http_request_t *r, ngx_uint_t status,
    const char *expected, const char *message)
{
    size_t  len = strlen(expected);

    CHECK(r->send_calls == 1, "purge outcome must send exactly one response");
    if (r->send_calls != 1) {
        return;
    }
    CHECK(r->sent_status == status, message);
    CHECK(r->sent_body.len == len, "purge JSON length must be exact");
    if (r->sent_body.len == len) {
        CHECK(memcmp(r->sent_body.data, expected, len) == 0,
              "purge JSON fields, order, and shape must be exact");
    }
}

static ngx_int_t
invoke_saved_callback(ngx_http_request_t *r,
    const ngx_http_cache_turbo_redis_walk_t *walk)
{
    if (saved_callback == NULL) {
        fprintf(stderr, "FAIL %s:%d: parked purge stored no callback\n",
                __FILE__, __LINE__);
        failures++;
        return NGX_ERROR;
    }

    return saved_callback(r, saved_data, NULL, 0, walk);
}

int
main(void)
{
    ngx_cache_turbo_l1_backend_t       l1 = { test_purge_all };
    ngx_cache_turbo_backend_t          l2 = { test_scan_del };
    ngx_http_cache_turbo_loc_conf_t    clcf = { &l1, &l2, 0 };
    ngx_http_cache_turbo_zone_t        zone;
    ngx_http_request_t                 request;
    ngx_pool_t                         pool;
    ngx_http_cache_turbo_redis_walk_t  walk;
    ngx_int_t                          rc;

    /* L1 residue is a normal bounded-snapshot outcome, not a reason to skip
     * the configured L2 purge. The state must survive the park and turn an
     * otherwise-complete callback into an exact 500. */
    reset_request(&request, &pool);
    l1_result = NGX_AGAIN;
    l1_purged = 513;
    l2_result = NGX_DONE;
    rc = ngx_http_cache_turbo_admin_purge_dispatch(&request, &clcf, &zone);
    CHECK(rc == NGX_DONE, "L1-incomplete purge must still park on L2");
    CHECK(l1_calls == 1 && l2_calls == 1,
          "L1-incomplete purge must query both tiers exactly once");
    CHECK(l2_arg_purged == 513 && l2_arg_l1_incomplete == 1,
          "parked callback state must carry L1 count and incompleteness");
    CHECK(request.send_calls == 0,
          "parked combined purge must not send a synchronous response");
    walk = (ngx_http_cache_turbo_redis_walk_t) {
        .status = NGX_OK, .pages = 2, .blocks = 3, .deadline = 0
    };
    rc = invoke_saved_callback(&request, &walk);
    CHECK(rc == NGX_OK, "combined callback must propagate its send result");
    check_response(&request, NGX_HTTP_INTERNAL_SERVER_ERROR,
                   "{\"purged\":513,\"l1\":\"incomplete\"}\n",
                   "L1 residue must keep the async response at HTTP 500");

    /* Both tiers can be incomplete independently; neither fact may hide the
     * other in the asynchronous completion response. */
    reset_request(&request, &pool);
    l1_result = NGX_AGAIN;
    l1_purged = 23;
    l2_result = NGX_DONE;
    rc = ngx_http_cache_turbo_admin_purge_dispatch(&request, &clcf, &zone);
    CHECK(rc == NGX_DONE && saved_callback != NULL,
          "combined-failure fixture must park with a callback");
    walk = (ngx_http_cache_turbo_redis_walk_t) {
        .status = NGX_ABORT, .pages = 2, .blocks = 4, .deadline = 1
    };
    rc = invoke_saved_callback(&request, &walk);
    CHECK(rc == NGX_OK, "combined-failure callback must send its response");
    check_response(&request, NGX_HTTP_INTERNAL_SERVER_ERROR,
                   "{\"purged\":23,\"l1\":\"incomplete\","
                   "\"l2\":\"incomplete\",\"reason\":\"deadline\"}\n",
                   "combined incomplete purge must send HTTP 500");

    /* A synchronous L2 launch failure also retains L1 residue in the exact
     * combined response instead of returning either tier's state alone. */
    reset_request(&request, &pool);
    l1_result = NGX_AGAIN;
    l1_purged = 11;
    l2_result = NGX_ERROR;
    rc = ngx_http_cache_turbo_admin_purge_dispatch(&request, &clcf, &zone);
    CHECK(rc == NGX_OK, "synchronous combined 500 must return send_json rc");
    CHECK(l1_calls == 1 && l2_calls == 1,
          "synchronous combined failure must attempt both tiers");
    check_response(&request, NGX_HTTP_INTERNAL_SERVER_ERROR,
                   "{\"purged\":11,\"l1\":\"incomplete\","
                   "\"l2\":\"unavailable\"}\n",
                   "combined synchronous failure must send HTTP 500");

    /* Complete L1 + unavailable L2 preserves the established L2-only shape. */
    reset_request(&request, &pool);
    l1_result = NGX_OK;
    l1_purged = 29;
    l2_result = NGX_ERROR;
    rc = ngx_http_cache_turbo_admin_purge_dispatch(&request, &clcf, &zone);
    CHECK(rc == NGX_OK, "dispatcher must propagate the L2 500 send result");
    CHECK(l2_arg_purged == 29 && l2_arg_l1_incomplete == 0,
          "complete L1 state must reach the L2 path unchanged");
    check_response(&request, NGX_HTTP_INTERNAL_SERVER_ERROR,
                   "{\"purged\":29,\"l2\":\"unavailable\"}\n",
                   "L2 unavailability must send HTTP 500");

    /* Complete async success remains a single 200 from the callback. */
    reset_request(&request, &pool);
    l1_result = NGX_OK;
    l1_purged = 7;
    l2_result = NGX_DONE;
    rc = ngx_http_cache_turbo_admin_purge_dispatch(&request, &clcf, &zone);
    CHECK(rc == NGX_DONE && request.send_calls == 0,
          "complete configured purge must park without a sync response");
    walk = (ngx_http_cache_turbo_redis_walk_t) {
        .status = NGX_OK, .pages = 1, .blocks = 2, .deadline = 0
    };
    rc = invoke_saved_callback(&request, &walk);
    CHECK(rc == NGX_OK, "successful L2 callback must return its send result");
    check_response(&request, NGX_HTTP_OK, "{\"purged\":7}\n",
                   "complete two-tier purge must send HTTP 200");

    /* No-L2 behavior is preserved: L1 residue reports the same synchronous
     * 500, while a complete L1 purge reaches the common synchronous 200. */
    clcf.backend = NULL;
    reset_request(&request, &pool);
    l1_result = NGX_AGAIN;
    l1_purged = 17;
    rc = ngx_http_cache_turbo_admin_purge_dispatch(&request, &clcf, &zone);
    CHECK(rc == NGX_OK && l2_calls == 0,
          "L1-only incomplete purge must stay synchronous");
    check_response(&request, NGX_HTTP_INTERNAL_SERVER_ERROR,
                   "{\"purged\":17,\"l1\":\"incomplete\"}\n",
                   "L1-only residue must preserve its HTTP 500 contract");

    reset_request(&request, &pool);
    l1_result = NGX_OK;
    l1_purged = 7;
    rc = ngx_http_cache_turbo_admin_purge_dispatch(&request, &clcf, &zone);
    CHECK(rc == NGX_OK && l2_calls == 0,
          "complete L1-only purge must remain synchronous");
    check_response(&request, NGX_HTTP_OK, "{\"purged\":7}\n",
                   "idle L1-only purge must send HTTP 200");

    fprintf(stderr, "admin purge-all contract: %d failures\n", failures);
    return failures ? 1 : 0;
}
