/* Purge-all errors must send one exact 500 without dispatcher 200 fallthrough. */
#include "ngx_shim_admin_purge_all.h"

#include "generated_admin_purge_all.inc"

static int        failures;
static ngx_int_t  l1_result;
static ngx_uint_t l1_purged;
static int        l1_calls;
static int        l2_calls;
static ngx_uint_t l2_arg_purged;
static ngx_int_t  l2_result;

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
    l1_calls = 0;
    l2_calls = 0;
    l2_arg_purged = 0;
}

int
main(void)
{
    static const char l1_expected[] =
        "{\"purged\":513,\"l1\":\"incomplete\"}\n";
    static const char l2_expected[] =
        "{\"purged\":29,\"l2\":\"unavailable\"}\n";
    static const char ok_expected[] = "{\"purged\":7}\n";
    ngx_cache_turbo_l1_backend_t    l1 = { test_purge_all };
    ngx_cache_turbo_backend_t       l2 = { test_scan_del };
    ngx_http_cache_turbo_loc_conf_t clcf = { &l1, &l2, 0 };
    ngx_http_cache_turbo_zone_t     zone;
    ngx_http_request_t              request;
    ngx_pool_t                      pool;
    ngx_int_t                       rc;

    reset_request(&request, &pool);
    l1_result = NGX_AGAIN;
    l1_purged = 513;
    l2_result = NGX_DONE;
    rc = ngx_http_cache_turbo_admin_purge_dispatch(&request, &clcf, &zone);

    CHECK(rc == NGX_OK, "dispatcher must propagate the L1 500 send result");
    CHECK(l1_calls == 1, "purge-all must query L1 exactly once");
    CHECK(request.send_calls == 1,
          "L1 incompleteness must send exactly one response, not a later 200");
    if (request.send_calls == 1) {
        CHECK(request.sent_status == NGX_HTTP_INTERNAL_SERVER_ERROR,
              "L1 incompleteness must send HTTP 500");
        CHECK(request.sent_body.len == sizeof(l1_expected) - 1,
              "L1-incomplete JSON length must be exact");
        if (request.sent_body.len == sizeof(l1_expected) - 1) {
            CHECK(memcmp(request.sent_body.data, l1_expected,
                         sizeof(l1_expected) - 1) == 0,
                  "L1-incomplete JSON fields and shape must be exact");
        }
    }
    CHECK(l2_calls == 0, "L1 incompleteness must not launch an L2 purge");

    reset_request(&request, &pool);
    l1_result = NGX_OK;
    l1_purged = 29;
    l2_result = NGX_ERROR;
    rc = ngx_http_cache_turbo_admin_purge_dispatch(&request, &clcf, &zone);
    CHECK(rc == NGX_OK, "dispatcher must propagate the L2 500 send result");
    CHECK(l1_calls == 1 && l2_calls == 1,
          "L2-unavailable path must purge L1 and try L2 exactly once");
    CHECK(l2_arg_purged == 29,
          "L2-unavailable state must preserve the exact L1 count");
    CHECK(request.send_calls == 1,
          "L2 unavailability must send exactly one response, not a later 200");
    if (request.send_calls == 1) {
        CHECK(request.sent_status == NGX_HTTP_INTERNAL_SERVER_ERROR,
              "L2 unavailability must send HTTP 500");
        CHECK(request.sent_body.len == sizeof(l2_expected) - 1,
              "L2-unavailable JSON length must be exact");
        if (request.sent_body.len == sizeof(l2_expected) - 1) {
            CHECK(memcmp(request.sent_body.data, l2_expected,
                         sizeof(l2_expected) - 1) == 0,
                  "L2-unavailable JSON fields and shape must be exact");
        }
    }

    /* Positive reachability control: the same configured backend parks once
     * when it starts successfully. Without this, the unavailable-path L2 call
     * assertion could pass against a shim that never distinguishes outcomes. */
    reset_request(&request, &pool);
    l1_result = NGX_OK;
    l1_purged = 7;
    l2_result = NGX_DONE;
    rc = ngx_http_cache_turbo_admin_purge_dispatch(&request, &clcf, &zone);
    CHECK(rc == NGX_DONE, "complete L1 must propagate the parked L2 status");
    CHECK(l1_calls == 1 && l2_calls == 1,
          "complete L1 must launch the configured L2 purge exactly once");
    CHECK(l2_arg_purged == 7,
          "the L2 completion state must preserve the exact L1 count");
    CHECK(request.send_calls == 0,
          "a parked L2 purge must not send a synchronous response");

    /* The common synchronous 200 remains reachable when no L2 is configured.
     * This makes an unconditional early return after purge_all falsifiable. */
    reset_request(&request, &pool);
    clcf.backend = NULL;
    l1_result = NGX_OK;
    l1_purged = 7;
    rc = ngx_http_cache_turbo_admin_purge_dispatch(&request, &clcf, &zone);
    CHECK(rc == NGX_OK, "idle L1-only purge must propagate the 200 send result");
    CHECK(request.send_calls == 1 && request.sent_status == NGX_HTTP_OK,
          "idle L1-only purge must send exactly one HTTP 200");
    CHECK(request.sent_body.len == sizeof(ok_expected) - 1,
          "successful purge JSON length must be exact");
    if (request.sent_body.len == sizeof(ok_expected) - 1) {
        CHECK(memcmp(request.sent_body.data, ok_expected,
                     sizeof(ok_expected) - 1) == 0,
              "successful purge JSON fields and shape must be exact");
    }

    fprintf(stderr, "admin purge-all contract: %d failures\n", failures);
    return failures ? 1 : 0;
}
