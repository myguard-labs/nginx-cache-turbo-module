#include <stdio.h>
#include <stdlib.h>

typedef unsigned long ngx_uint_t;
typedef unsigned long ngx_msec_t;

typedef struct {
    void       *elts;
    ngx_uint_t  nelts;
} ngx_array_t;

typedef struct {
    ngx_msec_t  header_time;
    ngx_uint_t  status;
} ngx_http_upstream_state_t;

typedef struct {
    ngx_array_t  *upstream_states;
} ngx_http_request_t;

static ngx_uint_t
ngx_http_cache_turbo_breaker_is_origin_failure(ngx_uint_t status)
{
    return status >= 500 && status <= 599;
}

#include "generated_breaker_retry.inc"

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "FAIL: %s\n", (msg));                           \
            return EXIT_FAILURE;                                             \
        }                                                                    \
    } while (0)

int
main(void)
{
    ngx_http_upstream_state_t  states[4] = {0};
    ngx_array_t                 attempts = { states, 0 };
    ngx_http_request_t          request = { &attempts };
    ngx_http_request_t          no_attempts = { NULL };

    CHECK(ngx_http_cache_turbo_breaker_retry_failures(&no_attempts) == 0,
          "a request without upstream states must have no retry failures");

    attempts.nelts = 1;
    states[0].header_time = (ngx_msec_t) -1;
    states[0].status = 503;
    CHECK(ngx_http_cache_turbo_breaker_retry_failures(&request) == 0,
          "the sole final/current attempt must be excluded");

    attempts.nelts = 2;
    states[0].header_time = 1;
    states[0].status = 200;
    states[1].header_time = (ngx_msec_t) -1;
    states[1].status = 503;
    CHECK(ngx_http_cache_turbo_breaker_retry_failures(&request) == 0,
          "the final/current attempt must be excluded from retry failures");

    states[0].header_time = (ngx_msec_t) -1;
    states[0].status = 0;
    states[1].header_time = 1;
    states[1].status = 200;
    CHECK(ngx_http_cache_turbo_breaker_retry_failures(&request) == 1,
          "a prior transport failure must count without an HTTP status");

    states[0].header_time = 1;
    states[0].status = 502;
    CHECK(ngx_http_cache_turbo_breaker_retry_failures(&request) == 1,
          "a prior HTTP 5xx response must count");

    attempts.nelts = 4;
    states[0].header_time = 1;
    states[0].status = 404;
    states[1].header_time = (ngx_msec_t) -1;
    states[1].status = 0;
    states[2].header_time = 1;
    states[2].status = 599;
    states[3].header_time = 1;
    states[3].status = 503;
    CHECK(ngx_http_cache_turbo_breaker_retry_failures(&request) == 2,
          "mixed prior attempts must count only transport and 5xx failures");

    puts("PASS: breaker retry failures");
    return EXIT_SUCCESS;
}
