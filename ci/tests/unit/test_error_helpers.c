/* Exact contracts for real admin and L2 terminal-error compositions. */
#include "ngx_shim_error_helpers.h"

#include <stdio.h>

#include "generated_error_helpers.inc"

ngx_uint_t  ngx_test_log_calls;
ngx_int_t   ngx_test_log_level;
ngx_uint_t  ngx_test_log_errno;
void       *ngx_test_log;
const char *ngx_test_log_format;
ngx_uint_t  ngx_test_send_json_calls;
ngx_http_request_t *ngx_test_send_json_request;
ngx_uint_t  ngx_test_send_json_status;
ngx_str_t   ngx_test_send_json_body;
ngx_int_t   ngx_test_send_json_result;
ngx_uint_t  ngx_test_mc_arm_calls;
ngx_addr_t *ngx_test_mc_arm_addr;
ngx_msec_t  ngx_test_mc_arm_delay;
ngx_uint_t  ngx_test_mc_clear_calls;
ngx_uint_t  ngx_test_mc_done_calls;
ngx_http_cache_turbo_mc_op_t *ngx_test_mc_done_op;
ngx_uint_t  ngx_test_redis_arm_calls;
ngx_addr_t *ngx_test_redis_arm_addr;
ngx_msec_t  ngx_test_redis_arm_delay;
ngx_uint_t  ngx_test_redis_clear_calls;
ngx_uint_t  ngx_test_redis_done_calls;
ngx_http_cache_turbo_redis_op_t *ngx_test_redis_done_op;
ngx_uint_t  ngx_test_phase_calls;
ngx_uint_t  ngx_test_posted_calls;
ngx_uint_t  ngx_test_finalize_calls;
ngx_http_request_t *ngx_test_finalize_request;
ngx_int_t   ngx_test_finalize_rc;
ngx_int_t   ngx_test_handle_write_result;
ngx_int_t   ngx_test_handle_read_result;
ngx_uint_t  ngx_test_add_timer_calls;
ngx_uint_t  ngx_test_del_timer_calls;
ngx_int_t   ngx_test_redis_frame_result;
ngx_int_t   ngx_test_redis_fill_result;
ngx_int_t   ngx_test_redis_frame_scan_result;
ngx_int_t   ngx_test_redis_parse_array_result;
ngx_uint_t  ngx_test_members_calls;
ngx_str_t  *ngx_test_members;
ngx_uint_t  ngx_test_nmembers;
const ngx_http_cache_turbo_redis_walk_t *ngx_test_walk;
ngx_int_t   ngx_test_members_result;

static const u_char *test_recv_data;
static size_t        test_recv_len;
static ssize_t       test_recv_result;
static int           failures;

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, msg);   \
            failures++;                                                      \
        }                                                                    \
    } while (0)

static ssize_t
send_error(ngx_connection_t *c, u_char *buf, size_t size)
{
    (void) c;
    (void) buf;
    (void) size;
    return NGX_ERROR;
}

static ssize_t
scripted_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    (void) c;

    if (test_recv_result > 0) {
        CHECK((size_t) test_recv_result <= size,
              "scripted recv fixture must fit the production buffer");
        CHECK((size_t) test_recv_result <= test_recv_len,
              "scripted recv result must not exceed fixture bytes");
        memcpy(buf, test_recv_data, (size_t) test_recv_result);
    }
    return test_recv_result;
}

static ngx_int_t
members_callback(ngx_http_request_t *r, void *data, ngx_str_t *members,
    ngx_uint_t nmembers, const ngx_http_cache_turbo_redis_walk_t *walk)
{
    (void) r;
    CHECK(data == (void *) (uintptr_t) 0x51,
          "SMEMBERS completion must preserve callback data");
    ngx_test_members_calls++;
    ngx_test_members = members;
    ngx_test_nmembers = nmembers;
    ngx_test_walk = walk;
    return ngx_test_members_result;
}

static void
reset_observations(void)
{
    ngx_test_log_calls = 0;
    ngx_test_log_level = 0;
    ngx_test_log_errno = 99;
    ngx_test_log = NULL;
    ngx_test_log_format = NULL;
    ngx_test_send_json_calls = 0;
    ngx_test_send_json_request = NULL;
    ngx_test_send_json_status = 0;
    ngx_test_send_json_body.len = 0;
    ngx_test_send_json_body.data = NULL;
    ngx_test_send_json_result = NGX_DONE;
    ngx_test_mc_arm_calls = 0;
    ngx_test_mc_arm_addr = NULL;
    ngx_test_mc_arm_delay = 0;
    ngx_test_mc_clear_calls = 0;
    ngx_test_mc_done_calls = 0;
    ngx_test_mc_done_op = NULL;
    ngx_test_redis_arm_calls = 0;
    ngx_test_redis_arm_addr = NULL;
    ngx_test_redis_arm_delay = 0;
    ngx_test_redis_clear_calls = 0;
    ngx_test_redis_done_calls = 0;
    ngx_test_redis_done_op = NULL;
    ngx_test_phase_calls = 0;
    ngx_test_posted_calls = 0;
    ngx_test_finalize_calls = 0;
    ngx_test_finalize_request = NULL;
    ngx_test_finalize_rc = 99;
    ngx_test_handle_write_result = NGX_OK;
    ngx_test_handle_read_result = NGX_OK;
    ngx_test_add_timer_calls = 0;
    ngx_test_del_timer_calls = 0;
    ngx_test_redis_frame_result = NGX_OK;
    ngx_test_redis_fill_result = NGX_ERROR;
    ngx_test_redis_frame_scan_result = NGX_ERROR;
    ngx_test_redis_parse_array_result = NGX_ERROR;
    ngx_test_members_calls = 0;
    ngx_test_members = (ngx_str_t *) (uintptr_t) 1;
    ngx_test_nmembers = 99;
    ngx_test_walk = (const ngx_http_cache_turbo_redis_walk_t *) (uintptr_t) 1;
    ngx_test_members_result = 418;
    test_recv_data = NULL;
    test_recv_len = 0;
    test_recv_result = NGX_ERROR;
}

static void
init_request(ngx_http_request_t *r, ngx_connection_t *c, ngx_pool_t *pool,
    ngx_event_t *read, ngx_event_t *write)
{
    memset(r, 0, sizeof(*r));
    memset(c, 0, sizeof(*c));
    memset(pool, 0, sizeof(*pool));
    memset(read, 0, sizeof(*read));
    memset(write, 0, sizeof(*write));
    c->read = read;
    c->write = write;
    read->data = c;
    write->data = c;
    r->connection = c;
    r->pool = pool;
}

static void
test_warm_prerequisite_error(void)
{
    static const char body[] =
        "{\"error\":\"warm url_file: nginx must be built with --with-threads "
        "and have an available/default thread pool\"}\n";
    static const char log_format[] =
        "cache_turbo: warm url_file requires nginx built with --with-threads "
        "and an available/default thread pool";
    ngx_connection_t   connection;
    ngx_http_request_t request;
    ngx_int_t          rc;
    int                log_token;

    memset(&connection, 0, sizeof(connection));
    memset(&request, 0, sizeof(request));
    connection.log = &log_token;
    request.connection = &connection;
    reset_observations();

    rc = ngx_http_cache_turbo_warm_file_prereq_error(&request);
    CHECK(rc == NGX_DONE,
          "warm prerequisite helper must propagate the JSON callback result");
    CHECK(ngx_test_send_json_calls == 1
              && ngx_test_send_json_request == &request,
          "warm prerequisite error must send exactly one response");
    CHECK(ngx_test_send_json_status == NGX_HTTP_INTERNAL_SERVER_ERROR,
          "warm prerequisite response must use HTTP 500");
    CHECK(ngx_test_send_json_body.len == sizeof(body) - 1
              && memcmp(ngx_test_send_json_body.data, body,
                        sizeof(body) - 1) == 0,
          "warm prerequisite response body must retain its exact JSON contract");
    CHECK(ngx_test_log_calls == 1 && ngx_test_log_level == NGX_LOG_ERR
              && ngx_test_log_errno == 0 && ngx_test_log == &log_token,
          "warm prerequisite failure must emit one request-scoped error log");
    CHECK(ngx_test_log_format != NULL
              && strcmp(ngx_test_log_format, log_format) == 0,
          "warm prerequisite error log must retain its exact operator message");
}

static void
test_warm_schedule_error(void)
{
    static const char body[] =
        "{\"error\":\"warm url_file: thread-pool task could not be "
        "scheduled\"}\n";
    static const char log_format[] =
        "cache_turbo: warm url_file thread-pool task could not be scheduled";
    ngx_connection_t   connection;
    ngx_http_request_t request;
    ngx_int_t          rc;
    int                log_token;

    memset(&connection, 0, sizeof(connection));
    memset(&request, 0, sizeof(request));
    connection.log = &log_token;
    request.connection = &connection;
    reset_observations();

    rc = ngx_http_cache_turbo_warm_file_schedule_error(&request);
    CHECK(rc == NGX_DONE,
          "warm schedule helper must propagate the JSON callback result");
    CHECK(ngx_test_send_json_calls == 1
              && ngx_test_send_json_request == &request
              && ngx_test_send_json_status == NGX_HTTP_INTERNAL_SERVER_ERROR,
          "warm schedule failure must send exactly one HTTP 500 response");
    CHECK(ngx_test_send_json_body.len == sizeof(body) - 1
              && memcmp(ngx_test_send_json_body.data, body,
                        sizeof(body) - 1) == 0,
          "warm schedule failure must not masquerade as a prerequisite error");
    CHECK(ngx_test_log_calls == 1 && ngx_test_log_level == NGX_LOG_ERR
              && ngx_test_log_errno == 0 && ngx_test_log == &log_token,
          "warm schedule failure must emit one request-scoped error log");
    CHECK(ngx_test_log_format != NULL
              && strcmp(ngx_test_log_format, log_format) == 0,
          "warm schedule error log must retain its exact operator message");
}

static void
init_mc_get(ngx_http_cache_turbo_mc_op_t *op,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_request_t *r)
{
    memset(op, 0, sizeof(*op));
    memset(clcf, 0, sizeof(*clcf));
    memset(ctx, 0, sizeof(*ctx));
    clcf->redis_connect_backoff = 731;
    op->clcf = clcf;
    op->ctx = ctx;
    op->request = r;
    op->unconnected = 1;
}

static void
check_mc_get_completion(ngx_http_cache_turbo_mc_op_t *op,
    ngx_http_cache_turbo_ctx_t *ctx, ngx_http_request_t *r, const char *where)
{
    CHECK(ngx_test_mc_arm_calls == 1
              && ngx_test_mc_arm_addr == &op->clcf->redis_addr
              && ngx_test_mc_arm_delay == 731,
          where);
    CHECK(op->unconnected == 0,
          "memcached terminal classification must consume unconnected");
    CHECK(ctx->l2_result == NGX_ERROR && ctx->l2_done == 1,
          "memcached failed GET must publish exact error completion state");
    CHECK(ngx_test_mc_done_calls == 1 && ngx_test_mc_done_op == op,
          "memcached failed GET must tear down exactly once");
    CHECK(ngx_test_phase_calls == 1 && ngx_test_posted_calls == 1
              && ngx_test_finalize_calls == 1
              && ngx_test_finalize_request == r
              && ngx_test_finalize_rc == NGX_DONE,
          "memcached failed GET must resume and release its parked request once");
}

static void
test_memcached_compositions(void)
{
    ngx_http_cache_turbo_loc_conf_t clcf;
    ngx_http_cache_turbo_ctx_t      ctx;
    ngx_http_cache_turbo_mc_op_t    op;
    ngx_http_request_t              request;
    ngx_connection_t                connection;
    ngx_pool_t                      pool;
    ngx_event_t                     read, write;
    ngx_buf_t                       send;
    u_char                          byte = 'x';

    init_request(&request, &connection, &pool, &read, &write);
    init_mc_get(&op, &clcf, &ctx, &request);
    reset_observations();
    ngx_http_cache_turbo_mc_op_fail(&op);
    check_mc_get_completion(&op, &ctx, &request,
        "memcached op_fail -> real get_finish must arm exactly once");

    init_mc_get(&op, &clcf, &ctx, &request);
    connection.data = &op;
    write.timedout = 1;
    reset_observations();
    ngx_http_cache_turbo_mc_write(&write);
    check_mc_get_completion(&op, &ctx, &request,
        "memcached write timeout composition must arm exactly once");

    init_mc_get(&op, &clcf, &ctx, &request);
    op.request = NULL;
    send.pos = &byte;
    send.last = &byte + 1;
    op.send = &send;
    connection.data = &op;
    connection.send = send_error;
    write.timedout = 0;
    reset_observations();
    ngx_http_cache_turbo_mc_write(&write);
    CHECK(ngx_test_mc_arm_calls == 1 && op.unconnected == 0,
          "memcached send-error composition must arm once and consume state");
    CHECK(ngx_test_mc_done_calls == 1 && ngx_test_phase_calls == 0,
          "memcached fire-and-forget send error must only tear down its op");

    init_mc_get(&op, &clcf, &ctx, &request);
    reset_observations();
    ngx_http_cache_turbo_mc_get_finish(&op, NGX_ERROR, NULL, 0);
    check_mc_get_completion(&op, &ctx, &request,
        "direct memcached read failure must still own one backoff arm");
}

static void
test_memcached_drain_ownership(void)
{
    static const u_char reply[] = "STORED\r\n";
    ngx_http_cache_turbo_loc_conf_t clcf;
    ngx_http_cache_turbo_ctx_t      ctx;
    ngx_http_cache_turbo_mc_op_t    op;
    ngx_http_request_t              request;
    ngx_connection_t                connection;
    ngx_pool_t                      pool;
    ngx_event_t                     read, write;

    init_request(&request, &connection, &pool, &read, &write);
    init_mc_get(&op, &clcf, &ctx, &request);
    op.request = NULL;
    connection.data = &op;
    connection.recv = scripted_recv;
    reset_observations();
    test_recv_result = 0;
    ngx_http_cache_turbo_mc_read_drain(&read);
    CHECK(ngx_test_mc_arm_calls == 1 && op.unconnected == 0,
          "memcached drain zero-byte failure must arm once and consume state");
    CHECK(ngx_test_mc_done_calls == 1 && op.clean == 0,
          "memcached drain zero-byte failure must close through op_done unclean");

    init_mc_get(&op, &clcf, &ctx, &request);
    op.request = NULL;
    connection.data = &op;
    connection.recv = scripted_recv;
    reset_observations();
    test_recv_data = reply;
    test_recv_len = sizeof(reply) - 1;
    test_recv_result = (ssize_t) (sizeof(reply) - 1);
    ngx_http_cache_turbo_mc_read_drain(&read);
    CHECK(ngx_test_mc_arm_calls == 0 && ngx_test_mc_clear_calls == 1
              && op.unconnected == 0,
          "memcached drain first reply byte must clear, never arm, backoff state");
    CHECK(op.clean == 1 && ngx_test_mc_done_calls == 1,
          "memcached complete first reply must remain poolable and tear down once");
}

static void
init_redis(ngx_http_cache_turbo_redis_op_t *op,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_request_t *r, ngx_pool_t *pool)
{
    memset(op, 0, sizeof(*op));
    memset(clcf, 0, sizeof(*clcf));
    memset(ctx, 0, sizeof(*ctx));
    clcf->redis_connect_backoff = 907;
    op->clcf = clcf;
    op->ctx = ctx;
    op->request = r;
    op->pool = pool;
    op->rpool = pool;
    op->unconnected = 1;
}

static void
check_redis_resume(ngx_http_cache_turbo_redis_op_t *op,
    ngx_http_request_t *r, const char *where)
{
    CHECK(ngx_test_redis_arm_calls == 1
              && ngx_test_redis_arm_addr == &op->clcf->redis_addr
              && ngx_test_redis_arm_delay == 907,
          where);
    CHECK(op->unconnected == 0,
          "Redis terminal classification must consume unconnected");
    CHECK(ngx_test_redis_done_calls == 1 && ngx_test_redis_done_op == op,
          "Redis terminal request must tear down exactly once");
    CHECK(ngx_test_phase_calls == 1 && ngx_test_posted_calls == 1
              && ngx_test_finalize_calls == 1
              && ngx_test_finalize_request == r
              && ngx_test_finalize_rc == NGX_DONE,
          "Redis terminal request must resume and release its park once");
}

static void
test_redis_get_and_lock_compositions(void)
{
    ngx_http_cache_turbo_loc_conf_t clcf;
    ngx_http_cache_turbo_ctx_t      ctx;
    ngx_http_cache_turbo_redis_op_t op;
    ngx_http_request_t              request;
    ngx_connection_t                connection;
    ngx_pool_t                      pool;
    ngx_event_t                     read, write;

    init_request(&request, &connection, &pool, &read, &write);
    init_redis(&op, &clcf, &ctx, &request, &pool);
    reset_observations();
    ngx_http_cache_turbo_redis_op_fail(&op);
    CHECK(ctx.l2_result == NGX_ERROR && ctx.l2_done == 1,
          "Redis op_fail GET must publish NGX_ERROR, not a negative miss");
    check_redis_resume(&op, &request,
        "Redis op_fail -> real get_finish must arm exactly once");

    init_redis(&op, &clcf, &ctx, &request, &pool);
    op.is_lock = 1;
    reset_observations();
    ngx_http_cache_turbo_redis_op_fail(&op);
    CHECK(ctx.lock_result == NGX_ERROR && ctx.lock_done == 1,
          "Redis op_fail lock must publish exact transport-failure state");
    check_redis_resume(&op, &request,
        "Redis op_fail -> real lock_finish must arm exactly once");

    init_redis(&op, &clcf, &ctx, &request, &pool);
    reset_observations();
    ngx_http_cache_turbo_redis_get_finish(&op, NGX_ERROR, NULL, 0);
    check_redis_resume(&op, &request,
        "direct Redis GET read failure must still arm exactly once");
}

static void
test_redis_smembers_zero_byte(void)
{
    ngx_http_cache_turbo_loc_conf_t clcf;
    ngx_http_cache_turbo_ctx_t      ctx;
    ngx_http_cache_turbo_redis_op_t op;
    ngx_http_request_t              request;
    ngx_connection_t                connection;
    ngx_pool_t                      pool;
    ngx_event_t                     read, write;

    init_request(&request, &connection, &pool, &read, &write);
    init_redis(&op, &clcf, &ctx, &request, &pool);
    op.members_cb = members_callback;
    op.members_data = (void *) (uintptr_t) 0x51;
    connection.data = &op;
    reset_observations();
    ngx_http_cache_turbo_redis_read_smembers(&read);

    CHECK(ngx_test_redis_arm_calls == 1 && op.unconnected == 0,
          "Redis SMEMBERS zero-byte fill failure must arm exactly once");
    CHECK(ngx_test_members_calls == 1 && ngx_test_members == NULL
              && ngx_test_nmembers == 0 && ngx_test_walk == NULL,
          "Redis SMEMBERS zero-byte failure must run its callback as empty");
    CHECK(ngx_test_redis_done_calls == 1 && ngx_test_phase_calls == 0
              && ngx_test_posted_calls == 1 && ngx_test_finalize_calls == 1
              && ngx_test_finalize_rc == ngx_test_members_result,
          "Redis SMEMBERS failure must tear down and finalize exactly once");

    init_redis(&op, &clcf, &ctx, &request, &pool);
    op.members_cb = members_callback;
    op.members_data = (void *) (uintptr_t) 0x51;
    reset_observations();
    ngx_http_cache_turbo_redis_op_fail(&op);
    CHECK(ngx_test_redis_arm_calls == 1,
          "Redis op_fail -> real SMEMBERS finish must not double-arm");
    CHECK(ngx_test_members_calls == 1 && ngx_test_redis_done_calls == 1,
          "Redis op_fail must retain SMEMBERS callback and cleanup");
}

static void
test_redis_drain_ownership(void)
{
    static const u_char reply[] = "+OK\r\n";
    ngx_http_cache_turbo_loc_conf_t clcf;
    ngx_http_cache_turbo_ctx_t      ctx;
    ngx_http_cache_turbo_redis_op_t op;
    ngx_http_request_t              request;
    ngx_connection_t                connection;
    ngx_pool_t                      pool;
    ngx_event_t                     read, write;

    init_request(&request, &connection, &pool, &read, &write);
    init_redis(&op, &clcf, &ctx, &request, &pool);
    op.request = NULL;
    connection.data = &op;
    connection.recv = scripted_recv;
    reset_observations();
    test_recv_result = 0;
    ngx_http_cache_turbo_redis_read_drain(&read);
    CHECK(ngx_test_redis_arm_calls == 1 && op.unconnected == 0,
          "Redis drain zero-byte failure must arm once and consume state");
    CHECK(ngx_test_redis_done_calls == 1 && op.clean == 0,
          "Redis drain zero-byte failure must close through op_done unclean");

    init_redis(&op, &clcf, &ctx, &request, &pool);
    op.request = NULL;
    connection.data = &op;
    connection.recv = scripted_recv;
    reset_observations();
    test_recv_data = reply;
    test_recv_len = sizeof(reply) - 1;
    test_recv_result = (ssize_t) (sizeof(reply) - 1);
    ngx_http_cache_turbo_redis_read_drain(&read);
    CHECK(ngx_test_redis_arm_calls == 0 && ngx_test_redis_clear_calls == 1
              && op.unconnected == 0,
          "Redis drain first reply byte must clear, never arm, backoff state");
    CHECK(op.clean == 1 && ngx_test_redis_done_calls == 1,
          "Redis complete first reply must remain poolable and tear down once");
}

int
main(void)
{
    test_warm_prerequisite_error();
    test_warm_schedule_error();
    test_memcached_compositions();
    test_memcached_drain_ownership();
    test_redis_get_and_lock_compositions();
    test_redis_smembers_zero_byte();
    test_redis_drain_ownership();

    fprintf(stderr, "terminal error compositions: %d failures\n", failures);
    return failures ? 1 : 0;
}
