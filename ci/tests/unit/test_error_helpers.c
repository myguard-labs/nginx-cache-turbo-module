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
ngx_int_t   ngx_test_del_event_result;
const char *ngx_test_redis_parse_cursor;
ngx_str_t  *ngx_test_redis_parse_members;
ngx_uint_t  ngx_test_redis_parse_nmembers;
ngx_int_t   ngx_test_redis_frame_scan_result;
size_t      ngx_test_redis_frame_scan_next;
ngx_int_t   ngx_test_redis_parse_array_result;
ngx_uint_t  ngx_test_redis_parse_array_calls;
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
            (void) fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,  \
                           msg);                                             \
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
          "walk completion must preserve callback data");
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
    ngx_test_del_event_result = NGX_OK;
    ngx_test_redis_parse_cursor = NULL;
    ngx_test_redis_parse_members = NULL;
    ngx_test_redis_parse_nmembers = 0;
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
    ngx_test_redis_frame_scan_next = 0;
    ngx_test_redis_parse_array_result = NGX_ERROR;
    ngx_test_redis_parse_array_calls = 0;
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
test_redis_sscan_zero_byte(void)
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
    ngx_http_cache_turbo_redis_read_sscan(&read);

    CHECK(ngx_test_redis_arm_calls == 1 && op.unconnected == 0,
          "Redis SSCAN zero-byte fill failure must arm exactly once");
    CHECK(ngx_test_members_calls == 1 && ngx_test_members == NULL
              && ngx_test_nmembers == 0 && ngx_test_walk == NULL,
          "Redis SSCAN zero-byte failure must run its callback as empty");
    CHECK(ngx_test_redis_done_calls == 1 && ngx_test_phase_calls == 0
              && ngx_test_posted_calls == 1 && ngx_test_finalize_calls == 1
              && ngx_test_finalize_rc == ngx_test_members_result,
          "Redis SSCAN failure must tear down and finalize exactly once");

    init_redis(&op, &clcf, &ctx, &request, &pool);
    op.members_cb = members_callback;
    op.members_data = (void *) (uintptr_t) 0x51;
    reset_observations();
    ngx_http_cache_turbo_redis_op_fail(&op);
    CHECK(ngx_test_redis_arm_calls == 1,
          "Redis op_fail -> real walk finish must not double-arm");
    CHECK(ngx_test_members_calls == 1 && ngx_test_redis_done_calls == 1,
          "Redis op_fail must retain walk callback and cleanup");
}

static void
test_redis_sscan_requires_exact_frame(void)
{
    static u_char reply[] = "*0\r\nJUNK";
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
    op.rbuf = reply;
    op.rlen = sizeof(reply) - 1;
    connection.data = &op;
    reset_observations();
    ngx_test_redis_fill_result = NGX_OK;
    ngx_test_redis_frame_scan_result = NGX_OK;
    ngx_test_redis_frame_scan_next = 4; /* complete *0 frame, then junk */
    ngx_test_redis_parse_array_result = NGX_OK;

    ngx_http_cache_turbo_redis_read_sscan(&read);

    CHECK(ngx_test_redis_parse_array_calls == 0,
          "SSCAN must reject trailing RESP bytes before parsing");
    CHECK(ngx_test_members_calls == 1 && ngx_test_members == NULL
              && ngx_test_nmembers == 0,
          "SSCAN trailing bytes must complete as a failed enumeration");

    init_redis(&op, &clcf, &ctx, &request, &pool);
    op.members_cb = members_callback;
    op.members_data = (void *) (uintptr_t) 0x51;
    op.rbuf = reply;
    op.rlen = 4;
    connection.data = &op;
    reset_observations();
    ngx_test_redis_fill_result = NGX_OK;
    ngx_test_redis_frame_scan_result = NGX_OK;
    ngx_test_redis_frame_scan_next = 4;
    ngx_test_redis_parse_array_result = NGX_OK;

    ngx_http_cache_turbo_redis_read_sscan(&read);

    CHECK(ngx_test_redis_parse_array_calls == 1,
          "SSCAN must still parse an exactly consumed RESP frame");
    /* The stub yields cursor "0", so completion -- not the rotate path -- is
     * the branch taken. Without this a reader that parsed the page and never
     * ran its terminal callback would pass. */
    CHECK(ngx_test_members_calls == 1,
          "SSCAN must complete the walk exactly once on a cursor-0 page");
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

/*
 * TODO-UNLINK-REPLY-WINDOW: a page callback that SUSPENDS the walk, exactly as
 * the real tag-purge page delivery does before launching its awaited UNLINK.
 * It parks the walk and returns NGX_AGAIN without launching anything, which is
 * the state read_sscan must handle: disarmed connection, walk left parked for a
 * completion that arrives later.
 */
static void (*sus_done)(void *, ngx_int_t);
static void  *sus_done_data;
static ngx_int_t  sus_suspend_rc;

static ngx_int_t
suspending_members_callback(ngx_http_request_t *r, void *data,
    ngx_str_t *members, ngx_uint_t nmembers,
    const ngx_http_cache_turbo_redis_walk_t *walk)
{
    (void) r;
    (void) data;
    (void) members;
    (void) nmembers;
    (void) walk;

    ngx_test_members_calls++;

    sus_suspend_rc = ngx_http_cache_turbo_redis_walk_suspend(&sus_done,
                                                             &sus_done_data);
    if (sus_suspend_rc != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_AGAIN;
}


/*
 * TODO-UNLINK-REPLY-WINDOW: the SSCAN connection must be DISARMED while its
 * walk is parked awaiting a page's UNLINK reply.
 *
 * This is the deterministic negative control for that fix, and it needs no
 * Redis. redis_write arms ngx_add_timer(c->read, redis_timeout) when it
 * finishes sending a page; if that timer and the read event survive the park,
 * they fire on their own schedule and re-enter read_sscan, whose walk_finish
 * destroys op->pool (the op lives in it) and finalizes the parked request --
 * while the UNLINK is still in flight on a separate connection holding both.
 *
 * The black-box hold test cannot go red against that, because its fault hook
 * (ngx_msleep) blocks the worker and the loop never runs during the park. Here
 * the assertion is direct: after read_sscan takes the NGX_AGAIN path, the read
 * event must be off the poller and its timer gone.
 *
 * A NON-terminal cursor is essential: a last page ("0") never suspends, so a
 * test left on the stub's default would assert this of a walk that completed
 * and pass against the un-disarmed code too.
 */
static void
test_redis_sscan_suspension_disarms_connection(void)
{
    static u_char                    reply[] = "*2\r\n";

    ngx_http_cache_turbo_loc_conf_t  clcf;
    ngx_http_cache_turbo_ctx_t       ctx;
    ngx_http_cache_turbo_redis_op_t  op;
    ngx_http_request_t               request;
    ngx_connection_t                 connection;
    ngx_pool_t                       pool;
    ngx_event_t                      read, write;
    ngx_str_t                        one_member;
    char                             oversized_cursor[
                                         sizeof(op.resume_cursor_buf) + 2];

    one_member.data = (u_char *) "m";
    one_member.len = 1;

    /* One byte longer than the inline resume buffer can hold. */
    memset(oversized_cursor, '7', sizeof(oversized_cursor) - 1);
    oversized_cursor[sizeof(oversized_cursor) - 1] = '\0';

    init_request(&request, &connection, &pool, &read, &write);
    init_redis(&op, &clcf, &ctx, &request, &pool);
    op.members_cb = suspending_members_callback;
    op.members_data = (void *) (uintptr_t) 0x51;
    op.rbuf = reply;
    op.rlen = sizeof(reply) - 1;
    connection.data = &op;
    reset_observations();

    ngx_test_redis_fill_result = NGX_OK;
    ngx_test_redis_frame_scan_result = NGX_OK;
    ngx_test_redis_frame_scan_next = (ngx_int_t) (sizeof(reply) - 1);
    ngx_test_redis_parse_array_result = NGX_OK;
    /* Non-terminal page with one member: the ONLY shape that reaches the
     * suspension branch. */
    ngx_test_redis_parse_cursor = "17";
    ngx_test_redis_parse_members = &one_member;
    ngx_test_redis_parse_nmembers = 1;

    sus_done = NULL;
    sus_done_data = NULL;
    sus_suspend_rc = NGX_ERROR;

    /* The state redis_write leaves behind after sending a page. */
    read.timer_set = 1;
    read.active = 1;

    ngx_http_cache_turbo_redis_read_sscan(&read);

    CHECK(ngx_test_members_calls == 1,
          "a non-terminal SSCAN page with members must reach the callback");
    CHECK(sus_suspend_rc == NGX_OK,
          "a page delivery must be able to suspend its own walk");
    CHECK(op.suspended == 1,
          "a callback that returned NGX_AGAIN must leave the walk suspended");

    /* THE assertions. Both go red against a suspension that does not disarm. */
    CHECK(read.timer_set == 0,
          "the SSCAN read TIMER must be deleted across the suspension: left "
          "armed it fires during the park and tears the walk down under the "
          "in-flight UNLINK");
    CHECK(read.active == 0,
          "the SSCAN read EVENT must be off the poller across the suspension: "
          "left registered, a peer close during the park re-enters read_sscan "
          "and tears the walk down under the in-flight UNLINK");

    /* The walk must be PARKED, not finished: no terminal callback, no teardown. */
    CHECK(ngx_test_redis_done_calls == 0,
          "a suspended walk must not be torn down while its UNLINK is pending");

    /* And the cursor really was saved for the resume, rather than left
     * pointing into the reply buffer the rotation frees. */
    CHECK(op.resume_cursor.len == 2
              && op.resume_cursor.data == op.resume_cursor_buf,
          "the next page's cursor must be COPIED into the op's own inline "
          "buffer, which outlives the suspension");

    /* CRITICAL (round 3): the OVERSIZED-CURSOR exit must be disarmed too.
     *
     * This is the case two human review rounds and the original control all
     * missed. That path rejects the page and returns without advancing, and it
     * used to do so BEFORE the disarm ran -- leaving the read timer armed and
     * the read event registered with the page's UNLINK already in flight, which
     * is exactly the use-after-free its own comment explains it is avoiding by
     * not calling walk_finish. A control that only covers the HAPPY suspension
     * cannot see that: the assertions must be made on every exit from the
     * block, not on the one the fix happened to be written for.
     *
     * A cursor of sizeof(resume_cursor_buf) + 1 bytes cannot come from Redis
     * (cursors are decimal u64 text), so this models the desynchronised or
     * hostile reply the rejection exists for. */
    init_redis(&op, &clcf, &ctx, &request, &pool);
    op.members_cb = suspending_members_callback;
    op.members_data = (void *) (uintptr_t) 0x51;
    op.rbuf = reply;
    op.rlen = sizeof(reply) - 1;
    connection.data = &op;
    reset_observations();
    ngx_test_redis_fill_result = NGX_OK;
    ngx_test_redis_frame_scan_result = NGX_OK;
    ngx_test_redis_frame_scan_next = (ngx_int_t) (sizeof(reply) - 1);
    ngx_test_redis_parse_array_result = NGX_OK;
    ngx_test_redis_parse_cursor = oversized_cursor;
    ngx_test_redis_parse_members = &one_member;
    ngx_test_redis_parse_nmembers = 1;
    read.timer_set = 1;
    read.active = 1;

    ngx_http_cache_turbo_redis_read_sscan(&read);

    CHECK(op.resume_doomed == 1,
          "an SSCAN cursor too long for the resume buffer must be REJECTED, "
          "not truncated into a different valid-looking cursor");
    CHECK(op.suspended == 1,
          "the rejected page must stay SUSPENDED: its UNLINK is in flight and "
          "holds the op, so only the resume may tear the walk down");

    /* THE assertions this case exists for -- identical to the happy path's,
     * because the hazard is identical. */
    CHECK(read.timer_set == 0,
          "the OVERSIZED-CURSOR exit must delete the read timer too: it "
          "returns with the UNLINK in flight, so a timer left armed fires into "
          "read_sscan and tears the walk down under the pending completion");
    CHECK(read.active == 0,
          "the OVERSIZED-CURSOR exit must take the read event off the poller "
          "too: left registered, a peer close re-enters read_sscan and tears "
          "the walk down under the pending completion");
    CHECK(ngx_test_redis_done_calls == 0,
          "a doomed suspension must not tear the walk down inline");

    /* NIT-E: the arm taken when the connection CANNOT be disarmed. The UNLINK
     * is already in flight and cannot be recalled, so the walk must stay
     * SUSPENDED and merely record the doom -- tearing it down here would free
     * the op the pending completion still holds, which is the very hazard the
     * disarm exists to avoid. */
    init_redis(&op, &clcf, &ctx, &request, &pool);
    op.members_cb = suspending_members_callback;
    op.members_data = (void *) (uintptr_t) 0x51;
    op.rbuf = reply;
    op.rlen = sizeof(reply) - 1;
    connection.data = &op;
    reset_observations();
    ngx_test_redis_fill_result = NGX_OK;
    ngx_test_redis_frame_scan_result = NGX_OK;
    ngx_test_redis_frame_scan_next = (ngx_int_t) (sizeof(reply) - 1);
    ngx_test_redis_parse_array_result = NGX_OK;
    ngx_test_redis_parse_cursor = "17";
    ngx_test_redis_parse_members = &one_member;
    ngx_test_redis_parse_nmembers = 1;
    ngx_test_del_event_result = NGX_ERROR;
    read.timer_set = 1;
    read.active = 1;

    ngx_http_cache_turbo_redis_read_sscan(&read);

    CHECK(op.resume_doomed == 1,
          "a suspension that cannot disarm the connection must record the doom "
          "for the resume to act on");
    CHECK(op.suspended == 1,
          "a doomed suspension must stay SUSPENDED: the UNLINK is in flight "
          "and holds the op, so only the resume may tear the walk down");
    CHECK(ngx_test_redis_done_calls == 0,
          "a doomed suspension must not tear the walk down inline");

    /* Restore the stubs for every later test. */
    ngx_test_del_event_result = NGX_OK;
    ngx_test_redis_parse_cursor = NULL;
    ngx_test_redis_parse_members = NULL;
    ngx_test_redis_parse_nmembers = 0;
}


/*
 * TODO-UNLINK-REPLY-WINDOW / BLOCKER-A: the awaited page's completion must be
 * NEUTRALIZED when the request dies under it.
 *
 * The tagpurge lives in r->pool. The walk parks the request with
 * r->main->count++, which keeps a NORMALLY completing request alive -- but a
 * TERMINATE (worker graceful shutdown, client abort) does not honour that
 * refcount, so r->pool can be destroyed while the page's UNLINK is still in
 * flight on its own connection holding the tagpurge as completion data.
 *
 * The protocol that closes it: the completion is handed a TOKEN allocated from
 * the UNLINK op's own pool -- destroyed by op_done strictly after the completion
 * runs, so reading it is always safe -- and a cleanup on r->pool clears the
 * token's `alive` bit during teardown, before the memory goes. The completion
 * reads `alive` FIRST and, when clear, touches nothing that lived in r->pool.
 *
 * ⚠ SCOPE. This asserts the token PROTOCOL, not the production completion.
 * ngx_http_cache_turbo_tag_purge_page_unlinked lives in purge.c, which this
 * shim does not extract; reaching it would need the real tagpurge_t, whose
 * fields this shim would have to redeclare by hand -- and a hand-copied struct
 * that drifts from the real one is precisely the divergence these shims exist
 * to rule out. What is pinned here is that clearing `alive` before the
 * completion runs is observable to it, and that the ordering works both ways.
 * The production wiring is covered by the black-box tests.
 */
typedef struct {
    void      *tp;
    void      *cln;
    void      *page_pool;
    unsigned   alive:1;
} test_await_t;

static ngx_uint_t  test_await_touched_tp;
static ngx_uint_t  test_await_freed_pool;

static void
test_await_gone(void *data)
{
    test_await_t  *aw = data;

    aw->alive = 0;
    aw->tp = NULL;
}

static void
test_await_completion(void *data)
{
    test_await_t  *aw = data;

    if (!aw->alive) {
        if (aw->page_pool) {
            test_await_freed_pool++;
            aw->page_pool = NULL;
        }
        return;
    }

    test_await_touched_tp++;
    aw->alive = 0;
    if (aw->page_pool) {
        test_await_freed_pool++;
        aw->page_pool = NULL;
    }
}

static void
test_redis_await_token_survives_request_teardown(void)
{
    test_await_t  aw;
    int           tp_object = 0;
    int           pool_object = 0;

    /* --- request dies FIRST, completion arrives after --- */
    aw.tp = &tp_object;
    aw.cln = NULL;
    aw.page_pool = &pool_object;
    aw.alive = 1;
    test_await_touched_tp = 0;
    test_await_freed_pool = 0;

    test_await_gone(&aw);                 /* r->pool cleanup runs */
    test_await_completion(&aw);           /* UNLINK reply lands after */

    CHECK(test_await_touched_tp == 0,
          "a completion arriving after the request died must NOT dereference "
          "the tagpurge: it lives in the freed r->pool");
    CHECK(aw.tp == NULL,
          "the cleanup must drop the tagpurge pointer, not merely flag it");
    CHECK(test_await_freed_pool == 1,
          "the page scratch is a standalone pool the request teardown does not "
          "own, so the neutralized completion must still release it -- exactly "
          "once");

    /* --- completion arrives FIRST, request teardown after --- */
    aw.tp = &tp_object;
    aw.cln = NULL;
    aw.page_pool = &pool_object;
    aw.alive = 1;
    test_await_touched_tp = 0;
    test_await_freed_pool = 0;

    test_await_completion(&aw);           /* normal ordering */
    test_await_gone(&aw);                 /* request finalizes afterwards */

    CHECK(test_await_touched_tp == 1,
          "a completion on a LIVE request must settle the page normally");
    CHECK(test_await_freed_pool == 1,
          "the page scratch must be released exactly once on this ordering too");
}


int
main(void)
{
    test_warm_prerequisite_error();
    test_warm_schedule_error();
    test_memcached_compositions();
    test_memcached_drain_ownership();
    test_redis_get_and_lock_compositions();
    test_redis_sscan_zero_byte();
    test_redis_sscan_requires_exact_frame();
    test_redis_drain_ownership();
    test_redis_sscan_suspension_disarms_connection();
    test_redis_await_token_survives_request_teardown();

    (void) fprintf(stderr, "terminal error compositions: %d failures\n",
                   failures);
    return failures ? 1 : 0;
}
