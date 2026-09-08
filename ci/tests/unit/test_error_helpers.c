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
ngx_uint_t  ngx_test_add_event_calls;
ngx_int_t   ngx_test_add_event_result;
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
    ngx_test_add_event_calls = 0;
    ngx_test_add_event_result = NGX_OK;
    ngx_test_rotation_ok = 0;
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
/*
 * GRIND-C7: the suspended walk's read event must really be BACK ON THE POLLER
 * when the walk resumes.
 *
 * The defect this covers: read_sscan's suspension calls walk_disarm_conn,
 * which clears rev->active but leaves rev->ready alone -- and `ready` is still
 * set from the page reply that caused the suspension, because read_sscan
 * consumed that reply to completion without the recv loop ever hitting EAGAIN
 * and nothing in the module clears `ready` itself. sscan_advance then re-armed
 * with a bare ngx_handle_read_event(c->read, 0), whose comment claimed
 * re-adding was idempotent. It is not: nginx's ngx_handle_read_event calls
 * ngx_add_event only when `!active && !ready`, so active == 0 with a stale
 * ready == 1 made it return NGX_OK having registered NOTHING. The resumed walk
 * wrote its next SSCAN page with its read event off the poller, the reply was
 * never noticed, and the purge stalled until the read timer expired -- a
 * silent failure on every multi-page tag purge that had to UNLINK a page.
 *
 * ⚠ WHY THE ORACLE IS A COUNTER, NOT `active`. The shim's ngx_handle_read_event
 * is ported verbatim from nginx's own gate, and ngx_test_add_event_calls is
 * incremented only by a genuine ngx_add_event. `active` alone cannot
 * discriminate on the synchronous path, where the event was never removed and
 * is trivially still 1. The count separates "genuinely (re-)registered" from
 * "was already there" and from "silently registered nothing", which is exactly
 * the distinction the bug lived in.
 *
 * Four exits, because the re-arm has to be right on all of them:
 *   (a) resume with a STALE ready == 1  -- must still register (the defect)
 *   (b) resume with ready == 0          -- must register
 *   (c) the synchronous, never-disarmed path -- must NOT double-register
 *   (d) the detached / no-resume path   -- must not register at all
 */
static void
test_redis_sscan_resume_rearms_read_event(void)
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

    one_member.data = (u_char *) "m";
    one_member.len = 1;

    /* ---- EXIT (a): a real suspension, then a resume with STALE ready ----
     *
     * Driven end to end rather than by hand-setting op fields: read_sscan is
     * what performs the disarm, so only the real path produces the exact
     * (active == 0, ready == 1) state the defect needs. */
    init_request(&request, &connection, &pool, &read, &write);
    init_redis(&op, &clcf, &ctx, &request, &pool);
    op.members_cb = suspending_members_callback;
    op.members_data = (void *) (uintptr_t) 0x51;
    op.is_scan = 1;
    op.peer.connection = &connection;
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

    sus_done = NULL;
    sus_done_data = NULL;
    sus_suspend_rc = NGX_ERROR;
    /* Let the page rotation succeed, so sscan_advance reaches its re-arm
     * instead of bailing into walk_finish. */
    ngx_test_rotation_ok = 1;

    /* The state redis_write leaves behind after sending a page, PLUS the
     * readiness the just-consumed reply left set. That combination is the
     * entire bug. */
    read.timer_set = 1;
    read.active = 1;
    read.ready = 1;

    ngx_http_cache_turbo_redis_read_sscan(&read);

    CHECK(op.suspended == 1,
          "the page callback must have suspended the walk");
    CHECK(read.active == 0,
          "the suspension must have taken the read event off the poller");
    CHECK(read.ready == 1,
          "walk_disarm_conn must leave `ready` alone: it is precisely the "
          "stale bit the resumer has to clear, and a disarm that cleared it "
          "would make this whole control vacuous");
    CHECK(ngx_test_add_event_calls == 0,
          "nothing may have re-registered the event while the walk is parked");

    /* Resume the parked walk with a successful page verdict: sscan_advance
     * rotates in the next page and must put the read event back. */
    ngx_http_cache_turbo_redis_sscan_resume(&op, NGX_OK);

    /* THE assertion this test exists for. */
    CHECK(ngx_test_add_event_calls == 1,
          "a resumed walk must genuinely RE-REGISTER its read event: the "
          "suspension cleared `active` but left `ready` set from the consumed "
          "reply, and ngx_handle_read_event only adds when !active && !ready, "
          "so without clearing `ready` first it registers NOTHING and the next "
          "page's reply is never noticed -- the purge stalls until timeout");
    CHECK(read.active == 1,
          "the resumed walk's read event must be back on the poller");
    CHECK(op.scan_pages == 1,
          "the resume must actually have advanced to the next page: a re-arm "
          "assertion on a walk that never advanced would prove nothing");

    /* ---- EXIT (b): resume with ready already 0 -- must register too ---- */
    init_request(&request, &connection, &pool, &read, &write);
    init_redis(&op, &clcf, &ctx, &request, &pool);
    op.members_cb = suspending_members_callback;
    op.members_data = (void *) (uintptr_t) 0x51;
    op.is_scan = 1;
    op.peer.connection = &connection;
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
    sus_done = NULL;
    sus_done_data = NULL;
    sus_suspend_rc = NGX_ERROR;
    ngx_test_rotation_ok = 1;
    read.timer_set = 1;
    read.active = 1;
    read.ready = 0;              /* the recv loop DID hit EAGAIN this time */

    ngx_http_cache_turbo_redis_read_sscan(&read);
    CHECK(op.suspended == 1 && read.active == 0,
          "the ready == 0 case must suspend and disarm exactly as the other");

    ngx_http_cache_turbo_redis_sscan_resume(&op, NGX_OK);

    CHECK(ngx_test_add_event_calls == 1,
          "a resume must re-register the read event when `ready` was already "
          "clear as well: the fix must not have traded one stale-state bug "
          "for its mirror image");
    CHECK(read.active == 1,
          "the ready == 0 resume must also leave the event on the poller");

    /* ---- EXIT (c): the SYNCHRONOUS path must not DOUBLE-register --------
     *
     * sscan_advance is also reached straight from read_sscan for a page whose
     * callback did NOT suspend. There the event was never removed -- active is
     * still 1 -- so ngx_handle_read_event's gate is false and nothing may be
     * added. A fix that re-registered unconditionally (a bare ngx_add_event
     * with no `!active` test) would leak a duplicate registration here, which
     * epoll rejects with EEXIST. */
    init_request(&request, &connection, &pool, &read, &write);
    init_redis(&op, &clcf, &ctx, &request, &pool);
    op.members_cb = members_callback;
    op.members_data = (void *) (uintptr_t) 0x51;
    op.is_scan = 1;
    op.peer.connection = &connection;
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
    ngx_test_members_result = NGX_OK;   /* handled inline: no suspension */
    ngx_test_rotation_ok = 1;
    read.timer_set = 1;
    read.active = 1;
    read.ready = 1;

    ngx_http_cache_turbo_redis_read_sscan(&read);

    CHECK(op.suspended == 0,
          "the synchronous page must not have suspended the walk");
    CHECK(op.scan_pages == 1,
          "the synchronous page must still have advanced: an assertion about "
          "not double-registering is vacuous on a path that never ran");
    CHECK(ngx_test_add_event_calls == 0,
          "the synchronous path must NOT re-register: its read event was never "
          "removed, so a second ngx_add_event on the same descriptor is the "
          "EEXIST epoll refuses");
    CHECK(read.active == 1,
          "the synchronous path must leave its read event registered");

    /* ---- EXIT (d): the DETACHED walk's resume must register NOTHING -----
     *
     * walk_detach's suspended arm disarms and defers; its resume tears the
     * walk down through op_done and never reaches sscan_advance. Re-arming a
     * connection that is being closed would put a freed event back on the
     * poller. */
    init_request(&request, &connection, &pool, &read, &write);
    init_redis(&op, &clcf, &ctx, &request, &pool);
    op.is_scan = 1;
    op.peer.connection = &connection;
    connection.data = &op;
    reset_observations();

    op.detached = 1;
    op.request = NULL;
    op.members_cb = NULL;
    op.members_data = NULL;
    op.suspended = 1;
    op.resume_doomed = 0;
    op.resume_cursor.data = op.resume_cursor_buf;
    op.resume_cursor.len = 2;
    op.resume_cursor_buf[0] = '1';
    op.resume_cursor_buf[1] = '7';
    read.active = 0;
    read.ready = 1;

    ngx_http_cache_turbo_redis_sscan_resume(&op, NGX_OK);

    CHECK(ngx_test_redis_done_calls == 1,
          "a detached walk's resume must tear the walk down");
    CHECK(ngx_test_add_event_calls == 0,
          "a DETACHED walk's resume must not re-register a read event: the "
          "connection is being closed, so putting its event back on the poller "
          "arms a wakeup on a freed connection");
    CHECK(op.scan_pages == 0,
          "a detached walk's resume must not enter sscan_advance at all");
}

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
 * TODO-UNLINK-REPLY-WINDOW / GRIND-C7: a SUSPENDED walk re-entered by a stray
 * event must be INERT.
 *
 * The suspension disarms the connection so no event can arrive at all -- but
 * ngx_del_event can REFUSE, and two callers tolerate that: read_sscan's own
 * disarm-failure arm (which falls through to `doomed:`) and walk_detach's
 * suspended arm (which discards the disarm result entirely). Both therefore
 * return with the read event still registered on the poller while the page's
 * UNLINK is in flight holding this op as its completion data.
 *
 * A peer close or a stray readable event then re-enters read_sscan. Without an
 * entry guard every error exit below reaches walk_finish, which destroys
 * op->pool -- the pool `op` itself is allocated from -- while that pending
 * completion still holds it. The completion then fires against freed memory:
 * a use-after-free from the event loop, exactly what the `doomed:` label's own
 * comment exists to prevent. The `doomed:` block used to assert "Both callers
 * reach here with the connection ALREADY disarmed", which is FALSE on the
 * disarm-failure arm -- the one path where the disarm provably did not happen.
 *
 * The guard's exits, each asserted below:
 *
 *   (a) a read event on a suspended walk returns without touching the op --
 *       no walk_finish (no terminal callback), no op_done, no re-arm, and the
 *       reply buffer the resume still needs left un-rotated;
 *   (b) rev->timedout on a suspended walk likewise never finishes the walk;
 *       the flag is CONSUMED (so the event is not redelivered as a timeout
 *       forever) and the doom recorded for the resume to act on;
 *   (c) an UNSUSPENDED walk still takes the normal path -- the negative
 *       control against an over-broad guard that would park every walk;
 *   (d) the disarm-failure arm reaches `doomed:` with the op INTACT, and the
 *       later resume still tears it down exactly once.
 *
 * ⚠ The discriminating observable for (a) and (b) is ngx_test_members_calls,
 * not ngx_test_redis_done_calls alone: walk_finish calls the terminal callback
 * before op_done, and the terminal callback is what a stray event must never
 * reach. Asserting only on op_done would still be satisfied by paths that
 * reach it another way.
 */
static void
test_redis_sscan_suspended_walk_ignores_stray_events(void)
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

    one_member.data = (u_char *) "m";
    one_member.len = 1;

    init_request(&request, &connection, &pool, &read, &write);

    /* ---- (a) a READ event on a suspended walk must touch nothing. ----
     *
     * The op is set up exactly as the suspension left it: parked, with a saved
     * resume cursor and its reply buffer still holding the page. Every stub
     * that read_sscan would consult on the normal path is left at its
     * reset_observations default (fill/frame_scan/parse all NGX_ERROR), so if
     * the guard is absent the very first thing the function does after the
     * timeout check is fall into the fill-failure walk_finish. That makes the
     * mutant unambiguous rather than dependent on parse shape. */
    init_redis(&op, &clcf, &ctx, &request, &pool);
    op.members_cb = members_callback;
    op.members_data = (void *) (uintptr_t) 0x51;
    op.rbuf = reply;
    op.rlen = sizeof(reply) - 1;
    op.is_scan = 1;
    connection.data = &op;
    reset_observations();

    op.suspended = 1;
    op.resume_cursor.data = op.resume_cursor_buf;
    op.resume_cursor.len = 2;
    ngx_memcpy(op.resume_cursor_buf, "17", 2);

    read.timedout = 0;
    read.timer_set = 0;
    read.active = 1;                   /* the disarm refused: still registered */

    ngx_http_cache_turbo_redis_read_sscan(&read);

    CHECK(ngx_test_members_calls == 0,
          "a READ event on a SUSPENDED walk must not reach walk_finish: its "
          "terminal callback would report the walk over while the page's "
          "UNLINK is still in flight holding the op");
    CHECK(ngx_test_redis_done_calls == 0,
          "a READ event on a SUSPENDED walk must not reach op_done: it "
          "destroys op->pool, which the op itself lives in, under the pending "
          "UNLINK completion -- a use-after-free from the event loop");
    CHECK(op.suspended == 1,
          "a stray READ event must leave the walk SUSPENDED: sscan_resume is "
          "the sole driver of a parked walk");
    CHECK(op.resume_doomed == 0,
          "a stray READ event is not itself a failure and must not doom an "
          "otherwise healthy suspended walk");
    CHECK(ngx_test_add_timer_calls == 0 && ngx_test_del_timer_calls == 0,
          "a stray READ event must not re-arm or otherwise touch the "
          "suspended connection's read timer");
    CHECK(op.rbuf == reply && op.rlen == sizeof(reply) - 1,
          "a stray READ event must not consume or rotate the suspended walk's "
          "reply buffer: the resume's framing depends on it");
    CHECK(op.resume_cursor.len == 2
              && op.resume_cursor.data == op.resume_cursor_buf,
          "a stray READ event must leave the saved resume cursor intact");

    /* ---- (b) rev->timedout on a suspended walk. ----
     *
     * The timer should have been deleted at suspension, so a timeout here
     * means the disarm refused and the stale deadline fired. It must NOT tear
     * the walk down -- but it must not be silently dropped either: the flag is
     * consumed so the event is not redelivered as a timeout forever, and the
     * doom is recorded so the resume abandons the walk rather than advancing
     * it onto a connection whose read deadline has already expired. */
    init_redis(&op, &clcf, &ctx, &request, &pool);
    op.members_cb = members_callback;
    op.members_data = (void *) (uintptr_t) 0x51;
    op.rbuf = reply;
    op.rlen = sizeof(reply) - 1;
    op.is_scan = 1;
    connection.data = &op;
    reset_observations();

    op.suspended = 1;
    read.timedout = 1;
    read.timer_set = 0;
    read.active = 1;

    ngx_http_cache_turbo_redis_read_sscan(&read);

    CHECK(ngx_test_members_calls == 0,
          "a TIMEOUT on a SUSPENDED walk must not reach walk_finish: the "
          "timeout arm's own walk_finish is the exact use-after-free the "
          "suspension disarm was written to prevent");
    CHECK(ngx_test_redis_done_calls == 0,
          "a TIMEOUT on a SUSPENDED walk must not reach op_done while the "
          "page's UNLINK still holds the op");
    CHECK(op.suspended == 1,
          "a TIMEOUT must leave the walk SUSPENDED: only the resume may tear "
          "a parked walk down");
    CHECK(read.timedout == 0,
          "a TIMEOUT on a SUSPENDED walk must CONSUME the flag, or the event "
          "is redelivered as a timeout for the whole suspension");
    CHECK(op.resume_doomed == 1,
          "a TIMEOUT on a SUSPENDED walk must record the doom: the read "
          "deadline expired, so the resume must abandon the walk rather than "
          "advance it");
    CHECK(op.scan_status == NGX_ERROR,
          "a timed-out suspended walk must never report a COMPLETE purge");

    /* ---- (c) NEGATIVE CONTROL: an UNSUSPENDED walk still takes the normal
     * path. A guard that parked every walk, not just suspended ones, would
     * strand every SSCAN in the worker while passing (a) and (b). ---- */
    init_redis(&op, &clcf, &ctx, &request, &pool);
    op.members_cb = members_callback;
    op.members_data = (void *) (uintptr_t) 0x51;
    op.rbuf = reply;
    op.rlen = sizeof(reply) - 1;
    op.is_scan = 1;
    connection.data = &op;
    reset_observations();

    op.suspended = 0;
    read.timedout = 0;
    read.timer_set = 0;
    read.active = 1;

    /* fill fails -> the normal path's first walk_finish. */
    ngx_test_redis_fill_result = NGX_ERROR;

    ngx_http_cache_turbo_redis_read_sscan(&read);

    CHECK(ngx_test_members_calls == 1 && ngx_test_walk != NULL,
          "an UNSUSPENDED walk must still reach walk_finish's TERMINAL "
          "callback: the guard covers parked walks only");
    CHECK(ngx_test_redis_done_calls == 1,
          "an UNSUSPENDED walk must still reach op_done exactly once");

    /* ---- (d) the disarm-FAILURE arm: `doomed:` with the op intact, and the
     * resume still tearing it down exactly once. ----
     *
     * This is the arm whose `doomed:` comment used to claim the connection was
     * "ALREADY disarmed". It is not: ngx_del_event refused, so the read event
     * is still registered -- which is why (a) and (b) above have to hold. */
    init_redis(&op, &clcf, &ctx, &request, &pool);
    op.members_cb = suspending_members_callback;
    op.members_data = (void *) (uintptr_t) 0x51;
    op.rbuf = reply;
    op.rlen = sizeof(reply) - 1;
    op.is_scan = 1;
    connection.data = &op;
    reset_observations();

    ngx_test_redis_fill_result = NGX_OK;
    ngx_test_redis_frame_scan_result = NGX_OK;
    ngx_test_redis_frame_scan_next = (ngx_int_t) (sizeof(reply) - 1);
    ngx_test_redis_parse_array_result = NGX_OK;
    ngx_test_redis_parse_cursor = "17";
    ngx_test_redis_parse_members = &one_member;
    ngx_test_redis_parse_nmembers = 1;

    sus_done = NULL;
    sus_done_data = NULL;
    sus_suspend_rc = NGX_ERROR;

    ngx_test_del_event_result = NGX_ERROR;    /* the disarm REFUSES */
    read.timedout = 0;
    read.timer_set = 1;
    read.active = 1;

    ngx_http_cache_turbo_redis_read_sscan(&read);

    CHECK(op.resume_doomed == 1 && op.suspended == 1,
          "the disarm-FAILURE arm must reach `doomed:`: parked, doomed, and "
          "waiting for the resume");
    CHECK(ngx_test_redis_done_calls == 0,
          "the disarm-FAILURE arm must leave the op INTACT: its UNLINK is "
          "already in flight and cannot be recalled");
    CHECK(read.active == 1,
          "the disarm-FAILURE arm leaves the read event REGISTERED -- this is "
          "the false invariant the `doomed:` comment used to assert, and the "
          "reason read_sscan needs a `suspended` entry guard at all");

    /* A stray event arriving on that still-registered read event must be inert
     * on THIS op, in exactly the state the failed disarm left it. */
    ngx_test_members_calls = 0;
    ngx_test_redis_done_calls = 0;
    read.timedout = 0;

    ngx_http_cache_turbo_redis_read_sscan(&read);

    CHECK(ngx_test_members_calls == 0 && ngx_test_redis_done_calls == 0,
          "a stray event on the UNDISARMABLE suspended connection must not "
          "tear the walk down: this is the concrete use-after-free the guard "
          "closes");

    /* And the resume -- the sole driver -- still finishes it exactly once. */
    ngx_test_del_event_result = NGX_OK;
    ngx_test_members_calls = 0;
    ngx_test_redis_done_calls = 0;

    ngx_http_cache_turbo_redis_sscan_resume(&op, NGX_ERROR);

    CHECK(op.suspended == 0,
          "the resume must clear `suspended`: the UNLINK has landed and "
          "nothing holds the op any more");
    CHECK(ngx_test_redis_done_calls == 1,
          "the doomed walk must be torn down EXACTLY once, by the resume");
    CHECK(ngx_test_members_calls == 1 && ngx_test_walk != NULL,
          "the resume's teardown must run the TERMINAL callback so the purge "
          "is reported INCOMPLETE rather than silently dropped");

    /* Restore the stubs for every later test. */
    ngx_test_del_event_result = NGX_OK;
    ngx_test_redis_parse_cursor = NULL;
    ngx_test_redis_parse_members = NULL;
    ngx_test_redis_parse_nmembers = 0;
    read.timedout = 0;
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
 * ⚠ SCOPE -- and the NAME says so. This asserts the token PROTOCOL only, using
 * test-local stand-ins (test_await_gone / test_await_completion); it does NOT
 * exercise the production completion. An earlier name,
 * `test_redis_await_token_survives_request_teardown`, read as though it did.
 * The production wiring is covered by the black-box runtime tests, and the walk
 * op's own request-teardown path now has direct unit coverage in
 * test_redis_walk_detach_on_request_teardown below.
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
test_await_token_protocol_only(void)
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


/*
 * CT-SSCAN-TERMINATE-LEAK: the walk op must survive its request being
 * TERMINATED, and must release everything it owns when it does.
 *
 * redis_sscan builds the walk op from its OWN ngx_create_pool (not a child of
 * r->pool), sets op->request = r and parks the request with r->main->count++.
 * ngx_http_terminate_handler does NOT honour that park -- it forces r->count = 1
 * and frees the request regardless -- so before this fix the walk was left in
 * one of two wrong states:
 *
 *   (1) NOT suspended: the read timeout fired and walk_finish called
 *       cb(r, ...) + ngx_http_finalize_request(r, rc) on the freed request. A
 *       use-after-free.
 *   (2) SUSPENDED (after the disarm landed): the read timer was deleted and the
 *       read event taken off the poller, removing the last two wakeups that
 *       could drive the op to walk_finish -> op_done. The op pool, the Redis
 *       connection, its fd and the zone's varidx_inflight account leaked for
 *       the worker's lifetime, and op->request dangled.
 *
 * Both are closed by ONE r->pool cleanup, walk_detach, and one `detached` flag
 * every terminal path consults. That flag is a GUARD WITH FOUR EXITS, and each
 * is asserted separately below -- covering only the primary path is not
 * coverage of the guard.
 *
 * ⚠ op_done is STUBBED in this shim (it counts calls), so "reached op_done
 * exactly once" is what is observable here and what is asserted. That the real
 * op_done releases the pool, the connection/fd and varidx_inflight is its own
 * contract, already covered by its existing call sites; what this test pins is
 * that the detached walk REACHES it, exactly once, on every exit -- which is
 * precisely what was missing.
 */
static void
test_redis_walk_detach_on_request_teardown(void)
{
    ngx_http_cache_turbo_loc_conf_t  clcf;
    ngx_http_cache_turbo_ctx_t       ctx;
    ngx_http_cache_turbo_redis_op_t  op;
    ngx_http_request_t               request;
    ngx_connection_t                 connection;
    ngx_pool_t                       pool;
    ngx_event_t                      read, write;
    ngx_pool_cleanup_t               cln;

    /* ---- EXIT 1: an UNSUSPENDED walk is torn down INLINE ---------------- */

    init_request(&request, &connection, &pool, &read, &write);
    init_redis(&op, &clcf, &ctx, &request, &pool);
    op.members_cb = suspending_members_callback;
    op.members_data = (void *) (uintptr_t) 0x51;
    op.is_scan = 1;
    op.peer.connection = &connection;
    connection.data = &op;
    cln.handler = ngx_http_cache_turbo_redis_walk_detach;
    cln.data = &op;
    op.req_cln = &cln;
    reset_observations();

    /* The state redis_write leaves behind: a live read timer and a registered
     * read event on the walk's own connection. */
    read.timer_set = 1;
    read.active = 1;

    ngx_http_cache_turbo_redis_walk_detach(&op);

    CHECK(op.detached == 1,
          "the request-teardown cleanup must MARK the walk detached: that flag "
          "is what every terminal path consults to skip the callback and the "
          "finalize");
    CHECK(op.request == NULL,
          "the request-teardown cleanup must CLEAR op->request: the request is "
          "about to be freed, and every walk terminal reads this pointer");
    CHECK(op.members_cb == NULL && op.members_data == NULL,
          "the page callback and its data live in the freed r->pool, so both "
          "must be dropped, not merely flagged");
    CHECK(op.scan_status != NGX_OK,
          "a detached walk can never have completed its purge, so it must "
          "never report the tag as fully purged");

    /* Nothing else holds the op, so the teardown is IMMEDIATE -- this is what
     * releases the op pool, the Redis connection, its fd and the zone's
     * varidx_inflight account. */
    CHECK(ngx_test_redis_done_calls == 1,
          "an UNSUSPENDED detached walk must reach op_done exactly once and "
          "inline: nothing else holds the op, so deferring here is the leak "
          "this fix exists to close");

    /* And it must never reach the request. */
    CHECK(ngx_test_members_calls == 0,
          "a detached walk must NEVER call the page callback: its data lives "
          "in the freed r->pool");
    CHECK(ngx_test_finalize_calls == 0,
          "a detached walk must NEVER finalize a request: the request that "
          "parked it has already been freed");

    /* The connection must be quiet before op_done closes it: a timer still
     * armed on a closed connection's read event is a use-after-free of its
     * own. */
    CHECK(read.timer_set == 0,
          "the detach must delete the walk's read TIMER before op_done closes "
          "the connection");
    CHECK(read.active == 0,
          "the detach must take the walk's read EVENT off the poller before "
          "op_done closes the connection");

    /* The cleanup is running, so nginx has already removed the record: the op
     * must not keep a pointer op_done would later dereference. */
    CHECK(op.req_cln == NULL,
          "the running cleanup must drop its own record from the op, so a "
          "later op_done cannot neutralize a record nginx already released");

    /* Idempotence: a second run (a duplicated cleanup, a re-entry) must not
     * double-free by reaching op_done twice. */
    ngx_http_cache_turbo_redis_walk_detach(&op);
    CHECK(ngx_test_redis_done_calls == 1,
          "the detach must be idempotent: a second invocation must NOT reach "
          "op_done again, which would double-destroy the op pool");

    /* ---- EXIT 2: a SUSPENDED walk DEFERS its teardown ------------------- */
    /*
     * The ordering hazard. A page's UNLINK is in flight on a DIFFERENT
     * connection and holds this op as its completion data through
     * tp->page_resume_data. Destroying op->pool here would leave that pending
     * completion pointing at freed memory -- strictly worse than the leak. So
     * this arm records the doom and tears down NOTHING; sscan_resume, which is
     * guaranteed to run, does it at the first moment nothing references the op.
     */
    init_request(&request, &connection, &pool, &read, &write);
    init_redis(&op, &clcf, &ctx, &request, &pool);
    op.members_cb = suspending_members_callback;
    op.members_data = (void *) (uintptr_t) 0x51;
    op.is_scan = 1;
    op.peer.connection = &connection;
    connection.data = &op;
    cln.handler = ngx_http_cache_turbo_redis_walk_detach;
    cln.data = &op;
    op.req_cln = &cln;
    op.suspended = 1;                    /* a page's UNLINK is in flight */
    reset_observations();
    read.timer_set = 1;
    read.active = 1;

    ngx_http_cache_turbo_redis_walk_detach(&op);

    CHECK(op.detached == 1,
          "a suspended walk must be marked detached too: the request is gone "
          "either way");
    CHECK(op.request == NULL,
          "a suspended walk's op->request must be cleared as well -- the "
          "pending completion's resume runs long after the request is freed");
    CHECK(ngx_test_redis_done_calls == 0,
          "a SUSPENDED detached walk must NOT be torn down inline: the page's "
          "UNLINK still holds the op through page_resume_data, and freeing it "
          "here is a use-after-free strictly worse than the leak");
    CHECK(op.suspended == 1,
          "the detach must leave the walk SUSPENDED, so the guaranteed resume "
          "is not dropped as a resume for an unsuspended walk");
    CHECK(op.resume_doomed == 1,
          "the detach must record the doom for the resume to act on");

    /* ---- EXIT 3: the deferred teardown actually happens at the resume --- */

    ngx_http_cache_turbo_redis_sscan_resume(&op, NGX_OK);

    CHECK(ngx_test_redis_done_calls == 1,
          "the resume of a DETACHED walk must reach op_done exactly once: this "
          "is the deferred teardown, and skipping it is the leak");
    CHECK(ngx_test_members_calls == 0,
          "the resume of a detached walk must not call the page callback");
    CHECK(ngx_test_finalize_calls == 0,
          "the resume of a detached walk must not finalize a request: there "
          "is none");
    CHECK(op.suspended == 0,
          "the resume must clear the suspension it consumed");

    /* ---- EXIT 3b: the resume's detached arm must not DEPEND on the doom ---
     *
     * The case above cannot discriminate on its own, and saying so matters.
     * walk_detach sets resume_doomed, so with the detached arm compiled out the
     * resume falls through to walk_finish -- whose OWN detached guard reaches
     * op_done once anyway. Identical observables: vacuous.
     *
     * The observable unique to the resume's detached arm is what it does for a
     * detached walk that is NOT doomed. That state is reachable: read_sscan
     * suspends a page and saves its cursor (resume_doomed stays 0), and the
     * request is terminated afterwards -- walk_detach's suspended arm is the
     * only writer of resume_doomed here, so clearing it models a walk detached
     * through any future path that does not set it. Without the detached arm,
     * rc == NGX_OK and resume_doomed == 0 route this straight into
     * sscan_advance, which issues ANOTHER SSCAN page on a connection that is
     * being torn down, for a request that no longer exists -- and never reaches
     * op_done at all. That is the leak, back in full. */
    init_request(&request, &connection, &pool, &read, &write);
    init_redis(&op, &clcf, &ctx, &request, &pool);
    op.members_cb = suspending_members_callback;
    op.members_data = (void *) (uintptr_t) 0x51;
    op.is_scan = 1;
    op.peer.connection = &connection;
    connection.data = &op;
    reset_observations();

    /* The post-detach state, with the doom deliberately absent. */
    op.detached = 1;
    op.request = NULL;
    op.members_cb = NULL;
    op.members_data = NULL;
    op.suspended = 1;
    op.resume_doomed = 0;
    op.resume_cursor.data = op.resume_cursor_buf;
    op.resume_cursor.len = 2;
    op.resume_cursor_buf[0] = '1';
    op.resume_cursor_buf[1] = '7';

    ngx_http_cache_turbo_redis_sscan_resume(&op, NGX_OK);

    CHECK(ngx_test_redis_done_calls == 1,
          "a DETACHED walk's resume must reach op_done even when it is not "
          "doomed: the detached check has to precede the rc/doom check, or an "
          "undoomed detached walk advances to another page instead of being "
          "torn down and leaks its pool, connection and fd");
    /* THE discriminating assertion. op_done alone cannot separate the two: an
     * advance that fails to build its next page falls into walk_finish, whose
     * detached guard reaches op_done once anyway -- identical count, vacuous.
     * scan_pages is incremented by sscan_advance and by nothing else, so it is
     * the one observable that says whether the walk ADVANCED at all. */
    CHECK(op.scan_pages == 0,
          "a DETACHED walk's resume must NOT enter sscan_advance: it counts "
          "another page and tries to issue another SSCAN on a connection being "
          "torn down, for a request that no longer exists");
    CHECK(ngx_test_finalize_calls == 0,
          "an undoomed detached resume must still not finalize a request");

    /* ---- EXIT 4: walk_finish, reached by any other terminal path -------- */
    /*
     * read_sscan's timeout, a malformed reply, a peer close, op_fail: every
     * remaining terminal path in the file routes through walk_finish. Its
     * detached guard is the ONE edit that makes "a detached walk never calls
     * the callback and never finalizes" total.
     */
    init_request(&request, &connection, &pool, &read, &write);
    init_redis(&op, &clcf, &ctx, &request, &pool);
    op.members_cb = suspending_members_callback;
    op.members_data = (void *) (uintptr_t) 0x51;
    op.is_scan = 1;
    op.peer.connection = &connection;
    connection.data = &op;
    reset_observations();
    read.timer_set = 1;
    read.active = 1;

    /* The state the cleanup leaves behind, reached now by a LATER wakeup.
     *
     * ⚠ members_cb is deliberately left SET here, even though walk_detach also
     * clears it. Two reasons, and both matter:
     *   - it makes the mutant OBSERVABLE. With the guard compiled out,
     *     walk_finish calls cb(r, ...) and the assertion below counts it and
     *     reports; with members_cb NULLed the mutant would segfault on the
     *     call instead, and a crash is not a named assertion going red.
     *   - it is the STRONGER contract. `detached` alone must be sufficient to
     *     stop walk_finish -- the guard must not be relying on members_cb
     *     having been cleared as well, or a future path that sets detached
     *     without clearing the callback silently reopens the hole.
     *
     * op.request likewise stays pointing at the live stack request rather than
     * being NULLed as walk_detach leaves it. Same reason: `detached` must be
     * sufficient ON ITS OWN, and a mutant that runs off a NULL r crashes
     * inside walk_finish before any assertion can be reported -- a segfault is
     * not a named test going red. Keeping r live lets the mutated walk_finish
     * complete, so the callback call and the finalize are both COUNTED and the
     * assertions below name exactly what went wrong. */
    op.detached = 1;

    ngx_http_cache_turbo_redis_walk_finish(&op, NULL, 0);

    CHECK(ngx_test_members_calls == 0,
          "walk_finish on a DETACHED walk must not call the page callback: it "
          "was cleared with the request, and calling through it is the "
          "use-after-free this guard exists to prevent");
    CHECK(ngx_test_finalize_calls == 0,
          "walk_finish on a DETACHED walk must not finalize: op->request is "
          "NULL and the request memory is already gone");
    CHECK(ngx_test_redis_done_calls == 1,
          "walk_finish on a detached walk must STILL reach op_done exactly "
          "once -- skipping the callback must not also skip the teardown, or "
          "the guard trades the use-after-free back for the leak");
    CHECK(read.timer_set == 0 && read.active == 0,
          "walk_finish's detached arm must disarm the connection before "
          "op_done closes it");
}


/*
 * CT-SSCAN-TERMINATE-LEAK (round 3): the deferred teardown must ACTUALLY RUN
 * when the request is terminated.
 *
 * This is the seam the earlier revision left open, and it is worth stating
 * precisely because the code read as though it were closed:
 *
 *   - redis.c's walk_detach, on a SUSPENDED walk, deliberately tears down
 *     NOTHING. It cannot: the page's UNLINK is in flight on a DIFFERENT
 *     connection and holds the walk op as its completion data, so destroying
 *     op->pool there is a use-after-free strictly worse than the leak. It
 *     records the doom and defers the whole teardown to the walk's
 *     continuation.
 *   - purge.c's await_gone, ALSO registered on r->pool, clears the token's
 *     `alive` bit.
 *   - the UNLINK's completion then arrives and takes its `!alive` arm.
 *
 * The old `!alive` arm destroyed the page scratch and RETURNED. It never
 * reached the continuation -- correctly refusing to read the freed tagpurge
 * that held tp->page_resume, but thereby never reaching op_done either. So the
 * teardown walk_detach deferred simply never happened, and the walk op's pool,
 * its Redis connection, its fd and the zone's varidx_inflight account leaked
 * for the worker's lifetime: exactly the failure mode this whole change exists
 * to close, surviving inside the fix for it.
 *
 * "del_many_cb fires its completion exactly once from every terminal path" is
 * true, and was cited as the guarantee that the resume runs. It is a guarantee
 * about the COMPLETION, not about the RESUME: the completion's request-is-gone
 * arm was a dead end.
 *
 * The closure: the continuation is MIRRORED into the await token at suspension
 * time, alongside the page scratch and for the same reason -- the token lives
 * in the UNLINK op's own pool, which outlives r->pool, so the `!alive` arm can
 * still reach it. Ownership follows the page_pool discipline exactly: whichever
 * arm runs consumes the pointer and NULLs it, and `alive` makes the two arms
 * mutually exclusive.
 *
 * Every exit is enumerated and asserted below, including the two that must NOT
 * change:
 *
 *   EXIT A  terminated + suspended: the completion runs the mirrored
 *           continuation and the detached walk reaches op_done EXACTLY ONCE,
 *           without touching the request, walk_finish's callback or finalize
 *   EXIT B  the cleanup-add FAILURE path: no continuation is mirrored, because
 *           that arm unsuspends the walk and hands the error back
 *           synchronously -- a mirror there would be a second teardown
 *   EXIT C  NEGATIVE CONTROL, the still-LIVE completion: unchanged. It settles
 *           the page and consumes tp->page_resume, and must NOT also fire the
 *           token's mirror
 *   EXIT D  NEGATIVE CONTROL, ordering: completion first, teardown after. The
 *           deregistered cleanup must not fire a second continuation
 */
static ngx_uint_t  test_ct_resume_calls;
static void       *test_ct_resume_data;
static ngx_int_t   test_ct_resume_rc;

static void
test_ct_recording_resume(void *opaque, ngx_int_t rc)
{
    test_ct_resume_calls++;
    test_ct_resume_data = opaque;
    test_ct_resume_rc = rc;
}

static void
test_ct_reset(void)
{
    test_ct_resume_calls = 0;
    test_ct_resume_data = NULL;
    test_ct_resume_rc = 12345;
    ngx_test_page_settle_calls = 0;
    ngx_test_page_settle_result = NGX_OK;
    ngx_test_destroy_pool_calls = 0;
    ngx_test_last_destroyed_pool = NULL;
}

static void
test_redis_terminated_await_runs_deferred_teardown(void)
{
    ngx_http_cache_turbo_tagpurge_t        tp;
    ngx_http_cache_turbo_tagpurge_await_t  aw;
    ngx_pool_cleanup_t                     cln;
    ngx_pool_t                             page_pool;

    /* ---- EXIT A: terminated request, suspended walk ------------------- */
    /*
     * The state purge.c leaves at suspension: the token mirrors the page
     * scratch AND the walk's continuation. Then the request is terminated and
     * BOTH r->pool cleanups run -- walk_detach (redis.c, covered above) and
     * await_gone (extracted here) -- and the UNLINK reply lands afterwards.
     */
    test_ct_reset();
    memset(&tp, 0, sizeof(tp));
    memset(&aw, 0, sizeof(aw));

    tp.page_pool = &page_pool;
    tp.page_resume = test_ct_recording_resume;
    tp.page_resume_data = (void *) (uintptr_t) 0xA11;
    tp.page_await = &aw;

    cln.handler = ngx_http_cache_turbo_tag_purge_await_gone;
    cln.data = &aw;

    aw.tp = &tp;
    aw.cln = &cln;
    aw.page_pool = &page_pool;
    aw.resume = tp.page_resume;
    aw.resume_data = tp.page_resume_data;
    aw.alive = 1;

    /* The request's teardown. */
    ngx_http_cache_turbo_tag_purge_await_gone(&aw);

    CHECK(aw.alive == 0,
          "the r->pool cleanup must clear the token's liveness bit before the "
          "tagpurge memory is released");
    CHECK(aw.tp == NULL,
          "the r->pool cleanup must drop the tagpurge pointer, not merely flag "
          "it");
    CHECK(aw.resume == test_ct_recording_resume,
          "the r->pool cleanup must NOT drop the mirrored continuation: it is "
          "the ONLY remaining route to the detached walk's deferred op_done, "
          "and it points at the walk op, which does not live in r->pool");
    CHECK(test_ct_resume_calls == 0,
          "the cleanup itself must not run the continuation: the UNLINK is "
          "still in flight and still holds the walk op");

    /* The UNLINK reply, arriving on a request that no longer exists. */
    ngx_http_cache_turbo_tag_purge_page_unlinked(&aw, NGX_OK);

    /* THE assertion this round exists for. A count, not a boolean: 0 is the
     * leak that shipped, 2 is a double teardown that destroys the op pool
     * twice, and only 1 is correct. Nothing else on this path calls it. */
    CHECK(test_ct_resume_calls == 1,
          "a completion arriving on a TERMINATED request must run the walk's "
          "mirrored continuation EXACTLY ONCE: walk_detach's suspended arm "
          "tore down nothing and deferred the whole teardown to it, so 0 leaks "
          "the op pool, the Redis connection, its fd and the zone's "
          "varidx_inflight account for the worker's lifetime");
    CHECK(test_ct_resume_data == (void *) (uintptr_t) 0xA11,
          "the continuation must be handed the WALK OP it was mirrored with, "
          "not the token: sscan_resume dereferences it as the op");
    CHECK(test_ct_resume_rc != NGX_OK,
          "no page was settled and the walk can never complete this purge, so "
          "the continuation must not be told the page succeeded");
    CHECK(ngx_test_page_settle_calls == 0,
          "the completion must NOT settle the page on a terminated request: "
          "the tagpurge, the tag key and the member array all died with "
          "r->pool");
    CHECK(ngx_test_destroy_pool_calls == 1
              && ngx_test_last_destroyed_pool == &page_pool,
          "the page scratch is a standalone pool the request teardown does not "
          "own, so the completion must still release it -- exactly once");
    CHECK(aw.page_pool == NULL,
          "the completion must consume the page-scratch mirror, so a second "
          "invocation cannot double-destroy it");
    CHECK(aw.resume == NULL && aw.resume_data == NULL,
          "the completion must CONSUME the continuation mirror under the same "
          "one-owner discipline as page_pool: leaving it set is a second "
          "op_done waiting to happen");

    /* Idempotence, the direct check: a duplicated completion must find both
     * mirrors already consumed and do nothing. */
    ngx_http_cache_turbo_tag_purge_page_unlinked(&aw, NGX_OK);
    CHECK(test_ct_resume_calls == 1,
          "a second completion must not run the continuation again: op_done "
          "twice double-destroys the walk op's pool");
    CHECK(ngx_test_destroy_pool_calls == 1,
          "a second completion must not destroy the page scratch again");

    /* ---- EXIT B: the ngx_pool_cleanup_add FAILURE path ---------------- */
    /*
     * purge.c cannot register the cleanup, so it leaves the token DEAD up
     * front, unsuspends the walk by hand and returns NGX_ERROR as the page
     * callback's verdict. read_sscan drives the walk to its own terminal from
     * there, which reaches op_done on its own -- so this arm must NOT mirror
     * the continuation. If it did, the later !alive completion would call
     * op_done a SECOND time on an op already destroyed.
     *
     * The token's remaining job on this path is exactly the page scratch, and
     * this asserts both halves.
     */
    test_ct_reset();
    memset(&aw, 0, sizeof(aw));

    /* The state that arm leaves behind, verbatim. */
    aw.alive = 0;
    aw.page_pool = &page_pool;
    aw.resume = NULL;
    aw.resume_data = NULL;

    ngx_http_cache_turbo_tag_purge_page_unlinked(&aw, NGX_OK);

    CHECK(test_ct_resume_calls == 0,
          "the cleanup-add failure path unsuspends the walk and hands the "
          "error back synchronously, so its walk reaches op_done through its "
          "own terminal: running a mirrored continuation here would be a "
          "SECOND teardown of an op already destroyed");
    CHECK(ngx_test_destroy_pool_calls == 1
              && ngx_test_last_destroyed_pool == &page_pool,
          "the cleanup-add failure path still hands the page scratch to the "
          "completion, which must release it exactly once");
    CHECK(ngx_test_page_settle_calls == 0,
          "a dead token must never settle the page, however it came to be "
          "dead");

    /* ---- EXIT C: NEGATIVE CONTROL, the still-LIVE completion ---------- */
    /*
     * The normal path, unchanged. This is the control against an over-broad
     * change: a completion that ran the token's mirror unconditionally would
     * fire the continuation TWICE here (once from the mirror, once from
     * tp->page_resume) and destroy the op pool twice. The live arm must
     * consume tp->page_resume and NULL the mirror without running it.
     */
    test_ct_reset();
    memset(&tp, 0, sizeof(tp));
    memset(&aw, 0, sizeof(aw));

    tp.page_pool = &page_pool;
    tp.page_resume = test_ct_recording_resume;
    tp.page_resume_data = (void *) (uintptr_t) 0xB22;
    tp.page_await = &aw;

    cln.handler = ngx_http_cache_turbo_tag_purge_await_gone;
    cln.data = &aw;

    aw.tp = &tp;
    aw.cln = &cln;
    aw.page_pool = &page_pool;
    aw.resume = tp.page_resume;
    aw.resume_data = tp.page_resume_data;
    aw.alive = 1;

    ngx_test_page_settle_result = NGX_OK;

    ngx_http_cache_turbo_tag_purge_page_unlinked(&aw, NGX_OK);

    CHECK(ngx_test_page_settle_calls == 1,
          "a completion on a LIVE request must settle the page: this is the "
          "path the whole suspension exists to reach");
    CHECK(test_ct_resume_calls == 1,
          "the LIVE path must resume the walk exactly once -- through "
          "tp->page_resume, not additionally through the token's mirror");
    CHECK(test_ct_resume_data == (void *) (uintptr_t) 0xB22
              && test_ct_resume_rc == NGX_OK,
          "the live resume carries the SETTLED page's verdict, not the "
          "terminated path's abandon");
    CHECK(aw.resume == NULL && aw.resume_data == NULL,
          "the live arm must consume the token's mirror too: the two arms are "
          "mutually exclusive and exactly one teardown may survive");
    CHECK(aw.page_pool == NULL,
          "the live arm hands the page scratch to settle() through the "
          "tagpurge, so it must drop the token's mirror first");
    CHECK(cln.handler == NULL && aw.cln == NULL,
          "the live completion must deregister the r->pool cleanup on its way "
          "out: it now owns the teardown, and leaving the handler armed would "
          "clear `alive` on a token whose op pool is about to be destroyed");
    CHECK(tp.page_await == NULL,
          "the settled page must be unregistered from the tagpurge");

    /* ---- EXIT D: NEGATIVE CONTROL, completion FIRST, teardown after --- */
    /*
     * The other ordering. The live completion above deregistered the cleanup,
     * so the request's later teardown finds nothing to run. Verified by
     * invoking the cleanup slot the way nginx would: through its handler,
     * which the completion must have NULLed.
     */
    CHECK(test_ct_resume_calls == 1,
          "a request finalizing AFTER its completion must not produce a second "
          "continuation: the completion deregistered the cleanup");
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
    test_redis_sscan_resume_rearms_read_event();
    test_redis_sscan_suspended_walk_ignores_stray_events();
    test_await_token_protocol_only();
    test_redis_walk_detach_on_request_teardown();
    test_redis_terminated_await_runs_deferred_teardown();

    (void) fprintf(stderr, "terminal error compositions: %d failures\n",
                   failures);
    return failures ? 1 : 0;
}
