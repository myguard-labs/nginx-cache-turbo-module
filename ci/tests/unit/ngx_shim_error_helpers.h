/* Minimal nginx/module surface for extracted terminal-error compositions. */
#ifndef NGX_CACHE_TURBO_UNIT_SHIM_ERROR_HELPERS_H
#define NGX_CACHE_TURBO_UNIT_SHIM_ERROR_HELPERS_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

typedef intptr_t       ngx_int_t;
typedef uintptr_t      ngx_uint_t;
typedef uintptr_t      ngx_msec_t;
typedef unsigned char  u_char;

#define NGX_OK                           0
#define NGX_ERROR                       -1
#define NGX_AGAIN                       -2
#define NGX_DONE                        -4
#define NGX_DECLINED                    -5
#define NGX_LOG_ERR                      3
#define NGX_LOG_INFO                     6
#define NGX_ETIMEDOUT                  110
#define NGX_HTTP_OK                    200
#define NGX_HTTP_INTERNAL_SERVER_ERROR 500
#define CR                              '\r'
#define LF                              '\n'

#define ngx_memcpy  memcpy
#define ngx_strncmp(s1, s2, n) \
    strncmp((const char *) (s1), (const char *) (s2), (n))

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

typedef struct ngx_pool_s {
    ngx_uint_t  token;
} ngx_pool_t;

typedef struct ngx_event_s ngx_event_t;
typedef struct ngx_connection_s ngx_connection_t;

struct ngx_event_s {
    void       *data;
    void      (*handler)(ngx_event_t *ev);
    unsigned    timedout:1;
    unsigned    timer_set:1;
};

struct ngx_connection_s {
    void         *log;
    void         *data;
    ngx_event_t  *read;
    ngx_event_t  *write;
    ssize_t     (*send)(ngx_connection_t *c, u_char *buf, size_t size);
    ssize_t     (*recv)(ngx_connection_t *c, u_char *buf, size_t size);
};

typedef struct {
    u_char  *pos;
    u_char  *last;
} ngx_buf_t;

typedef struct {
    ngx_connection_t  *connection;
    ngx_pool_t        *pool;
} ngx_http_request_t;

typedef struct {
    int  token;
} ngx_addr_t;

typedef struct {
    ngx_addr_t  redis_addr;
    ngx_msec_t  redis_connect_backoff;
} ngx_http_cache_turbo_loc_conf_t;

typedef struct {
    ngx_int_t   l2_result;
    ngx_uint_t  l2_done;
    u_char     *l2_blob;
    size_t      l2_blob_len;
    ngx_int_t   lock_result;
    ngx_uint_t  lock_done;
} ngx_http_cache_turbo_ctx_t;

typedef struct {
    ngx_http_cache_turbo_loc_conf_t  *clcf;
    ngx_http_request_t               *request;
    ngx_http_cache_turbo_ctx_t       *ctx;
    ngx_buf_t                        *send;
    ngx_msec_t                        timeout;
    void                            (*read_handler)(ngx_event_t *ev);
    u_char                            recv[128];
    size_t                            recv_len;
    unsigned                          clean:1;
    unsigned                          unconnected:1;
} ngx_http_cache_turbo_mc_op_t;

typedef struct ngx_http_cache_turbo_redis_walk_s {
    ngx_int_t   status;
    ngx_uint_t  pages;
    ngx_uint_t  deadline;
    ngx_uint_t  blocks;
} ngx_http_cache_turbo_redis_walk_t;

typedef ngx_int_t (*ngx_http_cache_turbo_redis_members_pt)(
    ngx_http_request_t *r, void *data, ngx_str_t *members,
    ngx_uint_t nmembers, const ngx_http_cache_turbo_redis_walk_t *walk);

typedef struct {
    ngx_http_cache_turbo_loc_conf_t       *clcf;
    ngx_http_request_t                    *request;
    ngx_http_cache_turbo_ctx_t            *ctx;
    ngx_http_cache_turbo_redis_members_pt  members_cb;
    void                                  *members_data;
    ngx_pool_t                            *pool;
    ngx_pool_t                            *rpool;
    ngx_uint_t                             expected_replies;
    ngx_int_t                              scan_status;
    ngx_uint_t                             scan_pages;
    ngx_uint_t                             scan_deadline_hit;
    u_char                                *rbuf;
    size_t                                 rlen;
    u_char                                 recv[128];
    size_t                                 recv_len;
    unsigned                               clean:1;
    unsigned                               unconnected:1;
    unsigned                               is_scan:1;
    unsigned                               is_lock:1;
} ngx_http_cache_turbo_redis_op_t;

extern ngx_uint_t  ngx_test_log_calls;
extern ngx_int_t   ngx_test_log_level;
extern ngx_uint_t  ngx_test_log_errno;
extern void       *ngx_test_log;
extern const char *ngx_test_log_format;
extern ngx_uint_t  ngx_test_send_json_calls;
extern ngx_http_request_t *ngx_test_send_json_request;
extern ngx_uint_t  ngx_test_send_json_status;
extern ngx_str_t   ngx_test_send_json_body;
extern ngx_int_t   ngx_test_send_json_result;
extern ngx_uint_t  ngx_test_mc_arm_calls;
extern ngx_addr_t *ngx_test_mc_arm_addr;
extern ngx_msec_t  ngx_test_mc_arm_delay;
extern ngx_uint_t  ngx_test_mc_clear_calls;
extern ngx_uint_t  ngx_test_mc_done_calls;
extern ngx_http_cache_turbo_mc_op_t *ngx_test_mc_done_op;
extern ngx_uint_t  ngx_test_redis_arm_calls;
extern ngx_addr_t *ngx_test_redis_arm_addr;
extern ngx_msec_t  ngx_test_redis_arm_delay;
extern ngx_uint_t  ngx_test_redis_clear_calls;
extern ngx_uint_t  ngx_test_redis_done_calls;
extern ngx_http_cache_turbo_redis_op_t *ngx_test_redis_done_op;
extern ngx_uint_t  ngx_test_phase_calls;
extern ngx_uint_t  ngx_test_posted_calls;
extern ngx_uint_t  ngx_test_finalize_calls;
extern ngx_http_request_t *ngx_test_finalize_request;
extern ngx_int_t   ngx_test_finalize_rc;
extern ngx_int_t   ngx_test_handle_write_result;
extern ngx_int_t   ngx_test_handle_read_result;
extern ngx_uint_t  ngx_test_add_timer_calls;
extern ngx_uint_t  ngx_test_del_timer_calls;
extern ngx_int_t   ngx_test_redis_frame_result;
extern ngx_int_t   ngx_test_redis_fill_result;
extern ngx_int_t   ngx_test_redis_frame_scan_result;
extern size_t      ngx_test_redis_frame_scan_next;
extern ngx_int_t   ngx_test_redis_parse_array_result;
extern ngx_uint_t  ngx_test_redis_parse_array_calls;
extern ngx_uint_t  ngx_test_members_calls;
extern ngx_str_t  *ngx_test_members;
extern ngx_uint_t  ngx_test_nmembers;
extern const ngx_http_cache_turbo_redis_walk_t *ngx_test_walk;
extern ngx_int_t   ngx_test_members_result;

#define ngx_str_set(str, text)                                               \
    do {                                                                     \
        (str)->len = sizeof(text) - 1;                                       \
        (str)->data = (u_char *) text;                                       \
    } while (0)

#define ngx_log_error(level, log, err, fmt, ...)                             \
    do {                                                                     \
        ngx_test_log_calls++;                                                \
        ngx_test_log_level = (level);                                        \
        ngx_test_log_errno = (err);                                          \
        ngx_test_log = (log);                                                \
        ngx_test_log_format = (fmt);                                         \
    } while (0)

static void ngx_http_cache_turbo_mc_op_fail(
    ngx_http_cache_turbo_mc_op_t *op);
static void ngx_http_cache_turbo_mc_get_finish(
    ngx_http_cache_turbo_mc_op_t *op, ngx_int_t result,
    u_char *blob, size_t blob_len);
static void ngx_http_cache_turbo_redis_smembers_finish(
    ngx_http_cache_turbo_redis_op_t *op, ngx_str_t *members,
    ngx_uint_t nmembers);
static void ngx_http_cache_turbo_redis_get_finish(
    ngx_http_cache_turbo_redis_op_t *op, ngx_int_t result,
    u_char *blob, size_t blob_len);
static void ngx_http_cache_turbo_redis_lock_finish(
    ngx_http_cache_turbo_redis_op_t *op, ngx_int_t result);
static void ngx_http_cache_turbo_redis_op_fail(
    ngx_http_cache_turbo_redis_op_t *op);

static ngx_int_t
ngx_http_cache_turbo_send_json(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t *body)
{
    ngx_test_send_json_calls++;
    ngx_test_send_json_request = r;
    ngx_test_send_json_status = status;
    ngx_test_send_json_body = *body;
    return ngx_test_send_json_result;
}

static void
ngx_http_cache_turbo_mc_backoff_arm(ngx_addr_t *addr, ngx_msec_t delay)
{
    ngx_test_mc_arm_calls++;
    ngx_test_mc_arm_addr = addr;
    ngx_test_mc_arm_delay = delay;
}

static void
ngx_http_cache_turbo_mc_backoff_clear(ngx_addr_t *addr)
{
    (void) addr;
    ngx_test_mc_clear_calls++;
}

static void
ngx_http_cache_turbo_redis_backoff_arm(ngx_addr_t *addr, ngx_msec_t delay)
{
    ngx_test_redis_arm_calls++;
    ngx_test_redis_arm_addr = addr;
    ngx_test_redis_arm_delay = delay;
}

static void
ngx_http_cache_turbo_redis_backoff_clear(ngx_addr_t *addr)
{
    (void) addr;
    ngx_test_redis_clear_calls++;
}

static u_char *
ngx_strlchr(u_char *p, u_char *last, u_char c)
{
    while (p < last) {
        if (*p == c) {
            return p;
        }
        p++;
    }
    return NULL;
}

static void
ngx_http_cache_turbo_mc_op_done(ngx_http_cache_turbo_mc_op_t *op)
{
    ngx_test_mc_done_calls++;
    ngx_test_mc_done_op = op;
}

static void
ngx_http_cache_turbo_redis_op_done(ngx_http_cache_turbo_redis_op_t *op)
{
    ngx_test_redis_done_calls++;
    ngx_test_redis_done_op = op;
}

static void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    static u_char storage[256];

    (void) pool;
    return size <= sizeof(storage) ? storage : NULL;
}

static void
ngx_http_cache_turbo_blob_clear_vetted(u_char *blob, size_t blob_len)
{
    (void) blob;
    (void) blob_len;
}

static void
ngx_http_core_run_phases(ngx_http_request_t *r)
{
    (void) r;
    ngx_test_phase_calls++;
}

static void
ngx_http_run_posted_requests(ngx_connection_t *c)
{
    (void) c;
    ngx_test_posted_calls++;
}

static void
ngx_http_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_test_finalize_calls++;
    ngx_test_finalize_request = r;
    ngx_test_finalize_rc = rc;
}

static ngx_int_t
ngx_handle_write_event(ngx_event_t *ev, ngx_uint_t flags)
{
    (void) ev;
    (void) flags;
    return ngx_test_handle_write_result;
}

static ngx_int_t
ngx_handle_read_event(ngx_event_t *ev, ngx_uint_t flags)
{
    (void) ev;
    (void) flags;
    return ngx_test_handle_read_result;
}

static void
ngx_add_timer(ngx_event_t *ev, ngx_msec_t timeout)
{
    (void) timeout;
    ev->timer_set = 1;
    ngx_test_add_timer_calls++;
}

static void
ngx_del_timer(ngx_event_t *ev)
{
    ev->timer_set = 0;
    ngx_test_del_timer_calls++;
}

static ngx_int_t
ngx_http_cache_turbo_redis_frame(u_char *p, u_char *end, ngx_uint_t depth,
    u_char **next)
{
    (void) p;
    (void) depth;
    *next = end;
    return ngx_test_redis_frame_result;
}

static ngx_int_t
ngx_http_cache_turbo_redis_fill(ngx_http_cache_turbo_redis_op_t *op,
    ngx_event_t *rev)
{
    (void) op;
    (void) rev;
    return ngx_test_redis_fill_result;
}

static ngx_int_t
ngx_http_cache_turbo_redis_frame_scan(ngx_http_cache_turbo_redis_op_t *op,
    u_char **next)
{
    *next = op->rbuf + ngx_test_redis_frame_scan_next;
    return ngx_test_redis_frame_scan_result;
}

static ngx_int_t
ngx_http_cache_turbo_redis_parse_array(
    ngx_http_cache_turbo_redis_op_t *op, ngx_str_t **members,
    ngx_uint_t *nmembers)
{
    (void) op;
    ngx_test_redis_parse_array_calls++;
    *members = NULL;
    *nmembers = 0;
    return ngx_test_redis_parse_array_result;
}

static ngx_uint_t
ngx_http_cache_turbo_redis_pool_blocks(ngx_pool_t *pool)
{
    return pool == NULL ? 0 : pool->token;
}

#endif
