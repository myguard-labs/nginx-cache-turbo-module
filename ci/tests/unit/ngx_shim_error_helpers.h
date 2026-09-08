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
    /* TODO-UNLINK-REPLY-WINDOW: read_sscan's suspension takes the read event
     * off the poller, which needs `active` and ngx_del_event below.
     * ⚠ LOAD-BEARING, not padding. test_redis_sscan_suspension_disarms_
     * connection overrides the parse_scan stub's cursor (ngx_test_redis_parse_
     * cursor) so a page really does suspend, and ASSERTS this bit is cleared on
     * every exit from that block. Deleting it does not merely shrink the mock;
     * it voids the only deterministic control for the disarm. */
    unsigned    active:1;
    /* GRIND-C7 (re-arm): nginx's readiness bit. LOAD-BEARING -- it is the
     * second half of ngx_handle_read_event's `!active && !ready` gate, and a
     * shim without it cannot tell a genuine re-registration from a no-op. */
    unsigned    ready:1;
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

/* CT-SSCAN-TERMINATE-LEAK: the r->pool cleanup record. redis_sscan registers
 * one holding walk_detach, and op_done cancels it by neutralizing the handler
 * -- so the shim needs the real field shape for both the extracted detach and
 * the extracted op_done to compile and behave identically. */
typedef struct ngx_pool_cleanup_s  ngx_pool_cleanup_t;
struct ngx_pool_cleanup_s {
    void  (*handler)(void *data);
    void   *data;
};

/* Minimal stand-in for nginx's ngx_peer_connection_t. sscan_advance reads the
 * op's connection through op->peer.connection rather than through an event, so
 * the mock op needs the same shape for the extracted function to compile. */
typedef struct {
    ngx_connection_t  *connection;
} ngx_peer_connection_t;

typedef struct {
    ngx_addr_t  redis_addr;
    ngx_msec_t  redis_connect_backoff;
    /* TODO-REDIS-PAGINATION: read_sscan carries the SCAN walk's wall-clock
     * ceiling. Left 0 by init_redis, which disables it -- these unit tests
     * exercise the reader's terminal paths, not the deadline (that has its own
     * runtime test, test_scan_walk_deadline_reports_incomplete). */
    ngx_msec_t  redis_scan_deadline;
} ngx_http_cache_turbo_loc_conf_t;

/* CT-SSCAN-TERMINATE-LEAK: the tagpurge names its zone only as a pointer, and
 * nothing on the completion paths under test dereferences it. An opaque type
 * keeps the real struct out of this shim without a hand-copy that could drift. */
typedef struct ngx_http_cache_turbo_zone_s  ngx_http_cache_turbo_zone_t;

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
    ngx_peer_connection_t                  peer;
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
    /* TODO-REDIS-PAGINATION: read_sscan's per-page rotation state. The stubbed
     * parse_scan always yields cursor "0", so the rotation branch is never
     * TAKEN here -- these fields exist so it still COMPILES against the mock
     * op, exactly as the real reader does against the real one. */
    ngx_buf_t                             *send;
    ngx_buf_t                             *command;
    ngx_str_t                              sscan_key;
    ngx_msec_t                             scan_start;
    size_t                                 rcap;
    size_t                                 reply_max;
    size_t                                 frame_off;
    ngx_uint_t                             frame_depth;
    /* TODO-UNLINK-REPLY-WINDOW: the awaited-reply completion on a drained op,
     * and the SSCAN walk's suspend/resume state. They exist so the extracted
     * readers compile against the mock op exactly as they do against the real
     * one, which is what keeps this shim from silently drifting into testing a
     * different function than the one that ships.
     * ⚠ Unlike the rotation fields above, `suspended`, `resume_doomed` and
     * `resume_cursor_buf` are EXERCISED: the suspension test overrides the
     * parse_scan stub's cursor so a page genuinely suspends, and asserts on
     * them for both the normal and the oversized-cursor exit. */
    void                                 (*drain_cb)(void *, ngx_int_t);
    void                                  *drain_data;
    unsigned                               drain_done:1;
    unsigned                               drain_failed:1;
    unsigned                               suspended:1;
    unsigned                               resume_doomed:1;
    /* CT-SSCAN-TERMINATE-LEAK: the request-teardown detach state. EXERCISED --
     * the detach test drives walk_detach through both its suspended and its
     * unsuspended exit and asserts on both fields. */
    unsigned                               detached:1;
    ngx_pool_cleanup_t                    *req_cln;
    ngx_str_t                              resume_cursor;
    u_char                                 resume_cursor_buf[64];
} ngx_http_cache_turbo_redis_op_t;

/* Matching the real file's file-scope "page delivery on the stack" pointer. */
static ngx_http_cache_turbo_redis_op_t  *ngx_http_cache_turbo_redis_delivering;

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
/* TODO-UNLINK-REPLY-WINDOW: parse_scan overrides. NULL cursor keeps the legacy
 * "0" (last page); a non-NULL one makes the stubbed page non-terminal so the
 * suspension path is reachable. Members must be non-empty for read_sscan to
 * call the page callback at all. */
/* Forward declarations for the extracted redis walk functions: the extractor
 * emits them in source order, so walk_suspend (which names sscan_resume) and
 * read_sscan (which names sscan_advance) are compiled before their definitions.
 * The real translation unit has these at the top of the file for the same
 * reason. */
static void ngx_http_cache_turbo_redis_sscan_resume(void *opaque, ngx_int_t rc);
static void ngx_http_cache_turbo_redis_sscan_advance(
    ngx_http_cache_turbo_redis_op_t *op, ngx_str_t cursor);

/* NIT-E: forced ngx_del_event failure; NGX_OK (the reset default) disables. */
extern ngx_int_t   ngx_test_del_event_result;
/* GRIND-C7: the re-arm oracle. ngx_test_add_event_calls counts genuine
 * ngx_add_event registrations; ngx_test_add_event_result forces a refusal. */
extern ngx_uint_t  ngx_test_add_event_calls;
extern ngx_int_t   ngx_test_add_event_result;
extern const char *ngx_test_redis_parse_cursor;
extern ngx_str_t  *ngx_test_redis_parse_members;
extern ngx_uint_t  ngx_test_redis_parse_nmembers;
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
static void ngx_http_cache_turbo_redis_walk_finish(
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

/* TODO-REDIS-PAGINATION scaffolding for read_sscan's page rotation. The stubbed
 * parse_scan always returns cursor "0", so the reader always takes its
 * completion path and none of this runs -- it exists so the extracted reader
 * compiles unchanged against the mock. */
#ifndef ngx_pagesize
#define ngx_pagesize  4096
#endif
#ifndef ngx_min
#define ngx_min(a, b)  ((a) < (b) ? (a) : (b))
#endif

typedef ngx_int_t  ngx_msec_int_t;

#define NGX_HTTP_CACHE_TURBO_REDIS_SCAN_MAX_PAGES  (1024 * 1024)
#ifndef NGX_ABORT
#define NGX_ABORT  (-6)
#endif

static ngx_msec_t  ngx_current_msec;
static int         ngx_posted_events;
static struct { void *log; }  ngx_cycle_stub;
#define ngx_cycle  (&ngx_cycle_stub)

#define ngx_post_event(ev, q)  do { (void) (ev); (void) (q); } while (0)

/* GRIND-C7: sscan_advance's page rotation, made REACHABLE.
 *
 * Both of these used to return NULL unconditionally, which made every
 * sscan_advance call bail into walk_finish before it could get as far as
 * re-arming the read event -- so the re-arm was untestable and, as it turned
 * out, wrong. ngx_test_rotation_ok = 1 lets the rotation succeed so the tail
 * of sscan_advance actually runs. It defaults to 0, preserving the previous
 * always-fails behaviour every earlier test was written against. */
static int  ngx_test_rotation_ok;

static ngx_buf_t *
ngx_http_cache_turbo_redis_sscan_cmd(ngx_pool_t *pool, ngx_str_t *tagkey,
    ngx_str_t *cursor)
{
    static ngx_buf_t  cmd;

    (void) pool; (void) tagkey; (void) cursor;

    return ngx_test_rotation_ok ? &cmd : NULL;
}

static void *
ngx_create_pool(size_t size, void *log)
{
    static ngx_pool_t  rotated;

    (void) size;
    (void) log;

    return ngx_test_rotation_ok ? &rotated : NULL;
}

/* CT-SSCAN-TERMINATE-LEAK: the page settle, STUBBED.
 *
 * The real one walks the page's member array and issues the SREM that strips
 * tag membership, needing the whole L2 surface. The arm under test -- the
 * awaited UNLINK's completion arriving on a TERMINATED request -- returns long
 * before reaching it, and the still-live arm is exercised here only as a
 * negative control against an over-broad change. Counting the call is
 * therefore both sufficient and the honest boundary: it says whether the
 * completion took the live path, without pretending to model the SREM. */
struct ngx_http_cache_turbo_tagpurge_s;
static ngx_uint_t  ngx_test_page_settle_calls;
static ngx_int_t   ngx_test_page_settle_result;

static ngx_int_t
ngx_http_cache_turbo_tag_purge_page_settle(void *tp, ngx_int_t rc)
{
    (void) tp; (void) rc;
    ngx_test_page_settle_calls++;
    return ngx_test_page_settle_result;
}

/* CT-SSCAN-TERMINATE-LEAK: pool destruction is COUNTED, not merely accepted.
 * The awaited UNLINK's completion must release the page scratch exactly once
 * whichever arm it takes, and "exactly once" is only assertable if the shim
 * observes each release. `last_destroyed` lets a test tell WHICH pool went. */
static ngx_uint_t   ngx_test_destroy_pool_calls;
static ngx_pool_t  *ngx_test_last_destroyed_pool;

static void
ngx_destroy_pool(ngx_pool_t *pool)
{
    ngx_test_destroy_pool_calls++;
    ngx_test_last_destroyed_pool = pool;
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

#define NGX_READ_EVENT   0
#define NGX_WRITE_EVENT  1

/* GRIND-C7: poller REGISTRATION. Counted, because a registration counter is
 * the only observable that a genuine ngx_add_event happened -- `active` alone
 * cannot separate "re-added" from "was never removed". */
static ngx_int_t ngx_add_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags) __attribute__((unused));

static ngx_int_t
ngx_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    (void) event;
    (void) flags;

    if (ngx_test_add_event_result != NGX_OK) {
        return ngx_test_add_event_result;
    }

    ev->active = 1;
    ngx_test_add_event_calls++;
    return NGX_OK;
}

static ngx_int_t
ngx_handle_write_event(ngx_event_t *ev, ngx_uint_t flags)
{
    (void) ev;
    (void) flags;
    return ngx_test_handle_write_result;
}

/*
 * GRIND-C7: ngx_handle_read_event, ported FAITHFULLY from nginx's
 * src/event/ngx_event.c rather than stubbed.
 *
 * The stub it replaces returned a canned status and touched nothing, so any
 * assertion about re-arming was vacuous: registered and unregistered were
 * indistinguishable. The whole point of the defect under test is that the real
 * function is NOT unconditional -- under NGX_USE_CLEAR_EVENT (epoll/kqueue)
 * and NGX_USE_LEVEL_EVENT alike it calls ngx_add_event only when
 * `!ev->active && !ev->ready`, so a stale `ready` left over from a consumed
 * reply silently suppresses the registration. Modelling that gate is what
 * makes ngx_test_add_event_calls a real oracle.
 *
 * ngx_test_handle_read_result still forces a failure return for the callers
 * that need one; it is checked first so those tests keep working.
 */
static ngx_int_t
ngx_handle_read_event(ngx_event_t *ev, ngx_uint_t flags)
{
    (void) flags;

    if (ngx_test_handle_read_result != NGX_OK) {
        return ngx_test_handle_read_result;
    }

    if (!ev->active && !ev->ready) {
        if (ngx_add_event(ev, NGX_READ_EVENT, 0) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
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


/* Mirrors nginx's poller de-registration: the suspension calls this to stop the
 * SSCAN connection waking while the walk is parked. */
static ngx_int_t ngx_del_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags) __attribute__((unused));

static ngx_int_t
ngx_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    (void) event;
    (void) flags;
    /* NIT-E: injectable failure, so the suspension's resume_doomed arm -- the
     * branch taken when the connection CANNOT be disarmed -- has coverage
     * instead of being unreachable in both harnesses. */
    if (ngx_test_del_event_result != NGX_OK) {
        return ngx_test_del_event_result;
    }
    ev->active = 0;
    return NGX_OK;
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

/* TODO-REDIS-PAGINATION: the tag walk is SSCAN now, whose reply is parse_scan's
 * [cursor, members] shape -- parse_array went with the SMEMBERS reader. The
 * stub keeps the same observation counters (the assertions are about WHEN the
 * reader parses, not which parser), and yields cursor "0" -- UNLESS a test
 * overrides ngx_test_redis_parse_cursor -- so the stubbed page is the walk's
 * last: read_sscan then takes its completion path rather than rotating a page
 * pool this shim does not provide. The suspension test sets that override
 * precisely because a last page never suspends. */
static ngx_int_t
ngx_http_cache_turbo_redis_parse_scan(
    ngx_http_cache_turbo_redis_op_t *op, ngx_str_t *cursor,
    ngx_str_t **members, ngx_uint_t *nmembers)
{
    static u_char  zero[] = "0";

    (void) op;
    ngx_test_redis_parse_array_calls++;
    /* TODO-UNLINK-REPLY-WINDOW: cursor "0" (a LAST page, so read_sscan
     * completes rather than rotating a pool this shim does not provide) unless
     * a test asks for a non-terminal one. The suspension assertions need a
     * NON-"0" cursor, because a last page never suspends: its callback's
     * verdict is consumed by the completion path instead. */
    if (ngx_test_redis_parse_cursor != NULL) {
        cursor->data = (u_char *) ngx_test_redis_parse_cursor;
        cursor->len = strlen(ngx_test_redis_parse_cursor);
    } else {
        cursor->data = zero;
        cursor->len = 1;
    }
    *members = ngx_test_redis_parse_members;
    *nmembers = ngx_test_redis_parse_nmembers;
    return ngx_test_redis_parse_array_result;
}

static ngx_uint_t
ngx_http_cache_turbo_redis_pool_blocks(ngx_pool_t *pool)
{
    return pool == NULL ? 0 : pool->token;
}

#endif
