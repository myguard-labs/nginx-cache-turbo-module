/*
 * Event/connection surface for the sliced Redis reply readers
 * ngx_http_cache_turbo_redis_read_preamble() and _read_lock()
 * (generated_redis_readers.inc, from extract_redis_readers.sh).
 *
 * Include after ngx_shim.h and generated_parser.inc (read_lock calls the
 * sliced _frame()). Everything the two handlers touch outside the op struct is
 * here, reduced to the fields and semantics they use:
 *
 *   - c->recv() is the fuzz transport. It copies the next scheduled chunk into
 *     the reader's buffer, never more than the space it was offered (as a
 *     socket recv() does), and returns NGX_AGAIN when the current chunk is
 *     spent or 0 (EOF) once the whole reply has been delivered. Bytes it did
 *     not write are ASan-poisoned up to the end of the offered space, so a
 *     reader that looks at recv[] past recv_len is a heap-buffer-overflow
 *     report even though recv[] is an in-struct array.
 *   - ngx_http_cache_turbo_redis_op_fail / _lock_finish record the terminal
 *     verdict instead of tearing a request down; _write is a marker symbol the
 *     preamble reader installs as the write handler on success.
 *   - ngx_handle_read_event succeeds, timers and logging are no-ops,
 *     ngx_post_event records that the write event was posted.
 */

#ifndef NGX_CACHE_TURBO_FUZZ_SHIM_REDIS_READERS_H
#define NGX_CACHE_TURBO_FUZZ_SHIM_REDIS_READERS_H

#include <sys/types.h>      /* ssize_t */

#include "ngx_shim.h"         /* ngx_int_t, NGX_OK, the op struct */

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define NGX_FUZZ_ASAN  1
#endif
#endif
#if defined(__SANITIZE_ADDRESS__) && !defined(NGX_FUZZ_ASAN)
#define NGX_FUZZ_ASAN  1
#endif

#if defined(NGX_FUZZ_ASAN)
#include <sanitizer/asan_interface.h>
#define ngx_fuzz_poison(p, n)    ASAN_POISON_MEMORY_REGION(p, n)
#define ngx_fuzz_unpoison(p, n)  ASAN_UNPOISON_MEMORY_REGION(p, n)
#else
#define ngx_fuzz_poison(p, n)    ((void) (p), (void) (n))
#define ngx_fuzz_unpoison(p, n)  ((void) (p), (void) (n))
#endif

typedef struct ngx_event_s       ngx_event_t;
typedef struct ngx_connection_s  ngx_connection_t;
typedef void                     ngx_log_t;
typedef ssize_t (*ngx_recv_pt)(ngx_connection_t *c, u_char *buf, size_t size);
typedef void (*ngx_event_handler_pt)(ngx_event_t *ev);

struct ngx_event_s {
    void                  *data;
    ngx_event_handler_pt   handler;
    unsigned               timedout:1;
};

/* The scripted transport behind c->recv(): chunk boundaries are offsets into
 * `reply`. `chunk_end` is where the chunk being handed out stops; the driver
 * advances it between handler invocations.
 *
 * Two peer schedules for the end of the reply, selected by `eof_late`:
 *   0  (default) early EOF: once pos >= len every recv() returns 0, so the
 *      recv() that follows the final bytes sees EOF in the SAME handler wake.
 *   1  late EOF: the first recv() at pos >= len returns NGX_AGAIN (buffer
 *      poisoned, as for a spent segment); only a recv() in a LATER wake
 *      returns 0. The driver bumps `wake` before each handler invocation.
 * `again_wake` (wake + 1 of the late NGX_AGAIN, 0 = not yet issued) and
 * `eof_hit` (a recv() has returned 0) are driver-visible bookkeeping. */
typedef struct {
    const u_char  *reply;
    size_t         len;
    size_t         pos;
    size_t         chunk_end;
    unsigned       eof_late;
    size_t         wake;
    size_t         again_wake;
    unsigned       eof_hit;
} ngx_fuzz_wire_t;

struct ngx_connection_s {
    void             *data;
    ngx_recv_pt       recv;
    ngx_event_t      *read;
    ngx_event_t      *write;
    ngx_log_t        *log;
    ngx_fuzz_wire_t  *wire;
};

#define NGX_LOG_ERR    4
#define NGX_LOG_INFO   7
#define NGX_ETIMEDOUT  110

/* nginx's ngx_log_error() is variadic; the readers' arguments have no side
 * effects, so dropping them is faithful. */
#define ngx_log_error(level, log, err, ...)  ((void) 0)

#define ngx_add_timer(ev, timer)  ((void) (ev), (void) (timer))

/* read_lock matches the exact nil reply. Verbatim from nginx
 * src/core/ngx_core.h and src/core/ngx_string.h. */
#define CRLF  "\r\n"
#define ngx_memcmp(s1, s2, n)  memcmp(s1, s2, n)

typedef struct {
    int  fuzz_unused;
} ngx_queue_t;

static ngx_queue_t  ngx_posted_events;

/* Terminal-outcome recorder shared by both readers. */
typedef struct {
    ngx_uint_t  fails;          /* op_fail() calls (preamble)              */
    ngx_uint_t  finishes;       /* lock_finish() calls                     */
    ngx_int_t   lock_result;    /* last lock_finish() result               */
    ngx_uint_t  posted;         /* ngx_post_event() calls                  */
    ngx_uint_t  backoff_clears;
} ngx_fuzz_reader_rec_t;

static ngx_fuzz_reader_rec_t  ngx_fuzz_rec;

static void
ngx_post_event(ngx_event_t *ev, ngx_queue_t *q)
{
    (void) ev;
    (void) q;
    ngx_fuzz_rec.posted++;
}

static ngx_int_t
ngx_handle_read_event(ngx_event_t *rev, ngx_uint_t flags)
{
    (void) rev;
    (void) flags;
    return NGX_OK;
}

/* The readers call ngx_http_cache_turbo_redis_backoff_clear(
 * &op->clcf->redis_addr). The shim loc conf has no redis_addr (adding one
 * would change every `{ max_size }` initializer the other harnesses use), so
 * the macro drops the argument unevaluated -- it has no side effects -- and
 * only counts the call. */
#define ngx_http_cache_turbo_redis_backoff_clear(addr)                       \
    ngx_fuzz_backoff_clear()

static void
ngx_fuzz_backoff_clear(void)
{
    ngx_fuzz_rec.backoff_clears++;
}

static void
ngx_http_cache_turbo_redis_op_fail(ngx_http_cache_turbo_redis_op_t *op)
{
    (void) op;
    ngx_fuzz_rec.fails++;
}

static void
ngx_http_cache_turbo_redis_lock_finish(ngx_http_cache_turbo_redis_op_t *op,
    ngx_int_t result)
{
    (void) op;
    ngx_fuzz_rec.finishes++;
    ngx_fuzz_rec.lock_result = result;
}

/* Marker only: the preamble reader installs it as c->write->handler. */
static void
ngx_http_cache_turbo_redis_write(ngx_event_t *wev)
{
    (void) wev;
}

static ssize_t
ngx_fuzz_wire_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ngx_fuzz_wire_t  *w = c->wire;
    size_t            n;

    ngx_fuzz_unpoison(buf, size);

    if (w->pos >= w->len) {
        if (w->eof_late && (w->again_wake == 0 || w->again_wake == w->wake + 1))
        {
            w->again_wake = w->wake + 1;
            ngx_fuzz_poison(buf, size);
            return NGX_AGAIN;          /* peer idle; EOF comes on a later wake */
        }
        w->eof_hit = 1;
        n = 0;                         /* EOF: the peer has said everything */

    } else if (w->pos >= w->chunk_end) {
        ngx_fuzz_poison(buf, size);
        return NGX_AGAIN;              /* this segment is spent */

    } else {
        n = w->chunk_end - w->pos;
        if (n > size) {
            n = size;
        }
        memcpy(buf, w->reply + w->pos, n);
        w->pos += n;
    }

    ngx_fuzz_poison(buf + n, size - n);
    return (ssize_t) n;
}

#endif /* NGX_CACHE_TURBO_FUZZ_SHIM_REDIS_READERS_H */
