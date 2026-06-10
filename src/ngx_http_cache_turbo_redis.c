/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * http-cache-turbo — L2 Redis driver (v2b).
 *
 * Native nginx client: no hiredis, no libevent adapter. RESP is hand-rolled
 * (encode is trivial: *N\r\n$len\r\n<bytes>\r\n per argument; the reply parser
 * here handles only the bulk-string / nil / error forms GET can return). The
 * connection lifecycle uses ngx_event_connect_peer + the worker's epoll loop
 * directly, so there is no per-reply malloc and no extra runtime dependency.
 *
 *   - SET (write-through, v2b-1): fire-and-forget on store. op->request == NULL.
 *   - GET (sync-on-L1-miss, v2b-2): parks the request (count++, NGX_AGAIN) and
 *     resumes the phase engine when the reply lands. op->request == r.
 *
 * See memory/nginx+angie/cache-turbo-module-design.md ("L2 Redis driver
 * decision" + "Read model — sync on miss").
 */

#include "ngx_http_cache_turbo_module.h"


/* Hard ceiling on a GET reply, so a bogus/huge value can't grow the recv
 * buffer without bound. Comfortably above any sane cached page. */
#define NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY  (64 * 1024 * 1024)


/*
 * One in-flight async redis operation. It owns its own pool so a fire-and-
 * forget SET can outlive the request that spawned it. A GET instead pins the
 * request with count++ and uses op->request to resume it.
 */
typedef struct {
    ngx_peer_connection_t        peer;
    ngx_pool_t                  *pool;
    ngx_buf_t                   *send;     /* RESP command to write           */
    ngx_msec_t                   timeout;

    ngx_http_request_t          *request;  /* GET: parked request; SET: NULL  */
    ngx_http_cache_turbo_ctx_t  *ctx;      /* GET: request ctx to fill        */

    u_char                      *rbuf;     /* GET: growable reply buffer      */
    size_t                       rcap;
    size_t                       rlen;

    u_char                       recv[128];/* SET: reply scratch (+OK / -ERR) */
} ngx_http_cache_turbo_redis_op_t;


static void ngx_http_cache_turbo_redis_write(ngx_event_t *wev);
static void ngx_http_cache_turbo_redis_read_drain(ngx_event_t *rev);
static void ngx_http_cache_turbo_redis_read_get(ngx_event_t *rev);
static void ngx_http_cache_turbo_redis_op_done(
    ngx_http_cache_turbo_redis_op_t *op);
static void ngx_http_cache_turbo_redis_get_finish(
    ngx_http_cache_turbo_redis_op_t *op, ngx_int_t result,
    u_char *blob, size_t blob_len);
static void ngx_http_cache_turbo_redis_op_fail(
    ngx_http_cache_turbo_redis_op_t *op);


size_t
ngx_http_cache_turbo_redis_key(ngx_str_t *prefix, u_char *key_hash, u_char *buf)
{
    u_char  *p;

    p = ngx_cpymem(buf, prefix->data, prefix->len);
    p = ngx_hex_dump(p, key_hash, 32);     /* 32 bytes -> 64 lowercase hex */

    return (size_t) (p - buf);
}


/*
 * Encode a RESP command (array of bulk strings) into a single buffer allocated
 * from pool. Binary-safe: lengths are explicit, so blob bytes with NULs or CRLF
 * are fine.
 */
static ngx_buf_t *
ngx_http_cache_turbo_redis_encode(ngx_pool_t *pool, ngx_str_t *argv,
    ngx_uint_t argc)
{
    size_t      len;
    ngx_uint_t  i;
    ngx_buf_t  *b;
    u_char     *p;

    /* "*<argc>\r\n" then per arg "$<len>\r\n<bytes>\r\n" */
    len = 1 + NGX_INT_T_LEN + 2;
    for (i = 0; i < argc; i++) {
        len += 1 + NGX_SIZE_T_LEN + 2 + argv[i].len + 2;
    }

    b = ngx_create_temp_buf(pool, len);
    if (b == NULL) {
        return NULL;
    }

    p = ngx_sprintf(b->last, "*%ui\r\n", argc);
    for (i = 0; i < argc; i++) {
        p = ngx_sprintf(p, "$%uz\r\n", argv[i].len);
        p = ngx_cpymem(p, argv[i].data, argv[i].len);
        *p++ = CR; *p++ = LF;
    }
    b->last = p;

    return b;
}


/* Open a connection for op and arm the shared write handler. Returns NGX_OK on
 * success (op now owns the connection), NGX_ERROR if it could not start (caller
 * still owns op->pool and must destroy it). */
static ngx_int_t
ngx_http_cache_turbo_redis_connect(ngx_http_cache_turbo_redis_op_t *op,
    ngx_addr_t *addr, void (*read_handler)(ngx_event_t *))
{
    ngx_int_t          rc;
    ngx_connection_t  *c;

    op->peer.sockaddr = addr->sockaddr;
    op->peer.socklen = addr->socklen;
    op->peer.name = &addr->name;
    op->peer.get = ngx_event_get_peer;
    op->peer.log = ngx_cycle->log;
    op->peer.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&op->peer);
    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        if (op->peer.connection) {
            ngx_close_connection(op->peer.connection);
            op->peer.connection = NULL;
        }
        return NGX_ERROR;
    }

    c = op->peer.connection;
    c->data = op;
    c->write->handler = ngx_http_cache_turbo_redis_write;
    c->read->handler = read_handler;

    if (op->timeout) {
        ngx_add_timer(c->write, op->timeout);
    }

    if (rc == NGX_OK) {
        /* Connected immediately. Do NOT run the write handler inline: for a GET
         * an inline failure would resume the request before redis_get has
         * parked it (count++), a use-after-free. Post it so all I/O runs after
         * redis_get/redis_set returns. */
        ngx_post_event(c->write, &ngx_posted_events);
    }
    /* rc == NGX_AGAIN: connect in progress, write handler fires when writable */

    return NGX_OK;
}


/* Allocate an op with its own pool (so it can outlive the spawning request)
 * preloaded with the configured timeout. NULL on failure (pool destroyed). */
static ngx_http_cache_turbo_redis_op_t *
ngx_http_cache_turbo_redis_op_create(ngx_http_cache_turbo_loc_conf_t *clcf)
{
    ngx_pool_t                       *pool;
    ngx_http_cache_turbo_redis_op_t  *op;

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
        return NULL;
    }

    op = ngx_pcalloc(pool, sizeof(ngx_http_cache_turbo_redis_op_t));
    if (op == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    op->pool = pool;
    op->timeout = clcf->redis_timeout;

    return op;
}


void
ngx_http_cache_turbo_redis_set(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, u_char *key_hash,
    u_char *blob, size_t blob_len, time_t fresh_ttl)
{
    time_t                            stale_ttl;
    ngx_pool_t                       *pool;
    ngx_str_t                         argv[5];
    ngx_http_cache_turbo_redis_op_t  *op;
    u_char                           *keybuf, *blobcopy, *msbuf;

    if (!clcf->redis_enable) {
        return;
    }

    /* L2 entry lives as long as the L1 copy could be served stale. */
    stale_ttl = ngx_http_cache_turbo_stale_ttl(fresh_ttl);
    if (stale_ttl <= 0) {
        return;
    }

    op = ngx_http_cache_turbo_redis_op_create(clcf);
    if (op == NULL) {
        return;
    }
    pool = op->pool;

    /* Copy the blob out of the request pool: this op may outlive the request. */
    blobcopy = ngx_pnalloc(pool, blob_len);
    keybuf = ngx_pnalloc(pool, clcf->redis_prefix.len + 64);
    msbuf = ngx_pnalloc(pool, NGX_INT64_LEN);
    if (blobcopy == NULL || keybuf == NULL || msbuf == NULL) {
        ngx_destroy_pool(pool);
        return;
    }
    ngx_memcpy(blobcopy, blob, blob_len);

    argv[0].data = (u_char *) "SET";
    argv[0].len = sizeof("SET") - 1;
    argv[1].data = keybuf;
    argv[1].len = ngx_http_cache_turbo_redis_key(&clcf->redis_prefix,
                                                 key_hash, keybuf);
    argv[2].data = blobcopy;
    argv[2].len = blob_len;
    argv[3].data = (u_char *) "PX";
    argv[3].len = sizeof("PX") - 1;
    argv[4].data = msbuf;
    argv[4].len = (size_t) (ngx_sprintf(msbuf, "%T", stale_ttl * 1000) - msbuf);

    op->send = ngx_http_cache_turbo_redis_encode(pool, argv, 5);
    if (op->send == NULL) {
        ngx_destroy_pool(pool);
        return;
    }

    if (ngx_http_cache_turbo_redis_connect(op, &clcf->redis_addr,
            ngx_http_cache_turbo_redis_read_drain) != NGX_OK)
    {
        ngx_destroy_pool(pool);
    }
}


void
ngx_http_cache_turbo_redis_del(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *key_hash)
{
    ngx_pool_t                       *pool;
    ngx_str_t                         argv[2];
    ngx_http_cache_turbo_redis_op_t  *op;
    u_char                           *keybuf;

    if (!clcf->redis_enable) {
        return;
    }

    op = ngx_http_cache_turbo_redis_op_create(clcf);
    if (op == NULL) {
        return;
    }
    pool = op->pool;

    keybuf = ngx_pnalloc(pool, clcf->redis_prefix.len + 64);
    if (keybuf == NULL) {
        ngx_destroy_pool(pool);
        return;
    }

    argv[0].data = (u_char *) "DEL";
    argv[0].len = sizeof("DEL") - 1;
    argv[1].data = keybuf;
    argv[1].len = ngx_http_cache_turbo_redis_key(&clcf->redis_prefix,
                                                 key_hash, keybuf);

    op->send = ngx_http_cache_turbo_redis_encode(pool, argv, 2);
    if (op->send == NULL) {
        ngx_destroy_pool(pool);
        return;
    }

    if (ngx_http_cache_turbo_redis_connect(op, &clcf->redis_addr,
            ngx_http_cache_turbo_redis_read_drain) != NGX_OK)
    {
        ngx_destroy_pool(pool);
    }
}


ngx_int_t
ngx_http_cache_turbo_redis_get(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx)
{
    ngx_pool_t                       *pool;
    ngx_str_t                         argv[2];
    ngx_http_cache_turbo_redis_op_t  *op;
    u_char                           *keybuf;

    if (!clcf->redis_enable) {
        return NGX_DECLINED;
    }

    op = ngx_http_cache_turbo_redis_op_create(clcf);
    if (op == NULL) {
        return NGX_DECLINED;
    }
    pool = op->pool;
    op->request = r;
    op->ctx = ctx;

    op->rcap = ngx_pagesize * 4;          /* grows on demand up to MAX_REPLY */
    op->rbuf = ngx_pnalloc(pool, op->rcap);
    keybuf = ngx_pnalloc(pool, clcf->redis_prefix.len + 64);
    if (op->rbuf == NULL || keybuf == NULL) {
        ngx_destroy_pool(pool);
        return NGX_DECLINED;
    }

    argv[0].data = (u_char *) "GET";
    argv[0].len = sizeof("GET") - 1;
    argv[1].data = keybuf;
    argv[1].len = ngx_http_cache_turbo_redis_key(&clcf->redis_prefix,
                                                 ctx->key_hash, keybuf);

    op->send = ngx_http_cache_turbo_redis_encode(pool, argv, 2);
    if (op->send == NULL) {
        ngx_destroy_pool(pool);
        return NGX_DECLINED;
    }

    if (ngx_http_cache_turbo_redis_connect(op, &clcf->redis_addr,
            ngx_http_cache_turbo_redis_read_get) != NGX_OK)
    {
        ngx_destroy_pool(pool);
        return NGX_DECLINED;
    }

    /* Parked: hold a reference so the request survives until the reply resumes
     * it (released by ngx_http_finalize_request(NGX_DONE) in get_finish). */
    ctx->l2_pending = 1;
    r->main->count++;

    return NGX_AGAIN;
}


static void
ngx_http_cache_turbo_redis_write(ngx_event_t *wev)
{
    ssize_t                           n;
    ngx_buf_t                        *b;
    ngx_connection_t                 *c;
    ngx_http_cache_turbo_redis_op_t  *op;

    c = wev->data;
    op = c->data;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "cache_turbo: redis write timed out");
        ngx_http_cache_turbo_redis_op_fail(op);
        return;
    }

    b = op->send;

    while (b->pos < b->last) {
        n = c->send(c, b->pos, b->last - b->pos);

        if (n == NGX_AGAIN) {
            if (ngx_handle_write_event(wev, 0) != NGX_OK) {
                ngx_http_cache_turbo_redis_op_fail(op);
            }
            return;
        }
        if (n == NGX_ERROR || n == 0) {
            ngx_http_cache_turbo_redis_op_fail(op);
            return;
        }
        b->pos += n;
    }

    /* fully sent; switch the timer onto the read side and wait for the reply */
    if (wev->timer_set) {
        ngx_del_timer(wev);
    }
    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_http_cache_turbo_redis_op_fail(op);
        return;
    }
    if (op->timeout) {
        ngx_add_timer(c->read, op->timeout);
    }
    c->read->handler(c->read);
}


/* SET reply: we only need redis to have acknowledged; drain one read and stop. */
static void
ngx_http_cache_turbo_redis_read_drain(ngx_event_t *rev)
{
    ssize_t                           n;
    ngx_connection_t                 *c;
    ngx_http_cache_turbo_redis_op_t  *op;

    c = rev->data;
    op = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "cache_turbo: redis read timed out");
        ngx_http_cache_turbo_redis_op_done(op);
        return;
    }

    n = c->recv(c, op->recv, sizeof(op->recv));

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_http_cache_turbo_redis_op_done(op);
        }
        return;
    }

    /* Any reply (+OK / -ERR), EOF, or error: the SET is durable the moment
     * redis acknowledges; fire-and-forget cares no more. */
    if (n > 0 && op->recv[0] == '-') {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "cache_turbo: redis SET error: %*s",
                      (size_t) (n > 64 ? 64 : n), op->recv);
    }
    ngx_http_cache_turbo_redis_op_done(op);
}


/*
 * Parse an accumulated GET reply in op->rbuf[0..op->rlen]. Returns:
 *   NGX_OK       - bulk string complete; blob/blob_len point into rbuf
 *   NGX_AGAIN    - need more bytes
 *   NGX_DECLINED - nil / error / unparseable: treat as an L2 miss
 */
static ngx_int_t
ngx_http_cache_turbo_redis_parse(ngx_http_cache_turbo_redis_op_t *op,
    u_char **blob, size_t *blob_len)
{
    u_char    *p, *crlf, *end;
    ngx_int_t  len;

    p = op->rbuf;
    end = op->rbuf + op->rlen;

    if (p == end) {
        return NGX_AGAIN;
    }

    /* Only a bulk string carries a stored value. nil ($-1), errors (-...),
     * and anything else mean "not a usable L2 value" -> miss. */
    if (*p != '$') {
        return NGX_DECLINED;
    }

    crlf = ngx_strlchr(p + 1, end, CR);
    if (crlf == NULL || crlf + 1 >= end || crlf[1] != LF) {
        return NGX_AGAIN;                  /* length line not complete yet */
    }

    len = ngx_atoi(p + 1, crlf - (p + 1));
    if (len == NGX_ERROR || len < 0) {
        return NGX_DECLINED;               /* $-1 nil, or malformed length */
    }

    if (len > NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY) {
        return NGX_DECLINED;               /* refuse absurd payloads */
    }

    p = crlf + 2;                          /* start of payload */

    if (end - p < len + 2) {               /* payload + trailing CRLF */
        return NGX_AGAIN;
    }

    *blob = p;
    *blob_len = (size_t) len;
    return NGX_OK;
}


/* GET reply: accumulate, parse, then resume the parked request with the value
 * (hit) or a miss. */
static void
ngx_http_cache_turbo_redis_read_get(ngx_event_t *rev)
{
    ssize_t                           n;
    u_char                           *blob, *nbuf;
    size_t                            blob_len, ncap;
    ngx_int_t                         rc;
    ngx_connection_t                 *c;
    ngx_http_cache_turbo_redis_op_t  *op;

    c = rev->data;
    op = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "cache_turbo: redis GET timed out");
        ngx_http_cache_turbo_redis_get_finish(op, NGX_DECLINED, NULL, 0);
        return;
    }

    for ( ;; ) {
        if (op->rlen == op->rcap) {
            /* buffer full but reply incomplete: grow (bounded) */
            if (op->rcap >= NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY) {
                ngx_http_cache_turbo_redis_get_finish(op, NGX_DECLINED, NULL, 0);
                return;
            }
            ncap = op->rcap * 2;
            if (ncap > NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY) {
                ncap = NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY;
            }
            nbuf = ngx_pnalloc(op->pool, ncap);
            if (nbuf == NULL) {
                ngx_http_cache_turbo_redis_get_finish(op, NGX_DECLINED, NULL, 0);
                return;
            }
            ngx_memcpy(nbuf, op->rbuf, op->rlen);
            op->rbuf = nbuf;
            op->rcap = ncap;
        }

        n = c->recv(c, op->rbuf + op->rlen, op->rcap - op->rlen);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_http_cache_turbo_redis_get_finish(op, NGX_DECLINED,
                                                      NULL, 0);
            }
            return;
        }
        if (n == NGX_ERROR || n == 0) {
            /* connection closed/error before a full reply: treat as miss */
            ngx_http_cache_turbo_redis_get_finish(op, NGX_DECLINED, NULL, 0);
            return;
        }

        op->rlen += n;

        rc = ngx_http_cache_turbo_redis_parse(op, &blob, &blob_len);
        if (rc == NGX_AGAIN) {
            continue;                      /* read more */
        }
        if (rc == NGX_OK) {
            ngx_http_cache_turbo_redis_get_finish(op, NGX_OK, blob, blob_len);
        } else {
            ngx_http_cache_turbo_redis_get_finish(op, NGX_DECLINED, NULL, 0);
        }
        return;
    }
}


/* SET path teardown: close the connection and free the op pool. */
static void
ngx_http_cache_turbo_redis_op_done(ngx_http_cache_turbo_redis_op_t *op)
{
    ngx_pool_t  *pool = op->pool;

    if (op->peer.connection) {
        ngx_close_connection(op->peer.connection);
    }
    ngx_destroy_pool(pool);
}


/*
 * GET path teardown + resume. On a hit the blob (which lives in the op pool) is
 * copied into the request pool first, then recorded in ctx; the op pool is torn
 * down, and finally the parked request is resumed through the phase engine and
 * its parked reference released — exactly the park/resume dance error-abuse's
 * async redis adapter uses.
 */
static void
ngx_http_cache_turbo_redis_get_finish(ngx_http_cache_turbo_redis_op_t *op,
    ngx_int_t result, u_char *blob, size_t blob_len)
{
    ngx_http_request_t               *r = op->request;
    ngx_http_cache_turbo_ctx_t       *ctx = op->ctx;
    u_char                           *copy;

    if (result == NGX_OK && blob_len > 0) {
        copy = ngx_pnalloc(r->pool, blob_len);
        if (copy == NULL) {
            result = NGX_DECLINED;
        } else {
            ngx_memcpy(copy, blob, blob_len);
            ctx->l2_blob = copy;
            ctx->l2_blob_len = blob_len;
        }
    }

    ctx->l2_result = result;
    ctx->l2_pending = 0;
    ctx->l2_done = 1;

    /* tear down our own connection + pool (blob is now copied into r->pool) */
    ngx_http_cache_turbo_redis_op_done(op);

    /* resume the parked request, then release the reference taken at park */
    ngx_http_core_run_phases(r);
    ngx_http_run_posted_requests(r->connection);
    ngx_http_finalize_request(r, NGX_DONE);
}


/* Terminal failure on the shared paths: dispatch by op kind. */
static void
ngx_http_cache_turbo_redis_op_fail(ngx_http_cache_turbo_redis_op_t *op)
{
    if (op->request) {
        ngx_http_cache_turbo_redis_get_finish(op, NGX_DECLINED, NULL, 0);
    } else {
        ngx_http_cache_turbo_redis_op_done(op);
    }
}
