/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * http-cache-turbo — L2 Redis driver (v2b).
 *
 * Native nginx client: no hiredis, no libevent adapter. RESP is hand-rolled
 * (the encode side is trivial: *N\r\n$len\r\n<bytes>\r\n per argument). The
 * connection lifecycle uses ngx_event_connect_peer + the worker's epoll loop
 * directly, so there is no per-reply malloc and no extra runtime dependency.
 *
 * This file implements the write path (async write-through SET on store). The
 * sync-on-L1-miss GET + reply parser land in v2b-2. See the design spec:
 * memory/nginx+angie/cache-turbo-module-design.md ("L2 Redis driver decision").
 */

#include "ngx_http_cache_turbo_module.h"


/*
 * One in-flight async redis operation. It owns its own pool so it can outlive
 * the request that spawned it: a write-through SET is fire-and-forget and may
 * still be draining its reply after ngx_http_finalize_request has freed the
 * request pool.
 */
typedef struct {
    ngx_peer_connection_t   peer;
    ngx_pool_t             *pool;
    ngx_buf_t              *send;       /* RESP command, sent then forgotten   */
    ngx_msec_t              timeout;
    u_char                  recv[128];  /* reply scratch; we only need +OK     */
} ngx_http_cache_turbo_redis_op_t;


static void ngx_http_cache_turbo_redis_write(ngx_event_t *wev);
static void ngx_http_cache_turbo_redis_read(ngx_event_t *rev);
static void ngx_http_cache_turbo_redis_close(
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
 * from pool. argv/argc describe the arguments; binary-safe (lengths are
 * explicit, so blob bytes with NULs or CRLF are fine).
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


void
ngx_http_cache_turbo_redis_set(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, u_char *key_hash,
    u_char *blob, size_t blob_len, time_t fresh_ttl)
{
    time_t                            stale_ttl;
    ngx_int_t                         rc;
    ngx_pool_t                       *pool;
    ngx_str_t                         argv[5];
    ngx_connection_t                 *c;
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

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
        return;
    }

    op = ngx_pcalloc(pool, sizeof(ngx_http_cache_turbo_redis_op_t));
    if (op == NULL) {
        ngx_destroy_pool(pool);
        return;
    }
    op->pool = pool;
    op->timeout = clcf->redis_timeout;

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

    op->peer.sockaddr = clcf->redis_addr.sockaddr;
    op->peer.socklen = clcf->redis_addr.socklen;
    op->peer.name = &clcf->redis_addr.name;
    op->peer.get = ngx_event_get_peer;
    op->peer.log = ngx_cycle->log;
    op->peer.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&op->peer);
    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        if (op->peer.connection) {
            ngx_close_connection(op->peer.connection);
        }
        ngx_destroy_pool(pool);
        return;
    }

    c = op->peer.connection;
    c->data = op;
    c->write->handler = ngx_http_cache_turbo_redis_write;
    c->read->handler = ngx_http_cache_turbo_redis_read;

    if (op->timeout) {
        ngx_add_timer(c->write, op->timeout);
    }

    if (rc == NGX_OK) {
        /* connected immediately */
        ngx_http_cache_turbo_redis_write(c->write);
    }
    /* rc == NGX_AGAIN: connect in progress, write handler fires when writable */
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
        ngx_http_cache_turbo_redis_close(op);
        return;
    }

    b = op->send;

    while (b->pos < b->last) {
        n = c->send(c, b->pos, b->last - b->pos);

        if (n == NGX_AGAIN) {
            if (ngx_handle_write_event(wev, 0) != NGX_OK) {
                ngx_http_cache_turbo_redis_close(op);
            }
            return;
        }
        if (n == NGX_ERROR || n == 0) {
            ngx_http_cache_turbo_redis_close(op);
            return;
        }
        b->pos += n;
    }

    /* fully sent; wait for the reply (+OK), reusing the timer */
    if (wev->timer_set) {
        ngx_del_timer(wev);
    }
    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_http_cache_turbo_redis_close(op);
        return;
    }
    if (op->timeout) {
        ngx_add_timer(c->read, op->timeout);
    }
    ngx_http_cache_turbo_redis_read(c->read);
}


static void
ngx_http_cache_turbo_redis_read(ngx_event_t *rev)
{
    ssize_t                           n;
    ngx_connection_t                 *c;
    ngx_http_cache_turbo_redis_op_t  *op;

    c = rev->data;
    op = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "cache_turbo: redis read timed out");
        ngx_http_cache_turbo_redis_close(op);
        return;
    }

    n = c->recv(c, op->recv, sizeof(op->recv));

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_http_cache_turbo_redis_close(op);
        }
        return;
    }

    /* Any reply (+OK / -ERR), EOF, or error: we are done either way. The SET
     * is durable the moment redis acknowledges; fire-and-forget cares no more. */
    if (n > 0 && op->recv[0] == '-') {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "cache_turbo: redis SET error: %*s",
                      (size_t) (n > 64 ? 64 : n), op->recv);
    }
    ngx_http_cache_turbo_redis_close(op);
}


static void
ngx_http_cache_turbo_redis_close(ngx_http_cache_turbo_redis_op_t *op)
{
    ngx_pool_t  *pool = op->pool;

    if (op->peer.connection) {
        ngx_close_connection(op->peer.connection);
    }
    ngx_destroy_pool(pool);
}
