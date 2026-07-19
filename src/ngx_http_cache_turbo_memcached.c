/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * http-cache-turbo — L2 memcached driver (v13).
 *
 * A second, deliberately minimal L2 backend behind the same
 * ngx_cache_turbo_backend_t vtable as the Redis driver. It speaks the memcached
 * TEXT protocol over a plain TCP connection on the worker's epoll loop (same
 * native, no-malloc-per-reply, no-extra-dependency model as _redis.c — copy of
 * its connect / write / park-resume structure, minus everything memcached lacks):
 *
 *   - get/set/del/del_raw only. tagkey/tag_add/purge_tag/scan_del/lock/unlock
 *     stay NULL in the vtable: memcached has no SADD/SCAN/atomic SET-NX, so
 *     tag-purge, whole-keyspace purge (?all) and cross-node single-flight are
 *     simply unavailable on this backend (the call sites guard on NULL).
 *   - no AUTH/SELECT preamble, no TLS, no keepalive pool: each op opens a
 *     connection, runs one command, and closes. L2 is advisory, so a failed op
 *     just degrades to an L2 miss / lost write-through — never a request error.
 *   - SET (write-through, fire-and-forget): op->request == NULL.
 *   - GET (sync-on-L1-miss): parks the request (count++, NGX_AGAIN) and resumes
 *     the phase engine when the reply lands. op->request == r.
 *
 * Wire forms used:
 *   set <key> 0 <exptime> <bytes>\r\n<data>\r\n   ->  STORED\r\n
 *   get <key>\r\n   ->  VALUE <key> <flags> <bytes>\r\n<data>\r\nEND\r\n | END\r\n
 *   delete <key>\r\n   ->  DELETED\r\n | NOT_FOUND\r\n
 *
 * The L2 key is the same prefix+hex as Redis (ngx_http_cache_turbo_redis_key):
 * printable, no spaces/control chars, <=250 bytes — valid as a memcached key.
 *
 * See memory/eilandert/nginx-cache-turbo-module/history.md "v13 memcached".
 */

#include "ngx_http_cache_turbo_module.h"


/* memcached's default single-item ceiling is 1 MiB (-I default). A value at or
 * above this would be rejected by the server, so skip an oversized SET locally
 * and cap a GET reply so a bogus huge "VALUE" header can't grow the recv buffer
 * without bound. */
#define NGX_HTTP_CACHE_TURBO_MC_MAX_VALUE  (1024 * 1024)
/* recv-buffer ceiling: value + the "VALUE <key> <flags> <bytes>\r\n" header and
 * trailing "\r\nEND\r\n" — a comfortable slab over MAX_VALUE. */
#define NGX_HTTP_CACHE_TURBO_MC_MAX_REPLY  (NGX_HTTP_CACHE_TURBO_MC_MAX_VALUE \
                                            + 4096)


/*
 * One in-flight async memcached operation. Owns its own pool so a fire-and-
 * forget SET/DELETE can outlive the request that spawned it. A GET pins the
 * request with count++ and uses op->request to resume it.
 */
typedef struct {
    ngx_peer_connection_t             peer;
    ngx_pool_t                       *pool;
    ngx_buf_t                        *send;     /* buffer being written        */
    ngx_msec_t                        timeout;
    ngx_http_cache_turbo_loc_conf_t  *clcf;     /* for keepalive pool config   */

    ngx_http_request_t               *request;  /* GET: parked request         */
    ngx_http_cache_turbo_ctx_t       *ctx;      /* GET: request ctx to fill    */
    void                            (*read_handler)(ngx_event_t *);

    u_char                           *rbuf;     /* GET: growable reply buffer  */
    size_t                            rcap;
    size_t                            rlen;

    u_char                            recv[128];/* SET/DELETE reply scratch    */
} ngx_http_cache_turbo_mc_op_t;


static void ngx_http_cache_turbo_mc_write(ngx_event_t *wev);
static void ngx_http_cache_turbo_mc_read_drain(ngx_event_t *rev);
static void ngx_http_cache_turbo_mc_read_get(ngx_event_t *rev);
static void ngx_http_cache_turbo_mc_op_done(ngx_http_cache_turbo_mc_op_t *op);
static void ngx_http_cache_turbo_mc_get_finish(
    ngx_http_cache_turbo_mc_op_t *op, ngx_int_t result,
    u_char *blob, size_t blob_len);
static void ngx_http_cache_turbo_mc_op_fail(ngx_http_cache_turbo_mc_op_t *op);
static ngx_http_cache_turbo_memcached_ka_bucket_t *
    ngx_http_cache_turbo_mc_ka_bucket(ngx_addr_t *addr, ngx_uint_t create);
static ngx_connection_t *
    ngx_http_cache_turbo_mc_ka_get(ngx_addr_t *addr);
static ngx_uint_t
    ngx_http_cache_turbo_mc_ka_save(ngx_http_cache_turbo_mc_op_t *op);


/* Global memcached keepalive pool. */
ngx_http_cache_turbo_memcached_ka_t ngx_http_cache_turbo_memcached_ka;


/* Locate or create the keepalive bucket for addr. Unlike redis, memcached has
 * no auth/TLS/db, so identity is just peer addr. create=0 for lookup only. */
static ngx_http_cache_turbo_memcached_ka_bucket_t *
ngx_http_cache_turbo_mc_ka_bucket(ngx_addr_t *addr, ngx_uint_t create)
{
    ngx_uint_t                                 i, max;
    ngx_http_cache_turbo_memcached_ka_t       *ka = &ngx_http_cache_turbo_memcached_ka;
    ngx_http_cache_turbo_memcached_ka_bucket_t *b;

    for (i = 0; i < ka->nbuckets; i++) {
        b = &ka->buckets[i];
        if (b->socklen == addr->socklen
            && ngx_memcmp(&b->sockaddr, addr->sockaddr, addr->socklen) == 0) {
            return b;
        }
    }

    if (!create) {
        return NULL;
    }

    if (ka->nbuckets >= NGX_HTTP_CACHE_TURBO_MEMCACHED_KA_MAX_BUCKETS) {
        return NULL;
    }

    b = &ka->buckets[ka->nbuckets];
    max = NGX_HTTP_CACHE_TURBO_KEEPALIVE_MAX; /* use redis cap; memcached uses per-loc override */

    b->items = ngx_palloc(ngx_cycle->pool,
                          max * sizeof(ngx_http_cache_turbo_memcached_ka_item_t));
    if (b->items == NULL) {
        return NULL;
    }

    ngx_queue_init(&b->cache);
    ngx_queue_init(&b->free);
    for (i = 0; i < max; i++) {
        b->items[i].bucket = b;
        ngx_queue_insert_head(&b->free, &b->items[i].queue);
    }

    b->max = max;
    b->count = 0;
    b->timeout = 60000; /* default, overridden at save time from loc_conf */
    b->socklen = addr->socklen;
    ngx_memcpy(&b->sockaddr, addr->sockaddr, addr->socklen);
    b->inited = 1;
    ka->nbuckets++;

    return b;
}


static ngx_connection_t *
ngx_http_cache_turbo_mc_ka_get(ngx_addr_t *addr)
{
    ngx_queue_t                                 *q;
    ngx_connection_t                           *c;
    ngx_http_cache_turbo_memcached_ka_item_t   *item;
    ngx_http_cache_turbo_memcached_ka_bucket_t *b;

    b = ngx_http_cache_turbo_mc_ka_bucket(addr, 0);
    if (b == NULL || ngx_queue_empty(&b->cache)) {
        return NULL;
    }

    q = ngx_queue_head(&b->cache);
    item = ngx_queue_data(q, ngx_http_cache_turbo_memcached_ka_item_t, queue);
    c = item->connection;

    ngx_queue_remove(q);
    ngx_queue_insert_head(&b->free, q);
    b->count--;
    item->connection = NULL;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
    c->idle = 0;
    c->read->handler = NULL;
    c->write->handler = NULL;

    return c;
}


static ngx_uint_t
ngx_http_cache_turbo_mc_ka_save(ngx_http_cache_turbo_mc_op_t *op)
{
    ngx_addr_t                                  addr;
    ngx_queue_t                                *q;
    ngx_connection_t                           *c = op->peer.connection;
    ngx_http_cache_turbo_memcached_ka_item_t   *item;
    ngx_http_cache_turbo_memcached_ka_bucket_t *b;
    ngx_http_cache_turbo_loc_conf_t            *clcf;
    ngx_int_t                                   ka;

    if (c == NULL || op->clcf == NULL) {
        return 0;
    }

    clcf = op->clcf;
    ka = clcf->memcached_keepalive;
    if (ka <= 0) {
        return 0;  /* keepalive disabled */
    }

    addr.sockaddr = op->peer.sockaddr;
    addr.socklen = op->peer.socklen;
    addr.name = *op->peer.name;

    b = ngx_http_cache_turbo_mc_ka_bucket(&addr, 1);
    if (b == NULL || b->count >= (ngx_uint_t) ka) {
        return 0; /* pool full or no pool: close normally */
    }

    if (ngx_queue_empty(&b->free)) {
        return 0;
    }

    q = ngx_queue_head(&b->free);
    item = ngx_queue_data(q, ngx_http_cache_turbo_memcached_ka_item_t, queue);

    ngx_queue_remove(q);
    ngx_queue_insert_head(&b->cache, q);
    b->count++;
    item->connection = c;

    c->idle = 1;
    c->read->handler = NULL;
    c->write->handler = NULL;
    b->timeout = clcf->memcached_keepalive_timeout
                     ? clcf->memcached_keepalive_timeout : 60000;
    ngx_add_timer(c->read, b->timeout);

    return 1;
}


/* Open a connection for op and arm the shared write handler. Returns NGX_OK on
 * success (op now owns the connection), NGX_ERROR if it could not start (caller
 * still owns op->pool and must destroy it). */
static ngx_int_t
ngx_http_cache_turbo_mc_connect(ngx_http_cache_turbo_mc_op_t *op,
    ngx_addr_t *addr, void (*read_handler)(ngx_event_t *))
{
    ngx_int_t          rc;
    ngx_connection_t  *c;

    /* Try keepalive pool first. */
    c = ngx_http_cache_turbo_mc_ka_get(addr);
    if (c != NULL) {
        op->peer.connection = c;
        c->data = op;
        op->read_handler = read_handler;
        c->write->handler = ngx_http_cache_turbo_mc_write;
        c->read->handler = read_handler;

        if (op->timeout) {
            ngx_add_timer(c->write, op->timeout);
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "cache_turbo: memcached reuse pooled fd:%d -> %V",
                       c->fd, addr->name);

        ngx_post_event(c->write, &ngx_posted_events);
        return NGX_OK;
    }

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

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "cache_turbo: memcached connect fd:%d -> %V",
                   c->fd, op->peer.name);

    op->read_handler = read_handler;
    c->write->handler = ngx_http_cache_turbo_mc_write;
    c->read->handler = read_handler;

    if (op->timeout) {
        ngx_add_timer(c->write, op->timeout);
    }

    if (rc == NGX_OK) {
        /* Connected immediately. Do NOT run the write handler inline: for a GET
         * an inline failure would resume the request before mc_get parked it
         * (count++), a use-after-free. Post it so I/O runs after mc_get returns. */
        ngx_post_event(c->write, &ngx_posted_events);
    }
    /* rc == NGX_AGAIN: connect in progress, write handler fires when writable */

    return NGX_OK;
}


/* Allocate an op with its own pool (so it can outlive the spawning request)
 * preloaded with the configured timeout. NULL on failure (pool destroyed). */
static ngx_http_cache_turbo_mc_op_t *
ngx_http_cache_turbo_mc_op_create(ngx_http_cache_turbo_loc_conf_t *clcf)
{
    ngx_pool_t                    *pool;
    ngx_http_cache_turbo_mc_op_t  *op;

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
        return NULL;
    }

    op = ngx_pcalloc(pool, sizeof(ngx_http_cache_turbo_mc_op_t));
    if (op == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    op->pool = pool;
    op->clcf = clcf;
    op->timeout = clcf->redis_timeout;

    return op;
}


static void
ngx_http_cache_turbo_memcached_set(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, u_char *key_hash,
    u_char *blob, size_t blob_len, time_t fresh_ttl)
{
    time_t                         stale_ttl;
    ngx_pool_t                    *pool;
    ngx_buf_t                     *b;
    ngx_http_cache_turbo_mc_op_t  *op;
    u_char                        *keybuf, *p;
    size_t                         keylen, hdr;

    if (!clcf->redis_enable) {
        return;
    }

    /* memcached rejects an item at/above its 1 MiB ceiling; skip oversize so it
     * delegates to L1-only (or native cache, when stacked) without a wire error. */
    if (blob_len >= NGX_HTTP_CACHE_TURBO_MC_MAX_VALUE) {
        return;
    }

    /* L2 entry lives as long as the L1 copy could be served stale. */
    stale_ttl = ngx_http_cache_turbo_stale_ttl(fresh_ttl, clcf->stale_mult);
    if (stale_ttl <= 0) {
        return;
    }
    /* memcached interprets an exptime > 30 days as an ABSOLUTE Unix timestamp,
     * not a relative duration. A large relative window would otherwise be read
     * as a timestamp near the epoch and expire instantly — convert it to a real
     * absolute deadline so long-lived objects persist as intended. */
    if (stale_ttl > 60 * 60 * 24 * 30) {
        stale_ttl = ngx_time() + stale_ttl;
    }

    op = ngx_http_cache_turbo_mc_op_create(clcf);
    if (op == NULL) {
        return;
    }
    pool = op->pool;

    keybuf = ngx_pnalloc(pool, clcf->redis_prefix.len + 64);
    if (keybuf == NULL) {
        ngx_destroy_pool(pool);
        return;
    }
    keylen = ngx_http_cache_turbo_redis_key(&clcf->redis_prefix, key_hash,
                                            keybuf);

    /* "set <key> 0 <exptime> <bytes>\r\n" + <blob> + "\r\n" */
    hdr = sizeof("set ") - 1 + keylen + sizeof(" 0 ") - 1 + NGX_TIME_T_LEN
          + 1 + NGX_SIZE_T_LEN + 2;
    b = ngx_create_temp_buf(pool, hdr + blob_len + 2);
    if (b == NULL) {
        ngx_destroy_pool(pool);
        return;
    }

    p = ngx_sprintf(b->last, "set %*s 0 %T %uz\r\n", keylen, keybuf,
                    stale_ttl, blob_len);
    p = ngx_cpymem(p, blob, blob_len);
    *p++ = CR; *p++ = LF;
    b->last = p;
    op->send = b;

    if (ngx_http_cache_turbo_mc_connect(op, &clcf->redis_addr,
            ngx_http_cache_turbo_mc_read_drain) != NGX_OK)
    {
        ngx_destroy_pool(pool);
    }
}


/* Fire-and-forget a "delete <key>\r\n" for an already-built raw key. The key
 * bytes are copied into the op pool, so they need only be valid for this call. */
static void
ngx_http_cache_turbo_memcached_del_raw(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *key, size_t key_len)
{
    ngx_buf_t                     *b;
    ngx_http_cache_turbo_mc_op_t  *op;
    u_char                        *p;

    if (!clcf->redis_enable) {
        return;
    }

    op = ngx_http_cache_turbo_mc_op_create(clcf);
    if (op == NULL) {
        return;
    }

    b = ngx_create_temp_buf(op->pool,
                            sizeof("delete ") - 1 + key_len + 2);
    if (b == NULL) {
        ngx_destroy_pool(op->pool);
        return;
    }
    p = ngx_cpymem(b->last, "delete ", sizeof("delete ") - 1);
    p = ngx_cpymem(p, key, key_len);
    *p++ = CR; *p++ = LF;
    b->last = p;
    op->send = b;

    if (ngx_http_cache_turbo_mc_connect(op, &clcf->redis_addr,
            ngx_http_cache_turbo_mc_read_drain) != NGX_OK)
    {
        ngx_destroy_pool(op->pool);
    }
}


static void
ngx_http_cache_turbo_memcached_del(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *key_hash)
{
    ngx_pool_t  *tmp;
    u_char      *keybuf;
    size_t       keylen;

    if (!clcf->redis_enable) {
        return;
    }

    /* Build the hex L2 key in a short-lived pool; del_raw copies it before this
     * returns, so the pool can be torn down immediately afterwards. */
    tmp = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (tmp == NULL) {
        return;
    }

    keybuf = ngx_pnalloc(tmp, clcf->redis_prefix.len + 64);
    if (keybuf != NULL) {
        keylen = ngx_http_cache_turbo_redis_key(&clcf->redis_prefix, key_hash,
                                                keybuf);
        ngx_http_cache_turbo_memcached_del_raw(clcf, keybuf, keylen);
    }

    ngx_destroy_pool(tmp);
}


static ngx_int_t
ngx_http_cache_turbo_memcached_get(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx)
{
    ngx_pool_t                    *pool;
    ngx_buf_t                     *b;
    ngx_http_cache_turbo_mc_op_t  *op;
    u_char                        *keybuf, *p;
    size_t                         keylen;

    if (!clcf->redis_enable) {
        return NGX_DECLINED;
    }

    op = ngx_http_cache_turbo_mc_op_create(clcf);
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
    keylen = ngx_http_cache_turbo_redis_key(&clcf->redis_prefix, ctx->key_hash,
                                            keybuf);

    b = ngx_create_temp_buf(pool, sizeof("get ") - 1 + keylen + 2);
    if (b == NULL) {
        ngx_destroy_pool(pool);
        return NGX_DECLINED;
    }
    p = ngx_cpymem(b->last, "get ", sizeof("get ") - 1);
    p = ngx_cpymem(p, keybuf, keylen);
    *p++ = CR; *p++ = LF;
    b->last = p;
    op->send = b;

    if (ngx_http_cache_turbo_mc_connect(op, &clcf->redis_addr,
            ngx_http_cache_turbo_mc_read_get) != NGX_OK)
    {
        ngx_destroy_pool(pool);
        return NGX_DECLINED;
    }

    /* Parked: hold a reference so the request survives until the reply resumes
     * it (released by ngx_http_finalize_request(NGX_DONE) in get_finish). */
    r->main->count++;

    return NGX_AGAIN;
}


/* Shared write handler: drain op->send to the socket, then install the read
 * handler and wait for the reply. */
static void
ngx_http_cache_turbo_mc_write(ngx_event_t *wev)
{
    ssize_t                        n;
    ngx_buf_t                     *b;
    ngx_connection_t              *c;
    ngx_http_cache_turbo_mc_op_t  *op;

    c = wev->data;
    op = c->data;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "cache_turbo: memcached write timed out");
        ngx_http_cache_turbo_mc_op_fail(op);
        return;
    }

    b = op->send;

    while (b->pos < b->last) {
        n = c->send(c, b->pos, b->last - b->pos);

        if (n == NGX_AGAIN) {
            if (ngx_handle_write_event(wev, 0) != NGX_OK) {
                ngx_http_cache_turbo_mc_op_fail(op);
            }
            return;
        }
        if (n == NGX_ERROR || n == 0) {
            ngx_http_cache_turbo_mc_op_fail(op);
            return;
        }
        b->pos += n;
    }

    /* fully sent; switch the timer onto the read side and wait for the reply */
    if (wev->timer_set) {
        ngx_del_timer(wev);
    }
    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_http_cache_turbo_mc_op_fail(op);
        return;
    }
    if (op->timeout) {
        ngx_add_timer(c->read, op->timeout);
    }

    c->read->handler = op->read_handler;
    c->read->handler(c->read);
}


/* SET/DELETE reply: we only need memcached to have acknowledged; drain one read
 * and stop. Fire-and-forget: any reply / EOF / error ends the op. */
static void
ngx_http_cache_turbo_mc_read_drain(ngx_event_t *rev)
{
    ssize_t                        n;
    ngx_connection_t              *c;
    ngx_http_cache_turbo_mc_op_t  *op;

    c = rev->data;
    op = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "cache_turbo: memcached read timed out");
        ngx_http_cache_turbo_mc_op_done(op);
        return;
    }

    n = c->recv(c, op->recv, sizeof(op->recv));

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_http_cache_turbo_mc_op_done(op);
        }
        return;
    }

    /* A non-"STORED"/"DELETED"/"NOT_FOUND" reply (ERROR/CLIENT_ERROR/
     * SERVER_ERROR) is worth a log line, but the op is fire-and-forget either
     * way: L2 is advisory, so we never surface it to the request. */
    if (n > 0
        && ngx_strncmp(op->recv, "STORED", 6) != 0
        && ngx_strncmp(op->recv, "DELETED", 7) != 0
        && ngx_strncmp(op->recv, "NOT_FOUND", 9) != 0)
    {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "cache_turbo: memcached reply: %*s",
                      (size_t) (n > 64 ? 64 : n), op->recv);
    }

    ngx_http_cache_turbo_mc_op_done(op);
}


/*
 * Append one recv() of reply bytes into op->rbuf, growing it (bounded by
 * MAX_REPLY) when full. Returns:
 *   NGX_OK    - op->rlen advanced; caller should re-parse
 *   NGX_AGAIN - nothing readable yet, read event re-armed; caller must return
 *   NGX_ERROR - cap exceeded, alloc failed, or the peer closed/errored
 */
static ngx_int_t
ngx_http_cache_turbo_mc_fill(ngx_http_cache_turbo_mc_op_t *op, ngx_event_t *rev)
{
    ssize_t            n;
    u_char            *nbuf;
    size_t             ncap;
    ngx_connection_t  *c = rev->data;

    if (op->rlen == op->rcap) {
        if (op->rcap >= NGX_HTTP_CACHE_TURBO_MC_MAX_REPLY) {
            return NGX_ERROR;
        }
        ncap = op->rcap * 2;
        if (ncap > NGX_HTTP_CACHE_TURBO_MC_MAX_REPLY) {
            ncap = NGX_HTTP_CACHE_TURBO_MC_MAX_REPLY;
        }
        nbuf = ngx_pnalloc(op->pool, ncap);
        if (nbuf == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(nbuf, op->rbuf, op->rlen);
        op->rbuf = nbuf;
        op->rcap = ncap;
    }

    n = c->recv(c, op->rbuf + op->rlen, op->rcap - op->rlen);

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            return NGX_ERROR;
        }
        return NGX_AGAIN;
    }
    if (n == NGX_ERROR || n == 0) {
        return NGX_ERROR;
    }

    op->rlen += (size_t) n;
    return NGX_OK;
}


/*
 * Parse an accumulated GET reply in op->rbuf[0..op->rlen]. memcached text:
 *   VALUE <key> <flags> <bytes>[ <cas>]\r\n<data>\r\nEND\r\n   (hit)
 *   END\r\n                                                    (miss)
 *   ERROR / CLIENT_ERROR / SERVER_ERROR ...\r\n                (treat as miss)
 * Returns:
 *   NGX_OK       - data complete; blob/blob_len point into rbuf
 *   NGX_AGAIN    - need more bytes
 *   NGX_DECLINED - miss / error / unparseable
 */
static ngx_int_t
ngx_http_cache_turbo_mc_parse(ngx_http_cache_turbo_mc_op_t *op,
    u_char **blob, size_t *blob_len)
{
    u_char    *p, *end, *cr, *q, *sp, *data;
    ngx_int_t  len;

    p = op->rbuf;
    end = op->rbuf + op->rlen;

    if (p == end) {
        return NGX_AGAIN;
    }

    /* locate the end of the first line (CRLF) */
    cr = ngx_strlchr(p, end, CR);
    if (cr == NULL || cr + 1 >= end) {
        return NGX_AGAIN;                  /* header line not complete yet */
    }
    if (cr[1] != LF) {
        return NGX_DECLINED;               /* malformed */
    }

    /* miss: a bare "END" line */
    if (cr - p == 3 && ngx_strncmp(p, "END", 3) == 0) {
        return NGX_DECLINED;
    }

    /* hit: must start with "VALUE " */
    if (cr - p < (ssize_t) (sizeof("VALUE ") - 1)
        || ngx_strncmp(p, "VALUE ", sizeof("VALUE ") - 1) != 0)
    {
        return NGX_DECLINED;               /* ERROR / unexpected line -> miss */
    }

    /* fields after "VALUE ": <key> <flags> <bytes>[ <cas>], up to cr */
    q = p + sizeof("VALUE ") - 1;

    sp = ngx_strlchr(q, cr, ' ');          /* end of key */
    if (sp == NULL) {
        return NGX_DECLINED;
    }
    q = sp + 1;

    sp = ngx_strlchr(q, cr, ' ');          /* end of flags */
    if (sp == NULL) {
        return NGX_DECLINED;
    }
    q = sp + 1;                            /* start of <bytes> */

    sp = ngx_strlchr(q, cr, ' ');          /* optional <cas> separator */
    len = ngx_atoi(q, (sp ? sp : cr) - q);
    if (len == NGX_ERROR || len < 0) {
        return NGX_DECLINED;
    }
    if (len > NGX_HTTP_CACHE_TURBO_MC_MAX_VALUE) {
        return NGX_DECLINED;               /* refuse absurd payloads */
    }

    data = cr + 2;                         /* payload starts after header CRLF */

    /* need: <data> + "\r\n" + "END\r\n" */
    if (end - data < len + (ssize_t) (sizeof("\r\nEND\r\n") - 1)) {
        return NGX_AGAIN;
    }

    *blob = data;
    *blob_len = (size_t) len;
    return NGX_OK;
}


/* GET reply: accumulate, parse, then resume the parked request with the value
 * (hit) or a miss. */
static void
ngx_http_cache_turbo_mc_read_get(ngx_event_t *rev)
{
    u_char                        *blob;
    size_t                         blob_len;
    ngx_int_t                      rc;
    ngx_connection_t              *c;
    ngx_http_cache_turbo_mc_op_t  *op;

    c = rev->data;
    op = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "cache_turbo: memcached GET timed out");
        ngx_http_cache_turbo_mc_get_finish(op, NGX_DECLINED, NULL, 0);
        return;
    }

    for ( ;; ) {
        rc = ngx_http_cache_turbo_mc_fill(op, rev);
        if (rc == NGX_AGAIN) {
            return;                        /* wait for more, or re-arm failed */
        }
        if (rc == NGX_ERROR) {
            ngx_http_cache_turbo_mc_get_finish(op, NGX_DECLINED, NULL, 0);
            return;
        }

        rc = ngx_http_cache_turbo_mc_parse(op, &blob, &blob_len);
        if (rc == NGX_AGAIN) {
            continue;                      /* read more */
        }
        if (rc == NGX_OK) {
            ngx_http_cache_turbo_mc_get_finish(op, NGX_OK, blob, blob_len);
        } else {
            ngx_http_cache_turbo_mc_get_finish(op, NGX_DECLINED, NULL, 0);
        }
        return;
    }
}


/* Op teardown: close the connection and free the op pool. */
static void
ngx_http_cache_turbo_mc_op_done(ngx_http_cache_turbo_mc_op_t *op)
{
    ngx_pool_t        *pool = op->pool;
    ngx_connection_t  *c = op->peer.connection;

    if (c) {
        if (ngx_http_cache_turbo_mc_ka_save(op)) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "cache_turbo: memcached conn park fd:%d", c->fd);
            /* conn is now in the pool, don't close */
            op->peer.connection = NULL;
        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "cache_turbo: memcached conn close fd:%d", c->fd);
            ngx_close_connection(c);
        }
    }
    ngx_destroy_pool(pool);
}


/*
 * GET path teardown + resume. On a hit the blob (which lives in the op pool) is
 * copied into the request pool first, then recorded in ctx; the op pool is torn
 * down, and finally the parked request is resumed through the phase engine and
 * its parked reference released — the same park/resume dance as the Redis driver.
 */
static void
ngx_http_cache_turbo_mc_get_finish(ngx_http_cache_turbo_mc_op_t *op,
    ngx_int_t result, u_char *blob, size_t blob_len)
{
    ngx_http_request_t          *r = op->request;
    ngx_http_cache_turbo_ctx_t  *ctx = op->ctx;
    u_char                      *copy;

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
    ctx->l2_done = 1;

    /* tear down our own connection + pool (blob is now copied into r->pool) */
    ngx_http_cache_turbo_mc_op_done(op);

    /* resume the parked request, then release the reference taken at park */
    ngx_http_core_run_phases(r);
    ngx_http_run_posted_requests(r->connection);
    ngx_http_finalize_request(r, NGX_DONE);
}


/* Terminal failure on the write path: a parked GET resumes as a miss; a fire-
 * and-forget SET/DELETE just tears down. */
static void
ngx_http_cache_turbo_mc_op_fail(ngx_http_cache_turbo_mc_op_t *op)
{
    if (op->request) {
        ngx_http_cache_turbo_mc_get_finish(op, NGX_DECLINED, NULL, 0);
    } else {
        ngx_http_cache_turbo_mc_op_done(op);
    }
}


/* L2 memcached backend instance. Only get/set/del/del_raw are implemented;
 * tagkey/tag_add/purge_tag/scan_del/lock/unlock stay NULL — memcached has no
 * SADD/SCAN/atomic SET-NX, so tag-purge, ?all whole-keyspace purge and cross-
 * node single-flight are unavailable on this backend (call sites guard NULL). */
ngx_cache_turbo_backend_t  ngx_http_cache_turbo_memcached_backend = {
    ngx_string("memcached"),
    ngx_http_cache_turbo_memcached_get,
    ngx_http_cache_turbo_memcached_set,
    ngx_http_cache_turbo_memcached_del,
    ngx_http_cache_turbo_memcached_del_raw,
    NULL,   /* tagkey    — no tag sets   */
    NULL,   /* tag_add   — no tag sets   */
    NULL,   /* tag_add_many — no tag sets */
    NULL,   /* purge_tag — no SMEMBERS   */
    NULL,   /* scan_del  — no SCAN       */
    NULL,   /* lock      — no atomic NX  */
    NULL,   /* unlock                    */
};
