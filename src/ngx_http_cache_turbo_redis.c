/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
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

#if (NGX_SSL)
#include <ngx_event_openssl.h>
#endif


/* Hard ceiling on a GET reply, so a bogus/huge value can't grow the recv
 * buffer without bound. Comfortably above any sane cached page. */
#define NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY  (64 * 1024 * 1024)

/* Upper bound on an array reply element count, so a bogus "*<huge>" header
 * can't make us allocate an enormous members array before any data arrives. */
#define NGX_HTTP_CACHE_TURBO_REDIS_MAX_MEMBERS  (1024 * 1024)


/*
 * One in-flight async redis operation. It owns its own pool so a fire-and-
 * forget SET can outlive the request that spawned it. A GET instead pins the
 * request with count++ and uses op->request to resume it.
 */
typedef struct {
    ngx_peer_connection_t        peer;
    ngx_pool_t                  *pool;
    ngx_buf_t                   *send;     /* buffer currently being written  */
    ngx_msec_t                   timeout;

    ngx_http_request_t          *request;  /* GET/SMEMBERS/SCAN/lock: parked req */
    ngx_http_cache_turbo_ctx_t  *ctx;      /* GET/lock: request ctx to fill   */
    ngx_http_cache_turbo_loc_conf_t *clcf; /* DSN/TLS + SCAN rebuild + del_raw */
    unsigned                     is_lock:1;/* lock op (deposits ctx->lock_*)  */
    unsigned                     reused:1; /* conn came from keepalive pool   */
    unsigned                     clean:1;  /* reply fully consumed at boundary:
                                            * connection is reusable (v15)     */

    /* AUTH/SELECT preamble (v5 DSN). When the backend needs auth or a non-zero
     * db, `preamble` holds the pipelined AUTH (+SELECT) RESP; it is written
     * first and its `preamble_replies` simple replies consumed before `command`
     * (the real op) is written and `read_handler` installed. */
    ngx_buf_t                   *command;     /* the real RESP op             */
    ngx_buf_t                   *preamble;    /* AUTH/SELECT, or NULL          */
    ngx_uint_t                   preamble_replies;
    unsigned                     in_preamble:1;
    void                       (*read_handler)(ngx_event_t *); /* real reader  */

    /* SMEMBERS / SCAN: completion callback + opaque data (purge policy) */
    ngx_http_cache_turbo_redis_members_pt  members_cb;
    void                        *members_data;

    /* read_drain (fire-and-forget) only: how many top-level RESP replies the
     * pipelined command produces. The connection is poolable (clean=1) only
     * once ALL of them are fully framed (STAB-1). DEL = 1, tag_add = 3. */
    ngx_uint_t                   expected_replies;

    u_char                      *rbuf;     /* GET/SMEMBERS: growable reply buf */
    size_t                       rcap;
    size_t                       rlen;

    u_char                       recv[256];/* SET/lock/preamble reply scratch */
    size_t                       recv_len; /* bytes buffered in recv[]        */
} ngx_http_cache_turbo_redis_op_t;


static void ngx_http_cache_turbo_redis_write(ngx_event_t *wev);
static void ngx_http_cache_turbo_redis_read_preamble(ngx_event_t *rev);
static void ngx_http_cache_turbo_redis_read_drain(ngx_event_t *rev);
static void ngx_http_cache_turbo_redis_read_get(ngx_event_t *rev);
static void ngx_http_cache_turbo_redis_read_smembers(ngx_event_t *rev);
static void ngx_http_cache_turbo_redis_read_lock(ngx_event_t *rev);
static void ngx_http_cache_turbo_redis_read_scan(ngx_event_t *rev);
static void ngx_http_cache_turbo_redis_lock_finish(
    ngx_http_cache_turbo_redis_op_t *op, ngx_int_t result);
static void ngx_http_cache_turbo_redis_op_done(
    ngx_http_cache_turbo_redis_op_t *op);
static void ngx_http_cache_turbo_redis_get_finish(
    ngx_http_cache_turbo_redis_op_t *op, ngx_int_t result,
    u_char *blob, size_t blob_len);
static void ngx_http_cache_turbo_redis_smembers_finish(
    ngx_http_cache_turbo_redis_op_t *op, ngx_str_t *members,
    ngx_uint_t nmembers);
static void ngx_http_cache_turbo_redis_op_fail(
    ngx_http_cache_turbo_redis_op_t *op);
static ngx_int_t ngx_http_cache_turbo_redis_launch(
    ngx_http_cache_turbo_redis_op_t *op,
    ngx_http_cache_turbo_loc_conf_t *clcf, void (*read_handler)(ngx_event_t *));
static ngx_int_t ngx_http_cache_turbo_redis_frame(u_char *p, u_char *end,
    ngx_uint_t depth, u_char **next);
#if (NGX_SSL)
static void ngx_http_cache_turbo_redis_tls_handshake(ngx_event_t *ev);
static void ngx_http_cache_turbo_redis_tls_handshake_done(
    ngx_connection_t *c);
#endif


/* ------------------------------------------------------------------------- *
 * Keepalive pool (v15)
 *
 * A per-worker (process-global) cache of idle L2 connections, keyed by peer
 * addr, so an op reuses a live TCP connection instead of connect()+close per
 * op. Modelled on ngx_http_upstream_keepalive: a fixed array of items split
 * between a `cache` queue (holding a live idle connection) and a `free` queue
 * (empty slots). An idle pooled connection carries a close-on-readable handler
 * (peer hung up / sent unsolicited data -> drop) plus an idle timer.
 *
 * TLS pooling (v15-2): a TLS connection's c->ssl is allocated from a dedicated
 * connection-owned pool (created in redis_connect, parented at worker lifetime),
 * NOT the op pool — so the conn (and its live, already-handshaked, already-AUTH'd
 * TLS session) outlives the op that opened it and can be reused with neither a
 * handshake nor a preamble. The same TLS channel persists across reuse, so no
 * re-handshake or cert re-verification is needed; only liveness is re-checked
 * (boundary peek on save + close-on-readable handler while idle). Pool entries
 * carry a `tls` bit so a TLS op never reuses a plaintext conn or vice versa.
 * A reused dead connection (redis closed it between park and reuse) just fails
 * the op, which degrades to an L2 miss / lost fire-and-forget write / serve-
 * stale — all safe, since L2 is advisory.
 * ------------------------------------------------------------------------- */

typedef struct {
    ngx_queue_t        queue;
    ngx_connection_t  *connection;
    socklen_t          socklen;
    unsigned           tls:1;          /* pooled conn is TLS (match on reuse) */
    unsigned           tls_verify:1;   /* exact-match field (SEC-3)           */
    uint32_t           ctx_fp;         /* security-context fingerprint (fast pre-filter) */
    ngx_int_t          db;             /* SEC-3 exact-match profile fields...  */
    ngx_str_t          user;           /* (data points into the config pool,  */
    ngx_str_t          password;       /*  which outlives this worker, so no   */
    ngx_str_t          tls_ca;         /*  copy is needed)                     */
    ngx_str_t          tls_name;
    ngx_str_t          host;
    ngx_sockaddr_t     sockaddr;       /* copy of peer addr, for match */
} ngx_http_cache_turbo_redis_ka_item_t;


/* Fingerprint the security context a pooled connection was opened under. Reuse
 * skips the AUTH/SELECT preamble (and, for TLS, cert verification), so a pooled
 * conn may ONLY be handed to a location with the IDENTICAL db, credentials and
 * TLS trust — otherwise ops would run on the wrong db or under the wrong
 * identity. The peer address and `tls` bit are matched separately; everything
 * else that changes the connection's authenticated state folds in here. */
static uint32_t
ngx_http_cache_turbo_redis_ka_fp(ngx_http_cache_turbo_loc_conf_t *clcf)
{
    uint32_t  crc;
    u_char    flags[2];

    ngx_crc32_init(crc);

    flags[0] = (u_char) (clcf->redis_tls_verify ? 1 : 0);
    flags[1] = 0;
    ngx_crc32_update(&crc, flags, sizeof(flags));
    ngx_crc32_update(&crc, (u_char *) &clcf->redis_db, sizeof(clcf->redis_db));

    /* NUL-separated so field boundaries can't alias (""+"ab" vs "a"+"b"). */
    ngx_crc32_update(&crc, clcf->redis_user.data, clcf->redis_user.len);
    ngx_crc32_update(&crc, (u_char *) "", 1);
    ngx_crc32_update(&crc, clcf->redis_password.data, clcf->redis_password.len);
    ngx_crc32_update(&crc, (u_char *) "", 1);
    ngx_crc32_update(&crc, clcf->redis_tls_ca.data, clcf->redis_tls_ca.len);
    ngx_crc32_update(&crc, (u_char *) "", 1);
    ngx_crc32_update(&crc, clcf->redis_tls_name.data, clcf->redis_tls_name.len);
    ngx_crc32_update(&crc, (u_char *) "", 1);
    ngx_crc32_update(&crc, clcf->redis_host.data, clcf->redis_host.len);

    ngx_crc32_final(crc);
    return crc;
}


static ngx_inline ngx_int_t
ngx_http_cache_turbo_str_eq(ngx_str_t *a, ngx_str_t *b)
{
    return a->len == b->len
           && (a->len == 0 || ngx_memcmp(a->data, b->data, a->len) == 0);
}


/* SEC-3: exact security-context match. The CRC fingerprint (ka_fp) is only a
 * fast O(1) pre-filter — a 32-bit collision could otherwise hand a pooled conn
 * (which skips the AUTH/SELECT/cert-verify preamble) to a location with a
 * DIFFERENT db/credential/TLS-trust profile. This compares the profile fields
 * byte-for-byte, so reuse is exact. The item's ngx_str_t values reference the
 * config pool (process/worker lifetime), so no copy is needed. */
static ngx_int_t
ngx_http_cache_turbo_redis_ka_profile_eq(
    ngx_http_cache_turbo_redis_ka_item_t *item,
    ngx_http_cache_turbo_loc_conf_t *clcf)
{
    return item->db == clcf->redis_db
        && item->tls_verify == (unsigned) (clcf->redis_tls_verify ? 1 : 0)
        && ngx_http_cache_turbo_str_eq(&item->user, &clcf->redis_user)
        && ngx_http_cache_turbo_str_eq(&item->password, &clcf->redis_password)
        && ngx_http_cache_turbo_str_eq(&item->tls_ca, &clcf->redis_tls_ca)
        && ngx_http_cache_turbo_str_eq(&item->tls_name, &clcf->redis_tls_name)
        && ngx_http_cache_turbo_str_eq(&item->host, &clcf->redis_host);
}

typedef struct {
    ngx_uint_t   inited;
    ngx_uint_t   max;                  /* cap (cache_turbo_redis keepalive=N) */
    ngx_uint_t   count;                /* live idle connections held */
    ngx_msec_t   timeout;              /* idle close timeout */
    ngx_queue_t  cache;                /* items holding a live connection */
    ngx_queue_t  free;                 /* empty item slots */
    ngx_http_cache_turbo_redis_ka_item_t *items;
} ngx_http_cache_turbo_redis_ka_t;

/* Process-global: each worker gets its own copy after fork. */
static ngx_http_cache_turbo_redis_ka_t  ngx_http_cache_turbo_redis_ka;

static void ngx_http_cache_turbo_redis_ka_close_handler(ngx_event_t *ev);
static void ngx_http_cache_turbo_redis_ka_dummy_handler(ngx_event_t *ev);


/* Lazily build the per-worker item array sized to the first-seen keepalive cap.
 * Items live in ngx_cycle->pool (worker lifetime). Returns 0 if keepalive is
 * off or the array cannot be allocated. */
static ngx_uint_t
ngx_http_cache_turbo_redis_ka_init(ngx_http_cache_turbo_loc_conf_t *clcf)
{
    ngx_uint_t                              i, max;
    ngx_http_cache_turbo_redis_ka_t        *ka = &ngx_http_cache_turbo_redis_ka;

    if (clcf->redis_keepalive <= 0) {
        return 0;
    }

    if (ka->inited) {
        return ka->max > 0;
    }

    ka->inited = 1;
    max = (ngx_uint_t) clcf->redis_keepalive;

    ka->items = ngx_palloc(ngx_cycle->pool,
                           max * sizeof(ngx_http_cache_turbo_redis_ka_item_t));
    if (ka->items == NULL) {
        ka->max = 0;
        return 0;
    }

    ngx_queue_init(&ka->cache);
    ngx_queue_init(&ka->free);
    for (i = 0; i < max; i++) {
        ngx_queue_insert_head(&ka->free, &ka->items[i].queue);
    }

    ka->max = max;
    ka->count = 0;
    ka->timeout = clcf->redis_keepalive_timeout
                      ? clcf->redis_keepalive_timeout : 60000;

    return 1;
}


/* Close a pooled connection and return its slot to the free queue. */
static void
ngx_http_cache_turbo_redis_ka_drop(ngx_http_cache_turbo_redis_ka_item_t *item)
{
    ngx_connection_t                 *c = item->connection;
    ngx_http_cache_turbo_redis_ka_t  *ka = &ngx_http_cache_turbo_redis_ka;

    ngx_queue_remove(&item->queue);
    ngx_queue_insert_head(&ka->free, &item->queue);
    ka->count--;

    item->connection = NULL;
    if (c) {
#if (NGX_SSL)
        ngx_pool_t  *cpool = c->pool;  /* conn-owned pool (TLS) or NULL (plain) */

        if (c->ssl) {
            c->ssl->no_wait_shutdown = 1;
            (void) ngx_ssl_shutdown(c); /* best-effort close_notify */
        }
        c->pool = NULL;
        ngx_close_connection(c);
        if (cpool) {
            ngx_destroy_pool(cpool);
        }
#else
        ngx_close_connection(c);       /* plain conn: c->pool is NULL */
#endif
    }
}


/* Pop a live pooled connection matching `addr` for reuse, or NULL. On success
 * the caller owns the connection: it must install its own read/write handlers
 * and either reuse or close it. */
static ngx_connection_t *
ngx_http_cache_turbo_redis_ka_get(ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_addr_t *addr)
{
    ngx_queue_t                            *q;
    ngx_connection_t                       *c;
    ngx_http_cache_turbo_redis_ka_item_t   *item;
    ngx_http_cache_turbo_redis_ka_t        *ka = &ngx_http_cache_turbo_redis_ka;
    ngx_uint_t                              want_tls = clcf->redis_tls ? 1 : 0;
    uint32_t                                want_fp = ngx_http_cache_turbo_redis_ka_fp(clcf);

    if (!ngx_http_cache_turbo_redis_ka_init(clcf)) {
        return NULL;
    }

    for (q = ngx_queue_head(&ka->cache);
         q != ngx_queue_sentinel(&ka->cache);
         q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_http_cache_turbo_redis_ka_item_t, queue);

        if (item->tls == want_tls
            && item->ctx_fp == want_fp
            && item->socklen == addr->socklen
            && ngx_memcmp(&item->sockaddr, addr->sockaddr, addr->socklen) == 0
            && ngx_http_cache_turbo_redis_ka_profile_eq(item, clcf))
        {
            c = item->connection;

            ngx_queue_remove(q);
            ngx_queue_insert_head(&ka->free, q);
            ka->count--;
            item->connection = NULL;

            if (c->read->timer_set) {
                ngx_del_timer(c->read);
            }
            c->idle = 0;
            c->read->handler = NULL;
            c->write->handler = NULL;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "cache_turbo: redis reuse pooled conn fd:%d (%ui left)",
                           c->fd, ka->count);
            return c;
        }
    }

    return NULL;
}


/* Park op's connection on the idle pool if it is reusable. Returns 1 if parked
 * (caller must NOT close it), 0 if the caller should close it as usual. */
static ngx_uint_t
ngx_http_cache_turbo_redis_ka_save(ngx_http_cache_turbo_redis_op_t *op)
{
    u_char                                  scratch[1];
    ssize_t                                 n;
    ngx_queue_t                            *q;
    ngx_connection_t                       *c = op->peer.connection;
    ngx_http_cache_turbo_redis_ka_item_t   *item;
    ngx_http_cache_turbo_redis_ka_t        *ka = &ngx_http_cache_turbo_redis_ka;

    if (!op->clean || c == NULL || op->clcf == NULL) {
        return 0;
    }
    if (c->read->error || c->write->error || c->read->eof
        || c->read->timedout || c->write->timedout || c->error)
    {
        return 0;
    }
    if (!ngx_http_cache_turbo_redis_ka_init(op->clcf)) {
        return 0;
    }
    if (ka->count >= ka->max || ngx_queue_empty(&ka->free)) {
        return 0;                          /* pool full: close it */
    }

    /* The stream must be exactly at a reply boundary: redis should have nothing
     * more to send. A readable byte here means leftover/unsolicited data (or a
     * close) — don't pool a connection we can't trust. */
    n = c->recv(c, scratch, sizeof(scratch));
    if (n != NGX_AGAIN) {
        return 0;
    }

    q = ngx_queue_head(&ka->free);
    ngx_queue_remove(q);
    item = ngx_queue_data(q, ngx_http_cache_turbo_redis_ka_item_t, queue);
    ngx_queue_insert_head(&ka->cache, q);
    ka->count++;

    item->connection = c;
    item->socklen = op->peer.socklen;
    item->tls = c->ssl ? 1 : 0;
    item->ctx_fp = ngx_http_cache_turbo_redis_ka_fp(op->clcf);
    /* SEC-3 exact-match profile snapshot (config-pool-backed, no copy). */
    item->tls_verify = op->clcf->redis_tls_verify ? 1 : 0;
    item->db = op->clcf->redis_db;
    item->user = op->clcf->redis_user;
    item->password = op->clcf->redis_password;
    item->tls_ca = op->clcf->redis_tls_ca;
    item->tls_name = op->clcf->redis_tls_name;
    item->host = op->clcf->redis_host;
    ngx_memcpy(&item->sockaddr, op->peer.sockaddr, op->peer.socklen);

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    c->data = item;
    c->read->handler = ngx_http_cache_turbo_redis_ka_close_handler;
    c->write->handler = ngx_http_cache_turbo_redis_ka_dummy_handler;
    c->idle = 1;                           /* core closes on worker shutdown */

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_http_cache_turbo_redis_ka_drop(item);
        return 1;                          /* drop closed it; do not double-close */
    }

    ngx_add_timer(c->read, ka->timeout);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "cache_turbo: redis pool conn fd:%d (%ui idle)",
                   c->fd, ka->count);
    return 1;
}


/* Idle pooled connection became readable (peer closed or sent unsolicited
 * data) or the idle timer fired: drop it. */
static void
ngx_http_cache_turbo_redis_ka_close_handler(ngx_event_t *ev)
{
    ngx_connection_t                       *c = ev->data;
    ngx_http_cache_turbo_redis_ka_item_t   *item = c->data;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "cache_turbo: redis pooled conn fd:%d dropped (%s)",
                   c->fd, ev->timedout ? "idle timeout" : "peer event");
    ngx_http_cache_turbo_redis_ka_drop(item);
}


static void
ngx_http_cache_turbo_redis_ka_dummy_handler(ngx_event_t *ev)
{
    /* An idle pooled connection should never get a write event; ignore it. */
}


size_t
ngx_http_cache_turbo_redis_key(ngx_str_t *prefix, u_char *key_hash, u_char *buf)
{
    u_char  *p;

    p = ngx_cpymem(buf, prefix->data, prefix->len);
    p = ngx_hex_dump(p, key_hash, 32);     /* 32 bytes -> 64 lowercase hex */

    return (size_t) (p - buf);
}


size_t
ngx_http_cache_turbo_redis_lockkey(ngx_str_t *prefix, u_char *key_hash,
    u_char *buf)
{
    u_char  *p;

    p = ngx_cpymem(buf, prefix->data, prefix->len);
    p = ngx_cpymem(p, "lock:", sizeof("lock:") - 1);
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

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "cache_turbo: redis connect fd:%d -> %V",
                   c->fd, op->peer.name);

#if (NGX_SSL)
    if (op->clcf != NULL && op->clcf->redis_tls) {
        /* A peer connection has no pool of its own; ngx_ssl_create_connection
         * allocates c->ssl from c->pool. Give the connection a DEDICATED pool
         * (parented at worker lifetime via ngx_create_pool, not borrowed from
         * op->pool) so c->ssl outlives the spawning op and the connection can be
         * parked on the keepalive pool (v15-2). It is destroyed only when the
         * connection is finally closed (op_done non-park / ka_drop). */
        c->pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
        if (c->pool == NULL) {
            ngx_close_connection(c);
            op->peer.connection = NULL;
            return NGX_ERROR;
        }

        /* TLS: drive the SSL handshake first; only after it completes do we run
         * the redis write/read handlers. The handshake handler fires on the
         * connect-complete (writable) event. */
        c->write->handler = ngx_http_cache_turbo_redis_tls_handshake;
        c->read->handler = ngx_http_cache_turbo_redis_tls_handshake;

        if (op->timeout) {
            ngx_add_timer(c->write, op->timeout);
        }
        if (rc == NGX_OK) {
            ngx_post_event(c->write, &ngx_posted_events);
        }
        return NGX_OK;
    }
#endif

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


/* Build the AUTH (+ optional ACL user) and SELECT <db> preamble pipeline for a
 * DSN backend, into one buffer allocated from pool. Sets *nreplies to the number
 * of simple replies to consume (0, 1, or 2) and *out to the buffer.
 *
 * Tri-state (STAB-2): NULL alone cannot distinguish "no preamble is needed"
 * from "the preamble could not be built", and conflating them is unsafe — a
 * SELECT-only backend (no password, db > 0) has no AUTH to make redis reject a
 * missing preamble, so a swallowed alloc failure would run the op silently
 * against db 0, the WRONG database. So:
 *   NGX_OK       — preamble built, *out set, send it then consume *nreplies.
 *   NGX_DECLINED — none needed (no password, db 0); *out = NULL.
 *   NGX_ERROR    — allocation failed; caller MUST fail closed, never connect. */
static ngx_int_t
ngx_http_cache_turbo_redis_preamble(ngx_pool_t *pool,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_buf_t **out, ngx_uint_t *nreplies)
{
    ngx_str_t   argv[3];
    ngx_buf_t  *au = NULL, *sel = NULL, *res;
    u_char     *dbbuf;
    size_t      n1, n2;

    *out = NULL;
    *nreplies = 0;

    if (clcf->redis_password.len) {
        argv[0].data = (u_char *) "AUTH";
        argv[0].len = sizeof("AUTH") - 1;
        if (clcf->redis_user.len) {
            argv[1] = clcf->redis_user;
            argv[2] = clcf->redis_password;
            au = ngx_http_cache_turbo_redis_encode(pool, argv, 3);
        } else {
            argv[1] = clcf->redis_password;
            au = ngx_http_cache_turbo_redis_encode(pool, argv, 2);
        }
        if (au == NULL) {
            return NGX_ERROR;
        }
        (*nreplies)++;
    }

    if (clcf->redis_db > 0) {
        dbbuf = ngx_pnalloc(pool, NGX_INT_T_LEN);
        if (dbbuf == NULL) {
            return NGX_ERROR;
        }
        argv[0].data = (u_char *) "SELECT";
        argv[0].len = sizeof("SELECT") - 1;
        argv[1].data = dbbuf;
        argv[1].len = (size_t) (ngx_sprintf(dbbuf, "%i", clcf->redis_db)
                                - dbbuf);
        sel = ngx_http_cache_turbo_redis_encode(pool, argv, 2);
        if (sel == NULL) {
            return NGX_ERROR;
        }
        (*nreplies)++;
    }

    if (au == NULL && sel == NULL) {
        return NGX_DECLINED;
    }
    if (sel == NULL) {
        *out = au;
        return NGX_OK;
    }
    if (au == NULL) {
        *out = sel;
        return NGX_OK;
    }

    /* pipeline AUTH + SELECT into one buffer */
    n1 = au->last - au->pos;
    n2 = sel->last - sel->pos;
    res = ngx_create_temp_buf(pool, n1 + n2);
    if (res == NULL) {
        return NGX_ERROR;
    }
    res->last = ngx_cpymem(res->last, au->pos, n1);
    res->last = ngx_cpymem(res->last, sel->pos, n2);
    *out = res;
    return NGX_OK;
}


/* Wire op->command (the real RESP op, already in op->send) + the AUTH/SELECT
 * preamble, then connect. The write path sends the preamble first (if any),
 * consumes its replies, then sends the command and installs read_handler. */
static ngx_int_t
ngx_http_cache_turbo_redis_launch(ngx_http_cache_turbo_redis_op_t *op,
    ngx_http_cache_turbo_loc_conf_t *clcf, void (*read_handler)(ngx_event_t *))
{
    ngx_connection_t  *c;
    ngx_int_t          rc;

    op->clcf = clcf;
    op->command = op->send;
    op->read_handler = read_handler;

    /* Keepalive (v15): reuse a pooled idle connection if one is live. A pooled
     * connection is already AUTH'd + SELECT'd (and, for TLS (v15-2), already
     * handshaked), so it skips both the preamble and the handshake and sends the
     * command straight away over the persistent (TLS) channel. */
    if (clcf->redis_keepalive > 0) {
        c = ngx_http_cache_turbo_redis_ka_get(clcf, &clcf->redis_addr);
        if (c != NULL) {
            op->reused = 1;
            op->peer.connection = c;
            op->peer.sockaddr = clcf->redis_addr.sockaddr;
            op->peer.socklen = clcf->redis_addr.socklen;
            op->peer.name = &clcf->redis_addr.name;
            op->peer.log = ngx_cycle->log;
            c->data = op;
            c->write->handler = ngx_http_cache_turbo_redis_write;
            c->read->handler = read_handler;

            if (op->timeout) {
                ngx_add_timer(c->write, op->timeout);
            }
            /* Post (don't run inline): a GET parks with count++ only after this
             * returns, so an inline failure must not resume the request yet. */
            ngx_post_event(c->write, &ngx_posted_events);
            return NGX_OK;
        }
    }

    rc = ngx_http_cache_turbo_redis_preamble(op->pool, clcf, &op->preamble,
                                             &op->preamble_replies);
    if (rc == NGX_ERROR) {
        /* STAB-2: fail closed. Connecting without the AUTH/SELECT preamble
         * would authenticate nothing and, for db > 0, silently target db 0. */
        return NGX_ERROR;
    }
    if (rc == NGX_OK) {
        op->send = op->preamble;
        op->in_preamble = 1;
    }

    return ngx_http_cache_turbo_redis_connect(op, &clcf->redis_addr,
               read_handler);
}


#if (NGX_SSL)
/* Outgoing-TLS handshake driver. Fires on connect-complete, wraps the socket in
 * the location's client SSL context, runs the handshake, and on success hands
 * off to the redis write path. Any failure tears the op down as a miss. */
static void
ngx_http_cache_turbo_redis_tls_handshake(ngx_event_t *ev)
{
    ngx_int_t                         rc;
    ngx_connection_t                 *c = ev->data;
    ngx_http_cache_turbo_redis_op_t  *op = c->data;

    if (c->read->timedout || c->write->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "cache_turbo: redis TLS handshake timed out");
        ngx_http_cache_turbo_redis_op_fail(op);
        return;
    }

    if (c->ssl == NULL) {
        if (ngx_ssl_create_connection(op->clcf->redis_ssl, c,
                NGX_SSL_BUFFER|NGX_SSL_CLIENT) != NGX_OK)
        {
            ngx_http_cache_turbo_redis_op_fail(op);
            return;
        }

        /* SNI: send the DSN host (or tls_name override) as the server name. */
        {
            ngx_str_t  sni = op->clcf->redis_tls_name.len
                                 ? op->clcf->redis_tls_name
                                 : op->clcf->redis_host;
            if (sni.len) {
                u_char *name = ngx_pnalloc(op->pool, sni.len + 1);
                if (name != NULL) {
                    ngx_memcpy(name, sni.data, sni.len);
                    name[sni.len] = '\0';
                    (void) SSL_set_tlsext_host_name(c->ssl->connection,
                                                    (char *) name);
                }
            }
        }
    }

    rc = ngx_ssl_handshake(c);

    if (rc == NGX_AGAIN) {
        c->ssl->handler = ngx_http_cache_turbo_redis_tls_handshake_done;
        return;
    }

    ngx_http_cache_turbo_redis_tls_handshake_done(c);
}


static void
ngx_http_cache_turbo_redis_tls_handshake_done(ngx_connection_t *c)
{
    ngx_http_cache_turbo_redis_op_t  *op = c->data;

    if (!c->ssl->handshaked) {
        ngx_http_cache_turbo_redis_op_fail(op);
        return;
    }

    if (op->clcf->redis_tls_verify) {
        ngx_str_t  name = op->clcf->redis_tls_name.len
                              ? op->clcf->redis_tls_name
                              : op->clcf->redis_host;

        if (SSL_get_verify_result(c->ssl->connection) != X509_V_OK) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "cache_turbo: redis TLS certificate verify failed");
            ngx_http_cache_turbo_redis_op_fail(op);
            return;
        }
        if (name.len && ngx_ssl_check_host(c, &name) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "cache_turbo: redis TLS host \"%V\" mismatch", &name);
            ngx_http_cache_turbo_redis_op_fail(op);
            return;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "cache_turbo: redis TLS handshake ok fd:%d", c->fd);

    /* handshake good: now run the redis write path (preamble then command) */
    c->write->handler = ngx_http_cache_turbo_redis_write;
    c->read->handler = op->read_handler;

    if (op->timeout) {
        ngx_add_timer(c->write, op->timeout);
    }
    ngx_post_event(c->write, &ngx_posted_events);
}
#endif


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
    stale_ttl = ngx_http_cache_turbo_stale_ttl(fresh_ttl, clcf->stale_mult);
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

    if (ngx_http_cache_turbo_redis_launch(op, clcf,
            ngx_http_cache_turbo_redis_read_drain) != NGX_OK)
    {
        ngx_destroy_pool(pool);
    }
}


/* Fire-and-forget a single RESP command (drains the reply, ignores it). The
 * argv bytes are copied into the op pool by encode, so they need only be valid
 * for the duration of this call. */
static void
ngx_http_cache_turbo_redis_fire_argv(ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_str_t *argv, ngx_uint_t argc)
{
    ngx_http_cache_turbo_redis_op_t  *op;

    op = ngx_http_cache_turbo_redis_op_create(clcf);
    if (op == NULL) {
        return;
    }

    op->expected_replies = 1;              /* one command -> one RESP reply */

    op->send = ngx_http_cache_turbo_redis_encode(op->pool, argv, argc);
    if (op->send == NULL) {
        ngx_destroy_pool(op->pool);
        return;
    }

    if (ngx_http_cache_turbo_redis_launch(op, clcf,
            ngx_http_cache_turbo_redis_read_drain) != NGX_OK)
    {
        ngx_destroy_pool(op->pool);
    }
}


void
ngx_http_cache_turbo_redis_del_raw(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *key, size_t key_len)
{
    ngx_str_t  argv[2];

    if (!clcf->redis_enable) {
        return;
    }

    argv[0].data = (u_char *) "DEL";
    argv[0].len = sizeof("DEL") - 1;
    argv[1].data = key;
    argv[1].len = key_len;

    ngx_http_cache_turbo_redis_fire_argv(clcf, argv, 2);
}


void
ngx_http_cache_turbo_redis_del(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *key_hash)
{
    ngx_pool_t  *tmp;
    u_char      *keybuf, *lockbuf;
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
        ngx_http_cache_turbo_redis_del_raw(clcf, keybuf, keylen);
    }

    /* Also drop the cross-node single-flight lock (v4-2 SET NX PX). It is held
     * for lock_ttl and self-heals only by PX expiry; a purge that removes the
     * object but leaves the lock would make the NEXT cold-miss winner lose the
     * NX to this now-stale lock and then wait the full lock_timeout for an L2
     * fill that was just purged (a ~5s stall, the V-HANG). Clearing it here lets
     * the post-purge cold miss re-acquire the lock and go to origin at once. */
    lockbuf = ngx_pnalloc(tmp, clcf->redis_prefix.len + sizeof("lock:") - 1 + 64);
    if (lockbuf != NULL) {
        size_t  locklen;
        locklen = ngx_http_cache_turbo_redis_lockkey(&clcf->redis_prefix,
                                                     key_hash, lockbuf);
        ngx_http_cache_turbo_redis_del_raw(clcf, lockbuf, locklen);
    }

    ngx_destroy_pool(tmp);
}


/* Keys per pipelined UNLINK. UNLINK is variadic and returns a SINGLE integer
 * reply regardless of how many keys it names, so one chunk costs one reply —
 * read_drain frames `nchunks` of them (STAB-1 expected_replies). */
#define NGX_HTTP_CACHE_TURBO_REDIS_DEL_CHUNK  256


void
ngx_http_cache_turbo_redis_del_many(ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_str_t *keys, ngx_uint_t nkeys)
{
    ngx_uint_t                        i, m, nchunks, emitted;
    size_t                            total;
    ngx_str_t                        *argv;
    ngx_buf_t                       **bufs, *cmd;
    ngx_http_cache_turbo_redis_op_t  *op;

    if (!clcf->redis_enable || nkeys == 0) {
        return;
    }

    op = ngx_http_cache_turbo_redis_op_create(clcf);
    if (op == NULL) {
        return;
    }

    /* "UNLINK" + up to CHUNK keys per command. */
    argv = ngx_palloc(op->pool,
               (1 + NGX_HTTP_CACHE_TURBO_REDIS_DEL_CHUNK) * sizeof(ngx_str_t));
    nchunks = (nkeys + NGX_HTTP_CACHE_TURBO_REDIS_DEL_CHUNK - 1)
              / NGX_HTTP_CACHE_TURBO_REDIS_DEL_CHUNK;
    bufs = ngx_palloc(op->pool, nchunks * sizeof(ngx_buf_t *));
    if (argv == NULL || bufs == NULL) {
        ngx_destroy_pool(op->pool);
        return;
    }
    argv[0].data = (u_char *) "UNLINK";
    argv[0].len = sizeof("UNLINK") - 1;

    total = 0;
    emitted = 0;
    i = 0;
    while (i < nkeys) {
        m = 0;
        while (m < NGX_HTTP_CACHE_TURBO_REDIS_DEL_CHUNK && i < nkeys) {
            if (keys[i].len) {            /* skip empty keys defensively */
                argv[1 + m] = keys[i];    /* shallow; encode copies the bytes */
                m++;
            }
            i++;
        }
        if (m == 0) {
            continue;                     /* chunk held only empty keys */
        }
        cmd = ngx_http_cache_turbo_redis_encode(op->pool, argv, 1 + m);
        if (cmd == NULL) {
            ngx_destroy_pool(op->pool);
            return;
        }
        bufs[emitted++] = cmd;
        total += (size_t) (cmd->last - cmd->pos);
    }

    if (emitted == 0) {                   /* nothing to delete */
        ngx_destroy_pool(op->pool);
        return;
    }

    op->send = ngx_create_temp_buf(op->pool, total);
    if (op->send == NULL) {
        ngx_destroy_pool(op->pool);
        return;
    }
    for (i = 0; i < emitted; i++) {
        op->send->last = ngx_cpymem(op->send->last, bufs[i]->pos,
                                    (size_t) (bufs[i]->last - bufs[i]->pos));
    }

    op->expected_replies = emitted;       /* one integer reply per UNLINK */

    if (ngx_http_cache_turbo_redis_launch(op, clcf,
            ngx_http_cache_turbo_redis_read_drain) != NGX_OK)
    {
        ngx_destroy_pool(op->pool);
    }
}


size_t
ngx_http_cache_turbo_redis_tagkey(ngx_str_t *prefix, u_char *name,
    size_t name_len, u_char *buf)
{
    u_char  *p;

    p = ngx_cpymem(buf, prefix->data, prefix->len);
    p = ngx_cpymem(p, "tag:", sizeof("tag:") - 1);
    p = ngx_cpymem(p, name, name_len);

    return (size_t) (p - buf);
}


void
ngx_http_cache_turbo_redis_tag_add(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *key_hash, u_char *name, size_t name_len, time_t ttl)
{
    ngx_str_t                         argv[4];
    ngx_buf_t                        *sadd, *exp_nx, *exp_gt;
    size_t                            n1, n2, n3;
    ngx_http_cache_turbo_redis_op_t  *op;
    u_char                           *tagkey, *member, *ttlbuf;

    if (!clcf->redis_enable || ttl <= 0 || name_len == 0) {
        return;
    }

    op = ngx_http_cache_turbo_redis_op_create(clcf);
    if (op == NULL) {
        return;
    }

    tagkey = ngx_pnalloc(op->pool,
                         clcf->redis_prefix.len + sizeof("tag:") - 1 + name_len);
    member = ngx_pnalloc(op->pool, clcf->redis_prefix.len + 64);
    ttlbuf = ngx_pnalloc(op->pool, NGX_INT64_LEN);
    if (tagkey == NULL || member == NULL || ttlbuf == NULL) {
        ngx_destroy_pool(op->pool);
        return;
    }

    /* SADD <prefix>tag:<name> <object L2 key> */
    argv[0].data = (u_char *) "SADD";
    argv[0].len = sizeof("SADD") - 1;
    argv[1].data = tagkey;
    argv[1].len = ngx_http_cache_turbo_redis_tagkey(&clcf->redis_prefix, name,
                                                    name_len, tagkey);
    argv[2].data = member;
    argv[2].len = ngx_http_cache_turbo_redis_key(&clcf->redis_prefix, key_hash,
                                                 member);
    sadd = ngx_http_cache_turbo_redis_encode(op->pool, argv, 3);

    /* Bound the tag set's lifetime so dead members can't accumulate forever,
     * but NEVER below the longest-lived member's TTL (COR-8). A tag set holds
     * members from many objects, each with its own TTL; a plain
     * `EXPIRE tag <this-ttl>` on every store lets a later short-TTL object
     * shorten the whole set, expiring it while longer-lived members are still
     * cached — a tag purge then misses them and a stale variant survives.
     *
     * Take the max of the current and incoming expiry with two pipelined
     * EXPIRE flags (both Redis >= 7.0):
     *   NX — set TTL only if the key currently has none (freshly SADD'd set);
     *        GT alone can't do this because redis treats a no-TTL key as
     *        infinite, so GT would never bound a brand-new set (leak forever).
     *   GT — set TTL only if it is greater than the current one (extend, never
     *        reduce) for a set that already carries an expiry.
     * Exactly one of the two takes effect on a set with an expiry; NX seeds a
     * set without one. Either way the set TTL only ever grows. */
    argv[0].data = (u_char *) "EXPIRE";
    argv[0].len = sizeof("EXPIRE") - 1;
    /* argv[1] (tagkey) unchanged */
    argv[2].data = ttlbuf;
    argv[2].len = (size_t) (ngx_sprintf(ttlbuf, "%T", ttl) - ttlbuf);
    argv[3].data = (u_char *) "NX";
    argv[3].len = sizeof("NX") - 1;
    exp_nx = ngx_http_cache_turbo_redis_encode(op->pool, argv, 4);
    argv[3].data = (u_char *) "GT";
    argv[3].len = sizeof("GT") - 1;
    exp_gt = ngx_http_cache_turbo_redis_encode(op->pool, argv, 4);

    if (sadd == NULL || exp_nx == NULL || exp_gt == NULL) {
        ngx_destroy_pool(op->pool);
        return;
    }

    /* Pipeline all three commands into one buffer (one round trip). */
    n1 = sadd->last - sadd->pos;
    n2 = exp_nx->last - exp_nx->pos;
    n3 = exp_gt->last - exp_gt->pos;
    op->send = ngx_create_temp_buf(op->pool, n1 + n2 + n3);
    if (op->send == NULL) {
        ngx_destroy_pool(op->pool);
        return;
    }
    op->send->last = ngx_cpymem(op->send->last, sadd->pos, n1);
    op->send->last = ngx_cpymem(op->send->last, exp_nx->pos, n2);
    op->send->last = ngx_cpymem(op->send->last, exp_gt->pos, n3);

    op->expected_replies = 3;              /* SADD + EXPIRE NX + EXPIRE GT */

    if (ngx_http_cache_turbo_redis_launch(op, clcf,
            ngx_http_cache_turbo_redis_read_drain) != NGX_OK)
    {
        ngx_destroy_pool(op->pool);
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

    if (ngx_http_cache_turbo_redis_launch(op, clcf,
            ngx_http_cache_turbo_redis_read_get) != NGX_OK)
    {
        ngx_destroy_pool(pool);
        return NGX_DECLINED;
    }

    /* Parked: hold a reference so the request survives until the reply resumes
     * it (released by ngx_http_finalize_request(NGX_DONE) in get_finish). */
    r->main->count++;

    return NGX_AGAIN;
}


ngx_int_t
ngx_http_cache_turbo_redis_lock(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    time_t ttl)
{
    ngx_pool_t                       *pool;
    ngx_str_t                         argv[6];
    ngx_http_cache_turbo_redis_op_t  *op;
    u_char                           *lockbuf, *ownerbuf, *msbuf;

    if (!clcf->redis_enable) {
        return NGX_DECLINED;
    }
    if (ttl <= 0) {
        ttl = 5;
    }

    op = ngx_http_cache_turbo_redis_op_create(clcf);
    if (op == NULL) {
        return NGX_DECLINED;
    }
    pool = op->pool;
    op->request = r;
    op->ctx = ctx;
    op->is_lock = 1;

    lockbuf = ngx_pnalloc(pool,
                  clcf->redis_prefix.len + sizeof("lock:") - 1 + 64);
    ownerbuf = ngx_pnalloc(pool, NGX_INT_T_LEN + 1 + NGX_INT64_LEN);
    msbuf = ngx_pnalloc(pool, NGX_INT64_LEN);
    if (lockbuf == NULL || ownerbuf == NULL || msbuf == NULL) {
        ngx_destroy_pool(pool);
        return NGX_DECLINED;
    }

    /* SET <prefix>lock:<hex> <owner> NX PX <ttl_ms>. The owner is unique per
     * attempt (pid + random) for debuggability; it is never used to release the
     * lock (no CAS unlock in v4-2 — the PX TTL is the only release), so its
     * exact value does not affect correctness. */
    argv[0].data = (u_char *) "SET";
    argv[0].len = sizeof("SET") - 1;
    argv[1].data = lockbuf;
    argv[1].len = ngx_http_cache_turbo_redis_lockkey(&clcf->redis_prefix,
                                                     ctx->key_hash, lockbuf);
    argv[2].data = ownerbuf;
    argv[2].len = (size_t) (ngx_sprintf(ownerbuf, "%P:%xL",
                      ngx_pid, (int64_t) ngx_random()) - ownerbuf);
    argv[3].data = (u_char *) "NX";
    argv[3].len = sizeof("NX") - 1;
    argv[4].data = (u_char *) "PX";
    argv[4].len = sizeof("PX") - 1;
    argv[5].data = msbuf;
    argv[5].len = (size_t) (ngx_sprintf(msbuf, "%T", ttl * 1000) - msbuf);

    op->send = ngx_http_cache_turbo_redis_encode(pool, argv, 6);
    if (op->send == NULL) {
        ngx_destroy_pool(pool);
        return NGX_DECLINED;
    }

    if (ngx_http_cache_turbo_redis_launch(op, clcf,
            ngx_http_cache_turbo_redis_read_lock) != NGX_OK)
    {
        ngx_destroy_pool(pool);
        return NGX_DECLINED;
    }

    r->main->count++;

    return NGX_AGAIN;
}


ngx_int_t
ngx_http_cache_turbo_redis_smembers(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, u_char *name, size_t name_len,
    ngx_http_cache_turbo_redis_members_pt cb, void *data)
{
    ngx_str_t                         argv[2];
    ngx_http_cache_turbo_redis_op_t  *op;
    u_char                           *tagkey;

    if (!clcf->redis_enable) {
        return NGX_ERROR;
    }

    op = ngx_http_cache_turbo_redis_op_create(clcf);
    if (op == NULL) {
        return NGX_ERROR;
    }
    op->request = r;
    op->members_cb = cb;
    op->members_data = data;

    op->rcap = ngx_pagesize * 4;          /* grows on demand up to MAX_REPLY */
    op->rbuf = ngx_pnalloc(op->pool, op->rcap);
    tagkey = ngx_pnalloc(op->pool,
                         clcf->redis_prefix.len + sizeof("tag:") - 1 + name_len);
    if (op->rbuf == NULL || tagkey == NULL) {
        ngx_destroy_pool(op->pool);
        return NGX_ERROR;
    }

    argv[0].data = (u_char *) "SMEMBERS";
    argv[0].len = sizeof("SMEMBERS") - 1;
    argv[1].data = tagkey;
    argv[1].len = ngx_http_cache_turbo_redis_tagkey(&clcf->redis_prefix, name,
                                                    name_len, tagkey);

    op->send = ngx_http_cache_turbo_redis_encode(op->pool, argv, 2);
    if (op->send == NULL) {
        ngx_destroy_pool(op->pool);
        return NGX_ERROR;
    }

    if (ngx_http_cache_turbo_redis_launch(op, clcf,
            ngx_http_cache_turbo_redis_read_smembers) != NGX_OK)
    {
        ngx_destroy_pool(op->pool);
        return NGX_ERROR;
    }

    /* Parked: hold a reference until the reply resumes the request (released by
     * ngx_http_finalize_request in smembers_finish). */
    r->main->count++;

    return NGX_DONE;
}


/* How many keys SCAN returns per round trip. A hint, not a hard limit; the
 * cursor loop iterates until the cursor returns to "0". */
#define NGX_HTTP_CACHE_TURBO_REDIS_SCAN_COUNT  "256"


/* Encode one SCAN <cursor> MATCH <prefix>* COUNT <n> command into pool. The
 * prefix is escaped: SCAN MATCH treats *, ?, [, ], \ as glob metacharacters, so
 * a prefix that happens to contain one (or a deliberately crafted one) must not
 * widen the pattern. Only the single trailing '*' we append is a wildcard. */
static ngx_buf_t *
ngx_http_cache_turbo_redis_scan_cmd(ngx_pool_t *pool,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_str_t *cursor)
{
    ngx_str_t   argv[6];
    u_char     *match, *p, *s, *end;

    /* Worst case every byte is a metachar needing a backslash, plus trailing '*'. */
    match = ngx_pnalloc(pool, clcf->redis_prefix.len * 2 + 1);
    if (match == NULL) {
        return NULL;
    }
    p = match;
    s = clcf->redis_prefix.data;
    end = s + clcf->redis_prefix.len;
    for (; s < end; s++) {
        if (*s == '*' || *s == '?' || *s == '[' || *s == ']' || *s == '\\') {
            *p++ = '\\';
        }
        *p++ = *s;
    }
    *p++ = '*';

    argv[0].data = (u_char *) "SCAN";
    argv[0].len = sizeof("SCAN") - 1;
    argv[1] = *cursor;
    argv[2].data = (u_char *) "MATCH";
    argv[2].len = sizeof("MATCH") - 1;
    argv[3].data = match;
    argv[3].len = p - match;
    argv[4].data = (u_char *) "COUNT";
    argv[4].len = sizeof("COUNT") - 1;
    argv[5].data = (u_char *) NGX_HTTP_CACHE_TURBO_REDIS_SCAN_COUNT;
    argv[5].len = sizeof(NGX_HTTP_CACHE_TURBO_REDIS_SCAN_COUNT) - 1;

    return ngx_http_cache_turbo_redis_encode(pool, argv, 6);
}


ngx_int_t
ngx_http_cache_turbo_redis_scan_del(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_http_cache_turbo_redis_members_pt cb, void *data)
{
    ngx_str_t                         cursor0 = ngx_string("0");
    ngx_http_cache_turbo_redis_op_t  *op;

    if (!clcf->redis_enable) {
        return NGX_ERROR;
    }

    /* Refuse to scan-delete with an empty prefix: that would be SCAN MATCH *,
     * i.e. the entire (possibly shared) Redis keyspace. An empty prefix is also
     * rejected at config time; this is the last-line guard. */
    if (clcf->redis_prefix.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "cache_turbo: refusing L2 all-purge with empty key prefix "
                      "(would SCAN MATCH * the whole keyspace)");
        return NGX_ERROR;
    }

    op = ngx_http_cache_turbo_redis_op_create(clcf);
    if (op == NULL) {
        return NGX_ERROR;
    }
    op->request = r;
    op->clcf = clcf;
    op->members_cb = cb;
    op->members_data = data;

    op->rcap = ngx_pagesize * 4;          /* grows on demand up to MAX_REPLY */
    op->rbuf = ngx_pnalloc(op->pool, op->rcap);
    if (op->rbuf == NULL) {
        ngx_destroy_pool(op->pool);
        return NGX_ERROR;
    }

    op->send = ngx_http_cache_turbo_redis_scan_cmd(op->pool, clcf, &cursor0);
    if (op->send == NULL) {
        ngx_destroy_pool(op->pool);
        return NGX_ERROR;
    }

    if (ngx_http_cache_turbo_redis_launch(op, clcf,
            ngx_http_cache_turbo_redis_read_scan) != NGX_OK)
    {
        ngx_destroy_pool(op->pool);
        return NGX_ERROR;
    }

    /* Parked: released by ngx_http_finalize_request in smembers_finish (reused
     * as the scan completion: cb(r, data, NULL, 0)). */
    r->main->count++;

    return NGX_DONE;
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

    /* Whichever buffer just went out decides the reader: the AUTH/SELECT
     * preamble is followed by the preamble drainer; the real command by its
     * own read handler. */
    c->read->handler = op->in_preamble
                           ? ngx_http_cache_turbo_redis_read_preamble
                           : op->read_handler;
    c->read->handler(c->read);
}


/*
 * Consume the AUTH/SELECT preamble replies (each a one-line +OK / -ERR), then
 * send the real command. A '-' reply (auth failed, wrong db) fails the op. The
 * replies are tiny and arrive together, so the fixed recv[] scratch suffices;
 * we only ever need to count CRLF-terminated lines.
 */
static void
ngx_http_cache_turbo_redis_read_preamble(ngx_event_t *rev)
{
    ssize_t                           n;
    ngx_uint_t                        seen;
    u_char                           *p, *last;
    ngx_connection_t                 *c;
    ngx_http_cache_turbo_redis_op_t  *op;

    c = rev->data;
    op = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "cache_turbo: redis AUTH/SELECT timed out");
        ngx_http_cache_turbo_redis_op_fail(op);
        return;
    }

    for ( ;; ) {
        if (op->recv_len >= sizeof(op->recv)) {
            /* preamble replies should never be this large */
            ngx_http_cache_turbo_redis_op_fail(op);
            return;
        }

        n = c->recv(c, op->recv + op->recv_len,
                    sizeof(op->recv) - op->recv_len);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_http_cache_turbo_redis_op_fail(op);
            }
            return;
        }
        if (n == NGX_ERROR || n == 0) {
            ngx_http_cache_turbo_redis_op_fail(op);
            return;
        }

        op->recv_len += (size_t) n;

        /* count complete one-line replies; bail on the first error reply */
        seen = 0;
        p = op->recv;
        last = op->recv + op->recv_len;
        while (p < last && seen < op->preamble_replies) {
            u_char *crlf = ngx_strlchr(p, last, LF);
            if (crlf == NULL) {
                break;                 /* partial line: read more */
            }
            if (*p == '-') {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                    "cache_turbo: redis AUTH/SELECT rejected: %*s",
                    (size_t) (crlf - p > 96 ? 96 : crlf - p), p);
                ngx_http_cache_turbo_redis_op_fail(op);
                return;
            }
            seen++;
            p = crlf + 1;
        }

        if (seen < op->preamble_replies) {
            continue;                  /* need more reply bytes */
        }

        /* preamble done: send the real command, install its reader */
        op->in_preamble = 0;
        op->recv_len = 0;
        op->send = op->command;

        if (op->timeout) {
            ngx_add_timer(c->write, op->timeout);
        }
        c->write->handler = ngx_http_cache_turbo_redis_write;
        ngx_post_event(c->write, &ngx_posted_events);
        return;
    }
}


/*
 * Fire-and-forget reply drain (SET / DEL / pipelined SADD+EXPIRE). The command
 * is durable the moment redis acknowledges, so the RESULT is ignored — but the
 * connection may only be POOLED once every expected reply is fully framed.
 *
 * STAB-1: the old code set clean=1 on any single recv() that returned >0 bytes.
 * That pooled a connection (a) when a reply arrived TCP-split (`+OK` now, `\r\n`
 * later) and (b) for tag_add, which pipelines THREE replies (SADD + EXPIRE NX +
 * EXPIRE GT) — draining one and pooling left two replies in flight, so the next
 * reuse read them as its own reply and desynced. Now we accumulate into the
 * scratch buffer and frame op->expected_replies complete RESP replies before
 * marking the connection clean.
 */
static void
ngx_http_cache_turbo_redis_read_drain(ngx_event_t *rev)
{
    ssize_t                           n;
    ngx_int_t                         rc;
    ngx_uint_t                        seen, expected;
    u_char                           *p, *last, *next;
    ngx_connection_t                 *c;
    ngx_http_cache_turbo_redis_op_t  *op;

    c = rev->data;
    op = c->data;

    expected = op->expected_replies ? op->expected_replies : 1;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "cache_turbo: redis read timed out");
        ngx_http_cache_turbo_redis_op_done(op);   /* clean stays 0: not pooled */
        return;
    }

    for ( ;; ) {
        if (op->recv_len >= sizeof(op->recv)) {
            /* Replies to our fire-and-forget commands (integers, +OK, a short
             * -ERR) never fill the scratch buffer; if one somehow does, just
             * don't pool the connection rather than grow it unbounded. */
            ngx_http_cache_turbo_redis_op_done(op);
            return;
        }

        n = c->recv(c, op->recv + op->recv_len,
                    sizeof(op->recv) - op->recv_len);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_http_cache_turbo_redis_op_done(op);
            }
            return;
        }
        if (n == NGX_ERROR || n == 0) {
            /* Peer closed/errored before all replies framed: don't pool. */
            ngx_http_cache_turbo_redis_op_done(op);
            return;
        }

        op->recv_len += (size_t) n;

        /* Frame every expected reply; only when ALL are fully buffered is the
         * stream at a clean boundary and the connection poolable. */
        seen = 0;
        p = op->recv;
        last = op->recv + op->recv_len;
        while (seen < expected) {
            rc = ngx_http_cache_turbo_redis_frame(p, last, 0, &next);
            if (rc == NGX_AGAIN) {
                break;                     /* partial: read more bytes */
            }
            if (rc == NGX_DECLINED) {
                /* Malformed reply: drain is best-effort, don't pool. */
                ngx_http_cache_turbo_redis_op_done(op);
                return;
            }
            if (*p == '-') {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "cache_turbo: redis command error: %*s",
                              (size_t) (next - p > 64 ? 64 : next - p), p);
            }
            seen++;
            p = next;
        }

        if (seen < expected) {
            continue;                      /* need more reply bytes */
        }

        op->clean = 1;                     /* all replies consumed: poolable */
        ngx_http_cache_turbo_redis_op_done(op);
        return;
    }
}


/*
 * Append one recv() of reply bytes into op->rbuf, growing it (bounded by
 * MAX_REPLY) when full. Shared by the GET / SMEMBERS / SCAN readers so the
 * grow + recv + event-rearm boilerplate lives in one place. Returns:
 *   NGX_OK    - op->rlen advanced by the bytes read; caller should re-parse
 *   NGX_AGAIN - nothing readable yet, read event re-armed; caller must return
 *   NGX_ERROR - cap exceeded, alloc failed, or the peer closed/errored; caller
 *               must run its op-specific finish(fail)
 */
static ngx_int_t
ngx_http_cache_turbo_redis_fill(ngx_http_cache_turbo_redis_op_t *op,
    ngx_event_t *rev)
{
    ssize_t            n;
    u_char            *nbuf;
    size_t             ncap;
    ngx_connection_t  *c = rev->data;

    if (op->rlen == op->rcap) {
        if (op->rcap >= NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY) {
            return NGX_ERROR;
        }
        ncap = op->rcap * 2;
        if (ncap > NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY) {
            ncap = NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY;
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
    u_char                           *blob;
    size_t                            blob_len;
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
        rc = ngx_http_cache_turbo_redis_fill(op, rev);
        if (rc == NGX_AGAIN) {
            return;                        /* wait for more, or re-arm failed */
        }
        if (rc == NGX_ERROR) {
            /* cap/alloc/closed: treat as an L2 miss */
            ngx_http_cache_turbo_redis_get_finish(op, NGX_DECLINED, NULL, 0);
            return;
        }

        rc = ngx_http_cache_turbo_redis_parse(op, &blob, &blob_len);
        if (rc == NGX_AGAIN) {
            continue;                      /* read more */
        }
        /* A definitive parse result (hit or nil/miss) means a complete, well-
         * formed reply was consumed: the connection is at a clean boundary and
         * may be pooled (v15). */
        op->clean = 1;
        if (rc == NGX_OK) {
            ngx_http_cache_turbo_redis_get_finish(op, NGX_OK, blob, blob_len);
        } else {
            ngx_http_cache_turbo_redis_get_finish(op, NGX_DECLINED, NULL, 0);
        }
        return;
    }
}


/* Cap recursion so a buggy/hostile server can't blow the stack with deeply
 * nested arrays. Replies to the commands we issue nest at most 2 deep (SCAN). */
#define NGX_HTTP_CACHE_TURBO_REDIS_FRAME_MAX_DEPTH  8


/*
 * Scan exactly ONE complete RESP reply in [p, end) WITHOUT allocating or
 * interpreting the payload, recursing into arrays. On NGX_OK *next points one
 * byte past the reply. Lets callers know a reply boundary is fully buffered:
 *   - read_drain pools a keepalive conn only after ALL pipelined replies are in
 *     (STAB-1: a TCP-split +OK or a 3-reply tag_add no longer pools early);
 *   - read_smembers/read_scan confirm the whole array arrived before the single
 *     parse+alloc pass (STAB-3: no per-recv re-alloc/re-walk of the members
 *     array).
 * Returns NGX_AGAIN (need more bytes) or NGX_DECLINED (malformed/too deep).
 */
static ngx_int_t
ngx_http_cache_turbo_redis_frame(u_char *p, u_char *end, ngx_uint_t depth,
    u_char **next)
{
    u_char     *crlf;
    ngx_int_t   v, rc;
    ngx_uint_t  i;

    if (depth > NGX_HTTP_CACHE_TURBO_REDIS_FRAME_MAX_DEPTH) {
        return NGX_DECLINED;
    }
    if (p >= end) {
        return NGX_AGAIN;
    }

    switch (*p) {

    case '+':                              /* simple string */
    case '-':                              /* error */
    case ':':                              /* integer */
        crlf = ngx_strlchr(p + 1, end, CR);
        if (crlf == NULL || crlf + 1 >= end || crlf[1] != LF) {
            return NGX_AGAIN;
        }
        *next = crlf + 2;
        return NGX_OK;

    case '$':                              /* bulk string */
        crlf = ngx_strlchr(p + 1, end, CR);
        if (crlf == NULL || crlf + 1 >= end || crlf[1] != LF) {
            return NGX_AGAIN;
        }
        v = ngx_atoi(p + 1, crlf - (p + 1));
        if (v == NGX_ERROR) {
            return NGX_DECLINED;
        }
        if (v < 0) {                       /* $-1 nil: no payload */
            *next = crlf + 2;
            return NGX_OK;
        }
        if (v > NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY) {
            return NGX_DECLINED;
        }
        p = crlf + 2;
        if (end - p < v + 2) {             /* payload + trailing CRLF */
            return NGX_AGAIN;
        }
        *next = p + v + 2;
        return NGX_OK;

    case '*':                              /* array */
        crlf = ngx_strlchr(p + 1, end, CR);
        if (crlf == NULL || crlf + 1 >= end || crlf[1] != LF) {
            return NGX_AGAIN;
        }
        v = ngx_atoi(p + 1, crlf - (p + 1));
        if (v == NGX_ERROR) {
            return NGX_DECLINED;
        }
        p = crlf + 2;
        if (v < 0) {                       /* *-1 nil array: no elements */
            *next = p;
            return NGX_OK;
        }
        if (v > NGX_HTTP_CACHE_TURBO_REDIS_MAX_MEMBERS) {
            return NGX_DECLINED;
        }
        for (i = 0; i < (ngx_uint_t) v; i++) {
            rc = ngx_http_cache_turbo_redis_frame(p, end, depth + 1, &p);
            if (rc != NGX_OK) {
                return rc;                 /* AGAIN or DECLINED bubbles up */
            }
        }
        *next = p;
        return NGX_OK;

    default:
        return NGX_DECLINED;
    }
}


/*
 * Parse an accumulated SMEMBERS array reply in op->rbuf[0..op->rlen]:
 *   *<count>\r\n  then count bulk strings  $<len>\r\n<bytes>\r\n
 * On NGX_OK, *members (allocated from op->pool) points at ngx_str_t entries that
 * reference into rbuf; nil array (*-1) and empty (*0) yield NGX_OK with 0.
 * Returns NGX_AGAIN (need more bytes) or NGX_DECLINED (malformed/non-array).
 */
static ngx_int_t
ngx_http_cache_turbo_redis_parse_array(ngx_http_cache_turbo_redis_op_t *op,
    ngx_str_t **members, ngx_uint_t *nmembers)
{
    u_char     *p, *crlf, *end;
    ngx_int_t   count, len;
    ngx_uint_t  i;
    ngx_str_t  *list;

    p = op->rbuf;
    end = op->rbuf + op->rlen;

    if (p == end) {
        return NGX_AGAIN;
    }

    if (*p != '*') {
        return NGX_DECLINED;               /* not an array reply */
    }

    crlf = ngx_strlchr(p + 1, end, CR);
    if (crlf == NULL || crlf + 1 >= end || crlf[1] != LF) {
        return NGX_AGAIN;
    }

    count = ngx_atoi(p + 1, crlf - (p + 1));
    if (count == NGX_ERROR) {
        return NGX_DECLINED;
    }
    if (count < 0) {                       /* *-1 nil array */
        *members = NULL;
        *nmembers = 0;
        return NGX_OK;
    }
    if (count > NGX_HTTP_CACHE_TURBO_REDIS_MAX_MEMBERS) {
        return NGX_DECLINED;
    }
    if (count == 0) {
        *members = NULL;
        *nmembers = 0;
        return NGX_OK;
    }

    /* ngx_palloc (not ngx_pnalloc): the ngx_str_t array needs pointer
     * alignment; an unaligned base is UB (trapped by UBSan). */
    list = ngx_palloc(op->pool, count * sizeof(ngx_str_t));
    if (list == NULL) {
        return NGX_DECLINED;
    }

    p = crlf + 2;

    for (i = 0; i < (ngx_uint_t) count; i++) {
        if (p >= end) {
            return NGX_AGAIN;
        }
        if (*p != '$') {
            return NGX_DECLINED;
        }

        crlf = ngx_strlchr(p + 1, end, CR);
        if (crlf == NULL || crlf + 1 >= end || crlf[1] != LF) {
            return NGX_AGAIN;
        }

        len = ngx_atoi(p + 1, crlf - (p + 1));
        if (len == NGX_ERROR) {
            return NGX_DECLINED;
        }

        if (len < 0) {                     /* nil element: empty member */
            list[i].data = NULL;
            list[i].len = 0;
            p = crlf + 2;
            continue;
        }

        if (len > NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY) {
            return NGX_DECLINED;
        }

        p = crlf + 2;
        if (end - p < len + 2) {           /* payload + trailing CRLF */
            return NGX_AGAIN;
        }

        list[i].data = p;
        list[i].len = (size_t) len;
        p += len + 2;
    }

    *members = list;
    *nmembers = (ngx_uint_t) count;
    return NGX_OK;
}


static void
ngx_http_cache_turbo_redis_read_smembers(ngx_event_t *rev)
{
    ngx_str_t                        *members;
    ngx_uint_t                        nmembers;
    ngx_int_t                         rc;
    ngx_connection_t                 *c;
    ngx_http_cache_turbo_redis_op_t  *op;

    c = rev->data;
    op = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "cache_turbo: redis SMEMBERS timed out");
        ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
        return;
    }

    for ( ;; ) {
        u_char  *next;

        rc = ngx_http_cache_turbo_redis_fill(op, rev);
        if (rc == NGX_AGAIN) {
            return;
        }
        if (rc == NGX_ERROR) {
            ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
            return;
        }

        /* STAB-3: confirm the ENTIRE array reply is buffered before the single
         * alloc+parse pass, so a reply split across recvs no longer re-allocs
         * the members array (and re-walks it) on every partial fill. */
        rc = ngx_http_cache_turbo_redis_frame(op->rbuf, op->rbuf + op->rlen,
                                              0, &next);
        if (rc == NGX_AGAIN) {
            continue;                      /* read more before parsing */
        }
        /* NGX_DECLINED falls through: parse_array reports the same miss. */

        rc = ngx_http_cache_turbo_redis_parse_array(op, &members, &nmembers);
        if (rc == NGX_OK) {
            ngx_http_cache_turbo_redis_smembers_finish(op, members, nmembers);
        } else {
            ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
        }
        return;
    }
}


/*
 * Parse an accumulated SCAN reply in op->rbuf[0..op->rlen]. SCAN returns a
 * 2-element array: [ next-cursor (bulk string), [ matched keys (bulk strings) ] ]
 * On NGX_OK *cursor + the keys array (allocated from op->pool, pointing into
 * rbuf) are filled. Returns NGX_AGAIN (need more bytes) or NGX_DECLINED
 * (malformed / not the expected shape).
 */
static ngx_int_t
ngx_http_cache_turbo_redis_parse_scan(ngx_http_cache_turbo_redis_op_t *op,
    ngx_str_t *cursor, ngx_str_t **keys, ngx_uint_t *nkeys)
{
    u_char     *p, *crlf, *end;
    ngx_int_t   count, len;
    ngx_uint_t  i;
    ngx_str_t  *list;

    p = op->rbuf;
    end = op->rbuf + op->rlen;

    if (p == end) {
        return NGX_AGAIN;
    }
    if (*p != '*') {
        return NGX_DECLINED;               /* not an array reply */
    }

    crlf = ngx_strlchr(p + 1, end, CR);
    if (crlf == NULL || crlf + 1 >= end || crlf[1] != LF) {
        return NGX_AGAIN;
    }
    count = ngx_atoi(p + 1, crlf - (p + 1));
    if (count != 2) {
        return NGX_DECLINED;               /* SCAN always replies a 2-tuple */
    }
    p = crlf + 2;

    /* element 0: the next cursor, a bulk string */
    if (p >= end) {
        return NGX_AGAIN;
    }
    if (*p != '$') {
        return NGX_DECLINED;
    }
    crlf = ngx_strlchr(p + 1, end, CR);
    if (crlf == NULL || crlf + 1 >= end || crlf[1] != LF) {
        return NGX_AGAIN;
    }
    len = ngx_atoi(p + 1, crlf - (p + 1));
    if (len == NGX_ERROR || len < 0) {
        return NGX_DECLINED;
    }
    if (len > NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY) {
        return NGX_DECLINED;               /* bound before len + 2 (no overflow) */
    }
    p = crlf + 2;
    if (end - p < len + 2) {
        return NGX_AGAIN;
    }
    cursor->data = p;
    cursor->len = (size_t) len;
    p += len + 2;

    /* element 1: the array of matched keys */
    if (p >= end) {
        return NGX_AGAIN;
    }
    if (*p != '*') {
        return NGX_DECLINED;
    }
    crlf = ngx_strlchr(p + 1, end, CR);
    if (crlf == NULL || crlf + 1 >= end || crlf[1] != LF) {
        return NGX_AGAIN;
    }
    count = ngx_atoi(p + 1, crlf - (p + 1));
    if (count == NGX_ERROR) {
        return NGX_DECLINED;
    }
    if (count < 0) {                       /* nil array: treat as no keys */
        count = 0;
    }
    if (count > NGX_HTTP_CACHE_TURBO_REDIS_MAX_MEMBERS) {
        return NGX_DECLINED;
    }
    p = crlf + 2;

    list = NULL;
    if (count > 0) {
        /* ngx_palloc (not ngx_pnalloc): ngx_str_t needs pointer alignment. */
        list = ngx_palloc(op->pool, count * sizeof(ngx_str_t));
        if (list == NULL) {
            return NGX_DECLINED;
        }
    }

    for (i = 0; i < (ngx_uint_t) count; i++) {
        if (p >= end) {
            return NGX_AGAIN;
        }
        if (*p != '$') {
            return NGX_DECLINED;
        }
        crlf = ngx_strlchr(p + 1, end, CR);
        if (crlf == NULL || crlf + 1 >= end || crlf[1] != LF) {
            return NGX_AGAIN;
        }
        len = ngx_atoi(p + 1, crlf - (p + 1));
        if (len == NGX_ERROR) {
            return NGX_DECLINED;
        }
        if (len < 0) {                     /* nil element */
            list[i].data = NULL;
            list[i].len = 0;
            p = crlf + 2;
            continue;
        }
        if (len > NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY) {
            return NGX_DECLINED;
        }
        p = crlf + 2;
        if (end - p < len + 2) {
            return NGX_AGAIN;
        }
        list[i].data = p;
        list[i].len = (size_t) len;
        p += len + 2;
    }

    *keys = list;
    *nkeys = (ngx_uint_t) count;
    return NGX_OK;
}


/*
 * SCAN reply reader: accumulate, parse one [cursor, keys] page, DEL every key,
 * then either finish (cursor back to "0") or post the write event to issue the
 * next SCAN with the returned cursor. Posting (not recursing) keeps the stack
 * bounded for an arbitrarily large keyspace.
 */
static void
ngx_http_cache_turbo_redis_read_scan(ngx_event_t *rev)
{
    ngx_str_t                         cursor, *keys;
    ngx_uint_t                        nkeys;
    ngx_int_t                         rc;
    ngx_connection_t                 *c;
    ngx_http_cache_turbo_redis_op_t  *op;

    c = rev->data;
    op = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "cache_turbo: redis SCAN timed out");
        ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
        return;
    }

    for ( ;; ) {
        u_char  *next;

        rc = ngx_http_cache_turbo_redis_fill(op, rev);
        if (rc == NGX_AGAIN) {
            return;
        }
        if (rc == NGX_ERROR) {
            ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
            return;
        }

        /* STAB-3: frame the whole [cursor, keys] page before parsing, so a
         * SCAN reply split across recvs doesn't re-alloc the keys array each
         * partial fill. */
        rc = ngx_http_cache_turbo_redis_frame(op->rbuf, op->rbuf + op->rlen,
                                              0, &next);
        if (rc == NGX_AGAIN) {
            continue;                      /* read more before parsing */
        }
        /* NGX_DECLINED falls through: parse_scan reports the same failure. */

        rc = ngx_http_cache_turbo_redis_parse_scan(op, &cursor, &keys, &nkeys);
        if (rc != NGX_OK) {
            ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
            return;
        }

        /* PERF-1: drop the whole page in one pipelined UNLINK connection rather
         * than a fresh fire-and-forget connection per key (an FD/timer storm on
         * a large keyspace). Keys point into rbuf; del_many copies them before
         * the next SCAN resets rbuf. */
        ngx_http_cache_turbo_redis_del_many(op->clcf, keys, nkeys);

        if (cursor.len == 1 && cursor.data[0] == '0') {
            /* whole keyspace walked: emit the response via the callback */
            ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
            return;
        }

        /* Issue the next SCAN with the returned cursor. encode copies the
         * cursor bytes (which point into rbuf) into a fresh send buffer, so it
         * is safe to reset rbuf afterwards. */
        op->send = ngx_http_cache_turbo_redis_scan_cmd(op->pool, op->clcf,
                                                       &cursor);
        if (op->send == NULL) {
            ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
            return;
        }
        op->rlen = 0;
        ngx_post_event(c->write, &ngx_posted_events);
        return;
    }
}


/*
 * SMEMBERS teardown + resume. Hands the parsed members to the policy callback
 * (which must purge + produce the HTTP response while the members are still
 * valid), tears down the op pool, then finalizes the parked request with the
 * rc the callback returned. On any failure the callback runs with 0 members so
 * the caller always gets a well-formed response.
 */
static void
ngx_http_cache_turbo_redis_smembers_finish(
    ngx_http_cache_turbo_redis_op_t *op, ngx_str_t *members,
    ngx_uint_t nmembers)
{
    ngx_http_request_t                     *r = op->request;
    ngx_http_cache_turbo_redis_members_pt   cb = op->members_cb;
    void                                   *data = op->members_data;
    ngx_int_t                               rc;

    /* Callback consumes members (pointing into op->rbuf) synchronously. */
    rc = cb(r, data, members, nmembers);

    /* Now safe to drop our connection + pool (members no longer referenced). */
    ngx_http_cache_turbo_redis_op_done(op);

    ngx_http_run_posted_requests(r->connection);
    ngx_http_finalize_request(r, rc);
}


/* SET path teardown: close the connection and free the op pool. */
static void
ngx_http_cache_turbo_redis_op_done(ngx_http_cache_turbo_redis_op_t *op)
{
    ngx_pool_t        *pool = op->pool;
    ngx_connection_t  *c = op->peer.connection;

    if (c && ngx_http_cache_turbo_redis_ka_save(op)) {
        /* parked on the idle pool; the connection outlives this op */
        ngx_destroy_pool(pool);
        return;
    }

    if (c) {
#if (NGX_SSL)
        ngx_pool_t  *cpool = c->pool;  /* conn-owned pool (TLS) or NULL (plain) */
#endif
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "cache_turbo: redis conn close fd:%d", c->fd);
#if (NGX_SSL)
        if (c->ssl) {
            /* best-effort: don't block teardown waiting on close_notify */
            c->ssl->no_wait_shutdown = 1;
            (void) ngx_ssl_shutdown(c);
        }
        /* c->pool is the dedicated conn pool (TLS path); ngx_close_connection
         * must not treat it as its own — we destroy it after the close. */
        c->pool = NULL;
        ngx_close_connection(c);
        if (cpool) {
            ngx_destroy_pool(cpool);
        }
#else
        ngx_close_connection(c);
#endif
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
    ctx->l2_done = 1;

    /* tear down our own connection + pool (blob is now copied into r->pool) */
    ngx_http_cache_turbo_redis_op_done(op);

    /* resume the parked request, then release the reference taken at park */
    ngx_http_core_run_phases(r);
    ngx_http_run_posted_requests(r->connection);
    ngx_http_finalize_request(r, NGX_DONE);
}


/*
 * Lock (SET NX PX) reply reader. The reply is tiny (+OK / $-1 / -ERR), so a
 * single recv into the scratch buffer suffices. THREE outcomes (codex
 * follow-up — a Redis outage must not look like "peer holds the lock"):
 *   '+' (+OK)         -> NGX_OK       lock acquired, we own the regen
 *   '$' ($-1 nil)     -> NGX_DECLINED key already held by a peer: wait/serve stale
 *   timeout/EOF/-ERR  -> NGX_ERROR    lock channel unusable: degrade to per-box
 *                                     single-flight (regenerate locally), never
 *                                     suppress the refresh on a dead Redis.
 * Only a real nil reply ($-1) means a peer genuinely holds the lock; every
 * transport/protocol failure now maps to NGX_ERROR so the caller falls back
 * instead of freezing the whole fleet on stale during an outage.
 */
static void
ngx_http_cache_turbo_redis_read_lock(ngx_event_t *rev)
{
    ssize_t                           n;
    ngx_connection_t                 *c;
    ngx_http_cache_turbo_redis_op_t  *op;

    c = rev->data;
    op = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "cache_turbo: redis lock timed out");
        ngx_http_cache_turbo_redis_lock_finish(op, NGX_ERROR);
        return;
    }

    n = c->recv(c, op->recv, sizeof(op->recv));

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_http_cache_turbo_redis_lock_finish(op, NGX_ERROR);
        }
        return;
    }
    if (n <= 0) {
        ngx_http_cache_turbo_redis_lock_finish(op, NGX_ERROR);
        return;
    }

    op->clean = 1;                         /* reply consumed: connection poolable */
    ngx_http_cache_turbo_redis_lock_finish(op,
        op->recv[0] == '+' ? NGX_OK :
        op->recv[0] == '$' ? NGX_DECLINED : /* nil: a peer holds the lock */
        NGX_ERROR);                         /* -ERR / garbage: channel unusable */
}


/*
 * Lock teardown + resume. Records the outcome in ctx (lock_done + lock_result),
 * tears down the op, and resumes the parked request through the phase engine —
 * the access handler re-runs and acts on ctx->lock_* (win -> origin, lose ->
 * serve stale). Same park/resume dance as get_finish, minus the blob copy.
 */
static void
ngx_http_cache_turbo_redis_lock_finish(ngx_http_cache_turbo_redis_op_t *op,
    ngx_int_t result)
{
    ngx_http_request_t          *r = op->request;
    ngx_http_cache_turbo_ctx_t  *ctx = op->ctx;

    ctx->lock_result = result;
    ctx->lock_done = 1;

    ngx_http_cache_turbo_redis_op_done(op);

    ngx_http_core_run_phases(r);
    ngx_http_run_posted_requests(r->connection);
    ngx_http_finalize_request(r, NGX_DONE);
}


/* Terminal failure on the shared write path: dispatch by op kind. members_cb is
 * set for both SMEMBERS and SCAN (both finish through smembers_finish); is_lock
 * distinguishes a lock from a GET (both pin op->request + op->ctx). */
static void
ngx_http_cache_turbo_redis_op_fail(ngx_http_cache_turbo_redis_op_t *op)
{
    if (op->members_cb) {
        ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
    } else if (op->is_lock) {
        /* Write-path failure (connect/send/protocol error) is a transport
         * failure, not a peer holding the lock: NGX_ERROR so the caller degrades
         * to per-box single-flight rather than suppressing the refresh. */
        ngx_http_cache_turbo_redis_lock_finish(op, NGX_ERROR);
    } else if (op->request) {
        ngx_http_cache_turbo_redis_get_finish(op, NGX_DECLINED, NULL, 0);
    } else {
        ngx_http_cache_turbo_redis_op_done(op);
    }
}


/* L2 backend instance. purge_tag is the SMEMBERS-based tag walk; scan_del is the
 * v4-2 SCAN MATCH-based whole-keyspace purge; lock is the v4-2 cross-node SET NX
 * PX single-flight. unlock stays NULL: the lock is released only by PX expiry,
 * never by owner (see history.md v4-2 — early unlock would re-open the
 * single-flight window and cause cross-node double-regen). */
ngx_cache_turbo_backend_t  ngx_http_cache_turbo_redis_backend = {
    ngx_string("redis"),
    ngx_http_cache_turbo_redis_get,
    ngx_http_cache_turbo_redis_set,
    ngx_http_cache_turbo_redis_del,
    ngx_http_cache_turbo_redis_del_raw,
    ngx_http_cache_turbo_redis_tagkey,
    ngx_http_cache_turbo_redis_tag_add,
    ngx_http_cache_turbo_redis_smembers,
    ngx_http_cache_turbo_redis_scan_del,
    ngx_http_cache_turbo_redis_lock,
    NULL,   /* unlock — PX expiry only */
};
