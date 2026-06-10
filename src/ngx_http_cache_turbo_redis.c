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

    ngx_http_request_t          *request;  /* GET/SMEMBERS/SCAN/lock: parked req */
    ngx_http_cache_turbo_ctx_t  *ctx;      /* GET/lock: request ctx to fill   */
    ngx_http_cache_turbo_loc_conf_t *clcf; /* SCAN: rebuild next SCAN + del_raw */
    unsigned                     is_lock:1;/* lock op (deposits ctx->lock_*)  */

    /* SMEMBERS / SCAN: completion callback + opaque data (purge policy) */
    ngx_http_cache_turbo_redis_members_pt  members_cb;
    void                        *members_data;

    u_char                      *rbuf;     /* GET/SMEMBERS: growable reply buf */
    size_t                       rcap;
    size_t                       rlen;

    u_char                       recv[128];/* SET: reply scratch (+OK / -ERR) */
} ngx_http_cache_turbo_redis_op_t;


static void ngx_http_cache_turbo_redis_write(ngx_event_t *wev);
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

    if (ngx_http_cache_turbo_redis_connect(op, &clcf->redis_addr,
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

    op->send = ngx_http_cache_turbo_redis_encode(op->pool, argv, argc);
    if (op->send == NULL) {
        ngx_destroy_pool(op->pool);
        return;
    }

    if (ngx_http_cache_turbo_redis_connect(op, &clcf->redis_addr,
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
        ngx_http_cache_turbo_redis_del_raw(clcf, keybuf, keylen);
    }

    ngx_destroy_pool(tmp);
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
    ngx_str_t                         argv[3];
    ngx_buf_t                        *sadd, *expire;
    size_t                            n1, n2;
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

    /* EXPIRE <prefix>tag:<name> <ttl> — bound the tag set's lifetime so dead
     * members can't accumulate forever; refreshed on every store. */
    argv[0].data = (u_char *) "EXPIRE";
    argv[0].len = sizeof("EXPIRE") - 1;
    /* argv[1] (tagkey) unchanged */
    argv[2].data = ttlbuf;
    argv[2].len = (size_t) (ngx_sprintf(ttlbuf, "%T", ttl) - ttlbuf);
    expire = ngx_http_cache_turbo_redis_encode(op->pool, argv, 3);

    if (sadd == NULL || expire == NULL) {
        ngx_destroy_pool(op->pool);
        return;
    }

    /* Pipeline both commands into one buffer (one round trip). */
    n1 = sadd->last - sadd->pos;
    n2 = expire->last - expire->pos;
    op->send = ngx_create_temp_buf(op->pool, n1 + n2);
    if (op->send == NULL) {
        ngx_destroy_pool(op->pool);
        return;
    }
    op->send->last = ngx_cpymem(op->send->last, sadd->pos, n1);
    op->send->last = ngx_cpymem(op->send->last, expire->pos, n2);

    if (ngx_http_cache_turbo_redis_connect(op, &clcf->redis_addr,
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

    if (ngx_http_cache_turbo_redis_connect(op, &clcf->redis_addr,
            ngx_http_cache_turbo_redis_read_lock) != NGX_OK)
    {
        ngx_destroy_pool(pool);
        return NGX_DECLINED;
    }

    ctx->lock_pending = 1;
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

    if (ngx_http_cache_turbo_redis_connect(op, &clcf->redis_addr,
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


/* Encode one SCAN <cursor> MATCH <prefix>* COUNT <n> command into pool. */
static ngx_buf_t *
ngx_http_cache_turbo_redis_scan_cmd(ngx_pool_t *pool,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_str_t *cursor)
{
    ngx_str_t  argv[6];
    u_char    *match;

    match = ngx_pnalloc(pool, clcf->redis_prefix.len + 1);
    if (match == NULL) {
        return NULL;
    }
    ngx_memcpy(match, clcf->redis_prefix.data, clcf->redis_prefix.len);
    match[clcf->redis_prefix.len] = '*';

    argv[0].data = (u_char *) "SCAN";
    argv[0].len = sizeof("SCAN") - 1;
    argv[1] = *cursor;
    argv[2].data = (u_char *) "MATCH";
    argv[2].len = sizeof("MATCH") - 1;
    argv[3].data = match;
    argv[3].len = clcf->redis_prefix.len + 1;
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

    if (ngx_http_cache_turbo_redis_connect(op, &clcf->redis_addr,
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


/* Upper bound on a SMEMBERS reply element count, so a bogus "*<huge>" header
 * can't make us allocate an enormous members array before any data arrives. */
#define NGX_HTTP_CACHE_TURBO_REDIS_MAX_MEMBERS  (1024 * 1024)


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
    ssize_t                           n;
    ngx_str_t                        *members;
    u_char                           *nbuf;
    size_t                            ncap;
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
        if (op->rlen == op->rcap) {
            if (op->rcap >= NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY) {
                ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
                return;
            }
            ncap = op->rcap * 2;
            if (ncap > NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY) {
                ncap = NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY;
            }
            nbuf = ngx_pnalloc(op->pool, ncap);
            if (nbuf == NULL) {
                ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
                return;
            }
            ngx_memcpy(nbuf, op->rbuf, op->rlen);
            op->rbuf = nbuf;
            op->rcap = ncap;
        }

        n = c->recv(c, op->rbuf + op->rlen, op->rcap - op->rlen);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
            }
            return;
        }
        if (n == NGX_ERROR || n == 0) {
            ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
            return;
        }

        op->rlen += n;

        rc = ngx_http_cache_turbo_redis_parse_array(op, &members, &nmembers);
        if (rc == NGX_AGAIN) {
            continue;
        }
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
    ssize_t                           n;
    u_char                           *nbuf;
    size_t                            ncap;
    ngx_str_t                         cursor, *keys;
    ngx_uint_t                        i, nkeys;
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
        if (op->rlen == op->rcap) {
            if (op->rcap >= NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY) {
                ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
                return;
            }
            ncap = op->rcap * 2;
            if (ncap > NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY) {
                ncap = NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY;
            }
            nbuf = ngx_pnalloc(op->pool, ncap);
            if (nbuf == NULL) {
                ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
                return;
            }
            ngx_memcpy(nbuf, op->rbuf, op->rlen);
            op->rbuf = nbuf;
            op->rcap = ncap;
        }

        n = c->recv(c, op->rbuf + op->rlen, op->rcap - op->rlen);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
            }
            return;
        }
        if (n == NGX_ERROR || n == 0) {
            ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
            return;
        }

        op->rlen += n;

        rc = ngx_http_cache_turbo_redis_parse_scan(op, &cursor, &keys, &nkeys);
        if (rc == NGX_AGAIN) {
            continue;
        }
        if (rc != NGX_OK) {
            ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
            return;
        }

        /* DEL each matched key (keys point into rbuf; del_raw copies them). */
        for (i = 0; i < nkeys; i++) {
            if (keys[i].len) {
                ngx_http_cache_turbo_redis_del_raw(op->clcf, keys[i].data,
                                                   keys[i].len);
            }
        }

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


/*
 * Lock (SET NX PX) reply reader. The reply is tiny (+OK / $-1 / -ERR), so a
 * single recv into the scratch buffer suffices; the first byte decides:
 * '+' (+OK) = lock acquired; anything else ($-1 nil = key already held, -ERR,
 * EOF, error) = not acquired. Treating every non-'+' as "lost" is conservative:
 * the caller serves stale, never stampedes the origin on a Redis hiccup.
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
        ngx_http_cache_turbo_redis_lock_finish(op, NGX_DECLINED);
        return;
    }

    n = c->recv(c, op->recv, sizeof(op->recv));

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_http_cache_turbo_redis_lock_finish(op, NGX_DECLINED);
        }
        return;
    }
    if (n <= 0) {
        ngx_http_cache_turbo_redis_lock_finish(op, NGX_DECLINED);
        return;
    }

    ngx_http_cache_turbo_redis_lock_finish(op,
        op->recv[0] == '+' ? NGX_OK : NGX_DECLINED);
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
    ctx->lock_pending = 0;
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
        ngx_http_cache_turbo_redis_lock_finish(op, NGX_DECLINED);
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
    ngx_http_cache_turbo_redis_key,
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
