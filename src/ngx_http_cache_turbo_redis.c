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
#include "ngx_http_cache_turbo_internal.h"

/* R5-1 (perf-microtier-hitpath): default-hide every symbol this TU defines
 * so a module-internal call becomes a direct call instead of a PLT-indirect
 * one (see ngx_http_cache_turbo_module.h for why this is a per-file pragma
 * rather than a global -fvisibility=hidden CFLAGS addition, and why a
 * header-only pragma does not work). Anything in this file that nginx's
 * dynamic-module loader must resolve by name gets an explicit
 * __attribute__((visibility("default"))) at its definition, overriding this
 * pragma (GCC: an explicit attribute always wins over the pragma). */
#pragma GCC visibility push(hidden)

#if (NGX_SSL)
#include <ngx_event_openssl.h>
#endif


/* Hard ceiling on a GET reply, so a bogus/huge value can't grow the recv
 * buffer without bound. Comfortably above any sane cached page. */
#define NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY  (64 * 1024 * 1024)

/* Upper bound on an array reply element count, so a bogus "*<huge>" header
 * can't make us allocate an enormous members array before any data arrives. */
#define NGX_HTTP_CACHE_TURBO_REDIS_MAX_MEMBERS  (1024 * 1024)

/* AUD-SCAN1: hard ceiling on the number of SCAN pages one all-purge walk may
 * consume. read_scan terminates only when the server hands back cursor "0"; a
 * broken or hostile L2 that always returns a non-zero cursor otherwise loops
 * forever, and the per-page read timeout does not bound it because each page's
 * write re-arms the timer. At COUNT 256 this cap covers a ~268M-key keyspace,
 * far past any real cache, so an honest server never reaches it. Reaching it
 * ABANDONS the walk and reports the purge INCOMPLETE — it is never silently
 * treated as a completed purge. */
#define NGX_HTTP_CACHE_TURBO_REDIS_SCAN_MAX_PAGES  (1024 * 1024)

/* Cap recursion/nesting so a buggy/hostile server can't blow the stack (or the
 * resume stack below) with deeply nested arrays. Replies to the commands we
 * issue nest at most 2 deep (SCAN). Sizes op->frame_stack, so it must be
 * defined before the op struct. */
#define NGX_HTTP_CACHE_TURBO_REDIS_FRAME_MAX_DEPTH  8


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

    /* S231: 1 from a fresh (non-reused, non-TLS-handshake) connect() attempt
     * until the FIRST byte is actually written on the wire. A write-path
     * failure (op_fail) that fires while this is still 1 means nothing ever
     * left the socket -- the async ECONNREFUSED/RST/connect-timeout case,
     * which on this platform is how a closed-port connect actually surfaces
     * (ngx_event_connect_peer's own non-blocking connect() returns EINPROGRESS
     * -> NGX_AGAIN on loopback even for a port nothing listens on; the refusal
     * is only observable later, on the write event). Cleared to 0 the moment
     * any data is sent, so a later send()/timeout error (a real transport
     * failure mid-command, or a protocol error after the reply starts) is
     * correctly NOT treated as a connect failure and does not arm backoff. */
    unsigned                     unconnected:1;

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

    /* S231-L2-FRAMEQUAD: resume state for the iterative
     * ngx_http_cache_turbo_redis_frame_scan() walk, so a dribbled large array
     * is framed in ONE pass across many fill() calls instead of being
     * re-walked from byte 0 every time. frame_off is a BYTE OFFSET (not a
     * pointer) into op->rbuf: fill() may ngx_pnalloc() a bigger buffer and
     * memcpy the old bytes to the same relative position on grow, so an
     * offset survives that where a raw pointer would dangle. frame_remain[d]
     * is the element count still outstanding at nesting depth d (index 0 =
     * outermost array); frame_depth is the current stack height (0 = not
     * inside any array). Both are reset to 0 whenever rbuf/rlen are reset for
     * a new command (op init, and the SCAN per-page reset in read_scan) --
     * resuming into a buffer that no longer holds the same bytes is a
     * correctness bug, not just a stale-cache inefficiency. */
    size_t                       frame_off;
    ngx_uint_t                   frame_remain[NGX_HTTP_CACHE_TURBO_REDIS_FRAME_MAX_DEPTH];
    ngx_uint_t                   frame_depth;

    /* AUD-SCAN1: pool the reply buffer (and, on the SCAN walk, everything else
     * that only has to live for one page) is allocated from. It is op->pool for
     * every op except scan_del, where it is a per-page pool that is destroyed
     * once del_many has copied the page's keys out. Without that the whole walk
     * accumulated in op->pool: a keys array and a rebuilt SCAN command per
     * page, plus a reply buffer that only ever doubled — bounded per page, but
     * never released until the walk ended. */
    ngx_pool_t                  *rpool;

    /* SCAN walk bookkeeping (AUD-SCAN1). is_scan distinguishes the SCAN-del op
     * from the SMEMBERS op, which shares smembers_finish; scan_status is the
     * outcome handed to the completion callback (NGX_OK only when the server
     * returned cursor "0"), and starts as NGX_ERROR so every path that reaches
     * finish WITHOUT setting it reports INCOMPLETE rather than success. */
    unsigned                     is_scan:1;
    ngx_int_t                    scan_status;
    ngx_uint_t                   scan_pages;
    ngx_msec_t                   scan_start; /* S231-L2-SCANTIME: walk start
                                              * (ngx_current_msec), set once when
                                              * the SCAN op is launched          */
    unsigned                     scan_deadline_hit:1; /* S231-L2-SCANTIME: walk
                                              * abandoned by the wall-clock
                                              * deadline, not the page cap —
                                              * the oracle marker unique to this
                                              * path (surfaced via walk.status)  */

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
static ngx_int_t ngx_http_cache_turbo_redis_resp_len(u_char *p, size_t n,
    ngx_int_t *len);
static ngx_uint_t ngx_http_cache_turbo_redis_pool_blocks(ngx_pool_t *pool);
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

typedef struct ngx_http_cache_turbo_redis_ka_bucket_s
    ngx_http_cache_turbo_redis_ka_bucket_t;

/* A pooled connection slot. Profile identity (fp/tls/creds/db/addr) lives on the
 * owning bucket, not here — every item in a bucket shares that one profile — so
 * an item only needs the connection and a back-pointer to its bucket. */
typedef struct {
    ngx_queue_t        queue;
    ngx_connection_t  *connection;
    ngx_http_cache_turbo_redis_ka_bucket_t  *bucket;  /* owning bucket (for drop) */
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
 * config pool (process/worker lifetime), so no copy is needed. The byte-exact
 * profile compare lives in ka_bucket_eq: a keepalive bucket owns exactly one
 * profile, so any item inside a bucket is already an exact match. */

/* Per-profile keepalive sub-pool. Each distinct redis connection profile
 * (fingerprint + exact SEC-3 fields + peer addr + tls bit) gets its OWN bucket
 * with its OWN cap and timeout, taken from the first location that opens that
 * profile. This is the real fix for the old single-pool defect where cap and
 * timeout were latched once per worker by whichever keepalive-enabled location
 * inited first, silently discarding every other location's redis_keepalive[_timeout]
 * and letting mutually-unreusable profiles starve each other on one undivided
 * budget. Now each profile's budget is isolated and sized by the config that
 * owns it. */
struct ngx_http_cache_turbo_redis_ka_bucket_s {
    ngx_uint_t   inited;               /* slot allocated + queues initialized */
    ngx_uint_t   max;                  /* cap (this profile's cache_turbo_redis keepalive=N) */
    ngx_uint_t   count;                /* live idle connections held */
    ngx_msec_t   timeout;              /* idle close timeout */
    ngx_queue_t  cache;                /* items holding a live connection */
    ngx_queue_t  free;                 /* empty item slots */
    ngx_http_cache_turbo_redis_ka_item_t *items;

    /* Profile identity this bucket serves (config-pool-backed, no copy). */
    uint32_t         ctx_fp;
    unsigned         tls:1;
    unsigned         tls_verify:1;
    ngx_int_t        db;
    ngx_str_t        user;
    ngx_str_t        password;
    ngx_str_t        tls_ca;
    ngx_str_t        tls_name;
    ngx_str_t        host;
    socklen_t        socklen;
    ngx_sockaddr_t   sockaddr;
};

/* Max distinct redis profiles pooled per worker. A profile is a backend +
 * credential + db + TLS-trust combination; realistic deployments use 1-3.
 * The cap only bounds pathological configs; overflow (a rare 17th distinct
 * profile) simply runs unpooled — every op opens+closes a fresh conn, which is
 * fully functional since L2 is advisory. No eviction: a filled array never
 * realistically occurs and overflow degrades gracefully. */
#define NGX_HTTP_CACHE_TURBO_REDIS_KA_MAX_BUCKETS  16

typedef struct {
    ngx_uint_t  nbuckets;              /* buckets in use */
    ngx_http_cache_turbo_redis_ka_bucket_t
                buckets[NGX_HTTP_CACHE_TURBO_REDIS_KA_MAX_BUCKETS];
} ngx_http_cache_turbo_redis_ka_t;

/* Process-global: each worker gets its own copy after fork. */
static ngx_http_cache_turbo_redis_ka_t  ngx_http_cache_turbo_redis_ka;

static void ngx_http_cache_turbo_redis_ka_close_handler(ngx_event_t *ev);
static void ngx_http_cache_turbo_redis_ka_dummy_handler(ngx_event_t *ev);


/* Does bucket b serve the profile described by clcf/addr/fp? Same exact match
 * as ka_get uses on individual items: fp pre-filter, tls bit, peer addr, then
 * the byte-exact SEC-3 profile compare. */
static ngx_int_t
ngx_http_cache_turbo_redis_ka_bucket_eq(
    ngx_http_cache_turbo_redis_ka_bucket_t *b,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_addr_t *addr,
    uint32_t fp, ngx_uint_t want_tls)
{
    return b->ctx_fp == fp
        && b->tls == want_tls
        && b->socklen == addr->socklen
        && ngx_memcmp(&b->sockaddr, addr->sockaddr, addr->socklen) == 0
        && b->db == clcf->redis_db
        && b->tls_verify == (unsigned) (clcf->redis_tls_verify ? 1 : 0)
        && ngx_http_cache_turbo_str_eq(&b->user, &clcf->redis_user)
        && ngx_http_cache_turbo_str_eq(&b->password, &clcf->redis_password)
        && ngx_http_cache_turbo_str_eq(&b->tls_ca, &clcf->redis_tls_ca)
        && ngx_http_cache_turbo_str_eq(&b->tls_name, &clcf->redis_tls_name)
        && ngx_http_cache_turbo_str_eq(&b->host, &clcf->redis_host);
}


/* Locate the keepalive bucket for clcf/addr's profile, or NULL. When create is
 * set and no bucket exists yet, lazily allocate one sized from THIS location's
 * redis_keepalive[_timeout] (so per-location caps are honoured). Returns NULL if
 * keepalive is off, the bucket array is full, or allocation fails — all of which
 * make the caller run unpooled, which is safe. Items live in ngx_cycle->pool
 * (worker lifetime). */
static ngx_http_cache_turbo_redis_ka_bucket_t *
ngx_http_cache_turbo_redis_ka_bucket(ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_addr_t *addr, uint32_t fp, ngx_uint_t want_tls, ngx_uint_t create)
{
    ngx_uint_t                               i, max;
    ngx_http_cache_turbo_redis_ka_t         *ka = &ngx_http_cache_turbo_redis_ka;
    ngx_http_cache_turbo_redis_ka_bucket_t  *b;

    if (clcf->redis_keepalive <= 0) {
        return NULL;
    }

    for (i = 0; i < ka->nbuckets; i++) {
        b = &ka->buckets[i];
        if (ngx_http_cache_turbo_redis_ka_bucket_eq(b, clcf, addr, fp, want_tls)) {
            return b;
        }
    }

    if (!create) {
        return NULL;
    }

    if (ka->nbuckets >= NGX_HTTP_CACHE_TURBO_REDIS_KA_MAX_BUCKETS) {
        return NULL;                       /* array full: run unpooled */
    }

    b = &ka->buckets[ka->nbuckets];
    max = (ngx_uint_t) clcf->redis_keepalive;

    b->items = ngx_palloc(ngx_cycle->pool,
                          max * sizeof(ngx_http_cache_turbo_redis_ka_item_t));
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
    b->timeout = clcf->redis_keepalive_timeout
                     ? clcf->redis_keepalive_timeout : 60000;

    /* Snapshot the profile identity (config-pool-backed, no copy). */
    b->ctx_fp = fp;
    b->tls = want_tls;
    b->tls_verify = clcf->redis_tls_verify ? 1 : 0;
    b->db = clcf->redis_db;
    b->user = clcf->redis_user;
    b->password = clcf->redis_password;
    b->tls_ca = clcf->redis_tls_ca;
    b->tls_name = clcf->redis_tls_name;
    b->host = clcf->redis_host;
    b->socklen = addr->socklen;
    ngx_memcpy(&b->sockaddr, addr->sockaddr, addr->socklen);

    b->inited = 1;
    ka->nbuckets++;

    return b;
}


/* Close a pooled connection and return its slot to the free queue. */
static void
ngx_http_cache_turbo_redis_ka_drop(ngx_http_cache_turbo_redis_ka_item_t *item)
{
    ngx_connection_t                        *c = item->connection;
    ngx_http_cache_turbo_redis_ka_bucket_t  *b = item->bucket;

    ngx_queue_remove(&item->queue);
    ngx_queue_insert_head(&b->free, &item->queue);
    b->count--;

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
    ngx_http_cache_turbo_redis_ka_bucket_t *b;
    ngx_uint_t                              want_tls = clcf->redis_tls ? 1 : 0;
    uint32_t                                want_fp = ngx_http_cache_turbo_redis_ka_fp(clcf);

    /* A live connection can only exist in an already-created bucket, so don't
     * create one here (create=0). */
    b = ngx_http_cache_turbo_redis_ka_bucket(clcf, addr, want_fp, want_tls, 0);
    if (b == NULL) {
        return NULL;
    }

    /* Bucket identity already guarantees the full profile match; any parked
     * conn in it is reusable. Take the head. */
    if (ngx_queue_empty(&b->cache)) {
        return NULL;
    }

    q = ngx_queue_head(&b->cache);
    item = ngx_queue_data(q, ngx_http_cache_turbo_redis_ka_item_t, queue);
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

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "cache_turbo: redis reuse pooled conn fd:%d (%ui left)",
                   c->fd, b->count);
    return c;
}


/* Park op's connection on the idle pool if it is reusable. Returns 1 if parked
 * (caller must NOT close it), 0 if the caller should close it as usual. */
static ngx_uint_t
ngx_http_cache_turbo_redis_ka_save(ngx_http_cache_turbo_redis_op_t *op)
{
    u_char                                  scratch[1];
    ssize_t                                 n;
    ngx_addr_t                              addr;
    uint32_t                                fp;
    ngx_uint_t                              tls;
    ngx_queue_t                            *q;
    ngx_connection_t                       *c = op->peer.connection;
    ngx_http_cache_turbo_redis_ka_item_t   *item;
    ngx_http_cache_turbo_redis_ka_bucket_t *b;

    if (!op->clean || c == NULL || op->clcf == NULL) {
        return 0;
    }
    if (c->read->error || c->write->error || c->read->eof
        || c->read->timedout || c->write->timedout || c->error)
    {
        return 0;
    }

    addr.sockaddr = op->peer.sockaddr;
    addr.socklen = op->peer.socklen;
    fp = ngx_http_cache_turbo_redis_ka_fp(op->clcf);
    tls = c->ssl ? 1 : 0;

    b = ngx_http_cache_turbo_redis_ka_bucket(op->clcf, &addr, fp, tls, 1);
    if (b == NULL) {
        return 0;                          /* keepalive off / array full: close it */
    }
    if (b->count >= b->max || ngx_queue_empty(&b->free)) {
        return 0;                          /* this profile's pool full: close it */
    }

    /* The stream must be exactly at a reply boundary: redis should have nothing
     * more to send. A readable byte here means leftover/unsolicited data (or a
     * close) — don't pool a connection we can't trust. */
    n = c->recv(c, scratch, sizeof(scratch));
    if (n != NGX_AGAIN) {
        return 0;
    }

    q = ngx_queue_head(&b->free);
    ngx_queue_remove(q);
    item = ngx_queue_data(q, ngx_http_cache_turbo_redis_ka_item_t, queue);
    ngx_queue_insert_head(&b->cache, q);
    b->count++;

    item->connection = c;
    /* item->bucket was set at bucket-init and is stable. The connection's
     * profile identity is the bucket's; no per-item snapshot is needed. */

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

    ngx_add_timer(c->read, b->timeout);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "cache_turbo: redis pool conn fd:%d (%ui idle)",
                   c->fd, b->count);
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


/* S231: per-worker L2 connect backoff, redis side.
 *
 * After a connect FAILURE (ngx_event_connect_peer returning ERROR/BUSY/
 * DECLINED -- never a protocol/reply error) to a given peer, this worker
 * fails L2 ops fast for redis_connect_backoff ms instead of paying a fresh
 * connect() attempt on every request during an outage. A successful connect
 * (rc == NGX_OK or NGX_AGAIN from ngx_event_connect_peer) clears the window.
 *
 * Same shape as the keepalive pool above (process-global; each worker gets
 * its own copy after fork), keyed the same way: peer sockaddr only -- unlike
 * the KA bucket this deliberately does NOT include db/credentials/TLS
 * fingerprint, because a connect failure is about reaching the socket, not
 * about which profile was being negotiated once connected. A small fixed
 * table (not a hash) is enough: realistic deployments touch 1-3 distinct L2
 * peers per worker; overflow just never arms (fail open on the backoff
 * itself -- the ordinary per-request connect failure path still applies). */
#define NGX_HTTP_CACHE_TURBO_REDIS_BACKOFF_MAX_PEERS  16

typedef struct {
    ngx_uint_t       used;
    socklen_t        socklen;
    ngx_sockaddr_t   sockaddr;
    ngx_msec_t       until;    /* ngx_current_msec deadline; 0 = not armed */
} ngx_http_cache_turbo_redis_backoff_slot_t;

typedef struct {
    ngx_uint_t  nslots;
    ngx_http_cache_turbo_redis_backoff_slot_t
                slots[NGX_HTTP_CACHE_TURBO_REDIS_BACKOFF_MAX_PEERS];
} ngx_http_cache_turbo_redis_backoff_t;

static ngx_http_cache_turbo_redis_backoff_t  ngx_http_cache_turbo_redis_backoff;

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
/* Test-only observable: bumped exactly once per request that hit the
 * fail-fast backoff path (never on an ordinary connect failure, never on a
 * cache hit/miss that never touched L2). See test_armings-style headers in
 * ngx_http_cache_turbo_module.c for the surfacing convention this mirrors. */
ngx_atomic_uint_t  ngx_http_cache_turbo_redis_test_backoff_skips = 0;
#endif


static ngx_http_cache_turbo_redis_backoff_slot_t *
ngx_http_cache_turbo_redis_backoff_find(ngx_addr_t *addr, ngx_uint_t create)
{
    ngx_uint_t                                  i;
    ngx_http_cache_turbo_redis_backoff_slot_t  *s, *free_slot = NULL;

    for (i = 0; i < ngx_http_cache_turbo_redis_backoff.nslots; i++) {
        s = &ngx_http_cache_turbo_redis_backoff.slots[i];
        if (s->used
            && s->socklen == addr->socklen
            && ngx_memcmp(&s->sockaddr, addr->sockaddr, addr->socklen) == 0)
        {
            return s;
        }
    }

    if (!create) {
        return NULL;
    }

    if (ngx_http_cache_turbo_redis_backoff.nslots
        < NGX_HTTP_CACHE_TURBO_REDIS_BACKOFF_MAX_PEERS)
    {
        free_slot = &ngx_http_cache_turbo_redis_backoff.slots[
            ngx_http_cache_turbo_redis_backoff.nslots++];
    }

    if (free_slot == NULL) {
        /* Table full (pathological config): degrade gracefully, same as the
         * KA bucket cap -- no backoff tracking for the overflow peer rather
         * than corrupting another peer's slot. */
        return NULL;
    }

    ngx_memzero(free_slot, sizeof(ngx_http_cache_turbo_redis_backoff_slot_t));
    free_slot->used = 1;
    free_slot->socklen = addr->socklen;
    ngx_memcpy(&free_slot->sockaddr, addr->sockaddr, addr->socklen);

    return free_slot;
}


/* Is addr currently inside its backoff window? backoff_ms == 0 means the
 * feature is disabled for this location -- never back off, regardless of
 * this worker's failure history against addr. */
static ngx_uint_t
ngx_http_cache_turbo_redis_backoff_active(ngx_addr_t *addr,
    ngx_msec_t backoff_ms)
{
    ngx_http_cache_turbo_redis_backoff_slot_t  *s;

    if (backoff_ms == 0) {
        return 0;
    }

    s = ngx_http_cache_turbo_redis_backoff_find(addr, 0);
    if (s == NULL || s->until == 0) {
        return 0;
    }

    if ((ngx_msec_int_t) (s->until - ngx_current_msec) > 0) {
        return 1;
    }

    /* Window elapsed: clear it so the next check is O(1) again and a later
     * success doesn't have to fight a stale deadline. */
    s->until = 0;
    return 0;
}


static void
ngx_http_cache_turbo_redis_backoff_arm(ngx_addr_t *addr, ngx_msec_t backoff_ms)
{
    ngx_http_cache_turbo_redis_backoff_slot_t  *s;

    if (backoff_ms == 0) {
        return;
    }

    s = ngx_http_cache_turbo_redis_backoff_find(addr, 1);
    if (s == NULL) {
        return;
    }

    s->until = ngx_current_msec + backoff_ms;
}


static void
ngx_http_cache_turbo_redis_backoff_clear(ngx_addr_t *addr)
{
    ngx_http_cache_turbo_redis_backoff_slot_t  *s;

    s = ngx_http_cache_turbo_redis_backoff_find(addr, 0);
    if (s != NULL) {
        s->until = 0;
    }
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
        if (op->clcf != NULL) {
            ngx_http_cache_turbo_redis_backoff_arm(addr,
                op->clcf->redis_connect_backoff);
        }
        return NGX_ERROR;
    }

    /* rc == NGX_OK/NGX_AGAIN here only means the non-blocking connect()
     * STARTED without an immediate synchronous error -- on loopback even a
     * refused port typically returns EINPROGRESS, with ECONNREFUSED only
     * surfacing later on the write event. So this is NOT "connected" for
     * backoff purposes: op->unconnected stays armed (set below) and the
     * write handler is what actually confirms or arms backoff. */

    c = op->peer.connection;
    c->data = op;
    op->unconnected = 1;

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

    /* S231: fail fast during an armed backoff window instead of paying a
     * fresh connect() attempt on every request while this peer is known-down.
     * Checked BEFORE the keepalive lookup so the two never race: a pooled
     * idle connection that is still genuinely alive gets drained by ordinary
     * traffic and eventually reaped by its own keepalive_timeout even while
     * backoff is armed (nothing here closes it), but a fresh op does not go
     * looking for one -- keeping one single choke point for the fail-fast
     * check, and matching "connect failure only" scope: backoff never claims
     * a live pooled connection is down. */
    if (ngx_http_cache_turbo_redis_backoff_active(&clcf->redis_addr,
            clcf->redis_connect_backoff))
    {
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
        ngx_atomic_fetch_add(&ngx_http_cache_turbo_redis_test_backoff_skips, 1);
#endif
        return NGX_ERROR;
    }

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
    op->rpool = pool;                      /* scan_del re-points this per page */
    op->timeout = clcf->redis_timeout;

    return op;
}


void
ngx_http_cache_turbo_redis_set(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, u_char *key_hash,
    u_char *blob, size_t blob_len, time_t fresh_ttl, time_t retain_ttl)
{
    ngx_pool_t                       *pool;
    ngx_str_t                         argv[5];
    ngx_http_cache_turbo_redis_op_t  *op;
    u_char                           *keybuf, *blobcopy, *msbuf;

    if (!clcf->redis_enable) {
        return;
    }

    /* L2 entry lives as long as the caller says it should (retain_ttl) --
     * the backend no longer derives its own window from fresh_ttl. */
    if (retain_ttl <= 0) {
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
    argv[4].len = (size_t) (ngx_sprintf(msbuf, "%T", retain_ttl * 1000) - msbuf);

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


/* L9: index N tags for one object in a SINGLE pipelined op.
 *
 * Each tag costs three commands (SADD + EXPIRE NX + EXPIRE GT, see the COR-8
 * rationale below), and the store path can present up to MAX_TAGS of them. One
 * op per tag meant up to 16 separate pools, connections and round trips fired
 * by a single response; batching collapses that to one of each. The per-tag
 * wire encoding is unchanged -- only the number of ops is.
 *
 * Fire-and-forget (read_drain, no request parked on the reply), so a batched
 * failure degrades exactly as a single-tag failure did: the tag index misses
 * this object and a later purge of that tag does not invalidate it. */
ngx_int_t
ngx_http_cache_turbo_redis_tag_add_many(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *key_hash, ngx_str_t *names, ngx_uint_t nnames, time_t ttl)
{
    ngx_str_t                         argv[4];
    ngx_buf_t                        *sadd, *exp_nx, *exp_gt;
    size_t                            total = 0;
    ngx_uint_t                        i, nqueued = 0;
    ngx_http_cache_turbo_redis_op_t  *op;
    u_char                           *member, *ttlbuf;
    ngx_buf_t                        *cmds[NGX_HTTP_CACHE_TURBO_MAX_TAGS * 3];

    if (!clcf->redis_enable || ttl <= 0 || nnames == 0) {
        /* Nothing to index and nothing dropped -- an L2-less or empty call is
         * not a lost index write, so it must NOT arm the COR-5 self-heal. */
        return NGX_OK;
    }

    /* Defensive: the caller's dedup array is MAX_TAGS-bound, and cmds[] above
     * is sized off the same constant. Refuse rather than overrun if a future
     * caller presents more. */
    if (nnames > NGX_HTTP_CACHE_TURBO_MAX_TAGS) {
        nnames = NGX_HTTP_CACHE_TURBO_MAX_TAGS;
    }

    op = ngx_http_cache_turbo_redis_op_create(clcf);
    if (op == NULL) {
        return NGX_ERROR;
    }

    /* The object's L2 key and the TTL text are identical for every tag in the
     * batch, so encode them once. */
    member = ngx_pnalloc(op->pool, clcf->redis_prefix.len + 64);
    ttlbuf = ngx_pnalloc(op->pool, NGX_INT64_LEN);
    if (member == NULL || ttlbuf == NULL) {
        ngx_destroy_pool(op->pool);
        return NGX_ERROR;
    }

    argv[2].data = member;
    argv[2].len = ngx_http_cache_turbo_redis_key(&clcf->redis_prefix, key_hash,
                                                 member);

    for (i = 0; i < nnames; i++) {
        u_char  *tagkey;
        size_t   klen;

        if (names[i].len == 0) {
            continue;
        }

        tagkey = ngx_pnalloc(op->pool, clcf->redis_prefix.len
                             + sizeof("tag:") - 1 + names[i].len);
        if (tagkey == NULL) {
            ngx_destroy_pool(op->pool);
            return NGX_ERROR;
        }

        klen = ngx_http_cache_turbo_redis_tagkey(&clcf->redis_prefix,
                                                 names[i].data, names[i].len,
                                                 tagkey);

        /* SADD <prefix>tag:<name> <object L2 key> */
        argv[0].data = (u_char *) "SADD";
        argv[0].len = sizeof("SADD") - 1;
        argv[1].data = tagkey;
        argv[1].len = klen;
        /* argv[2] (member) encoded once above */
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
            return NGX_ERROR;
        }

        /* argv[2] is reused as the TTL text by the EXPIREs above, so restore
         * the member for the next tag's SADD. */
        argv[2].data = member;
        argv[2].len = ngx_http_cache_turbo_redis_key(&clcf->redis_prefix,
                                                     key_hash, member);

        cmds[nqueued++] = sadd;
        cmds[nqueued++] = exp_nx;
        cmds[nqueued++] = exp_gt;
        total += (size_t) (sadd->last - sadd->pos)
                 + (size_t) (exp_nx->last - exp_nx->pos)
                 + (size_t) (exp_gt->last - exp_gt->pos);
    }

    if (nqueued == 0) {                    /* every name was empty */
        ngx_destroy_pool(op->pool);
        return NGX_OK;                     /* nothing to send, nothing lost */
    }

    /* Pipeline every queued command into one buffer (one round trip). */
    op->send = ngx_create_temp_buf(op->pool, total);
    if (op->send == NULL) {
        ngx_destroy_pool(op->pool);
        return NGX_ERROR;
    }
    for (i = 0; i < nqueued; i++) {
        size_t  n = (size_t) (cmds[i]->last - cmds[i]->pos);
        op->send->last = ngx_cpymem(op->send->last, cmds[i]->pos, n);
    }

    /* 3 replies per tag: SADD + EXPIRE NX + EXPIRE GT */
    op->expected_replies = (ngx_uint_t) nqueued;

    if (ngx_http_cache_turbo_redis_launch(op, clcf,
            ngx_http_cache_turbo_redis_read_drain) != NGX_OK)
    {
        ngx_destroy_pool(op->pool);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/* Single-tag entry point, preserved for the auto-vary variant-index store
 * (one tag, nothing to batch) and any other one-shot caller. */
ngx_int_t
ngx_http_cache_turbo_redis_tag_add(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *key_hash, u_char *name, size_t name_len, time_t ttl)
{
    ngx_str_t  one;

    if (name_len == 0) {
        return NGX_OK;                     /* nothing asked for, nothing lost */
    }

    one.data = name;
    one.len = name_len;

    return ngx_http_cache_turbo_redis_tag_add_many(clcf, key_hash, &one, 1,
                                                   ttl);
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
    op->is_scan = 1;
    op->scan_status = NGX_ERROR;           /* until cursor "0" says otherwise */
    op->scan_start = ngx_current_msec;     /* S231-L2-SCANTIME: walk start    */

    /* AUD-SCAN1: everything that lives for exactly one SCAN page — the reply
     * buffer, the parsed keys array, the next SCAN command — comes out of a
     * per-page pool, rotated in read_scan. op->pool keeps only the op itself
     * and the connection, so the walk's footprint is O(1) in page count. */
    op->rpool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (op->rpool == NULL) {
        op->rpool = op->pool;
        ngx_destroy_pool(op->pool);
        return NGX_ERROR;
    }

    op->rcap = ngx_pagesize * 4;          /* grows on demand up to MAX_REPLY */
    op->rbuf = ngx_pnalloc(op->rpool, op->rcap);
    if (op->rbuf == NULL) {
        ngx_destroy_pool(op->rpool);
        op->rpool = op->pool;
        ngx_destroy_pool(op->pool);
        return NGX_ERROR;
    }

    op->send = ngx_http_cache_turbo_redis_scan_cmd(op->rpool, clcf, &cursor0);
    if (op->send == NULL) {
        ngx_destroy_pool(op->rpool);
        ngx_destroy_pool(op->pool);
        return NGX_ERROR;
    }

    if (ngx_http_cache_turbo_redis_launch(op, clcf,
            ngx_http_cache_turbo_redis_read_scan) != NGX_OK)
    {
        ngx_destroy_pool(op->rpool);
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
        /* S231: deliberately NOT clearing op->unconnected here. A refused
         * loopback connect can still accept a send() into the kernel's
         * socket buffer before the RST is processed -- measured: a dead
         * redis_dead peer logs "cache_turbo: redis connect" immediately
         * followed by "recv() failed (111: Connection refused)" with no
         * intervening write failure, so a write succeeding is NOT proof the
         * peer ever accepted the connection. Only a genuine reply byte
         * (first successful recv(), in _fill()/read_preamble()/the SET+lock
         * scratch reader) proves that. See op_fail() for where unconnected
         * actually gets resolved either way. */
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

        /* S231: a genuine reply byte proves the peer really accepted this
         * connection -- see op_fail()'s comment for why a write succeeding
         * is NOT proof (a refused loopback connect can still swallow a
         * send() before the RST surfaces). */
        if (op->unconnected) {
            op->unconnected = 0;
            if (op->clcf != NULL) {
                ngx_http_cache_turbo_redis_backoff_clear(&op->clcf->redis_addr);
            }
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

        if (p != last) {
            /* Extra buffered bytes are an unexpected partial/additional reply.
             * Closing is the only safe boundary; pooling would discard them. */
            ngx_http_cache_turbo_redis_op_done(op);
            return;
        }

        op->clean = 1;                     /* exact reply boundary: poolable */
        ngx_http_cache_turbo_redis_op_done(op);
        return;
    }
}


/*
 * AUD-SCAN1 oracle: count the allocation blocks a pool currently holds — its
 * chained data blocks plus its large (> pool max) allocations. nginx does not
 * record the size of a large block, so this counts blocks rather than bytes;
 * that is enough for the property under test, which is whether the SCAN walk's
 * footprint is CONSTANT in page count or grows with it. Pre-fix each page added
 * at least one large block (the 256-entry keys array) plus small blocks for the
 * rebuilt command, and nothing was ever released until the walk ended.
 *
 * Only ever read on the SCAN completion path and only reported under
 * TEST_FAULTS; it walks two short lists, so it is not on any hot path.
 */
static ngx_uint_t
ngx_http_cache_turbo_redis_pool_blocks(ngx_pool_t *pool)
{
    ngx_uint_t         n = 0;
    ngx_pool_t        *p;
    ngx_pool_large_t  *l;

    /* The chain walk below already tolerates a NULL pool; the large-list walk
     * dereferenced it unguarded, so the two disagreed about the contract and
     * clang --analyze reported core.NullDereference here. No caller passes NULL
     * today (both sites in redis_smembers_finish pass op->pool / op->rpool,
     * and every rpool assignment falls back to op->pool), so this is defensive,
     * not a bug fix -- it makes the function agree with its own first loop. */
    if (pool == NULL) {
        return 0;
    }

    for (p = pool; p; p = p->d.next) {
        n++;
    }
    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            n++;
        }
    }

    return n;
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
        nbuf = ngx_pnalloc(op->rpool, ncap);
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

    /* S231: see op_fail()'s comment -- a genuine reply byte is the actual
     * proof this connection reached a live peer. */
    if (op->unconnected) {
        op->unconnected = 0;
        if (op->clcf != NULL) {
            ngx_http_cache_turbo_redis_backoff_clear(&op->clcf->redis_addr);
        }
    }

    op->rlen += (size_t) n;
    return NGX_OK;
}


/*
 * Parse a RESP length field (the digits between the type byte and CRLF) into a
 * non-negative byte/element count.
 *
 * RESP encodes nil as exactly "-1" ($-1 bulk, *-1 array); ngx_atoi rejects any
 * leading '-' as NGX_ERROR, so it cannot represent that sentinel — a caller that
 * only tests `ngx_atoi(...) == NGX_ERROR` collapses "nil" into "malformed" and a
 * dead `< 0` branch below it can never fire. Split the three cases here:
 *   NGX_OK       - real length; *len >= 0
 *   NGX_DONE     - nil ("-1"); *len untouched
 *   NGX_ERROR    - malformed (non-"-1", non-numeric, or overflow)
 */
static ngx_int_t
ngx_http_cache_turbo_redis_resp_len(u_char *p, size_t n, ngx_int_t *len)
{
    ngx_int_t  v;

    *len = 0;                              /* always defined: keeps callers'
                                            * count/len provably >= 0 for the
                                            * static analyzer on every path */

    if (n == 2 && p[0] == '-' && p[1] == '1') {
        return NGX_DONE;                   /* nil sentinel */
    }

    v = ngx_atoi(p, n);
    if (v < 0) {                           /* NGX_ERROR (== -1): non-numeric,
                                            * empty, or overflow. The explicit
                                            * `< 0` (not `== NGX_ERROR`) also
                                            * makes *len >= 0 provable to the
                                            * static analyzer on the OK path. */
        return NGX_ERROR;
    }

    *len = v;
    return NGX_OK;
}


/*
 * Parse an accumulated GET reply in op->rbuf[0..op->rlen]. Returns:
 *   NGX_OK       - one exact bulk-string frame; blob/blob_len point into rbuf
 *   NGX_AGAIN    - need more bytes
 *   NGX_DECLINED - DEFINITIVE miss: a well-formed `$-1` nil. The key is absent.
 *   NGX_ERROR    - the reply was not a usable answer: a Redis error reply, an
 *                  unexpected type byte, an unparseable length, or an oversized
 *                  payload, delimiter, or trailing bytes. The request still
 *                  proceeds as a miss, but L2's answer is UNKNOWN.
 *
 * ⚠ The NGX_DECLINED / NGX_ERROR split is load-bearing, not cosmetic: only
 * NGX_DECLINED may arm the L13 negative memo. Collapsing them (as this function
 * did before) lets a malformed or error reply assert "this key is absent" -- see
 * ngx_http_cache_turbo_node_t.l2_neg_until.
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

    /* Only a bulk string carries a stored value. An error reply (`-ERR ...`) or
     * any other type byte is a protocol-level failure, not an answer about this
     * key: NGX_ERROR, so it cannot arm the memo. */
    if (*p != '$') {
        return NGX_ERROR;
    }

    crlf = ngx_strlchr(p + 1, end, CR);
    if (crlf == NULL || crlf + 1 >= end || crlf[1] != LF) {
        return NGX_AGAIN;                  /* length line not complete yet */
    }

    /* resp_len already separates the two cases this function must not conflate:
     * NGX_DONE = a well-formed `$-1` nil (the key genuinely does not exist),
     * NGX_ERROR = malformed/overflow. Map them straight through -- NGX_DONE is
     * THE definitive miss and the only parse outcome that may arm the L13 memo. */
    switch (ngx_http_cache_turbo_redis_resp_len(p + 1, crlf - (p + 1), &len)) {

    case NGX_DONE:
        if (crlf + 2 != end) {
            return NGX_ERROR;                  /* trailing bytes: not poolable */
        }
        return NGX_DECLINED;               /* $-1 nil: definitive miss */

    case NGX_OK:
        break;                             /* real length in `len` */

    default:
        return NGX_ERROR;                  /* malformed length line */
    }

    if (len > NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY) {
        return NGX_ERROR;                  /* refuse absurd payloads */
    }

    p = crlf + 2;                          /* start of payload */

    if (end - p < len + 2) {               /* payload + trailing CRLF */
        return NGX_AGAIN;
    }
    if (p[len] != CR || p[len + 1] != LF) {
        return NGX_ERROR;                  /* malformed payload delimiter */
    }
    if (end - p != len + 2) {
        return NGX_ERROR;                  /* trailing bytes: not poolable */
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
        /* L13: transport failure, NOT a definitive miss -- must not arm the memo */
        ngx_http_cache_turbo_redis_get_finish(op, NGX_ERROR, NULL, 0);
        return;
    }

    for ( ;; ) {
        rc = ngx_http_cache_turbo_redis_fill(op, rev);
        if (rc == NGX_AGAIN) {
            return;                        /* wait for more, or re-arm failed */
        }
        if (rc == NGX_ERROR) {
            /* cap/alloc/closed connection: L2's answer is UNKNOWN. Still resumes
             * the request as a miss (origin serves it), but L13 must not memo it. */
            ngx_http_cache_turbo_redis_get_finish(op, NGX_ERROR, NULL, 0);
            return;
        }

        rc = ngx_http_cache_turbo_redis_parse(op, &blob, &blob_len);
        if (rc == NGX_AGAIN) {
            continue;                      /* read more */
        }
        /* A hit or a nil means a complete, well-formed reply was consumed: the
         * connection is at a clean boundary and may be pooled (v15). NGX_ERROR
         * (malformed / error reply) leaves the stream at an UNKNOWN offset, so
         * the connection must NOT be pooled -- a later op would resync mid-reply. */
        if (rc == NGX_ERROR) {
            ngx_http_cache_turbo_redis_get_finish(op, NGX_ERROR, NULL, 0);
            return;
        }

        op->clean = 1;
        if (rc == NGX_OK) {
            ngx_http_cache_turbo_redis_get_finish(op, NGX_OK, blob, blob_len);
        } else {
            /* NGX_DECLINED: definitive $-1 miss -- may arm the L13 memo */
            ngx_http_cache_turbo_redis_get_finish(op, NGX_DECLINED, NULL, 0);
        }
        return;
    }
}


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
        rc = ngx_http_cache_turbo_redis_resp_len(p + 1, crlf - (p + 1), &v);
        if (rc == NGX_ERROR) {
            return NGX_DECLINED;
        }
        if (rc == NGX_DONE) {              /* $-1 nil: no payload, one CRLF */
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
        /* Same delimiter check as parse_bulk(): buffered is not the same as
         * well-formed, and framing off a bad length desynchronises the walk. */
        if (p[v] != CR || p[v + 1] != LF) {
            return NGX_DECLINED;
        }
        *next = p + v + 2;
        return NGX_OK;

    case '*':                              /* array */
        crlf = ngx_strlchr(p + 1, end, CR);
        if (crlf == NULL || crlf + 1 >= end || crlf[1] != LF) {
            return NGX_AGAIN;
        }
        rc = ngx_http_cache_turbo_redis_resp_len(p + 1, crlf - (p + 1), &v);
        if (rc == NGX_ERROR) {
            return NGX_DECLINED;
        }
        p = crlf + 2;
        if (rc == NGX_DONE) {              /* *-1 nil array: no elements */
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
 * Frame a top-level array reply (SMEMBERS / SCAN), same acceptance set and
 * same *next contract as ngx_http_cache_turbo_redis_frame(NULL depth 0), but
 * resumable across fill() calls via op->frame_off / frame_remain / frame_depth
 * so a dribbled large array is framed in ONE linear pass instead of being
 * re-walked from op->rbuf on every partial fill (S231-L2-FRAMEQUAD).
 *
 * Contract (part 1 of the required proof -- NOT stricter than frame()):
 *   - accepts exactly the byte sequences frame() accepts: same RESP grammar,
 *     same MAX_REPLY / MAX_MEMBERS / MAX_DEPTH ceilings, same '*'-only
 *     entrypoint (the GET reply path keeps using plain frame(), unchanged).
 *   - same return values: NGX_OK with *next one byte past the reply,
 *     NGX_AGAIN on a short buffer, NGX_DECLINED on malformed/too-deep/oversize.
 *   - same mutations: this function and frame() are both read-only over
 *     [rbuf, rbuf+rlen) -- neither touches the bytes. The only new mutation is
 *     to op->frame_off/frame_remain/frame_depth, which are pure resume state
 *     private to this op and read by no one else.
 *   - a resumed walk is byte-for-byte the SAME walk a fresh frame() call
 *     would perform on the same final buffer: every element this function
 *     confirms complete is one frame() would also confirm complete at the
 *     same offset, because the header/type-byte/length checks it runs when
 *     first entering an element are identical to frame()'s, just run once
 *     instead of once per fill() iteration.
 *
 * Iterative, not recursive, because a recursive call cannot resume mid-stack
 * without unwinding through frames that no longer exist across separate
 * event-loop re-entries into read_smembers/read_scan. frame_remain[d] holds
 * the element count still outstanding at nesting depth d (element index, not
 * byte offset); frame_off is the byte offset of the next unconfirmed element.
 * Nested arrays (SCAN's replies are flat; this exists only so a hostile/odd
 * server that nests one level deeper is still framed correctly, capped as
 * before by FRAME_MAX_DEPTH) push a new frame_remain[] entry.
 */
/*
 * Fresh-walk prologue for frame_scan(): runs exactly once per page, when
 * frame_depth == 0 && frame_off == 0 ("not currently inside an array").
 * Parses the top-level element exactly like the resume loop below would.
 * It must be an array ('*') for the resumable path -- SCAN/SMEMBERS replies
 * are always arrays; anything else is handed to plain frame() by the
 * caller-side convention (both callers only ever hit this on the '*' reply).
 *
 * Hands off purely through op->frame_* (and next/done on the *-1 short
 * circuit) -- no coupling to the resume loop's local state, so this is a
 * safe extraction per the MAINT-REDIS seam map.
 */
static ngx_int_t
ngx_http_cache_turbo_redis_frame_scan_prologue(
    ngx_http_cache_turbo_redis_op_t *op, u_char *end, u_char **next,
    ngx_int_t *done)
{
    u_char     *p, *crlf;
    ngx_int_t   v, rc;

    p = op->rbuf;
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
    rc = ngx_http_cache_turbo_redis_resp_len(p + 1, crlf - (p + 1), &v);
    if (rc == NGX_ERROR) {
        return NGX_DECLINED;
    }
    p = crlf + 2;
    if (rc == NGX_DONE) {                  /* *-1 nil array: no elements */
        *next = p;
        *done = 1;
        return NGX_OK;
    }
    if (v > NGX_HTTP_CACHE_TURBO_REDIS_MAX_MEMBERS) {
        return NGX_DECLINED;
    }
    op->frame_remain[0] = (ngx_uint_t) v;
    op->frame_depth = 1;
    op->frame_off = (size_t) (p - op->rbuf);
    *done = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_cache_turbo_redis_frame_scan(ngx_http_cache_turbo_redis_op_t *op,
    u_char **next)
{
    u_char     *p, *end, *crlf;
    ngx_int_t   v, rc;

    end = op->rbuf + op->rlen;

    /* Fresh walk (frame_depth == 0 means "not currently inside an array"):
     * see ngx_http_cache_turbo_redis_frame_scan_prologue() -- extracted
     * because it runs once per page and hands off purely through op->frame_*. */
    if (op->frame_depth == 0 && op->frame_off == 0) {
        ngx_int_t  done;

        rc = ngx_http_cache_turbo_redis_frame_scan_prologue(op, end, next,
                                                              &done);
        if (rc != NGX_OK || done) {
            return rc;
        }
    }

    p = op->rbuf + op->frame_off;

    /* Drain elements at the current depth, descending into nested arrays and
     * popping back up when one completes. Every element this loop confirms
     * advances frame_off permanently -- a later call re-enters at exactly
     * this p, never earlier, so already-confirmed elements are never
     * re-parsed. */
    while (op->frame_depth > 0) {
        ngx_uint_t  d = op->frame_depth - 1;

        if (op->frame_remain[d] == 0) {
            op->frame_depth--;
            op->frame_off = (size_t) (p - op->rbuf);
            continue;
        }

        if (p >= end) {
            op->frame_off = (size_t) (p - op->rbuf);
            return NGX_AGAIN;
        }

        switch (*p) {

        case '+':
        case '-':
        case ':':
            crlf = ngx_strlchr(p + 1, end, CR);
            if (crlf == NULL || crlf + 1 >= end || crlf[1] != LF) {
                op->frame_off = (size_t) (p - op->rbuf);
                return NGX_AGAIN;
            }
            p = crlf + 2;
            op->frame_remain[d]--;
            break;

        case '$':
            crlf = ngx_strlchr(p + 1, end, CR);
            if (crlf == NULL || crlf + 1 >= end || crlf[1] != LF) {
                op->frame_off = (size_t) (p - op->rbuf);
                return NGX_AGAIN;
            }
            rc = ngx_http_cache_turbo_redis_resp_len(p + 1, crlf - (p + 1), &v);
            if (rc == NGX_ERROR) {
                return NGX_DECLINED;
            }
            if (rc == NGX_DONE) {          /* $-1 nil element */
                p = crlf + 2;
                op->frame_remain[d]--;
                break;
            }
            if (v > NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY) {
                return NGX_DECLINED;
            }
            if (end - (crlf + 2) < v + 2) {
                op->frame_off = (size_t) (p - op->rbuf);
                return NGX_AGAIN;
            }
            /* Same delimiter check as parse_bulk()/frame(): the length test
             * above only proves the bytes are buffered, not that they are the
             * delimiter. Resuming off a bad length desynchronises the walk. */
            if ((crlf + 2)[v] != CR || (crlf + 2)[v + 1] != LF) {
                return NGX_DECLINED;
            }
            p = crlf + 2 + v + 2;
            op->frame_remain[d]--;
            break;

        case '*':
            if (op->frame_depth >= NGX_HTTP_CACHE_TURBO_REDIS_FRAME_MAX_DEPTH) {
                return NGX_DECLINED;
            }
            crlf = ngx_strlchr(p + 1, end, CR);
            if (crlf == NULL || crlf + 1 >= end || crlf[1] != LF) {
                op->frame_off = (size_t) (p - op->rbuf);
                return NGX_AGAIN;
            }
            rc = ngx_http_cache_turbo_redis_resp_len(p + 1, crlf - (p + 1), &v);
            if (rc == NGX_ERROR) {
                return NGX_DECLINED;
            }
            p = crlf + 2;
            op->frame_remain[d]--;         /* the nested array itself counts
                                             * as ONE element of its parent */
            if (rc == NGX_DONE || v == 0) { /* *-1 or *0: no children to push */
                break;
            }
            if (v > NGX_HTTP_CACHE_TURBO_REDIS_MAX_MEMBERS) {
                return NGX_DECLINED;
            }
            op->frame_remain[op->frame_depth] = (ngx_uint_t) v;
            op->frame_depth++;
            break;

        default:
            return NGX_DECLINED;
        }
    }

    op->frame_off = (size_t) (p - op->rbuf);
    *next = p;
    return NGX_OK;
}


/*
 * Parse one bulk string ($<len>\r\n<bytes>\r\n) at *p, bounded by end, into
 * *out. *p is advanced past the whole element on success. allow_nil selects
 * whether a $-1 nil element is accepted (out set to {NULL,0}) or treated as
 * malformed -- the SCAN cursor must be a real bulk string, but array/scan-key
 * elements may legitimately be nil.
 *
 * Shared by parse_scan()'s cursor read and its key loop, which were
 * near-identical clones; a bound/overflow fix now lands in one place instead
 * of two. Also folds AUD-REDIS-PARSE-SCAN-COUNT: callers that need
 * resp_len()'s sign/nil split (rather than a plain ngx_atoi) get it
 * uniformly.
 *
 * parse_array()'s per-element loop is the third caller (MAINT-REDIS), folded
 * in after the decomposition landed. Its *-1 nil-ARRAY and count == 0 cases
 * are a different shape and stay in parse_array above the loop.
 */
static ngx_int_t
ngx_http_cache_turbo_redis_parse_bulk(u_char **p, u_char *end,
    ngx_int_t allow_nil, ngx_str_t *out)
{
    u_char     *crlf;
    ngx_int_t   len, rc;

    if (*p >= end) {
        return NGX_AGAIN;
    }
    if (**p != '$') {
        return NGX_DECLINED;
    }

    crlf = ngx_strlchr(*p + 1, end, CR);
    if (crlf == NULL || crlf + 1 >= end || crlf[1] != LF) {
        return NGX_AGAIN;
    }

    rc = ngx_http_cache_turbo_redis_resp_len(*p + 1, crlf - (*p + 1), &len);
    if (rc == NGX_ERROR) {
        return NGX_DECLINED;
    }

    if (rc == NGX_DONE) {                  /* $-1 nil element */
        if (!allow_nil) {
            return NGX_DECLINED;
        }
        out->data = NULL;
        out->len = 0;
        *p = crlf + 2;
        return NGX_OK;
    }

    if (len > NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY) {
        return NGX_DECLINED;               /* bound before len + 2 (no overflow) */
    }

    *p = crlf + 2;
    if (end - *p < len + 2) {              /* payload + trailing CRLF */
        return NGX_AGAIN;
    }

    /* The two bytes after the payload must BE the delimiter, not merely exist:
     * the length check above only proves they are buffered. Without this,
     * "$1\r\naXX" parses as a valid 1-byte bulk string and the cursor lands
     * mid-element, desynchronising every following element in the reply. */
    if ((*p)[len] != CR || (*p)[len + 1] != LF) {
        return NGX_DECLINED;
    }

    out->data = *p;
    out->len = (size_t) len;
    *p += len + 2;

    return NGX_OK;
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
    ngx_int_t   count, rc;
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

    rc = ngx_http_cache_turbo_redis_resp_len(p + 1, crlf - (p + 1), &count);
    if (rc == NGX_ERROR) {
        return NGX_DECLINED;
    }
    if (rc == NGX_DONE) {                  /* *-1 nil array */
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

    /* A declared element count must be backed by bytes actually on the wire.
     * The shortest possible element is an empty bulk string, "$0\r\n" = 4
     * bytes, so a count needing more than (end - p) / 4 elements cannot be
     * honest. Without this, a hostile or MITM'd L2 turns a 12-byte reply
     * ("*1048576\r\n$0") into a 16MB allocation -- ~1.4M:1 amplification, once
     * per SCAN page. Checked BEFORE the alloc, because the per-element parse
     * loop below only rejects the lie after the memory is already committed. */
    if ((size_t) count > (size_t) (end - (crlf + 2)) / 4) {
        return NGX_DECLINED;
    }

    /* ngx_palloc (not ngx_pnalloc): the ngx_str_t array needs pointer
     * alignment; an unaligned base is UB (trapped by UBSan). */
    list = ngx_palloc(op->pool, count * sizeof(ngx_str_t));
    if (list == NULL) {
        return NGX_DECLINED;
    }

    p = crlf + 2;

    for (i = 0; i < (ngx_uint_t) count; i++) {
        /* MAINT-REDIS: the per-element walk was a byte-identical third copy of
         * parse_bulk(allow_nil=1) -- a nil element yields an empty member here,
         * exactly as it does for a scan key. The *-1 nil-array and count == 0
         * early returns above the loop are NOT part of that shape and stay. */
        rc = ngx_http_cache_turbo_redis_parse_bulk(&p, end, 1, &list[i]);
        if (rc != NGX_OK) {
            return rc;                     /* NGX_AGAIN or NGX_DECLINED */
        }
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
         * the members array. S231-L2-FRAMEQUAD: frame_scan() also stops the
         * FRAMING itself re-walking already-confirmed elements on every
         * partial fill (STAB-3 only fixed the alloc+parse re-walk) -- it
         * resumes from op->frame_off/frame_remain instead of op->rbuf. */
        rc = ngx_http_cache_turbo_redis_frame_scan(op, &next);
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
    ngx_int_t   count, rc;
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
    rc = ngx_http_cache_turbo_redis_resp_len(p + 1, crlf - (p + 1), &count);
    if (rc != NGX_OK || count != 2) {
        return NGX_DECLINED;               /* SCAN always replies a real 2-tuple */
    }
    p = crlf + 2;

    /* element 0: the next cursor, a bulk string (nil is malformed here) */
    rc = ngx_http_cache_turbo_redis_parse_bulk(&p, end, 0, cursor);
    if (rc != NGX_OK) {
        return rc;
    }

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
    rc = ngx_http_cache_turbo_redis_resp_len(p + 1, crlf - (p + 1), &count);
    if (rc == NGX_ERROR) {
        return NGX_DECLINED;
    }
    if (rc == NGX_DONE) {                  /* *-1 nil array: treat as no keys */
        count = 0;
    }
    if (count > NGX_HTTP_CACHE_TURBO_REDIS_MAX_MEMBERS) {
        return NGX_DECLINED;
    }
    p = crlf + 2;

    /* A declared element count must be backed by bytes actually on the wire.
     * The shortest possible element is an empty bulk string, "$0\r\n" = 4
     * bytes, so a count needing more than (end - p) / 4 elements cannot be
     * honest. Without this, a hostile or MITM'd L2 turns a 12-byte reply
     * ("*1048576\r\n$0") into a 16MB allocation -- ~1.4M:1 amplification, once
     * per SCAN page. Checked BEFORE the alloc, because the per-element parse
     * loop below only rejects the lie after the memory is already committed. */
    if ((size_t) count > (size_t) (end - p) / 4) {
        return NGX_DECLINED;
    }

    list = NULL;
    if (count > 0) {
        /* ngx_palloc (not ngx_pnalloc): ngx_str_t needs pointer alignment.
         * op->rpool, not op->pool: on the SCAN walk this array belongs to the
         * page and dies with it (AUD-SCAN1). */
        list = ngx_palloc(op->rpool, count * sizeof(ngx_str_t));
        if (list == NULL) {
            return NGX_DECLINED;
        }
    }

    for (i = 0; i < (ngx_uint_t) count; i++) {
        rc = ngx_http_cache_turbo_redis_parse_bulk(&p, end, 1, &list[i]);
        if (rc != NGX_OK) {
            return rc;
        }
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
 *
 * AUD-SCAN1: the stack was bounded, the POOL was not. Each page is now owned by
 * its own pool (op->rpool), rotated here: the next SCAN command and the next
 * reply buffer are allocated from a FRESH pool and the previous one is then
 * destroyed, so the walk's live allocation is O(1) in page count instead of
 * accumulating a keys array, a rebuilt command and a never-shrinking reply
 * buffer per page for the entire keyspace. Two orderings make that safe, both
 * already relied on before this change: del_many copies the page's keys before
 * we move on, and scan_cmd/encode copies the cursor bytes (which point into the
 * OLD reply buffer) into the new command — so the new command is built first
 * and the old pool destroyed only afterwards.
 *
 * The walk is also bounded by SCAN_MAX_PAGES. Reaching it abandons the walk and
 * reports the purge INCOMPLETE; it must never look like a completed purge.
 */
static void
ngx_http_cache_turbo_redis_read_scan(ngx_event_t *rev)
{
    ngx_str_t                         cursor, *keys;
    ngx_uint_t                        nkeys, max_pages;
    ngx_int_t                         rc;
    ngx_buf_t                        *send;
    u_char                           *rbuf;
    ngx_pool_t                       *np, *old;
    ngx_connection_t                 *c;
    ngx_http_cache_turbo_redis_op_t  *op;

    c = rev->data;
    op = c->data;

    max_pages = NGX_HTTP_CACHE_TURBO_REDIS_SCAN_MAX_PAGES;
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    if (op->clcf->test_scan_max_pages > 0
        && (ngx_uint_t) op->clcf->test_scan_max_pages < max_pages)
    {
        max_pages = (ngx_uint_t) op->clcf->test_scan_max_pages;
    }
#endif

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
         * partial fill. S231-L2-FRAMEQUAD: frame_scan() resumes framing from
         * op->frame_off/frame_remain instead of re-walking op->rbuf from
         * byte 0 on every partial fill within one page (per-page reset in
         * the cursor-rebuild block below keeps this correct across pages). */
        rc = ngx_http_cache_turbo_redis_frame_scan(op, &next);
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

        op->scan_pages++;

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
        /* S231-L2-SCANTIME: hold this page boundary so the deadline check
         * below is reachable regardless of runner speed. Placed BEFORE the
         * cursor==0 completion return on purpose: that return is what makes
         * the deadline unreachable on a walk that finishes, so the hold has to
         * precede it to bound a walk of any size. ngx_current_msec is the
         * CACHED clock, so this also forces the event loop's time to advance
         * across the walk. 0/unset = no hold. */
        if (op->clcf->test_scan_page_hold_ms > 0) {
            ngx_msleep((ngx_msec_t) op->clcf->test_scan_page_hold_ms);
            ngx_time_update();
        }
#endif

        if (cursor.len == 1 && cursor.data[0] == '0') {
            /* whole keyspace walked: emit the response via the callback */
            op->scan_status = NGX_OK;
            ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
            return;
        }

        if (op->scan_pages >= max_pages) {
            /* Non-termination guard: a server that never hands back cursor "0"
             * would otherwise walk forever (the per-page read timeout does not
             * bound the walk — each page's write re-arms it). Abandon, and let
             * the callback report the purge INCOMPLETE. Truncating silently
             * would swap a memory bug for a correctness bug. */
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "cache_turbo: L2 all-purge abandoned after %ui SCAN "
                          "pages without the cursor returning to 0; purge is "
                          "INCOMPLETE", op->scan_pages);
            op->scan_status = NGX_ABORT;
            ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
            return;
        }

        /* S231-L2-SCANTIME: wall-clock ceiling on the WHOLE walk, checked here
         * alongside the page cap. The page cap is a memory guard; this is the
         * time guard — each page's read re-arms redis_timeout, so a server
         * that always returns a non-zero cursor just under that timeout
         * otherwise parks the request for up to SCAN_MAX_PAGES pages (hours).
         * ngx_current_msec wraps, so compare with the signed-difference idiom,
         * never a plain '>'. 0 = disabled (page-cap only, legacy behaviour). */
        if (op->clcf->redis_scan_deadline > 0
            && (ngx_msec_int_t) (ngx_current_msec
                                  - (op->scan_start
                                     + op->clcf->redis_scan_deadline)) > 0)
        {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "cache_turbo: L2 all-purge abandoned after %ui SCAN "
                          "pages, wall-clock deadline %Mms exceeded; purge is "
                          "INCOMPLETE", op->scan_pages,
                          op->clcf->redis_scan_deadline);
            op->scan_status = NGX_ABORT;
            op->scan_deadline_hit = 1;
            ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
            return;
        }

        /* Issue the next SCAN with the returned cursor, out of a FRESH page
         * pool. encode copies the cursor bytes (which point into the old rbuf)
         * into the new send buffer, so the old pool is safe to drop right
         * after — and must be dropped, or the walk grows without bound. */
        np = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
        if (np == NULL) {
            ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
            return;
        }

        send = ngx_http_cache_turbo_redis_scan_cmd(np, op->clcf, &cursor);
        rbuf = send ? ngx_pnalloc(np, ngx_pagesize * 4) : NULL;
        if (rbuf == NULL) {
            ngx_destroy_pool(np);
            ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
            return;
        }

        old = op->rpool;
        op->rpool = np;
        op->send = send;
        op->command = send;                /* old buffer dies with `old` */
        op->rbuf = rbuf;
        op->rcap = ngx_pagesize * 4;       /* fresh page: drop any grown cap */
        op->rlen = 0;
        /* S231-L2-FRAMEQUAD part 4: frame_off/frame_remain/frame_depth are
         * resume state indexed into the OLD op->rbuf being replaced right
         * here. Carrying them forward would resume the next page's frame
         * walk at a byte offset and element-remaining count that belong to a
         * buffer this SCAN page never even wrote -- reset before the new
         * page's first fill() so read_scan's next frame_scan() call starts a
         * fresh walk exactly like a brand-new op would. */
        op->frame_off = 0;
        op->frame_depth = 0;
        ngx_destroy_pool(old);

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
 *
 * S231-VARY-LEAK: this function finalizes the parked request exactly ONCE, and
 * one finalize_request only ever drops ONE reference. Whether that single drop
 * balances the park's r->main->count++ depends on the PHASE the parking caller
 * returns NGX_DONE into, which differs between callers -- so the park's release
 * is owned by each CALL SITE, not by this function. Callers reached through
 * core->handler (admin_handler's ?tag= and all-purge) are balanced already,
 * because ngx_http_core_content_phase always runs ngx_http_finalize_request and
 * NGX_DONE routes into ngx_http_finalize_connection, which decrements. The
 * PRECONTENT caller (purge_request) gets no such drop -- ngx_http_core_generic
 * _phase answers NGX_DONE with a bare `return NGX_OK` -- so IT does its own
 * r->main->count-- right after the park returns. Do not "simplify" that by
 * moving the decrement in here: it would over-drop the content-phase callers
 * and trip "http request count is zero".
 */
static void
ngx_http_cache_turbo_redis_smembers_finish(
    ngx_http_cache_turbo_redis_op_t *op, ngx_str_t *members,
    ngx_uint_t nmembers)
{
    ngx_http_request_t                     *r = op->request;
    ngx_http_cache_turbo_redis_members_pt   cb = op->members_cb;
    void                                   *data = op->members_data;
    ngx_http_cache_turbo_redis_walk_t       walk;
    ngx_int_t                               rc;

    /* AUD-SCAN1: on the SCAN path, tell the callback HOW the walk ended.
     * op->scan_status is NGX_OK only where the server returned cursor "0";
     * every other terminal path (timeout, malformed reply, alloc failure, page
     * cap) leaves it non-OK and the purge is reported INCOMPLETE. */
    walk.status = op->scan_status;
    walk.pages = op->scan_pages;
    walk.deadline = op->scan_deadline_hit;
    walk.blocks = ngx_http_cache_turbo_redis_pool_blocks(op->pool)
                  + (op->rpool != op->pool
                     ? ngx_http_cache_turbo_redis_pool_blocks(op->rpool) : 0);

    /* Callback consumes members (pointing into op->rbuf) synchronously. */
    rc = cb(r, data, members, nmembers, op->is_scan ? &walk : NULL);

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

    /* AUD-SCAN1: the SCAN walk's current page pool is independent of op->pool
     * (it is rotated per page), so it has to be released explicitly. Every
     * other op leaves rpool == pool. */
    if (op->rpool != pool) {
        ngx_destroy_pool(op->rpool);
        op->rpool = pool;
    }

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

    /* S231: read failures on a GET (timeout / fill error / malformed reply) are
     * reported straight here rather than through op_fail(), so the same
     * "still unconnected" classification has to be repeated at this other
     * terminal point. op->unconnected only survives to here when NO reply
     * byte was ever read on this connection (see the field comment + the
     * clear sites in _fill()/read_preamble()), so a malformed/error REPLY
     * (which requires bytes to have arrived) can never hit this branch --
     * only a genuine connect-phase failure can. */
    if (result == NGX_ERROR && op->unconnected && op->clcf != NULL) {
        ngx_http_cache_turbo_redis_backoff_arm(&op->clcf->redis_addr,
            op->clcf->redis_connect_backoff);
    }

    if (result == NGX_OK && blob_len > 0) {
        copy = ngx_pnalloc(r->pool, blob_len);
        if (copy == NULL) {
            /* L13: L2 HAD the key -- we merely failed to copy it locally. Reporting
             * a miss here would arm a memo asserting the key is ABSENT, which is
             * the exact opposite of what L2 just told us. NGX_ERROR: unknown. */
            result = NGX_ERROR;
        } else {
            ngx_memcpy(copy, blob, blob_len);
            /* P4-3: these bytes came from L2 -- a writer this worker does not
             * control (compromised Redis, another tenant, a MITM: AUD-TLS1).
             * Strip BLOBF_HDRS_VETTED on our private copy BEFORE anything
             * reads it, so restore_response_headers() runs the full AUD-HDR1
             * gate over them exactly as it did before P4-3. This assignment
             * and its memcached.c twin are the ONLY producers of ctx->l2_blob,
             * so clearing here covers every downstream L2 consumer (the L1
             * promotion, the breaker/SIE snapshots, the vary-marker consume
             * and serve() itself) by construction. */
            ngx_http_cache_turbo_blob_clear_vetted(copy, blob_len);
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
    ngx_int_t                         rc;
    u_char                           *next;
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

    /* STAB-1: frame the reply before declaring the stream poolable. A single
     * recv() is NOT a boundary — a TCP-split "+OK\r\n" can arrive as "+O" then
     * "K\r\n", and setting clean=1 on the first chunk pools a connection with
     * bytes still on the wire, desyncing the next reuse (it reads the leftover
     * as its own reply type byte). read_drain already frames for exactly this
     * reason; the lock reader was not updated with it. ka_save's boundary peek
     * only catches the tail once it has ALREADY arrived, so it does not close
     * this. The +/$/else verdict is unchanged and still reads the first byte,
     * which framing guarantees is present. */
    for ( ;; ) {
        if (op->recv_len >= sizeof(op->recv)) {
            /* A SET NX PX reply is "+OK\r\n", "$-1\r\n" or a short -ERR; it
             * never fills the scratch buffer. If one somehow does, fail the
             * lock rather than grow the buffer or pool an unframed stream. */
            ngx_http_cache_turbo_redis_lock_finish(op, NGX_ERROR);
            return;
        }

        n = c->recv(c, op->recv + op->recv_len,
                    sizeof(op->recv) - op->recv_len);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_http_cache_turbo_redis_lock_finish(op, NGX_ERROR);
            }
            return;
        }
        if (n == NGX_ERROR || n == 0) {
            ngx_http_cache_turbo_redis_lock_finish(op, NGX_ERROR);
            return;
        }

        /* S231: see op_fail()'s comment -- a genuine reply byte is proof of
         * a live peer. */
        if (op->unconnected) {
            op->unconnected = 0;
            if (op->clcf != NULL) {
                ngx_http_cache_turbo_redis_backoff_clear(&op->clcf->redis_addr);
            }
        }

        op->recv_len += (size_t) n;

        rc = ngx_http_cache_turbo_redis_frame(op->recv,
                                              op->recv + op->recv_len,
                                              0, &next);
        if (rc == NGX_AGAIN) {
            continue;                      /* partial reply: read more bytes */
        }
        if (rc == NGX_DECLINED || next != op->recv + op->recv_len) {
            /* Malformed, or a complete reply with trailing bytes behind it:
             * either way the offset is unknown -- do not pool. */
            ngx_http_cache_turbo_redis_lock_finish(op, NGX_ERROR);
            return;
        }

        op->clean = 1;                     /* reply framed: connection poolable */
        ngx_http_cache_turbo_redis_lock_finish(op,
            op->recv[0] == '+' ? NGX_OK :
            op->recv[0] == '$' ? NGX_DECLINED : /* nil: a peer holds the lock */
            NGX_ERROR);                         /* -ERR / garbage: unusable */
        return;
    }
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

    /* S231: same "still unconnected" arm as get_finish() -- the lock reader
     * calls this directly instead of through op_fail(). */
    if (result == NGX_ERROR && op->unconnected && op->clcf != NULL) {
        ngx_http_cache_turbo_redis_backoff_arm(&op->clcf->redis_addr,
            op->clcf->redis_connect_backoff);
    }

    ctx->lock_result = result;
    ctx->lock_done = 1;

    ngx_http_cache_turbo_redis_op_done(op);

    ngx_http_core_run_phases(r);
    ngx_http_run_posted_requests(r->connection);
    ngx_http_finalize_request(r, NGX_DONE);
}


/* Terminal failure on the shared write path: dispatch by op kind. members_cb is
 * set for both SMEMBERS and SCAN (both finish through smembers_finish); is_lock
 * distinguishes a lock from a GET (both pin op->request + op->ctx).
 *
 * S231: single choke point for the connect-failure classification. Every
 * write/read/protocol failure on this op funnels through here (write timeout,
 * send() error, read timeout, recv() error, a malformed/error reply), and
 * op->unconnected is true iff no reply byte has EVER been read on this
 * connection since a fresh (non-reused) connect() -- see the field comment.
 * That is exactly "this op never got a real answer from the peer", which for
 * a freshly opened connection means the peer was never actually reachable:
 * arm the backoff window. A reused (keepalive) connection is never
 * "unconnected" (op_create zeroes it, only _connect's fresh-connect branch
 * sets it), so its failures never arm backoff, matching "connect failure
 * only, not protocol/reply errors" precisely -- a reused connection failing
 * mid-protocol is definitionally not a connect failure. */
static void
ngx_http_cache_turbo_redis_op_fail(ngx_http_cache_turbo_redis_op_t *op)
{
    if (op->unconnected && op->clcf != NULL) {
        ngx_http_cache_turbo_redis_backoff_arm(&op->clcf->redis_addr,
            op->clcf->redis_connect_backoff);
    }

    if (op->members_cb) {
        ngx_http_cache_turbo_redis_smembers_finish(op, NULL, 0);
    } else if (op->is_lock) {
        /* Write-path failure (connect/send/protocol error) is a transport
         * failure, not a peer holding the lock: NGX_ERROR so the caller degrades
         * to per-box single-flight rather than suppressing the refresh. */
        ngx_http_cache_turbo_redis_lock_finish(op, NGX_ERROR);
    } else if (op->request) {
        /* Connect/send/protocol failure on the GET path: same reasoning as the
         * lock path above -- a transport failure is not an answer about the key,
         * so NGX_ERROR keeps it from arming the L13 negative memo. */
        ngx_http_cache_turbo_redis_get_finish(op, NGX_ERROR, NULL, 0);
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
    ngx_http_cache_turbo_redis_tag_add_many,
    ngx_http_cache_turbo_redis_smembers,
    ngx_http_cache_turbo_redis_scan_del,
    ngx_http_cache_turbo_redis_lock,
    NULL,   /* unlock — PX expiry only */
};

#pragma GCC visibility pop
