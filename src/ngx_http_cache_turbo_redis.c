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


/* Absolute fallback ceiling for incomplete configuration state. Production
 * config rejects max_size=0 and values above this serialized-object limit;
 * iteration replies have their own fixed page ceiling. */
#ifndef NGX_HTTP_CACHE_TURBO_REDIS_MAX_VALUE
#define NGX_HTTP_CACHE_TURBO_REDIS_MAX_VALUE  (64 * 1024 * 1024)
#endif
#define NGX_HTTP_CACHE_TURBO_REDIS_GET_FRAMING_MAX  (NGX_INT_T_LEN + 5)
#define NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY  \
    (NGX_HTTP_CACHE_TURBO_REDIS_MAX_VALUE \
     + NGX_HTTP_CACHE_TURBO_REDIS_GET_FRAMING_MAX)

/* SCAN and tag enumeration are iteration operations, not object transfers.
 * Bound their replies independently of the GET limit. */
#define NGX_HTTP_CACHE_TURBO_REDIS_MAX_ITER_REPLY  (128 * 1024)

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
     * until the first genuine reply byte proves the peer, or a terminal
     * no-reply path consumes the classification. A successful send is not
     * proof: an asynchronous ECONNREFUSED/RST can surface only on the later
     * read. The consume-once failure helper arms backoff at most once even
     * when shared write failure dispatch nests an op-specific finish. */
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

    /* TODO-UNLINK-REPLY-WINDOW: optional REPLY completion for a drained op.
     * Fire-and-forget ops leave this NULL and keep the historic behaviour (the
     * reply is framed only to decide poolability, and its content is ignored).
     * When set, read_drain invokes it EXACTLY ONCE from every terminal path
     * with NGX_OK only when every expected reply framed cleanly and none was a
     * RESP error; a timeout, a short/oversized/malformed reply, a peer close
     * mid-flight and a `-ERR` reply all deliver NGX_ERROR. That distinction is
     * what lets the paginated tag purge gate its per-page SREM on the UNLINK
     * having actually SUCCEEDED at the server, rather than merely having been
     * written to a socket. */
    void                       (*drain_cb)(void *data, ngx_int_t rc);
    void                        *drain_data;
    unsigned                     drain_done:1;   /* drain_cb already fired */
    unsigned                     drain_failed:1; /* a framed reply was -ERR */

    /* COR5-PURGE-VARIDX-RACE: this op incremented the zone's varidx_inflight
     * counter before launch and owes it a decrement in op_done. Only the
     * auto-Vary variant-index tag_add sets it; every other op leaves it 0 so
     * op_done's decrement is skipped. */
    unsigned                     counts_inflight:1;

    u_char                      *rbuf;     /* GET/SMEMBERS: growable reply buf */
    size_t                       rcap;
    size_t                       rlen;
    size_t                       reply_max;/* op-specific wire-reply ceiling */

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
     * from the SSCAN tag walk, which shares walk_finish; scan_status is the
     * outcome handed to the completion callback (NGX_OK only when the server
     * returned cursor "0"), and starts as NGX_ERROR so every path that reaches
     * finish WITHOUT setting it reports INCOMPLETE rather than success. */
    unsigned                     is_scan:1;
    ngx_int_t                    scan_status;
    ngx_uint_t                   scan_pages;
    ngx_msec_t                   scan_start; /* S231-L2-SCANTIME: walk start
                                              * (ngx_current_msec), set once when
                                              * the SCAN op is launched          */
    /* TODO-REDIS-PAGINATION: the SSCAN walk's set key ("<prefix>tag:<name>"),
     * rebuilt into every page's command. Allocated from op->pool, NOT the
     * per-page op->rpool, because it must outlive every page. Empty for the
     * SCAN-del walk, which needs no key argument. */
    ngx_str_t                    sscan_key;

    /* TODO-UNLINK-REPLY-WINDOW: SSCAN walk suspension. When the per-page
     * callback returns NGX_AGAIN it has started an asynchronous sub-operation
     * (the page's UNLINK) and owns the walk until it calls sscan_resume(). The
     * cursor for the NEXT page normally points into op->rbuf and is consumed
     * immediately after the callback returns; across a suspension it must
     * instead survive into the resume, so it is COPIED into op->pool here.
     * op->pool is the walk's own pool and is not rotated per page, so the copy
     * outlives the suspension by construction. `suspended` exists so a stray or
     * duplicate resume is rejected rather than driving the walk twice. */
    unsigned                     suspended:1;
    /* Set when the walk decided to abandon while a sub-operation was still in
     * flight holding `op`. The walk cannot be torn down at that moment (the
     * pending completion would read freed memory), so the decision is deferred
     * to sscan_resume, which is the first point at which nothing references the
     * op any more. */
    unsigned                     resume_doomed:1;

    /* CT-SSCAN-TERMINATE-LEAK: the walk parks its request with
     * r->main->count++, but a TERMINATE (worker shutdown, client abort) does
     * NOT honour that refcount -- ngx_http_terminate_handler forces
     * r->count = 1 and frees the request regardless. Nothing on the request
     * side used to reach this op at all, so a terminate either left the op
     * pool, the Redis connection, its fd and this zone's varidx_inflight
     * account stranded for the worker's lifetime (while op->request dangled at
     * freed memory), or -- before the suspension disarm existed -- let the read
     * timeout drive walk_finish into cb()/ngx_http_finalize_request() on the
     * already-freed request.
     *
     * req_cln is the r->pool cleanup that closes both. It clears op->request,
     * sets `detached`, and drives a request-free teardown. op_done cancels it
     * (handler = NULL) on every normal completion, because the cleanup outlives
     * the op otherwise and would run against freed memory.
     *
     * `detached` is the flag every terminal path consults: a detached walk must
     * never call members_cb and never call ngx_http_finalize_request -- there is
     * no request left -- but must still reach op_done EXACTLY ONCE so the pool,
     * the connection/fd and varidx_inflight are all released. */
    unsigned                     detached:1;
    ngx_pool_cleanup_t          *req_cln;

    ngx_str_t                    resume_cursor;
    u_char                       resume_cursor_buf[64];

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
static void ngx_http_cache_turbo_redis_read_sscan(ngx_event_t *rev);
static void ngx_http_cache_turbo_redis_sscan_advance(
    ngx_http_cache_turbo_redis_op_t *op, ngx_str_t cursor);
static void ngx_http_cache_turbo_redis_sscan_resume(void *opaque, ngx_int_t rc);
static void ngx_http_cache_turbo_redis_walk_detach(void *data);
static ngx_int_t ngx_http_cache_turbo_redis_walk_disarm_conn(
    ngx_connection_t *c);
static void ngx_http_cache_turbo_redis_read_lock(ngx_event_t *rev);
static void ngx_http_cache_turbo_redis_read_scan(ngx_event_t *rev);
static void ngx_http_cache_turbo_redis_lock_finish(
    ngx_http_cache_turbo_redis_op_t *op, ngx_int_t result);
static void ngx_http_cache_turbo_redis_op_done(
    ngx_http_cache_turbo_redis_op_t *op);
static void ngx_http_cache_turbo_redis_get_finish(
    ngx_http_cache_turbo_redis_op_t *op, ngx_int_t result,
    u_char *blob, size_t blob_len);
static void ngx_http_cache_turbo_redis_walk_finish(
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


static size_t
ngx_http_cache_turbo_redis_encode_len(ngx_str_t *argv, ngx_uint_t argc)
{
    size_t      len;
    ngx_uint_t  i;

    len = 1 + NGX_INT_T_LEN + 2;
    for (i = 0; i < argc; i++) {
        len += 1 + NGX_SIZE_T_LEN + 2 + argv[i].len + 2;
    }

    return len;
}


static u_char *
ngx_http_cache_turbo_redis_encode_into(u_char *p, ngx_str_t *argv,
    ngx_uint_t argc)
{
    ngx_uint_t  i;

    p = ngx_sprintf(p, "*%ui\r\n", argc);
    for (i = 0; i < argc; i++) {
        p = ngx_sprintf(p, "$%uz\r\n", argv[i].len);
        p = ngx_cpymem(p, argv[i].data, argv[i].len);
        *p++ = CR; *p++ = LF;
    }

    return p;
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


/* Consume a fresh connection's terminal no-reply classification exactly once.
 * Shared write/TLS failures dispatch through op_fail() into an op-specific
 * finish helper, while direct readers call those finishes themselves. Clearing
 * here gives both call shapes one owner and prevents a nested finish re-arm. */
static void
ngx_http_cache_turbo_redis_backoff_fail(ngx_http_cache_turbo_redis_op_t *op)
{
    if (!op->unconnected) {
        return;
    }

    op->unconnected = 0;
    if (op->clcf != NULL) {
        ngx_http_cache_turbo_redis_backoff_arm(&op->clcf->redis_addr,
            op->clcf->redis_connect_backoff);
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


/*
 * Emit one pipelined, chunked variadic command over `keys` in a single
 * fire-and-forget connection: `<lead[0..nlead-1]> <up to CHUNK keys>`, repeated
 * until every key is covered. Each chunk is one command producing one reply, so
 * read_drain frames `emitted` of them (STAB-1 expected_replies).
 *
 * Factored out of del_many (TODO-REDIS-PAGINATION) so the SSCAN tag walk can
 * also emit `SREM <tagkey> <members...>` per page without a second copy of the
 * chunking, sizing and launch dance. `lead` is the fixed prefix ("UNLINK", or
 * "SREM" + the set key); keys are appended after it. Key bytes are copied by
 * encode_into, so the caller's arrays need not outlive the call.
 *
 * `keep_empty` decides what a zero-length element means. For UNLINK it is
 * garbage and is dropped, because "" is not a key anything could have stored.
 * For SREM it is a legitimate member -- a Redis set holds "" as happily as any
 * other string -- and dropping it would leave it in the set forever, so the set
 * would never reach empty and Redis would never retire the set key.
 */
static ngx_int_t
ngx_http_cache_turbo_redis_cmd_many(ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_str_t *lead, ngx_uint_t nlead, ngx_str_t *keys, ngx_uint_t nkeys,
    ngx_uint_t keep_empty, void (*done)(void *, ngx_int_t),
    size_t done_data_size, void **done_data)
{
    ngx_uint_t                        i, m, emitted, j;
    size_t                            total;
    ngx_str_t                        *argv;
    ngx_http_cache_turbo_redis_op_t  *op;

    if (!clcf->redis_enable || nkeys == 0 || nlead == 0) {
        /* Nothing asked for is not a failure -- and `done` is NOT invoked,
         * because no op was created and none will complete. The contract is
         * "done fires iff this function returned NGX_OK after a successful
         * launch"; a caller that needs the callback must therefore treat
         * NGX_OK-without-a-launch as already-complete. redis_del_many_cb below
         * distinguishes the two for its one caller. */
        return NGX_OK;
    }

    op = ngx_http_cache_turbo_redis_op_create(clcf);
    if (op == NULL) {
        return NGX_ERROR;
    }

    /* lead + up to CHUNK keys per command. */
    argv = ngx_palloc(op->pool,
               (nlead + NGX_HTTP_CACHE_TURBO_REDIS_DEL_CHUNK)
                   * sizeof(ngx_str_t));
    if (argv == NULL) {
        ngx_destroy_pool(op->pool);
        return NGX_ERROR;
    }
    for (j = 0; j < nlead; j++) {
        argv[j] = lead[j];
    }

    total = 0;
    emitted = 0;
    i = 0;
    while (i < nkeys) {
        m = 0;
        while (m < NGX_HTTP_CACHE_TURBO_REDIS_DEL_CHUNK && i < nkeys) {
            if (keep_empty || keys[i].len) {
                argv[nlead + m] = keys[i];/* shallow; encode copies the bytes */
                m++;
            }
            i++;
        }
        if (m == 0) {
            continue;                     /* chunk held only empty keys */
        }
        emitted++;
        total += ngx_http_cache_turbo_redis_encode_len(argv, nlead + m);
    }

    if (emitted == 0) {                   /* nothing to send */
        ngx_destroy_pool(op->pool);
        return NGX_OK;
    }

    op->send = ngx_create_temp_buf(op->pool, total);
    if (op->send == NULL) {
        ngx_destroy_pool(op->pool);
        return NGX_ERROR;
    }

    i = 0;
    while (i < nkeys) {
        m = 0;
        while (m < NGX_HTTP_CACHE_TURBO_REDIS_DEL_CHUNK && i < nkeys) {
            if (keep_empty || keys[i].len) {
                argv[nlead + m] = keys[i];
                m++;
            }
            i++;
        }
        if (m != 0) {
            op->send->last = ngx_http_cache_turbo_redis_encode_into(
                                  op->send->last, argv, nlead + m);
        }
    }

    if (emitted == 0) {
        /* Every key was empty and keep_empty is off, so nothing was encoded.
         * Launching would send a zero-byte command and then wait for a reply
         * that read_drain's `expected_replies ? : 1` fallback insists on,
         * parking the op until its read timeout -- and, for an awaited caller,
         * delivering a spurious NGX_ERROR for a delete that had nothing to do.
         * Sending nothing is vacuously a successful delete, so report it as the
         * no-op it is. `done` is deliberately NOT invoked: the contract is that
         * it fires only after a launch, and del_many_cb turns this NGX_OK into
         * its own already-complete answer. */
        ngx_destroy_pool(op->pool);
        return NGX_OK;
    }

    op->expected_replies = emitted;       /* one integer reply per command */
    op->drain_cb = done;                  /* NULL keeps fire-and-forget */

    if (done != NULL && done_data_size > 0) {
        /* The completion's state is allocated HERE, from the op's own pool,
         * and handed back for the caller to populate. That pool is destroyed by
         * op_done strictly after the completion has run, so it is the one arena
         * whose lifetime brackets the completion exactly -- unlike the caller's
         * request pool, which a terminated request frees out from under a
         * pending completion, and unlike the caller's page scratch, which the
         * completion itself releases. */
        op->drain_data = ngx_pcalloc(op->pool, done_data_size);
        if (op->drain_data == NULL) {
            ngx_destroy_pool(op->pool);
            return NGX_ERROR;
        }
        *done_data = op->drain_data;
    }

    if (ngx_http_cache_turbo_redis_launch(op, clcf,
            ngx_http_cache_turbo_redis_read_drain) != NGX_OK)
    {
        ngx_destroy_pool(op->pool);
        return NGX_ERROR;
    }

    /* NGX_DONE, not NGX_OK: the op is in flight and `done`, if any, WILL fire.
     * Every early NGX_OK above is a "nothing was sent" no-op for which it will
     * not, and the awaited caller has to tell the two apart -- a caller that
     * parked on a callback that is never coming hangs until its read timeout.
     * The fire-and-forget wrappers collapse both back to NGX_OK, so their
     * callers are unaffected. */
    return NGX_DONE;
}


ngx_int_t
ngx_http_cache_turbo_redis_del_many(ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_str_t *keys, ngx_uint_t nkeys)
{
    ngx_str_t  lead[1];

    lead[0].data = (u_char *) "UNLINK";
    lead[0].len = sizeof("UNLINK") - 1;

    /* Fire-and-forget: a launch and a nothing-to-send are both success. */
    return ngx_http_cache_turbo_redis_cmd_many(clcf, lead, 1, keys, nkeys, 0,
                                               NULL, 0, NULL) == NGX_ERROR
               ? NGX_ERROR : NGX_OK;
}


/*
 * TODO-UNLINK-REPLY-WINDOW: del_many, but AWAITING the server's reply.
 *
 * del_many is fire-and-forget: it reports only whether the UNLINK was LAUNCHED.
 * A delete that leaves the box and then fails at Redis -- a `-ERR`, a
 * connection dropped mid-flight, a read timeout -- is indistinguishable from a
 * success to its caller. For the paginated tag purge that is a data-loss
 * window, not a cosmetic one: tag membership is the ONLY pointer to an L2
 * object, so SREMing a page whose UNLINK silently failed strands a live object
 * that is unreachable by every later purge of that tag and occupies L2 until
 * its own TTL, behind an HTTP reply that claimed the purge succeeded.
 *
 * `done` is invoked EXACTLY ONCE, later and from the event loop, with NGX_OK
 * only when every pipelined reply framed cleanly and none was a RESP error.
 * It is invoked if and only if this function returns NGX_DONE. NGX_OK means
 * there was nothing to send (L2 disabled, or every key was empty), so the
 * caller may proceed immediately; NGX_ERROR means the command never launched
 * and `done` will never fire.
 */
ngx_int_t
ngx_http_cache_turbo_redis_del_many_cb(ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_str_t *keys, ngx_uint_t nkeys, void (*done)(void *, ngx_int_t),
    size_t done_data_size, void **done_data)
{
    ngx_str_t  lead[1];
    ngx_int_t  rc;

    *done_data = NULL;                    /* only a launch produces one */

    lead[0].data = (u_char *) "UNLINK";
    lead[0].len = sizeof("UNLINK") - 1;

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    if (clcf->test_unlink_reply_fail > 0
        && ++clcf->test_unlink_reply_seen
               >= (ngx_uint_t) clcf->test_unlink_reply_fail)
    {
        /* An unknown verb: launched and written exactly like the real one, and
         * answered by a real `-ERR unknown command` frame. That is a delete
         * that FAILED AT THE SERVER while looking, to everything upstream of
         * the reply, indistinguishable from one that worked -- the state the
         * pre-fix code SREMed over. */
        lead[0].data = (u_char *) "CACHETURBONOSUCHCOMMAND";
        lead[0].len = sizeof("CACHETURBONOSUCHCOMMAND") - 1;
    }

    if (clcf->test_unlink_launch_hold_ms > 0) {
        /* Burn wall-clock time with the walk ALREADY SUSPENDED (the page
         * callback suspends before calling us), so the SSCAN connection's read
         * timer -- armed when its page was sent -- would expire during the
         * park. If the suspension failed to disarm it, the event loop delivers
         * that timeout to read_sscan on the next iteration and the walk is torn
         * down under this still-unlaunched UNLINK. ngx_time_update so the
         * cached clock really advances across the hold. */
        ngx_msleep((ngx_msec_t) clcf->test_unlink_launch_hold_ms);
        ngx_time_update();
    }
#endif

    /* cmd_many's tri-state IS this function's contract, relayed unchanged:
     * NGX_DONE launched (done fires exactly once, later), NGX_OK nothing was
     * sent (done never fires; vacuously a successful delete), NGX_ERROR never
     * launched (done never fires). Re-deriving "was anything sent?" here by
     * re-scanning the keys would duplicate cmd_many's own emptiness filter and
     * silently diverge from it the first time either side changed. */
    rc = ngx_http_cache_turbo_redis_cmd_many(clcf, lead, 1, keys, nkeys, 0,
                                             done, done_data_size, done_data);
    if (rc != NGX_DONE) {
        *done_data = NULL;                /* nothing launched, nothing to fill */
    }

    return rc;
}


/*
 * TODO-REDIS-PAGINATION: drop `members` from the set `setkey`, pipelined and
 * chunked exactly like del_many.
 *
 * The SSCAN tag walk needs this for one reason: an ABANDONED walk keeps the tag
 * set key so the purge stays retryable, but retaining the key is worthless if
 * the members it already dropped are still IN it. A retry restarts at cursor 0,
 * re-walks the same first pages, hits the same page cap or deadline, and makes
 * no progress -- the tag is permanently unpurgeable, which is a worse failure
 * than the over-cap SMEMBERS bug this change fixed. SREMing each page as it is
 * dropped is what makes "retry the purge" actually converge.
 *
 * On a COMPLETE walk it is also what EMPTIES the set: there is no terminal DEL
 * of the tag key, because deleting it unconditionally would destroy a member
 * SADDed mid-walk that SSCAN never returned. Emptying the set page by page and
 * letting Redis retire the emptied key itself preserves that survivor instead.
 * Every visited member is passed, zero-length ones included (keep_empty), or
 * the set would never reach empty and the key would outlive a complete purge.
 */
ngx_int_t
ngx_http_cache_turbo_redis_srem_many(ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_str_t *setkey, ngx_str_t *members, ngx_uint_t nmembers)
{
    ngx_str_t  lead[2];

    if (setkey == NULL || setkey->len == 0) {
        return NGX_ERROR;
    }

    lead[0].data = (u_char *) "SREM";
    lead[0].len = sizeof("SREM") - 1;
    lead[1] = *setkey;

    /* Fire-and-forget: a launch and a nothing-to-send are both success. */
    return ngx_http_cache_turbo_redis_cmd_many(clcf, lead, 2, members,
                                               nmembers, 1, NULL, 0, NULL)
               == NGX_ERROR ? NGX_ERROR : NGX_OK;
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
/* COR5-PURGE-VARIDX-RACE: adjust this zone's in-flight index-write count.
 * Folded into a helper so the two call sites in tag_add_impl (arm before
 * launch, unwind on a launch that never reached the transport) and the one in
 * op_done stay single statements -- the accounting is incidental to each of
 * those functions and should not add branches to their bodies. */
static void
ngx_http_cache_turbo_redis_varidx_inflight_add(
    ngx_http_cache_turbo_redis_op_t *op, ngx_atomic_int_t delta)
{
    ngx_http_cache_turbo_zone_t  *z;

    if (!op->counts_inflight || op->clcf == NULL
        || op->clcf->shm_zone == NULL)
    {
        return;
    }

    z = op->clcf->shm_zone->data;
    if (z == NULL || ngx_http_cache_turbo_zone_sh(z) == NULL) {
        return;
    }

    (void) ngx_atomic_fetch_add(
               &ngx_http_cache_turbo_zone_sh(z)->varidx_inflight, delta);
}


static ngx_int_t
ngx_http_cache_turbo_redis_tag_add_impl(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *key_hash, ngx_str_t *names, ngx_uint_t nnames, time_t ttl,
    ngx_uint_t count_inflight)
{
    ngx_str_t                         argv[4];
    ngx_str_t                         tagkeys[NGX_HTTP_CACHE_TURBO_MAX_TAGS];
    ngx_str_t                         member_arg, ttl_arg;
    size_t                            total = 0;
    ngx_uint_t                        i, nqueued = 0;
    ngx_http_cache_turbo_redis_op_t  *op;
    u_char                           *member, *ttlbuf;

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
    member_arg = argv[2];
    ttl_arg.data = ttlbuf;
    ttl_arg.len = (size_t) (ngx_sprintf(ttlbuf, "%T", ttl) - ttlbuf);

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
        tagkeys[nqueued].data = tagkey;
        tagkeys[nqueued].len = klen;

        /* SADD <prefix>tag:<name> <object L2 key> */
        argv[0].data = (u_char *) "SADD";
        argv[0].len = sizeof("SADD") - 1;
        argv[1].data = tagkey;
        argv[1].len = klen;
        argv[2] = member_arg;
        total += ngx_http_cache_turbo_redis_encode_len(argv, 3);

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
        argv[2] = ttl_arg;
        argv[3].data = (u_char *) "NX";
        argv[3].len = sizeof("NX") - 1;
        total += ngx_http_cache_turbo_redis_encode_len(argv, 4);
        argv[3].data = (u_char *) "GT";
        argv[3].len = sizeof("GT") - 1;
        total += ngx_http_cache_turbo_redis_encode_len(argv, 4);

        nqueued++;
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
        argv[0].data = (u_char *) "SADD";
        argv[0].len = sizeof("SADD") - 1;
        argv[1] = tagkeys[i];
        argv[2] = member_arg;
        op->send->last = ngx_http_cache_turbo_redis_encode_into(op->send->last,
                                                                argv, 3);

        argv[0].data = (u_char *) "EXPIRE";
        argv[0].len = sizeof("EXPIRE") - 1;
        argv[2] = ttl_arg;
        argv[3].data = (u_char *) "NX";
        argv[3].len = sizeof("NX") - 1;
        op->send->last = ngx_http_cache_turbo_redis_encode_into(op->send->last,
                                                                argv, 4);

        argv[3].data = (u_char *) "GT";
        argv[3].len = sizeof("GT") - 1;
        op->send->last = ngx_http_cache_turbo_redis_encode_into(op->send->last,
                                                                argv, 4);
    }

    /* 3 replies per tag: SADD + EXPIRE NX + EXPIRE GT */
    op->expected_replies = (ngx_uint_t) (nqueued * 3);

    /* COR5-PURGE-VARIDX-RACE: account this write as in-flight BEFORE handing it
     * to the transport, so a PURGE whose SMEMBERS races it sees a non-zero gap
     * and reports "complete":false instead of a false success. Paired with the
     * decrement in op_done(); the increment has to happen before launch because
     * the keepalive path can post the write event and complete the op without
     * ever returning here. Ordering is safe on a single-threaded worker: a
     * posted event only runs after the current handler returns, so this
     * increment cannot be preempted by its own decrement. */
    /* op->clcf is what the in-flight helper resolves the zone through, and
     * redis_launch() below does not set it until after this point -- bind it
     * here so the arm cannot silently no-op and leave op_done's decrement
     * unpaired (which drifts the counter negative and wraps, pinning every
     * later purge in the zone at "complete":false). */
    op->clcf = clcf;
    op->counts_inflight = (unsigned) (count_inflight != 0);
    ngx_http_cache_turbo_redis_varidx_inflight_add(op, 1);

    if (ngx_http_cache_turbo_redis_launch(op, clcf,
            ngx_http_cache_turbo_redis_read_drain) != NGX_OK)
    {
        /* Never reached the transport: undo the in-flight account here rather
         * than in op_done, which this path deliberately bypasses. The caller
         * turns this NGX_ERROR into a varidx_drops bump + a pending bit, which
         * is the correct accounting for a genuine drop. */
        ngx_http_cache_turbo_redis_varidx_inflight_add(op, -1);
        ngx_destroy_pool(op->pool);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/* L9 batch entry point (cache_turbo_tag). Does NOT participate in the COR-5
 * in-flight accounting: that counter exists for the auto-Vary variant index,
 * whose absence a PURGE of the base URI silently under-reports. The tag index
 * has its own drop counter (tag_index_drops) and its own "complete":false
 * reporting on the by-tag purge path. */
ngx_int_t
ngx_http_cache_turbo_redis_tag_add_many(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *key_hash, ngx_str_t *names, ngx_uint_t nnames, time_t ttl)
{
    return ngx_http_cache_turbo_redis_tag_add_impl(clcf, key_hash, names,
                                                   nnames, ttl, 0);
}


/* Single-tag entry point, preserved for the auto-vary variant-index store
 * (one tag, nothing to batch) and any other one-shot caller.
 *
 * COR5-PURGE-VARIDX-RACE: this is the variant-index write, so it counts itself
 * as in-flight until L2 acknowledges. See the varidx_inflight comment in
 * module.h for why the store path cannot simply wait for the ack instead. */
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

    return ngx_http_cache_turbo_redis_tag_add_impl(clcf, key_hash, &one, 1,
                                                   ttl, 1);
}


/* Wire budget for one GET bulk reply. The configured serialized-object limit
 * is a payload limit; '$', the decimal length, and two CRLF pairs live outside
 * it. Config validation guarantees 1..MAX_VALUE; the defensive zero fallback
 * keeps this helper total for fuzz/unit callers and incomplete config state. */
static size_t
ngx_http_cache_turbo_redis_get_reply_max(size_t max_size)
{
    if (max_size == 0) {
        return NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY;
    }
    return max_size + NGX_HTTP_CACHE_TURBO_REDIS_GET_FRAMING_MAX;
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

    /* max_size is the serialized object ceiling. RESP adds '$', decimal
     * length, two CRLF pairs; NGX_INT_T_LEN bounds the decimal digits. */
    op->reply_max = ngx_http_cache_turbo_redis_get_reply_max(clcf->max_size);
    op->rcap = ngx_min(ngx_pagesize * 4, op->reply_max);
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

    op->reply_max = NGX_HTTP_CACHE_TURBO_REDIS_MAX_ITER_REPLY;
    op->rcap = ngx_min(ngx_pagesize * 4, op->reply_max);
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

    /* Parked: released by ngx_http_finalize_request in walk_finish (reused
     * as the scan completion: cb(r, data, NULL, 0)). */
    r->main->count++;

    return NGX_DONE;
}


/* How many members SSCAN returns per round trip. Same hint as the SCAN walk
 * (they share the page-cap, deadline and framing plumbing, so a shared page
 * size keeps the two walks' page accounting comparable). */
#define NGX_HTTP_CACHE_TURBO_REDIS_SSCAN_COUNT \
    NGX_HTTP_CACHE_TURBO_REDIS_SCAN_COUNT


/* Encode one `SSCAN <tagkey> <cursor> COUNT <n>` command into pool.
 *
 * Deliberately MATCH-less: every member of a tag set is an object key this
 * purge must drop, so there is nothing to filter, and adding a pattern would
 * only import scan_cmd's glob-escaping hazard for no gain.
 */
static ngx_buf_t *
ngx_http_cache_turbo_redis_sscan_cmd(ngx_pool_t *pool, ngx_str_t *tagkey,
    ngx_str_t *cursor)
{
    ngx_str_t  argv[5];

    argv[0].data = (u_char *) "SSCAN";
    argv[0].len = sizeof("SSCAN") - 1;
    argv[1] = *tagkey;
    argv[2] = *cursor;
    argv[3].data = (u_char *) "COUNT";
    argv[3].len = sizeof("COUNT") - 1;
    argv[4].data = (u_char *) NGX_HTTP_CACHE_TURBO_REDIS_SSCAN_COUNT;
    argv[4].len = sizeof(NGX_HTTP_CACHE_TURBO_REDIS_SSCAN_COUNT) - 1;

    return ngx_http_cache_turbo_redis_encode(pool, argv, 5);
}


/*
 * Paginated tag-set enumeration: `SSCAN <prefix>tag:<name>` cursor walk.
 *
 * TODO-REDIS-PAGINATION. This replaces a single SMEMBERS. SMEMBERS returns the
 * WHOLE set in one reply, so a tag set whose reply exceeded the 128 KiB
 * bounded-iteration cap (MAX_ITER_REPLY) failed the purge outright — 500, no
 * partial deletion, and permanently so until the set shrank on its own. SSCAN
 * bounds each REPLY instead of the set, so a tag of any size is purgeable.
 *
 * ⚠ COMPLETENESS IS WEAKER THAN SMEMBERS', DELIBERATELY (decision 2026-09-07).
 * SMEMBERS is an atomic snapshot: every member present when it ran is in the
 * reply, exactly once. SSCAN guarantees only that a member present for the
 * ENTIRE duration of the walk is returned at least once. Two consequences the
 * callers must live with, both documented for operators in README.md:
 *
 *   - A member SADDed midway through the walk MAY BE MISSED. A page tagged and
 *     stored while a purge of that tag is running can therefore survive it.
 *     Re-issue the purge if that matters. There is no way to close this without
 *     a key-format change (rejected) or server-side scripting (none in this
 *     tree, and none may be added).
 *   - A member MAY BE RETURNED MORE THAN ONCE (rehash during the walk). The
 *     per-page purge is therefore required to be IDEMPOTENT: dropping an
 *     already-dropped object key, lock key or L1 entry is a no-op, so a
 *     duplicate costs one redundant UNLINK argument and nothing else. The
 *     reported `purged` count is members VISITED, not distinct members —
 *     de-duplicating would need a set of every member seen so far, i.e. exactly
 *     the unbounded buffer this change exists to remove.
 *
 * Structurally this IS the scan_del walk (per-page rpool rotation, the
 * SCAN_MAX_PAGES cap, the scan_deadline wall-clock ceiling with the
 * signed-difference msec-wrap idiom, resumable frame_scan/parse_scan framing)
 * with two differences: the command is SSCAN over one key rather than SCAN over
 * the keyspace, and the per-page action is the CALLER'S, not del_many. The
 * callback is therefore invoked once PER PAGE with that page's members and
 * walk==NULL, then exactly once at the end with no members and walk!=NULL:
 * accumulating every page's members to hand over in one final call would
 * reintroduce the unbounded buffer.
 */
ngx_int_t
ngx_http_cache_turbo_redis_sscan(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, u_char *name, size_t name_len,
    ngx_http_cache_turbo_redis_members_pt cb, void *data)
{
    ngx_str_t                         cursor0 = ngx_string("0");
    ngx_pool_cleanup_t               *cln;
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
    op->is_scan = 1;
    op->scan_status = NGX_ERROR;           /* until cursor "0" says otherwise */
    op->scan_start = ngx_current_msec;     /* wall-clock ceiling, as scan_del */

    /* Per-page pool, exactly as scan_del: the reply buffer, the parsed member
     * array and the rebuilt SSCAN command all die with their page, so the
     * walk's live allocation is O(1) in page count. Without it a tag of a
     * million members would accumulate the whole set in op->pool — the very
     * thing this change removes. */
    op->rpool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (op->rpool == NULL) {
        op->rpool = op->pool;
        ngx_destroy_pool(op->pool);
        return NGX_ERROR;
    }

    op->reply_max = NGX_HTTP_CACHE_TURBO_REDIS_MAX_ITER_REPLY;
    op->rcap = ngx_min(ngx_pagesize * 4, op->reply_max);
    op->rbuf = ngx_pnalloc(op->rpool, op->rcap);

    /* The tag key is rebuilt into every page's command, so it must outlive any
     * single page: op->pool, never op->rpool. */
    op->sscan_key.data = ngx_pnalloc(op->pool,
                             clcf->redis_prefix.len + sizeof("tag:") - 1
                             + name_len);
    if (op->rbuf == NULL || op->sscan_key.data == NULL) {
        ngx_destroy_pool(op->rpool);
        op->rpool = op->pool;
        ngx_destroy_pool(op->pool);
        return NGX_ERROR;
    }
    op->sscan_key.len = ngx_http_cache_turbo_redis_tagkey(&clcf->redis_prefix,
                            name, name_len, op->sscan_key.data);

    op->send = ngx_http_cache_turbo_redis_sscan_cmd(op->rpool, &op->sscan_key,
                                                    &cursor0);
    if (op->send == NULL) {
        ngx_destroy_pool(op->rpool);
        op->rpool = op->pool;
        ngx_destroy_pool(op->pool);
        return NGX_ERROR;
    }

    /* CT-SSCAN-TERMINATE-LEAK: register the request-teardown detach BEFORE the
     * launch. The walk op is built from its OWN pool, not a child of r->pool,
     * and the r->main->count++ park below does not survive a TERMINATE, so
     * without this cleanup the request can be freed with the walk still live:
     * op->request dangles, and (once the suspension disarm removed the last
     * wakeups that could drive the op to walk_finish) the op pool, the Redis
     * connection, its fd and this zone's varidx_inflight account leak for the
     * worker's lifetime.
     *
     * Registering it before the launch is deliberate: a failed launch reaches
     * op_fail -> walk_finish, which would otherwise leave a cleanup pointing at
     * a destroyed op. op_done cancels the cleanup on every path that destroys
     * the op, so the ordering is safe in both directions -- but only because
     * the cleanup exists by the time any teardown can run.
     *
     * A cleanup slot that cannot be allocated is fatal to the walk: proceeding
     * would reinstate exactly the leak/use-after-free this closes. */
    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        ngx_destroy_pool(op->rpool);
        op->rpool = op->pool;
        ngx_destroy_pool(op->pool);
        return NGX_ERROR;
    }
    cln->handler = ngx_http_cache_turbo_redis_walk_detach;
    cln->data = op;
    op->req_cln = cln;

    if (ngx_http_cache_turbo_redis_launch(op, clcf,
            ngx_http_cache_turbo_redis_read_sscan) != NGX_OK)
    {
        /* The op is being destroyed here, not through op_done, so cancel the
         * cleanup by hand. */
        cln->handler = NULL;
        op->req_cln = NULL;
        ngx_destroy_pool(op->rpool);
        op->rpool = op->pool;
        ngx_destroy_pool(op->pool);
        return NGX_ERROR;
    }

    /* Parked: released by ngx_http_finalize_request in walk_finish -- unless the
     * request is TERMINATED first, in which case walk_detach above takes over
     * and the walk tears itself down without ever touching the request. */
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
        ngx_http_cache_turbo_redis_backoff_fail(op);
        ngx_http_cache_turbo_redis_op_done(op);   /* clean stays 0: not pooled */
        return;
    }

    for ( ;; ) {
        if (op->recv_len >= sizeof(op->recv)) {
            /* Replies to our fire-and-forget commands (integers, +OK, a short
             * -ERR) never fill the scratch buffer; if one somehow does, just
             * don't pool the connection rather than grow it unbounded. */
            ngx_http_cache_turbo_redis_backoff_fail(op);
            ngx_http_cache_turbo_redis_op_done(op);
            return;
        }

        n = c->recv(c, op->recv + op->recv_len,
                    sizeof(op->recv) - op->recv_len);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_http_cache_turbo_redis_backoff_fail(op);
                ngx_http_cache_turbo_redis_op_done(op);
            }
            return;
        }
        if (n == NGX_ERROR || n == 0) {
            /* Peer closed/errored before all replies framed: don't pool. */
            ngx_http_cache_turbo_redis_backoff_fail(op);
            ngx_http_cache_turbo_redis_op_done(op);
            return;
        }

        /* A genuine reply byte proves this fresh connection reached Redis.
         * The direct drain does not pass through redis_fill(), so it owns the
         * same clear performed there by GET/SMEMBERS/SCAN. */
        if (op->unconnected) {
            op->unconnected = 0;
            if (op->clcf != NULL) {
                ngx_http_cache_turbo_redis_backoff_clear(
                    &op->clcf->redis_addr);
            }
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
                ngx_http_cache_turbo_redis_backoff_fail(op);
                ngx_http_cache_turbo_redis_op_done(op);
                return;
            }
            if (*p == '-') {
                /* TODO-UNLINK-REPLY-WINDOW: a RESP error is a framed, complete
                 * reply, so the connection stays poolable -- but the COMMAND
                 * failed. Record it so a drain_cb consumer (the tag purge's
                 * per-page UNLINK) reports NGX_ERROR rather than treating
                 * "the server answered" as "the delete happened". */
                op->drain_failed = 1;
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
            ngx_http_cache_turbo_redis_backoff_fail(op);
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
     * today (both sites in redis_walk_finish pass op->pool / op->rpool,
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
        if (op->rcap >= op->reply_max) {
            return NGX_ERROR;
        }
        ncap = op->rcap * 2;
        if (ncap > op->reply_max) {
            ncap = op->reply_max;
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

    if ((size_t) len > (op->clcf != NULL && op->clcf->max_size > 0
                         ? op->clcf->max_size
                         : NGX_HTTP_CACHE_TURBO_REDIS_MAX_VALUE))
    {
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
 *   - read_sscan/read_scan confirm the whole array arrived before the single
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
        if ((size_t) v > NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY) {
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
 * event-loop re-entries into read_sscan/read_scan. frame_remain[d] holds
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
            if ((size_t) v > NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY) {
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
 * (TODO-REDIS-PAGINATION: parse_array(), formerly the third caller, went with
 * the SMEMBERS reader it existed for -- SSCAN's reply is parse_scan's shape.)
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

    if ((size_t) len > NGX_HTTP_CACHE_TURBO_REDIS_MAX_REPLY) {
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
        ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
        return;
    }

    for ( ;; ) {
        u_char  *next;

        rc = ngx_http_cache_turbo_redis_fill(op, rev);
        if (rc == NGX_AGAIN) {
            return;
        }
        if (rc == NGX_ERROR) {
            ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
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
        if (rc != NGX_OK || next != op->rbuf + op->rlen) {
            /* SCAN is likewise one request/reply per connection.  Reject a
             * complete first frame followed by any unconsumed bytes. */
            ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
            return;
        }

        rc = ngx_http_cache_turbo_redis_parse_scan(op, &cursor, &keys, &nkeys);
        if (rc != NGX_OK) {
            ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
            return;
        }

        /* PERF-1: drop the whole page in one pipelined UNLINK connection rather
         * than a fresh fire-and-forget connection per key (an FD/timer storm on
         * a large keyspace). Keys point into rbuf; del_many copies them before
         * the next SCAN resets rbuf.
         *
         * There is no tag set here (this is the whole-keyspace ?all=1 walk,
         * not the by-tag SSCAN walk), so a page whose UNLINK never launched
         * strands nothing invisible -- the keys stay enumerable on the next
         * SCAN of this same cursor range. But letting the walk carry on to
         * cursor "0" would still report a clean purge over objects that were
         * never dropped, which is exactly the under-reporting AUD-SCAN1
         * already refuses for the page-cap/deadline/malformed-reply paths.
         * Mirror read_sscan's contract: abandon the walk and let the terminal
         * callback report INCOMPLETE rather than clean. scan_status is
         * already NGX_ERROR here (it only becomes NGX_OK at cursor "0"). */
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
        /* GRIND-C6-READSCAN: force this page's del_many to report failure
         * deterministically, without taking Redis down (which would also
         * kill the SCAN side of the walk and prove nothing about this
         * specific branch). Skip the real call rather than launch-then-
         * override: del_many's UNLINK is fire-and-forget over a live
         * connection, so calling it for real and only overwriting the
         * return value would still delete every key in this page while
         * claiming the walk never dropped them -- exactly the dishonesty
         * this fault is meant to simulate, not exempt itself from. */
        if (op->clcf->test_scan_del_fail) {
            rc = NGX_ERROR;
        } else {
            rc = ngx_http_cache_turbo_redis_del_many(op->clcf, keys, nkeys);
        }
#else
        rc = ngx_http_cache_turbo_redis_del_many(op->clcf, keys, nkeys);
#endif

        /* The SCAN side of this page DID land (we have a parsed cursor/keys
         * reply in hand) even when del_many's launch failed, so this page
         * counts toward scan_pages either way. Without this the very first
         * page's del_many failure reports walk->pages == 0 at walk_finish,
         * which admin.c's all_purge_complete() reads as "the walk never
         * ran" (l2:"unavailable") rather than "it ran and stopped early"
         * (l2:"incomplete") -- a milder, wrong report for a purge that DID
         * enumerate a page and then fail to drop it. */
        op->scan_pages++;

        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "cache_turbo: L2 all-purge abandoned at SCAN page "
                          "%ui: UNLINK never launched; purge is INCOMPLETE",
                          op->scan_pages);
            ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
            return;
        }


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
            ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
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
            ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
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
            ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
            return;
        }

        /* Issue the next SCAN with the returned cursor, out of a FRESH page
         * pool. encode copies the cursor bytes (which point into the old rbuf)
         * into the new send buffer, so the old pool is safe to drop right
         * after — and must be dropped, or the walk grows without bound. */
        np = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
        if (np == NULL) {
            ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
            return;
        }

        send = ngx_http_cache_turbo_redis_scan_cmd(np, op->clcf, &cursor);
        rbuf = send ? ngx_pnalloc(np,
                    ngx_min(ngx_pagesize * 4, op->reply_max)) : NULL;
        if (rbuf == NULL) {
            ngx_destroy_pool(np);
            ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
            return;
        }

        old = op->rpool;
        op->rpool = np;
        op->send = send;
        op->command = send;                /* old buffer dies with `old` */
        op->rbuf = rbuf;
        op->rcap = ngx_min(ngx_pagesize * 4, op->reply_max);
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
 * SSCAN reply reader: accumulate one [cursor, members] page, hand that page's
 * members to the completion callback (walk == NULL, so the callback purges
 * them and returns without producing a response), then either finish (cursor
 * back to "0") or post the write event to issue the next SSCAN.
 *
 * TODO-REDIS-PAGINATION. This is read_scan's structure with the per-page action
 * delegated to the caller instead of being del_many: see redis_sscan() above
 * for why the members are consumed PER PAGE rather than accumulated (an
 * accumulating walk is the unbounded buffer this replaced SMEMBERS to remove),
 * and for the weakened completeness contract that follows from SSCAN.
 *
 * Every page-cap / deadline / malformed-reply / timeout path leaves
 * scan_status non-OK, so the terminal callback reports the purge INCOMPLETE
 * and — critically — does NOT delete the tag set key. Retaining it is what
 * keeps an abandoned purge retryable and its unvisited objects discoverable.
 */
/*
 * TODO-UNLINK-REPLY-WINDOW: the SSCAN walk whose page delivery is on the stack
 * RIGHT NOW, or NULL. Set only around the members_cb call in read_sscan and
 * cleared immediately after it returns, so it is live for exactly the duration
 * of one synchronous callback invocation and can never name a walk that has
 * already been torn down.
 *
 * A single scalar is sufficient and correct. nginx workers are single-threaded,
 * and -- the load-bearing half -- redis_launch POSTS the write event on every
 * path it takes (keepalive reuse, immediate connect, connect-in-progress) and
 * never runs a handler inline, so no sub-operation the callback starts can
 * complete inside members_cb. The callback therefore always unwinds before any
 * reply is processed, and at most one page delivery is ever on the stack in a
 * worker. (The weaker claim, that the callback merely does its I/O
 * asynchronously, would still permit an inline completion on a synchronous
 * failure path; it is the unconditional post that rules that out.)
 *
 * It exists so a page callback -- which is handed only the request and its own
 * data, deliberately, so purge policy stays out of the transport -- can still
 * reach its own walk to suspend it.
 */
static ngx_http_cache_turbo_redis_op_t  *ngx_http_cache_turbo_redis_delivering;


ngx_int_t
ngx_http_cache_turbo_redis_walk_suspend(void (**done)(void *, ngx_int_t),
    void **done_data)
{
    ngx_http_cache_turbo_redis_op_t  *op = ngx_http_cache_turbo_redis_delivering;

    /* No page delivery on the stack, or this walk is already parked: there is
     * nothing to suspend. Say so rather than handing back a continuation, so
     * the caller falls back to a synchronous decision instead of returning
     * NGX_AGAIN and parking a walk nothing will resume. */
    if (op == NULL || op->suspended) {
        return NGX_DECLINED;
    }

    op->suspended = 1;
    *done = ngx_http_cache_turbo_redis_sscan_resume;
    *done_data = op;

    return NGX_OK;
}


void
ngx_http_cache_turbo_redis_walk_unsuspend(void *opaque)
{
    ngx_http_cache_turbo_redis_op_t  *op = opaque;

    if (op != NULL) {
        op->suspended = 0;
    }
}


/*
 * CT-SSCAN-TERMINATE-LEAK: take this walk's Redis connection off the poller and
 * cancel its read timer.
 *
 * Factored out of read_sscan's suspension block so the request-teardown detach
 * can reuse exactly the same disarm. Both callers need the identical thing and
 * for the identical reason: a read timer or a registered read event outliving
 * the moment the walk stops being drivable re-enters read_sscan on its own
 * schedule and tears the op down under whatever still holds it.
 *
 * Returns NGX_OK when the connection is quiet, NGX_ERROR when ngx_del_event
 * refused -- the caller decides what an undisarmable connection means, because
 * the two call sites differ: the suspension must stay parked for its in-flight
 * UNLINK, while the detach has no request left to protect.
 */
static ngx_int_t
ngx_http_cache_turbo_redis_walk_disarm_conn(ngx_connection_t *c)
{
    ngx_event_t  *rev;

    if (c == NULL) {
        return NGX_OK;
    }

    rev = c->read;

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    /* ngx_del_event, NOT ngx_handle_read_event(NGX_CLOSE_EVENT): the latter
     * keeps the descriptor registered so a peer close is still reported, which
     * is precisely the wakeup that must not happen. */
    if (rev->active && ngx_del_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * CT-SSCAN-TERMINATE-LEAK: the r->pool cleanup registered by redis_sscan. Runs
 * from the request's OWN teardown -- including ngx_http_terminate_handler,
 * which ignores the walk's r->main->count++ park -- strictly before the memory
 * holding the request is released.
 *
 * Its whole job is to make the walk survivable without a request:
 *
 *   - op->request is cleared, so no later path can dereference freed memory.
 *     Every walk terminal reads it, so clearing it is the single edit that
 *     makes the dangling-pointer class impossible rather than merely unlikely.
 *   - members_cb is cleared for the same reason: it is a purge-policy callback
 *     whose data lives in r->pool.
 *   - `detached` is set, which is what walk_finish consults to skip the
 *     callback and the finalize while still reaching op_done.
 *
 * ORDERING HAZARD. When the walk is SUSPENDED, a page's UNLINK is in flight on
 * a DIFFERENT connection and holds this op as its completion data through
 * tp->page_resume_data. Destroying op->pool here would leave that pending
 * completion pointing at freed memory -- strictly worse than the leak. So the
 * suspended case tears down nothing: it records the doom and lets
 * sscan_resume perform the teardown at the first moment nothing references the
 * op.
 *
 * ⚠ THAT RESUME IS NOT AUTOMATIC. del_many_cb guarantees its COMPLETION fires
 * exactly once, but the completion's request-is-gone arm cannot reach
 * tp->page_resume: the tagpurge holding it died with r->pool. Reading the
 * guarantee as "so sscan_resume always runs" is how this deferral silently
 * became the leak it was meant to avoid. What closes it is purge.c mirroring
 * the continuation into the await token (which lives in the UNLINK op's own
 * pool) at suspension time, so the completion's !alive arm still calls it. Any
 * future awaiting caller that suspends a walk owes the same mirror.
 *
 * When the walk is NOT suspended, nothing else holds the op: the connection is
 * this op's own, so disarming it and calling op_done here releases the pool,
 * the connection, its fd and this zone's varidx_inflight account immediately.
 */
static void
ngx_http_cache_turbo_redis_walk_detach(void *data)
{
    ngx_http_cache_turbo_redis_op_t  *op = data;

    if (op == NULL || op->detached) {
        return;
    }

    op->detached = 1;
    op->request = NULL;
    op->members_cb = NULL;
    op->members_data = NULL;
    op->ctx = NULL;

    /* The cleanup is running: nginx removes it from the list itself, so the
     * pointer must not be reused by op_done afterwards. */
    op->req_cln = NULL;

    /* Whatever happens next, this walk can never complete a purge. */
    op->scan_status = NGX_ERROR;

    if (op->suspended) {
        /* A page's UNLINK still holds this op. Only the resume may tear it
         * down; sscan_resume sees resume_doomed (and detached) and calls
         * op_done there. The awaiting caller is responsible for keeping that
         * resume reachable after the request dies -- see the ⚠ above. Try to disarm the connection again -- it should
         * already be quiet from the suspension, and a re-disarm is harmless.
         *
         * The result is deliberately discarded: there is nothing useful to do
         * with a refusal here, and the walk must stay parked for its in-flight
         * UNLINK regardless. That means this arm CAN return with the read
         * event still registered, so read_sscan's `suspended` entry guard --
         * not this disarm -- is what makes a stray wakeup harmless. */
        op->resume_doomed = 1;
        (void) ngx_http_cache_turbo_redis_walk_disarm_conn(op->peer.connection);
        return;
    }

    /* Nothing else holds the op: release everything now. The disarm must
     * happen first -- op_done closes the connection, and a timer still armed
     * on a closed connection's read event is a use-after-free of its own. */
    (void) ngx_http_cache_turbo_redis_walk_disarm_conn(op->peer.connection);

    ngx_http_cache_turbo_redis_op_done(op);
}


/*
 * TODO-UNLINK-REPLY-WINDOW: advance the SSCAN tag walk past a page that has
 * been FULLY handled, given the cursor the server returned with it.
 *
 * Factored out of read_sscan so the resume path can reach it. The walk now has
 * two ways to finish a page: synchronously, straight out of read_sscan's parse
 * loop when the page callback handled it inline, and asynchronously, when the
 * callback awaited its UNLINK reply and resumed us afterwards. Both must apply
 * the SAME page accounting, page cap, wall-clock deadline and next-page
 * rotation, so there is exactly one copy of them.
 *
 * ⚠ This is the SSCAN walk's advance and issues sscan_cmd against
 * op->sscan_key. The SCAN-del keyspace walk keeps its own copy in read_scan and
 * must NOT be routed here: the two walks differ in the command they re-issue,
 * and sending SCAN on a tag-purge connection would walk the whole keyspace
 * instead of the tag set.
 *
 * `cursor` may point into op->rbuf (synchronous call) or into op->pool's saved
 * copy (resume). Either way sscan_cmd COPIES the bytes into the new page's send
 * buffer before op->rbuf is rotated, so neither outlives this call.
 *
 * Terminal on every path except the one that posts the next page's write.
 */
static void
ngx_http_cache_turbo_redis_sscan_advance(
    ngx_http_cache_turbo_redis_op_t *op, ngx_str_t cursor)
{
    ngx_uint_t         max_pages;
    ngx_buf_t         *send;
    u_char            *rbuf;
    ngx_pool_t        *np, *old;
    ngx_connection_t  *c = op->peer.connection;

    max_pages = NGX_HTTP_CACHE_TURBO_REDIS_SCAN_MAX_PAGES;
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    if (op->clcf->test_scan_max_pages > 0
        && (ngx_uint_t) op->clcf->test_scan_max_pages < max_pages)
    {
        max_pages = (ngx_uint_t) op->clcf->test_scan_max_pages;
    }
#endif

    op->scan_pages++;

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    /* Same page-boundary hold as read_scan, and placed BEFORE the
     * cursor==0 return for the same reason: that return is what makes the
     * deadline unreachable on a walk that finishes. */
    if (op->clcf->test_scan_page_hold_ms > 0) {
        ngx_msleep((ngx_msec_t) op->clcf->test_scan_page_hold_ms);
        ngx_time_update();
    }
#endif

    if (cursor.len == 1 && cursor.data[0] == '0') {
        /* Whole set walked: the terminal callback deletes the tag key and
         * emits the reply. */
        op->scan_status = NGX_OK;
        ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
        return;
    }

    if (op->scan_pages >= max_pages) {
        /* Non-termination guard, as read_scan: a server that never hands
         * back cursor "0" would otherwise walk forever (each page's write
         * re-arms the read timeout). Abandon and report INCOMPLETE. */
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "cache_turbo: L2 tag purge abandoned after %ui SSCAN "
                      "pages without the cursor returning to 0; purge is "
                      "INCOMPLETE", op->scan_pages);
        op->scan_status = NGX_ABORT;
        ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
        return;
    }

    /* Wall-clock ceiling on the WHOLE walk. ngx_current_msec wraps, so
     * compare with the signed-difference idiom, never a plain '>'.
     * 0 = disabled (page-cap only). */
    if (op->clcf->redis_scan_deadline > 0
        && (ngx_msec_int_t) (ngx_current_msec
                              - (op->scan_start
                                 + op->clcf->redis_scan_deadline)) > 0)
    {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "cache_turbo: L2 tag purge abandoned after %ui SSCAN "
                      "pages, wall-clock deadline %Mms exceeded; purge is "
                      "INCOMPLETE", op->scan_pages,
                      op->clcf->redis_scan_deadline);
        op->scan_status = NGX_ABORT;
        op->scan_deadline_hit = 1;
        ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
        return;
    }

    /* Next page out of a FRESH pool. encode copies the cursor bytes (which
     * point into the old rbuf) into the new send buffer, so the old pool is
     * safe to drop right after -- and must be, or the walk grows without
     * bound. op->sscan_key lives in op->pool and survives the rotation. */
    np = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (np == NULL) {
        ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
        return;
    }

    send = ngx_http_cache_turbo_redis_sscan_cmd(np, &op->sscan_key, &cursor);
    rbuf = send ? ngx_pnalloc(np,
                ngx_min(ngx_pagesize * 4, op->reply_max)) : NULL;
    if (rbuf == NULL) {
        ngx_destroy_pool(np);
        ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
        return;
    }

    old = op->rpool;
    op->rpool = np;
    op->send = send;
    op->command = send;                /* old buffer dies with `old` */
    op->rbuf = rbuf;
    op->rcap = ngx_min(ngx_pagesize * 4, op->reply_max);
    op->rlen = 0;
    /* frame_off/frame_remain/frame_depth index into the OLD rbuf being
     * replaced right here -- reset before the new page's first fill(). */
    op->frame_off = 0;
    op->frame_depth = 0;
    ngx_destroy_pool(old);

    /* RE-ARM after a suspension. The NGX_AGAIN branch in read_sscan drops this
     * connection's read event (and its timer) for the duration of the park, so
     * a resumed walk has to put the read event back before the next page's
     * reply can be noticed. The read TIMER needs nothing here: redis_write
     * re-arms ngx_add_timer(c->read, op->timeout) as soon as it finishes
     * sending, which is what bounds each page individually.
     *
     * Harmless on the synchronous path, where the event was never dropped:
     * ngx_handle_read_event on an already-active level-triggered event is a
     * no-op, and re-adding an edge-triggered one is idempotent. Doing it
     * unconditionally keeps the two entry paths from needing different
     * teardown state. */
    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
        return;
    }

    ngx_post_event(c->write, &ngx_posted_events);
}


/*
 * TODO-UNLINK-REPLY-WINDOW: resume a walk suspended by its page callback.
 *
 * `rc` is the callback's verdict on the page it was still handling when it
 * returned NGX_AGAIN: NGX_OK if the page is now fully handled (its UNLINK was
 * acknowledged by the server AND its members were SREMed), anything else if it
 * was not. A non-OK verdict abandons the walk with scan_status left non-OK, so
 * the terminal call reports "l2":"incomplete" and RETAINS the tag key --
 * byte-identical to the launch-failure outcome that already existed, which is
 * the point: a delete that failed at the server must be as visible as one that
 * never left the box.
 *
 * Rejecting a resume on a walk that is not suspended is not defensive noise: a
 * duplicate resume would drive the walk twice from one page, issuing two SSCANs
 * on one connection and desynchronising the reply stream.
 *
 * ⚠ REENTRANCY. This runs from redis_op_done, i.e. from the UNLINK op's own
 * event handler, never from inside the page callback's own stack frame: the
 * callback returns NGX_AGAIN to read_sscan and unwinds long before any reply
 * lands. The walk therefore never recurses through itself, and sscan_advance's
 * next page is POSTED (ngx_post_event), not run inline, so even the launch of
 * the following page unwinds to the event loop first.
 */
static void
ngx_http_cache_turbo_redis_sscan_resume(void *opaque, ngx_int_t rc)
{
    ngx_http_cache_turbo_redis_op_t  *op = opaque;

    if (op == NULL || !op->suspended) {
        return;
    }
    op->suspended = 0;

    /* CT-SSCAN-TERMINATE-LEAK: the request died while this page's UNLINK was in
     * flight. This resume is the first moment nothing references the op any
     * more -- the completion that called us is unwinding -- so it is where the
     * deferred teardown belongs. NOT walk_finish: there is no request to
     * finalize and no callback to call, and walk_finish would dereference both.
     * op_done alone still releases the op pool, the Redis connection and its
     * fd, and this zone's varidx_inflight account. */
    if (op->detached) {
        (void) ngx_http_cache_turbo_redis_walk_disarm_conn(op->peer.connection);
        ngx_http_cache_turbo_redis_op_done(op);
        return;
    }

    if (rc != NGX_OK || op->resume_doomed) {
        /* scan_status only ever becomes NGX_OK at cursor "0", which this walk
         * has not reached, so it is already non-OK here. Set it explicitly
         * anyway: the invariant is load-bearing enough that relying on it
         * implicitly is how a later edit turns a failed purge into a 200. */
        op->scan_status = NGX_ERROR;
        ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
        return;
    }

    ngx_http_cache_turbo_redis_sscan_advance(op, op->resume_cursor);
}


static void
ngx_http_cache_turbo_redis_read_sscan(ngx_event_t *rev)
{
    ngx_str_t                         cursor, *members;
    ngx_uint_t                        nmembers;
    ngx_int_t                         rc;
    ngx_connection_t                 *c;
    ngx_http_cache_turbo_redis_op_t  *op;

    c = rev->data;
    op = c->data;

    /* TODO-UNLINK-REPLY-WINDOW: a SUSPENDED walk is not ours to touch.
     *
     * While `suspended` is set, a page's UNLINK is in flight on a DIFFERENT
     * connection and holds this op as its completion data through
     * tp->page_resume_data. sscan_resume is the SOLE driver of a suspended
     * walk: it is guaranteed to run (del_many_cb fires its completion exactly
     * once from every terminal path) and it is the only place that may advance
     * or tear the walk down, because it is the first moment nothing else
     * references the op.
     *
     * The suspension normally disarms this connection so no event can reach
     * here at all -- but ngx_del_event can REFUSE, and both callers that
     * tolerate that (the suspension's disarm-failure arm below, and
     * walk_detach's suspended arm, which discards the disarm result) leave the
     * read event registered on the poller. A peer close or a stray readable
     * event then re-enters this function with the walk still parked, and every
     * error exit below calls walk_finish, which destroys op->pool -- the pool
     * `op` itself is allocated from -- while the pending UNLINK completion
     * still holds it. That completion then fires against freed memory: a
     * use-after-free from the event loop, precisely what the suspension's
     * `doomed:` label exists to prevent.
     *
     * So return, touching NOTHING. Do not parse, do not consume the
     * connection's buffered bytes (op->rbuf holds the page the resume still
     * needs, and rotating it would desynchronise the resumed walk's framing),
     * do not re-arm, and above all do not finish the walk.
     *
     * A timeout that lands here is likewise not ours: the timer was supposed
     * to be deleted at suspension and the deadline it measured -- how long this
     * connection may take to ANSWER -- stopped applying the moment the walk
     * started waiting on a different operation. Consume the flag so the event
     * is not re-delivered as a timeout forever, and record the doom so the
     * resume finishes the walk instead of advancing it onto a connection whose
     * read deadline has already expired. rev->timedout is never LOST: the
     * resume always runs and always acts on resume_doomed. */
    if (op->suspended) {
        if (rev->timedout) {
            rev->timedout = 0;
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                          "cache_turbo: redis SSCAN read timer fired on a "
                          "SUSPENDED walk; the resume will abandon it");
            op->scan_status = NGX_ERROR;
            op->resume_doomed = 1;
        }
        return;
    }

    /* The page cap, the wall-clock deadline and the next-page rotation moved
     * into sscan_advance, which both this reader and the suspended-walk resume
     * path share. */

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "cache_turbo: redis SSCAN timed out");
        ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
        return;
    }

    for ( ;; ) {
        u_char  *next;

        rc = ngx_http_cache_turbo_redis_fill(op, rev);
        if (rc == NGX_AGAIN) {
            return;
        }
        if (rc == NGX_ERROR) {
            ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
            return;
        }

        rc = ngx_http_cache_turbo_redis_frame_scan(op, &next);
        if (rc == NGX_AGAIN) {
            continue;                      /* read more before parsing */
        }
        if (rc != NGX_OK || next != op->rbuf + op->rlen) {
            /* One command owns this connection. Accepting a valid first frame
             * while ignoring trailing bytes would turn a desynchronised reply
             * into a successful purge enumeration. */
            ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
            return;
        }

        /* SSCAN's reply shape is byte-for-byte SCAN's: a 2-element array of
         * [ cursor bulk string, array of bulk strings ]. parse_scan is
         * therefore reused verbatim rather than duplicated -- it validates the
         * shape only and knows nothing about what the elements mean. */
        rc = ngx_http_cache_turbo_redis_parse_scan(op, &cursor, &members,
                                                   &nmembers);
        if (rc != NGX_OK) {
            ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
            return;
        }

        /* Drop this page NOW. walk == NULL marks it a page delivery: the
         * callback purges and returns NGX_DONE without touching the response.
         * Members point into op->rbuf and must not outlive this call, exactly
         * as del_many's keys must not outlive read_scan's.
         *
         * NGX_ERROR means the callback could NOT drop this page (only an
         * allocation failure can cause that). Abandon the walk rather than
         * continuing: carrying on would let the terminal call see cursor "0",
         * report a complete purge and delete the tag set key over members that
         * were never dropped -- silently unpurgeable, and exactly the
         * dishonesty the walk-status contract exists to prevent. scan_status
         * is already NGX_ERROR here (it only becomes NGX_OK at cursor "0"), so
         * the terminal call reports INCOMPLETE and keeps the key. */
        if (nmembers > 0) {
            ngx_int_t  prc;

            /* Publish this walk for the duration of the callback so it can
             * reach walk_suspend(). Cleared unconditionally on return: a walk
             * must never be suspendable from outside its own page delivery. */
            ngx_http_cache_turbo_redis_delivering = op;
            prc = op->members_cb(op->request, op->members_data, members,
                                 nmembers, NULL);
            ngx_http_cache_turbo_redis_delivering = NULL;

            if (prc == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                              "cache_turbo: L2 tag purge abandoned at SSCAN "
                              "page %ui: could not drop the page; purge is "
                              "INCOMPLETE", op->scan_pages + 1);
                ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
                return;
            }

            /* TODO-UNLINK-REPLY-WINDOW: NGX_AGAIN means the page callback has
             * launched an asynchronous sub-operation (the page's UNLINK) and
             * will not have finished handling this page until its reply lands.
             * Park the walk: save the cursor -- it points into op->rbuf, which
             * this function would otherwise rotate away underneath the pending
             * callback -- and return without advancing. The callback resumes us
             * through sscan_resume() with its verdict.
             *
             * A cursor longer than the buffer cannot come from Redis (cursors
             * are decimal u64 text, at most 20 bytes), but a desynchronised or
             * hostile reply could claim one, so it is rejected as a malformed
             * page rather than truncated into a cursor that would silently
             * restart or skip part of the walk. */
            if (prc == NGX_AGAIN) {
                /* NGX_AGAIN is only legal after a successful walk_suspend(),
                 * which is what sets op->suspended. A callback that returns it
                 * without suspending has parked a walk nothing will resume, so
                 * treat that as the abandoned page it really is rather than
                 * hanging the request until the read timeout. */
                if (!op->suspended) {
                    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                                  "cache_turbo: L2 tag purge abandoned at "
                                  "SSCAN page %ui: the page callback parked "
                                  "the walk without suspending it; purge is "
                                  "INCOMPLETE", op->scan_pages + 1);
                    op->scan_status = NGX_ERROR;
                    ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
                    return;
                }

                /* Save the cursor for the NEXT page. It points into op->rbuf,
                 * which sscan_advance rotates away, and the pending UNLINK's
                 * reply lands long after this stack frame is gone -- so the
                 * bytes must be COPIED somewhere that outlives the suspension.
                 * resume_cursor_buf is inline in the op struct, which lives in
                 * op->pool and is destroyed only by walk_finish, i.e. strictly
                 * after any resume.
                 *
                 * ⚠ DISARM THIS CONNECTION FIRST, before anything that can
                 * return. The write handler armed
                 * ngx_add_timer(c->read, op->timeout) when it finished sending
                 * this SSCAN, and nothing has deleted it. Left armed across the
                 * suspension it fires on its own schedule -- entirely unrelated
                 * to how long the UNLINK takes -- and re-enters read_sscan with
                 * rev->timedout, whose walk_finish destroys op->pool and
                 * finalizes the parked request while the UNLINK op still holds
                 * both. That is a use-after-free plus a double free of the page
                 * pool and a second finalize, fired from the event loop. A peer
                 * close does the same through a still-registered read event.
                 *
                 * ORDER IS THE WHOLE POINT. The UNLINK is already in flight by
                 * the time we get here -- the page callback suspends the walk
                 * and launches the delete before returning NGX_AGAIN -- so
                 * EVERY exit from this block leaves a pending completion
                 * holding this op, and every one of them must therefore leave
                 * the connection disarmed. An earlier revision rejected the
                 * oversized cursor BELOW this point and returned, which left
                 * the timer armed on exactly the path whose own comment
                 * explains why the walk must not be torn down. Anything added
                 * here that can return goes AFTER the disarm.
                 *
                 * The disarm is still the PRIMARY defence -- it is what stops
                 * the wakeup from ever being delivered -- but it is no longer
                 * the only one. ngx_del_event can refuse, so read_sscan opens
                 * with a `suspended` guard that makes a delivered wakeup inert.
                 * Neither replaces the other: the guard cannot stop the timer
                 * from firing spuriously for the whole UNLINK, and the disarm
                 * cannot be relied on to have succeeded.
                 *
                 * Disarming is also the honest accounting: redis_timeout bounds
                 * how long this connection may take to ANSWER, and time spent
                 * waiting on a different operation on a different connection is
                 * not that. sscan_advance re-arms it before the next page's
                 * write, so the bound applies to every page exactly as before.
                 */
                /* The disarm itself lives in walk_disarm_conn, shared with
                 * the request-teardown detach: both need the read timer gone
                 * and the read event off the poller, for the identical reason.
                 * sscan_advance puts the event back before the next page. */
                if (ngx_http_cache_turbo_redis_walk_disarm_conn(c) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                                  "cache_turbo: L2 tag purge abandoned: the "
                                  "SSCAN connection could not be disarmed for "
                                  "the suspension; purge is INCOMPLETE");
                    goto doomed;
                }

                /* Save the cursor for the NEXT page. A cursor longer than the
                 * buffer cannot come from Redis (cursors are decimal u64 text,
                 * at most 20 bytes), but a desynchronised or hostile reply
                 * could claim one. Reject it as a malformed page rather than
                 * truncating it into a DIFFERENT valid-looking cursor, which
                 * would silently restart the walk or skip an arbitrary span of
                 * the set. */
                if (cursor.len > sizeof(op->resume_cursor_buf)) {
                    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                                  "cache_turbo: L2 tag purge abandoned: SSCAN "
                                  "cursor of %uz bytes is not a cursor",
                                  cursor.len);
                    goto doomed;
                }

                ngx_memcpy(op->resume_cursor_buf, cursor.data, cursor.len);
                op->resume_cursor.data = op->resume_cursor_buf;
                op->resume_cursor.len = cursor.len;
                return;

            doomed:

                /* ⚠ Do NOT finish the walk here, and do NOT clear `suspended`.
                 * The page's UNLINK is ALREADY in flight and holds `op` as its
                 * completion data; walk_finish destroys op->pool, which `op`
                 * itself is allocated from, so finishing now would leave that
                 * pending completion pointing at freed memory -- a
                 * use-after-free fired from the event loop milliseconds later,
                 * strictly worse than the stranding this change exists to
                 * prevent. Clearing `suspended` is just as bad the other way:
                 * sscan_resume ignores a resume for an unsuspended walk, so it
                 * would drop the only call that can ever tear this walk down,
                 * leaking the op pool, the connection and the parked request
                 * for the life of the worker.
                 *
                 * Stay suspended and record the verdict. The resume is
                 * guaranteed to come -- del_many_cb fires its completion
                 * exactly once from every terminal path -- and sscan_resume
                 * sees resume_doomed and finishes the walk then, at which point
                 * nothing is in flight any more.
                 *
                 * The two callers share this label because they need the
                 * IDENTICAL handling, not because they share a precondition:
                 * the oversized-cursor caller reaches here with the connection
                 * already disarmed, while the disarm-FAILURE caller by
                 * definition does not. That asymmetry is why read_sscan opens
                 * with a `suspended` guard -- an event on a connection that
                 * could not be taken off the poller must not be allowed to
                 * finish this walk. */
                op->resume_doomed = 1;
                return;
            }
        }

        ngx_http_cache_turbo_redis_sscan_advance(op, cursor);
        return;
    }
}


/*
 * Walk teardown + resume, shared by the SSCAN tag walk and the SCAN-del
 * keyspace walk. Runs the policy callback ONE final time with no members and a
 * non-NULL walk outcome, so it produces the HTTP response; tears down the op
 * pool; then finalizes the parked request with the rc the callback returned.
 * Every failure path reaches here too, so the caller always gets a well-formed
 * response and always learns whether the walk completed.
 *
 * TODO-REDIS-PAGINATION: this used to be smembers_finish, the SINGLE call that
 * delivered the whole member set. The SSCAN walk delivers members per page from
 * read_sscan instead; this call is now purely terminal for it.
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
ngx_http_cache_turbo_redis_walk_finish(
    ngx_http_cache_turbo_redis_op_t *op, ngx_str_t *members,
    ngx_uint_t nmembers)
{
    ngx_http_request_t                     *r = op->request;
    ngx_http_cache_turbo_redis_members_pt   cb = op->members_cb;
    void                                   *data = op->members_data;
    ngx_http_cache_turbo_redis_walk_t       walk;
    ngx_int_t                               rc;

    /* CT-SSCAN-TERMINATE-LEAK: the request this walk was parked on is GONE --
     * walk_detach ran from r->pool's teardown. There is nothing to report the
     * walk outcome to and nothing to finalize: cb lives in the freed r->pool
     * and r is freed memory. Every remaining terminal path in this file routes
     * through here, so this ONE guard is what makes "a detached walk never
     * calls the callback and never finalizes a request" total -- and op_done
     * still runs, so the pool, the connection/fd and varidx_inflight are
     * released exactly as on any other terminal path. */
    if (op->detached) {
        /* The backoff classification is deliberately NOT consumed here. A
         * terminated request says nothing about whether the peer is healthy,
         * and arming the connect backoff off a client abort would penalize
         * every later L2 op in this worker for a fault Redis never had. Every
         * ATTACHED terminal below still consumes it, exactly as before. */
        (void) ngx_http_cache_turbo_redis_walk_disarm_conn(op->peer.connection);
        ngx_http_cache_turbo_redis_op_done(op);
        return;
    }

    /* Every successful/malformed reply passes through redis_fill(), which
     * clears unconnected on its first byte. A still-set flag here therefore
     * means the direct SMEMBERS/SCAN reader ended without any peer reply. */
    ngx_http_cache_turbo_redis_backoff_fail(op);

    /* Tell the callback HOW the bounded enumeration ended. For SCAN,
     * scan_status is NGX_OK only where the server returned cursor "0". For
     * SMEMBERS it is NGX_OK only after the exact reply parsed within its cap.
     * Every other terminal path stays non-OK and reports INCOMPLETE. */
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

    /* CT-SSCAN-TERMINATE-LEAK: this op is about to die, so its r->pool cleanup
     * must not survive it. Left registered, walk_detach would run at the
     * request's own teardown against an op whose pool this call destroys.
     * Neutralizing the handler is how the rest of this module cancels a pool
     * cleanup (purge.c does the same for the UNLINK await token); the cleanup
     * record itself belongs to r->pool and is released with it. */
    if (op->req_cln != NULL) {
        op->req_cln->handler = NULL;
        op->req_cln = NULL;
    }

    /* TODO-UNLINK-REPLY-WINDOW: deliver the REPLY outcome before anything is
     * torn down. Every terminal path of a drained op funnels here -- read_drain
     * calls op_done directly from all six of its returns, and a connect/send
     * failure reaches op_fail's else-arm, which calls op_done too -- so firing
     * from this one place is what makes the delivery EXACTLY-ONCE and total.
     * drain_done guards a re-entry that cannot happen today but would silently
     * double-report if a future path ever called op_done twice.
     *
     * The verdict is NGX_OK only when read_drain reached its clean-boundary
     * return (op->clean) AND no framed reply was a RESP `-ERR`. A timeout, a
     * peer close before the last reply framed, a malformed or oversized reply
     * and a write-path failure all leave clean == 0 and therefore report
     * NGX_ERROR. Treating a dropped connection as success is precisely the
     * silent-stranding bug this callback exists to close.
     *
     * The callback runs BEFORE the pool is destroyed, but it must not assume
     * anything it touches lives in op->pool -- its own data is the caller's. */
    if (op->drain_cb != NULL && !op->drain_done) {
        void  (*dcb)(void *, ngx_int_t) = op->drain_cb;
        void   *ddata = op->drain_data;
        ngx_int_t  drc = (op->clean && !op->drain_failed) ? NGX_OK : NGX_ERROR;

        op->drain_done = 1;
        dcb(ddata, drc);
    }

    /* COR5-PURGE-VARIDX-RACE: release this op's in-flight account. Every
     * completion AND every failure funnels through here -- read_drain's six
     * early returns all call op_done directly, and op_fail reaches its
     * op_done else-arm for a tag_add op (no members_cb, not is_lock, no parked
     * request). Decrementing here rather than in read_drain is what makes the
     * counter leak-proof: a timeout, a malformed reply or a peer close cannot
     * strand it non-zero and pin every later purge in this zone at
     * "complete":false. The one path that does NOT reach op_done -- a failed
     * launch -- undoes its own increment at the call site. */
    ngx_http_cache_turbo_redis_varidx_inflight_add(op, -1);
    op->counts_inflight = 0;

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
    if (result == NGX_ERROR) {
        ngx_http_cache_turbo_redis_backoff_fail(op);
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
    if (result == NGX_ERROR) {
        ngx_http_cache_turbo_redis_backoff_fail(op);
    }

    ctx->lock_result = result;
    ctx->lock_done = 1;

    ngx_http_cache_turbo_redis_op_done(op);

    ngx_http_core_run_phases(r);
    ngx_http_run_posted_requests(r->connection);
    ngx_http_finalize_request(r, NGX_DONE);
}


/* Terminal failure on the shared write path: dispatch by op kind. members_cb is
 * set for both SSCAN and SCAN (both finish through walk_finish); is_lock
 * distinguishes a lock from a GET (both pin op->request + op->ctx).
 *
 * S231: shared write failures consume the connect-failure classification here;
 * direct readers consume it through their op-specific finish. In either case,
 * op->unconnected is true iff no reply byte has ever been read on this
 * connection and no earlier terminal path has consumed it -- see the field
 * comment.
 * That is exactly "this fresh op never got a real answer from the peer", so
 * arm the backoff window. A reused (keepalive) connection is never
 * "unconnected" (op_create zeroes it, only _connect's fresh-connect branch
 * sets it), so its failures never arm backoff. Reply/protocol errors after a
 * first byte likewise cannot arm because that byte already cleared the flag. */
static void
ngx_http_cache_turbo_redis_op_fail(ngx_http_cache_turbo_redis_op_t *op)
{
    ngx_http_cache_turbo_redis_backoff_fail(op);

    if (op->members_cb) {
        ngx_http_cache_turbo_redis_walk_finish(op, NULL, 0);
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
    ngx_http_cache_turbo_redis_sscan,
    ngx_http_cache_turbo_redis_scan_del,
    ngx_http_cache_turbo_redis_lock,
    NULL,   /* unlock — PX expiry only */
};

#pragma GCC visibility pop
