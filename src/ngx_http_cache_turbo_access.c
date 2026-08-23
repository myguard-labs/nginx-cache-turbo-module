/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Access/precontent request-handling group (MAINT-SPLIT step F). Split out of
 * ngx_http_cache_turbo_module.c verbatim: the PURGE precontent handler, the
 * access handler and its request-shape/prologue gates, the blob-reference
 * pool cleanups, the breaker 503 responder, the full L1 phase (stale window,
 * request bounds, fresh/stale serve, breaker and stale-if-error arming), the
 * L2 phase (negative memo, GET, expired arm, promote-serve, miss accounting),
 * the only-if-cached, breaker and min-uses gates, and the cold-miss
 * single-flight machinery (resume, wait, timeout, winner marking, own-stub
 * adoption and the stub cleanup).
 *
 * This is the request HOT PATH and the module's main entry point.
 *
 * Handler registration. Unlike step E's filter chain, nothing mutable crosses
 * the TU boundary here: ngx_http_cache_turbo_init() in module.c only takes the
 * ADDRESS of the two phase handlers and pushes it into
 * cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers. So the two handlers simply
 * lose `static` and are declared in ngx_http_cache_turbo_internal.h; the pushes
 * stay exactly where and in the order they were. A filters.c-style *_init()
 * shim was considered and rejected -- it would add a call and an indirection
 * to buy encapsulation of two immutable function addresses, whereas step E's
 * shim existed to avoid exporting two MUTABLE next-filter pointers.
 *
 * Blob-reference cleanup. ngx_http_cache_turbo_blob_cln_t and its three
 * helpers (blob_cleanup, blob_ref_cleanup, brk_ref_drop) move here because
 * every arming call site is in this file. ngx_http_cache_turbo_serve(), which
 * stays in module.c, is the one remaining user: it registers blob_cleanup as a
 * pool cleanup handler and writes the record's two fields. The struct and
 * blob_cleanup are therefore declared in ngx_http_cache_turbo_internal.h. This
 * is a shared TYPE and a function address, not shared mutable module-scope
 * state -- every instance of the record is per-request pool memory, so there
 * is no cross-TU mutable global here.
 *
 * Export surface: three symbols lose `static` --
 * ngx_http_cache_turbo_access_handler, ngx_http_cache_turbo_precontent_handler
 * and ngx_http_cache_turbo_blob_cleanup. Eleven module.c helpers lose `static`
 * in the other direction so the moved code can still reach them:
 * ngx_http_cache_turbo_serve, ngx_http_cache_turbo_add_header,
 * ngx_http_cache_turbo_breaker_action, the seven request Cache-Control and
 * autotune helpers listed in the header, and ngx_http_cache_turbo_purge_request
 * (which refactor.md assigns to step G's _purge.c, so it stays in module.c
 * rather than widening this split's range). Every other function in the group
 * stays file-local static. No function in the moved range carried
 * `ngx_inline`, and none of the six newly exported symbols was inline either,
 * so no inlining qualifier had to be dropped and the hot path gains no call
 * that the compiler was previously required to inline.
 *
 * The UNIT-EXTRACT breaker-failure block stays wholly in module.c: this
 * split's range ends far above its BEGIN marker, so
 * ci/tests/unit/extract_shm.sh keeps slicing module.c unchanged. Its
 * breaker_action call-site sits in this file now, but no assertion in that
 * script targets that call site (the two call-site checks it does make are
 * against filters.c and the slice itself), so no retarget is needed.
 */

#include "ngx_http_cache_turbo_module.h"
#include "ngx_http_cache_turbo_internal.h"

/* Cold-miss single-flight helpers, defined at the tail of this file and called
 * from the access handler above them. Moved verbatim with their code from
 * ngx_http_cache_turbo_module.c (MAINT-SPLIT step F); they stay file-local
 * static -- no caller outside this TU. */
static ngx_int_t ngx_http_cache_turbo_cold_wait(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_ctx_t *ctx);
static void ngx_http_cache_turbo_cold_wait_timeout(ngx_event_t *ev);
static void ngx_http_cache_turbo_cold_wait_cleanup(void *data);
static void ngx_http_cache_turbo_cold_mark_winner(ngx_http_request_t *r,
    ngx_http_cache_turbo_ctx_t *ctx, ngx_http_cache_turbo_zone_t *z,
    uint64_t owner);
static void ngx_http_cache_turbo_cold_cleanup(void *data);
static ngx_int_t ngx_http_cache_turbo_cold_adopt_own_stub(
    ngx_http_request_t *r, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_cache_turbo_zone_t *z);



/* PURGE (v14) runs in the PRECONTENT phase, NOT the ACCESS phase. The ACCESS
 * phase (allow/deny, auth_basic, …) must complete first: handling PURGE in
 * ACCESS and returning NGX_DONE would short-circuit the phase engine and let an
 * unauthorized client purge the cache despite the documented allow/deny gate.
 * Precontent runs after access, so a 403 from allow/deny fires before we get
 * here. */
ngx_int_t
ngx_http_cache_turbo_precontent_handler(ngx_http_request_t *r)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);

    if (!clcf->enable || clcf->shm_zone == NULL || !clcf->purge) {
        return NGX_DECLINED;
    }

    if (r != r->main
        || r->method_name.len != sizeof("PURGE") - 1
        || ngx_strncmp(r->method_name.data, "PURGE", sizeof("PURGE") - 1) != 0)
    {
        return NGX_DECLINED;
    }

    return ngx_http_cache_turbo_purge_request(r, clcf);
}


/*
 * MAINT-SEAM: the request-shape eligibility gates that run before any cache
 * state is touched. Pure predicate over (r, clcf) -- no ctx, no zone, no
 * allocation, no side effects -- so it re-evaluates identically on a parked
 * L2/lock resume, exactly as the inline run of early returns did.
 *
 * NGX_OK = this request may proceed to the engaged path; NGX_DECLINED = the
 * caller declines. Split out of access_prologue() to keep the prologue's
 * branching about cache state rather than about request shape.
 */
static ngx_int_t
ngx_http_cache_turbo_access_eligible(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf)
{
    if (!clcf->enable || clcf->shm_zone == NULL) {
        return NGX_DECLINED;
    }

    /* PURGE is handled by the preceding PRECONTENT handler. Both handlers run
     * after ACCESS so cache hits cannot bypass allow/deny or auth modules. */

    /* Only cache safe idempotent reads for v1. */
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }

    if (r != r->main) {
        /* subrequest (e.g. our own background refresh) — never serve from
         * cache, let it hit the origin and repopulate. A warm subrequest (v3-3)
         * builds its key + captures in the header/body filters. */
        return NGX_DECLINED;
    }

    /* RFC 9111 shared-cache safety: do not reuse a public representation for a
     * request carrying credentials. response_cacheable() already prevents the
     * resulting response from being stored; this is the matching lookup gate.
     *
     * P0-1: this early return means ctx is NEVER allocated for an
     * Authorization request (see access_prologue() below), so the header
     * filter bails on `ctx == NULL` before response_cacheable()'s own
     * AUTHORIZATION reason can ever fire on the ordinary capture path --
     * that arm only protects an unusual caller that reaches
     * response_cacheable() with a ctx already in hand (a warm subrequest,
     * say). This IS the reachable site for the request-side refusal, so the
     * counter is bumped HERE, not in the header filter.
     *
     * P3-4: cache_turbo_serve_authorized (off by default) lifts THIS gate
     * only -- the credentialed request proceeds to the lookup and may be
     * served an existing entry. It does NOT touch the store floor: the
     * Authorization arm of response_cacheable() is that function's first
     * test, ungated by any directive, and ctx->captured (the sole gate on the
     * body filter's store) is only set when response_cacheable() returns
     * true. So every blob that exists was written by a request carrying NO
     * credentials, and relaxing the read side cannot expose one principal's
     * response to another -- no such response is ever stored.
     *
     * RFC 9111 SS3.5 needs more than anonymity of the stored copy: reuse FOR
     * an authenticated request additionally requires the response to have
     * authorised it (public / s-maxage / must-revalidate). That is enforced
     * at the serve chokepoint against BLOBF_AUTH_SHAREABLE, stamped at store
     * -- not here, because at this point no entry has been looked up yet.
     *
     * With the directive ON, ctx now IS allocated for an Authorization
     * request, so the header filter no longer bails on ctx == NULL and
     * response_cacheable()'s AUTHORIZATION arm becomes the reachable
     * refusal site for the STORE -- which is exactly why the counter bump
     * stays behind the !serve_authorized guard here: filters.c's
     * capture_count_refusal() attributes it instead, and counting it in both
     * places would double-count a single request. */
    if (r->headers_in.authorization != NULL && !clcf->serve_authorized) {
        if (clcf->shm_zone != NULL) {
            ngx_http_cache_turbo_zone_t  *rz = clcf->shm_zone->data;

            (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(rz)->refuse_authorization, 1);
        }
        return NGX_DECLINED;
    }

    return NGX_OK;
}


/*
 * CQ-2: prologue gates + per-request setup shared by every (re)entry of the
 * access handler (a parked L2/lock resume re-enters the handler, so this runs
 * again — build_key/auto-classify/no-cache/vary/bypass all re-evaluate, exactly
 * as before the extraction). Returns NGX_OK with ctxp/zp/hashp populated when
 * the caller should proceed to the L1 lookup; any other value is what the
 * handler must return (NGX_DECLINED for the not-cacheable/skip/bypass gates,
 * NGX_ERROR on ctx alloc / key build failure).
 */
static ngx_int_t
ngx_http_cache_turbo_access_prologue(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_http_cache_turbo_ctx_t **ctxp, ngx_http_cache_turbo_zone_t **zp,
    uint32_t *hashp)
{
    uint32_t                      hash;
    ngx_http_cache_turbo_ctx_t   *ctx;
    ngx_http_cache_turbo_zone_t  *z;

    if (ngx_http_cache_turbo_access_eligible(r, clcf) != NGX_OK) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_cache_turbo_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_cache_turbo_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_cache_turbo_module);
    }

    if (ngx_http_cache_turbo_build_key(r, clcf, ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Q1: cache-turbo is engaged for this request (enabled, cacheable method,
     * main request). The $cache_turbo_active variable reads this (gated by
     * cache_turbo_suppress_native) so a stacked native proxy_cache can defer.
     * Set before the bypass check on purpose: a bypassing request still stores
     * the fresh response, so native should defer to us on that path too. */
    ctx->ct_active = 1;

    z = clcf->shm_zone->data;
    hash = ngx_crc32_short(ctx->key_hash, 32);

    /* Auto-classify (cache_turbo auto / cache_turbo_backend): a curated union of
     * CMS cacheability heuristics. When the request matches a dynamic surface of
     * an active preset (login/session cookie, backend URI, dynamic arg) skip the
     * cache entirely — go to the origin and never capture (ctx->auto_skip vetoes
     * the body filter). Sits under the manual bypass/no_store overrides below.
     * honor_cc is auto-enabled with a preset so a plugin's own Cache-Control:
     * no-cache on an anon page self-excludes at store time. */
    /*
     * S232-BYPASS-STALE: an opted-in URI bypasses the LOOKUP exactly like the
     * arm below -- a stored breaker-only copy must never answer a normal
     * request -- but takes its own arm so capture is NOT vetoed, leaving a body
     * for the breaker to fall back on. Checked FIRST: this directive is the
     * operator naming these URIs explicitly, so it wins over an auto-classify
     * heuristic that would otherwise silently drop the fallback. It does NOT
     * override a manual cache_turbo_bypass predicate -- that check runs later
     * and still returns DECLINED without capture, so an operator's explicit
     * "never cache this" is never reinterpreted by this directive.
     */
    if (ngx_http_cache_turbo_bypass_stale_uri_match(r, clcf)) {
        ctx->brk_only = 1;

        /*
         * OPEN => fall through instead of declining, the same shape as the
         * request-revalidate gate below (see its comment for why falling
         * through is the whole mechanism rather than a shortcut). Declining
         * unconditionally here is what the first revision did, and it made the
         * feature inert: the breaker ARMS from the expired-entry site inside
         * the lookup, so a request that never reaches the lookup arms nothing
         * and the gate has no fallback to serve -- the stored copy existed and
         * the client still got the breaker's 503.
         *
         * Falling through is safe precisely because the stored blob carries
         * BLOBF_BREAKER_ONLY: the lookup may now find it, but the enforcement
         * in ngx_http_cache_turbo_serve() refuses it on every path except the
         * breaker's own STALE-BREAKER serve. So an OPEN breaker gets the
         * fallback while a normal hit still cannot happen.
         *
         * CLOSED (or breaker disabled) keeps the plain bypass: decline to the
         * origin without a lookup, which is the pre-existing behaviour for
         * these URLs and what the CLOSED-breaker negative control pins.
         */
        if (ngx_http_cache_turbo_breaker_should_consult(clcf)
            && ngx_http_cache_turbo_brk_state(ngx_http_cache_turbo_zone_sh(z)->breaker_state)
                   == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN)
        {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: bypass-stale \"%V\" + breaker OPEN "
                           "-> lookup for a breaker-only fallback", &r->uri);

        } else {
            /* Engaged: unlike the auto_skip arm we DO store, so a stacked
             * native cache must keep deferring to us on this URL. */
            ctx->status = NGX_HTTP_CACHE_TURBO_ST_BYPASS;
            (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->misses, 1);
            (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->bypasses, 1);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: bypass-stale \"%V\" -> origin "
                           "(breaker-only store)", &r->uri);
            return NGX_DECLINED;
        }
    }

    if ((NGX_HTTP_CACHE_TURBO_HAS_BACKEND(clcf->backend_presets)
         && ngx_http_cache_turbo_auto_skip(r, clcf))
        || ngx_http_cache_turbo_bypass_uri_match(r, clcf))
    {
        ctx->auto_skip = 1;
        /* cache-turbo neither serves nor stores an auto-classified dynamic
         * request, so it is NOT "engaged": leave $cache_turbo_active = 0 so a
         * stacked native cache is free to handle the URL itself. */
        ctx->ct_active = 0;
        ctx->status = NGX_HTTP_CACHE_TURBO_ST_BYPASS;
        (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->misses, 1);
        (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->bypasses, 1);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: auto-classify dynamic \"%V\" -> origin",
                       &r->uri);
        return NGX_DECLINED;
    }

    /* RFC-1 request Cache-Control, parsed once here for the whole request:
     * only-if-cached gates the origin-bound miss paths below (-> 504), no-store
     * vetoes capture in the header filter. */
    ctx->req_only_if_cached = ngx_http_cache_turbo_request_only_if_cached(r, ctx);
    ctx->req_no_store = ngx_http_cache_turbo_request_no_store(r, ctx);
    ngx_http_cache_turbo_request_freshness_bounds(r, ctx);

    /* Request Cache-Control: no-cache / Pragma: no-cache / max-age=0 (RFC 9111
     * §5.2.1.1/§5.2.1.4): do not reuse a stored response without validation.
     * With no validation channel for a hit, skip the lookup and go to the
     * origin — the fresh response still stores (refreshing the entry), like a
     * bypass. With only-if-cached the client refuses origin contact and we
     * cannot validate, so the answer is 504 (RFC 9111 §5.2.1.7).
     *
     * S231-NOCACHE-OUTAGE: that "skip the lookup" shortcut assumes the origin
     * is reachable to actually perform the revalidation. When the breaker for
     * this zone is already OPEN, taking it anyway would force every no-cache
     * request straight past a serveable stale copy and onto an origin we
     * already know is down -- exactly the stampede the breaker exists to
     * prevent. Read the breaker state RAW (ngx_http_cache_turbo_brk_state on
     * the shm word), the same pattern the only-if-cached breaker-serve site
     * above^ uses, rather than through _breaker_state(): that call is not a
     * pure getter, it performs the due OPEN -> HALF_OPEN promotion, and this
     * is not the place to spend it (the promoted probe must be the request
     * that reaches the pre-origin breaker gate below, not this early exit).
     * should_consult() is a plain config check (enabled/threshold/window),
     * so it's free to call unconditionally here.
     *
     * OPEN => fall through instead of declining. This is deliberately placed
     * BEFORE auto-Vary resolve (:4762 below) and the cache lookup: falling
     * through here means the request runs the EXACT SAME vary-resolve ->
     * L1/L2 lookup -> pre-origin breaker gate path as any other request, so
     * the variant key is resolved before any lookup happens (no separate
     * probe is added at this gate), and the existing breaker gate at the
     * lookup's end serves ctx->brk_snap under STALE-BREAKER when armed, or
     * falls through to the origin unchanged when nothing is armed for this
     * key. A stale-if-error window is handled the same way for free: SIE
     * only ever fires as a post-origin-failure fallback (sie_rewrite, called
     * from the upstream error path), so it never needed a pre-check here --
     * letting the request reach the origin normally is exactly what lets
     * sie_armed / sie_rewrite catch a failing revalidation, same as it does
     * for any other request today. CLOSED (or breaker disabled) takes the
     * original NGX_DECLINED unchanged -- today's behaviour, verified by a
     * negative-control test. */
    if (ngx_http_cache_turbo_request_revalidate(r, ctx)) {
        ngx_uint_t  brk_open_now;

        brk_open_now = ngx_http_cache_turbo_breaker_should_consult(clcf)
            && ngx_http_cache_turbo_brk_state(ngx_http_cache_turbo_zone_sh(z)->breaker_state)
                   == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN;

        if (ctx->req_only_if_cached) {
            /* Nothing serveable without origin contact the client forbids:
             * a cache miss from the client's view ($cache_turbo_status MISS,
             * the pcalloc default). EXPIRED is reserved for the case where we
             * DID find a cached entry but it was past its serveable window. */
            (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->misses, 1);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: request revalidate + only-if-cached "
                           "\"%V\" -> 504", &r->uri);
            return NGX_HTTP_GATEWAY_TIME_OUT;
        }

        if (brk_open_now) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: request no-cache + breaker OPEN "
                           "\"%V\" -> honour cache", &r->uri);
        } else {
            (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->misses, 1);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: request no-cache \"%V\" -> origin "
                           "(revalidate)", &r->uri);
            return NGX_DECLINED;
        }
    }

    /* auto-Vary (v11 other half), lock-free half only (S231-PERF-VARYLOCK):
     * precompute the marker key bytes for this base key. The lock-holding
     * marker LOOKUP + key_hash recompute now happens in access_handler,
     * folded into the same critical section as the main L1 lookup, so it no
     * longer pays a separate zone-mutex acquisition here. No marker (or
     * auto_vary off) => key_hash stays the base key, same as before.
     *
     * C3: deliberately NOT gated on the zone's `markers` presence counter,
     * unlike the lock-held lookup in access_l1() below. ctx->vary_marker_key
     * is not just an input to that lookup -- ngx_http_cache_turbo_access_l2_
     * marker_get() (P3-5's L2-backed marker consult) reads it directly to
     * build the L2 GET key, and that consult is exactly what a zone with ZERO
     * locally-resident L1 markers (cold node: fresh boot, or every marker
     * LRU-evicted) needs to fall back to -- a peer node may have classified
     * and stored this base URL's marker in L2 independently of what THIS
     * node's L1 currently holds. Gating this call the same way would leave
     * vary_marker_key zeroed, silently defeating that cross-node fallback for
     * as long as `markers` reads 0 on this node. This call is cheap (a single
     * digest over already-computed key bytes, no lock, no shm read), so
     * nothing is bought by gating it. */
    if (clcf->auto_vary) {
        ngx_http_cache_turbo_vary_prepare(ctx);
    }

    /* Bypass (v9): when a cache_turbo_bypass predicate trips, skip the cache
     * lookup entirely and go to the origin — but still let the filters store the
     * fresh response (so a bypassing request refreshes the entry). The key was
     * built above so the body filter stores under the right slot. */
    if (clcf->bypass != NULL
        && !ctx->l2_done && !ctx->lock_done
        && ngx_http_test_predicates(r, clcf->bypass) != NGX_OK)
    {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: bypass \"%V\" key=%ui -> origin",
                       &r->uri, (ngx_uint_t) hash);
        (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->misses, 1);
        (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->bypasses, 1);
        ctx->status = NGX_HTTP_CACHE_TURBO_ST_BYPASS;
        return NGX_DECLINED;
    }

    /* Live autotune (v4-3): throttled per-zone recompute of the beta verdict from
     * the window's stats. Cheap to call every request (one time compare on the
     * fast path); the heavy recompute runs at most once per interval per worker.
     * Takes the zone mutex itself, so call it before we lock below. */
    if (clcf->autotune) {
        ngx_http_cache_turbo_autotune_maybe(z,
            NGX_HTTP_CACHE_TURBO_AT_INTERVAL);
    }

    *ctxp = ctx;
    *zp = z;
    *hashp = hash;
    return NGX_OK;
}


/* PERF-7: request-pool cleanup that drops a zero-copy serve's blob reference once
 * the response has been fully sent (pool destroy happens after the output chain
 * drains). `z` + `data` identify the blob; the slab is freed here only if the
 * owning node already detached it (evict/refresh/purge raced the serve). */
/* The struct itself now lives in ngx_http_cache_turbo_internal.h: module.c's
 * ngx_http_cache_turbo_serve() registers this handler and fills the record's
 * two fields, so both TUs need the layout. */

void
ngx_http_cache_turbo_blob_cleanup(void *data)
{
    ngx_http_cache_turbo_blob_cln_t  *c = data;

    /* O4.3-c: c->data == NULL means the reference was already dropped early --
     * see the breaker gate, which releases a fallback nothing can consume once
     * its verdict is known. Pool cleanups cannot be unregistered, so disarming
     * one is exactly this: clear the payload and let it run as a no-op. */
    if (c->data == NULL) {
        return;
    }

    ngx_http_cache_turbo_blob_release(c->z, c->data);
    c->data = NULL;
}


/* P6/O4.3, S231-PERF-SIEARM: register the pool cleanup that drops an armed
 * blob's slab reference. Shared by the circuit-breaker arm and the SIE arm --
 * both pin a blob under the zone mutex (PERF-7 style) instead of copying it,
 * but UNLIKE the serve paths neither yet knows whether the blob will ever be
 * sent: most armed requests never consume their fallback (breaker: the gate
 * stays CLOSED; SIE: the origin revalidation does not come back 5xx). So the
 * reference is dropped by a cleanup tied to the REQUEST POOL rather than to a
 * serve call, which covers both outcomes with one drop.
 *
 * ⚠ That is also why the breaker's and SIE's own _serve()/restore call sites
 * never pass this same data as a second ref_data. A second cleanup for the
 * same blob would double-drop the refcount and free a slab still in use
 * elsewhere.
 *
 * Returns NGX_ERROR when the cleanup cannot be registered. Both callers run
 * this BEFORE ngx_http_cache_turbo_blob_acquire() precisely so that failure
 * path owns nothing: no reference has been taken yet, so the caller arms
 * nothing and releases nothing. A future caller that acquires first would have
 * to release here -- and could not, because blob_release() takes the zone mutex
 * the arming sites already hold. Keep the order.
 */
static ngx_int_t
ngx_http_cache_turbo_blob_ref_cleanup(ngx_http_request_t *r,
    ngx_http_cache_turbo_zone_t *z, u_char *data,
    ngx_http_cache_turbo_blob_cln_t **out)
{
    ngx_pool_cleanup_t               *cln;
    ngx_http_cache_turbo_blob_cln_t  *cc;

    cln = ngx_pool_cleanup_add(r->pool,
              sizeof(ngx_http_cache_turbo_blob_cln_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_cache_turbo_blob_cleanup;
    cc = cln->data;
    cc->z = z;
    cc->data = data;

    /* O4.3-c: hand the record back so the caller can drop the reference early
     * (see ngx_http_cache_turbo_brk_ref_drop). Optional -- pass NULL when the
     * pool-lifetime drop is all that is wanted (the SIE arm does this). */
    if (out != NULL) {
        *out = cc;
    }

    return NGX_OK;
}


/*
 * O4.3-c: drop a breaker fallback's slab reference NOW rather than at request
 * teardown, and disarm the pool cleanup that would otherwise drop it again.
 *
 * Called once the gate's verdict rules out a fallback serve. Idempotent, and
 * safe to call with nothing armed. See ctx->brk_cln for why holding the pin to
 * pool destruction is a reclamation hazard.
 */
static void
ngx_http_cache_turbo_brk_ref_drop(ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_cache_turbo_zone_t *z)
{
    ngx_http_cache_turbo_blob_cln_t  *cc = ctx->brk_cln;

    /* Only an L1 arming holds a slab reference. An L2 arming points at
     * ctx->l2_blob, which lives in r->pool and needs no release -- but it must
     * still be disarmed below, or this function is idempotent for one arming
     * source and not the other. */
    if (cc != NULL && cc->data != NULL) {
        ngx_http_cache_turbo_blob_release(z, cc->data);

        /* Disarm: the cleanup still runs at pool destruction, as a no-op. */
        cc->data = NULL;
    }

    ctx->brk_cln  = NULL;
    ctx->brk_ref  = NULL;
    ctx->brk_snap = NULL;
    ctx->brk_snap_len = 0;
    ctx->brk_armed = 0;
}


/*
 * P6/O4.3: answer a request the OPEN breaker refuses to forward and for which
 * no cached body of any age exists. 503 + Retry-After, generated locally with
 * no origin contact.
 *
 * ⚠ Finalizes and returns NGX_DONE, exactly like ngx_http_cache_turbo_serve().
 * This runs in the ACCESS phase, so returning the output filter's rc (or a bare
 * NGX_HTTP_SERVICE_UNAVAILABLE) would let the phase engine finalize a second
 * time on a request this function has already sent a body for. NGX_DONE is what
 * stops the engine here.
 *
 * On a HEAD the shared sender returns after ngx_http_send_header() via
 * r->header_only, so the headers -- Content-Length included -- are emitted with
 * no body. That is the correct HEAD representation per RFC 9110 §9.3.2
 * (identical fields to the GET, body omitted), not a framing bug; nginx knows
 * the response is body-less and keeps the connection in sync.
 *
 * Retry-After is advisory to the client and deliberately does NOT feed back
 * into the breaker's own timing: the breaker reopens on ITS schedule
 * (breaker_open), and a client that ignores the hint simply gets another 503.
 * Emitting the operator's configured value rather than the breaker's remaining
 * open time also avoids leaking the zone's internal state to every visitor.
 */
static ngx_int_t
ngx_http_cache_turbo_breaker_unavailable(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf)
{
    ngx_int_t                    rc;
    u_char                      *ra;
    size_t                       ra_len;
    time_t                       retry_after;
    ngx_http_cache_turbo_ctx_t  *ctx;
    ngx_str_t                    body = ngx_string("503 Service Unavailable\n");

    static u_char  ra_name[] = "Retry-After";
    static u_char  xc_name[] = "X-Cache";
    static u_char  xc_val[]  = "BREAKER-503";

    /* BRK-RA1: breaker_retry_after can now legitimately be NGX_CONF_UNSET
     * (nobody set it anywhere, at any level) because the config-time merge
     * no longer defaults it to breaker_open -- see the merge note above.
     * Resolve the effective value here instead: an explicit, set value
     * (!= NGX_CONF_UNSET) always wins, including an explicit 0 (which means
     * "send no Retry-After"); otherwise fall back to this location's fully
     * merged, request-scoped breaker_open. clcf is complete by request time,
     * so this lazy resolution needs no merge-order care at all. */
    retry_after = (clcf->breaker_retry_after != NGX_CONF_UNSET)
                  ? clcf->breaker_retry_after
                  : clcf->breaker_open;

    /* ⚠ Both headers go through ngx_http_cache_turbo_add_header() rather than a
     * bare ngx_list_push(). The helper also sets h->next = NULL on nginx 1.23+,
     * where repeated response headers form a linked chain rather than being
     * merged: a ngx_list_push() slot comes back with whatever the pool last
     * held, so an unset `next` is a dangling pointer that a downstream module
     * walking the chain will follow. */
    if (retry_after > 0) {
        ra = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
        if (ra == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ra_len = ngx_sprintf(ra, "%T", retry_after) - ra;

        if (ngx_http_cache_turbo_add_header(r, ra_name,
                sizeof("Retry-After") - 1, ra, ra_len) != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* Flag the reason the same way every other serve path does, so a log format
     * carrying X-Cache can tell a breaker 503 from an origin one. */
    if (ngx_http_cache_turbo_add_header(r, xc_name, sizeof("X-Cache") - 1,
            xc_val, sizeof("BREAKER-503") - 1) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* ⚠ Mark the request served BEFORE sending. Two things depend on it:
     *
     * 1. The body filter must not try to CAPTURE this 503 into the cache. It is
     *    our own locally generated response, not an origin body.
     * 2. The O4.2 recording site in the header filter early-returns on
     *    ctx->served, which is exactly right here: a breaker 503 never touched
     *    the origin, so counting it would let the breaker feed its OWN refusals
     *    back in as origin failures and hold itself open forever. (The
     *    r->upstream == NULL arm of _breaker_from_origin() already excludes it
     *    independently -- this is the second of the two guards, not the only
     *    one.)
     *
     * $cache_turbo_status is deliberately left at its default (MISS): the
     * existing status ids have no value meaning "refused without contacting the
     * origin", so this path leaves it alone. $cache_turbo_serve_reason (S7.2)
     * DOES record it, as SR_BREAKER_503 -- that variable exists precisely for
     * outcomes status's HIT/STALE/BYPASS/EXPIRED/MISS enum has no slot for. */
    ctx = ngx_http_get_module_ctx(r, ngx_http_cache_turbo_module);
    if (ctx != NULL) {
        ctx->served = 1;
        ctx->serve_reason = NGX_HTTP_CACHE_TURBO_SR_BREAKER_503;
    }

    rc = ngx_http_cache_turbo_send_body(r, NGX_HTTP_SERVICE_UNAVAILABLE, &body,
             "text/plain", sizeof("text/plain") - 1);

    ngx_http_finalize_request(r, rc);
    return NGX_DONE;
}




/* MAINT-H2 phase helper for ngx_http_cache_turbo_access_handler().
 * PHASE 1 -- the L1 critical section, extracted whole.
 *
 * ⚠ LOCK WINDOW: this helper takes the zone mutex on its FIRST line and every
 * exit path releases it before returning, exactly as the inline block did.
 * The mutex is never held across the helper boundary in either direction, so
 * no lock or unlock moved relative to any pointer that crosses it. The 9 lock
 * operations of this phase (1 lock + 8 unlocks) are all inside this function.
 *
 * ⚠ BREAKER ORDERING (#281): the circuit breaker ARMS from the expired-entry
 * site INSIDE this lookup, and the arming site's position relative to the
 * lookup, the vary_apply() key rewrite and the fresh/stale serve arms is
 * unchanged -- the whole span from ngx_shmtx_lock() to ngx_shmtx_unlock()
 * moved as ONE contiguous block with no reordering and no guard hoisted out.
 * The caller invokes this helper at exactly the point the inline code ran,
 * immediately after the prologue returns NGX_OK, so WHEN the lookup is
 * reached is bit-identical.
 *
 * `hash` is in/out: ngx_http_cache_turbo_vary_apply() may rewrite it to the
 * variant key that the lookup below must use, and the L2 phase's log lines
 * and l2_neg_set() key must see the rewritten value -- hence a pointer, not
 * a by-value copy.
 *
 * Returns NGX_DECLINED to mean "fall through to the L2 phase" (the inline
 * fall-through past the final unlock); NGX_DONE means this phase produced the
 * handler's return value, which it wrote to *out_rc. */
/* MAINT-H4d phase helper for ngx_http_cache_turbo_access_l1().
 * v4-4 load-adaptive stale window: widen ONLY the local `*stale_until` by the
 * autotune load factor when under sustained backend load. Pure computation,
 * no lock ops of its own -- always called while the caller already holds
 * z->shpool->mutex (it reads z's autotune state), and it must run before the
 * caller's serve/refresh-dice decisions, which is why it stays a plain
 * in/out helper rather than something the caller could defer. */
static void
ngx_http_cache_turbo_access_l1_stale_window(ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_http_cache_turbo_zone_t *z, time_t fresh_until, time_t *stale_until)
{
    if (*stale_until != 0 && clcf->autotune) {
        ngx_int_t  load = ngx_http_cache_turbo_effective_load(clcf, z);

        if (load > NGX_HTTP_CACHE_TURBO_AT_LOAD_BASE) {
            time_t  win = *stale_until - fresh_until;   /* stored stale span */

            if (win > 0) {
                *stale_until += win
                    * (load - NGX_HTTP_CACHE_TURBO_AT_LOAD_BASE)
                    / NGX_HTTP_CACHE_TURBO_AT_LOAD_BASE;
            }
        }
    }
}



/* MAINT-H4d phase helper for ngx_http_cache_turbo_access_l1().
 * RFC-1 request freshness bounds (max-age / min-fresh / max-stale): an
 * existing entry may be unacceptable to THIS client even when the cache
 * would serve it. Sets fresh_ok / stale_ok (out-params) and ctx->req_reval.
 * Pure computation, no lock ops -- always called while the caller holds the
 * zone mutex, purely to read ctn->data (already resolved by the caller). */
static void
ngx_http_cache_turbo_access_l1_req_bounds(ngx_http_request_t *r,
    ngx_http_cache_turbo_ctx_t *ctx, ngx_http_cache_turbo_node_t *ctn,
    time_t now, time_t fresh_until, time_t stale_until,
    ngx_int_t *fresh_ok, ngx_int_t *stale_ok)
{
    /* P2: only run the request-freshness-bounds verdict when the client
     * actually sent max-age/min-fresh/max-stale. With none set,
     * req_serve_verdict returns fresh_ok=stale_ok=1 unconditionally, so
     * the block below can never set req_reval — pure dead work on the
     * common (no request CC) hot path. only-if-cached is unaffected: it
     * is gated at :2998/:3511, not here.
     * len > 0 implies data != NULL (a real entry always has both; a
     * stub/counter node is len == 0) — the serve blocks below already
     * rely on this when they memcpy ctn->data. */
    if (!(ctx->has_req_bounds && ctn->len > 0)) {
        return;
    }

    {
        time_t  created = (time_t)
            ngx_http_cache_turbo_get_u64(ctn->data + 24);
        ngx_int_t  in_window = (now < fresh_until)
            || (stale_until == 0 || now < stale_until);

        ngx_http_cache_turbo_req_serve_verdict(ctx, created, now,
            fresh_until, fresh_ok, stale_ok);

        if (in_window
            && !((now < fresh_until) && *fresh_ok)
            && !(((stale_until == 0) || now < stale_until) && *stale_ok))
        {
            ctx->req_reval = 1;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "cache_turbo: entry fails request freshness bounds "
                "\"%V\" -> revalidate", &r->uri);
        }
    }
}



/* COR-5(b): re-issue an auto-Vary variant-index SADD that was dropped before
 * the wire at store time (see ngx_http_cache_turbo_node_t.varidx_pending).
 *
 * ⚠ MUST be called with z->shpool->mutex NOT held. access_l1() only CONSUMES
 * the node bit under the mutex and records it in ctx->varidx_reissue; the
 * actual re-issue allocates a pool and may connect(), so every terminal arm
 * calls this after its own unlock.
 *
 * Still fire-and-forget and still off the blocking path: tag_add() returns as
 * soon as the op is handed to (or refused by) the transport, so a HIT never
 * waits on Redis. If the re-issue is dropped AGAIN the bit is put back, and
 * the next hit retries -- during an outage the S231 backoff check short-
 * circuits before any connect(), so a retry costs a function call.
 *
 * ctx->cache_key is the BASE key on every path that reaches here (build_key()
 * resets it each entry and only key_hash is ever rewritten to the variant),
 * which is exactly what variant_index_name() must digest, and ctx->key_hash
 * is the variant's L2 key -- the same pair the store site used. */
static void
ngx_http_cache_turbo_varidx_reissue(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_cache_turbo_zone_t *z, uint32_t hash)
{
    u_char  vname[1 + 64];
    size_t  vlen;
    time_t  ttl;

    if (!ctx->varidx_reissue) {
        return;
    }

    ctx->varidx_reissue = 0;               /* consume: one detection, one try */

    if (clcf->backend == NULL || clcf->backend->tag_add == NULL) {
        return;
    }

    /* TTL = the node's OWN remaining physical retention, captured with the
     * pending bit under the mutex (ctx->varidx_reissue_ttl). The index entry
     * must outlive the body it names -- an index that expires first re-opens
     * the exact hole this heals -- and the set's TTL only ever GROWS
     * (EXPIRE NX/GT, COR-8), so this can never shorten a set seeded by some
     * other variant. A node with no expiry (stale_until == 0) falls back to
     * the location's stale-window default, since an unbounded index set is
     * not an option. */
    ttl = ctx->varidx_reissue_ttl;
    if (ttl <= 0) {
        ttl = ngx_http_cache_turbo_stale_ttl(clcf->valid, clcf->stale_mult);
    }
    if (ttl <= 0) {
        ttl = 1;
    }

    vlen = ngx_http_cache_turbo_variant_index_name(&ctx->cache_key, vname);

    if (clcf->backend->tag_add(clcf, ctx->key_hash, vname, vlen, ttl)
        != NGX_OK)
    {
        /* Dropped again -- re-arm so a later hit retries. */
        ngx_http_cache_turbo_shm_varidx_pending_set(z, ctx->key_hash, hash, 1);
        return;
    }

    /* c-1: unconditional, same as the drops counter in filters.c -- the
     * PURGE reply's "complete":false decision depends on this counter
     * catching up to varidx_drops in production, not only under
     * NGX_HTTP_CACHE_TURBO_TEST_FAULTS. */
    (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->varidx_reissues, 1);

    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
        "cache_turbo: auto-vary variant index re-issued for \"%V\" "
        "after an earlier dropped write", &r->uri);
}


/* MAINT-H4d phase helper for ngx_http_cache_turbo_access_l1().
 * PHASE -- the fresh-HIT serve arm (S232-BYPASS-STALE already routed
 * ctx->brk_only away before the caller reaches here).
 *
 * ⚠ LOCK WINDOW: entered with z->shpool->mutex HELD (the caller's lock from
 * the lookup above); this helper is the one that unlocks it, then pins the
 * blob with a refcount BEFORE unlocking (ngx_http_cache_turbo_blob_acquire),
 * so the pointer handed to serve() stays valid across the unlock -- eviction
 * or refresh by any other worker after the unlock only drops the shared
 * slab slot, never this ref. Always terminal (NGX_DONE): the caller must not
 * touch the mutex or `ctn` again after this returns. */
static ngx_int_t
ngx_http_cache_turbo_access_l1_serve_fresh(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_cache_turbo_zone_t *z, ngx_http_cache_turbo_node_t *ctn,
    time_t now, uint32_t hash, ngx_int_t *out_rc)
{
    /* PERF-7 fresh hit: serve the blob DIRECTLY out of shm (zero-copy).
     * Pin it with a reference under the mutex we already hold; the serve
     * path registers a pool cleanup that drops the ref once the response
     * has drained, so eviction/refresh by any worker is safe meanwhile. */
    u_char *body = ctn->data;
    size_t  body_len = ctn->len;
    ngx_http_cache_turbo_blob_acquire(body);
    /* True LRU: promote this node to the head on access, so eviction
     * targets the genuinely least-recently-used entry (not the oldest by
     * insertion/refresh). P1: coarse-gate the splice — skip the LRU WRITE
     * when this node was already spliced within the last second, so a
     * hot key serializes readers on the mutex at most once/second. */
    /* S8: shared promote-on-second-hit helper; also applies the P1
     * 1s coarse gate internally. clcf->scan_resistant_pct == 0 (the
     * default) makes this a plain probation re-head. */
    ngx_http_cache_turbo_shm_touch_lru(z, ctn, now,
                                       clcf->scan_resistant_pct);
    ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));

    /* COR-5(b): re-issue a dropped variant-index write here -- mutex just
     * released, and still BEFORE serve(). Must not be deferred past serve():
     * serve() finalizes the request, and an op launched after that races the
     * request teardown that closes the connection its posted write event
     * belongs to, so the SADD is queued and then dropped on the floor
     * (observed: reissues counter moved, SMEMBERS still had one member). */
    ngx_http_cache_turbo_varidx_reissue(r, clcf, ctx, z, hash);

    (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->hits, 1);
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cache_turbo: L1 HIT (fresh) \"%V\" key=%ui len=%uz",
                   &r->uri, (ngx_uint_t) hash, body_len);

    *out_rc = ngx_http_cache_turbo_serve(r, body, body_len, 0, z, body,
              NULL);
    return NGX_DONE;
}



/* MAINT-H4d phase helper for ngx_http_cache_turbo_access_l1().
 * PHASE -- the stale-but-serveable arm: cross-node single-flight resolution,
 * the per-box refresh dice, and the plain stale serve when nobody wins it.
 *
 * ⚠ LOCK WINDOW: entered with z->shpool->mutex HELD (same lock as the
 * fresh-hit arm above). This phase stayed WHOLE rather than being split
 * further: every pointer this phase pins (ctn->data via blob_acquire) is
 * registered with a pool cleanup (blob_ref_cleanup) BEFORE the matching
 * unlock, so it stays valid across the unlock and into warm_one()/serve() --
 * splitting the cross-node-lock / refresh-dice / plain-stale-serve arms
 * into separate helpers would force the lock (or an already-armed pin)
 * across a helper boundary, which PR #296 fixed this exact function to
 * avoid. No callee here re-acquires z->shpool->mutex: backend->lock() talks
 * to L2 (Redis), not the zone mutex, and warm_one()/serve() are called only
 * after this phase's own unlock. Always terminal (NGX_DONE) on every path
 * that runs, matching every unlock below. */
static ngx_int_t
ngx_http_cache_turbo_access_l1_serve_stale(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_cache_turbo_zone_t *z, ngx_http_cache_turbo_node_t *ctn,
    time_t now, time_t fresh_until, uint32_t hash, ngx_int_t *out_rc)
{
    time_t  stale_window;
    ngx_int_t  refresh;

    /* stale-but-serveable. The `len > 0` guard skips a cold-miss
     * single-flight STUB (v10: data == NULL, len == 0, stale_until == 0)
     * — a stub is an in-flight marker, never serveable; it falls through
     * to the cold path below where the waiter/claim logic handles it. */

    /* True LRU: promote on access (still a live, serveable entry).
     * P1: coarse-gate the splice (see the fresh-HIT site above). */
    /* S8: shared promote-on-second-hit helper; also applies the P1
     * 1s coarse gate internally. clcf->scan_resistant_pct == 0 (the
     * default) makes this a plain probation re-head. */
    ngx_http_cache_turbo_shm_touch_lru(z, ctn, now,
                                       clcf->scan_resistant_pct);

    /* Cross-node single-flight resolved (v4-2): we parked for the Redis
     * NX and the phase engine re-entered. If we won (NGX_OK), we own the
     * cluster-wide regen → go to origin. If the lock channel FAILED
     * (NGX_ERROR: Redis timeout/outage), there is no cross-node
     * coordination to honour, so degrade to per-box single-flight and
     * regenerate locally — `refreshing` is already claimed, so this box
     * still single-flights while a peer with a live Redis can win the NX.
     * Only a genuine peer-holds (NGX_DECLINED) falls through to serve
     * stale: the dice is skipped (refreshing claimed) and the tail below
     * serves stale — no extra state needed. */
    if (ctx->lock_done
        && (ctx->lock_result == NGX_OK || ctx->lock_result == NGX_ERROR))
    {
        /* We own the (cluster-wide, or per-box on L2 failure) regen. With
         * background_update (v8,
         * default) refresh in the background and serve stale now; else
         * fall through to the origin and regenerate inline. */
        if (clcf->background_update) {
            /* S231-PERF-BGSNAP: PERF-7 style zero-copy pin instead of a
             * full-body memcpy under the zone mutex -- same treatment as
             * the SIE/breaker arms above (S231-PERF-SIEARM). UNLIKE
             * those arming sites, the pinned pointer is used
             * immediately (not stashed for a maybe-never-consumed
             * fallback): it must stay valid across the unlock below,
             * across warm_one() (which may itself touch this zone), and
             * into serve(), which is exactly what the refcount is for
             * -- see the PERF-7 comment on the fresh-HIT site above
             * ("eviction/refresh by any worker is safe meanwhile").
             *
             * Register the drop BEFORE acquiring, same ordering
             * invariant as blob_ref_cleanup()'s own comment: the only
             * failing call here is ngx_pool_cleanup_add(), which
             * touches r->pool only, so failing first costs nothing to
             * undo. Acquiring first would force the failure arm to
             * call blob_release(), which takes the zone mutex we are
             * still holding here (ngx_shmtx is not recursive). */
            u_char *snap;
            size_t  snap_len;

            if (ngx_http_cache_turbo_blob_ref_cleanup(r, z, ctn->data,
                    NULL) != NGX_OK)
            {
                ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));

                *out_rc = NGX_ERROR;
                return NGX_DONE;

            }
            ngx_http_cache_turbo_blob_acquire(ctn->data);
            snap = ctn->data;
            snap_len = ctn->len;
            ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));
            (void) ngx_http_cache_turbo_warm_one(r, &r->uri, &r->args,
                                                 snap, snap_len,
                                                 NULL, NULL);
            (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->stale_serves, 1);
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: cross-node WON bg-refresh + STALE "
                           "serve \"%V\" key=%ui len=%uz",
                           &r->uri, (ngx_uint_t) hash, snap_len);
            /* ref_data is NULL: the cleanup was already registered
             * above (blob_ref_cleanup), so serve() must not register a
             * second one for the same pointer -- see the double-drop
             * warning on blob_ref_cleanup()'s comment. */

            *out_rc = ngx_http_cache_turbo_serve(r, snap, snap_len, 1,
                      z, NULL, NULL);
            return NGX_DONE;

        }
        ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: cross-node lock WON \"%V\" key=%ui "
                       "-> regenerate", &r->uri, (ngx_uint_t) hash);

        *out_rc = NGX_DECLINED;
        return NGX_DONE;

    }

    /* Refresh-dice window from the OBJECT's own deadlines, not the
     * location default (COR-3): a per-status TTL or an honor_cc upstream
     * max-age gives this node a different fresh/stale span than
     * clcf->valid, so using clcf->valid here mis-scaled the dice and such
     * objects could expire cold. stale_until == 0 (no stale deadline)
     * falls back to the location-derived window. */
    if (ctn->stale_until != 0) {
        stale_window = ctn->stale_until - fresh_until;
    } else {
        stale_window = ngx_http_cache_turbo_stale_ttl(clcf->valid,
                           clcf->stale_mult)
                       - clcf->valid;
    }
    if (stale_window <= 0) {
        stale_window = 1;
    }

    /* Hard single-flight: if a refresh is already claimed and its lock
     * window hasn't expired, every reader serves stale and skips the
     * dice entirely. Only when no lock is held (or it has expired, i.e.
     * the previous refresh died) does anyone roll to become the single
     * regenerator. This caps origin regens at ~one per stale cycle even
     * with many workers and aggressive beta. */
    refresh = NGX_DECLINED;
    if (!ctx->lock_done
        && (!ctn->refreshing || now >= ctn->refresh_lock_until))
    {
        refresh = ngx_http_cache_turbo_should_refresh(ctx->key_hash,
                      fresh_until, stale_window,
                      ngx_http_cache_turbo_effective_beta(clcf, z));
    }

    if (refresh == NGX_OK) {
        /* We win the per-box dice: claim the refresh under lock (atomic
         * with the check above). With background_update on (v8, default)
         * this request serves STALE and refreshes in the background — it
         * never blocks on origin; the bg subrequest restores a fresh copy
         * and a failed origin (5xx/timeout) leaves the stale entry intact
         * (stale-if-error). With background_update off it falls through to
         * the origin and regenerates SYNCHRONOUSLY (serving fresh). Either
         * way the OTHER concurrent readers serve stale. We count a
         * `refresh` here (the regen we triggered) plus a `stale_serve` on
         * the bg path (the stale response we hand back). The lock
         * self-heals after lock_ttl if the refresh never completes. */
        time_t  lock_ttl = clcf->lock_ttl;
        u_char *snap;
        size_t  snap_len;

        if (lock_ttl <= 0) {
            lock_ttl = 5;
        }

        /* v4-4: a slow origin (the load case) takes longer to regen, so
         * widen the single-flight window by the load factor — hold the
         * claim long enough that a still-running slow refresh isn't
         * re-claimed, collapsing more requests onto the one regen. */
        lock_ttl = lock_ttl
            * ngx_http_cache_turbo_effective_load(clcf, z)
            / NGX_HTTP_CACHE_TURBO_AT_LOAD_BASE;

        /* S231-PERF-BGSNAP: pin the stale copy under the lock instead
         * of memcpy'ing the full body — used to serve stale on the
         * single-box background-update path below (PERF-7 zero-copy,
         * same treatment as the cross-node WON arm just above and the
         * SIE/breaker arms, S231-PERF-SIEARM). The pin must outlive
         * this critical section: a cross-node lock() call below can
         * park this request (NGX_AGAIN) and never consume `snap` on
         * this stack at all, or `background_update` can be off and
         * fall straight through without consuming it either — both are
         * fine, since the ref is dropped by the pool cleanup
         * registered here regardless of whether it is ever served (the
         * same "arm now, maybe never consumed" shape the SIE/breaker
         * comment describes), not by anything on this stack.
         *
         * Register the drop BEFORE acquiring, per the ordering
         * invariant on blob_ref_cleanup(): the only failing call here
         * is ngx_pool_cleanup_add() (r->pool only), so failing first
         * costs nothing to undo, whereas acquiring first would force
         * the failure arm to call blob_release() while still holding
         * this same zone mutex (ngx_shmtx is not recursive). */
        snap_len = ctn->len;
        if (ngx_http_cache_turbo_blob_ref_cleanup(r, z, ctn->data,
                NULL) != NGX_OK)
        {
            ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));

            *out_rc = NGX_ERROR;
            return NGX_DONE;

        }
        ngx_http_cache_turbo_blob_acquire(ctn->data);
        snap = ctn->data;

        /* CTXRDR-ADOPT-LEASE: deliberately NO refresh_owner here. This is
         * the v8 background-update lease on an ENTRY that still has a
         * body, not the cold-miss stub lease. It is resolved by store()
         * overwriting the node, never by unstub() -- which ignores an
         * ENTRY (kind == COUNTER is required) -- and it is never adopted
         * across a redirect, because a request holding it is serving
         * stale rather than parking in cold_wait(). The two leases share
         * the `refreshing` flag and nothing else. */
        ctn->refreshing = 1;
        ctn->refresh_lock_until = now + lock_ttl;
        ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));
        (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->refreshes, 1);
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: stale, refresh dice WON \"%V\" "
                       "key=%ui", &r->uri, (ngx_uint_t) hash);

        /* Cross-node gate (v4-2): the per-box L1 dice win is necessary
         * but not sufficient — only the node that ALSO wins the Redis
         * SET NX PX regenerates; the rest serve stale. lock() parks for
         * the NX reply and re-enters this handler (ctx->lock_done set,
         * resolved at the top of this block — bg or inline). NGX_DECLINED
         * = L2 off / could not start → single-box fallback below. */
        if (clcf->backend && clcf->backend->lock) {
            ngx_int_t  lrc = clcf->backend->lock(r, clcf, ctx, lock_ttl);
            if (lrc == NGX_AGAIN) {
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: parked on L2 lock NX \"%V\" "
                               "key=%ui", &r->uri, (ngx_uint_t) hash);

                *out_rc = NGX_AGAIN;
                return NGX_DONE;
       /* parked; resume re-enters */
            }
        }

        /* single-box winner (no L2 lock, or it could not start). */
        if (clcf->background_update) {
            /* v8: fire a background refresh of this URI, serve stale. */
            (void) ngx_http_cache_turbo_warm_one(r, &r->uri, &r->args,
                                                 snap, snap_len,
                                                 NULL, NULL);
            (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->stale_serves, 1);
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: bg-refresh + STALE serve \"%V\" "
                           "key=%ui len=%uz", &r->uri, (ngx_uint_t) hash,
                           snap_len);

            *out_rc = ngx_http_cache_turbo_serve(r, snap, snap_len, 1,
                      z, NULL, NULL);
            return NGX_DONE;

        }


        *out_rc = NGX_DECLINED;
        return NGX_DONE;
       /* inline regen (serves fresh) */
    }

    /* serve stale, no regeneration on this request */
    {
        /* PERF-7: zero-copy stale serve (see the fresh-hit path). */
        u_char *body = ctn->data;
        size_t  body_len = ctn->len;
        ngx_http_cache_turbo_blob_acquire(body);
        ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));
        (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->stale_serves, 1);
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: STALE serve \"%V\" key=%ui len=%uz",
                       &r->uri, (ngx_uint_t) hash, body_len);

        *out_rc = ngx_http_cache_turbo_serve(r, body, body_len, 1, z, body,
                  NULL);
        return NGX_DONE;

    }
}



/* MAINT-H4d phase helper for ngx_http_cache_turbo_access_l1().
 * PHASE -- breaker-fallback arm from an expired L1 entry (P6/O4.3). Pure
 * arm-and-log, no lock ops of its own: always called while the caller still
 * holds z->shpool->mutex from the lookup (it pins ctn->data under that
 * lock). void: the inline block had no return, the caller always continues
 * into the SIE-arm phase afterward regardless of outcome. */
static void
ngx_http_cache_turbo_access_l1_breaker_arm(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_ctx_t *ctx, ngx_http_cache_turbo_node_t *ctn,
    uint32_t hash)
{
    /* P6/O4.3: arm the circuit-breaker fallback from this expired L1 entry.
     *
     * Unconditional on age, unlike the SIE arming below: the breaker's
     * contract is "any body beats a 503 once the origin is known down". The
     * entry has already fallen past its stale window here, so nothing on the
     * NORMAL path will ever serve it -- only the pre-origin breaker gate
     * can, and only while the breaker is OPEN.
     *
     * ⚠ Gated on breaker_should_consult() so this costs nothing when the
     * breaker is off by ANY of its off-switches: it is a full-blob memcpy
     * on the expired-entry path, which is every request to a cold-ish
     * key. Same predicate the pre-origin gate below uses.
     *
     * The !brk_armed guard makes the park/resume re-entries idempotent (the
     * L2 GET and the cold-wait both re-enter this handler from the top),
     * exactly as !sie_armed does below. */
    if (ctn->len > 0 && !ctx->brk_arm_done
        && ngx_http_cache_turbo_breaker_should_consult(clcf))
    {
        /* PERF-7 style zero-copy arm: pin the blob in the slab under the
         * mutex we already hold instead of copying it. A full-blob memcpy
         * here would run on EVERY enabled request that finds an expired
         * entry, inside the cross-worker zone lock, on objects up to
         * cache_turbo_max_object (1 MiB by default, configurable higher) --
         * a lock convoy on precisely the outage path this feature is meant
         * to smooth. The reference is released by the pool cleanup that
         * ngx_http_cache_turbo_serve() registers for ref_data.
         *
         * ⚠ Arming does not mean serving: most armed requests fall through
         * to the origin with a CLOSED breaker and never call _serve(). The
         * ref must therefore be dropped when nobody consumes it, which is
         * what the explicit cleanup below is for -- see brk_ref. */
        /* Register the drop BEFORE acquiring. ngx_pool_cleanup_add() is
         * the only thing here that can fail, and it touches r->pool only
         * -- no slab, no zone mutex -- so failing first costs nothing to
         * undo. Acquiring first would force the failure arm to call
         * blob_release(), which takes the zone mutex itself (shm.c) and so
         * requires unlocking here; ngx_shmtx is not recursive. That unlock
         * would invalidate `ctn` -- it was resolved at the lookup and is
         * only valid while the mutex is held -- letting a concurrent
         * evict/refresh/purge detach the blob and our own release then free
         * it, leaving the SIE block below dereferencing freed slab. */
        ngx_http_cache_turbo_blob_cln_t  *bcc = NULL;

        if (ngx_http_cache_turbo_blob_ref_cleanup(r, z, ctn->data, &bcc)
            == NGX_OK)
        {
            ctx->brk_arm_done = 1;
            ngx_http_cache_turbo_blob_acquire(ctn->data);
            ctx->brk_snap = ctn->data;
            ctx->brk_snap_len = ctn->len;
            ctx->brk_ref = ctn->data;
            ctx->brk_cln = bcc;
            ctx->brk_armed = 1;

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
            /* O4.4-i negative control for THIS site. Inside the
             * should_consult() branch on purpose -- see the field comment.
             * Bumps the L1 field only: a shared counter would let an L2
             * assertion pass on this site's bump. */
            (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->test_brk_armings_l1, 1);
#endif

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: breaker fallback armed from L1 "
                           "\"%V\" key=%ui", &r->uri, (ngx_uint_t) hash);
        }
    }
}



/* MAINT-H4d phase helper for ngx_http_cache_turbo_access_l1().
 * PHASE -- serve-on-error (RFC 5861 §4 / CTB4) snapshot arm from an expired
 * L1 entry. Pure arm-and-log, no lock ops of its own: always called while
 * the caller still holds z->shpool->mutex (same as the breaker-arm phase
 * just above). void: the inline block had no return, the caller always
 * continues to the L1 unlock afterward regardless of outcome. */
static void
ngx_http_cache_turbo_access_l1_sie_arm(ngx_http_request_t *r,
    ngx_http_cache_turbo_zone_t *z, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_cache_turbo_node_t *ctn, time_t now, uint32_t hash)
{
    if (ctn->len > 0 && !ctx->sie_armed) {
        time_t    created = (time_t)
            ngx_http_cache_turbo_get_u64(ctn->data + 24);
        uint32_t  sie_ttl = ngx_http_cache_turbo_get_u32(ctn->data + 40);

        if (sie_ttl > 0 && now < created + (time_t) sie_ttl) {
            /* S231-PERF-SIEARM: PERF-7 style zero-copy arm, same reasoning
             * as the breaker arm just above -- see its comment for the
             * full rationale; this is the identical hazard on the SAME
             * `ctn`, still under the SAME mutex hold.
             *
             * Register the drop BEFORE acquiring. ngx_pool_cleanup_add()
             * is the only thing here that can fail, and it touches
             * r->pool only -- no slab, no zone mutex -- so failing first
             * costs nothing to undo. Acquiring first would force the
             * failure arm to call blob_release(), which takes the zone
             * mutex itself (shm.c) and so requires unlocking here;
             * ngx_shmtx is not recursive. That unlock would invalidate
             * `ctn` -- it was resolved at the lookup and is only valid
             * while the mutex is held -- letting a concurrent
             * evict/refresh/purge detach the blob and our own release
             * then free it, leaving the L2-consult code below
             * dereferencing freed slab. */
            /* No early-drop caller for the SIE arm (unlike the breaker's
             * brk_ref_drop), so nothing needs the cleanup record back --
             * pass NULL and let the pool-lifetime drop be the only
             * owner. */
            if (ngx_http_cache_turbo_blob_ref_cleanup(r, z, ctn->data,
                    NULL) == NGX_OK)
            {
                ngx_http_cache_turbo_blob_acquire(ctn->data);
                ctx->sie_snap = ctn->data;
                ctx->sie_snap_len = ctn->len;
                ctx->sie_armed = 1;
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: SIE armed from L1 \"%V\" key=%ui",
                               &r->uri, (ngx_uint_t) hash);
            }
        }
    }
}



static ngx_int_t
ngx_http_cache_turbo_access_l1(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_cache_turbo_zone_t *z, uint32_t *hashp, ngx_int_t *out_rc)
{
    /* Local copy of the caller's `hash`, written back on the fall-through
     * path only. vary_apply() below may rewrite it to the variant key, and
     * every subsequent phase (the L2 log lines, l2_neg_set()) must see the
     * rewritten value -- so the write-back sits immediately before the
     * NGX_DECLINED return, which is the only exit that has a next phase. On
     * every terminal exit the caller returns *rc without reading hash again,
     * exactly as the inline code left its own `hash` local behind. */
    uint32_t                      hash = *hashp;
    ngx_http_cache_turbo_node_t  *ctn;

    ngx_shmtx_lock(ngx_http_cache_turbo_zone_mutex(z));

    /* S231-PERF-VARYLOCK: the marker lookup + key_hash recompute is folded
     * into THIS critical section (was a standalone lock/unlock pair in the
     * prologue) so a request pays one zone-mutex acquisition for both the
     * vary-marker probe and the main lookup below, not two. Must run before
     * the main lookup: it may rewrite ctx->key_hash/hash to the variant key
     * that lookup below needs to use.
     *
     * C3: `markers == 0` proves the zone holds no L1 marker node anywhere (see
     * the field comment in module.h -- the counter cannot under-count), so
     * vary_apply()'s own lock-held rbtree lookup on ctx->vary_marker_key is
     * guaranteed to find nothing. Skip it and replicate exactly the terminal
     * state its m == NULL branch leaves: ctx->vary_gen unconditionally 0
     * (vary_apply()'s own field comment: "ctx->vary_gen is set unconditionally
     * ... bits==0 => gen==0" -- and ctx is pcalloc'd/reset each pass, so 0 is
     * also vary_gen's own initialised value, making this assignment a
     * provable no-op whenever this is the first pass to touch it) and
     * ctx->vary_marker_l1_miss = 1, which is what arms the L2-backed marker
     * consult a few phases later (access_l2_marker_get()) -- that consult
     * must still fire on a counter-proven-empty L1, exactly as it would on an
     * ordinary miss, so a peer's L2-visible marker is still found. Nothing
     * else: vary_apply()'s m == NULL arm touches no other ctx field and never
     * rewrites `hash`. */
    if (clcf->auto_vary) {
        if (ngx_http_cache_turbo_zone_sh(z)->markers == 0) {
            ctx->vary_gen = 0;
            ctx->vary_marker_l1_miss = 1;

        } else {
            ngx_http_cache_turbo_vary_apply(r, clcf, z, ctx, &hash);
        }
    }

    /* P3-5: re-derive an L2-resolved variant on EVERY entry, exactly the way
     * vary_apply() just re-derived an L1-resolved one above -- see the field
     * comment on ctx->vary_marker_l2_bits for why this cannot instead rely
     * on the ctx->key_hash rewrite made at consult time surviving: build_key()
     * (called at the top of every access_prologue(), i.e. every re-entry of
     * this whole handler after a park) unconditionally resets ctx->key_hash
     * to the base key first. Only runs when vary_apply() did NOT already
     * resolve bits from L1 (an L1 hit is authoritative and always wins; an
     * L2-cached resolution from an EARLIER pass of this same request must
     * never override a marker that has since appeared in L1, e.g. via this
     * very self-heal). */
    if (clcf->auto_vary && ctx->vary_marker_l2_bits > 0 && hash == *hashp) {
        ngx_http_cache_turbo_variant_hash(r, &ctx->cache_key,
            ctx->vary_marker_l2_bits, ctx->vary_marker_l2_gen,
            ctx->key_hash);
        hash = ngx_crc32_short(ctx->key_hash, 32);
        ctx->vary_gen = ctx->vary_marker_l2_gen;
    }

    ctn = clcf->l1->lookup(z, ctx->key_hash, hash);

    /* COR-5(b): consume this node's dropped-index flag while we already hold
     * the mutex for the lookup above -- no extra acquisition, and the clear is
     * atomic with the read so two concurrent hits cannot both re-issue. The
     * re-issue itself happens AFTER each arm's unlock (see
     * ngx_http_cache_turbo_varidx_reissue); the retention is copied out by
     * value here because `ctn` must not be touched once the lock is gone. */
    if (ctn != NULL && ctn->varidx_pending) {
        ctn->varidx_pending = 0;
        ctx->varidx_reissue = 1;
        ctx->varidx_reissue_ttl = ctn->stale_until > 0
                                  ? ctn->stale_until - ngx_time()
                                  : 0;
    }

    if (ctn != NULL) {
        time_t     now = ngx_time();
        time_t     fresh_until = ctn->fresh_until;
        time_t     stale_until = ctn->stale_until;
        ngx_int_t  fresh_ok = 1, stale_ok = 1;

        /* v4-4 load-adaptive stale window + RFC-1 request freshness bounds:
         * two independent, pure, lock-free computations that must both run
         * before the serve/expire decisions below can read fresh_until /
         * stale_until / fresh_ok / stale_ok. Neither touches the mutex. */
        ngx_http_cache_turbo_access_l1_stale_window(clcf, z, fresh_until,
            &stale_until);
        ngx_http_cache_turbo_access_l1_req_bounds(r, ctx, ctn, now,
            fresh_until, stale_until, &fresh_ok, &stale_ok);

        /*
         * S232-BYPASS-STALE: a breaker-only entry is never a HIT, at any age.
         * Only a request that fell through the bypass-stale arm above (i.e.
         * the breaker is OPEN) gets here at all, and what it needs is the
         * fallback ARMED, not served -- so skip the fresh/stale serve arms
         * entirely and let the expired-entry arming site below pick this entry
         * up, exactly as it would an aged-out one.
         *
         * Without this the fresh arm calls serve(), the BLOBF_BREAKER_ONLY
         * guard there correctly refuses it, and the request goes to the dead
         * origin having armed NOTHING -- the stored copy exists and the client
         * still gets a 503. The guard is the backstop; this is the path.
         *
         * Deliberately keyed on ctx->brk_only (this request opted in) rather
         * than on the stored blob's bit: an ordinary entry must keep its
         * normal fresh-HIT behaviour even in a location that names other
         * prefixes, which the scope negative control pins.
         */
        /* c-2: a marker revalidation just armed by vary_apply() (this SAME
         * lock-held pass, immediately above) must not be short-circuited by
         * the ordinary fresh/stale serve arms below -- those serve the
         * OBJECT node `ctn` this lookup already found under the (possibly
         * stale, that is the whole point) resolved variant key, and every
         * exit from this function except the "fall through to L2" one below
         * returns straight to the caller without ever reaching
         * access_l2()/access_l2_marker_get(), where the revalidation GET
         * actually lives. Skipping both serve arms here is what makes the
         * fall-through happen: this object node itself is untouched (no
         * status/SIE/breaker state is set the way the genuinely-expired arm
         * below does), so a fail-open L2 GET failure still resolves back to
         * serving this exact node on the object-GET phase right after the
         * marker consult -- same fresh/stale object, just reached one phase
         * later than usual.
         *
         * Two flags, not one: vary_marker_revalidate is set by THIS pass's
         * own vary_apply() a few lines above and does NOT survive a park --
         * a resumed pass re-runs vary_apply() from the top, which re-derives
         * it fresh and (correctly) finds !vary_marker_l2_done false, so it
         * resets to 0 on exactly the resume that most needs the skip.
         * vary_marker_revalidate_inflight is the request-lifetime latch set
         * once at GET-launch time (access_l2_marker_get()) and cleared once
         * at consume time (access_l2_marker_consume()) -- see its own field
         * comment -- so it is what actually covers the resume. Checking
         * both here (rather than only the inflight one) keeps the skip
         * correct on the FIRST pass too, before the GET has even launched. */
        if (ctx->brk_only) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: bypass-stale \"%V\" -> arm only, "
                           "never a hit", &r->uri);

        } else if (!ctx->vary_marker_revalidate
                   && !ctx->vary_marker_revalidate_inflight
                   && now < fresh_until && fresh_ok)
        {
            /* serve_fresh() runs the COR-5(b) re-issue itself, immediately
             * after its own unlock and before it serves. */
            return ngx_http_cache_turbo_access_l1_serve_fresh(r, clcf, ctx,
                z, ctn, now, hash, out_rc);
        }

        if (!ctx->vary_marker_revalidate && !ctx->vary_marker_revalidate_inflight
            && !ctx->brk_only
            && (stale_until == 0 || now < stale_until) && ctn->len > 0
            && stale_ok)
        {
            /* COR-5(b): the stale arm is NOT a re-issue site. It has many
             * unlock paths and one of them PARKS the request on an L2 lock,
             * so there is no single point that is both past the unlock and
             * before the serve/park. Put the bit back instead (still under
             * this arm's lock -- serve_stale() has not unlocked yet) and let
             * the next fresh hit, or the next fall-through to L2, heal it.
             * Never dropping the bit is what makes deferring safe. */
            if (ctx->varidx_reissue) {
                ctx->varidx_reissue = 0;
                ctn->varidx_pending = 1;
            }

            return ngx_http_cache_turbo_access_l1_serve_stale(r, clcf,
                ctx, z, ctn, now, fresh_until, hash, out_rc);
        }

        /* expired: the L1 copy is past its stale window. Fall through to the
         * shared L2-consult/miss path below — another node may hold a fresher
         * copy in Redis, so we must check L2 before the origin (issue P6).
         *
         * $cache_turbo_status: a cached entry WAS found but is past its
         * serveable window -> EXPIRED (matches nginx $upstream_cache_status:
         * expired-and-refetched, distinct from a true cold MISS). Overwritten
         * to HIT/STALE below if L2 holds a serveable copy.
         *
         * RFC 5861 §4 / RFC-2 stale-if-error (CTB4): before going to origin,
         * arm a serve-on-error snapshot if this blob still carries a window
         * (created + sie_ttl) that covers now. If the origin revalidation then
         * fails (5xx/timeout), the header/body filters replay this snapshot
         * instead of surfacing the error. Arming only STASHES — the L2 consult
         * below still runs first (a peer may hold a fresh copy). len > 0 skips a
         * stub; the !sie_armed guard makes the park/resume re-entries idempotent.
         *
         * c-2 correction (S231-NOCACHE-OUTAGE): status alone is the
         * GENUINELY-expired bookkeeping -- $cache_turbo_status assumes the
         * object itself aged out, which is false for a revalidation
         * fall-through (the object is fresh or serveable-stale; only the
         * MARKER's resolve time triggered the fall-through), so ONLY that
         * assignment is conditional. The breaker-arm and SIE-arm calls are
         * NOT part of that reasoning and must run unconditionally: both are
         * documented "arm-only, idempotent, unconditional on age" pure
         * snapshots of `ctn` (see their own function comments -- breaker_arm
         * explicitly: "any body beats a 503 once the origin is known down"),
         * and the pre-origin breaker gate a few phases later reads
         * ctx->brk_armed regardless of WHY this request fell through past
         * the serve arms above. Skipping them here previously meant ANY
         * revalidation fall-through on a varying URL left nothing armed, so
         * an OPEN breaker's ACT_SERVE verdict had no snapshot to serve and
         * fell to ACT_FAIL's 503 -- turning a routine, bounded generation
         * recheck into an availability regression during exactly the outage
         * this module exists to smooth over. A possibly-stale cached variant
         * must always beat a 503; revalidation is a correctness improvement
         * on the healthy path only, never a reason to fail closed. */
        ctx->status = NGX_HTTP_CACHE_TURBO_ST_EXPIRED;

        ngx_http_cache_turbo_access_l1_breaker_arm(r, clcf, z, ctx, ctn,
            hash);
        ngx_http_cache_turbo_access_l1_sie_arm(r, z, ctx, ctn, now, hash);
    }

    /* L1 absent (miss) or expired. Consult L2 (Redis or memcached -- the
     * backend is a vtable) before falling through to the origin: another node
     * may already hold this object. The L2 GET is
     * async but logically synchronous — it parks the request and resumes it
     * when the reply lands (see ngx_http_cache_turbo_redis_get). */
    ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));

    /* COR-5(b): the expired-entry arm falls through to L2 rather than
     * serving, but the node it just passed over is still resident and still
     * missing from the index set -- heal it here too, now that the mutex is
     * released. A no-op when nothing was pending. */
    ngx_http_cache_turbo_varidx_reissue(r, clcf, ctx, z, hash);

    *hashp = hash;
    return NGX_DECLINED;
}



/* P3-5 phase helper for ngx_http_cache_turbo_access_l2().
 * PHASE 0 -- L2-backed vary marker consult, extracted whole.
 *
 * Only fires when vary_apply() (access_l1, still under the zone mutex)
 * flagged an L1 marker MISS (ctx->vary_marker_l1_miss) -- i.e. auto_vary is
 * on and key_hash is still the BASE key. On a warm marker (the common case)
 * this function is never called at all, so the warm path pays no extra L2
 * round trip; see the caller.
 *
 * The marker GET reuses ngx_cache_turbo_backend_t.get(), which always reads
 * ctx->key_hash -- there is no key-parametrised variant of get(). We
 * therefore point key_hash at ctx->vary_marker_key (the SAME marker_hash key
 * marker_store() writes through to L2), issue the GET, and restore key_hash
 * to the base key before returning either way. This is safe: both backend
 * get() implementations copy the key bytes into their own async op's buffer
 * synchronously, before this function returns/parks (redis.c
 * ngx_http_cache_turbo_redis_get / memcached.c ..._memcached_get both build
 * their wire key from key_hash inline, not by holding a pointer into ctx),
 * so nothing downstream can observe key_hash mid-flight with the marker
 * value still in it once this function returns.
 *
 * The result of the marker GET lands in the SAME ctx->l2_done/l2_result/l2_blob
 * fields the object GET uses (both backends' get_finish() write those
 * unconditionally) -- ctx->vary_marker_l2_tried disambiguates "this is the
 * marker's answer" from "this is the object's answer" on the re-entry after
 * park/resume, and is cleared before returning so the object-GET phase right
 * after this one in access_l2() sees a clean l2_done/l2_result/l2_blob to
 * fill in on its own park/resume, exactly as if this phase had not run.
 *
 * A validated marker hit rewrites key_hash/hash to the variant key (the same
 * transform vary_apply() itself performs from an L1 hit) and self-heals the
 * L1 marker so subsequent requests on this node resolve from L1 without
 * paying this GET again. Validation is the FULL blob_validate() (magic +
 * version + status/created/stale_ttl/TLV walk) -- the fast magic+version-only
 * check vary_apply() uses (S231-PERF-VARYMAGIC) is an optimisation that
 * trades a marginally weaker collision check for staying inside an
 * already-held zone mutex; an L2 blob is not read under that mutex and has
 * already paid a network round trip, so there is no lock-window budget to
 * economise here, and the extra fields blob_validate walks (headers_len==0
 * for a genuine marker) reject an L2 GET that landed a same-hash but
 * differently-shaped object blob (a marker_hash/key_hash collision) that the
 * cheap check alone would not catch on this less-trusted path. A corrupt,
 * too-short, or validation-failing reply is treated exactly like an L1
 * marker miss: bits stay 0, key_hash/hash are left as the base key, and the
 * request falls through to the normal (now correctly base-keyed) L2 object
 * GET below -- never to a wrong variant. */
static ngx_int_t
ngx_http_cache_turbo_access_l2_marker_get(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_cache_turbo_zone_t *z, ngx_int_t *out_rc)
{
    ngx_int_t   rc;
    u_char      saved_key[32];
    uint32_t    marker_hash;
    ngx_uint_t  revalidate;

    /* c-2: a warm marker revalidation (ctx->vary_marker_revalidate, set by
     * vary_apply() -- see its field comment) reuses this SAME GET, gated
     * identically except for the two differences noted at each site below.
     * The two triggers are mutually exclusive by construction
     * (vary_apply() sets vary_marker_l1_miss XOR vary_marker_revalidate,
     * never both), so `revalidate` here can only be true when
     * vary_marker_l1_miss is 0 and the `|| !ctx->vary_marker_l1_miss` arm
     * below would otherwise have declined -- hence the explicit OR. */
    revalidate = ctx->vary_marker_revalidate;

    if (!clcf->auto_vary || (!ctx->vary_marker_l1_miss && !revalidate)
        || ctx->vary_marker_l2_tried || ctx->vary_marker_l2_done
        || !clcf->backend || !clcf->backend->get)
    {
        return NGX_DECLINED;
    }

    marker_hash = ngx_crc32_short(ctx->vary_marker_key, 32);

    /* L13, extended to the marker key (admin.py CI regression): the marker
     * GET is exactly as memoable as the object GET it sits ahead of -- a
     * memo asserts "an L2 GET for this key missed within the last
     * l2_negative_ttl seconds", and that is just as true of the marker key
     * as of any object key. Skipping this check made the marker GET fire on
     * EVERY request regardless of a live memo (measured: a 5s burst issued
     * one GET per request, 0 suppressed -- test_l2_negative_ttl_expires
     * caught it), defeating l2_negative_ttl for every varied URL exactly
     * the way the base-key path is protected from. Mirrors
     * access_l2_neg_memo()'s check on ctx->key_hash, keyed on
     * vary_marker_key instead. vary_marker_l1_miss is left untouched on a
     * memoed skip (not cleared, not consumed) so this pass falls through to
     * the ordinary base-key object GET exactly as an unmemoized miss
     * would -- the memo answers "no marker", not "try again later".
     *
     * c-2 (integration hazard, verified at source): this memo is what fires
     * on EVERY request if a revalidation naively entered here on the
     * l1_miss path -- ctx->vary_marker_l1_miss is 0 for a warm-hit
     * revalidation (there IS a marker; vary_apply() just resolved it), so
     * this memo (an L2-GET-for-this-key-missed record) would never even be
     * SET by a revalidation's own GETs, which all land NGX_OK. That is not
     * why revalidation must skip this check, though -- the real reason is
     * semantic: the memo answers "does a marker exist at all", which a
     * revalidation already knows the answer to (yes, L1 just proved it).
     * Gating a revalidation on it would be gating on the wrong question,
     * and would let a stale-negative-memo edge case (this marker key was
     * memoed missing before self-healing, memo TTL not yet expired) silently
     * suppress every revalidation attempt for up to l2_negative_ttl
     * seconds -- worse than the every-request-GET regression this same memo
     * exists to prevent on the l1-miss path, because there the memo is
     * doing its documented job (this marker really doesn't exist yet) and
     * here it would not be (the marker demonstrably exists, right now, in
     * L1). Only the ORIGINAL l1-miss trigger consults the memo; a
     * revalidate trigger bypasses it and always proceeds to the rate-limit
     * below instead. */
    if (!revalidate && clcf->l2_negative_ttl > 0
        && clcf->l1->l2_neg_check(z, ctx->vary_marker_key, marker_hash)
               == NGX_DECLINED)
    {
        ctx->vary_marker_l1_miss = 0;
        ctx->vary_marker_l2_done = 1;
        (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->l2_neg_skips, 1);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: L2 vary-marker GET skipped by negative "
                       "memo \"%V\"", &r->uri);
        return NGX_DECLINED;
    }

    /* c-2: latch WHY before either trigger flag is touched below --
     * vary_marker_revalidate is about to be superseded by vary_marker_l2_tried/
     * l2_done for the rest of this pass, and will not survive a park/resume
     * at all (see the field comment on vary_marker_revalidate_inflight). */
    if (revalidate) {
        ctx->vary_marker_revalidate_inflight = 1;
    }

    ctx->vary_marker_l1_miss = 0;
    ctx->vary_marker_l2_tried = 1;
    ctx->vary_marker_l2_done = 1;

    ngx_memcpy(saved_key, ctx->key_hash, 32);
    ngx_memcpy(ctx->key_hash, ctx->vary_marker_key, 32);

    rc = clcf->backend->get(r, clcf, ctx);

    if (rc == NGX_AGAIN) {
        /* Parked on the MARKER GET. Restore key_hash before returning: the
         * op already copied the marker key bytes it needs, and a resume
         * re-enters the whole handler from the top (access_l1 runs again,
         * recomputing key_hash from vary_marker_key/vary_apply exactly as on
         * the first pass), so key_hash must not be left pointing at the
         * marker mid-park for any other reader of ctx in the meantime. */
        ngx_memcpy(ctx->key_hash, saved_key, 32);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: parked on L2 vary-marker GET \"%V\"",
                       &r->uri);
        *out_rc = NGX_AGAIN;
        return NGX_DONE;
    }

    /* NGX_DECLINED: backend could not launch (L2 down / disabled). No result
     * to consume -- key_hash/l2_done are untouched, fall through exactly as
     * an L1 marker miss with no L2 configured always has. */
    ngx_memcpy(ctx->key_hash, saved_key, 32);
    return NGX_DECLINED;
}


/* P3-5 phase helper for ngx_http_cache_turbo_access_l2().
 * PHASE 0b -- consume the result of a completed marker GET (the park/resume half
 * of the phase above). Called at the top of access_l2() on every entry;
 * a no-op unless a marker GET is actually in flight/landed
 * (vary_marker_l2_tried && l2_done). */
static void
ngx_http_cache_turbo_access_l2_marker_consume(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_cache_turbo_zone_t *z, uint32_t *hashp)
{
    ngx_int_t                        bits = 0;
    ngx_uint_t                       gen = 0;
    ngx_uint_t                       revalidate;
    ngx_http_cache_turbo_blob_hdr_t  bh;

    if (!ctx->vary_marker_l2_tried || !ctx->l2_done) {
        return;
    }

    ctx->vary_marker_l2_tried = 0;

    /* c-2: capture + consume the launch reason now, once, regardless of
     * which arm below returns -- see the field comment on
     * vary_marker_revalidate_inflight for why this cannot be re-derived
     * from ctx->vary_marker_revalidate at this point. */
    revalidate = ctx->vary_marker_revalidate_inflight;
    ctx->vary_marker_revalidate_inflight = 0;

    /* S231-L2-BACKOFF (P3-5 CI regression): the marker GET is a SECOND,
     * sequential L2 round trip ahead of the object GET on the marker-cold
     * path. Against a healthy backend this costs one extra GET only when
     * genuinely needed; against a DOWN backend it means this request's own
     * marker GET is what discovers the outage and arms connect_backoff --
     * and the object GET that follows a few lines below in this SAME
     * request then finds backoff already active and gets counted as a
     * fail-fast SKIP, even though this is still the very first request to
     * notice the outage, not a later one riding an already-armed window.
     * (Confirmed by log: two connects launched sequentially inside one
     * request against a dead peer, request 1's own skip counter moving
     * 0->1 -- ci/tools/areas/breaker.py's test_redis_connect_backoff_
     * fails_fast pins "the arming request must not count itself".)
     * NGX_ERROR here is the transport-failure outcome of the marker GET
     * (connect refused/timeout/malformed reply -- the same class that arms
     * backoff, per redis.c's op_fail/get_finish "unconnected" classifi-
     * cation): this request has ALREADY paid for and learned that L2 is
     * unreachable, so let the object-GET phase skip its own connect
     * attempt entirely instead of paying (and miscounting) a second one
     * for information this request already has. NGX_OK (a real, if
     * marker-shaped-invalid, reply) and NGX_DECLINED (definitive miss) are
     * untouched -- only a transport failure short-circuits the next phase. */
    if (ctx->l2_result == NGX_ERROR) {
        ctx->vary_marker_l2_down = 1;
    }

    /* codex-review P3-5: an L1 marker can appear WHILE this request's own
     * marker GET (launched on an earlier pass) is still in flight -- a
     * concurrent request on this node classifying + storing the same base
     * URL's marker into L1 mid-park. access_l1() always runs vary_apply()
     * BEFORE calling into access_l2() (and therefore before this function),
     * so if THIS pass's vary_apply() already resolved bits from L1, it just
     * cleared vary_marker_l1_miss to 0 -- meaning ctx->key_hash/hashp already
     * carry L1's answer, strictly newer than whatever this now-landed L2 GET
     * (launched on a PRIOR pass, against a PRIOR L1 state) is about to say.
     * Applying the L2 answer here would silently overwrite the newer L1
     * resolution with a stale one -- wrong variant, not merely wrong
     * performance. L1 is authoritative and wins unconditionally; drop the L2
     * answer on the floor (it already did its job of proving A a variant
     * exists, and the self-heal below is what would have (re)written this
     * same L1 marker anyway).
     *
     * c-2: this guard is exactly right for the l1-miss trigger (`revalidate`
     * false) and is left untouched for it. A revalidate trigger is the
     * opposite situation on purpose: vary_apply() only ever arms it when L1
     * DID resolve bits (ctx->vary_marker_l1_miss is 0 by construction on
     * that path -- see its field comment), so this same test would ALWAYS
     * return and the L2 answer this GET was launched specifically to obtain
     * would never be applied, silently defeating the whole feature. The
     * mid-park-fresher-L1-marker race this guard protects against is real
     * for a revalidate GET too (self-heal on THIS node, or a concurrent
     * request on this node, can refresh the marker while the GET is in
     * flight) -- but it is provably harmless here rather than needing the
     * same blanket drop: whatever refreshed L1 mid-flight already re-ran
     * vary_apply() on the resume pass immediately before this function (P3-5
     * `access_l1() always runs vary_apply() BEFORE access_l2()`, same
     * invariant this comment leans on above), so ctx->key_hash / *hashp and
     * ctx->vary_gen already carry that refreshed L1 answer walking in here.
     * The apply-if-bits>0 block below only OVERWRITES them if the landed L2
     * blob's own gen is >= ctx->vary_gen (never regresses to an older
     * generation than what L1 -- possibly refreshed since launch -- already
     * has) and always self-heals L1 from whichever generation wins, so a
     * mid-flight refresh cannot be clobbered by a stale L2 answer landing
     * after it: it is simply a no-op tie or the L2 answer confirms what L1
     * already had. */
    if (!ctx->vary_marker_l1_miss && !revalidate) {
        return;
    }

    if (ctx->l2_result == NGX_OK && ctx->l2_blob != NULL
        && ctx->l2_blob_len >= NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 1
        && ngx_http_cache_turbo_blob_validate(ctx->l2_blob, ctx->l2_blob_len,
               &bh, NULL, NULL, NULL, NULL) == NGX_OK
        /* P3-5 (codex-review MINOR): blob_validate() proves generic object
         * framing (magic/version/status/TTL ordering), NOT that this blob IS
         * a marker -- an ordinary captured response happens to satisfy every
         * check blob_validate performs. Require the exact shape
         * marker_store() writes (headers_len==0: markers are memzero'd and
         * never set it; body_len==2: the [bits][gen] pair) before trusting
         * the two body bytes below as an axis bitmask + purge generation
         * rather than the first two content bytes of an unrelated cached
         * response that happened to land under this key (a marker_hash/
         * key_hash collision, or a prefix/namespace mixup between multiple
         * cache_turbo_redis backends sharing one keyspace). A blob that
         * fails this is treated exactly like a corrupt/short marker: bits
         * stay 0, fall through to the ordinary base-key object GET. */
        && bh.headers_len == 0 && bh.body_len == 2)
    {
        bits = ctx->l2_blob[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE];
        if (ctx->l2_blob_len >= NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 2) {
            gen = ctx->l2_blob[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 1];
        }

        /* c-2: on a revalidate trigger only, never regress to a generation
         * OLDER than what this pass's own vary_apply() already resolved
         * from L1 (ctx->vary_gen -- set immediately before access_l2() was
         * called, and re-set on every re-entry including the resume this
         * function is consuming). AUD-GEN1's skip-0-on-wrap invariant
         * means a strict >= is the right test throughout the non-wrapped
         * range this feature operates in (generations bump by PURGE, not by
         * client traffic, so the request volume needed to wrap a one-byte
         * counter mid-revalidation-window is not a realistic race here).
         * Guards exactly the mid-flight-refresh case the guard above's
         * comment describes: if this node's own L1 self-healed to a newer
         * generation while this GET was in flight, an L2 reply still
         * carrying the OLDER generation must not clobber it. */
        if (revalidate && bits > 0 && gen < ctx->vary_gen) {
            bits = 0;
        }

        if (bits > 0) {
            time_t  age, rem_fresh, rem_stale;

            age = ngx_time() - (time_t) bh.created;
            if (age < 0) {
                age = 0;
            }
            rem_fresh = (time_t) bh.fresh_ttl - age;
            rem_stale = (time_t) bh.stale_ttl - age;

            if (rem_stale > 0) {
                ngx_http_cache_turbo_variant_hash(r, &ctx->cache_key, bits,
                                                  gen, ctx->key_hash);
                *hashp = ngx_crc32_short(ctx->key_hash, 32);
                ctx->vary_gen = gen;

                /* Persist the resolution -- see the field comment on
                 * vary_marker_l2_bits: a raw ctx->key_hash rewrite does NOT
                 * survive the next access_prologue()'s build_key() call, so
                 * access_l2_marker_apply() re-derives key_hash from these on
                 * every access_l1() entry instead. */
                ctx->vary_marker_l2_bits = bits;
                ctx->vary_marker_l2_gen = gen;

                /* Self-heal L1 (+ refresh L2): the next request on THIS node
                 * resolves from the (node-local, by-design) L1 marker without
                 * paying this L2 GET again. rem_fresh may be <=0 (the marker
                 * itself is past its fresh TTL but still within its stale
                 * window -- exactly the "accept a stale-but-serveable
                 * marker" contract vary_apply() already applies to an L1
                 * hit), so it is floored at 1s for the blob's fresh_ttl
                 * field, which must stay positive to mean anything. Pass
                 * rem_stale as retain_ttl EXPLICITLY (codex-review perf
                 * finding): marker_store() used to re-derive retain_ttl from
                 * `ttl` via stale_mult internally, which for a small
                 * rem_fresh produced a retention window far short of the
                 * marker's/object's REAL remaining life (rem_stale, already
                 * computed above from the L2 blob's own header) -- silently
                 * truncating a marker that had hundreds of seconds left down
                 * to a handful on every self-heal. rem_stale is already
                 * proven >0 by the `if (rem_stale > 0)` guard this block is
                 * inside. */
                ngx_http_cache_turbo_marker_store(r, clcf, z, &ctx->cache_key,
                    bits, gen, rem_fresh > 0 ? rem_fresh : 1, rem_stale);

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: L2 vary-marker hit \"%V\" "
                               "bits=0x%xi -> variant key, L1 self-healed",
                               &r->uri, bits);
            }
        }
    }

    /* c-2: a revalidation that reaches here with bits still 0 -- either the
     * outer `if` never entered at all (a genuine ctx->l2_result ==
     * NGX_DECLINED: L2 has no marker for this base) or bits<=0 after the
     * mid-flight-refresh gen check just above -- means the authoritative L2
     * side no longer agrees this base has a live variant classification.
     * That is exactly what a Redis-backed PURGE produces on a PEER node:
     * the purging node DELETES the L2 marker outright (purge.c's
     * backend->del(clcf, mk), never a gen-bump -- the gen-bump path is
     * L1-only/memcached ONLY, per that function's own doc comment), so a
     * peer's revalidation GET against the now-purged base gets a
     * well-formed NGX_DECLINED, not a lower generation to compare against.
     * The `bits > 0 && gen < ctx->vary_gen` check above cannot catch this
     * case at all (bits is already 0, nothing to compare) -- this is the
     * separate arm that closes it.
     *
     * This node's own warm L1 marker (still resolving the OLD variant --
     * that resolution is what armed this revalidation in the first place)
     * must be dropped, or the fail-open contract quietly defeats the whole
     * feature for exactly the case it exists to close: a peer's PURGE never
     * becomes visible here, because bits==0 already fails open to "keep
     * what vary_apply() resolved" everywhere else in this function. Rewind
     * to the BASE key: re-derive it from ctx->cache_key the same way
     * build_key() originally computed it (P3-5's own field comment on
     * vary_marker_l2_bits: a raw rewrite does not survive the next
     * access_prologue(), so this reset is only needed to steer THIS pass's
     * remaining phases -- the object-GET phase right after this one reads
     * *hashp/ctx->key_hash and must see the base key, not the stale
     * variant). Also purge the node-local L1 marker itself so the NEXT
     * request on this node re-arms vary_marker_l1_miss instead of
     * re-resolving the same now-invalid marker and re-triggering another
     * revalidation every window forever. */
    if (revalidate && bits == 0 && ctx->l2_result == NGX_DECLINED) {
        if (ngx_http_cache_turbo_digest(ctx->cache_key.data,
                ctx->cache_key.len, ctx->key_hash) == NGX_OK)
        {
            *hashp = ngx_crc32_short(ctx->key_hash, 32);
        }
        ctx->vary_gen = 0;
        ctx->vary_marker_l2_bits = 0;
        ctx->vary_marker_l2_gen = 0;

        /* purge_key() takes and releases the zone mutex ITSELF (see
         * ngx_http_cache_turbo_shm_purge_key() / purge.c's own call site at
         * ~line 101, both unlocked callers) -- this function runs entirely
         * outside any lock (access_l2()'s whole contract, verified by the
         * c-2 design's own park-safety note), so wrapping this call in an
         * extra lock/unlock pair here self-deadlocks on re-entry into the
         * SAME non-recursive ngx_shmtx. */
        (void) clcf->l1->purge_key(z, ctx->vary_marker_key,
            ngx_crc32_short(ctx->vary_marker_key, 32));

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: auto-Vary marker revalidation found "
                       "the L2 marker gone (peer PURGE) -- dropping stale "
                       "L1 resolution for \"%V\", falling back to base key",
                       &r->uri);
    }

    /* L13, extended to the marker key (admin.py CI regression): arm the
     * negative memo on a DEFINITIVE marker miss, mirroring
     * access_l2_miss_account()'s guard on ctx->key_hash exactly --
     * NGX_DECLINED only (a well-formed reply said "not there"; NGX_ERROR is
     * "unknown", per the tri-state contract on ctx->l2_result, and must
     * never arm a memo that asserts absence). No !l2_neg_skipped guard is
     * needed here the way access_l2_miss_account() has one: this function
     * only reaches this point when vary_marker_l2_get() actually LAUNCHED a
     * GET (a memoed skip returns straight from marker_get() and never sets
     * vary_marker_l2_tried, so consume() never runs for it), so a real
     * round-trip backs every arm site here, exactly the invariant that
     * guard protects on the object-key path.
     *
     * c-2: `!revalidate` excludes the revalidate trigger from ever arming
     * this memo. An L2 NGX_DECLINED here does NOT mean "no marker exists"
     * the way it does on the l1-miss path -- L1 already has a live marker
     * (that is the entire reason a revalidate GET was launched); an
     * NGX_DECLINED just means L2 does not (yet, or no longer) have its own
     * copy, which the fail-open contract already handles by leaving the L1
     * answer in place untouched. Arming the memo here would instead
     * SUPPRESS every future revalidation attempt for this base key for up
     * to l2_negative_ttl seconds regardless of window -- defeating the
     * feature's own bound (the ⚠ hazard this row exists to close, applied
     * to the fix itself). */
    if (!revalidate && clcf->l2_negative_ttl > 0
        && ctx->l2_result == NGX_DECLINED)
    {
        clcf->l1->l2_neg_set(z, ctx->vary_marker_key,
            ngx_crc32_short(ctx->vary_marker_key, 32), clcf->l2_negative_ttl);
    }

    /* Consumed: clear the marker GET result so the object-GET phase right
     * after this one sees a clean slate and fills l2_done/l2_result/l2_blob
     * in for the (now correctly keyed, whether base or variant) object
     * itself -- same contract as a request that never had a marker miss. */
    ctx->l2_done = 0;
    ctx->l2_result = 0;
    ctx->l2_blob = NULL;
    ctx->l2_blob_len = 0;
}


/* MAINT-H4e phase helper for ngx_http_cache_turbo_access_l2().
 * PHASE 1 -- the negative-memo short-circuit, extracted whole.
 *
 * ⚠ LOCK WINDOW: takes no lock of its own; l1->l2_neg_check() acquires and
 * releases the zone mutex internally, exactly as the inline call did. No
 * pointer crosses an unlock here.
 *
 * void: sets ctx state (l2_done/l2_result/l2_neg_skipped) but never produces
 * a value the caller must branch on -- the next phase re-reads ctx->l2_done
 * itself, same as the inline code fell through unconditionally. */
static void
ngx_http_cache_turbo_access_l2_neg_memo(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_cache_turbo_zone_t *z, uint32_t hash)
{
    /* L13: a live negative memo says an L2 GET for this key missed within the
     * last cache_turbo_l2_negative_ttl seconds. Skip the round-trip and treat
     * it as an L2 miss directly. Marking l2_done keeps the rest of the handler
     * (and the l2_misses metric below) on exactly the path a real miss takes,
     * so a memoed miss and a fetched miss are indistinguishable downstream. */
    if (clcf->backend && !ctx->l2_done && !ctx->l2_neg_force
        && clcf->l2_negative_ttl > 0
        && clcf->l1->l2_neg_check(z, ctx->key_hash, hash) == NGX_DECLINED)
    {
        ctx->l2_done = 1;
        /* NGX_DECLINED is right HERE (unlike the cold-wait re-poll seed, which
         * uses NGX_ERROR): the memo asserts L2 definitively lacks the key, and
         * downstream must not be able to tell a memoed miss from a fetched one.
         * l2_neg_skipped on the next line is what stops this from re-arming. */
        ctx->l2_result = NGX_DECLINED;
        ctx->l2_neg_skipped = 1;
        (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->l2_neg_skips, 1);
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: L2 GET skipped by negative memo \"%V\" "
                       "key=%ui", &r->uri, (ngx_uint_t) hash);
    }
}



/* MAINT-H4e phase helper for ngx_http_cache_turbo_access_l2().
 * PHASE 2 -- the (parking) backend GET, extracted whole.
 *
 * ⚠ This phase is the one that can PARK the request (NGX_AGAIN on
 * backend->get()). A resume re-enters the whole handler from the top, not
 * this function -- ctx->l2_done/l2_result/l2_blob live in the request ctx
 * (r->pool lifetime), not a stack local, so nothing cached here needs to
 * survive the park; the next call to access_l2() re-derives everything from
 * ctx exactly as the inline code did.
 *
 * Returns NGX_DONE with *out_rc == NGX_AGAIN when parked (caller must return
 * immediately without touching ctx again); NGX_DECLINED otherwise, meaning
 * "fall through to the L2-result phase" -- ctx->l2_done tells that phase
 * whether a result is actually ready. */
static ngx_int_t
ngx_http_cache_turbo_access_l2_get(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    uint32_t hash, ngx_int_t *out_rc)
{
    /* S231-L2-BACKOFF: this request's own marker GET already proved L2
     * unreachable (transport failure -- see access_l2_marker_consume()).
     * Skip paying (and miscounting against connect_backoff's fail-fast
     * window) a second, redundant connect attempt for information already
     * known; report the SAME "unknown" outcome an ordinary failed GET
     * would (NGX_ERROR, never NGX_DECLINED -- this is not a definitive
     * miss and must not arm the L13 negative memo). l2_done=1 so every
     * downstream reader (miss accounting, the negative-memo phase) treats
     * this exactly like a completed-but-inconclusive GET, not a GET that
     * never ran. */
    if (ctx->vary_marker_l2_down) {
        ctx->l2_done = 1;
        ctx->l2_result = NGX_ERROR;
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: L2 GET skipped -- this request's own "
                       "marker GET already proved L2 down \"%V\" key=%ui",
                       &r->uri, (ngx_uint_t) hash);
        return NGX_DECLINED;
    }

    if (clcf->backend && !ctx->l2_done) {
        ngx_int_t  rc = clcf->backend->get(r, clcf, ctx);
        if (rc == NGX_AGAIN) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: parked on L2 GET \"%V\" key=%ui",
                           &r->uri, (ngx_uint_t) hash);

            *out_rc = NGX_AGAIN;
            return NGX_DONE;
           /* parked; redis read handler resumes */
        }
        /* NGX_DECLINED: L2 disabled or could not start; go to origin */
    }

    return NGX_DECLINED;
}



/* MAINT-H4e phase helper for ngx_http_cache_turbo_access_l2().
 * PHASE 3a -- the L2 blob is present but past its serveable window: arm the
 * breaker/SIE fallbacks from it and mark EXPIRED. Stayed WHOLE rather than
 * being split further: the breaker-arm and SIE-arm blocks share the same
 * `bh` (validated header) and the same any-age arming rule, and both are
 * pure ctx writes with no lock of their own -- there is no lock or pinned
 * pointer to move across a boundary by keeping them together. void: this
 * arm-only path never produces a value the caller branches on; the caller
 * always falls through to the shared "corrupt/expired -> miss" return after
 * it, same as the inline code. */
static void
ngx_http_cache_turbo_access_l2_expired_arm(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_cache_turbo_zone_t *z, ngx_http_cache_turbo_blob_hdr_t *bh,
    uint32_t hash)
{
    /* Object outlived its serveable window in L2 (Redis TTL slack): treat
     * as a miss and go to origin.
     *
     * NOTE (v4-4 asymmetry, intentional): the load-adaptive stale
     * widening is applied to the L1 serve decision only (it widens
     * the local stale_until without rewriting the stored window).
     * It is deliberately NOT applied here: this branch both SERVES
     * and STORES the L2 blob into L1 (rem_stale below feeds
     * l1->store), so widening rem_stale would PERSIST a stretched
     * window into L1 and diverge from the serve-only L1 semantics.
     * An L2-restored entry past its stored window is conservatively
     * a miss; the origin single-flight bounds the refetch.
     *
     * RFC-2 stale-if-error (CTB4): if the L1 path did not already arm
     * a snapshot (L1 evicted, or this is a peer's fresher-but-expired
     * copy) and this L2 blob still carries a serve-on-error window
     * (created + sie_ttl) covering now, arm from it so a failing
     * origin below replays it instead of erroring. */
    /* P6/O4.3: arm the breaker fallback from the L2 blob too. This
     * is the L1-absent / L1-evicted case -- a peer's copy that is
     * past its serveable window. Same any-age rule and same
     * breaker_should_consult() off-switch as the L1 site above. */
    if (!ctx->brk_arm_done
        && ngx_http_cache_turbo_breaker_should_consult(clcf))
    {
        /* No copy: ctx->l2_blob already lives in r->pool with the
         * same lifetime as this request, so pointing at it is both
         * correct and free. brk_ref stays NULL -- there is no shm
         * slab reference to drop. */
        ctx->brk_snap = ctx->l2_blob;
        ctx->brk_snap_len = ctx->l2_blob_len;
        ctx->brk_ref = NULL;
        ctx->brk_arm_done = 1;
        ctx->brk_armed = 1;
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
        /* O4.4-i negative control for THIS site. Inside the
         * should_consult() branch on purpose -- see field comment.
         * Bumps the L2 field only, so a delta here cannot have come
         * from the L1 site above. */
        (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->test_brk_armings_l2, 1);
#endif
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: breaker fallback armed from "
                       "L2 \"%V\" key=%ui", &r->uri,
                       (ngx_uint_t) hash);
    }

    if (!ctx->sie_armed && bh->sie_ttl > 0
        && ngx_time() < (time_t) bh->created + (time_t) bh->sie_ttl)
    {
        u_char *snap = ngx_pnalloc(r->pool, ctx->l2_blob_len);
        if (snap != NULL) {
            ngx_memcpy(snap, ctx->l2_blob, ctx->l2_blob_len);
            ctx->sie_snap = snap;
            ctx->sie_snap_len = ctx->l2_blob_len;
            ctx->sie_armed = 1;
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: SIE armed from L2 \"%V\" "
                           "key=%ui", &r->uri, (ngx_uint_t) hash);
        }
    }
    /* L2 held this object but it is past its serveable window:
     * EXPIRED (a cached entry was found and refetched), not a cold
     * MISS. Covers the L1-absent / L1-evicted case where the L1
     * fall-through above never ran. */
    ctx->status = NGX_HTTP_CACHE_TURBO_ST_EXPIRED;
    /* V-HANG-2: L2 HAS the key, we just cannot serve it. If we are
     * a cold-miss waiter, the fill we are parked for has already
     * landed — every further poll re-fetches this same unserveable
     * blob, so waiting out lock_timeout adds pure latency. Record
     * it; the wait loop gives up on the next re-entry. */
    ctx->l2_present_unserveable = 1;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cache_turbo: L2 blob expired \"%V\" key=%ui "
                   "-> origin", &r->uri, (ngx_uint_t) hash);
}



/* MAINT-H4e phase helper for ngx_http_cache_turbo_access_l2().
 * PHASE 3b -- the L2 blob is still serveable: request-freshness-bounds
 * check, then promote into L1 and serve as a HIT. Stayed WHOLE rather than
 * being split further: promote (store_if) and serve must observe the SAME
 * rem_fresh/rem_stale decided together, and there is no lock held across
 * this phase to move by splitting it -- store_if() takes and releases the
 * zone mutex internally, same as the inline code, so no callee re-acquires
 * a mutex the caller holds.
 *
 * Returns NGX_DONE with *out_rc set when this phase served the response
 * (the "passed bounds and promoted" arm); NGX_DECLINED when the blob failed
 * request freshness bounds and must fall through to origin, matching the
 * inline req_reval arm. */
static ngx_int_t
ngx_http_cache_turbo_access_l2_promote_serve(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_cache_turbo_zone_t *z, ngx_http_cache_turbo_blob_hdr_t *bh,
    time_t rem_fresh, time_t rem_stale, uint32_t hash, ngx_int_t *out_rc)
{
    /* RFC-1: the L2 copy must also satisfy the request freshness
     * bounds. An L2 entry can be younger than the L1 one (a peer
     * refreshed it), so evaluate it on its own age, not the L1
     * verdict. If it fails, revalidate at origin instead of serving
     * the rejected copy (req_reval blocks the cold-claim re-serve). */
    ngx_int_t  l2_fresh_ok = 1, l2_stale_ok = 1;
    ngx_int_t  promote_rc;

    /* P2: same gate as the L1 verdict above — only run the bounds
     * check when the client actually sent one. With none set the
     * verdict leaves l2_fresh_ok/l2_stale_ok at 1 and the block below
     * can never set req_reval, so it is pure dead work on the L2 hot
     * path. The defaults are the no-bounds answer. */
    if (ctx->has_req_bounds) {
        ngx_http_cache_turbo_req_serve_verdict(ctx,
            (time_t) bh->created, ngx_time(),
            (time_t) bh->created + (time_t) bh->fresh_ttl,
            &l2_fresh_ok, &l2_stale_ok);
    }

    if ((rem_fresh > 0 && !l2_fresh_ok)
        || (rem_fresh <= 0 && !l2_stale_ok))
    {
        ctx->req_reval = 1;
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "cache_turbo: L2 blob fails request freshness bounds "
            "\"%V\" key=%ui -> origin", &r->uri, (ngx_uint_t) hash);
        return NGX_DECLINED;
    }

    /* The blob passed blob_validate() above: framing, the full
     * TLV walk, AND the status/TTL range checks — so the slot we
     * put in L1 cannot be structurally unserveable.
     *
     * AUD-HDR1: this comment used to claim "full validation",
     * which was read as licence to promote an L2 blob into shm
     * where every worker serves it. It was not true of the
     * CONTENT: blob_validate inspects no header bytes. The
     * content guarantee comes from header_admissible(), applied
     * on the way OUT in restore_response(), so a poisoned header
     * in this blob is dropped at serve time rather than
     * prevented from entering L1. Keep the two claims separate;
     * conflating them is what let AUD-HDR1 survive to HEAD. */
    /* AUD-L2-PROMOTE-RACE: this GET unlocked before the
     * request parked; on resume it used to promote
     * unconditionally, so a slow L2 reply could overwrite a
     * NEWER origin response that landed while parked.
     * store_if() decides "is the resident entry newer?" and
     * writes under ONE lock hold, closing that window.
     * NGX_DECLINED means the promotion did not happen -- that
     * is CORRECT, not an error: the blob we hold is still
     * valid and gets served below exactly as before, we
     * simply declined to displace a fresher L1 entry. */
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    /* AUD-L2-PROMOTE-RACE test hook: the gap this fix closes
     * is pure CPU between the unlock above and store_if()'s
     * own lock -- no I/O, no yield point, unreachable from a
     * black-box HTTP timing race. Blocking THIS worker here
     * (ngx_msleep = plain usleep, stalls only its own event
     * loop) gives a test a deterministic window to land a
     * concurrent write from a DIFFERENT worker before the
     * decide-and-store below runs. 0/unset = no hold. */
    if (clcf->test_l2_promote_hold_ms > 0) {
        ngx_msleep((ngx_msec_t) clcf->test_l2_promote_hold_ms);
    }
#endif
    promote_rc = clcf->l1->store_if(z,
               ctx->key_hash, hash,
               ctx->l2_blob, ctx->l2_blob_len,
               rem_fresh, rem_stale,
               NGX_HTTP_CACHE_TURBO_STORE_IF_NEWER);

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    /* AUD-L2-PROMOTE-RACE oracle: NOTICE (not debug) so it is
     * readable at the harness's default log level -- same
     * reasoning as test_sie_unconsumed (AUD-SIE-BODY). Two
     * DISTINCT values so a test can tell "declined" from
     * "stored" apart, never inferring one from the other's
     * absence: an absent line must fail the test, not read
     * as either. */
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                  "cache_turbo: test_l2_promote_rc=%i",
                  promote_rc);
#endif

    if (promote_rc == NGX_DECLINED) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: L2 promote skipped, "
                       "newer entry resident \"%V\" key=%ui",
                       &r->uri, (ngx_uint_t) hash);
    }

    (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->hits, 1);
    (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->l2_hits, 1);
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cache_turbo: L2 HIT \"%V\" key=%ui len=%uz "
                   "(filled L1)", &r->uri, (ngx_uint_t) hash,
                   ctx->l2_blob_len);

    *out_rc = ngx_http_cache_turbo_serve(r, ctx->l2_blob,
              ctx->l2_blob_len, rem_fresh <= 0 ? 1 : 0,
              z, NULL, NULL);
    return NGX_DONE;

                          /* L2 blob lives in r->pool, no ref */
}



/* MAINT-H2 phase helper for ngx_http_cache_turbo_access_handler().
 * PHASE 2 -- the L2 consult: negative-memo short-circuit, the (parking)
 * backend GET, and the L2-hit validate/arm/promote/serve block.
 *
 * ⚠ LOCK WINDOW: the zone mutex is NOT held on entry (phase 1 released it on
 * its fall-through path) and is not taken here; l1->l2_neg_check(),
 * l1->l2_neg_set() and l1->store_if() each acquire and release it internally,
 * so no callee re-acquires a mutex this caller holds.
 *
 * ⚠ This phase can PARK the request (NGX_AGAIN on the backend GET). A resume
 * re-enters the handler from the top, which is why every state change here is
 * guarded by an idempotency flag (l2_done, brk_arm_done, sie_armed,
 * l2_neg_skipped) exactly as before.
 *
 * MAINT-H4e: decomposed into ngx_http_cache_turbo_access_l2_neg_memo() (PHASE
 * 1), ngx_http_cache_turbo_access_l2_get() (PHASE 2), and
 * ngx_http_cache_turbo_access_l2_expired_arm() /
 * ngx_http_cache_turbo_access_l2_promote_serve() (PHASE 3a/3b, the two
 * mutually exclusive arms after blob_validate). This function is now the
 * dispatcher; every phase runs at exactly the point the inline code did. */
static ngx_int_t
ngx_http_cache_turbo_access_l2(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_cache_turbo_zone_t *z, uint32_t hash, ngx_int_t *out_rc)
{
    /* P3-5 PHASE -1/0: consume the result of a previously-parked marker GET (a
     * no-op on every entry except the resume of that specific park), then --
     * only on a genuine L1 marker miss with auto_vary on -- try the L2-backed
     * marker before the neg-memo/object-GET phases below, which are keyed on
     * `hash`/ctx->key_hash and must see the corrected variant key/hash if the
     * marker consult resolves one. Both are no-ops (return immediately) on
     * the warm-marker path: vary_marker_l1_miss is never set there, so this
     * costs the warm path nothing beyond the two flag reads. */
    ngx_http_cache_turbo_access_l2_marker_consume(r, clcf, ctx, z, &hash);

    if (ngx_http_cache_turbo_access_l2_marker_get(r, clcf, ctx, z, out_rc)
        == NGX_DONE)
    {
        return NGX_DONE;
    }

    ngx_http_cache_turbo_access_l2_neg_memo(r, clcf, ctx, z, hash);

    if (ngx_http_cache_turbo_access_l2_get(r, clcf, ctx, hash, out_rc)
        == NGX_DONE)
    {
        return NGX_DONE;
    }

    if (ctx->l2_done && ctx->l2_result == NGX_OK && ctx->l2_blob) {
        /* L2 hit: FULLY validate the blob (STAB-4) before touching L1, populate
         * L1 so later reads hit shm, then serve it as a normal HIT. */
        ngx_http_cache_turbo_blob_hdr_t  bh;

        if (ngx_http_cache_turbo_blob_validate(ctx->l2_blob, ctx->l2_blob_len,
                                               &bh, NULL, NULL,
                                               NULL, NULL) == NGX_OK)
        {
            time_t  age, rem_fresh, rem_stale;

            /* Restore the object's REMAINING lifetime, not the location
             * default — otherwise every L2 hit re-promotes a stale object as
             * fresh and it never expires (and per-status/upstream TTLs are
             * lost across the L2 round-trip). */
            age = ngx_time() - (time_t) bh.created;
            if (age < 0) {                 /* clock skew between writers */
                age = 0;
            }
            rem_fresh = (time_t) bh.fresh_ttl - age;   /* <=0 => stale */
            rem_stale = (time_t) bh.stale_ttl - age;   /* total window left */

            if (rem_stale <= 0) {
                ngx_http_cache_turbo_access_l2_expired_arm(r, clcf, ctx, z,
                    &bh, hash);
            } else {
                if (ngx_http_cache_turbo_access_l2_promote_serve(r, clcf,
                        ctx, z, &bh, rem_fresh, rem_stale, hash, out_rc)
                    == NGX_DONE)
                {
                    return NGX_DONE;
                }
            }
        }
        /* corrupt/short/expired blob: treat as a miss, fall through to origin */
    }
    return NGX_DECLINED;
}



/* MAINT-H2 phase helper for ngx_http_cache_turbo_access_handler().
 * PHASE 3 -- account the L2 miss once per request and arm the negative memo.
 *
 * void: the inline block had no return of any kind; the handler always
 * continues into the only-if-cached gate afterwards. */
static void
ngx_http_cache_turbo_access_l2_miss_account(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_cache_turbo_zone_t *z, uint32_t hash)
{
    /* L2 was consulted but did not satisfy the request (v12 metric). Count it
     * at most once per request: a cold miss parks on the L2 GET and then parks
     * AGAIN on the v4-2 NX lock / v10 cold-wait, re-entering this handler from
     * the top each resume — l2_miss_counted guards the double/triple count. */
    if (clcf->backend && ctx->l2_done && !ctx->l2_miss_counted) {
        ctx->l2_miss_counted = 1;
        (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->l2_misses, 1);

        /* L13: remember this miss so the next cold request skips the GET.
         *
         * ⚠ Guarded on !l2_neg_skipped: re-stamping a miss we only "knew about"
         * BECAUSE of a memo would slide the window forward on every request and
         * keep L2 switched off indefinitely for a hot-but-absent key. Only a
         * miss learned from a REAL round-trip may arm the memo, so the window
         * is bounded at l2_negative_ttl from the last actual L2 answer.
         *
         * ⚠ Guarded on l2_result == NGX_DECLINED: ONLY a definitive miss arms it.
         * l2_result is tri-state (see the ctx field) and NGX_ERROR means L2's
         * answer is unknown -- a timeout, a dropped connection, a malformed or
         * error reply, or a local alloc failure on a real HIT. Arming on those
         * turned an L2 OUTAGE into self-inflicted amplification: every failed GET
         * armed a memo, the memos then suppressed the GETs that would have noticed
         * L2 coming back, and the cache stayed switched off for up to
         * l2_negative_ttl past recovery. The alloc-failure sub-case was worse
         * still -- it armed "key is absent" immediately after L2 said it HAS the
         * key. (Codex #5 on PR #77.) */
        if (clcf->l2_negative_ttl > 0 && !ctx->l2_neg_skipped
            && ctx->l2_result == NGX_DECLINED)
        {
            clcf->l1->l2_neg_set(z, ctx->key_hash, hash,
                                 clcf->l2_negative_ttl);
        }
    }
}



/* MAINT-H2 phase helper for ngx_http_cache_turbo_access_handler().
 * PHASE 4 -- only-if-cached (RFC 9111 5.2.1.7): both caches are exhausted,
 * so either serve the breaker's armed snapshot (an OPEN breaker makes that a
 * pure cache serve) or answer 504. Reads the breaker state RAW so this
 * request cannot be promoted to probe.
 *
 * ⚠ Must stay BEFORE the breaker gate helper -- see that helper's comment. */
static ngx_int_t
ngx_http_cache_turbo_access_only_if_cached(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_cache_turbo_zone_t *z, uint32_t hash, ngx_int_t *out_rc)
{
    /* only-if-cached (RFC 9111 §5.2.1.7): L1 missed/expired and L2 (if any) did
     * not satisfy it either — both caches are exhausted. The client refuses
     * origin contact, so answer 504 rather than engaging the cold-miss
     * single-flight / origin path below. A fresh or stale HIT above already
     * returned (only-if-cached is satisfied by any cache serve). */
    if (ctx->req_only_if_cached) {

        /* P6/O4.3: the breaker's any-age snapshot is still a CACHE serve with
         * zero origin contact, so it satisfies only-if-cached in full -- but
         * only when the breaker is already OPEN. Read the state RAW rather than
         * through _breaker_state(), which is not a pure getter: it would
         * promote this request to probe, and an only-if-cached request can
         * never be a probe (it will not contact the origin by definition), so
         * the lease would be burnt and the recovery window lost. The admin
         * stats path reads raw for the same reason.
         *
         * A CLOSED or HALF_OPEN breaker falls through to the 504 below: with
         * the origin believed reachable, serving a body past every configured
         * window is the operator's outage policy, not this client's to invoke. */
        if (ngx_http_cache_turbo_breaker_should_consult(clcf)
            && ctx->brk_armed
            && ngx_http_cache_turbo_brk_state(ngx_http_cache_turbo_zone_sh(z)->breaker_state)
                   == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN)
        {
            (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->stale_serves, 1);
            /* S7.1: a genuine breaker-fallback SERVE (this is the
             * only-if-cached twin of the pre-origin-gate ACT_SERVE site
             * below; both deliver a STALE-BREAKER response). */
            (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->breaker_serves, 1);
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: only-if-cached + breaker OPEN -> "
                           "STALE-BREAKER serve \"%V\" key=%ui len=%uz",
                           &r->uri, (ngx_uint_t) hash, ctx->brk_snap_len);
            /* ref_data = NULL: the arming site owns the reference drop. */

            *out_rc = ngx_http_cache_turbo_serve(r, ctx->brk_snap,
                      ctx->brk_snap_len, 1, z, NULL, "STALE-BREAKER");
            return NGX_DONE;

        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: only-if-cached miss \"%V\" key=%ui -> 504",
                       &r->uri, (ngx_uint_t) hash);

        *out_rc = NGX_HTTP_GATEWAY_TIME_OUT;
        return NGX_DONE;

    }
    return NGX_DECLINED;
}



/* MAINT-H2 phase helper for ngx_http_cache_turbo_access_handler().
 * PHASE 5 -- the pre-origin circuit-breaker gate: the chokepoint every
 * origin-bound request passes exactly once.
 *
 * ⚠ ORDERING IS LOAD-BEARING and unchanged by this extraction: this helper is
 * called AFTER the only-if-cached phase (so a 504 is never preempted by a 503
 * and an only-if-cached request can never win the probe promotion) and BEFORE
 * the min_uses and cold-miss phases (so a stampede onto a dead origin never
 * claims a stub and parks in cold_wait for a fill that cannot arrive). The
 * full rationale is preserved in the comment inside.
 *
 * ⚠ Does NOT touch the zone mutex. _shm_breaker_state(), _brk_ref_drop() and
 * _breaker_unavailable() manage their own locking internally. */
static ngx_int_t
ngx_http_cache_turbo_access_breaker_gate(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_cache_turbo_zone_t *z, uint32_t hash, ngx_int_t *out_rc)
{
    /* ------------------------------------------------------------------
     * P6/O4.3: the pre-origin circuit-breaker gate.
     *
     * The chokepoint every ORIGIN-BOUND request passes exactly once: L1 has
     * missed or fallen past its stale window, L2 has been consulted and did not
     * satisfy us, and only-if-cached has already had its say. Everything below
     * this line (min_uses, the cold-miss single-flight, the plain miss) either
     * answers locally or returns NGX_DECLINED into the upstream.
     *
     * ⚠ SCOPE. This gate governs the requests this module can actually serve
     * from cache: anonymous, cacheable, main GET/HEAD. The prologue turns away
     * non-GET/HEAD, subrequests, Authorization-bearing requests, request
     * no-cache, auto-classified dynamic URIs and configured bypasses BEFORE the
     * handler ever gets here, and those still reach the origin while the
     * breaker is OPEN. That is not an oversight to be "fixed" by 503-ing them:
     * the breaker's whole mechanism is answering from a cached representation,
     * and for a request the module never caches there is nothing to answer
     * with. Refusing them would mean 503-ing authenticated and non-idempotent
     * traffic on the strength of a breaker that never observed it.
     *
     * ⚠ Placed AFTER the only-if-cached 504. RFC 9111 §5.2.1.7 makes 504 the
     * required answer when the cache cannot satisfy such a request, so the
     * breaker must not preempt it with a 503 -- and, more importantly, an
     * only-if-cached request must never become the origin PROBE, because by
     * definition it will not contact the origin. It would win the promotion and
     * then exit locally, burning one recovery lease per open window. A request
     * that CAN be satisfied from the breaker's snapshot returned above.
     *
     * ⚠ Placed BEFORE the cold-miss single-flight. A stampede onto a dead
     * origin must not first claim a stub and park every loser in cold_wait()
     * for a fill that can never arrive -- that turns an outage into lock_timeout
     * of latency on every request plus a parked worker for each.
     *
     * Three verdicts, from ngx_http_cache_turbo_shm_breaker_state():
     *
     *   CLOSED     -- normal service. Fall through untouched.
     *   HALF_OPEN  -- ⚠ WE ARE THE PROBE, and we hold the lease token in
     *                 ctx->brk_probe. This request MUST reach the origin so the
     *                 header filter can report the outcome back under that
     *                 token; serving it from cache would leave the breaker with
     *                 nobody to close it. Falling through is mandatory.
     *   OPEN       -- serve the fallback body if one was armed, else 503 +
     *                 Retry-After. Either way: no origin contact.
     *
     * ⚠ The state call is skipped entirely when breaker_should_consult() is
     * false (any of: not enabled, breaker off, threshold == 0, window == 0).
     * It is not a pure getter -- it performs the due OPEN -> HALF_OPEN
     * transition -- so calling it with the breaker disabled would drive a
     * state machine nothing can feed, and pay an shm read on every miss.
     */
    if (ngx_http_cache_turbo_breaker_should_consult(clcf))
    {
        ngx_uint_t  bact;

        /* ⚠ Consult at most ONCE per request; latch the verdict AND the lease
         * token. This handler is re-entered from the top on every park/resume
         * (L2 GET, the v4-2 NX lock, each cold_wait re-poll), and
         * _breaker_state() is not a pure getter -- it promotes exactly one
         * caller per open window and returns HALF_OPEN only to that promoter.
         * Consulting twice therefore hands a request that WAS the probe an OPEN
         * verdict on its resume, answers it locally, and leaves nobody to close
         * the breaker. See the brk_consulted field comment. */
        if (!ctx->brk_consulted) {
            ctx->brk_consulted = 1;
            ctx->brk_state = ngx_http_cache_turbo_shm_breaker_state(
                z, clcf->breaker_open, &ctx->brk_probe);
            ctx->brk_action = ngx_http_cache_turbo_breaker_action(
                ctx->brk_state, ctx->brk_armed);

            if (ctx->brk_state == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN) {
                /* Logged only on the consult that actually won the promotion.
                 * This line means "this request owes the breaker an outcome". */
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: breaker HALF_OPEN, this request is "
                               "the probe \"%V\" key=%ui -> origin",
                               &r->uri, (ngx_uint_t) hash);
            }
        }

        bact = ctx->brk_action;

        /* ⚠ O4.3-c (Codex F2): the probe leaves for the origin HERE, before
         * min_uses, claim(), the cross-node NX lock and cold_wait() -- every
         * one of which can park this request and resume it at the top of the
         * handler, where the L1 and L2 serve paths return BEFORE this gate and
         * brk_consulted stops the gate re-running. A parked probe answered from
         * a peer's fill never touches the origin, records no outcome, and
         * leaves the breaker HALF_OPEN until its lease expires -- the recovery
         * window is spent on a request that learned nothing.
         *
         * NGX_DECLINED is the handler's ordinary "carry on to the upstream"
         * return, the same one the fall-through below reaches; taking it early
         * simply skips the machinery that could divert us. */
        if (bact == NGX_HTTP_CACHE_TURBO_BRK_ACT_PROBE) {
            /* O4.3-c (F3): this request is going to the origin and can never
             * consume its armed fallback, so release the slab pin now instead
             * of holding it for the whole upstream round trip. */
            ngx_http_cache_turbo_brk_ref_drop(ctx, z);
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: breaker probe bypasses single-flight "
                           "\"%V\" key=%ui -> origin",
                           &r->uri, (ngx_uint_t) hash);

            *out_rc = NGX_DECLINED;
            return NGX_DONE;

        }

        /* O4.3-c (F3): same for an ordinary CLOSED-breaker request -- it falls
         * through to the origin below and will not serve the fallback either.
         * Only ACT_SERVE consumes it, and ACT_FAIL has nothing armed by
         * definition (it is the no-body verdict). Holding these pins across a
         * slow upstream is what lets an evictor drain the zone's LRU without
         * reclaiming any blob storage. */
        if (bact == NGX_HTTP_CACHE_TURBO_BRK_ACT_PASS) {
            ngx_http_cache_turbo_brk_ref_drop(ctx, z);
        }

        if (bact != NGX_HTTP_CACHE_TURBO_BRK_ACT_PASS) {

            if (bact == NGX_HTTP_CACHE_TURBO_BRK_ACT_SERVE) {
                /* Serve the stale body. ngx_http_cache_turbo_serve() is correct
                 * here and there is NO double-finalize hazard: we are in the
                 * ACCESS phase with no upstream in flight, the same position as
                 * every other _serve() call site. The hazard documented on
                 * ngx_http_cache_turbo_sie_rewrite() is specific to the HEADER
                 * FILTER, where a send_header + finalize would land inside
                 * ngx_http_special_response_handler on an already-finalizing
                 * request. Do not "unify" the two.
                 *
                 * stale = 1 suppresses the conditional-GET 304 shortcut: this
                 * copy is past its window and has NOT been revalidated, so a
                 * 304 would tell the client its cached copy is still good on
                 * the authority of an origin we cannot reach. */
                (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->stale_serves, 1);
                /* S7.1: the pre-origin-gate breaker-fallback SERVE. Bumped
                 * here (the delivery site), not at breaker_action()/
                 * ACT_SERVE classification, so this counts responses actually
                 * served, matching sie_serves/origin_failures discipline. */
                (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->breaker_serves, 1);
                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: breaker OPEN -> STALE-BREAKER serve "
                               "\"%V\" key=%ui len=%uz",
                               &r->uri, (ngx_uint_t) hash, ctx->brk_snap_len);
                /* ref_data = NULL on purpose: when brk_snap points into the
                 * slab, the ARMING site already registered the pool cleanup
                 * that drops that reference. Passing ctx->brk_ref here would
                 * register a SECOND cleanup for the same blob and double-drop
                 * the refcount, freeing a slab another worker may still be
                 * serving. The single cleanup covers both outcomes -- served
                 * and not served -- because it is tied to the request pool, not
                 * to this call. */

                *out_rc = ngx_http_cache_turbo_serve(r, ctx->brk_snap,
                          ctx->brk_snap_len, 1, z, NULL, "STALE-BREAKER");
                return NGX_DONE;

            }

            /* Nothing cached at any age: answer immediately rather than
             * spending a full connect/read timeout on a corpse. This is the
             * worker-exhaustion case the breaker exists for -- the 503 is the
             * feature, not a failure.
             *
             * Counted as a MISS so the zone totals stay reconcilable: every
             * other terminal branch in this handler bumps one of hits /
             * stale_serves / misses, and a branch that bumps nothing makes
             * hits+stale_serves+misses silently undercount once O4.4 makes the
             * breaker reachable. A miss is also what this is -- nothing was
             * served from cache. This is the ACT_FAIL branch (no body armed),
             * so it does not touch breaker_serves (S7.1) -- that counter is
             * bumped only at the two ACT_SERVE delivery sites above. */
            (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->misses, 1);
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: breaker OPEN, no body \"%V\" key=%ui "
                           "-> 503", &r->uri, (ngx_uint_t) hash);

            *out_rc = ngx_http_cache_turbo_breaker_unavailable(r, clcf);
            return NGX_DONE;

        }
    }
    return NGX_DECLINED;
}



/* MAINT-H2 phase helper for ngx_http_cache_turbo_access_handler().
 * PHASE 6 -- the min_uses gate for the cache_turbo_lock OFF case only. When
 * lock is ON the gate is merged into resolve_miss() inside the cold phase
 * (S231-PERF-MISSLOCKS); the `!clcf->lock` conjunct in the condition is what
 * keeps the two mutually exclusive, and it moved with the block. */
static ngx_int_t
ngx_http_cache_turbo_access_min_uses(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_cache_turbo_zone_t *z, uint32_t hash, ngx_int_t *out_rc)
{
    /* min_uses (v15): defer caching until the key has cold-missed min_uses times,
     * so one-hit-wonder URLs never occupy the cache. The gate sits AFTER the L2
     * consult (a popular key already held in L2 was served above, never blocked
     * by min_uses) and BEFORE the v10 lock path (no point single-flighting a key
     * we are not going to store yet). Run once per request — min_uses_passed
     * guards the park/resume re-entries (the L2 GET / NX lock / cold-wait wakes
     * all re-enter this handler from the top).
     *
     * S231-PERF-MISSLOCKS: when cache_turbo_lock is ALSO on, count_miss() here
     * and claim() in the block below fire back-to-back on this same call with
     * no park between them -- two separate zone-mutex acquisitions and two
     * rbtree descents on the identical key. clcf->l1->resolve_miss() (see its
     * contract comment in shm.c) collapses that into one lock/one lookup; the
     * `clcf->lock` case is handled entirely inside the block below via
     * ctx->min_uses_merged so this gate's own control flow (min_uses_skip,
     * misses/min_uses_skips counters, min_uses_passed, the NGX_DECLINED
     * short-circuit) stays exactly as it was for the lock-off case, where
     * there is no claim() to merge with and the standalone count_miss() call
     * is unchanged below. */
    if (clcf->min_uses > 1 && !ctx->min_uses_passed && !ctx->lock_done
        && !clcf->lock)
    {
        if (clcf->l1->count_miss(z, ctx->key_hash, hash, clcf->min_uses,
                clcf->min_uses_window) == NGX_DECLINED)
        {
            /* Still below the threshold: run to the origin but do NOT store (the
             * header filter checks min_uses_skip before capturing). */
            ctx->min_uses_skip = 1;
            (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->misses, 1);
            (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->min_uses_skips, 1);
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: below min_uses \"%V\" key=%ui -> origin "
                           "(no store)", &r->uri, (ngx_uint_t) hash);

            *out_rc = NGX_DECLINED;
            return NGX_DONE;

        }
        /* Threshold reached: this request stores via the normal cold path below. */
        ctx->min_uses_passed = 1;
    }
    return NGX_DECLINED;
}



/*
 * MAINT-SEAM: the cross-node NX resume arms of the cold-miss phase, taken when
 * ctx->lock_done says this request is re-entering after a park.
 *
 * ⚠ Called with the zone mutex NOT held, from before access_cold()'s
 * CLAIM_FRESH span -- it takes no lock of its own, and cold_wait() parks as it
 * did inline. The WON arm must run cold_mark_winner() with
 * ctx->pending_l1_owner: the claim_owner stack local that carried the lease
 * token does not survive the park, so the stash is the only handle left and
 * dropping it here would leak the L1 lease.
 *
 * Returns the value the caller assigns to *out_rc; the caller returns NGX_DONE
 * on both arms, exactly as the inline block did.
 */
static ngx_int_t
ngx_http_cache_turbo_cold_resume_locked(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_ctx_t *ctx, uint32_t hash)
{
    /* won -> we own the fleet-wide regen, go to origin; lost -> another node is
     * filling, wait for its L2 write-through. An NGX_ERROR (Redis outage: lock
     * channel failed) is NOT a peer holding the lock — going to origin would
     * stampede, but cold-waiting would add a full lock_timeout of dead latency
     * for a fill that will never arrive. Treat it as a win: the per-box stub we
     * already hold still single-flights this box, so degrade to per-box
     * single-flight and regenerate now (codex). */
    if (ctx->lock_result == NGX_OK || ctx->lock_result == NGX_ERROR) {
        (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->misses, 1);
        ngx_http_cache_turbo_cold_mark_winner(r, ctx, z,
                                              ctx->pending_l1_owner);
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: cold-miss cross-node WON%s \"%V\" "
                       "key=%ui -> origin",
                       ctx->lock_result == NGX_ERROR ? " (L2 down)" : "",
                       &r->uri, (ngx_uint_t) hash);

        return NGX_DECLINED;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cache_turbo: cold-miss cross-node LOST \"%V\" key=%ui "
                   "-> wait for L2 fill", &r->uri, (ngx_uint_t) hash);

    return ngx_http_cache_turbo_cold_wait(r, clcf, z, ctx);
}


/* MAINT-H2 phase helper for ngx_http_cache_turbo_access_handler().
 * PHASE 7 -- the cold-miss single-flight (cache_turbo_lock on).
 *
 * ⚠ LOCK WINDOW: this phase holds the zone mutex over exactly one span, the
 * CLAIM_FRESH re-lookup (lock / lookup / blob_acquire / unlock, plus the
 * second unlock on the not-fresh arm) -- 3 of the handler's 12 lock
 * operations. Both the acquire and both releases are inside this helper, so
 * the window is unchanged and `fresh`/`body` never escape it unpinned: the
 * blob_acquire() runs under the same hold that resolved the node, and the
 * reference is handed to serve() which registers the pool-lifetime drop.
 * l1->claim() and l1->resolve_miss() lock internally and are called with the
 * mutex NOT held, as before.
 *
 * ⚠ Can park (NGX_AGAIN on the cross-node NX lock); the lease token is
 * stashed in ctx->pending_l1_owner precisely because the claim_owner stack
 * local does not survive the park, and that local stays a local of THIS
 * helper -- the stash/restore pair moved together. */
static ngx_int_t
ngx_http_cache_turbo_access_cold(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_cache_turbo_zone_t *z, uint32_t hash, ngx_int_t *out_rc)
{
    /* Cold-miss single-flight (v10). L1 absent/expired and L2 missed: rather than
     * let every concurrent first-hit stampede the origin, the first request
     * becomes the single regenerator (per box via a stub shm node, cross-node via
     * the v4-2 Redis NX lock) and the rest WAIT for it to fill the cache, then
     * serve it. cache_turbo_lock off restores the old straight-to-origin path. */
    if (clcf->lock) {
        time_t     lock_ttl = clcf->lock_ttl;
        ngx_int_t  cl;
        uint64_t   claim_owner = 0;   /* CTXRDR-ADOPT-LEASE: set on CLAIM_WINNER */
        ngx_int_t  merge_min_uses = 0;

        if (lock_ttl <= 0) {
            lock_ttl = 5;
        }

        /* v4-4: widen the cold-miss single-flight window by the load factor too,
         * so a stampede onto an uncached key during a slow-origin spell collapses
         * onto one regen for longer (same rationale as the stale-refresh claim). */
        lock_ttl = lock_ttl
            * ngx_http_cache_turbo_effective_load(clcf, z)
            / NGX_HTTP_CACHE_TURBO_AT_LOAD_BASE;

        /* Resume after the cross-node NX park (we are the per-box claim winner
         * that fired the lock): won -> we own the fleet-wide regen, go to origin;
         * lost -> another node is filling, wait for its L2 write-through. An
         * NGX_ERROR (Redis outage: lock channel failed) is NOT a peer holding the
         * lock — going to origin would stampede, but cold-waiting would add a full
         * lock_timeout of dead latency for a fill that will never arrive. Treat it
         * as a win: the per-box stub we already hold still single-flights this box,
         * so degrade to per-box single-flight and regenerate now (codex). */
        if (ctx->lock_done) {
            *out_rc = ngx_http_cache_turbo_cold_resume_locked(r, clcf, z, ctx,
                                                              hash);
            return NGX_DONE;
        }

        /* S231-PERF-MISSLOCKS: min_uses>1 && lock-on is exactly the case the
         * gate above deferred to here -- merge_min_uses fires resolve_miss()
         * (count_miss()+claim() under one lock) instead of a bare claim(). The
         * same reentry guards as the gate above (!min_uses_passed &&
         * !lock_done) apply: on the cross-node park/resume paths above we
         * already returned, so reaching here with merge_min_uses true always
         * means this is the first synchronous pass. */
        merge_min_uses = (clcf->min_uses > 1 && !ctx->min_uses_passed);

        if (merge_min_uses) {
            ngx_int_t  count_miss_rc;
            u_char    *fresh_data = NULL;
            size_t     fresh_len_out = 0;

            cl = clcf->l1->resolve_miss(z, ctx->key_hash, hash, clcf->min_uses,
                     clcf->min_uses_window, lock_ttl, &claim_owner, &count_miss_rc,
                     &fresh_data, &fresh_len_out);

            if (count_miss_rc == NGX_DECLINED) {
                /* Identical to the standalone gate above: still below
                 * threshold, run to origin without storing. claim() did not
                 * run (see resolve_miss()'s contract). */
                ctx->min_uses_skip = 1;
                (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->misses, 1);
                (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->min_uses_skips, 1);
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: below min_uses \"%V\" key=%ui -> "
                               "origin (no store)", &r->uri, (ngx_uint_t) hash);

                *out_rc = NGX_DECLINED;
                return NGX_DONE;

            }

            ctx->min_uses_passed = 1;

            if (cl == NGX_HTTP_CACHE_TURBO_CLAIM_FRESH) {
                /* Mirrors the CLAIM_FRESH branch below, but resolve_miss()
                 * already handed back the raced-in blob PRE-REFERENCED (the
                 * PERF-7 blob_acquire() ran inside claim_locked()'s own
                 * critical section, before resolve_miss()'s internal unlock
                 * -- see its contract comment in shm.c). This request now
                 * OWNS that one reference: it must reach serve() (which
                 * registers the pool-lifetime release) on every path, or be
                 * explicitly released here if it does not. Acquiring AGAIN
                 * here would be a double-acquire leaking a reference every
                 * fresh-raced request; acquiring only after this unlock
                 * (what an earlier version of this diff did) is a
                 * use-after-free -- a concurrent evict can free the blob in
                 * the gap between resolve_miss()'s unlock and this line.
                 *
                 * RFC-1 re-validation kept identical to the pre-merge
                 * branch: a request revalidation-forced by its own
                 * freshness bounds must still fall through to the origin
                 * rather than re-serve -- but it must also release the
                 * reference it already owns instead of leaking it. */
                if (fresh_data != NULL && !ctx->req_reval) {
                    (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->hits, 1);
                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "cache_turbo: cold-miss raced to FRESH \"%V\" "
                                   "key=%ui -> serve", &r->uri, (ngx_uint_t) hash);

                    *out_rc = ngx_http_cache_turbo_serve(r, fresh_data,
                              fresh_len_out, 0, z, fresh_data, NULL);
                    return NGX_DONE;

                }
                if (fresh_data != NULL) {
                    /* req_reval blocked the re-serve: release the reference
                     * resolve_miss() already took on our behalf, or it leaks
                     * for the life of the shm zone. */
                    ngx_http_cache_turbo_blob_release(z, fresh_data);
                }
                /* vanished again (fresh_data NULL -- claim_locked() found no
                 * fresh entry this pass), or blocked by RFC-1: go to origin */
                (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->misses, 1);

                *out_rc = NGX_DECLINED;
                return NGX_DONE;

            }
        } else {
            cl = clcf->l1->claim(z, ctx->key_hash, hash, lock_ttl, &claim_owner);
        }
        /* Stash the lease token now: if this claim is a CLAIM_WINNER that
         * goes on to fire the cross-node NX lock below, the request parks
         * (NGX_AGAIN) and resumes at the top of this block on a fresh call
         * where claim_owner (a stack local) no longer holds it. */
        ctx->pending_l1_owner = claim_owner;

        if (!merge_min_uses && cl == NGX_HTTP_CACHE_TURBO_CLAIM_FRESH) {
            /* A real fresh entry raced in while we were on the cold path
             * (another local winner finished): re-serve it from L1. */
            ngx_http_cache_turbo_node_t  *fresh;
            size_t                        snap_len;

            ngx_shmtx_lock(ngx_http_cache_turbo_zone_mutex(z));
            fresh = clcf->l1->lookup(z, ctx->key_hash, hash);
            /* RFC-1: do NOT re-serve the raced-in fresh entry when this request
             * is a revalidation forced by its own freshness bounds (max-age /
             * min-fresh) — that entry is exactly what the client rejected. Fall
             * through to the origin instead. */
            if (fresh != NULL && fresh->len > 0
                && ngx_time() < fresh->fresh_until
                && !ctx->req_reval)
            {
                /* PERF-7: zero-copy serve of the raced-in fresh entry. */
                u_char *body = fresh->data;
                snap_len = fresh->len;
                ngx_http_cache_turbo_blob_acquire(body);
                ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));
                (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->hits, 1);
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: cold-miss raced to FRESH \"%V\" "
                               "key=%ui -> serve", &r->uri, (ngx_uint_t) hash);

                *out_rc = ngx_http_cache_turbo_serve(r, body, snap_len, 0, z, body,
                          NULL);
                return NGX_DONE;

            }
            ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));
            /* vanished again (evicted/expired in the race): go to origin */
            (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->misses, 1);

            *out_rc = NGX_DECLINED;
            return NGX_DONE;

        }

        if (cl == NGX_HTTP_CACHE_TURBO_CLAIM_LOSER) {
            /* CTXRDR: we may have LOST to ourselves. An internal redirect
             * (error_page / X-Accel-Redirect) memzeros r->ctx mid-request, so a
             * second pass over a key that is stable across the redirect finds
             * the stub its own first pass planted and would otherwise park on
             * it for the full lock_timeout. Adopt it and proceed as the winner
             * we already are. */
            if (ngx_http_cache_turbo_cold_adopt_own_stub(r, ctx, z) == NGX_OK) {
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: cold-miss adopted OWN stub across "
                               "internal redirect \"%V\" key=%ui",
                               &r->uri, (ngx_uint_t) hash);

                *out_rc = NGX_DECLINED;
                return NGX_DONE;
      /* go to origin as the winner */
            }


            *out_rc = ngx_http_cache_turbo_cold_wait(r, clcf, z, ctx);
            return NGX_DONE;

        }

        /* CLAIM_WINNER: we created/took over the in-flight stub. Fire the
         * cross-node NX lock (v4-2) so the whole fleet single-flights too; park
         * for the reply (resolved at the top of this block on resume).
         * NGX_DECLINED = no L2 / could not start -> single-box winner now. */
        if (clcf->backend && clcf->backend->lock) {
            ngx_int_t  lrc = clcf->backend->lock(r, clcf, ctx, lock_ttl);
            if (lrc == NGX_AGAIN) {
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: cold-miss parked on L2 lock NX \"%V\" "
                               "key=%ui", &r->uri, (ngx_uint_t) hash);

                *out_rc = NGX_AGAIN;
                return NGX_DONE;

            }
        }

        (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->misses, 1);
        ngx_http_cache_turbo_cold_mark_winner(r, ctx, z, claim_owner);
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: cold-miss single-box WON \"%V\" key=%ui "
                       "-> origin", &r->uri, (ngx_uint_t) hash);

        *out_rc = NGX_DECLINED;
        return NGX_DONE;

    }
    return NGX_DECLINED;
}



/*
 * P5-6: cache_turbo_store_head. A HEAD is eligible for LOOKUP (see
 * ngx_http_cache_turbo_access_eligible() above) but can never be STORED: the
 * capture gate in filters.c refuses HEAD outright, because nginx core sets
 * r->header_only = 1 for a HEAD once headers are sent
 * (ngx_http_header_filter_module.c) and the body chain -- where every store in
 * this module lives -- then never runs. So a URL that only ever receives HEAD
 * (monitors, link checkers, some crawlers) is a permanent 100%% miss.
 *
 * Fix it with the mechanism the SWR background refresh already uses: one
 * internal background subrequest with header_only = 0. That subrequest is a
 * REAL GET, so it flows through the ordinary capture gate and the ordinary
 * body-filter store -- this feature adds NO second store path, and every gate,
 * invariant and index write happens exactly once, in code that already ships.
 * The cost is one wasted origin body per HEAD-miss, paid rarely by
 * construction on the workload the directive exists for.
 *
 * The stored entry is stamped BLOBF_HEAD_DERIVED (via ctx->head_derived on the
 * SUBREQUEST's ctx) and the serve chokepoint refuses it to every non-HEAD
 * request -- a HEAD-derived entry must NEVER answer a GET.
 *
 * ⚠ CALLED FROM EVERY GO-TO-ORIGIN RETURN of the access handler, not just the
 * one at the bottom. cache_turbo_lock is ON by default, so a cold HEAD miss
 * leaves through the cold-miss phase's own NGX_DECLINED and never reaches the
 * tail of the handler at all -- placing this there made the feature dead code
 * under the shipped default, which is exactly the cycle-6 failure shape. Every
 * arm that hands the request to the origin routes through here instead.
 *
 * Idempotent per request: ctx->head_warm_fired makes a re-entry (the cold-wait
 * re-poll and the L2/lock park both re-run this handler) fire at most one
 * subrequest, so a parked HEAD cannot multiply warms.
 *
 * A HIT/STALE returns long before any of these call sites, so a URL that
 * already has an entry never pays the extra fetch; the subrequest is subject
 * to the SAME zone-wide cache_turbo_background_update_max cap as SWR
 * (warm_one() checks it first); and the return value is deliberately
 * discarded, exactly as the SWR callers discard it -- a refused or failed warm
 * must never change what THIS request does, which is proceed to the origin as
 * an ordinary miss.
 */
static void
ngx_http_cache_turbo_head_store_warm(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx)
{
    ngx_http_cache_turbo_ctx_t  *wctx = NULL;

    if (!clcf->store_head
        || !(r->method & NGX_HTTP_HEAD)
        || ctx == NULL
        || ctx->head_warm_fired)
    {
        return;
    }

    ctx->head_warm_fired = 1;

    (void) ngx_http_cache_turbo_warm_one(r, &r->uri, &r->args, NULL, 0, &wctx, NULL);

    /* Stamp on the ctx's EXISTENCE, not on warm_one()'s return value. A posted
     * subrequest cannot be unwound, so a failure arm AFTER the ctx was
     * published still leaves `sr` live, still recognisably ours to the body
     * filter, and still able to reach the store. An unstamped head-derived
     * blob is the one outcome the invariant cannot tolerate, so stamp whenever
     * there is a ctx at all. wctx stays NULL when warm_one() refused before
     * creating the subrequest (bg cap reached, ngx_http_subrequest() failed,
     * ctx alloc failed) -- nothing was posted then and there is nothing to
     * stamp. */
    if (wctx != NULL) {
        wctx->head_derived = 1;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cache_turbo: HEAD miss \"%V\" -> warm subrequest",
                   &r->uri);
}


/* MAINT-H2: the access handler is a fixed SEQUENCE of phases, each extracted
 * above into a named helper and each able to terminate the request. The parent
 * is a straight-line driver: it evaluates the phases in the original order and
 * returns the first phase-produced verdict.
 *
 * Every helper returns NGX_DECLINED for "I did not answer, continue to the
 * next phase" and NGX_DONE for "I produced the handler's return value", which
 * it writes to `out_rc`. NGX_DONE is safe as the sentinel because no phase ever
 * *returns* NGX_DONE as the handler's own value -- the two terminal helpers
 * that finalize the request (_breaker_unavailable via the gate, and
 * _cold_wait via the cold phase) hand back their own value through `rc`.
 *
 * The ordering between phases is load-bearing throughout (see each helper's
 * comment); no phase was merged with another and no lock operation moved
 * across a helper boundary. */
ngx_int_t
ngx_http_cache_turbo_access_handler(ngx_http_request_t *r)
{
    uint32_t                          hash;
    ngx_int_t                         prc, rc;
    ngx_http_cache_turbo_ctx_t       *ctx;
    ngx_http_cache_turbo_zone_t      *z;
    ngx_http_cache_turbo_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);

    /* Prologue: enablement, method/subrequest/auth vetoes, ctx + key, auto-
     * classify, request no-cache, auto-Vary key prep, bypass, autotune. NGX_OK
     * => proceed with ctx/z/hash set; otherwise that is our return value. */
    prc = ngx_http_cache_turbo_access_prologue(r, clcf, &ctx, &z, &hash);
    if (prc != NGX_OK) {
        return prc;
    }

    if (ngx_http_cache_turbo_access_l1(r, clcf, ctx, z, &hash, &rc)
        == NGX_DONE)
    {
        if (rc == NGX_DECLINED) {
            ngx_http_cache_turbo_head_store_warm(r, clcf, ctx);
        }
        return rc;
    }

    if (ngx_http_cache_turbo_access_l2(r, clcf, ctx, z, hash, &rc)
        == NGX_DONE)
    {
        if (rc == NGX_DECLINED) {
            ngx_http_cache_turbo_head_store_warm(r, clcf, ctx);
        }
        return rc;
    }

    ngx_http_cache_turbo_access_l2_miss_account(r, clcf, ctx, z, hash);

    if (ngx_http_cache_turbo_access_only_if_cached(r, clcf, ctx, z, hash, &rc)
        == NGX_DONE)
    {
        /* only-if-cached answers 504 itself and never reaches the origin --
         * warming here would fetch a body the client explicitly refused to
         * let us fetch (RFC 9111 5.2.1.7). Deliberately NOT warmed. */
        return rc;
    }

    if (ngx_http_cache_turbo_access_breaker_gate(r, clcf, ctx, z, hash, &rc)
        == NGX_DONE)
    {
        if (rc == NGX_DECLINED) {
            ngx_http_cache_turbo_head_store_warm(r, clcf, ctx);
        }
        return rc;
    }

    if (ngx_http_cache_turbo_access_min_uses(r, clcf, ctx, z, hash, &rc)
        == NGX_DONE)
    {
        if (rc == NGX_DECLINED) {
            ngx_http_cache_turbo_head_store_warm(r, clcf, ctx);
        }
        return rc;
    }

    if (ngx_http_cache_turbo_access_cold(r, clcf, ctx, z, hash, &rc)
        == NGX_DONE)
    {
        if (rc == NGX_DECLINED) {
            ngx_http_cache_turbo_head_store_warm(r, clcf, ctx);
        }
        return rc;
    }

    /* true miss (cache_turbo_lock off): mark for capture, run to the origin */
    (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->misses, 1);
    ngx_http_cache_turbo_head_store_warm(r, clcf, ctx);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cache_turbo: MISS \"%V\" key=%ui -> origin",
                   &r->uri, (ngx_uint_t) hash);
    return NGX_DECLINED;
}



/* Cold-miss single-flight waiter (v10). A request that lost the cold-miss claim
 * (or the cross-node NX) parks on a short timer and re-checks L1/L2 until the
 * winner fills the entry (a later re-entry then serves it) or lock_timeout
 * elapses, at which point it falls through to the origin itself. Mirrors the
 * redis park/resume dance: count++ here, finalize(NGX_DONE) in the timer handler. */
static ngx_int_t
ngx_http_cache_turbo_cold_wait(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_ctx_t *ctx)
{
    ngx_msec_t       now = ngx_current_msec;
    ngx_msec_int_t   remaining;
    ngx_msec_t       delay;

    if (!ctx->waiting) {
        ctx->waiting = 1;
        ctx->wait_deadline = now + clcf->lock_timeout;
        (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->lock_waits, 1);
    }

    /* V-HANG-2: a previous re-poll already found the key PRESENT in L2 but past
     * its stored stale window. The winner's fill has landed; it is simply not
     * serveable to us. Polling again can only re-read the same blob, so stop
     * waiting and regenerate now instead of burning the rest of lock_timeout.
     *
     * ⚠ This is NOT an early `unlock`. The cross-node NX lock is still held by
     * its owner and still expires only by PX (module.h: unlock stays NULL, and
     * releasing it here would re-open the dogpile window). We only stop THIS
     * waiter from parking for a fill that has demonstrably already happened —
     * the per-box stub still single-flights this box.
     *
     * Bites whenever the stored stale window is shorter than lock_ttl: e.g.
     * cache_turbo_stale_mult 1 makes stale_window == fresh_ttl, so the entry is
     * unserveable ~1s after it is written while the lock lives 5s. Every
     * request in that gap stalled the full lock_timeout (~5s) before this.
     *
     * ⚠ Gated on wait_polled, NOT on ctx->waiting: waiting is set unconditionally
     * a few lines above, so it is always 1 by the time we read it here and tests
     * nothing. The inference "the fill has already landed" is only valid AFTER we
     * have actually parked once — on the first pass a CLAIM_LOSER can reach this
     * with the flag set by its own initial L2 lookup, before the winner has
     * written anything, and giving up there stampedes the origin with every
     * loser. Do not relax this back to ctx->waiting. */
    if (ctx->wait_polled && ctx->l2_present_unserveable) {
        ctx->waiting = 0;
        (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->misses, 1);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: cold-wait sees L2 filled-but-unserveable "
                       "\"%V\" -> origin", &r->uri);
        return NGX_DECLINED;
    }

    remaining = (ngx_msec_int_t) (ctx->wait_deadline - now);
    if (remaining <= 0) {
        /* Waited long enough: give up. If a stale-if-error snapshot is
         * already armed (from an earlier expired-but-within-SIE-window L1/L2
         * lookup on THIS request, ctx->sie_snap / ctx->sie_armed -- armed at
         * :1196-1198 (L1, shm-pinned) or :1469-1474 (L2, r->pool copy)),
         * serve it instead of stampeding the origin: a slow origin is
         * exactly the case where every timed-out loser piling on at once
         * hurts most. `ref_data` is NULL on purpose here even for the L1
         * (shm-pinned) case -- the arm site already registered the pool
         * cleanup that drops the blob reference (S231-PERF-SIEARM), so
         * passing sie_snap again as ref_data would register a SECOND
         * cleanup for the same pointer and double-drop the refcount (see
         * the identical warning at :880). The snapshot is safe to read
         * here regardless of which arm produced it: the L1 pin is refcounted
         * and only released when r->pool is destroyed, and the L2 copy lives
         * in r->pool directly -- both outlive this request-scoped ctx,
         * which is the only place any of these fields are ever read.
         * "STALE-IF-ERROR" matches the diagnostic header already used for
         * this exact snapshot on its other serve path (module.c:3080). */
        if (ctx->sie_armed && ctx->sie_snap != NULL) {
            ctx->waiting = 0;
            (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->stale_serves, 1);
            /* S7.1: dedicated SIE counter, bumped alongside stale_serves at
             * the delivery site -- same "generic + reason-specific, both at
             * the actual serve" discipline the breaker-fallback stale serve
             * uses for stale_serves/breaker_serves (:1967-1972). Without
             * this, sie_serves silently undercounts whenever delivery comes
             * from a cold-wait timeout rather than an upstream error
             * rewrite. */
            (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->sie_serves, 1);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: cold-miss wait timeout \"%V\" -> "
                           "serving armed SIE snapshot", &r->uri);
            return ngx_http_cache_turbo_serve(r, ctx->sie_snap,
                       ctx->sie_snap_len, 1, z, NULL, "STALE-IF-ERROR");
        }

        /* Waited long enough: give up and regenerate ourselves. Our store ends
         * the wait for any remaining readers. Bounded by lock_timeout. */
        ctx->waiting = 0;
        (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->misses, 1);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: cold-miss wait timeout \"%V\" -> origin",
                       &r->uri);
        return NGX_DECLINED;
    }

    /* Re-consult L2 on the next re-entry so a cross-node winner's write-through
     * is picked up (per-box fills are caught by the L1 lookup itself).
     *
     * L13: that cross-node pickup is the ONE thing the negative memo would
     * wrongly suppress -- we are here precisely because we expect a peer to
     * publish the key mid-wait, which is the memo's blind spot. So force a real
     * L2 GET on every cold-wait re-poll (l2_neg_force) and clear the
     * skipped-flag, rather than letting a memo armed moments ago short-circuit
     * the wait into a guaranteed origin fetch. */
    ctx->l2_done = 0;
    ctx->l2_neg_skipped = 0;
    ctx->l2_neg_force = 1;
    /* ⚠ NGX_ERROR ("no L2 answer yet"), NOT NGX_DECLINED. Since L13-fix,
     * NGX_DECLINED means "L2 definitively does not have this key" and is what
     * licenses arming the negative memo. Seeding a pre-GET placeholder with it
     * makes every cold-wait re-poll look like a fresh definitive miss: combined
     * with the l2_neg_skipped reset above, that re-arms the memo on each poll and
     * slides l2_neg_until forward indefinitely, so a hot-but-absent key never
     * re-consults L2. The real result overwrites this when the GET completes. */
    ctx->l2_result = NGX_ERROR;
    ctx->l2_blob = NULL;
    ctx->l2_blob_len = 0;

    delay = NGX_HTTP_CACHE_TURBO_LOCK_POLL_MS;
    if (delay > (ngx_msec_t) remaining) {
        delay = (ngx_msec_t) remaining;
    }

    if (ctx->cold_wait_ev.handler == NULL) {
        ngx_pool_cleanup_t  *cln;

        ctx->cold_wait_ev.handler = ngx_http_cache_turbo_cold_wait_timeout;
        ctx->cold_wait_ev.data = r;
        ctx->cold_wait_ev.log = r->connection->log;

        /* Cancel a still-pending poll timer at request teardown. Without this,
         * a request torn down while parked here (client abort, or worker exit
         * under cold-key churn) leaves cold_wait_ev armed on a freed r and the
         * count++ below unbalanced -- the connection cannot close, surfacing as
         * "open socket left in connection" at shutdown. Registered once, on the
         * same one-shot path that first arms the timer; the timeout handler runs
         * ngx_del_timer implicitly via its finalize, so a normal wake leaves
         * timer_set == 0 and the cleanup is a no-op. */
        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            /* Never arm the timer without its teardown cancellation: under the
             * memory exhaustion that makes this fail, a subsequent teardown is
             * exactly when the orphaned-timer socket leak would bite. Fail
             * closed (the access handler finalizes 500) instead. */
            return NGX_ERROR;
        }
        cln->handler = ngx_http_cache_turbo_cold_wait_cleanup;
        cln->data = ctx;
    }

    ngx_add_timer(&ctx->cold_wait_ev, delay);
    r->main->count++;
    /* We are now genuinely parked: any subsequent re-entry is a re-poll, so the
     * V-HANG-2 give-up at the top of this function may trust an
     * l2_present_unserveable observed from here on. Never cleared. */
    ctx->wait_polled = 1;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cache_turbo: cold-miss WAIT \"%V\" poll=%M ms",
                   &r->uri, delay);
    return NGX_AGAIN;
}


/* Timer fired: re-drive the parked waiter through the phase engine (re-enters the
 * access handler, which re-checks L1/L2). Same teardown as the redis get_finish
 * resume — run_phases, run_posted_requests, then release the parked reference. */
static void
ngx_http_cache_turbo_cold_wait_timeout(ngx_event_t *ev)
{
    ngx_http_request_t  *r = ev->data;
    ngx_connection_t    *c = r->connection;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "cache_turbo: cold-miss wait wake \"%V\"", &r->uri);

    ngx_http_core_run_phases(r);
    ngx_http_run_posted_requests(c);
    ngx_http_finalize_request(r, NGX_DONE);
}


/* Pool cleanup: delete a still-armed cold-wait poll timer at request teardown.
 * The timer's ev.data points at r; once the request pool is being destroyed that
 * pointer is dangling, so a timer left in the event tree would fire the handler
 * on freed memory. Deleting it here makes teardown safe on every path that
 * bypasses the normal timer wake (worker exit under cold-key churn, connection
 * reset). A normal wake already ran ngx_del_timer, so timer_set is 0 and this
 * is a no-op. */
static void
ngx_http_cache_turbo_cold_wait_cleanup(void *data)
{
    ngx_http_cache_turbo_ctx_t  *ctx = data;

    if (ctx->cold_wait_ev.timer_set) {
        ngx_del_timer(&ctx->cold_wait_ev);
    }
}


/* Mark this request as the cold-miss winner that owns the in-flight stub, and
 * register a pool cleanup so the stub is removed at request teardown if the
 * winner never stored a real entry (non-cacheable response, oversized body,
 * upstream error, client abort). The header filter clears it earlier for the
 * common non-cacheable case; this is the backstop for every other non-store
 * exit. Registered once per request (the winner-DECLINED sites are reached at
 * most once). */
static void
ngx_http_cache_turbo_cold_mark_winner(ngx_http_request_t *r,
    ngx_http_cache_turbo_ctx_t *ctx, ngx_http_cache_turbo_zone_t *z,
    uint64_t owner)
{
    ngx_pool_cleanup_t  *cln;

    if (ctx->cold_winner) {
        return;
    }

    ctx->cold_winner = 1;
    ctx->cold_zone = z;
    /* CTXRDR-ADOPT-LEASE: the lease token claim() issued to us, or 0 when this
     * win did not come with an L1 lease (the cross-node L2 path, and the
     * out-of-slab claim that could not create a node). 0 is inert everywhere:
     * such a winner stores normally but never clears anyone's lease. */
    ctx->cold_owner = owner;

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return;
    }
    cln->handler = ngx_http_cache_turbo_cold_cleanup;
    cln->data = ctx;
}


/*
 * CTXRDR: find a cold-miss stub that an EARLIER ctx of THIS SAME REQUEST is
 * still holding for `key_hash`, and hand its ownership to `ctx`.
 *
 * An internal redirect (error_page, X-Accel-Redirect, a rewrite that reaches a
 * new location) memzeros r->ctx unconditionally -- ngx_http_core_module.c:2614,
 * and the one-module-preserving variant at special_response.c:547 is the
 * filter_finalize path, not this one. r->pool is NOT reset, so a ctx that won a
 * claim before the redirect keeps its pool cleanup and its cold_winner/cold_zone
 * state, but the access handler on the second pass sees r->ctx == NULL, pcallocs
 * a FRESH ctx (cold_winner = 0), and no longer knows the request owns the stub.
 *
 * With a key that is stable across the redirect -- $request_uri, the form every
 * doc here recommends precisely because it survives one -- both passes hash to
 * the same key, so the second pass finds its OWN stub, reads it as another
 * request's in-flight fill, and parks in cold_wait() until lock_timeout (5s by
 * default) before giving up and re-winning. The request answers correctly but
 * pays the full timeout, and none of the three header/body-filter unstub sites
 * can prevent it: an intercepted error is finalized by
 * ngx_http_upstream_intercept_errors() without traversing the output filter
 * chain at all, so only the pool cleanup remains and that runs at teardown --
 * long after the second pass has already parked.
 *
 * The cleanup list is the authority for WHICH ctx of this request last held a
 * stub for the key: it is already the request-lifetime record of "this ctx owns
 * an unresolved stub", it is exactly what the redirect leaves intact, and
 * reusing it keeps one source of truth instead of two that can disagree. The
 * list is short (a handful of entries per request) and this runs only on the
 * CLAIM_LOSER path.
 *
 * ⚠ CTXRDR-ADOPT-LEASE -- the cleanup list is NOT sufficient on its own, and an
 * earlier version of this function that stopped there was wrong. cold_winner +
 * !cold_stored + zone + key prove only that this request owned a stub for this
 * key at SOME point. They cannot prove it owns the live one, because claim()
 * deliberately re-leases a stub whose refresh_lock_until has passed to a
 * different request, and CLAIM_LOSER is the zone telling us authoritatively that
 * someone else holds it NOW. Overriding that on stale request-local state let
 * two requests regenerate concurrently and let the loser's unstub() clear the
 * winner's live lease -- single-flight broken and the origin stampeded, exactly
 * during the origin slowness that opened the window.
 *
 * So the cleanup list only nominates a candidate; shm_owns() adjudicates it
 * against the zone under the mutex. Both must agree before we adopt.
 */
static ngx_int_t
ngx_http_cache_turbo_cold_adopt_own_stub(ngx_http_request_t *r,
    ngx_http_cache_turbo_ctx_t *ctx, ngx_http_cache_turbo_zone_t *z)
{
    ngx_pool_cleanup_t          *c;
    ngx_http_cache_turbo_ctx_t  *prev;

    for (c = r->pool->cleanup; c; c = c->next) {
        if (c->handler != ngx_http_cache_turbo_cold_cleanup) {
            continue;
        }

        prev = c->data;

        if (prev == NULL || prev == ctx) {
            continue;
        }

        /* Same key, same zone, and the stub is still unresolved: this request
         * already owns it. Compare the full 32-byte key -- the rbtree's crc32
         * is collision-prone by design, and adopting on a collision would clear
         * a DIFFERENT key's stub. */
        if (prev->cold_winner
            && !prev->cold_stored
            && prev->cold_zone == z
            && ngx_memcmp(prev->key_hash, ctx->key_hash, 32) == 0)
        {
            /* The candidate held a stub for this key. Now ask the ZONE whether
             * that lease is still ours, rather than assuming it from the above.
             * A mismatch means claim() re-leased it (or store()/unstub() already
             * resolved it) and CLAIM_LOSER was right: fall through, keep
             * searching, and ultimately wait like any other loser. */
            if (ngx_http_cache_turbo_shm_owns(z, ctx->key_hash,
                    ngx_crc32_short(ctx->key_hash, 32),
                    prev->cold_owner) != NGX_OK)
            {
                continue;
            }

            /* Transfer ownership to the live ctx, INCLUDING the lease token --
             * without it the adopting ctx could not prove ownership to unstub()
             * and would leave the stub to expire on its own. Retarget this very
             * cleanup instead of registering a second one: the entry is already
             * in the list, so ownership moves with a single store that cannot
             * fail, and there is exactly one cleanup per live stub. The earlier
             * shape (mark inert + ngx_pool_cleanup_add) could fail its
             * allocation AFTER disarming the old entry and still return NGX_OK,
             * leaving an adopted stub with no teardown owner at all. */
            ctx->cold_winner = 1;
            ctx->cold_zone = z;
            ctx->cold_owner = prev->cold_owner;

            prev->cold_stored = 1;   /* the old ctx no longer owns anything */
            c->data = ctx;           /* ...and this cleanup now speaks for us */

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


/* Pool cleanup: if the cold-miss winner never resolved its stub (no real entry
 * stored, stub not already cleared), remove the leftover stub so waiters for
 * this key stop blocking. unstub only drops a node that is still a stub. */
static void
ngx_http_cache_turbo_cold_cleanup(void *data)
{
    ngx_http_cache_turbo_ctx_t  *ctx = data;
    uint32_t                     hash;

    if (!ctx->cold_winner || ctx->cold_stored || ctx->cold_zone == NULL) {
        return;
    }

    hash = ngx_crc32_short(ctx->key_hash, 32);
    ngx_http_cache_turbo_shm_unstub(ctx->cold_zone, ctx->key_hash, hash,
                                    ctx->cold_owner);
}
