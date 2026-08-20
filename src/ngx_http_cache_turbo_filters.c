/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Response header/body filter group (MAINT-SPLIT step E). Split out of
 * ngx_http_cache_turbo_module.c verbatim: the header filter and its four
 * helpers (TEST_FAULTS observability headers, breaker recording, the
 * stale-if-error rewrite trigger, snapshot capture), the downstream body
 * forwarder, and the body filter with its twelve helpers (mid-body SIE
 * rescue, SIE consume/emit, forced file buf, capture, window accounting,
 * header measurement, blob write, store, tag split/index, store tail).
 *
 * This is the request HOT PATH: both filters run on every response.
 *
 * Filter-chain state. The two static next-filter pointers,
 * ngx_http_next_header_filter and ngx_http_next_body_filter, move HERE
 * with the code that calls them -- every call site is in this file, and
 * the alternative (leaving them in module.c and exporting two mutable
 * function pointers) would put the chain hand-off behind an extra
 * cross-TU indirection on the hot path for no benefit.
 * module.c's filter_init calls
 * ngx_http_cache_turbo_filter_chain_init() below, which performs the same
 * two save-and-install pairs in the same order as before the split, so the
 * registration order at the top of the output chain is unchanged.
 *
 * Export surface: three functions lose `static` --
 * ngx_http_cache_turbo_header_filter and ngx_http_cache_turbo_body_filter
 * (installed by the chain init here, and named in module.c only through
 * that call), plus the new ngx_http_cache_turbo_filter_chain_init. They are
 * declared in ngx_http_cache_turbo_internal.h. Every other helper in the
 * group stays file-local static. No function in the moved range carried
 * `ngx_inline`, so no qualifier had to be dropped and there is no
 * inlining change on the hot path.
 *
 * The UNIT-EXTRACT breaker-failure block stays wholly in module.c: this
 * split's range begins below its END marker, so
 * ci/tests/unit/extract_shm.sh keeps slicing module.c unchanged.
 */

#include "ngx_http_cache_turbo_module.h"
#include "ngx_http_cache_turbo_internal.h"


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
/* COR-5(b): does this request ask for its variant-index write to be dropped?
 * Only consulted when cache_turbo_test_varidx_fail is on, so an unarmed
 * location ignores the header entirely. */
static ngx_uint_t
ngx_http_cache_turbo_test_varidx_drop_requested(ngx_http_request_t *r)
{
    ngx_list_part_t  *part = &r->headers_in.headers.part;
    ngx_table_elt_t  *h = part->elts;
    ngx_uint_t        i;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len == sizeof("X-Cache-Turbo-Test-Varidx-Drop") - 1
            && ngx_strncasecmp(h[i].key.data,
                   (u_char *) "X-Cache-Turbo-Test-Varidx-Drop",
                   sizeof("X-Cache-Turbo-Test-Varidx-Drop") - 1) == 0
            && h[i].value.len == 1 && h[i].value.data[0] == '1')
        {
            return 1;
        }
    }

    return 0;
}


#endif


/* Stamp the TEST_FAULTS-only observability headers onto this response.
 *
 * `has_ctx` distinguishes the two call sites: the ctx==NULL/served early-return
 * path may run with no module ctx at all, and the armings header is stamped
 * only when a ctx exists (O4.4-i: a request that armed from L1 is frequently
 * the one that then serves the snapshot, and the test must be able to read the
 * counter off any response it makes). The remaining three read no ctx and are
 * stamped unconditionally. In a production build the whole body compiles away
 * and this is an empty function the compiler inlines to nothing. */
static void
ngx_http_cache_turbo_header_filter_test_headers(ngx_http_request_t *r,
    ngx_uint_t has_ctx)
{
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    if (has_ctx) {
        (void) ngx_http_cache_turbo_test_armings_header(r);
    }
    (void) ngx_http_cache_turbo_test_backoff_header(r);
    (void) ngx_http_cache_turbo_test_arg_scan_header(r);
    (void) ngx_http_cache_turbo_test_cookie_scan_header(r);
    (void) ngx_http_cache_turbo_test_varidx_header(r);
#else
    (void) r;
    (void) has_ctx;
#endif
}


/* P6/O4.2: feed this origin outcome into the per-zone circuit breaker.
 *
 * Placement matters in three ways:
 *
 * 1. AFTER the ctx->served early-return above, so only responses that
 *    really came from the origin are recorded. A cache serve never reaches
 *    here, and must not -- a breaker fed by its own cache hits would read a
 *    dead origin as healthy for as long as the cache kept serving.
 * 2. BEFORE the stale-if-error rewrite below, which overwrites
 *    r->headers_out.status with the snapshot's 200. Recorded after it, the
 *    origin's 502 would be counted as a success and the breaker could never
 *    trip on exactly the outage it exists to handle.
 * 3. OUTSIDE the `ctx->sie_armed` guard the SIE trigger sits behind. A cold
 *    URL with no armed snapshot is precisely the case where the breaker
 *    matters most, and those failures must count even though nothing
 *    stale-serves them.
 *
 * O4.4: gated on breaker_should_consult() rather than the bare
 * clcf->enable this used before the breaker had its own directives.
 * threshold/window at their 0 defaults (or breaker_enable off, or the
 * module itself disabled) make _breaker_record() inert (it returns before
 * touching any window state), so this predicate simply makes that "no
 * config can trip it" state explicit and skips the shm read entirely
 * rather than paying it every response. Successes are recorded just as
 * broadly as failures -- a breaker that only ever hears about failures
 * can never close again.
 *
 * ⚠ NOT recorded at the autotune_record_cost() site the plan first named.
 * That call lives inside the store block, behind ~10 cacheability gates
 * (enable, not-HEAD, status_ttl >= 0, response_cacheable, require_hdr_ok,
 * not-encoded, no_store predicates, ...). A healthy origin serving an
 * uncacheable 200 would never record a success there, so a breaker tripped
 * by a transient outage could never close. Success recording has to be at
 * least as broad as failure recording, which is why both live here.
 *
 * ⚠ r->upstream is the load-bearing part of this condition, not decoration.
 * !ctx->served proves we are not replaying a cached body; it does NOT prove
 * the origin was ever contacted. This module generates 5xx locally: a
 * request carrying `Cache-Control: only-if-cached` that finds nothing
 * serveable is answered NGX_HTTP_GATEWAY_TIME_OUT straight from the access
 * handler (module.c:4422 and :5002), with ctx allocated and ctx->served
 * unset, having spoken to no upstream at all. Counting those would let a
 * client trip a HEALTHY zone's breaker on demand simply by repeating a
 * request header -- a remote denial of service against the origin's own
 * traffic. Only a response with an upstream behind it carries information
 * about whether the origin is up.
 *
 * ⚠ The threshold/window off-switch is now enforced entirely by
 * should_consult(clcf) above -- should_record()'s own `threshold` argument
 * is a legacy positional parameter kept for the unit slice, not a second
 * independent gate. The reason this call must still be SKIPPED outright
 * (rather than trusting _breaker_record() to be inert when off) is that
 * _breaker_record() only checks the off-switch on its FAILURE path
 * (shm.c:1297); the success path returns earlier at :1266 having already
 * written breaker_fails = 0. Calling it unconditionally would therefore
 * put a shared-memory write on every successful response even with the
 * breaker disabled -- not the no-op this step is supposed to be.
 * Skipping the call outright keeps "breaker off" genuinely free.
 *
 * Extracted verbatim from the header filter; the caller must still invoke
 * it at exactly that point in the sequence -- after the ctx->served
 * early-return and before the stale-if-error rewrite -- for reasons 1-3
 * above. It takes no lock of its own; _breaker_record() owns the zone
 * mutex internally and nothing here holds it across the call. */
static void
ngx_http_cache_turbo_header_filter_record_breaker(ngx_http_request_t *r,
    ngx_http_cache_turbo_ctx_t *ctx, ngx_http_cache_turbo_loc_conf_t *clcf)
{
    if (ngx_http_cache_turbo_breaker_should_consult(clcf)
        && clcf->shm_zone != NULL
        && ngx_http_cache_turbo_breaker_should_record(
               0,                      /* ctx->served: excluded above already */
               ngx_http_cache_turbo_breaker_from_origin(
                   r->upstream != NULL,
#if (NGX_HTTP_CACHE)
                   r->cached),
#else
                   0),
#endif
               r == r->main || ctx->warm,
               clcf->breaker_threshold))
    {
        /* ⚠ ctx->brk_probe is the lease token, non-zero only when THIS request
         * won the promotion. Passing it is what stops an unrelated origin
         * response -- one that started before the trip, or one this module
         * served from a peer's L2 fill -- from closing a HALF_OPEN breaker no
         * probe actually tested. Non-probe requests pass 0 (NO_PROBE) and can
         * still count failures toward a CLOSED breaker's threshold, which is
         * the one thing they legitimately observe. */
        ngx_http_cache_turbo_zone_t  *bz = clcf->shm_zone->data;
        ngx_uint_t  is_failure = ngx_http_cache_turbo_breaker_is_origin_failure(
                                      r->headers_out.status);

        /* S7.1: count the origin request as a failure right where the
         * breaker itself is fed that verdict, so this counter and the
         * breaker's own fail/window accounting can never disagree about what
         * counts as a failure. Bumped before the record() call (not after)
         * only as a matter of local ordering -- record() cannot fail and
         * there is no early-return between the two, so the order is not
         * load-bearing. */
        if (is_failure) {
            (void) ngx_atomic_fetch_add(&bz->sh->origin_failures, 1);
        }

        /* P5-5r: OPT-IN (cache_turbo_breaker_count_retries, default off --
         * see the field comment on breaker_count_retries in the .h). Off,
         * only the single shm_breaker_record() call below the loop ever
         * runs, exactly as before this change. On, every
         * proxy_next_upstream peer attempt that failed before this final
         * one ALSO counts as a failure, one shm_breaker_record() call each,
         * BEFORE this response's own final outcome is recorded.
         *
         * ⚠ ORDER IS LOAD-BEARING, and the reach of this feature is bounded
         * by it: shm_breaker_record()'s success branch (shm.c) zeroes
         * breaker_fails UNCONDITIONALLY on any success, not only while
         * CLOSED -- "a success clears the failure run" is the breaker's
         * own, pre-existing, protected invariant, not something this item
         * may change. That means retry failures recorded here can only
         * ever survive to reach threshold WITHIN this same request's own
         * calls, before this response's own final-outcome record() call
         * (below) runs and, if the final attempt succeeded, wipes them.
         * They do NOT accumulate across separate requests that each
         * individually succeed: request N's own trailing success always
         * clears whatever request N-1's retries added. Recording retries
         * FIRST is what lets THIS SINGLE request's own retry chain --
         * enough failed peer attempts before its own final success -- push
         * the counter to threshold and trip CLOSED -> OPEN mid-call; once
         * OPEN, the trailing final-outcome call's success branch no longer
         * has a CLOSED-state or matching-probe HALF_OPEN edge to act on, so
         * it only re-zeroes breaker_fails (state stays OPEN, harmless).
         * Recording them AFTER the final call instead would have that
         * SAME final call's own success wipe every retry failure before it
         * could ever be counted, defeating the feature outright -- see
         * ci/t/core/breaker-retry-count.t for the empirical trace that
         * found this. A half-dead group that spreads its failures across
         * many separately-successful requests rather than one request's
         * own retry chain is a known, accepted limit of this scope: fixing
         * it would require loosening shm_breaker_record()'s reset
         * semantics, which this item is explicitly scoped not to touch. */
        if (clcf->breaker_count_retries) {
            ngx_uint_t  retry_fails =
                ngx_http_cache_turbo_breaker_retry_failures(r);
            ngx_uint_t  j;

            for (j = 0; j < retry_fails; j++) {
                (void) ngx_atomic_fetch_add(&bz->sh->origin_failures, 1);
                ngx_http_cache_turbo_shm_breaker_record(
                    clcf->shm_zone->data,
                    0,                      /* prior attempt: always a failure */
                    clcf->breaker_threshold,
                    clcf->breaker_window,
                    NGX_HTTP_CACHE_TURBO_BREAKER_NO_PROBE);
            }
        }

        ngx_http_cache_turbo_shm_breaker_record(
            clcf->shm_zone->data,
            !is_failure,
            clcf->breaker_threshold,
            clcf->breaker_window,
            ctx->brk_probe);
    }
}


/* RFC-2 stale-if-error: an armed serve-on-error snapshot + a status the
 * configured `cache_turbo_use_stale` set names means replace the error with
 * the stale copy. Do this BEFORE the capture gate so the (replaced) error is
 * never captured, and clear any cold-miss stub we own so waiters do not
 * block on a key we will not store.
 *
 * Returns, exactly mirroring the three outcomes of the inline block it
 * replaces:
 *   NGX_ERROR -- sie_rewrite() failed; the caller must return NGX_ERROR.
 *   NGX_OK    -- the error WAS replaced by the snapshot; the caller must hand
 *                off to the next header filter immediately and run none of the
 *                remaining phases.
 *   NGX_DECLINED -- no SIE serve happened (gate not met, or sie_rewrite()
 *                returned neither OK nor ERROR); the caller continues into the
 *                auto-Vary / capture phases as before. */
static ngx_int_t
ngx_http_cache_turbo_header_filter_try_sie(ngx_http_request_t *r,
    ngx_http_cache_turbo_ctx_t *ctx, ngx_http_cache_turbo_loc_conf_t *clcf)
{
    ngx_int_t  rc;

    if (ctx->sie_armed && !ctx->sie_serving
        && ngx_http_cache_turbo_use_stale_triggers(clcf->use_stale,
                                     r->headers_out.status,
                                     ngx_http_cache_turbo_transport_failure(r)))
    {
        rc = ngx_http_cache_turbo_sie_rewrite(r, ctx);
        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }
        if (rc == NGX_OK) {
            ctx->served = 1;      /* block capture of the replaced error */
            ctx->sie_serving = 1; /* body filter emits the snapshot body */

            /* S7.1: this IS the SIE serve -- sie_rewrite() returning NGX_OK
             * means the error response was actually replaced with the stale
             * snapshot and will be delivered. Bumped here rather than inside
             * sie_rewrite() itself so the counter lives beside sie_serving,
             * the other "this response is now the SIE snapshot" flag. */
            if (clcf->shm_zone != NULL) {
                ngx_http_cache_turbo_zone_t  *sz = clcf->shm_zone->data;
                (void) ngx_atomic_fetch_add(&sz->sh->sie_serves, 1);
            }

            if (ctx->cold_winner && !ctx->cold_stored
                && ctx->cold_zone != NULL)
            {
                uint32_t  h = ngx_crc32_short(ctx->key_hash, 32);
                ngx_http_cache_turbo_shm_unstub(ctx->cold_zone,
                                                ctx->key_hash, h,
                                                ctx->cold_owner);
                ctx->cold_stored = 1;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: STALE-IF-ERROR serve \"%V\" len=%uz",
                           &r->uri, ctx->sie_body_len);
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


/* Decide whether this response is captured for storage, and do the work that
 * hangs off that decision: the auto-Vary classification that can veto capture,
 * the cacheability gate itself, the warm-subrequest key build, the
 * Surrogate-Key emission, and the cold-miss stub clear for the not-captured
 * case.
 *
 * Returns void: the one early exit inside (a warm subrequest whose key could
 * not be built) short-circuited straight to the next header filter in the
 * original, and the caller forwards downstream unconditionally either way, so
 * there is no outcome for the caller to branch on. */

/* P0-1 phase helper: HEAD and 206 are cheap, request/status-only facts
 * already available before the capture gate runs, so they are counted here
 * rather than duplicating the gate's own tests inside it. */
static void
ngx_http_cache_turbo_capture_count_head_partial(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf)
{
    ngx_http_cache_turbo_zone_t  *rz;

    if (clcf->shm_zone == NULL) {
        return;
    }
    rz = clcf->shm_zone->data;

    if (r->method & NGX_HTTP_HEAD) {
        (void) ngx_atomic_fetch_add(&rz->sh->refuse_head, 1);
    }
    if (r->headers_out.status == NGX_HTTP_PARTIAL_CONTENT) {
        (void) ngx_atomic_fetch_add(&rz->sh->refuse_partial, 1);
    }
}


/* P0-1 phase helper: attribute a NOT-captured response to whichever of
 * response_cacheable()/require_hdr_ok()/response_encoded() actually vetoed
 * it. Called only when the capture gate's shared legs (enable, method,
 * vary_nocache, min_uses_skip, auto_skip, req_no_store, status_ttl) already
 * passed and the response still was not captured, so cacheable_reason is
 * meaningful exactly when it is non-NONE (the short-circuit chain stops AT
 * the first false leg, so a later leg failing means every earlier one,
 * including response_cacheable(), passed). require_hdr_ok()/
 * response_encoded() are re-evaluated here (small, bounded header-list
 * scans, same cost class as their gate call) rather than threaded through
 * as extra out-params -- this path never runs on a HIT. */
static void
ngx_http_cache_turbo_capture_count_refusal(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_uint_t cacheable_reason)
{
    ngx_http_cache_turbo_zone_t  *rz;

    if (clcf->shm_zone == NULL) {
        return;
    }
    rz = clcf->shm_zone->data;

    switch (cacheable_reason) {
    case NGX_HTTP_CACHE_TURBO_REFUSE_SET_COOKIE:
        (void) ngx_atomic_fetch_add(&rz->sh->refuse_set_cookie, 1);
        return;
    case NGX_HTTP_CACHE_TURBO_REFUSE_AUTHORIZATION:
        (void) ngx_atomic_fetch_add(&rz->sh->refuse_authorization, 1);
        return;
    case NGX_HTTP_CACHE_TURBO_REFUSE_CACHE_CONTROL:
        (void) ngx_atomic_fetch_add(&rz->sh->refuse_cache_control, 1);
        return;
    default:
        break;
    }

    if (!ngx_http_cache_turbo_require_hdr_ok(r, clcf)) {
        (void) ngx_atomic_fetch_add(&rz->sh->refuse_require_header, 1);
    } else if (ngx_http_cache_turbo_response_encoded(r)) {
        (void) ngx_atomic_fetch_add(&rz->sh->refuse_encoded, 1);
    }
}


/* P3-2: may an ENCODED response (response_encoded() == 1) still be captured?
 * Off by default (cache_turbo_key_encoded_origin unset) this is always 0,
 * unchanged from the original all-or-nothing refusal.
 *
 * When the directive is on, only the three classes the variant-key/serve-
 * guard machinery actually understands (gzip/br/zstd, via
 * response_ae_class()) are captured -- `compress`, `deflate` or any other
 * Content-Encoding this module has no ae-class bucket for is still refused,
 * because there would be nothing for the serve-side guard to check the
 * request's Accept-Encoding against (see response_ae_class()'s own
 * docstring: it folds an unrecognised coding to IDENTITY, which would
 * wrongly mark the object as always-acceptable). On a match, force
 * VARY_ENCODING into *vary_bits (the origin never sent a Vary:
 * Accept-Encoding header for classify_vary() to have picked this up from --
 * that IS the all-or-nothing case this item targets) and report the class
 * via *class_out so the caller can stamp ctx->origin_encoded_capture. */
static ngx_uint_t
ngx_http_cache_turbo_capture_encoded_ok(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_int_t *vary_bits,
    ngx_uint_t *class_out)
{
    ngx_uint_t  class;

    if (!clcf->key_encoded_origin) {
        return 0;
    }

    class = ngx_http_cache_turbo_response_ae_class(r);
    if (class == NGX_HTTP_CACHE_TURBO_AE_CLASS_IDENTITY) {
        return 0;                              /* unrecognised coding */
    }

    *vary_bits |= NGX_HTTP_CACHE_TURBO_VARY_ENCODING;
    *class_out = class;
    return 1;
}


static void
ngx_http_cache_turbo_header_filter_capture(ngx_http_request_t *r,
    ngx_http_cache_turbo_ctx_t *ctx, ngx_http_cache_turbo_loc_conf_t *clcf)
{
    ngx_uint_t  cacheable_reason = NGX_HTTP_CACHE_TURBO_REFUSE_NONE;
    ngx_uint_t  encoded_ok = 0;
    ngx_uint_t  encoded_class = NGX_HTTP_CACHE_TURBO_AE_CLASS_IDENTITY;

    /* auto-Vary (v11 other half): classify the response Vary header once. bits =
     * the safe-axis bitmask the body filter folds into the variant key + marker;
     * vary_nocache vetoes caching when the response varies on something the
     * whitelist refuses (*, Cookie, Authorization). Done before the capture gate
     * so vary_nocache can suppress capture (and the cold-stub clear below fires).
     *
     * P0-1: classify_vary() also reports (via unsafe_axis_out, out-param -- no
     * extra header walk) whether the veto was itself an unrecognised/non-
     * whitelisted axis, as opposed to the two axes ("*", request-adjacent
     * Cookie/Authorization tokens named IN THE VARY HEADER) that are already
     * covered by dedicated Vary-unrelated counters elsewhere. Only the
     * "genuinely unknown axis" case is unique to this path, so that is what
     * refuse_vary_unsafe measures -- it does not double-count every
     * vary_nocache trip. */
    if (clcf->auto_vary) {
        ngx_uint_t  nocache = 0;
        ngx_uint_t  unsafe_axis = 0;

        ngx_http_cache_turbo_classify_vary(r, clcf, &ctx->vary_bits, &nocache,
                                            &unsafe_axis);
        ctx->vary_nocache = nocache ? 1 : 0;

        if (unsafe_axis && clcf->shm_zone != NULL) {
            ngx_http_cache_turbo_zone_t  *rz = clcf->shm_zone->data;

            (void) ngx_atomic_fetch_add(&rz->sh->refuse_vary_unsafe, 1);
        }
    }

    ngx_http_cache_turbo_capture_count_head_partial(r, clcf);

    /* P3-2: decide, BEFORE the capture gate below, whether an encoded
     * response gets a pass. Deliberately computed unconditionally (not only
     * when response_encoded() is already known true) so ctx->vary_bits picks
     * up VARY_ENCODING in the same pass classify_vary() already ran in,
     * exactly like every other axis bit -- doing this INSIDE the gate's
     * boolean chain would make it conditional on evaluation order instead of
     * a single well-defined point. capture_encoded_ok() itself re-derives
     * the class from response_ae_class() (cheap: one typed-field read, same
     * cost class as response_encoded()) rather than trusting a response that
     * is not actually encoded, so it is always safe to call. */
    encoded_ok = ngx_http_cache_turbo_capture_encoded_ok(r, clcf,
                                                          &ctx->vary_bits,
                                                          &encoded_class);

    /* Only capture cacheable responses. 200 always, plus any status named by a
     * cache_turbo_valid <code> rule (redirects / negative caching, v6). Never a
     * HEAD — its empty body must not overwrite the GET entry. Normally the main
     * request only; a warm subrequest (ctx->warm) is the deliberate exception.
     *
     * P0-1: response_cacheable() reports its own refusal reason via an
     * out-param (no extra header-list walk; see its definition). The boolean
     * short-circuit chain and evaluation order below are otherwise
     * byte-for-byte unchanged from before P0-1.
     *
     * P3-2: an encoded response is no longer an unconditional refusal --
     * !response_encoded(r) || encoded_ok. encoded_ok is 0 whenever
     * cache_turbo_key_encoded_origin is off (the directive's default), so
     * this collapses back to the original `!response_encoded(r)` test in
     * every existing deployment; nothing changes unless an operator opts
     * in. */
    if (clcf->enable && (r == r->main || ctx->warm)
        && !(r->method & NGX_HTTP_HEAD)
        && !ctx->vary_nocache
        && !ctx->min_uses_skip
        && !ctx->auto_skip
        && !ctx->req_no_store
        && ngx_http_cache_turbo_status_ttl(clcf, r->headers_out.status) >= 0
        && ngx_http_cache_turbo_response_cacheable(r, &cacheable_reason)
        && ngx_http_cache_turbo_require_hdr_ok(r, clcf)
        && (!ngx_http_cache_turbo_response_encoded(r) || encoded_ok)
        && (clcf->no_store == NULL
            || ngx_http_test_predicates(r, clcf->no_store) == NGX_OK))
    {
        if (encoded_ok) {
            ctx->origin_encoded_capture = 1;
            ctx->origin_encoded_class = encoded_class;
        }

        /* P3-4: resolve the RFC 9111 SS3.5 reuse authorisation NOW, while the
         * response headers still exist. The body filter stamps it onto the
         * blob; it cannot re-derive it after headers are sent. Recorded on
         * every capture regardless of clcf->serve_authorized, so enabling the
         * directive later does not require flushing entries stored before. */
        ctx->auth_shareable =
            ngx_http_cache_turbo_response_auth_shareable(r) ? 1 : 0;

        /* A warm subrequest is deliberately excluded from lookup, so its key
         * was never built. Build it here from the subrequest URI before flagging
         * capture, so the body filter stores under the same key a later real
         * request will look up. */
        if (ctx->warm
            && ngx_http_cache_turbo_build_key(r, clcf, ctx) != NGX_OK)
        {
            return;
        }
        ctx->captured = 1;

        /* cache_turbo_surrogate_key: this response is a MISS being stored, so
         * emit the tag list downstream as a Surrogate-Key header for a fronting
         * CDN NOW, while headers are still mutable (the body-filter store runs
         * after headers are sent). Capture-path only -- a HIT returns earlier via
         * ctx->served and never re-emits. */
        if (clcf->surrogate_key) {
            ngx_http_cache_turbo_emit_surrogate_key(r, clcf);
        }
    } else if (clcf->enable && (r == r->main || ctx->warm)
               && !(r->method & NGX_HTTP_HEAD) && !ctx->vary_nocache
               && !ctx->min_uses_skip && !ctx->auto_skip
               && !ctx->req_no_store
               && ngx_http_cache_turbo_status_ttl(clcf,
                      r->headers_out.status) >= 0)
    {
        /* Every shared leg up to response_cacheable() passed and the
         * response still was not captured -- attribute the refusal. */
        ngx_http_cache_turbo_capture_count_refusal(r, clcf, cacheable_reason);
    } else if (clcf->enable && clcf->shm_zone != NULL
               && (r == r->main || ctx->warm)
               && !(r->method & NGX_HTTP_HEAD)
               && !ctx->req_no_store
               && r->headers_out.status == NGX_HTTP_NOT_MODIFIED)
    {
        /* P5-4: 304 freshening. This is an ORIGIN-sent 304 answering a
         * revalidation (the client-facing 304 replay module.c synthesizes
         * from a HIT sets ctx->served, which returns at the top of
         * ngx_http_cache_turbo_header_filter() long before this function
         * runs -- so a served-from-cache 304 can never reach here; only a
         * real round trip to the origin can). status_ttl() refuses 304
         * unconditionally (it is not `cache_turbo_valid`-able at all, see
         * conf.c), so the normal capture branch above never fires for it --
         * this is the distinct path that exists BECAUSE that refusal is
         * correct and permanent, not a bug to route around.
         *
         * Deliberately its own `else if`, gated on none of vary_nocache /
         * min_uses_skip / auto_skip / status_ttl: those gate whether a BODY
         * may be captured, and this never captures a body -- it only
         * extends the life of one already resident from an earlier 200.
         * req_no_store is still honoured: a request that opted this
         * response out of caching gets no side effect from it either. */
        time_t  fresh_ttl = clcf->valid;

        if (clcf->honor_cc && !clcf->ignore_cc) {
            time_t  up = ngx_http_cache_turbo_upstream_ttl(r);
            if (up >= 0) {
                fresh_ttl = up;
            }
        }

        if (fresh_ttl > NGX_HTTP_CACHE_TURBO_TTL_MAX) {
            fresh_ttl = NGX_HTTP_CACHE_TURBO_TTL_MAX;
        }

        if (ctx->warm && ngx_http_cache_turbo_build_key(r, clcf, ctx) != NGX_OK) {
            return;
        }

        {
            ngx_http_cache_turbo_zone_t  *z = clcf->shm_zone->data;
            uint32_t                      hash =
                ngx_crc32_short(ctx->key_hash, 32);
            time_t                        stale_window =
                ngx_http_cache_turbo_stale_ttl(fresh_ttl, clcf->stale_mult);
            ngx_int_t                     rc;

            rc = clcf->l1->freshen(z, ctx->key_hash, hash, fresh_ttl,
                                    stale_window);

            if (rc == NGX_OK) {
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: 304 freshened \"%V\" "
                               "fresh_ttl=%T", &r->uri, fresh_ttl);
                (void) ngx_atomic_fetch_add(&z->sh->refreshes, 1);
            } else {
                /* No resident entry to freshen (evicted/never stored/not
                 * yet this key) -- nothing to extend, and nothing to store
                 * either (a 304 still has no body). The revalidation was
                 * not wasted from the origin's point of view, but this zone
                 * has no record of it. */
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: 304 with nothing to freshen "
                               "\"%V\"", &r->uri);
            }
        }
    }

    /* Cold-miss single-flight (v10): if we are the winner but this response is
     * NOT cacheable, the body filter will never store, so clear our in-flight
     * stub now rather than make waiters block on it until lock_ttl. The pool
     * cleanup is the backstop for the remaining non-store paths. */
    if (ctx->cold_winner && !ctx->cold_stored && !ctx->captured
        && ctx->cold_zone != NULL)
    {
        uint32_t  hash = ngx_crc32_short(ctx->key_hash, 32);
        ngx_http_cache_turbo_shm_unstub(ctx->cold_zone, ctx->key_hash, hash,
                                        ctx->cold_owner);
        ctx->cold_stored = 1;
    }
}


/* MAINT-H1: this filter is a fixed SEQUENCE of independent phases, each
 * extracted above into a named helper. The ordering between them is
 * load-bearing (see each helper's own comment) but no phase reads state a
 * later phase has not yet written, so the parent is a straight-line driver.
 * Every phase takes (r, ctx, clcf) and returns to this one function for the
 * hand-off to ngx_http_next_header_filter(), which stays here so there is
 * exactly one downstream-forward site on the non-error path. */
ngx_int_t
ngx_http_cache_turbo_header_filter(ngx_http_request_t *r)
{
    ngx_http_cache_turbo_ctx_t       *ctx;
    ngx_http_cache_turbo_loc_conf_t  *clcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_cache_turbo_module);

    if (ctx == NULL || ctx->served) {
        ngx_http_cache_turbo_header_filter_test_headers(r, ctx != NULL);
        return ngx_http_next_header_filter(r);
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);

    ngx_http_cache_turbo_header_filter_test_headers(r, 1);

    ngx_http_cache_turbo_header_filter_record_breaker(r, ctx, clcf);

    switch (ngx_http_cache_turbo_header_filter_try_sie(r, ctx, clcf)) {
    case NGX_ERROR:
        return NGX_ERROR;
    case NGX_OK:
        return ngx_http_next_header_filter(r);
    default:
        break;
    }

    ngx_http_cache_turbo_header_filter_capture(r, ctx, clcf);

    return ngx_http_next_header_filter(r);
}


/* Downstream forward for the body filter. For a normal (main or SIE) request
 * this is the real next body filter. For a background WARM subrequest it
 * SWALLOWS the chain instead: a warm sr has no client, and forwarding its body
 * into the postpone/write chain accrues r->buffered on the shared main
 * connection. ngx_http_finalize_request then parks the subrequest on
 * ngx_http_writer (the `r != r->main && r->buffered` branch) instead of taking
 * the r->background count-drop, so the warm sr's r->main->count++ is never
 * balanced. If the worker enters graceful exit while parked, the parent
 * stale-serve client connection can never close -> "open socket left in
 * connection" at shutdown (proven via gdb core dump, s84). The body is already
 * captured into ctx->body above; nothing downstream needs it. Consuming the
 * buffers (pos=last, mark consumed) lets the upstream see the output as fully
 * written so the sr finalizes with r->buffered == 0. */
static ngx_int_t
ngx_http_cache_turbo_forward_body(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_chain_t                 *cl;
    ngx_http_cache_turbo_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_cache_turbo_module);

    if (ctx == NULL || !ctx->warm) {
        /* S231-SIE-MIDBODY: this IS the pre-flush oracle -- the moment any
         * non-empty buffer is handed to the real next body filter, those
         * bytes may already be on the wire to the client and the mid-body
         * rescue below can no longer replace them. A warm subrequest (the
         * branch above) never reaches a client, so it does not count.
         *
         * Deliberately NOT TEST_FAULTS-gated, even though the only current
         * READER of the bit is the test-only rescue block. The cost is
         * already nil in a production build -- the `!sie_flushed` guard makes
         * this run at most once per request and the loop breaks on the first
         * non-empty buffer -- and gating it would give the field different
         * semantics per build flavor, so the day a real production trigger
         * for mid-body death is found it would read a bit that was never set
         * in the very build that needs it. Keep the oracle unconditional. */
        if (ctx != NULL && !ctx->sie_flushed) {
            ngx_chain_t  *fcl;

            for (fcl = in; fcl; fcl = fcl->next) {
                if (ngx_buf_in_memory(fcl->buf)
                    && fcl->buf->last > fcl->buf->pos)
                {
                    ctx->sie_flushed = 1;
                    break;
                }
                if (fcl->buf->in_file && fcl->buf->file_last > fcl->buf->file_pos)
                {
                    ctx->sie_flushed = 1;
                    break;
                }
            }
        }
        return ngx_http_next_body_filter(r, in);
    }

    for (cl = in; cl; cl = cl->next) {
        cl->buf->pos = cl->buf->last;
        cl->buf->file_pos = cl->buf->file_last;
        cl->buf->sync = 1;
    }

    return NGX_OK;
}


/* S231-SIE-MIDBODY: rescue a mid-body origin death.
 *
 * The header-filter SIE trigger (~:7948) only fires when the ORIGIN'S
 * STATUS line is an error -- but a mid-body death arrives with headers
 * already sent as a normal 200 (the origin was fine when it opened the
 * response and died partway through the body), so that trigger can never
 * see it. This is the only place left that can still act: BEFORE any
 * byte of this response has reached the client (ctx->sie_flushed is the
 * pre-flush oracle, set the first time a non-empty buffer is forwarded
 * downstream). ngx_http_cache_turbo_forward_body() is the SINGLE set
 * site, and that is sufficient: every downstream exit on the capture
 * path routes through it -- the not-cacheable and oversize aborts, the
 * file-backed delegate, the served/uncaptured early return and the store
 * tail. The only ngx_http_next_body_filter() call this filter makes
 * directly is the sie_serving emit below, which is this rescue's own
 * output and is guarded by sie_body_sent instead. If a future change adds
 * another direct downstream call on the capture path, it MUST set this
 * bit or the rescue will splice into an already-flushed response.
 *
 * Once flushed, this is provably too late: the client already holds an
 * unknown-length prefix of the truncated body, and splicing the snapshot
 * in now would produce a corrupt concatenation (truncated-prefix +
 * full-snapshot), which is strictly worse than the truncated response
 * alone. There is no recovery from that without a protocol the client
 * understands (range replay, chunked trailer, etc) that this module does
 * not have. Ship pre-flush only; do not claim broader coverage.
 *
 * ⚠ Headers are NOT rewritten here, unlike the header-filter SIE path.
 * By the time the body filter runs, ngx_http_next_header_filter() has
 * already returned for THIS response's 200 -- the header chain has
 * already serialised r->headers_out into the wire buffer with no
 * postponement contract (same fact the AUD-SIE-BODY test counter comment
 * below relies on). Rewriting r->headers_out here would change nothing
 * the client observes: the status line stays whatever the origin sent
 * (200), only the BODY is replaced with the complete snapshot instead of
 * the truncated one. That is still strictly better than a truncated 200
 * with no recovery at all, but it is a body-only rescue -- say so plainly
 * rather than claiming header coverage this cannot deliver.
 *
 * ⚠ FRAMING, not just status: the Content-Length this response is framed
 * with was ALSO already serialised on the wire by the time this filter
 * runs (same fact as above). Splicing in a snapshot body of a DIFFERENT
 * length than what the client was told to expect corrupts the framing --
 * the client waits for bytes that never arrive (Content-Length longer
 * than the snapshot), or rejects/desyncs a pipelined connection
 * (Content-Length shorter). That is worse than the truncated body this
 * rescue exists to fix. So the rescue is only framing-safe when either
 * (a) the origin sent no Content-Length at all (content_length_n == -1,
 * i.e. chunked/EOF-framed -- the client places no length expectation on
 * the body, so any snapshot length is safe), or (b) the snapshot body is
 * EXACTLY the length the origin advertised. Checked BEFORE calling
 * sie_rewrite(): sie_rewrite() is destructive (wipes r->headers_out.headers
 * via ngx_list_init(), clears the typed Content-Length field) so there is
 * no way to call it, discover a mismatch, and back out --
 * sie_snap_body_len() reads the snapshot's length straight from the
 * blob's validated header, with no side effect on r->headers_out.
 *
 * Detecting the failure: no in-process production signal proved reliable
 * (r->upstream->peer.connection == NULL races the connection close
 * timing; unmet r->upstream->length can be legitimate chunked/EOF
 * framing; c->error is set too late relative to this filter running).
 * Ship the deterministic TEST_FAULTS trigger
 * (cache_turbo_test_midbody_abort, module.h ~:1656) instead: it treats
 * the FIRST arriving buffer as the failure, which is how this module
 * tests every other origin-failure path it cannot otherwise force.
 *
 * Returns NGX_ERROR if sie_rewrite() failed (the caller must propagate it);
 * NGX_OK otherwise. On a successful rescue ctx->sie_serving is set, so the
 * caller falls into the sie_serving emit phase below -- exactly as when the
 * block was inline.
 */
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
static ngx_int_t
ngx_http_cache_turbo_body_filter_midbody_rescue(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx)
{
    off_t      origin_cl;
    size_t     snap_body_len;
    ngx_uint_t framing_ok;
    ngx_int_t  rc;

    /* use_stale_triggers() switches on the STATUS r->headers_out carries --
     * always 200 here, since a mid-body death by definition happened after a
     * successful header phase, so calling it with the real status can never
     * match. What we need instead is "does this location's use_stale policy
     * treat a representative connection failure as stale-eligible at all" --
     * the same question the breaker's ERROR/TIMEOUT fold (P5-5 comment above
     * ngx_http_cache_turbo_transport_failure(), module.c) answers for a real
     * request by reading r->upstream->state->header_time. There is no real
     * r->upstream attempt to read here -- this whole path is the TEST_FAULTS
     * fault injector standing in for a connection-level death mid-body -- so
     * transport_failure is passed hardcoded 1: NGX_HTTP_BAD_GATEWAY is the
     * representative status nginx itself synthesises for a transport
     * failure, and passing transport_failure=1 alongside it sets the SAME
     * ERROR bit a real transport failure would set, matching the
     * USE_STALE_DEFAULT every other SIE fixture in this suite relies on
     * (HTTP_502 always matches the status alone; ERROR now needs this 1). */
    if (ctx == NULL || !clcf->test_midbody_abort
        || !ctx->sie_armed || ctx->sie_serving || ctx->sie_flushed
        || !ngx_http_cache_turbo_use_stale_triggers(clcf->use_stale,
                                                    NGX_HTTP_BAD_GATEWAY, 1))
    {
        return NGX_OK;
    }

    origin_cl = r->headers_out.content_length_n;

    framing_ok = (ngx_http_cache_turbo_sie_snap_body_len(ctx,
                                                &snap_body_len) == NGX_OK)
                 && (origin_cl == -1
                     || (off_t) snap_body_len == origin_cl);

    if (!framing_ok) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: STALE-IF-ERROR mid-body rescue "
                       "declined \"%V\" -- snapshot length would not "
                       "match the already-serialised Content-Length: %O",
                       &r->uri, origin_cl);
        return NGX_OK;
    }

    rc = ngx_http_cache_turbo_sie_rewrite(r, ctx);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }
    if (rc == NGX_OK) {
        ctx->served = 1;
        ctx->sie_serving = 1;

        if (clcf->shm_zone != NULL) {
            ngx_http_cache_turbo_zone_t  *sz = clcf->shm_zone->data;
            (void) ngx_atomic_fetch_add(&sz->sh->sie_serves, 1);
        }

        /* S231-SIE-MIDBODY / lease: mirror the header-filter SIE
         * path (~:7981) exactly. This request is now served from the
         * snapshot and will never reach the store tail, so a cold-miss
         * lease it won would otherwise sit owned until cleanup/expiry,
         * parking every waiter behind it for no reason. */
        if (ctx->cold_winner && !ctx->cold_stored
            && ctx->cold_zone != NULL)
        {
            uint32_t  h = ngx_crc32_short(ctx->key_hash, 32);
            ngx_http_cache_turbo_shm_unstub(ctx->cold_zone,
                                            ctx->key_hash, h,
                                            ctx->cold_owner);
            ctx->cold_stored = 1;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: STALE-IF-ERROR mid-body rescue \"%V\" "
                       "len=%uz (pre-flush, body-only)",
                       &r->uri, ctx->sie_body_len);
        /* Discard the truncated prefix the fault delivered in THIS
         * call (nothing was forwarded yet -- sie_flushed is still 0)
         * and fall into the existing sie_serving emit block below,
         * which already knows how to consume `in` and emit
         * ctx->sie_body as a single last_buf chain. */
    }

    return NGX_OK;
}
#endif


/* Mark every buffer in `in` fully consumed (pos=last, buffers released back
 * to the upstream). With proxy_buffering off, nothing else ever advances
 * those buffers, so skipping this leaves them stuck on the upstream's
 * busy_bufs forever and the request hangs.
 *
 * AUD-SIE-BODY: the TEST_FAULTS counter observes the chain AFTER the consume
 * loop -- this is the postcondition the fix is supposed to establish (every
 * buffer in `in` fully consumed), not a pre-count of how much data arrived.
 * With the fix present the loop always leaves pos == last, so this is always
 * 0; reverting ONLY the consume loop (this counter/log stays) leaves the
 * buffers exactly as the upstream delivered them, so this counts them > 0.
 * Logged (not a response header): by the time this runs,
 * ngx_http_next_header_filter() has already returned for this request --
 * nginx's header filter chain serializes r->headers_out.headers into the wire
 * buffer synchronously and has no postponement contract, so a header added
 * here would be invisible to the client and would always read 0 (verified).
 * The greppable "cache_turbo: test_sie_unconsumed=" token is the oracle the
 * runtime test reads out of logs/error.log instead. */
static void
ngx_http_cache_turbo_body_filter_sie_consume(ngx_http_request_t *r,
    ngx_http_cache_turbo_ctx_t *ctx, ngx_chain_t *in)
{
    ngx_chain_t  *cl;

    for (cl = in; cl; cl = cl->next) {
        cl->buf->pos = cl->buf->last;
        cl->buf->file_pos = cl->buf->file_last;
        cl->buf->sync = 1;
    }

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->pos != cl->buf->last) {
            ctx->test_sie_unconsumed++;
        }
    }
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                  "cache_turbo: test_sie_unconsumed=%ui",
                  ctx->test_sie_unconsumed);
#else
    (void) r;
    (void) ctx;
#endif
}


/* RFC-2 stale-if-error, body half. The header filter replaced an origin error
 * with the stale snapshot; discard the upstream error body and emit the
 * snapshot body ONCE with last_buf. sie_body_sent swallows any trailing error
 * buffers the upstream still streams after the last_buf.
 *
 * Returns NGX_DECLINED when the snapshot body was already sent and the caller
 * must simply return NGX_OK (the upstream chain has been consumed here);
 * NGX_ERROR on allocation failure; NGX_OK with *out set to the single-link
 * chain the caller hands to ngx_http_next_body_filter(). The downstream
 * hand-off deliberately stays in the parent. */
static ngx_int_t
ngx_http_cache_turbo_body_filter_sie_emit(ngx_http_request_t *r,
    ngx_http_cache_turbo_ctx_t *ctx, ngx_chain_t *in, ngx_chain_t *out)
{
    ngx_buf_t  *eb;

    if (ctx->sie_body_sent) {
        ngx_http_cache_turbo_body_filter_sie_consume(r, ctx, in);
        return NGX_DECLINED;
    }
    ctx->sie_body_sent = 1;

    eb = ngx_calloc_buf(r->pool);
    if (eb == NULL) {
        return NGX_ERROR;
    }
    eb->pos = ctx->sie_body;
    eb->last = ctx->sie_body + ctx->sie_body_len;
    eb->memory = (ctx->sie_body_len > 0) ? 1 : 0;
    eb->last_buf = (r == r->main) ? 1 : 0;
    eb->last_in_chain = 1;
    if (ctx->sie_body_len == 0) {
        eb->sync = 1;
    }

    ngx_http_cache_turbo_body_filter_sie_consume(r, ctx, in);

    out->buf = eb;
    out->next = NULL;
    return NGX_OK;
}


/* CI-only: deterministically drive the file-backed delegate path. The real
 * trigger (an in_file && !in_memory buffer) is fs/directio dependent and
 * cannot be produced reliably in the harness. Take the SAME abort-capture +
 * delegate-unmodified-chain action here, without forging b->in_file (which
 * would make downstream sendfile garbage).
 *
 * Returns NGX_DECLINED when the fault fired and the caller must delegate the
 * chain downstream; NGX_OK otherwise. */
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
static ngx_int_t
ngx_http_cache_turbo_body_filter_force_file_buf(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx)
{
    if (!clcf->test_force_file_buf) {
        return NGX_OK;
    }

    ctx->captured = 0;
    ctx->body = NULL;
    ctx->body_last = NULL;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cache_turbo: test_force_file_buf \"%V\" -> delegate to "
                   "native (capture abandoned)", &r->uri);
    return NGX_DECLINED;
}
#endif


/* Append the incoming buffers to our captured chain (copying the bytes into
 * the request pool so they survive past this filter call). Seed the append
 * cursor from the cached tail so a multi-call streamed body does not re-walk
 * the whole chain every filter invocation (was O(n²)).
 *
 * ⚠ The cursor that survives re-entry is ctx->body_last, a chain LINK we
 * allocated in r->pool and own -- not a pointer into any upstream buffer.
 * r->pool blocks are never realloc'd or moved, and nothing frees an
 * individual link before the pool dies at request end, so it stays valid
 * across filter invocations. Every path that abandons capture
 * (file-backed, oversize, test_force_file_buf) resets body/body_last to NULL
 * together with captured=0, so no stale cursor survives an abort.
 *
 * Returns NGX_DECLINED when capture was abandoned and the caller must
 * delegate the chain downstream; NGX_ERROR on allocation failure; NGX_OK
 * otherwise, with *last set when the response is complete. */
static ngx_int_t
ngx_http_cache_turbo_body_filter_capture(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_chain_t *in, ngx_uint_t *last)
{
    u_char        *p;
    size_t         n;
    ngx_buf_t     *b;
    ngx_chain_t   *cl, **ll;

    ll = ctx->body_last ? &ctx->body_last->next : &ctx->body;

    for (cl = in; cl; cl = cl->next) {
        ngx_buf_t    *nb;
        ngx_chain_t  *ncl;

        b = cl->buf;

        /* Only in-memory bytes are capturable. A file-backed buffer (sendfile
         * path) carries no valid b->pos for its declared ngx_buf_size(), so
         * copying from b->pos would read out of bounds. Abort capture and
         * delegate the whole response downstream rather than store garbage. */
        if (b->in_file && !ngx_buf_in_memory(b)
            && b->file_last > b->file_pos)
        {
            ctx->captured = 0;
            ctx->body = NULL;
            ctx->body_last = NULL;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: file-backed body \"%V\" -> delegate to "
                           "native (cannot capture from memory)", &r->uri);
            return NGX_DECLINED;
        }

        n = ngx_buf_in_memory(b) ? (size_t) (b->last - b->pos) : 0;

        if (n > 0) {
            /* Q2: oversize early-abort, BEFORE the alloc+memcpy. Once the body
             * would cross max_size we will never store this response (the store
             * gate below refuses it), so a single huge buffer must not be fully
             * copied into the request pool just to be discarded at last_buf.
             * Drop the partial capture, mark the request non-capturing, and
             * forward downstream untouched. A stacked native proxy_cache (README
             * pattern B) keeps the object on disk; cache-turbo delegates oversize
             * media with ~zero shm/pool overhead. Any cold-miss stub is cleared
             * by the pool-cleanup backstop at request end. */
            if (clcf->max_size > 0 && ctx->body_len + n > clcf->max_size) {
                ctx->captured = 0;
                ctx->body = NULL;
                ctx->body_last = NULL;
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "cache_turbo: oversize capture aborted \"%V\" "
                               "body>%uz -> delegate to native",
                               &r->uri, clcf->max_size);
                return NGX_DECLINED;
            }

            p = ngx_pnalloc(r->pool, n);
            if (p == NULL) {
                return NGX_ERROR;
            }
            ngx_memcpy(p, b->pos, n);

            nb = ngx_calloc_buf(r->pool);
            if (nb == NULL) {
                return NGX_ERROR;
            }
            nb->pos = p;
            nb->last = p + n;
            nb->memory = 1;

            ncl = ngx_alloc_chain_link(r->pool);
            if (ncl == NULL) {
                return NGX_ERROR;
            }
            ncl->buf = nb;
            ncl->next = NULL;

            *ll = ncl;
            ll = &ncl->next;
            ctx->body_last = ncl;

            ctx->body_len += n;
        }

        if (b->last_buf || b->last_in_chain) {
            *last = 1;
        }
    }

    return NGX_OK;
}


/* Compute this response's freshness windows: the fresh TTL, the absolute
 * serveable window (fresh + stale) and the RFC-2 stale-if-error deadline.
 * Pure computation off clcf + r->headers_out; no shared state is touched, so
 * this takes no lock and holds none.
 *
 * Returns NGX_DECLINED when the status is not cacheable at all (the caller
 * must delegate downstream); NGX_OK with the three out-params set. */
static ngx_int_t
ngx_http_cache_turbo_body_filter_windows(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, time_t *out_ttl,
    time_t *out_stale_window, time_t *out_sie_window)
{
    time_t  ttl, stale_window, sie_window = 0;

    ttl = ngx_http_cache_turbo_status_ttl(clcf, r->headers_out.status);
    if (ttl < 0) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: not cacheable \"%V\" status=%ui",
                       &r->uri, r->headers_out.status);
        return NGX_DECLINED;                            /* not cacheable */
    }

    /* O6/S3.1: a negative-cached error (e.g. "cache_turbo_valid 503 1m")
     * must never overwrite a body that is still worth serving. The guard
     * itself lives at the store site below (search "refusing to overwrite
     * cached body"), which is the single source of truth for the predicate
     * and why it looks the way it does -- including why the blob's sie_ttl
     * is deliberately NOT consulted. Do not restate the predicate here; an
     * earlier copy of it in this comment went stale the moment the
     * implementation changed. */
    /* Honor upstream freshness (v7): let the response's own
     * Cache-Control/Expires set the fresh TTL when enabled. ignore_cc wins:
     * if the operator told us to ignore Cache-Control, the TTL is the static
     * cache_turbo_valid, never the (ignored) upstream max-age/Expires. */
    if (clcf->honor_cc && !clcf->ignore_cc) {
        time_t  up = ngx_http_cache_turbo_upstream_ttl(r);
        if (up >= 0) {
            ttl = up;
        }
    }

    /* STAB-5: clamp the fresh TTL to the uint32 ceiling before it feeds the
     * blob fresh_ttl cast, the stale-window multiply, and the L2 PX. An
     * unbounded upstream max-age (honor_cc) is the realistic source. */
    if (ttl > NGX_HTTP_CACHE_TURBO_TTL_MAX) {
        ttl = NGX_HTTP_CACHE_TURBO_TTL_MAX;
    }

    /* Absolute serveable window (fresh + stale) from now, reused by the blob
     * metadata, the L1 store, and the L2 EXPIRE so all three agree. */
    stale_window = ngx_http_cache_turbo_stale_ttl(ttl, clcf->stale_mult);

    /* RFC 5861 / RFC-2: a response stale-while-revalidate=N sets the stale
     * window explicitly (fresh + N), overriding the cache_turbo_stale_mult
     * default. The existing SWR machinery (background_update) then serves
     * stale + refreshes within it. must-revalidate below still wins (it
     * collapses the window). Only meaningful for a finite TTL.
     *
     * ignore_cc skips ALL three response-Cache-Control window adjustments
     * (swr here, must-revalidate + stale-if-error below): the operator told
     * us to ignore the upstream Cache-Control, so an upstream max-age=0 /
     * must-revalidate / stale-while|if-* must NOT reshape the window built
     * from cache_turbo_valid + cache_turbo_stale_mult. Matches the
     * proxy_ignore_headers Cache-Control contract (the whole header is
     * inert), not just the cacheability floor. */
    if (ttl > 0 && !clcf->ignore_cc) {
        time_t  swr = ngx_http_cache_turbo_response_swr(r);
        if (swr >= 0) {
            /* AUD-CC-DELTA-OVF: swr is parsed straight off the wire and can
             * be up to NGX_MAX_INT_T_VALUE (e.g. stale-while-revalidate=
             * 9223372036854775807) -- clamp the delta BEFORE the add, not
             * the sum after, or ttl + swr overflows signed time_t (UB). */
            stale_window = ngx_http_cache_turbo_add_ttl_clamped(ttl, swr);
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: stale-while-revalidate=%T \"%V\"",
                           swr, &r->uri);
        }
    }

    /* RFC 9111 must-revalidate / proxy-revalidate: once stale, the response
     * must NOT be served without revalidation. We have no validation channel
     * for a hit, so collapse the stale window to the fresh TTL — the object
     * is served fresh until its deadline, then re-fetched (no stale serve,
     * no stale-if-error). Only meaningful for a finite TTL. Skipped under
     * ignore_cc (see the swr block above — the whole upstream Cache-Control
     * is inert, so an upstream must-revalidate must not collapse the
     * operator-configured stale window). */
    if (ttl > 0 && !clcf->ignore_cc
        && ngx_http_cache_turbo_response_must_revalidate(r))
    {
        stale_window = ttl;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: must-revalidate \"%V\" -> no stale window",
                       &r->uri);

    } else if (ttl > 0 && !clcf->ignore_cc) {
        /* RFC 5861 §4 / RFC-2: a response stale-if-error=N records an absolute
         * serve-on-error window (fresh + N) in the blob's sie_ttl (CTB4), so a
         * later origin failure may serve this copy PAST the normal stale
         * window. 0 = absent => no serve-on-error beyond the stale window.
         * Gated behind !must-revalidate above (must-revalidate forbids any
         * stale serve, stale-if-error included). The serve-on-error path that
         * consumes sie_ttl lands in a follow-up; the field is carried now so
         * the wire format turns over once (single cold-cache event). */
        time_t  sie = ngx_http_cache_turbo_response_sie(r);
        if (sie >= 0) {
            /* AUD-CC-DELTA-OVF: same wire-controlled overflow as the swr
             * clamp above -- clamp the delta before the add. */
            sie_window = ngx_http_cache_turbo_add_ttl_clamped(ttl, sie);
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: stale-if-error=%T \"%V\"",
                           sie, &r->uri);

        } else if (ttl > 0 && clcf->keep_stale > 0) {
            /* S2.2 / D-1: no response stale-if-error to honor here, so fall
             * back to the operator's cache_turbo_keep_stale baseline (fresh +
             * keep_stale). This branch only runs when a response SIE was
             * absent -- a HONORED response stale-if-error above already took
             * this window and we must NOT also apply keep_stale on top of it
             * (that would be max(), which the plan explicitly rejects: an
             * origin that states its own error window is making a statement,
             * not setting a floor). Still gated behind the outer
             * !must-revalidate branch above, so a honored must-revalidate
             * still collapses the window to `ttl` and suppresses keep_stale
             * too -- must-revalidate forbids ANY stale serve. */
            sie_window = ttl + clcf->keep_stale;
            if (sie_window > NGX_HTTP_CACHE_TURBO_TTL_MAX) {
                sie_window = NGX_HTTP_CACHE_TURBO_TTL_MAX;
            }
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: keep_stale=%T \"%V\"",
                           clcf->keep_stale, &r->uri);
        }

    } else if (ttl > 0 && clcf->ignore_cc && clcf->keep_stale > 0) {
        /* D-1: under ignore_cc the response-derived swr/must-revalidate/sie
         * branches above never run (the whole upstream Cache-Control is
         * inert), so this location's stale window is untouched by the
         * response and sie_window is still 0 here. keep_stale is OPERATOR
         * config, not upstream config -- ignore_cc only makes the upstream
         * header inert, it does not disable operator-configured retention.
         * Apply the keep_stale baseline unconditionally in this case (no
         * response SIE to compare against, and no honored must-revalidate
         * to suppress it -- must-revalidate is itself response-derived and
         * therefore inert under ignore_cc). */
        sie_window = ttl + clcf->keep_stale;
        if (sie_window > NGX_HTTP_CACHE_TURBO_TTL_MAX) {
            sie_window = NGX_HTTP_CACHE_TURBO_TTL_MAX;
        }
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: keep_stale=%T (ignore_cc) \"%V\"",
                       clcf->keep_stale, &r->uri);
    }

    *out_ttl = ttl;
    *out_stale_window = stale_window;
    *out_sie_window = sie_window;
    return NGX_OK;
}


/* First pass: measure the header block that _blob_write() will emit.
 *
 * ⚠ AUD-HDR1: this walk and the emit walk in _blob_write() MUST make
 * identical decisions or headers_len would lie about the block that follows.
 * They are deliberately NOT merged into one walk: the measure pass has to
 * complete before the blob can be sized and allocated, so a single fused
 * walk is not expressible without buffering the whole block twice. The
 * shared ngx_http_cache_turbo_header_admissible() gate is what guarantees
 * the two passes agree -- one helper, called twice. */
static void
ngx_http_cache_turbo_body_filter_measure_headers(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_str_t *ct, size_t *out_hdr_bytes,
    uint32_t *out_nheaders)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;
    size_t            hdr_bytes = 0;
    uint32_t          nheaders = 0;
    ngx_uint_t        i;

    /* P4-3: Content-Type goes through the SAME admissibility gate as every
     * other pair. It used to be emitted unconditionally, so a CR/LF in an
     * origin's Content-Type was caught only on the way OUT, by
     * restore_response_headers(). That was survivable while restore always
     * re-validated; it is not survivable once BLOBF_HDRS_VETTED lets restore
     * skip that pass, because the bit would then assert a check that never
     * ran on this one field. Gating it here is what makes the bit's claim
     * true for the whole blob.
     *
     * ⚠ Must stay byte-identical to the emit pass in _blob_write(), or
     * headers_len lies about the block that follows (AUD-HDR1). */
    if (ct->len
        && ngx_http_cache_turbo_header_admissible(clcf,
               (u_char *) "Content-Type", sizeof("Content-Type") - 1,
               ct->data, ct->len))
    {
        hdr_bytes += sizeof(uint32_t) + sizeof("Content-Type") - 1
                     + sizeof(uint32_t) + ct->len;
        nheaders++;
    }

    part = &r->headers_out.headers.part;
    h = part->elts;
    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (h[i].hash == 0
            || !ngx_http_cache_turbo_header_admissible(clcf,
                    h[i].key.data, h[i].key.len,
                    h[i].value.data, h[i].value.len))
        {
            continue;
        }
        hdr_bytes += sizeof(uint32_t) + h[i].key.len
                     + sizeof(uint32_t) + h[i].value.len;
        nheaders++;
    }

    *out_hdr_bytes = hdr_bytes;
    *out_nheaders = nheaders;
}


/* Serialise the blob: the fixed 44-byte LE wire header (STAB-4), then the
 * header block, then the captured body. `blob` must be at least
 * NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + hdr_bytes + ctx->body_len bytes, as
 * measured by _measure_headers(). The header emit walk here is the second
 * half of the AUD-HDR1 pair -- see that helper's comment. */
static void
ngx_http_cache_turbo_body_filter_blob_write(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    u_char *blob, ngx_str_t *ct, size_t hdr_bytes, uint32_t nheaders,
    time_t ttl, time_t stale_window, time_t sie_window)
{
    ngx_http_cache_turbo_blob_hdr_t   bhw;
    ngx_list_part_t                  *part;
    ngx_table_elt_t                  *h;
    ngx_chain_t                      *cl;
    u_char                           *w;
    ngx_uint_t                        i;

    ngx_memzero(&bhw, sizeof(bhw));
    bhw.nheaders = nheaders;
    bhw.headers_len = (uint32_t) hdr_bytes;
    bhw.body_len = (uint32_t) ctx->body_len;
    bhw.status = (uint32_t) r->headers_out.status;
    /* Freshness metadata so an L2 hit restores the remaining lifetime
     * (not the location default). stale_ttl is the absolute serveable
     * window from creation (fresh + stale), matching shm_store. */
    bhw.created = (int64_t) ngx_time();
    bhw.fresh_ttl = (uint32_t) (ttl > 0 ? ttl : 0);
    bhw.stale_ttl = (uint32_t) stale_window;
    bhw.sie_ttl = (uint32_t) sie_window;   /* CTB4 (RFC-2 SIE) */
    /* S232-BYPASS-STALE: stamp breaker-only on an opted-in URI's blob.
     * ⚠ Assigned unconditionally (bhw is an uninitialised stack struct
     * populated field-by-field) -- an unset flags here would stamp
     * stack garbage, and a stray BLOBF_BREAKER_ONLY would make an
     * ordinary entry unserveable while a MISSING one would publish a
     * breaker-only body to the normal hit path.
     *
     * P3-2: same "assign unconditionally" reasoning applies to
     * BLOBF_ORIGIN_ENCODED + the packed ae-class -- a missing bit on a body
     * that IS origin-pre-compressed would let the serve chokepoint hand it
     * to a client whose Accept-Encoding cannot decode it (the exact failure
     * mode the class exists to prevent, vary.c:196-201). */
    bhw.flags = ctx->brk_only
                ? NGX_HTTP_CACHE_TURBO_BLOBF_BREAKER_ONLY : 0;
    if (ctx->origin_encoded_capture) {
        bhw.flags |= NGX_HTTP_CACHE_TURBO_BLOBF_ORIGIN_ENCODED;
        bhw.flags |= ((uint32_t) ctx->origin_encoded_class
                          << NGX_HTTP_CACHE_TURBO_BLOBF_AE_CLASS_SHIFT)
                      & NGX_HTTP_CACHE_TURBO_BLOBF_AE_CLASS_MASK;
    }
    if (ctx->auth_shareable) {
        bhw.flags |= NGX_HTTP_CACHE_TURBO_BLOBF_AUTH_SHAREABLE;
    }

    /* P4-3: every pair this function emits below passed
     * ngx_http_cache_turbo_header_admissible() first -- the Content-Type
     * branch and the headers-list loop both gate on it, and the measure pass
     * gated identically. So the claim the bit makes ("the AUD-HDR1 gate has
     * already run over this header block") is true for the blob we are about
     * to write, and restore_response_headers() may skip re-running it on an
     * L1 hit.
     *
     * ⚠ Set unconditionally for the same reason bhw.flags is assigned
     * unconditionally above: this is the ONE place the bit is ever set. If a
     * future edit makes any pair reach CT_PUT without the gate, this line
     * becomes a lie and the restore-side skip becomes a header-injection
     * bypass -- keep the gate and this stamp in the same function.
     *
     * The bit is stripped again the moment such a blob comes back from L2
     * (blob.c ngx_http_cache_turbo_blob_clear_vetted, called at both L2
     * ingress points), which is what keeps an untrusted L2 writer from
     * setting it themselves. */
    bhw.flags |= NGX_HTTP_CACHE_TURBO_BLOBF_HDRS_VETTED;

    ngx_http_cache_turbo_blob_hdr_write(blob, &bhw);

    w = blob + NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE;

    /* write a single name/value pair (lengths fixed-endian, STAB-4) */
    #define CT_PUT(np, nl, vp, vl)                                     \
        do {                                                          \
            ngx_http_cache_turbo_put_u32(w, (uint32_t) (nl)); w += 4; \
            ngx_memcpy(w, (np), (nl)); w += (nl);                     \
            ngx_http_cache_turbo_put_u32(w, (uint32_t) (vl)); w += 4; \
            ngx_memcpy(w, (vp), (vl)); w += (vl);                     \
        } while (0)

    /* P4-3: mirror of the measure pass's gate -- see the comment there. */
    if (ct->len
        && ngx_http_cache_turbo_header_admissible(clcf,
               (u_char *) "Content-Type", sizeof("Content-Type") - 1,
               ct->data, ct->len))
    {
        CT_PUT("Content-Type", sizeof("Content-Type") - 1,
               ct->data, ct->len);
    }

    part = &r->headers_out.headers.part;
    h = part->elts;
    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (h[i].hash == 0
            || !ngx_http_cache_turbo_header_admissible(clcf,
                    h[i].key.data, h[i].key.len,
                    h[i].value.data, h[i].value.len))
        {
            continue;
        }
        CT_PUT(h[i].key.data, h[i].key.len,
               h[i].value.data, h[i].value.len);
    }
    #undef CT_PUT

    /* append body */
    for (cl = ctx->body; cl; cl = cl->next) {
        size_t bn = ngx_buf_size(cl->buf);
        ngx_memcpy(w, cl->buf->pos, bn);
        w += bn;
    }
}


/* The L1 store, kept whole as ONE helper because it is one decision: the
 * 5xx-protecting store_if() and the plain store() are two arms of the same
 * choice, and the AUD-5XX-CTA fold that made the predicate and the write
 * share a single lock hold lives inside shm_store_if(). Splitting the arms
 * apart, or hoisting the store_rc dispatch into the parent, would put a
 * caller boundary between the predicate and the write it guards.
 *
 * O6/S3.1: a negative-cached error (e.g. "cache_turbo_valid 503 1m")
 * must never overwrite a body that is still worth serving -- that is
 * the exact inverse of outage resilience.
 *
 * AUD-5XX-CTA: this used to be a separate check-then-act -- lock,
 * lookup, decide `protect`, unlock, THEN store re-locked later.
 * Reachable under cache_turbo_bypass (skips lookup AND
 * single-flight, still permits storing), another worker could
 * change the node in the gap between the two critical sections.
 * Folded into a single store_if() call below: the predicate
 * (search "refusing to overwrite cached body") and the write now
 * share ONE lock hold, via
 * NGX_HTTP_CACHE_TURBO_STORE_IF_ABSENT_OR_DEAD, which is exactly
 * the old `protect` predicate --
 *   kind == ENTRY && ctn->len > 0 && (stale_until == 0
 *                                     || now < stale_until)
 * -- moved inside shm_store_if(). stale_until == 0 means FOREVER,
 * not expired.
 *
 * ⚠ D-4 ("does this also cover a body alive ONLY via
 * cache_turbo_keep_stale, i.e. past stale_until?") is YES, and it is
 * ALREADY SATISFIED UPSTREAM -- deliberately NOT by a second branch
 * on the blob's sie_ttl here. A keep-stale-only body arms an SIE
 * snapshot at access time (see the `sie_ttl > 0 && now < created +
 * sie_ttl` arming test in the access handler), and the header filter
 * then rewrites the origin's 5xx into that snapshot and sets
 * ctx->served = 1 BEFORE the capture gate -- so the 5xx never
 * reaches this body filter at all and there is nothing here to
 * guard. An earlier revision of this guard did test
 * `now < created + sie_ttl` as a fallback arm; it was UNREACHABLE
 * (identical predicate to the arming test, evaluated on the same
 * fields) and was removed rather than shipped as dead weight. The
 * only way past the arming test is its ngx_pnalloc() for the
 * snapshot failing under memory pressure -- not worth a branch.
 * Do not "restore" the sie_ttl arm without first writing a test
 * that reaches it.
 *
 * ⚠ store_if() MUST probe the key this store will actually write,
 * and `store_key` only diverges from ctx->key_hash at the auto-Vary
 * variant relocation in the caller. Probing ctx->key_hash instead
 * would check the BASE key while the store overwrites the VARIANT --
 * protecting on an unrelated body and still clobbering the variant
 * this guard exists to save. store_key is what is passed in here,
 * preserving that property.
 *
 * Returns NGX_DECLINED when store_if() refused the write because a still-
 * servable good body is resident under store_key (the caller must delegate
 * downstream and must NOT touch ctx->cold_stored -- nothing was written, so
 * the cold-miss stub cleanup must still run); NGX_OK otherwise. */
static ngx_int_t
ngx_http_cache_turbo_body_filter_store(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_cache_turbo_zone_t *z, u_char *store_key, uint32_t hash,
    u_char *blob, size_t blob_len, time_t ttl, time_t stale_window)
{
    ngx_int_t  store_rc;
    ngx_uint_t is_5xx = (r->headers_out.status
                          >= NGX_HTTP_INTERNAL_SERVER_ERROR);

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    /* AUD-STORE-ERR-STUB: deterministically simulate a failed store
     * without depending on real slab exhaustion timing.
     *
     * The store is SKIPPED, not called-then-overridden. Masking the
     * return value of a store that actually succeeded is not the same
     * fault: the entry lands in L1 anyway, the next request is a plain
     * L1 HIT, and no cold-miss stub is ever orphaned -- so the test
     * built on it passed identically with and without the fix. The
     * defect under test is "no entry was written, so the stub must be
     * cleaned up", which requires no entry to be written. */
    if (clcf->test_store_fail) {
        store_rc = NGX_ERROR;
    }
    else
#endif
    if (is_5xx) {
        store_rc = clcf->l1->store_if(z, store_key, hash,
                   blob, blob_len, ttl, stale_window,
                   NGX_HTTP_CACHE_TURBO_STORE_IF_ABSENT_OR_DEAD);

    } else {
        store_rc = clcf->l1->store(z, store_key, hash,
                   blob, blob_len, ttl,
                   stale_window);
    }

    /* AUD-5XX-CTA: NGX_DECLINED means store_if() refused the write
     * because a still-servable good body is resident under
     * store_key -- equivalent to the old `protect` branch. Return
     * BEFORE touching ctx->cold_stored, same as before: nothing was
     * written, so the cold-miss stub cleanup (AUD-STORE-ERR-STUB,
     * just below) must still run. */
    if (store_rc == NGX_DECLINED) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: refusing to overwrite cached "
                       "body \"%V\" with error status=%ui",
                       &r->uri, r->headers_out.status);
        return NGX_DECLINED;
    }

    if (store_rc == NGX_OK) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: stored \"%V\" len=%uz ttl=%T",
                       &r->uri, blob_len, ttl);

        /* v10: store overwrote any cold-miss stub into a real entry (or
         * we cleared the relocated base stub above), so the cleanup
         * must not remove it. */
        ctx->cold_stored = 1;

    } else {
        /* AUD-STORE-ERR-STUB: a failed store leaves whatever was under
         * store_key untouched -- no real entry was written, so the
         * cold-miss stub (if any) still needs the pool cleanup to run
         * and unstub it. Leaving ctx->cold_stored at 0 here is what
         * arms that cleanup; setting it unconditionally (the bug) told
         * the cleanup a real entry existed and left the stub to block
         * every waiter until lock_ttl. */
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: store failed \"%V\" len=%uz "
                       "ttl=%T", &r->uri, blob_len, ttl);
    }

    return NGX_OK;
}


/* Tokenise the cache_turbo_tag value into `seen`, deduped within the value and
 * capped at NGX_HTTP_CACHE_TURBO_MAX_TAGS entries of at most MAX_TAG_LEN bytes
 * each. Returns the tag count.
 *
 * ⚠ `*sp` is an IN/OUT cursor into the caller's tagval, advanced to where the
 * tokeniser stopped. The caller needs that resume point to tell "the value ran
 * out" from "the cap was reached" for the truncation warning, so it is returned
 * rather than recomputed. It stays valid because tagval lives in r->pool for
 * the whole call and nothing here reallocates or reorders it; seen[] points
 * INTO that same buffer, so the entries are only valid for this call's
 * lifetime, which is exactly how the caller uses them (SADD, then done).
 *
 * PERF-2: the tag value is upstream-controlled (e.g. an X-Cache-Tags header),
 * so without bounds a hostile/buggy origin could name thousands of tags and
 * make ONE response fire thousands of SADD connections. Cap the count, cap each
 * tag's length, and dedup so the same tag in one value is SADD'd once.
 *
 * CR297-TAGLEN: an over-long single tag is silently dropped here -- unlike the
 * MAX_TAGS count cap (which the caller detects via the returned `*sp` cursor
 * and warns on), a length drop still advances `s` past the whole token, so
 * the caller's `s < e` check cannot see it: the entry becomes unpurgeable on
 * that tag with no signal anywhere. Warn here, at the point the drop actually
 * happens, naming the tag length and the limit. */
static ngx_uint_t
ngx_http_cache_turbo_body_filter_tag_split(ngx_http_request_t *r, u_char **sp,
    u_char *e, ngx_str_t *seen)
{
    u_char     *s = *sp, *tok;
    size_t      toklen;
    ngx_uint_t  ntags = 0, k;

    while (s < e && ntags < NGX_HTTP_CACHE_TURBO_MAX_TAGS) {
        while (s < e && (*s == ' ' || *s == '\t' || *s == ','
                         || *s == '\r' || *s == '\n'))
        {
            s++;
        }
        tok = s;
        while (s < e && *s != ' ' && *s != '\t' && *s != ','
               && *s != '\r' && *s != '\n')
        {
            s++;
        }
        toklen = (size_t) (s - tok);
        if (toklen == 0) {
            continue;          /* empty: skip, nothing to warn about */
        }
        if (toklen > NGX_HTTP_CACHE_TURBO_MAX_TAG_LEN) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "cache_turbo: tag of length %uz for \"%V\" exceeds "
                "NGX_HTTP_CACHE_TURBO_MAX_TAG_LEN=%ui -- this tag is NOT "
                "indexed and a purge of it will NOT invalidate this entry",
                toklen, &r->uri,
                (ngx_uint_t) NGX_HTTP_CACHE_TURBO_MAX_TAG_LEN);
            continue;          /* over-long: skip */
        }

        for (k = 0; k < ntags; k++) {   /* dedup within value */
            if (seen[k].len == toklen
                && ngx_memcmp(seen[k].data, tok, toklen) == 0)
            {
                break;
            }
        }
        if (k < ntags) {
            continue;          /* already added this tag */
        }

        seen[ntags].data = tok;
        seen[ntags].len = toklen;
        ntags++;
    }

    *sp = s;
    return ntags;
}


/* Tag index (v2c): for each tag in the cache_turbo_tag expression, SADD this
 * object's L2 key to the tag set so it can be purged by tag later. Tags live
 * only in L2; skip when Redis is off. The memcached backend has no tag support
 * (tag_add == NULL, v13).
 *
 * cache_turbo_surrogate_key (emit the same tags downstream for a fronting CDN)
 * is handled separately in the HEADER filter -- headers are already sent by
 * the time this body-filter store runs, so the emit MUST happen before
 * next_header_filter, not here. */
static void
ngx_http_cache_turbo_body_filter_tag_index(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, u_char *store_key, time_t retain_ttl)
{
    ngx_str_t  tagval;
    u_char    *s, *e;
    ngx_uint_t ntags, k;
    /* Bounded and deduped by _tag_split(); see that helper for the PERF-2
     * rationale behind the count and length caps. */
    ngx_str_t  seen[NGX_HTTP_CACHE_TURBO_MAX_TAGS];

    if (ngx_http_complex_value(r, clcf->tag, &tagval) != NGX_OK
        || tagval.len == 0)
    {
        return;
    }

    s = tagval.data;
    e = tagval.data + tagval.len;

    ntags = ngx_http_cache_turbo_body_filter_tag_split(r, &s, e, seen);

    /* L9: index the whole deduped set in ONE pipelined op
     * (one pool, one connection, one round trip) rather than
     * one op per tag -- a MAX_TAGS response fired up to 16.
     * seen[] is already deduped and cap-bound by the loop
     * above, which is exactly tag_add_many's contract. Fall
     * back to per-tag calls on a backend that predates the
     * batched slot. */
    if (ntags > 0) {
        if (clcf->backend->tag_add_many) {
            clcf->backend->tag_add_many(clcf, store_key, seen,
                                        ntags, retain_ttl);
        } else {
            for (k = 0; k < ntags; k++) {
                clcf->backend->tag_add(clcf, store_key,
                                       seen[k].data,
                                       seen[k].len, retain_ttl);
            }
        }
    }

    /* The MAX_TAGS cap is a DoS bound (above), not a hint -- but
     * hitting it SILENTLY is a correctness trap: the tags past the
     * cap are never indexed, so a later purge of one of them does
     * NOT invalidate this page and the operator sees stale content
     * with no signal anywhere. Real origins hit this: a Magento
     * category page emits one cat_p_<id> tag PER PRODUCT, so a
     * 40-product page overflows a 16-tag cap and quietly stops
     * being purgeable on the dropped tags.
     *
     * Warn, once per affected response, only when tags were
     * actually dropped -- s < e means the tokeniser stopped early
     * because the cap was reached, not because the value ran out.
     * Skip trailing separators first so a value ending in ", "
     * does not report a phantom drop. */
    while (s < e && (*s == ' ' || *s == '\t' || *s == ','
                     || *s == '\r' || *s == '\n'))
    {
        s++;
    }
    if (s < e) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "cache_turbo: tag list truncated at %ui tags for "
            "\"%V\" -- the remaining tags are NOT indexed and a "
            "purge of them will NOT invalidate this entry "
            "(raise NGX_HTTP_CACHE_TURBO_MAX_TAGS or emit fewer "
            "tags)", (ngx_uint_t) NGX_HTTP_CACHE_TURBO_MAX_TAGS,
            &r->uri);
    }
}


/* auto-Vary tail: persist the active-axis bitmask as an L1 marker under the
 * base key (self-heals if evicted) and, for a Redis backend, SADD this
 * variant's L2 key into the per-base variant index so a later PURGE of the
 * base URI can enumerate + drop every variant from L1+L2. Split out of
 * _store_tail so that function's CCN stays readable; mirrors how the L9 tag
 * path already sits in _body_filter_tag_split above.
 *
 * No early exit: every path here is a fire-and-forget side effect and falls
 * through to the caller's next statement, so pulling it into its own void
 * function changes no control flow in _store_tail. */
static void
ngx_http_cache_turbo_body_filter_varidx_store(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    ngx_http_cache_turbo_zone_t *z, u_char *store_key, uint32_t hash,
    time_t ttl, time_t retain_ttl)
{
    ngx_http_cache_turbo_marker_store(r, clcf, z, &ctx->cache_key,
                                      ctx->vary_bits, ctx->vary_gen,
                                      ttl, retain_ttl);

    /* COR-5 variant index: SADD this variant's L2 key into the
     * per-base index set so a later PURGE of the base URI can
     * enumerate + drop every variant from L1+L2. Redis only
     * (memcached has no sets => tag_add NULL; its variants are
     * invalidated by the L1-only generation bump + TTL instead). */
    if (clcf->backend && clcf->backend->tag_add) {
        u_char     vname[1 + 64];
        size_t     vlen;
        ngx_int_t  varidx_rc;

        vlen = ngx_http_cache_turbo_variant_index_name(
                   &ctx->cache_key, vname);

        /* COR-5(b): the SADD is fire-and-forget, but "handed to the
         * transport" and "dropped before the wire" are NOT the same
         * outcome and used to be indistinguishable here. A drop (armed
         * S231 connect-backoff, failed connect, alloc failure) leaves the
         * object in L1 while the per-base index set does not list it, so
         * a later PURGE of the base -- which enumerates that set with
         * SMEMBERS -- reports success and keeps serving this variant
         * stale until its own TTL.
         *
         * Arm the node's self-heal bit instead: the next L1 hit on this
         * variant re-issues the SADD (access_l1). Still no blocking
         * round trip on the store path -- tag_add returns the moment the
         * op reaches, or fails to reach, the transport. */

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
        /* COR-5(b) fault injection: stand in for redis_launch() refusing
         * this write. The call is SKIPPED, not called-then-overridden --
         * issuing the SADD and merely reporting failure would leave the
         * index already correct and make the self-heal assertion vacuous
         * (the purge would enumerate both variants with the re-issue
         * compiled out). This is the arm the mutation test flips.
         * Armed per REQUEST via X-Cache-Turbo-Test-Varidx-Drop: 1 so the
         * 4-worker runner cannot smear the fault across variants. */
        if (clcf->test_varidx_fail
            && ngx_http_cache_turbo_test_varidx_drop_requested(r))
        {
            varidx_rc = NGX_ERROR;
        } else
#endif
        {
            varidx_rc = clcf->backend->tag_add(clcf, store_key, vname,
                                               vlen, retain_ttl);
        }

        if (varidx_rc != NGX_OK) {
            ngx_http_cache_turbo_shm_varidx_pending_set(z, store_key,
                                                        hash, 1);
            /* c-1: this counter is READ by the PURGE reply's
             * "complete":false decision (purge.c), which is a
             * production wire-contract feature, not a test-only one --
             * it must move on a real dropped write, not only under
             * NGX_HTTP_CACHE_TURBO_TEST_FAULTS. Only the FAULT that
             * produces varidx_rc != NGX_OK stays test-gated above; the
             * accounting for a genuine drop is unconditional. */
            (void) ngx_atomic_fetch_add(&z->sh->varidx_drops, 1);
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "cache_turbo: auto-vary variant index write dropped "
                "for \"%V\" (L2 unreachable); queued for re-issue on "
                "the next hit", &r->uri);
        }
    }
}


/* The store tail: everything that happens once the response is complete and
 * within max_size -- blob serialisation, the L1 store, the auto-Vary marker
 * and variant index, the autotune cost sample, the L2 write-through and the
 * tag index.
 *
 * Returns NGX_DECLINED when the response must simply be delegated downstream
 * without being stored (not cacheable, or store_if() refused the overwrite);
 * NGX_OK otherwise. */
static ngx_int_t
ngx_http_cache_turbo_body_filter_store_tail(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx)
{
    uint32_t                      hash, nheaders = 0;
    u_char                       *blob;
    u_char                        store_key[32];
    size_t                        hdr_bytes = 0, blob_len = 0;
    ngx_str_t                     ct;
    time_t                        ttl, stale_window, sie_window;
    time_t                        retain_ttl;
    ngx_http_cache_turbo_zone_t  *z;

    if (ngx_http_cache_turbo_body_filter_windows(r, clcf, &ttl, &stale_window,
                                                 &sie_window) == NGX_DECLINED)
    {
        return NGX_DECLINED;
    }

    /* Synthesise a Content-Type entry from the typed field (it is not in
     * the headers list). Everything else comes from headers_out.headers. */
    ct = r->headers_out.content_type;

    ngx_http_cache_turbo_body_filter_measure_headers(r, clcf, &ct, &hdr_bytes,
                                                     &nheaders);

    /* STAB-5: headers_len and body_len are uint32 in the blob header. Refuse
     * to store (rather than write a header that lies about the layout) if a
     * pathological response would truncate either. body_len is already
     * bounded by max_size on the capture path; this also covers a max_size
     * configured above 4 GiB and an unbounded header block. Reuse the
     * blob==NULL skip below (same as an alloc failure: silently don't cache). */
    if (hdr_bytes > 0xFFFFFFFFUL || ctx->body_len > 0xFFFFFFFFUL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "cache_turbo: \"%V\" not cached: header/body block "
                      "exceeds the 4 GiB blob field limit", &r->uri);
        blob = NULL;
    } else {
        blob_len = NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE
                   + hdr_bytes + ctx->body_len;
        blob = ngx_pnalloc(r->pool, blob_len);
    }

    if (blob == NULL) {
        return NGX_OK;
    }

    ngx_http_cache_turbo_body_filter_blob_write(r, clcf, ctx, blob, &ct,
                                                hdr_bytes, nheaders, ttl,
                                                stale_window, sie_window);

    /* The L2 retention window, used for the object key AND for every L2
     * index that points at it (variant index, tag index). stale_window
     * already carries any stale-while-revalidate widening; sie_window is
     * the RFC-2 stale-if-error deadline and can extend past it entirely.
     * Both are absolute windows off the same base ttl and are already
     * clamped to TTL_MAX, so max() needs no further bounding.
     *
     * The indexes MUST NOT outlive-mismatch the object: if an index
     * expired at the stale window while the object survived into the
     * SIE-only interval, a tag or base purge in that interval could no
     * longer find the object and would leave it undeletable in L2. */
    retain_ttl = stale_window;
    if (sie_window > retain_ttl) {
        retain_ttl = sie_window;
    }

    z = clcf->shm_zone->data;

    /* auto-Vary (v11 other half): when the response varies on a safe
     * axis, store the object under the SECONDARY variant key (folding the
     * named request headers) instead of the base key, so distinct
     * representations never collide. store_key == key_hash otherwise (no
     * auto_vary, no/whitelist-only Vary, or key_hash was already the
     * variant via the request-time marker). */
    ngx_memcpy(store_key, ctx->key_hash, 32);
    if (clcf->auto_vary && ctx->vary_bits > 0) {
        ngx_http_cache_turbo_variant_hash(r, &ctx->cache_key,
                                          ctx->vary_bits, ctx->vary_gen,
                                          store_key);
    }
    hash = ngx_crc32_short(store_key, 32);

    /* If we relocated the key away from the base (cold-miss winner that
     * only learned the Vary now), the cold-miss stub the access handler
     * left under the base key would never be overwritten by this store →
     * clear it so waiters on the base key stop blocking. unstub only drops
     * a still-stub node, so a real base entry (if any) is untouched. */
    if (ctx->cold_winner && !ctx->cold_stored
        && ngx_memcmp(store_key, ctx->key_hash, 32) != 0)
    {
        ngx_http_cache_turbo_shm_unstub(z, ctx->key_hash,
                           ngx_crc32_short(ctx->key_hash, 32),
                           ctx->cold_owner);
    }

    if (ngx_http_cache_turbo_body_filter_store(r, clcf, ctx, z, store_key,
                                               hash, blob, blob_len, ttl,
                                               stale_window) == NGX_DECLINED)
    {
        return NGX_DECLINED;
    }

    /* auto-Vary: persist the active-axis bitmask as an L1 marker under
     * the base key so the next request resolves straight to this variant
     * (node-local; self-heals if evicted), and index the variant for
     * base-URI PURGE enumeration. See _body_filter_varidx_store above. */
    if (clcf->auto_vary && ctx->vary_bits > 0) {
        ngx_http_cache_turbo_body_filter_varidx_store(r, clcf, ctx, z,
                                                       store_key, hash,
                                                       ttl, retain_ttl);
    }

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cache_turbo: STORE \"%V\" key=%ui len=%uz ttl=%T",
                   &r->uri, (ngx_uint_t) hash, blob_len, ttl);

    /* Record this origin regeneration's cost for the autotune (v4-3).
     * This store site is the origin→cache path only (the L2→L1 fill in
     * the access handler is a separate store call), so request_time here
     * is real origin latency — exactly the miss-cost the autotune feeds
     * on. Recorded unconditionally so the admin cost_ms is meaningful and
     * autotune has history the moment it is enabled; just two atomics. */
    {
        ngx_time_t      *tp = ngx_timeofday();
        ngx_msec_int_t   ms;

        ms = (ngx_msec_int_t)
             ((tp->sec - r->start_sec) * 1000
              + (tp->msec - r->start_msec));
        ngx_http_cache_turbo_autotune_record_cost(z, ms);
    }

    /* L2 write-through (async, fire-and-forget). Copies the blob into
     * its own pool, so it is safe even though `blob` lives in r->pool.
     * The caller owns the L2 key's retention window: retain_ttl (computed
     * above, shared with the L2 index writes) is max(stale_window,
     * sie_window). Passing stale_window alone here would silently
     * truncate the L2 key's PX/EXPIRE to the stale deadline, so an
     * SIE-armed object's L2 copy is already gone by the time an origin
     * failure needs it — the access handler's SIE-from-L2 path would
     * then always miss. */
    if (clcf->backend) {
        clcf->backend->set(r, clcf, store_key,
                           blob, blob_len, ttl, retain_ttl);
    }

    if (clcf->backend && clcf->backend->tag_add && clcf->tag) {
        ngx_http_cache_turbo_body_filter_tag_index(r, clcf, store_key,
                                                   retain_ttl);
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_cache_turbo_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                         rc;
    ngx_chain_t                       eout;
    ngx_http_cache_turbo_ctx_t       *ctx;
    ngx_http_cache_turbo_loc_conf_t  *clcf;
    ngx_uint_t                        last = 0;

    ctx = ngx_http_get_module_ctx(r, ngx_http_cache_turbo_module);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    if (ngx_http_cache_turbo_body_filter_midbody_rescue(r, clcf, ctx)
        == NGX_ERROR)
    {
        return NGX_ERROR;
    }
#endif

    if (ctx != NULL && ctx->sie_serving) {
        rc = ngx_http_cache_turbo_body_filter_sie_emit(r, ctx, in, &eout);
        if (rc == NGX_DECLINED) {
            return NGX_OK;
        }
        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }
        return ngx_http_next_body_filter(r, &eout);
    }

    if (ctx == NULL || !ctx->captured || ctx->served) {
        return ngx_http_cache_turbo_forward_body(r, in);
    }

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    if (ngx_http_cache_turbo_body_filter_force_file_buf(r, clcf, ctx)
        == NGX_DECLINED)
    {
        return ngx_http_cache_turbo_forward_body(r, in);
    }
#endif

    rc = ngx_http_cache_turbo_body_filter_capture(r, clcf, ctx, in, &last);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }
    if (rc == NGX_DECLINED) {
        return ngx_http_cache_turbo_forward_body(r, in);
    }

    /* Store once the response is complete and within max_size. A zero-length
     * body is allowed (v6): a 301/302/308 redirect or a 204 has no body but is
     * worth caching for its headers. (HEAD is already excluded at capture.) */
    if (last
        && (clcf->max_size == 0 || ctx->body_len <= clcf->max_size))
    {
        (void) ngx_http_cache_turbo_body_filter_store_tail(r, clcf, ctx);
    }

    return ngx_http_cache_turbo_forward_body(r, in);
}


/* Install this module's header and body filters at the top of the output
 * chain, saving the previous top as this file's next-filter pointers. Called
 * once from ngx_http_cache_turbo_filter_init() in module.c, at exactly the
 * point the two inline pairs used to sit, so ordering is unchanged. */
ngx_int_t
ngx_http_cache_turbo_filter_chain_init(void)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_cache_turbo_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_cache_turbo_body_filter;

    return NGX_OK;
}
