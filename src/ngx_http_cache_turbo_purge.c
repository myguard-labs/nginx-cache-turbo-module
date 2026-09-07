/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Purge group (MAINT-SPLIT step G). Split out of ngx_http_cache_turbo_module.c
 * verbatim: the PURGE <uri> precontent body (ngx_http_cache_turbo_purge_request,
 * called from access.c's precontent handler) and the async SMEMBERS completion
 * for a Redis tag purge (ngx_http_cache_turbo_tag_purge_complete, called from
 * both purge_request's COR-5 variant-index path and admin.c's ?tag= handler),
 * plus hexdecode, whose only caller is the completion.
 *
 * Two non-contiguous halves, ~301 lines total: purge_request sat directly
 * above step F's access.c range and was deliberately left in module.c for
 * this step; tag_purge_complete (+ its private hexdecode helper) sits further
 * down, between the config-command handlers and the warm group. No function
 * in between belongs to this group, so nothing was widened to make the range
 * contiguous.
 *
 * Export surface: both entry points were already declared non-static
 * (ngx_http_cache_turbo_purge_request in ngx_http_cache_turbo_internal.h,
 * ngx_http_cache_turbo_tag_purge_complete in ngx_http_cache_turbo_module.h)
 * before this split, since access.c and admin.c already called them across
 * the TU boundary. No declaration changed. hexdecode keeps `static` — its
 * only caller is tag_purge_complete, now in the same file. No function in
 * the moved range carried `ngx_inline`, so no inlining qualifier was dropped.
 *
 * Nothing shared crosses the TU boundary beyond the call itself: both entry
 * points are functions of their arguments over per-request ctx, the zone's
 * own shared-memory state (locked through the existing zone API) or a
 * ngx_http_cache_turbo_tagpurge_t allocated from the request pool — no
 * module-scope mutable state is read or written here (confirmed by the note
 * already in ngx_http_cache_turbo_internal.h above the purge_request
 * declaration, carried over unchanged by this split).
 *
 * The UNIT-EXTRACT breaker-failure block stays wholly in module.c: this
 * split's two ranges sit well clear of its BEGIN/END markers on both sides,
 * so ci/tests/unit/extract_shm.sh keeps slicing module.c unchanged and needs
 * no retarget. No ci/ script asserts a call-site or invariant against either
 * moved function's body.
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


typedef struct {
    u_char  marker[32];
    u_char  variant_index[1 + 64];
    size_t  variant_index_len;
} ngx_http_cache_turbo_purge_vary_keys_t;


/* COR-5 helper: invalidate every auto-Vary variant of the base URI just
 * purged. Variants are stored under variant keys (base material + the
 * folded axis values), not the base key, so the base purge in the caller
 * never touches them. Two strategies by L2 capability:
 *   - Redis (purge_tag): the variants were SADD'd into a per-base index set
 *     at store time. SMEMBERS it and drop every variant from L1 + L2 + the
 *     set (async). Delete the node-local marker so this node stops resolving
 *     to the now-removed variants; the keyspace resets cleanly to gen 0.
 *   - L1-only / memcached (no enumerable index): bump the marker generation
 *     so old-generation variants are orphaned (new requests key on gen+1;
 *     orphans age out via L1 LRU + TTL / memcached value TTL).
 *
 * Returns NGX_DONE if the async purge_tag path parked the request (caller
 * must return NGX_DONE immediately, without touching r->main->count again);
 * returns NGX_OK otherwise, in which case *purged has been updated in
 * place for the caller's synchronous JSON reply. */
static ngx_int_t
ngx_http_cache_turbo_purge_auto_vary(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_purge_vary_keys_t *keys, ngx_uint_t *purged)
{
    ngx_int_t                     bits = 0;
    ngx_uint_t                    mgen = 0;
    ngx_uint_t                    next_gen;
    time_t                        mttl = 0;
    ngx_uint_t                    have_marker = 0;
    ngx_http_cache_turbo_node_t  *m;

    ngx_shmtx_lock(ngx_http_cache_turbo_zone_mutex(z));
    m = clcf->l1->lookup(z, keys->marker,
                         ngx_crc32_short(keys->marker, 32));
    if (m != NULL && m->data != NULL
        && m->len >= NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 1)
    {
        ngx_http_cache_turbo_blob_hdr_t  mh;
        if (ngx_http_cache_turbo_blob_validate(m->data, m->len, &mh,
                NULL, NULL, NULL, NULL, NULL, 0) == NGX_OK)
        {
            have_marker = 1;
            bits = m->data[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE];
            if (m->len >= NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 2) {
                mgen = m->data[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 1];
            }
            mttl = (time_t) mh.fresh_ttl;
        }
    }
    ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));

    if (clcf->backend && clcf->backend->purge_tag) {
        ngx_http_cache_turbo_tagpurge_t  *tp;
        ngx_int_t                         prc;

        (void) clcf->l1->purge_key(z, keys->marker,
                                   ngx_crc32_short(keys->marker, 32));

        /* P3-5 (codex-review MINOR): the marker write-through means an L2
         * copy of THIS base's marker can now exist independently of the L1
         * one just purged above -- drop it too, or a cold node's later
         * marker-miss consult resolves stale pre-purge bits/gen and chases a
         * variant key every one of the SMEMBERS-driven deletes below is
         * about to remove, costing an extra round trip for nothing (never a
         * wrong-variant risk: the variant OBJECT itself is gone from L2 by
         * the time any such consult could complete, so it can only ever
         * miss through to origin, not misresolve). Fire-and-forget, same as
         * every other write-through/delete on this path. */
        if (clcf->backend->del) {
            clcf->backend->del(clcf, keys->marker);
        }

        tp = ngx_pcalloc(r->pool, sizeof(*tp));
        if (tp == NULL) {
            /* could not launch (alloc): fall through to the sync
             * base-only reply below. */
            return NGX_OK;
        }

        tp->clcf = clcf;
        tp->zone = z;
        tp->is_auto_vary = 1;

        /* c-1: snapshot the outstanding-drop gap BEFORE launching SMEMBERS.
         * varidx_drops counts every index write ever dropped before the
         * wire in this zone; varidx_reissues counts every one successfully
         * re-issued. drops > reissues means at least one variant somewhere
         * in the zone currently has an un-healed varidx_pending bit -- i.e.
         * the per-base index set this SMEMBERS is about to read can be
         * short a variant that is still resident in L1 and still serving.
         * This is zone-scoped, not base-scoped (the index set carries no
         * per-member pending flag to check directly), so it is a
         * conservative signal: it can flag a purge "degraded" because some
         * OTHER base has an outstanding drop, never the reverse. A false
         * "degraded" costs nothing (the operator re-purges or waits); a
         * false "complete" is the defect this exists to catch, so the
         * asymmetry is the safe one.
         *
         * COR5-PURGE-VARIDX-RACE: varidx_inflight is the second term, and it
         * covers the case the drops/reissues pair structurally cannot see. A
         * SADD that redis_launch() accepted is NOT a drop -- it never bumps
         * varidx_drops -- yet until L2 acknowledges it the index set this
         * SMEMBERS is about to read may still be short that variant. Without
         * this term a PURGE racing a just-completed store enumerates one
         * variant of two and reports {"purged":1} as an unqualified success
         * while the other keeps serving.
         *
         * Read inflight FIRST so the snapshot errs the safe way: a store that
         * completes midway through these three reads can only inflate the gap
         * (counted here, its decrement not yet reflected in the pair below),
         * never hide it. */
        tp->pending_at_launch =
            (ngx_uint_t) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->varidx_inflight, 0)
            + (ngx_uint_t) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->varidx_drops, 0)
            - (ngx_uint_t) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->varidx_reissues, 0);
        tp->tag.data = ngx_pnalloc(r->pool, keys->variant_index_len);
        if (tp->tag.data == NULL) {
            return NGX_OK;
        }

        ngx_memcpy(tp->tag.data, keys->variant_index,
                   keys->variant_index_len);
        tp->tag.len = keys->variant_index_len;

        /* TODO-REDIS-PAGINATION: build the tag set key once here, reuse it
         * across every page instead of rebuilding on each one. Allocated from
         * r->pool which survives the walk. */
        tp->sscan_key.data = ngx_pnalloc(r->pool,
                                clcf->redis_prefix.len + sizeof("tag:") - 1
                                + tp->tag.len);
        if (tp->sscan_key.data == NULL) {
            return NGX_OK;
        }
        tp->sscan_key.len = clcf->backend->tagkey(&clcf->redis_prefix,
                               tp->tag.data, tp->tag.len, tp->sscan_key.data);

        prc = clcf->backend->purge_tag(r, clcf, keys->variant_index,
                  keys->variant_index_len,
                  ngx_http_cache_turbo_tag_purge_complete, tp);
        if (prc != NGX_DONE) {
            /* could not launch (L2 down): fall through to the sync
             * base-only reply below. */
            return NGX_OK;
        }

        /* parked; the completion drops every variant + the index
         * set and sends {"purged":N}. */

        /* S231-VARY-LEAK: release the park's reference here,
         * because THIS caller is the one that never gets a free
         * drop. purge_request runs in the PRECONTENT phase, and
         * ngx_http_core_generic_phase answers NGX_DONE with a
         * bare `return NGX_OK` -- it never calls
         * ngx_http_finalize_request at all. The completion's
         * single finalize would therefore leave count at 1 with
         * nothing left to drop it, orphaning the client
         * connection with its fd open (visible only at worker
         * shutdown as "open socket left in connection").
         *
         * The module's other two parked purge entry points --
         * admin_handler's ?tag= (purge_tag) and its all-purge
         * (scan_del) -- must NOT do this: they are reached
         * through core->handler, and
         * ngx_http_core_content_phase ALWAYS runs
         * ngx_http_finalize_request(r, rc), where NGX_DONE goes
         * to ngx_http_finalize_connection -> the count != 1
         * branch -> ngx_http_close_request, which decrements.
         * Their parks are already balanced; dropping again
         * there trips "http request count is zero". The
         * asymmetry is the CALLER'S PHASE, not the op kind, so
         * the release belongs at each acquire site rather than
         * in the shared completion. */
        r->main->count--;

        return NGX_DONE;
    }

    if (!have_marker) {
        return NGX_OK;
    }

    /* AUD-GEN1: wrap explicitly, and NEVER land back on 0. gen 0 is
     * the permanent "never purged" identity (default when no marker
     * exists yet); folding it unconditionally (see variant_hash)
     * stops it colliding with the pre-COR-5 untagged keyspace, but
     * that alone does not stop THIS purge sequence from reproducing
     * its OWN gen-0 identity every 256 purges -- 256 & 0xFF == 0,
     * numerically indistinguishable from "never purged" once stored
     * in one byte, so a request racing the wrap would resolve back to
     * whatever is still resident under the base's original,
     * pre-first-purge key (proven by a real 256-purge round trip
     * against the unpatched arithmetic, not just reasoned about).
     * Skipping 0 on wrap makes 0 permanently exclusive to "never
     * purged": once a base has been purged at all, its generation can
     * never again equal the identity a fresh, unpurged base uses.
     * The residual (generation N colliding with N+255, still a
     * 1-byte counter) is the accepted trade-off the ledger row
     * documents; this closes the specific, highest-risk collision --
     * the one with the longest-lived, most-likely-still-resident
     * data. */
    next_gen = (mgen + 1) & 0xFF;
    if (next_gen == 0) {
        next_gen = 1;
    }
    if (ngx_http_cache_turbo_marker_store_key(r, clcf, z, keys->marker, bits,
                                              next_gen, mttl,
                                              ngx_http_cache_turbo_stale_ttl(
                                                  mttl, clcf->stale_mult))
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "cache_turbo: PURGE partially completed for \"%V\": "
                      "the base object was deleted but the auto-vary "
                      "generation marker update failed; old-generation "
                      "variants may remain resolvable",
                      &r->uri);
        return NGX_ERROR;
    }
    (*purged)++;

    return NGX_OK;
}


/* PURGE <uri> (v14): drop this URI's entry from L1 (+ L2) and answer
 * {"purged":N}. Reuses the request's own key (built via the configured
 * cache_turbo_key), so the purged slot matches what a GET would look up. The
 * location must be gated with allow/deny. */
ngx_int_t
ngx_http_cache_turbo_purge_request(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf)
{
    uint32_t                                  hash;
    ngx_int_t                                 drc;
    ngx_uint_t                                purged;
    ngx_str_t                                 body;
    u_char                                   *p;
    ngx_http_cache_turbo_ctx_t               *ctx;
    ngx_http_cache_turbo_purge_vary_keys_t    vary_keys;
    ngx_http_cache_turbo_zone_t              *z;

    drc = ngx_http_discard_request_body(r);
    if (drc != NGX_OK) {
        return drc;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_cache_turbo_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (ngx_http_cache_turbo_build_key(r, clcf, ctx) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Digest-derived purge keys are a transaction precondition. Derive every
     * key the auto-Vary path can need before deleting the base, marker, or L2
     * object; an EVP failure must leave the cache completely untouched. */
    if (clcf->auto_vary) {
        if (ngx_http_cache_turbo_marker_hash(&ctx->cache_key,
                                             vary_keys.marker) != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        vary_keys.variant_index_len = 0;
        if (clcf->backend && clcf->backend->purge_tag
            && ngx_http_cache_turbo_variant_index_name(
                   &ctx->cache_key, vary_keys.variant_index,
                   &vary_keys.variant_index_len) != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    z = clcf->shm_zone->data;
    hash = ngx_crc32_short(ctx->key_hash, 32);

    purged = (ngx_uint_t) clcf->l1->purge_key(z, ctx->key_hash, hash);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cache_turbo: PURGE \"%V\" key=%ui purged=%ui",
                   &r->uri, (ngx_uint_t) hash, purged);

    /* Drop from L2 too, so a purge can't be silently refilled from Redis. */
    if (clcf->backend) {
        clcf->backend->del(clcf, ctx->key_hash);
    }

    /* COR-5: a PURGE of the base URI must also invalidate every auto-Vary
     * variant; see ngx_http_cache_turbo_purge_auto_vary() for the L2
     * strategy split. NGX_DONE means it parked the async completion, which
     * already sent the reply and finalized the request. */
    if (clcf->auto_vary) {
        ngx_int_t  rc;

        rc = ngx_http_cache_turbo_purge_auto_vary(r, clcf, z, &vary_keys,
                                                   &purged);
        if (rc == NGX_DONE) {
            return NGX_DONE;
        }
        if (rc != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    p = ngx_pnalloc(r->pool, sizeof("{\"purged\":4294967295}\n"));
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    body.data = p;
    body.len = ngx_sprintf(p, "{\"purged\":%ui}\n", purged) - p;

    /* PRECONTENT phase (after ACCESS/allow-deny): send the reply, finalize, and
     * return NGX_DONE so the phase engine stops here instead of falling through
     * to the content handler / proxy_pass (same pattern as serve()). */
    drc = ngx_http_cache_turbo_send_json(r, NGX_HTTP_OK, &body);
    ngx_http_finalize_request(r, drc);
    return NGX_DONE;
}


/* Decode len hex chars at src into len/2 bytes at dst. NGX_ERROR on odd length
 * or any non-hex char. */
static ngx_int_t
ngx_http_cache_turbo_hexdecode(u_char *src, size_t len, u_char *dst)
{
    size_t     i;
    ngx_int_t  hi, lo;

    if (len & 1) {
        return NGX_ERROR;
    }
    for (i = 0; i < len; i += 2) {
        hi = ngx_http_cache_turbo_hexval(src[i]);
        lo = ngx_http_cache_turbo_hexval(src[i + 1]);
        if (hi < 0 || lo < 0) {
            return NGX_ERROR;
        }
        dst[i / 2] = (u_char) ((hi << 4) | lo);
    }
    return NGX_OK;
}


/* ngx_http_cache_turbo_tagpurge_t is defined in ngx_http_cache_turbo_module.h
 * (shared with the COR-5 variant-index purge launched from purge_request, and
 * with the admin tag-purge path in admin.c). */


/* Tag-purge walk callback, TWO-PHASE (TODO-REDIS-PAGINATION).
 *
 * The tag set is enumerated by a paginated SSCAN walk, not a single SMEMBERS,
 * so this runs once per page and once at the end:
 *
 *   walk == NULL  one page's members: evict each from L1, and pipeline its
 *                 object key + its `lock:` key into one UNLINK. The running
 *                 count goes into tp->purged. NO response, NO tag-key delete.
 *   terminal      emit the JSON reply. No tag-key delete: every page SREMs
 *                 its own members, so a complete walk empties the set and
 *                 Redis drops the emptied key itself. walk may be NULL here
 *                 when the transport failed before any page landed, which is
 *                 an abandoned walk.
 *
 * Dropping each page as it arrives is the whole point: accumulating members to
 * delete them in one final pass would reintroduce exactly the unbounded buffer
 * that replacing SMEMBERS removed. `members` point into a per-page reply buffer
 * released the moment this returns, so everything is acted on synchronously.
 *
 * Idempotent by construction, as SSCAN requires: purge_key on an absent L1 slot
 * and UNLINK on an absent L2 key are both no-ops, so a member returned on two
 * pages costs one redundant UNLINK argument. It does inflate tp->purged, which
 * is why that field counts members visited rather than distinct members.
 *
 * Non-static: called from admin.c too. */
ngx_int_t
ngx_http_cache_turbo_tag_purge_complete(ngx_http_request_t *r, void *data,
    ngx_str_t *members, ngx_uint_t nmembers,
    const ngx_http_cache_turbo_redis_walk_t *walk)
{
    ngx_http_cache_turbo_tagpurge_t  *tp = data;
    ngx_uint_t                        i, ndel = 0;
    size_t                            plen;
    u_char                           *p;
    ngx_str_t                        *delkeys, body;

    plen = tp->clcf->redis_prefix.len;

    /* ONE discriminator, matching the members_pt contract: no members means the
     * TERMINAL call. Keying the page branch off `walk == NULL` alone would send
     * a terminal call that carries no walk (transport failure before any page
     * landed) into the page branch, which returns NGX_DONE without emitting a
     * body -- walk_finish then finalizes and the client waits forever. That is
     * unreachable today only because walk_finish passes `op->is_scan ? &walk :
     * NULL` and redis_sscan always sets is_scan, which is luck, not a contract.
     * read_sscan never invokes the callback for an empty non-terminal page, so
     * nmembers == 0 is unambiguous here. */
    if (walk == NULL && nmembers > 0) {
        /* ---- page delivery ---- */
        ngx_pool_t  *tmp;

        /* ⚠ PAGE-SCOPED POOL, NOT r->pool. r->pool is not released until the
         * request finalizes, which happens only after the LAST page -- so
         * allocating this page's scratch there would accumulate every page's
         * delkeys array and every member's lockbuf for the whole walk. That is
         * the unbounded buffer this pagination exists to remove, merely moved
         * from the transport into the request pool: a million-member tag would
         * hold tens of megabytes while the transport side truthfully reported
         * O(1) in page count. Pre-pagination it was one allocation for one
         * (whole-set) delivery and did not matter; now it does.
         *
         * Destroying it right after del_many is safe because del_many COPIES
         * the key bytes into its own op pool before returning (encode_into's
         * ngx_cpymem). members[] point into the walk's per-page reply buffer,
         * not into this pool, so they are unaffected either way. */
        tmp = ngx_create_pool(ngx_pagesize, r->connection->log);
        if (tmp == NULL) {
            return NGX_ERROR;
        }

        /* PERF-2: one pipelined UNLINK per PAGE (each member's object key plus
         * its cross-node lock key), rather than two fire-and-forget
         * connections per member. Sized per page, so it is bounded by the
         * SSCAN COUNT hint however large the tag set is -- pre-pagination this
         * array was sized for the entire set. */
        delkeys = ngx_palloc(tmp, (nmembers * 2) * sizeof(ngx_str_t));
        if (delkeys == NULL) {
            ngx_destroy_pool(tmp);
            /* Out of memory mid-walk. Skipping this page silently would let
             * the terminal call see a completed walk and delete the tag key
             * over members that were never dropped -- silently unpurgeable.
             * NGX_ERROR from a page delivery abandons the whole walk
             * (read_sscan), so the purge reports INCOMPLETE and keeps the
             * key. */
            return NGX_ERROR;
        }

        for (i = 0; i < nmembers; i++) {
            if (members[i].len == 0) {
                continue;
            }

            /* The member IS the object's L2 key. */
            delkeys[ndel++] = members[i];

            /* member = <prefix><64 hex of the 32-byte key hash>: drop from L1,
             * and also drop the object's cross-node single-flight lock (v4-2
             * SET NX PX) — otherwise a stale lock outlives the purged object
             * and stalls the next cold-miss winner for lock_timeout (the
             * V-HANG; see redis_del). A member that is not that shape is not
             * one of ours: drop the L2 key, skip the L1/lock work rather than
             * hex-decoding garbage. */
            if (members[i].len == plen + 64) {
                u_char    key_hash[32];
                uint32_t  hash;

                if (ngx_http_cache_turbo_hexdecode(members[i].data + plen, 64,
                                                   key_hash) == NGX_OK)
                {
                    u_char  *lockbuf;

                    hash = ngx_crc32_short(key_hash, 32);
                    (void) tp->clcf->l1->purge_key(tp->zone, key_hash, hash);

                    lockbuf = ngx_pnalloc(tmp,
                                  plen + sizeof("lock:") - 1 + 64);
                    if (lockbuf == NULL) {
                        ngx_destroy_pool(tmp);
                        /* Out of memory mid-walk, same policy as delkeys and
                         * tagkey failures: abandon the walk so the response says
                         * INCOMPLETE rather than claiming a clean purge while a
                         * stale lock survives to cause V-HANG on the next
                         * cold-miss winner. */
                        return NGX_ERROR;
                    }
                    delkeys[ndel].data = lockbuf;
                    delkeys[ndel].len =
                        ngx_http_cache_turbo_redis_lockkey(
                            &tp->clcf->redis_prefix, key_hash, lockbuf);
                    ndel++;
                }
            }
        }

        if (ngx_http_cache_turbo_redis_del_many(tp->clcf, delkeys, ndel)
                != NGX_OK)
        {
            ngx_destroy_pool(tmp);
            /* The page's UNLINK never left the box (no connection, no memory,
             * backoff armed). Do NOT SREM: tag membership is the only pointer
             * to those objects, so removing it while the objects are still in
             * L2 would strand them -- serving until their own TTL, invisible
             * to every later purge of this tag, and behind a reply that said
             * the purge succeeded. Leaving the members in the set keeps them
             * discoverable, which is the safety net the pre-pagination
             * terminal-DEL design had for free. Abandon the walk so the
             * response says INCOMPLETE rather than claiming a clean purge. */
            return NGX_ERROR;
        }

        /* del_many succeeded: count every non-empty member in this page. This
         * counts visited members, not distinct members (SSCAN may revisit a
         * member on a rehash), which matches the purged contract and the README
         * caveat. */
        for (i = 0; i < nmembers; i++) {
            if (members[i].len > 0) {
                tp->purged++;
            }
        }

        /* Drop this page's members from the tag set itself, so an ABANDONED
         * walk leaves behind a set holding only what it never reached. The
         * terminal call keeps the set key on an incomplete walk to make the
         * purge retryable -- but that is worthless if the members already
         * dropped are still in it: a retry would restart at cursor 0, re-walk
         * the same pages, hit the same cap or deadline and make no progress,
         * leaving the tag permanently unpurgeable. This is what makes "re-issue
         * the purge" converge. On a COMPLETE walk it is also what EMPTIES the
         * set -- there is no terminal DEL any more -- so it is unconditional: a
         * page cannot know whether it is the last one.
         *
         * `members` is passed straight through, so EVERY member this page
         * visited is removed, including a zero-length one. The delkeys loop
         * above skips an empty member because it is not a usable L2 key, but it
         * IS a real member of the set and SREM removes it perfectly well.
         * Filtering it out would leave it behind forever: the set would never
         * reach empty, Redis would never retire the set key, and the tag would
         * keep reporting as present after a complete purge. Pinned by
         * test_l2_tag_purge_sscan_malformed_member_is_skipped, whose fixture
         * SADDs "" precisely to hold this honest. */
        /* TODO-REDIS-PAGINATION: reuse tp->sscan_key (built once at launch,
         * not rebuilt on every page). Saves allocation + computation per page
         * and guarantees consistency. */
        {
            ngx_int_t  src;

            src = ngx_http_cache_turbo_redis_srem_many(tp->clcf, &tp->sscan_key,
                                                       members, nmembers);
            if (src != NGX_OK) {
                ngx_destroy_pool(tmp);
                /* The SREM never launched, so this page's members are gone
                 * from both tiers but still listed in the tag set. Reporting
                 * the page handled would let a complete walk answer 200 over a
                 * set that never emptied -- the key survives and the tag reads
                 * as present -- and would let a capped walk re-visit the same
                 * dead members on every retry without converging. Abandon the
                 * walk, exactly as the allocation failures above do. */
                return NGX_ERROR;
            }
        }

        ngx_destroy_pool(tmp);
        return NGX_DONE;
    }

    /* ---- terminal ---- */

    /* A walk that could not enumerate the full set is a failed purge. Do NOT
     * delete the tag key here: retaining it makes the operation safely
     * retryable and keeps every unvisited object discoverable.
     *
     * TODO-REDIS-PAGINATION changed what this body reports. Pre-pagination an
     * abandoned walk had deleted NOTHING (SMEMBERS was all-or-nothing), so
     * "purged":0 was true. The paginated walk drops each page as it goes, so an
     * abandoned walk has really removed tp->purged members and reporting 0
     * would be a lie about the state of the cache — the operator would believe
     * both tiers were untouched while some fraction of the tag is gone. The
     * count is therefore reported honestly alongside "l2":"incomplete", which
     * is what already tells the consumer the purge did not finish. The status
     * (500) and the "l2":"incomplete" field are unchanged, so a consumer that
     * only checks those is unaffected. */
    /* walk == NULL means the transport failed before any page landed, which is
     * an abandoned enumeration and takes the same INCOMPLETE reply as an
     * explicitly-abandoned walk. Dereferencing it here would be a NULL-deref on
     * a dead Redis connection. */
    if (walk == NULL || walk->status != NGX_OK) {
        p = ngx_pnalloc(r->pool,
                sizeof("{\"purged\":4294967295,\"l2\":\"incomplete\"}\n"));
        if (p == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        body.data = p;
        body.len = ngx_sprintf(p, "{\"purged\":%ui,\"l2\":\"incomplete\"}\n",
                               tp->purged) - p;
        return ngx_http_cache_turbo_send_json(
                    r, NGX_HTTP_INTERNAL_SERVER_ERROR, &body);
    }

    /* Complete walk: NOTHING to delete here. Every page SREMs its own members,
     * so a fully-enumerated set has already emptied itself and Redis drops an
     * emptied set key automatically -- the terminal DEL this replaces was
     * redundant on that path.
     *
     * It was also actively harmful on the one path SSCAN newly admits. A member
     * SADDed mid-walk may be missed (the weaker completeness this change
     * accepts), and such a member is still in the set when the walk reaches
     * cursor 0. An unconditional DEL would destroy that membership, orphaning a
     * live L2 object with no tag pointing at it -- undiscoverable by any later
     * purge, i.e. permanently unpurgeable. Letting the set key expire naturally
     * once it is genuinely empty preserves the survivor instead, so reissuing
     * the purge finds it. This is why the delete is gone rather than made
     * conditional: there is no state in which it is the right operation. */

    /* c-1 / SILENT-INDEX-DROP(c): report a DEGRADED enumeration explicitly
     * rather than silently under-counting. tp->pending_at_launch != 0 means
     * this zone had an outstanding index drop when the walk was launched, so
     * the set it just enumerated may not have listed every live entry -- an
     * object can be resident in L1 and still serving while absent from the
     * index. Both callers now populate it (auto-Vary from the unhealed varidx
     * gap, admin ?tag= from tag_index_drops); the snapshot itself encodes which
     * counter is meaningful, so no caller check here.
     *
     * "complete" is additive and defaults to true, so a healthy purge's reply
     * is byte-identical to before and existing consumers are unaffected.
     * Staleness itself is unaffected -- this is a REPORTING field only. For
     * the auto-Vary path the marker delete upstream already covers staleness;
     * for the by-tag path nothing does, which is precisely why the report
     * matters: it is the operator's only signal that the purge they just
     * issued did not reach everything it claimed.
     *
     * TODO-REDIS-PAGINATION: SSCAN's own weaker guarantee -- a member SADDed
     * mid-walk may be missed -- is NOT reported here. It is not observable
     * from inside the walk (nothing distinguishes "never added" from "added
     * after we passed that bucket"), so it is documented for operators in
     * README.md instead of being guessed at in the reply. */
    p = ngx_pnalloc(r->pool,
                    sizeof("{\"purged\":4294967295,\"complete\":false}\n"));
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    body.data = p;
    if (tp->pending_at_launch != 0) {
        body.len = ngx_sprintf(p, "{\"purged\":%ui,\"complete\":false}\n",
                                tp->purged) - p;
    } else {
        body.len = ngx_sprintf(p, "{\"purged\":%ui}\n", tp->purged) - p;
    }

    return ngx_http_cache_turbo_send_json(r, NGX_HTTP_OK, &body);
}

#pragma GCC visibility pop
