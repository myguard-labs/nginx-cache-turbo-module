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


/* SMEMBERS completion: drop every member object from L1 + L2, delete the now-
 * empty tag set, and answer {"purged":N}. Runs while `members` (which point
 * into the redis op buffer) are still valid; everything it keeps is copied or
 * acted on synchronously here. Non-static: called from admin.c too. */
ngx_int_t
ngx_http_cache_turbo_tag_purge_complete(ngx_http_request_t *r, void *data,
    ngx_str_t *members, ngx_uint_t nmembers,
    const ngx_http_cache_turbo_redis_walk_t *walk)
{
    ngx_http_cache_turbo_tagpurge_t  *tp = data;
    ngx_uint_t                        i, purged = 0, ndel = 0;
    size_t                            plen, n;
    u_char                           *tagkey, *p;
    ngx_str_t                        *delkeys, body;

    (void) walk;                 /* SMEMBERS walks no keyspace: always NULL */

    plen = tp->clcf->redis_prefix.len;

    /* PERF-2: collect every L2 key to drop (each member's object key + its
     * cross-node lock key + the tag set itself) and issue ONE pipelined UNLINK
     * connection, instead of two fire-and-forget connections per member plus
     * one for the set. A tag with thousands of members previously opened
     * thousands of sockets at once (worker_connections exhaustion); now it is a
     * single bounded connection. L1 eviction stays inline (no socket). */
    delkeys = ngx_palloc(r->pool, (nmembers * 2 + 1) * sizeof(ngx_str_t));
    if (delkeys == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    for (i = 0; i < nmembers; i++) {
        if (members[i].len == 0) {
            continue;
        }

        /* The member IS the object's L2 key. */
        delkeys[ndel++] = members[i];

        /* member = <prefix><64 hex of the 32-byte key hash>: drop from L1, and
         * also drop the object's cross-node single-flight lock (v4-2 SET NX PX)
         * — otherwise a stale lock outlives the purged object and stalls the
         * next cold-miss winner for lock_timeout (the V-HANG; see redis_del). */
        if (members[i].len == plen + 64) {
            u_char    key_hash[32];
            uint32_t  hash;

            if (ngx_http_cache_turbo_hexdecode(members[i].data + plen, 64,
                                               key_hash) == NGX_OK)
            {
                u_char  *lockbuf;

                hash = ngx_crc32_short(key_hash, 32);
                (void) tp->clcf->l1->purge_key(tp->zone, key_hash, hash);

                lockbuf = ngx_pnalloc(r->pool,
                              plen + sizeof("lock:") - 1 + 64);
                if (lockbuf != NULL) {
                    delkeys[ndel].data = lockbuf;
                    delkeys[ndel].len = ngx_http_cache_turbo_redis_lockkey(
                                  &tp->clcf->redis_prefix, key_hash, lockbuf);
                    ndel++;
                }
            }
        }

        purged++;
    }

    /* Remove the (now-emptied) tag set itself in the same pipeline. */
    tagkey = ngx_pnalloc(r->pool, plen + sizeof("tag:") - 1 + tp->tag.len);
    if (tagkey != NULL) {
        n = tp->clcf->backend->tagkey(&tp->clcf->redis_prefix,
                 tp->tag.data, tp->tag.len, tagkey);
        delkeys[ndel].data = tagkey;
        delkeys[ndel].len = n;
        ndel++;
    }

    ngx_http_cache_turbo_redis_del_many(tp->clcf, delkeys, ndel);

    /* c-1 / SILENT-INDEX-DROP(c): report a DEGRADED enumeration explicitly
     * rather than silently under-counting. tp->pending_at_launch != 0 means
     * this zone had an outstanding index drop when SMEMBERS was issued above,
     * so the set this purge just enumerated may not have listed every live
     * entry -- an object can be resident in L1 and still serving while absent
     * from the index. Both callers now populate it (auto-Vary from the
     * unhealed varidx gap, admin ?tag= from tag_index_drops); the snapshot
     * itself encodes which counter is meaningful, so no caller check here.
     *
     * "complete" is additive and defaults to true, so a healthy purge's reply
     * is byte-identical to before and existing consumers are unaffected.
     * Staleness itself is unaffected -- this is a REPORTING field only. For
     * the auto-Vary path the marker delete upstream already covers staleness;
     * for the by-tag path nothing does, which is precisely why the report
     * matters: it is the operator's only signal that the purge they just
     * issued did not reach everything it claimed. */
    p = ngx_pnalloc(r->pool,
                    sizeof("{\"purged\":4294967295,\"complete\":false}\n"));
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    body.data = p;
    if (tp->pending_at_launch != 0) {
        body.len = ngx_sprintf(p, "{\"purged\":%ui,\"complete\":false}\n",
                                purged) - p;
    } else {
        body.len = ngx_sprintf(p, "{\"purged\":%ui}\n", purged) - p;
    }

    return ngx_http_cache_turbo_send_json(r, NGX_HTTP_OK, &body);
}

#pragma GCC visibility pop
