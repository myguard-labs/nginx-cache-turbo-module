/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * MAINT-C2: the admin request handler (stats/purge/warm HTTP endpoint), split
 * out of ngx_http_cache_turbo_module.c. Behaviour-preserving move + local
 * decomposition into one static helper per admin endpoint; no response body,
 * status code, header or log message changed. See history.md (MAINT-C2).
 */

#include "ngx_http_cache_turbo_module.h"

/* R5-1 (perf-microtier-hitpath): default-hide every symbol this TU defines
 * so a module-internal call becomes a direct call instead of a PLT-indirect
 * one (see ngx_http_cache_turbo_module.h for why this is a per-file pragma
 * rather than a global -fvisibility=hidden CFLAGS addition, and why a
 * header-only pragma does not work). Anything in this file that nginx's
 * dynamic-module loader must resolve by name gets an explicit
 * __attribute__((visibility("default"))) at its definition, overriding this
 * pragma (GCC: an explicit attribute always wins over the pragma). */
#pragma GCC visibility push(hidden)


/* P5-2-p0: bounds on the ?url_file= list-driven warm source. The file itself
 * is read in one pnalloc'd buffer at admin-request time (no startup hook, no
 * on-disk cache format -- explicitly out of scope), so every dimension of
 * that read must be bounded or an operator-supplied path becomes an
 * unbounded allocation / unbounded origin fan-out:
 *   - FILE_MAX_SIZE   caps the read (and thus the allocation) regardless of
 *     the real file size on disk.
 *   - LINE_MAX_LEN    caps how much of one unterminated line is scanned
 *     before it is rejected, so a file with no newline at all cannot make
 *     the parser treat the whole capped buffer as a single giant entry
 *     silently -- it errors instead.
 *   - warm_max (cache_turbo_warm_max, config directive, default 32 below)
 *     caps how many of the parsed entries are actually fired as warm
 *     subrequests, same as the inline ?url= list.
 */
#define NGX_HTTP_CACHE_TURBO_WARM_FILE_MAX_SIZE  (64 * 1024)
#define NGX_HTTP_CACHE_TURBO_WARM_LINE_MAX_LEN   2048
#define NGX_HTTP_CACHE_TURBO_WARM_FILE_ALERT_MS  60000

/* Forward decls: admin_handler dispatches to the ?url=/?url_file= warm
 * endpoints, defined below it (kept next to warm_uri_is_safe, its own
 * helper). */
static ngx_int_t ngx_http_cache_turbo_warm(ngx_http_request_t *r,
    ngx_str_t *urls, ngx_int_t warm_max);
static ngx_int_t ngx_http_cache_turbo_warm_file(ngx_http_request_t *r,
    ngx_str_t *path, ngx_int_t warm_max);

typedef struct {
    ngx_http_request_t  *r;
    ngx_str_t           path;
    ngx_str_t           list;
    ngx_uint_t          warm_max;
    const char         *file_error;
    ngx_err_t           file_errno;
    ssize_t             nread;
    u_char             *nul;
} ngx_http_cache_turbo_warm_file_ctx_t;

static ngx_int_t ngx_http_cache_turbo_warm_file_start(ngx_http_request_t *r,
    ngx_str_t *path, ngx_int_t warm_max);
static ngx_int_t ngx_http_cache_turbo_warm_file_finish(ngx_http_request_t *r,
    ngx_str_t *list, ngx_int_t warm_max);
#if (NGX_THREADS)
static void ngx_http_cache_turbo_warm_file_thread_handler(void *data,
    ngx_log_t *log);
static void ngx_http_cache_turbo_warm_file_thread_event(ngx_event_t *ev);
#endif

/* State carried through an async all-purge (?all=1) from the admin handler to
 * the SCAN-del completion callback. Holds the synchronous L1 count and its
 * finite-snapshot outcome so the reply can combine them with the parked L2
 * result. */
typedef struct {
    ngx_uint_t  purged;          /* L1 entries dropped (reported as purged) */
    ngx_flag_t  l1_incomplete;   /* finite snapshot left concurrent residue */
} ngx_http_cache_turbo_allpurge_t;


/* Emit the combined L1/L2 outcome for ?all=1.  L1 incompleteness and an L2
 * failure are independent: both fields are retained when both tiers were
 * incomplete, so a caller never mistakes a partial purge for success. */
static ngx_int_t
ngx_http_cache_turbo_all_purge_reply(ngx_http_request_t *r,
    ngx_http_cache_turbo_allpurge_t *ap, const char *l2_state,
    const char *reason, const ngx_http_cache_turbo_redis_walk_t *walk)
{
    u_char      *p;
    ngx_str_t    body;
    ngx_uint_t   status;

    status = (ap->l1_incomplete || l2_state != NULL)
             ? NGX_HTTP_INTERNAL_SERVER_ERROR : NGX_HTTP_OK;

    p = ngx_pnalloc(r->pool,
                    sizeof("{\"purged\":4294967295,"
                           "\"l1\":\"incomplete\","
                           "\"l2\":\"unavailable\",\"reason\":\"page-cap\","
                           "\"scan_pages\":4294967295,"
                           "\"scan_pool_blocks\":4294967295}\n"));
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    body.data = p;
    p = ngx_sprintf(p, "{\"purged\":%ui", ap->purged);
    if (ap->l1_incomplete) {
        p = ngx_sprintf(p, ",\"l1\":\"incomplete\"");
    }
    if (l2_state != NULL) {
        if (reason != NULL) {
            p = ngx_sprintf(p, ",\"l2\":\"%s\",\"reason\":\"%s\"",
                            l2_state, reason);
        } else {
            p = ngx_sprintf(p, ",\"l2\":\"%s\"", l2_state);
        }
    }
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    /* Walk diagnostics, CI builds only: scan_pool_blocks is the oracle for the
     * per-page-pool release (constant in scan_pages when the walk is O(1) in
     * page count, linear in it when the whole walk shares one pool). Not a
     * permanent operator-facing field — same convention as the TEST_FAULTS
     * breaker counters. */
    if (walk != NULL) {
        p = ngx_sprintf(p, ",\"scan_pages\":%ui,\"scan_pool_blocks\":%ui",
                        walk->pages, walk->blocks);
    }
#else
    (void) walk;
#endif
    p = ngx_sprintf(p, "}\n");
    body.len = p - body.data;

    return ngx_http_cache_turbo_send_json(r, status, &body);
}


/* SCAN-del completion (?all=1): the L2 keyspace walk has ended. `purged`
 * remains the exact L1 count; L2 deletions are fire-and-forget and not
 * separately counted. members/nmembers are unused (always 0 here).
 *
 * AUD-SCAN1: the walk does NOT always finish. It ends early on a read timeout,
 * a malformed reply, an allocation failure, or the SCAN page cap — and in every
 * one of those cases part of the L2 keyspace still holds entries the caller was
 * told were gone. That is worse than an outright error: an operator who purged
 * before a config rollout believes L2 is empty when it is not. So a walk that
 * did not reach cursor 0 is reported as a FAILURE (500) carrying
 * "l2":"incomplete" plus the reason, never as a 200. AUD-PURGE-HONESTY1
 * refines that: a walk that consumed ZERO pages never ran at all (L2 refused
 * the connection), so it reports "l2":"unavailable" — L2 is intact, not partly
 * purged. `walk == NULL` cannot
 * happen on this path (the SCAN backend always supplies it); it is treated as
 * complete only so the callback stays total. */
static ngx_int_t
ngx_http_cache_turbo_all_purge_complete(ngx_http_request_t *r, void *data,
    ngx_str_t *members, ngx_uint_t nmembers,
    const ngx_http_cache_turbo_redis_walk_t *walk)
{
    ngx_http_cache_turbo_allpurge_t  *ap = data;
    const char                       *reason;
    const char                       *state;

    (void) members;
    (void) nmembers;

    if (walk == NULL || walk->status == NGX_OK) {
        state = NULL;
        reason = NULL;
    } else {
        reason = (walk->status != NGX_ABORT) ? "error"
                 : walk->deadline ? "deadline" : "page-cap";

        /* AUD-PURGE-HONESTY1: separate "the walk ran and stopped early" from
         * "the walk never happened". Zero pages consumed means no SCAN reply
         * was ever parsed -- L2 refused the connection, or died before the
         * first page -- so the whole keyspace is intact rather than partly
         * purged. Both are 500; the field tells the operator which state L2 is
         * actually in, and "incomplete" would overstate what was done. */
        state = (walk->pages == 0) ? "unavailable" : "incomplete";
    }

    return ngx_http_cache_turbo_all_purge_reply(r, ap, state, reason, walk);
}


/* ?all=1 whole-zone purge (POST/PUT/DELETE). Mirrors the admin_handler dispatch
 * exactly: on success sets *purged and returns NGX_OK so the caller emits the
 * common {"purged":N} reply; on a synchronous path that sends its own response
 * sets *responded so admin_handler does not mistake send_json()'s NGX_OK for
 * purge success and emit a second 200. Parked SCAN and send failures propagate
 * their rc directly. */
static ngx_int_t
ngx_http_cache_turbo_admin_purge_all(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_zone_t *z,
    ngx_uint_t *purged, ngx_flag_t *responded)
{
    ngx_int_t   l1_rc;
    ngx_flag_t  l1_incomplete;

    *responded = 0;

    l1_rc = clcf->l1->purge_all(z, purged);
    l1_incomplete = (l1_rc != NGX_OK);

    /* L2-aware all-purge (v4-2): also clear the whole L2 keyspace for
     * this prefix via a parked SCAN MATCH <prefix>* + DEL loop, so an
     * object cleared from L1 cannot be silently refilled from Redis on
     * the next miss. Needs cache_turbo_redis on this admin location.
     * The completion callback emits {"purged":<L1 count>}. */
    if (clcf->backend && clcf->backend->scan_del) {
        ngx_http_cache_turbo_allpurge_t  *ap;
        ngx_int_t                         rc;

        ap = ngx_palloc(r->pool,
                        sizeof(ngx_http_cache_turbo_allpurge_t));
        if (ap == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ap->purged = *purged;
        ap->l1_incomplete = l1_incomplete;

        rc = clcf->backend->scan_del(r, clcf,
                 ngx_http_cache_turbo_all_purge_complete, ap);
        if (rc == NGX_DONE) {
            return NGX_DONE;        /* parked; completion sends reply */
        }

        /* AUD-PURGE-HONESTY1: the walk did not even START — L2 is down,
         * or the connection was never established — so the entire L2
         * keyspace still holds entries the caller asked to be gone.
         * This used to fall through to the synchronous
         * 200 {"purged":<L1 count>} below, which reads as a complete
         * purge. Same dishonesty class as AUD-SCAN1 (a walk that starts
         * and ends early), so it gets the same answer shape: non-2xx
         * plus an explicit L2 state. "unavailable" rather than
         * "incomplete" — nothing was walked at all. L1 really was
         * purged and "purged" still reports that count. */
        *responded = 1;
        return ngx_http_cache_turbo_all_purge_reply(r, ap, "unavailable",
                                                     NULL, NULL);
    }

    if (l1_incomplete) {
        ngx_http_cache_turbo_allpurge_t  ap;

        ap.purged = *purged;
        ap.l1_incomplete = 1;
        *responded = 1;
        return ngx_http_cache_turbo_all_purge_reply(r, &ap, NULL, NULL, NULL);
    }

    return NGX_OK;
}


/* ?key=<string> single-key purge (POST/PUT/DELETE). Always synchronous;
 * returns NGX_OK with *purged set so the caller emits the common
 * {"purged":N} reply, or 500 before touching either tier when key derivation
 * fails. */
static ngx_int_t
ngx_http_cache_turbo_admin_purge_key(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_zone_t *z,
    ngx_str_t *arg, ngx_uint_t *purged)
{
    u_char     key_hash[32];
    uint32_t   hash;

    /* SEC-2: must match build_key's digest so ?key=<rendered key>
     * resolves to the same slot. */
    if (ngx_http_cache_turbo_digest(arg->data, arg->len, key_hash) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    hash = ngx_crc32_short(key_hash, 32);

    *purged = clcf->l1->purge_key(z, key_hash, hash);

    /* L2-aware purge (issue P6): also drop the entry from Redis, so a
     * purge that cleared L1 cannot be silently refilled from L2 on the
     * next miss. Fire-and-forget; needs cache_turbo_redis on this admin
     * location (inherit it from server/http level). Reported "purged"
     * still reflects the L1 removal only. */
    if (clcf->backend) {
        clcf->backend->del(clcf, key_hash);
    }

    return NGX_OK;
}


/* ?tag=<name> purge (POST/PUT/DELETE). Every path sends its own response
 * (validation error, missing backend, parked SMEMBERS, or backend-unavailable
 * gateway error) and returns that rc directly — admin_handler propagates it
 * unchanged and never reaches the common {"purged":N} reply for this arm,
 * matching the original inline behaviour exactly. */
static ngx_int_t
ngx_http_cache_turbo_admin_purge_tag(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_zone_t *z,
    ngx_str_t *arg)
{
    /* Purge by tag. The tag index lives only in L2, so this needs
     * cache_turbo_redis. SMEMBERS parks the request; the completion
     * callback drops each object from L1 + L2, deletes the tag set, and
     * sends {"purged":N}. */
    ngx_http_cache_turbo_tagpurge_t  *tp;
    ngx_int_t                         rc;
    u_char                            ch;
    ngx_uint_t                        ti;
    ngx_str_t                         body;

    if (clcf->backend == NULL || clcf->backend->purge_tag == NULL) {
        ngx_str_set(&body,
            "{\"error\":\"tag purge requires cache_turbo_redis\"}\n");
        return ngx_http_cache_turbo_send_json(r,
                   NGX_HTTP_BAD_REQUEST, &body);
    }

    /* AUD-TAG1: mirror the surrogate-key tokeniser's own rules
     * (ngx_http_cache_turbo_emit_surrogate_key above) so a tag never
     * exceeds NGX_HTTP_CACHE_TURBO_MAX_TAG_LEN or contains one of the
     * tokeniser's separator bytes. Nothing downstream URL-decodes
     * ?tag=, so today this is belt-and-braces around a distant
     * parser (nginx rejects a raw space in the request line) rather
     * than a live bypass -- but the check should live locally, not
     * depend on that. */
    if (arg->len == 0 || arg->len > NGX_HTTP_CACHE_TURBO_MAX_TAG_LEN) {
        ngx_str_set(&body,
            "{\"error\":\"invalid tag: empty or too long "
            "(max 128 bytes)\"}\n");
        return ngx_http_cache_turbo_send_json(r,
                   NGX_HTTP_BAD_REQUEST, &body);
    }

    for (ti = 0; ti < arg->len; ti++) {
        ch = arg->data[ti];
        if (ch == ' ' || ch == '\t' || ch == ',' || ch == '\r'
            || ch == '\n')
        {
            ngx_str_set(&body,
                "{\"error\":\"invalid tag: contains a "
                "space/tab/comma/CR/LF\"}\n");
            return ngx_http_cache_turbo_send_json(r,
                       NGX_HTTP_BAD_REQUEST, &body);
        }
    }

    /* pcalloc, not palloc: pending_at_launch is read by the completion and
     * was never assigned on this path (it only mattered while the read was
     * gated on is_auto_vary, which this path leaves clear -- SILENT-INDEX-
     * DROP(c) removes that gate, so the field is now load-bearing here and
     * an indeterminate value would make the reply report at random). Both
     * fields are still assigned explicitly below; the pcalloc is the belt to
     * that braces for any field added to the struct later. */
    tp = ngx_pcalloc(r->pool, sizeof(ngx_http_cache_turbo_tagpurge_t));
    if (tp == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    tp->clcf = clcf;
    tp->zone = z;
    tp->is_auto_vary = 0;

    /* SILENT-INDEX-DROP(c): snapshot the zone's outstanding tag-index drops
     * BEFORE launching SMEMBERS below, so the reply can report a degraded
     * enumeration instead of silently under-counting. A dropped tag-index
     * write leaves an object resident in L1 and serving but ABSENT from the
     * tag set this purge is about to read, so the purge would otherwise
     * report success while that object keeps serving stale until its TTL.
     *
     * Unlike the auto-Vary path there is no reissues counter to subtract:
     * tags cannot self-heal (the tag set is a response-derived complex
     * value), so the raw drop count IS the outstanding gap. Consequence,
     * intended: once this zone has dropped a tag-index write, every later
     * purge-by-tag in it reports "complete":false until reload. That is
     * honest -- nothing has repaired the index -- and it is the signal an
     * operator needs to know a re-purge or an origin-side purge is required.
     *
     * TAG-CAP-SILENT-DROP: sum in tag_cap_drops too. It is a distinct fault
     * class (a tag that never got selected because the cap truncated the
     * value, versus a selected tag whose SADD never reached L2) but it is
     * the SAME user-visible defect -- an object the enumeration below
     * cannot see stays resident and stale -- so it must gate the same
     * "complete":false reply. Neither counter self-heals, so the sum is
     * exactly as outstanding as either half. */
    tp->pending_at_launch = (ngx_uint_t)
        ngx_atomic_fetch_add(
            &ngx_http_cache_turbo_zone_sh(z)->tag_index_drops, 0)
        + (ngx_uint_t)
          ngx_atomic_fetch_add(
              &ngx_http_cache_turbo_zone_sh(z)->tag_cap_drops, 0);

    tp->tag.len = arg->len;
    tp->tag.data = ngx_pnalloc(r->pool, arg->len);
    if (tp->tag.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(tp->tag.data, arg->data, arg->len);

    rc = clcf->backend->purge_tag(r, clcf,
             tp->tag.data, tp->tag.len,
             ngx_http_cache_turbo_tag_purge_complete, tp);
    if (rc == NGX_DONE) {
        return NGX_DONE;            /* parked; completion sends reply */
    }

    ngx_str_set(&body,
        "{\"error\":\"tag purge backend unavailable\"}\n");
    return ngx_http_cache_turbo_send_json(r, NGX_HTTP_BAD_GATEWAY,
               &body);
}


/* POST/PUT/DELETE dispatch: ?all=1 / ?key=<string> / ?tag=<name> / ?url=<...>,
 * else the "specify ..." error. Sends its own reply on every path (either
 * directly from a per-endpoint helper's rc, the common {"purged":N} wrapper,
 * or the "specify" error), so admin_handler returns this rc unchanged. */
static ngx_int_t
ngx_http_cache_turbo_admin_purge_dispatch(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_zone_t *z)
{
    ngx_str_t   arg;
    ngx_uint_t  purged = 0;
    u_char     *p;
    ngx_str_t   body;

    /* Require all=1 explicitly (COR-10): mere presence of the arg used to
     * purge, so a typo like ?all=0 destroyed the whole zone. Only the exact
     * value "1" triggers the all-purge now. */
    if (r->args.len
        && ngx_http_arg(r, (u_char *) "all", 3, &arg) == NGX_OK
        && arg.len == 1 && arg.data[0] == '1')
    {
        ngx_flag_t  responded;
        ngx_int_t   rc;

        rc = ngx_http_cache_turbo_admin_purge_all(r, clcf, z, &purged,
                                                   &responded);
        if (responded || rc != NGX_OK) {
            return rc;
        }

    } else if (r->args.len
               && ngx_http_arg(r, (u_char *) "key", 3, &arg) == NGX_OK)
    {
        ngx_int_t  rc;

        rc = ngx_http_cache_turbo_admin_purge_key(r, clcf, z, &arg,
                                                   &purged);
        if (rc != NGX_OK) {
            return rc;
        }

    } else if (r->args.len
               && ngx_http_arg(r, (u_char *) "tag", 3, &arg) == NGX_OK)
    {
        return ngx_http_cache_turbo_admin_purge_tag(r, clcf, z, &arg);

    } else if (r->args.len
               && ngx_http_arg(r, (u_char *) "url", 3, &arg) == NGX_OK)
    {
        /* Warm (v3-3): pre-populate the cache for one or more comma-
         * separated site URLs by firing background subrequests that hit the
         * origin and store the result. Best-effort/async — the reply reports
         * how many warm subrequests were fired, not how many actually
         * stored. Sends its own JSON, so return its rc directly. */
        return ngx_http_cache_turbo_warm(r, &arg, clcf->warm_max);

    } else if (r->args.len
               && ngx_http_arg(r, (u_char *) "url_file", 8, &arg) == NGX_OK)
    {
        /* P5-2-p0: same warm path, but the URL list comes from a file on
         * disk (one path per line) instead of the query string -- lets an
         * operator drive cold-start warming from an external list without a
         * query string long enough to hit URL-length limits. Bounded read;
         * see the FILE_MAX_SIZE/LINE_MAX_LEN comment above. */
        return ngx_http_cache_turbo_warm_file(r, &arg, clcf->warm_max);

    } else {
        ngx_str_set(&body,
            "{\"error\":\"specify ?all=1, ?key=<string>, ?tag=<name>, "
            "?url=<path[,path...]> or ?url_file=<path>\"}\n");
        return ngx_http_cache_turbo_send_json(r, NGX_HTTP_BAD_REQUEST,
                   &body);
    }

    p = ngx_pnalloc(r->pool, sizeof("{\"purged\":4294967295}\n"));
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    body.data = p;
    body.len = ngx_sprintf(p, "{\"purged\":%ui}\n", purged) - p;
    return ngx_http_cache_turbo_send_json(r, NGX_HTTP_OK, &body);
}


/* GET/HEAD ?format=prometheus stats rendering. Returns the send_body rc
 * directly (sends its own response). */
static ngx_int_t
ngx_http_cache_turbo_admin_stats_prometheus(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_stats_t *st)
{
    ngx_str_t   zname = clcf->admin_zone->shm.name;
    ngx_str_t   body;
    u_char     *p;
    size_t      len;

    /* Twenty-eight counters (*_total) + seven gauges, each labelled by zone
     * so one Prometheus job can scrape many zones. Exposition format
     * 0.0.4. The per-metric budget must track the emitted count (35):
     * every metric line renders one %V (zone) + one %uA (value), so a
     * short multiplier could truncate the last line under a long zone
     * name. The fixed term covers the HELP/TYPE prose, which grows
     * with every metric added -- bump BOTH when adding one (L13 added
     * the 14th and needed ~180 bytes of prose; a stale 13 truncated
     * the JSON arm's neighbour into invalid output; S7.1 added three
     * more, prose term bumped by ~450 bytes for their HELP/TYPE
     * lines; H7.3a added breaker_opens_total (counter) and
     * breaker_state (gauge), prose term bumped by ~350 bytes -- the
     * breaker_state HELP documents the numeric mapping since the
     * value itself is deliberately NOT a label, see the emit call
     * below; P0-1 added eight refuse_*_total counters, prose term
     * bumped by ~1050 bytes for their HELP/TYPE lines; P3-7 added
     * bg_inflight (gauge), prose term bumped by ~180 bytes; P4-1b added
     * sketch_gen (gauge), sketch_bumps_total (counter) and
     * admission_refused_total (counter), prose term bumped by ~530 bytes
     * for their HELP/TYPE lines and the count 28 -> 31; P4-2-s3a added
     * used_bytes (gauge) and the count 31 -> 32; TAG-CAP-SILENT-DROP added
     * tag_cap_drops_total (counter), prose term re-measured and the count
     * 32 -> 35 -- ci/tools/lint-admin-buffer-budget.py caught the earlier
     * miscount at CI time (the multiplier and term must track %V/%uA
     * occurrences, not the metric-name comment above, which had already
     * drifted before this bump)).
     *
     * ⚠ P4-2-s3a: the fixed term is no longer eyeballed. Every previous bump
     * was an estimate ("~180 bytes", "~530 bytes") and they had drifted
     * BELOW the truth: measured against the format string, the fixed prose
     * was 5897 bytes while the term still said 5660. That 237-byte shortfall
     * never truncated only because NGX_ATOMIC_T_LEN reserves 20 bytes per
     * value and real counters render far shorter, so the per-value slack
     * silently absorbed it -- i.e. the budget was already relying on an
     * accident. The term below is the MEASURED fixed prose (sum of the
     * literal bytes, less 2 per %V and 3 per %uA) plus lint-admin-buffer-
     * budget.py's 128-byte margin. When adding a metric, re-measure rather
     * than adding an estimate -- run the lint locally, it prints the exact
     * required value. C3 added cache_turbo_markers (gauge), count 35 -> 36,
     * fixed term re-measured 7152 -> 7345. PERF-AUD2-08's sketch_gen HELP
     * text change re-measured 7345 -> 7376 (prose 7248 + 128 margin, no
     * metric count change). */
    len = 7376 + 36 * zname.len + 36 * NGX_ATOMIC_T_LEN;
    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    body.data = p;
    body.len = ngx_snprintf(p, len,
        "# HELP cache_turbo_hits_total Fresh L1 cache hits served.\n"
        "# TYPE cache_turbo_hits_total counter\n"
        "cache_turbo_hits_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_misses_total Misses that went to the origin.\n"
        "# TYPE cache_turbo_misses_total counter\n"
        "cache_turbo_misses_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_stale_serves_total Stale copies served while a refresh ran.\n"
        "# TYPE cache_turbo_stale_serves_total counter\n"
        "cache_turbo_stale_serves_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_refreshes_total Background single-flight refreshes started.\n"
        "# TYPE cache_turbo_refreshes_total counter\n"
        "cache_turbo_refreshes_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_evictions_total Entries evicted under memory pressure (LRU).\n"
        "# TYPE cache_turbo_evictions_total counter\n"
        "cache_turbo_evictions_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_l2_hits_total L1 misses satisfied by the L2 tier (Redis or memcached).\n"
        "# TYPE cache_turbo_l2_hits_total counter\n"
        "cache_turbo_l2_hits_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_l2_misses_total L1 misses that L2 could not satisfy (went to origin).\n"
        "# TYPE cache_turbo_l2_misses_total counter\n"
        "cache_turbo_l2_misses_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_lock_waits_total Cold-miss requests that waited for a single-flight fill (v10).\n"
        "# TYPE cache_turbo_lock_waits_total counter\n"
        "cache_turbo_lock_waits_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_min_uses_skips_total Cold misses sent to origin without storing because the key is below cache_turbo_min_uses (v15).\n"
        "# TYPE cache_turbo_min_uses_skips_total counter\n"
        "cache_turbo_min_uses_skips_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_l2_neg_skips_total L2 GETs skipped because a negative memo already recorded a miss for the key (L13).\n"
        "# TYPE cache_turbo_l2_neg_skips_total counter\n"
        "cache_turbo_l2_neg_skips_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_bypasses_total Requests skipped straight to origin by a cache_turbo_bypass predicate or a CMS backend preset (subset of misses).\n"
        "# TYPE cache_turbo_bypasses_total counter\n"
        "cache_turbo_bypasses_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_refuse_set_cookie_total Store refused because the response carried a Set-Cookie header.\n"
        "# TYPE cache_turbo_refuse_set_cookie_total counter\n"
        "cache_turbo_refuse_set_cookie_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_refuse_encoded_total Store refused because the response was already Content-Encoding'd (origin pre-compression or filter mis-order).\n"
        "# TYPE cache_turbo_refuse_encoded_total counter\n"
        "cache_turbo_refuse_encoded_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_refuse_vary_unsafe_total Store refused: Vary named an axis outside the whitelist or \"*\".\n"
        "# TYPE cache_turbo_refuse_vary_unsafe_total counter\n"
        "cache_turbo_refuse_vary_unsafe_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_refuse_authorization_total Store refused because the request carried Authorization.\n"
        "# TYPE cache_turbo_refuse_authorization_total counter\n"
        "cache_turbo_refuse_authorization_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_refuse_cache_control_total Store refused by a Cache-Control (or CDN-/Surrogate-) no-store/no-cache/private/max-age=0 directive.\n"
        "# TYPE cache_turbo_refuse_cache_control_total counter\n"
        "cache_turbo_refuse_cache_control_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_refuse_require_header_total Store refused because cache_turbo_require_header was unmet (absent or not affirmative).\n"
        "# TYPE cache_turbo_refuse_require_header_total counter\n"
        "cache_turbo_refuse_require_header_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_refuse_partial_total Store refused because the response was 206 Partial Content.\n"
        "# TYPE cache_turbo_refuse_partial_total counter\n"
        "cache_turbo_refuse_partial_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_refuse_head_total Store refused because the request was HEAD.\n"
        "# TYPE cache_turbo_refuse_head_total counter\n"
        "cache_turbo_refuse_head_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_regen_cost_ms Average origin regeneration cost in milliseconds.\n"
        "# TYPE cache_turbo_regen_cost_ms gauge\n"
        "cache_turbo_regen_cost_ms{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_autotuned_beta Live autotuned SWR beta (x1000; 0 = none).\n"
        "# TYPE cache_turbo_autotuned_beta gauge\n"
        "cache_turbo_autotuned_beta{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_autotuned_load Live load factor widening stale window + lock_ttl under load (x1000; 1000 = none).\n"
        "# TYPE cache_turbo_autotuned_load gauge\n"
        "cache_turbo_autotuned_load{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_sie_serves_total Responses served from a stale-if-error snapshot.\n"
        "# TYPE cache_turbo_sie_serves_total counter\n"
        "cache_turbo_sie_serves_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_breaker_serves_total Responses served from the circuit breaker's armed fallback while OPEN.\n"
        "# TYPE cache_turbo_breaker_serves_total counter\n"
        "cache_turbo_breaker_serves_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_origin_failures_total Origin responses recorded as a failure by the circuit breaker.\n"
        "# TYPE cache_turbo_origin_failures_total counter\n"
        "cache_turbo_origin_failures_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_varidx_drops_total Auto-Vary variant-index writes dropped before reaching the transport at store time (self-heals on the next hit).\n"
        "# TYPE cache_turbo_varidx_drops_total counter\n"
        "cache_turbo_varidx_drops_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_tag_index_drops_total Purge-by-tag index "
        "writes dropped before reaching the transport at store time "
        "(no self-heal; a later purge of the tag will not invalidate "
        "the affected object until its own TTL).\n"
        "# TYPE cache_turbo_tag_index_drops_total counter\n"
        "cache_turbo_tag_index_drops_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_tag_cap_drops_total Tags silently dropped from "
        "the purge-by-tag index because a response named more than "
        "NGX_HTTP_CACHE_TURBO_MAX_TAGS distinct tags (no self-heal; a later "
        "purge of a dropped tag will not invalidate the affected object "
        "until its own TTL).\n"
        "# TYPE cache_turbo_tag_cap_drops_total counter\n"
        "cache_turbo_tag_cap_drops_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_breaker_opens_total Lifetime count of CLOSED->OPEN circuit breaker trips.\n"
        "# TYPE cache_turbo_breaker_opens_total counter\n"
        "cache_turbo_breaker_opens_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_breaker_state Circuit breaker state (0=closed, 1=open, 2=half-open).\n"
        "# TYPE cache_turbo_breaker_state gauge\n"
        "cache_turbo_breaker_state{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_bg_inflight Background-refresh subrequests currently in flight for this zone (cache_turbo_background_update_max cap).\n"
        "# TYPE cache_turbo_bg_inflight gauge\n"
        "cache_turbo_bg_inflight{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_sketch_gen W-TinyLFU sketch aging generation (full incremental halving laps completed so far; 0 = never aged or no sketch).\n"
        "# TYPE cache_turbo_sketch_gen gauge\n"
        "cache_turbo_sketch_gen{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_sketch_bumps_total Lifetime W-TinyLFU sketch increments (0 on a live zone means the sketch was never allocated).\n"
        "# TYPE cache_turbo_sketch_bumps_total counter\n"
        "cache_turbo_sketch_bumps_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_admission_refused_total New entries refused by W-TinyLFU admission control (cache_turbo_zone ... admission=on).\n"
        "# TYPE cache_turbo_admission_refused_total counter\n"
        "cache_turbo_admission_refused_total{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_used_bytes Slab bytes currently charged for cached payload and metadata in this zone (excludes fixed per-zone init overhead).\n"
        "# TYPE cache_turbo_used_bytes gauge\n"
        "cache_turbo_used_bytes{zone=\"%V\"} %uA\n"
        "# HELP cache_turbo_markers Live count of L1 auto-Vary marker nodes resident in this zone (0 gates the vary-marker probe off, C3).\n"
        "# TYPE cache_turbo_markers gauge\n"
        "cache_turbo_markers{zone=\"%V\"} %uA\n",
        &zname, st->hits, &zname, st->misses, &zname, st->stale_serves,
        &zname, st->refreshes, &zname, st->evictions,
        &zname, st->l2_hits, &zname, st->l2_misses, &zname, st->lock_waits,
        &zname, st->min_uses_skips, &zname, st->l2_neg_skips,
        &zname, st->bypasses,
        &zname, st->refuse_set_cookie, &zname, st->refuse_encoded,
        &zname, st->refuse_vary_unsafe, &zname, st->refuse_authorization,
        &zname, st->refuse_cache_control, &zname, st->refuse_require_header,
        &zname, st->refuse_partial, &zname, st->refuse_head,
        &zname, st->cost_ms, &zname, st->autotuned_beta,
        &zname, st->autotuned_load,
        &zname, st->sie_serves, &zname, st->breaker_serves,
        &zname, st->origin_failures,
        &zname, st->varidx_drops, &zname, st->tag_index_drops,
        &zname, st->tag_cap_drops,
        &zname, st->breaker_opens,
        &zname, (ngx_atomic_uint_t) ngx_http_cache_turbo_brk_state(
            (ngx_uint_t) st->breaker_state),
        &zname, st->bg_inflight,
        &zname, st->sketch_gen, &zname, st->sketch_bumps,
        &zname, st->admission_refused,
        &zname, st->used_bytes,
        &zname, st->markers) - p;

    return ngx_http_cache_turbo_send_body(r, NGX_HTTP_OK, &body,
        "text/plain; version=0.0.4; charset=utf-8",
        sizeof("text/plain; version=0.0.4; charset=utf-8") - 1);
}


/* GET/HEAD default JSON stats reply (the ?format=prometheus branch is handled
 * separately by admin_stats_prometheus before this runs).
 *
 * "lock_ttl" is the one EFFECTIVE-CONFIG field on this object; everything else
 * is a zone counter. It reports clcf->lock_ttl -- the post-merge, post-clamp
 * single-flight lock TTL in seconds, i.e. what the runtime claim path in
 * ngx_http_cache_turbo_access.c actually multiplies by effective_load(). It is
 * read off THIS ADMIN LOCATION's own loc_conf, not the cached location's:
 * lock_ttl is per-location while the counters are per-zone, so an operator
 * reading it back must set cache_turbo_lock_ttl on the admin location whose
 * value they mean to inspect (the fixture's /_cache_lockttl does exactly this).
 *
 * Only the effective value is exposed, not the raw configured one: the clamp in
 * ngx_http_cache_turbo_lock_ttl_conf() overwrites its local before storing into
 * lock_ttl_raw, so an out-of-range configured value is not retained anywhere
 * and there is no pre-clamp number left to report. Adding a field purely to
 * carry it would be a test-only knob on a shipped surface, which this module
 * deliberately does not do (C3 removed exactly that shape). The clamp is
 * observable as "an oversized value reads back as 4294967295", which is the
 * operator-facing question ("why does my 999999999s behave as a ceiling?")
 * answered by the value itself. */
static ngx_int_t
ngx_http_cache_turbo_admin_stats_json(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_stats_t *st)
{
    ngx_str_t   body;
    u_char     *p;
    size_t      len;

    len = sizeof("{\"hits\":,\"misses\":,\"stale_serves\":,\"refreshes\":,"
                 "\"evictions\":,\"l2_hits\":,\"l2_misses\":,\"lock_waits\":,"
                 "\"min_uses_skips\":,\"l2_neg_skips\":,\"bypasses\":,"
                 "\"refuse_set_cookie\":,\"refuse_encoded\":,"
                 "\"refuse_vary_unsafe\":,\"refuse_authorization\":,"
                 "\"refuse_cache_control\":,\"refuse_require_header\":,"
                 "\"refuse_partial\":,\"refuse_head\":,"
                 "\"cost_ms\":,"
                 "\"autotuned_beta\":,\"autotuned_load\":,"
                 "\"breaker_state\":\"\",\"breaker_opens\":,"
                 "\"sie_serves\":,\"breaker_serves\":,"
                 "\"origin_failures\":,\"varidx_drops\":,"
                 "\"tag_index_drops\":,\"tag_cap_drops\":,\"bg_inflight\":,"
                 "\"sketch_gen\":,\"sketch_bumps\":,"
                 "\"admission_refused\":,\"used_bytes\":,\"markers\":,"
                 "\"lock_ttl\":}\n")
          + 35 * NGX_ATOMIC_T_LEN
          + sizeof("half-open") - 1    /* longest _breaker_state_str value */
          /* lock_ttl renders as %T, a signed time_t, NOT an ngx_atomic_uint_t,
           * so it is budgeted on its own rather than by bumping the 35 above:
           * NGX_TIME_T_LEN is the width ngx_sprintf can emit for that type,
           * sign included. It is capped at NGX_HTTP_CACHE_TURBO_TTL_MAX
           * (4294967295, 10 digits) in practice, but budget the type's full
           * width -- sizing to the value's practical range is exactly the
           * estimate ci/tools/lint-admin-buffer-budget.py exists to forbid. */
          + NGX_TIME_T_LEN;
    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    body.data = p;
    body.len = ngx_sprintf(p,
        "{\"hits\":%uA,\"misses\":%uA,\"stale_serves\":%uA,"
        "\"refreshes\":%uA,\"evictions\":%uA,\"l2_hits\":%uA,"
        "\"l2_misses\":%uA,\"lock_waits\":%uA,\"min_uses_skips\":%uA,"
        "\"l2_neg_skips\":%uA,"
        "\"bypasses\":%uA,"
        "\"refuse_set_cookie\":%uA,\"refuse_encoded\":%uA,"
        "\"refuse_vary_unsafe\":%uA,\"refuse_authorization\":%uA,"
        "\"refuse_cache_control\":%uA,\"refuse_require_header\":%uA,"
        "\"refuse_partial\":%uA,\"refuse_head\":%uA,"
        "\"cost_ms\":%uA,\"autotuned_beta\":%uA,"
        "\"autotuned_load\":%uA,"
        "\"breaker_state\":\"%s\",\"breaker_opens\":%uA,"
        "\"sie_serves\":%uA,\"breaker_serves\":%uA,"
        "\"origin_failures\":%uA,\"varidx_drops\":%uA,"
        "\"tag_index_drops\":%uA,\"tag_cap_drops\":%uA,\"bg_inflight\":%uA,"
        "\"sketch_gen\":%uA,\"sketch_bumps\":%uA,"
        "\"admission_refused\":%uA,\"used_bytes\":%uA,\"markers\":%uA,"
        "\"lock_ttl\":%T}\n",
        st->hits, st->misses, st->stale_serves,
        st->refreshes, st->evictions, st->l2_hits, st->l2_misses,
        st->lock_waits, st->min_uses_skips, st->l2_neg_skips,
        st->bypasses,
        st->refuse_set_cookie, st->refuse_encoded, st->refuse_vary_unsafe,
        st->refuse_authorization, st->refuse_cache_control,
        st->refuse_require_header, st->refuse_partial, st->refuse_head,
        st->cost_ms,
        st->autotuned_beta, st->autotuned_load,
        ngx_http_cache_turbo_shm_breaker_state_str(
            (ngx_uint_t) st->breaker_state),
        st->breaker_opens,
        st->sie_serves, st->breaker_serves, st->origin_failures,
        st->varidx_drops, st->tag_index_drops, st->tag_cap_drops,
        st->bg_inflight,
        st->sketch_gen, st->sketch_bumps, st->admission_refused,
        st->used_bytes, st->markers,
        clcf->lock_ttl) - p;

    return ngx_http_cache_turbo_send_json(r, NGX_HTTP_OK, &body);
}


/* Stats dispatch. The only force path is an unsafe-method action=value command
 * from admin_handler; GET/HEAD stay read-only even if they carry the legacy
 * ?autotune=1 query. `?format=prometheus` renders the Prometheus text
 * exposition format (for a scrape) instead of JSON. Snapshot the counters
 * through the L1 backend rather than reading the live shctx here. */
static ngx_int_t
ngx_http_cache_turbo_admin_stats_dispatch(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_zone_t *z,
    ngx_uint_t force_autotune)
{
    ngx_http_cache_turbo_stats_t  st;
    ngx_str_t                     arg;

    if (force_autotune) {
        ngx_http_cache_turbo_autotune_force(z);
    }

    clcf->l1->stats(z, &st);

    if (r->args.len
        && ngx_http_arg(r, (u_char *) "format", 6, &arg) == NGX_OK
        && arg.len == sizeof("prometheus") - 1
        && ngx_strncmp(arg.data, "prometheus", arg.len) == 0)
    {
        return ngx_http_cache_turbo_admin_stats_prometheus(r, clcf, &st);
    }

    return ngx_http_cache_turbo_admin_stats_json(r, clcf, &st);
}


/* GET  -> JSON stats for the zone.
 * POST -> purge: ?all=1 purges the whole zone; ?key=<string> purges one key
 *         (hashed the same way the cache hashes its key); ?tag=<name> purges
 *         every object tagged <name> across L1 + L2 (needs cache_turbo_redis).
 * Gating is the caller's responsibility (allow/deny in the location).
 * Non-static: assigned as core->handler from module.c's admin() directive. */
ngx_int_t
ngx_http_cache_turbo_admin_handler(ngx_http_request_t *r)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf;
    ngx_http_cache_turbo_zone_t      *z;
    ngx_int_t                         drc;
    ngx_str_t                         arg;
    ngx_table_elt_t                  *h;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_cache_turbo_module);
    if (!clcf->admin || clcf->admin_zone == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }

    /* Content handler must consume any request body (a purge/warm POST may carry
     * one) or the bytes desync a keepalive connection. */
    drc = ngx_http_discard_request_body(r);
    if (drc != NGX_OK) {
        return drc;
    }

    z = clcf->admin_zone->data;

    if (r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)) {
        return ngx_http_cache_turbo_admin_stats_dispatch(r, clcf, z, 0);
    }

    if ((r->method & NGX_HTTP_POST)
        && r->args.len
        && ngx_http_arg(r, (u_char *) "action", 6, &arg) == NGX_OK
        && arg.len == sizeof("autotune") - 1
        && ngx_strncmp(arg.data, "autotune", arg.len) == 0
        && ngx_http_arg(r, (u_char *) "value", 5, &arg) == NGX_OK
        && arg.len == 1 && arg.data[0] == '1')
    {
        return ngx_http_cache_turbo_admin_stats_dispatch(r, clcf, z, 1);
    }

    if (r->method & (NGX_HTTP_POST|NGX_HTTP_PUT|NGX_HTTP_DELETE)) {
        return ngx_http_cache_turbo_admin_purge_dispatch(r, clcf, z);
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
#if (nginx_version >= 1023000)
    h->next = NULL;
#endif
    ngx_str_set(&h->key, "Allow");
    ngx_str_set(&h->value, "GET, HEAD, POST, PUT, DELETE");

    return NGX_HTTP_NOT_ALLOWED;
}
static ngx_uint_t
ngx_http_cache_turbo_warm_uri_is_safe(ngx_str_t *uri)
{
    u_char  *p, *last, *seg;

    last = uri->data + uri->len;

    for (p = uri->data; p < last; p++) {
        if (*p == '\0') {
            return 0;
        }
    }

    /* uri->data[0] == '/' is guaranteed by the caller, so every segment
     * starts right after a '/'. Walk segments delimited by '/' and reject
     * one that is exactly "..". */
    seg = uri->data + 1;
    for (p = seg; p < last; p++) {
        if (*p == '/') {
            if (p - seg == 2 && seg[0] == '.' && seg[1] == '.') {
                return 0;
            }
            seg = p + 1;
        }
    }

    if (last - seg == 2 && seg[0] == '.' && seg[1] == '.') {
        return 0;
    }

    return 1;
}


/* The RAW (still-escaped) span is what warm_one() puts on the wire verbatim as
 * sr->unparsed_uri, so it needs its own gate: warm_uri_is_safe() above runs on
 * the DECODED path and therefore says nothing about the bytes actually sent.
 * Any control byte here would be spliced straight into the upstream request
 * line -- reject the whole entry rather than sanitising it, because a warm
 * list entry that needs sanitising is an operator error worth surfacing. */
static ngx_uint_t
ngx_http_cache_turbo_warm_raw_is_safe(ngx_str_t *raw)
{
    u_char  *p, *last;

    for (p = raw->data, last = p + raw->len; p < last; p++) {
        if (*p < 0x21 || *p == 0x7f) {
            return 0;
        }
    }

    return 1;
}


/*
 * POST /_cache?url=<path[,path,...]> — warm each comma- (or newline-, so the
 * same parser also drives ?url_file=) separated path. Each path is percent-
 * decoded (so an encoded URL still resolves) and an optional "?query" suffix
 * is passed through as the subrequest args. Only absolute paths ('/'...) are
 * accepted; anything else is skipped. Fires at most warm_max subrequests
 * (cache_turbo_warm_max, config directive, default 32) regardless of how
 * many entries the list contains -- P5-2-p0: this is the bound on the
 * operator-supplied origin fan-out one admin call can trigger, so it is
 * enforced here whether the list came from the query string or a file.
 * Replies {"warmed":N} with N = number of warm subrequests actually fired.
 * The bg subrequests outlive this reply: each bumped r->main->count, so the
 * connection survives admin finalize until they complete.
 */
static ngx_int_t
ngx_http_cache_turbo_warm(ngx_http_request_t *r, ngx_str_t *urls,
    ngx_int_t warm_max)
{
    u_char     *p, *last, *sep, *raw_end, *q, *dst, *s;
    ngx_uint_t  warmed = 0;

    ngx_str_t   uri, args, body;
    u_char     *out;

    p = urls->data;
    last = p + urls->len;

    while (p < last && warmed < (ngx_uint_t) warm_max) {
        sep = ngx_strlchr(p, last, ',');
        q = ngx_strlchr(p, last, '\n');
        if (q != NULL && (sep == NULL || q < sep)) {
            sep = q;
        }
        if (sep == NULL) {
            sep = last;
        }

        if (sep > p) {
            uri.data = p;
            uri.len = sep - p;

            /* Tolerate a CRLF line ending from a file-driven list (Windows-
             * edited operator lists are common) by trimming a trailing '\r'
             * before it can be mistaken for part of the path. */
            raw_end = sep;

            if (uri.len > 0 && uri.data[uri.len - 1] == '\r') {
                uri.len--;
                /* Trim the raw end too. `sep` itself must NOT move: it is the
                 * loop's advance cursor (`p = sep + 1` below), so backing it
                 * up would restart the next entry on the '\r'. The raw span is
                 * measured from raw_end instead, because it lands on the wire
                 * verbatim as sr->unparsed_uri and a bare CR there would go
                 * into the upstream request line. */
                raw_end--;
            }

            ngx_str_null(&args);

            /* split off a "?query" suffix; keep it as the subrequest args */
            q = ngx_strlchr(uri.data, uri.data + uri.len, '?');
            if (q != NULL) {
                args.data = q + 1;
                args.len = uri.data + uri.len - (q + 1);
                uri.len = q - uri.data;
            }

            /* Snapshot the RAW (still percent-escaped) "uri?args" span exactly
             * as it appeared in the operator's warm list, BEFORE decoding --
             * this is what warm_one() needs as unparsed_uri_src (see
             * UB-PROXYNULLURI in module.c): sr->unparsed_uri is copied
             * verbatim onto the wire, so it must stay escaped, unlike `uri`
             * below which the subrequest wants decoded. `sep` is the original
             * end of this list entry (before the '\r' trim), so
             * [uri.data, sep) covers uri+'?'+args contiguously in the source
             * buffer whether or not a '?' was present. */
            {
                ngx_str_t  raw;

                raw.data = uri.data;
                raw.len = (size_t) (raw_end - uri.data);

                /* percent-decode the path into a fresh buffer (subrequest expects
                 * an unescaped uri); decoding never grows the string. */
                if (uri.len > 0 && uri.data[0] == '/') {
                    dst = ngx_pnalloc(r->pool, uri.len);
                    if (dst == NULL) {
                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                    }
                    s = uri.data;
                    {
                        u_char  *d = dst;
                        ngx_unescape_uri(&d, &s, uri.len, 0);
                        uri.data = dst;
                        uri.len = d - dst;
                    }

                    if (uri.len > 0 && uri.data[0] == '/'
                        && ngx_http_cache_turbo_warm_uri_is_safe(&uri)
                        && ngx_http_cache_turbo_warm_raw_is_safe(&raw)
                        && ngx_http_cache_turbo_warm_one(r, &uri, &args, NULL, 0,
                                                         NULL, &raw)
                           == NGX_OK)
                    {
                        warmed++;
                    }
                }
            }
        }

        /* `sep == last` means this was the final unterminated entry. Do not
         * form `last + 1`: the scan is complete and that pointer is outside
         * the buffer's one-past boundary. */
        if (sep == last) {
            break;
        }
        p = sep + 1;
    }

    out = ngx_pnalloc(r->pool, sizeof("{\"warmed\":4294967295}\n"));
    if (out == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    body.data = out;
    body.len = ngx_sprintf(out, "{\"warmed\":%ui}\n", warmed) - out;
    return ngx_http_cache_turbo_send_json(r, NGX_HTTP_OK, &body);
}


static ngx_int_t
ngx_http_cache_turbo_warm_file_finish(ngx_http_request_t *r, ngx_str_t *list,
    ngx_int_t warm_max)
{
    ngx_str_t   body;
    u_char     *p, *last, *line_start;

    /* Reject any single line (delimited by '\n', or the buffer end for the
     * last/only line) longer than WARM_LINE_MAX_LEN before it ever reaches
     * the warm parser -- a file with no newline at all must not be treated
     * as one giant entry silently; it errors instead of being scanned. */
    p = list->data;
    last = list->data + list->len;
    line_start = p;
    while (p < last) {
        if (*p == '\n') {
            if ((ngx_uint_t) (p - line_start)
                > NGX_HTTP_CACHE_TURBO_WARM_LINE_MAX_LEN)
            {
                ngx_str_set(&body,
                    "{\"error\":\"warm url_file: a line exceeds the "
                    "length limit\"}\n");
                return ngx_http_cache_turbo_send_json(r,
                           NGX_HTTP_INTERNAL_SERVER_ERROR, &body);
            }
            line_start = p + 1;
        }
        p++;
    }

    if ((ngx_uint_t) (last - line_start)
        > NGX_HTTP_CACHE_TURBO_WARM_LINE_MAX_LEN)
    {
        ngx_str_set(&body,
            "{\"error\":\"warm url_file: a line exceeds the "
            "length limit\"}\n");
        return ngx_http_cache_turbo_send_json(r,
                   NGX_HTTP_INTERNAL_SERVER_ERROR, &body);
    }

    return ngx_http_cache_turbo_warm(r, list, warm_max);
}


static ngx_int_t
ngx_http_cache_turbo_warm_file_prereq_error(ngx_http_request_t *r)
{
    ngx_str_t  body;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        "cache_turbo: warm url_file requires nginx built with --with-threads "
        "and an available/default thread pool");
    ngx_str_set(&body,
        "{\"error\":\"warm url_file: nginx must be built with --with-threads "
        "and have an available/default thread pool\"}\n");
    return ngx_http_cache_turbo_send_json(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
               &body);
}


static ngx_int_t
ngx_http_cache_turbo_warm_file_read_error(ngx_http_request_t *r)
{
    ngx_str_t  body;

    ngx_str_set(&body,
        "{\"error\":\"warm url_file: unreadable, not a regular file, "
        "or over the size limit\"}\n");
    return ngx_http_cache_turbo_send_json(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
               &body);
}


static ngx_int_t
ngx_http_cache_turbo_warm_file_schedule_error(ngx_http_request_t *r)
{
    ngx_str_t  body;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        "cache_turbo: warm url_file thread-pool task could not be scheduled");
    ngx_str_set(&body,
        "{\"error\":\"warm url_file: thread-pool task could not be "
        "scheduled\"}\n");
    return ngx_http_cache_turbo_send_json(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
               &body);
}


static ngx_int_t
ngx_http_cache_turbo_warm_file_start(ngx_http_request_t *r, ngx_str_t *path,
    ngx_int_t warm_max)
{
    u_char           *nul;
    ngx_http_cache_turbo_warm_file_ctx_t  *ctx;
#if (NGX_THREADS)
    u_char                    *buf;
    ngx_str_t                  name;
    ngx_thread_pool_t         *tp;
    ngx_thread_task_t         *task;
    ngx_http_core_loc_conf_t  *clcf;
#endif

    nul = ngx_pnalloc(r->pool, path->len + 1);
    if (nul == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(nul, path->data, path->len);
    nul[path->len] = '\0';

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_cache_turbo_warm_file_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->r = r;
    ctx->warm_max = warm_max;
    ctx->nul = nul;
    ctx->path = *path;
#if (NGX_THREADS)
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    tp = clcf->thread_pool;

    if (tp == NULL) {
        if (clcf->thread_pool_value == NULL) {
            return ngx_http_cache_turbo_warm_file_prereq_error(r);
        }

        if (ngx_http_complex_value(r, clcf->thread_pool_value, &name)
            != NGX_OK)
        {
            return ngx_http_cache_turbo_warm_file_schedule_error(r);
        }

        tp = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, &name);
        if (tp == NULL) {
            return ngx_http_cache_turbo_warm_file_prereq_error(r);
        }
    }

    buf = ngx_pnalloc(r->pool, NGX_HTTP_CACHE_TURBO_WARM_FILE_MAX_SIZE);
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ctx->list.data = buf;

    task = ngx_thread_task_alloc(r->pool, 0);
    if (task == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    task->ctx = ctx;
    task->handler = ngx_http_cache_turbo_warm_file_thread_handler;
    task->event.data = ctx;
    task->event.handler = ngx_http_cache_turbo_warm_file_thread_event;
    task->event.log = r->connection->log;

    r->main->blocked++;
    r->aio = 1;
    if (ngx_thread_task_post(tp, task) != NGX_OK) {
        r->main->blocked--;
        r->aio = 0;
        return ngx_http_cache_turbo_warm_file_schedule_error(r);
    }

    /* Watchdog only: nginx thread-pool tasks cannot be cancelled safely once
     * posted.  The timer reports a slow task but deliberately leaves blocked,
     * aio and the request reference intact until the sole completion event
     * observes the worker's result and finalizes the request. */
    ngx_add_timer(&task->event, NGX_HTTP_CACHE_TURBO_WARM_FILE_ALERT_MS);
    r->main->count++;
    return NGX_DONE;
#else
    return ngx_http_cache_turbo_warm_file_prereq_error(r);
#endif
}


static ngx_int_t
ngx_http_cache_turbo_warm_file(ngx_http_request_t *r, ngx_str_t *path,
    ngx_int_t warm_max)
{
    return ngx_http_cache_turbo_warm_file_start(r, path, warm_max);
}


#if (NGX_THREADS)

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
static void
ngx_http_cache_turbo_warm_file_test_delay(
    ngx_http_cache_turbo_warm_file_ctx_t *ctx, const char *stage)
{
    u_char  marker[32];

    ngx_snprintf(marker, sizeof(marker), ".delay-%s%Z", stage);
    if (ngx_strstr(ctx->nul, marker) != NULL) {
        ngx_msleep(5000);
    }
}
#else
#define ngx_http_cache_turbo_warm_file_test_delay(ctx, stage)
#endif

static void
ngx_http_cache_turbo_warm_file_thread_handler(void *data, ngx_log_t *log)
{
    ngx_fd_t                                fd;
    ngx_file_info_t                        fi;
    ngx_http_cache_turbo_warm_file_ctx_t  *ctx;

    ctx = data;
    ngx_http_cache_turbo_warm_file_test_delay(ctx, "open");
    fd = ngx_open_file(ctx->nul, NGX_FILE_RDONLY | NGX_FILE_NONBLOCK,
                       NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ctx->file_errno = ngx_errno;
        ctx->file_error = "open";
        return;
    }

    ngx_http_cache_turbo_warm_file_test_delay(ctx, "fstat");
    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ctx->file_errno = ngx_errno;
        ctx->file_error = "fstat";
        ngx_close_file(fd);
        return;
    }

    if (!ngx_is_file(&fi)) {
        ctx->file_error = "not a regular file";
        ngx_close_file(fd);
        return;
    }

    if (ngx_file_size(&fi) < 0
        || ngx_file_size(&fi) > NGX_HTTP_CACHE_TURBO_WARM_FILE_MAX_SIZE)
    {
        ctx->file_error = "over the size limit";
        ngx_close_file(fd);
        return;
    }

    ctx->list.len = (size_t) ngx_file_size(&fi);
    ngx_http_cache_turbo_warm_file_test_delay(ctx, "read");
    ctx->nread = ngx_read_fd(fd, ctx->list.data, ctx->list.len);
    if (ctx->nread == NGX_ERROR) {
        ctx->file_errno = ngx_errno;
        ctx->file_error = "read";
    } else if ((size_t) ctx->nread != ctx->list.len) {
        ctx->file_error = "short read";
    }
    ngx_close_file(fd);
    (void) log;
}


static void
ngx_http_cache_turbo_warm_file_thread_event(ngx_event_t *ev)
{
    ngx_int_t                                rc;
    ngx_connection_t                       *c;
    ngx_http_request_t                     *r;
    ngx_http_cache_turbo_warm_file_ctx_t   *ctx;

    ctx = ev->data;
    r = ctx->r;
    c = r->connection;

    ngx_http_set_log_request(c->log, r);

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
            "cache_turbo: warm url_file thread operation still running after "
            "%Mms", NGX_HTTP_CACHE_TURBO_WARM_FILE_ALERT_MS);
        /* Alert-only watchdog: do not decrement blocked/count, clear aio or
         * finalize here.  The worker still owns ctx and may still own its fd;
         * its eventual completion event is the only safe release point. */
        ev->timedout = 0;
        return;
    }

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    r->main->blocked--;
    r->aio = 0;

    if (r->main->terminated) {
        c->write->handler(c->write);
        return;
    }

    if (ctx->file_error) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ctx->file_errno,
            "cache_turbo: warm url_file \"%s\" failed at %s",
            ctx->nul, ctx->file_error);
        rc = ngx_http_cache_turbo_warm_file_read_error(r);
    } else {
        rc = ngx_http_cache_turbo_warm_file_finish(r, &ctx->list,
                 ctx->warm_max);
    }

    ngx_http_finalize_request(r, rc);
    ngx_http_run_posted_requests(c);
}

#endif

#pragma GCC visibility pop
