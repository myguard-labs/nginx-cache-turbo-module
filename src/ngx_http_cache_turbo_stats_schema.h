/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef NGX_HTTP_CACHE_TURBO_STATS_SCHEMA_H
#define NGX_HTTP_CACHE_TURBO_STATS_SCHEMA_H

/* Private admin schema. Order is JSON order; prom_order preserves the legacy
 * Prometheus order. No shared-memory layout or request-path state changes.
 * The backend fills stats once; counters sampled separately are not a
 * globally atomic snapshot. lock_ttl belongs to the admin location. */
typedef struct {
    ngx_http_cache_turbo_stats_t  stats;
    time_t                        lock_ttl;
} ngx_http_cache_turbo_stats_snapshot_t;

typedef enum {
    CT_STATS_COUNTER, CT_STATS_GAUGE, CT_STATS_STATE, CT_STATS_TIME
} ngx_http_cache_turbo_stats_kind_t;

typedef struct {
    ngx_str_t                          json_name;
    ngx_str_t                          prom_name;
    ngx_str_t                          help;
    ngx_http_cache_turbo_stats_kind_t  kind;
    size_t                             offset;
    ngx_uint_t                         prom_order;
} ngx_http_cache_turbo_stats_descriptor_t;

static const ngx_http_cache_turbo_stats_descriptor_t
ngx_http_cache_turbo_stats_descriptors[] = {
    { ngx_string("hits"),
      ngx_string("cache_turbo_hits_total"),
      ngx_string("Fresh L1 cache hits served."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, hits), 0 },
    { ngx_string("misses"),
      ngx_string("cache_turbo_misses_total"),
      ngx_string("Misses that went to the origin."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, misses), 1 },
    { ngx_string("stale_serves"),
      ngx_string("cache_turbo_stale_serves_total"),
      ngx_string("Stale copies served while a refresh ran."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, stale_serves), 2 },
    { ngx_string("refreshes"),
      ngx_string("cache_turbo_refreshes_total"),
      ngx_string("Background single-flight refreshes started."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, refreshes), 3 },
    { ngx_string("evictions"),
      ngx_string("cache_turbo_evictions_total"),
      ngx_string("Entries evicted under memory pressure (LRU)."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, evictions), 4 },
    { ngx_string("l2_hits"),
      ngx_string("cache_turbo_l2_hits_total"),
      ngx_string("L1 misses satisfied by the L2 tier (Redis or memcached)."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, l2_hits), 5 },
    { ngx_string("l2_misses"),
      ngx_string("cache_turbo_l2_misses_total"),
      ngx_string("L1 misses that L2 could not satisfy (went to origin)."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, l2_misses), 6 },
    { ngx_string("lock_waits"),
      ngx_string("cache_turbo_lock_waits_total"),
      ngx_string("Cold-miss requests that waited for a single-flight fill (v10)."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, lock_waits), 7 },
    { ngx_string("min_uses_skips"),
      ngx_string("cache_turbo_min_uses_skips_total"),
      ngx_string("Cold misses sent to origin without storing because the key is below cache_turbo_min_uses (v15)."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, min_uses_skips), 8 },
    { ngx_string("l2_neg_skips"),
      ngx_string("cache_turbo_l2_neg_skips_total"),
      ngx_string("L2 GETs skipped because a negative memo already recorded a miss for the key (L13)."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, l2_neg_skips), 9 },
    { ngx_string("bypasses"),
      ngx_string("cache_turbo_bypasses_total"),
      ngx_string("Requests skipped straight to origin by a cache_turbo_bypass predicate or a CMS backend preset (subset of misses)."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, bypasses), 10 },
    { ngx_string("refuse_set_cookie"),
      ngx_string("cache_turbo_refuse_set_cookie_total"),
      ngx_string("Store refused because the response carried a Set-Cookie header."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, refuse_set_cookie), 11 },
    { ngx_string("refuse_encoded"),
      ngx_string("cache_turbo_refuse_encoded_total"),
      ngx_string("Store refused because the response was already Content-Encoding'd (origin pre-compression or filter mis-order)."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, refuse_encoded), 12 },
    { ngx_string("refuse_vary_unsafe"),
      ngx_string("cache_turbo_refuse_vary_unsafe_total"),
      ngx_string("Store refused: Vary named an axis outside the whitelist or \"*\"."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, refuse_vary_unsafe), 13 },
    { ngx_string("refuse_authorization"),
      ngx_string("cache_turbo_refuse_authorization_total"),
      ngx_string("Store refused because the request carried Authorization."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, refuse_authorization), 14 },
    { ngx_string("refuse_cache_control"),
      ngx_string("cache_turbo_refuse_cache_control_total"),
      ngx_string("Store refused by a Cache-Control (or CDN-/Surrogate-) no-store/no-cache/private/max-age=0 directive."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, refuse_cache_control), 15 },
    { ngx_string("refuse_require_header"),
      ngx_string("cache_turbo_refuse_require_header_total"),
      ngx_string("Store refused because cache_turbo_require_header was unmet (absent or not affirmative)."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, refuse_require_header), 16 },
    { ngx_string("refuse_partial"),
      ngx_string("cache_turbo_refuse_partial_total"),
      ngx_string("Store refused because the response was 206 Partial Content."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, refuse_partial), 17 },
    { ngx_string("refuse_head"),
      ngx_string("cache_turbo_refuse_head_total"),
      ngx_string("Store refused because the request was HEAD."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, refuse_head), 18 },
    { ngx_string("cost_ms"),
      ngx_string("cache_turbo_regen_cost_ms"),
      ngx_string("Average origin regeneration cost in milliseconds."),
      CT_STATS_GAUGE, offsetof(ngx_http_cache_turbo_stats_t, cost_ms), 19 },
    { ngx_string("autotuned_beta"),
      ngx_string("cache_turbo_autotuned_beta"),
      ngx_string("Live autotuned SWR beta (x1000; 0 = none)."),
      CT_STATS_GAUGE, offsetof(ngx_http_cache_turbo_stats_t, autotuned_beta), 20 },
    { ngx_string("autotuned_load"),
      ngx_string("cache_turbo_autotuned_load"),
      ngx_string("Live load factor widening stale window + lock_ttl under load (x1000; 1000 = none)."),
      CT_STATS_GAUGE, offsetof(ngx_http_cache_turbo_stats_t, autotuned_load), 21 },
    { ngx_string("breaker_state"),
      ngx_string("cache_turbo_breaker_state"),
      ngx_string("Circuit breaker state (0=closed, 1=open, 2=half-open)."),
      CT_STATS_STATE, offsetof(ngx_http_cache_turbo_stats_t, breaker_state), 29 },
    { ngx_string("breaker_opens"),
      ngx_string("cache_turbo_breaker_opens_total"),
      ngx_string("Lifetime count of CLOSED->OPEN circuit breaker trips."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, breaker_opens), 28 },
    { ngx_string("sie_serves"),
      ngx_string("cache_turbo_sie_serves_total"),
      ngx_string("Responses served from a stale-if-error snapshot."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, sie_serves), 22 },
    { ngx_string("breaker_serves"),
      ngx_string("cache_turbo_breaker_serves_total"),
      ngx_string("Responses served from the circuit breaker's armed fallback while OPEN."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, breaker_serves), 23 },
    { ngx_string("origin_failures"),
      ngx_string("cache_turbo_origin_failures_total"),
      ngx_string("Origin responses recorded as a failure by the circuit breaker."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, origin_failures), 24 },
    { ngx_string("varidx_drops"),
      ngx_string("cache_turbo_varidx_drops_total"),
      ngx_string("Auto-Vary variant-index writes dropped before reaching the transport at store time (self-heals on the next hit)."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, varidx_drops), 25 },
    { ngx_string("tag_index_drops"),
      ngx_string("cache_turbo_tag_index_drops_total"),
      ngx_string("Purge-by-tag index writes dropped before reaching the transport at store time (no self-heal; a later"
                 " purge of the tag will not invalidate the affected object until its own TTL)."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, tag_index_drops), 26 },
    { ngx_string("tag_cap_drops"),
      ngx_string("cache_turbo_tag_cap_drops_total"),
      ngx_string("Tags silently dropped from the purge-by-tag index because a response named more than "
                 "NGX_HTTP_CACHE_TURBO_MAX_TAGS distinct tags (no self-heal; a later purge of a dropped tag will not "
                 "invalidate the affected object until its own TTL)."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, tag_cap_drops), 27 },
    { ngx_string("bg_inflight"),
      ngx_string("cache_turbo_bg_inflight"),
      ngx_string("Background-refresh subrequests currently in flight for this zone (cache_turbo_background_update_max cap)."),
      CT_STATS_GAUGE, offsetof(ngx_http_cache_turbo_stats_t, bg_inflight), 30 },
    { ngx_string("sketch_gen"),
      ngx_string("cache_turbo_sketch_gen"),
      ngx_string("W-TinyLFU sketch aging generation (full incremental halving laps completed so far; 0 = never aged or no sketch)."),
      CT_STATS_GAUGE, offsetof(ngx_http_cache_turbo_stats_t, sketch_gen), 31 },
    { ngx_string("sketch_bumps"),
      ngx_string("cache_turbo_sketch_bumps_total"),
      ngx_string("Lifetime W-TinyLFU sketch increments (0 on a live zone means the sketch was never allocated)."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, sketch_bumps), 32 },
    { ngx_string("admission_refused"),
      ngx_string("cache_turbo_admission_refused_total"),
      ngx_string("New entries refused by W-TinyLFU admission control (cache_turbo_zone ... admission=on)."),
      CT_STATS_COUNTER, offsetof(ngx_http_cache_turbo_stats_t, admission_refused), 33 },
    { ngx_string("used_bytes"),
      ngx_string("cache_turbo_used_bytes"),
      ngx_string("Slab bytes currently charged for cached payload and metadata in this zone (excludes fixed per-zone init overhead)."),
      CT_STATS_GAUGE, offsetof(ngx_http_cache_turbo_stats_t, used_bytes), 34 },
    { ngx_string("markers"),
      ngx_string("cache_turbo_markers"),
      ngx_string("Live count of L1 auto-Vary marker nodes resident in this zone (0 gates the vary-marker probe off, C3)."),
      CT_STATS_GAUGE, offsetof(ngx_http_cache_turbo_stats_t, markers), 35 },
    { ngx_string("zone_size_bytes"),
      ngx_string("cache_turbo_zone_size_bytes"),
      ngx_string("Configured shared-memory zone size in bytes."),
      CT_STATS_GAUGE, offsetof(ngx_http_cache_turbo_stats_t, zone_size_bytes), 36 },
    { ngx_string("zone_reserved_bytes"),
      ngx_string("cache_turbo_zone_reserved_bytes"),
      ngx_string("Zone bytes reserved by slab pages and allocator metadata (includes fixed zone overhead and bin slack)."),
      CT_STATS_GAUGE, offsetof(ngx_http_cache_turbo_stats_t, zone_reserved_bytes), 37 },
    { ngx_string("lock_ttl"), ngx_null_string, ngx_null_string,
      CT_STATS_TIME, 0, 0 }
};

#define CT_STATS_COUNT (sizeof(ngx_http_cache_turbo_stats_descriptors) \
                        / sizeof(ngx_http_cache_turbo_stats_descriptors[0]))

/* Shared count/write primitive: a NULL destination measures the exact bytes.
 * Both paths check size_t arithmetic; short buffers fail without an overrun. */
typedef struct {
    u_char  *data;
    size_t   len;
    size_t   capacity;
    ngx_int_t error;
} ngx_http_cache_turbo_stats_writer_t;

static void
ngx_http_cache_turbo_stats_write(ngx_http_cache_turbo_stats_writer_t *w,
    const void *data, size_t len)
{
    if (w->error || len > w->capacity - w->len) {
        w->error = NGX_ERROR;
        return;
    }
    if (w->data != NULL && len != 0) {
        if (data == NULL) {
            w->error = NGX_ERROR;
            return;
        }
        ngx_memcpy(w->data + w->len, data, len);
    }
    w->len += len;
}

#define CT_STATS_LITERAL(w, text) \
    ngx_http_cache_turbo_stats_write(w, text, sizeof(text) - 1)

/* JSON requires all control bytes escaped. Prometheus requires exactly
 * backslash, quote and LF escaping; ordinary configuration label bytes stay
 * byte-identical. No request-controlled labels are introduced. */
static void
ngx_http_cache_turbo_stats_escape(ngx_http_cache_turbo_stats_writer_t *w,
    ngx_str_t text, ngx_flag_t json)
{
    size_t        i, start;
    u_char        c, escaped[6];
    static const u_char hex[] = "0123456789abcdef";

    start = 0;
    for (i = 0; i < text.len; i++) {
        c = text.data[i];
        if (c != '\\' && c != '"' && c != '\n' && !(json && c < 0x20)) {
            continue;
        }
        ngx_http_cache_turbo_stats_write(w, text.data + start, i - start);
        escaped[0] = '\\';
        escaped[1] = c == '\n' ? 'n' : c;
        if (json && c < 0x20 && c != '\n') {
            escaped[1] = 'u';
            escaped[2] = '0';
            escaped[3] = '0';
            escaped[4] = hex[c >> 4];
            escaped[5] = hex[c & 15];
            ngx_http_cache_turbo_stats_write(w, escaped, 6);
        } else {
            ngx_http_cache_turbo_stats_write(w, escaped, 2);
        }
        start = i + 1;
    }
    if (text.len != start) {
        ngx_http_cache_turbo_stats_write(w, text.data + start, text.len - start);
    }
}

/* Decimal conversion uses a full uintmax_t-sized local scratch buffer. Signed
 * time_t minima are converted without negating the minimum signed value. */
static void
ngx_http_cache_turbo_stats_number(ngx_http_cache_turbo_stats_writer_t *w,
    uintmax_t value)
{
    u_char  digits[sizeof(uintmax_t) * 3];
    size_t  n;

    n = sizeof(digits);
    do {
        digits[--n] = (u_char) ('0' + value % 10);
        value /= 10;
    } while (value != 0);
    ngx_http_cache_turbo_stats_write(w, digits + n, sizeof(digits) - n);
}

static ngx_atomic_uint_t
ngx_http_cache_turbo_stats_value(
    const ngx_http_cache_turbo_stats_snapshot_t *snapshot,
    const ngx_http_cache_turbo_stats_descriptor_t *descriptor)
{
    ngx_atomic_uint_t value;

    /* All stats members have this exact type; memcpy avoids aliasing or
     * alignment assumptions in the offset-based descriptor access. */
    ngx_memcpy(&value, (const u_char *) &snapshot->stats + descriptor->offset,
               sizeof(value));
    return value;
}

/* One walk drives bounds and rendering. Bounds use full atomic/time widths,
 * not current values, and exact escaped label lengths. This avoids a second
 * hand-maintained prose skeleton or metric multiplier. */
static ngx_int_t
ngx_http_cache_turbo_stats_render(
    const ngx_http_cache_turbo_stats_snapshot_t *snapshot, ngx_str_t zone,
    ngx_flag_t prometheus, ngx_flag_t measure, u_char *data, size_t capacity,
    size_t *length)
{
    const ngx_http_cache_turbo_stats_descriptor_t *d, *ordered[CT_STATS_COUNT];
    ngx_http_cache_turbo_stats_writer_t           w;
    ngx_atomic_uint_t                            value;
    ngx_str_t                                    state;
    const char                                  *name;
    size_t                                       i, count;
    uintmax_t                                    seconds;

    w.data = data;
    w.len = 0;
    w.capacity = capacity;
    w.error = NGX_OK;
    count = 0;
    for (i = 0; i < CT_STATS_COUNT; i++) {
        ordered[i] = NULL;
        if (!prometheus || ngx_http_cache_turbo_stats_descriptors[i].kind
                           != CT_STATS_TIME)
        {
            count++;
        }
    }
    for (i = 0; i < CT_STATS_COUNT; i++) {
        d = &ngx_http_cache_turbo_stats_descriptors[i];
        if (prometheus && d->kind == CT_STATS_TIME) {
            continue;
        }
        if (prometheus && (d->prom_order >= count || ordered[d->prom_order])) {
            return NGX_ERROR;
        }
        ordered[prometheus ? d->prom_order : i] = d;
    }
    if (!prometheus) {
        CT_STATS_LITERAL(&w, "{");
    }
    for (i = 0; i < count; i++) {
        d = ordered[i];
        if (prometheus) {
            CT_STATS_LITERAL(&w, "# HELP ");
            ngx_http_cache_turbo_stats_write(&w, d->prom_name.data, d->prom_name.len);
            CT_STATS_LITERAL(&w, " ");
            ngx_http_cache_turbo_stats_write(&w, d->help.data, d->help.len);
            CT_STATS_LITERAL(&w, "\n# TYPE ");
            ngx_http_cache_turbo_stats_write(&w, d->prom_name.data, d->prom_name.len);
            if (d->kind == CT_STATS_COUNTER) {
                CT_STATS_LITERAL(&w, " counter\n");
            } else {
                CT_STATS_LITERAL(&w, " gauge\n");
            }
            ngx_http_cache_turbo_stats_write(&w, d->prom_name.data, d->prom_name.len);
            CT_STATS_LITERAL(&w, "{zone=\"");
            ngx_http_cache_turbo_stats_escape(&w, zone, 0);
            CT_STATS_LITERAL(&w, "\"} ");
        } else {
            if (i != 0) {
                CT_STATS_LITERAL(&w, ",");
            }
            CT_STATS_LITERAL(&w, "\"");
            ngx_http_cache_turbo_stats_escape(&w, d->json_name, 1);
            CT_STATS_LITERAL(&w, "\":");
        }
        if (d->kind == CT_STATS_TIME) {
            if (measure) {
                ngx_http_cache_turbo_stats_write(&w, NULL, NGX_TIME_T_LEN);
            } else {
                if (snapshot->lock_ttl < 0) {
                    CT_STATS_LITERAL(&w, "-");
                    seconds = (uintmax_t) -(snapshot->lock_ttl + 1) + 1;
                } else {
                    seconds = (uintmax_t) snapshot->lock_ttl;
                }
                ngx_http_cache_turbo_stats_number(&w, seconds);
            }
        } else if (d->kind == CT_STATS_STATE && !prometheus) {
            CT_STATS_LITERAL(&w, "\"");
            if (measure) {
                ngx_http_cache_turbo_stats_write(&w, NULL, sizeof("half-open") - 1);
            } else {
                value = ngx_http_cache_turbo_stats_value(snapshot, d);
                name = ngx_http_cache_turbo_shm_breaker_state_str((ngx_uint_t) value);
                state.data = (u_char *) name;
                state.len = ngx_strlen(name);
                ngx_http_cache_turbo_stats_escape(&w, state, 1);
            }
            CT_STATS_LITERAL(&w, "\"");
        } else if (measure) {
            ngx_http_cache_turbo_stats_write(&w, NULL, NGX_ATOMIC_T_LEN);
        } else {
            value = ngx_http_cache_turbo_stats_value(snapshot, d);
            if (d->kind == CT_STATS_STATE) {
                value = ngx_http_cache_turbo_brk_state((ngx_uint_t) value);
            }
            ngx_http_cache_turbo_stats_number(&w, value);
        }
        if (prometheus) {
            CT_STATS_LITERAL(&w, "\n");
        }
    }
    if (!prometheus) {
        CT_STATS_LITERAL(&w, "}\n");
    }
    *length = w.len;
    return w.error;
}

#endif /* NGX_HTTP_CACHE_TURBO_STATS_SCHEMA_H */
