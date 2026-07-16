/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Live autotune within preset bands (v4-3). Ported from the wp-redis PHP
 * implementation (eilandert/wp-redis/includes/class-swr-autotune.php): the same
 * gates and constants derive a beta from live cache stats so the edge cache
 * tunes itself the way the object cache does. The PHP runs per cache-group on a
 * 6h cron over 24h telemetry; the edge cache has no group concept, so this
 * works per shm zone, recomputes on a throttled interval, and windows the stats
 * with a delta-snapshot (so it adapts down as well as up). See history.md v4-3.
 *
 * The request path (access handler) consumes z->sh->autotuned_beta, re-clamped
 * to the location's preset band — this file only ever produces the global-clamped
 * cost-derived target. All math is integer fixed-point, like swr.c: beta is
 * ×1000, hit-rate compared as a percentage, cost divisor / churn cap are plain
 * integers.
 */

#include "ngx_http_cache_turbo_module.h"


void
ngx_http_cache_turbo_autotune_record_cost(ngx_http_cache_turbo_zone_t *z,
    ngx_msec_int_t ms)
{
    if (ms < 0) {
        ms = 0;
    }

    (void) ngx_atomic_fetch_add(&z->sh->cost_sum_ms, (ngx_atomic_int_t) ms);
    (void) ngx_atomic_fetch_add(&z->sh->cost_count, 1);
}


/*
 * Decide a target beta (×1000) from one window's stat deltas. Mirrors
 * WP_Redis_SWR_Autotune::compute_verdict for a single group:
 *
 *   - too little data (total < MISSES_FLOOR, or no cost sample) → -1
 *     ("leave the last verdict as-is")
 *   - qualifies when:
 *       cost_ms >= COST_STRONG_MS && misses >= MISSES_FLOOR, OR
 *       cost_ms >= COST_MOD_MS   && hit_rate < HIT_RATE_CAP
 *   - disqualified (→ 0) when churn_ratio (refreshes/misses) > CHURN_CAP
 *   - beta = clamp(BETA_MIN, cost_ms*1000 / COST_DIVISOR, BETA_MAX)
 *
 * Return: >0 = publish this beta; 0 = evaluated but did not qualify (clear the
 * verdict, fall back to preset); -1 = too little data, keep the previous verdict.
 *
 * Integer fixed-point: hit_rate < CAP% is hits*100 < total*CAP; the cost→beta map
 * is cost_ms*1000/20 (×1000 beta).
 */
static ngx_int_t
ngx_http_cache_turbo_autotune_verdict(ngx_uint_t d_hits, ngx_uint_t d_misses,
    ngx_uint_t d_refreshes, ngx_uint_t d_cost_sum, ngx_uint_t d_cost_count,
    ngx_int_t *load_out)
{
    ngx_uint_t  total, cost_ms, qualifies;
    ngx_int_t   beta, load;

    total = d_hits + d_misses;

    /* v4-4: *load_out mirrors the return value's data-sufficiency contract.
     * -1 ("too little data, keep last") on both; a real window publishes both
     * beta and a load factor. Default to -1 so every early return keeps the
     * last load verdict, exactly like beta. */
    *load_out = -1;

    if (total < (ngx_uint_t) NGX_HTTP_CACHE_TURBO_AT_MISSES_FLOOR
        || d_cost_count == 0)
    {
        return -1;
    }

    cost_ms = d_cost_sum / d_cost_count;

    qualifies = 0;

    if (cost_ms >= (ngx_uint_t) NGX_HTTP_CACHE_TURBO_AT_COST_STRONG_MS
        && d_misses >= (ngx_uint_t) NGX_HTTP_CACHE_TURBO_AT_MISSES_FLOOR)
    {
        qualifies = 1;

    } else if (cost_ms >= (ngx_uint_t) NGX_HTTP_CACHE_TURBO_AT_COST_MOD_MS
               && d_hits * 100 < total * NGX_HTTP_CACHE_TURBO_AT_HIT_RATE_CAP)
    {
        qualifies = 1;
    }

    /*
     * Churn gate. refreshes/misses > CHURN_CAP means we are mostly re-fetching
     * hot (potentially volatile) keys rather than serving genuinely-cold misses;
     * widening SWR there risks surfacing stale-overwritten content, so back off
     * to the static beta. An edge cache cannot observe app-driven writes (the
     * PHP's sets/misses), so refreshes/misses is the closest proxy — coarse,
     * documented in history.md v4-3.
     */
    if (qualifies
        && d_refreshes
           > d_misses * (ngx_uint_t) NGX_HTTP_CACHE_TURBO_AT_CHURN_CAP)
    {
        qualifies = 0;
    }

    if (!qualifies) {
        /* Not under load: beta clears to the preset (0) and the load factor
         * snaps back to baseline (no stale/lock widening). */
        *load_out = NGX_HTTP_CACHE_TURBO_AT_LOAD_BASE;
        return 0;
    }

    beta = (ngx_int_t) (cost_ms * 1000 / NGX_HTTP_CACHE_TURBO_BETA_COST_DIVISOR);

    if (beta < NGX_HTTP_CACHE_TURBO_BETA_MIN) {
        beta = NGX_HTTP_CACHE_TURBO_BETA_MIN;

    } else if (beta > NGX_HTTP_CACHE_TURBO_BETA_MAX) {
        beta = NGX_HTTP_CACHE_TURBO_BETA_MAX;
    }

    /* v4-4 load factor from the same avg regen cost: AT_LOAD_PER_MS per ms, so it
     * is exactly 1× at the AT_COST_MOD_MS moderate-load gate and rises with a
     * slower origin, hard-capped at AT_LOAD_MAX (≤4×). Never below baseline (a
     * qualifying window is, by definition, under load). */
    load = (ngx_int_t) (cost_ms * NGX_HTTP_CACHE_TURBO_AT_LOAD_PER_MS);

    if (load < NGX_HTTP_CACHE_TURBO_AT_LOAD_BASE) {
        load = NGX_HTTP_CACHE_TURBO_AT_LOAD_BASE;

    } else if (load > NGX_HTTP_CACHE_TURBO_AT_LOAD_MAX) {
        load = NGX_HTTP_CACHE_TURBO_AT_LOAD_MAX;
    }

    *load_out = load;
    return beta;
}


/*
 * Compute the verdict over the window since the last snapshot and publish it.
 * Caller holds z->shpool->mutex. Advances the snapshot so the next call windows
 * from here; counters are monotonic and snapshots ≤ current, so each delta is the
 * activity since the previous recompute (the first recompute's window = since
 * worker start).
 */
static void
ngx_http_cache_turbo_autotune_recompute_locked(ngx_http_cache_turbo_zone_t *z)
{
    ngx_uint_t  hits, misses, refreshes, cost_sum, cost_count;
    ngx_int_t   verdict, load;

    hits       = (ngx_uint_t) z->sh->hits;
    misses     = (ngx_uint_t) z->sh->misses;
    refreshes  = (ngx_uint_t) z->sh->refreshes;
    cost_sum   = (ngx_uint_t) z->sh->cost_sum_ms;
    cost_count = (ngx_uint_t) z->sh->cost_count;

    verdict = ngx_http_cache_turbo_autotune_verdict(
                  hits       - (ngx_uint_t) z->sh->snap_hits,
                  misses     - (ngx_uint_t) z->sh->snap_misses,
                  refreshes  - (ngx_uint_t) z->sh->snap_refreshes,
                  cost_sum   - (ngx_uint_t) z->sh->snap_cost_sum,
                  cost_count - (ngx_uint_t) z->sh->snap_cost_count,
                  &load);

    z->sh->snap_hits       = hits;
    z->sh->snap_misses     = misses;
    z->sh->snap_refreshes  = refreshes;
    z->sh->snap_cost_sum   = cost_sum;
    z->sh->snap_cost_count = cost_count;

    /* >=0 publishes (0 = clear / fall back to preset); -1 keeps the last good
     * verdict (too little data this window to re-decide). beta and the v4-4 load
     * factor share that contract and are set together by the verdict, so the one
     * guard covers both. */
    if (verdict >= 0) {
        z->sh->autotuned_beta = (ngx_atomic_t) verdict;
        z->sh->autotuned_load = (ngx_atomic_t) load;
    }
}


void
ngx_http_cache_turbo_autotune_maybe(ngx_http_cache_turbo_zone_t *z,
    time_t interval)
{
    time_t  now;

    if (interval <= 0) {
        interval = NGX_HTTP_CACHE_TURBO_AT_INTERVAL;
    }

    now = ngx_time();

    /* Fast path: not due yet. Unlocked read of autotune_next — a benign race only
     * risks two workers recomputing on the same tick, which is idempotent. */
    if ((time_t) z->sh->autotune_next > now) {
        return;
    }

    ngx_shmtx_lock(&z->shpool->mutex);

    /* Re-check under the lock and claim the slot, so one worker recomputes per
     * interval rather than every worker that raced past the unlocked check. */
    if ((time_t) z->sh->autotune_next > now) {
        ngx_shmtx_unlock(&z->shpool->mutex);
        return;
    }
    z->sh->autotune_next = (ngx_atomic_t) (now + interval);

    ngx_http_cache_turbo_autotune_recompute_locked(z);

    ngx_shmtx_unlock(&z->shpool->mutex);
}


void
ngx_http_cache_turbo_autotune_force(ngx_http_cache_turbo_zone_t *z)
{
    ngx_shmtx_lock(&z->shpool->mutex);
    ngx_http_cache_turbo_autotune_recompute_locked(z);
    ngx_shmtx_unlock(&z->shpool->mutex);
}
