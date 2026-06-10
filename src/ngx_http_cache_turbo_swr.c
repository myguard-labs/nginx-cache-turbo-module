/*
 * Copyright (c) 2026 Eilander
 * SPDX-License-Identifier: MIT
 *
 * Stale-while-revalidate math, ported from the wp-redis PHP implementation
 * (eilandert/wp-redis/includes/class-swr.php). Keeping the algorithm and
 * constants identical means the edge cache and the object cache speak the
 * same language and tune the same way.
 */

#include "ngx_http_cache_turbo_module.h"


/*
 * Compute the stale-TTL given a fresh-TTL. A fresh-TTL of 0 ("forever") stays
 * 0; otherwise multiply by STALE_MULTIPLIER so the slab entry survives the
 * whole stale window before it is evicted.
 */
time_t
ngx_http_cache_turbo_stale_ttl(time_t fresh_ttl)
{
    if (fresh_ttl <= 0) {
        return 0;
    }

    return fresh_ttl * NGX_HTTP_CACHE_TURBO_STALE_MULTIPLIER;
}


/*
 * Decide whether the current read should win the refresh dice.
 *
 * Probability model (linear rise across the stale window): at fresh_until the
 * probability is 0; at fresh_until + stale_window it is effectively 1. Beta
 * scales aggressiveness — beta=1.0 means probability matches the elapsed
 * fraction directly, beta=2.0 refreshes earlier/more often, beta=0.5 lets it
 * drift further. Across all concurrent readers ONE wins the dice and
 * regenerates; the rest serve the stale value. Lock-free single-flight.
 *
 * beta_milli is fixed-point (beta * 1000) to avoid floats in the hot path.
 *
 * Returns NGX_OK if this caller should regenerate, NGX_DECLINED otherwise.
 */
ngx_int_t
ngx_http_cache_turbo_should_refresh(u_char *key_hash, time_t fresh_until,
    time_t stale_window, ngx_int_t beta_milli)
{
    time_t      now;
    time_t      elapsed;
    ngx_int_t   window;
    uint64_t    dice;          /* random in [0, 1<<20)                     */
    uint64_t    threshold;     /* elapsed_frac * beta, same 1<<20 scale    */

    now = ngx_time();

    if (now < fresh_until) {
        return NGX_DECLINED;       /* still fresh */
    }

    window = (stale_window > 0) ? (ngx_int_t) stale_window : 1;

    elapsed = now - fresh_until;
    if (elapsed >= window) {
        return NGX_OK;             /* past the window: always refresh */
    }

    /*
     * threshold = elapsed_frac * beta, computed in a 1<<20 fixed-point space:
     *   elapsed_frac = elapsed / window           (in [0,1))
     *   threshold    = elapsed_frac * beta_milli/1000
     * Clamp beta floor to 0.01 like the PHP (max(0.01, beta)).
     */
    if (beta_milli < 10) {
        beta_milli = 10;           /* 0.01 floor */
    }

    threshold = ((uint64_t) elapsed << 20) / (uint64_t) window;   /* frac<<20 */
    threshold = (threshold * (uint64_t) beta_milli) / 1000;

    if (threshold >= (1ULL << 20)) {
        return NGX_OK;
    }

    /* Per-key dice: hash the key bytes with the current second so that within
     * one second all workers/readers of a key roll the same value (mirrors the
     * PHP per-request memoisation), but it re-rolls each second. */
    dice = ngx_crc32_long(key_hash, 32);
    dice ^= (uint64_t) now * 2654435761ULL;
    dice &= (1ULL << 20) - 1;

    return (dice < threshold) ? NGX_OK : NGX_DECLINED;
}
