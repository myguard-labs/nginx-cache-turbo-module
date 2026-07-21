/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit tests for the cache-turbo pure-math units (SWR TTL/dice + autotune
 * verdict). Compiles the SHIPPED src units verbatim against
 * ci/tests/unit/ngx_shim_math.h so the assertions run against production code,
 * not a copy.
 *
 * We suppress the real src/ngx_http_cache_turbo_module.h by pre-defining its
 * include guard, then supply exactly the types/constants/stubs the two units
 * use. ngx_time()/ngx_random() are stubbed to globals so the clock and the
 * refresh dice are deterministic — the whole point is to drive the boundary
 * branches (TTL overflow clamp, forever-TTL, band fallback, beta/load clamps,
 * data-sufficiency floor, churn gate) the HTTP runtime suite cannot reach.
 */

#define NGX_HTTP_CACHE_TURBO_MODULE_H_INCLUDED_   /* suppress the real header */
#include "ngx_shim_math.h"

/* deterministic clock + RNG backing ngx_time()/ngx_random() in the shim */
time_t  ngx_shim_now  = 1000000;
long    ngx_shim_rand = 0;

/* the units under test, verbatim */
#include "../../src/ngx_http_cache_turbo_swr.c"
#include "../../src/ngx_http_cache_turbo_autotune.c"

#include <stdio.h>
#include <string.h>

static int failures = 0;
static int checks   = 0;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        checks++;                                                              \
        if (!(cond)) {                                                         \
            failures++;                                                        \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (msg));    \
        }                                                                      \
    } while (0)

#define CHECK_EQ(got, want, msg)                                               \
    do {                                                                       \
        long g_ = (long) (got), w_ = (long) (want);                            \
        checks++;                                                              \
        if (g_ != w_) {                                                        \
            failures++;                                                        \
            fprintf(stderr, "FAIL %s:%d: %s (got %ld, want %ld)\n",            \
                    __FILE__, __LINE__, (msg), g_, w_);                        \
        }                                                                      \
    } while (0)


static void
test_stale_ttl(void)
{
    /* fresh_ttl <= 0 ("forever" resolves to 0 here) stays 0 (swr.c:24) */
    CHECK_EQ(ngx_http_cache_turbo_stale_ttl(0, 4), 0, "stale_ttl(0) == 0");
    CHECK_EQ(ngx_http_cache_turbo_stale_ttl(-5, 4), 0, "stale_ttl(<0) == 0");

    /* normal multiply */
    CHECK_EQ(ngx_http_cache_turbo_stale_ttl(100, 4), 400, "stale_ttl 100*4");

    /* stale_mult <= 0 falls back to BALANCED default (swr.c:28) */
    CHECK_EQ(ngx_http_cache_turbo_stale_ttl(100, 0), 400,
             "stale_ttl mult 0 -> default 4");
    CHECK_EQ(ngx_http_cache_turbo_stale_ttl(100, -3), 400,
             "stale_ttl mult <0 -> default 4");

    /* STAB-5 overflow clamp: fresh_ttl * mult would exceed TTL_MAX (swr.c:34) */
    CHECK_EQ(ngx_http_cache_turbo_stale_ttl((time_t) 0xFFFFFFFF, 8),
             (time_t) 0xFFFFFFFF, "stale_ttl overflow clamps to TTL_MAX");
    /* exactly on the boundary (TTL_MAX / mult) must NOT clamp */
    CHECK_EQ(ngx_http_cache_turbo_stale_ttl((time_t) (0xFFFFFFFF / 4), 4),
             (time_t) ((0xFFFFFFFF / 4) * 4),
             "stale_ttl at boundary does not clamp");
}


static void
test_should_refresh(void)
{
    u_char  key[32];
    memset(key, 0, sizeof(key));

    /* still fresh: now < fresh_until -> DECLINED (swr.c:68) */
    ngx_shim_now = 1000;
    CHECK_EQ(ngx_http_cache_turbo_should_refresh(key, 2000, 100, 1000),
             NGX_DECLINED, "should_refresh still-fresh -> DECLINED");

    /* past the whole stale window -> always OK (swr.c:75) */
    ngx_shim_now = 5000;
    CHECK_EQ(ngx_http_cache_turbo_should_refresh(key, 2000, 100, 1000),
             NGX_OK, "should_refresh past window -> OK");

    /* inside window, threshold saturates (elapsed_frac*beta >= 1) -> OK
     * (swr.c:92). elapsed=90 of window=100, beta=2000 (2.0): frac 0.9*2=1.8 */
    ngx_shim_now = 2090;
    CHECK_EQ(ngx_http_cache_turbo_should_refresh(key, 2000, 100, 2000),
             NGX_OK, "should_refresh saturated threshold -> OK");

    /* inside window, dice below threshold -> OK; dice above -> DECLINED.
     * elapsed=50/100, beta=1000 -> threshold = 0.5<<20. Force the dice each
     * way via the RNG stub: dice = (rand ^ now*k) & mask, so rand=now*k folds
     * the mix to 0 (below threshold -> OK), and rand=(now*k ^ mask) drives the
     * dice to all-ones (>= threshold -> DECLINED). Deterministic under the
     * fixed clock, and both dice branches are now exercised. */
    ngx_shim_now = 2050;
    uint64_t mix = (uint64_t) ngx_shim_now * 2654435761ULL;
    ngx_shim_rand = (long) mix;                 /* mixed dice becomes 0 */
    CHECK_EQ(ngx_http_cache_turbo_should_refresh(key, 2000, 100, 1000),
             NGX_OK, "should_refresh dice below threshold -> OK");
    ngx_shim_rand = (long) (mix ^ ((1ULL << 20) - 1));
    CHECK_EQ(ngx_http_cache_turbo_should_refresh(key, 2000, 100, 1000),
             NGX_DECLINED, "should_refresh dice above threshold -> DECLINED");
    /* beta_milli < 10 hits the 0.01 floor (swr.c:85); dice still 0 -> OK */
    ngx_shim_rand = (long) mix;
    CHECK_EQ(ngx_http_cache_turbo_should_refresh(key, 2000, 100, 0),
             NGX_OK, "should_refresh floors beta to 0.01 -> OK");

    /* window <= 0 is coerced to 1, so any elapsed>=1 is past-window -> OK
     * (swr.c:72). now-fresh_until = 1 >= window(1). */
    ngx_shim_now = 2001;
    CHECK_EQ(ngx_http_cache_turbo_should_refresh(key, 2000, 0, 1000),
             NGX_OK, "should_refresh zero-window coerced to 1 -> OK");
}


/* Build a zone whose CURRENT counters minus snapshot give the window deltas we
 * want, then autotune_force runs the verdict over that single window. */
static ngx_http_cache_turbo_shctx_t  g_sh;
static ngx_slab_pool_t               g_pool;
static ngx_http_cache_turbo_zone_t   g_zone;

static void
zone_reset(void)
{
    memset(&g_sh, 0, sizeof(g_sh));
    memset(&g_pool, 0, sizeof(g_pool));
    g_zone.sh = &g_sh;
    g_zone.shpool = &g_pool;
}

/* set the window deltas by loading current counters (snapshot stays 0) */
static void
zone_window(ngx_uint_t hits, ngx_uint_t misses, ngx_uint_t refreshes,
    ngx_uint_t cost_sum, ngx_uint_t cost_count)
{
    g_sh.hits = hits;
    g_sh.misses = misses;
    g_sh.refreshes = refreshes;
    g_sh.cost_sum_ms = cost_sum;
    g_sh.cost_count = cost_count;
    g_sh.snap_hits = g_sh.snap_misses = g_sh.snap_refreshes = 0;
    g_sh.snap_cost_sum = g_sh.snap_cost_count = 0;
    g_sh.autotuned_beta = 0;
    g_sh.autotuned_load = 0;
}


static void
test_autotune_record_cost(void)
{
    zone_reset();
    /* negative ms is clamped to 0 (autotune.c:27) */
    ngx_http_cache_turbo_autotune_record_cost(&g_zone, -50);
    CHECK_EQ(g_sh.cost_sum_ms, 0, "record_cost clamps negative ms to 0");
    CHECK_EQ(g_sh.cost_count, 1, "record_cost counts the sample");

    ngx_http_cache_turbo_autotune_record_cost(&g_zone, 25);
    CHECK_EQ(g_sh.cost_sum_ms, 25, "record_cost accumulates ms");
    CHECK_EQ(g_sh.cost_count, 2, "record_cost increments count");
}


static void
test_autotune_verdict(void)
{
    /* too little data: total < MISSES_FLOOR -> keep last verdict, beta stays 0
     * (autotune.c:70). */
    zone_reset();
    zone_window(10, 10, 0, 1000, 10);
    ngx_http_cache_turbo_autotune_force(&g_zone);
    CHECK_EQ(g_sh.autotuned_beta, 0, "verdict too-little-data keeps beta 0");

    /* no cost sample (cost_count == 0) -> keep last (autotune.c:71) */
    zone_reset();
    zone_window(200, 200, 0, 0, 0);
    ngx_http_cache_turbo_autotune_force(&g_zone);
    CHECK_EQ(g_sh.autotuned_beta, 0, "verdict no-cost-sample keeps beta 0");

    /* qualifies via STRONG cost + enough misses; cost 40ms -> beta 40*1000/20
     * = 2000, within [500,3000]. (autotune.c:80,113) */
    zone_reset();
    zone_window(0, 200, 0, 40 * 200, 200);   /* avg cost 40ms, 200 misses */
    ngx_http_cache_turbo_autotune_force(&g_zone);
    CHECK_EQ(g_sh.autotuned_beta, 2000, "verdict strong-load beta = cost/20");
    CHECK_EQ(g_sh.autotuned_load, 4000,
             "verdict load = min(cost*100, MAX) = 4000");

    /* beta clamps to MIN: tiny avg cost 5ms qualifying via MOD gate needs
     * cost>=10, so use cost 10ms -> beta 500 == MIN exactly; push cost 4ms
     * can't qualify. Use the MOD path with low hit-rate: cost 10ms, hits 0,
     * misses 200 -> beta 10*1000/20 = 500 = MIN (autotune.c:115). */
    zone_reset();
    zone_window(0, 200, 0, 10 * 200, 200);
    ngx_http_cache_turbo_autotune_force(&g_zone);
    CHECK_EQ(g_sh.autotuned_beta, 500, "verdict beta clamps to MIN (500)");

    /* beta clamps to MAX: huge avg cost 100ms -> 100*1000/20 = 5000 > 3000
     * (autotune.c:118). */
    zone_reset();
    zone_window(0, 200, 0, 100 * 200, 200);
    ngx_http_cache_turbo_autotune_force(&g_zone);
    CHECK_EQ(g_sh.autotuned_beta, 3000, "verdict beta clamps to MAX (3000)");

    /* churn gate: refreshes/misses > CHURN_CAP(2) disqualifies -> beta 0,
     * load snaps to BASE (autotune.c:99,106). 200 misses, 500 refreshes. */
    zone_reset();
    zone_window(0, 200, 500, 40 * 200, 200);
    ngx_http_cache_turbo_autotune_force(&g_zone);
    CHECK_EQ(g_sh.autotuned_beta, 0, "verdict churn-gated -> beta 0");
    CHECK_EQ(g_sh.autotuned_load, NGX_HTTP_CACHE_TURBO_AT_LOAD_BASE,
             "verdict churn-gated load snaps to BASE");

    /* qualifies but does not: high cost, but hit-rate >= CAP and misses <
     * FLOOR -> MOD gate fails, STRONG gate fails -> not qualified -> beta 0.
     * cost 12ms (>=MOD, <STRONG), hits 1000, misses 100 (>=floor via total),
     * hit-rate 1000/1100 = 90% < 95% so MOD *does* qualify. Flip to hit-rate
     * 99%: hits 9900 misses 100 -> hit-rate 99% >= 95 -> MOD fails. */
    zone_reset();
    zone_window(9900, 100, 0, 12 * 100, 100);
    ngx_http_cache_turbo_autotune_force(&g_zone);
    CHECK_EQ(g_sh.autotuned_beta, 0,
             "verdict high-hit-rate MOD gate fails -> beta 0");
}


int
main(void)
{
    test_stale_ttl();
    test_should_refresh();
    test_autotune_record_cost();
    test_autotune_verdict();

    fprintf(stderr, "unit: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
