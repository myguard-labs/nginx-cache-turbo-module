/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Minimal nginx surface for UNIT-TESTING the cache-turbo pure-math units:
 *   src/ngx_http_cache_turbo_swr.c       (stale_ttl, should_refresh)
 *   src/ngx_http_cache_turbo_autotune.c  (verdict via record_cost/force paths)
 *
 * These functions are integer fixed-point arithmetic with several boundary
 * branches — TTL overflow clamp, "forever" TTL, mis-resolved band fallback,
 * beta/load clamps, the data-sufficiency floor — that the HTTP runtime suite
 * structurally cannot reach (it can't drive fresh_ttl<=0 into stale_ttl, nor a
 * negative regen cost, nor force a single window's stat deltas across the
 * qualify/churn/clamp gates). We compile the SHIPPED .c verbatim against this
 * shim so the test is locked to production code, and stub ngx_time/ngx_random
 * so the dice and clocks are deterministic.
 *
 * The struct layout here only needs to satisfy the field ACCESSES autotune.c
 * makes (z->sh->{hits,misses,...}, z->shpool); it is not the real shctx and is
 * never shared with a running nginx — unit scope only.
 */

#ifndef NGX_CACHE_TURBO_UNIT_SHIM_MATH_H
#define NGX_CACHE_TURBO_UNIT_SHIM_MATH_H

#include <stdint.h>
#include <stddef.h>

/* Scalar types, faithful to nginx on LP64. */
typedef intptr_t        ngx_int_t;
typedef uintptr_t       ngx_uint_t;
typedef intptr_t        ngx_flag_t;
typedef long            time_t_shim;   /* real time_t comes from <time.h> below */
typedef long            ngx_msec_int_t;
typedef long            ngx_atomic_int_t;
typedef unsigned long   ngx_atomic_t;
typedef unsigned char   u_char;

#include <time.h>       /* real time_t for the swr/autotune time math */

#define NGX_OK           0
#define NGX_ERROR       -1
#define NGX_DECLINED    -5

/* ---- deterministic clock + RNG ---------------------------------------- *
 * The tests set these before calling into the units.                      */
extern time_t     ngx_shim_now;
extern long       ngx_shim_rand;

static inline time_t ngx_time(void)  { return ngx_shim_now; }
static inline long   ngx_random(void) { return ngx_shim_rand; }

/* ---- shared-memory context the autotune functions touch --------------- */
typedef struct {
    ngx_atomic_t  hits;
    ngx_atomic_t  misses;
    ngx_atomic_t  refreshes;
    ngx_atomic_t  cost_sum_ms;
    ngx_atomic_t  cost_count;

    ngx_atomic_t  snap_hits;
    ngx_atomic_t  snap_misses;
    ngx_atomic_t  snap_refreshes;
    ngx_atomic_t  snap_cost_sum;
    ngx_atomic_t  snap_cost_count;

    ngx_atomic_t  autotuned_beta;
    ngx_atomic_t  autotuned_load;
    ngx_atomic_t  autotune_next;
} ngx_http_cache_turbo_shctx_t;

/* ngx_shmtx / slab pool: the unit test is single-threaded, so the mutex is a
 * no-op. Only the address is needed (&z->shpool->mutex). */
typedef struct { int _unused; } ngx_shmtx_t;
typedef struct { ngx_shmtx_t mutex; } ngx_slab_pool_t;

typedef struct {
    ngx_http_cache_turbo_shctx_t  *sh;
    ngx_slab_pool_t               *shpool;
} ngx_http_cache_turbo_zone_t;

static inline void ngx_shmtx_lock(ngx_shmtx_t *m)   { (void) m; }
static inline void ngx_shmtx_unlock(ngx_shmtx_t *m) { (void) m; }

static inline ngx_atomic_int_t
ngx_atomic_fetch_add(ngx_atomic_t *value, ngx_atomic_int_t add)
{
    ngx_atomic_int_t old = (ngx_atomic_int_t) *value;
    *value = (ngx_atomic_t) (old + add);
    return old;
}

/* ---- constants the units reference ------------------------------------ *
 * Kept byte-identical to src/ngx_http_cache_turbo_module.h. A drift here is
 * caught by tests/unit/check_constants.sh (grep-compares the two).         */
#define NGX_HTTP_CACHE_TURBO_STALE_MULTIPLIER   4
#define NGX_HTTP_CACHE_TURBO_TTL_MAX            ((time_t) 0xFFFFFFFF)

#define NGX_HTTP_CACHE_TURBO_BETA_MIN           500
#define NGX_HTTP_CACHE_TURBO_BETA_MAX           3000
#define NGX_HTTP_CACHE_TURBO_BETA_COST_DIVISOR  20

#define NGX_HTTP_CACHE_TURBO_AT_COST_STRONG_MS  30
#define NGX_HTTP_CACHE_TURBO_AT_COST_MOD_MS     10
#define NGX_HTTP_CACHE_TURBO_AT_MISSES_FLOOR    100
#define NGX_HTTP_CACHE_TURBO_AT_HIT_RATE_CAP    95
#define NGX_HTTP_CACHE_TURBO_AT_CHURN_CAP       2
#define NGX_HTTP_CACHE_TURBO_AT_LOAD_BASE       1000
#define NGX_HTTP_CACHE_TURBO_AT_LOAD_MAX        4000
#define NGX_HTTP_CACHE_TURBO_AT_LOAD_PER_MS     100
#define NGX_HTTP_CACHE_TURBO_AT_INTERVAL        30

/* Prototypes for the units under test (definitions come from the #included
 * .c files in the driver). */
time_t    ngx_http_cache_turbo_stale_ttl(time_t fresh_ttl, ngx_int_t stale_mult);
ngx_int_t ngx_http_cache_turbo_should_refresh(u_char *key_hash,
              time_t fresh_until, time_t stale_window, ngx_int_t beta_milli);
void      ngx_http_cache_turbo_autotune_record_cost(
              ngx_http_cache_turbo_zone_t *z, ngx_msec_int_t ms);
void      ngx_http_cache_turbo_autotune_force(ngx_http_cache_turbo_zone_t *z);

#endif /* NGX_CACHE_TURBO_UNIT_SHIM_MATH_H */
