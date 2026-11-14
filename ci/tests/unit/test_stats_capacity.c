/* Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause */
#include "capacity_test_source.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Valid allocator snapshots. Acquisition publishes the current generation;
 * release replaces shared scalars so sampling before/after the hold is visible.
 * Live admin tests separately exercise nginx's real allocator transitions. */
static union {
    ngx_slab_pool_t pool;
    u_char mapping[65536];
} memory;
static shctx_t shared;
static ngx_uint_t current_used, current_free;
static unsigned locks, unlocks;

void
ngx_shmtx_lock(ngx_shmtx_t *mutex)
{
    assert(mutex->depth == 0);
    mutex->depth++;
    locks++;
    memory.pool.pfree = current_free;
    shared.used_bytes = current_used;
}

void
ngx_shmtx_unlock(ngx_shmtx_t *mutex)
{
    assert(mutex->depth == 1);
    mutex->depth--;
    unlocks++;
    memory.pool.pfree = 0;
    shared.used_bytes = sizeof(memory.mapping);
}

static void
sample(ngx_http_cache_turbo_zone_t *zone, const char *name,
    ngx_uint_t used, ngx_uint_t free_pages)
{
    ngx_http_cache_turbo_stats_t snapshot;
    unsigned before = locks;

    memset(&snapshot, 0xa5, sizeof(snapshot));
    current_used = used;
    current_free = free_pages;
    shared.hits = 17;
    shared.markers = 3;
    ngx_http_cache_turbo_shm_stats(zone, &snapshot);
    assert(locks == before + 1 && unlocks == locks);
    assert(memory.pool.mutex.depth == 0);
    assert(snapshot.zone_size_bytes == sizeof(memory.mapping));
    assert(snapshot.zone_reserved_bytes == sizeof(memory.mapping) - free_pages * ngx_pagesize);
    assert(snapshot.used_bytes <= snapshot.zone_reserved_bytes);
    assert(snapshot.used_bytes == used);
    assert(snapshot.zone_reserved_bytes <= snapshot.zone_size_bytes);
    assert(snapshot.hits == 17 && snapshot.markers == 3);
    printf("capacity: %s used=%lu reserved=%lu size=%lu; locked scalar snapshot\n",
           name, (unsigned long) snapshot.used_bytes,
           (unsigned long) snapshot.zone_reserved_bytes,
           (unsigned long) snapshot.zone_size_bytes);
}

int
main(void)
{
    ngx_http_cache_turbo_zone_t zone = {&shared, &memory.pool}, reloaded;

    memory.pool.end = memory.mapping + sizeof(memory.mapping);
    sample(&zone, "empty (fixed overhead)", 0, 12);
    sample(&zone, "populated (bin slack)", 5000, 10);
    sample(&zone, "evicted", 0, 12);
    sample(&zone, "exhausted", 40000, 0);
    /* A new config context points to the retained shared mapping. */
    reloaded = zone;
    sample(&reloaded, "reload retained mapping", 5000, 10);
    return 0;
}
