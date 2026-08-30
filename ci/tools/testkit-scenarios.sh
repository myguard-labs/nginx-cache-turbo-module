#!/usr/bin/env bash
# Canonical nginx-module-testkit scenario matrix for this consumer.
# Source this file; it intentionally performs no work on its own.
# shellcheck disable=SC2034  # public arrays consumed by workflow run blocks

TESTKIT_SCENARIOS_ALL=(
    consumer-cache-turbo
    shm-coherence-varidx
    fault-slab-store
    redis-connect-backoff
    alloc-per-request
    fd-starve
    multi-worker
    l2-cross-instance-fill
    rss-slope
    reload-mid-upload
    reload-cycle
)

TESTKIT_SCENARIOS_PLAIN=(
    consumer-cache-turbo
    shm-coherence-varidx
    fault-slab-store
    redis-connect-backoff
    alloc-per-request
    fd-starve
    multi-worker
)

# Scheduled cross-server compatibility witness. Keep this representative and
# cheap: the full plain matrix already gates nginx on every applicable PR.
TESTKIT_SCENARIOS_ANGIE=(
    consumer-cache-turbo
)

TESTKIT_SCENARIOS_SANITIZED=(
    consumer-cache-turbo
    l2-cross-instance-fill
    shm-coherence-varidx
    rss-slope
    reload-mid-upload
    reload-cycle
)

TESTKIT_SCENARIOS_VALGRIND=(
    consumer-cache-turbo
    shm-coherence-varidx
    fault-slab-store
    alloc-per-request
    fd-starve
    multi-worker
)
