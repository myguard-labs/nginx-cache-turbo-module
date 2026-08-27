#!/usr/bin/env bash
#
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# S25 port of testkit's scenarios/rss-slope against a real cache_turbo HIT
# path (../nginx.conf), not the bare `return 200` the generic conf ships.
# Mechanism (prober_slope_check, PROBER_SLOPE_*, the SANITIZER skip on oracle
# 2) is identical to upstream's driver.sh -- read there for the full
# rationale. What changed:
#
#   - The stimulus path is /cached/item, not /. A cold GET first (outside the
#     measured window) populates the cache entry; every warmup/sampled request
#     after that is a genuine cache_turbo HIT -- header replay, refcounted
#     zone lookup -- not a passthrough return. Oracle 0 below asserts that
#     first HIT explicitly so a broken cache (permanently MISSing, silently
#     falling through to origin) cannot pass this file having measured a
#     pass-through the whole time.
#   - Zone declared in nginx.conf itself (cache_turbo_zone), not via
#     PROBER_PROBE_ZONE -- same as ../alloc-per-request and ../fault-slab-store.
#
# CADENCE: same as upstream -- this is the weekly/ci-deep lane, not the PR
# gate. 60 post-warmup ops plus 10 warmup ops is a few hundred requests; cheap
# in isolation, but it is a LOOP over identical operations, which is the
# category testkit.yml's own PR-gate cost budget excludes (see fault-slab-store's
# comment on why IT stayed in the PR gate: single-shot, no loop -- this
# scenario is the opposite shape).
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"
PATH_UNDER_TEST=/cached/item

export PROBER_ERROR_LOG="$ELOG"

WARMUP="${PROBER_SLOPE_WARMUP:-10}"
OPS="${PROBER_SLOPE_OPS:-60}"
MAX_DIRTY="${PROBER_SLOPE_MAX_DIRTY:-4}"

FAILED=0

echo "1..3"

# --- oracle 0: the stimulus path is a genuine HIT, not a passthrough --------
# One cold GET (outside the measured warmup/sample window) to populate the
# entry, then one more to confirm the second reads back X-Cache: HIT. Without
# this, a conf bug routing /cached/ to a plain 200 -- or a cache that silently
# never stores -- would run this whole file against a passthrough and every
# "flat slope" verdict below would be true for the wrong reason.
miss_out="$(mktemp)"
hit_out="$(mktemp)"
(
    exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
    printf 'GET %s HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' "$PATH_UNDER_TEST" >&3
    cat <&3 2>/dev/null || true
) >"$miss_out" 2>/dev/null || true
(
    exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
    printf 'GET %s HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' "$PATH_UNDER_TEST" >&3
    cat <&3 2>/dev/null || true
) >"$hit_out" 2>/dev/null || true

if grep -q '^HTTP/1.1 200' "$miss_out" && grep -qi '^X-Cache: HIT' "$hit_out"; then
    echo "ok 1 - stimulus path served a genuine cache HIT (X-Cache: HIT on the second GET)"
else
    echo "not ok 1 - stimulus path did not confirm a genuine HIT -- every oracle below would be measuring a passthrough"
    FAILED=1
fi
rm -f "$miss_out" "$hit_out"

# --- oracle 1: cycle-pool slope is exactly flat, across HIT operations -----
if out="$(prober_slope_check "$HOST" "$PORT" cycle_used "$PATH_UNDER_TEST" \
            "$WARMUP" "$OPS" 0)"; then
    echo "ok 2 - cycle-pool slope is flat across $OPS cache_turbo HIT operations"
    printf '%s\n' "$out"
else
    echo "not ok 2 - cycle-pool slope is flat across $OPS cache_turbo HIT operations"
    printf '%s\n' "$out"
    FAILED=1
fi

# --- oracle 2: RSS slope stays under the per-op bound -----------------------
# Same sanitizer skip as upstream -- see its driver.sh for why.
if grep -qa '__asan_\|__ubsan_' "$PROBER_SERVER_BIN"; then
    echo "ok 3 - RSS private_dirty slope # SKIP sanitizer build dirties its own pages (not a module leak)"
elif out="$(prober_slope_check "$HOST" "$PORT" private_dirty "$PATH_UNDER_TEST" \
            "$WARMUP" "$OPS" "$MAX_DIRTY")"; then
    echo "ok 3 - RSS private_dirty slope stays under ${MAX_DIRTY} kB/op across cache_turbo HIT operations"
    printf '%s\n' "$out"
else
    echo "not ok 3 - RSS private_dirty slope stays under ${MAX_DIRTY} kB/op across cache_turbo HIT operations"
    printf '%s\n' "$out"
    FAILED=1
fi

exit "$FAILED"
