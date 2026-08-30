#!/usr/bin/env bash
#
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# S26 port of testkit's scenarios/reload-cycle: the server is reloaded
# (SIGHUP) several times in a row while otherwise idle. Each reload builds a
# NEW cycle and must release the OLD one; oracle shape and rationale
# (cycle-pool counters, worker/master fds, master RSS band) are testkit's own
# (../../../nginx-module-testkit/ci/prober/scenarios/reload-cycle/driver.sh).
#
# THE MODULE-SPECIFIC CLAIM THIS PORT ADDS: this scenario routes through
# ../nginx.conf's real `cache_turbo` location and reads cache_turbo's OWN
# probe (cache_turbo_probe, not testkit's generic test_ref_probe -- see
# ../env). Before S26 that was not possible at all: the probe zone pointer
# in ngx_http_cache_turbo_probe.c was a process-lifetime `static`, and the
# directive handler's duplicate guard rejected every parse after the first
# with "cache_turbo_probe is duplicate" -- so this scenario's SECOND SIGHUP
# alone would have failed at config parse before a single reload assertion
# ran (CTPROBE-STATIC-ZONE-NO-RELOAD, memory/labs/nginx-cache-turbo-module/
# issues.md). Two assertions below are new because of that fix and did not
# exist in the upstream port:
#
#   - assertion 9: a cold GET against /cached/item MISSes once, then HITs on
#     every request after, INCLUDING requests issued after later reloads --
#     proving the shm zone (not a per-worker cache, and not something a
#     reload resets) is what is actually serving.
#   - assertion 10: cache_turbo's own zone counters (hits+misses=lookups)
#     read through cache_turbo_probe are non-decreasing across the whole
#     reload series, which can only be measured at all once the probe
#     directive itself survives being parsed more than once.
#
# ONE WORKER (nginx.conf), so every per-worker reading in this driver is
# taken from the single worker actually serving -- see nginx.conf's header
# for why multiple workers would make the resource comparison meaningless.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"
MASTER="$PROBER_SERVER_PID"

export PROBER_ERROR_LOG="$ELOG"

RELOADS=8
WORKERS=1

FAILED=0

# run-scenario.sh validates and normalizes this before invoking a driver. Keep
# every harness deadline proportional to the same scale used by rules-mode so
# valgrind/sanitizer runs do not retain one hidden native-speed timeout.
TIMEOUT_SCALE="${PROBER_TIMEOUT_SCALE:-1}"

echo "1..11"

# --- helpers -----------------------------------------------------------

snapshot() {
    local body
    body="$(prober_probe_body "$HOST" "$PORT")" || return 1
    SNAP_PPID="$(prober_probe_field "$body" ppid || true)"
    SNAP_FDS="$(prober_probe_field "$body" fds)" || return 1
    SNAP_USED="$(prober_probe_field "$body" cycle_used)" || return 1
    SNAP_BLOCKS="$(prober_probe_field "$body" cycle_blocks)" || return 1
    SNAP_LARGE="$(prober_probe_field "$body" cycle_large)" || return 1
    # cache_turbo's own zone counter (hits+misses, rendered pre-summed since
    # the probe format takes one field path per rule). Only reachable at all
    # because ../env points @PROBE@ at cache_turbo_probe -- see the header
    # comment above.
    SNAP_LOOKUPS="$(prober_probe_field "$body" lookups)" || return 1
}

# One request through cache_turbo's own location. Prints the response headers
# to stdout so the caller can grep for X-Cache.
cached_request() {
    (
        exec 3<>"/dev/tcp/$HOST/$PORT" 2>/dev/null || exit 1
        printf 'GET /cached/item HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' >&3
        timeout 2 cat <&3 2>/dev/null || true
    )
}

warm() {
    local i
    for ((i = 0; i < 3; i++)); do
        (
            exec 3<>"/dev/tcp/$HOST/$PORT" 2>/dev/null || exit 0
            printf 'GET / HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' >&3 2>/dev/null
            timeout 2 cat <&3 >/dev/null 2>&1 || true
        ) || true
    done
}

master_fds() {
    [ -r "/proc/$MASTER/fd" ] || return 1
    # shellcheck disable=SC2012
    ls "/proc/$MASTER/fd" 2>/dev/null | wc -l
}

master_rss_pages() {
    [ -r "/proc/$MASTER/statm" ] || return 1
    awk '{print $2}' "/proc/$MASTER/statm" 2>/dev/null
}

# --- baseline: MISS then HIT before any reload --------------------------

MISS_RESP="$(cached_request)"
if ! printf '%s' "$MISS_RESP" | grep -qi '^HTTP/1.1 200'; then
    echo "Bail out! the baseline cache_turbo request did not answer 200"
    exit 1
fi
if printf '%s' "$MISS_RESP" | grep -qi '^X-Cache: HIT'; then
    echo "Bail out! the FIRST request against /cached/item was already a HIT -- the fixture is not cold, assertion 9 would prove nothing"
    exit 1
fi

HIT_RESP="$(cached_request)"
CACHE_OK=1
if ! printf '%s' "$HIT_RESP" | grep -qi '^HTTP/1.1 200'; then
    CACHE_OK=0
fi
if ! printf '%s' "$HIT_RESP" | grep -qi '^X-Cache: HIT'; then
    CACHE_OK=0
fi

warm
if ! snapshot; then
    echo "Bail out! the probe endpoint did not answer before the first reload"
    exit 1
fi

BASE_PPID="$SNAP_PPID"
M_FDS_BASE="$(master_fds || true)"
M_RSS_BASE="$(master_rss_pages || true)"
LOOKUPS_PREV="$SNAP_LOOKUPS"
LOOKUPS_REGRESSED=0

# --- the reload series ---------------------------------------------------

ABSORBED=0
PPID_STABLE=1
DRAINED=1
DRAIN_OBSERVABLE=1
FIRST_SET=0
FDS_REF=; USED_REF=; BLOCKS_REF=; LARGE_REF=
DRIFT=""

for ((r = 1; r <= RELOADS; r++)); do
    if prober_signal_wait HUP "$MASTER" "$HOST" "$PORT" \
        "$((5000 * TIMEOUT_SCALE))"; then
        ABSORBED=$((ABSORBED + 1))
    else
        echo "# reload $r was not absorbed within the scaled deadline (no new worker answered)"
        continue
    fi

    DRC=0
    prober_drain_wait "$MASTER" "$WORKERS" \
        "$((10000 * TIMEOUT_SCALE))" || DRC=$?
    case "$DRC" in
        0) ;;
        2) DRAIN_OBSERVABLE=0 ;;
        *) echo "# reload $r: the previous cycle's workers missed the scaled drain deadline"
           DRAINED=0 ;;
    esac

    # Every request after a reload should still HIT: the shm zone, not the
    # worker's own memory, is what cache_turbo actually reads from.
    POST_HIT_RESP="$(cached_request)"
    if ! printf '%s' "$POST_HIT_RESP" | grep -qi '^HTTP/1.1 200' \
       || ! printf '%s' "$POST_HIT_RESP" | grep -qi '^X-Cache: HIT'; then
        CACHE_OK=0
        DRIFT="$DRIFT
reload $r: /cached/item did not HIT after the reload"
    fi

    warm
    if ! snapshot; then
        echo "# reload $r: the probe endpoint did not answer afterwards"
        DRIFT="$DRIFT
reload $r: no snapshot"
        continue
    fi

    if [ "$SNAP_LOOKUPS" -lt "$LOOKUPS_PREV" ]; then
        LOOKUPS_REGRESSED=1
    fi
    LOOKUPS_PREV="$SNAP_LOOKUPS"

    if [ -n "$BASE_PPID" ] && [ "$SNAP_PPID" != "$BASE_PPID" ]; then
        PPID_STABLE=0
    fi

    if [ "$FIRST_SET" -eq 0 ]; then
        # The FIRST post-reload snapshot is the reference, not the pre-reload
        # baseline -- see upstream's own reasoning (fresh master startup cost
        # is not a per-reload cost). This scenario claims reload K costs the
        # same as reload 1, for every K.
        FDS_REF="$SNAP_FDS"; USED_REF="$SNAP_USED"
        BLOCKS_REF="$SNAP_BLOCKS"; LARGE_REF="$SNAP_LARGE"
        FIRST_SET=1
        continue
    fi

    drift_if() {   # NAME GOT WANT
        [ "$2" = "$3" ] && return 0
        DRIFT="$DRIFT
reload $r: $1 = $2, want $3"
    }
    drift_if fds          "$SNAP_FDS"    "$FDS_REF"
    drift_if cycle_used   "$SNAP_USED"   "$USED_REF"
    drift_if cycle_blocks "$SNAP_BLOCKS" "$BLOCKS_REF"
    drift_if cycle_large  "$SNAP_LARGE"  "$LARGE_REF"
done

# --- 1: every reload landed ------------------------------------------------
if [ "$ABSORBED" -eq "$RELOADS" ]; then
    echo "ok 1 - all $RELOADS reloads were absorbed"
else
    echo "not ok 1 - only $ABSORBED of $RELOADS reloads were absorbed"
    FAILED=$((FAILED + 1))
fi

# --- 2: comparable snapshots were actually collected -----------------------
if [ "$FIRST_SET" -eq 1 ]; then
    echo "ok 2 - post-reload snapshots were collected for comparison"
else
    echo "not ok 2 - no post-reload snapshot could be taken; the comparisons below prove nothing"
    FAILED=$((FAILED + 1))
fi

# --- 3: worker cycle pool and descriptors flat across the series ----------
if [ -z "$DRIFT" ] && [ "$FIRST_SET" -eq 1 ]; then
    echo "ok 3 - worker fds and cycle-pool counters identical across all reloads"
    echo "# fds=$FDS_REF cycle_used=$USED_REF cycle_blocks=$BLOCKS_REF cycle_large=$LARGE_REF"
else
    echo "not ok 3 - worker state drifted across reloads (per-cycle leak?)"
    printf '%s\n' "$DRIFT" | sed '/^$/d; s/^/# /'
    FAILED=$((FAILED + 1))
fi

# --- 4: every worker stayed a child of the same master ---------------------
if [ -z "$BASE_PPID" ]; then
    echo "ok 4 - master parentage # SKIP this module .so emits no \"ppid\" field"
elif [ "$PPID_STABLE" -eq 1 ]; then
    echo "ok 4 - every post-reload worker was a child of the original master"
else
    echo "not ok 4 - a post-reload worker reported a different master (ppid changed from $BASE_PPID)"
    FAILED=$((FAILED + 1))
fi

# --- 5: no worker died by signal across the series --------------------------
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "not ok 5 - a worker died by signal during the reload series"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    FAILED=$((FAILED + 1))
else
    echo "ok 5 - no worker died by signal across the reload series"
fi

# --- 6: the master leaked no descriptor -------------------------------------
M_FDS_END="$(master_fds || true)"
if [ -z "$M_FDS_BASE" ] || [ -z "$M_FDS_END" ]; then
    echo "ok 6 - master descriptor count # SKIP /proc/$MASTER/fd not readable on this host"
elif [ "$M_FDS_END" -eq "$M_FDS_BASE" ]; then
    echo "ok 6 - the master held $M_FDS_END descriptors before and after $RELOADS reloads"
else
    echo "not ok 6 - the master's descriptor count moved $M_FDS_BASE -> $M_FDS_END across $RELOADS reloads"
    FAILED=$((FAILED + 1))
fi

# --- 7: the master did not grow grossly -------------------------------------
M_RSS_END="$(master_rss_pages || true)"
if [ "${PROBER_SANITIZED:-0}" -eq 1 ]; then
    echo "ok 7 - master resident size # SKIP sanitized build: the runtime's quarantine and shadow state dominate RSS"
elif [ -z "$M_RSS_BASE" ] || [ -z "$M_RSS_END" ]; then
    echo "ok 7 - master resident size # SKIP /proc/$MASTER/statm not readable on this host"
else
    RSS_BAND=$(( 16 * RELOADS ))
    RSS_GROWTH=$(( M_RSS_END - M_RSS_BASE ))
    if [ "$RSS_GROWTH" -le "$RSS_BAND" ]; then
        echo "ok 7 - master resident size grew $RSS_GROWTH pages over $RELOADS reloads (band $RSS_BAND)"
    else
        echo "not ok 7 - master resident size grew $RSS_GROWTH pages over $RELOADS reloads (band $RSS_BAND)"
        FAILED=$((FAILED + 1))
    fi
fi

# --- 8: every old cycle's workers went away ---------------------------------
if [ "$DRAIN_OBSERVABLE" -eq 0 ]; then
    echo "ok 8 - old-cycle worker drain # SKIP pgrep unavailable on this host"
elif [ "$DRAINED" -eq 1 ]; then
    echo "ok 8 - every reload drained back to $WORKERS worker"
else
    echo "not ok 8 - a previous cycle's worker was still running after a reload"
    FAILED=$((FAILED + 1))
fi

# --- 9: cache_turbo served MISS-then-HIT, and HIT survived every reload ----
# S26's own claim: before the fix this scenario could not run a SINGLE
# reload (the probe directive itself would refuse to parse a second time),
# so this assertion did not exist in the upstream port.
if [ "$CACHE_OK" -eq 1 ]; then
    echo "ok 9 - /cached/item MISSed once, then HIT on every request including after every reload"
else
    echo "not ok 9 - a cache_turbo request did not answer 200+X-Cache:HIT where expected"
    printf '%s\n' "$DRIFT" | grep -F 'did not HIT' | sed 's/^/# /' || true
    FAILED=$((FAILED + 1))
fi

# --- 10: cache_turbo's own zone counters, read via cache_turbo_probe, are
#         non-decreasing across the whole reload series -----------------
# lookups (hits+misses) is zeroed once at zone carve and never reset by a
# reload (module.c's own probe.c comment: "a reload inherits the live shm
# rather than re-initialising it"). A regression here would mean either the
# zone was NOT preserved across a reload, or cache_turbo_probe itself is
# reading a stale/wrong zone after a reload.
if [ "$LOOKUPS_REGRESSED" -eq 0 ]; then
    echo "ok 10 - cache_turbo's lookups counter (hits+misses) never decreased across $RELOADS reloads (final=$LOOKUPS_PREV)"
else
    echo "not ok 10 - cache_turbo's lookups counter decreased at some point across the reload series"
    FAILED=$((FAILED + 1))
fi

# --- post-reload coherence (prober, folded in as diagnostics) --------------
# PIPESTATUS, not $?: the client pipeline would otherwise report sed's status,
# silently discarding a red prober leg.
"$PROBER_CLIENT" -H "$HOST" -p "$PORT" \
    -t "$((8000 * TIMEOUT_SCALE))" \
    "$PROBER_SCENARIO/post-reload.rule" | sed 's/^/# prober: /'
STATUS=${PIPESTATUS[0]}

if [ "$STATUS" -eq 0 ]; then
    echo "ok 11 - the post-reload worker serves cache_turbo cleanly"
else
    echo "not ok 11 - the post-reload worker did not serve cache_turbo cleanly"
    FAILED=$((FAILED + 1))
fi

if [ "$FAILED" -gt 0 ] || [ "$STATUS" -ne 0 ]; then
    exit 1
fi
exit 0
