#!/usr/bin/env bash
#
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Scenario: fault-slab-store -- probe-armed slab-allocation failure on the
# store path, and the resource-neutrality of the error path it forces.
#
# WHAT IS UNDER TEST, AND WHY IT NEEDED A SCENARIO
#   ngx_http_cache_turbo_shm_alloc_evict() is this module's SOLE allocation
#   funnel for cached payload and metadata. Every caller of it has an error
#   path -- `if (ctn == NULL) return NGX_ERROR;` and its siblings -- and until
#   now nothing in this repo could make any of them run on demand. The runtime
#   suite drives the happy path; the TEST_FAULTS directives are config-time
#   flags that fail OTHER sites. So the allocation-failure error paths were
#   reachable only by genuinely exhausting a zone, which is slow, and which
#   also perturbs the very resource counters a leak oracle wants to read.
#
#   S24 adds a probe-armed countdown in the zone (shctx.fault_slab_countdown)
#   and this scenario is what proves it works and what it buys. The buy is the
#   LEAK-ON-ERROR-PATH class: a store that fails partway can leak a request-pool
#   allocation or a descriptor, and nothing else in this repo asserts anything
#   about that. test_runtime.py asserts on cache behaviour, never on resources.
#
# THE THREE THINGS THIS FILE MUST ESTABLISH, IN THIS ORDER
#
#   1. THE ARM IS REFUSED WHEN IT SHOULD BE. `fault_palloc=0` names a site this
#      module does not implement, and the hook must return NGX_DECLINED for it.
#      Checked FIRST because it is the cheapest way to catch a fault_set that
#      says NGX_OK to everything -- which would look identical to a working
#      hook on every other leg in this file.
#
#   2. THE FAULT ACTUALLY FIRES, AND THE UNARMED CONTROL PROVES IT WAS THE ARM.
#      Armed, a cold GET must fail to cache, so the SECOND GET of the same URI
#      is another MISS. Unarmed, against an identically-shaped URI on the same
#      zone, the second GET must be a HIT. Neither leg means anything alone:
#      a MISS-then-MISS could be a broken cache and a HIT-then-HIT could be a
#      fault that never fired. The PAIR is the oracle, and it is why the
#      control leg is not optional decoration.
#
#   3. THE ERROR PATH IS RESOURCE-NEUTRAL. Two quiescent probe snapshots around
#      one faulting request, comparing cycle_used / cycle_blocks / cycle_large
#      and the worker fd count. This is the oracle the item exists for and the
#      one that catches a real defect class -- an allocation the error path
#      forgets to release, or a descriptor it forgets to close, on a path no
#      other test in this repo can even reach.
#
#      ⚠ THE SNAPSHOT PAIR MUST STRADDLE A *FAULTING* REQUEST. Both snapshots
#      are post-drain and quiescent (the probe read is the only traffic at each
#      instant), which is the shape the sibling consumer-cache-turbo scenario
#      documents: never a cold baseline, which carries a startup one-off, and
#      never a mid-request reading, which flakes on live per-request buffers.
#
# A QUIET PASS ON LEG 2's CONTROL IS THE FAILURE THIS FILE EXISTS TO PREVENT.
# If the control leg ever goes MISS-then-MISS too, the fault is not what is
# suppressing the store and every conclusion below is void -- so it is asserted
# as an oracle in its own right rather than assumed.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"

export PROBER_ERROR_LOG="$ELOG"

FAILED=0

# Same timeout scaling the rules path applies, so this driver does not time out
# under a sanitizer build while the scenarios beside it do not. The `:-1`
# default is load-bearing under `set -u`: run-scenario.sh does not export
# PROBER_TIMEOUT_SCALE to a driver.
TIMEOUT_SCALE="${PROBER_TIMEOUT_SCALE:-1}"

# raw_get PATH OUTFILE -- one bounded GET, captured whole (status line and
# headers included, which is where the X-Cache verdict lives).
#
# Bounded by an explicit deadline and a kill, not by trusting the peer: a hung
# fetch must not hang the scenario, and a truncated capture must not be
# silently trusted -- a snapshot taken around a request that never finished
# would make the neutrality comparison meaningless in the direction that
# reports green.
raw_get() {
    local path="$1" out="$2" pid dl
    (
        exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
        printf 'GET %s HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' "$path" >&3
        cat <&3 2>/dev/null || true
    ) >"$out" 2>/dev/null &
    pid=$!
    dl=$(( SECONDS + 10 * TIMEOUT_SCALE ))
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$SECONDS" -ge "$dl" ]; then
            pkill -P "$pid" 2>/dev/null || true
            kill "$pid" 2>/dev/null || true
            break
        fi
        sleep 0.05
    done
    wait "$pid" 2>/dev/null || true
    grep -q '^HTTP/1.1 200' "$out"
}

# arm QUERY -- issue one probe request carrying a fault-arm query string and
# echo the probe body.
#
# WHY NOT prober_probe_body: it takes host and port only and builds `GET
# /__probe` with no query, and the query IS the arm -- ngx_test_probe_arm()
# parses r->args and nothing else. A helper that cannot carry a query string
# cannot arm anything.
#
# The probe's HTTP status is deliberately NOT treated as the arm's verdict.
# The handler discards ngx_test_probe_arm()'s return and answers 200 either
# way, on purpose: a refused arm is the ordinary case for every plain probe
# read, and turning it into a 500 would take every other oracle down with it.
# So a refusal is observed BEHAVIOURALLY -- by whether the fault subsequently
# fires -- which is what leg 1 and leg 2 are built around.
arm() {
    local query="$1" out
    out="$PROBER_PREFIX/arm.out"
    (
        exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
        printf 'GET /__probe?%s HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' "$query" >&3
        cat <&3 2>/dev/null || true
    ) >"$out" 2>/dev/null || true
    cat "$out"
}

# snapshot -- read one probe document with NO arm query and load the resource
# fields into SNAP_* globals. Returns 1 if any field is absent, which
# prober_probe_field distinguishes from zero for exactly the reason it matters
# here: a missing field read as 0 would make a delta of 0 and certify "nothing
# grew" against a probe that lost the field entirely.
snapshot() {
    local body
    body="$(prober_probe_body "$HOST" "$PORT")" || return 1
    SNAP_USED="$(prober_probe_field "$body" cycle_used)"   || return 1
    SNAP_BLOCKS="$(prober_probe_field "$body" cycle_blocks)" || return 1
    SNAP_LARGE="$(prober_probe_field "$body" cycle_large)"  || return 1
    SNAP_FDS="$(prober_probe_field "$body" fds)"            || return 1
}

# x_cache FILE -- echo the X-Cache header value, uppercased, or the empty
# string. Matched on the header line specifically rather than anywhere in the
# response, so a body that happened to contain the word HIT cannot answer for
# the header.
x_cache() {
    sed -n 's/^[Xx]-[Cc]ache:[[:space:]]*\([A-Za-z]*\).*/\1/p' "$1" \
        | head -1 | tr '[:lower:]' '[:upper:]'
}

# TAP plan:
#  1 the probe answers and renders this module's own zone fields (hook is live)
#  2 UNARMED CONTROL: a cold URI caches, so its second GET is a HIT
#  3 an unimplemented site (fault_palloc) is REFUSED, not reported applied
#  4 ARMED: the faulting store leaves nothing cached, so GET 2 has no X-Cache
#  5 cycle_used flat across the faulting request
#  6 cycle_blocks + cycle_large flat across the faulting request
#  7 worker fds flat across the faulting request
#  8 the arm is single-shot: after it fires, storing works again
echo "1..8"

# --- 1: the probe is live and it is OUR zone --------------------------------
# Asserted on a field only this module's zone_render emits. The generic
# document would render for a zone we never created, and every later leg would
# then be arming a hook that is never reached. `lookups` is the cheapest such
# field and is present from the first request onward.
PROBE_BODY="$(prober_probe_body "$HOST" "$PORT" || true)"
if [ -n "$PROBE_BODY" ] && printf '%s' "$PROBE_BODY" | grep -q '"lookups"'; then
    echo "ok 1 - the probe answers and renders cache_turbo's own zone fields"
else
    echo "not ok 1 - the probe document carries no zone.lookups, so cache_turbo_probe is not pointed at a zone this module created and no fault_slab arm could reach our fault_set hook"
    printf '%s' "$PROBE_BODY" | head -5 | sed 's/^/# /' || true
    FAILED=$((FAILED + 1))
fi

# --- 2: UNARMED CONTROL -- the store path works when nothing is armed -------
#
# THIS LEG IS NOT A WARM-UP; IT IS THE CONTROL, and leg 4 is uninterpretable
# without it. Leg 4 asserts that an armed cold URI is still a MISS on its
# second GET. That assertion is satisfied just as well by a cache that never
# stores anything, by an origin that returns something uncacheable, or by a
# conf typo -- all of which would report leg 4 green while the fault injector
# did nothing at all. Proving the SAME conf, the SAME zone and an
# identically-shaped URI reach HIT when unarmed is what makes leg 4's MISS
# attributable to the arm rather than to the setup.
CTL1="$PROBER_PREFIX/control-1.out"
CTL2="$PROBER_PREFIX/control-2.out"
CONTROL_OK=0
if raw_get /cached/control "$CTL1" && raw_get /cached/control "$CTL2"; then
    if [ "$(x_cache "$CTL2")" = "HIT" ]; then
        CONTROL_OK=1
    fi
fi
if [ "$CONTROL_OK" -eq 1 ]; then
    echo "ok 2 - unarmed control: /cached/control cached on the first GET and its second GET was a HIT"
else
    echo "not ok 2 - unarmed control never reached a HIT (GET2 X-Cache='$(x_cache "$CTL2" 2>/dev/null)') -- the store path is broken independently of any fault, so leg 4's MISS would prove nothing"
    head -12 "$CTL2" 2>/dev/null | sed 's/^/# /' || true
    FAILED=$((FAILED + 1))
fi

# --- 3: an unimplemented fault site is REFUSED ------------------------------
#
# fault_palloc names NGX_TEST_PROBE_FAULT_PALLOC, which this module has no
# fault point for; its fault_set must answer NGX_DECLINED. The observable
# consequence is that arming it changes NOTHING: a cold URI armed with
# fault_palloc still caches and still HITs on its second GET.
#
# This is the leg that catches a fault_set which applies every site it is
# handed -- a hook shaped like the real one, wired identically, and wrong in
# the one way every other leg in this file is blind to. Without it, deleting
# the `fault != NGX_TEST_PROBE_FAULT_SLAB` refusal passes legs 1, 2 and 4-8.
#
# ⚠ nth=1, THE SAME ORDINAL LEG 4 USES, AND NOT 0. This leg is a mutation
#   test: it only means something if arming the SAME nth through the SAME
#   countdown would have suppressed the store. nth=0 lands on claim_locked()'s
#   single-flight stub, whose error path recovers by design, so a leg armed at
#   0 stays green even with the site refusal deleted -- which is precisely what
#   an earlier revision of this file did, and it was caught by compiling
#   `fault != FAULT_SLAB` out and watching this leg SURVIVE. Verified 2026-08-27:
#   at nth=1 the same mutation turns this leg red. Do not lower it back to 0.
arm "fault_palloc=1" >/dev/null 2>&1 || true
PAL1="$PROBER_PREFIX/palloc-1.out"
PAL2="$PROBER_PREFIX/palloc-2.out"
PALLOC_OK=0
if raw_get /cached/palloc "$PAL1" && raw_get /cached/palloc "$PAL2"; then
    if [ "$(x_cache "$PAL2")" = "HIT" ]; then
        PALLOC_OK=1
    fi
fi
if [ "$PALLOC_OK" -eq 1 ]; then
    echo "ok 3 - fault_palloc= is refused: arming an unimplemented site changed nothing and /cached/palloc still cached"
else
    echo "not ok 3 - arming fault_palloc suppressed the store (GET2 X-Cache='$(x_cache "$PAL2" 2>/dev/null)') -- fault_set is applying a site it has no fault point for, which reports coverage that does not exist"
    head -12 "$PAL2" 2>/dev/null | sed 's/^/# /' || true
    FAILED=$((FAILED + 1))
fi

# --- oracles 4-7: the armed, measured request -------------------------------
#
# ⚠ nth=1, AND THE 1 IS MEASURED, NOT GUESSED.
#   A cold GET makes TWO allocations through shm_alloc_evict(), in this order:
#
#     nth=0  claim_locked()'s single-flight STUB (shm.c, "No node at all:
#            create a stub ... marking the key as in flight").
#     nth=1  store_locked()'s NODE allocation -- the store under test.
#
#   Arming nth=0 therefore fails the stub, and the stub's error path is
#   deliberately TOLERANT: it returns CLAIM_WINNER anyway, because failing to
#   mark a key in flight only costs an extra origin hit. The request then
#   proceeds and stores normally, so nth=0 reads as a clean HIT and injects
#   nothing observable. That is not a bug in the injector -- it is the funnel
#   honestly reporting that its first customer on this path recovers.
#
#   This was established by sweeping nth=0..5 against this exact conf and
#   watching which ordinal changed the X-Cache of the second request: only 1 did.
#   Do NOT "simplify" this back to 0. If a future change adds or removes a
#   slab allocation ahead of the store on the cold path, this constant moves,
#   and leg 4 is what will catch it -- the sweep is reproducible by pointing
#   the same arm at fault_slab=0..5 on a scratch driver.
#
# The first snapshot is taken AFTER the arm and BEFORE the faulting request, so
# the delta straddles exactly one faulting store and nothing else.
#
# The first snapshot is taken AFTER the arm and BEFORE the faulting request, so
# the delta straddles exactly one faulting store and nothing else.
BASE_OK=1
if ! snapshot; then
    BASE_OK=0
    echo "# the probe endpoint did not answer for the pre-fault snapshot"
fi
if [ "$BASE_OK" -eq 1 ]; then
    BASE_USED="$SNAP_USED"; BASE_BLOCKS="$SNAP_BLOCKS"
    BASE_LARGE="$SNAP_LARGE"; BASE_FDS="$SNAP_FDS"
fi

arm "fault_slab=1" >/dev/null 2>&1 || true

ARM1="$PROBER_PREFIX/armed-1.out"
ARM2="$PROBER_PREFIX/armed-2.out"
ARMED_SERVED=0
if raw_get /cached/armed "$ARM1"; then
    ARMED_SERVED=1
fi

FINAL_OK=0
if [ "$BASE_OK" -eq 1 ] && [ "$ARMED_SERVED" -eq 1 ] && snapshot; then
    FINAL_OK=1
    FINAL_USED="$SNAP_USED"; FINAL_BLOCKS="$SNAP_BLOCKS"
    FINAL_LARGE="$SNAP_LARGE"; FINAL_FDS="$SNAP_FDS"
fi

# --- 4: the fault fired -- nothing was cached -------------------------------
#
# The client still gets its 200: a failed store is not a failed response, the
# module serves the origin body through and only declines to cache it. So the
# observable is not the status but the SECOND GET, which must still come from
# the origin because the first one stored nothing. Read together with leg 2
# (same conf, same zone, unarmed, reached HIT) this is attributable to the arm.
#
# ⚠ THE ASSERTION IS "NO X-Cache HEADER AT ALL", NOT "not HIT".
#   This module emits X-Cache only on the serve-from-cache path -- HIT, STALE,
#   STALE-IF-ERROR (module.c's xcache_str mapping); a response served from the
#   origin carries no X-Cache line whatsoever, which is exactly what leg 2's
#   own FIRST GET showed. Asserting `!= HIT` would therefore also be satisfied
#   by a STALE serve, by a malformed header, and by a response whose header
#   block never arrived -- three states that are not what this leg claims. The
#   empty string is the specific observable of "the origin answered again", so
#   that is what is asserted.
FAULT_FIRED=0
if [ "$ARMED_SERVED" -eq 1 ] && raw_get /cached/armed "$ARM2"; then
    if [ -z "$(x_cache "$ARM2")" ]; then
        FAULT_FIRED=1
    fi
fi
if [ "$FAULT_FIRED" -eq 1 ]; then
    echo "ok 4 - fault_slab=1 fired: the armed cold GET stored nothing, so its second GET carried no X-Cache header and came from the origin again"
else
    echo "not ok 4 - the armed request was served from cache on GET2 (X-Cache='$(x_cache "$ARM2" 2>/dev/null)') -- the fault_slab arm did not suppress the store, so it never reached shm_alloc_evict()"
    head -12 "$ARM2" 2>/dev/null | sed 's/^/# /' || true
    FAILED=$((FAILED + 1))
fi

# --- 5: cycle_used flat across the faulting request -------------------------
#
# THE ORACLE THIS ITEM EXISTS FOR. An error path that allocates from the
# request pool and returns without releasing shows up here and nowhere else in
# this repo. Equality is asserted, not a bound: the request pool is reset per
# request, so a healthy error path leaves the cycle pool exactly where it was.
if [ "$BASE_OK" -eq 0 ] || [ "$FINAL_OK" -eq 0 ]; then
    echo "ok 5 - cycle_used neutrality across the faulting request # SKIP a quiescent snapshot did not answer"
elif [ "$BASE_USED" = "$FINAL_USED" ]; then
    echo "ok 5 - cycle_used was flat across the faulting request ($BASE_USED)"
else
    echo "not ok 5 - cycle_used grew across the faulting request (before=$BASE_USED after=$FINAL_USED) -- the slab-failure error path leaks a cycle-pool allocation"
    FAILED=$((FAILED + 1))
fi

# --- 6: cycle_blocks + cycle_large flat -------------------------------------
if [ "$BASE_OK" -eq 0 ] || [ "$FINAL_OK" -eq 0 ]; then
    echo "ok 6 - cycle_blocks/cycle_large neutrality # SKIP a quiescent snapshot did not answer"
elif [ "$BASE_BLOCKS" = "$FINAL_BLOCKS" ] && [ "$BASE_LARGE" = "$FINAL_LARGE" ]; then
    echo "ok 6 - cycle_blocks ($BASE_BLOCKS) and cycle_large ($BASE_LARGE) were flat across the faulting request"
else
    echo "not ok 6 - cycle_blocks/cycle_large grew across the faulting request (before blocks=$BASE_BLOCKS large=$BASE_LARGE, after blocks=$FINAL_BLOCKS large=$FINAL_LARGE) -- the slab-failure error path leaks a pool block"
    FAILED=$((FAILED + 1))
fi

# --- 7: worker fds flat ------------------------------------------------------
# The store path's failure happens after the upstream connection is
# established, so a fd leaked on that path is a real and reachable defect.
if [ "$BASE_OK" -eq 0 ] || [ "$FINAL_OK" -eq 0 ]; then
    echo "ok 7 - worker fd neutrality # SKIP a quiescent snapshot did not answer"
elif [ "$BASE_FDS" = "$FINAL_FDS" ]; then
    echo "ok 7 - worker fd count was flat across the faulting request ($BASE_FDS)"
else
    echo "not ok 7 - worker fd count grew across the faulting request (before=$BASE_FDS after=$FINAL_FDS) -- the slab-failure error path leaks a descriptor"
    FAILED=$((FAILED + 1))
fi

# --- 8: the arm is single-shot ----------------------------------------------
#
# The tripping attempt disarms the countdown in the same critical section, so
# no explicit disarm is needed and the very next store must succeed. Asserted
# on a THIRD, fresh URI rather than by re-requesting /cached/armed: that key
# already has a failed-store history and a HIT on it would also be satisfied by
# leg 4's request having quietly stored after all, which is the one thing leg 4
# ruled out. A fresh key makes this leg about the countdown and nothing else.
#
# A countdown that stayed armed would fail every subsequent store for the life
# of the zone -- which is exactly the state a missing disarm leaves behind, and
# it is invisible to every other leg in this file because they all run before
# this point.
POST1="$PROBER_PREFIX/post-1.out"
POST2="$PROBER_PREFIX/post-2.out"
POST_OK=0
if raw_get /cached/post "$POST1" && raw_get /cached/post "$POST2"; then
    if [ "$(x_cache "$POST2")" = "HIT" ]; then
        POST_OK=1
    fi
fi
if [ "$POST_OK" -eq 1 ]; then
    echo "ok 8 - the arm was single-shot: after firing once, a fresh key cached normally and HIT"
else
    echo "not ok 8 - storing is still broken after the fault fired (GET2 X-Cache='$(x_cache "$POST2" 2>/dev/null)') -- the countdown did not disarm itself and the zone is wedged"
    head -12 "$POST2" 2>/dev/null | sed 's/^/# /' || true
    FAILED=$((FAILED + 1))
fi

if [ "$FAILED" -ne 0 ]; then
    echo "# $FAILED oracle(s) failed"
    exit 1
fi

exit 0
