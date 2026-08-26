#!/usr/bin/env bash
#
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Scenario: shm-coherence-varidx -- real, falsifiable coverage of all three
# `zone_invariant` forms against cache_turbo's own shared-memory counters.
#
# Read shm-coherence-varidx.rule for WHAT is asserted and which field feeds
# which form. This file is about why there is a driver here at all.
#
# THREE JOBS, IN THIS ORDER
#
#   1. ANTI-VACUITY. The forms only mean something if the fields they read
#      actually MOVED during the run. Against a field that was never anything
#      but its initial value, `coherent` is satisfied by any constant,
#      `at_rest <f> == N` by a field that was always N, and `monotonic` by a
#      constant sequence -- which is precisely why testkit's own shm-coherence
#      scenario refuses to assert any of the three against its reference
#      module. A bare rules run cannot tell "the invariants held" from "nothing
#      happened"; this leg reads the probe document directly and FAILS when the
#      counters are still at their initial values.
#
#   2. The honest cases must be GREEN.
#
#   3. THE NEGATIVE CONTROLS must be observed RED -- one per form, and red for
#      the RIGHT REASON. An exit status alone is not enough: a rule file that
#      failed to parse, a server that stopped answering, or a typo'd field name
#      would all exit nonzero and would "prove" an oracle fires when it never
#      ran. So each control's output is matched against its OWN form's message
#      (`zone_invariant at_rest ...`, `... coherent ...`, `... monotonic ...`),
#      which the prober prints from three distinct snprintf sites in assert.c.
#      A nonzero exit with no such line FAILS the control.
#
#      These three fixtures are the RUN-time half of the negative-control
#      obligation. They break the ORACLE (by asserting something the healthy
#      zone provably does not satisfy) and so prove the comparison is live on
#      this box, in this run. The other half -- breaking the CODE and watching
#      the healthy rule file redden -- is recorded in the rule file's history
#      and in memory; it cannot ship as a fixture because it requires editing
#      src/ and rebuilding.
#
# A quiet PASS on any control leg is the failure this file exists to make
# impossible: a green fixture means that form's comparison stopped comparing,
# and every zone_invariant of that form in the tree silently became a test
# that cannot fail.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"

# Same slicing the rules path exports, so a case's no_error_log /
# grep_error_log directive works identically under this driver.
export PROBER_ERROR_LOG="$PROBER_PREFIX/logs/error.log"

# Same invocation run-scenario.sh builds for a rules scenario, including the
# PROBER_TIMEOUT_SCALE factor -- a driver that hardcoded the timeout would time
# out under valgrind while the rules path beside it did not, and the difference
# would be blamed on the scenario. The `:-1` default is load-bearing under
# `set -u`: run-scenario.sh does NOT export PROBER_TIMEOUT_SCALE to a driver,
# and a bare arithmetic reference would abort the shell from inside a function,
# so the `|| RC=$?` at the call site would never run and the driver would die
# having printed only its plan line.
TIMEOUT_SCALE="${PROBER_TIMEOUT_SCALE:-1}"

run_rules() {
    "$PROBER_CLIENT" -H "$HOST" -p "$PORT" \
        -t "$((8000 * TIMEOUT_SCALE))" "$1"
}

# Reap the Redis this scenario's ./env started. prober_cleanup removes the run
# PREFIX and stops the server IT booted; it knows nothing about our fixture,
# and a leaked one is not cosmetic -- the next run computes the SAME port from
# the same base port, finds the leftover still listening, and silently inherits
# its keys.
#
# EXIT only (not the signal list): the trap must run once, on the single path
# out of a driver whose exit status IS the scenario's TAP result.
# shellcheck disable=SC2317  # invoked by the EXIT trap below, not inline
ct_reap() {
    local rc=$?
    if [ -n "${CT_REDIS_PID:-}" ] && kill -0 "$CT_REDIS_PID" 2>/dev/null; then
        kill -TERM "$CT_REDIS_PID" 2>/dev/null || true
        for _r in $(seq 1 40); do
            kill -0 "$CT_REDIS_PID" 2>/dev/null || break
            sleep 0.05
        done
        kill -KILL "$CT_REDIS_PID" 2>/dev/null || true
    fi
    return "$rc"
}
trap ct_reap EXIT

FAILED=0
fail() { echo "not ok $1 - $2"; FAILED=1; }

# probe_field NAME -> the integer the probe currently renders for zone.<NAME>,
# or the empty string when the field is absent. A bounded raw GET rather than
# curl: the prober's own client speaks the rule language, not ad-hoc reads, and
# adding a curl dependency to a scenario that already gates on four binaries is
# not worth it.
probe_field() {
    local name="$1" out
    out="$PROBER_PREFIX/probe-$name.out"
    (
        exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
        printf 'GET /__probe HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' >&3
        cat <&3 2>/dev/null || true
    ) >"$out" 2>/dev/null || true
    sed -n "s/.*\"$name\":\([0-9][0-9]*\).*/\1/p" "$out" | head -1
}

# one_get URI ACCEPT_ENCODING -- drive one request through the varidx path.
get_varidx() {
    local ae="$1" out
    out="$PROBER_PREFIX/get-$ae.out"
    (
        exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
        printf 'GET /varidx/a HTTP/1.1\r\nHost: prober\r\nAccept-Encoding: %s\r\nConnection: close\r\n\r\n' "$ae" >&3
        cat <&3 2>/dev/null || true
    ) >"$out" 2>/dev/null || true
    grep -q '^HTTP/1.1 200' "$out"
}

echo "1..6"

# --- 1: the Redis fixture is actually up -----------------------------------
# Checked as an ORACLE, not assumed. A dead Redis leaves varidx_inflight a
# constant 0 and every form below passes tautologically while reporting green
# -- the exact shape this scenario was written to eliminate. This repo has
# already paid once for a dead Redis reading as a module defect; here the
# failure direction is the opposite and worse, so it is checked first.
if [ "${CT_REDIS_UP:-0}" = "1" ]; then
    echo "ok 1 - the Redis fixture accepted a connection on port ${CT_REDIS_PORT:-?}"
else
    fail 1 "Redis fixture never accepted on port ${CT_REDIS_PORT:-?} -- varidx_inflight would stay a constant 0 and all three zone_invariant forms would pass tautologically"
fi

# --- 2: the hook is wired and the fields are present ------------------------
# The probe must be rendering OUR fields, not just the generic zone members. An
# absent field is reported by the prober as the -1 unavailable sentinel, and a
# rule reading it would fail with a message about the field rather than about
# the invariant -- readable, but this leg names the cause directly.
BASE_LOOKUPS="$(probe_field lookups || true)"
if [ -n "$BASE_LOOKUPS" ]; then
    echo "ok 2 - the zone_render hook is live: zone.lookups renders as $BASE_LOOKUPS"
else
    fail 2 "the probe document carries no zone.lookups -- the zone_render hook was not called, so this .so either lacks NGX_TEST_HARNESS or the probe is pointed at a zone this module did not create"
    sed 's/^/# /' "$PROBER_PREFIX/probe-lookups.out" 2>/dev/null || true
fi

# --- 3: the counters actually MOVE ------------------------------------------
# THE ANTI-VACUITY LEG. Drive two distinct variants through the auto-Vary path
# and require the lifetime lookup tally to advance. A field that does not move
# makes `monotonic` trivially true and `coherent` trivially true, and this is
# the only leg that can tell that apart from a healthy run.
if [ "$FAILED" -eq 0 ]; then
    get_varidx gzip >/dev/null 2>&1 || true
    get_varidx br   >/dev/null 2>&1 || true
    AFTER_LOOKUPS="$(probe_field lookups || true)"

    if [ -n "$AFTER_LOOKUPS" ] && [ "$AFTER_LOOKUPS" -gt "$BASE_LOOKUPS" ]; then
        echo "ok 3 - the shared counters move under traffic: zone.lookups $BASE_LOOKUPS -> $AFTER_LOOKUPS"
    else
        fail 3 "zone.lookups did not advance under traffic ($BASE_LOOKUPS -> ${AFTER_LOOKUPS:-absent}) -- against a field that never moves, coherent and monotonic are satisfied by any constant and this scenario would report green while asserting nothing"
    fi
else
    fail 3 "skipped: an earlier leg already failed, so this measurement would be meaningless"
fi

# --- 4: the honest cases are green ------------------------------------------
# Run before the controls. If the live invariants cannot hold on this box at
# all, that is the finding, and reporting it first keeps a genuine invariant
# failure from being read as a broken control.
HONEST_OUT="$PROBER_PREFIX/honest.out"
HONEST_RC=0

# Not `set -e`-fatal: a red here must be REPORTED as a red, with its output,
# not abort the driver and lose the plan line and the control legs entirely.
run_rules "$PROBER_SCENARIO/shm-coherence-varidx.rule" >"$HONEST_OUT" 2>&1 \
    || HONEST_RC=$?

if [ "$HONEST_RC" -eq 0 ]; then
    echo "ok 4 - the live four-worker zone_invariant cases are green"
    sed 's/^/# /' "$HONEST_OUT"
else
    fail 4 "the live four-worker zone_invariant cases are green"
    echo "# prober exited $HONEST_RC; its output follows"
    sed 's/^/# /' "$HONEST_OUT"
fi

# --- 5 and 6: each form's negative control is observed RED ------------------
#
# One fixture per form, each asserting something the healthy zone provably does
# not satisfy, each matched against its own form's message. Reported as two TAP
# lines (a roll-up of the three fixtures plus a per-fixture detail line) rather
# than three, so the plan stays stable if a fourth form is ever added.
#
# The patterns match the STABLE PREFIX the prober prints -- `zone_invariant
# <form> <field>:` -- and deliberately not the numbers, which vary run to run,
# nor the trailing wording, which an edit could change without changing the
# behaviour under test.
control() {   # control FIXTURE PATTERN LABEL
    local fixture="$1" pattern="$2" label="$3"
    local out rc=0
    out="$PROBER_PREFIX/negctl-$label.out"

    run_rules "$PROBER_SCENARIO/$fixture" >"$out" 2>&1 || rc=$?

    if [ "$rc" -eq 0 ]; then
        echo "#   $label: DID NOT FIRE -- the fixture passed, so the $label"
        echo "#     comparison stopped comparing and every zone_invariant"
        echo "#     $label in the tree is now a test that cannot fail"
        sed 's/^/#     /' "$out"
        return 1
    fi

    if grep -qE "$pattern" "$out"; then
        echo "#   $label: observed RED with its own message:"
        grep -E "$pattern" "$out" | head -2 | sed 's/^/#     /'
        return 0
    fi

    # Nonzero, but not from the oracle: a parse error, a dead server, a renamed
    # field. A FAILED control, because it proves nothing about the comparison
    # this leg exists to exercise.
    echo "#   $label: exited $rc but printed no '$label' invariant message, so"
    echo "#     the $label oracle is not what failed it -- this control ran"
    echo "#     and proved nothing"
    sed 's/^/#     /' "$out"
    return 1
}

CTL_RC=0

echo "# negative controls: one fixture per zone_invariant form"
control negative-control-at_rest.rule.fixture \
        'zone_invariant at_rest zone\.varidx_inflight:' \
        at_rest    || CTL_RC=1
control negative-control-coherent.rule.fixture \
        'zone_invariant coherent pid:' \
        coherent   || CTL_RC=1
control negative-control-monotonic.rule.fixture \
        'zone_invariant monotonic smaps\.pss:' \
        monotonic  || CTL_RC=1

if [ "$CTL_RC" -eq 0 ]; then
    echo "ok 5 - all three zone_invariant forms fired on their negative control"
else
    fail 5 "all three zone_invariant forms fired on their negative control"
fi

# --- 6: the controls failed for the INVARIANT, not for the traffic ----------
# Every fixture drives the same request the honest cases drive and carries the
# same expects, so a fixture that reddened because the SERVER broke rather than
# because the invariant broke would also have printed a status/body failure.
# Requiring the absence of one is what separates "the oracle fired" from "the
# run fell over and the oracle was never reached".
STRAY=0
for label in at_rest coherent monotonic; do
    out="$PROBER_PREFIX/negctl-$label.out"
    [ -f "$out" ] || continue
    if grep -qE 'status=|body~|Bail out!' "$out"; then
        echo "# $label control printed a transport/expect failure as well as (or"
        echo "#   instead of) its invariant message -- the red is not attributable"
        echo "#   to the invariant alone"
        grep -E 'status=|body~|Bail out!' "$out" | head -3 | sed 's/^/#   /'
        STRAY=1
    fi
done

if [ "$STRAY" -eq 0 ]; then
    echo "ok 6 - each control's red is attributable to its invariant, not to a transport or expect failure"
else
    fail 6 "each control's red is attributable to its invariant, not to a transport or expect failure"
fi

# The driver's exit status is the scenario's verdict.
[ "$FAILED" -eq 0 ] || exit 1
exit 0
