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
# or a nonzero status when the complete probe response or field is absent.
# Delegate both the bounded/retried read and numeric field parsing to testkit's
# public helpers. Open-coding /dev/tcp + an unbounded cat here let a stalled
# probe hang the entire CI job and made this driver's parser disagree with the
# assertion engine's unavailable-field contract.
probe_field() {
    local name="$1" out body
    out="$PROBER_PREFIX/probe-$name.out"
    body="$(prober_probe_body "$HOST" "$PORT")" || return 1
    printf '%s\n' "$body" >"$out"
    prober_probe_field "$body" "$name"
}

# one_get URI ACCEPT_ENCODING -- drive one request through the varidx path.
get_varidx() {
    local ae="$1" out
    out="$PROBER_PREFIX/get-$ae.out"
    (
        exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
        printf 'GET /varidx/a HTTP/1.1\r\nHost: prober\r\nAccept-Language: %s\r\nConnection: close\r\n\r\n' "$ae" >&3
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

# --- 3: the counters actually MOVE, AND THE VARIANT-INDEX PATH IS REACHED ----
#
# THE ANTI-VACUITY LEG, and the most important one in this file. Everything
# below it is satisfied by a zone nothing ever touched: against a field that
# never moves, `coherent` is satisfied by any constant, `monotonic` by a
# constant sequence, and `at_rest <f> == 0` by a field that was never anything
# but 0. This leg is the only thing standing between a green run and a green
# run that asserted nothing.
#
# ⚠ WHY IT CHECKS THE VARIANT INDEX SPECIFICALLY AND NOT JUST `lookups`.
#   The first version of this scenario checked only that zone.lookups advanced,
#   and it PASSED while varidx_inflight was never touched once -- the conf's
#   origin emitted `Vary: Accept-Encoding` on an identity body, which
#   classify_vary() (vary.c:1280-1293) deliberately treats as inert, so
#   ctx->vary_bits stayed 0, the `auto_vary && vary_bits > 0` gate at
#   filters.c:2511 never fired, and no variant-index write was ever issued. The
#   at_rest oracle was reading a field that had never been anything but 0. It
#   was caught only by MUTATING the module: with the increment inflated from
#   +1 to +5 the whole scenario still reported green, which is what proved the
#   counter was untouched.
#
#   `lookups` advancing does NOT imply the variant path ran -- a plain cached
#   GET bumps hits/misses without ever reaching it. So this leg asserts the
#   variant index directly: after driving two distinct Accept-Language
#   variants of one base URI, the module must report that it wrote a variant
#   index for them. redis-cli is the oracle because the write is a Redis SADD
#   and the key is observable from outside the process.
if [ "$FAILED" -eq 0 ]; then
    get_varidx en >/dev/null 2>&1 || true
    get_varidx fr >/dev/null 2>&1 || true
    AFTER_LOOKUPS="$(probe_field lookups || true)"

    # The variant-index SET the auto-Vary path SADDs into. Its key is
    # `ct:tag:<hash>` -- the `ct:` is the module's redis_prefix and `tag:` is
    # the index namespace; the hash comes from
    # ngx_http_cache_turbo_variant_index_name(), so it is matched by PREFIX and
    # never by an exact key.
    #
    # The CARDINALITY, not the key count, is what is asserted. One key would
    # exist even if only a single variant had ever been indexed, and a single
    # variant is exactly the state a broken auto-Vary produces (it stores the
    # object but never partitions it). Two members means two distinct variants
    # of one base URI genuinely reached the index -- which is the multi-membered
    # set a PURGE's SMEMBERS enumerates, and therefore the shape COR-5 is about.
    VIDX_CARD=0
    while IFS= read -r _k; do
        [ -n "$_k" ] || continue
        _c="$(redis-cli -h "$HOST" -p "${CT_REDIS_PORT:-0}" scard "$_k" 2>/dev/null || echo 0)"
        case "$_c" in ''|*[!0-9]*) _c=0 ;; esac
        # if/fi, NOT `[ ] && x`. Under `set -e` a trailing test that is the
        # LAST statement of a loop body aborts the whole script when it is
        # false -- and here false is the normal case for every key after the
        # largest. shellcheck does not flag this shape.
        if [ "$_c" -gt "$VIDX_CARD" ]; then
            VIDX_CARD="$_c"
        fi
    done <<EOF
$(redis-cli -h "$HOST" -p "${CT_REDIS_PORT:-0}" --scan --pattern 'ct:tag:*' 2>/dev/null)
EOF

    if [ -z "$AFTER_LOOKUPS" ] || [ "$AFTER_LOOKUPS" -le "$BASE_LOOKUPS" ]; then
        fail 3 "zone.lookups did not advance under traffic ($BASE_LOOKUPS -> ${AFTER_LOOKUPS:-absent}) -- against a field that never moves, coherent and monotonic are satisfied by any constant and this scenario would report green while asserting nothing"
    elif [ "${VIDX_CARD:-0}" -lt 2 ]; then
        fail 3 "zone.lookups advanced ($BASE_LOOKUPS -> $AFTER_LOOKUPS) but the largest ct:tag:* variant-index set holds ${VIDX_CARD:-0} member(s), not the 2 this leg drove -- so the auto-Vary variant path was not taken for both variants and varidx_inflight was never properly incremented. The at_rest oracle below would be reading a field that has only ever been 0. Check that the origin's Vary axis is one classify_vary() actually keys on: Accept-Encoding on an IDENTITY body is deliberately inert (vary.c:1280-1293) and was the original cause of exactly this vacuity"
    else
        echo "ok 3 - the shared counters move and the variant-index path is reached: zone.lookups $BASE_LOOKUPS -> $AFTER_LOOKUPS, variant-index set holds $VIDX_CARD members"
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

if [ "$CTL_RC" -eq 0 ]; then
    echo "ok 5 - the at_rest and coherent forms fired on their negative controls"
else
    fail 5 "the at_rest and coherent forms fired on their negative controls"
fi

# THE MONOTONIC FORM HAS NO DETERMINISTIC CONTROL ON THIS HARNESS, AND IS
# THEREFORE NOT GATED HERE. Its fixture is checked in beside the other two and
# is runnable by hand, but it is NOT asserted, because it does not fire
# reliably and a flaky control is worse than an absent one -- it teaches a
# reader to re-run until green, which is how a broken oracle survives.
#
# The cause is structural, not a fixture bug, and it is worth stating here so
# the next person does not spend the afternoon this cost. collect_zone_readings
# (prober.c:634) takes its N readings AFTER the fan has fully drained, as N
# sequential idle probe GETs, each on its own `Connection: close` socket. By
# that point every counter in the document has settled, so there is no field
# left that DECREASES between two readings by construction:
#
#   zone.varidx_inflight  settled 0 at every reading (its high window is one
#                         event-loop turn, and the fan's legs are sequential)
#   zone.slab_pages_free  falls once, on the first store, before reading 1 --
#                         measured constant at 2032 (8m zone) and at 12 (64k)
#   connections.free      constant at 125; each read closes before the next
#   fds / timers / config_generation / pool.cycle_* / connections.total
#                         all constant across 24 reads
#   smaps.pss             DOES fall, but only when the probe reads rotate
#                         across workers -- measured firing 11 of 12 runs at
#                         fanout 64, and only ~1 of 3 at fanout 24
#
# Full evidence and the options considered are in the memory mirror as
# ZONEINV-MONOTONIC-NO-DETERMINISTIC-FALL. The honest fixes all live in
# TESTKIT, not here (a per-leg reading captured during the fan, or a
# consumer-supplied traffic hook between collect reads), which is why this
# scenario records the gap rather than papering it with an ~80% control.
echo "# monotonic: NOT GATED -- no field in this harness decreases"
echo "#   deterministically across collect_zone_readings' post-drain idle"
echo "#   probe reads. negative-control-monotonic.rule.fixture is checked in"
echo "#   and runnable by hand (it fires ~11 of 12 runs on smaps.pss at"
echo "#   fanout 64) but is deliberately not asserted: a flaky control"
echo "#   teaches re-running until green. See issues.md"
echo "#   ZONEINV-MONOTONIC-NO-DETERMINISTIC-FALL."

# --- 6: the controls failed for the INVARIANT, not for the traffic ----------
# Every fixture drives the same request the honest cases drive and carries the
# same expects, so a fixture that reddened because the SERVER broke rather than
# because the invariant broke would also have printed a status/body failure.
# Requiring the absence of one is what separates "the oracle fired" from "the
# run fell over and the oracle was never reached".
STRAY=0
for label in at_rest coherent; do
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
