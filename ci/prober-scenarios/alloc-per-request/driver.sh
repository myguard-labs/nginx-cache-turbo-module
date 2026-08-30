#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
set -euo pipefail

# Warm the cache before the honest run takes its origin snapshot. This makes
# every measured request a HIT and lets probe_baseline distinguish cumulative
# HIT-path slab churn from the legitimate allocations that store a cold item.
HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
TIMEOUT_SCALE="${PROBER_TIMEOUT_SCALE:-1}"
export PROBER_ERROR_LOG="$PROBER_PREFIX/logs/error.log"

run_rules() {
	"$PROBER_CLIENT" -H "$HOST" -p "$PORT" \
		-t "$((5000 * TIMEOUT_SCALE))" "$1"
}

FAILED=0
fail() {
	echo "not ok $1 - $2"
	FAILED=1
}

run_green() {
	local number="$1" fixture="$2" label="$3" out rc=0
	out="$PROBER_PREFIX/alloc-$number.out"
	run_rules "$PROBER_SCENARIO/$fixture" >"$out" 2>&1 || rc=$?
	if [ "$rc" -eq 0 ]; then
		echo "ok $number - $label"
	else
		fail "$number" "$label"
	fi
	sed 's/^/# /' "$out"
}

run_red() {
	local number="$1" fixture="$2" pattern="$3" label="$4" out rc=0
	out="$PROBER_PREFIX/alloc-$number.out"
	run_rules "$PROBER_SCENARIO/$fixture" >"$out" 2>&1 || rc=$?
	if [ "$rc" -ne 0 ] && grep -qE "$pattern" "$out"; then
		echo "ok $number - $label"
	else
		fail "$number" "$label"
	fi
	sed 's/^/# /' "$out"
}

echo "1..4"
run_green 1 warmup.rule.fixture \
	"a cold MISS stores the item and the next request is a genuine HIT"
run_green 2 alloc-per-request.rule \
	"HIT-path request sizes leave slab and cycle-pool resources flat"
run_red 3 negative-control-slab.rule.fixture \
	'delta zone\.slab_reqs:' \
	"the slab-allocation comparator fires on its negative control"
run_red 4 negative-control-cleanup.rule.fixture \
	'delta pool\.cycle_cleanup:' \
	"the cycle-cleanup comparator fires on its negative control"

exit "$FAILED"
