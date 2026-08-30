#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

TIMEOUT_SCALE="${PROBER_TIMEOUT_SCALE:-1}"
export PROBER_ERROR_LOG="$PROBER_PREFIX/logs/error.log"

run_rules() {
    "$PROBER_CLIENT" -H 127.0.0.1 -p "$PROBER_RESOLVED_PORT" \
        -t "$((5000 * TIMEOUT_SCALE))" "$1"
}

echo "1..2"
FAILED=0

HONEST_OUT="$PROBER_PREFIX/honest.out"
HONEST_RC=0
run_rules "$PROBER_SCENARIO/multi-worker.rule" >"$HONEST_OUT" 2>&1 \
    || HONEST_RC=$?
if [ "$HONEST_RC" -eq 0 ]; then
    echo "ok 1 - cache HITs reached at least two workers"
    sed 's/^/# /' "$HONEST_OUT"
else
    echo "not ok 1 - cache HITs reached at least two workers"
    echo "# prober exited $HONEST_RC; output follows"
    sed 's/^/# /' "$HONEST_OUT"
    FAILED=1
fi

NEG_OUT="$PROBER_PREFIX/negative-control.out"
NEG_RC=0
run_rules "$PROBER_SCENARIO/negative-control.rule.fixture" >"$NEG_OUT" 2>&1 \
    || NEG_RC=$?
if [ "$NEG_RC" -ne 0 ] \
    && grep -qE 'fanout coverage: .* distinct worker.* need >= 5' "$NEG_OUT"; then
    echo "ok 2 - impossible five-worker fanout fired the coverage oracle"
    grep -E 'fanout coverage:|^not ok' "$NEG_OUT" | sed 's/^/# /'
else
    echo "not ok 2 - impossible five-worker fanout fired the coverage oracle"
    echo "# expected nonzero plus the >= 5 fanout coverage diagnostic; rc=$NEG_RC"
    sed 's/^/# /' "$NEG_OUT"
    FAILED=1
fi

exit "$FAILED"
