#!/bin/sh
# ci/tools/assert-fixtures.sh — fail the build if the runtime suite silently
# skipped a requested fixture (AUD-TESTFIX1).
#
# Motivation: --redis-server/--memcached-server are passed to test_runtime.py
# on real CI runners that have redis-server + openssl, so the best-effort TLS
# sub-fixture (redis_tls, redis_tls_untrusted, redis_tls_expired) must not
# silently skip -- that would mean ~80 L2/TLS tests, including the AUD-TLS1
# negative-verification tests, never ran while the suite still exited 0.
#
# Shared by every workflow that captures a runtime-suite log (build-test.yml,
# asan.yml single-process and multi-worker) so the check and its rationale
# live in exactly one place instead of being copy-pasted per workflow.
#
# Usage: ci/tools/assert-fixtures.sh <logfile>
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <runtime-suite-logfile>" >&2
    exit 2
fi

LOG="$1"

if [ ! -r "$LOG" ]; then
    echo "::error::assert-fixtures.sh: log file not readable: $LOG" >&2
    exit 2
fi

if grep -q '^FIXTURE SKIPPED:' "$LOG"; then
    echo "::error::runtime suite skipped a requested fixture:"
    grep '^FIXTURE SKIPPED:' "$LOG"
    exit 1
fi
