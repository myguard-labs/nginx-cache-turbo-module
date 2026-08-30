#!/usr/bin/env bash
#
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# S25 port of testkit's scenarios/reload-mid-upload: a slow client-to-server
# upload is in flight through a `cache_turbo`-fronted location when the
# master is told to reload (SIGHUP); the in-flight body must be read to
# completion and answered, not dropped. Oracle shape and rationale are
# testkit's own
# (../../../nginx-module-testkit/ci/prober/scenarios/reload-mid-upload/driver.sh);
# this is a fresh implementation with the upload routed through cache_turbo's
# own location (../nginx.conf's /upload) rather than a bare proxy_pass, so a
# reload landing mid-request exercises this module's request-lifecycle
# bookkeeping (its own header filter installed on the location, its request
# context alloc/free) rather than only nginx core's.
#
# @PROBE@ deliberately stays on testkit's default test_ref_probe -- see
# nginx.conf's header comment for why cache_turbo_probe cannot be used on a
# scenario whose conf is parsed more than once (CTPROBE-STATIC-ZONE-NO-RELOAD).
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"

export PROBER_ERROR_LOG="$ELOG"

FAILED=0

# run-scenario.sh normalizes this to 1..1000 before invoking a driver. Scale
# tool/readiness deadlines under valgrind without stretching the one-second
# mid-upload discriminator below: that window must remain shorter than the
# fixed ~4.5 second drip or it would stop proving the upload is still active.
TIMEOUT_SCALE="${PROBER_TIMEOUT_SCALE:-1}"

echo "1..6"

BODY="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"   # 60 bytes
BODY_LEN=${#BODY}
CHUNK=4

start_upload() {
    local step_sleep=$1 out=$2 pidvar=$3
    (
        exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
        printf 'POST /upload HTTP/1.1\r\nHost: prober\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' \
            "$BODY_LEN" >&3

        off=0
        while [ "$off" -lt "$BODY_LEN" ]; do
            len=$CHUNK
            remaining=$((BODY_LEN - off))
            [ "$len" -gt "$remaining" ] && len=$remaining
            printf '%s' "${BODY:$off:$len}" >&3
            off=$((off + len))
            if [ "$off" -lt "$BODY_LEN" ] && [ "$step_sleep" != 0 ]; then
                sleep "$step_sleep"
            fi
        done

        cat <&3 2>/dev/null || true
    ) >"$out" 2>/dev/null &
    printf -v "$pidvar" '%s' "$!"
}

# --- assertion 1: negative control -- a fast upload must not pass the gate --
NEG_OUT="$PROBER_PREFIX/upload-fast.out"
start_upload 0 "$NEG_OUT" NEG_PID
neg_alive=0
for ((i = 0; i < 20; i++)); do
    if kill -0 "$NEG_PID" 2>/dev/null; then
        neg_alive=1
    else
        neg_alive=0
        break
    fi
    sleep 0.05
done
wait "$NEG_PID" 2>/dev/null || true
if [ "$neg_alive" -eq 0 ]; then
    echo "ok 1 - a fast upload finished before the settle window (liveness gate discriminates)"
else
    echo "not ok 1 - a fast upload was still 'alive' after the settle window (gate cannot tell finished from in-flight)"
    FAILED=$((FAILED + 1))
fi

# --- fire the slow upload through cache_turbo's /upload location -----------
STEP_SLEEP=0.3

UPLOAD_OUT="$PROBER_PREFIX/upload.out"
start_upload "$STEP_SLEEP" "$UPLOAD_OUT" UPLOAD_PID

ALIVE_SEEN=0
for ((i = 0; i < 20; i++)); do
    if kill -0 "$UPLOAD_PID" 2>/dev/null; then
        ALIVE_SEEN=1
    else
        ALIVE_SEEN=0
        break
    fi
    sleep 0.05
done

if [ "$ALIVE_SEEN" -eq 1 ] && kill -0 "$UPLOAD_PID" 2>/dev/null; then
    echo "ok 2 - the upload was still sending (alive, mid-drip) before the reload"
else
    echo "not ok 2 - the upload subshell was not alive through the settle window (mistimed or finished early)"
    FAILED=$((FAILED + 1))
fi

if prober_signal_wait HUP "$PROBER_SERVER_PID" "$HOST" "$PORT" \
    "$((5000 * TIMEOUT_SCALE))"; then
    echo "ok 3 - the reload was absorbed while the upload was in flight"
else
    echo "not ok 3 - the reload never landed (no new worker answered)"
    FAILED=$((FAILED + 1))
fi

join_deadline=$(( SECONDS + 15 * TIMEOUT_SCALE ))
while kill -0 "$UPLOAD_PID" 2>/dev/null; do
    if [ "$SECONDS" -ge "$join_deadline" ]; then
        pkill -P "$UPLOAD_PID" 2>/dev/null || true
        kill "$UPLOAD_PID" 2>/dev/null || true
        break
    fi
    sleep 0.1
done
wait "$UPLOAD_PID" 2>/dev/null || true

# A new worker answering does not mean the old upload-serving worker has
# exited. Wait until the old cycle drains before the post-reload rule measures
# descriptors/pool state; otherwise it can sample transient handover state and
# report either false drift or false agreement depending on which worker wins.
DRAIN_RC=0
prober_drain_wait "$PROBER_SERVER_PID" 1 "$((10000 * TIMEOUT_SCALE))" \
    || DRAIN_RC=$?
case "$DRAIN_RC" in
    0) ;;
    2) echo "# old-worker drain check unavailable: pgrep is not installed" ;;
    *) echo "# old upload-serving worker did not drain before post-reload checks"
       FAILED=$((FAILED + 1)) ;;
esac

if grep -q '^HTTP/1.1 200' "$UPLOAD_OUT" \
   && grep -q 'UPLOADED' "$UPLOAD_OUT"; then
    echo "ok 4 - the upload completed intact through cache_turbo across the reload"
else
    echo "not ok 4 - the upload was dropped or truncated by the reload"
    sed 's/^/# /' "$UPLOAD_OUT" | head -20
    FAILED=$((FAILED + 1))
fi

if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "not ok 5 - a worker died by signal across the reload"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    FAILED=$((FAILED + 1))
else
    echo "ok 5 - no worker died by signal across the reload"
fi

"$PROBER_CLIENT" -H "$HOST" -p "$PORT" \
    -t "$((8000 * TIMEOUT_SCALE))" \
    "$PROBER_SCENARIO/post-reload.rule" | sed 's/^/# prober: /'
STATUS=${PIPESTATUS[0]}
if [ "$STATUS" -eq 0 ]; then
    echo "ok 6 - the post-reload worker serves cleanly"
else
    echo "not ok 6 - the post-reload worker did not serve cleanly"
    FAILED=$((FAILED + 1))
fi

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
