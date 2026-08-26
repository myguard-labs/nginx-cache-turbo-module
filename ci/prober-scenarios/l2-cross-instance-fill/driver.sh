#!/usr/bin/env bash
#
# Scenario: L2 CROSS-INSTANCE FILL, under the testkit prober.
#
# WHAT THIS EXISTS TO DO
#   Read the text of SRV-ASAN-ABORT-L2-XFILL. CI run 32906728011 failed BOTH
#   ASan legs of this repo's own python suite inside
#   test_l2_cross_instance_fill: the single-process leg reported `nginx exited
#   with -6` (SIGABRT) at admin.py:1887 `b.stop()`, the multi-worker leg an
#   `AddressSanitizer` marker at :1888 `b.assert_clean_logs()`. The TEXT of
#   neither report has ever been read, across four cycles, because the python
#   suite deletes its tmpdir on the way out (test_runtime.py:586) and has no
#   --keep-temp. The diagnostic is destroyed by the harness that produced it.
#
#   Under the prober that cannot happen. lib.sh:1225-1314 keeps BOTH the
#   redirected error_log AND the pre-redirect server.err, and lib.sh:1424
#   treats a sanitizer report as FATAL and never exemptable -- PROBER_ALLOW_LOG
#   cannot reach it. So if the abort reproduces here, its text survives.
#
#   Both instances' logs live under $PROBER_PREFIX, which the harness's cleanup
#   removes only after the driver has finished -- and this driver copies
#   instance B's logs next to instance A's before it returns, so B's
#   diagnostic is scraped by the same fatal-sanitizer gate that covers A.
#   That copy is the load-bearing step: prober_scrape_log reads exactly two
#   files, and B is not one of them.
#
# THE SHAPE BEING EXERCISED
#   A (this scenario's prober-booted server) serves /l2/p2 cold: MISS ->
#   origin -> writes L1 + L2 (Redis).
#   B (booted by THIS driver, own prefix, own port, own cold L1, SAME Redis
#   and SAME origin) then serves /l2/p2. It must answer from the shared L2
#   without a second origin visit. Then B is stopped -- and stopping B is
#   precisely where the python suite aborted.
#
# ⚠ IT MAY NOT REPRODUCE. The python suite and the prober drive different
#   paths: different conf, different request pattern, different shutdown
#   sequencing. A non-repro here is a RECORDED FINDING, not evidence the bug
#   is absent, and this driver reports it as such -- an explicit "no sanitizer
#   report was produced" oracle, never a silent pass.
#
# WHY THE ORACLE COUNTS ORIGIN VISITS RATHER THAN COMPARING BODIES
#   There is one origin, so a genuine L2 fill and a plain origin refetch
#   return byte-identical bodies. `body_b == body_a` is satisfied by both and
#   is therefore a vacuous oracle for the property under test. The
#   distinguishing observable is that a real L2 fill does NOT visit the
#   origin, so the origin access-log line count is the oracle.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"

export PROBER_ERROR_LOG="$ELOG"

URI=/l2/p2
ORIGIN_LOG="$PROBER_PREFIX/logs/origin.log"

# The objs/ dir, derived from the ONE path the driver contract guarantees is
# exported: PROBER_SERVER_BIN. PROBER_RESOLVED_BUILD and PROBER_MODULE_PATH are
# lib.sh internals -- set by prober_resolve, never exported to drivers -- so
# reading them here is an unbound-variable death under `set -u`. The server
# binary lives in objs/ alongside both .so, which is the whole premise of the
# staged tree, so its dirname IS the objs dir.
OBJS="$(dirname "$PROBER_SERVER_BIN")"

# Instance B's own prefix, INSIDE the run prefix so the harness's cleanup
# reaps it, and its port well clear of A's and of the Redis port env picked
# (A+21). +40 leaves room and stays inside the run's band.
B_PREFIX="$PROBER_PREFIX/instance-b"
B_PORT=$(( PORT + 40 ))
B_ELOG="$B_PREFIX/logs/error.log"
B_ERR="$B_PREFIX/logs/server.err"
B_PID=""

# ---- reap everything this scenario started ----------------------------------
# The harness's prober_cleanup removes the run PREFIX and stops the server IT
# booted. It knows nothing about the Redis started by this scenario's `env`
# file, nor about instance B started below -- both are this driver's
# responsibility, and a leaked one is not a cosmetic untidiness: the next run
# computes the SAME Redis port from the same base port, finds the leftover
# still listening, and silently inherits its keys. Instance A's "cold" first
# request then comes back with an Age: and X-Cache: STALE, and every L2 oracle
# measures a warm cache while reporting green. That happened during
# development of this scenario; the trap and the port check in `env` are the
# two halves of the fix.
#
# EXIT only (not the signal list): the trap must run once, on the single path
# out of a driver whose exit status IS the scenario's TAP result.
# shellcheck disable=SC2317  # invoked by the EXIT trap below, not inline
ct_reap() {
    local rc=$?
    if [ -n "${B_PID:-}" ] && kill -0 "$B_PID" 2>/dev/null; then
        kill -TERM "$B_PID" 2>/dev/null || true
        for _r in $(seq 1 40); do
            kill -0 "$B_PID" 2>/dev/null || break
            sleep 0.05
        done
        kill -KILL "$B_PID" 2>/dev/null || true
    fi
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

echo "1..7"

fail() { echo "not ok $1 - $2"; FAILED=1; }
FAILED=0

# origin_hits: exact count of visits to /origin, from the access log the conf
# writes one line per visit into. An absent file means zero visits so far,
# which is a legitimate state (nginx creates it lazily), NOT an error.
origin_hits() {
    [ -f "$ORIGIN_LOG" ] && wc -l < "$ORIGIN_LOG" || echo 0
}

# get URI PORT OUTFILE -- one bounded GET, raw response captured. Same
# bounded-subshell-kill shape as the sibling consumer scenario's one_request:
# a hung fetch must not hang the scenario, and a truncated capture must not be
# trusted as a completed request.
get() {
    local uri="$1" port="$2" out="$3" pid dl
    (
        exec 3<>"/dev/tcp/$HOST/$port" || exit 1
        printf 'GET %s HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' "$uri" >&3
        cat <&3 2>/dev/null || true
    ) >"$out" 2>/dev/null &
    pid=$!
    dl=$(( SECONDS + 15 ))
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

hdr() {   # hdr FILE NAME -> lowercased header value, empty if absent
    tr -d '\r' < "$1" | awk -v n="$2" '
        BEGIN { IGNORECASE = 1 }
        /^$/  { exit }
        index(tolower($0), tolower(n) ":") == 1 {
            sub(/^[^:]*:[ \t]*/, ""); print tolower($0); exit
        }'
}

# ---- 1: the Redis fixture is actually up ------------------------------------
# Checked as an ORACLE, not assumed. A dead Redis makes every L2 assertion
# below fail in a way that reads exactly like a module defect -- this repo has
# already paid for that once (a stale Redis squatting the port reported as an
# outage). Failing here names the fixture instead.
if [ "${CT_REDIS_UP:-0}" = "1" ]; then
    echo "ok 1 - the Redis fixture accepted a connection on port ${CT_REDIS_PORT:-?}"
else
    fail 1 "Redis fixture never accepted on port ${CT_REDIS_PORT:-?} -- every L2 oracle below would misreport a fixture outage as a module defect"
fi

# ---- 2: A serves the object cold, from the origin ---------------------------
A_OUT="$PROBER_PREFIX/a.out"
if [ "$FAILED" -eq 0 ] && get "$URI" "$PORT" "$A_OUT"; then
    echo "ok 2 - instance A served $URI cold with a clean 200"
else
    fail 2 "instance A did not serve $URI (cold origin fetch failed)"
fi

# Let A's write-through to L2 land. The store is asynchronous with respect to
# the response, so a bounded wait on the Redis key is the correct gate -- not
# a sleep, and not "assume it is there".
A_STORED=0
if [ "$FAILED" -eq 0 ]; then
    for _i in $(seq 1 100); do
        if redis-cli -h "$HOST" -p "$CT_REDIS_PORT" --scan --pattern '*' 2>/dev/null | grep -q . ; then
            A_STORED=1
            break
        fi
        sleep 0.05
    done
fi

ORIGIN_AFTER_A="$(origin_hits)"

# ---- 3: A wrote the object through to L2 ------------------------------------
# Anti-vacuity for oracle 5: if nothing reached Redis, B cannot possibly fill
# from L2, and "B did not hit the origin" would be measuring the wrong thing.
if [ "$FAILED" -eq 0 ] && [ "$A_STORED" -eq 1 ]; then
    echo "ok 3 - instance A wrote the object through to the shared L2 (Redis)"
else
    fail 3 "instance A never wrote anything to L2 -- the cross-instance fill under test cannot occur"
fi

# ---- boot instance B --------------------------------------------------------
# Rendered from the SAME template as A, with B's own port and prefix. The
# error_log path is B's own, so B's diagnostic does not interleave with A's.
if [ "$FAILED" -eq 0 ]; then
    mkdir -p "$B_PREFIX/logs"
    # @LOAD@ for B. PROBER_LOAD is set by prober_detect_load but NOT exported
    # to drivers, so it is recomputed here from the two facts that ARE
    # exported. The empty case is real and must be preserved: a statically
    # linked (asan/coverage) build has the probe compiled IN, and emitting a
    # load_module line for it would kill B's config test with a duplicate
    # module. Mirrors lib.sh:194-199.
    B_LOAD=""
    if [ -n "${PROBER_MODULE:-}" ] && [ -f "$OBJS/${PROBER_MODULE}" ]; then
        B_LOAD="load_module $OBJS/${PROBER_MODULE};"
    fi

    sed -e "s#@REDIS_PORT@#${CT_REDIS_PORT}#g" \
        -e "s#@LOAD@#${B_LOAD}#" \
        -e "s#@BUILD_OBJS@#${OBJS}#" \
        -e "s#@PORT@#${B_PORT}#g" \
        -e "s#@PREFIX@#${B_PREFIX}#g" \
        -e "s#@PROBE@#${PROBER_PROBE:-}#" \
        -e "s#@PROBE_ZONE@#${PROBER_PROBE_ZONE:-}#" \
        "$CT_SCENARIO_DIR/instance-a.conf.in" > "$B_PREFIX/nginx.conf"

    # ⚠ B's origin proxy_pass now points at B's OWN port, because @PORT@ was
    # substituted with B_PORT throughout. That is deliberate and it is what
    # makes the origin-visit oracle work at all: B has its own /origin
    # location and its own access_log, so a refetch by B lands in B's log, not
    # A's. Oracle 5 therefore checks BOTH -- A's count must not move (B did
    # not reach across) and B's must stay empty (B did not refetch locally).

    # Config test first, exactly as the harness does for A: a conf error must
    # be reported as a conf error, not as a boot timeout.
    if ! "$PROBER_SERVER_BIN" -t -p "$B_PREFIX" -c "$B_PREFIX/nginx.conf" \
            > "$B_PREFIX/logs/conftest.out" 2>&1; then
        fail 4 "instance B failed its config test: $(tr '\n' ' ' < "$B_PREFIX/logs/conftest.out" | tail -c 400)"
    else
        "$PROBER_SERVER_BIN" -p "$B_PREFIX" -c "$B_PREFIX/nginx.conf" \
            > "$B_ERR" 2>&1 &
        B_PID=$!
        # Bounded wait for B's listener.
        B_UP=0
        for _i in $(seq 1 200); do
            if (exec 3<>"/dev/tcp/$HOST/$B_PORT") 2>/dev/null; then B_UP=1; break; fi
            kill -0 "$B_PID" 2>/dev/null || break
            sleep 0.05
        done
        if [ "$B_UP" -eq 1 ]; then
            echo "ok 4 - instance B booted with a cold L1 against the shared L2"
        else
            fail 4 "instance B never accepted on port $B_PORT (died during startup? see server.err)"
        fi
    fi
fi

# ---- 5: B fills from L2 without a second origin visit -----------------------
B_OUT="$B_PREFIX/b.out"
B_ORIGIN_LOG="$B_PREFIX/logs/origin.log"
if [ "$FAILED" -eq 0 ] && get "$URI" "$B_PORT" "$B_OUT"; then
    xc="$(hdr "$B_OUT" x-cache)"
    a_now="$(origin_hits)"
    b_hits=0
    [ -f "$B_ORIGIN_LOG" ] && b_hits="$(wc -l < "$B_ORIGIN_LOG")"
    if [ "$xc" = "hit" ] && [ "$a_now" -eq "$ORIGIN_AFTER_A" ] && [ "$b_hits" -eq 0 ]; then
        echo "ok 5 - instance B served the object from the shared L2 (X-Cache: hit, no origin visit on either instance)"
    else
        fail 5 "B did not fill from L2: X-Cache='$xc' A-origin=$a_now (was $ORIGIN_AFTER_A) B-origin=$b_hits"
    fi
elif [ "$FAILED" -eq 0 ]; then
    fail 5 "instance B did not serve $URI at all"
fi

# ---- 6: stopping B -- THE STEP THE PYTHON SUITE ABORTED IN ------------------
# admin.py:1887 `b.stop()` is where the single-process ASan leg reported
# `nginx exited with -6`. SIGTERM, then a bounded wait, then the exit status
# is INSPECTED rather than discarded: a signal death here is the finding.
B_RC=""
B_SIGNAL=""
if [ -n "$B_PID" ] && kill -0 "$B_PID" 2>/dev/null; then
    kill -TERM "$B_PID" 2>/dev/null || true
    dl=$(( SECONDS + 20 ))
    while kill -0 "$B_PID" 2>/dev/null; do
        if [ "$SECONDS" -ge "$dl" ]; then
            kill -KILL "$B_PID" 2>/dev/null || true
            break
        fi
        sleep 0.05
    done
    set +e
    wait "$B_PID"
    B_RC=$?
    set -e
    # 128+N is the shell's encoding of "died by signal N". 134 = SIGABRT,
    # which is exactly what an ASan/UBSan halt_on_error abort produces and
    # exactly what the python suite saw as "-6".
    if [ "$B_RC" -gt 128 ]; then
        B_SIGNAL=$(( B_RC - 128 ))
    fi
fi

if [ -z "$B_RC" ]; then
    echo "ok 6 - instance B was already stopped before the teardown (nothing to signal)"
elif [ -n "$B_SIGNAL" ]; then
    fail 6 "instance B DIED BY SIGNAL $B_SIGNAL on shutdown (exit $B_RC) -- this is the SRV-ASAN-ABORT-L2-XFILL shape; the diagnostic follows below and in $B_ELOG / $B_ERR"
else
    echo "ok 6 - instance B shut down cleanly on SIGTERM (exit $B_RC, no signal death)"
fi

# ---- 7: B's logs carry no sanitizer report ----------------------------------
# The scenario's REASON FOR EXISTING. prober_scrape_log covers instance A's
# two log files only, so B's are checked here explicitly AND copied next to
# A's so the harness's own fatal-sanitizer gate sees them too. Belt and
# braces deliberately: a sanitizer report that is found by neither gate is the
# exact failure this whole exercise is correcting.
SAN_RE='(AddressSanitizer|LeakSanitizer|ThreadSanitizer|UndefinedBehaviorSanitizer|SUMMARY: .*Sanitizer|runtime error:)'
B_SAN=""
for f in "$B_ELOG" "$B_ERR"; do
    [ -f "$f" ] || continue
    if grep -Eqa "$SAN_RE" "$f"; then
        B_SAN="${B_SAN}
=== sanitizer report in $f ==="
        B_SAN="${B_SAN}
$(grep -Ea -A 40 "$SAN_RE" "$f")"
    fi
done

# Copy B's logs where prober_scrape_log will also read them. Appended, never
# overwriting: A's own error_log content must survive.
for f in "$B_ELOG" "$B_ERR"; do
    [ -f "$f" ] || continue
    {
        echo "--- instance B ($f) ---"
        cat "$f"
    } >> "$PROBER_PREFIX/logs/server.err" 2>/dev/null || true
done

if [ -n "$B_SAN" ]; then
    # Printed as TAP diagnostics (# prefixed) so the text reaches the run's
    # output verbatim and is not mistaken for TAP protocol lines.
    printf '%s\n' "$B_SAN" | sed 's/^/# /'
    fail 7 "a SANITIZER REPORT was produced by instance B -- text above, and in $B_ELOG / $B_ERR"
else
    echo "ok 7 - instance B produced no sanitizer report in its error_log or server.err"
    # NOT a claim that the bug is absent. If this scenario is running against
    # an UNSANITIZED tree, oracle 7 is vacuous by construction -- there is no
    # sanitizer runtime to report anything. Say so, visibly, rather than
    # letting a green line imply a clean sanitizer run.
    if [ "${PROBER_SANITIZED:-0}" != "1" ]; then
        echo "# NOTE: this tree is NOT sanitized (PROBER_SANITIZED=${PROBER_SANITIZED:-unset})."
        echo "# Oracle 7 is vacuous here -- it can only ever pass. Run this scenario via"
        echo "# ci/tools/testkit-run.sh --sanitizer for it to mean anything."
    fi
fi

exit "$FAILED"
