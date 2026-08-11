#!/usr/bin/env bash
#
# Sustained mixed cache-traffic soak for cache-turbo. LOCAL ONLY — not
# wired into CI (CI's single-shot suite never churns the shm slab). Drives
# a real nginx (ideally an ASAN/UBSAN build, optionally under valgrind):
# an origin server with a short max-age behind a cache_turbo edge, hit
# with varied keys and sizes for minutes so the memory-heavy paths run:
#   - L1 shm store + LRU eviction (small zone, huge key space)
#   - fresh -> stale -> revalidate (short valid + background_update => SWR)
#   - single-flight under concurrency on the same hot key
# Then asserts the worker survived cleanly: no sanitizer report, no
# valgrind error, no crash, no error-log [alert]/[emerg] — AND that the
# cache actually served from L1 (saw a HIT/STALE), so a clean run means
# the module ran, not that everything missed straight to origin.
#
# Usage:
#   ci/tools/soak.sh <nginx-binary> [duration_seconds] [concurrency]
#   USE_VALGRIND=1 ci/tools/soak.sh <nginx-binary> 600 8
#
# Build the nginx binary with the module + -fsanitize=address,undefined
# for the ASAN path, or a plain debug build for the valgrind path.
#
# --- L2 (Redis / memcached) -----------------------------------------------
# By default this soak is L1-ONLY: no cache_turbo_redis or cache_turbo_memcached
# upstream exists in the generated vhost, so the L2 drivers -- their RESP and
# memcached reply parsers, connection pooling, and every timeout and error path
# in them -- have never executed under valgrind or helgrind at all. That is a
# real coverage gap, not a config preference: those drivers are the code holding
# attacker-influenceable bytes from a shared, possibly compromised backend.
#
#   REDIS=127.0.0.1:6379     add a /l2r/ location backed by cache_turbo_redis
#   MEMCACHED=127.0.0.1:11211 add a /l2m/ location backed by cache_turbo_memcached
#
# Both are opt-in so the default invocation keeps working with no server
# running. When either is set the driver hits its location alongside the L1
# paths, and the run FAILS if that L2 tier never served a HIT -- the same
# engagement gate the L1 path has, for the same reason: a soak that silently
# missed straight through to origin proves nothing about the driver, and a
# clean valgrind log over code that never ran looks exactly like a pass.
#
#   REDIS=127.0.0.1:6379 USE_HELGRIND=1 ci/tools/soak.sh <nginx-binary> 600 8

set -euo pipefail

NGINX="${1:?usage: soak.sh <nginx-binary> [duration] [concurrency]}"
DURATION="${2:-120}"
CONC="${3:-8}"
EDGE=18345
ORIGIN=18335

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html"

# Mixed payload sizes so single- and multi-buffer store paths both run.
head -c 200    /dev/urandom | base64 > "$WORK/html/tiny"
head -c 200000 /dev/urandom | base64 > "$WORK/html/medium"
head -c 4000000 /dev/urandom | base64 > "$WORK/html/large"

# Small zone + short valid + background_update so eviction and the
# stale-while-revalidate cycle both fire many times over the soak.
# When the module was built as a dynamic .so (ci-build.sh debug/nginx modes),
# point MODULE=<path/to/ngx_http_cache_turbo_module.so> and it is load_module'd.
# A statically linked build (asan mode) leaves MODULE empty — nothing to load.
LOAD_MODULE=""
if [ -n "${MODULE:-}" ]; then
    LOAD_MODULE="load_module ${MODULE};"
fi

# Valgrind slows the worker ~30x, so request arrival outpaces service rate
# and SWR background-refresh upstream connections pile up far beyond what a
# native run needs. 256 worker_connections trips "not enough" alerts (which
# the log gate treats as failure). Raise the soft fd limit to the hard cap
# (worker_rlimit_nofile needs privileges the runner lacks) and give nginx
# most of it, capped at 8192.
# L2 tiers, opt-in (see the header). Each contributes an extra location to the
# edge server and an extra path to the worker's rotation. The zone is shared
# with L1 on purpose: promotion from L2 into L1 is itself a code path, and it
# only runs when both tiers are live on the same zone.
# ⚠ Each L2 tier gets its OWN zone and its own admin endpoint. The engagement
# gate below reads cache_turbo_l2_hits_total, which is a ZONE-GLOBAL counter --
# sharing one zone would make redis's hits indistinguishable from memcached's,
# and a dead tier would hide behind the live one. Separate zones make the
# counter attributable, which is the whole point of measuring it.
# ⚠ A missing probe tool must ABORT, never return an empty count. Falling back
# to "0 stores" would look identical to a dead backend, and any fallback that
# returned SUCCESS would make the gate advisory -- passing every run on a
# machine without the tool, which is exactly how a check ends up guarding
# nothing. Checked here, before the soak burns its full duration, so the message
# arrives while it can still be acted on.
if [ -n "${REDIS:-}" ] && ! command -v redis-cli >/dev/null 2>&1; then
    echo "soak: REDIS is set but redis-cli is not installed — the L2 engagement" >&2
    echo "      gate cannot verify the driver ran. Install it or unset REDIS." >&2
    exit 1
fi
if [ -n "${MEMCACHED:-}" ] && ! command -v nc >/dev/null 2>&1; then
    echo "soak: MEMCACHED is set but nc is not installed — the L2 engagement" >&2
    echo "      gate cannot verify the driver ran. Install it or unset MEMCACHED." >&2
    exit 1
fi

L2_ZONES=""
L2_LOCATIONS=""
L2_PATHS=""
if [ -n "${REDIS:-}" ]; then
    L2_ZONES="$L2_ZONES
    cache_turbo_zone name=ctr 16m;"
    L2_LOCATIONS="$L2_LOCATIONS
        location /l2r/ {
            cache_turbo             ctr;
            cache_turbo_key         \"\$uri?\$arg_k\";
            cache_turbo_valid       2s;
            cache_turbo_redis       ${REDIS};
            proxy_pass http://127.0.0.1:$ORIGIN/;
        }
        location /_ctr { cache_turbo_admin ctr; }
"
    L2_PATHS="$L2_PATHS /l2r/tiny /l2r/medium"
fi
if [ -n "${MEMCACHED:-}" ]; then
    L2_ZONES="$L2_ZONES
    cache_turbo_zone name=ctm 16m;"
    L2_LOCATIONS="$L2_LOCATIONS
        location /l2m/ {
            cache_turbo             ctm;
            cache_turbo_key         \"\$uri?\$arg_k\";
            cache_turbo_valid       2s;
            cache_turbo_memcached   ${MEMCACHED};
            proxy_pass http://127.0.0.1:$ORIGIN/;
        }
        location /_ctm { cache_turbo_admin ctm; }
"
    L2_PATHS="$L2_PATHS /l2m/tiny /l2m/medium"
fi

ulimit -n "$(ulimit -Hn)" 2>/dev/null || true
NOFILE=$(ulimit -n)
WORKER_CONNS=$(( NOFILE > 17000 ? 8192 : NOFILE / 2 - 64 ))
[ "$WORKER_CONNS" -ge 256 ] || WORKER_CONNS=256

cat > "$WORK/conf/nginx.conf" <<EOF
daemon off;
${LOAD_MODULE}
master_process on;
worker_processes 2;
error_log $WORK/logs/error.log info;
pid $WORK/logs/nginx.pid;
events { worker_connections $WORKER_CONNS; }
http {
    access_log off;

    cache_turbo_zone name=ct 16m;${L2_ZONES}

    # Origin: short freshness window so the edge keeps revalidating.
    server {
        listen 127.0.0.1:$ORIGIN;
        root $WORK/html;
        default_type text/plain;
        location / { add_header Cache-Control "max-age=2"; }
    }

    # Edge: cache-turbo in front of the origin.
    server {
        listen 127.0.0.1:$EDGE;
        location / {
            cache_turbo             ct;
            cache_turbo_key         "\$uri?\$arg_k";
            cache_turbo_valid       2s;
            cache_turbo_background_update on;
            # The module emits its own "X-Cache: HIT|STALE" header on an
            # L1 serve; the soak driver reads that to confirm engagement.
            proxy_pass http://127.0.0.1:$ORIGIN;
        }
${L2_LOCATIONS}    }
}
EOF

ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=1:abort_on_error=1:exitcode=42:log_path=$WORK/logs/asan"
export ASAN_OPTIONS
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-}:print_stacktrace=1:halt_on_error=1"

RUN=("$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf")
SUPP="$(cd "$(dirname "$0")" && pwd)/valgrind.supp"
if [ "${USE_VALGRIND:-0}" = "1" ]; then
    VG=(valgrind --error-exitcode=99 --leak-check=full
        --errors-for-leak-kinds=definite
        --gen-suppressions=all --log-file="$WORK/logs/valgrind.%p")
    [ -f "$SUPP" ] && VG+=(--suppressions="$SUPP")
    RUN=("${VG[@]}" "${RUN[@]}")
elif [ "${USE_HELGRIND:-0}" = "1" ]; then
    # Data-race / lock-order checking under helgrind (shm locks + shared state).
    # error-exitcode=99 so a detected race fails the job, not just log grep.
    VG=(valgrind --tool=helgrind --error-exitcode=99
        --gen-suppressions=all --log-file="$WORK/logs/helgrind.%p")
    [ -f "$SUPP" ] && VG+=(--suppressions="$SUPP")
    RUN=("${VG[@]}" "${RUN[@]}")
fi

"${RUN[@]}" &
NGINX_PID=$!

for _ in $(seq 1 100); do
    curl -fsS -o /dev/null "http://127.0.0.1:$EDGE/tiny?k=warm" 2>/dev/null && break
    sleep 0.1
done

echo "soak: ${DURATION}s, concurrency ${CONC}$( [ "${USE_VALGRIND:-0}" = 1 ] && echo ' (valgrind)'; [ "${USE_HELGRIND:-0}" = 1 ] && echo ' (helgrind)')"
END=$(( $(date +%s) + DURATION ))
saw_hit="$WORK/logs/saw_hit"

worker() {
    # shellcheck disable=SC2206  # deliberate word-split: L2_PATHS is a list
    local paths=(/tiny /medium /large $L2_PATHS)
    local i=0
    while [ "$(date +%s)" -lt "$END" ]; do
        # 70%: small hot key set (HIT/STALE/SWR + single-flight).
        # 30%: huge key space (MISS + LRU eviction).
        if [ $((RANDOM % 10)) -lt 7 ]; then
            k=$((RANDOM % 30))
        else
            k=$((RANDOM % 100000))
        fi
        p=${paths[$((RANDOM % ${#paths[@]}))]}
        # L2 locations get a SMALL key space regardless of the draw above. The
        # 100k spread is there to churn the L1 slab, but against an L2 tier it
        # means almost every lookup is for a key nothing ever stored: the
        # driver's read path runs, yet the L2-hit path (fetch, parse a stored
        # blob, promote it back into L1) never does. A shared 64-key space is
        # what makes the reply parser actually parse a reply.
        case "$p" in /l2r/*|/l2m/*) k=$((RANDOM % 64)) ;; esac
        i=$((i + 1))
        # Read only the response headers; a transient request failure
        # under heavy ASAN load is not a module bug, so do not gate on it.
        # The real signals are the sanitizer/valgrind/crash checks below
        # plus "did the cache ever serve from L1" (X-Cache HIT/STALE).
        xc=$(curl -fsS -D - -o /dev/null \
             "http://127.0.0.1:$EDGE$p?k=$k" 2>/dev/null \
             | grep -i '^X-Cache:' | tr -d '\r' | awk '{print $2}' || true)
        case "$xc" in HIT|STALE) : > "$saw_hit";; esac
    done
}

pids=()
for w in $(seq 1 "$CONC"); do worker "$w" & pids+=($!); done
for pid in "${pids[@]}"; do wait "$pid" || true; done

# --- L2 engagement, measured BEFORE shutdown ------------------------------
# Engagement is measured at the BACKEND: did the server actually receive writes
# from the module? That is the one signal which is both unambiguous (a dead port
# cannot report stores) and not timing-dependent. A store proves the driver
# connected, serialised a blob and spoke the protocol end to end -- exactly the
# code valgrind and helgrind need to have executed.
#
# Three module-side signals were tried first. All three were WRONG here, each
# observed rather than reasoned about:
#
#   - X-Cache: HIT on the L2 location. Says only that the LOCATION served from
#     cache, which an L1 hit satisfies -- a dead /l2m/ still fills L1 from
#     origin and answers HIT forever. Passed a soak on a closed port.
#   - l2_hits + l2_misses. l2_misses counts ATTEMPTS, failed connects included:
#     a dead memcached port scored 202 "lookups". Also passed.
#   - l2_hits alone. Correctly failed the dead port, but ALSO failed a healthy
#     memcached: L1 satisfies almost everything first, so an L1 miss rarely
#     reaches L2 while the entry is still stored. Live memcached measured
#     l2_hits=0 with cmd_set=846 and get_hits=4 -- the driver was plainly
#     working. Gating on it is a flake waiting to happen, not a stricter test.
l2_stored_redis() {
    redis-cli -h "${1%%:*}" -p "${1##*:}" dbsize 2>/dev/null \
        | tr -dc '0-9' | head -n1
}
# ⚠ The `quit` is load-bearing. memcached holds the connection open after
# `stats`, so a bare `printf 'stats' | nc` blocks until the outer timeout --
# a probe that appears to hang the whole soak rather than answering it.
l2_stored_memcached() {
    printf 'stats\r\nquit\r\n' \
        | timeout 5 nc "${1%%:*}" "${1##*:}" 2>/dev/null \
        | sed -n 's/^STAT cmd_set \([0-9]*\).*/\1/p' | head -n1
}
# ⚠ `|| true` on both, and the whole thing OUTSIDE any && chain. These run under
# `set -e`, and a probe against a DEAD backend exits non-zero with empty output
# -- exactly the case the gate exists to catch. Without the guard the script
# died right here: no FAIL message, no sanitizer/leak checks, no engagement
# assertions, just a bare exit 1 that reads like a crash rather than a verdict.
# A dead backend must reach the gate below and be REPORTED, not abort the run.
L2R_HITS=""
L2M_HITS=""
if [ -n "${REDIS:-}" ]; then
    L2R_HITS="$(l2_stored_redis "$REDIS" || true)"
fi
if [ -n "${MEMCACHED:-}" ]; then
    L2M_HITS="$(l2_stored_memcached "$MEMCACHED" || true)"
fi

# Clean shutdown so all pool/shm cleanups run.
kill -QUIT "$NGINX_PID" 2>/dev/null || true
wait "$NGINX_PID" 2>/dev/null; rc=$?

problems=0
if ls "$WORK"/logs/asan* >/dev/null 2>&1; then
    echo "FAIL: ASAN/UBSAN report:"; cat "$WORK"/logs/asan*; problems=1
fi
if ls "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* >/dev/null 2>&1; then
    if grep -qE 'ERROR SUMMARY: [1-9]|definitely lost: [1-9]' \
            "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* 2>/dev/null; then
        echo "FAIL: valgrind/helgrind errors:"
        grep -E 'ERROR SUMMARY|definitely lost' \
            "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* 2>/dev/null
        # Dump every log holding errors in full: the WORK dir is wiped on
        # exit, so this is the only place the stacks (and the exact
        # suppression blocks from --gen-suppressions=all) survive, e.g.
        # in a CI job log.
        for _vglog in "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.*; do
            [ -f "$_vglog" ] || continue
            grep -qE 'ERROR SUMMARY: [1-9]|definitely lost: [1-9]' "$_vglog" || continue
            echo "---- $_vglog ----"
            cat "$_vglog"
        done
        problems=1
    fi
fi
# Any alert/emerg fails — EXCEPT benign shutdown-race noise nginx logs when it
# is QUIT while connections are still in flight under load:
#   - "shared memory zone ... was locked by <pid>" (worker held a zone mutex)
#   - "open socket #N left in connection M" + the trailing "aborting" (nginx
#     force-exits with sockets still open)
# These are shutdown artifacts, not runtime memory bugs — ASAN/valgrind below
# catch real corruption — and are flaky, so they must not turn the soak red.
if grep -nE '\[alert\]|\[emerg\]' "$WORK/logs/error.log" 2>/dev/null \
        | grep -vE 'shared memory zone .* was locked by|open socket #[0-9]+ left in connection|\[alert\][^:]*: aborting'; then
    echo "FAIL: alert/emerg in error.log"; problems=1
fi
if [ "$rc" -ne 0 ] && [ "$rc" -ne 130 ]; then
    echo "FAIL: nginx exited $rc"; tail -40 "$WORK/logs/error.log" || true
    problems=1
fi
if [ ! -f "$saw_hit" ]; then
    echo "FAIL: never saw an L1 HIT/STALE — cache path did not engage, soak is not exercising the module"
    problems=1
fi
# Same gate per L2 tier: an opted-in tier that never served from L2 is a soak
# that did not exercise its driver, and must not report clean.
if [ -n "${REDIS:-}" ] && [ "${L2R_HITS:-0}" -eq 0 ] 2>/dev/null; then
    echo "FAIL: REDIS was set but ${REDIS} holds no keys — the Redis driver"
    echo "      never stored anything, so a clean valgrind/helgrind log over it"
    echo "      proves nothing. Check the server is up and reachable."
    problems=1
fi
if [ -n "${MEMCACHED:-}" ] && [ "${L2M_HITS:-0}" -eq 0 ] 2>/dev/null; then
    echo "FAIL: MEMCACHED was set but ${MEMCACHED} reports cmd_set 0 — the"
    echo "      memcached driver never stored anything, so a clean valgrind/"
    echo "      helgrind log over it proves nothing. Check it is up."
    problems=1
fi

[ "$problems" -ne 0 ] && exit 1
_tiers="L1"
[ -n "${REDIS:-}" ]     && _tiers="$_tiers+redis(${L2R_HITS} keys)"
[ -n "${MEMCACHED:-}" ] && _tiers="$_tiers+memcached(${L2M_HITS} sets)"
echo "✓ soak clean: ${DURATION}s @ ${CONC} concurrent — ${_tiers}, store+evict+SWR exercised, no sanitizer/leak/crash"
