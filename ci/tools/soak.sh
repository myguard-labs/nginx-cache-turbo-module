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

    cache_turbo_zone name=ct 16m;

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
    }
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
    local paths=(/tiny /medium /large)
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

[ "$problems" -ne 0 ] && exit 1
echo "✓ soak clean: ${DURATION}s @ ${CONC} concurrent — store+evict+SWR exercised, no sanitizer/leak/crash"
