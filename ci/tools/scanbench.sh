#!/bin/sh
# S8 scan-resistance measurement: hot-set HIT% survival across a one-shot scan.
#
# bench.sh CANNOT measure this: it primes every key before measuring, so HIT%
# is ~100 by construction and there is no scan stream. Here the zone is sized
# so that hot set + scan does NOT fit -- the scan must force eviction, which is
# the only condition under which segmented LRU can differ from flat LRU.
#
# Protocol per arm (scan_resistant on|off), zone freshly created each arm:
#   1. prime HOT hot keys, then touch each twice so they are eligible for
#      promotion to PROTECTED (S8 promotes on touch, not on store)
#   2. stream SCAN one-shot keys (each requested once, like a crawler)
#   3. re-request the hot set; HIT% is the measurement
#
# Reports median of PASSES per arm.
#
# Usage:
#   ci/tools/scanbench.sh <nginx-binary> <module.so>
#   ZONE=512k HOT=50 SCAN=800 PASSES=5 ci/tools/scanbench.sh ...
#
# MEASURED 2026-07-20 (nginx 1.31.1, ZONE=512k HOT=50 BODY=1024, median of 5,
# SCAN in {200, 800, 2000} -- 15 runs, zero variance):
#
#   off  hot-set HIT%:  0.0
#   on   hot-set HIT%: 82.0      delta +82.0 pp
#
# The 82% is STRUCTURAL, not a workload artifact: protected_pct defaults to 80
# (NGX_HTTP_CACHE_TURBO_PROTECTED_PCT_DEFAULT), so the protected queue is capped
# at 80% of the zone and the hot set survives up to that cap. That is why the
# figure does not move across a 10x range of scan sizes.
#
# ⚠ Two ways this harness silently measures NOTHING. Both were hit while
# writing it; both produce a plausible-looking "0.0 vs 0.0, no difference":
#
#   1. NO SLEEP BETWEEN TOUCHES -> nothing is ever promoted (see run_arm).
#   2. SCAN/ZONE ratio too high -> the scan evicts the protected set too, so
#      both arms read 0%. Too low and the zone holds everything, so both read
#      100%. The pre-scan precondition catches (1)-style priming failures; a
#      0-vs-0 or 100-vs-100 result means re-tune ZONE/SCAN, not "no effect".
set -eu

NGINX="${1:?usage: scanbench.sh <nginx-binary> <module.so>}"
MODULE="${2:?usage: scanbench.sh <nginx-binary> <module.so>}"

HOT="${HOT:-200}"          # hot keys, requested repeatedly
SCAN="${SCAN:-4000}"       # one-shot scan keys (the crawler)
ZONE="${ZONE:-2m}"         # small on purpose: hot+scan must NOT fit
BODY="${BODY:-1024}"       # body bytes per key
PASSES="${PASSES:-5}"      # median of N

WORK="$(mktemp -d /tmp/ct-scanbench-XXXXXX)"
cleanup() {
    trap - EXIT INT TERM     # disarm first: `kill 0` in a trap re-enters it
    if [ -n "${NGX_PID:-}" ] && [ "${NGX_PID:-0}" -gt 1 ]; then
        kill "$NGX_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html"

PORT=19310
ORIGIN=19311

# Origin body: fixed size, long freshness so nothing revalidates mid-run.
awk -v n="$BODY" 'BEGIN{s="";while(length(s)<n)s=s "x";print substr(s,1,n)}' \
    > "$WORK/html/body.txt"

emit_conf() {  # $1 = on|off
    cat > "$WORK/conf/nginx.conf" <<EOF
daemon off;
load_module $(realpath "$MODULE");
master_process on;
worker_processes 1;
error_log $WORK/logs/error.log error;
pid $WORK/logs/nginx.pid;
events { worker_connections 1024; }
http {
    # Status is read from the ACCESS LOG, not from an add_header readback.
    # The status variable is documented as a LOGGING variable, resolved after
    # the header filter runs, so an add_header copy of it reads MISS even on a
    # request the debug log shows as "L1 HIT (fresh)". The access log is the
    # sanctioned read point and agrees with the module's own decisions.
    # NB: this heredoc is UNQUOTED - every nginx variable, in config AND in
    # comments, must be backslash-escaped or the shell eats it under set -u.
    log_format ct '\$uri\$is_args\$args \$cache_turbo_status';
    access_log $WORK/logs/access.log ct;
    cache_turbo_zone name=ct $ZONE;
    server {
        listen 127.0.0.1:$ORIGIN;
        root $WORK/html;
        default_type text/plain;
        location / { add_header Cache-Control "max-age=600"; try_files /body.txt =404; }
    }
    server {
        listen 127.0.0.1:$PORT;
        location / {
            cache_turbo       ct;
            cache_turbo_key   \$uri\$is_args\$args;
            cache_turbo_valid 300s;
            cache_turbo_scan_resistant $1;
            proxy_pass http://127.0.0.1:$ORIGIN;
        }
    }
}
EOF
}

start_nginx() {
    "$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf" >"$WORK/logs/stdout.log" 2>&1 &
    NGX_PID=$!
    i=0
    while [ "$i" -lt 100 ]; do
        if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$PORT/hot?k=probe" 2>/dev/null; then
            return 0
        fi
        i=$((i+1)); sleep 0.1
    done
    echo "FATAL: nginx did not come up" >&2
    sed -n '1,20p' "$WORK/logs/error.log" >&2
    exit 1
}

stop_nginx() { kill "$NGX_PID" 2>/dev/null || true; wait "$NGX_PID" 2>/dev/null || true; }

# Batch requester: one curl invocation for many URLs. A curl-per-key loop is far
# too slow at SCAN=4000. Statuses are NOT read from here -- see log_mark/log_hits.
# NB: `-o /dev/null` on the command line does NOT apply to URLs supplied via a
# -K config; each url line needs its own `output`, or the response BODY lands on
# stdout. (Cost an hour: HOT=50 read back as 99 "responses".)
batch() {  # stdin = paths
    sed "s#^#url = \"http://127.0.0.1:$PORT#; s#\$#\"\noutput = \"/dev/null\"#" \
      | curl -s -K - -o /dev/null 2>/dev/null || true
}

# Access-log cursor: remember the line count, then count HITs written after it.
log_mark() { wc -l < "$WORK/logs/access.log" 2>/dev/null || echo 0; }
log_since() {  # $1 = mark -> emits the status column of lines after the mark
    sleep 0.3   # access_log is buffered per-request but written by the worker
    tail -n +"$(( $1 + 1 ))" "$WORK/logs/access.log" 2>/dev/null \
      | awk '$1 ~ /^\/hot/ {print $2}'
}

seqp() { awk -v n="$1" -v p="$2" 'BEGIN{for(i=0;i<n;i++)print p i}'; }

run_arm() {  # $1 = on|off  -> prints hot-set HIT%
    emit_conf "$1"
    start_nginx

    # 1. prime + two touches so the hot set is promotion-eligible.
    #
    # THE 1.2s SLEEPS ARE LOAD-BEARING. Promotion needs a SECOND hit, and the P1
    # coarse re-splice gate only fires when now - last_access >= 1s. Batched
    # touches land within milliseconds of each other, so the gate swallows every
    # one, NOTHING is promoted, and both arms degenerate to flat LRU -- which
    # reports a real-looking "0.0 vs 0.0, no difference" that proves nothing.
    # (_s8_hot_status in ci/tools/test_runtime.py sleeps for exactly this reason.)
    seqp "$HOT" "/hot?k=" | batch >/dev/null      # store -> probation
    sleep 1.2
    seqp "$HOT" "/hot?k=" | batch >/dev/null      # 1st touch
    sleep 1.2
    seqp "$HOT" "/hot?k=" | batch >/dev/null      # 2nd touch -> PROTECTED if on

    # PRECONDITION: the hot set must be cached BEFORE the scan. Without this
    # assert, a run where priming silently failed reports 0% for both arms and
    # looks like "no difference" -- the s72 vacuous-test trap in mirror image.
    m=$(log_mark)
    seqp "$HOT" "/hot?k=" | batch
    log_since "$m" > "$WORK/pre.txt"
    pre_hits=$(grep -c '^HIT$' "$WORK/pre.txt" || true)
    pre_tot=$(grep -c . "$WORK/pre.txt" || true)
    echo "  [$1] pre-scan hot HIT: $pre_hits/$pre_tot" >&2
    [ "$pre_hits" -eq "$HOT" ] || {
        echo "FATAL: arm $1 hot set not fully cached before the scan" >&2
        echo "       ($pre_hits/$HOT HIT) -- the scan result would be vacuous." >&2
        exit 1
    }

    # 2. the crawler: every scan key requested exactly once
    seqp "$SCAN" "/scan?k=" | batch

    # 3. measure hot-set survival
    m=$(log_mark)
    seqp "$HOT" "/hot?k=" | batch
    log_since "$m" > "$WORK/final.txt"

    hits=$(grep -c '^HIT$' "$WORK/final.txt" || true)
    tot=$(grep -c . "$WORK/final.txt" || true)
    stop_nginx
    [ "$tot" -gt 0 ] || { echo "FATAL: no responses parsed in arm $1" >&2; exit 1; }
    [ "$tot" -eq "$HOT" ] || echo "WARN: arm $1 parsed $tot responses, expected $HOT" >&2
    awk -v h="$hits" -v t="$tot" 'BEGIN{printf "%.1f\n", 100*h/t}'
}

median() { sort -n | awk '{a[NR]=$1} END{print (NR%2)?a[(NR+1)/2]:(a[NR/2]+a[NR/2+1])/2}'; }

echo "S8 scan-resistance: HOT=$HOT SCAN=$SCAN ZONE=$ZONE BODY=$BODY PASSES=$PASSES"
echo

for arm in off on; do
    : > "$WORK/res.$arm"
    p=1
    while [ "$p" -le "$PASSES" ]; do
        run_arm "$arm" >> "$WORK/res.$arm"
        p=$((p+1))
    done
    printf '%-4s hot-set HIT%%: %s   (passes: %s)\n' \
        "$arm" "$(median < "$WORK/res.$arm")" "$(tr '\n' ' ' < "$WORK/res.$arm")"
done

off_m=$(median < "$WORK/res.off")
on_m=$(median < "$WORK/res.on")
echo
awk -v o="$off_m" -v n="$on_m" 'BEGIN{printf "delta (on - off): %+.1f pp\n", n-o}'
