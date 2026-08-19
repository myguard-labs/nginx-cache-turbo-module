#!/bin/sh
# Zipf-distributed multi-key hit-ratio + throughput measurement.
#
# bench.sh and scanbench.sh CANNOT measure this: bench.sh primes every key
# before measuring (~100% HIT by construction, single hot key); scanbench.sh
# is a one-shot crawl, not a steady-state key distribution. Neither can
# validate anything about admission policy, eviction ordering or working-set
# sizing (PLAN-optimize.md P3-1 scan-resistance, P4-1 W-TinyLFU admission,
# P4-2 lock residency, P4-5 buffer chunking all need a real key distribution
# under real concurrency). This harness generates one: a Zipf(s) request
# stream over a configurable key-space, driven by multiple concurrent
# workers, with NO priming pass -- misses happen because the distribution and
# the zone size say they should.
#
# Reports, per run:
#   HIT ratio           -- from the EDGE access log ($cache_turbo_status)
#   p50 / p99 latency    -- from curl-measured per-request wall time
#   ORIGIN REQUEST COUNT -- from the ORIGIN's own access log, not inferred
#                           from client-side status. This is the number that
#                           matters most: it is the real offload figure, and
#                           an edge-side HIT/MISS count can be wrong under
#                           concurrent fills, single-flight collapsing, or a
#                           counter that races the response write.
#
# Usage:
#   ci/tools/zipfbench.sh <nginx-binary> <module.so>
#   KEYS=5000 ZIPF_S=1.05 ZONE=8m WORKERS=8 REQS=20000 zipfbench.sh ...
#
# Key knobs (env):
#   KEYS      size of the key-space                       (default 5000)
#   ZIPF_S    Zipf exponent -- higher = more skewed/hot    (default 1.0)
#   ZONE      cache_turbo zone size                        (default 8m)
#   BODY      body bytes per key                           (default 2048)
#   WORKERS   concurrent client workers (xargs -P)          (default 8)
#   REQS      total requests issued                        (default 20000)
#   PASSES    measured passes, reports median               (default 1)
#
# Sizing KEYS*BODY against ZONE is what puts the run into or out of the
# eviction regime on purpose -- see "Choosing parameters" in BENCHMARK.md.
#
# ⚠ TWO SELF-INVALIDATION TRAPS, copied from scanbench.sh because they are
# the same failure mode restated for a Zipf workload. Both were caught while
# writing this harness; both produce a plausible-looking but MEANINGLESS
# number instead of an error:
#
#   1. ZONE way bigger than KEYS*BODY -> the whole key-space fits, nothing is
#      ever evicted, HIT ratio saturates near 100% regardless of ZIPF_S or
#      admission policy. A "100% HIT, looks great" result here proves the
#      harness is not exercising eviction at all, not that the config is good.
#   2. ZONE way smaller than the Zipf head (the few hottest keys), or REQS
#      too low to let the hot keys accumulate repeat hits before their first
#      eviction -- the effective working set never survives long enough to
#      register a HIT, and every arm reads ~0% regardless of what is being
#      compared. That reads as "no difference" and is actually "measured
#      nothing".
#
#   A result of 0-vs-0 or 100-vs-100 between two configurations you expected
#   to differ means RE-TUNE ZONE/KEYS/ZIPF_S/REQS, not "no effect". This
#   script checks for exactly those two degenerate bands on every run and
#   prints "INVALID RUN" instead of a clean-looking number when it detects one.
set -eu

NGINX="${1:?usage: zipfbench.sh <nginx-binary> <module.so>}"
MODULE="${2:?usage: zipfbench.sh <nginx-binary> <module.so>}"

KEYS="${KEYS:-5000}"
ZIPF_S="${ZIPF_S:-1.0}"
ZONE="${ZONE:-8m}"
BODY="${BODY:-2048}"
WORKERS="${WORKERS:-8}"
REQS="${REQS:-20000}"
PASSES="${PASSES:-1}"

case "$KEYS" in ''|*[!0-9]*) echo "FATAL: KEYS must be a positive integer" >&2; exit 2;; esac
case "$WORKERS" in ''|*[!0-9]*) echo "FATAL: WORKERS must be a positive integer" >&2; exit 2;; esac
case "$REQS" in ''|*[!0-9]*) echo "FATAL: REQS must be a positive integer" >&2; exit 2;; esac
case "$PASSES" in ''|*[!0-9]*) echo "FATAL: PASSES must be a positive integer" >&2; exit 2;; esac

command -v python3 >/dev/null 2>&1 || { echo "FATAL: python3 not found (needed for the Zipf sampler)" >&2; exit 2; }

WORK="$(mktemp -d /tmp/ct-zipfbench-XXXXXX)"
cleanup() {
    trap - EXIT INT TERM
    if [ -n "${NGX_PID:-}" ] && [ "${NGX_PID:-0}" -gt 1 ]; then
        kill "$NGX_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html"

PORT=19320
ORIGIN=19321

awk -v n="$BODY" 'BEGIN{s="";while(length(s)<n)s=s "x";print substr(s,1,n)}' \
    > "$WORK/html/body.txt"

cat > "$WORK/conf/nginx.conf" <<EOF
daemon off;
load_module $(realpath "$MODULE");
master_process on;
worker_processes auto;
error_log $WORK/logs/error.log error;
pid $WORK/logs/nginx.pid;
events { worker_connections 4096; }
http {
    # Edge status read from the access log, same rationale as scanbench.sh:
    # \$cache_turbo_status is a logging variable resolved after the header
    # filter, so an add_header readback of it is stale/wrong on the very
    # request that just decided HIT vs MISS.
    log_format ct '\$uri\$is_args\$args \$cache_turbo_status';
    access_log $WORK/logs/access.log ct;
    cache_turbo_zone name=zk $ZONE;
    server {
        # Origin has its OWN access log with NO cache-status field --
        # this is the ground truth for how many requests actually reached
        # it, independent of anything the edge believes about itself.
        listen 127.0.0.1:$ORIGIN;
        access_log $WORK/logs/origin.log;
        root $WORK/html;
        default_type text/plain;
        location / { add_header Cache-Control "max-age=300"; try_files /body.txt =404; }
    }
    server {
        listen 127.0.0.1:$PORT;
        location / {
            cache_turbo       zk;
            cache_turbo_key   \$uri\$is_args\$args;
            cache_turbo_valid 300s;
            proxy_pass http://127.0.0.1:$ORIGIN;
        }
    }
}
EOF

start_nginx() {
    "$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf" >"$WORK/logs/stdout.log" 2>&1 &
    NGX_PID=$!
    i=0
    while [ "$i" -lt 100 ]; do
        if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$PORT/zk?k=probe" 2>/dev/null; then
            return 0
        fi
        i=$((i+1)); sleep 0.1
    done
    echo "FATAL: nginx did not come up" >&2
    sed -n '1,20p' "$WORK/logs/error.log" >&2
    exit 1
}
stop_nginx() { kill "$NGX_PID" 2>/dev/null || true; wait "$NGX_PID" 2>/dev/null || true; }

# Zipf(s) key stream over [0, KEYS). Uses the standard rejection sampler
# (Zipf via inverse CDF approximation is not exact enough at small n; this
# is the well-known Devroye/"Rejection-Inversion" style loop, simplified),
# emitted as REQS lines. Deterministic-ish (seeded) so a re-run is comparable.
gen_stream() {
    python3 - "$KEYS" "$ZIPF_S" "$REQS" <<'PYEOF'
import random, sys
n, s, reqs = int(sys.argv[1]), float(sys.argv[2]), int(sys.argv[3])
random.seed(1234)
# Precompute the Zipf CDF over ranks 1..n (n up to a few 10^4 -- fine to build
# in memory once per run rather than per-request).
weights = [1.0 / (r ** s) for r in range(1, n + 1)]
total = sum(weights)
cum = []
acc = 0.0
for w in weights:
    acc += w
    cum.append(acc / total)
import bisect
for _ in range(reqs):
    x = random.random()
    idx = bisect.bisect_left(cum, x)
    if idx >= n:
        idx = n - 1
    print(idx)
PYEOF
}

log_mark() { wc -l < "$WORK/logs/access.log" 2>/dev/null || echo 0; }
origin_mark() { wc -l < "$WORK/logs/origin.log" 2>/dev/null || echo 0; }

run_pass() {
    edge_mark=$(log_mark)
    orig_mark=$(origin_mark)

    gen_stream > "$WORK/stream.txt"

    # Real concurrency: WORKERS parallel curl processes via xargs -P, not a
    # serial loop and not wrk (wrk's Lua key generation would have to
    # reimplement the Zipf sampler in Lua; a plain concurrent curl fleet is
    # simpler and gives us origin-side truth for free via nginx's own log).
    xargs -P "$WORKERS" -I{} sh -c \
        'curl -s -o /dev/null -w "%{time_total}\n" --max-time 5 "http://127.0.0.1:'"$PORT"'/zk?k={}" 2>/dev/null || echo 0' \
        < "$WORK/stream.txt" > "$WORK/latencies.txt"

    sleep 0.3   # access_log is buffered per-request but written by the worker

    tail -n +"$(( edge_mark + 1 ))" "$WORK/logs/access.log" \
        | awk '$1 ~ /^\/zk/ {print $2}' > "$WORK/statuses.txt"
    hits=$(grep -c '^HIT$' "$WORK/statuses.txt" || true)
    tot=$(grep -c . "$WORK/statuses.txt" || true)

    orig_reqs=$(( $(origin_mark) - orig_mark ))

    [ "$tot" -gt 0 ] || { echo "FATAL: no responses parsed" >&2; exit 1; }

    hit_pct=$(awk -v h="$hits" -v t="$tot" 'BEGIN{printf "%.1f", 100*h/t}')

    # p50/p99 latency in ms, sorted ascending.
    sort -n "$WORK/latencies.txt" > "$WORK/latencies.sorted"
    n=$(grep -c . "$WORK/latencies.sorted" || true)
    p50_line=$(( (n + 1) / 2 ))
    p99_line=$(( (n * 99 + 99) / 100 ))
    [ "$p50_line" -ge 1 ] || p50_line=1
    [ "$p99_line" -gt "$n" ] && p99_line="$n"
    p50=$(awk -v L="$p50_line" 'NR==L{printf "%.2f", $1*1000}' "$WORK/latencies.sorted")
    p99=$(awk -v L="$p99_line" 'NR==L{printf "%.2f", $1*1000}' "$WORK/latencies.sorted")

    echo "$hit_pct $p50 $p99 $orig_reqs $tot"
}

echo "Zipf hit-ratio/throughput: KEYS=$KEYS ZIPF_S=$ZIPF_S ZONE=$ZONE BODY=$BODY WORKERS=$WORKERS REQS=$REQS PASSES=$PASSES"
echo

start_nginx
: > "$WORK/results.txt"
p=1
while [ "$p" -le "$PASSES" ]; do
    run_pass >> "$WORK/results.txt"
    p=$((p+1))
done
stop_nginx

median_field() {  # $1 = field number
    awk -v f="$1" '{print $f}' "$WORK/results.txt" | sort -n \
        | awk '{a[NR]=$1} END{print (NR%2)?a[(NR+1)/2]:(a[NR/2]+a[NR/2+1])/2}'
}

hit_m=$(median_field 1)
p50_m=$(median_field 2)
p99_m=$(median_field 3)
orig_m=$(median_field 4)
tot_m=$(median_field 5)

printf 'HIT ratio:            %s%%   (median of %s pass(es))\n' "$hit_m" "$PASSES"
printf 'p50 latency:          %s ms\n' "$p50_m"
printf 'p99 latency:          %s ms\n' "$p99_m"
printf 'origin request count: %s / %s   (%.1f%% of requests reached the origin)\n' \
    "$orig_m" "$tot_m" "$(awk -v o="$orig_m" -v t="$tot_m" 'BEGIN{if(t>0)printf "%.1f",100*o/t;else print 0}')"

echo

# --- degenerate-run detection (the two self-invalidation traps above) -----
awk -v h="$hit_m" 'BEGIN{
    if (h <= 0.5) {
        print "INVALID RUN: HIT ratio ~0% -- ZONE/KEYS/ZIPF_S/REQS are mis-tuned" > "/dev/stderr"
        print "  for this KEYS*BODY vs ZONE, either the working set never fits" > "/dev/stderr"
        print "  (shrink KEYS or ZIPF_S, or grow ZONE) or REQS is too low for" > "/dev/stderr"
        print "  the hot keys to repeat before their first eviction (grow REQS)." > "/dev/stderr"
        print "  This is NOT \"the feature has no effect\" -- re-tune and re-run." > "/dev/stderr"
        exit 3
    }
    if (h >= 99.5) {
        print "INVALID RUN: HIT ratio ~100% -- ZONE holds the entire KEYS*BODY" > "/dev/stderr"
        print "  working set, so nothing is ever evicted and eviction/admission" > "/dev/stderr"
        print "  policy cannot be exercised at all. Shrink ZONE or grow KEYS/BODY" > "/dev/stderr"
        print "  until the working set deliberately overflows the zone." > "/dev/stderr"
        exit 3
    }
}'
