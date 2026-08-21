#!/usr/bin/env bash
#
# Copyright (C) 2026 Thijs Eilander
#
# Allocation-churn workload for P4-2-s2 (PLAN-optimize.md / TODO.md). LOCAL
# ONLY -- not wired into CI (perf needs a symboled build and takes too long
# for a required PR gate; same rationale as perf-profile.sh).
#
# WHY THIS SCRIPT EXISTS -- neither existing harness can see the thing P4-2
# is about:
#
#   * bench.sh primes every key before measuring -- ~100% HIT by
#     construction (its own header says so). Hits never call
#     ngx_slab_alloc_locked/ngx_slab_free_locked; a HIT-heavy run cannot
#     exercise, let alone contend, the slab pool.
#   * zipfbench.sh's "overflowing" arm gets misses via a Zipf-skewed
#     key-space that deliberately does NOT fit the zone, but it is still
#     built to spend most of its traffic on a hot head -- the point there is
#     hit-ratio discrimination, not allocation rate.
#
# P4-2-s0 decided Arm A (one slab pool PER STRIPE) specifically to remove the
# shared-slab-pool serialization point. The only workload that can validate
# or refute that decision is one where allocation itself is the hot path:
# many DISTINCT keys, sized so the zone cannot hold the working set, so most
# requests are cold MISSes that ngx_slab_alloc_locked a fresh entry, and
# enough turnover that ngx_slab_free_locked runs constantly behind it under
# LRU eviction. That is what this script drives -- no priming pass, one-shot
# keys drawn from a space far larger than any single run's request volume,
# deliberately far from any Zipf head.
#
# Usage:
#   eval "$(ci/tools/ci-build.sh nginx 1.31.3 profile)"   # exports binary= module=
#   ci/tools/allocbench.sh "$binary" "$module"
#   WORKERS=8 ZONE=8m KEYS=2000000 DURATION=20 ci/tools/allocbench.sh "$binary" "$module"
#
# Env:
#   ZONE      cache_turbo_zone size                          (default 8m)
#   BODY      body bytes per key                              (default 512)
#   KEYS      size of the (uniform-random) key-space. wrk is duration-driven,
#             not request-count-driven, so this must be sized against the
#             THROUGHPUT this box actually sustains for DURATION seconds, not
#             against a target request count -- see "why uniform" below
#             (default 2,000,000, comfortably above any single-box rps*20s)
#   WORKERS   nginx worker_processes -- concurrency ACROSS the
#             shared slab pool is the whole point; 1 worker cannot show
#             cross-worker contention at all                    (default 8)
#   CONC      concurrent client connections (wrk -c)             (default WORKERS*4)
#   DURATION  wrk load duration in seconds                       (default 20)
#   PROFILE   1 = wrap the load pass in `perf record` and report
#             self-time by symbol, same convention as perf-profile.sh
#             (default 1; set 0 to skip if perf is unavailable/unprivileged)
#   FREQ      perf sampling frequency                           (default 999)
#   STRIPES   N values to report simulated per-stripe occupancy
#             skew for (space-separated)                        (default "2 4 8 16")
#
# Why UNIFORM random keys, not Zipf: Zipf concentrates traffic on a small hot
# head, which is exactly the case zipfbench.sh already covers and which -- by
# design -- keeps re-serving the SAME few resident entries (few distinct
# allocations after the head is primed once). Arm A's cost model instead
# depends on the "no head at all" extreme: every distinct key gets its own
# slab allocation, so alloc/free churn is maximised and per-stripe hashing
# (crc32-keyed, see shm.c) sees its natural, unskewed input distribution.
# A workload half-way between (mild Zipf) would blur the two questions this
# script exists to answer separately: (1) can allocation itself be made to
# dominate, and (2) how uneven does crc32%N land keys across N stripes when
# nothing forces it either way.
#
# Self-invalidation trap this script guards against (same shape as
# zipfbench.sh's two): if ZONE comfortably holds KEYS*BODY, nothing is ever
# evicted after the warm-up window and the run measures allocation into
# free space, not the steady-state alloc/evict/free cycle Arm A actually
# has to survive. ZONE is sized relative to KEYS*BODY by default (roughly
# 1/8) specifically to force sustained eviction; overriding ZONE without
# also checking the reported hit ratio can silently walk back into that
# trap, so the script always reports observed hit ratio and warns if it is
# not comfortably low.

set -euo pipefail

NGINX="${1:?usage: allocbench.sh <nginx-binary> <module.so>}"
MODULE="${2:?usage: allocbench.sh <nginx-binary> <module.so>}"

ZONE="${ZONE:-8m}"
BODY="${BODY:-512}"
KEYS="${KEYS:-2000000}"
WORKERS="${WORKERS:-8}"
CONC="${CONC:-$((WORKERS * 4))}"
DURATION="${DURATION:-20}"
PROFILE="${PROFILE:-1}"
FREQ="${FREQ:-999}"
STRIPES="${STRIPES:-2 4 8 16}"

for v in KEYS WORKERS CONC DURATION FREQ; do
    val="${!v}"
    case "$val" in ''|*[!0-9]*) echo "FATAL: $v must be a positive integer, got '$val'" >&2; exit 2;; esac
done

command -v python3 >/dev/null 2>&1 || { echo "FATAL: python3 not found (needed for key generation + crc32 skew model)" >&2; exit 2; }
command -v wrk >/dev/null 2>&1 || { echo "FATAL: wrk not found." >&2; exit 2; }
command -v gawk >/dev/null 2>&1 || command -v awk >/dev/null 2>&1 || { echo "FATAL: awk not found." >&2; exit 2; }

if [ "$PROFILE" = "1" ]; then
    command -v perf >/dev/null 2>&1 || {
        echo "FATAL: perf not found and PROFILE=1. Install linux-perf, or set" >&2
        echo "  PROFILE=0 and defend the number as unprofiled in the report." >&2
        exit 2
    }
    paranoid="$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 3)"
    if [ "$paranoid" -gt 2 ] && [ "$(id -u)" -ne 0 ]; then
        echo "FATAL: perf_event_paranoid=$paranoid blocks unprivileged perf_event_open." >&2
        echo "  Run as root, or set PROFILE=0 (result becomes unprofiled)." >&2
        exit 2
    fi
fi

WORK="$(mktemp -d /tmp/ct-allocbench-XXXXXX)"
OUT="${OUT:-$PWD/ci/tools/perf-out}"
cleanup() {
    trap - EXIT INT TERM
    if [ -n "${NGX_MASTER:-}" ]; then kill -QUIT "$NGX_MASTER" 2>/dev/null || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html" "$OUT"

head -c "$BODY" /dev/urandom | base64 | head -c "$BODY" > "$WORK/html/body.txt"
# base64 expansion can undershoot BODY for small values; pad deterministically.
cur=$(wc -c < "$WORK/html/body.txt")
if [ "$cur" -lt "$BODY" ]; then
    awk -v n="$((BODY - cur))" 'BEGIN{s="";while(length(s)<n)s=s "x";print substr(s,1,n)}' >> "$WORK/html/body.txt"
fi

LOAD_MODULE="load_module $(realpath "$MODULE");"
ORIGIN=19430
EDGE=19432

cat > "$WORK/conf/nginx.conf" <<EOF
daemon off;
$LOAD_MODULE
master_process on;
worker_processes $WORKERS;
error_log $WORK/logs/error.log error;
pid $WORK/logs/nginx.pid;
events { worker_connections 4096; }
http {
    access_log off;
    cache_turbo_zone name=zk $ZONE;
    # This workload is miss-dominated by design (0.1-1% HIT -- see header),
    # unlike bench.sh/zipfbench.sh's mostly-HIT traffic, so it is the first
    # harness in this repo where every miss's edge->origin proxy_pass
    # actually matters to the profile. Without an upstream keepalive pool,
    # nginx opens a FRESH TCP connection to the origin per miss; at ~0.2%
    # HIT that is a new connect() on ~every request, which buried the module
    # symbols in the profile under kernel TCP/connection-establishment cost
    # (__inet_hash_connect, tcp_twsk_unique, _raw_spin_lock) during script
    # development -- caught by inspecting the raw perf report, not assumed.
    # keepalive reuses origin connections so the profile reflects the
    # SLAB-ALLOCATOR path this script exists to measure, not socket churn.
    upstream origin_pool {
        server 127.0.0.1:$ORIGIN;
        keepalive 64;
    }
    server {
        listen 127.0.0.1:$ORIGIN;
        root $WORK/html;
        default_type text/plain;
        location / { add_header Cache-Control "max-age=300"; try_files /body.txt =404; }
    }
    server {
        listen 127.0.0.1:$EDGE;
        location / {
            cache_turbo       zk;
            cache_turbo_key   \$uri\$is_args\$args;
            cache_turbo_valid 300s;
            proxy_http_version 1.1;
            proxy_set_header   Connection "";
            proxy_pass http://origin_pool;
        }
        location = /_cache_zk { cache_turbo_admin zk; allow 127.0.0.1; deny all; }
    }
}
EOF

"$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf" &
NGX_MASTER=$!

for _ in $(seq 1 100); do
    curl -fsS -o /dev/null "http://127.0.0.1:$EDGE/k?u=probe" 2>/dev/null && break
    sleep 0.1
done

worker_pids=""
if [ "$PROFILE" = "1" ]; then
    for _ in $(seq 1 50); do
        worker_pids="$(pgrep -P "$NGX_MASTER" -f nginx 2>/dev/null | tr '\n' ',' | sed 's/,$//')"
        n_found="$(tr ',' '\n' <<<"$worker_pids" | sed '/^$/d' | wc -l)"
        [ "$n_found" -ge "$WORKERS" ] && break
        sleep 0.1
    done
    [ -n "$worker_pids" ] || { echo "FATAL: could not find nginx worker pid(s)" >&2; exit 3; }
fi

scrape() {
    curl -fsS "http://127.0.0.1:$EDGE/_cache_zk?format=prometheus" 2>/dev/null \
        | awk -v m="$1" '$1 ~ "^"m"\\{" {print $2; found=1} END { if (!found) print 0 }' | head -1
}

# Uniform-random one-shot key stream over [0, KEYS) -- see header comment for
# why uniform, not Zipf. Emitted as a wrk Lua rotor so the load generator
# itself is real concurrent wrk (not a serial/xargs curl fleet like
# zipfbench.sh -- needed here because we want wrk's own rps/latency numbers
# alongside the allocation counters, and the volume is high enough that per-request
# curl fork overhead would dominate the client side).
python3 - "$KEYS" > "$WORK/keys.lua" <<'PYEOF'
import sys
n = int(sys.argv[1])
# wrk gives every thread its OWN Lua VM. A single fixed randomseed() called
# from the top level runs before threads fork and is shared/re-seeded
# identically in each, so every thread replays the SAME pseudo-random
# sequence in lockstep -- with CONC connections round-robined across threads,
# that collapses to heavy duplicate keys issued concurrently by different
# threads, which is exactly the false ~50% hit ratio this script's smoke
# test caught (2,000,000-key space against a few hundred thousand requests
# should read near 0% HIT, not 50%). setup(thread)/init(args) globals did NOT
# reliably cross into request()'s scope on this wrk build (PANIC: attempt to
# perform arithmetic on a nil value) -- seeding lazily on each thread's FIRST
# request() call instead is the portable fix: os.clock() (process CPU time,
# differs slightly per thread by scheduling) mixed with os.time() gives each
# thread's Lua VM an effectively-independent seed without relying on any
# cross-callback state passing.
print("local seeded = false")
print("request = function()")
print("  if not seeded then")
print("    math.randomseed(os.clock() * 1e9 + os.time())")
print("    seeded = true")
print("  end")
print(f"  local k = math.random(0, {n - 1})")
print('  return wrk.format(nil, "/k?u=" .. k)')
print("end")
PYEOF

hits0=$(scrape cache_turbo_hits_total)
miss0=$(scrape cache_turbo_misses_total)
evict0=$(scrape cache_turbo_evictions_total)

run_load() {
    wrk -t"$(( CONC < WORKERS*2 ? CONC : WORKERS*2 ))" -c"$CONC" -d"${DURATION}s" \
        -s "$WORK/keys.lua" --latency "http://127.0.0.1:$EDGE/" 2>/dev/null
}

perf_data=""
report_txt=""
if [ "$PROFILE" = "1" ]; then
    perf_data="$OUT/allocbench-perf.data"
    report_txt="$OUT/allocbench-perf-report.txt"
    rm -f "$perf_data"
    echo "== perf record: pid(s)=$worker_pids freq=${FREQ}Hz duration=${DURATION}s workers=$WORKERS ==" >&2
    perf record -p "$worker_pids" -F "$FREQ" --call-graph fp -o "$perf_data" &
    PERF_PID=$!
    sleep 0.3
    wrk_out="$(run_load)"
    kill -INT "$PERF_PID" 2>/dev/null || true
    wait "$PERF_PID" 2>/dev/null || true
    perf report -i "$perf_data" --stdio --sort=overhead,symbol -g none --no-children > "$report_txt" 2>/dev/null || true
else
    wrk_out="$(run_load)"
fi

hits1=$(scrape cache_turbo_hits_total)
miss1=$(scrape cache_turbo_misses_total)
evict1=$(scrape cache_turbo_evictions_total)

dh=$((hits1 - hits0))
dm=$((miss1 - miss0))
de=$((evict1 - evict0))
tot=$((dh + dm))
[ "$tot" -gt 0 ] || { echo "FATAL: no hit/miss deltas observed -- run failed" >&2; exit 3; }

hit_pct=$(awk -v h="$dh" -v t="$tot" 'BEGIN{printf "%.2f", 100*h/t}')
alloc_events=$dm
free_events=$de
# alloc:free ratio -- steady-state churn has these close together (every
# evicted slot's slab gets freed, then re-alloc'd by the next miss landing
# there); a run still filling virgin zone space reads alloc >> free instead.
if [ "$free_events" -gt 0 ]; then
    af_ratio=$(awk -v a="$alloc_events" -v f="$free_events" 'BEGIN{printf "%.3f", a/f}')
else
    af_ratio="inf (zone never evicted -- see self-invalidation trap in header)"
fi

rps=$(awk '/Requests\/sec/{print $2}' <<<"$wrk_out")
p50=$(awk '/^ *50%/{print $2}' <<<"$wrk_out")
p99=$(awk '/^ *99%/{print $2}' <<<"$wrk_out")

# -- per-stripe occupancy skew model -----------------------------------
# crc32(key) % N over the SAME uniform key space actually issued (KEYS
# distinct keys, not resampled) -- this is Arm A's exact stripe selector
# (shm.c's ngx_crc32_short(key_hash, 32) lookup hash; see TODO.md P4-2-s1).
# A perfectly uniform hash lands ~KEYS/N per stripe; this reports the
# actual max/min spread so s3 can judge whether "a full stripe evicts
# while the zone has room" (Arm A's accepted cost) is a real risk at
# realistic N or a non-issue.
skew_report="$(python3 - "$KEYS" "$STRIPES" <<'PYEOF'
import sys, zlib
keys = int(sys.argv[1])
stripe_ns = [int(x) for x in sys.argv[2].split()]
# Match ngx_crc32_short(key_hash, 32): the module crc32's a 32-byte binary
# key derived from the URI (typically an MD5). We do not have MD5 access to
# real request keys here, so we crc32 the same *decimal string* key id used
# on the wire (?u=<id>) -- this is a reasonable proxy for "does crc32 spread
# an arbitrary uniform input evenly", which is exactly what P4-2-s1 needed to
# know and what this table extends to N stripes. It does not model any
# key-length or key-content skew (there is none in this workload by design).
for n in stripe_ns:
    buckets = [0] * n
    for k in range(keys):
        h = zlib.crc32(str(k).encode()) & 0xffffffff
        buckets[h % n] += 1
    lo, hi = min(buckets), max(buckets)
    mean = keys / n
    skew_pct = (hi - lo) / mean * 100 if mean > 0 else 0
    print(f"  N={n:<3} min={lo} max={hi} mean={mean:.0f}  spread={skew_pct:.1f}% of mean")
PYEOF
)"

# -- fragmentation-overhead proxy ----------------------------------------
# The module exposes no direct pfree/slab-stat counter (checked: admin.c's
# Prometheus/JSON output has hits/misses/evictions/etc but nothing byte-level
# for the shm pool). Proxy: after churn, how many resident entries does the
# SAME zone actually hold vs. the naive ZONE/BODY capacity estimate. A fresh
# zone that has only ever been filled (no eviction cycles) should land close
# to ZONE/BODY minus slab/rbtree/blob overhead; a zone that has been through
# many alloc/evict/free cycles under fragmentation-inducing churn will hold
# FEWER resident entries at the same occupied-bytes level if the slab
# allocator cannot fully reclaim freed slots. We approximate resident count
# from evictions: in steady state, residency ~= min(KEYS seen, capacity), and
# a churned zone's effective capacity is exposed by how early sustained
# eviction begins relative to ZONE/BODY.
zone_upper="$(echo "$ZONE" | tr '[:lower:]' '[:upper:]')"
naive_capacity=$(( $(numfmt --from=iec "$zone_upper" 2>/dev/null || echo 0) / BODY ))
if [ "$naive_capacity" -gt 0 ]; then
    frag_note="naive_capacity(ZONE/BODY)=$naive_capacity entries; evictions_observed=$de against $tot total requests -- see report for interpretation, this is a CANDIDATE proxy, not a byte-exact fragmentation measurement (module exposes no slab pfree/used-bytes stat)."
else
    frag_note="naive_capacity unavailable (numfmt could not parse ZONE=$ZONE); evictions_observed=$de -- CANDIDATE proxy only."
fi

echo "Allocation-churn workload: ZONE=$ZONE BODY=$BODY KEYS=$KEYS WORKERS=$WORKERS CONC=$CONC DURATION=${DURATION}s"
echo
echo "== RESULT =="
echo "hit_ratio_pct=$hit_pct  (hits=$dh miss=$dm evictions=$de total=$tot)"
echo "alloc_events(=misses)=$alloc_events free_events(=evictions)=$free_events alloc:free_ratio=$af_ratio"
echo "rps=${rps:-n/a} p50=${p50:-n/a} p99=${p99:-n/a}"
if [ "$hit_pct" != "" ] && awk -v h="$hit_pct" 'BEGIN{exit !(h>15)}'; then
    echo "WARNING: hit_ratio_pct=$hit_pct is not comfortably low -- this run may not be" >&2
    echo "  in the allocation-dominated regime the script is meant to force. Shrink" >&2
    echo "  ZONE or grow KEYS/BODY and re-run before trusting the alloc/free numbers." >&2
fi
echo
echo "-- per-stripe occupancy skew (crc32(key) % N over the $KEYS-key uniform space) --"
echo "$skew_report"
echo
echo "-- fragmentation-overhead proxy --"
echo "$frag_note"
echo
if [ "$PROFILE" = "1" ]; then
    unresolved_pct="$(awk '
        /^#/ {next}
        NF >= 4 && $1 ~ /^[0-9.]+%$/ { if ($0 ~ /\[unknown\]/ || $0 ~ /unknown/) { sub("%","",$1); s+=$1 } }
        END { printf "%.2f", s+0 }
    ' "$report_txt")"
    shmtx_pct="$(awk '
        /^#/ {next}
        NF >= 4 && $1 ~ /^[0-9.]+%$/ && $0 ~ /ngx_shmtx_/ { sub("%","",$1); s+=$1 }
        END { printf "%.2f", s+0 }
    ' "$report_txt")"
    slab_pct="$(awk '
        /^#/ {next}
        NF >= 4 && $1 ~ /^[0-9.]+%$/ && $0 ~ /ngx_slab_(alloc|free)/ { sub("%","",$1); s+=$1 }
        END { printf "%.2f", s+0 }
    ' "$report_txt")"
    top_syms="$(awk '
        /^#/ {next}
        NF >= 4 && $1 ~ /^[0-9.]+%$/ { print; c++; if (c>=15) exit }
    ' "$report_txt")"
    echo "worker_pids=$worker_pids"
    echo "perf.data=$perf_data"
    echo "perf-report.txt=$report_txt"
    echo "unresolved_symbol_pct=$unresolved_pct"
    echo "ngx_shmtx_self_time_pct=$shmtx_pct"
    echo "ngx_slab_alloc_free_self_time_pct=$slab_pct"
    echo
    echo "-- top symbols (self time, flat) --"
    echo "$top_syms"
else
    echo "PROFILE=0 -- no perf data collected. Treat any perf-shaped claim about this"
    echo "run as UNBENCHMARKED and mark it a CANDIDATE, not a result."
fi
