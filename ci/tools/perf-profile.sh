#!/usr/bin/env bash
#
# Copyright (C) 2026 Thijs Eilander
#
# perf profile of the cache_turbo L1 hit path (P2-2, PLAN-optimize.md).
# LOCAL ONLY — not wired into CI (perf needs a build with symbols, and a
# `perf record` pass is too slow/noisy for a required PR gate). Run this by
# hand whenever P4-1/P4-2's rankings need re-checking against a fresh build.
#
# Stands up ONE cache_turbo L1-shm edge server (mode C from bench.sh, same
# ports/config shape reused so the two tools agree on what "hit path" means),
# primes it so every measured request is an L1 HIT (verified via the
# cache_turbo admin counters, not assumed), then wraps a wrk load pass in
# `perf record -p <worker-pid> --call-graph …` and emits `perf report` text
# plus the raw perf.data.
#
# `tiny` (200B) is the ONLY size this script drives: PLAN-optimize.md P2-2
# calls for it specifically because at 200B the fixed per-hit cost (lock
# acquire, lookup, header restore) is ~100% of the work — a `medium`/`large`
# profile would be dominated by memcpy and tell you nothing about the P4-1/
# P4-2 rankings, which are about the LOOKUP+LOCK path, not payload copy.
#
# IMPORTANT: build with `ci-build.sh nginx <ver> profile` (or an equivalent
# -O2 -g -fno-omit-frame-pointer build) — see that script's mode doc. A
# no-frame-pointer -O2 build makes `perf report` fall back to DWARF/fp-less
# unwinding and can misattribute or drop stack frames; this script checks the
# binary was NOT built with sanitizers/NGX_DEBUG_PALLOC (those change the hit
# path's instruction mix) but cannot verify frame-pointer-ness itself — that
# is on the caller.
#
# Usage:
#   ci/tools/perf-profile.sh <nginx-binary> [duration_seconds] [concurrency]
#   MODULE=<path/to/.so> ci/tools/perf-profile.sh <nginx-binary> 20 8
#
# Env:
#   MODULE   path to ngx_http_cache_turbo_module.so (dynamic builds — adds a
#            load_module line; omit if the module is statically linked)
#   THREADS  wrk worker threads                      (default min(conc,nproc))
#   FREQ     perf record sampling frequency (Hz)      (default 999, an odd
#            number so the sampler doesn't alias against periodic timers)
#   CALLGRAPH  perf --call-graph mode: fp | dwarf     (default fp)
#   WORKERS  nginx worker_processes                   (default 1). A single
#            worker's shm mutex is NEVER contended (nothing else holds it) --
#            it can only measure the uncontended fast-path cost. Set
#            WORKERS>1 (<= nproc) to put real cross-worker pressure on the
#            SAME zone mutex, the only way P4-1's "lock contention" claim can
#            show up in a profile at all. perf then samples every worker pid
#            together (`perf record -p pid1,pid2,...`).
#   OUT      output directory for perf.data/report/results  (default
#            ci/tools/perf-out, gitignored — see .gitignore)
#   VARY     opt-in: origin adds `add_header Vary "Accept-Encoding";` and wrk
#            sends `Accept-Encoding: gzip` on every request, so the profiled
#            path is the auto-Vary marker/variant-index path (cache_turbo_vary
#            module) instead of the base-key hit path. Off by default — the
#            default profile is unchanged (PLAN-optimize.md P2-2's original
#            tiny/base-key measurement). VARY=1 is a PREREQUISITE for measuring
#            any variant_hash/Vary-related optimisation; do not compare a
#            VARY=1 profile against a pre-VARY baseline run with a different
#            harness version.
#
# Requires: /usr/bin/perf (readable perf_event_paranoid, i.e. <=1 as root or
# <=2 unprivileged with CAP_PERFMON — this host is pinned at 1, do not try to
# change it), wrk, gawk, curl.

set -euo pipefail

NGINX="${1:?usage: perf-profile.sh <nginx-binary> [duration] [concurrency]}"
DURATION="${2:-20}"
CONC="${3:-8}"
MODULE="${MODULE:-}"
NPROC="$(nproc 2>/dev/null || echo 4)"
THREADS="${THREADS:-$(( CONC < NPROC ? CONC : NPROC ))}"
FREQ="${FREQ:-999}"
CALLGRAPH="${CALLGRAPH:-fp}"
OUT="${OUT:-$PWD/ci/tools/perf-out}"
VARY="${VARY:-}"
# 1 worker cannot show shm-mutex CONTENTION at all -- only one process ever
# holds it, so ngx_shmtx_lock's fast path never blocks. Default keeps the
# original single-worker/single-pid profile (simplest to attribute), but P4-1
# ("lock contention on the shm mutex") can only be confirmed or refuted with
# WORKERS>1 driving real cross-worker pressure on the SAME zone mutex.
WORKERS="${WORKERS:-1}"
case "$WORKERS" in ''|*[!0-9]*) echo "FATAL: WORKERS must be a positive integer" >&2; exit 2;; esac
WORKERS=$((10#$WORKERS))
[ "$WORKERS" -ge 1 ] || { echo "FATAL: WORKERS must be >= 1" >&2; exit 2; }

case "$CALLGRAPH" in
    fp|dwarf) ;;
    *) echo "FATAL: CALLGRAPH must be 'fp' or 'dwarf', got '$CALLGRAPH'" >&2; exit 2;;
esac

command -v perf >/dev/null 2>&1 || {
    echo "FATAL: perf not found. This harness measures nothing without it —" >&2
    echo "  install linux-perf / linux-tools-\$(uname -r), do not skip the run." >&2
    exit 2
}
command -v wrk >/dev/null 2>&1 || {
    echo "FATAL: wrk not found. apt-get install wrk (or build from github.com/wg/wrk)." >&2
    exit 2
}
command -v gawk >/dev/null 2>&1 || {
    echo "FATAL: gawk not found; required for hit-ratio arithmetic." >&2
    exit 2
}

paranoid="$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 3)"
if [ "$paranoid" -gt 2 ] && [ "$(id -u)" -ne 0 ]; then
    echo "FATAL: /proc/sys/kernel/perf_event_paranoid=$paranoid blocks unprivileged" >&2
    echo "  perf_event_open. Run as root, or lower it (host policy permitting)." >&2
    echo "  Do NOT silently fall back to an unmeasured run." >&2
    exit 2
fi

mkdir -p "$OUT"

ORIGIN=18350   # backend
C=18352        # cache_turbo L1 shm (mirrors bench.sh's C port block, own range)

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html"

# tiny only — see header comment: this is the size PLAN-optimize.md P2-2
# asks for, where fixed per-hit cost dominates.
head -c 200 /dev/urandom | base64 > "$WORK/html/tiny"

LOAD_MODULE=""
[ -n "$MODULE" ] && LOAD_MODULE="load_module $(realpath "$MODULE");"

# VARY=1: origin emits Vary: Accept-Encoding so a request carrying
# Accept-Encoding: gzip (added to the wrk invocation below) drives the
# auto-Vary marker/variant-index path instead of the base-key hit path.
# Whole-line splice (not a fragment) so the default render is BYTE-IDENTICAL
# to the pre-VARY script -- this harness's value is cross-run comparability,
# and a fragment splice leaves a trailing blank line the default never had.
LOCATION_BLOCK='location / { add_header Cache-Control "max-age=600"; }'
[ -n "$VARY" ] && LOCATION_BLOCK='location / { add_header Cache-Control "max-age=600"; add_header Vary "Accept-Encoding"; }'

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
    cache_turbo_zone name=ct 64m;

    server {
        listen 127.0.0.1:$ORIGIN;
        root $WORK/html;
        default_type text/plain;
        $LOCATION_BLOCK
    }

    server {
        listen 127.0.0.1:$C;
        location / {
            cache_turbo        ct;
            cache_turbo_valid  60s;
            proxy_pass http://127.0.0.1:$ORIGIN;
        }
        location = /_cache_c { cache_turbo_admin ct; allow 127.0.0.1; deny all; }
    }
}
EOF

# WORKERS=1 (default): `perf record -p <pid>` targets ONE process and the
# profile is unambiguous about which PID it measured, but the shm mutex is
# NEVER contended (nothing else holds it) -- it can only show the mutex's
# uncontended fast-path cost, not P4-1's contention claim.
# WORKERS>1: perf record takes a comma-separated pid list so every worker
# sharing the SAME zone mutex is sampled together, the only way contention
# can show up at all.
"$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf" &
MASTER_PID=$!
trap 'kill -QUIT "$MASTER_PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT

for _ in $(seq 1 100); do
    curl -fsS -o /dev/null "http://127.0.0.1:$ORIGIN/tiny" 2>/dev/null && break
    sleep 0.1
done

# Find the WORKER pid(s) (not master) — those are the processes actually
# serving requests and holding the shm mutex.
worker_pids=""
for _ in $(seq 1 50); do
    worker_pids="$(pgrep -P "$MASTER_PID" -f nginx 2>/dev/null | tr '\n' ',' | sed 's/,$//')"
    n_found="$(tr ',' '\n' <<<"$worker_pids" | sed '/^$/d' | wc -l)"
    [ "$n_found" -ge "$WORKERS" ] && break
    sleep 0.1
done
[ -n "$worker_pids" ] || { echo "FATAL: could not find nginx worker pid(s) under master $MASTER_PID" >&2; exit 3; }
n_found="$(tr ',' '\n' <<<"$worker_pids" | sed '/^$/d' | wc -l)"
[ "$n_found" -ge "$WORKERS" ] || {
    echo "FATAL: expected $WORKERS worker(s), only found $n_found ($worker_pids)" >&2
    exit 3
}

url="http://127.0.0.1:$C/tiny"

# Prime + verify the key is actually cached before trusting anything measured
# under perf. A profile of the miss/origin path answers the wrong question.
# VARY=1: prime with the SAME Accept-Encoding: gzip header the measured wrk
# pass sends, else priming fills the base-key variant and the measured run
# (which carries the header) would cold-miss its own auto-Vary variant key.
curl_vary_args=()
[ -n "$VARY" ] && curl_vary_args=(-H "Accept-Encoding: gzip")
hit=0
for _ in $(seq 1 30); do
    curl -fsS "${curl_vary_args[@]}" -D - -o /dev/null "$url" 2>/dev/null > "$WORK/logs/hdr" || true
    xc=$(grep -i '^X-Cache:' "$WORK/logs/hdr" | tr -d '\r' | awk '{print toupper($2)}' || true)
    if [ "$xc" = "HIT" ]; then hit=1; break; fi
    sleep 0.1
done
[ "$hit" -eq 1 ] || {
    echo "FATAL: $url never reported X-Cache: HIT after 30 priming requests." >&2
    echo "  -> perf would profile the MISS/origin path, not the L1 hit path. Aborting." >&2
    exit 3
}

scrape() {
    curl -fsS "http://127.0.0.1:$C/_cache_c?format=prometheus" 2>/dev/null \
        | awk -v m="$1" '$1 ~ "^"m"\\{" {print $2; found=1} END { if (!found) print 0 }' | head -1
}

h0=$(scrape cache_turbo_hits_total)
mi0=$(scrape cache_turbo_misses_total)
st0=$(scrape cache_turbo_stale_serves_total)

# --call-graph fp needs the target built -fno-omit-frame-pointer (ci-build.sh
# `profile` mode does this); dwarf works without it but costs more overhead
# per sample and needs bigger stack captures. Default fp since ci-build.sh's
# profile mode guarantees it.
cg="$CALLGRAPH"
[ "$cg" = "dwarf" ] && cg="dwarf,16384"

perf_data="$OUT/perf.data"
rm -f "$perf_data"

echo "== perf record: pid(s)=$worker_pids freq=${FREQ}Hz callgraph=$CALLGRAPH duration=${DURATION}s workers=$WORKERS vary=${VARY:-0} ==" >&2
perf record -p "$worker_pids" -F "$FREQ" --call-graph "$cg" -o "$perf_data" &
PERF_PID=$!
# perf record needs a moment to attach before load starts, else the first
# fraction of the run goes unsampled.
sleep 0.3

wrk_vary_args=()
[ -n "$VARY" ] && wrk_vary_args=(-H "Accept-Encoding: gzip")
wrk_out=$(wrk -t"$THREADS" -c"$CONC" -d"${DURATION}s" --latency "${wrk_vary_args[@]}" "$url" 2>/dev/null)

# perf record only exits when its target exits (or on SIGINT); signal it to
# stop sampling now that the load pass is done.
kill -INT "$PERF_PID" 2>/dev/null || true
wait "$PERF_PID" 2>/dev/null || true

h1=$(scrape cache_turbo_hits_total)
mi1=$(scrape cache_turbo_misses_total)
st1=$(scrape cache_turbo_stale_serves_total)
dh=$(( h1 - h0 )); dm=$(( mi1 - mi0 )); ds=$(( st1 - st0 ))
tot=$(( dh + dm + ds ))
hit_pct="n/a"
[ "$tot" -gt 0 ] && hit_pct=$(awk "BEGIN{printf \"%.2f\", 100*($dh+$ds)/$tot}")

rps=$(awk '/Requests\/sec:/ {print $2}' <<<"$wrk_out")
p50=$(awk '$1=="50%"{print $2}' <<<"$wrk_out")
p99=$(awk '$1=="99%"{print $2}' <<<"$wrk_out")

[ -s "$perf_data" ] || {
    echo "FATAL: $perf_data is empty/missing — perf never sampled the worker." >&2
    echo "  Check perf_event_paranoid and that the worker pid stayed alive." >&2
    exit 3
}

# --no-children (self time, no callers/callees folded in) + -g none is the
# FLAT self-time ranking -- what actually answers "which function burns the
# cycles", as opposed to perf's default --children view where every caller
# up to main() inherits 100% of its callees' overhead and swamps a top-N cut
# with call-tree roots instead of hot leaves.
report_txt="$OUT/perf-report.txt"
perf report -i "$perf_data" --stdio --sort=overhead,symbol -g none --no-children \
    > "$report_txt" 2>/dev/null || {
    echo "FATAL: perf report failed to read $perf_data" >&2
    exit 3
}

top_syms="$(awk '
    /^#/ {next}
    NF >= 4 && $1 ~ /^[0-9.]+%$/ { print; n++; if (n>=15) exit }
' "$report_txt")"

unresolved_pct="$(awk '
    /^#/ {next}
    NF >= 4 && $1 ~ /^[0-9.]+%$/ {
        sym=$0
        if (sym ~ /\[unknown\]/ || sym ~ /unknown/) { sub("%","",$1); s+=$1 }
    }
    END { printf "%.2f", s+0 }
' "$report_txt")"

# Sum every ngx_shmtx_* self-time row -- the exact symbol group P4-1
# ("lock contention on the shm mutex") and P4-2 ("hit-path lock residency")
# are both claims about. $plt entries are the same call counted at the PLT
# stub under -O2 with a dynamic module; folded in so the total isn't split.
shmtx_pct="$(awk '
    /^#/ {next}
    NF >= 4 && $1 ~ /^[0-9.]+%$/ && $0 ~ /ngx_shmtx_/ { sub("%","",$1); s+=$1 }
    END { printf "%.2f", s+0 }
' "$report_txt")"

echo
echo "== RESULT =="
echo "hit_ratio_pct=$hit_pct  (hits=$dh miss=$dm stale=$ds total=$tot)"
echo "rps=$rps p50=${p50} p99=${p99}"
echo "workers=$WORKERS worker_pids=$worker_pids"
echo "perf.data=$perf_data"
echo "perf-report.txt=$report_txt"
echo "unresolved_symbol_pct=$unresolved_pct"
echo "ngx_shmtx_self_time_pct=$shmtx_pct"
echo
echo "-- top symbols (self time, flat) --"
echo "$top_syms"
