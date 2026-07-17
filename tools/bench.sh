#!/usr/bin/env bash
#
# Throughput/latency benchmark for cache-turbo. LOCAL ONLY — not wired into
# CI. The sibling tools/soak.sh proves the module SURVIVES heavy churn; this
# proves how FAST it serves, and how that compares to the alternatives.
#
# Stands up one nginx with an origin plus four edge servers on separate
# ports, primes each so the measured run hits the cache (not the origin),
# scrapes the Prometheus stats before+after every run, drives load with
# `wrk --latency`, and prints an rps / p50 / p99 / hit-ratio table:
#
#   A  origin direct ............ no edge cache  (the floor)
#   B  nginx proxy_cache ........ native cache   (the thing to beat)
#   C  cache_turbo L1 shm ....... this module, RAM only
#   D  cache_turbo L2 Redis ..... this module + Redis  (only if REDIS= set)
#
# IMPORTANT: build the nginx binary as a RELEASE build (-O2, NO
# -fsanitize / NO valgrind). Sanitizers tank throughput 10-50x and measure
# nothing real — that is soak.sh's job, not this one.
#
# Usage:
#   tools/bench.sh <nginx-binary> [duration_seconds] [concurrency]
#   SIZES="tiny medium" tools/bench.sh <nginx-binary> 15 8
#   REDIS="redis://127.0.0.1:6379/0" tools/bench.sh <nginx-binary> 15 8
#
# Env:
#   SIZES   space list from {tiny,medium,large}   (default "tiny medium")
#   REDIS   DSN to add run D (L2 Redis)            (default: D skipped)
#   MODULE  path to ngx_http_cache_turbo_module.so (dynamic builds — adds
#           a load_module line; omit if the module is statically linked)
#   THREADS wrk worker threads                     (default min(conc,nproc))
#   KEYS    N distinct hot keys per size           (default 1 = single hot key)
#           >1 spreads load across N cached keys via a wrk Lua rotor. The
#           single-key default cannot show LRU-splice / per-key lock
#           contention wins (P1): every request hammers ONE node's LRU
#           linkage under the zone mutex, so a fix that skips redundant
#           splices is invisible. Run e.g. KEYS=1000 with a high CONC and
#           `worker_processes auto` and watch rps scale (or not) with cores.
#           HIT% stays ~100 because all N keys are primed before measuring.
#
# Release binary + dynamic module, the shipped artifact:
#   eval "$(tools/ci-build.sh nginx 1.31.1 nginx)"   # sets binary= module=
#   MODULE="$module" tools/bench.sh "$binary" 15 8

set -euo pipefail

NGINX="${1:?usage: bench.sh <nginx-binary> [duration] [concurrency]}"
DURATION="${2:-15}"
CONC="${3:-8}"
SIZES="${SIZES:-tiny medium}"
REDIS="${REDIS:-}"
KEYS="${KEYS:-1}"      # distinct hot keys per size (P1 contention bench)
case "$KEYS" in ''|*[!0-9]*) echo "FATAL: KEYS must be a positive integer" >&2; exit 2;; esac
[ "$KEYS" -ge 1 ] || { echo "FATAL: KEYS must be >= 1" >&2; exit 2; }
MODULE="${MODULE:-}"   # path to ngx_http_cache_turbo_module.so for a dynamic build
NPROC="$(nproc 2>/dev/null || echo 4)"
THREADS="${THREADS:-$(( CONC < NPROC ? CONC : NPROC ))}"

command -v wrk >/dev/null 2>&1 || {
    echo "FATAL: wrk not found. apt-get install wrk (or build from github.com/wg/wrk)." >&2
    exit 2
}

ORIGIN=18335   # backend
A=18340        # origin direct (no cache)
B=18341        # native proxy_cache
C=18342        # cache_turbo L1 shm
D=18343        # cache_turbo L2 Redis

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html" "$WORK/pc"

# Mixed payload sizes so single- and multi-buffer serve paths both run.
# Sizes match soak.sh so the two tools exercise the same shapes.
head -c 200     /dev/urandom | base64 > "$WORK/html/tiny"
head -c 200000  /dev/urandom | base64 > "$WORK/html/medium"
head -c 4000000 /dev/urandom | base64 > "$WORK/html/large"

REDIS_HTTP=""
REDIS_EDGE=""
if [ -n "$REDIS" ]; then
    REDIS_HTTP="cache_turbo_zone name=ctr 64m;"
    REDIS_EDGE="
    # D: cache_turbo with an L2 Redis tier.
    server {
        listen 127.0.0.1:$D;
        location / {
            cache_turbo        ctr;
            cache_turbo_valid  60s;
            cache_turbo_max_size 16m;   # default 1m would refuse the 4M 'large' body
            cache_turbo_redis  $REDIS;
            proxy_pass http://127.0.0.1:$ORIGIN;
        }
        location = /_cache_d { cache_turbo_admin ctr; allow 127.0.0.1; deny all; }
    }"
fi

LOAD_MODULE=""
# nginx resolves load_module relative to its prefix (-p $WORK), so the .so
# path must be absolute.
[ -n "$MODULE" ] && LOAD_MODULE="load_module $(realpath "$MODULE");"

cat > "$WORK/conf/nginx.conf" <<EOF
daemon off;
$LOAD_MODULE
master_process on;
worker_processes auto;
error_log $WORK/logs/error.log error;
pid $WORK/logs/nginx.pid;
events { worker_connections 4096; }
http {
    access_log off;
    # Big zones + long TTL: we want a pure-HIT steady state, not eviction.
    cache_turbo_zone name=ct 64m;
    $REDIS_HTTP
    proxy_cache_path $WORK/pc levels=1:2 keys_zone=pc:64m max_size=512m inactive=1h;

    # Origin: long freshness so nothing revalidates mid-run.
    server {
        listen 127.0.0.1:$ORIGIN;
        root $WORK/html;
        default_type text/plain;
        location / { add_header Cache-Control "max-age=600"; }
    }

    # A: origin direct, no edge cache — the floor.
    server {
        listen 127.0.0.1:$A;
        location / { proxy_pass http://127.0.0.1:$ORIGIN; }
    }

    # B: nginx native proxy_cache — the thing to beat.
    server {
        listen 127.0.0.1:$B;
        location / {
            proxy_cache       pc;
            proxy_cache_valid 200 60s;
            add_header X-Cache-Status \$upstream_cache_status;
            proxy_pass http://127.0.0.1:$ORIGIN;
        }
    }

    # C: cache_turbo, L1 shm only.
    server {
        listen 127.0.0.1:$C;
        location / {
            cache_turbo        ct;
            cache_turbo_valid  60s;
            cache_turbo_max_size 16m;   # default 1m would refuse the 4M 'large' body
            proxy_pass http://127.0.0.1:$ORIGIN;
        }
        location = /_cache_c { cache_turbo_admin ct; allow 127.0.0.1; deny all; }
    }
$REDIS_EDGE
}
EOF

# Multi-key rotor (KEYS>1): each wrk connection walks the N-key range with a
# per-connection offset, so requests spread over N distinct cache nodes instead
# of hammering one node's LRU linkage under the zone mutex. The path template is
# passed in via WRK_PATH (e.g. "/tiny?k="); wrk appends the key index.
if [ "$KEYS" -gt 1 ]; then
    cat > "$WORK/conf/rotor.lua" <<'LUA'
local keys = tonumber(os.getenv("WRK_KEYS")) or 1
local base = os.getenv("WRK_PATH") or "/"
local i = 0
function init(args) i = math.random(0, keys - 1) end
function request()
    i = (i + 1) % keys
    return wrk.format(nil, base .. i)
end
LUA
fi

"$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf" &
NGINX_PID=$!
trap 'kill -QUIT "$NGINX_PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT

# Wait for listeners.
for _ in $(seq 1 100); do
    curl -fsS -o /dev/null "http://127.0.0.1:$ORIGIN/tiny" 2>/dev/null && break
    sleep 0.1
done

# Scrape a single counter from a cache_turbo admin endpoint. $1=port
# $2=admin-path $3=metric. Echoes 0 when the endpoint/metric is absent
# (modes A/B have no admin endpoint).
scrape() {
    local port="$1" path="$2" metric="$3"
    curl -fsS "http://127.0.0.1:$port$path?format=prometheus" 2>/dev/null \
        | awk -v m="$metric" '$1 ~ "^"m"\\{" {print $2; found=1}
                              END { if (!found) print 0 }' | head -1
}

# Prime + verify a key is actually cached before we measure it.
# $1=port $2=url $3=mode. Fails loud if the cache never engages.
prime() {
    local port="$1" url="$2" mode="$3" hdr xc
    case "$mode" in
        A) curl -fsS -o /dev/null "$url"; return 0;;        # nothing to cache
        B) hdr="X-Cache-Status";;
        *) hdr="X-Cache";;
    esac
    # 30 tries with a small gap: priming runs right after the previous
    # mode's wrk pass, so the box is still draining TIME_WAIT sockets and a
    # cold-miss fill to the shared origin can flake for a moment.
    for _ in $(seq 1 30); do
        curl -fsS -D - -o /dev/null "$url" 2>/dev/null > "$WORK/logs/hdr" || true
        xc=$(grep -i "^$hdr:" "$WORK/logs/hdr" | tr -d '\r' | awk '{print toupper($2)}' || true)
        if [ "$xc" = "HIT" ]; then return 0; fi
        sleep 0.1
    done
    echo "FATAL: $mode $url never reported $hdr: HIT after 30 priming requests" >&2
    echo "  -> the run would measure the origin, not the cache. Aborting." >&2
    exit 3
}

# Prime N distinct keys under one base URL (KEYS>1). $1=port $2=baseurl $3=mode.
# baseurl carries the "?k=" template; each key i is baseurl.i.
prime_keys() {
    local port="$1" base="$2" mode="$3" i
    for (( i=0; i<KEYS; i++ )); do
        prime "$port" "${base}${i}" "$mode"
    done
}

# Run one wrk pass and emit "rps p50_ms p99_ms". With KEYS>1 pass $2=path
# template (e.g. "/tiny?k=") + $3=one full seed URL; the Lua rotor spreads
# requests over the key range from that connection base.
runwrk() {
    local url="$1" path="${2:-}" out
    if [ "$KEYS" -gt 1 ] && [ -n "$path" ]; then
        out=$(WRK_KEYS="$KEYS" WRK_PATH="$path" \
              wrk -t"$THREADS" -c"$CONC" -d"${DURATION}s" --latency \
                  -s "$WORK/conf/rotor.lua" "$url" 2>/dev/null)
    else
        out=$(wrk -t"$THREADS" -c"$CONC" -d"${DURATION}s" --latency "$url" 2>/dev/null)
    fi
    local rps p50 p99
    rps=$(awk '/Requests\/sec:/ {print $2}' <<<"$out")
    # "Latency Distribution" block prints e.g. "     50%    1.23ms"
    p50=$(awk '$1=="50%"{print $2}' <<<"$out")
    p99=$(awk '$1=="99%"{print $2}' <<<"$out")
    echo "${rps:-0} ${p50:-?} ${p99:-?}"
}

modes=(A B C)
ports=("A:$A" "B:$B" "C:$C")
admin=("A:" "B:" "C:/_cache_c")
[ -n "$REDIS" ] && { modes+=(D); ports+=("D:$D"); admin+=("D:/_cache_d"); }

declare -A PORT ADMIN
for kv in "${ports[@]}"; do PORT[${kv%%:*}]=${kv#*:}; done
for kv in "${admin[@]}"; do ADMIN[${kv%%:*}]=${kv#*:}; done

declare -A names=( [A]="origin-direct" [B]="proxy_cache" [C]="cache_turbo-shm" [D]="cache_turbo-redis" )

echo "bench: ${DURATION}s/run, ${CONC} conns, ${THREADS} threads, sizes: $SIZES, keys: $KEYS"
echo "       warmup run discarded; report is the second measured pass."
printf '\n%-10s %-18s %12s %10s %10s %9s\n' SIZE MODE REQ/S P50 P99 HIT%
printf '%s\n' "------------------------------------------------------------------------"

for size in $SIZES; do
    for m in "${modes[@]}"; do
        port="${PORT[$m]}"; ap="${ADMIN[$m]}"
        sleep 1                       # let the previous pass's sockets drain
        if [ "$KEYS" -gt 1 ]; then
            path="/$size?k="                     # rotor appends the key index
            url="http://127.0.0.1:$port${path}0" # seed URL for the wrk connection
            prime_keys "$port" "http://127.0.0.1:$port$path" "$m"
        else
            path=""
            url="http://127.0.0.1:$port/$size"
            prime "$port" "$url" "$m"
        fi

        # Discard one warmup pass (JIT TCP windows / shm fault-in).
        runwrk "$url" "$path" >/dev/null

        # hit-ratio over the measured pass, from the module's own counters.
        local_hit="n/a"
        if [ -n "$ap" ]; then
            h0=$(scrape "$port" "$ap" cache_turbo_hits_total)
            mi0=$(scrape "$port" "$ap" cache_turbo_misses_total)
            st0=$(scrape "$port" "$ap" cache_turbo_stale_serves_total)
        fi

        read -r rps p50 p99 < <(runwrk "$url" "$path")

        if [ -n "$ap" ]; then
            h1=$(scrape "$port" "$ap" cache_turbo_hits_total)
            mi1=$(scrape "$port" "$ap" cache_turbo_misses_total)
            st1=$(scrape "$port" "$ap" cache_turbo_stale_serves_total)
            dh=$(( h1 - h0 )); dm=$(( mi1 - mi0 )); ds=$(( st1 - st0 ))
            tot=$(( dh + dm + ds ))
            if [ "$tot" -gt 0 ]; then
                local_hit=$(awk "BEGIN{printf \"%.1f\", 100*($dh+$ds)/$tot}")
            fi
        fi

        printf '%-10s %-18s %12s %10s %10s %9s\n' \
            "$size" "${names[$m]}" "$rps" "$p50" "$p99" "$local_hit"
    done
    echo
done

echo "Notes:"
echo "  * REQ/S higher is better; P50/P99 lower is better."
echo "  * HIT% from cache_turbo's own counters (modes C/D). <100% on a"
echo "    primed long-TTL run means something is bypassing the cache —"
echo "    investigate before trusting the rps."
echo "  * A is the no-cache floor; C/D should sit well above B for small"
echo "    bodies (no disk, no upstream round-trip on a hit)."
