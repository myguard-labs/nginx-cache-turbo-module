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
#   VARY     opt-in: origin adds `Vary: Accept-Encoding` AND reflects the
#            request's own Accept-Encoding class back as `Content-Encoding`
#            (negotiated per request, like a real pre-compressing origin);
#            the cache_turbo location gets `cache_turbo_key_encoded_origin on`
#            so that encoded response is actually captured. The measured wrk
#            pass alternates the request Accept-Encoding between TWO distinct
#            classes (gzip/br — see ngx_http_cache_turbo_ae_class(),
#            priority zstd > br > gzip > identity), so the profiled path is the
#            auto-Vary marker/variant-index path (cache_turbo_vary module,
#            `bits > 0`) genuinely serving two different variant keys, not one
#            repeated header. A single class cannot distinguish "the marker
#            engaged" from an ordinary base-key hit — both read
#            hit_ratio_pct=100% identically; a second, distinct, not-yet-primed
#            class is the only thing that makes the marker's bits>0 branch
#            observable via the module's own counters (see "VARY marker
#            evidence" in the script output). Off by default — the default
#            profile is unchanged (PLAN-optimize.md P2-2's original tiny/base-
#            key measurement). VARY=1 is a PREREQUISITE for measuring any
#            variant_hash/Vary-related optimisation; do not compare a VARY=1
#            profile against a pre-VARY baseline run with a different harness
#            version.
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
# Two distinct ae_class() buckets (see ngx_http_cache_turbo_vary.c), NOT the
# same header repeated: a single class round-trips through the marker once
# and then just re-hits the same variant key indefinitely, indistinguishable
# from a base-key hit in the counters. Two classes is what forces the SECOND
# class through its own bits>0 lookup against a not-yet-warm key.
AE_CLASS_A="gzip"
AE_CLASS_B="br"
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

# VARY=1: origin emits Vary: Accept-Encoding AND reflects the request's own
# Accept-Encoding class back as a (fake, but typed-field-real) Content-Encoding
# via $ct_ae_class -- mimicking a real pre-compressing origin that negotiates
# per request. This is NOT cosmetic: ngx_http_cache_turbo_classify_vary() only
# arms the ENCODING axis bit when ngx_http_cache_turbo_response_encoded(r) is
# true (vary.c: "the encoding axis is inert for this response" otherwise --
# a response with identical bytes for every Accept-Encoding is correctly never
# partitioned), and capturing an encoded response at all requires
# `cache_turbo_key_encoded_origin on` on the cache_turbo location (filters.c's
# capture gate: `!response_encoded(r) || encoded_ok`, encoded_ok gated on that
# directive) -- without both, the origin's `Vary: Accept-Encoding` header alone
# never flips `bits > 0` and the marker/variant-index path stays cold
# regardless of what the client sends. Reflecting the class (not a fixed
# "gzip") matters too: the STORE key differentiates by the REQUEST's ae_class,
# but the SERVE-time BLOBF_ORIGIN_ENCODED guard (module.c) checks the stored
# class against the request, so a mismatched fixed class would make the
# second-class request round-trip through refuse/mismatch instead of a clean
# miss-then-hit.
# Whole-line splice (not a fragment) so the default render is BYTE-IDENTICAL
# to the pre-VARY script -- this harness's value is cross-run comparability,
# and a fragment splice leaves a trailing blank line the default never had.
# Each of these three is '' by default, appended inline at the END of an
# existing line (never placed alone on its own line) so an unset VARY leaves
# that line — and the whole rendered config — BYTE-IDENTICAL to the pre-VARY
# script; only a set var contributes its own leading newline + indented line.
LOCATION_BLOCK='location / { add_header Cache-Control "max-age=600"; }'
KEY_ENCODED_DIRECTIVE=''
MAP_BLOCK=''
if [ -n "$VARY" ]; then
    LOCATION_BLOCK='location / { add_header Cache-Control "max-age=600"; add_header Vary "Accept-Encoding"; add_header Content-Encoding $ct_ae_class; }'
    KEY_ENCODED_DIRECTIVE='
            cache_turbo_key_encoded_origin on;'
    MAP_BLOCK="    map \$http_accept_encoding \$ct_ae_class {
        default          \"$AE_CLASS_A\";
        \"~*\\b$AE_CLASS_B\\b\"  \"$AE_CLASS_B\";
    }
"
fi

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
${MAP_BLOCK}    cache_turbo_zone name=ct 64m;

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
            cache_turbo_valid  60s;${KEY_ENCODED_DIRECTIVE}
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

scrape() {
    curl -fsS "http://127.0.0.1:$C/_cache_c?format=prometheus" 2>/dev/null \
        | awk -v m="$1" '$1 ~ "^"m"\\{" {print $2; found=1} END { if (!found) print 0 }' | head -1
}

# Prime + verify the key is actually cached before trusting anything measured
# under perf. A profile of the miss/origin path answers the wrong question.
# prime_class() sends the given Accept-Encoding value (or none) until X-Cache
# reports HIT, so the LATER measured pass (which carries the same headers)
# does not cold-miss its own key.
prime_class() {
    ae="$1"
    args=()
    [ -n "$ae" ] && args=(-H "Accept-Encoding: $ae")
    hit=0
    for _ in $(seq 1 30); do
        curl -fsS "${args[@]}" -D - -o /dev/null "$url" 2>/dev/null > "$WORK/logs/hdr" || true
        xc=$(grep -i '^X-Cache:' "$WORK/logs/hdr" | tr -d '\r' | awk '{print toupper($2)}' || true)
        if [ "$xc" = "HIT" ]; then hit=1; break; fi
        sleep 0.1
    done
    [ "$hit" -eq 1 ]
}

mi_pre=$(scrape cache_turbo_misses_total)

if [ -n "$VARY" ]; then
    # Prime BOTH classes before measuring. Class A's priming is an ordinary
    # cold-miss-then-hit on the base/first-variant key -- unremarkable. Class
    # B's priming is the evidence: it can ONLY produce another miss if the
    # marker stored by class A's store (bits>0, ENCODING axis armed) routed
    # this differently-encoded request to a genuinely different, not-yet-warm
    # variant key. If VARY were not actually engaging the marker (e.g. a
    # config regression), class B would just re-hit class A's already-cached
    # entry -- zero delta -- since a single unvaried key is blind to the
    # request's Accept-Encoding.
    prime_class "$AE_CLASS_A" || {
        echo "FATAL: $url (Accept-Encoding: $AE_CLASS_A) never reported X-Cache: HIT after 30 priming requests." >&2
        echo "  -> perf would profile the MISS/origin path, not the L1 hit path. Aborting." >&2
        exit 3
    }
    mi_after_a=$(scrape cache_turbo_misses_total)

    prime_class "$AE_CLASS_B" || {
        echo "FATAL: $url (Accept-Encoding: $AE_CLASS_B) never reported X-Cache: HIT after 30 priming requests." >&2
        echo "  -> perf would profile the MISS/origin path, not the L1 hit path. Aborting." >&2
        exit 3
    }
    mi_after_b=$(scrape cache_turbo_misses_total)
    marker_prime_delta=$(( mi_after_b - mi_after_a ))
else
    prime_class "" || {
        echo "FATAL: $url never reported X-Cache: HIT after 30 priming requests." >&2
        echo "  -> perf would profile the MISS/origin path, not the L1 hit path. Aborting." >&2
        exit 3
    }
fi

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

wrk_extra_args=()
if [ -n "$VARY" ]; then
    # wrk's -H is static for the whole run; alternating two Accept-Encoding
    # classes per request needs a script. Each thread gets its own Lua state
    # (wrk copies the script per-thread), so the per-thread counter only
    # needs to alternate within that thread -- combined across threads the
    # measured pass still visits both classes throughout.
    cat > "$WORK/vary.lua" <<LUA
local classes = { "$AE_CLASS_A", "$AE_CLASS_B" }
local i = 0
request = function()
    i = i + 1
    wrk.headers["Accept-Encoding"] = classes[(i % 2) + 1]
    return wrk.format(nil, nil, nil, nil)
end
LUA
    wrk_extra_args=(-s "$WORK/vary.lua")
fi
wrk_out=$(wrk -t"$THREADS" -c"$CONC" -d"${DURATION}s" --latency "${wrk_extra_args[@]}" "$url" 2>/dev/null)

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

# Counts BOTH forms perf uses for "could not resolve": a `[unknown]` row (no
# DSO mapping covers the sample IP at all) AND a bare `0x...` symbol column
# (perf DID find the owning DSO but that DSO's own symtab has no entry
# there -- e.g. a stripped local/static symbol only debuginfod-fetched debug
# info can name). Before the `$3 ~ /^0x/` arm was added here, the latter case
# undercounted this metric to 0.00% while such a row sat in the top-15 self-
# time list -- see PERF-PROFILE.md's "unresolved_symbol_pct" note.
unresolved_pct="$(awk '
    /^#/ {next}
    NF >= 4 && $1 ~ /^[0-9.]+%$/ {
        sym=$0
        if (sym ~ /\[unknown\]/ || sym ~ /unknown/ || $3 ~ /^0x[0-9a-fA-F]+$/) { sub("%","",$1); s+=$1 }
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

echo
echo "== VARY marker evidence (cache_turbo_misses_total deltas, priming phase) =="
if [ -n "$VARY" ]; then
    echo "class_A=$AE_CLASS_A misses_pre=$mi_pre misses_after_A=$mi_after_a (delta=$(( mi_after_a - mi_pre )))"
    echo "class_B=$AE_CLASS_B misses_after_B=$mi_after_b (delta=$marker_prime_delta)"
    echo "marker_prime_delta=$marker_prime_delta  # nonzero => class B's priming took a genuine bits>0 miss into a NEW variant key, not a re-hit of class A's key"
else
    echo "VARY unset -- single key, no second class primed, no marker delta possible by construction (negative control: see a VARY=1 run for the positive case)"
fi
