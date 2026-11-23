#!/usr/bin/env bash
#
# Pinned A/B performance matrix around ci/tools/bench.sh. LOCAL ONLY.
#
# Runs baseline vs candidate nginx+module binaries in the C382 shape: server
# pinned to one CPU, wrk pinned to a CPU set, one fresh bench.sh run (mode C,
# one measured pass) per sample, N alternating pairs per size, a short
# discarded warmup and a longer measured pass. Emits JSON with per-size
# median, MAD, margin and a verdict (PASS / REGRESSION / INCONCLUSIVE).
# Passing the same binary on both sides is a valid A/A run.
#
# Usage:
#   ci/tools/perf-matrix.sh --base-bin NGINX [--base-module SO] \
#       --cand-bin NGINX [--cand-module SO] [--out DIR] [--pairs 8] \
#       [--sizes "tiny medium"] [--dry-run]
#   ci/tools/perf-matrix.sh --from-samples samples.tsv [--idle idle.tsv] \
#       [--out DIR]
#
# --dry-run prints the planned order and the bench.sh invocation of every
# sample without starting nginx or wrk (binaries are not required to exist).
# --from-samples skips the benchmark and runs only the median/MAD/verdict
# computation over recorded samples.tsv (columns: size side pair rps p50 p99
# wrk_cpu_pct hits misses stale); same exit codes as a live run.
#
# Env (defaults = the C382 shape):
#   SERVER_CPU=2  WRK_CPUS=4,6,8,10  DURATION=10  WARMUP=2  CONC=32
#   THREADS (default: number of WRK_CPUS)
#   MASK_PCT=80  IDLE_MAX_BUSY_PCT=10  HIT_MIN_PCT=99.9
#   MARGIN_PCT=3  MAD_MULT=3  IDLE_WINDOW=1 (seconds per pre/post idle window)
#   SETTLE=1 (seconds between bench.sh exit and the post idle window, so the
#   server shutdown is not counted as foreign load)
# Fewer than 3 pairs is always INCONCLUSIVE (too few samples for a MAD).
# Requires /usr/bin/time (bench.sh's per-sample wrk CPU for the MASKED check).
#
# Exit: 0 PASS; 1 REGRESSION; 3 INCONCLUSIVE (a sample was client-MASKED, a
# pinned CPU or its SMT sibling was busy before/after/around a sample, or a
# per-pass hit ratio from the module's own counters was below HIT_MIN_PCT);
# 2 usage or tool error. Margin = max(MARGIN_PCT% of base median, MAD_MULT x
# base MAD). Build the binaries with a RELEASE recipe, for example
# `BUILD_ROOT=DIR ci/tools/ci-build.sh nginx "" profile`.
# Outputs in --out: matrix.json, samples.tsv, idle.tsv, logs/.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATS="$HERE/perf_matrix_stats.py"

SERVER_CPU="${SERVER_CPU:-2}"
WRK_CPUS="${WRK_CPUS:-4,6,8,10}"
DURATION="${DURATION:-10}"
WARMUP="${WARMUP:-2}"
CONC="${CONC:-32}"
MASK_PCT="${MASK_PCT:-80}"
IDLE_MAX_BUSY_PCT="${IDLE_MAX_BUSY_PCT:-10}"
HIT_MIN_PCT="${HIT_MIN_PCT:-99.9}"
MARGIN_PCT="${MARGIN_PCT:-3}"
MAD_MULT="${MAD_MULT:-3}"
IDLE_WINDOW="${IDLE_WINDOW:-1}"
SETTLE="${SETTLE:-1}"

BASE_BIN="" BASE_MODULE="" CAND_BIN="" CAND_MODULE=""
OUT="" PAIRS=8 SIZES_LIST="tiny medium" DRY_RUN=0 FROM_SAMPLES="" FROM_IDLE=""

die() {
    echo "perf-matrix: $*" >&2
    exit 2
}

while [ "$#" -gt 0 ]; do
    if [ "$1" != --dry-run ] && [ "$#" -lt 2 ]; then die "$1 needs a value"; fi
    case "$1" in
        --base-bin)
            BASE_BIN="$2"
            shift 2
            ;;
        --base-module)
            BASE_MODULE="$2"
            shift 2
            ;;
        --cand-bin)
            CAND_BIN="$2"
            shift 2
            ;;
        --cand-module)
            CAND_MODULE="$2"
            shift 2
            ;;
        --out)
            OUT="$2"
            shift 2
            ;;
        --pairs)
            PAIRS="$2"
            shift 2
            ;;
        --sizes)
            SIZES_LIST="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --from-samples)
            FROM_SAMPLES="$2"
            shift 2
            ;;
        --idle)
            FROM_IDLE="$2"
            shift 2
            ;;
        *) die "unknown argument: $1" ;;
    esac
done
command -v python3 >/dev/null 2>&1 || die "python3 not found"
WRK_COUNT="$(python3 -I -B "$STATS" cpus "$WRK_CPUS" --count)" || die "bad WRK_CPUS: $WRK_CPUS"
THREADS="${THREADS:-$WRK_COUNT}"
ANALYZE_OPTS=(--threads "$THREADS" --wrk-cpu-count "$WRK_COUNT"
    --mask-pct "$MASK_PCT" --idle-max-busy-pct "$IDLE_MAX_BUSY_PCT"
    --hit-min-pct "$HIT_MIN_PCT" --margin-pct "$MARGIN_PCT" --mad-mult "$MAD_MULT")

if [ -n "$FROM_SAMPLES" ]; then
    [ -r "$FROM_SAMPLES" ] || die "--from-samples file not readable: $FROM_SAMPLES"
    out_args=()
    if [ -n "$OUT" ]; then
        mkdir -p "$OUT"
        out_args=(--out "$OUT/matrix.json")
    fi
    idle_args=()
    [ -n "$FROM_IDLE" ] && idle_args=(--idle "$FROM_IDLE")
    rc=0
    python3 -I -B "$STATS" analyze --samples "$FROM_SAMPLES" "${idle_args[@]}" \
        "${out_args[@]}" "${ANALYZE_OPTS[@]}" || rc=$?
    exit "$rc"
fi

case "$PAIRS" in '' | *[!0-9]*) die "--pairs must be a positive integer" ;; esac
PAIRS=$((10#$PAIRS)) # base 10, so "08" is not an octal error
[ "$PAIRS" -ge 1 ] || die "--pairs must be >= 1"

if [ "$DRY_RUN" -eq 1 ]; then
    echo "# perf-matrix dry run: pairs=$PAIRS sizes=\"$SIZES_LIST\" server_cpu=$SERVER_CPU wrk_cpus=$WRK_CPUS threads=$THREADS warmup=${WARMUP}s measured=${DURATION}s conc=$CONC"
    n=0
    while IFS=$'\t' read -r size side pair; do
        n=$((n + 1))
        if [ "$side" = base ]; then
            bin="$BASE_BIN"
            module="$BASE_MODULE"
        else
            bin="$CAND_BIN"
            module="$CAND_MODULE"
        fi
        echo "$n $size/$side/pair$pair: SIZES=$size MODES=C PASSES=1 WORKERS=1 THREADS=$THREADS NGINX_CPUS=$SERVER_CPU WRK_CPUS=$WRK_CPUS WARMUP=$WARMUP MODULE=${module:-} bash ci/tools/bench.sh ${bin:-<${side}-bin>} $DURATION $CONC"
    done < <(python3 -I -B "$STATS" schedule --pairs "$PAIRS" --sizes "$SIZES_LIST")
    exit 0
fi

[ -x "$BASE_BIN" ] || die "--base-bin must be an executable nginx"
[ -x "$CAND_BIN" ] || die "--cand-bin must be an executable nginx"
# Without /usr/bin/time bench.sh reports 0% wrk CPU and the MASKED check
# could never fire; refuse rather than risk a false PASS.
[ -x /usr/bin/time ] || die "/usr/bin/time not found (needed for the client-MASKED check)"
command -v taskset >/dev/null 2>&1 || die "taskset not found"
[ -n "$OUT" ] || OUT="$(mktemp -d)"
mkdir -p "$OUT/logs"
: >"$OUT/samples.tsv"
: >"$OUT/idle.tsv"

CHECK_CPUS="$(python3 -I -B "$STATS" cpus "$SERVER_CPU,$WRK_CPUS")" || die "bad CPU lists"

snap() { cat /proc/stat >"$1"; }

# idle_window LABEL KIND: sleep IDLE_WINDOW seconds and record per-CPU busy %.
idle_window() {
    snap "$OUT/.stat.a"
    sleep "$IDLE_WINDOW"
    snap "$OUT/.stat.b"
    python3 -I -B "$STATS" busy --before "$OUT/.stat.a" --after "$OUT/.stat.b" \
        --cpus "$CHECK_CPUS" --sample "$1" --kind "$2" >>"$OUT/idle.tsv"
}

run_sample() {
    local side="$1" size="$2" pair="$3" bin module label tsv log
    if [ "$side" = base ]; then
        bin="$BASE_BIN"
        module="$BASE_MODULE"
    else
        bin="$CAND_BIN"
        module="$CAND_MODULE"
    fi
    label="$size/$side/pair$pair"
    tsv="$OUT/logs/$size-$side-$pair.tsv"
    log="$OUT/logs/$size-$side-$pair.log"
    : >"$tsv"
    idle_window "$label" pre
    snap "$OUT/.stat.c"
    SIZES="$size" MODES=C PASSES=1 WORKERS=1 THREADS="$THREADS" \
        NGINX_CPUS="$SERVER_CPU" WRK_CPUS="$WRK_CPUS" WARMUP="$WARMUP" \
        MODULE="$module" BENCH_TSV="$tsv" \
        bash "$HERE/bench.sh" "$bin" "$DURATION" "$CONC" >"$log" 2>&1 ||
        die "bench.sh failed for $label (see $log)"
    snap "$OUT/.stat.d"
    sleep "$SETTLE"
    # Whole-sample window: only the SMT siblings of the pinned CPUs, which
    # must stay idle while the pinned CPUs run. (The pinned CPUs themselves
    # are busy by design; they are checked in the pre/post windows.)
    local sib
    sib="$(python3 -I -B "$STATS" cpus "$SERVER_CPU,$WRK_CPUS" --siblings-only)"
    if [ -n "$sib" ]; then
        python3 -I -B "$STATS" busy --before "$OUT/.stat.c" --after "$OUT/.stat.d" \
            --cpus "$sib" --sample "$label" --kind during-sibling >>"$OUT/idle.tsv"
    fi
    idle_window "$label" post
    local rows
    rows="$(wc -l <"$tsv")"
    [ "$rows" -eq 1 ] || die "$label: expected 1 counter row, got $rows (see $log)"
    awk -F'\t' '$4 + 0 > 0 && $7 + 0 > 0 { ok = 1 } END { exit !ok }' "$tsv" ||
        die "$label: bench.sh reported no req/s or no wrk CPU (see $log)"
    awk -F'\t' -v side="$side" -v pair="$pair" '{print $1 "\t" side "\t" pair "\t" $4 "\t" $5 "\t" $6 "\t" $7 "\t" $8 "\t" $9 "\t" $10}' \
        "$tsv" >>"$OUT/samples.tsv"
}

while IFS=$'\t' read -r size side pair; do
    run_sample "$side" "$size" "$pair"
done < <(python3 -I -B "$STATS" schedule --pairs "$PAIRS" --sizes "$SIZES_LIST")

rc=0
python3 -I -B "$STATS" analyze --samples "$OUT/samples.tsv" --idle "$OUT/idle.tsv" \
    --out "$OUT/matrix.json" "${ANALYZE_OPTS[@]}" || rc=$?
exit "$rc"
