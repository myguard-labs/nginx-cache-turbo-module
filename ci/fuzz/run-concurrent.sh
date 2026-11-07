#!/usr/bin/env bash
#
# Run the long libFuzzer budget for several targets concurrently.
#
# Usage: ci/fuzz/run-concurrent.sh [target:corpus:dict ...]
#   With no argument the five production targets run. A spec is
#   <binary>:<corpus-dir>:<dict-or-empty>, resolved relative to the working
#   directory (CI runs it from ci/fuzz/).
#
# Env:
#   FUZZ_SECS   per-target -max_total_time (required, decimal seconds)
#   FUZZ_JOBS   max concurrent targets (default 3: three of a 4-vCPU slot, so
#               each target keeps a full core; the rest queue)
#   FUZZ_LOGDIR per-target logs (default ./fuzz-logs)
#   FUZZ_MERGE  1 (default) minimizes each passing target's corpus into
#               <corpus>-min after the wait; 0 skips it
#
# Fail-closed: the run fails when any target exits non-zero, when a target
# leaves a libFuzzer crash-/leak-/timeout-/oom- artifact (all written under the
# crash-<bin>- prefix so one upload glob finds them; slow-unit- files are kept
# and uploaded but, as before, do not fail a run that exits 0), or when
# a target cannot be started. Every target is always waited for; a failure of
# one never cancels the others, so their artifacts and logs are still produced.
set -uo pipefail

: "${FUZZ_SECS:?FUZZ_SECS must be set}"
case "$FUZZ_SECS" in
    ''|*[!0-9]*|0) echo "FUZZ_SECS must be a positive decimal integer (0 means unlimited to libFuzzer)" >&2; exit 2 ;;
esac
JOBS="${FUZZ_JOBS:-3}"
case "$JOBS" in
    ''|*[!0-9]*|0) echo "FUZZ_JOBS must be a positive integer" >&2; exit 2 ;;
esac
LOGDIR="${FUZZ_LOGDIR:-fuzz-logs}"
MERGE="${FUZZ_MERGE:-1}"

if [ "$#" -eq 0 ]; then
    set -- fuzz_resp_parser:corpus:fuzz.dict \
           fuzz_norm_args:corpus_norm_args: \
           fuzz_mc_parser:corpus_mc:fuzz_mc.dict \
           fuzz_auto_classify:corpus_auto: \
           fuzz_blob:corpus_blob:
fi

mkdir -p "$LOGDIR"
rcdir="$(mktemp -d)"
trap 'rm -rf "$rcdir"' EXIT

# spec parts, by index
bins=(); corps=(); dicts=()
for t in "$@"; do
    bin="${t%%:*}"; rest="${t#*:}"
    for seen in "${bins[@]}"; do
        [ "$seen" = "$bin" ] && { echo "duplicate target $bin (logs and status are keyed by binary)" >&2; exit 2; }
    done
    bins+=("$bin"); corps+=("${rest%%:*}"); dicts+=("${rest#*:}")
done

run_one() {
    local bin="$1" corp="$2" dict="$3"
    local -a args=("-max_total_time=$FUZZ_SECS" -print_final_stats=1
                   "-artifact_prefix=crash-${bin}-")
    [ -n "$dict" ] && args+=("-dict=$dict")
    {
        echo "=== $bin over $corp (${FUZZ_SECS}s)${dict:+ dict=$dict} start $(date -u +%T.%N) ==="
        "./$bin" "${args[@]}" "$corp/"
        local rc=$?
        echo "=== $bin end $(date -u +%T.%N) exit $rc ==="
        echo "$rc" > "$rcdir/$bin.rc"
    } > "$LOGDIR/$bin.log" 2>&1
}

running=0
for i in "${!bins[@]}"; do
    while [ "$running" -ge "$JOBS" ]; do
        wait -n || true
        running=$((running - 1))
    done
    echo "=== launching ${bins[$i]} (${FUZZ_SECS}s, max $JOBS concurrent) ==="
    run_one "${bins[$i]}" "${corps[$i]}" "${dicts[$i]}" &
    running=$((running + 1))
done
wait

failed=0
for i in "${!bins[@]}"; do
    bin="${bins[$i]}"; corp="${corps[$i]}"
    bad=""
    rc="$(cat "$rcdir/$bin.rc" 2>/dev/null || true)"
    if [ -z "$rc" ]; then
        bad="did not complete (no exit status recorded)"
    elif [ "$rc" != 0 ]; then
        bad="exit $rc"
    fi
    arts="$(find . -maxdepth 1 \( -name "crash-${bin}-crash-*" -o -name "crash-${bin}-leak-*" \
        -o -name "crash-${bin}-timeout-*" -o -name "crash-${bin}-oom-*" \) -type f 2>/dev/null | sort)"
    if [ -n "$arts" ]; then
        bad="${bad:+$bad, }artifact(s): $(echo "$arts" | tr '\n' ' ')"
    fi
    if [ -n "$bad" ]; then
        failed=$((failed + 1))
        echo "FAIL $bin: $bad"
        echo "--- tail of $LOGDIR/$bin.log ---"
        tail -n 40 "$LOGDIR/$bin.log" 2>/dev/null || true
        echo "--- end ---"
        continue
    fi
    echo "OK $bin: no crashes in ${FUZZ_SECS}s"
    if [ "$MERGE" = 1 ]; then
        mkdir -p "${corp}-min"
        if "./$bin" -merge=1 "${corp}-min/" "$corp/" >> "$LOGDIR/$bin.log" 2>&1; then
            echo "merged $corp: $(find "${corp}-min" -type f | wc -l) units"
        else
            failed=$((failed + 1))
            echo "FAIL $bin: corpus merge failed"
            tail -n 40 "$LOGDIR/$bin.log"
        fi
    fi
done

if [ "$failed" -ne 0 ]; then
    echo "FAIL: $failed of ${#bins[@]} fuzz target(s) failed"
    exit 1
fi
echo "OK: all ${#bins[@]} fuzz target(s) clean"
