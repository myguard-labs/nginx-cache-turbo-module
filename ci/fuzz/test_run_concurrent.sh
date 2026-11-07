#!/usr/bin/env bash
#
# Proof for ci/fuzz/run-concurrent.sh with toy libFuzzer targets (tiny budget):
#   green      : 4 clean targets, FUZZ_JOBS=2 -> all pass, runs overlap, max 2
#   crash      : one target aborts on a seeded input -> non-zero, names it,
#                crash-<bin>-* artifact kept, the others still complete
#   exit-only  : a target exits non-zero without an artifact -> non-zero
#   stale-art  : a leftover crash-<bin>-* from a clean run still fails (closed)
# Needs clang with libFuzzer. Usage: bash ci/fuzz/test_run_concurrent.sh
# shellcheck disable=SC2016,SC2317,SC2329  # bash -c bodies are single-quoted on purpose; helpers are called via chk
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN="$HERE/run-concurrent.sh"
CC="${CC:-clang}"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
fail=0
# chk "description" cmd...: pass when cmd succeeds.
chk() { local d="$1"; shift; if "$@"; then echo "ok   - $d"; else echo "FAIL - $d"; fail=1; fi; }
rc_zero() { [ "$(cat "$W/rc.$1")" = 0 ]; }
rc_nonzero() { ! rc_zero "$1"; }
has() { grep -q -- "$1" "$2"; }

mk() { # name body
    printf '#include <stdint.h>\n#include <stddef.h>\n#include <stdlib.h>\n%s\n' "$2" > "$W/$1.c"
    $CC -g -O1 -fsanitize=fuzzer,address "$W/$1.c" -o "$W/$1" 2>"$W/$1.cc.log" \
        || { echo "toy build failed: $1"; cat "$W/$1.cc.log"; exit 1; }
}
clean='int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){(void)d;(void)n;return 0;}'
mk t_a "$clean"; mk t_b "$clean"; mk t_c "$clean"; mk t_d "$clean"
mk t_crash 'int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){if(n>=1&&d[0]==0x42)abort();return 0;}'
mk t_exit 'int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){(void)d;(void)n;return 0;}
__attribute__((constructor)) static void early(void){ if(getenv("TOY_EXIT")) _Exit(7); }'
for c in ca cb cc cd ccrash cexit; do mkdir -p "$W/$c"; echo seed > "$W/$c/s"; done
printf 'B' > "$W/ccrash/seed"   # seeded crashing input

run() { # name env... -- specs...; leaves output in $W/out.<name>
    local n="$1"; shift
    local -a envs=()
    while [ "$1" != -- ]; do envs+=("$1"); shift; done; shift
    ( cd "$W" && rm -f crash-* && env "${envs[@]}" FUZZ_LOGDIR="$W/logs-$n" FUZZ_MERGE=0 \
        bash "$RUN" "$@" ) > "$W/out.$n" 2>&1
    echo $? > "$W/rc.$n"
}

# green + concurrency
run green FUZZ_SECS=6 FUZZ_JOBS=2 -- t_a:ca: t_b:cb: t_c:cc: t_d:cd:
chk "green run exits 0" rc_zero green
for b in t_a t_b t_c t_d; do
    chk "$b completed exit 0" has "$b end .* exit 0" "$W/logs-green/$b.log"
done
# peak number of targets running at once, from the start/end stamps
peak="$(for b in t_a t_b t_c t_d; do
    s="$(sed -n 's/.* start \([0-9:.]*\) ===/\1/p' "$W/logs-green/$b.log" | head -1)"
    e="$(sed -n 's/.* end \([0-9:.]*\) exit.*/\1/p' "$W/logs-green/$b.log" | head -1)"
    echo "S $s $b"; echo "E $e $b"; done | sort -k2,2 -k1,1r | awk '
    {c+=($1=="S")?1:-1; if(c>m)m=c} END{print m}')"
chk "peak concurrency is 2 (FUZZ_JOBS=2, 4 targets queued), got $peak" [ "$peak" = 2 ]

# seeded crash
run crash FUZZ_SECS=6 FUZZ_JOBS=3 -- t_a:ca: t_crash:ccrash: t_b:cb:
chk "crashing target fails the run" rc_nonzero crash
chk "report names t_crash" has '^FAIL t_crash' "$W/out.crash"
chk "t_a still completed" has '^OK t_a' "$W/out.crash"
chk "t_b still completed" has '^OK t_b' "$W/out.crash"
chk "artifact crash-t_crash-* kept" bash -c 'compgen -G "$1/crash-t_crash-*" >/dev/null' _ "$W"

# non-zero exit without artifact
run exit TOY_EXIT=1 FUZZ_SECS=3 FUZZ_JOBS=3 -- t_a:ca: t_exit:cexit:
chk "exit-only failure fails the run" rc_nonzero exit
chk "report names t_exit" has '^FAIL t_exit: exit' "$W/out.exit"
chk "no artifact left (pure exit-code path)" bash -c '! compgen -G "$1/crash-*" >/dev/null' _ "$W"

# artifact present although the exit code is clean
run stale FUZZ_SECS=2 FUZZ_JOBS=1 -- t_a:ca: # baseline clean
chk "baseline single target is green" rc_zero stale
( cd "$W" && rm -f crash-* && touch crash-t_a-leak-deadbeef \
    && FUZZ_SECS=2 FUZZ_LOGDIR="$W/logs-stale" FUZZ_MERGE=0 bash "$RUN" t_a:ca: ) > "$W/out.stale" 2>&1
echo $? > "$W/rc.stale"
chk "leak-* artifact fails an otherwise clean target" rc_nonzero stale
chk "report names the artifact" has 'FAIL t_a: artifact' "$W/out.stale"

# slow-unit artifact with a clean exit does not fail (previous behaviour)
( cd "$W" && rm -f crash-* && touch crash-t_a-slow-unit-deadbeef \
    && FUZZ_SECS=2 FUZZ_LOGDIR="$W/logs-slow" FUZZ_MERGE=0 bash "$RUN" t_a:ca: ) > "$W/out.slow" 2>&1
echo $? > "$W/rc.slow"
chk "slow-unit-* alone does not fail a clean target" rc_zero slow

# bad config
chk "non-numeric FUZZ_SECS rejected (exit 2)" bash -c 'FUZZ_SECS=x bash "$1" t_a:ca: >/dev/null 2>&1; [ $? = 2 ]' _ "$RUN"
chk "FUZZ_JOBS=0 rejected (exit 2)" bash -c 'FUZZ_SECS=1 FUZZ_JOBS=0 bash "$1" t_a:ca: >/dev/null 2>&1; [ $? = 2 ]' _ "$RUN"
chk "FUZZ_SECS=0 rejected (exit 2)" bash -c 'FUZZ_SECS=0 bash "$1" t_a:ca: >/dev/null 2>&1; [ $? = 2 ]' _ "$RUN"
chk "duplicate target rejected (exit 2)" bash -c 'FUZZ_SECS=1 bash "$1" t_a:ca: t_a:cb: >/dev/null 2>&1; [ $? = 2 ]' _ "$RUN"

exit $fail
