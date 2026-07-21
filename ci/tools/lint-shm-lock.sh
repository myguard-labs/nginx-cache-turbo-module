#!/usr/bin/env bash
#
# Enforce the shm-mutex hold invariant (issue R7).
#
# The zone mutex (ngx_shmtx_lock(&...->mutex)) must only ever be held across
# bounded, synchronous work: slab alloc/free, rbtree/queue ops, memcpy. It must
# NEVER be held across anything that yields control back to the event loop,
# parks the request, produces output, runs the phase engine, registers a timer,
# or otherwise re-enters the module. A worker that parked or slept while holding
# the mutex would strand it: nginx force-unlocks it at reap and logs
# "[alert] shared memory zone ... was locked by <pid>", and worse, every other
# worker contending for the zone stalls until the parked request resumes.
#
# The R7 audit (2026-06-12) proved no such path exists today. This lint locks
# that invariant in so a future edit can't reintroduce it: it scans each C
# source for a forbidden, control-yielding call appearing textually between a
# ngx_shmtx_lock and its matching ngx_shmtx_unlock, and fails the build if it
# finds one. Comment lines are ignored.
#
# Usage: ci/tools/lint-shm-lock.sh [src-file ...]   (defaults to src/*.c)

set -euo pipefail

cd "$(dirname "$0")/.."

if [ "$#" -gt 0 ]; then
    files=("$@")
else
    files=(src/*.c)
fi

# Calls that hand control to the event loop / re-enter the request. Holding the
# zone mutex across any of these is the bug R7 guards against. Keep this list in
# sync with the module's yield points (L2 vtable ->get/->lock park; serve and
# warm_one drive the output filter / a subrequest; run_phases / posted_requests
# / finalize re-enter the engine; add_timer defers; NGX_AGAIN returns parked).
# NOTE: paren matched with the bracket expression [(] rather than \( on
# purpose. This string is handed to awk via -v, and awk's -v assignment runs
# backslash-escape processing on the value, which strips the \ from \( and
# leaves a bare ( -> "fatal: invalid regexp: Unmatched (" on gawk (mawk was
# lenient, which is why CI caught this and a local mawk run did not). [(]
# carries no backslash, so it survives -v unchanged on every awk.
forbidden='ngx_http_output_filter|ngx_http_finalize_request|ngx_http_core_run_phases|ngx_http_run_posted_requests|ngx_http_subrequest|ngx_add_timer|ngx_http_cache_turbo_serve|ngx_http_cache_turbo_warm_one|ngx_http_cache_turbo_cold_wait|return[[:space:]]+NGX_AGAIN|->[[:space:]]*get[[:space:]]*[(]|->[[:space:]]*lock[[:space:]]*[(]'

status=0

for f in "${files[@]}"; do
    [ -f "$f" ] || continue
    awk -v file="$f" -v forbidden="$forbidden" '
        # Strip // line comments and whole-line /* ... */ comments so a mention
        # of a forbidden name in prose never trips the lint. (The sources keep
        # block-comment bodies on their own lines, so per-line stripping is
        # enough here; no multi-line comment-state machine needed.)
        {
            line = $0
            sub(/\/\/.*/, "", line)
        }
        line ~ /^[[:space:]]*\*/      { next }   # continuation of a block comment
        line ~ /^[[:space:]]*\/\*/    { next }   # block-comment opener line
        line ~ /ngx_shmtx_lock[[:space:]]*\(/   { locked = 1; next }
        line ~ /ngx_shmtx_unlock[[:space:]]*\(/ { locked = 0; next }
        locked && line ~ forbidden {
            trimmed = line
            sub(/^[[:space:]]+/, "", trimmed)
            printf "%s:%d: yielding call under shm mutex: %s\n", \
                   file, FNR, trimmed
            bad = 1
        }
        END { exit bad ? 1 : 0 }
    ' "$f" || status=1
done

if [ "$status" -ne 0 ]; then
    echo "FAIL: shm-mutex held across a control-yielding call (R7 invariant)." >&2
    echo "      Copy the value out of shm under the lock, unlock, THEN yield." >&2
    exit 1
fi

echo "ok: shm-mutex invariant holds (no yield under zone lock)"
