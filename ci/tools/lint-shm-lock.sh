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

# ../.. -- the REPO ROOT, not ci/. This script lives in ci/tools/, so a single
# climb lands in ci/, where `src/*.c` matches nothing: bash leaves an unmatched
# glob as the literal string, the `[ -f "$f" ] || continue` guard below skips
# it, and the loop reports "ok" having read ZERO files. The climb was correct
# while this script lived in tools/ at the repo root and was not updated when
# the tree moved under ci/, so the R7 gate has been vacuously green in CI and
# in the hook ever since -- the empty-selection class, caught by planting a
# real violation and watching the checker pass.
cd "$(dirname "$0")/../.."

if [ "$#" -gt 0 ]; then
    files=("$@")
else
    files=(src/*.c)
fi

# An empty or unmatched selection is "could not run", never "clean". Without
# this the only symptom of a broken path is a cheerful ok line, which is the
# defect above wearing the face of a passing gate.
if [ "${#files[@]}" -eq 0 ] || [ ! -f "${files[0]}" ]; then
    echo "lint-shm-lock: no source files matched (${files[*]}) -- refusing to report ok on an empty scan" >&2
    exit 2
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
# The list is an allowlist-by-omission: a yield point that is not named here
# passes silently, which is the same shape of failure as the vacuous ../.. scan
# fixed above. The second group below closes the gap for the request-engine
# entry points a future edit is most likely to reach for -- none of them appears
# under the lock today, so adding them is pure future-proofing, not a fix.
#
# Deliberately NOT listed: ->store( / ->set( / ->purge_tag(. Those slot names are
# shared by the L1 vtable, whose store is not a yield point (shm_store takes the
# mutex itself), so pinning them would fire on correct code. The L2 park points
# are already covered by ->get( and ->lock(.
forbidden='ngx_http_output_filter|ngx_http_finalize_request|ngx_http_core_run_phases|ngx_http_run_posted_requests|ngx_http_subrequest|ngx_add_timer|ngx_del_timer|ngx_http_send_header|ngx_http_send_special|ngx_http_post_request|ngx_http_internal_redirect|ngx_http_named_location|ngx_http_read_client_request_body|ngx_http_cache_turbo_serve|ngx_http_cache_turbo_warm_one|ngx_http_cache_turbo_cold_wait|return[[:space:]]+NGX_AGAIN|->[[:space:]]*get[[:space:]]*[(]|->[[:space:]]*lock[[:space:]]*[(]'

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

        # Scan in SOURCE ORDER rather than per-line, so a lock (or unlock) that
        # shares its line with a forbidden call is still judged. An earlier form
        # flipped `locked` and did `next`, which skipped the check for the WHOLE
        # line -- so `ngx_shmtx_lock(&z->shpool->mutex); ngx_http_finalize_request(r, rc);`
        # passed, as did a forbidden call sitting BEFORE an unlock on one line.
        # No source does that today, which is exactly why it needed catching by
        # construction: same empty-selection class as the ../.. bug above, where
        # the gate reports ok having examined nothing.
        {
            rest = line
            while (rest != "") {
                li = match(rest, /ngx_shmtx_lock[[:space:]]*\(/)
                lp = li ? RSTART : 0
                ll = li ? RLENGTH : 0
                ui = match(rest, /ngx_shmtx_unlock[[:space:]]*\(/)
                up = ui ? RSTART : 0
                ul = ui ? RLENGTH : 0

                # "unlock" contains "lock", so a bare lock match at the same
                # offset as an unlock match is that unlock -- prefer the unlock.
                if (up && lp && lp >= up && lp < up + ul) { lp = 0 }

                if (lp && (!up || lp < up)) { pos = lp; len = ll; nowlocked = 1 }
                else if (up)                { pos = up; len = ul; nowlocked = 0 }
                else                        { pos = 0 }

                if (pos == 0) {
                    seg = rest
                    rest = ""
                } else {
                    seg = substr(rest, 1, pos - 1)
                    rest = substr(rest, pos + len)
                }

                if (locked && seg ~ forbidden) {
                    trimmed = line
                    sub(/^[[:space:]]+/, "", trimmed)
                    printf "%s:%d: yielding call under shm mutex: %s\n", \
                           file, FNR, trimmed
                    bad = 1
                }

                if (pos != 0) { locked = nowlocked }
            }
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
