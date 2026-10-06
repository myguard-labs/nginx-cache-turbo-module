#!/usr/bin/env bash
#
# Tripwire for weak-ordering atomics (CI-ARM64-NO-LIVE-LANE).
#
# The module has no live arm64 CI lane, and that is an accepted risk only
# because src/ takes ordering entirely from nginx's atomic primitives: on
# aarch64 nginx falls back to the __sync builtins, which are full barriers, and
# the module never spells a weaker ordering itself. That argument stops holding
# the day src/ gains any of:
#
#   - ngx_memory_barrier            a hand-rolled acquire/release protocol,
#   - a raw __atomic_* call with an explicit weak ordering
#     (__ATOMIC_RELAXED / CONSUME / ACQUIRE / RELEASE / ACQ_REL, or the C11
#      memory_order_* spellings of the same).
#
# __ATOMIC_SEQ_CST is deliberately not flagged: it is the strength the accepted
# risk already assumes.
#
# When this fires, do not silence it. Re-open CI-ARM64-NO-LIVE-LANE in the
# memory ledger (issues.md): the audit that retired the arm64 lane must be
# redone, or a live arm64 lane provisioned, before the new ordering ships.
#
# NOTE: no \b below -- POSIX awk/mawk have no word boundary, and a pattern
# written with one matches nothing (see lint-stripe-seam.sh). Word edges are
# explicit character classes over a padded line.
#
# Usage: ci/tools/lint-atomic-ordering.sh [src-file ...]   (defaults to src/*.[ch])

set -euo pipefail

cd "$(dirname "$0")/../.."

if [ "$#" -gt 0 ]; then
    files=("$@")
else
    files=(src/*.c src/*.h)
fi

if [ "${#files[@]}" -eq 0 ] || [ ! -f "${files[0]}" ]; then
    echo "lint-atomic-ordering: no source files matched (${files[*]}) -- refusing to report ok on an empty scan" >&2
    exit 2
fi

status=0

for f in "${files[@]}"; do
    [ -f "$f" ] || continue

    awk -v file="$f" '
        # Block comments can span lines; prose about the barrier is fine.
        {
            line = $0
            out = ""
            while (length(line) > 0) {
                if (in_c) {
                    p = index(line, "*/")
                    if (p == 0) { line = ""; break }
                    line = substr(line, p + 2); in_c = 0
                } else {
                    p = index(line, "/*")
                    if (p == 0) { out = out line; line = ""; break }
                    out = out substr(line, 1, p - 1)
                    line = substr(line, p + 2); in_c = 1
                }
            }
            sub(/\/\/.*/, "", out)
            probe = " " out " "
        }

        probe ~ /[^A-Za-z0-9_]ngx_memory_barrier[^A-Za-z0-9_]/ ||
        probe ~ /[^A-Za-z0-9_]__ATOMIC_(RELAXED|CONSUME|ACQUIRE|RELEASE|ACQ_REL)[^A-Za-z0-9_]/ ||
        probe ~ /[^A-Za-z0-9_]memory_order_(relaxed|consume|acquire|release|acq_rel)[^A-Za-z0-9_]/ {
            trimmed = out
            sub(/^[[:space:]]+/, "", trimmed)
            printf "%s:%d: weak-ordering atomic or memory barrier: %s\n", file, FNR, trimmed
            bad = 1
        }

        END { exit bad ? 1 : 0 }
    ' "$f" || status=1
done

if [ "$status" -ne 0 ]; then
    echo "FAIL: src/ gained ngx_memory_barrier or a weak-ordering __atomic_* call (CI-ARM64-NO-LIVE-LANE)." >&2
    echo "      The accepted-risk argument (nginx aarch64 uses full-barrier __sync builtins) no longer covers it." >&2
    echo "      Re-open CI-ARM64-NO-LIVE-LANE per its re-open conditions in issues.md before shipping." >&2
    exit 1
fi

echo "lint-atomic-ordering: ok (no ngx_memory_barrier / weak-ordering atomics in ${#files[@]} file(s))"
