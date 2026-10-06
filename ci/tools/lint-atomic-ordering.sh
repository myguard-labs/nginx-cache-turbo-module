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
# Usage: ci/tools/lint-atomic-ordering.sh [src-file ...]   (defaults to every .c/.h under src/, recursive)

set -euo pipefail

cd "$(dirname "$0")/../.."

if [ "$#" -gt 0 ]; then
    files=("$@")
else
    # Recursive, deterministic (C-locale sorted) default set. Computed into a
    # temp file so a find/sort failure is exit 2, never an empty or partial scan.
    list="$(mktemp)" || { echo "lint-atomic-ordering: cannot create temp file" >&2; exit 2; }
    trap 'rm -f "$list"' EXIT
    if ! { find src -type f \( -name '*.c' -o -name '*.h' \) -print0 | LC_ALL=C sort -z; } >"$list"; then
        echo "lint-atomic-ordering: cannot compute the src/ file set" >&2
        exit 2
    fi
    mapfile -d '' -t files <"$list"
fi

if [ "${#files[@]}" -eq 0 ] || [ ! -f "${files[0]}" ]; then
    echo "lint-atomic-ordering: no source files matched (${files[*]}) -- refusing to report ok on an empty scan" >&2
    exit 2
fi

status=0

for f in "${files[@]}"; do
    [ -f "$f" ] || continue

    awk -v file="$f" '
        # Small C lexer: block comments, line comments, string and char
        # literals. Comment markers inside a literal are NOT comment syntax
        # (a "/*" string must not swallow the code after it), and a quote
        # inside a comment is not a literal. State that can legally cross a
        # line: a block comment, and a string/char/line comment whose line ends
        # in a backslash continuation. Literal CONTENTS are blanked, so a banned
        # token spelled only inside a string does not fire; comments are dropped.
        {
            line = $0
            n = length(line)
            out = ""
            cont = (n > 0 && substr(line, n, 1) == "\\")
            i = 1
            while (i <= n) {
                ch = substr(line, i, 1)
                two = substr(line, i, 2)
                if (in_c) {
                    if (two == "*/") { in_c = 0; i += 2 } else i++
                } else if (in_lc) {
                    i = n + 1
                } else if (q != "") {
                    if (ch == "\\") { out = out "  "; i += 2 }
                    else if (ch == q) { out = out q; q = ""; i++ }
                    else { out = out " "; i++ }
                } else if (two == "/*") { in_c = 1; out = out " "; i += 2 }
                else if (two == "//") { in_lc = 1; i = n + 1 }
                else if (ch == "\"" || ch == "\047") { q = ch; out = out ch; i++ }
                else { out = out ch; i++ }
            }
            # An unterminated literal or line comment ends with its line unless
            # a backslash continues it.
            if (!cont) { q = ""; in_lc = 0 }
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
