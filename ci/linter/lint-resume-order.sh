#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/linter/lint-resume-order.sh -- the resume-finalize order invariant.
#
# THIS CHECK IS THIS MODULE'S OWN and has no counterpart in
# labs/nginx-skeleton-module.
#
# What it enforces, in one line: a parked request is resumed with
# ngx_http_finalize_request(r, ...) FIRST and ngx_http_run_posted_requests(c)
# LAST, where `c` was read from r->connection BEFORE the finalize. The reverse
# order (run_posted_requests, then finalize) is a use-after-free: running the
# posted queue can complete and free `r` (or its connection) before the module
# touches it again, and `ngx_http_run_posted_requests(r->connection)` reads the
# connection out of a request that finalize may already have freed.
#
# Rule, per C function (a function ends at a `}` in column 0), comments and
# string/char literals blanked first:
#   1. after `ngx_http_run_posted_requests(...)` closes, the identifier `r`
#      must not appear again before the function ends;
#   2. the argument must not be `r->connection` (hoist `c` first).
#
# Whole-tree by nature, like lint-shm-lock.sh: the staged list only decides
# whether this checker is relevant, never which lines it reads. The scanner is
# in this file (ci/tools/ is not touched by this checker).
#
# Usage: ci/linter/lint-resume-order.sh [files...]   Env: LINT_MODE=staged|all
#        ci/linter/lint-resume-order.sh --scan file...   scan files as given,
#                                       skipping the src/ selection (selftest)
# Exit:  0 clean, 1 the invariant is violated, 2 could not run.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

if [ "${1:-}" = "--scan" ]; then
    shift
    [ "$#" -gt 0 ] || die "lint-resume-order: --scan needs files"
    FILES=("$@")
else
    lint_files_into FILES '^src/.*\.[ch]$' "$@"
    [ "${#FILES[@]}" -gt 0 ] || { echo "lint-resume-order: no C files to check"; exit 0; }
fi

echo "lint-resume-order: ${#FILES[@]} file(s)"
say "resume-finalize order invariant"

# shellcheck disable=SC2016  # awk program, not shell
PROG='
# Blank comments and string/char literal bodies; state survives across lines
# only for /* */ blocks.
function strip(s,    i, n, ch, nx, q, out) {
    n = length(s); q = ""; out = ""
    for (i = 1; i <= n; i++) {
        ch = substr(s, i, 1); nx = substr(s, i + 1, 1)
        if (inblk) {
            if (ch == "*" && nx == "/") { inblk = 0; i++; out = out "  " }
            else out = out " "
        } else if (q != "") {
            if (ch == "\\") { i++; out = out "  " }
            else if (ch == q) { q = ""; out = out ch }
            else out = out " "
        } else if (ch == "/" && nx == "*") { inblk = 1; i++; out = out "  " }
        else if (ch == "/" && nx == "/") { break }
        else if (ch == "\"" || ch == "\047") { q = ch; out = out ch }
        else out = out ch
    }
    return out
}
function has_r(s) {
    gsub(/->[ \t]*[A-Za-z_][A-Za-z0-9_]*/, " ", s)
    gsub(/\.[ \t]*[A-Za-z_][A-Za-z0-9_]*/, " ", s)
    return (s ~ /(^|[^A-Za-z0-9_])r([^A-Za-z0-9_]|$)/)
}
function flush(    i, k, ln, p, rest, depth, j, ch, arg, endl, tail, t, started) {
    for (i = 1; i <= nl; i++) {
        p = index(L[i], "ngx_http_run_posted_requests")
        if (!p) continue
        # collect the argument text, balancing parentheses across lines
        rest = substr(L[i], p + 28); arg = ""; depth = 0; started = 0
        endl = 0; tail = ""
        for (k = i; k <= nl && !endl; k++) {
            ln = (k == i) ? rest : L[k]
            for (j = 1; j <= length(ln); j++) {
                ch = substr(ln, j, 1)
                if (ch == "(") { depth++; started = 1; if (depth == 1) continue }
                else if (ch == ")") { depth--; if (started && depth == 0) { endl = k; tail = substr(ln, j + 1); break } }
                if (started) arg = arg ch
            }
            if (!endl) arg = arg " "
        }
        if (!endl) { print file ":" LN[i] ": unterminated ngx_http_run_posted_requests call"; continue }
        if (arg ~ /^[ \t]*r[ \t]*->[ \t]*connection[ \t]*$/)
            print file ":" LN[i] ": ngx_http_run_posted_requests(r->connection): hoist c = r->connection before ngx_http_finalize_request"
        t = tail
        for (k = endl; k <= nl; k++) {
            if (k > endl) t = L[k]
            if (has_r(t)) {
                print file ":" LN[k] ": r used after ngx_http_run_posted_requests (call at line " LN[i] "): finalize first, run_posted_requests last"
                break
            }
        }
    }
    nl = 0
}
{
    line = $0; sub(/\r$/, "", line)
    code = strip(line)
    nl++; L[nl] = code; LN[nl] = FNR
    if (substr(line, 1, 1) == "}" && !inblk) flush()
}
END { flush() }
'

status=0
for f in "${FILES[@]}"; do
    [ -f "$f" ] || continue
    out=""; arc=0
    out="$(awk -v file="$f" "$PROG" "$f")" || arc=$?
    if [ "$arc" -ne 0 ]; then
        echo "lint-resume-order: awk failed on $f (exit $arc)" >&2
        exit 2
    fi
    if [ -n "$out" ]; then
        printf '%s\n' "$out"
        status=1
    fi
done

if [ "$status" -ne 0 ]; then
    echo "FAIL: resume-finalize order -- ngx_http_run_posted_requests must be the last use of the request (see ci/linter/lint-resume-order.sh)" >&2
    exit 1
fi
echo "lint-resume-order: ok"
