#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/linter/lint-park-contract.sh -- the request-park contract.
#
# THIS CHECK IS THIS MODULE'S OWN and has no counterpart in
# labs/nginx-skeleton-module.
#
# A "park" is an `r->main->count++` that keeps a request alive while an async
# operation (L2 reply, cold-wait timer, thread task, SCAN walk) finishes. Each
# park has a contract, registered in ci/park-sites.tsv, one row per function:
#   file  function  phase  handler  detach  abort_tests  [detach_via]
# Rules (comments and string/char literals blanked first):
#   (a) every live `r->main->count++` in src/*.c sits in a function the TSV
#       lists, and every TSV row still matches a live site (no stale rows);
#   (b) phase access|precontent: the function assigns r->write_event_handler to
#       the listed handler (a parked access-phase request must ignore client
#       events, or a stray read re-enters the phase engine);
#   (c) the `detach` symbol appears in the function, or in the function named
#       by `detach_via`; `none:<reason>` needs a non-empty reason and is exempt;
#   (e) test-build tripwire (BP-B2): the park function carries CT_PARK_ENTER or
#       CT_PARK_ENTER_SLOT, and its file carries a CT_PARK_CHECK or
#       CT_PARK_CHECK_SLOT naming the site (function minus the module prefix,
#       as a string literal inside the macro's argument list; comments are
#       removed there but string literals kept) in the completion path;
#   (d) every abort_tests name (comma list) exists as `def test_` in
#       ci/tools/areas/*.py.
# Whole-tree by nature: the staged list only decides relevance.
#
# Usage: ci/linter/lint-park-contract.sh [files...]   Env: LINT_MODE=staged|all
#        ci/linter/lint-park-contract.sh --root DIR   check the tree at DIR
#                                       (src/, ci/park-sites.tsv, ci/tools/areas)
# Exit:  0 clean, 1 contract broken, 2 could not run (missing tree/TSV,
#        malformed TSV row, awk failure).

if [ "${1:-}" = "--root" ]; then
    [ "$#" -ge 2 ] || { echo "ERROR: lint-park-contract: --root needs a directory" >&2; exit 2; }
    ROOT="$2"
    [ -d "$ROOT" ] || { echo "ERROR: lint-park-contract: no such directory: $ROOT" >&2; exit 2; }
    ROOT="$(cd "$ROOT" && pwd)"
else
    # shellcheck source=ci/linter/lib.sh
    . "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"
    ROOT="$(repo_root)"
    lint_files_into FILES '^(src/.*\.[ch]|ci/park-sites\.tsv|ci/tools/areas/.*\.py|ci/linter/lint-park-contract\.sh)$' "$@"
    [ "${#FILES[@]}" -gt 0 ] || { echo "lint-park-contract: no relevant files to check"; exit 0; }
fi

cd "$ROOT" || exit 2
TSV=ci/park-sites.tsv
[ -f "$TSV" ] || { echo "ERROR: lint-park-contract: missing $TSV" >&2; exit 2; }
shopt -s nullglob
SRC=(src/*.c)
[ "${#SRC[@]}" -gt 0 ] || { echo "ERROR: lint-park-contract: no src/*.c under $ROOT" >&2; exit 2; }
echo "lint-park-contract: ${#SRC[@]} source file(s)"

# shellcheck disable=SC2016  # awk program, not shell
PROG='
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
# Comments blanked (same width), string/char literals kept: the CT_PARK_CHECK
# site label is matched inside the macro argument list of this text.
function nocomment(s,    i, n, ch, nx, q, out) {
    n = length(s); q = ""; out = ""
    for (i = 1; i <= n; i++) {
        ch = substr(s, i, 1); nx = substr(s, i + 1, 1)
        if (inblk2) {
            if (ch == "*" && nx == "/") { inblk2 = 0; i++; out = out "  " }
            else out = out " "
        } else if (q != "") {
            if (ch == "\\") { i++; out = out ch nx }
            else { if (ch == q) q = ""; out = out ch }
        } else if (ch == "/" && nx == "*") { inblk2 = 1; i++; out = out "  " }
        else if (ch == "/" && nx == "/") { break }
        else { if (ch == "\"" || ch == "\047") q = ch; out = out ch }
    }
    return out
}
# The argument list of the macro call starting at column p of s (comments
# already removed), up to its matching close paren, quotes respected.
function macroargs(s, p,    i, n, ch, q, d, out) {
    n = length(s); q = ""; d = 0; out = ""
    for (i = p; i <= n; i++) {
        ch = substr(s, i, 1)
        if (q != "") {
            if (ch == "\\") { out = out ch substr(s, i + 1, 1); i++; continue }
            if (ch == q) q = ""
        } else if (ch == "\"" || ch == "\047") q = ch
        else if (ch == "(") d++
        else if (ch == ")") { d--; if (d == 0) return out }
        if (d > 0) out = out ch
    }
    return out
}
function squash(s) { gsub(/[ \t]+/, "", s); return s }
FNR == NR {
    sub(/\r$/, "")
    if ($0 ~ /^#/ || $0 ~ /^file\t/ || $0 ~ /^[ \t]*$/) next
    nf = split($0, c, "\t")
    if (nf < 6 || nf > 7 || c[1] == "" || c[2] == "" || c[3] !~ /^(access|precontent|content|admin)$/ || c[4] == "" || c[5] == "") {
        print "ERROR: " tsv ":" FNR ": malformed row (6-7 tab-separated fields, valid phase)" > "/dev/stderr"
        bad = 1; exit 2
    }
    k = c[1] SUBSEP c[2]
    row[k] = 1; phase[k] = c[3]; handler[k] = c[4]; detach[k] = c[5]; tests[k] = c[6]; via[k] = (nf == 7 ? c[7] : "")
    rowname[k] = c[1] ":" c[2]
    next
}
FNR == 1 { infn = 0; fn = ""; inblk = 0; inblk2 = 0 }
{
    line = $0; sub(/\r$/, "", line)
    code = strip(line)
    nocm = nocomment(line)
    c1 = substr(line, 1, 1)
    if (!infn && c1 !~ /[ \t#{}\/*]/ && c1 != "" && match(code, /[A-Za-z_][A-Za-z0-9_]*[ \t]*\(/)) {
        nm = substr(code, RSTART, RLENGTH); sub(/[ \t]*\($/, "", nm); fn = nm
    }
    if (substr(line, 1, 1) == "{" && !inblk) infn = 1
    if (infn) {
        key = FILENAME SUBSEP fn
        body[key] = body[key] " " code
        if (match(code, /CT_PARK_CHECK(_SLOT)?[ \t]*\(/))
            chkarg[FILENAME] = chkarg[FILENAME] " " macroargs(nocm, RSTART)
        if (code ~ /r[ \t]*->[ \t]*main[ \t]*->[ \t]*count[ \t]*\+\+/) {
            if (!(key in row)) {
                print FILENAME ":" FNR ": (a) r->main->count++ park in " fn "() is not registered in " tsv
                found = 1
            } else live[key] = 1
        }
    }
    if (substr(line, 1, 1) == "}" && !inblk) infn = 0
}
END {
    if (bad) exit 2
    for (k in row) {
        if (!(k in live)) {
            print tsv ": (a) stale row " rowname[k] ": no live r->main->count++ park there"
            found = 1; continue
        }
        if (phase[k] == "access" || phase[k] == "precontent") {
            want = "r->write_event_handler=" handler[k] ";"
            if (index(squash(body[k]), want) == 0) {
                print rowname[k] ": (b) " phase[k] "-phase park does not assign r->write_event_handler = " handler[k]
                found = 1
            }
        }
        if (body[k] !~ /(^|[^A-Za-z0-9_])CT_PARK_ENTER(_SLOT)?[ \t]*\(/) {
            print rowname[k] ": (e) park has no CT_PARK_ENTER / CT_PARK_ENTER_SLOT"
            found = 1
        }
        site = substr(k, index(k, SUBSEP) + 1); sub(/^ngx_http_cache_turbo_/, "", site)
        if (index(chkarg[substr(k, 1, index(k, SUBSEP) - 1)], "\"" site "\"") == 0) {
            print rowname[k] ": (e) no CT_PARK_CHECK / CT_PARK_CHECK_SLOT for site \"" site "\" in the completion path"
            found = 1
        }
        if (detach[k] ~ /^none:/) {
            if (length(detach[k]) <= 5) { print tsv ": (c) " rowname[k] ": detach=none: needs a reason"; found = 1 }
        } else {
            vk = via[k] == "" ? k : (substr(k, 1, index(k, SUBSEP) - 1) SUBSEP via[k])
            if (!(vk in body) || !match(body[vk], "(^|[^A-Za-z0-9_])" detach[k] "([^A-Za-z0-9_]|$)")) {
                print rowname[k] ": (c) detach symbol " detach[k] " not found in " (via[k] == "" ? "the function" : via[k] "()")
                found = 1
            }
        }
    }
    exit found ? 1 : 0
}
'

out=""; arc=0
out="$(awk -v tsv="$TSV" "$PROG" "$TSV" "${SRC[@]}")" || arc=$?
[ "$arc" -eq 2 ] && { printf '%s\n' "$out"; echo "ERROR: lint-park-contract: could not parse $TSV" >&2; exit 2; }
[ "$arc" -le 1 ] || { echo "ERROR: lint-park-contract: awk failed (exit $arc)" >&2; exit 2; }
status=0
if [ -n "$out" ]; then printf '%s\n' "$out"; status=1; fi

# (d) every abort_tests name must exist as a def in ci/tools/areas/*.py
names="$(cat ci/tools/areas/*.py 2>/dev/null | grep -oE '^def test_[A-Za-z0-9_]+' | sed 's/^def //')" || names=""
# Unit separator, not tab: tab is IFS whitespace, so read would collapse an
# empty abort_tests column and shift detach_via into it.
while IFS=$'\x1f' read -r f fn tests; do
    case "$f" in ''|\#*|file) continue ;; esac
    [ -n "$tests" ] || { echo "$TSV: (d) $f:$fn: abort_tests is empty"; status=1; continue; }
    IFS=',' read -ra T <<< "$tests"
    for t in "${T[@]}"; do
        if ! grep -qxF -- "$t" <<< "$names"; then
            echo "$TSV: (d) $f:$fn: abort test $t is not a def test_ in ci/tools/areas/*.py"
            status=1
        fi
    done
done < <(awk -F'\t' '{ sub(/\r$/, ""); print $1 "\037" $2 "\037" $6 }' "$TSV")

if [ "$status" -ne 0 ]; then
    echo "FAIL: park contract broken (see ci/linter/lint-park-contract.sh and ci/park-sites.tsv)" >&2
    exit 1
fi
echo "lint-park-contract: ok"
