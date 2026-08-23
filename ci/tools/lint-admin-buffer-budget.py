#!/usr/bin/env python3
"""Fail CI when an admin stats buffer budget is smaller than the prose it must render.

WHY THIS EXISTS
---------------
ngx_http_cache_turbo_admin_stats_prometheus() and _stats_json() each build
their reply into a single ngx_pnalloc()'d buffer whose size is a HAND-MAINTAINED
expression:

    len = <fixed> + <n> * zname.len + <n> * NGX_ATOMIC_T_LEN;

The <fixed> term is meant to cover the format string's literal bytes (the
HELP/TYPE prose). Every historical bump was an ESTIMATE written into a comment
("prose term bumped by ~180 bytes"), and by P4-2-s3a the accumulated estimates
had drifted 237 bytes BELOW the truth: measured fixed prose 5897, term 5660.

It had not truncated yet only because NGX_ATOMIC_T_LEN reserves 20 bytes per
value while real counters render in 1-6, so the per-value slack absorbed the
shortfall. That is an accident, not a margin: a zone with large counters, or
one more metric, turns it into a silently truncated final metric -- which has
already bitten this file twice (see its len= comment).

This lint removes the estimate. It parses the format string out of the C
source, computes the exact fixed prose (literal bytes, less the 2 bytes a %V
placeholder occupies and the 3 a %uA occupies), and requires the declared fixed
term to be at least that plus a margin. Adding a metric now fails the build
until the term is re-measured, rather than passing on a guess.
"""
import re
import sys
from pathlib import Path

MARGIN = 128

SRC = Path(__file__).resolve().parents[2] / "src" / "ngx_http_cache_turbo_admin.c"

# (function name, the emit call that starts the format string)
TARGETS = [
    ("ngx_http_cache_turbo_admin_stats_prometheus", "body.len = ngx_snprintf"),
]

# _stats_json() budgets differently: instead of `<fixed> + <n> * zname.len` it
# writes `sizeof("<the punctuation skeleton>") + <n> * NGX_ATOMIC_T_LEN + ...`,
# where the skeleton is the format string with every conversion deleted. That
# shape is self-measuring for the prose (the skeleton IS the literal bytes), so
# the drift the checks above catch cannot happen there -- but the MULTIPLIER
# still can, and it is the half that truncates the last field. Check it: the
# declared `<n> * NGX_ATOMIC_T_LEN` must cover every %uA the format string
# actually renders. Non-%uA conversions (%s for breaker_state, %T for lock_ttl)
# are budgeted by their own explicit terms and are asserted to be present
# rather than counted, since each carries a different width constant.
JSON_FN = "ngx_http_cache_turbo_admin_stats_json"
JSON_EMIT = "body.len = ngx_sprintf"
# conversion -> the budget term that must appear for it, once per occurrence
JSON_SCALAR_TERMS = {
    "%s": "sizeof(\"half-open\")",
    "%T": "NGX_TIME_T_LEN",
}


def check_json(src: str, failures: list) -> None:
    try:
        start = src.index(JSON_FN + "(\n") if (JSON_FN + "(\n") in src \
            else src.index(JSON_FN)
    except ValueError:
        failures.append(f"{JSON_FN}: not found in {SRC.name} (renamed?)")
        return

    seg_start = src.index(JSON_EMIT, start)
    seg_end = src.index(") - p;", seg_start)
    fmt = literals(src[seg_start:seg_end])

    # The budget expression sits between the function's `len = ` and the
    # ngx_pnalloc that consumes it.
    try:
        blen = src.index("len = sizeof(", start)
        bend = src.index("ngx_pnalloc", blen)
    except ValueError:
        failures.append(f"{JSON_FN}: could not locate the `len = sizeof(...)` budget")
        return
    budget = src[blen:bend]

    m = re.search(r"(\d+) \* NGX_ATOMIC_T_LEN", budget)
    if not m:
        failures.append(f"{JSON_FN}: could not parse the `<n> * NGX_ATOMIC_T_LEN` term")
        return
    declared_n = int(m.group(1))

    n_a = fmt.count("%uA")
    if n_a != declared_n:
        failures.append(
            f"{JSON_FN}: budget reserves {declared_n} * NGX_ATOMIC_T_LEN but the "
            f"format string renders {n_a} %uA values -- a short multiplier "
            f"silently truncates the last field of the JSON object"
        )

    # Every non-%uA conversion needs its own named width term in the budget.
    for conv, term in JSON_SCALAR_TERMS.items():
        want = fmt.count(conv)
        if want and term not in budget:
            failures.append(
                f"{JSON_FN}: format string renders {conv} but the budget has no "
                f"{term} term to cover it"
            )

    # The skeleton must still describe the same field set as the format string:
    # both are hand-maintained, and a field added to one but not the other is
    # the exact drift this file exists to catch.
    skeleton = literals(budget)
    fields_fmt = re.findall(r'"([a-z0-9_]+)":', fmt)
    fields_skel = re.findall(r'"([a-z0-9_]+)":', skeleton)
    if fields_fmt != fields_skel:
        missing = [f for f in fields_fmt if f not in fields_skel]
        extra = [f for f in fields_skel if f not in fields_fmt]
        failures.append(
            f"{JSON_FN}: the sizeof() skeleton and the format string disagree on "
            f"the field set (missing from skeleton: {missing or 'none'}; "
            f"in skeleton but not emitted: {extra or 'none'}) -- the skeleton is "
            f"the entire prose budget, so a field missing from it is unbudgeted"
        )


def literals(segment: str) -> str:
    """Concatenate the C string literals of a format string, unescaped."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', segment)
    return "".join(parts).encode().decode("unicode_escape")


def main() -> int:
    src = SRC.read_text()
    failures = []

    for fn, emit in TARGETS:
        try:
            start = src.index(fn)
        except ValueError:
            failures.append(f"{fn}: not found in {SRC.name} (renamed?)")
            continue

        # The declared budget.
        m = re.search(r"len = (\d+) \+ (\d+) \* zname\.len", src[start:])
        if not m:
            failures.append(f"{fn}: could not parse the `len = <fixed> + <n> * zname.len` budget")
            continue
        declared, declared_n = int(m.group(1)), int(m.group(2))

        # The format string, from the emit call to the end of the call's args.
        seg_start = src.index(emit, start)
        seg_end = src.index(") - p;", seg_start)
        fmt = literals(src[seg_start:seg_end])

        n_v = fmt.count("%V")
        n_a = fmt.count("%uA")
        # A %V renders zname (budgeted separately at zname.len each) and a %uA
        # renders a value (budgeted at NGX_ATOMIC_T_LEN each), so the
        # placeholders' own bytes must come OUT of the fixed prose term.
        prose = len(fmt) - n_v * 2 - n_a * 3

        if n_v != declared_n or n_a != declared_n:
            failures.append(
                f"{fn}: budget multiplier is {declared_n} but the format string has "
                f"{n_v} %V and {n_a} %uA -- a short multiplier truncates the last metric"
            )

        need = prose + MARGIN
        if declared < need:
            failures.append(
                f"{fn}: fixed budget term is {declared} but the format string's fixed "
                f"prose measures {prose} bytes (need >= {need}, prose + {MARGIN} margin). "
                f"Re-measure the term; do not add an estimate."
            )

    check_json(src, failures)

    if failures:
        for f in failures:
            print(f"lint-admin-buffer-budget: ✗ {f}", file=sys.stderr)
        return 1

    print(f"lint-admin-buffer-budget: OK ({len(TARGETS) + 1} budget(s) measured against their format string)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
