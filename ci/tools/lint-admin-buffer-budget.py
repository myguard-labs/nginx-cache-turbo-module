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

    if failures:
        for f in failures:
            print(f"lint-admin-buffer-budget: ✗ {f}", file=sys.stderr)
        return 1

    print(f"lint-admin-buffer-budget: OK ({len(TARGETS)} budget(s) measured against their format string)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
