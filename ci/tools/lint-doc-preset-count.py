#!/usr/bin/env python3
"""Fail CI when README.md's CMS-preset claims drift from the C source.

README.md:572 said "it named 3 of the 29 presets that now exist" while
ngx_http_cache_turbo_backend_names[] held 34 distinct preset bits. The count had
rotted silently across several preset-adding PRs -- nothing in CI reads a doc
sentence, so a hand-written number in prose is only ever correct on the day it is
typed. Same defect class as the DOC-A/DOC-C rows: documentation asserting a fact
about the source with no mechanical link to it.

The array is the ONLY authority. It is the table the config parser walks, so a
name absent from it is a config error however the README spells it, and a bit
present in it is a shipped preset however the README counts.

Two checks, both derived from the array rather than from a second hardcoded list:

  1. COUNT -- every "<N> presets that now exist"-shaped claim in README.md must
     equal the number of DISTINCT preset bits, excluding the NONE sentinel.
     Distinct BITS, not rows: `mantis`/`mantisbt` are two spellings of one
     preset, and counting rows would inflate the number by the alias count.

  2. COVERAGE -- every accepted spelling in the array (excluding `none`) must
     appear somewhere in README.md as `backtick-quoted` text. This catches the
     other half of the drift: a preset added to the source and never documented
     at all, which no count check can see because the author updates the number
     from the source and the name list from nothing.

Deliberately NOT checked: that the directive-table list is in array order, or
that each name appears in a specific section. Both would fail on harmless
editorial reordering and train --no-verify, which costs more than the drift.

Usage: ci/tools/lint-doc-preset-count.py [repo-root]
Exit 0 + "OK" line on a clean run; exit 1 naming every drifted claim and every
undocumented preset on a regression. No side effects, reads two files.

Extend here: if a second doc surface grows a preset count (docs/README.md, the
published guide), add its path to DOC_PATHS -- the count regex is deliberately
shaped around the claim's wording, not around README.md specifically.
"""

import re
import sys
from pathlib import Path

SRC = Path("src/ngx_http_cache_turbo_module.c")
DOC_PATHS = [Path("README.md")]

# The array's rows: { "name", NGX_HTTP_CACHE_TURBO_BACKEND_BIT, implies },
# possibly wrapped across lines between the `= {` and the closing `};`.
ARRAY_RE = re.compile(
    r"ngx_http_cache_turbo_backend_names\[\]\s*=\s*\{(.*?)\n\};", re.S
)
ROW_RE = re.compile(r'\{\s*"([a-z0-9]+)"\s*,\s*(NGX_HTTP_CACHE_TURBO_BACKEND_[A-Z0-9]+)')

# "3 of the 29 presets that now exist" -- capture the number, allow any prose
# between it and the trailing phrase so a rewording does not silently disable
# the check.
#
# Matched against the WHOLE file, not line by line: the claim is inside a
# blockquote and wraps mid-phrase ("...that now\n>   exist"), so a per-line scan
# finds nothing and reports the sentence as reworded. `\s` therefore has to
# tolerate the newline plus the "> " continuation marker.
COUNT_RE = re.compile(r"(\d+)[\s>]+presets[\s>]+that[\s>]+now[\s>]+exist")


def parse_presets(root):
    text = (root / SRC).read_text(encoding="utf-8")
    m = ARRAY_RE.search(text)
    if not m:
        sys.exit(
            f"{SRC}: ngx_http_cache_turbo_backend_names[] not found -- the lint "
            "cannot verify anything, so this is a hard failure, not a skip"
        )
    rows = ROW_RE.findall(m.group(1))
    if not rows:
        sys.exit(f"{SRC}: backend_names[] parsed to zero rows")
    names = [n for n, _ in rows if n != "none"]
    bits = {b for _, b in rows if not b.endswith("_NONE")}
    return names, bits


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    names, bits = parse_presets(root)
    expected = len(bits)
    errors = []

    for doc in DOC_PATHS:
        path = root / doc
        text = path.read_text(encoding="utf-8")

        claims = 0
        for m in COUNT_RE.finditer(text):
            claims += 1
            got = int(m.group(1))
            if got != expected:
                lineno = text.count("\n", 0, m.start()) + 1
                errors.append(
                    f"{doc}:{lineno}: claims {got} presets, "
                    f"backend_names[] has {expected} distinct bits"
                )
        if claims == 0:
            errors.append(
                f"{doc}: no '<N> presets that now exist' claim found -- either "
                "the sentence was reworded (update COUNT_RE) or the count check "
                "is silently doing nothing"
            )

        for name in names:
            if f"`{name}`" not in text:
                errors.append(
                    f"{doc}: preset `{name}` is accepted by backend_names[] but "
                    "is not documented"
                )

    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        return 1

    print(f"OK: {expected} presets, {len(names)} accepted spellings, all documented")
    return 0


if __name__ == "__main__":
    sys.exit(main())
