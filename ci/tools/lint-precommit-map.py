#!/usr/bin/env python3
"""Fail when ci/tools/precommit-test-map.tsv does not cover the tree (CI-P4).

The pre-commit selector (precommit-tests.sh) runs only what the map names, so a
source or test file with no row would be committed with ZERO checks and nothing
would say so. This is the mapping twin of lint-orphan-tests.py: every
  * src/*.c
  * ci/tools/areas/<area>.py (not __init__.py)
  * ci/tests/unit/{check_*, test_*.c, extract_*.sh}
must match at least one row glob. It also validates the rows themselves
(3 TAB columns, known `needs`, existing `@area` names) and that no row selects
a whole suite (run_all, test_runtime.py, ci/tests/unit/run.sh).

Usage: lint-precommit-map.py [--root DIR] [--map FILE]
Exit:  0 clean, 1 findings, 2 usage / unreadable map.
"""

from __future__ import annotations

import argparse
import fnmatch
import pathlib
import re
import sys

NEEDS = {"none", "build", "clang"}
WHOLE_SUITE = re.compile(r"run_all|test_runtime\.py|tests/unit/run\.sh|ci/tools/test_runtime")


def parse_map(path: pathlib.Path):
    """Return (rows, problems); rows are (lineno, globs, needs, command)."""
    rows, problems = [], []
    for n, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        cols = line.split("\t")
        if len(cols) != 3 or not all(c.strip() for c in cols):
            problems.append(f"{path.name}:{n}: expected 3 non-empty TAB columns")
            continue
        globs, needs, cmd = cols
        rows.append((n, globs.split("|"), needs, cmd))
    return rows, problems


def universe(root: pathlib.Path):
    files = sorted(root.glob("src/*.c"))
    files += sorted(p for p in root.glob("ci/tools/areas/*.py") if p.name != "__init__.py")
    unit = root / "ci" / "tests" / "unit"
    for pat in ("check_*", "test_*.c", "extract_*.sh"):
        files += sorted(unit.glob(pat))
    return [p.relative_to(root).as_posix() for p in files]


def check(root: pathlib.Path, map_path: pathlib.Path) -> list[str]:
    rows, problems = parse_map(map_path)
    for n, _globs, needs, cmd in rows:
        if needs not in NEEDS:
            problems.append(f"{map_path.name}:{n}: unknown needs '{needs}'")
        if WHOLE_SUITE.search(cmd):
            problems.append(f"{map_path.name}:{n}: row selects a whole suite: {cmd}")
        if cmd.startswith("@area "):
            for area in cmd.split()[1:]:
                if not (root / "ci" / "tools" / "areas" / f"{area}.py").is_file():
                    problems.append(f"{map_path.name}:{n}: no such area '{area}'")
    for rel in universe(root):
        if not any(fnmatch.fnmatchcase(rel, g) for _n, gl, _x, _c in rows for g in gl):
            problems.append(
                f"{rel}: no row in {map_path.name} "
                "(map it, or the pre-commit hook runs nothing for it)"
            )
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    here = pathlib.Path(__file__).resolve().parent
    ap.add_argument("--root", type=pathlib.Path, default=here.parent.parent)
    ap.add_argument("--map", type=pathlib.Path)
    args = ap.parse_args()
    map_path = args.map or args.root / "ci" / "tools" / "precommit-test-map.tsv"
    if not map_path.is_file():
        print(f"lint-precommit-map: map not found: {map_path}", file=sys.stderr)
        return 2
    problems = check(args.root, map_path)
    for p in problems:
        print(f"lint-precommit-map: {p}", file=sys.stderr)
    if not problems:
        print("lint-precommit-map: map covers every src/area/unit file")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
