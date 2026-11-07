#!/usr/bin/env python3
"""Fail when a pre-commit @area map entry would run a fault-only test ungated.

run_all() (ci/tools/test_runtime.py) calls some tests only under
`if ng.fault_injection:`. The pre-commit selector runs tests of an areas/*.py
file by name, bypassing run_all(), so it must apply the same capability gating
(CT-HOOK-AREA-FAULT-ONLY-TESTS). This lint derives the fault-only set from
run_all() (ci/tools/fault_only_tests.py, never a hand-copied list) and, for
every `@area A` row of the map whose areas/A.py defines a fault-only test,
runs the selector in --dry-run and requires its plan line for that area to
report `fault-only=<n>` with n equal to the derived count. A selector that
does not gate (no count, or a different count) fails, naming the map row, the
area and the tests that would run ungated. An empty derived set fails too: it
means the derivation broke, not that nothing is gated.

Usage: lint-fault-gate.py [--root DIR] [--selector FILE]
  --root      repo root holding ci/tools/{test_runtime.py,areas,precommit-test-map.tsv}
              (default: the repo containing this script)
  --selector  selector script (default: <root>/ci/tools/precommit-tests.sh)
Exit 0 + OK line; 1 naming each ungated area; 2 on a usage/derivation error.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _load_fault_only():
    spec = importlib.util.spec_from_file_location(
        "fault_only_tests", HERE / "fault_only_tests.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.fault_only_tests


def area_defs(path: Path) -> set[str]:
    return set(re.findall(r"^def (test_\w+)\(", path.read_text(), re.MULTILINE))


def map_area_rows(map_path: Path) -> list[tuple[int, list[str], str]]:
    rows = []
    for no, line in enumerate(map_path.read_text().splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 3 or not parts[2].startswith("@area "):
            continue
        for area in parts[2].split()[1:]:
            rows.append((no, parts[0].split("|"), area))
    return rows


def probe_plan_line(root: Path, selector: Path, map_path: Path,
                    literal: str, area: str) -> str:
    """The selector's --dry-run plan line for `area`, or '' when none."""
    env = dict(os.environ, PRECOMMIT_ROOT=str(root))
    env.pop("PRECOMMIT_TESTS", None)
    r = subprocess.run(
        ["bash", str(selector), "--dry-run", "--map", str(map_path),
         "--files", literal],
        capture_output=True, text=True, env=env, check=False)
    if r.returncode != 0:
        return ""
    return next((ln for ln in r.stdout.splitlines()
                 if f"areas/{area}.py" in ln), "")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(HERE.parent.parent))
    ap.add_argument("--selector")
    args = ap.parse_args()
    root = Path(args.root).resolve()
    selector = Path(args.selector) if args.selector else root / "ci/tools/precommit-tests.sh"
    map_path = root / "ci/tools/precommit-test-map.tsv"
    try:
        fault_only = set(_load_fault_only()(root / "ci/tools/test_runtime.py"))
    except (OSError, SyntaxError, ValueError) as exc:
        print(f"lint-fault-gate: cannot derive fault-only tests: {exc}", file=sys.stderr)
        return 2
    if not fault_only:
        print("lint-fault-gate: FAIL: run_all() yields no fault-only tests "
              "(derivation broke?)", file=sys.stderr)
        return 1

    bad = 0
    checked = 0
    probed: set[str] = set()
    for lineno, globs, area in map_area_rows(map_path):
        if area in probed:
            continue
        area_py = root / "ci/tools/areas" / f"{area}.py"
        if not area_py.is_file():
            print(f"lint-fault-gate: {map_path.name}:{lineno}: @area {area}: "
                  f"{area_py} missing", file=sys.stderr)
            return 2
        hit = sorted(area_defs(area_py) & fault_only)
        probed.add(area)
        if not hit:
            continue
        literal = next((g for g in globs if not re.search(r"[*?\[]", g)), None)
        if literal is None:
            print(f"lint-fault-gate: {map_path.name}:{lineno}: no literal path "
                  f"to probe @area {area}", file=sys.stderr)
            return 2
        line = probe_plan_line(root, selector, map_path, literal, area)
        want = f"fault-only={len(hit)}"
        checked += 1
        if want not in line:
            bad += 1
            print(f"lint-fault-gate: FAIL: {map_path.name}:{lineno} @area {area} "
                  f"would run {len(hit)} fault-only test(s) without the "
                  f"capability gate (selector {selector.name} plan line "
                  f"{line!r} lacks {want}): {', '.join(hit)}", file=sys.stderr)
    if bad:
        return 1
    print(f"lint-fault-gate: OK ({len(fault_only)} fault-only tests, "
          f"{checked} gated @area map entr{'y' if checked == 1 else 'ies'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
