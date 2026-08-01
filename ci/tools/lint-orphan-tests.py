#!/usr/bin/env python3
"""Fail CI if a test_*() in ci/tools/test_runtime.py is defined but never
invoked from run_all() (CI-REG1).

test_l2_forged_blob_cannot_inject_headers shipped in PR #178 defined at
test_runtime.py:13517 with no call site: run_all() never invoked it, so the
security gate it was written to prove had never executed in CI. This is the
SECOND time this file has shipped tests that are defined, collected (by
py_compile / import) and executed zero times while the suite still exits 0
(first occurrence: five tests, 2026-07-26). Prose guidance in the CI skill did
not stop the repeat, so this check is mechanical: parse the file with `ast`
(not regex -- a regex call-site scanner misses attribute calls, conditional
calls, calls split across lines, etc. and produces a false green, which is
worse than not having the lint) and diff "defined" against "reachable from
run_all()".

Reachability is NOT just run_all()'s own body: if run_all ever grows a call
to a helper function that itself calls test_*() (a "run_group"-style
wrapper), those calls must count too, or a refactor that introduces such a
helper silently blinds this lint back to zero. So this walks run_all()'s
body for calls to test_* names directly, AND recursively follows any
non-test_* function call made from within run_all() (or from an
already-followed helper) into that function's body, collecting further
test_* calls found there. As of 2026-08-01 run_all() has no such helper --
every test_*() call is direct -- but the lint does not assume that stays true.

Usage: ci/tools/lint-orphan-tests.py [path-to-test_runtime.py]
Exit 0 + "OK" line on a clean run, exit 1 naming every orphaned test on a
regression.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

# Explicit opt-out list for tests that are deliberately never called from
# run_all() -- e.g. a manual/exploratory harness kept in-tree for a human to
# invoke directly. Each entry needs a comment saying WHY it's here. Do not
# add a test to this list just to make the lint pass; an orphan found that
# isn't already explained here is a real regression -- report it, don't
# silence it.
ALLOWED_ORPHANS: set[str] = set((
    # (none as of 2026-08-01)
))


def defined_tests(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    out: dict[str, ast.FunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            out[node.name] = node
    return out


def called_names(node: ast.AST) -> set[str]:
    """Every bare-name function call made directly inside `node`'s body
    (not walking into nested FunctionDefs -- callers are resolved by the
    reachability BFS below, not by flattening everything up front)."""
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child is not node:
            continue  # a nested def's body is that def's own scope
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
            names.add(child.func.id)
    return names


def reachable_tests_from_run_all(
    tree: ast.Module, run_all: ast.FunctionDef, all_funcs: dict[str, ast.FunctionDef]
) -> set[str]:
    """BFS over run_all()'s call graph. Any test_* name reached, directly or
    through a chain of plain function calls, counts as invoked."""
    reached_tests: set[str] = set()
    seen_helpers: set[str] = set()
    frontier = [run_all]
    while frontier:
        fn = frontier.pop()
        for name in called_names(fn):
            if name.startswith("test_"):
                reached_tests.add(name)
            elif name in all_funcs and name not in seen_helpers and all_funcs[name] is not fn:
                seen_helpers.add(name)
                frontier.append(all_funcs[name])
    return reached_tests


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "ci/tools/test_runtime.py")
    src = path.read_text()
    tree = ast.parse(src, filename=str(path))

    tests = defined_tests(tree)

    all_funcs: dict[str, ast.FunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            all_funcs[node.name] = node

    run_all = all_funcs.get("run_all")
    if run_all is None:
        print(f"lint-orphan-tests: {path}: no run_all() found -- refusing to "
              "report OK on a file this lint cannot parse", file=sys.stderr)
        return 1

    reached = reachable_tests_from_run_all(tree, run_all, all_funcs)

    orphans = sorted(set(tests) - reached - ALLOWED_ORPHANS)
    stale_allow = sorted(ALLOWED_ORPHANS - set(tests))

    status = 0
    if stale_allow:
        for name in stale_allow:
            print(f"lint-orphan-tests: {path}: ALLOWED_ORPHANS lists "
                  f"'{name}' but no such test_* is defined any more -- "
                  "remove the stale opt-out entry", file=sys.stderr)
        status = 1

    if orphans:
        for name in orphans:
            lineno = tests[name].lineno
            print(f"lint-orphan-tests: {path}:{lineno}: '{name}' is defined "
                  "but never called from run_all() (or a helper it calls) -- "
                  "the test never executes in CI. Call it from run_all(), or "
                  "add it to ALLOWED_ORPHANS with a comment saying why it's "
                  "deliberately manual-only.", file=sys.stderr)
        status = 1

    if status == 0:
        print(f"lint-orphan-tests: OK ({len(tests)} test_* defined, "
              f"{len(reached)} reachable from run_all(), "
              f"{len(ALLOWED_ORPHANS)} explicit opt-outs)")

    return status


if __name__ == "__main__":
    raise SystemExit(main())
