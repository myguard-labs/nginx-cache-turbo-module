#!/usr/bin/env python3
"""List the tests run_all() calls ONLY under an `if ng.fault_injection:` block.

WHY: run_all() in ci/tools/test_runtime.py skips these tests on a build
without fault injection (no --fault-injection / no TEST_FAULTS). The
pre-commit selector (ci/tools/precommit-tests.sh) runs tests of an areas/*.py
file by name, bypassing run_all(), so it must apply the same capability
gating or a plain build fails on tests that only exist for fault builds
(CT-HOOK-AREA-FAULT-ONLY-TESTS). The set is derived from run_all() here, by
AST, never copied by hand.

A test also called anywhere outside such a block is NOT fault-only: it runs
on every build. Only bare-name calls directly in run_all() are considered,
matching lint-orphan-tests.py's reachability model. A condition counts as the
fault gate when it is `ng.fault_injection` or an `and` containing it.

Usage: fault_only_tests.py [path-to-test_runtime.py | --root REPO]
       (one name per line; --root REPO reads REPO/ci/tools/test_runtime.py and
       prints nothing when that file does not exist: a tree without the full
       suite has no run_all() whose gating could be mirrored)
Exit 0; 2 when run_all() is missing or the file cannot be parsed.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path


def _is_fault_attr(node: ast.AST) -> bool:
    return (isinstance(node, ast.Attribute) and node.attr == "fault_injection"
            and isinstance(node.value, ast.Name) and node.value.id == "ng")


def _is_fault_gate(test: ast.AST) -> bool:
    if _is_fault_attr(test):
        return True
    return (isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And)
            and any(_is_fault_gate(v) for v in test.values))


def fault_only_tests(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    run_all = next((n for n in ast.walk(tree)
                    if isinstance(n, ast.FunctionDef) and n.name == "run_all"),
                   None)
    if run_all is None:
        raise ValueError(f"{path}: no run_all()")
    gated: dict[str, None] = {}
    plain: set[str] = set()

    def visit(node: ast.AST, in_fault: bool) -> None:
        if isinstance(node, ast.If) and _is_fault_gate(node.test):
            for child in node.body:
                visit(child, True)
            for child in node.orelse:
                visit(child, in_fault)
            return
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id.startswith("test_")):
            if in_fault:
                gated.setdefault(node.func.id)
            else:
                plain.add(node.func.id)
        for child in ast.iter_child_nodes(node):
            visit(child, in_fault)

    for stmt in run_all.body:
        visit(stmt, False)
    return [n for n in gated if n not in plain]


def main() -> int:
    argv = sys.argv[1:]
    if len(argv) == 2 and argv[0] == "--root":
        path = Path(argv[1]) / "ci/tools/test_runtime.py"
        if not path.is_file():
            return 0
    else:
        path = Path(argv[0] if argv else "ci/tools/test_runtime.py")
    try:
        names = fault_only_tests(path)
    except (OSError, SyntaxError, ValueError) as exc:
        print(f"fault_only_tests: {exc}", file=sys.stderr)
        return 2
    print("\n".join(names))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
