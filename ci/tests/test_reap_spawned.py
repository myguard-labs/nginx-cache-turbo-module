"""Exercise the fallback reaper using only its source AST and fake children."""

import ast
import contextlib
import io
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

SOURCE = Path(os.environ.get(
    "REAPER_SOURCE", Path(__file__).resolve().parents[1] / "tools/test_runtime_base.py"
))


def reaper(children):
    tree = ast.parse(SOURCE.read_text())
    func = next(node for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == "_reap_spawned")
    module = ast.fix_missing_locations(ast.Module(body=[func], type_ignores=[]))
    scope = {"_SPAWNED": children, "subprocess": subprocess, "sys": sys, "time": time}
    exec(compile(module, str(SOURCE), "exec"), scope)  # noqa: S102
    scope["_reap_spawned"]()


class Child:
    def __init__(self, *, exited=False, failures=None):
        self.exited = exited
        self.failures = {name: list(errors) for name, errors in (failures or {}).items()}
        self.calls = []

    def _call(self, name):
        self.calls.append(name)
        errors = self.failures.get(name, [])
        if errors:
            error = errors.pop(0)
            if error:
                raise error

    def poll(self):
        self._call("poll")
        return 0 if self.exited else None

    def terminate(self):
        self._call("terminate")

    def wait(self, timeout):
        self.calls.append(("timeout", timeout))
        self._call("wait")
        self.exited = True
        return 0

    def kill(self):
        self._call("kill")


class ReaperTests(unittest.TestCase):
    def test_empty_exited_and_graceful(self):
        reaper([])
        exited, graceful = Child(exited=True), Child()
        reaper([exited, graceful])
        self.assertEqual(exited.calls, ["poll", "poll"])
        self.assertEqual([c for c in graceful.calls if isinstance(c, str)],
                         ["poll", "terminate", "poll", "wait"])

    def test_hung_child_is_waited_after_kill(self):
        child = Child(failures={"wait": [subprocess.TimeoutExpired("fake", 5)]})
        reaper([child])
        self.assertEqual([c for c in child.calls if isinstance(c, str)],
                         ["poll", "terminate", "poll", "wait", "kill", "wait"])
        self.assertTrue(all(0 < c[1] <= 5 for c in child.calls if isinstance(c, tuple)))

    def test_errors_do_not_skip_later_children(self):
        for operation in ("poll", "terminate", "wait", "kill"):
            with self.subTest(operation=operation):
                failures = {operation: [OSError(operation)]}
                if operation == "kill":
                    failures["wait"] = [subprocess.TimeoutExpired("fake", 5)]
                first, later = Child(failures=failures), Child()
                with contextlib.redirect_stderr(io.StringIO()) as errors:
                    reaper([first, later])
                self.assertIn(operation, errors.getvalue())
                self.assertIn("terminate", later.calls)
                self.assertIn("wait", later.calls)

    def test_unresolved_child_remains_owned_and_reported(self):
        child = Child(failures={"wait": [subprocess.TimeoutExpired("fake", 5),
                                         subprocess.TimeoutExpired("fake", 0.1)],
                                "kill": [OSError("kill failed")]})
        children = [child]
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            reaper(children)
        self.assertEqual(children, [child])
        self.assertFalse(child.exited)
        self.assertIn("post-kill wait failed", errors.getvalue())

    def test_base_exceptions_propagate(self):
        for error in (KeyboardInterrupt(), SystemExit()):
            with self.subTest(error=type(error)), self.assertRaises(type(error)):
                reaper([Child(failures={"terminate": [error]})])


if __name__ == "__main__":
    unittest.main()
