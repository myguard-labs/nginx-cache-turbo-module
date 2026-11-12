"""Exercise backend stop methods in isolation with inert fake children."""

import ast
import os
import subprocess
import unittest
from pathlib import Path

SOURCE = Path(os.environ.get(
    "BACKEND_STOP_SOURCE", Path(__file__).resolve().parents[1] / "tools/test_runtime_base.py"
))


def stop_method(class_name):
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    cls = next(node for node in tree.body
               if isinstance(node, ast.ClassDef) and node.name == class_name)
    method = next(node for node in cls.body
                  if isinstance(node, ast.FunctionDef) and node.name == "stop")
    module = ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[]))
    scope = {"subprocess": subprocess}
    exec(compile(module, str(SOURCE), "exec"), scope)  # noqa: S102
    return scope["stop"]


class Child:
    def __init__(self, *, exited=False, failures=None):
        self.exited = exited
        self.failures = {key: list(value) for key, value in (failures or {}).items()}
        self.calls = []

    def call(self, operation):
        self.calls.append(operation)
        errors = self.failures.get(operation, [])
        if errors:
            error = errors.pop(0)
            if error is not None:
                raise error

    def poll(self):
        self.call("poll")
        return 0 if self.exited else None

    def terminate(self):
        self.call("terminate")

    def kill(self):
        self.call("kill")

    def wait(self, timeout):
        self.calls.append(("timeout", timeout))
        self.call("wait")
        self.exited = True
        return 0


class Owner:
    def __init__(self, process):
        self.process = process


class BackendStopTests(unittest.TestCase):
    classes = ("RedisServer", "MemcachedServer")

    def test_absent_exited_and_graceful(self):
        for name in self.classes:
            with self.subTest(name=name):
                stop = stop_method(name)
                absent = Owner(None)
                stop(absent)
                self.assertIsNone(absent.process)
                for child, expected in ((Child(exited=True), ["poll"]),
                                        (Child(), ["poll", "terminate", ("timeout", 10), "wait"])):
                    owner = Owner(child)
                    stop(owner)
                    self.assertIsNone(owner.process)
                    self.assertEqual(child.calls, expected)

    def test_hung_child_is_killed_and_reaped(self):
        for name in self.classes:
            with self.subTest(name=name):
                child = Child(failures={"wait": [subprocess.TimeoutExpired("fake", 10)]})
                owner = Owner(child)
                stop_method(name)(owner)
                self.assertEqual(child.calls, ["poll", "terminate", ("timeout", 10), "wait",
                                               "kill", ("timeout", 10), "wait"])
                self.assertTrue(child.exited)
                self.assertIsNone(owner.process)

    def test_failures_retain_handle_and_propagate(self):
        for name in self.classes:
            for stage in ("poll", "terminate", "wait", "kill", "post-kill wait",
                          "post-kill timeout"):
                with self.subTest(name=name, stage=stage):
                    error = (subprocess.TimeoutExpired("fake", 10)
                             if stage == "post-kill timeout" else OSError(stage))
                    failures = {stage: [error]}
                    if stage == "kill":
                        failures["wait"] = [subprocess.TimeoutExpired("fake", 10)]
                    elif stage in ("post-kill wait", "post-kill timeout"):
                        failures = {"wait": [subprocess.TimeoutExpired("fake", 10), error]}
                    child = Child(failures=failures)
                    owner = Owner(child)
                    with self.assertRaises(type(error)) as caught:
                        stop_method(name)(owner)
                    self.assertIs(caught.exception, error)
                    self.assertIs(owner.process, child)
                    self.assertFalse(child.exited)

    def test_base_exceptions_propagate(self):
        for name in self.classes:
            for error in (KeyboardInterrupt(), SystemExit()):
                with self.subTest(name=name, error=type(error)):
                    child = Child(failures={"terminate": [error]})
                    owner = Owner(child)
                    with self.assertRaises(type(error)) as caught:
                        stop_method(name)(owner)
                    self.assertIs(caught.exception, error)
                    self.assertIs(owner.process, child)


if __name__ == "__main__":
    unittest.main()
