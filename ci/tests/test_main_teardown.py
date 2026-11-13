"""Exercise the main runtime teardown directly from its source AST."""

import ast
import contextlib
import io
import os
import traceback
import unittest
from pathlib import Path

SOURCE = Path(os.environ.get(
    "TEARDOWN_SOURCE", Path(__file__).resolve().parents[1] / "tools/test_runtime.py"
))
NAMES = ("ng", "redis", "redis_auth", "redis_tls", "redis_tls_untrusted",
         "redis_tls_expired", "mc", "origin")


def teardown(body, owners):
    tree = ast.parse(SOURCE.read_text())
    matches = [node for node in ast.walk(tree) if isinstance(node, ast.Try)
               and any(isinstance(child, ast.Expr)
                       and isinstance(child.value, ast.Call)
                       and isinstance(child.value.func, ast.Attribute)
                       and child.value.func.attr == "stop"
                       for child in ast.walk(ast.Module(body=node.finalbody, type_ignores=[])))]
    # The runtime teardown owns origin and nginx in the _main implementation.
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                and node.name == "_main")
    matches = [node for node in matches if node in list(ast.walk(main))
               and any(isinstance(child, ast.Name) and child.id == "origin"
                       for stmt in node.finalbody for child in ast.walk(stmt))]
    assert len(matches) == 1
    test = ast.Try(body=[ast.Expr(value=ast.Call(func=ast.Name(id="body", ctx=ast.Load()),
                                                args=[], keywords=[]))],
                   handlers=matches[0].handlers, orelse=[], finalbody=matches[0].finalbody)
    initialize = ast.Assign(targets=[ast.Name(id="body_failed", ctx=ast.Store())],
                            value=ast.Constant(value=False))
    module = ast.fix_missing_locations(ast.Module(body=[initialize, test], type_ignores=[]))
    scope = dict(owners, body=body, traceback=traceback)
    exec(compile(module, str(SOURCE), "exec"), scope)  # noqa: S102


class StopError(Exception):
    pass


class Owner:
    def __init__(self, name, calls, fail=False):
        self.name, self.calls, self.fail = name, calls, fail

    def stop(self):
        self.calls.append(self.name)
        if self.fail:
            raise StopError(self.name)


class MainTeardownTests(unittest.TestCase):
    def run_case(self, absent=(), failures=(), body_error=None):
        calls = []
        owners = {name: None if name in absent else Owner(name, calls, name in failures)
                  for name in NAMES}

        def body():
            if body_error is not None:
                raise body_error

        output = io.StringIO()
        caught = None
        try:
            with contextlib.redirect_stderr(output):
                teardown(body, owners)
        except BaseException as error:
            caught = error
        return calls, caught, output.getvalue()

    def test_success_and_optional_owners(self):
        for absent in ((), NAMES[1:-1]):
            with self.subTest(absent=absent):
                calls, error, output = self.run_case(absent=absent)
                self.assertEqual(calls, [name for name in NAMES if name not in absent])
                self.assertIsNone(error)
                self.assertEqual(output, "")

    def test_body_error_survives(self):
        body_error = ValueError("body")
        calls, error, _ = self.run_case(body_error=body_error)
        self.assertEqual(calls, list(NAMES))
        self.assertIs(error, body_error)
        self.assertIn("body", [frame.name for frame in traceback.extract_tb(error.__traceback__)])

    def test_cleanup_failure_inside_caller_exception_handler(self):
        try:
            raise ValueError("caller")
        except ValueError:
            calls, error, _ = self.run_case(failures=("ng",))
        self.assertEqual(calls, list(NAMES))
        self.assertIsInstance(error, StopError)

    def test_single_and_multiple_stop_errors(self):
        for failures in (("ng",), ("ng", "redis_tls", "origin")):
            with self.subTest(failures=failures):
                calls, error, output = self.run_case(failures=failures)
                self.assertEqual(calls, list(NAMES))
                self.assertIsInstance(error, StopError)
                self.assertEqual(str(error), failures[0])
                for name in failures:
                    self.assertIn(f"StopError: {name}", output)

    def test_body_error_survives_stop_errors(self):
        body_error = ValueError("body")
        calls, error, output = self.run_case(failures=("ng", "origin"), body_error=body_error)
        self.assertEqual(calls, list(NAMES))
        self.assertIs(error, body_error)
        self.assertIn("body", [frame.name for frame in traceback.extract_tb(error.__traceback__)])
        self.assertIn("StopError: ng", output)
        self.assertIn("StopError: origin", output)


if __name__ == "__main__":
    unittest.main()
