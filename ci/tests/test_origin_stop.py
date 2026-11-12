"""Exercise Origin.stop from source with inert server and thread handles."""

import ast
import os
import unittest
from pathlib import Path

SOURCE = Path(os.environ.get(
    "ORIGIN_STOP_SOURCE", Path(__file__).resolve().parents[1] / "tools/origin.py"
))


def stop_method():
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    cls = next(node for node in tree.body
               if isinstance(node, ast.ClassDef) and node.name == "Origin")
    method = next(node for node in cls.body
                  if isinstance(node, ast.FunctionDef) and node.name == "stop")
    module = ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[]))
    scope = {}
    exec(compile(module, str(SOURCE), "exec"), scope)  # noqa: S102
    return scope["stop"]


class Handle:
    def __init__(self, calls, failures=None, alive=False):
        self.calls = calls
        self.failures = failures or {}
        self.alive = alive

    def call(self, operation):
        self.calls.append(operation)
        if operation in self.failures:
            raise self.failures[operation]

    def shutdown(self):
        self.call("shutdown")

    def server_close(self):
        self.call("close")

    def join(self, timeout):
        self.calls.append(("join", timeout))
        if "join" in self.failures:
            raise self.failures["join"]

    def is_alive(self):
        self.call("is_alive")
        return self.alive


class Owner:
    def __init__(self, server, thread):
        self._server = server
        self._thread = thread


class OriginStopTests(unittest.TestCase):
    def test_stop_joins_and_repeated_stop_is_empty(self):
        calls = []
        owner = Owner(Handle(calls), Handle(calls))
        stop = stop_method()
        stop(owner)
        stop(owner)
        self.assertEqual(calls, ["shutdown", "close", ("join", 5), "is_alive"])
        self.assertIsNone(owner._server)
        self.assertIsNone(owner._thread)

    def test_serverless_thread_and_empty_owner(self):
        calls = []
        owner = Owner(None, Handle(calls))
        stop_method()(owner)
        self.assertEqual(calls, [("join", 5), "is_alive"])
        self.assertIsNone(owner._thread)
        stop_method()(Owner(None, None))

    def test_live_or_failed_join_retains_thread(self):
        for failure in (None, OSError("join")):
            with self.subTest(failure=failure):
                calls = []
                thread = Handle(calls, {"join": failure} if failure else {}, alive=True)
                owner = Owner(None, thread)
                with self.assertRaises(OSError if failure else RuntimeError):
                    stop_method()(owner)
                self.assertIs(owner._thread, thread)

    def test_cleanup_errors_are_exposed_and_remaining_steps_run(self):
        for operation in ("shutdown", "close"):
            with self.subTest(operation=operation):
                calls = []
                error = OSError(operation)
                server = Handle(calls, {operation: error})
                owner = Owner(server, Handle(calls))
                with self.assertRaises(OSError) as caught:
                    stop_method()(owner)
                self.assertIs(caught.exception, error)
                self.assertEqual(calls, ["shutdown", "close", ("join", 5), "is_alive"])
                self.assertIs(owner._server, server)
                self.assertIsNone(owner._thread)

    def test_multiple_errors_preserve_first_and_report_rest(self):
        calls = []
        error = OSError("shutdown")
        owner = Owner(Handle(calls, {"shutdown": error, "close": ValueError("close")}),
                      Handle(calls, {"join": RuntimeError("join")}))
        with self.assertRaises(OSError) as caught:
            stop_method()(owner)
        self.assertIs(caught.exception, error)
        self.assertIn("close", caught.exception.__notes__[0])
        self.assertIn("join", caught.exception.__notes__[1])
        self.assertIsNotNone(owner._server)
        self.assertIsNotNone(owner._thread)

    def test_base_exception_propagates(self):
        for operation in ("shutdown", "close", "join"):
            with self.subTest(operation=operation):
                calls = []
                error = KeyboardInterrupt()
                owner = Owner(Handle(calls, {operation: error}),
                              Handle(calls, {operation: error}))
                with self.assertRaises(KeyboardInterrupt) as caught:
                    stop_method()(owner)
                self.assertIs(caught.exception, error)


if __name__ == "__main__":
    unittest.main()
