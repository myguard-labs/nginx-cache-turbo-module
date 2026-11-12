"""Exercise the real AbortRig exit method with inert cleanup owners."""

import ast
import pathlib
import types
import unittest
from collections.abc import Callable

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "tools/abort_fixture.py"


def exit_method():
    tree = ast.parse(SOURCE.read_text())
    rig = next(node for node in tree.body
               if isinstance(node, ast.ClassDef) and node.name == "AbortRig")
    method = next(node for node in rig.body
                  if isinstance(node, ast.FunctionDef) and node.name == "__exit__")
    module = ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[]))
    namespace = {"Callable": Callable}
    exec(compile(module, str(SOURCE), "exec"), namespace)
    return namespace["__exit__"]


class AbortRigExitTests(unittest.TestCase):
    def run_exit(self, failures=None, body=None, uris=None, retired=None):
        calls = []
        failures = failures or {}

        def action(name):
            def invoke(*args):
                key = args[0] if args else name
                calls.append(key)
                if key in failures:
                    raise failures[key]
            return invoke

        rig = types.SimpleNamespace(
            node=types.SimpleNamespace(stop=action("node")),
            proxy=types.SimpleNamespace(stop=action("proxy")),
            site=types.SimpleNamespace(forget=action("forget")),
            uris=["a", "b"] if uris is None else uris,
            retired=["c"] if retired is None else retired,
        )
        try:
            if body is None:
                exit_method()(rig, None, None, None)
            else:
                try:
                    raise body
                except Exception as error:
                    exit_method()(rig, type(error), error, error.__traceback__)
                    raise
        except BaseException as error:
            return calls, error
        return calls, None

    def test_success_and_empty(self):
        self.assertEqual(self.run_exit(), (["node", "proxy", "a", "b", "c"], None))
        self.assertEqual(self.run_exit(uris=[], retired=[]), (["node", "proxy"], None))
        self.assertEqual(self.run_exit(uris=[], retired=["c"]),
                         (["node", "proxy", "c"], None))

    def test_each_failure_does_not_skip_later_cleanup(self):
        for key in ("node", "proxy", "a", "b"):
            with self.subTest(key=key):
                failure = RuntimeError(key)
                calls, error = self.run_exit({key: failure})
                self.assertEqual(calls, ["node", "proxy", "a", "b", "c"])
                self.assertIs(error, failure)

    def test_multiple_failures_preserve_first_and_note_later(self):
        first, second = ValueError("first"), RuntimeError("second")
        calls, error = self.run_exit({"node": first, "b": second})
        self.assertEqual(calls, ["node", "proxy", "a", "b", "c"])
        self.assertIs(error, first)
        self.assertIn("second", " ".join(error.__notes__))

    def test_body_identity_and_cleanup_context(self):
        body = ValueError("body")
        calls, error = self.run_exit({"node": RuntimeError("cleanup")}, body)
        self.assertEqual(calls, ["node", "proxy", "a", "b", "c"])
        self.assertIs(error, body)
        self.assertIn("cleanup", " ".join(error.__notes__))

    def test_base_exception_propagates(self):
        interrupt = KeyboardInterrupt()
        calls, error = self.run_exit({"proxy": interrupt})
        self.assertEqual(calls, ["node", "proxy"])
        self.assertIs(error, interrupt)


if __name__ == "__main__":
    unittest.main()
