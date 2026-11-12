"""Exercise AbortRig entry and cleanup with inert owners."""

import ast
import pathlib
import traceback
import types
import unittest
from collections.abc import Callable

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "tools/abort_fixture.py"


def rig_class():
    tree = ast.parse(SOURCE.read_text())
    rig = next(node for node in tree.body
               if isinstance(node, ast.ClassDef) and node.name == "AbortRig")
    methods = [node for node in rig.body if isinstance(node, ast.FunctionDef)
               and node.name in ("__enter__", "__exit__")]
    cls = ast.ClassDef(name="Rig", bases=[], keywords=[], body=methods,
                       decorator_list=[])
    module = ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[]))
    namespace = {"Callable": Callable, "AbortRig": object}
    exec(compile(module, str(SOURCE), "exec"), namespace)
    return namespace["Rig"]


class AbortRigEntryTests(unittest.TestCase):
    def make_rig(self, failures=None, prime=True):
        calls = []
        failures = failures or {}

        def action(name):
            def invoke(*_args):
                calls.append(name)
                if name in failures:
                    raise failures[name]
            return invoke

        class Proxy:
            start = staticmethod(action("start_proxy"))
            stop = staticmethod(action("stop_proxy"))

            @property
            def delay(self):
                return self._delay

            @delay.setter
            def delay(self, value):
                action("delay")()
                self._delay = value

        rig = rig_class()()
        rig.proxy = Proxy()
        rig.node = types.SimpleNamespace(write_config=action("write"),
                                         config_test=action("config"),
                                         start=action("start_node"),
                                         stop=action("stop_node"))
        rig.site = types.SimpleNamespace(prime=prime, arrange=action("arrange"),
                                         forget=lambda uri: action(uri)())
        rig._prime = action("prime")
        rig.proxy_delay = 42
        rig.uris = ["a", "b"]
        rig.retired = ["c"]
        return rig, calls

    def test_success_order_and_prime_toggle(self):
        for prime in (True, False):
            with self.subTest(prime=prime):
                rig, calls = self.make_rig(prime=prime)
                self.assertIs(rig.__enter__(), rig)
                self.assertEqual(calls, ["start_proxy", "write", "config", "start_node"]
                                 + (["prime"] if prime else []) + ["delay", "arrange"])
                self.assertEqual(rig.proxy.delay, 42)

    def test_each_entry_failure_cleans_up(self):
        for stage in ("start_proxy", "write", "config", "start_node", "prime", "delay", "arrange"):
            with self.subTest(stage=stage):
                failure = ValueError(stage)
                rig, calls = self.make_rig({stage: failure})
                with self.assertRaises(ValueError) as caught:
                    rig.__enter__()
                self.assertIs(caught.exception, failure)
                self.assertEqual(calls[-5:], ["stop_node", "stop_proxy", "a", "b", "c"])

    def test_cleanup_failures_preserve_setup_error_and_attempt_all(self):
        primary = ValueError("setup")
        rig, calls = self.make_rig({"write": primary, "stop_node": RuntimeError("node"),
                                    "stop_proxy": RuntimeError("proxy"),
                                    "b": RuntimeError("forget")})
        try:
            rig.__enter__()
        except ValueError as error:
            self.assertIs(error, primary)
            frames = traceback.extract_tb(error.__traceback__)
            self.assertIn("invoke", [frame.name for frame in frames])
            self.assertEqual(len(error.__notes__), 3)
            for message in ("node", "proxy", "forget"):
                self.assertIn(message, " ".join(error.__notes__))
        else:
            self.fail("setup error did not propagate")
        self.assertEqual(calls[-5:], ["stop_node", "stop_proxy", "a", "b", "c"])

    def test_base_exception_setup_and_cleanup(self):
        primary = KeyboardInterrupt("setup")
        rig, calls = self.make_rig({"start_proxy": primary, "stop_node": RuntimeError("cleanup")})
        with self.assertRaises(KeyboardInterrupt) as caught:
            rig.__enter__()
        self.assertIs(caught.exception, primary)
        self.assertIn("cleanup", " ".join(primary.__notes__))
        self.assertEqual(calls[-5:], ["stop_node", "stop_proxy", "a", "b", "c"])
        cleanup = SystemExit("cleanup")
        rig, calls = self.make_rig({"write": ValueError("setup"), "stop_proxy": cleanup})
        with self.assertRaises(SystemExit) as caught:
            rig.__enter__()
        self.assertIs(caught.exception, cleanup)
        self.assertEqual(calls[-2:], ["stop_node", "stop_proxy"])


if __name__ == "__main__":
    unittest.main()
