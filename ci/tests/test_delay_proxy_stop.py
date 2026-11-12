"""Exercise the source DelayProxy.stop with inert loop/thread boundaries.

No event loop, server, thread or socket is started by these controls.
"""

import ast
import concurrent.futures
import pathlib
import types
import unittest
from collections.abc import Callable

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "tools/abort_fixture.py"


def stop_method():
    tree = ast.parse(SOURCE.read_text())
    proxy = next(node for node in tree.body
                 if isinstance(node, ast.ClassDef) and node.name == "DelayProxy")
    method = next(node for node in proxy.body
                  if isinstance(node, ast.FunctionDef) and node.name == "stop")
    module = ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[]))
    namespace = {"Callable": Callable, "concurrent": concurrent}
    exec(compile(module, str(SOURCE), "exec"), namespace)
    return namespace["stop"]


class DelayProxyStopTests(unittest.TestCase):
    def rig(self, failures=None, alive=False, loop=True, thread=True, server=True, execute=True):
        calls = []
        ownership = []
        queued = []
        failures = failures or {}

        def action(name, result=None):
            def invoke(*args, **kwargs):
                calls.append((name, args, kwargs))
                ownership.append((proxy._loop, proxy._thread))
                if name in failures:
                    raise failures[name]
                return result
            return invoke

        server_owner = types.SimpleNamespace(close=action("close"))
        loop_owner = types.SimpleNamespace(stop=action("stop"))

        def schedule(callback):
            name = ("schedule-close" if callback is server_owner.close else
                    "schedule-stop" if callback is loop_owner.stop else "schedule-timers")
            action(name)(callback)
            if name == "schedule-timers":
                queued.append(callback)

        loop_owner.call_soon_threadsafe = schedule
        def join(*args, **kwargs):
            action("join")(*args, **kwargs)
            if execute:
                for callback in queued:
                    callback()
                queued.clear()

        thread_owner = types.SimpleNamespace(
            join=join, is_alive=action("is-alive", alive))
        proxy = types.SimpleNamespace(
            _loop=loop_owner if loop else None,
            _thread=thread_owner if thread else None,
            _server=server_owner if server else None,
            _timers=set(),
        )
        return proxy, calls, ownership

    def assert_retained(self, proxy, initial, ownership):
        self.assertEqual((proxy._loop, proxy._thread), initial)
        self.assertTrue(all(pair == initial for pair in ownership),
                        "ownership was cleared before termination was confirmed")

    def names(self, calls):
        return [name for name, _, _ in calls]

    def test_success_keeps_ownership_through_join_and_liveness_check(self):
        proxy, calls, ownership = self.rig()
        initial = proxy._loop, proxy._thread
        stop = stop_method()
        stop(proxy)
        self.assertEqual(self.names(calls),
                         ["schedule-close", "schedule-timers", "schedule-stop", "join", "is-alive"])
        self.assertEqual(calls[0][1], (proxy._server.close,))
        self.assertEqual(calls[2][1], (initial[0].stop,))
        self.assertEqual(calls[3], ("join", (), {"timeout": 10}))
        self.assertTrue(all(pair == initial for pair in ownership))
        self.assertEqual((proxy._loop, proxy._thread), (None, None))
        stop(proxy)
        self.assertEqual(len(calls), 5)

    def test_empty_and_repeated_stop(self):
        proxy, calls, _ = self.rig(loop=False, thread=False, server=False)
        stop = stop_method()
        stop(proxy)
        stop(proxy)
        self.assertEqual(calls, [])
        self.assertEqual((proxy._loop, proxy._thread), (None, None))

    def test_handles_remain_owned_during_cleanup(self):
        proxy, _, ownership = self.rig()
        initial = proxy._loop, proxy._thread
        stop_method()(proxy)
        self.assertTrue(ownership)
        self.assertTrue(all(pair == initial for pair in ownership),
                        "ownership was cleared before termination was confirmed")

    def test_no_server_still_stops_and_confirms_thread(self):
        proxy, calls, _ = self.rig(server=False)
        stop_method()(proxy)
        self.assertEqual(self.names(calls),
                         ["schedule-timers", "schedule-stop", "join", "is-alive"])
        self.assertEqual((proxy._loop, proxy._thread), (None, None))

    def test_failed_start_empty_timers_and_terminated_thread_clear_ownership(self):
        # start_server failure returns from the thread before run_forever; the
        # queued cancellation cannot run, and no handler has registered a timer.
        proxy, calls, ownership = self.rig(server=False, execute=False)
        initial = proxy._loop, proxy._thread
        stop = stop_method()
        stop(proxy)
        self.assertEqual(self.names(calls),
                         ["schedule-timers", "schedule-stop", "join", "is-alive"])
        self.assertTrue(all(pair == initial for pair in ownership))
        self.assertEqual(proxy._timers, set())
        self.assertEqual((proxy._loop, proxy._thread), (None, None))
        stop(proxy)
        self.assertEqual(len(calls), 4)

    def test_unobserved_cancellation_empty_timers_and_live_thread_is_failure(self):
        proxy, calls, ownership = self.rig(alive=True, execute=False)
        initial = proxy._loop, proxy._thread
        with self.assertRaisesRegex(RuntimeError, "thread did not terminate") as caught:
            stop_method()(proxy)
        self.assertEqual(caught.exception.__notes__, [
            "Cleanup failure: RuntimeError('DelayProxy timer cancellation did not complete')",
        ])
        self.assertEqual(self.names(calls).count("is-alive"), 1)
        self.assert_retained(proxy, initial, ownership)

    def test_unobserved_cancellation_needs_confirmed_termination(self):
        failure = ValueError("unknown liveness")
        proxy, calls, ownership = self.rig({"is-alive": failure}, execute=False)
        initial = proxy._loop, proxy._thread
        with self.assertRaises(ValueError) as caught:
            stop_method()(proxy)
        self.assertIs(caught.exception, failure)
        self.assertEqual(failure.__notes__, [
            "Cleanup failure: RuntimeError('DelayProxy timer cancellation did not complete')",
        ])
        self.assertEqual(self.names(calls).count("is-alive"), 1)
        self.assert_retained(proxy, initial, ownership)

    def test_partial_ownership_attempts_available_cleanup_and_retains_handles(self):
        for loop, thread, expected in (
            (True, False, ["schedule-close", "schedule-timers", "schedule-stop"]),
            (False, True, ["join", "is-alive"]),
        ):
            with self.subTest(loop=loop, thread=thread):
                proxy, calls, ownership = self.rig(loop=loop, thread=thread)
                initial = proxy._loop, proxy._thread
                with self.assertRaisesRegex(RuntimeError, "partial loop/thread ownership"):
                    stop_method()(proxy)
                self.assertEqual(self.names(calls), expected)
                self.assert_retained(proxy, initial, ownership)

    def test_alive_after_join_is_failure_and_can_be_retried(self):
        proxy, calls, ownership = self.rig(alive=True)
        initial = proxy._loop, proxy._thread
        with self.assertRaisesRegex(RuntimeError, "thread did not terminate"):
            stop_method()(proxy)
        self.assertEqual(self.names(calls),
                         ["schedule-close", "schedule-timers", "schedule-stop", "join", "is-alive"])
        self.assert_retained(proxy, initial, ownership)
        proxy._thread.is_alive = lambda: False
        stop_method()(proxy)
        self.assertEqual((proxy._loop, proxy._thread), (None, None))

    def test_each_ordinary_failure_attempts_remaining_cleanup_and_retains_handles(self):
        for name in ("schedule-close", "schedule-timers", "schedule-stop", "join", "is-alive"):
            with self.subTest(action=name):
                failure = ValueError(name)
                proxy, calls, ownership = self.rig({name: failure})
                initial = proxy._loop, proxy._thread
                with self.assertRaises(ValueError) as caught:
                    stop_method()(proxy)
                self.assertIs(caught.exception, failure)
                self.assertEqual(self.names(calls),
                                 ["schedule-close", "schedule-timers", "schedule-stop",
                                  "join", "is-alive"])
                self.assert_retained(proxy, initial, ownership)

    def test_multiple_ordinary_errors_preserve_first_and_note_later(self):
        first, second, third = ValueError("close"), OSError("stop"), RuntimeError("join")
        proxy, calls, ownership = self.rig(
            {"schedule-close": first, "schedule-stop": second, "join": third}, alive=True)
        initial = proxy._loop, proxy._thread
        with self.assertRaises(ValueError) as caught:
            stop_method()(proxy)
        self.assertIs(caught.exception, first)
        self.assertEqual(first.__notes__, [
            f"Cleanup failure: {second!r}", f"Cleanup failure: {third!r}",
            "Cleanup failure: RuntimeError('DelayProxy thread did not terminate')",
            "Cleanup failure: RuntimeError('DelayProxy timer cancellation did not complete')",
        ])
        self.assertEqual(self.names(calls),
                         ["schedule-close", "schedule-timers", "schedule-stop", "join", "is-alive"])
        self.assert_retained(proxy, initial, ownership)

    def test_base_exception_propagates_without_clearing_ownership(self):
        names = ["schedule-close", "schedule-timers", "schedule-stop", "join", "is-alive"]
        for index, name in enumerate(names):
            with self.subTest(action=name):
                interrupt = KeyboardInterrupt(name)
                proxy, calls, ownership = self.rig({name: interrupt})
                initial = proxy._loop, proxy._thread
                with self.assertRaises(KeyboardInterrupt) as caught:
                    stop_method()(proxy)
                self.assertIs(caught.exception, interrupt)
                self.assertEqual(self.names(calls), names[:index + 1])
                self.assert_retained(proxy, initial, ownership)


if __name__ == "__main__":
    unittest.main()
