"""Run extracted proxy methods with inert timers, coroutines and thread owners.

No event loop, server, thread or socket is started by these controls.
"""

import ast
import asyncio
import collections
import concurrent.futures
import pathlib
import types
import unittest
import weakref
from collections.abc import Callable

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "tools/abort_fixture.py"
EPS = 1e-6


def complete(coroutine):
    try:
        coroutine.send(None)
    except StopIteration as done:
        return done.value
    raise AssertionError("inert coroutine unexpectedly suspended")


def proxy_class(loop, upstream):
    tree = ast.parse(SOURCE.read_text())
    proxy = next(node for node in tree.body
                 if isinstance(node, ast.ClassDef) and node.name == "DelayProxy")
    proxy.body = [node for node in proxy.body
                  if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                  and node.name in ("__init__", "_handle", "_relay", "stop", "_drain",
                                    "_close_writer", "_spawn", "_close_client")]

    async def connect(*_args):
        return upstream

    def task(coroutine):
        complete(coroutine)
        result = type("Done", (), {})()
        result.cancel = lambda: None
        result.done = lambda: True
        result.cancelled = lambda: False
        result.exception = lambda: None
        result.add_done_callback = lambda callback: callback(result)
        return result

    async def wait(tasks, **_kwargs):
        return set(tasks), set()

    async def pause(_delay):
        return None

    async def ignore(*_args, **_kwargs):
        return None

    namespace = {
        "asyncio": types.SimpleNamespace(get_running_loop=lambda: loop,
                                          open_connection=connect,
                                          ensure_future=task, wait=wait,
                                          gather=ignore, shield=ignore, sleep=pause, FIRST_COMPLETED=object()),
        "collections": collections, "concurrent": concurrent,
        "Callable": Callable, "time": types.SimpleNamespace(monotonic=lambda: 100),
        "CommandSplitter": lambda: None,
        "ReplyCounter": lambda: types.SimpleNamespace(feed=lambda _data: []),
        "REPLY_ORDER_EPS": EPS,
    }
    module = ast.fix_missing_locations(ast.Module(
        body=[ast.ImportFrom(module="__future__",
                             names=[ast.alias(name="annotations")], level=0), proxy],
        type_ignores=[]))
    exec(compile(module, str(SOURCE), "exec"), namespace)
    return namespace["DelayProxy"]


class Reader:
    def __init__(self, chunks=(), eof=False):
        self.chunks = iter(chunks)
        self.eof = eof

    async def read(self, _size):
        return next(self.chunks, b"")

    def at_eof(self):
        return self.eof


class Writer:
    def __init__(self):
        self.closed = False
        self.data = []
        self.failure = None

    async def wait_closed(self):
        assert self.closed

    def is_closing(self):
        return self.closed

    def write(self, data):
        if self.failure:
            raise self.failure
        self.data.append(data)

    def close(self):
        self.closed = True


class Loop:
    def __init__(self):
        self.timers = []
        self.queued = []
        self.events = []
        self.schedule_failure = None
        self.execute = True
        self.executing = False
        self.cancelled = []

    def create_task(self, coroutine):
        complete(coroutine)

    def time(self):
        return 100

    def get_debug(self):
        return False

    def call_exception_handler(self, context):
        raise context["exception"]

    def _timer_handle_cancelled(self, timer):
        assert self.executing, "timer cancelled outside its owning loop"
        self.cancelled.append(timer)

    def call_at(self, due, callback, *args):
        timer = asyncio.TimerHandle(due, callback, args, self)
        self.timers.append(timer)
        return timer

    def call_soon_threadsafe(self, callback):
        if callback.__name__ == "cancel_timers" and self.schedule_failure:
            raise self.schedule_failure
        self.queued.append(callback)

    def stop(self):
        self.events.append("stop")
        if hasattr(self, "proxy"):
            assert not self.proxy._timers, "loop stopped before timer cancellation"

    def join(self, timeout):
        assert timeout == 10
        if self.execute:
            queued, self.queued = self.queued, []
            self.executing = True
            try:
                for callback in queued:
                    callback()
            finally:
                self.executing = False
        if hasattr(self, "owner"):
            self.owner._loop_closed = True

    def fire(self, timer):
        self.timers.remove(timer)
        timer._run()


class DelayProxyTimerTests(unittest.TestCase):
    def rig(self, chunks=(b"first", b"second"), eof=False):
        loop = Loop()
        proxy = proxy_class(loop, (Reader(chunks), Writer()))(1, 2)
        proxy.delay = 5
        writer = Writer()
        complete(proxy._handle(Reader(eof=eof), writer))
        proxy._loop = loop
        loop.owner = proxy
        proxy._thread = types.SimpleNamespace(join=loop.join, is_alive=lambda: False)
        return proxy, loop, writer

    def test_both_timer_kinds_owned_after_handler_finally(self):
        proxy, loop, writer = self.rig()
        self.assertEqual(len(loop.timers), 3)
        self.assertEqual(proxy._timers, set(loop.timers))
        self.assertFalse(writer.closed)
        self.assertTrue(all(not timer.cancelled() for timer in loop.timers))

    def test_normal_firing_removes_only_itself_and_preserves_payload_deadlines(self):
        proxy, loop, writer = self.rig()
        first, second, close = loop.timers
        self.assertEqual([t.when() for t in loop.timers],
                         [105, 105 + EPS, 105 + 2 * EPS])
        loop.fire(first)
        self.assertEqual(proxy._timers, {second, close})
        self.assertEqual(writer.data, [b"first"])
        self.assertFalse(writer.closed)
        loop.fire(second)
        self.assertEqual(proxy._timers, {close})
        self.assertEqual(writer.data, [b"first", b"second"])
        loop.fire(close)
        self.assertEqual(proxy._timers, set())
        self.assertTrue(writer.closed)

    def test_completed_callbacks_do_not_retain_connection(self):
        proxy, loop, writer = self.rig()
        reference = weakref.ref(writer)
        while loop.timers:
            loop.fire(loop.timers[0])
        del writer
        self.assertIsNone(reference(), "completed timer retained its connection")
        self.assertEqual(proxy._timers, set())

    def test_closing_client_skips_payload_and_still_releases_timers(self):
        proxy, loop, writer = self.rig(eof=True)
        self.assertTrue(writer.closed)
        while loop.timers:
            loop.fire(loop.timers[0])
        self.assertEqual(writer.data, [])
        self.assertEqual(proxy._timers, set())

    def test_callback_error_releases_its_handle(self):
        for error in (ValueError("write"), KeyboardInterrupt("write")):
            with self.subTest(error=type(error).__name__):
                proxy, loop, writer = self.rig()
                writer.failure = error
                timer = loop.timers[0]
                with self.assertRaises(type(error)):
                    loop.fire(timer)
                self.assertNotIn(timer, proxy._timers)
                self.assertEqual(proxy._timers, set(loop.timers))

    def test_stop_cancels_all_pending_timers_on_owner_before_loop_stop(self):
        proxy, loop, writer = self.rig()
        loop.proxy = proxy
        timers = list(loop.timers)
        # Isolate stop's cancellation contract from registration's own control.
        proxy._timers = set(timers)
        proxy.stop()
        self.assertEqual(loop.events, ["stop"])
        self.assertEqual(set(loop.cancelled), set(timers))
        self.assertTrue(all(timer.cancelled() for timer in timers))
        self.assertTrue(all(timer._callback is None for timer in timers))
        self.assertEqual(proxy._timers, set())
        self.assertEqual(writer.data, [])
        self.assertTrue(writer.closed)
        self.assertEqual(proxy._writers, set())
        proxy.stop()
        self.assertEqual(loop.events, ["stop"])

    def test_empty_timer_registry_and_repeated_stop(self):
        proxy, loop, _ = self.rig(chunks=())
        loop.fire(loop.timers[0])
        self.assertEqual(proxy._timers, set())
        proxy.stop()
        proxy.stop()
        self.assertEqual(loop.events, ["stop"])

    def test_scheduling_failure_retains_pending_timers_and_ownership(self):
        proxy, loop, _ = self.rig()
        initial = proxy._loop, proxy._thread
        timers = set(loop.timers)
        error = ValueError("schedule cancellation")
        loop.schedule_failure = error
        with self.assertRaises(ValueError) as caught:
            proxy.stop()
        self.assertIs(caught.exception, error)
        self.assertEqual((proxy._loop, proxy._thread), initial)
        self.assertEqual(proxy._timers, timers)
        self.assertTrue(all(not timer.cancelled() for timer in timers))
        self.assertEqual(loop.events, [])

    def test_unobserved_cancellation_cannot_report_success(self):
        proxy, loop, _ = self.rig()
        initial = proxy._loop, proxy._thread
        loop.execute = False
        with self.assertRaisesRegex(RuntimeError, "timer cancellation did not complete"):
            proxy.stop()
        self.assertEqual((proxy._loop, proxy._thread), initial)
        self.assertEqual(proxy._timers, set(loop.timers))

    def test_timer_queued_after_cancellation_prevents_success(self):
        proxy, loop, _ = self.rig()
        initial = proxy._loop, proxy._thread
        stop = loop.stop

        def late_stop():
            timer = loop.call_at(200, lambda: None)
            proxy._timers.add(timer)
            stop()

        loop.stop = late_stop
        with self.assertRaisesRegex(RuntimeError, "timers remain pending"):
            proxy.stop()
        self.assertEqual((proxy._loop, proxy._thread), initial)
        self.assertEqual(len(proxy._timers), 1)

    def test_call_at_failure_keeps_previously_scheduled_timer(self):
        loop = Loop()
        proxy = proxy_class(loop, (Reader((b"first", b"second")), Writer()))(1, 2)
        schedule = loop.call_at

        def fail_second(*args):
            if loop.timers:
                raise ValueError("call_at")
            return schedule(*args)

        loop.call_at = fail_second
        with self.assertRaisesRegex(ValueError, "call_at"):
            complete(proxy._handle(Reader(), Writer()))
        self.assertEqual(len(loop.timers), 1)
        self.assertEqual(proxy._timers, set(loop.timers))

    def test_ordinary_cancel_errors_attempt_other_timers_and_keep_first(self):
        proxy, loop, _ = self.rig()
        errors = [ValueError("first"), OSError("second")]
        attempted = []

        class FailedTimer:
            def __init__(self, error):
                self.error = error

            def cancel(self):
                attempted.append(self.error)
                raise self.error

        failures = {FailedTimer(error) for error in errors}
        # Set iteration has no promised order; capture the actual attempt order.
        proxy._timers.update(failures)
        with self.assertRaises((ValueError, OSError)) as caught:
            proxy.stop()
        self.assertIs(caught.exception, attempted[0])
        self.assertIn(f"Cleanup failure: {attempted[1]!r}", caught.exception.__notes__)
        self.assertEqual(set(attempted), set(errors))
        self.assertEqual(proxy._timers, failures)
        self.assertTrue(all(timer.cancelled() for timer in loop.timers))

    def test_cancellation_error_is_propagated_with_failed_timer_owned(self):
        for error in (ValueError("cancel"), KeyboardInterrupt("cancel")):
            with self.subTest(error=type(error).__name__):
                proxy, loop, _ = self.rig(chunks=())

                def fail(error=error):
                    raise error

                # A hashable stand-in that fails on the owner loop.
                timer = type("FailedTimer", (), {"cancel": staticmethod(fail)})()
                proxy._timers = {timer}
                initial = proxy._loop, proxy._thread
                with self.assertRaises(type(error)) as caught:
                    proxy.stop()
                self.assertIs(caught.exception, error)
                self.assertEqual(proxy._timers, {timer})
                self.assertEqual((proxy._loop, proxy._thread), initial)
                self.assertEqual(loop.events, [])


if __name__ == "__main__":
    unittest.main()
