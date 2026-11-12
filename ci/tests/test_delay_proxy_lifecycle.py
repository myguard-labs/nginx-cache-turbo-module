"""Source-bound lifecycle controls; no real sockets, servers or threads.

Async cases use in-memory streams. Owner boundaries execute on inert stand-ins;
these controls do not establish real network acceptance quiescence.
"""

import asyncio
import types
import unittest
from unittest.mock import patch

from test_delay_proxy_ownership import Reader, Writer, memory_stream, proxy_class


class Server:
    def __init__(self):
        self.closed = False
        self.waited = False
        self.gate = None
        self.close_error = None
        self.wait_error = None
        self.on_close = lambda: None

    def close(self):
        if self.close_error:
            raise self.close_error
        self.closed = True
        self.on_close()

    async def wait_closed(self):
        assert self.closed, "listener waited before close"
        self.waited = True
        if self.gate is not None:
            await self.gate.wait()
        if self.wait_error:
            raise self.wait_error


class DrainLifecycleTests(unittest.IsolatedAsyncioTestCase):
    def rig(self):
        cls, _ = proxy_class()
        proxy = cls(1, 2)
        proxy._server = Server()
        return proxy, proxy._server

    async def test_listener_close_is_awaited_after_buffered_writer(self):
        proxy, server = self.rig()
        writer, transport = memory_stream(None, defer_loss=True)
        proxy._writers.add(writer)
        draining = asyncio.create_task(proxy._drain())
        try:
            await writer.wait_started.wait()
            self.assertTrue(server.closed, "listener was not closed before writer drainage")
            self.assertFalse(server.waited, "server wait preceded owned writer drainage")
            self.assertFalse(draining.done(), "buffered writer drainage was skipped")
        finally:
            transport.lose()
            await draining
        self.assertTrue(server.waited, "listener closure was never awaited")
        self.assertTrue(proxy._server_closed)
        self.assertEqual(proxy._writers, set())

    async def test_queued_accept_is_owned_and_drained_without_upstream_connect(self):
        proxy, server = self.rig()
        writer = Writer()
        loop = asyncio.get_running_loop()
        server.on_close = lambda: loop.call_soon(proxy._accept, Reader(), writer)
        with patch.object(asyncio, "open_connection", side_effect=AssertionError("late connect")):
            await proxy._drain()
        self.assertTrue(writer.closed, "queued accept escaped callback barrier")
        self.assertEqual(writer.waited, 1)
        self.assertEqual(proxy._writers, set())
        self.assertEqual(proxy._tasks, set())

    async def test_accept_queued_during_listener_wait_is_included_in_next_pass(self):
        proxy, server = self.rig()
        writer, transport = memory_stream(None)

        async def wait_closed():
            server.waited = True
            asyncio.get_running_loop().call_soon(proxy._accept, Reader(), writer)

        server.wait_closed = wait_closed
        await proxy._drain()
        self.assertTrue(transport.lost, "post-listener accept was not drained")
        self.assertFalse(writer._protocol._closed.cancelled())
        self.assertEqual(proxy._tasks, set())
        self.assertEqual(proxy._writers, set())

    async def test_listener_timeout_preserves_shared_wait_for_retry(self):
        proxy, server = self.rig()
        server.gate = asyncio.Event()
        with self.assertRaisesRegex(TimeoutError, "server drainage timed out"):
            await proxy._drain(timeout=0)
        waiter = proxy._server_wait
        self.assertIsNotNone(waiter)
        self.assertFalse(waiter.done(), "server timeout cancelled shared closure wait")
        self.assertFalse(proxy._server_closed)
        server.gate.set()
        await proxy._drain()
        self.assertIs(proxy._server_wait, waiter)
        self.assertTrue(waiter.done())
        self.assertFalse(waiter.cancelled())
        self.assertTrue(proxy._server_closed)

    async def test_buffered_writer_timeout_keeps_protocol_future_and_writer_owned(self):
        proxy, server = self.rig()
        writer, transport = memory_stream(None, defer_loss=True)
        proxy._writers.add(writer)
        with self.assertRaisesRegex(TimeoutError, "writer drainage timed out"):
            await proxy._drain(timeout=0)
        waiter = proxy._writer_waits[writer]
        protocol_waiter = writer._protocol._get_close_waiter(writer)
        self.assertFalse(waiter.done(), "bounded drainage cancelled writer close task")
        self.assertFalse(protocol_waiter.done(), "timeout cancelled protocol shared Future")
        self.assertIn(writer, proxy._writers)
        self.assertTrue(server.waited)
        transport.lose()
        await proxy._drain()
        self.assertEqual(proxy._writers, set())
        self.assertEqual(proxy._writer_waits, {})
        self.assertFalse(protocol_waiter.cancelled())

    async def test_cancellation_resistant_task_times_out_and_remains_owned(self):
        proxy, _ = self.rig()
        entered, finalizing, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def resistant():
            entered.set()
            try:
                await asyncio.Future()
            finally:
                finalizing.set()
                await release.wait()

        proxy._spawn(resistant())
        task, = proxy._tasks
        await entered.wait()
        with self.assertRaisesRegex(TimeoutError, "task drainage timed out"):
            await proxy._drain(timeout=0)
        self.assertTrue(finalizing.is_set())
        self.assertIn(task, proxy._tasks, "timeout dropped pending handler ownership")
        self.assertFalse(task.done())
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        await proxy._drain()
        self.assertEqual(proxy._tasks, set())

    async def test_late_work_cannot_extend_global_deadline(self):
        proxy, _ = self.rig()
        writer = Writer()
        original = asyncio.sleep
        pauses = 0

        async def pause(delay):
            nonlocal pauses
            pauses += 1
            await original(delay)
            if pauses == 2:
                proxy._writers.add(writer)

        with patch.object(asyncio, "sleep", pause):
            with self.assertRaisesRegex(TimeoutError, "DelayProxy drainage timed out"):
                await proxy._drain(timeout=0)
        self.assertIn(writer, proxy._writers)
        await proxy._drain()
        self.assertEqual(writer.waited, 1)

    async def test_new_task_after_completed_batch_cannot_extend_deadline(self):
        proxy, _ = self.rig()
        original = asyncio.wait
        entered = asyncio.Event()
        release = asyncio.Event()

        async def first():
            entered.set()
            await release.wait()

        async def late():
            await release.wait()

        proxy._spawn(first())
        await entered.wait()
        waits = 0

        async def wait(tasks, **kwargs):
            nonlocal waits
            result = await original(tasks, **kwargs)
            waits += 1
            if waits == 1:
                proxy._spawn(late())
            return result

        with patch.object(asyncio, "wait", wait):
            with self.assertRaisesRegex(TimeoutError, "task drainage timed out"):
                await proxy._drain(timeout=0)
        self.assertTrue(proxy._tasks, "late task ownership was discarded")
        release.set()
        await proxy._drain()
        self.assertEqual(proxy._tasks, set())

    async def test_listener_close_error_attempts_other_cleanup_and_remains_visible(self):
        proxy, server = self.rig()
        failure = ValueError("listener close")
        server.close_error = failure
        writer = Writer()
        proxy._writers.add(writer)
        with self.assertRaises(ValueError) as caught:
            await proxy._drain()
        self.assertIs(caught.exception, failure)
        self.assertEqual(writer.waited, 1)
        self.assertFalse(proxy._server_closed)
        self.assertIs(proxy._server, server)

    async def test_listener_wait_scheduling_failure_closes_coroutine_and_retains_server(self):
        proxy, server = self.rig()
        coroutines = []

        def fail(coroutine):
            coroutines.append(coroutine)
            raise ValueError("schedule listener wait")

        with patch.object(asyncio, "ensure_future", fail):
            with self.assertRaisesRegex(ValueError, "schedule listener wait"):
                await proxy._drain()
        self.assertIsNone(coroutines[0].cr_frame, "failed listener scheduling leaked coroutine")
        self.assertIsNone(proxy._server_wait)
        self.assertFalse(proxy._server_closed)
        self.assertIs(proxy._server, server)
        await proxy._drain()
        self.assertTrue(proxy._server_closed)

    async def test_completed_listener_wait_failure_is_reported_then_retried(self):
        proxy, server = self.rig()
        failure = ValueError("transient listener wait")
        server.wait_error = failure
        with self.assertRaises(ValueError) as caught:
            await proxy._drain()
        self.assertIs(caught.exception, failure)
        self.assertFalse(proxy._server_closed)
        self.assertIs(proxy._server, server)
        self.assertIsNone(proxy._server_wait, "completed failed listener wait blocked retry")
        server.wait_error = None
        await proxy._drain()
        self.assertTrue(proxy._server_closed, "retry did not confirm listener closure")
        self.assertTrue(proxy._server_wait.done())

    async def test_completed_listener_wait_cancellation_or_base_exception_allows_retry(self):
        for failure in (asyncio.CancelledError("wait cancelled"),
                        KeyboardInterrupt("wait interrupted")):
            with self.subTest(error=type(failure).__name__):
                proxy, server = self.rig()
                waiter = asyncio.get_running_loop().create_future()
                if isinstance(failure, asyncio.CancelledError):
                    waiter.cancel()
                else:
                    waiter.set_exception(failure)
                proxy._server_wait = waiter
                with self.assertRaises(type(failure)):
                    await proxy._drain()
                self.assertFalse(proxy._server_closed)
                self.assertIs(proxy._server, server)
                self.assertIsNone(proxy._server_wait,
                                  "completed exceptional listener wait blocked retry")
                await proxy._drain()
                self.assertTrue(proxy._server_closed)
                self.assertIsNot(proxy._server_wait, waiter)

    async def test_drain_cancellation_preserves_pending_listener_wait_for_retry(self):
        proxy, server = self.rig()
        entered, release = asyncio.Event(), asyncio.Event()

        async def wait_closed():
            entered.set()
            await release.wait()

        server.wait_closed = wait_closed
        draining = asyncio.create_task(proxy._drain())
        await entered.wait()
        waiter = proxy._server_wait
        draining.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await draining
        self.assertIs(proxy._server_wait, waiter)
        self.assertFalse(waiter.done(), "drain cancellation cancelled shared listener wait")
        self.assertFalse(proxy._server_closed)
        release.set()
        await proxy._drain()
        self.assertIs(proxy._server_wait, waiter)
        self.assertTrue(proxy._server_closed)

    async def test_drain_cancellation_does_not_discard_completed_successful_wait(self):
        proxy, _ = self.rig()
        waiter = asyncio.get_running_loop().create_future()
        waiter.set_result(None)
        proxy._server_wait = waiter
        with patch.object(asyncio, "shield", side_effect=asyncio.CancelledError("owner cancelled")):
            with self.assertRaises(asyncio.CancelledError):
                await proxy._drain()
        self.assertIs(proxy._server_wait, waiter)
        self.assertFalse(proxy._server_closed)
        await proxy._drain()
        self.assertTrue(proxy._server_closed)

    async def test_listener_wait_error_and_base_exception_remain_visible(self):
        proxy, server = self.rig()
        failure = ValueError("listener wait")
        server.wait_error = failure
        with self.assertRaises(ValueError) as caught:
            await proxy._drain()
        self.assertIs(caught.exception, failure)
        self.assertFalse(proxy._server_closed)
        self.assertIsNone(proxy._server_wait)
        server.close_error = KeyboardInterrupt("listener close")
        with self.assertRaisesRegex(KeyboardInterrupt, "listener close"):
            await proxy._drain()
        self.assertIs(proxy._server, server)


class OwnerLifecycleTests(unittest.TestCase):
    def rig(self, *, startup_error=None, run_error=None, close_error=None, late=False):
        cls, namespace = proxy_class()
        proxy = cls(1, 2)
        server, events = Server(), []
        owner = False

        async def start_server(*_args):
            self.assertTrue(owner)
            events.append("listen")
            if startup_error:
                raise startup_error
            return server

        def run_until_complete(coroutine):
            try:
                coroutine.send(None)
            except StopIteration as done:
                return done.value
            raise AssertionError("inert start unexpectedly suspended")

        def run_forever():
            self.assertTrue(owner)
            events.append("run")
            if run_error:
                raise run_error
            if late and events.count("run") == 1:
                proxy._writers.add(server)
            else:
                proxy._writers.clear()

        def close():
            self.assertTrue(owner, "loop was closed outside owner thread boundary")
            events.append("close")
            if close_error:
                raise close_error

        loop = types.SimpleNamespace(run_until_complete=run_until_complete,
                                     run_forever=run_forever, close=close)

        def thread(**kwargs):
            def start():
                nonlocal owner
                owner = True
                try:
                    kwargs["target"]()
                finally:
                    owner = False
            return types.SimpleNamespace(start=start, join=lambda **_kw: None,
                                         is_alive=lambda: False)

        namespace["threading"] = types.SimpleNamespace(Thread=thread)
        namespace["asyncio"] = types.SimpleNamespace(
            new_event_loop=lambda: loop, set_event_loop=lambda _loop: None,
            start_server=start_server)
        return proxy, loop, events

    def test_normal_owner_exit_closes_loop_on_owner_boundary(self):
        proxy, _, events = self.rig()
        proxy.start()
        self.assertEqual(events, ["listen", "run", "close"],
                         "normal owner exit did not close loop")
        self.assertTrue(proxy._loop_closed)

    def test_startup_exception_and_base_exception_close_before_error_is_delivered(self):
        for failure in (ValueError("startup"), KeyboardInterrupt("startup")):
            with self.subTest(error=type(failure).__name__):
                proxy, _, events = self.rig(startup_error=failure)
                with self.assertRaises(type(failure)) as caught:
                    proxy.start()
                self.assertIs(caught.exception, failure)
                self.assertEqual(events, ["listen", "close"],
                                 "failed startup left loop unclosed")
                proxy.stop()
                proxy.stop()
                self.assertEqual((proxy._loop, proxy._thread), (None, None))

    def test_late_registered_ownership_keeps_owner_running_before_close(self):
        proxy, _, events = self.rig(late=True)
        proxy.start()
        self.assertEqual(events, ["listen", "run", "run", "close"],
                         "owner closed loop with late registered writer")

    def test_run_forever_failure_is_reported_and_ownership_retained(self):
        for failure in (ValueError("run failed"), KeyboardInterrupt("run failed")):
            with self.subTest(error=type(failure).__name__):
                proxy, loop, events = self.rig(run_error=failure)
                proxy.start()
                self.assertEqual(events, ["listen", "run", "close"])
                with self.assertRaises(type(failure)) as caught:
                    proxy.stop()
                self.assertIs(caught.exception, failure)
                self.assertIs(proxy._loop, loop)
                self.assertIsNotNone(proxy._thread)

    def test_loop_close_failure_after_startup_or_run_is_visible_and_owned(self):
        for startup_error in (None, ValueError("startup")):
            for failure in (ValueError("loop close"), KeyboardInterrupt("loop close")):
                with self.subTest(startup=startup_error, error=type(failure).__name__):
                    proxy, loop, events = self.rig(startup_error=startup_error,
                                                  close_error=failure)
                    # A failed close leaves a terminated owner with an unclosed
                    # loop. Scheduling is inert; the recorded error must survive.
                    loop.call_soon_threadsafe = lambda _callback: None
                    if startup_error:
                        with self.assertRaises(ValueError):
                            proxy.start()
                    else:
                        proxy.start()
                    self.assertEqual(events[-1], "close")
                    with self.assertRaises(type(failure)) as caught:
                        proxy.stop()
                    self.assertIs(caught.exception, failure)
                    self.assertFalse(proxy._loop_closed)
                    self.assertIs(proxy._loop, loop)

    def test_run_and_close_failures_preserve_both_diagnostics(self):
        proxy, loop, _ = self.rig(run_error=ValueError("run"), close_error=OSError("close"))
        loop.call_soon_threadsafe = lambda _callback: None
        proxy.start()
        with self.assertRaisesRegex(OSError, "close") as caught:
            proxy.stop()
        self.assertIn("Loop failure: ValueError('run')", caught.exception.__notes__)


class StopTimeoutTests(unittest.TestCase):
    def test_timeout_keeps_owner_running_and_can_be_retried(self):
        cls, _ = proxy_class()
        proxy = cls(1, 2)
        queued, events = [], []
        writer = object()
        proxy._writers.add(writer)
        timeout = TimeoutError("writer drainage timed out")

        async def drain():
            raise timeout

        def create_task(coroutine):
            try:
                coroutine.send(None)
            except StopIteration:
                return
            raise AssertionError("inert drain unexpectedly suspended")

        def stop():
            events.append("stop")
            proxy._loop_closed = True

        proxy._drain = drain
        loop = types.SimpleNamespace(call_soon_threadsafe=queued.append,
                                     create_task=create_task, stop=stop)

        def join(timeout):
            self.assertEqual(timeout, 10)
            callbacks, queued[:] = queued[:], []
            for callback in callbacks:
                callback()

        proxy._loop = loop
        thread = types.SimpleNamespace(join=join, is_alive=lambda: not proxy._loop_closed)
        proxy._thread = thread
        with self.assertRaisesRegex(RuntimeError, "thread did not terminate") as caught:
            proxy.stop()
        self.assertIn(f"Cleanup failure: {timeout!r}", caught.exception.__notes__)
        self.assertEqual(events, [], "timeout stopped owner with unconfirmed resources")
        self.assertEqual((proxy._loop, proxy._thread), (loop, thread))
        self.assertEqual(proxy._writers, {writer})

        async def confirmed():
            proxy._writers.clear()

        proxy._drain = confirmed
        proxy.stop()
        self.assertEqual(events, ["stop"])
        self.assertEqual((proxy._loop, proxy._thread), (None, None))


if __name__ == "__main__":
    unittest.main()
