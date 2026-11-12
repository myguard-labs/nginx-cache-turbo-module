"""Source-extracted proxy ownership, with in-memory streams and no networking.

Async controls use a local event loop but never a real thread, server or socket.
Stop's cross-thread boundary is exercised separately with an inert scheduler.
"""

import ast
import asyncio
import collections
import concurrent.futures
import errno
import pathlib
import time
import types
import unittest
from collections.abc import Callable
from unittest.mock import patch

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "tools/abort_fixture.py"


def proxy_class():
    tree = ast.parse(SOURCE.read_text())
    proxy = next(node for node in tree.body
                 if isinstance(node, ast.ClassDef) and node.name == "DelayProxy")
    proxy.body = [node for node in proxy.body
                  if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                  and node.name in ("__init__", "start", "stop", "_spawn", "_accept",
                                    "_close_writer", "_close_client", "_drain",
                                    "_handle", "_relay")]
    module = ast.fix_missing_locations(ast.Module(body=[
        ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0),
        proxy], type_ignores=[]))
    namespace = {
        "asyncio": asyncio, "collections": collections, "concurrent": concurrent,
        "Callable": Callable, "time": time, "REPLY_ORDER_EPS": 1e-6,
        "CommandSplitter": lambda: types.SimpleNamespace(feed=lambda data: ([], data)),
        "ReplyCounter": lambda: types.SimpleNamespace(feed=lambda _data: []),
    }
    exec(compile(module, str(SOURCE), "exec"), namespace)
    return namespace["DelayProxy"], namespace


class Reader:
    def __init__(self, chunks=(), *, blocked=False, eof=False):
        self.chunks = iter(chunks)
        self.blocked = blocked
        self.eof = eof
        self.entered = asyncio.Event()
        self.cancelled = False

    async def read(self, _size):
        data = next(self.chunks, None)
        if data is not None:
            return data
        if self.blocked:
            self.entered.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                self.cancelled = True
                raise
        return b""

    def at_eof(self):
        return self.eof


class Writer:
    def __init__(self):
        self.closed = False
        self.waited = 0
        self.data = []
        self.close_error = None
        self.wait_error = None
        self.drain_error = None
        self.drain_entered = asyncio.Event()
        self.block_drain = False
        self.drain_cancelled = False
        self.wait_entered = asyncio.Event()
        self.wait_gate = None

    def close(self):
        if self.close_error:
            raise self.close_error
        self.closed = True

    async def wait_closed(self):
        assert self.closed, "writer waited before close"
        self.wait_entered.set()
        if self.wait_gate is not None:
            await self.wait_gate.wait()
        if self.wait_error:
            raise self.wait_error
        self.waited += 1

    def is_closing(self):
        return self.closed

    def write(self, data):
        self.data.append(data)

    async def drain(self):
        if self.drain_error:
            raise self.drain_error
        if self.block_drain:
            self.drain_entered.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                self.drain_cancelled = True
                raise


class MemoryTransport(asyncio.Transport):
    """Supply connection_lost to the real stream protocol without a socket."""

    def __init__(self, protocol, error, defer_loss=False):
        super().__init__()
        self.defer_loss = defer_loss
        self.protocol = protocol
        self.error = error
        self.closed = False
        self.lost = False

    def is_closing(self):
        return self.closed

    def close(self):
        if not self.closed:
            self.closed = True
            if not self.defer_loss:
                asyncio.get_running_loop().call_soon(self.lose)

    def lose(self):
        if not self.lost:
            self.closed = self.lost = True
            self.protocol.connection_lost(self.error)


class ObservedStreamWriter(asyncio.StreamWriter):
    async def wait_closed(self):
        self.wait_started.set()
        await super().wait_closed()


def memory_stream(error, *, defer_loss=False):
    # Real stdlib waiter behavior, including the error recorded by
    # connection_lost; only the actual I/O transport is replaced.
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
    transport = MemoryTransport(protocol, error, defer_loss)
    protocol.connection_made(transport)
    writer = ObservedStreamWriter(transport, protocol, reader, loop)
    writer.wait_started = asyncio.Event()
    return writer, transport


class OwnershipTests(unittest.IsolatedAsyncioTestCase):
    def rig(self):
        cls, namespace = proxy_class()
        return cls(1, 2), namespace

    async def test_accept_registers_before_task_runs_and_connect_failure_awaits_client(self):
        proxy, _ = self.rig()
        writer = Writer()

        async def connect(*_args):
            self.assertIn(writer, proxy._writers)
            self.assertIn(asyncio.current_task(), proxy._tasks)
            raise OSError("upstream refused")

        with patch.object(asyncio, "open_connection", connect):
            proxy._accept(Reader(), writer)
            tasks = tuple(proxy._tasks)
            self.assertEqual(len(tasks), 1, "accepted handler was not retained")
            self.assertEqual(proxy._writers, {writer})
            await asyncio.gather(*tasks)
        self.assertEqual(proxy._tasks, set())
        self.assertEqual(proxy._writers, set())
        self.assertTrue(writer.closed)
        self.assertEqual(writer.waited, 1)
        await proxy._drain()

    async def test_direct_connect_cancellation_closes_and_awaits_client(self):
        # Existing _handle entry is deliberate: this assertion also runs against
        # the pinned pre-ownership source without relying on a new helper.
        proxy, _ = self.rig()
        writer = Writer()
        entered = asyncio.Event()

        async def connect(*_args):
            entered.set()
            await asyncio.Future()

        with patch.object(asyncio, "open_connection", connect):
            handler = asyncio.create_task(proxy._handle(Reader(), writer))
            await entered.wait()
            handler.cancel()
            await asyncio.gather(handler, return_exceptions=True)
        self.assertTrue(writer.closed, "cancelled upstream connect left client open")
        self.assertEqual(writer.waited, 1, "client close was not awaited")

    async def test_direct_connect_failure_awaits_client_close(self):
        proxy, _ = self.rig()
        writer = Writer()

        async def connect(*_args):
            raise OSError("upstream refused")

        with patch.object(asyncio, "open_connection", connect):
            await proxy._handle(Reader(), writer)
        self.assertEqual(writer.waited, 1, "refused upstream client close was not awaited")

    async def test_stop_cancels_connect_and_awaits_client_without_unrelated_task(self):
        proxy, _ = self.rig()
        writer = Writer()
        entered = asyncio.Event()
        cancelled = []

        async def connect(*_args):
            entered.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                cancelled.append(True)
                raise

        unrelated = asyncio.create_task(asyncio.Event().wait())
        try:
            with patch.object(asyncio, "open_connection", connect):
                proxy._accept(Reader(), writer)
                await entered.wait()
                await proxy._drain()
            self.assertEqual(cancelled, [True])
            self.assertFalse(unrelated.done(), "fixture cancelled unrelated loop task")
            self.assertEqual(proxy._tasks, set())
            self.assertEqual(proxy._writers, set())
            self.assertEqual(writer.waited, 1)
        finally:
            unrelated.cancel()
            await asyncio.gather(unrelated, return_exceptions=True)

    async def test_blocked_pump_reads_and_drain_are_cancelled_before_writer_release(self):
        for blocked_drain in (False, True):
            with self.subTest(blocked_drain=blocked_drain):
                proxy, _ = self.rig()
                client = Reader((b"request",) if blocked_drain else (), blocked=True)
                upstream = Reader(blocked=True)
                cw, uw = Writer(), Writer()
                uw.block_drain = blocked_drain
                proxy._feed_request = lambda *_args: b""

                async def connect(*_args, upstream=upstream, uw=uw):
                    return upstream, uw

                with patch.object(asyncio, "open_connection", connect):
                    proxy._accept(client, cw)
                    await upstream.entered.wait()
                    await (uw.drain_entered if blocked_drain else client.entered).wait()
                    self.assertEqual(proxy._writers, {cw, uw})
                    await proxy._drain()
                self.assertTrue(upstream.cancelled)
                self.assertEqual(uw.drain_cancelled, blocked_drain)
                self.assertEqual(client.cancelled, not blocked_drain)
                self.assertEqual((cw.waited, uw.waited), (1, 1))
                self.assertEqual(proxy._writers, set())
                self.assertEqual(proxy._tasks, set())

    async def test_pump_failure_and_eof_close_and_await_both_writers(self):
        proxy, _ = self.rig()
        cw, uw = Writer(), Writer()
        uw.drain_error = ValueError("upstream drain")
        proxy._feed_request = lambda *_args: b""
        upstream = Reader(blocked=True)

        async def connect(*_args):
            return upstream, uw

        with patch.object(asyncio, "open_connection", connect):
            proxy._accept(Reader((b"request",), eof=True), cw)
            await asyncio.gather(*tuple(proxy._tasks))
        self.assertTrue(upstream.cancelled)
        self.assertEqual((cw.waited, uw.waited), (1, 1))
        self.assertEqual(proxy._writers, set())
        await proxy._drain()

    async def test_handler_completion_retains_delayed_client_until_close_timer(self):
        proxy, _ = self.rig()
        cw, uw = Writer(), Writer()
        proxy.delay = 3600

        async def connect(*_args):
            return Reader((b"reply",)), uw

        with patch.object(asyncio, "open_connection", connect):
            proxy._accept(Reader(blocked=True), cw)
            await asyncio.gather(*tuple(proxy._tasks))
        self.assertFalse(cw.closed, "handler closed client before delayed reply")
        self.assertEqual(proxy._writers, {cw})
        self.assertEqual(uw.waited, 1)
        timers = sorted(proxy._timers, key=lambda timer: timer.when())
        self.assertEqual(len(timers), 2)
        timers[0]._run()
        self.assertEqual(cw.data, [b"reply"])
        self.assertFalse(cw.closed)
        cw.wait_gate = asyncio.Event()
        timers[1]._run()
        closing = tuple(proxy._tasks)
        self.assertEqual(len(closing), 1, "delayed close task was not retained")
        await cw.wait_entered.wait()
        self.assertIn(cw, proxy._writers, "writer released before wait_closed")
        cw.wait_gate.set()
        await asyncio.gather(*closing)
        self.assertEqual(cw.waited, 1)
        self.assertEqual(proxy._writers, set())
        self.assertEqual(proxy._tasks, set())
        self.assertEqual(proxy._timers, set())
        for timer in timers:
            timer.cancel()

    async def test_cleanup_attempts_other_writers_retains_failure_and_can_retry(self):
        proxy, _ = self.rig()
        failed, other = Writer(), Writer()
        failure = ValueError("wait_closed failed")
        failed.wait_error = failure
        proxy._writers.update((failed, other))
        with self.assertRaises(ValueError) as caught:
            await proxy._drain()
        self.assertIs(caught.exception, failure)
        self.assertEqual(other.waited, 1)
        self.assertEqual(proxy._writers, {failed})
        failed.wait_error = None
        await proxy._drain()
        await proxy._drain()
        self.assertEqual(proxy._writers, set())
        self.assertEqual(failed.waited, 1)

    async def test_cancelled_delayed_close_keeps_real_shared_waiter_intact(self):
        for error in (None, ConnectionResetError(errno.ECONNRESET, "peer reset"),
                      OSError(errno.EIO, "unexpected wait error")):
            with self.subTest(error=type(error).__name__):
                proxy, _ = self.rig()
                writer, transport = memory_stream(error, defer_loss=True)
                proxy._writers.add(writer)
                proxy._close_client(writer)
                await writer.wait_started.wait()
                closing = tuple(proxy._tasks)
                draining = asyncio.create_task(proxy._drain())
                await asyncio.gather(*closing, return_exceptions=True)
                shared_cancelled = transport.protocol._closed.cancelled()
                transport.lose()
                outcome, = await asyncio.gather(draining, return_exceptions=True)
                self.assertFalse(shared_cancelled, "cancellation poisoned shared close waiter")
                self.assertEqual(proxy._writer_waits, {})
                if isinstance(error, OSError) and not isinstance(error, ConnectionResetError):
                    self.assertIs(outcome, error)
                    self.assertIn(writer, proxy._writers)
                else:
                    self.assertIsNone(outcome)
                    self.assertEqual(proxy._writers, set())

    async def test_close_wait_task_scheduling_failure_closes_coroutine_and_retains_writer(self):
        proxy, _ = self.rig()
        writer = Writer()
        proxy._writers.add(writer)
        coroutines = []

        def fail(coroutine):
            coroutines.append(coroutine)
            raise ValueError("schedule close waiter")

        with patch.object(asyncio, "ensure_future", fail):
            with self.assertRaisesRegex(ValueError, "schedule close waiter"):
                await proxy._close_writer(writer)
        self.assertIsNone(coroutines[0].cr_frame, "failed scheduling leaked close coroutine")
        self.assertEqual(proxy._writer_waits, {})
        self.assertIn(writer, proxy._writers)
        await proxy._drain()

    async def test_early_client_pump_failure_closes_after_all_pending_replies(self):
        for replies in ((), (b"first", b"second")):
            with self.subTest(replies=replies):
                proxy, _ = self.rig()
                proxy.delay = 3600
                cw, uw = Writer(), Writer()
                upstream = Reader(replies, blocked=True)

                class FailedClient:
                    async def read(self, _size):
                        await self.upstream.entered.wait()
                        raise OSError("client read failed")

                    def at_eof(self):
                        return False

                client = FailedClient()
                client.upstream = upstream

                async def connect(*_args, upstream=upstream, uw=uw):
                    return upstream, uw

                loop = asyncio.get_running_loop()

                def timer(due, callback, *args, loop=loop):
                    return asyncio.TimerHandle(due, callback, args, loop)

                with (patch.object(asyncio, "open_connection", connect),
                      patch.object(loop, "call_at", timer)):
                    proxy._accept(client, cw)
                    await asyncio.gather(*tuple(proxy._tasks))
                timers = sorted(proxy._timers, key=lambda timer: timer.when())
                self.assertEqual(len(timers), len(replies) + 1,
                                 "early pump exit left no client-close timer")
                self.assertFalse(cw.closed)
                for timer in timers[:-1]:
                    timer._run()
                    self.assertFalse(cw.closed, "client closed before queued reply")
                self.assertEqual(cw.data, list(replies))
                if replies:
                    self.assertGreater(timers[-1].when(), timers[-2].when())
                timers[-1]._run()
                await asyncio.gather(*tuple(proxy._tasks))
                self.assertTrue(cw.closed)
                self.assertEqual(cw.waited, 1)
                self.assertEqual(proxy._writers, set())
                for timer in timers:
                    timer.cancel()
                await proxy._drain()

    async def test_peer_close_waiter_errors_confirm_closure_and_release_writer(self):
        for error in (ConnectionResetError(errno.ECONNRESET, "peer reset"),
                      BrokenPipeError(errno.EPIPE, "peer closed")):
            for already_lost in (False, True):
                with self.subTest(error=type(error).__name__, already_lost=already_lost):
                    proxy, _ = self.rig()
                    writer, transport = memory_stream(error)
                    if already_lost:
                        transport.lose()
                    proxy._writers.add(writer)
                    outcome, = await asyncio.gather(proxy._drain(), return_exceptions=True)
                    self.assertTrue(transport.lost, "close waiter returned before connection_lost")
                    self.assertTrue(writer.is_closing())
                    self.assertIsNone(outcome, "closed peer was reported as failed writer drainage")
                    self.assertEqual(proxy._writers, set())
                    await proxy._drain()

    async def test_peer_reset_delayed_close_task_releases_writer_without_task_failure(self):
        proxy, _ = self.rig()
        writer, transport = memory_stream(ConnectionResetError(errno.ECONNRESET, "peer reset"))
        proxy._writers.add(writer)
        proxy._close_client(writer)
        await asyncio.gather(*tuple(proxy._tasks), return_exceptions=True)
        self.assertTrue(transport.lost)
        self.assertEqual(proxy._tasks, set())
        self.assertEqual(proxy._task_errors, [], "expected peer reset became a task failure")
        self.assertEqual(proxy._writers, set())
        await proxy._drain()

    async def test_other_close_waiter_errors_remain_visible_and_owned(self):
        for error in (OSError(errno.EIO, "unexpected I/O error"),
                      ConnectionAbortedError(errno.ECONNABORTED, "unexpected abort")):
            with self.subTest(error=type(error).__name__):
                proxy, _ = self.rig()
                writer, transport = memory_stream(error)
                proxy._writers.add(writer)
                with self.assertRaises(type(error)) as caught:
                    await proxy._drain()
                self.assertIs(caught.exception, error)
                self.assertTrue(transport.lost)
                self.assertIn(writer, proxy._writers)

    async def test_peer_error_from_close_call_remains_visible_and_owned(self):
        for error in (ConnectionResetError(errno.ECONNRESET, "close failed"),
                      BrokenPipeError(errno.EPIPE, "close failed")):
            with self.subTest(error=type(error).__name__):
                proxy, _ = self.rig()
                writer, other = Writer(), Writer()
                writer.close_error = error
                proxy._writers.update((writer, other))
                with self.assertRaises(type(error)) as caught:
                    await proxy._drain()
                self.assertIs(caught.exception, error)
                self.assertEqual(writer.waited, 0)
                self.assertEqual(other.waited, 1)
                self.assertEqual(proxy._writers, {writer})

    async def test_close_failure_retains_writer_and_process_control_propagates(self):
        proxy, _ = self.rig()
        writer = Writer()
        proxy._writers.add(writer)
        for error in (OSError("close"), KeyboardInterrupt("close")):
            with self.subTest(error=type(error).__name__):
                writer.close_error = error
                with self.assertRaises(type(error)) as caught:
                    await proxy._drain()
                self.assertIs(caught.exception, error)
                self.assertIn(writer, proxy._writers)
        writer.close_error = None
        await proxy._drain()

    async def test_pending_delayed_close_is_cancelled_then_writer_awaited_by_drain(self):
        proxy, _ = self.rig()
        writer = Writer()
        writer.wait_gate = asyncio.Event()
        proxy._writers.add(writer)
        proxy._close_client(writer)
        await writer.wait_entered.wait()
        closing = tuple(proxy._tasks)
        draining = asyncio.create_task(proxy._drain())
        # The close task's completion is a deterministic cancellation boundary.
        await asyncio.gather(*closing, return_exceptions=True)
        self.assertTrue(closing[0].cancelled())
        self.assertIn(writer, proxy._writers)
        self.assertFalse(draining.done(), "drain skipped pending writer wait")
        writer.wait_gate.set()
        await draining
        self.assertEqual(writer.waited, 1)
        self.assertEqual(proxy._writers, set())

    async def test_task_failure_retained_after_completion_and_reported_once(self):
        proxy, _ = self.rig()
        failure = ValueError("handler")

        async def failed():
            raise failure

        proxy._spawn(failed())
        await asyncio.gather(*tuple(proxy._tasks), return_exceptions=True)
        self.assertEqual(proxy._tasks, set())
        with self.assertRaises(ValueError) as caught:
            await proxy._drain()
        self.assertIs(caught.exception, failure)
        await proxy._drain()
        proxy._task_errors.append(KeyboardInterrupt("completed task"))
        with self.assertRaisesRegex(KeyboardInterrupt, "completed task"):
            await proxy._drain()

    async def test_late_accept_closes_without_connect_and_is_owned(self):
        proxy, _ = self.rig()
        proxy._stopping = True
        writer = Writer()
        with patch.object(asyncio, "open_connection", side_effect=AssertionError("late connect")):
            proxy._accept(Reader(), writer)
            self.assertEqual(proxy._writers, {writer})
            self.assertEqual(len(proxy._tasks), 1)
            await asyncio.gather(*tuple(proxy._tasks))
        self.assertEqual(writer.waited, 1)
        self.assertEqual(proxy._writers, set())

    async def test_spawn_failure_closes_coroutine_but_keeps_accepted_writer(self):
        proxy, _ = self.rig()
        writer = Writer()
        with patch.object(asyncio, "ensure_future", side_effect=ValueError("schedule handler")):
            with self.assertRaisesRegex(ValueError, "schedule handler"):
                proxy._accept(Reader(), writer)
        self.assertEqual(proxy._writers, {writer})
        await proxy._drain()
        self.assertEqual(writer.waited, 1)


class StopDrainTests(unittest.TestCase):
    def test_stop_waits_for_drain_future_before_stopping_owner(self):
        cls, namespace = proxy_class()
        proxy = cls(1, 2)
        queued, coroutines, events = [], [], []

        def immediate_task(coroutine):
            try:
                coroutine.send(None)
            except StopIteration as done:
                future = concurrent.futures.Future()
                future.set_result(done.value)
                return future
            raise AssertionError("inert close unexpectedly suspended")

        async def shield(future):
            return future.result()

        namespace["asyncio"] = types.SimpleNamespace(ensure_future=immediate_task,
                                                      shield=shield)
        # Seed the same resource for both pinned and repaired source so the
        # negative control reaches stop's writer-drain assertion.
        proxy._writers = {Writer()}

        def create_task(coroutine):
            coroutines.append(coroutine)

        def stop_loop():
            self.assertEqual(proxy._writers, set(), "loop stopped with owned writer")
            events.append("stop")

        loop = types.SimpleNamespace(call_soon_threadsafe=queued.append,
                                     create_task=create_task, stop=stop_loop)

        def join(timeout):
            self.assertEqual(timeout, 10)
            for callback in queued:
                callback()
            self.assertEqual(events, [], "loop stopped before async drainage completed")
            self.assertEqual(len(coroutines), 1)
            try:
                coroutines[0].send(None)
            except StopIteration:
                pass
            else:
                self.fail("inert writer drainage unexpectedly suspended")
            self.assertEqual(events, ["stop"])

        proxy._loop = loop
        proxy._thread = types.SimpleNamespace(join=join, is_alive=lambda: False)
        proxy.stop()
        self.assertEqual((proxy._loop, proxy._thread), (None, None))
        proxy.stop()

    def test_unobserved_drain_with_dead_thread_keeps_nonempty_ownership(self):
        cls, _ = proxy_class()
        for registry in ("_tasks", "_writers"):
            with self.subTest(registry=registry):
                proxy = cls(1, 2)
                getattr(proxy, registry).add(object())
                proxy._loop = types.SimpleNamespace(call_soon_threadsafe=lambda _callback: None)
                proxy._thread = types.SimpleNamespace(join=lambda **_kw: None, is_alive=lambda: False)
                initial = proxy._loop, proxy._thread
                with self.assertRaisesRegex(RuntimeError, "cancellation did not complete"):
                    proxy.stop()
                self.assertEqual((proxy._loop, proxy._thread), initial)

    def test_completed_drain_cannot_release_unconfirmed_task_or_writer(self):
        cls, _ = proxy_class()
        for registry in ("_tasks", "_writers"):
            with self.subTest(registry=registry):
                proxy = cls(1, 2)
                getattr(proxy, registry).add(object())
                queued = []

                async def incomplete():
                    return None

                proxy._drain = incomplete

                def create_task(coroutine):
                    try:
                        coroutine.send(None)
                    except StopIteration:
                        return
                    self.fail("inert drainage unexpectedly suspended")

                proxy._loop = types.SimpleNamespace(call_soon_threadsafe=queued.append,
                                                     create_task=create_task, stop=lambda: None)
                proxy._thread = types.SimpleNamespace(
                    join=lambda queued=queued, **_kw: [callback() for callback in queued],
                    is_alive=lambda: False)
                initial = proxy._loop, proxy._thread
                with self.assertRaisesRegex(RuntimeError, "tasks or writers remain pending"):
                    proxy.stop()
                self.assertEqual((proxy._loop, proxy._thread), initial)

    def test_start_uses_synchronous_accept_and_resets_stopping_state(self):
        cls, namespace = proxy_class()
        proxy = cls(1, 2)
        proxy._stopping = True
        events = []
        server = object()

        async def start_server(callback, address, port):
            self.assertEqual(callback, proxy._accept)
            self.assertEqual((address, port), ("127.0.0.1", 1))
            self.assertFalse(proxy._stopping)
            events.append("accept-installed")
            return server

        def run_until_complete(coroutine):
            try:
                coroutine.send(None)
            except StopIteration as done:
                return done.value
            raise AssertionError("inert start unexpectedly suspended")

        loop = types.SimpleNamespace(run_until_complete=run_until_complete,
                                     run_forever=lambda: events.append("run-forever"))

        def thread(**kwargs):
            self.assertEqual(kwargs["name"], "abort-delay-proxy")
            self.assertTrue(kwargs["daemon"])
            return types.SimpleNamespace(start=kwargs["target"])

        namespace["threading"] = types.SimpleNamespace(Thread=thread)
        with (patch.object(asyncio, "new_event_loop", return_value=loop),
              patch.object(asyncio, "set_event_loop") as set_loop,
              patch.object(asyncio, "start_server", start_server)):
            proxy.start()
        set_loop.assert_called_once_with(loop)
        self.assertEqual(events, ["accept-installed", "run-forever"])
        self.assertIs(proxy._server, server)

    def test_drain_creation_failure_is_ferried_without_unawaited_coroutine(self):
        cls, _ = proxy_class()
        proxy = cls(1, 2)
        queued, events = [], []
        failure = ValueError("create drainage task")

        def create_task(coroutine):
            raise failure

        loop = types.SimpleNamespace(call_soon_threadsafe=queued.append,
                                     create_task=create_task, stop=lambda: events.append("stop"))
        proxy._loop = loop
        proxy._thread = types.SimpleNamespace(
            join=lambda **_kw: [callback() for callback in queued], is_alive=lambda: False)
        with self.assertRaises(ValueError) as caught:
            proxy.stop()
        self.assertIs(caught.exception, failure)
        self.assertIs(proxy._loop, loop)
        self.assertEqual(events, ["stop"])


if __name__ == "__main__":
    unittest.main()
