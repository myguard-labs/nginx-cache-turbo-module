#!/usr/bin/env python3
"""Pure-Python checks of the abort fixture's reply accounting and its "before"
deadline (CT-ABORT-FIXTURE-READ-ATTRIBUTION, CT-ABORT-COLDWAIT-WINDOW).

The proxy checks run the real DelayProxy against a scripted loopback upstream,
so they exercise the read loops that pair a watched request with its reply:
no nginx, no Redis. The deadline checks feed a fake anchor.
"""

import asyncio
import pathlib
import sys
import threading
import time
import types
import unittest
from unittest import mock

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "ci" / "tools"))

import abort_fixture as af

A, B = b"GET /a ", b"GET /b "


class ScriptedUpstream:
    """Loopback server: on each connection it reads until `expect` bytes
    arrived, then runs `script(writer)` (a list of (delay, bytes) steps)."""

    def __init__(self, expect: int, steps: list[tuple[float, bytes]]) -> None:
        self.expect, self.steps = expect, steps
        self.loop = asyncio.new_event_loop()
        self.port = 0
        ready = threading.Event()

        def run() -> None:
            asyncio.set_event_loop(self.loop)
            srv = self.loop.run_until_complete(
                asyncio.start_server(self.handle, "127.0.0.1", 0))
            self.port = srv.sockets[0].getsockname()[1]
            self.srv = srv
            ready.set()
            self.loop.run_forever()

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        assert ready.wait(5)

    async def handle(self, r: asyncio.StreamReader,
                     w: asyncio.StreamWriter) -> None:
        got = 0
        while got < self.expect:
            chunk = await r.read(65536)
            if not chunk:
                return
            got += len(chunk)
        for delay, data in self.steps:
            await asyncio.sleep(delay)
            w.write(data)
            await w.drain()
        await asyncio.sleep(0.5)
        w.close()

    def stop(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)


class ProxyCase(unittest.TestCase):
    def rig(self, expect: int, steps: list[tuple[float, bytes]],
            markers: list[bytes]) -> tuple[af.DelayProxy, ScriptedUpstream]:
        up = ScriptedUpstream(expect, steps)
        self.addCleanup(up.stop)
        # Any free local port: bind and release.
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        proxy = af.DelayProxy(port, up.port)
        proxy.start()
        self.addCleanup(proxy.stop)
        proxy.watch(markers)
        return proxy, up

    def send(self, proxy: af.DelayProxy, parts: list[tuple[float, bytes]]):
        import socket
        sock = socket.create_connection(("127.0.0.1", proxy.port))
        self.addCleanup(sock.close)
        for delay, data in parts:
            time.sleep(delay)
            sock.sendall(data)
        return sock

    def test_two_replies_in_one_read_each_get_a_sighting(self) -> None:
        both = b"+OK\r\n$3\r\nabc\r\n"
        proxy, _ = self.rig(len(A + B), [(0.0, both)], [A, B])
        self.send(proxy, [(0.0, A + B)])
        for m in (A, B):
            proxy.wait_replied(m, timeout=2.0)
        self.assertEqual(proxy.sighting(A).reply_head, b"+OK\r\n")
        self.assertEqual(proxy.sighting(B).reply_head, b"$3\r\nabc\r\n")

    def test_split_reply_is_not_early_for_the_next_sighting(self) -> None:
        steps = [(0.0, b"$5\r\nhel"), (0.2, b"lo\r\n"), (0.3, b"+OK\r\n")]
        proxy, _ = self.rig(len(A + B), steps, [A, B])
        t0 = time.monotonic()
        self.send(proxy, [(0.0, A + B)])
        a_at = proxy.wait_replied(A, timeout=2.0)
        self.assertGreaterEqual(a_at - t0, 0.15,
                                "A was released before its reply completed")
        self.assertEqual(proxy.sighting(A).reply_head, b"$5\r\nhello\r\n")
        self.assertFalse(proxy.sighting(B).replied.is_set(),
                         "B took the tail of A's reply")
        b_at = proxy.wait_replied(B, timeout=2.0)
        self.assertGreaterEqual(b_at - t0, 0.45)

    def test_http_reply_stays_one_per_read(self) -> None:
        proxy, _ = self.rig(len(A), [(0.0, b"HTTP/1.1 200 OK\r\n\r\n")], [A])
        self.send(proxy, [(0.0, A)])
        proxy.wait_replied(A, timeout=2.0)
        self.assertEqual(proxy.sighting(A).reply_head, b"HTTP/1.1 200 OK\r")

    def test_marker_spread_over_three_reads_is_seen(self) -> None:
        marker = b"ABCDEF"
        proxy, _ = self.rig(6, [(0.0, b"+OK\r\n")], [marker])
        self.send(proxy, [(0.0, b"AB"), (0.05, b"CD"), (0.05, b"EF")])
        proxy.wait_seen(marker, timeout=2.0)
        self.assertEqual(proxy.sighting(marker).count, 1)


class FakeAnchor:
    def __init__(self, parked_at: float, wake: float | None) -> None:
        self.parked_at = parked_at
        if wake is not None:
            self.earliest_wake = lambda: wake

    def wait_parked(self) -> float:
        return self.parked_at


class DeadlineCase(unittest.TestCase):
    # A frozen clock: the deadline math reads time.monotonic(), so a real clock
    # would let a scheduling delay close the window these cases keep open.
    NOW = 1000.0

    def deadline(self, anchor: FakeAnchor) -> float | None:
        with mock.patch.object(af.time, "monotonic", return_value=self.NOW):
            return af._abort_deadline(anchor, "before", 0, 0.1, 1.0)

    def test_fast_observation_keeps_the_original_deadline(self) -> None:
        now = self.NOW
        got = self.deadline(FakeAnchor(now, now + 0.09))
        self.assertAlmostEqual(got, now + 0.03, places=6)

    def test_slow_observation_aborts_ahead_of_the_first_wake(self) -> None:
        now = self.NOW
        wake = now + 0.025         # park seen 75ms into a 100ms poll window
        got = self.deadline(FakeAnchor(now, wake))
        self.assertIsNotNone(got)
        self.assertLess(got, wake)

    def test_closed_window_is_reported_not_judged(self) -> None:
        now = self.NOW
        self.assertIsNone(self.deadline(FakeAnchor(now, now - 0.01)))

    def test_anchor_without_a_wake_is_unchanged(self) -> None:
        now = self.NOW
        got = self.deadline(FakeAnchor(now, None))
        self.assertAlmostEqual(got, now + 0.03, places=6)


class RetryCase(unittest.TestCase):
    def rig(self, prime: bool) -> types.SimpleNamespace:
        return types.SimpleNamespace(site=types.SimpleNamespace(prime=prime),
                                     retired=[])

    def test_retry_uses_fresh_keys_and_tracks_them(self) -> None:
        rig = self.rig(False)
        got = [af.AbortRig.retry_uri(rig, "/ab/k", n) for n in (1, 2)]
        self.assertEqual(got, ["/ab/k-r1", "/ab/k-r2"])
        self.assertEqual(rig.retired, got)

    def test_retry_is_bounded_and_loud(self) -> None:
        rig = self.rig(False)
        with self.assertRaisesRegex(AssertionError, "fixture error"):
            af.AbortRig.retry_uri(rig, "/ab/k", af.ABORT_WINDOW_RETRIES + 1)

    def test_primed_key_cannot_be_retried(self) -> None:
        with self.assertRaisesRegex(AssertionError, "primed"):
            af.AbortRig.retry_uri(self.rig(True), "/ab/k", 1)


if __name__ == "__main__":
    unittest.main()
