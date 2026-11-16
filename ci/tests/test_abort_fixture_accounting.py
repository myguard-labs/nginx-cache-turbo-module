#!/usr/bin/env python3
"""Pure-Python checks of the abort fixture's reply accounting and its "before"
deadline (CT-ABORT-FIXTURE-READ-ATTRIBUTION, CT-ABORT-COLDWAIT-WINDOW).

The proxy checks run the real DelayProxy against a scripted loopback upstream,
so they exercise the read loops that pair a watched request with its reply:
no nginx, no Redis. The deadline checks feed a fake anchor.
"""

import asyncio
import contextlib
import os
import pathlib
import sys
import threading
import time
import types
import typing
import unittest
from unittest import mock

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "ci" / "tools"))

import abort_fixture as af
from test_runtime_base import ASAN_TIME_SCALE, sanitizer_time_scale

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

    def test_unwatched_command_ahead_does_not_take_the_sighting(self) -> None:
        ping = b"*1\r\n$4\r\nPING\r\n"
        get = b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n"
        marker = b"GET\r\n$1\r\nk"
        proxy, _ = self.rig(len(ping + get), [(0.0, b"+PONG\r\n$3\r\nabc\r\n")],
                            [marker])
        self.send(proxy, [(0.0, ping + get)])
        proxy.wait_replied(marker, timeout=2.0)
        self.assertEqual(proxy.sighting(marker).reply_head, b"$3\r\nabc\r\n")

    def test_command_split_across_reads_is_one_sighting(self) -> None:
        get = b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n"
        marker = b"GET\r\n$1\r\nk"
        proxy, _ = self.rig(len(get), [(0.0, b"+OK\r\n")], [marker])
        self.send(proxy, [(0.0, get[:9]), (0.05, get[9:])])
        proxy.wait_replied(marker, timeout=2.0)
        self.assertEqual(proxy.sighting(marker).count, 1)


class ReplyGapCase(ProxyCase):
    """The settle margin's evidence: release of a reply -> next request read."""

    def exchange(self, pause: float) -> af.DelayProxy:
        """A, its reply read by the client, `pause`, then B: one gap."""
        proxy, _ = self.rig(len(A), [(0.0, b"+OK\r\n")], [A, B])
        sock = self.send(proxy, [(0.0, A)])
        sock.settimeout(2.0)
        self.assertEqual(sock.recv(64), b"+OK\r\n")
        time.sleep(pause)
        sock.sendall(B)
        proxy.wait_seen(B, timeout=2.0)
        return proxy

    def test_request_after_a_release_records_the_gap(self) -> None:
        gaps = self.exchange(0.08).take_reply_gaps()
        self.assertEqual(len(gaps), 1, gaps)
        self.assertGreaterEqual(gaps[0], 0.08)
        self.assertLess(gaps[0], 0.5)

    def test_take_starts_over(self) -> None:
        proxy = self.exchange(0.0)
        self.assertEqual(len(proxy.take_reply_gaps()), 1)
        self.assertEqual(proxy.take_reply_gaps(), [])

    def test_first_request_has_no_gap(self) -> None:
        proxy, _ = self.rig(len(A), [(0.0, b"+OK\r\n")], [A])
        self.send(proxy, [(0.0, A)])
        proxy.wait_replied(A, timeout=2.0)
        self.assertEqual(proxy.take_reply_gaps(), [])

    def test_take_forgets_a_release_before_it(self) -> None:
        # The reply landed, then take(): B is not timed from that reply, the
        # way a key's first request is not timed from the last key's reply.
        proxy, _ = self.rig(len(A), [(0.0, b"+OK\r\n")], [A, B])
        sock = self.send(proxy, [(0.0, A)])
        sock.settimeout(2.0)
        self.assertEqual(sock.recv(64), b"+OK\r\n")
        self.assertEqual(proxy.take_reply_gaps(), [])
        sock.sendall(B)
        proxy.wait_seen(B, timeout=2.0)
        self.assertEqual(proxy.take_reply_gaps(), [])


@contextlib.contextmanager
def asan_env(options: str | None) -> typing.Iterator[None]:
    """Run with ASAN_OPTIONS set to `options`, or absent for None: the switch
    both sanitizer_time_scale() and abort_settle() read."""
    with mock.patch.dict(os.environ):
        os.environ.pop("ASAN_OPTIONS", None)
        if options is not None:
            os.environ["ASAN_OPTIONS"] = options
        yield


# What base b77c03b settled for under a sanitizer: 0.1 x the time scale. The
# per-key crash attribution of the single-process ASan lane depends on it.
BASE_SANITIZED_SETTLE = 0.1 * ASAN_TIME_SCALE


class SettleCase(unittest.TestCase):
    def test_plain_settle_is_the_plain_margin(self) -> None:
        with asan_env(None):
            self.assertEqual(sanitizer_time_scale(), 1.0)
            self.assertEqual(af.abort_settle(), 0.05)

    def test_sanitized_settle_is_the_base_value(self) -> None:
        with asan_env("detect_leaks=0"):
            self.assertEqual(af.abort_settle(), BASE_SANITIZED_SETTLE)
            self.assertEqual(af.abort_settle(), 0.1 * sanitizer_time_scale())

    def test_empty_asan_options_switches_like_the_time_scale(self) -> None:
        # Presence, not content, flips both: an empty value is a sanitizer run.
        with asan_env(""):
            self.assertEqual(sanitizer_time_scale(), ASAN_TIME_SCALE)
            self.assertEqual(af.abort_settle(), BASE_SANITIZED_SETTLE)

    def test_sanitized_settle_outlasts_the_plain_one(self) -> None:
        with asan_env(None):
            plain = af.abort_settle()
        with asan_env("detect_leaks=0"):
            self.assertGreater(af.abort_settle(), plain * ASAN_TIME_SCALE)


class DescribeGapsCase(unittest.TestCase):
    def describe(self, gaps: list[float], options: str | None = None) -> str:
        with asan_env(options):
            return af.describe_reply_gaps(gaps)

    def test_no_gap_is_not_applicable(self) -> None:
        self.assertEqual(self.describe([]), "reply-to-next-max=n/a")

    def test_worst_gap_against_half_the_settle(self) -> None:
        self.assertEqual(self.describe([0.001, 0.0042]),
                         "reply-to-next-max=4.2ms/25.0ms n=2")
        self.assertEqual(self.describe([0.0042], ""),
                         "reply-to-next-max=4.2ms/100.0ms n=1")

    def test_gap_past_half_the_settle_is_marked(self) -> None:
        half = af.ABORT_SETTLE_MARGIN / 2
        self.assertTrue(self.describe([half + 0.001]).endswith(" over"))
        self.assertFalse(self.describe([half]).endswith(" over"))
        # The same gap is inside the settle of a sanitizer build.
        self.assertFalse(self.describe([half + 0.001], "").endswith(" over"))
        self.assertTrue(self.describe([BASE_SANITIZED_SETTLE / 2 + 0.001],
                                      "").endswith(" over"))

    def test_arm_line_carries_the_gaps_only_when_collected(self) -> None:
        bare = af.ArmResult("s k t", [af.Landing(True, -0.01)], [])
        self.assertNotIn("reply-to-next", bare.describe())
        with asan_env(None):
            line = af.ArmResult("s k t", [], [], [0.002]).describe()
        self.assertTrue(line.endswith(
            "fatal=0 reply-to-next-max=2.0ms/25.0ms n=1"), line)


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

    def test_wake_guard_scales_with_the_sanitizer_factor(self) -> None:
        now = self.NOW
        wake = now + 0.05          # unscaled guard (10ms) leaves 40ms open
        with mock.patch.object(af.time, "monotonic", return_value=now):
            self.assertIsNotNone(
                af._before_deadline(FakeAnchor(now, wake), now, 1.0))
            # at x10 the guard is 100ms: the wake is inside it, window closed
            self.assertIsNone(
                af._before_deadline(FakeAnchor(now, wake), now, 10.0))

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


class FakeNode:
    def __init__(self, fatal: list[str] | None = None) -> None:
        self._fatal = fatal or []

    def require_http2(self) -> None:
        pass

    def wait_released(self) -> list[str]:
        return []

    def fatal_lines(self) -> list[str]:
        return list(self._fatal)

    def diagnostics(self) -> str:
        return "\n".join(f"log{n}" for n in range(12))

    def stop(self) -> None:
        pass

    def assert_clean_logs(self) -> None:
        pass


class FakeProxy:
    """Every take returns one gap, so the arm's collection can be counted."""

    def __init__(self) -> None:
        self.takes = 0

    def take_reply_gaps(self) -> list[float]:
        self.takes += 1
        return [float(self.takes)]


class FakeAbortRig(af.AbortRig):
    """The real retry_uri and origin accounting around a fake node."""
    instances: typing.ClassVar[list["FakeAbortRig"]] = []

    def __init__(self, ng, site, slug, keys) -> None:
        self.site = site
        self.uris = [f"/{site.name}/k{n}" for n in range(keys)]
        self.retired: list[str] = []
        self.delay = 0.1
        self.node = FakeNode()
        self.fake_proxy = FakeProxy()
        self.proxy = typing.cast(af.DelayProxy, self.fake_proxy)
        self.anchored: list[str] = []
        FakeAbortRig.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        pass

    def anchor(self, uri: str):
        self.anchored.append(uri)
        return types.SimpleNamespace(times=lambda: af.ParkTimes(
            0.5, 2.0, 0.0, 0.0, True))


def fake_site() -> types.SimpleNamespace:
    return types.SimpleNamespace(
        name="s", prime=False, origin_hits=1, method="GET",
        request_target=lambda u: u)


class FakeOrigin:
    """hits_for() is 0 at the arm's baseline read, `hits` after it."""

    def __init__(self, hits: int) -> None:
        self.hits, self.reads = hits, 0

    def hits_for(self, prefix: str) -> int:
        self.reads += 1
        return 0 if self.reads == 1 else self.hits


class ClosedWindowCase(unittest.TestCase):
    def setUp(self) -> None:
        FakeAbortRig.instances.clear()
        p = mock.patch.object(af, "AbortRig", FakeAbortRig)
        p.start()
        self.addCleanup(p.stop)

    def test_abort_arm_retries_closed_keys_without_a_landing(self) -> None:
        def one(node, anchor, kind, timing, index, delay, path, method):
            if path.endswith("-r1"):
                return 1.0
            raise af.ParkWindowClosed()

        with mock.patch.object(af, "_abort_one", side_effect=one):
            # 3 first tries + 3 retries reach the origin once each
            res = af.run_abort_arm(None, FakeOrigin(6), fake_site(),
                                   "http1_rst", "before")
        rig = FakeAbortRig.instances[0]
        self.assertEqual(rig.retired, [f"{u}-r1" for u in rig.uris])
        self.assertEqual(len(res.landings), len(rig.uris))
        self.assertEqual(rig.anchored[1::2], rig.retired)
        self.assertEqual(res.fatal, [])
        # Per key: discard before each of two tries, collect after the judged
        # one. Only the collected takes (3rd, 6th, 9th) reach the arm.
        self.assertEqual(rig.fake_proxy.takes, 9)
        self.assertEqual(res.gaps, [3.0, 6.0, 9.0])

    def test_abort_arm_origin_accounting_counts_retired_keys(self) -> None:
        def one(node, anchor, kind, timing, index, delay, path, method):
            if path.endswith("-r1"):
                return 1.0
            raise af.ParkWindowClosed()

        with mock.patch.object(af, "_abort_one", side_effect=one), \
                self.assertRaisesRegex(AssertionError, "reached the origin"):
            af.run_abort_arm(None, FakeOrigin(3), fake_site(),
                             "http1_rst", "before")

    def test_abort_arm_retry_exhaustion_is_wrapped_like_the_sibling(self):
        with mock.patch.object(af, "_abort_one",
                               side_effect=af.ParkWindowClosed()), \
                self.assertRaises(AssertionError) as cm:
            af.run_abort_arm(None, FakeOrigin(0), fake_site(),
                             "http1_rst", "before")
        msg = str(cm.exception)
        self.assertIn("s http1_rst before:", msg)
        self.assertIn("key 0/3", msg)
        self.assertIn("fixture error", msg)
        self.assertIn("log tail:", msg)

    def reentry(self, closed_problems: list[str]) -> None:
        calls: list[str] = []

        def one(rig, uri, arm, landings):
            calls.append(uri)
            if not uri.endswith("-r1"):
                return list(closed_problems), True
            landings.append(af.Landing(True, -0.01))
            return [], False

        site = fake_site()
        ng = types.SimpleNamespace(root=types.SimpleNamespace(parent=None))
        with mock.patch.object(af, "_reentry_one", side_effect=one), \
                mock.patch.object(af, "reentry_site", lambda s, _: s):
            af.run_reentry_test(ng, FakeOrigin(6), site, "rst")
        self.assertEqual(len(calls), 6)

    def test_reentry_closed_attempt_answer_problems_are_dropped(self) -> None:
        self.reentry(["wrong answer: late", "extra backend op: late",
                      "no complete answer: late"])

    def test_reentry_closed_attempt_keeps_the_held_socket(self) -> None:
        with self.assertRaisesRegex(AssertionError,
                                    "client connection never closed"):
            self.reentry(["wrong answer: late",
                          f"{af.REENTRY_HELD}: sock"])

    def test_reentry_retry_exhaustion_is_wrapped_like_the_abort_arm(self):
        ng = types.SimpleNamespace(root=types.SimpleNamespace(parent=None))
        with mock.patch.object(af, "_reentry_one",
                               side_effect=lambda *a: ([], True)), \
                mock.patch.object(af, "reentry_site", lambda s, _: s), \
                self.assertRaises(AssertionError) as cm:
            af.run_reentry_test(ng, FakeOrigin(0), fake_site(), "rst")
        msg = str(cm.exception)
        self.assertIn("s reentry rst:", msg)
        self.assertIn("key 0/3", msg)
        self.assertIn("log tail:", msg)


if __name__ == "__main__":
    unittest.main()
