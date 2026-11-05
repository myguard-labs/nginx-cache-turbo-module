"""Client-abort fixture: hold a request parked on a slow backend, then abort it.

CT-RESUME-FINALIZE-UAF lived for so long because nothing in the runtime suite
ever reset a parked request: the oracle existed (assert_clean_logs fails on
[alert]) but the stimulus did not. A clean client or a plain FIN does not set
c->error, so only an RST, a dead-connection write or an HTTP/2 stream or
connection teardown reaches the broken path. This module supplies that stimulus
for any site that parks a request on an L2 backend:

    DelayProxy  sits in front of the real backend and delays only the replies.
    ParkAnchor  the events one parked request is timed from: when it parked,
                when the reply ending the park lands. Every abort is timed from
                these, so it proves its own park. ProxyAnchor reads them from
                commands crossing the DelayProxy; a site that parks on something
                else supplies another ParkAnchor.
    Http1Client raw socket: a real RST (SO_LINGER 0) or a real FIN.
    H2Client    dependency-free h2c prior knowledge: RST_STREAM, connection
                close, or a full clean read.
    AbortNode   one-worker nginx with its own small config. The shared
                nginx_config has no HTTP/2 listener, and these tests must be
                able to restart the server to empty L1 without disturbing it.
    AbortSite   what differs per parked site. See run_abort_arm().

Sleeping a fixed time after connecting would be wrong: on a loaded host nginx
may not have accepted the request yet, the abort lands first, nothing parks and
the test passes on broken code. Timing from the backend's view removes that.

No test_* lives here. The tests are in areas/l2.py, so the orphan lint sees them.
"""

from __future__ import annotations

import asyncio
import collections
import concurrent.futures
import ctypes
import dataclasses
import functools
import json
import os
import pathlib
import re
import select
import socket
import struct
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from typing import Protocol

from nginx_config import PORT_OFFSETS, _errlog_level
from test_runtime_base import (
    SANITIZER_MARKERS,
    Nginx,
    Origin,
    fetch,
    sanitizer_time_scale,
    wait_for,
)

# Aborts per arm, one primed key each. The bug fires per abort, so more keys are
# repeats rather than coverage, and the suite runs under a wall-clock limit.
ABORT_KEYS = 3
# The boundary arm cycles through its offsets, and only those before the reply
# lands still find a parked request, so it needs enough keys to reach several.
ABORT_BOUNDARY_KEYS = 6

# Reply delay at the proxy. It must comfortably exceed scheduling noise, because
# "before the reply" has to be a real window.
ABORT_REPLY_DELAY = 0.1

# Once the backend has gone quiet for this long the parked request has finished
# or crashed. It must exceed the gap between a reply landing and nginx sending
# its next command, so it is a real margin on a loaded host, not a tight fit.
ABORT_SETTLE_MARGIN = 0.1

# Boundary arm: offsets around the moment the reply lands, cycled over the keys.
ABORT_BOUNDARY_OFFSETS = (-0.003, -0.002, -0.001, 0.0, 0.001, 0.002, 0.003)
ABORT_BOUNDARY_WINDOW = 0.005

HTTP1_KINDS = ("http1_rst", "http1_fin")
HTTP2_KINDS = ("h2_rst_stream", "h2_close")
ABORT_TIMINGS = ("before", "after", "boundary")


def _sleep_until(deadline: float) -> None:
    """Sleep to a time.monotonic() deadline, spinning for the last 2ms: the
    boundary arm needs a few ms of accuracy and time.sleep() overshoots."""
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        if remaining > 0.002:
            time.sleep(remaining - 0.002)


# --------------------------------------------------------------------------- #
# Delay proxy
# --------------------------------------------------------------------------- #


@dataclasses.dataclass
class _Sighting:
    """What the proxy saw for one watched request."""
    seen: threading.Event = dataclasses.field(default_factory=threading.Event)
    replied: threading.Event = dataclasses.field(
        default_factory=threading.Event)
    seen_at: float = 0.0      # time.monotonic() the request reached the proxy
    reply_at: float = 0.0     # time.monotonic() the reply is released to nginx
    count: int = 0            # times the request was sent


class DelayProxy:
    """TCP proxy delaying the server-to-client direction by `delay` seconds.

    Requests go through at once, so the backend's state changes on time and only
    nginx's view of the reply is late. `delay` may change between requests: a
    test primes at 0 and then raises it, so priming stays fast.

    watch() registers byte markers. Each marker is matched in the
    nginx-to-backend stream and the next reply on that connection is attributed
    to it, which is what lets a test wait for "this key's GET left nginx".
    Markers must not overlap, or one command would claim two replies.
    """

    def __init__(self, port: int, upstream_port: int) -> None:
        self.port = port
        self.upstream_port = upstream_port
        self.delay = 0.0
        self._watch: dict[bytes, _Sighting] = {}
        self._tail_len = 0
        self._busy_until = 0.0    # last request seen or reply release scheduled
        self.request_bytes = 0    # everything nginx ever sent to the backend
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: asyncio.base_events.Server | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        ready: concurrent.futures.Future[None] = concurrent.futures.Future()

        def run() -> None:
            asyncio.set_event_loop(loop)
            try:
                self._server = loop.run_until_complete(asyncio.start_server(
                    self._handle, "127.0.0.1", self.port))
            except Exception as exc:
                ready.set_exception(exc)
                return
            ready.set_result(None)
            loop.run_forever()

        self._thread = threading.Thread(target=run, daemon=True,
                                        name="abort-delay-proxy")
        self._thread.start()
        ready.result(timeout=10)

    def stop(self) -> None:
        loop, thread = self._loop, self._thread
        self._loop = self._thread = None
        if loop is None or thread is None:
            return
        if self._server is not None:
            loop.call_soon_threadsafe(self._server.close)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=10)

    def watch(self, markers: list[bytes]) -> None:
        """Start watching for these markers, forgetting any earlier set."""
        self._tail_len = max((len(m) for m in markers), default=1) - 1
        self._watch = {m: _Sighting() for m in markers}

    def sighting(self, marker: bytes) -> _Sighting:
        return self._watch[marker]

    def wait_seen(self, marker: bytes, timeout: float = 5.0) -> float:
        """Block until the marked request reached the backend; return when."""
        s = self._watch[marker]
        if not s.seen.wait(timeout * sanitizer_time_scale()):
            raise AssertionError(
                f"nginx never sent {marker!r} to the backend: the request did "
                f"not park, so an abort here would prove nothing")
        return s.seen_at

    def wait_replied(self, marker: bytes, timeout: float = 5.0) -> float:
        """Block until the marked request's reply was scheduled; return when
        that reply is released to nginx."""
        s = self._watch[marker]
        if not s.replied.wait(timeout * sanitizer_time_scale()):
            raise AssertionError(f"the backend never answered {marker!r}")
        return s.reply_at

    def wait_quiet(self, margin: float, timeout: float = 5.0) -> None:
        """Block until every scheduled reply has been released and no request
        has crossed for `margin` seconds. A reply being merely scheduled is not
        enough: nginx acts on it only once it lands, so a crash or a next
        command comes later than wait_replied() returns."""
        deadline = time.monotonic() + timeout * sanitizer_time_scale()
        while True:
            now = time.monotonic()
            remaining = self._busy_until + margin - now
            if remaining <= 0:
                return
            if now >= deadline:
                raise AssertionError(
                    f"the backend connection never went quiet for {margin}s")
            time.sleep(min(remaining, deadline - now))

    def _note_request(self, data: bytes, now: float,
                      pending: collections.deque[_Sighting]) -> None:
        self._busy_until = max(self._busy_until, now)
        for marker, s in self._watch.items():
            hits = data.count(marker)
            if not hits:
                continue
            if not s.count:
                s.seen_at = now
                s.seen.set()
            s.count += hits
            pending.extend([s] * hits)

    async def _handle(self, cr: asyncio.StreamReader,
                      cw: asyncio.StreamWriter) -> None:
        loop = asyncio.get_running_loop()
        try:
            ur, uw = await asyncio.open_connection("127.0.0.1",
                                                   self.upstream_port)
        except OSError:
            cw.close()
            return
        pending: collections.deque[_Sighting] = collections.deque()

        def deliver(data: bytes) -> None:
            if not cw.is_closing():
                cw.write(data)

        async def client_to_server() -> None:
            tail = b""
            while data := await cr.read(65536):
                self.request_bytes += len(data)
                self._note_request(tail + data, time.monotonic(), pending)
                tail = data[-self._tail_len:] if self._tail_len else b""
                uw.write(data)
                await uw.drain()

        async def server_to_client() -> None:
            while data := await ur.read(65536):
                # loop.time() is time.monotonic() on Unix, so reply_at compares
                # directly with the time the test aborts at.
                due = loop.time() + self.delay
                self._busy_until = max(self._busy_until, due)
                if pending:
                    s = pending.popleft()
                    s.reply_at = due
                    s.replied.set()
                loop.call_at(due, deliver, data)
            loop.call_at(loop.time() + self.delay, cw.close)

        tasks = [asyncio.ensure_future(client_to_server()),
                 asyncio.ensure_future(server_to_client())]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        except OSError:
            pass
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            uw.close()
            # A reply still inside its delay must still reach nginx: closing
            # here would turn "slow backend" into "backend died". The upstream
            # EOF branch above closes cw itself, and an nginx-side close leaves
            # nothing to deliver to.
            if cr.at_eof():
                cw.close()


# --------------------------------------------------------------------------- #
# Park anchors
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class ParkTimes:
    """time.monotonic() of one request's park events; 0.0 means never happened.

    The first and the final park are the same one at a site that parks once.
    """
    parked_at: float        # the request parked
    first_reply_at: float   # the reply ending the first park landed
    final_seen_at: float    # the last park began
    final_reply_at: float   # the reply ending the last park landed
    single_park: bool


class ParkAnchor(Protocol):
    """How a test observes one parked request. One instance per request."""

    def wait_parked(self) -> float:
        """Block until the request parked; return when it did. Raises
        AssertionError if it never does: such an abort would prove nothing."""

    def wait_final_reply(self) -> float:
        """Block until the release time of the reply ending the last park is
        known, which is ahead of the release itself; return that time."""

    def settle(self) -> None:
        """Block until nothing more can happen for this request: every reply
        has landed and the worker has had time to act on it, or to crash."""

    def times(self) -> ParkTimes:
        ...

    def assert_each_step_once(self) -> None:
        """A client that stayed went through each park exactly once."""


class ProxyAnchor:
    """Parks observed as commands crossing the DelayProxy, in the order nginx
    sends them for one request. Any command works, not only a GET: name what the
    site really sends (SET .. NX, SSCAN) and the timing follows."""

    def __init__(self, proxy: DelayProxy, commands: Sequence[bytes]) -> None:
        self.proxy = proxy
        self.commands = list(commands)
        proxy.watch(self.commands)

    def wait_parked(self) -> float:
        return self.proxy.wait_seen(self.commands[0])

    def wait_final_reply(self) -> float:
        return self.proxy.wait_replied(self.commands[-1])

    def settle(self) -> None:
        self.proxy.wait_quiet(ABORT_SETTLE_MARGIN * sanitizer_time_scale())

    def times(self) -> ParkTimes:
        first = self.proxy.sighting(self.commands[0])
        final = self.proxy.sighting(self.commands[-1])
        return ParkTimes(first.seen_at, first.reply_at, final.seen_at,
                         final.reply_at, len(self.commands) == 1)

    def assert_each_step_once(self) -> None:
        for command in self.commands:
            count = self.proxy.sighting(command).count
            assert count == 1, f"{command!r} sent {count} times, wanted once"


class WalkAnchor(ProxyAnchor):
    """A purge walk: a run of commands, some sent more than once.

    A walk opens a connection per op, and each one starts with SELECT, so the
    same bytes cross the proxy several times for one request. `commands` are
    the walk's parks in order, the last one being the reply that lets the walk
    answer; `trailing` are commands it sends only after answering, watched so
    their count is checked too. `sends` is how often each of commands +
    trailing crosses the proxy for one request that runs to the end.

    The "after" abort lands inside the last park, timed from when its command
    left nginx: a walk's parks are not all one delay long from the first.
    """

    def __init__(self, proxy: DelayProxy, commands: Sequence[bytes],
                 sends: Sequence[int], trailing: Sequence[bytes] = ()) -> None:
        super().__init__(proxy, commands)
        self.watched = [*commands, *trailing]
        assert len(sends) == len(self.watched), (sends, self.watched)
        self.sends = list(sends)
        proxy.watch(self.watched)

    def after_deadline(self, scale: float) -> float:
        return self.proxy.wait_seen(self.commands[-1]) + 0.05 * scale

    def assert_each_step_once(self) -> None:
        """Each command as often as one complete walk sends it."""
        for command, want in zip(self.watched, self.sends, strict=True):
            count = self.proxy.sighting(command).count
            assert count == want, f"{command!r} sent {count} times, wanted {want}"


# Linux inotify, from <sys/inotify.h>.
IN_OPEN = 0x20
IN_CLOSE_NOWRITE = 0x10
# TEST_FAULTS: a ".delay-<stage>" url_file sleeps this long before that stage
# (ngx_http_cache_turbo_warm_file_test_delay, admin.c).
WARM_FILE_TEST_DELAY = 5.0


class FileAnchor:
    """A request parked on a thread-pool task reading one file.

    The admin warm ?url_file= handler posts a task that opens, stats and reads
    the list, and parks the request on r->main->count++ until the task's event
    runs. A TEST_FAULTS build sleeps WARM_FILE_TEST_DELAY in the task when the
    file name says ".delay-fstat": after the open, before the rest. inotify
    sees both ends from outside, so no timing is assumed:

        parked       the task opened the file (IN_OPEN)
        final reply  the task closed it (IN_CLOSE_NOWRITE); its completion
                     event resumes the request right after. Known ahead as
                     open + WARM_FILE_TEST_DELAY, which the boundary arm needs.

    There is one park. "after" aborts once the request has been answered.
    """

    def __init__(self, path: pathlib.Path) -> None:
        self.path = path
        path.write_bytes(b"")
        libc = ctypes.CDLL(None, use_errno=True)
        self.fd = libc.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1")
        wd = libc.inotify_add_watch(self.fd, bytes(path),
                                    IN_OPEN | IN_CLOSE_NOWRITE)
        if wd < 0:
            os.close(self.fd)
            raise OSError(ctypes.get_errno(), f"inotify_add_watch {path}")
        self.opens: list[float] = []
        self.closes: list[float] = []
        self._opened = threading.Event()
        self._closed = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._read, daemon=True,
                                        name="file-anchor")
        self._thread.start()

    def _read(self) -> None:
        try:
            while not self._stop.is_set():
                ready, _, _ = select.select([self.fd], [], [], 0.05)
                if not ready:
                    continue
                now = time.monotonic()
                data = os.read(self.fd, 4096)
                while data:
                    _, mask, _, length = struct.unpack("iIII", data[:16])
                    data = data[16 + length:]
                    if mask & IN_OPEN:
                        self.opens.append(now)
                        self._opened.set()
                    if mask & IN_CLOSE_NOWRITE:
                        self.closes.append(now)
                        self._closed.set()
        finally:
            os.close(self.fd)

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)

    def wait_parked(self) -> float:
        if not self._opened.wait(5.0 * sanitizer_time_scale()):
            raise AssertionError(
                f"{self.path.name}: the warm task never opened the list, so "
                f"the request did not park and an abort would prove nothing")
        return self.opens[0]

    def wait_final_reply(self) -> float:
        return self.wait_parked() + WARM_FILE_TEST_DELAY

    def after_deadline(self, scale: float) -> float:
        """Past the only park: the request has already been answered."""
        return self.wait_final_reply() + 0.05 * scale

    def settle(self) -> None:
        scale = sanitizer_time_scale()
        if not self._closed.wait(WARM_FILE_TEST_DELAY + 5.0 * scale):
            raise AssertionError(f"{self.path.name}: the warm task never "
                                 f"closed the list")
        _sleep_until(self.closes[0] + ABORT_SETTLE_MARGIN * scale)
        self.close()

    def times(self) -> ParkTimes:
        opened = self.opens[0] if self.opens else 0.0
        closed = self.closes[0] if self.closes else 0.0
        return ParkTimes(opened, closed, opened, closed, True)

    def assert_each_step_once(self) -> None:
        assert len(self.opens) == 1 and len(self.closes) == 1, (
            f"{self.path.name}: opened {len(self.opens)} and closed "
            f"{len(self.closes)} times, wanted once each")


# NGX_HTTP_CACHE_TURBO_LOCK_POLL_MS: a cold-wait waiter wakes this often.
COLD_WAIT_POLL = 0.1


class ColdWaitAnchor:
    """A waiter parked on the cold-wait poll timer behind a slow leader.

    The waiter itself sends nothing to any backend: it parks on a timer and
    re-checks L1 every COLD_WAIT_POLL until the leader's fill lands. So the
    events come from elsewhere:

        leader        a clean HTTP/1 client for the same key, started here. Its
                      origin fetch crosses the proxy, which holds the reply for
                      AbortSite.proxy_delay. Once that fetch is seen the leader
                      holds the cold-miss claim, so the next request parks.
        parked        the zone's lock_waits counter moved, read from an admin
                      location on the node. cold_wait() bumps it right before
                      count++ and the timer. Polling brackets the park between
                      the start of the last poll that had not moved and the end
                      of the first that had.
        first wake    one poll after the park. Bracketed the same way, so
                      "before" must land before the earliest possible wake and
                      "after" after the latest.
        final reply   the leader's reply released to nginx: the fill. The
                      waiter serves on its first wake after it, so the boundary
                      arm aborts in the last park, next to the fill.
    """

    def __init__(self, rig: AbortRig, uri: str, admin: str) -> None:
        self.rig = rig
        self.uri = uri
        self.admin = admin
        # proxy_pass ends in "/", so /ab/x reaches the origin as /x.
        self.marker = f"GET /{uri.removeprefix('/ab/')} ".encode()
        rig.proxy.watch([self.marker])
        self.leader_result: tuple[int, dict[str, str], bytes] | BaseException | None = None
        self._leader_done = threading.Event()
        self.park_lo = self.park_hi = 0.0
        self.base_waits = self.lock_waits()
        leader = Http1Client(rig.node.port, uri)

        def read_leader() -> None:
            try:
                self.leader_result = leader.read_response()
            except BaseException as exc:  # noqa: BLE001 - reported by the checks
                self.leader_result = exc
            finally:
                self._leader_done.set()

        threading.Thread(target=read_leader, daemon=True,
                         name="cold-wait-leader").start()
        rig.proxy.wait_seen(self.marker)
        # The waiter is sent only after this returns, so it cannot park before
        # now. wait_parked() raises this bound with every poll that saw no park.
        self.park_lo = time.monotonic()

    def lock_waits(self) -> int:
        _, body, _ = fetch(self.rig.node.port, self.admin)
        return int(json.loads(body)["lock_waits"])

    def wait_parked(self) -> float:
        if self.park_hi:
            return self.park_hi
        deadline = time.monotonic() + 5.0 * sanitizer_time_scale()
        while True:
            started = time.monotonic()
            moved = self.lock_waits() > self.base_waits
            now = time.monotonic()
            if moved:
                self.park_hi = now
                return now
            self.park_lo = started
            if now >= deadline:
                raise AssertionError(
                    f"{self.uri}: the waiter never parked in cold_wait(), so an "
                    f"abort here would prove nothing")
            time.sleep(0.002)

    def wait_final_reply(self) -> float:
        return self.rig.proxy.wait_replied(self.marker)

    def settle(self) -> None:
        """The leader is answered and the waiter has had its serving wake."""
        scale = sanitizer_time_scale()
        if not self._leader_done.wait(10.0 * scale):
            raise AssertionError(f"{self.uri}: the leader never finished")
        self.rig.proxy.wait_quiet(ABORT_SETTLE_MARGIN * scale)
        _sleep_until(self.wait_final_reply() + COLD_WAIT_POLL
                     + ABORT_SETTLE_MARGIN * scale)
        if isinstance(self.leader_result, tuple):
            self.rig.bodies.setdefault(self.uri, self.leader_result[2])

    def times(self) -> ParkTimes:
        s = self.rig.proxy.sighting(self.marker)
        return ParkTimes(self.park_hi, self.park_lo + COLD_WAIT_POLL,
                         self.park_hi + COLD_WAIT_POLL, s.reply_at, False)

    def assert_each_step_once(self) -> None:
        """One origin fetch for the key, by the leader, which got the body; one
        waiter that waited once, not a second claim or an origin fallback."""
        count = self.rig.proxy.sighting(self.marker).count
        assert count == 1, f"{self.uri}: origin fetched {count} times, wanted once"
        result = self.leader_result
        assert isinstance(result, tuple) and result[0] == 200, (
            f"{self.uri}: leader got {result!r}")
        waits = self.lock_waits() - self.base_waits
        assert waits == 1, f"{self.uri}: lock_waits moved {waits}, wanted 1"


# --------------------------------------------------------------------------- #
# Clients
# --------------------------------------------------------------------------- #


def _drain_nonblocking(sock: socket.socket) -> None:
    """Consume whatever is queued. close() with unread data sends an RST rather
    than a FIN, which would silently turn a FIN arm into an RST arm."""
    sock.setblocking(False)
    try:
        while sock.recv(65536):
            pass
    except OSError:
        pass


class Http1Client:
    """One raw HTTP/1.1 request on its own connection, aborted or read to the
    end. GET by default; a POST (the admin purges) carries an empty body."""

    def __init__(self, port: int, path: str, method: str = "GET") -> None:
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        length = "Content-Length: 0\r\n" if method != "GET" else ""
        self.sock.sendall(f"{method} {path} HTTP/1.1\r\nHost: abort-fixture\r\n"
                          f"{length}Connection: close\r\n\r\n".encode())

    def abort_rst(self) -> None:
        """SO_LINGER with a zero timeout: close() sends an RST at once."""
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                             struct.pack("ii", 1, 0))
        self.sock.close()

    def abort_fin(self) -> None:
        _drain_nonblocking(self.sock)
        self.sock.close()

    def read_response(self, timeout: float = 10.0
                      ) -> tuple[int, dict[str, str], bytes]:
        """Read to EOF; return (status, lower-cased headers, body)."""
        self.sock.settimeout(timeout * sanitizer_time_scale())
        data = b""
        try:
            while chunk := self.sock.recv(65536):
                data += chunk
        finally:
            self.sock.close()
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        return int(lines[0].split()[1]), headers, body


# RFC 9113 frame types and flags, only those this client uses.
H2_DATA, H2_HEADERS, H2_RST_STREAM, H2_SETTINGS = 0, 1, 3, 4
H2_GOAWAY, H2_WINDOW_UPDATE = 7, 8
H2_FLAG_ACK = 0x1
H2_FLAG_END_STREAM = 0x1
H2_FLAG_END_HEADERS = 0x4
H2_CANCEL = 8
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
# HPACK static table, indexed ":method" fields (RFC 7541 App A).
H2_METHOD = {"GET": b"\x82", "POST": b"\x83"}
# HPACK static table entries for the indexed form of ":status" (RFC 7541 App A).
H2_STATIC_STATUS = {8: 200, 9: 204, 10: 206, 11: 304, 12: 400, 13: 404, 14: 500}


def _h2_frame(ftype: int, flags: int, stream: int, payload: bytes = b"") -> bytes:
    return (struct.pack(">I", len(payload))[1:] + bytes([ftype, flags])
            + struct.pack(">I", stream) + payload)


def _hpack_literal(name_index: int, value: bytes) -> bytes:
    """Literal header field without indexing, name from the static table,
    value not Huffman coded. Both integers must fit HPACK's short forms."""
    assert name_index < 15 and len(value) < 127, (name_index, value)
    return bytes([name_index, len(value)]) + value


class H2Client:
    """h2c prior-knowledge client, one stream at a time on one connection."""

    def __init__(self, port: int) -> None:
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        # A large connection and stream window keeps flow control out of the
        # way: this client has no reason to pace a cached body.
        settings = struct.pack(">HI", 4, 1 << 24)   # INITIAL_WINDOW_SIZE
        self.sock.sendall(
            H2_PREFACE
            + _h2_frame(H2_SETTINGS, 0, 0, settings)
            + _h2_frame(H2_WINDOW_UPDATE, 0, 0, struct.pack(">I", 1 << 24)))
        self.buf = b""

    def send_get(self, path: str, stream: int = 1) -> None:
        self.send_request(path, "GET", stream)

    def send_request(self, path: str, method: str = "GET",
                     stream: int = 1) -> None:
        """One request with no body: GET, or POST for the admin purges."""
        block = (H2_METHOD[method] + b"\x86"                # :method, :scheme http
                 + _hpack_literal(4, path.encode())         # :path
                 + _hpack_literal(1, b"abort-fixture"))     # :authority
        # END_STREAM matters: an unfinished stream counts as "has a body", and
        # the module bypasses the cache for those, so nothing would park. A
        # POST needs it too, or nginx waits for a body that never comes.
        self.sock.sendall(_h2_frame(H2_HEADERS,
                                    H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
                                    stream, block))

    def rst_stream(self, stream: int = 1) -> None:
        self.sock.sendall(_h2_frame(H2_RST_STREAM, 0, stream,
                                    struct.pack(">I", H2_CANCEL)))

    def close(self) -> None:
        """Close the connection with a FIN, not an RST: see _drain_nonblocking."""
        _drain_nonblocking(self.sock)
        self.sock.close()

    def _read_frame(self) -> tuple[int, int, int, bytes]:
        while len(self.buf) < 9:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise AssertionError("h2c: connection closed mid-response")
            self.buf += chunk
        length = int.from_bytes(self.buf[:3], "big")
        while len(self.buf) < 9 + length:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise AssertionError("h2c: connection closed mid-frame")
            self.buf += chunk
        ftype, flags = self.buf[3], self.buf[4]
        stream = int.from_bytes(self.buf[5:9], "big") & 0x7fffffff
        payload = self.buf[9:9 + length]
        self.buf = self.buf[9 + length:]
        return ftype, flags, stream, payload

    def read_response(self, stream: int = 1,
                      timeout: float = 10.0) -> tuple[int, bytes]:
        """Read this stream to END_STREAM; return (status, body)."""
        self.sock.settimeout(timeout * sanitizer_time_scale())
        status = 0
        body = b""
        while True:
            ftype, flags, sid, payload = self._read_frame()
            if ftype == H2_SETTINGS and not flags & H2_FLAG_ACK:
                self.sock.sendall(_h2_frame(H2_SETTINGS, H2_FLAG_ACK, 0))
            elif ftype == H2_GOAWAY or (ftype == H2_RST_STREAM and sid == stream):
                raise AssertionError(f"h2c: frame {ftype} before END_STREAM: "
                                     f"{payload!r}")
            elif ftype == H2_HEADERS and sid == stream:
                status = H2_STATIC_STATUS.get(payload[0] & 0x7f, 0)
                if flags & H2_FLAG_END_STREAM:
                    return status, body
            elif ftype == H2_DATA and sid == stream:
                body += payload
                if flags & H2_FLAG_END_STREAM:
                    return status, body


# --------------------------------------------------------------------------- #
# Dedicated nginx
# --------------------------------------------------------------------------- #


@functools.lru_cache(maxsize=None)
def http2_style(binary: str) -> str | None:
    """How this binary enables HTTP/2: "on", "listen", or None if it cannot.

    `http2 on` only exists from nginx 1.25.1, and the legacy CI job runs this
    suite on 1.22.1, where the same thing is a `listen ... http2` parameter.
    Angie reports no nginx/ version and has the modern directive.
    """
    out = subprocess.run([binary, "-V"], check=True, timeout=20, text=True,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
    if "--with-http_v2_module" not in out:
        return None
    m = re.search(r"nginx version: nginx/(\d+)\.(\d+)\.(\d+)", out)
    if m and tuple(int(g) for g in m.groups()) < (1, 25, 1):
        return "listen"
    return "on"


@functools.lru_cache(maxsize=None)
def binary_has_debug_log(binary: str) -> bool:
    out = subprocess.run([binary, "-V"], check=True, timeout=20, text=True,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
    return "--with-debug" in out


class AbortNode(Nginx):
    """One-worker nginx with a config of its own, on the shared origin."""

    def __init__(self, ng: Nginx, name: str, directives: str, valid: str,
                 errlog: str | None = None, upstream_port: int | None = None,
                 server_extra: str = "") -> None:
        super().__init__(ng.binary, ng.module, ng.root.parent / name,
                         ng.port + PORT_OFFSETS["abort_node"], ng.origin_port,
                         ng.runner_raw, ng.single_process)
        self.sanitizer = ng.sanitizer
        self.h2_port = ng.port + PORT_OFFSETS["abort_node_h2"]
        self.directives = directives
        self.valid = valid
        self.errlog = errlog or _errlog_level()
        self.h2_style = http2_style(str(ng.binary))
        self.upstream_port = upstream_port or ng.origin_port
        self.server_extra = server_extra

    def write_config(self, sr_off: bool = False) -> None:
        (self.root / "conf").mkdir(parents=True, exist_ok=True)
        (self.root / "logs").mkdir(parents=True, exist_ok=True)
        load = f"load_module {self.module};\n" if self.module else ""
        # Two listeners, so one config works on both sides of nginx 1.25.1,
        # where a `listen ... http2` port stops speaking HTTP/1 at all.
        h2_listen = " http2" if self.h2_style == "listen" else ""
        h2_on = "http2 on;" if self.h2_style == "on" else ""
        h2_port_line = (f"listen 127.0.0.1:{self.h2_port}{h2_listen};"
                        if self.h2_style else "")
        (self.root / "conf" / "nginx.conf").write_text(f"""{load}
worker_processes 1;
pid {self.root}/nginx.pid;
error_log {self.root}/logs/error.log {self.errlog};
events {{ worker_connections 512; }}
http {{
    access_log off;
    cache_turbo_zone name=abort 16m;
    server {{
        listen 127.0.0.1:{self.port};
        {h2_port_line}
        {h2_on}
        location /ab/ {{
            cache_turbo abort;
            cache_turbo_key $uri;
            cache_turbo_valid {self.valid};
            cache_turbo_keep_stale off;
            {self.directives}
            proxy_pass http://127.0.0.1:{self.upstream_port}/;
        }}
        {self.server_extra}
    }}
}}
""", encoding="ascii")

    def require_http2(self) -> None:
        """Fail, never skip: a skipped HTTP/2 arm looks like coverage. The
        suite's builds enable the module in ci/tools/ci-build.sh."""
        assert self.h2_style is not None, (
            f"{self.binary} was built without --with-http_v2_module, so the "
            f"HTTP/2 abort arms cannot run")

    def restart(self) -> None:
        """Stop and start: the zone is shared memory, so this empties L1."""
        self.stop()
        self.start()

    def wait_worker(self) -> None:
        """Block until a worker is serving, so a crash the last request caused
        cannot take the next one down with it and be blamed on that one."""
        if self.single_process:
            assert self.process is not None and self.process.poll() is None, (
                "single-process nginx is gone")
            return

        def alive() -> bool:
            for pid in self.worker_pids():
                try:
                    stat = pathlib.Path(f"/proc/{pid}/stat").read_text()
                except OSError:
                    continue
                if stat.rpartition(")")[2].split()[0] != "Z":
                    return True
            return False

        assert wait_for(alive, timeout=10.0, interval=0.01), (
            "the master did not respawn a worker")

    def fatal_lines(self) -> list[str]:
        """Every line the abort oracle treats as a failure. A crash is an
        [alert]: `worker process N exited on signal 11`. A sanitizer report is
        not, because ASan ends the worker with an exit code at notice level."""
        needles = ("[alert]", "[emerg]", "count is zero", *SANITIZER_MARKERS)
        return [ln for ln in self.diagnostics().splitlines()
                if any(n in ln for n in needles)
                and "ERROR SUMMARY: 0 errors" not in ln]


# --------------------------------------------------------------------------- #
# One abort arm
# --------------------------------------------------------------------------- #


def restart_cold(rig: AbortRig) -> None:
    """Empty L1, so the next request for a primed key has to ask L2."""
    rig.node.restart()


@dataclasses.dataclass(frozen=True)
class AbortSite:
    """Everything that differs between parked sites.

    name         short slug, used in URIs and in the node's directory name
    upstream     real backend port behind the delay proxy
    directives   location directives wiring the site to the backend. Takes
                 {proxy_port}, the only address nginx may use.
    anchor       (rig, uri) -> a fresh ParkAnchor for one request. Built only
                 after priming, so a priming command cannot count as a park.
    stored       uri -> bool, the backend holds the primed value
    forget       uri -> None, drop the primed value
    valid        cache_turbo_valid of the location
    served       X-Cache a client that stays must see
    arrange      rig -> None, put the primed keys into the state that parks.
                 Runs once, with the proxy already delaying. A hit on L2 parks
                 from a cold node; a site that needs L1 populated replaces this.
    prime        fetch every key once before the arm. A site that parks on a
                 miss, not on a hit, turns this off.
    origin_proxy the proxy sits in front of the origin instead of an L2
                 backend: `upstream` is then the origin port and proxy_pass
                 goes through the proxy.
    proxy_delay  reply delay at the proxy, seconds before sanitizer scaling.
                 None means ABORT_REPLY_DELAY.
    server_extra config added to the node's server block, e.g. an admin
                 location the anchor reads.
    origin_hits  requests per key the origin is expected to see during an arm
    method       request method; the admin purges are POSTs
    target       uri -> the request target actually sent. None sends the uri
                 itself. A site whose request is not a cached GET (an admin
                 purge, keyed by the uri's tag or keyspace) maps it here.
    verify       (rig, uri, status, body) -> None, the clean client's check
                 that the request did its job. None means: X-Cache is
                 `served` and the body is the primed one.
    """
    name: str
    upstream: int
    directives: str
    anchor: Callable[[AbortRig, str], ParkAnchor]
    stored: Callable[[str], bool]
    forget: Callable[[str], object]
    valid: str = "60s"
    served: str = "HIT"
    arrange: Callable[[AbortRig], None] = restart_cold
    prime: bool = True
    origin_proxy: bool = False
    proxy_delay: float | None = None
    server_extra: str = ""
    origin_hits: int = 0
    method: str = "GET"
    target: Callable[[str], str] | None = None
    verify: Callable[[AbortRig, str, int, bytes], None] | None = None

    def request_target(self, uri: str) -> str:
        return uri if self.target is None else self.target(uri)


@dataclasses.dataclass(frozen=True)
class Landing:
    """Where one abort landed."""
    in_phase: bool       # inside the window its timing names
    minus_reply: float   # abort time minus the last reply seen, seconds


@dataclasses.dataclass
class ArmResult:
    arm: str
    landings: list[Landing]
    fatal: list[str]

    def describe(self) -> str:
        deltas = [x.minus_reply * 1000 for x in self.landings]
        spread = f"{min(deltas):+.1f}..{max(deltas):+.1f}ms" if deltas else "n/a"
        hit = sum(x.in_phase for x in self.landings)
        return (f"{self.arm}: aborts={len(self.landings)} in-phase={hit} "
                f"abort-minus-last-reply={spread} fatal={len(self.fatal)}")


def _abort_deadline(anchor: ParkAnchor, timing: str, index: int, delay: float,
                    scale: float) -> float:
    """When to abort: time.monotonic(), from this request's own park events.

    A primed L2 hit parks twice, on the vary-marker GET and then on the object
    GET, so the final reply lands about two delays after the request parked.
    before    inside the first park
    after     past the first reply: inside the last park. At a site that parks
              once it is past the only reply, so the request has already resumed
              and answered, and the abort finds nothing parked. That is a control
              which stays clean even on broken resume code.
    boundary  a few ms either side of the reply that ends the last park
    """
    parked_at = anchor.wait_parked()
    if timing == "before":
        return parked_at + 0.03 * scale
    if timing == "after":
        # An anchor whose parks are not each one delay long names the moment
        # itself (WalkAnchor, FileAnchor); it is not part of ParkAnchor
        # because every other anchor uses the rule below.
        after = getattr(anchor, "after_deadline", None)
        if after is not None:
            return after(scale)
        return parked_at + delay + 0.05 * scale
    if timing == "boundary":
        offsets = ABORT_BOUNDARY_OFFSETS
        return anchor.wait_final_reply() + offsets[index % len(offsets)]
    raise ValueError(f"unknown abort timing: {timing}")


def _landing(timing: str, aborted_at: float, t: ParkTimes) -> Landing:
    last_reply = t.final_reply_at or t.first_reply_at or aborted_at
    minus_reply = aborted_at - last_reply
    if timing == "before":
        # No reply at all counts: a dead client may drop the backend connection.
        in_phase = not t.first_reply_at or aborted_at < t.first_reply_at
    elif timing == "after":
        in_phase = (aborted_at > t.first_reply_at if t.single_park
                    else 0 < t.final_seen_at <= aborted_at < t.final_reply_at)
    else:
        in_phase = abs(minus_reply) <= ABORT_BOUNDARY_WINDOW
    return Landing(in_phase, minus_reply)


def _abort_one(node: AbortNode, anchor: ParkAnchor, kind: str, timing: str,
               index: int, delay: float, path: str, method: str = "GET") -> float:
    """One abort of one parked request; return when it was aborted.

    Returns only once the request is over and a worker is serving, because keys
    run one at a time and a failure must belong to the key that caused it.
    """
    h2: H2Client | None = None
    h1: Http1Client | None = None
    if kind in HTTP2_KINDS:
        h2 = H2Client(node.h2_port)
        h2.send_request(path, method)
    elif kind in HTTP1_KINDS:
        h1 = Http1Client(node.port, path, method)
    else:
        raise ValueError(f"unknown abort kind: {kind}")

    _sleep_until(_abort_deadline(anchor, timing, index, delay,
                                 sanitizer_time_scale()))
    aborted_at = time.monotonic()
    if kind == "http1_rst":
        h1.abort_rst()
    elif kind == "http1_fin":
        h1.abort_fin()
    elif kind == "h2_rst_stream":
        h2.rst_stream()
    else:
        h2.close()

    anchor.settle()
    if kind == "h2_rst_stream":
        # Only now: closing earlier would turn this arm into a connection
        # close, which is the next kind.
        h2.close()
    node.wait_worker()
    return aborted_at


def _check_stimulus(result: ArmResult, timing: str) -> None:
    """Refuse a vacuous arm: an abort that missed its window proves nothing
    about that window. One stalled key is not a failure, a whole arm is. The
    boundary arm needs only one hit, because its window is a few ms wide."""
    hit = sum(x.in_phase for x in result.landings)
    need = 1 if timing == "boundary" else len(result.landings) // 2 + 1
    assert hit >= need, (
        f"{result.arm}: only {hit}/{len(result.landings)} aborts landed "
        f"{timing} (need {need}), so this run did not test that window: "
        f"{[round(x.minus_reply * 1000, 1) for x in result.landings]} ms from "
        f"the last reply")


class AbortRig:
    """A proxy and a one-worker node for one site, primed and restarted cold.

    Use as a context manager. On entry the keys are in the backend, L1 is empty
    and the proxy delays replies, so the next request for any key parks.
    """

    def __init__(self, ng: Nginx, site: AbortSite, slug: str, keys: int,
                 errlog: str | None = None) -> None:
        self.site = site
        self.uris = [f"/ab/{site.name}-{slug}-{i}" for i in range(keys)]
        self.bodies: dict[str, bytes] = {}
        # Arm timing ("after" aborts one delay past the park) uses this; the
        # proxy's own delay may differ, see AbortSite.proxy_delay.
        self.delay = ABORT_REPLY_DELAY * sanitizer_time_scale()
        self.proxy_delay = (self.delay if site.proxy_delay is None
                            else site.proxy_delay * sanitizer_time_scale())
        self.proxy = DelayProxy(ng.port + PORT_OFFSETS["abort_proxy"],
                                site.upstream)
        self.node = AbortNode(
            ng, f"abort-{site.name}-{slug}",
            site.directives.format(proxy_port=self.proxy.port), site.valid,
            errlog, self.proxy.port if site.origin_proxy else None,
            site.server_extra)

    def _prime(self) -> None:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda u: fetch(self.node.port, u), self.uris))
        for uri, (status, body, _) in zip(self.uris, results, strict=True):
            assert status == 200, f"priming {uri}: status {status}"
            self.bodies[uri] = body.encode()
        missing = [u for u in self.uris
                   if not wait_for(lambda u=u: self.site.stored(u))]
        assert not missing, f"never reached the backend: {missing}"

    def __enter__(self) -> AbortRig:
        self.proxy.start()
        try:
            self.node.write_config()
            self.node.config_test()
            self.node.start()
            if self.site.prime:
                self._prime()
            self.proxy.delay = self.proxy_delay
            self.site.arrange(self)
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, exc_type: object, *exc: object) -> None:
        try:
            self.node.stop()
        except RuntimeError:
            # A single-process nginx that crashed fails stop() too. Let the
            # failure already on its way out, which names the cause, win.
            if exc_type is None:
                raise
        finally:
            self.proxy.stop()
            for uri in self.uris:
                self.site.forget(uri)

    def anchor(self, uri: str) -> ParkAnchor:
        return self.site.anchor(self, uri)

    def assert_no_origin_traffic(self, origin: Origin, base: int) -> None:
        """A key that missed L2 goes to the origin instead of parking on a hit,
        so an origin hit means the arm did not test what it says. A site whose
        park needs origin traffic (a cold-wait leader) names how much."""
        now = origin.hits_for(f"{self.site.name}-")
        want = base + self.site.origin_hits * len(self.uris)
        assert now == want, (
            f"{now - base} requests reached the origin, wanted "
            f"{want - base}: a key did not park the way this site needs")


def run_abort_arm(ng: Nginx, origin: Origin, site: AbortSite, kind: str,
                  timing: str) -> ArmResult:
    """Prime, restart cold, abort one parked request per key, stop, read logs.

    Stays at the default notice log level: debug logging may read the freed
    request's strings and change how the bug shows up.

    Returns the fatal log lines for assert_abort_clean() to judge, so a caller
    can report an arm without failing it. Fatal lines outrank every other check
    here: they are what the arm exists to catch, and the stimulus checks that
    follow would only blame the crash's side effects. On a clean run those
    checks are what keep a pass from being vacuous.
    """
    arm = f"{site.name} {kind} {timing}"
    keys = ABORT_BOUNDARY_KEYS if timing == "boundary" else ABORT_KEYS
    landings: list[Landing] = []
    with AbortRig(ng, site, f"{kind}-{timing}", keys) as rig:
        if kind in HTTP2_KINDS:
            rig.node.require_http2()
        base = origin.hits_for(f"{site.name}-")
        for i, uri in enumerate(rig.uris):
            anchor = rig.anchor(uri)
            try:
                aborted_at = _abort_one(rig.node, anchor, kind, timing, i,
                                        rig.delay, site.request_target(uri),
                                        site.method)
            except (AssertionError, OSError) as exc:
                fatal = rig.node.fatal_lines()
                cause = f"{len(fatal)} fatal lines, first: {fatal[0]}\n" if fatal else ""
                log = rig.node.diagnostics().splitlines()[-8:]
                raise AssertionError(
                    f"{arm}: {cause}key {i}/{keys}: {exc}\nlog tail:\n"
                    + "\n".join(log)) from exc
            landings.append(_landing(timing, aborted_at, anchor.times()))
        rig.node.stop()
        result = ArmResult(arm, landings, rig.node.fatal_lines())
        print(f"abort-arm {result.describe()}", flush=True)
        if not result.fatal:
            rig.assert_no_origin_traffic(origin, base)
            _check_stimulus(result, timing)
        return result


def assert_abort_clean(result: ArmResult) -> None:
    assert not result.fatal, (
        f"{result.describe()}\nfirst: {result.fatal[0]}")


def run_abort_test(ng: Nginx, origin: Origin, site: AbortSite, kind: str,
                   timing: str) -> None:
    """One abort arm as a test: no alert, no sanitizer report."""
    assert_abort_clean(run_abort_arm(ng, origin, site, kind, timing))


def run_clean_test(ng: Nginx, origin: Origin, site: AbortSite,
                   protocol: str) -> None:
    """Negative control: a client that stays gets the full cached body, from L2,
    through the same park, and nothing is logged."""
    with AbortRig(ng, site, f"clean-{protocol}", ABORT_KEYS) as rig:
        if protocol == "http2":
            rig.node.require_http2()
        base = origin.hits_for(f"{site.name}-")
        for uri in rig.uris:
            anchor = rig.anchor(uri)
            path = site.request_target(uri)
            if protocol == "http2":
                h2 = H2Client(rig.node.h2_port)
                h2.send_request(path, site.method)
                status, body = h2.read_response()
                h2.close()
            else:
                status, headers, body = Http1Client(
                    rig.node.port, path, site.method).read_response()
                assert site.verify or headers.get("x-cache") == site.served, (
                    f"{uri}: X-Cache={headers.get('x-cache')}, wanted {site.served}")
            # A site with nothing primed learns the expected body from its
            # anchor, which has it once the request is over.
            anchor.settle()
            if site.verify is not None:
                site.verify(rig, uri, status, body)
            else:
                assert status == 200, f"{uri}: status {status}"
                assert body == rig.bodies[uri], (
                    f"{uri}: body {body!r} is not the primed {rig.bodies[uri]!r}")
            anchor.assert_each_step_once()
        rig.assert_no_origin_traffic(origin, base)
        rig.node.stop()
        fatal = rig.node.fatal_lines()
        assert not fatal, f"clean client logged: {fatal[0]}"
        rig.node.assert_clean_logs()


def run_parks_test(ng: Nginx, origin: Origin, site: AbortSite,
                   parks: int, parked_lines: Callable[[str], list[str]]) -> None:
    """The fixture's own proof: a primed key after a restart really parks, and
    the timing the abort arms rely on holds. If this breaks, every abort arm is
    suspect, so it stands apart from them.

    parks         how many times one request parks at this site
    parked_lines  uri -> the debug lines one request logs while parked. Checked
                  only on a --with-debug build, the only one that logs them.
    """
    debug = binary_has_debug_log(str(ng.binary))
    with AbortRig(ng, site, "parks", 1, "debug" if debug else None) as rig:
        uri = rig.uris[0]
        base = origin.hits_for(f"{site.name}-")

        def parked_counts() -> list[int]:
            log = rig.node.diagnostics()
            return [log.count(line) for line in parked_lines(uri)]

        # Priming walked the same code path into the same log.
        primed = parked_counts()
        anchor = rig.anchor(uri)
        started = time.monotonic()
        status, headers, body = Http1Client(rig.node.port, uri).read_response()
        elapsed = time.monotonic() - started
        assert status == 200, f"{uri}: status {status}"
        assert headers.get("x-cache") == site.served, (
            f"{uri}: X-Cache={headers.get('x-cache')}, wanted {site.served}")
        assert body == rig.bodies[uri], f"{uri}: body {body!r}"
        rig.assert_no_origin_traffic(origin, base)
        anchor.assert_each_step_once()
        assert elapsed >= parks * rig.delay, (
            f"{uri}: answered in {elapsed:.3f}s, under {parks} parks of "
            f"{rig.delay}s each, so it did not wait on the backend")
        t = anchor.times()
        assert t.parked_at < t.first_reply_at <= t.final_seen_at < t.final_reply_at \
            or t.single_park, f"{uri}: park events out of order: {t}"
        once = [n + 1 for n in primed]
        if debug:
            assert parked_counts() == once, (
                f"{uri}: {parked_lines(uri)} logged {parked_counts()} times, "
                f"wanted {once} including priming")

        # Negative control: L1 can now answer alone, so nothing may reach the
        # backend, which also shows that the checks above can tell the difference.
        anchor.settle()
        sent = rig.proxy.request_bytes
        assert sent > 0, "the proxy's request counter never moved"
        started = time.monotonic()
        status, headers, _ = Http1Client(rig.node.port, uri).read_response()
        elapsed = time.monotonic() - started
        assert status == 200, f"{uri}: L1 status {status}"
        assert headers.get("x-cache") == site.served, (
            f"{uri}: L1 X-Cache={headers.get('x-cache')}, wanted {site.served}")
        assert rig.proxy.request_bytes == sent, (
            f"{uri}: an L1 hit sent {rig.proxy.request_bytes - sent} bytes to the backend")
        assert elapsed < rig.delay, (
            f"{uri}: an L1 hit took {elapsed:.3f}s, as long as a park")
        if debug:
            assert parked_counts() == once, (
                f"{uri}: an L1 hit logged a park: {parked_counts()}, wanted {once}")
        rig.node.stop()
        rig.node.assert_clean_logs()
