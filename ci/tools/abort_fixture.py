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
import signal
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
    wait_port,
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
# Gap between two scheduled proxy deliveries (see the reply ordering below).
REPLY_ORDER_EPS = 1e-6

# Boundary arm: offsets around the moment the reply lands, cycled over the keys.
ABORT_BOUNDARY_OFFSETS = (-0.003, -0.002, -0.001, 0.0, 0.001, 0.002, 0.003)
ABORT_BOUNDARY_WINDOW = 0.005

# "before" must land this long ahead of an anchor's earliest wake, so the abort
# itself (a send after the spin-sleep) still precedes the wake.
ABORT_WAKE_GUARD = 0.01
# Fresh keys a "before" abort may burn on a closed window before the fixture
# gives up loudly.
ABORT_WINDOW_RETRIES = 3

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
    reply_at: float = 0.0     # time.monotonic() the first reply is released
    count: int = 0            # times the request was sent
    reply_head: bytes = b""   # first bytes of that first reply
    # DelayProxy.hold(): the reply is released this many seconds after the
    # backend sent it, instead of the proxy's delay. None: the proxy's delay.
    hold: float | None = None
    # nginx closed (FIN or RST) the connection the request first crossed on.
    closed: threading.Event = dataclasses.field(
        default_factory=threading.Event)
    closed_at: float = 0.0    # time.monotonic() the proxy saw that close


# Bytes of a watched reply the proxy keeps, enough to tell a hit from a miss.
REPLY_HEAD_LEN = 16


# Reply types a RESP value may start with. Anything else (an HTTP origin, the
# memcached text protocol) is not framed here: one read stays one reply.
_RESP_LINE = b"+-:,#_("
_RESP_BULK = b"$!="
_RESP_AGGREGATE = b"*~>%"
_RESP_ATTRIBUTE = b"|"


def resp_value_end(buf: bytes | bytearray, pos: int = 0) -> int | None:
    """End offset of the complete RESP value starting at `pos`, None if more
    bytes are needed. Raises ValueError for a byte that starts no RESP type."""
    need = 1
    while need:
        if pos >= len(buf):
            return None
        kind = buf[pos:pos + 1]
        if kind not in _RESP_LINE + _RESP_BULK + _RESP_AGGREGATE + _RESP_ATTRIBUTE:
            raise ValueError(f"not RESP: {bytes(buf[pos:pos + 8])!r}")
        eol = buf.find(b"\r\n", pos)
        if eol == -1:
            return None
        header = bytes(buf[pos + 1:eol])
        pos = eol + 2
        if kind in _RESP_LINE:
            need -= 1
            continue
        try:
            n = int(header)
        except ValueError as exc:
            raise ValueError(f"bad RESP length: {header!r}") from exc
        if kind in _RESP_BULK:
            if n >= 0:
                if len(buf) < pos + n + 2:
                    return None
                pos += n + 2
            need -= 1
        elif kind in _RESP_ATTRIBUTE:
            need += 2 * max(n, 0)
        else:
            need -= 1
            if n > 0:
                need += n * (2 if kind == b"%" else 1)
    return pos


class ReplyCounter:
    """Splits one connection's upstream bytes into replies.

    feed() returns the first REPLY_HEAD_LEN bytes of every reply that became
    complete with this read: none while a reply is still split across reads,
    several when replies were coalesced. A stream that is not RESP falls back to
    one reply per read, which is all an HTTP origin read needs.
    """

    def __init__(self) -> None:
        self.buf = bytearray()
        self.framed = True

    def feed(self, data: bytes) -> list[bytes]:
        if not self.framed:
            return [data[:REPLY_HEAD_LEN]]
        self.buf += data
        heads: list[bytes] = []
        try:
            while self.buf:
                end = resp_value_end(self.buf)
                if end is None:
                    break
                heads.append(bytes(self.buf[:min(end, REPLY_HEAD_LEN)]))
                del self.buf[:end]
        except ValueError:
            self.framed = False
            self.buf.clear()
            return heads + [data[:REPLY_HEAD_LEN]]
        return heads


class CommandSplitter:
    """Splits one connection's nginx-to-backend bytes into RESP commands.

    feed() returns (commands, rest): the complete commands, and the bytes to
    scan the old way. A stream that is not RESP (memcached text, HTTP) stops
    being framed and comes back whole in `rest`; once framed is False every
    later read is `rest` too.
    """

    def __init__(self) -> None:
        self.buf = bytearray()
        self.framed = True

    def feed(self, data: bytes) -> tuple[list[bytes], bytes]:
        if not self.framed:
            return [], data
        self.buf += data
        cmds: list[bytes] = []
        try:
            while self.buf:
                end = resp_value_end(self.buf)
                if end is None:
                    break
                cmds.append(bytes(self.buf[:end]))
                del self.buf[:end]
        except ValueError:
            self.framed = False
            rest = bytes(self.buf)
            self.buf.clear()
            return cmds, rest
        return cmds, b""


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

    def hold(self, marker: bytes, seconds: float) -> None:
        """Release the reply to a watched marker `seconds` after the backend
        sent it, whatever the proxy's delay: a backend that stalls one command
        and answers the rest. A read carrying that reply is held as a whole, so
        a reply coalesced with it waits as long."""
        self._watch[marker].hold = seconds

    def wait_closed(self, marker: bytes, timeout: float) -> float | None:
        """Block until nginx closed the connection the marked request first
        crossed on; return when, or None if it was still open at `timeout`
        (seconds, not scaled: the caller times it against nginx's timers)."""
        s = self._watch[marker]
        return s.closed_at if s.closed.wait(timeout) else None

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

    def _note_request(self, data: bytes, old: int, now: float,
                      pending: collections.deque[_Sighting | None],
                      here: dict[int, _Sighting] | None = None) -> None:
        """Note the markers in `data`, whose first `old` bytes are the tail of
        the previous read, carried over so a marker split across two reads is
        still seen. A match ending inside that tail was counted last time: a
        marker shorter than the tail (SELECT) would otherwise count twice and
        take the reply meant for the next command. Replies come back in request
        order, so matches queue in byte order, not marker order."""
        self._busy_until = max(self._busy_until, now)
        hits: list[tuple[int, _Sighting]] = []
        for marker, s in self._watch.items():
            at = data.find(marker)
            while at != -1:
                if at + len(marker) > old:
                    hits.append((at, s))
                at = data.find(marker, at + 1)
        for _, s in sorted(hits, key=lambda hit: hit[0]):
            if not s.count:
                s.seen_at = now
                s.seen.set()
                if here is not None:
                    here[id(s)] = s
            s.count += 1
            pending.append(s)

    def _note_command(self, cmd: bytes, now: float,
                      pending: collections.deque[_Sighting | None],
                      here: dict[int, _Sighting] | None = None) -> None:
        """Queue exactly one entry for one framed command: its sighting when it
        carries a marker, else a placeholder (None), so an unwatched command
        pipelined ahead of a watched one takes its own reply, not the
        watched one's."""
        self._busy_until = max(self._busy_until, now)
        first: tuple[int, _Sighting] | None = None
        for marker, s in self._watch.items():
            at = cmd.find(marker)
            if at != -1 and (first is None or at < first[0]):
                first = (at, s)
        if first is None:
            pending.append(None)
            return
        s = first[1]
        if not s.count:
            s.seen_at = now
            s.seen.set()
            if here is not None:
                here[id(s)] = s
        s.count += 1
        pending.append(s)

    def _feed_request(self, tail: bytes, data: bytes, now: float,
                      pending: collections.deque[_Sighting | None],
                      here: dict[int, _Sighting] | None = None) -> bytes:
        """Scan one nginx-to-backend read; return the tail to carry into the
        next one. The tail is cut from the previous tail plus this read, so a
        marker spread over three or more reads is still found."""
        self._note_request(tail + data, len(tail), now, pending, here)
        return (tail + data)[-self._tail_len:] if self._tail_len else b""

    async def _handle(self, cr: asyncio.StreamReader,
                      cw: asyncio.StreamWriter) -> None:
        loop = asyncio.get_running_loop()
        try:
            ur, uw = await asyncio.open_connection("127.0.0.1",
                                                   self.upstream_port)
        except OSError:
            cw.close()
            return
        pending: collections.deque[_Sighting | None] = collections.deque()

        splitter = CommandSplitter()

        def deliver(data: bytes) -> None:
            if not cw.is_closing():
                cw.write(data)

        # Ids of the sightings whose first crossing was on this connection:
        # nginx closing it is what wait_closed() reports for them.
        # Holds the sightings themselves: a watch() that replaces the set
        # must not free one, or its id could be reused by a new sighting.
        here: dict[int, _Sighting] = {}

        async def client_to_server() -> None:
            tail = b""
            try:
                while data := await cr.read(65536):
                    self.request_bytes += len(data)
                    now = time.monotonic()
                    cmds, rest = splitter.feed(data)
                    for cmd in cmds:
                        self._note_command(cmd, now, pending, here)
                    if rest:
                        tail = self._feed_request(tail, rest, now, pending,
                                                  here)
                    uw.write(data)
                    await uw.drain()
            except ConnectionResetError:
                pass
            # nginx closed its end (a backend close cancels this task first,
            # so it never reaches here).
            now = time.monotonic()
            for s in here.values():
                if not s.closed.is_set():
                    s.closed_at = now
                    s.closed.set()

        async def server_to_client() -> None:
            counter = ReplyCounter()
            last_due = 0.0
            while data := await ur.read(65536):
                # One sighting per complete reply, not per read: two replies
                # coalesced in one read each take their own, and a reply split
                # across reads takes its sighting only when it completes.
                taken: list[tuple[_Sighting | None, bytes]] = []
                for head in counter.feed(data):
                    if not pending:
                        break
                    taken.append((pending.popleft(), head))
                # loop.time() is time.monotonic() on Unix, so reply_at compares
                # directly with the time the test aborts at. A held reply
                # holds the whole read it arrived in.
                delay = max([self.delay, *(s.hold for s, _ in taken
                                           if s is not None
                                           and s.hold is not None)])
                # Never ahead of an earlier, held read: replies keep their order.
                # Strictly after it, too: asyncio's timer heap does not keep
                # insertion order among equal deadlines.
                due = max(loop.time() + delay, last_due + REPLY_ORDER_EPS)
                last_due = due
                self._busy_until = max(self._busy_until, due)
                for s, head in taken:
                    # A marker sent more than once (a walk's SELECT, one per
                    # op connection) keeps its first reply: that is the one
                    # ending the first park.
                    if s is not None and not s.replied.is_set():
                        s.reply_at = due
                        s.reply_head = head
                        s.replied.set()
                loop.call_at(due, deliver, data)
            loop.call_at(max(loop.time() + self.delay,
                                 last_due + REPLY_ORDER_EPS), cw.close)

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

    def wait_final_seen(self) -> float:
        """Block until the command of the last park reached the backend."""
        return self.proxy.wait_seen(self.commands[-1])

    def final_reply_head(self) -> bytes:
        """The first bytes of the reply ending the last park."""
        return self.proxy.sighting(self.commands[-1]).reply_head

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

    def earliest_wake(self) -> float:
        """The first moment the park can end by itself: one poll after the
        earliest the waiter could have parked."""
        return self.park_lo + COLD_WAIT_POLL

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

    def __init__(self, port: int, path: str, method: str = "GET",
                 headers: dict[str, str] | None = None) -> None:
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        length = "Content-Length: 0\r\n" if method != "GET" else ""
        extra = "".join(f"{k}: {v}\r\n" for k, v in (headers or {}).items())
        self.sock.sendall(f"{method} {path} HTTP/1.1\r\nHost: abort-fixture\r\n"
                          f"{length}{extra}Connection: close\r\n\r\n".encode())

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
        # nginx closing without a response is the failure these tests hunt:
        # report it with the bytes received, not as a parser IndexError.
        status = lines[0].split()
        if len(status) < 2 or not status[0].startswith("HTTP/") \
                or not status[1].isdigit():
            raise AssertionError(
                f"no HTTP/1 response before close: {data[:200]!r}")
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        return int(status[1]), headers, body


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
                 server_extra: str = "", main_extra: str = "") -> None:
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
        self.main_extra = main_extra

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
{self.main_extra}
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

    def start(self) -> None:
        """Start, and return only once every listener answers.

        Nginx.start() waits for the HTTP/1 port alone. nginx binds its
        listeners one at a time, so that port can answer while the HTTP/2 one
        is still unbound, and an arm whose first connection is HTTP/2 (a site
        with nothing to prime) is then refused before nginx has logged a line.
        """
        super().start()
        if self.h2_style:
            try:
                wait_port(self.h2_port)
            except Exception:
                self.stop()
                raise

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

    def held_client_sockets(self) -> list[str]:
        """Client connections the serving process still holds, from /proc.

        A request that nothing will ever finalize keeps its connection's fd
        open and logs nothing, and stop() is a SIGTERM, which does not report
        open sockets the way a graceful quit would. So the leak is looked for
        here: a socket fd on one of this node's ports that is not listening,
        or one the kernel no longer lists at all, which a peer's RST does to
        the socket while its fd stays open. Backend connections are ignored:
        they are on the proxy's port, and an RST is only ever sent by a client
        here. Returns one description per held socket.
        """
        ports = {self.port, self.h2_port}
        listed: dict[str, tuple[int, str]] = {}
        for table in ("tcp", "tcp6", "udp", "udp6", "unix", "netlink"):
            try:
                rows = pathlib.Path(f"/proc/net/{table}").read_text().splitlines()[1:]
            except OSError:
                continue
            for row in rows:
                cols = row.split()
                if table.startswith(("tcp", "udp")):
                    port = int(cols[1].rsplit(":", 1)[1], 16)
                    listed[cols[9]] = (port if table.startswith("tcp") else 0, cols[3])
                elif table == "unix":
                    listed[cols[6]] = (0, "")
                else:
                    listed[cols[-1]] = (0, "")
        pids = self.worker_pids() or ({self.process.pid} if self.process else set())
        held = []
        for pid in pids:
            fds = pathlib.Path(f"/proc/{pid}/fd")
            try:
                entries = list(fds.iterdir())
            except OSError:
                continue
            for fd in entries:
                try:
                    target = os.readlink(fd)
                except OSError:
                    continue
                if not target.startswith("socket:["):
                    continue
                inode = target[len("socket:["):-1]
                if inode not in listed:
                    held.append(f"pid {pid} fd {fd.name}: reset, still open")
                    continue
                port, state = listed[inode]
                if port in ports and state != "0A":   # 0A = TCP_LISTEN
                    held.append(f"pid {pid} fd {fd.name}: port {port} state {state}")
        return held

    def wait_released(self) -> list[str]:
        """Wait for the node to let go of every client connection; return the
        ones it still holds. A finished request closes its connection at once,
        so the wait only matters on a loaded host; a leak never clears."""
        held: list[str] = []

        def released() -> bool:
            nonlocal held
            held = self.held_client_sockets()
            return not held

        wait_for(released, timeout=1.0 * sanitizer_time_scale(), interval=0.02)
        return held

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
                 location the anchor reads. {proxy_port} is replaced as in
                 `directives`; nothing else is, so its braces stay literal.
    main_extra   config added at the main level, e.g. a thread_pool
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
    main_extra: str = ""
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


class ParkWindowClosed(Exception):
    """The park was observed too late to abort inside its "before" window.
    The key is spent (a cold-wait leader filled it), so the caller retries on a
    fresh key and records no landing for this one."""


def _before_deadline(anchor: ParkAnchor, parked_at: float, scale: float,
                     now: float | None = None) -> float | None:
    """When to abort inside the first park, None if that window has closed.

    The park is observed at parked_at, but an anchor whose park ends by itself
    (earliest_wake) is only open until then, which a slow observation can pass.
    The guard scales with `scale`: a sanitizer build sends later after the
    spin-sleep, so it needs a wider margin ahead of the wake.
    """
    deadline = parked_at + 0.03 * scale
    wake = getattr(anchor, "earliest_wake", None)
    if wake is not None:
        deadline = min(deadline, wake() - ABORT_WAKE_GUARD * scale)
        if deadline <= (time.monotonic() if now is None else now):
            return None
    return deadline


def _abort_deadline(anchor: ParkAnchor, timing: str, index: int, delay: float,
                    scale: float) -> float | None:
    """When to abort: time.monotonic(), from this request's own park events.

    A primed L2 hit parks twice, on the vary-marker GET and then on the object
    GET, so the final reply lands about two delays after the request parked.
    before    inside the first park
    after     past the first reply: inside the last park. At a site that parks
              once it is past the only reply, so the request has already resumed
              and answered, and the abort finds nothing parked. That is a control
              which stays clean even on broken resume code.
    boundary  a few ms either side of the reply that ends the last park

    None means the "before" window closed before the park was observed.
    """
    parked_at = anchor.wait_parked()
    if timing == "before":
        return _before_deadline(anchor, parked_at, scale)
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

    deadline = _abort_deadline(anchor, timing, index, delay,
                               sanitizer_time_scale())
    closed = deadline is None
    if deadline is not None:
        _sleep_until(deadline)
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
    if closed:
        # Aborted late, so nothing is judged: the caller retries a fresh key.
        # The late abort still ran, so a crash it caused stays in the log.
        raise ParkWindowClosed()
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
        self.retired: list[str] = []   # keys burned by a closed window
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
            site.server_extra.replace("{proxy_port}", str(self.proxy.port)),
            site.main_extra)

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
            for uri in self.uris + self.retired:
                self.site.forget(uri)

    def anchor(self, uri: str) -> ParkAnchor:
        return self.site.anchor(self, uri)

    def retry_uri(self, uri: str, attempt: int) -> str:
        """A fresh key for another try after a closed "before" window. Only a
        site that parks on a miss has one: a primed key is not in the backend."""
        if self.site.prime:
            raise AssertionError(
                f"{uri}: the 'before' window closed on a primed key, which "
                "cannot be retried; the fixture cannot judge this landing")
        if attempt > ABORT_WINDOW_RETRIES:
            raise AssertionError(
                f"fixture error: {uri}: the 'before' window closed "
                f"{attempt} times in a row; the host is too slow to land an "
                "abort ahead of the first wake")
        fresh = f"{uri}-r{attempt}"
        self.retired.append(fresh)
        return fresh

    def assert_no_origin_traffic(self, origin: Origin, base: int) -> None:
        """A key that missed L2 goes to the origin instead of parking on a hit,
        so an origin hit means the arm did not test what it says. A site whose
        park needs origin traffic (a cold-wait leader) names how much."""
        now = origin.hits_for(f"{self.site.name}-")
        want = base + self.site.origin_hits * (len(self.uris)
                                               + len(self.retired))
        assert now == want, (
            f"{now - base} requests reached the origin, wanted "
            f"{want - base}: a key did not park the way this site needs")


def _arm_failure(arm: str, rig: AbortRig, i: int, keys: int,
                 exc: BaseException) -> AssertionError:
    """The arm's failure for key `i`: fatal lines first, then the log tail."""
    fatal = rig.node.fatal_lines()
    cause = f"{len(fatal)} fatal lines, first: {fatal[0]}\n" if fatal else ""
    log = rig.node.diagnostics().splitlines()[-8:]
    return AssertionError(
        f"{arm}: {cause}key {i}/{keys}: {exc}\nlog tail:\n" + "\n".join(log))


def run_abort_arm(ng: Nginx, origin: Origin, site: AbortSite, kind: str,
                  timing: str) -> ArmResult:
    """Prime, restart cold, abort one parked request per key, stop, read logs.

    Stays at the default notice log level: debug logging may read the freed
    request's strings and change how the bug shows up.

    Returns the fatal log lines, and any client connection a key left held,
    for assert_abort_clean() to judge, so a caller can report an arm without
    failing it. Fatal lines outrank every other check
    here: they are what the arm exists to catch, and the stimulus checks that
    follow would only blame the crash's side effects. On a clean run those
    checks are what keep a pass from being vacuous.
    """
    arm = f"{site.name} {kind} {timing}"
    keys = ABORT_BOUNDARY_KEYS if timing == "boundary" else ABORT_KEYS
    landings: list[Landing] = []
    held: list[str] = []
    with AbortRig(ng, site, f"{kind}-{timing}", keys) as rig:
        if kind in HTTP2_KINDS:
            rig.node.require_http2()
        base = origin.hits_for(f"{site.name}-")
        for i, key in enumerate(rig.uris):
            uri, attempt = key, 0
            while True:
                anchor = rig.anchor(uri)
                try:
                    aborted_at = _abort_one(
                        rig.node, anchor, kind, timing, i, rig.delay,
                        site.request_target(uri), site.method)
                except ParkWindowClosed:
                    # Nothing was judged; the late abort's crash, if any, is
                    # still in the log read below.
                    held.extend(f"key {i}: client connection never closed: {h}"
                                for h in rig.node.wait_released())
                    attempt += 1
                    try:
                        uri = rig.retry_uri(key, attempt)
                    except AssertionError as exc:
                        raise _arm_failure(arm, rig, i, keys, exc) from exc
                    continue
                except (AssertionError, OSError) as exc:
                    raise _arm_failure(arm, rig, i, keys, exc) from exc
                break
            landings.append(_landing(timing, aborted_at, anchor.times()))
            # A request nothing finalizes logs nothing and does not crash: it
            # keeps its connection. That is how the walks fail on the old
            # resume order, so a held socket is as fatal as an alert.
            held.extend(f"key {i}: client connection never closed: {h}"
                        for h in rig.node.wait_released())
        rig.node.stop()
        result = ArmResult(arm, landings, rig.node.fatal_lines() + held)
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
            held = rig.node.wait_released()
            assert not held, f"{uri}: connection still held after the answer: {held}"
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


# --------------------------------------------------------------------------- #
# Client events while parked (CT-PARKED-REENTRY)
# --------------------------------------------------------------------------- #

# A parked request keeps r->write_event_handler = ngx_http_core_run_phases. With
# epoll (edge triggered, one entry for both directions) any event on the client
# fd reports EPOLLOUT too, and once the connection's write event is active the
# worker calls its handler: the phases run again on a request that is parked.
# The write event becomes active the first time a send blocks, and it stays
# active for the life of the keep-alive connection. So each arm first sends a
# response too big to fit in the client's window, proves the send blocked, reads
# it all, then sends the request that parks on the same connection:
#
#     poke     the client sends a few bytes while the request is parked
#     rst      the client resets the connection while it is parked
#     clean    nothing more: the event that delivered the request is already
#              one, as epoll reports EPOLLOUT with it
#     control  as poke, but the warm-up response is small and the window large,
#              so no send ever blocked and no write event is active. It must
#              pass on any build; if it fails, the fixture is broken.
REENTRY_ARMS = ("poke", "rst", "clean", "control")
REENTRY_RCVBUF = 4096
REENTRY_SMALL = 1024
# A parked request whose answer never comes is the failure being looked for, so
# a client that stays reads by Content-Length with a deadline, not to EOF.
REENTRY_READ_TIMEOUT = 5.0


def _tcp_wmem_max() -> int:
    """Largest send buffer the kernel autotunes a socket to."""
    try:
        text = pathlib.Path("/proc/sys/net/ipv4/tcp_wmem").read_text(encoding="ascii")
        return int(text.split()[2])
    except (OSError, IndexError, ValueError):
        return 4194304


def reentry_site(site: AbortSite, root: pathlib.Path) -> AbortSite:
    """`site` with the two warm-up files and their locations added. The big one
    is larger than the biggest send buffer, so the client's small window has to
    block nginx's send; it is sparse, so it costs no disk."""
    files = root / "abort-reentry-files"
    files.mkdir(parents=True, exist_ok=True)
    big, small = files / "big", files / "small"
    size = _tcp_wmem_max() + (1 << 20)
    if not big.exists() or big.stat().st_size != size:
        with big.open("wb") as fh:
            fh.truncate(size)
    if not small.exists():
        small.write_bytes(b"s" * REENTRY_SMALL)
    extra = f"""{site.server_extra}
        location = /_ab_big {{ alias {big}; }}
        location = /_ab_small {{ alias {small}; }}"""
    return dataclasses.replace(site, server_extra=extra)


class KeepaliveClient:
    """One HTTP/1.1 connection: a keep-alive warm-up request, then the request
    that parks, with Connection: close."""

    def __init__(self, node: AbortNode, small_window: bool) -> None:
        self.node = node
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if small_window:
            # Before connect(): the window scale is fixed in the handshake.
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                                 REENTRY_RCVBUF)
        self.sock.settimeout(10.0 * sanitizer_time_scale())
        self.sock.connect(("127.0.0.1", node.port))
        self.pending = bytearray()

    def _send(self, method: str, path: str, close: bool) -> None:
        length = "Content-Length: 0\r\n" if method not in ("GET", "PURGE") else ""
        conn = "Connection: close\r\n" if close else ""
        self.sock.sendall(f"{method} {path} HTTP/1.1\r\nHost: abort-fixture\r\n"
                          f"{length}{conn}\r\n".encode())

    def server_tx_queue(self) -> int | None:
        """Bytes nginx's side of this connection has queued and not had
        acknowledged, from /proc/net/tcp; None if the row is not there."""
        local = f"{self.node.port:04X}"
        remote = f"{self.sock.getsockname()[1]:04X}"
        try:
            rows = pathlib.Path("/proc/net/tcp").read_text(encoding="ascii").splitlines()[1:]
        except OSError:
            return None
        for row in rows:
            cols = row.split()
            if (cols[1].rsplit(":", 1)[1] == local
                    and cols[2].rsplit(":", 1)[1] == remote):
                return int(cols[4].split(":")[0], 16)
        return None

    def prove_blocked(self) -> int:
        """Wait until nginx's send to this client is stuck: a non-empty send
        queue that does not move while the client reads nothing. Raises a
        fixture error otherwise, because then no write event is active and the
        arm would pass on any build."""
        deadline = time.monotonic() + 5.0 * sanitizer_time_scale()
        last = None
        while time.monotonic() < deadline:
            queued = self.server_tx_queue()
            if queued and queued == last:
                return queued
            last = queued
            time.sleep(0.05)
        raise AssertionError(
            "fixture error: nginx's send to the client never blocked "
            f"(server tx_queue {last}), so no write event is active and this "
            "arm would prove nothing")

    def read_response(self, timeout: float) -> tuple[int, dict[str, str], bytes]:
        """One response, read by Content-Length (or chunked, or to EOF)."""
        deadline = time.monotonic() + timeout * sanitizer_time_scale()

        def more() -> bool:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("no complete response before the deadline")
            self.sock.settimeout(left)
            chunk = self.sock.recv(262144)
            self.pending += chunk
            return bool(chunk)

        while b"\r\n\r\n" not in self.pending:
            if not more():
                raise ConnectionError(
                    f"closed before the response headers: {bytes(self.pending)!r}")
        end = self.pending.index(b"\r\n\r\n")
        lines = bytes(self.pending[:end]).decode("latin-1").split("\r\n")
        del self.pending[:end + 4]
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        status = int(lines[0].split()[1])
        if "content-length" in headers:
            want = int(headers["content-length"])
            while len(self.pending) < want:
                if not more():
                    raise ConnectionError(
                        f"closed after {len(self.pending)}/{want} body bytes")
            body = bytes(self.pending[:want])
            del self.pending[:want]
        elif headers.get("transfer-encoding") == "chunked":
            while not self.pending.endswith(b"0\r\n\r\n"):
                if not more():
                    raise ConnectionError("closed inside a chunked body")
            raw, out = bytes(self.pending), b""
            self.pending.clear()
            while True:
                size_line, _, raw = raw.partition(b"\r\n")
                n = int(size_line.split(b";")[0], 16)
                if n == 0:
                    break
                out, raw = out + raw[:n], raw[n + 2:]
            body = out
        else:
            while more():
                pass
            body = bytes(self.pending)
            self.pending.clear()
        return status, headers, body

    def warm(self, big: bool) -> None:
        """The keep-alive warm-up. With `big`, proves the send blocked first."""
        self._send("GET", "/_ab_big" if big else "/_ab_small", close=False)
        if big:
            self.prove_blocked()
        status, _, body = self.read_response(30.0)
        want = _tcp_wmem_max() + (1 << 20) if big else REENTRY_SMALL
        assert status == 200 and len(body) == want, (
            f"fixture error: warm-up answered {status} with {len(body)} bytes, "
            f"wanted 200 with {want}")

    def send(self, method: str, path: str) -> None:
        self._send(method, path, close=True)

    def poke(self) -> None:
        self.sock.sendall(b"\r\n")

    def abort_rst(self) -> None:
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                             struct.pack("ii", 1, 0))
        self.sock.close()

    def close(self) -> None:
        if self.sock.fileno() != -1:
            _drain_nonblocking(self.sock)
            self.sock.close()


REENTRY_HELD = "client connection never closed"


def _reentry_one(rig: AbortRig, uri: str, arm: str,
                 landings: list[Landing]) -> tuple[list[str], bool]:
    """One parked request on a warmed connection; return what went wrong and
    whether the "before" window had closed (no landing recorded: retry a fresh
    key).

    Fixture errors (the send never blocked, the request never parked) raise:
    such a key tested nothing. Everything the bug can cause is returned, so
    the remaining keys still run and the summary names every failure.
    """
    site, scale = rig.site, sanitizer_time_scale()
    problems: list[str] = []
    closed = False
    client = KeepaliveClient(rig.node, small_window=arm != "control")
    try:
        client.warm(big=arm != "control")
        anchor = rig.anchor(uri)
        client.send(site.method, site.request_target(uri))
        try:
            parked_at = anchor.wait_parked()
        except AssertionError as exc:
            raise AssertionError(f"fixture error: {exc}") from exc
        aborted_at = 0.0
        if arm != "clean":
            deadline = _before_deadline(anchor, parked_at, scale)
            closed = deadline is None
            if deadline is not None:
                _sleep_until(deadline)
            aborted_at = time.monotonic()
            if arm == "rst":
                client.abort_rst()
            else:
                client.poke()
        answer = None
        if arm != "rst":
            try:
                answer = client.read_response(REENTRY_READ_TIMEOUT)
            except (OSError, ValueError) as exc:
                problems.append(f"no complete answer: {exc!r}")
        anchor.settle()
        if aborted_at and not closed:
            landings.append(_landing("before", aborted_at, anchor.times()))
        if answer is not None:
            status, headers, body = answer
            try:
                if site.verify is not None:
                    site.verify(rig, uri, status, body)
                else:
                    assert status == 200, f"status {status}"
                    assert headers.get("x-cache") == site.served, (
                        f"X-Cache={headers.get('x-cache')}, wanted {site.served}")
                    assert body == rig.bodies[uri], "body is not the primed one"
            except AssertionError as exc:
                problems.append(f"wrong answer: {exc}")
        if arm != "rst":
            try:
                anchor.assert_each_step_once()
            except AssertionError as exc:
                problems.append(f"extra backend op: {exc}")
    finally:
        client.close()
    rig.node.wait_worker()
    problems.extend(f"{REENTRY_HELD}: {h}" for h in rig.node.wait_released())
    return problems, closed


def run_reentry_test(ng: Nginx, origin: Origin, site: AbortSite,
                     arm: str) -> None:
    """One arm of the parked re-entry matrix as a test. Fails on an alert, a
    count-zero line, a sanitizer report, a held client socket, a missing or
    wrong answer, or a backend op sent more than once."""
    if arm not in REENTRY_ARMS:
        raise ValueError(f"unknown re-entry arm: {arm}")
    site = reentry_site(site, ng.root.parent)
    name = f"{site.name} reentry {arm}"
    problems: list[str] = []
    landings: list[Landing] = []
    with AbortRig(ng, site, f"reentry-{arm}", ABORT_KEYS) as rig:
        base = origin.hits_for(f"{site.name}-")
        for i, key in enumerate(rig.uris):
            uri, attempt = key, 0
            while True:
                found, closed = _reentry_one(rig, uri, arm, landings)
                if closed:
                    # The abort came too late to be judged: the answer and
                    # body checks of this attempt are not evidence, only a
                    # held client socket is (a crash is in the fatal lines).
                    found = [p for p in found if p.startswith(REENTRY_HELD)]
                problems.extend(f"key {i}: {p}" for p in found)
                if not closed:
                    break
                attempt += 1
                try:
                    uri = rig.retry_uri(key, attempt)
                except AssertionError as exc:
                    raise _arm_failure(name, rig, i, len(rig.uris), exc) \
                        from exc
        rig.node.stop()
        fatal = rig.node.fatal_lines()
        result = ArmResult(name, landings, fatal + problems)
        print(f"reentry-arm {result.describe()} problems={len(problems)}",
              flush=True)
        assert not result.fatal, (
            f"{result.describe()}\nfirst: {result.fatal[0]}")
        rig.assert_no_origin_traffic(origin, base)
        if landings:
            _check_stimulus(result, "before")
        if arm != "rst":
            rig.node.assert_clean_logs()


# --------------------------------------------------------------------------- #
# Graceful shutdown while parked (CT-PARKED-SHUTDOWN)
# --------------------------------------------------------------------------- #
#
# A reload sends the old worker a graceful quit. With worker_shutdown_timeout
# set, nginx's ngx_shutdown_timer_handler then sets c->close and c->error on
# every connection still open and calls its read handler. For an HTTP/1 request
# that is ngx_http_request_handler, which takes c->close to
# ngx_http_terminate_request: the posted terminate handler forces count = 1 and
# frees the request, park reference or not. The backend op is a connection of
# its own with a timer that is not cancelable, so the worker stays up for its
# reply and then resumes the request it was parked for. No client abort and no
# client event is involved, so neither the resume order nor the parked handler
# covers it. HTTP/2 does not take that branch: the shutdown finalizes the h2
# connection, which only marks each stream's fake connection with an error and
# waits for the stream to finish.

SHUTDOWN_TIMEOUT_MS = 100
# Long enough that the shutdown timer always fires inside the park, even on a
# loaded host where the reload takes a while to reach the old worker. Short
# enough that, scaled for a sanitizer (x2), it stays under the sites' 2s L2
# timeout: at 1.0s the ASan reply landed on the timeout and the graceful
# control got no cache answer.
SHUTDOWN_REPLY_DELAY = 0.75
# http1, http2  a reload with worker_shutdown_timeout while parked
# graceful      the same reload with no shutdown timeout, HTTP/1: the old worker
#               waits for the request, which gets its answer. It must pass on
#               any build; if it fails, the fixture is broken.
# http1_hit     the http1 reload, sent once the request is parked on its last
#               GET, the object's, so the late reply is the stored value and
#               the resume copies a hit into the freed request. The other arms
#               reload inside the first park, the vary-marker GET, which is a
#               miss. Takes the site's `hit` predicate over the first bytes of
#               that reply and fails unless every key's reply passes it.
# early_teardown  the http1 reload on a site whose L2 timeout (OWN_TIMEOUT)
#               falls after the shutdown timer and before the backend reply.
#               The request cleanup (redis_*_detach) must tear the op down when
#               nginx frees the request, so the old worker exits before the
#               op's own timer could fire and no "timed out" line is logged.
#               The other arms wait out the reply, so an op that merely
#               survived detached (ended later by its timer or the reply)
#               passes them. A GET or lock op cannot end by its own timeout
#               after the request is freed; only a suspended purge walk can.
SHUTDOWN_ARMS = ("http1", "http2", "graceful", "http1_hit",
                 "early_teardown")
# early_teardown: the site's L2 timeout (AbortSite directive) and the proxy's
# reply delay, seconds before sanitizer scaling. The timeout must sit past the
# shutdown timer (reload + SHUTDOWN_TIMEOUT_MS, with a loaded-host margin) and
# well before the reply.
OWN_TIMEOUT = 1.0
OWN_TIMEOUT_REPLY_DELAY = 2.5
TIMED_OUT = "timed out"


def redis_hit_reply(head: bytes) -> bool:
    """A RESP GET reply carrying a value: a bulk string that is not nil."""
    return head.startswith(b"$") and not head.startswith(b"$-1")


def memcached_hit_reply(head: bytes) -> bool:
    """A memcached text-protocol get reply carrying a value."""
    return head.startswith(b"VALUE ")


def shutdown_site(site: AbortSite, timeout: bool,
                  delay: float = SHUTDOWN_REPLY_DELAY) -> AbortSite:
    """`site` with a reply delay longer than the shutdown timeout, and that
    timeout set unless `timeout` is false."""
    extra = f"\nworker_shutdown_timeout {SHUTDOWN_TIMEOUT_MS}ms;" if timeout else ""
    return dataclasses.replace(site, proxy_delay=delay,
                               main_extra=site.main_extra + extra)


def run_shutdown_test(ng: Nginx, origin: Origin, site: AbortSite,
                      arm: str,
                      hit: Callable[[bytes], bool] | None = None) -> None:
    """Reload while one request per key is parked; the old worker's shutdown
    timer closes the client connection before the backend answers. The client
    stays connected and does nothing. Fails on an alert, a count-zero line, a
    sanitizer report, a held client socket, or an old worker that never exits.
    The answer the client gets is nginx's business there (the timeout closes the
    connection), so only the graceful control checks it.

    Multi-worker mode only: a single-process nginx has no master to reload (the
    ASan single-process job). The Runtime and ASan multi-worker jobs run it."""
    if arm not in SHUTDOWN_ARMS:
        raise ValueError(f"unknown shutdown arm: {arm}")
    if (arm == "http1_hit") != (hit is not None):
        raise ValueError("a hit predicate goes with the http1_hit arm only")
    if ng.single_process:
        print(f"shutdown-arm {site.name} shutdown {arm}: SKIPPED "
              "(single-process nginx has no master to reload)", flush=True)
        return
    protocol = "http2" if arm == "http2" else "http1"
    own = arm == "early_teardown"
    site = shutdown_site(site, timeout=arm != "graceful",
                         delay=OWN_TIMEOUT_REPLY_DELAY if own
                         else SHUTDOWN_REPLY_DELAY)
    name = f"{site.name} shutdown {arm}"
    scale = sanitizer_time_scale()
    problems: list[str] = []
    landings: list[Landing] = []
    # The op timeout lines are logged at info.
    with AbortRig(ng, site, f"shutdown-{arm}", ABORT_KEYS,
                  "info" if own else None) as rig:
        if protocol == "http2":
            rig.node.require_http2()
        assert rig.node.process is not None and not rig.node.single_process, (
            "the shutdown arm needs a master process to reload")
        base = origin.hits_for(f"{site.name}-")
        for i, uri in enumerate(rig.uris):
            rig.node.wait_worker()
            old = rig.node.worker_pids()
            anchor = rig.anchor(uri)
            path = site.request_target(uri)
            h1: Http1Client | None = None
            h2: H2Client | None = None
            if protocol == "http2":
                h2 = H2Client(rig.node.h2_port)
                h2.send_request(path, site.method)
            else:
                h1 = Http1Client(rig.node.port, path, site.method)
            try:
                parked_at = anchor.wait_parked()
                if hit is not None:
                    assert isinstance(anchor, ProxyAnchor) and len(
                        anchor.commands) > 1, "the hit arm needs a two-park site"
                    parked_at = anchor.wait_final_seen()
            except AssertionError as exc:
                raise AssertionError(f"{name}: fixture error: {exc}") from exc
            _sleep_until(parked_at + 0.03 * scale)
            reloaded_at = time.monotonic()
            os.kill(rig.node.process.pid, signal.SIGHUP)
            exited_at: float | None = None
            if wait_for(lambda old=old: not (rig.node.worker_pids() & old),
                        timeout=(max(SHUTDOWN_REPLY_DELAY,
                                     OWN_TIMEOUT_REPLY_DELAY) + 5.0) * scale,
                        interval=0.02):
                exited_at = time.monotonic()
            else:
                problems.append(f"key {i}: old worker never exited")
            anchor.settle()
            if arm == "graceful" and h1 is not None:
                try:
                    status, headers, body = h1.read_response()
                    assert status == 200, f"status {status}"
                    assert headers.get("x-cache") == site.served, (
                        f"X-Cache={headers.get('x-cache')}, wanted {site.served}")
                    assert body == rig.bodies[uri], "body is not the primed one"
                except (AssertionError, OSError, ValueError, IndexError) as exc:
                    problems.append(f"key {i}: no clean answer: {exc!r}")
            # In phase: the shutdown timer was due while the request was still
            # parked, i.e. before the reply ending its last park. A cold-wait
            # waiter re-parks on every poll until the leader's fill, so for it
            # that is the fill, not its first wake.
            t = anchor.times()
            end = t.final_reply_at or t.first_reply_at
            fired = reloaded_at + SHUTDOWN_TIMEOUT_MS / 1000
            if hit is not None:
                # In phase only if the backend answered the object GET with the
                # value and the shutdown timer was due before that reply
                # landed: a missing reply would let a miss or a lost key pass
                # as this arm.
                assert isinstance(anchor, ProxyAnchor)
                head = anchor.final_reply_head()
                if not t.final_reply_at:
                    problems.append(f"key {i}: the object GET got no reply")
                elif not hit(head):
                    problems.append(f"key {i}: the object GET reply is not a "
                                    f"hit: {head!r}")
                in_phase = (bool(t.final_reply_at) and hit(head)
                            and t.final_seen_at <= reloaded_at
                            and fired < t.final_reply_at)
            elif own:
                # In phase only if the shutdown timer was due before the op's
                # own timer, and the worker was gone before that timer: the
                # request cleanup, not the timer or the late reply, ended the
                # op.
                timer_at = parked_at + OWN_TIMEOUT * scale
                if exited_at is not None and exited_at >= timer_at:
                    problems.append(
                        f"key {i}: the worker outlived the op's own timeout "
                        f"by {exited_at - timer_at:.3f}s, so the freed "
                        "request did not tear the op down")
                in_phase = (exited_at is not None
                            and fired < timer_at and exited_at < timer_at)
            else:
                in_phase = not end or fired < end
            landings.append(Landing(in_phase,
                                    reloaded_at - (end or reloaded_at)))
            for client in (h1, h2):
                if client is not None:
                    try:
                        client.sock.close()
                    except OSError:
                        pass
            rig.node.wait_worker()
            problems.extend(f"key {i}: client connection never closed: {h}"
                            for h in rig.node.wait_released())
        rig.node.stop()
        if own:
            late = [ln for ln in rig.node.diagnostics().splitlines()
                    if TIMED_OUT in ln]
            print(f"shutdown-arm {name}: {len(late)} op timeout lines",
                  flush=True)
            problems.extend(f"the op ended by its own timer: {ln[:160]}"
                            for ln in late)
        fatal = rig.node.fatal_lines()
        result = ArmResult(name, landings, fatal + problems)
        print(f"shutdown-arm {result.describe()} problems={len(problems)}",
              flush=True)
        assert not result.fatal, (
            f"{result.describe()}\nfirst: {result.fatal[0]}")
        rig.assert_no_origin_traffic(origin, base)
        _check_stimulus(result, "before")


# --------------------------------------------------------------------------- #
# A suspended purge walk that outlives its request
# --------------------------------------------------------------------------- #

# CT-SHUTDOWN-OWN-TIMEOUT-ARM. A GET or lock op is torn down by its request's
# cleanup the moment nginx frees the request (the early_teardown arm above), so
# the only op that can still end on its own after that is a suspended walk: a
# page's UNLINK is in flight on its own connection, walk_detach records the
# doom and returns, and sscan_resume tears the walk down when that UNLINK ends.
#
# The request is freed the way the shutdown arms free it: a reload while the
# walk waits on its UNLINK, whose worker_shutdown_timeout terminates the parked
# request. A client abort cannot do it here: a parked HTTP/1 request does not
# read its connection, so nginx only sees the abort when the walk answers.
#
# own_timeout  the backend never answers the UNLINK inside its timeout, so the
#              UNLINK op's own timer ends it, and the walk is torn down then.
# reply        the converse: the UNLINK reply lands before that timer, and the
#              walk is torn down on the reply.
#
# Both arms then serve a fresh purge and a GET from the new worker and quit
# nginx gracefully. A walk that is never torn down keeps its connection open
# until the old worker exits, which reports it as an open socket (alert).
WALK_TIMEOUT_ARMS = ("own_timeout", "reply")
# The site's L2 timeout, seconds before sanitizer scaling (the caller builds
# the site with walk_timeout_ms()). Past the reload plus the shutdown timer.
WALK_OP_TIMEOUT = 1.5
# How long the backend sits on the UNLINK reply in the reply arm, as a share
# of that timeout.
WALK_REPLY_SHARE = 0.5
# The own_timeout arm holds the reply this long past the timeout.
WALK_HOLD_PAST = 1.0
# Slack for a timer that fires a little early (nginx rounds its clock to ms).
WALK_TIMER_SLACK = 0.02


def own_timeout_ms() -> str:
    """The L2 timeout directive value for the early_teardown arm."""
    return f"{round(OWN_TIMEOUT * sanitizer_time_scale() * 1000)}ms"


def walk_timeout_ms() -> str:
    """The L2 timeout directive value for a walk_timeout site."""
    return f"{round(WALK_OP_TIMEOUT * sanitizer_time_scale() * 1000)}ms"


def _wait_peer_closed(sock: socket.socket, timeout: float) -> float | None:
    """Block until nginx closed this client connection (FIN or RST), reading
    and dropping anything it sent first; return when, or None at `timeout`."""
    deadline = time.monotonic() + timeout
    sock.setblocking(False)
    while (remaining := deadline - time.monotonic()) > 0:
        readable, _, _ = select.select([sock], [], [], remaining)
        if not readable:
            continue
        try:
            if not sock.recv(65536):
                return time.monotonic()
        except BlockingIOError:
            continue
        except OSError:
            return time.monotonic()
    return None


def run_walk_timeout_test(ng: Nginx, site: AbortSite) -> None:
    """Both WALK_TIMEOUT_ARMS on a walk site built with walk_timeout_ms(). The
    site's anchor names the walk's commands, its page read second to last and
    the page's UNLINK last (the SSCAN tag walk). Fails on an alert, a sanitizer
    report, a request that was not freed while the walk was suspended, a walk
    connection nginx never closes or closes on the wrong event, a missing or
    stray op timeout line, an old worker that never exits, a later purge or GET
    that is not served, or a graceful quit that does not exit cleanly.

    Multi-worker mode only, like run_shutdown_test: a single-process nginx has
    no master to reload."""
    if ng.single_process:
        print(f"walk-timeout {site.name}: SKIPPED (single-process nginx has "
              "no master to reload)", flush=True)
        return
    for arm in WALK_TIMEOUT_ARMS:
        _walk_timeout_arm(ng, site, arm)


def _walk_timeout_arm(ng: Nginx, site: AbortSite, arm: str) -> None:
    scale = sanitizer_time_scale()
    timeout = WALK_OP_TIMEOUT * scale
    own = arm == "own_timeout"
    hold = timeout + WALK_HOLD_PAST * scale if own else timeout * WALK_REPLY_SHARE
    name = f"{site.name} walk {arm}"
    problems: list[str] = []
    site = shutdown_site(site, timeout=True, delay=0.0)
    # The op timeout lines are logged at info.
    with AbortRig(ng, site, f"walk-{arm}", 2, "info") as rig:
        assert rig.node.process is not None and not rig.node.single_process
        uri, fresh = rig.uris
        anchor = rig.anchor(uri)
        page, unlink = anchor.commands[-2], anchor.commands[-1]
        rig.proxy.hold(unlink, hold)
        old = rig.node.worker_pids()
        h1 = Http1Client(rig.node.port, site.request_target(uri), site.method)
        # The UNLINK crossing the proxy is the suspension: the walk suspends
        # before it launches the page's UNLINK.
        sent_at = rig.proxy.wait_seen(unlink)
        os.kill(rig.node.process.pid, signal.SIGHUP)
        freed_at = _wait_peer_closed(h1.sock, hold + 5.0 * scale)
        h1.sock.close()
        replied_at = rig.proxy.wait_replied(unlink)
        walk_open = not rig.proxy.sighting(page).closed.is_set()
        if freed_at is None:
            problems.append("the shutdown timer never closed the client: the "
                            "parked request was not terminated")
        elif freed_at >= min(sent_at + timeout, replied_at):
            problems.append(
                f"fixture: the request was freed {freed_at - sent_at:.3f}s "
                "after the UNLINK left, not while the walk was suspended, so "
                "this arm proves nothing")
        elif not walk_open:
            problems.append("the walk connection closed with its request, "
                            "while its UNLINK was in flight: the walk did not "
                            "outlive the request")
        closed_at = rig.proxy.wait_closed(page, hold + timeout + 5.0 * scale)
        timer_at = sent_at + timeout - WALK_TIMER_SLACK
        if closed_at is None:
            problems.append("nginx never closed the walk's connection: the "
                            "suspended walk was not torn down")
        elif own and not timer_at <= closed_at < replied_at:
            problems.append(
                f"the walk closed {closed_at - sent_at:.3f}s after its UNLINK, "
                f"wanted on the UNLINK's own {timeout:.3f}s timer, before the "
                f"reply at {replied_at - sent_at:.3f}s")
        elif not own and not replied_at <= closed_at < timer_at:
            problems.append(
                f"the walk closed {closed_at - sent_at:.3f}s after its UNLINK, "
                f"wanted on the reply at {replied_at - sent_at:.3f}s, before "
                f"the {timeout:.3f}s timer")
        # Both closes can land in one proxy loop pass in either order.
        unlink_closed = rig.proxy.wait_closed(unlink, ABORT_SETTLE_MARGIN * scale)
        if own and (unlink_closed is None or unlink_closed >= replied_at):
            problems.append("the UNLINK connection outlived the UNLINK's own "
                            "timeout")
        exited_at: float | None = None
        if wait_for(lambda: not (rig.node.worker_pids() & old),
                    timeout=hold + 5.0 * scale, interval=0.02):
            exited_at = time.monotonic()
        else:
            problems.append("the old worker never exited")
        # Let the held reply land on the closed connection before more traffic.
        rig.proxy.wait_quiet(ABORT_SETTLE_MARGIN * scale, timeout=hold + 5.0)
        rig.node.wait_worker()
        late = [ln for ln in rig.node.diagnostics().splitlines()
                if TIMED_OUT in ln]

        def rel(at: float | None) -> str:
            return "never" if at is None else f"{at - sent_at:+.3f}s"

        print(f"walk-timeout {name}: request freed {rel(freed_at)}, walk "
              f"closed {rel(closed_at)}, old worker exited {rel(exited_at)}, "
              f"reply {rel(replied_at)}, timer {timeout:.3f}s, {len(late)} op "
              "timeout lines", flush=True)
        if own and not late:
            problems.append("no op timeout line: the UNLINK did not end on "
                            "its own timer")
        if not own:
            problems.extend(f"an op ended by its own timer: {ln[:160]}"
                            for ln in late)
        # A fresh purge and a GET are served once the walk is gone. The fresh
        # walk's UNLINK carries the same bytes, so stop holding them first.
        rig.proxy.watch([])
        h1 = Http1Client(rig.node.port, site.request_target(fresh), site.method)
        status, _, body = h1.read_response()
        if site.verify is not None:
            try:
                site.verify(rig, fresh, status, body)
            except AssertionError as exc:
                problems.append(f"the next purge: {exc}")
        status, _, _ = fetch(rig.node.port, f"/ab/{site.name}-walk-{arm}-get")
        if status != 200:
            problems.append(f"the next GET answered {status}")
        # Graceful quit: a connection still held is an "open socket" alert.
        os.kill(rig.node.process.pid, signal.SIGQUIT)
        try:
            rc = rig.node.process.wait(timeout=10.0 * scale)
        except subprocess.TimeoutExpired:
            rc = None
            problems.append("nginx did not quit gracefully within "
                            f"{10.0 * scale:.1f}s")
        if rc is not None:
            rig.node.process = None
            if rc != 0:
                problems.append(f"graceful quit exited with {rc}")
        fatal = rig.node.fatal_lines() + problems
        print(f"walk-timeout {name}: fatal={len(fatal)} "
              f"problems={len(problems)}", flush=True)
        assert not fatal, f"{name}: {len(fatal)} failures, first: {fatal[0]}"
