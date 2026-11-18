#!/usr/bin/env python3
"""Scripted TCP / unix-socket Redis and memcached peer for runtime tests.

A hostile or merely odd backend is easier to describe than to run: this peer
accepts connections, reads one command at a time (RESP array or inline for
``redis``, a text line plus its data block for ``memcached``), and answers from
a script.  It never interprets the commands; what it sends is exactly what the
script says.  It records every accepted connection and every received command
so a test can assert what the module said on the wire.

A script is a list of :class:`Step` objects, one consumed per received command:

    Step(expect=b"GET ct:", reply=b"$-1\\r\\n")                 # prefix match
    Step(reply=b"$5\\r\\nhel", then=CLOSE)                       # truncate+close
    Step(reply=big, chunk=7, delay=0.01)                        # dribble
    Step(then=RST) / Step(then=HALF_CLOSE) / Step(never=True)   # no/odd reply
    Step(reply=b"+OK\r\n", late=b"$-1\r\n", late_delay=0.2)    # unsolicited

``expect`` is compared with the received command joined by single spaces
(``GET key``), the verb case-folded for redis.  ``None`` accepts anything.  A
mismatch is recorded in ``Peer.mismatches`` and handled per ``Step.on_mismatch``
(default: close the connection).  When a script runs out, ``on_exhausted``
(default ``"close"``) applies.

Which script a connection gets: ``scripts`` is a list of scripts (connection
``i`` uses ``scripts[min(i, len-1)]``) or a callable ``(index) -> script``.
Alternatively ``responder(Command) -> Step | None`` answers every command
(``None`` means the ``on_exhausted`` action); it is how a replay is built.

Where it listens: ``port=0`` (default) takes an ephemeral port; a caller in a
CI port band passes its own.  ``unix_path`` listens on a unix socket instead.
"""

from __future__ import annotations

import contextlib
import os
import socket
import struct
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

NONE = "none"          # keep the connection open for the next command
CLOSE = "close"        # orderly close (FIN) after the reply
RST = "rst"            # abortive close (RST) after the reply
HALF_CLOSE = "half_close"  # shutdown(SHUT_WR) after the reply, keep reading

_THENS = (NONE, CLOSE, RST, HALF_CLOSE)


@dataclass(frozen=True)
class Step:
    expect: bytes | None = None
    reply: bytes = b""
    chunk: int = 0              # 0 = one send; N = N-byte sends
    delay: float = 0.0          # seconds slept BEFORE each chunk
    then: str = NONE
    never: bool = False         # consume the command, send nothing, hold open
    on_mismatch: str = CLOSE    # CLOSE | RST | "ignore" (reply anyway)
    late: bytes = b""           # sent in one write late_delay s after reply
    late_delay: float = 0.0     # (an unsolicited reply on an idle connection)

    def __post_init__(self) -> None:
        if self.then not in _THENS:
            raise ValueError(f"bad then={self.then!r}")
        if self.chunk < 0 or self.delay < 0 or self.late_delay < 0:
            raise ValueError("chunk, delay and late_delay must be >= 0")


@dataclass(frozen=True)
class Command:
    conn: int                   # connection index (accept order, from 0)
    args: tuple[bytes, ...]     # RESP array items / memcached line tokens
    data: bytes | None = None   # memcached storage data block, else None

    @property
    def line(self) -> bytes:
        """Space-joined args, with the verb upper-cased for comparison."""
        if not self.args:
            return b""
        return b" ".join((self.args[0].upper(), *self.args[1:]))


@dataclass
class ConnRecord:
    index: int
    peer: str
    opened: float
    closed: float | None = None
    commands: list[Command] = field(default_factory=list)


Script = Sequence[Step]


class _Eof(Exception):
    pass


class _ProtocolError(ValueError):
    """Malformed client input: handled silently (connection closed).

    Only this, EOF and socket errors are silent; any other exception raised
    while serving (responder, script selector/callable) goes to Peer.errors.
    """


class _Reader:
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buf = b""

    def _fill(self) -> None:
        d = self.sock.recv(65536)
        if not d:
            raise _Eof
        self.buf += d

    def line(self) -> bytes:
        while b"\r\n" not in self.buf:
            self._fill()
        ln, self.buf = self.buf.split(b"\r\n", 1)
        return ln

    def exact(self, n: int) -> bytes:
        if n < 0:
            raise _ProtocolError(f"negative data length {n}")
        while len(self.buf) < n:
            self._fill()
        out, self.buf = self.buf[:n], self.buf[n:]
        return out


def _parse_int(raw: bytes) -> int:
    try:
        return int(raw)
    except ValueError:
        raise _ProtocolError(f"bad integer {raw[:16]!r}") from None


def _read_redis(rd: _Reader) -> tuple[tuple[bytes, ...], None]:
    first = rd.line()
    if first[:1] != b"*":
        return tuple(first.split()), None          # inline command
    args = []
    count = _parse_int(first[1:])
    for _ in range(count):
        hdr = rd.line()
        if hdr[:1] != b"$":
            raise _ProtocolError(f"bad RESP item header {hdr[:16]!r}")
        n = _parse_int(hdr[1:])
        args.append(rd.exact(n))
        if rd.exact(2) != b"\r\n":
            raise _ProtocolError("RESP item not CRLF terminated")
    return tuple(args), None


_MC_STORE = {b"set", b"add", b"replace", b"append", b"prepend", b"cas"}


def _read_memcached(rd: _Reader) -> tuple[tuple[bytes, ...], bytes | None]:
    toks = tuple(rd.line().split())
    if toks and toks[0].lower() in _MC_STORE and len(toks) >= 5:
        n = _parse_int(toks[4])
        data = rd.exact(n)
        if rd.exact(2) != b"\r\n":
            raise _ProtocolError("memcached data block not CRLF terminated")
        return toks, data
    return toks, None


class Peer:
    def __init__(self, scripts: Sequence[Script] | Callable[[int], Script]
                 | None = None, *,
                 responder: Callable[[Command], Step | None] | None = None,
                 proto: str = "redis", host: str = "127.0.0.1", port: int = 0,
                 unix_path: str | None = None,
                 on_exhausted: str = CLOSE) -> None:
        if proto not in ("redis", "memcached"):
            raise ValueError(f"bad proto {proto!r}")
        if on_exhausted not in (CLOSE, RST, NONE):
            raise ValueError(f"bad on_exhausted {on_exhausted!r}")
        if (scripts is None) == (responder is None):
            raise ValueError("give exactly one of scripts / responder")
        self._scripts = scripts
        self._responder = responder
        self.proto = proto
        self.host = host
        self.port = port
        self.unix_path = unix_path
        self.on_exhausted = on_exhausted
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._records: list[ConnRecord] = []
        self._mismatches: list[tuple[int, bytes, Command]] = []
        self._socks: set[socket.socket] = set()
        self._errors: list[Exception] = []
        self._threads: list[threading.Thread] = []
        self._srv: socket.socket | None = None
        self._stop = threading.Event()

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> Peer:
        if self.unix_path:
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(self.unix_path)
        else:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            self.port = srv.getsockname()[1]
        srv.listen(64)
        srv.settimeout(0.1)
        self._srv = srv
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()
        self._threads.append(t)
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._srv is not None:
            self._srv.close()
            self._srv = None
        if self.unix_path:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(self.unix_path)
        # Join the accept loop first so no connection can slip in after the
        # snapshot below.
        for t in list(self._threads[:1]):
            t.join(timeout=5)
        with self._lock:
            socks = list(self._socks)
        for s in socks:
            try:
                s.shutdown(socket.SHUT_RDWR)    # wakes a blocked recv
            except OSError:
                pass
        for t in list(self._threads[1:]):
            t.join(timeout=5)
        self._threads.clear()

    def __enter__(self) -> Peer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    @property
    def address(self) -> str:
        return self.unix_path or f"{self.host}:{self.port}"

    # -- recording ---------------------------------------------------------
    @property
    def connections(self) -> list[ConnRecord]:
        with self._lock:
            return [ConnRecord(r.index, r.peer, r.opened, r.closed,
                               list(r.commands)) for r in self._records]

    @property
    def accepted(self) -> int:
        with self._lock:
            return len(self._records)

    def commands(self) -> list[Command]:
        with self._lock:
            return [c for r in self._records for c in r.commands]

    @property
    def mismatches(self) -> list[tuple[int, bytes, Command]]:
        """(step index, expected prefix, received command) per mismatch."""
        with self._lock:
            return list(self._mismatches)

    @property
    def errors(self) -> list[Exception]:
        """Unexpected exceptions raised while serving (script selection,
        responder); the connection is still closed and recorded."""
        with self._lock:
            return list(self._errors)

    def wait_for_commands(self, n: int, timeout: float = 5.0) -> bool:
        end = time.monotonic() + timeout
        with self._cond:
            while sum(len(r.commands) for r in self._records) < n:
                left = end - time.monotonic()
                if left <= 0:
                    return False
                self._cond.wait(min(left, 0.05))
        return True

    def wait_for_closed(self, n: int = 1, timeout: float = 5.0) -> bool:
        """Wait until n connections have been seen closed by the client or us."""
        end = time.monotonic() + timeout
        with self._cond:
            while sum(r.closed is not None for r in self._records) < n:
                left = end - time.monotonic()
                if left <= 0:
                    return False
                self._cond.wait(min(left, 0.05))
        return True

    # -- serving -----------------------------------------------------------
    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            srv = self._srv
            if srv is None:
                return
            try:
                conn, addr = srv.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with self._cond:
                rec = ConnRecord(len(self._records), str(addr or "unix"),
                                 time.monotonic())
                self._records.append(rec)
                self._socks.add(conn)
                self._cond.notify_all()
            t = threading.Thread(target=self._serve, args=(conn, rec),
                                 daemon=True)
            self._threads.append(t)
            t.start()

    def _script_for(self, index: int) -> Script:
        s = self._scripts
        if callable(s):
            return s(index)
        assert s is not None
        return s[min(index, len(s) - 1)]

    def _serve(self, conn: socket.socket, rec: ConnRecord) -> None:
        rd = _Reader(conn)
        read = _read_redis if self.proto == "redis" else _read_memcached
        script: Script | None = None
        pos = 0
        try:
            if self._responder is None:
                script = self._script_for(rec.index)
            while not self._stop.is_set():
                args, data = read(rd)
                cmd = Command(rec.index, args, data)
                with self._cond:
                    rec.commands.append(cmd)
                    self._cond.notify_all()
                if self._responder is not None:
                    step = self._responder(cmd)
                    pos = len(rec.commands)
                else:
                    assert script is not None
                    step = script[pos] if pos < len(script) else None
                    pos += 1
                if step is None:
                    self._finish(conn, self.on_exhausted)
                    if self.on_exhausted != NONE:
                        return
                    continue
                if step.expect is not None and not _matches(cmd, step.expect):
                    with self._cond:
                        self._mismatches.append((max(pos - 1, 0), step.expect, cmd))
                        self._cond.notify_all()
                    if step.on_mismatch != "ignore":
                        self._finish(conn, step.on_mismatch)
                        return
                if step.never:
                    self._hold(conn)
                    return
                if not self._send(conn, step):
                    return
                if step.then != NONE:
                    self._finish(conn, step.then)
                    if step.then != HALF_CLOSE:
                        return
        except (_Eof, OSError, _ProtocolError):
            pass
        except Exception as exc:  # noqa: BLE001  bad selector, Peer([]), responder
            with self._cond:
                self._errors.append(exc)
        finally:
            with self._cond:
                if rec.closed is None:
                    rec.closed = time.monotonic()
                self._socks.discard(conn)
                self._cond.notify_all()
            try:
                conn.close()
            except OSError:
                pass

    def _send(self, conn: socket.socket, step: Step) -> bool:
        data = step.reply
        size = step.chunk or max(len(data), 1)
        try:
            for i in range(0, len(data), size):
                if step.delay:
                    if self._stop.wait(step.delay):
                        return False
                conn.sendall(data[i:i + size])
            if step.late:
                if self._stop.wait(step.late_delay):
                    return False
                conn.sendall(step.late)
        except OSError:
            return False
        return True

    def _hold(self, conn: socket.socket) -> None:
        """Never reply: hold the connection until the client or stop() ends it."""
        conn.settimeout(0.1)
        while not self._stop.is_set():
            try:
                if not conn.recv(4096):
                    return
            except TimeoutError:
                continue
            except OSError:
                return

    def _finish(self, conn: socket.socket, how: str) -> None:
        if how == RST:
            _rst_close(conn)
        elif how == HALF_CLOSE:
            try:
                conn.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        elif how == CLOSE:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def _matches(cmd: Command, expect: bytes) -> bool:
    head, sep, rest = expect.partition(b" ")
    return cmd.line.startswith(head.upper() + sep + rest)


def _rst_close(sock: socket.socket) -> None:
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass
