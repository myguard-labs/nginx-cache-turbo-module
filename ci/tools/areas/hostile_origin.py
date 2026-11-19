"""cache-turbo runtime tests -- hostile origin response replay matrix (HARD-O1).

test_hostile_origin_framing_matrix (areas/http.py) proves that malformed
upstream FRAMING is not stored on the MISS side.  This matrix adds the replay
dimension: a raw origin answers each case with one hostile but well-framed
(or deliberately mis-framed) response, and the same request is fetched three
times on a cached location:

  MISS  the first request (origin answers, the module may store it in L1
        and write it through to the real Redis fixture);
  L1    the same request again (an L1 HIT when the response was stored);
  L2    the same request after an L1-ONLY purge (the admin location has no
        cache_turbo_redis, so its purge cannot reach Redis): an
        L2-promoted HIT when the write-through landed.

A leg is a REPLAY when the origin was not contacted for the case path and the
answer came from the cache (X-CT-Status HIT/STALE or an l2_hits increment).

Case families: 101 Upgrade and 1xx interim responses on a cached location,
204/304 with a body, a HEAD response with a body, short and long
Content-Length, conflicting duplicate Cache-Control / Vary / Surrogate-Key /
Expires / Age, ``Vary: *``, 1000 Set-Cookie lines, a Content-Encoding that
does not match the body, X-Accel-Redirect / -Buffering / -Limit-Rate /
-Expires / -Charset on a 200, and Location on a 200.

Case.store is the module's storage POLICY for the response:

  forbid  never stored: a non-200 status (status_ttl stores 200 only under
          ``cache_turbo_valid 60s``), a HEAD answer, an incomplete body,
          ``Cache-Control: no-store``, ``Vary: *`` / ``Vary: Cookie``
          (auto_vary refuses them), Set-Cookie (the store floor) or a
          Content-Encoding (refused unless cache_turbo_key_encoded_origin).
  may     stored or not; only the replay properties apply.

Properties, judged by the pure ``judge()`` on an ``Obs`` (L1 and L2 legs):

  P1-no-store      a ``forbid`` case is never replayed.
  P2-no-redirect   a replayed leg causes no internal redirect: the redirect
                   target (an internal location proxied to the origin) is not
                   requested and the body is not the target's.
  P3-no-new-header a replayed leg sends no header line (name and value; the
                   1xx interim lines included) the MISS did not send, apart
                   from REPLAY_VOLATILE (Date, Age, X-Cache, X-CT-Status and
                   the connection framing headers).
  P4-same-body     a replayed leg's body is the MISS body byte for byte.
  P5-no-rate       a replayed leg is not rate limited (finishes in under
                   RATE_SLOW_S; the X-Accel-Limit-Rate case needs ~5 s when
                   the rate applies).  X-Accel-Buffering has no client-visible
                   effect beyond its header, which P3 covers.
  P6-sanitizer     no sanitizer report, no crit/alert/emerg log line, nginx
                   and its worker alive.

Harness properties (never known-red):

  H-miss     the MISS reached the origin.
  H-replay   CTRL-HO-CLEAN was an L1 HIT and then an L2-promoted HIT (proves
             the L1 and the L2 legs really replay).
  H-purge    the L1-only purge answered 200 and, when L1 held the entry, the
             L2 leg was not served from L1.

Negative control: CTRL-HO-ACCEL-UNCACHED sends the X-Accel-Redirect response
from an UNCACHED location; nginx redirects on every request there, and its
L1/L2 legs are judged as replays for P2 only, so P2-no-redirect MUST fail.
CTRL-HO-CLEAN must pass every property.

Known defects live in ORIGIN_KNOWN_RED with the properties they fail; such a
case does not fail the run, a known-red case that passes (xpass) does.  Red
cases and traces: memory/labs/nginx-cache-turbo-module/
hard-l2-evidence-20261118.md, section HARD-O1 (HARD-O2 input).

The node and origin reuse the HARD-L2 port offsets (the matrices run
sequentially and each stops its rig before the next starts); the Redis is
the suite's real fixture under its own key prefix.

Environment: HOSTILE_ORIGIN_ONLY=ID[,ID...] runs a subset;
HOSTILE_ORIGIN_REPORT=path writes the per-case results as JSON.
"""

from __future__ import annotations

import collections
import contextlib
import json
import os
import socket
import socketserver
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

from test_runtime_base import *
from test_runtime_base import _errlog_window_start

from areas import hostile_l2 as hl

__all__ = ["test_hostile_origin_replay_matrix"]

HOST = "localhost"
ZONE = "ho"
ADMIN = "/_ho"            # L1-only admin: no cache_turbo_redis
PREFIX = "ho:"
LOC_CACHED = "c"
LOC_UNCACHED = "n"
ACCEL = "/accel"          # internal redirect target prefix
ACCEL_MARK = b"ACCEL-TARGET "
LEG_S = 12.0              # per-leg read bound (sanitizer-scaled)
SETTLE_S = 0.05
RATE = 512                # X-Accel-Limit-Rate bytes/s
RATE_BODY = 3072          # ~5 s at RATE when the rate applies
RATE_SLOW_S = 2.5         # a replay this slow was rate limited
LEGS = ("MISS", "L1", "L2")

PROPS = ("P1-no-store", "P2-no-redirect", "P3-no-new-header", "P4-same-body",
         "P5-no-rate", "P6-sanitizer")
HARNESS_PROPS = ("H-miss", "H-replay", "H-purge")
STORES = ("forbid", "may")

# Headers a replay may add or change: framing, the clock, the cache's own
# status lines and Accept-Ranges (nginx's range filter advertises byte ranges
# on every in-memory replay, CTRL-HO-CLEAN included; it carries no origin
# data).  Everything else must be a line the MISS sent.
REPLAY_VOLATILE = frozenset({
    "date", "age", "x-cache", "x-ct-status", "connection", "keep-alive",
    "content-length", "transfer-encoding", "accept-ranges"})


# --------------------------------------------------------------------------- #
# Case table.
# --------------------------------------------------------------------------- #

CT = "Content-Type: text/plain"
CC = "Cache-Control: public, max-age=60"


def raw(status: str, headers: list[str], body: bytes,
        cl: int | None = -1) -> bytes:
    """One HTTP/1.1 response; cl=-1: Content-Length = len(body), None: no
    Content-Length."""
    lines = list(headers)
    if cl is not None:
        lines.append(f"Content-Length: {len(body) if cl == -1 else cl}")
    head = f"HTTP/1.1 {status}\r\n" + "".join(f"{h}\r\n" for h in lines)
    return (head + "\r\n").encode("latin-1") + body


def accel_target(path: str) -> str:
    return ACCEL + path


def origin_body(path: str, gen: str) -> bytes:
    return f"ho {path} {gen}\n".encode()


Responder = Callable[[str, str], bytes]


@dataclass(frozen=True)
class Case:
    id: str
    store: str
    respond: Responder = field(repr=False)   # (path, gen) -> response bytes
    method: str = "GET"
    loc: str = LOC_CACHED
    control: bool = False
    must_replay: bool = False
    note: str = ""


def _ok(*extra: str, ct: str = CT, cc: str | None = CC) -> Responder:
    hdrs = [ct] + ([cc] if cc else []) + list(extra)
    return lambda p, g: raw("200 OK", hdrs, origin_body(p, g))


def _accel(p: str, g: str) -> bytes:
    return raw("200 OK", [CT, CC, f"X-Accel-Redirect: {accel_target(p)}"],
               origin_body(p, g))


def _rate(p: str, g: str) -> bytes:
    b = origin_body(p, g)
    return raw("200 OK", [CT, CC, f"X-Accel-Limit-Rate: {RATE}"],
               b + b"r" * (RATE_BODY - len(b)))


def build_cases() -> list[Case]:
    cookies = [f"Set-Cookie: ho{i:04d}=v; Path=/" for i in range(1000)]
    return [
        Case("CTRL-HO-CLEAN", "may", _ok(), control=True, must_replay=True,
             note="clean cacheable 200: stored, L1 HIT, L2-promoted HIT"),
        Case("CTRL-HO-ACCEL-UNCACHED", "may", _accel, loc=LOC_UNCACHED,
             control=True, note="X-Accel-Redirect from an uncached location"),
        Case("HO-101-UPGRADE", "forbid",
             lambda p, g: raw("101 Switching Protocols",
                              ["Upgrade: websocket", "Connection: Upgrade",
                               CC], b"", cl=None),
             note="101 to a plain GET"),
        Case("HO-1XX-100", "may",
             lambda p, g: b"HTTP/1.1 100 Continue\r\n\r\n"
             + raw("200 OK", [CT, CC], origin_body(p, g)),
             note="100 Continue before the 200 (nginx relays the 100 as the "
             "final status)"),
        Case("HO-1XX-103", "may",
             lambda p, g: (b"HTTP/1.1 103 Early Hints\r\n"
                           b"Link: </ho.css>; rel=preload\r\n\r\n")
             + raw("200 OK", [CT, CC], origin_body(p, g)),
             note="103 Early Hints with Link before the 200"),
        Case("HO-204-BODY", "forbid",
             lambda p, g: raw("204 No Content", [CC], origin_body(p, g))),
        Case("HO-304-BODY", "forbid",
             lambda p, g: raw("304 Not Modified", [CC, 'ETag: "ho"'],
                              origin_body(p, g))),
        Case("HO-HEAD-BODY", "forbid", _ok(), method="HEAD",
             note="body bytes on a HEAD answer"),
        Case("HO-CL-SHORT", "may",
             lambda p, g: raw("200 OK", [CT, CC],
                              origin_body(p, g) + b"SURPLUS-TAIL",
                              cl=len(origin_body(p, g))),
             note="Content-Length shorter than the bytes sent"),
        Case("HO-CL-LONG", "forbid",
             lambda p, g: raw("200 OK", [CT, CC], origin_body(p, g),
                              cl=len(origin_body(p, g)) + 64),
             note="Content-Length longer than the bytes sent, then EOF"),
        Case("HO-DUP-CC", "forbid", _ok("Cache-Control: no-store"),
             note="max-age=60 and no-store"),
        Case("HO-DUP-VARY", "forbid",
             _ok("Vary: Accept-Encoding", "Vary: Cookie")),
        Case("HO-DUP-SK", "may",
             _ok("Surrogate-Key: ho-a ho-b", "Surrogate-Key: ho-c")),
        Case("HO-DUP-EXPIRES", "may",
             _ok("Expires: Thu, 01 Jan 2099 00:00:00 GMT",
                 "Expires: Thu, 01 Jan 1970 00:00:00 GMT", cc=None)),
        Case("HO-DUP-AGE", "may", _ok("Age: 5", "Age: 999999")),
        Case("HO-VARY-STAR", "forbid", _ok("Vary: *")),
        Case("HO-SETCOOKIE-1000", "forbid", _ok(*cookies),
             note="1000 Set-Cookie lines"),
        Case("HO-CE-MISMATCH", "forbid", _ok("Content-Encoding: gzip"),
             note="gzip label on a plain body"),
        Case("HO-XA-REDIRECT", "may", _accel),
        Case("HO-XA-BUFFERING", "may", _ok("X-Accel-Buffering: no")),
        Case("HO-XA-LIMIT-RATE", "may", _rate),
        Case("HO-XA-EXPIRES", "may", _ok("X-Accel-Expires: 0")),
        Case("HO-XA-CHARSET", "may",
             _ok("X-Accel-Charset: koi8-r",
                 ct="Content-Type: text/html")),
        Case("HO-LOCATION-200", "may",
             _ok("Location: http://evil.example/ho")),
    ]


# Known defects: case id -> the properties it fails (HARD-O2 input, see the
# evidence file).  HARD-O2 removes a row when it fixes the defect.
ORIGIN_KNOWN_RED: dict[str, frozenset[str]] = {}

# Control id -> the exact failure set that proves the oracle bites.
CONTROL_EXPECTED: dict[str, frozenset[str]] = {
    "CTRL-HO-CLEAN": frozenset(),
    "CTRL-HO-ACCEL-UNCACHED": frozenset({"P2-no-redirect"}),
}
CONTROL_IDS = frozenset(CONTROL_EXPECTED)
ACCEPTED = frozenset({"green", "known-red", "control-ok"})


def classify(case_id: str, failed: set[str] | frozenset[str],
             known: dict[str, frozenset[str]] | None = None) -> str:
    """green | known-red | control-ok are acceptable; red | xpass |
    known-red-drift | control-broken | harness-fail fail the matrix."""
    known = ORIGIN_KNOWN_RED if known is None else known
    if any(p in failed for p in HARNESS_PROPS):
        return "harness-fail"
    if case_id in CONTROL_EXPECTED:
        ok = set(failed) == CONTROL_EXPECTED[case_id]
        return "control-ok" if ok else "control-broken"
    if case_id in known:
        if not failed:
            return "xpass"
        return "known-red" if set(failed) <= known[case_id] else "known-red-drift"
    return "red" if failed else "green"


# --------------------------------------------------------------------------- #
# Raw HTTP/1 response parsing (pure).
# --------------------------------------------------------------------------- #

Pairs = tuple[tuple[str, str], ...]


@dataclass
class Resp:
    status: int = 0
    pairs: Pairs = ()              # final header lines, names lowercased
    interim: Pairs = ()            # ("1xx:<status>", "") and ("1xx:<name>", v)
    body: bytes = b""
    tail: bytes = b""              # bytes after the framed body


def _head(block: bytes) -> tuple[int, Pairs]:
    lines = block.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise ValueError(f"not an HTTP response: {lines[0][:60]!r}")
    pairs = []
    for ln in lines[1:]:
        k, _, v = ln.partition(":")
        pairs.append((k.strip().lower(), v.strip()))
    return int(parts[1]), tuple(pairs)


def _dechunk(buf: bytes) -> tuple[bytes, bytes]:
    out, pos = b"", 0
    while True:
        eol = buf.find(b"\r\n", pos)
        if eol < 0:
            return out, b""
        size = int(buf[pos:eol].split(b";")[0].strip() or b"0", 16)
        pos = eol + 2
        if size == 0:
            end = buf.find(b"\r\n\r\n", pos - 2)
            return out, (buf[end + 4:] if end >= 0 else b"")
        out += buf[pos:pos + size]
        pos += size + 2


def parse_response(buf: bytes, method: str = "GET") -> Resp:
    """Parse a whole connection's bytes (Connection: close, read to EOF)."""
    interim: list[tuple[str, str]] = []
    while True:
        end = buf.find(b"\r\n\r\n")
        if end < 0:
            raise ValueError(f"incomplete head: {buf[:60]!r}")
        status, pairs = _head(buf[:end])
        rest = buf[end + 4:]
        if 100 <= status < 200 and status != 101:
            interim.append((f"1xx:{status}", ""))
            interim.extend((f"1xx:{k}", v) for k, v in pairs)
            buf = rest
            continue
        break
    hdr = dict(pairs)
    if method == "HEAD" or status in (101, 204, 304):
        body, tail = b"", rest
    elif "chunked" in hdr.get("transfer-encoding", "").lower():
        body, tail = _dechunk(rest)
    elif "content-length" in hdr:
        n = int(hdr["content-length"])
        body, tail = rest[:n], rest[n:]
    else:
        body, tail = rest, b""
    return Resp(status, pairs, tuple(interim), body, tail)


# --------------------------------------------------------------------------- #
# Oracle (pure).
# --------------------------------------------------------------------------- #

@dataclass
class Leg:
    """One fetch of the case path.  status 0 = no response."""
    name: str = ""
    status: int = 0
    pairs: Pairs = ()
    interim: Pairs = ()
    body: bytes = b""
    cache: str = ""                # X-CT-Status
    origin_hits: int = 0           # origin requests for the case path
    accel_hits: int = 0            # redirect-target requests
    l2_hits: int = 0               # zone l2_hits delta
    seconds: float = 0.0
    error: str = ""

    @property
    def replay(self) -> bool:
        """Served from the cache without contacting the origin."""
        return (self.status != 0 and self.origin_hits == 0
                and (self.cache in ("HIT", "STALE") or self.l2_hits > 0))


def redirected(leg: Leg) -> bool:
    """The leg performed an internal redirect to the accel target."""
    return leg.accel_hits > 0 or leg.body.startswith(ACCEL_MARK)


def new_lines(miss: Leg, leg: Leg) -> list[tuple[str, str]]:
    """Header lines (final and interim) `leg` sent that the MISS did not."""
    def lines(x: Leg) -> collections.Counter[tuple[str, str]]:
        return collections.Counter(
            (k, v) for k, v in x.pairs + x.interim
            if k not in REPLAY_VOLATILE)
    return sorted((lines(leg) - lines(miss)).elements())


@dataclass
class Obs:
    legs: list[Leg] = field(default_factory=list)   # MISS, L1, L2
    purge_status: int = 0
    sanitizer: str = ""            # non-empty: what went wrong


def _add(fail: dict[str, str], prop: str, msg: str) -> None:
    fail[prop] = f"{fail[prop]}; {msg}" if prop in fail else msg


def judge(case: Case, o: Obs) -> dict[str, str]:
    fail: dict[str, str] = {}
    if len(o.legs) != len(LEGS):
        _add(fail, "H-miss", f"{len(o.legs)} legs observed")
        return fail
    miss, l1, l2 = o.legs
    if miss.origin_hits < 1:
        _add(fail, "H-miss", "MISS never reached the origin "
                             f"(status={miss.status} {miss.error})")
    if case.must_replay and not (
            l1.replay and l1.cache == "HIT" and l1.l2_hits == 0
            and l2.replay and l2.l2_hits >= 1):
        _add(fail, "H-replay",
             f"L1 cache={l1.cache or '-'} origin={l1.origin_hits} "
             f"l2_hits={l1.l2_hits}; L2 cache={l2.cache or '-'} "
             f"origin={l2.origin_hits} l2_hits={l2.l2_hits}")
    if o.purge_status != 200:
        _add(fail, "H-purge", f"L1-only purge answered {o.purge_status}")
    elif l1.replay and l2.replay and l2.l2_hits == 0:
        _add(fail, "H-purge", "L2 leg was served from L1 after the purge")
    for leg in (l1, l2):
        if case.store == "forbid" and leg.replay:
            _add(fail, "P1-no-store",
                 f"{leg.name} replayed (cache={leg.cache or '-'} "
                 f"l2_hits={leg.l2_hits})")
        # A leg the origin never saw (no X-CT-Status on the redirect target,
        # so Leg.replay is false) that still redirected was served from the
        # cache: judge it like a replay.
        unseen = leg.status != 0 and leg.origin_hits == 0
        if (leg.replay or unseen or case.control) and redirected(leg):
            _add(fail, "P2-no-redirect",
                 f"{leg.name} redirected (target hits={leg.accel_hits} "
                 f"body={leg.body[:40]!r})")
        if not leg.replay:
            continue
        extra = new_lines(miss, leg)
        if extra:
            _add(fail, "P3-no-new-header",
                 f"{leg.name} sent {extra[:4]} not on the MISS")
        if leg.body != miss.body:
            _add(fail, "P4-same-body",
                 f"{leg.name} body {leg.body[:40]!r} != MISS "
                 f"{miss.body[:40]!r}")
        if leg.seconds >= RATE_SLOW_S:
            _add(fail, "P5-no-rate",
                 f"{leg.name} took {leg.seconds:.2f}s")
    if o.sanitizer:
        _add(fail, "P6-sanitizer", o.sanitizer)
    return fail


@dataclass
class Result:
    id: str
    failed: dict[str, str] = field(default_factory=dict)
    verdict: str = ""
    trace: dict[str, object] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Harness: raw origin and a one-worker nginx with the real Redis behind it.
# --------------------------------------------------------------------------- #

class _RawOrigin:
    """Answers /<loc>/<CASE-ID>/<tag> with the case's raw bytes and
    /accel/... with the redirect target; counts requests per path."""

    def __init__(self, port: int, cases: dict[str, Case]) -> None:
        hits: collections.Counter[str] = collections.Counter()
        lock = threading.Lock()

        def respond(path: str, n: int) -> bytes:
            if path.startswith(ACCEL + "/"):
                return raw("200 OK", [CT, "X-Accel-Target: 1"],
                           ACCEL_MARK + path.encode() + b"\n")
            parts = path.split("/")
            case = cases.get(parts[2]) if len(parts) > 3 else None
            if case is None:
                return raw("404 Not Found", [CT], b"no such case\n")
            return case.respond(path, f"{n}-{uuid.uuid4().hex[:8]}")

        class H(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                sock = self.request
                sock.settimeout(5)
                data = b""
                try:
                    while b"\r\n\r\n" not in data and len(data) < 65536:
                        chunk = sock.recv(4096)
                        if not chunk:
                            return
                        data += chunk
                    line = data.split(b"\r\n", 1)[0].decode("latin-1")
                    path = line.split(" ")[1].split("?", 1)[0]
                    with lock:
                        hits[path] += 1
                        n = hits[path]
                    sock.sendall(respond(path, n))
                except (OSError, IndexError):
                    return

        class S(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self.hits = hits
        self._lock = lock
        self.srv = S(("127.0.0.1", port), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def count(self, path: str) -> int:
        with self._lock:
            return self.hits[path]

    def stop(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()


def _config(root, port: int, module, origin: int, redis: int) -> str:
    load = f"load_module {module};\n" if module else ""
    up = f"proxy_pass http://127.0.0.1:{origin};"
    return f"""{load}worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/logs/error.log info;
events {{ worker_connections 256; }}
http {{
    access_log off;
    proxy_buffer_size 64k;
    proxy_buffers 8 64k;
    proxy_busy_buffers_size 128k;
    cache_turbo_zone name={ZONE} 4m;
    server {{
        listen 127.0.0.1:{port};
        server_name {HOST};
        location = {ADMIN} {{ cache_turbo_admin {ZONE}; }}
        location /{LOC_CACHED}/ {{
            cache_turbo {ZONE}; cache_turbo_key $uri; cache_turbo_valid 60s;
            cache_turbo_lock off;
            cache_turbo_redis 127.0.0.1:{redis} prefix={PREFIX} connect_backoff=0;
            add_header X-CT-Status $cache_turbo_status always;
            {up}
        }}
        location /{LOC_UNCACHED}/ {{ {up} }}
        location {ACCEL}/ {{ internal; {up} }}
    }}
}}
"""


class _Rig:
    def __init__(self, ng: Nginx, redis: RedisServer) -> None:
        base = ng.port
        self.redis = redis
        self.origin = _RawOrigin(base + PORT_OFFSETS["hostile_l2_origin"],
                                 {c.id: c for c in build_cases()})
        oport = self.origin.srv.server_address[1]
        self.tmp = ng.root.parent / "hostile-origin"
        self.node = Nginx(ng.binary, ng.module, self.tmp,
                          base + PORT_OFFSETS["hostile_l2_node"], oport,
                          ng.runner_raw, ng.single_process)
        text = _config(self.tmp, self.node.port, ng.module, oport, redis.port)

        def write_config(sr_off: bool = False) -> None:
            del sr_off
            (self.tmp / "conf").mkdir(parents=True, exist_ok=True)
            (self.tmp / "logs").mkdir(parents=True, exist_ok=True)
            (self.tmp / "conf" / "nginx.conf").write_text(text,
                                                          encoding="ascii")

        self.node.write_config = write_config  # type: ignore[method-assign]

    def start(self) -> None:
        try:
            self.node.write_config()
            self.node.config_test()
            self.node.start()
        except BaseException:
            with contextlib.suppress(Exception):
                self.stop()
            raise

    def stop(self) -> None:
        try:
            self.node.stop()
        finally:
            self.origin.stop()

    def workers(self) -> frozenset[int]:
        p = self.node.process
        return hl.descendants(p.pid) if p is not None else frozenset()

    def alive(self) -> bool:
        p = self.node.process
        return p is not None and p.poll() is None

    def l2_hits(self) -> int:
        _, b, _ = fetch(self.node.port, ADMIN)
        return int(json.loads(b).get("l2_hits", 0))

    def dbsize(self) -> int:
        return int(self.redis.cli("DBSIZE") or 0)

    def purge_l1(self, path: str) -> int:
        s, _, _ = fetch(self.node.port, f"{ADMIN}?key={path}", method="POST")
        return s

    def fetch_leg(self, name: str, method: str, path: str,
                  bound: float) -> Leg:
        leg = Leg(name)
        o0 = self.origin.count(path)
        a0 = self.origin.count(accel_target(path))
        h0 = self.l2_hits()
        t0 = time.monotonic()
        buf = b""
        try:
            with socket.create_connection(("127.0.0.1", self.node.port),
                                          timeout=bound) as s:
                s.sendall(f"{method} {path} HTTP/1.1\r\nHost: {HOST}\r\n"
                          "Connection: close\r\n\r\n".encode())
                deadline = t0 + bound
                while time.monotonic() < deadline:
                    s.settimeout(max(deadline - time.monotonic(), 0.01))
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
        except OSError as exc:
            leg.error = f"{type(exc).__name__}: {exc}"
        leg.seconds = time.monotonic() - t0
        if buf:
            try:
                r = parse_response(buf, method)
                leg.status, leg.pairs, leg.interim = r.status, r.pairs, r.interim
                leg.body = r.body
                # nginx relays an upstream 100 as the final status line (the
                # origin's real 200 then reads as body): take X-CT-Status
                # from that interim head when the final one has none.
                leg.cache = dict(r.pairs).get(
                    "x-ct-status", dict(r.interim).get("1xx:x-ct-status", ""))
            except ValueError as exc:
                leg.error = leg.error or str(exc)
        time.sleep(SETTLE_S)
        leg.origin_hits = self.origin.count(path) - o0
        leg.accel_hits = self.origin.count(accel_target(path)) - a0
        leg.l2_hits = self.l2_hits() - h0
        return leg


def _run_case(rig: _Rig, case: Case, tag: str) -> Result:
    res = Result(case.id)
    scale = sanitizer_time_scale()
    bound = LEG_S * scale
    path = f"/{case.loc}/{case.id}/{tag}"
    o = Obs()
    log0 = _errlog_window_start(rig.node)
    san0 = hl._sanitizer_count(rig)  # type: ignore[arg-type]
    workers0 = rig.workers()
    problems: list[str] = []
    try:
        db0 = rig.dbsize()
        o.legs.append(rig.fetch_leg("MISS", case.method, path, bound))
        o.legs.append(rig.fetch_leg("L1", case.method, path, bound))
        if o.legs[1].replay:
            # the L2 write-through is issued after the response: let it land
            wait_for(lambda: rig.dbsize() > db0, timeout=2.0)
        o.purge_status = rig.purge_l1(path)
        o.legs.append(rig.fetch_leg("L2", case.method, path, bound))
    except (OSError, ValueError, RuntimeError) as exc:
        problems.append(f"rig error: {type(exc).__name__}: {exc}")

    if hl._sanitizer_count(rig) > san0:  # type: ignore[arg-type]
        problems.append("new sanitizer report")
    if not rig.alive():
        problems.append("nginx died")
    else:
        lost = hl.worker_loss(workers0, rig.workers())
        if lost:
            problems.append(f"worker(s) {sorted(lost)} exited")
    lines = hl._log_from(rig, log0)  # type: ignore[arg-type]
    fatal = [ln for ln in lines if any(f"[{lv}]" in ln for lv in
                                       ("crit", "alert", "emerg"))]
    if fatal:
        problems.append(fatal[0][:200])
    o.sanitizer = "; ".join(problems)

    res.failed = judge(case, o)
    res.trace.update({
        "path": path, "purge": o.purge_status,
        "legs": [{"leg": lg.name, "status": lg.status,
                  "cache": lg.cache, "replay": lg.replay,
                  "origin": lg.origin_hits, "accel": lg.accel_hits,
                  "l2_hits": lg.l2_hits, "seconds": round(lg.seconds, 3),
                  "headers": [f"{k}: {v[:60]}" for k, v in
                              (lg.pairs + lg.interim)[:24]],
                  "body": lg.body[:60].decode("latin-1"),
                  "error": lg.error} for lg in o.legs],
        "log": [ln[:240] for ln in lines[:6]]})
    if not rig.alive():
        with contextlib.suppress(RuntimeError):
            rig.node.stop()
        rig.node.start()
    return res


def run_matrix(ng: Nginx, redis: RedisServer,
               only: set[str] | None = None) -> list[Result]:
    ids = [c.id for c in build_cases()]
    unknown = sorted((only or set()) - set(ids))
    if unknown:
        raise ValueError(f"HOSTILE_ORIGIN_ONLY: unknown case id(s) {unknown}")
    rig = _Rig(ng, redis)
    rig.start()
    results: list[Result] = []
    try:
        for case in build_cases():
            if only and case.id not in only:
                continue
            res = _run_case(rig, case, uuid.uuid4().hex[:8])
            res.verdict = classify(case.id, set(res.failed))
            results.append(res)
            legs = res.trace["legs"]
            assert isinstance(legs, list)
            brief = " ".join(
                f"{lg['leg']}={lg['status']}/{lg['cache'] or '-'}"
                f"{'/R' if lg['replay'] else ''}" for lg in legs)
            print(f"  hostile-origin {res.verdict:<14} {case.id:<24} "
                  f"{brief} "
                  f"{'; '.join(f'{k}: {v}' for k, v in res.failed.items())}",
                  flush=True)
    finally:
        rig.stop()
    return results


def summarize(results: list[Result]) -> dict[str, int]:
    out: dict[str, int] = {"total": len(results)}
    for r in results:
        out[r.verdict] = out.get(r.verdict, 0) + 1
    return out


def test_hostile_origin_replay_matrix(ng: Nginx, redis: RedisServer) -> None:
    """HARD-O1: hostile origin response replay matrix (MISS, L1 HIT,
    L2-promoted HIT) plus the uncached X-Accel-Redirect negative control;
    see the module docstring."""
    only_env = os.environ.get("HOSTILE_ORIGIN_ONLY", "")
    only = {x.strip() for x in only_env.split(",") if x.strip()} or None
    results = run_matrix(ng, redis, only)
    summary = summarize(results)
    print(f"  hostile-origin summary: {json.dumps(summary, sort_keys=True)}")
    report = os.environ.get("HOSTILE_ORIGIN_REPORT")
    if report:
        with open(report, "w", encoding="utf-8") as fh:
            json.dump({"summary": summary, "cases": [
                {"id": r.id, "verdict": r.verdict, "failed": r.failed,
                 "trace": r.trace} for r in results]},
                fh, indent=1, sort_keys=True)
    if only is None:
        assert CONTROL_IDS <= {r.id for r in results}, "control did not run"
    bad = [r for r in results if r.verdict not in ACCEPTED]
    assert not bad, "hostile origin matrix: " + "; ".join(
        f"{r.id}={r.verdict} {r.failed}" for r in bad)
