"""cache-turbo runtime tests -- hostile HTTP/2 request matrix (HARD-R2).

nginx core owns HTTP/2 framing and the HTTP/2 -> HTTP/1 downgrade; this
matrix proves how the MODULE reacts when a client sends a malformed or
ambiguous HTTP/2 request at a cached location.  It is the HTTP/2 sibling of
the HARD-R1 HTTP/1 matrix (areas/hostile_http.py) and reuses its oracle
vocabulary.  A victim entry is primed (a HIT, over HTTP/1) first; then, per
case, one h2c prior-knowledge connection carries the bad request on stream 1
and a clean victim request on stream 3.  When nginx ends the connection
(GOAWAY, or a close) the victim goes out on a fresh connection and that is
recorded (Obs.goaway / Obs.closed).

The client is hand-built (frames plus a literal-only HPACK encoder): a real
HTTP/2 library refuses to send the malformed field sections this matrix
exists for, and the CI runners have no python h2 package.

Case families (H2-*): duplicate, misordered, unknown and missing
pseudo-headers; uppercase field names; connection-specific fields
(Connection, Keep-Alive, Transfer-Encoding, Upgrade, TE other than
``trailers``); ``:authority`` versus ``Host`` conflicts; CR/LF/NUL in a
value (header injection into the HTTP/1 upstream request); a field name or
value at and one past ``large_client_header_buffers`` (the directive nginx
honours for HTTP/2 since 1.19.7; ``http2_max_field_size`` is deprecated);
DATA that a downgrade could turn into a smuggled upstream request.

Expectations (Case.expect): ``reject``, ``safe`` and ``own`` as HARD-R1,
plus ``either``: the request may be served as the victim (no foreign body)
or as its own resource (a store is allowed); used where nginx versions
differ on which authority wins.  Stream errors (RST_STREAM) and connection
errors (GOAWAY) count as a rejection.  The legacy CI job runs nginx 1.22.1,
so cases nginx only rejects in newer releases are ``safe``, not ``reject``.

Properties (PROPS), judged by the pure ``judge()``: P1-reaction,
P2-no-store, P3-own-key, P4-victim, P5-no-desync (no frames on a stream the
client never opened, the origin never saw a smuggled request),
P6-error-not-stored, P7-sanitizer, with the HARD-R1 meanings.  The victim
check is body-based: the origin's every body is unique, so the primed body
byte for byte means the cached entry answered.

Cookie shapes (CK-<preset>): for every backend preset with a session-bypass
cookie (areas/core.py _COOKIE_NEEDLE_TABLE, first needle), the cookie is
sent three ways at that preset's primed location: HTTP/2 cookie crumbs
(three ``cookie`` fields), one HTTP/1 ``Cookie`` line, and three HTTP/1
``Cookie`` lines.  C1-bypass: the crumb shape bypasses (a fresh origin
body, nothing stored); C2-same-verdict: all three shapes get the same
verdict.

Negative control: CTRL-CK-NO-PRESET sends the WordPress session cookie the
same three ways to a location with no backend preset; the crumb shape must
come back cacheable (a HIT of the primed entry), so C1-bypass MUST fail
there -- that proves the crumb case sees the preset's bypass and not some
unrelated reaction to cookie crumbs.  CTRL-H2-CLEAN proves a clean HTTP/2
request passes every property.

HTTP/3: the CI nginx is built without ``--with-http_v3_module``, so H3-ARM
is a SKIP with the reason; a QUIC build still SKIPs (no QUIC client here)
and says so.

Known defects live in H2_KNOWN_RED (UBSan-only rows gated on ``nginx -V``
as in HARD-R1).  Red cases and traces: memory/labs/nginx-cache-turbo-module/
hard-l2-evidence-20261118.md, section HARD-R2 (HARD-R3 input).

The node and origin reuse the HARD-L2 port offsets (node, origin, and the
Redis offset for the HTTP/2 listener): the matrices run sequentially and
each stops its rig before the next starts.

Environment: HOSTILE_HTTP2_ONLY=ID[,ID...] runs a subset;
HOSTILE_HTTP2_REPORT=path writes the per-case results as JSON.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import struct
import subprocess
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field

from abort_fixture import http2_style
from test_runtime_base import *
from test_runtime_base import _errlog_window_start

from areas import core as ct_core
from areas import hostile_http as hh
from areas import hostile_l2 as hl

__all__ = ["test_hostile_http2_matrix"]

HOST = hh.HOST
HDR_BUF = 1024            # large_client_header_buffers size
READ_S = 2.0
QUIET_S = 0.15
SETTLE_S = 0.05
ZONE = "h2z"
ADMIN = "/_h2z"
LOC_RAW = "c"
LOC_NONE = "p-none"       # no backend preset (negative control)
SMUGGLE = "/c/h2-smuggled"
CONTROL_PRESET = "wordpress"

PROPS = ("P1-reaction", "P2-no-store", "P3-own-key", "P4-victim",
         "P5-no-desync", "P6-error-not-stored", "P7-sanitizer")
COOKIE_PROPS = ("C1-bypass", "C2-same-verdict", "P7-sanitizer")
HARNESS_PROP = hh.HARNESS_PROP
EXPECTS = ("reject", "safe", "own", "either")
SHAPES: tuple[str, ...] = ("h2-crumbs", "h1-line", "h1-dup")

# --------------------------------------------------------------------------- #
# Frames and HPACK (pure).
# --------------------------------------------------------------------------- #

DATA, HEADERS, RST_STREAM, SETTINGS = 0x0, 0x1, 0x3, 0x4
PING, GOAWAY, WINDOW_UPDATE, CONTINUATION = 0x6, 0x7, 0x8, 0x9
FLAG_END_STREAM = 0x1
FLAG_ACK = 0x1
FLAG_END_HEADERS = 0x4
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
# RFC 7541 Appendix A: static-table indexes of the ":status" entries.
STATIC_STATUS = {8: 200, 9: 204, 10: 206, 11: 304, 12: 400, 13: 404, 14: 500}


def frame(ftype: int, flags: int, stream: int, payload: bytes = b"") -> bytes:
    return (struct.pack(">I", len(payload))[1:] + bytes([ftype, flags])
            + struct.pack(">I", stream & 0x7fffffff) + payload)


def parse_frame(buf: bytes) -> tuple[int, int, int, bytes, bytes] | None:
    """(type, flags, stream, payload, rest) of the first frame; None while
    the buffer holds less than one whole frame."""
    if len(buf) < 9:
        return None
    n = int.from_bytes(buf[:3], "big")
    if len(buf) < 9 + n:
        return None
    sid = int.from_bytes(buf[5:9], "big") & 0x7fffffff
    return buf[3], buf[4], sid, buf[9:9 + n], buf[9 + n:]


def hpack_int(value: int, prefix: int, first: int = 0) -> bytes:
    """RFC 7541 5.1 integer with an N-bit prefix; `first` carries the bits
    above the prefix."""
    top = (1 << prefix) - 1
    if value < top:
        return bytes([first | value])
    out = bytearray([first | top])
    value -= top
    while value >= 128:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def hpack_decode_int(buf: bytes, pos: int, prefix: int) -> tuple[int, int]:
    """(value, next position) of the RFC 7541 5.1 integer at `pos`."""
    top = (1 << prefix) - 1
    value = buf[pos] & top
    pos += 1
    if value < top:
        return value, pos
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        value += (b & 0x7f) << shift
        shift += 7
        if not b & 0x80:
            return value, pos


def hpack_field(name: bytes, value: bytes) -> bytes:
    """Literal field without indexing, new name, both strings raw (no
    Huffman): any byte goes on the wire exactly as given."""
    return (b"\x00" + hpack_int(len(name), 7) + name
            + hpack_int(len(value), 7) + value)


def header_block(fields: tuple[tuple[str, str], ...]) -> bytes:
    return b"".join(hpack_field(n.encode("latin-1"), v.encode("latin-1"))
                    for n, v in fields)


def h2_status(block: bytes) -> int:
    """The :status of nginx's response field block (nginx always encodes it
    first: a static index, or literal-with-indexing on index 8 with three
    raw digits).  0 when the block does not start that way."""
    pos = 0
    try:
        while pos < len(block) and block[pos] & 0xe0 == 0x20:
            _, pos = hpack_decode_int(block, pos, 5)   # table size update
        b = block[pos]
        if b & 0x80:
            return STATIC_STATUS.get(hpack_decode_int(block, pos, 7)[0], 0)
        if b & 0xc0 == 0x40:
            idx, pos = hpack_decode_int(block, pos, 6)
        else:
            idx, pos = hpack_decode_int(block, pos, 4)
        if idx != 8 or block[pos] & 0x80:
            return 0
        n, pos = hpack_decode_int(block, pos, 7)
        digits = block[pos:pos + n]
        ok = n == 3 and len(digits) == 3 and digits.isdigit()
        return int(digits) if ok else 0
    except IndexError:
        return 0


# --------------------------------------------------------------------------- #
# Case table (pure).
# --------------------------------------------------------------------------- #

def victim_path(loc: str) -> str:
    return hh.victim_path(loc)


V = victim_path(LOC_RAW)


def base(path: str = V, authority: str | None = HOST
         ) -> list[tuple[str, str]]:
    out = [(":method", "GET"), (":scheme", "http")]
    if authority is not None:
        out.append((":authority", authority))
    out.append((":path", path))
    return out


@dataclass(frozen=True)
class Case:
    id: str
    expect: str
    fields: tuple[tuple[str, str], ...]
    data: bytes = b""              # DATA after the HEADERS (END_STREAM there)
    smuggle: bool = False          # data carries a smuggled request
    victim: bool = True            # the request names the victim resource
    control: bool = False
    note: str = ""

    @property
    def on_victim(self) -> bool:
        return self.victim and self.expect != "own"


def smuggled(tag: str) -> bytes:
    return f"GET {SMUGGLE}-{tag} HTTP/1.1\r\nHost: {HOST}\r\n\r\n".encode()


def request_data(case: Case, tag: str) -> bytes:
    return case.data.replace(b"@SMUGGLE@", smuggled(tag))


def build_cases() -> list[Case]:
    def c(id_: str, expect: str, fields: list[tuple[str, str]],
          **kw: object) -> Case:
        return Case(id_, expect, tuple(fields), **kw)  # type: ignore[arg-type]

    b = base()
    pad_at = "a" * HDR_BUF
    pad_past = "a" * (HDR_BUF + 1)
    return [
        # --- pseudo-headers ---
        c("H2-PSEUDO-DUP-PATH", "reject", [*b, (":path", "/c/other")],
          note="two :path"),
        c("H2-PSEUDO-DUP-METHOD", "reject", [*b, (":method", "POST")],
          note="two :method"),
        c("H2-PSEUDO-DUP-SCHEME", "reject", [*b, (":scheme", "https")],
          note="two :scheme"),
        c("H2-PSEUDO-DUP-AUTHORITY", "safe",
          [*b, (":authority", "other.invalid")],
          note="two :authority (1.31 rejects; older nginx may not)"),
        c("H2-PSEUDO-AFTER-REGULAR", "reject",
          [*b[:3], ("x-a", "1"), b[3]],
          note=":path after a regular field"),
        c("H2-PSEUDO-UNKNOWN", "reject", [*b, (":foo", "bar")],
          note="unknown pseudo-header"),
        c("H2-PSEUDO-STATUS", "reject", [*b, (":status", "200")],
          note="response pseudo-header in a request"),
        c("H2-PSEUDO-NO-PATH", "reject", b[:3], note="no :path"),
        c("H2-PSEUDO-NO-METHOD", "reject", b[1:], note="no :method"),
        c("H2-PATH-RELATIVE", "reject", base("c/victim"),
          note=":path without a leading slash"),
        # --- field names / values ---
        c("H2-UPPER-NAME", "reject", [*b, ("X-Foo", "1")],
          note="uppercase field name"),
        c("H2-UPPER-COOKIE", "reject",
          [*b, ("Cookie", "wordpress_logged_in_x=1")],
          note="uppercase Cookie name"),
        c("H2-VALUE-CRLF", "reject",
          [*b, ("x-a", "1\r\nx-injected: 1")],
          note="CRLF in a value (upstream header injection)"),
        c("H2-VALUE-NUL", "reject", [*b, ("x-a", "1\x00b")],
          note="NUL in a value"),
        # --- connection-specific fields (RFC 9113 8.2.2) ---
        c("H2-CONN-CONNECTION", "safe", [*b, ("connection", "keep-alive")],
          note="Connection"),
        c("H2-CONN-KEEPALIVE", "safe", [*b, ("keep-alive", "300")],
          note="Keep-Alive"),
        c("H2-CONN-TE-CHUNKED", "safe", [*b, ("transfer-encoding", "chunked")],
          note="Transfer-Encoding"),
        c("H2-CONN-UPGRADE", "safe", [*b, ("upgrade", "h2c")],
          note="Upgrade"),
        c("H2-CONN-TE-GZIP", "safe", [*b, ("te", "gzip")],
          note="TE other than trailers"),
        c("H2-CONN-TE-TRAILERS", "safe", [*b, ("te", "trailers")],
          note="TE: trailers (the one legal TE)"),
        # --- authority ---
        c("H2-AUTH-HOST-CONFLICT", "either",
          [*b, ("host", "other.invalid")],
          note=":authority victim, Host other"),
        c("H2-AUTH-OTHER-HOST-VICTIM", "either",
          [*base(authority="other.invalid"), ("host", HOST)],
          note=":authority other, Host victim"),
        c("H2-HOST-ONLY-OTHER", "own",
          [*base(authority=None), ("host", "other.invalid")],
          victim=False, note="no :authority, Host other: its own key"),
        c("H2-NO-AUTHORITY-NO-HOST", "reject", base(authority=None),
          note="neither :authority nor Host"),
        # --- large_client_header_buffers ---
        c("H2-FIELD-AT-LIMIT", "safe", [*b, ("x-pad", pad_at)],
          note="value exactly large_client_header_buffers"),
        c("H2-FIELD-PAST-LIMIT", "reject", [*b, ("x-pad", pad_past)],
          note="value one byte past it (GOAWAY)"),
        c("H2-NAME-PAST-LIMIT", "reject", [*b, ("x" * (HDR_BUF + 1), "1")],
          note="name one byte past it"),
        # --- downgrade: DATA on a GET ---
        c("H2-CL0-DATA-SMUGGLE", "safe", [*b, ("content-length", "0")],
          data=b"@SMUGGLE@", smuggle=True,
          note="content-length 0 but DATA carries a request"),
        c("H2-TE-CHUNKED-SMUGGLE", "safe",
          [*b, ("transfer-encoding", "chunked")],
          data=b"0\r\n\r\n@SMUGGLE@", smuggle=True,
          note="TE chunked, DATA ends the chunks then carries a request"),
        c("H2-GET-DATA", "safe", list(b), data=b"hello",
          note="GET with DATA, no content-length"),
        # --- path forms ---
        c("H2-PATH-DOTDOT-ENC", "own", base("/c/x/%2e%2e/victim"),
          victim=False, note="%2e%2e normalizes onto the victim path"),
        # --- control ---
        c("CTRL-H2-CLEAN", "own", base("/c/h2-ctrl-clean"), victim=False,
          control=True, note="clean HTTP/2 request: every property holds"),
    ]


@dataclass(frozen=True)
class CookieCase:
    id: str
    preset: str | None             # None: the no-preset control location
    needle: str
    control: bool = False

    @property
    def loc(self) -> str:
        return f"p-{self.preset}" if self.preset else LOC_NONE


def preset_needles() -> dict[str, str]:
    """preset -> its first session-bypass cookie needle."""
    return {p: needles[0] for p, (_, needles)
            in ct_core._COOKIE_NEEDLE_TABLE.items() if needles}


def build_cookie_cases() -> list[CookieCase]:
    out = [CookieCase(f"CK-{p.upper()}", p, n)
           for p, n in sorted(preset_needles().items())]
    out.append(CookieCase("CTRL-CK-NO-PRESET", None,
                          preset_needles()[CONTROL_PRESET], control=True))
    return out


def crumbs(needle: str) -> tuple[str, str, str]:
    """The bypass cookie between two unrelated ones, so a matcher that only
    looks at the first or last crumb misses it."""
    return ("ct_a=1", f"{needle}zzz=1", "ct_b=2")


def cookie_fields(shape: str, cs: tuple[str, ...]) -> list[tuple[str, str]]:
    if shape == "h2-crumbs":
        return [("cookie", x) for x in cs]
    if shape == "h1-line":
        return [("Cookie", "; ".join(cs))]
    if shape == "h1-dup":
        return [("Cookie", x) for x in cs]
    raise ValueError(f"unknown cookie shape {shape!r}")


def h1_request(path: str, fields: list[tuple[str, str]]) -> bytes:
    lines = [f"GET {path} HTTP/1.1", f"Host: {HOST}"]
    lines += [f"{n}: {v}" for n, v in fields]
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def cookie_verdict(status: int, body: bytes, primed: bytes,
                   stored: tuple[int, int]) -> str:
    """bypass | hit | store | status-<n>: what the cookie request got at a
    location whose entry was primed right before."""
    if stored != (0, 0):
        return "store"
    if status != 200:
        return f"status-{status}"
    return "hit" if body == primed else "bypass"


# --------------------------------------------------------------------------- #
# Known reds and classification (pure).
# --------------------------------------------------------------------------- #

# Known defects: case id -> the properties it fails today (see the evidence
# file).  HARD-R3 removes a row when it fixes the defect.
H2_KNOWN_RED: dict[str, frozenset[str]] = {}

# Rows only a UBSan build observes (gated on `nginx -V`, as HARD-R1).
H2_KNOWN_RED_UBSAN: dict[str, frozenset[str]] = {}


def known_red(ubsan: bool) -> dict[str, frozenset[str]]:
    return {**H2_KNOWN_RED, **(H2_KNOWN_RED_UBSAN if ubsan else {})}


CONTROL_EXPECTED: dict[str, frozenset[str]] = {
    "CTRL-H2-CLEAN": frozenset(),
    "CTRL-CK-NO-PRESET": frozenset({"C1-bypass"}),
}
CONTROL_IDS = frozenset(CONTROL_EXPECTED)
ACCEPTED = frozenset({"green", "known-red", "control-ok", "skip"})


def classify(case_id: str, failed: set[str] | frozenset[str],
             known: dict[str, frozenset[str]] | None = None) -> str:
    known = H2_KNOWN_RED if known is None else known
    if HARNESS_PROP in failed:
        return "harness-fail"
    if case_id in CONTROL_EXPECTED:
        ok = set(failed) == CONTROL_EXPECTED[case_id]
        return "control-ok" if ok else "control-broken"
    if case_id in known:
        if not failed:
            return "xpass"
        return "known-red" if set(failed) <= known[case_id] else "known-red-drift"
    return "red" if failed else "green"


def h3_skip_reason(version_text: str) -> str:
    if "--with-http_v3_module" not in version_text:
        return "nginx built without --with-http_v3_module (no QUIC listener)"
    return "nginx has http_v3 but this matrix has no QUIC client"


# --------------------------------------------------------------------------- #
# Oracle (pure).
# --------------------------------------------------------------------------- #

@dataclass
class Obs:
    """What one H2 case did.  status 0 = no response."""
    status: int = 0
    rst: int | None = None         # RST_STREAM error code on the bad stream
    goaway: int | None = None      # GOAWAY error code
    closed: bool = False           # nginx closed the connection
    body: bytes = b""
    stored: tuple[int, int] = (0, 0)
    victim_body: bytes = b""
    origin_bodies: tuple[bytes, ...] = ()
    victim_status: int = 0
    victim_got: bytes = b""
    unsolicited: tuple[str, ...] = ()
    smuggle_seen: bool = False
    sanitizer: str = ""
    primed: bool = True


def judge(case: Case, o: Obs) -> dict[str, str]:
    fail: dict[str, str] = {}
    st = o.status
    ok2 = 200 <= st < 300
    err = (st >= 400 or o.rst is not None
           or (st == 0 and (o.goaway is not None or o.closed)))
    if not o.primed:
        fail[HARNESS_PROP] = "victim was not a HIT before the case"
    if case.expect == "reject":
        if not err:
            fail["P1-reaction"] = (f"status={st} rst={o.rst} "
                                   f"goaway={o.goaway} (expected rejection)")
    elif not (ok2 or err) or (500 <= st and st != 501):
        fail["P1-reaction"] = f"status={st} rst={o.rst} goaway={o.goaway}"
    if case.control and (not ok2 or o.rst is not None):
        fail["P1-reaction"] = (f"clean control not served: status={st} "
                               f"rst={o.rst} goaway={o.goaway}")
    if ok2 and case.expect in ("reject", "safe") and o.stored != (0, 0):
        fail["P2-no-store"] = f"stored used_bytes/markers delta={o.stored}"
    if ok2:
        if case.on_victim:
            if o.body != o.victim_body and o.body not in o.origin_bodies:
                fail["P3-own-key"] = ("victim-path answer is neither the "
                                      f"cached nor an origin body: "
                                      f"{o.body[:60]!r}")
        elif o.body == o.victim_body:
            fail["P3-own-key"] = f"served the victim's entry: {o.body[:60]!r}"
    if o.victim_status != 200 or o.victim_got != o.victim_body:
        fail["P4-victim"] = (f"victim status={o.victim_status} "
                             f"body={o.victim_got[:60]!r}")
    if o.unsolicited or o.smuggle_seen:
        fail["P5-no-desync"] = (f"unsolicited={list(o.unsolicited)[:4]} "
                                f"smuggled-to-origin={o.smuggle_seen}")
    if err and o.stored != (0, 0):
        fail["P6-error-not-stored"] = (f"status={st} charged "
                                       f"used_bytes/markers={o.stored}")
    if o.sanitizer:
        fail["P7-sanitizer"] = o.sanitizer
    return fail


def judge_cookie(verdicts: Mapping[str, str], primed: bool,
                 sanitizer: str = "", control: bool = False) -> dict[str, str]:
    fail: dict[str, str] = {}
    if not primed:
        fail[HARNESS_PROP] = "preset location was not a HIT before the case"
    if verdicts.get("h2-crumbs") != "bypass":
        fail["C1-bypass"] = f"h2-crumbs verdict={verdicts.get('h2-crumbs')}"
    if len(set(verdicts.values())) != 1 or set(verdicts) != set(SHAPES):
        fail["C2-same-verdict"] = json.dumps(verdicts, sort_keys=True)
    if control and any(v != "hit" for v in verdicts.values()):
        fail["C3-control-hit"] = json.dumps(verdicts, sort_keys=True)
    if sanitizer:
        fail["P7-sanitizer"] = sanitizer
    return fail


@dataclass
class Result:
    id: str
    failed: dict[str, str] = field(default_factory=dict)
    verdict: str = ""
    trace: dict[str, object] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# HTTP/2 client.
# --------------------------------------------------------------------------- #

@dataclass
class Stream:
    status: int = 0
    body: bytes = b""
    ended: bool = False
    rst: int | None = None


class H2Conn:
    """h2c prior-knowledge client: raw frames, literal-only HPACK."""

    def __init__(self, port: int) -> None:
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.buf = b""
        self.eof = False
        self.goaway: int | None = None
        self.streams: dict[int, Stream] = {}
        self.unsolicited: list[str] = []
        self.send(PREFACE
                  + frame(SETTINGS, 0, 0, struct.pack(">HI", 4, 1 << 24))
                  + frame(WINDOW_UPDATE, 0, 0, struct.pack(">I", 1 << 24)))

    def send(self, data: bytes) -> bool:
        try:
            self.sock.sendall(data)
            return True
        except OSError:
            self.eof = True
            return False

    def request(self, sid: int, fields: tuple[tuple[str, str], ...],
                data: bytes = b"") -> bool:
        flags = FLAG_END_HEADERS | (0 if data else FLAG_END_STREAM)
        out = frame(HEADERS, flags, sid, header_block(fields))
        if data:
            out += frame(DATA, FLAG_END_STREAM, sid, data)
        self.streams[sid] = Stream()
        return self.send(out)

    def _fill(self, deadline: float) -> bool:
        left = deadline - time.monotonic()
        if left <= 0 or self.eof:
            return False
        self.sock.settimeout(left)
        try:
            chunk = self.sock.recv(65536)
        except TimeoutError:
            return False
        except OSError:
            chunk = b""
        if not chunk:
            self.eof = True
            return False
        self.buf += chunk
        return True

    def _dispatch(self, ftype: int, flags: int, sid: int,
                  payload: bytes) -> None:
        if sid == 0:
            if ftype == SETTINGS and not flags & FLAG_ACK:
                self.send(frame(SETTINGS, FLAG_ACK, 0))
            elif ftype == PING and not flags & FLAG_ACK:
                self.send(frame(PING, FLAG_ACK, 0, payload))
            elif ftype == GOAWAY and len(payload) >= 8:
                self.goaway = int.from_bytes(payload[4:8], "big")
            return
        st = self.streams.get(sid)
        if st is None:
            if ftype in (HEADERS, DATA, CONTINUATION):
                self.unsolicited.append(f"type={ftype} stream={sid}")
            return
        if ftype == HEADERS:
            if not st.status:
                st.status = h2_status(payload)
            if flags & FLAG_END_STREAM:
                st.ended = True
        elif ftype == DATA:
            st.body += payload
            if payload:
                self.send(frame(WINDOW_UPDATE, 0, sid,
                                struct.pack(">I", len(payload))))
            if flags & FLAG_END_STREAM:
                st.ended = True
        elif ftype == RST_STREAM and len(payload) >= 4:
            st.rst = int.from_bytes(payload[:4], "big")
            st.ended = True

    def _pump(self) -> None:
        while True:
            got = parse_frame(self.buf)
            if got is None:
                return
            ftype, flags, sid, payload, self.buf = got
            self._dispatch(ftype, flags, sid, payload)

    def wait(self, sid: int, bound: float) -> Stream:
        deadline = time.monotonic() + bound
        st = self.streams[sid]
        while True:
            self._pump()
            if st.ended or self.eof:
                return st
            if self.goaway is not None and not self.buf:
                # nginx may still finish a stream at or below last_stream_id;
                # give it the quiet window, then stop.
                self.quiet(QUIET_S)
                return st
            if not self._fill(deadline):
                self._pump()
                return st

    def quiet(self, window: float) -> None:
        deadline = time.monotonic() + window
        while self._fill(deadline):
            self._pump()
        self._pump()

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.sock.close()


# --------------------------------------------------------------------------- #
# Harness: one-worker nginx with its own origin and an h2c listener.
# --------------------------------------------------------------------------- #

def _config(root, port: int, h2port: int, style: str, module,
            origin: int, presets: list[str]) -> str:
    load = f"load_module {module};\n" if module else ""
    common = (f"cache_turbo {ZONE}; cache_turbo_valid 60s; "
              "cache_turbo_lock off; "
              "add_header X-CT-Status $cache_turbo_status always; "
              f"proxy_pass http://127.0.0.1:{origin};")
    h2_listen = " http2" if style == "listen" else ""
    h2_on = "http2 on;" if style == "on" else ""
    preset_locs = "\n".join(
        f"        location /p-{p}/ {{ cache_turbo_backend {p}; {common} }}"
        for p in presets)
    return f"""{load}worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/logs/error.log info;
events {{ worker_connections 256; }}
http {{
    access_log off;
    client_header_buffer_size {HDR_BUF};
    large_client_header_buffers 2 {HDR_BUF};
    client_header_timeout 2s;
    client_body_timeout 2s;
    keepalive_timeout 10s;
    cache_turbo_zone name={ZONE} 4m;
    server {{
        listen 127.0.0.1:{port};
        listen 127.0.0.1:{h2port}{h2_listen};
        {h2_on}
        server_name {HOST};
        location = {ADMIN} {{ cache_turbo_admin {ZONE}; }}
        location /{LOC_RAW}/ {{ {common} }}
        location /{LOC_NONE}/ {{ {common} }}
{preset_locs}
    }}
}}
"""


class _Rig:
    def __init__(self, ng: Nginx, style: str) -> None:
        base_port = ng.port
        self.origin = hl._Origin(base_port + PORT_OFFSETS["hostile_l2_origin"])
        self.tmp = ng.root.parent / "hostile-http2"
        self.h2_port = base_port + PORT_OFFSETS["hostile_l2_redis"]
        self.node = Nginx(ng.binary, ng.module, self.tmp,
                          base_port + PORT_OFFSETS["hostile_l2_node"],
                          self.origin.srv.server_address[1], ng.runner_raw,
                          ng.single_process)
        text = _config(self.tmp, self.node.port, self.h2_port, style,
                       ng.module, self.origin.srv.server_address[1],
                       sorted(preset_needles()))

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
            if not wait_for(lambda: _port_open(self.h2_port), timeout=10):
                raise RuntimeError("hostile-http2: h2c listener never opened")
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

    def stats(self) -> tuple[int, int]:
        _, b, _ = fetch(self.node.port, ADMIN)
        d = json.loads(b)
        return int(d.get("used_bytes", 0)), int(d.get("markers", 0))

    def h1(self, raw: bytes, bound: float) -> hh.Resp | None:
        c = hh.Conn(self.node.port)
        try:
            c.send(raw)
            return c.response(bound)
        finally:
            c.close()

    def prime(self, loc: str, bound: float) -> tuple[bool, bytes]:
        for _ in range(3):
            r = self.h1(hh.victim_request(loc, close=True), bound)
            if r is not None and r.status == 200 and \
                    r.headers.get("x-ct-status") == "HIT":
                return True, r.body
            time.sleep(SETTLE_S)
        return False, b""


def _port_open(port: int) -> bool:
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        return True
    except OSError:
        return False


class _Watch:
    """Sanitizer / log / worker-loss window around one case."""

    def __init__(self, rig: _Rig) -> None:
        self.rig = rig
        self.log0 = _errlog_window_start(rig.node)
        self.san0 = hl._sanitizer_count(rig)  # type: ignore[arg-type]
        self.workers0 = rig.workers()

    def problems(self, extra: str = "") -> tuple[str, list[str]]:
        rig = self.rig
        out = [extra] if extra else []
        if hl._sanitizer_count(rig) > self.san0:  # type: ignore[arg-type]
            out.append("new sanitizer report")
        if not rig.alive():
            out.append("nginx died")
        else:
            lost = hl.worker_loss(self.workers0, rig.workers())
            if lost:
                out.append(f"worker(s) {sorted(lost)} exited")
        lines = hl._log_from(rig, self.log0)  # type: ignore[arg-type]
        fatal = [ln for ln in lines if any(f"[{lv}]" in ln for lv in
                                           ("crit", "alert", "emerg"))]
        if fatal:
            out.append(fatal[0][:200])
        return "; ".join(out), lines

    def restart_if_dead(self) -> None:
        if not self.rig.alive():
            with contextlib.suppress(RuntimeError):
                self.rig.node.stop()
            self.rig.node.start()


def _run_case(rig: _Rig, case: Case, tag: str) -> Result:
    res = Result(case.id)
    bound = READ_S * sanitizer_time_scale()
    quiet = QUIET_S * sanitizer_time_scale()
    o = Obs()
    o.primed, o.victim_body = rig.prime(LOC_RAW, bound)
    watch = _Watch(rig)
    s0 = rig.stats()
    stats_error = ""
    unsolicited: list[str] = []
    conn = H2Conn(rig.h2_port)
    try:
        conn.request(1, case.fields, request_data(case, tag))
        st = conn.wait(1, bound)
        conn.quiet(quiet)
        o.status, o.body, o.rst = st.status, st.body, st.rst
        o.goaway, o.closed = conn.goaway, conn.eof
        time.sleep(SETTLE_S * sanitizer_time_scale())
        try:
            s1 = rig.stats()
            o.stored = (s1[0] - s0[0], s1[1] - s0[1])
        except (OSError, ValueError) as exc:
            stats_error = f"stats unreachable: {exc}"
        vsid = 3
        if conn.goaway is not None or conn.eof:
            unsolicited += conn.unsolicited
            conn.close()
            conn = H2Conn(rig.h2_port)
            vsid = 1
        conn.request(vsid, tuple(base()))
        v = conn.wait(vsid, bound)
        conn.quiet(quiet)
        o.victim_status, o.victim_got = v.status, v.body
        unsolicited += conn.unsolicited
    except OSError as exc:
        stats_error = stats_error or f"connection failed: {exc}"
    finally:
        conn.close()
    o.unsolicited = tuple(unsolicited)
    o.origin_bodies = tuple(b.encode() for b in rig.origin.bodies(V))
    o.smuggle_seen = bool(rig.origin.bodies(f"{SMUGGLE}-{tag}"))
    o.sanitizer, lines = watch.problems(stats_error)
    res.failed = judge(case, o)
    res.trace.update({
        "status": o.status, "rst": o.rst, "goaway": o.goaway,
        "closed": o.closed, "stored": list(o.stored),
        "body": o.body[:80].decode("latin-1"),
        "victim": [o.victim_status, o.victim_got == o.victim_body],
        "unsolicited": list(o.unsolicited)[:4],
        "smuggle_seen": o.smuggle_seen,
        "log": [ln[:240] for ln in lines[:6]]})
    watch.restart_if_dead()
    return res


def _send_shape(rig: _Rig, shape: str, path: str, cs: tuple[str, ...],
                bound: float) -> tuple[int, bytes, str]:
    fields = cookie_fields(shape, cs)
    if shape.startswith("h1-"):
        r = rig.h1(h1_request(path, fields), bound)
        if r is None:
            return 0, b"", ""
        return r.status, r.body, r.headers.get("x-ct-status", "")
    conn = H2Conn(rig.h2_port)
    try:
        conn.request(1, (*base(path), *fields))
        st = conn.wait(1, bound)
        return st.status, st.body, f"rst={st.rst}" if st.rst is not None else ""
    finally:
        conn.close()


def _run_cookie(rig: _Rig, case: CookieCase) -> Result:
    res = Result(case.id)
    bound = READ_S * sanitizer_time_scale()
    primed, pbody = rig.prime(case.loc, bound)
    watch = _Watch(rig)
    path = victim_path(case.loc)
    cs = crumbs(case.needle)
    verdicts: dict[str, str] = {}
    shapes: dict[str, object] = {}
    error = ""
    for shape in SHAPES:
        try:
            s0 = rig.stats()
            status, body, cache = _send_shape(rig, shape, path, cs, bound)
            time.sleep(SETTLE_S * sanitizer_time_scale())
            s1 = rig.stats()
        except (OSError, ValueError) as exc:
            error = error or f"{shape}: {exc}"
            verdicts[shape] = "error"
            continue
        stored = (s1[0] - s0[0], s1[1] - s0[1])
        verdicts[shape] = cookie_verdict(status, body, pbody, stored)
        shapes[shape] = {"status": status, "cache": cache,
                         "stored": list(stored)}
    sanitizer, lines = watch.problems(error)
    res.failed = judge_cookie(verdicts, primed, sanitizer, case.control)
    res.trace.update({"preset": case.preset, "needle": case.needle,
                      "verdicts": verdicts, "shapes": shapes,
                      "log": [ln[:240] for ln in lines[:6]]})
    watch.restart_if_dead()
    return res


def all_ids() -> list[str]:
    return ([c.id for c in build_cases()]
            + [c.id for c in build_cookie_cases()] + ["H3-ARM"])


def _version_text(binary: str) -> str:
    proc = subprocess.run([str(binary), "-V"], capture_output=True, text=True,
                          timeout=30, check=False)
    return proc.stdout + proc.stderr


def _print(res: Result) -> None:
    t = res.trace
    head = (f"st={t.get('status')} rst={t.get('rst')} goaway={t.get('goaway')}"
            if "status" in t else f"verdicts={t.get('verdicts')}"
            if "verdicts" in t else f"reason={t.get('reason')}")
    print(f"  hostile-http2 {res.verdict:<14} {res.id:<26} {head} "
          f"{'; '.join(f'{k}: {v}' for k, v in res.failed.items())}",
          flush=True)


def run_matrix(ng: Nginx, only: set[str] | None = None) -> list[Result]:
    unknown = sorted((only or set()) - set(all_ids()))
    if unknown:
        raise ValueError(f"HOSTILE_HTTP2_ONLY: unknown case id(s) {unknown}")
    vtext = _version_text(ng.binary)
    results: list[Result] = []
    if not only or "H3-ARM" in only:
        h3 = Result("H3-ARM", verdict="skip")
        h3.trace["reason"] = h3_skip_reason(vtext)
        results.append(h3)
        _print(h3)
    style = http2_style(str(ng.binary))
    if style is None:
        skip = Result("H2-ARM", verdict="skip")
        skip.trace["reason"] = "nginx built without --with-http_v2_module"
        results.append(skip)
        _print(skip)
        return results
    known = known_red("undefined" in hh.sanitizers_of(vtext))
    rig = _Rig(ng, style)
    rig.start()
    try:
        for case in build_cases():
            if only and case.id not in only:
                continue
            res = _run_case(rig, case, uuid.uuid4().hex[:8])
            res.verdict = classify(case.id, set(res.failed), known)
            results.append(res)
            _print(res)
        for ck in build_cookie_cases():
            if only and ck.id not in only:
                continue
            res = _run_cookie(rig, ck)
            res.verdict = classify(ck.id, set(res.failed), known)
            results.append(res)
            _print(res)
    finally:
        rig.stop()
    return results


def summarize(results: list[Result]) -> dict[str, int]:
    out: dict[str, int] = {"total": len(results)}
    for r in results:
        out[r.verdict] = out.get(r.verdict, 0) + 1
    return out


def test_hostile_http2_matrix(ng: Nginx) -> None:
    """HARD-R2: hostile HTTP/2 request matrix, the per-preset cookie-shape
    equivalence and the no-preset negative control; see the module
    docstring."""
    only_env = os.environ.get("HOSTILE_HTTP2_ONLY", "")
    only = {x.strip() for x in only_env.split(",") if x.strip()} or None
    results = run_matrix(ng, only)
    summary = summarize(results)
    print(f"  hostile-http2 summary: {json.dumps(summary, sort_keys=True)}")
    report = os.environ.get("HOSTILE_HTTP2_REPORT")
    if report:
        with open(report, "w", encoding="utf-8") as fh:
            json.dump({"summary": summary, "cases": [
                {"id": r.id, "verdict": r.verdict, "failed": r.failed,
                 "trace": r.trace} for r in results]},
                fh, indent=1, sort_keys=True)
    if only is None and http2_style(str(ng.binary)) is not None:
        assert CONTROL_IDS <= {r.id for r in results}, "control did not run"
    bad = [r for r in results if r.verdict not in ACCEPTED]
    assert not bad, "hostile HTTP/2 matrix: " + "; ".join(
        f"{r.id}={r.verdict} {r.failed}" for r in bad)
