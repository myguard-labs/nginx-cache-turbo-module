"""cache-turbo runtime tests -- hostile HTTP/1 request matrix (HARD-R1).

nginx core owns HTTP/1 framing; this matrix proves how the MODULE reacts when
a client sends a malformed or ambiguous request at a cached location.  A
victim entry is primed (a HIT) first; then, per case, one keepalive raw
socket carries the bad request followed by a clean victim request on the
same connection.  When nginx closes the connection after the bad request
(the normal reaction to a 400) the victim goes out on a fresh connection and
the close is recorded (Obs.closed).

Case families: CL+TE (both orders), duplicate and comma-list Content-Length,
bad chunk sizes and extensions, Transfer-Encoding other than chunked,
obs-fold, NUL / CTL / bare CR in header values, bare-LF line ends,
absolute-form target with a conflicting Host, duplicate or empty Host,
HTTP/1.0 without Host, ``%00``, ``%2e%2e``, ``;params``, ``#`` and overlong
UTF-8 in the path, request line and header line at and one past
``large_client_header_buffers``, GET with a body (CL 0, CL>0, chunked,
``Expect: 100-continue``).  Framing cases carry a smuggled request tail.

Expectations (Case.expect):

  reject  nginx answers >= 400 (or closes without a response).
  safe    nginx rejects, or the request is served WITHOUT a store (a HIT of
          the primed entry or a bypass).
  own     the request is a different resource from the victim: it may be
          served from the origin and stored, but only under its own key.

Properties (PROPS), judged by the pure ``judge()`` on an ``Obs``:

  P1-reaction   reject: status >= 400 or closed; safe/own: 2xx, >= 400 or
                closed (a 3xx or a 5xx other than 501 is a failure).
  P2-no-store   a 2xx answer to a reject/safe case stored nothing: zone
                ``used_bytes`` and ``markers`` deltas over the bad request
                are zero.
  P3-own-key    a 2xx answer carries the right body: for a request on the
                victim path the victim's cached body or an origin body for
                that path; for an ``own`` request NOT the victim's cached
                entry (no HIT, not the victim body) -- path confusion.
  P4-victim     the victim, sent after the bad request, gets its own cached
                body (200, X-CT-Status HIT, the primed body byte for byte).
  P5-no-desync  no response arrives that the client did not ask for, nothing
                is left over after the victim, and the origin never saw the
                smuggled request tail.
  P6-error-not-stored  a >= 400 answer (or a close) charged nothing to the
                zone (``used_bytes``/``markers`` deltas zero): nginx error
                pages are never stored.
  P7-sanitizer  no sanitizer report, no crit/alert/emerg log line, nginx
                and its worker alive.

``H-primed`` (unwaivable): the victim was a HIT right before the case.

Negative control: CTRL-HR-URI-KEY sends the ``%2e%2e`` path-confusion request
to /u/, a location keyed on the normalized ``$uri`` instead of the module's
raw default key (Host + unparsed URI).  ``proxy_pass`` without a URI part
forwards the raw target, so the normalized key maps a different upstream
request onto the victim's entry; P3-own-key MUST fail there.
CTRL-HR-CLEAN proves a clean request passes every property.

Known defects live in HTTP_KNOWN_RED with the properties they fail; such a
case does not fail the run, a known-red case that passes (xpass) does.
HTTP_KNOWN_RED_UBSAN rows apply only when ``nginx -V`` shows
``-fsanitize=...undefined`` (the defect is invisible on a plain build).  Red
cases and traces: memory/labs/nginx-cache-turbo-module/
hard-l2-evidence-20261118.md, section HARD-R1 (HARD-R3 input).

The node and origin reuse the HARD-L2 port offsets: the matrices run
sequentially and each stops its rig before the next starts.

Environment: HOSTILE_HTTP_ONLY=ID[,ID...] runs a subset;
HOSTILE_HTTP_REPORT=path writes the per-case results as JSON.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass, field

from test_runtime_base import *
from test_runtime_base import _errlog_window_start

from areas import hostile_l2 as hl

__all__ = ["test_hostile_http_matrix"]

HOST = "localhost"
HDR_BUF = 1024            # client_header_buffer_size / large buffer size
READ_S = 2.0              # per-response read bound (sanitizer-scaled)
QUIET_S = 0.15            # "nothing else arrives" window
SETTLE_S = 0.05           # let a store land before the stats read
ZONE = "hh"
ADMIN = "/_hh"
LOC_RAW = "c"             # default key: Host + unparsed URI
LOC_URI = "u"             # cache_turbo_key $uri (negative control)
SMUGGLE = "/c/smuggled"   # tag-suffixed per run

PROPS = ("P1-reaction", "P2-no-store", "P3-own-key", "P4-victim",
         "P5-no-desync", "P6-error-not-stored", "P7-sanitizer")
HARNESS_PROP = "H-primed"
EXPECTS = ("reject", "safe", "own")


def victim_path(loc: str) -> str:
    return f"/{loc}/victim"


def line_target(total: int, prefix: str = "/c/len-") -> str:
    """A target whose request line ``GET <t> HTTP/1.1`` is `total` bytes long
    (CRLF excluded)."""
    pad = total - len("GET  HTTP/1.1") - len(prefix)
    if pad < 1:
        raise ValueError(f"line length {total} too short")
    return prefix + "a" * pad


def header_line(total: int, name: str = "X-Pad") -> str:
    """A header line ``<name>: aaa...`` of `total` bytes (CRLF excluded)."""
    pad = total - len(name) - 2
    if pad < 1:
        raise ValueError(f"header length {total} too short")
    return f"{name}: " + "a" * pad


# Longest request / header line (CRLF excluded) nginx accepts with
# large_client_header_buffers 2 1k: the line plus its CR must be shorter than
# the buffer (measured on 1.31.3: 1022 -> 200, 1023 -> 414 / 400).
URI_AT = HDR_BUF - 2
HDR_AT = HDR_BUF - 2


@dataclass(frozen=True)
class Case:
    id: str
    expect: str
    target: str                    # request target as sent
    head: str = ""                 # extra header lines, CRLF-joined, no end
    body: bytes = b""              # sent right after the head
    later: bytes = b""             # sent after a pause (Expect: 100-continue)
    version: str = "HTTP/1.1"
    host: str | None = HOST        # None: no Host header
    eol: str = "\r\n"
    smuggle: bool = False          # body carries a smuggled request tail
    loc: str = LOC_RAW
    control: bool = False
    note: str = ""

    @property
    def on_victim(self) -> bool:
        """The target's raw path and Host are the victim's (only the framing
        is bad); a different authority is a different cache key."""
        return self.host == HOST and self.target == victim_path(self.loc)


def smuggled(tag: str) -> bytes:
    return (f"GET {SMUGGLE}-{tag} HTTP/1.1\r\nHost: {HOST}\r\n\r\n").encode()


def build_request(case: Case, tag: str) -> bytes:
    """The bad request's bytes (Case.later not included)."""
    eol = case.eol
    lines = [f"GET {case.target} {case.version}"]
    if case.host is not None:
        lines.append(f"Host: {case.host}")
    if case.head:
        lines.extend(case.head.split("\r\n"))
    body = case.body.replace(b"@SMUGGLE@", smuggled(tag))
    head = eol.join(lines).replace("@BODY@", str(len(body)))
    return (head + eol + eol).encode("latin-1") + body


def victim_request(loc: str, close: bool = False) -> bytes:
    extra = "Connection: close\r\n" if close else ""
    return (f"GET {victim_path(loc)} HTTP/1.1\r\nHost: {HOST}\r\n"
            f"{extra}\r\n").encode()


V = victim_path(LOC_RAW)
CHUNK0 = b"0\r\n\r\n"


def build_cases() -> list[Case]:
    s = b"@SMUGGLE@"
    return [
        # --- framing: target the primed victim.  A smuggle case's tail is
        # body under one reading of the framing and a second request under
        # the other (@BODY@ = the body's length). ---
        Case("HR-CL-TE", "reject", V,
             "Content-Length: @BODY@\r\nTransfer-Encoding: chunked",
             CHUNK0 + s, smuggle=True, note="CL then TE"),
        Case("HR-TE-CL", "reject", V,
             "Transfer-Encoding: chunked\r\nContent-Length: @BODY@",
             CHUNK0 + s, smuggle=True, note="TE then CL"),
        Case("HR-CL-DUP-DIFF", "reject", V,
             "Content-Length: 0\r\nContent-Length: @BODY@", s, smuggle=True,
             note="two different Content-Length"),
        Case("HR-CL-DUP-SAME", "reject", V,
             "Content-Length: @BODY@\r\nContent-Length: @BODY@", s,
             smuggle=True, note="two identical Content-Length"),
        Case("HR-CL-COMMA", "reject", V, "Content-Length: @BODY@, @BODY@", s,
             smuggle=True, note="comma-list Content-Length"),
        Case("HR-CHUNK-SIZE-BAD", "safe", V, "Transfer-Encoding: chunked",
             b"zz\r\nhello\r\n" + CHUNK0, note="non-hex chunk size"),
        Case("HR-CHUNK-SIZE-OVERFLOW", "safe", V,
             "Transfer-Encoding: chunked",
             b"fffffffffffffffffff\r\nhello\r\n" + CHUNK0,
             note="chunk size overflows off_t"),
        Case("HR-CHUNK-EXT-BAD", "safe", V, "Transfer-Encoding: chunked",
             b"5;\x01x\r\nhello\r\n" + CHUNK0,
             note="CTL byte in a chunk extension"),
        Case("HR-TE-GZIP", "reject", V, "Transfer-Encoding: gzip", CHUNK0,
             note="TE other than chunked"),
        Case("HR-TE-CHUNKED-GZIP", "reject", V,
             "Transfer-Encoding: chunked, gzip", CHUNK0,
             note="chunked not the final coding"),
        Case("HR-TE-IDENTITY", "reject", V, "Transfer-Encoding: identity",
             CHUNK0, note="TE identity"),
        # --- header-value bytes / line ends (victim path, no body) ---
        Case("HR-OBS-FOLD", "safe", V, "X-A: a\r\n folded",
             note="obs-fold continuation line"),
        Case("HR-NUL-VALUE", "safe", V, "X-A: a\x00b",
             note="NUL in a header value"),
        Case("HR-CTL-VALUE", "safe", V, "X-A: a\x01b",
             note="CTL in a header value"),
        Case("HR-BARE-CR-VALUE", "safe", V, "X-A: a\rb",
             note="bare CR in a header value"),
        Case("HR-BARE-LF", "safe", V, "X-A: lf", eol="\n",
             note="bare-LF line ends throughout"),
        # --- Host / authority ---
        Case("HR-ABS-FORM-HOST", "own", f"http://other.invalid{V}",
             note="absolute-form authority conflicts with Host"),
        Case("HR-HOST-DUP", "reject", V, "Host: other.invalid",
             note="second Host header"),
        Case("HR-HOST-EMPTY", "own", V, host="",
             note="empty Host"),
        Case("HR-HTTP10-NOHOST", "own", V, version="HTTP/1.0", host=None,
             note="HTTP/1.0 without Host"),
        # --- path forms ---
        Case("HR-PATH-NUL", "reject", "/c/a%00b", note="%00 in the path"),
        Case("HR-PATH-DOTDOT-ENC", "own", "/c/x/%2e%2e/victim",
             note="%2e%2e normalizes onto the victim path"),
        Case("HR-PATH-DOTDOT", "own", "/c/x/../victim",
             note="../ normalizes onto the victim path"),
        Case("HR-PATH-PARAMS", "own", "/c/victim;jsessionid=x",
             note=";params"),
        Case("HR-PATH-FRAGMENT", "own", "/c/victim#frag",
             note="# fragment in the target"),
        Case("HR-PATH-OVERLONG-UTF8", "own", "/c/%c0%afvictim",
             note="overlong UTF-8 '/' (%c0%af)"),
        Case("HR-PATH-OVERLONG-RAW", "own", "/c/\xc0\xafvictim",
             note="overlong UTF-8 bytes, unescaped"),
        # --- large_client_header_buffers boundary ---
        Case("HR-URI-AT-LIMIT", "own", line_target(URI_AT),
             note="longest request line nginx accepts"),
        Case("HR-URI-PAST-LIMIT", "reject", line_target(URI_AT + 1),
             note="one byte past it (414)"),
        Case("HR-HDR-AT-LIMIT", "safe", V, header_line(HDR_AT),
             note="longest header line nginx accepts"),
        Case("HR-HDR-PAST-LIMIT", "reject", V, header_line(HDR_AT + 1),
             note="one byte past it (400)"),
        # --- GET with a body ---
        Case("HR-GET-CL0", "safe", V, "Content-Length: 0",
             note="GET, Content-Length: 0"),
        Case("HR-GET-CL-BODY", "safe", V, "Content-Length: 5", b"hello",
             note="GET with a 5-byte body on a HIT"),
        Case("HR-GET-CL-BODY-MISS", "safe", "/c/get-body-miss",
             "Content-Length: 5", b"hello",
             note="GET with a 5-byte body on a MISS: no store"),
        Case("HR-GET-CHUNKED-BODY", "safe", V, "Transfer-Encoding: chunked",
             b"5\r\nhello\r\n" + CHUNK0, note="GET with a chunked body"),
        Case("HR-GET-EXPECT-100", "safe", V,
             "Content-Length: 5\r\nExpect: 100-continue", later=b"hello",
             note="GET, Expect: 100-continue, body after a pause"),
        # --- controls ---
        Case("CTRL-HR-URI-KEY", "own", "/u/x/%2e%2e/victim", loc=LOC_URI,
             control=True,
             note="$uri-keyed location: path confusion MUST fail P3"),
        Case("CTRL-HR-CLEAN", "own", "/c/ctrl-clean", control=True,
             note="clean request: every property holds"),
    ]


# Known defects: case id -> the properties it fails today (filled from runs;
# see the evidence file).  HARD-R3 removes a row when it fixes the defect.
HTTP_KNOWN_RED: dict[str, frozenset[str]] = {}

# Known defects only a UBSan build can observe (on a plain build the case is
# green, so the row must not apply there or it would read as an xpass).
# HR-HTTP10-NOHOST: HTTP/1.0 without Host leaves r->headers_in.server.data
# NULL and the default-key build copies it (memcpy(k, NULL, 0), UB); UBSan
# halts the worker mid-request.  Evidence: HARD-R1 section.
HTTP_KNOWN_RED_UBSAN: dict[str, frozenset[str]] = {
    "HR-HTTP10-NOHOST": frozenset({"P7-sanitizer"}),
}


def known_red(ubsan: bool) -> dict[str, frozenset[str]]:
    return {**HTTP_KNOWN_RED, **(HTTP_KNOWN_RED_UBSAN if ubsan else {})}


def sanitizers_of(version_text: str) -> frozenset[str]:
    """The -fsanitize= list in `nginx -V` output (empty for a plain build)."""
    out: set[str] = set()
    for word in version_text.split():
        if "-fsanitize=" in word:
            out.update(word.split("-fsanitize=", 1)[1].strip("'\"").split(","))
    return frozenset(x for x in out if x)


def ubsan_build(binary: str) -> bool:
    proc = subprocess.run([str(binary), "-V"], capture_output=True, text=True,
                          timeout=30, check=False)
    return "undefined" in sanitizers_of(proc.stdout + proc.stderr)

# Control id -> the exact failure set that proves the oracle bites.
CONTROL_EXPECTED: dict[str, frozenset[str]] = {
    "CTRL-HR-URI-KEY": frozenset({"P3-own-key"}),
    "CTRL-HR-CLEAN": frozenset(),
}
CONTROL_IDS = frozenset(CONTROL_EXPECTED)
ACCEPTED = frozenset({"green", "known-red", "control-ok"})


def classify(case_id: str, failed: set[str] | frozenset[str],
             known: dict[str, frozenset[str]] | None = None) -> str:
    """green | known-red | control-ok are acceptable; red | xpass |
    known-red-drift | control-broken | harness-fail fail the matrix."""
    known = HTTP_KNOWN_RED if known is None else known
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


# --------------------------------------------------------------------------- #
# Raw HTTP/1 response parsing (pure).
# --------------------------------------------------------------------------- #

@dataclass
class Resp:
    status: int
    headers: dict[str, str]
    body: bytes
    close: bool                    # the response ends the connection


def _dechunk(buf: bytes) -> tuple[bytes, int] | None:
    """(body, bytes consumed) of a complete chunked body, None if short."""
    out, pos = b"", 0
    while True:
        eol = buf.find(b"\r\n", pos)
        if eol < 0:
            return None
        size = int(buf[pos:eol].split(b";")[0].strip() or b"0", 16)
        pos = eol + 2
        if size == 0:
            end = buf.find(b"\r\n\r\n", pos - 2)
            if end < 0:
                return None
            return out, end + 4
        if len(buf) < pos + size + 2:
            return None
        out += buf[pos:pos + size]
        pos += size + 2


def parse_response(buf: bytes, eof: bool = False) -> tuple[Resp, bytes] | None:
    """One complete final response off the front of `buf` (1xx interim
    responses are skipped) and the bytes after it; None while incomplete.
    A body without length runs to EOF (`eof` says the peer closed)."""
    while True:
        end = buf.find(b"\r\n\r\n")
        if end < 0:
            return None
        head = buf[:end].decode("latin-1").split("\r\n")
        parts = head[0].split(" ", 2)
        if len(parts) < 2 or not parts[0].startswith("HTTP/"):
            raise ValueError(f"not an HTTP response: {head[0][:60]!r}")
        status = int(parts[1])
        hdrs: dict[str, str] = {}
        for ln in head[1:]:
            k, _, v = ln.partition(":")
            hdrs[k.strip().lower()] = v.strip()
        rest = buf[end + 4:]
        if 100 <= status < 200:
            buf = rest
            continue
        close = (hdrs.get("connection", "").lower() == "close"
                 or parts[0] == "HTTP/1.0"
                 and hdrs.get("connection", "").lower() != "keep-alive")
        if status in (204, 304):
            return Resp(status, hdrs, b"", close), rest
        if "chunked" in hdrs.get("transfer-encoding", "").lower():
            got = _dechunk(rest)
            if got is None:
                return None
            return Resp(status, hdrs, got[0], close), rest[got[1]:]
        if "content-length" in hdrs:
            n = int(hdrs["content-length"])
            if len(rest) < n:
                return None
            return Resp(status, hdrs, rest[:n], close), rest[n:]
        if not eof:
            return None
        return Resp(status, hdrs, rest, True), b""


class Conn:
    """A raw client connection with a receive buffer."""

    def __init__(self, port: int) -> None:
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.buf = b""
        self.eof = False

    def send(self, data: bytes) -> bool:
        try:
            self.sock.sendall(data)
            return True
        except OSError:
            self.eof = True
            return False

    def _fill(self, deadline: float) -> bool:
        """Read once before `deadline`; False on timeout or EOF."""
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

    def response(self, bound: float) -> Resp | None:
        deadline = time.monotonic() + bound
        while True:
            got = parse_response(self.buf, self.eof)
            if got is not None:
                resp, self.buf = got
                return resp
            if not self._fill(deadline):
                got = parse_response(self.buf, self.eof)
                if got is not None:
                    resp, self.buf = got
                    return resp
                return None

    def quiet(self, window: float) -> bytes:
        """Bytes that arrive within `window` (unsolicited data)."""
        deadline = time.monotonic() + window
        while self._fill(deadline):
            pass
        out, self.buf = self.buf, b""
        return out

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.sock.close()


# --------------------------------------------------------------------------- #
# Oracle (pure).
# --------------------------------------------------------------------------- #

@dataclass
class Obs:
    """What one case did.  status 0 = no response (closed / timed out)."""
    status: int = 0
    cache: str = ""                # X-CT-Status of the bad request's answer
    body: bytes = b""
    closed: bool = False           # nginx ended the bad request's connection
    stored: tuple[int, int] = (0, 0)   # (used_bytes, markers) deltas
    victim_body: bytes = b""       # the primed (expected) victim body
    origin_bodies: tuple[bytes, ...] = ()  # origin bodies for the victim path
    victim_status: int = 0
    victim_cache: str = ""
    victim_got: bytes = b""
    unsolicited: bytes = b""       # arrived before the victim was sent
    leftover: bytes = b""          # arrived after the victim's response
    smuggle_seen: bool = False     # the origin got the smuggled tail
    sanitizer: str = ""            # non-empty: what went wrong
    primed: bool = True


def judge(case: Case, o: Obs) -> dict[str, str]:
    fail: dict[str, str] = {}
    st = o.status
    ok2 = 200 <= st < 300
    err = st >= 400 or (st == 0 and o.closed)
    if not o.primed:
        fail[HARNESS_PROP] = "victim was not a HIT before the case"
    if case.expect == "reject":
        if not err:
            fail["P1-reaction"] = f"status={st} (expected >= 400 or close)"
    elif not (ok2 or err) or (500 <= st and st != 501):
        fail["P1-reaction"] = f"status={st}"
    if ok2 and case.expect != "own" and o.stored != (0, 0):
        fail["P2-no-store"] = (f"stored used_bytes/markers delta={o.stored} "
                               f"cache={o.cache or '-'}")
    if ok2:
        if case.on_victim:
            if o.body != o.victim_body and o.body not in o.origin_bodies:
                fail["P3-own-key"] = ("victim-path answer is neither the "
                                      "cached nor an origin body: "
                                      f"{o.body[:60]!r}")
        elif case.expect == "own" and (o.cache == "HIT"
                                       or o.body == o.victim_body):
            fail["P3-own-key"] = ("served the victim's entry: "
                                  f"cache={o.cache} body={o.body[:60]!r}")
    if (o.victim_status != 200 or o.victim_cache != "HIT"
            or o.victim_got != o.victim_body):
        fail["P4-victim"] = (f"victim status={o.victim_status} "
                             f"cache={o.victim_cache or '-'} "
                             f"body={o.victim_got[:60]!r}")
    if o.unsolicited or o.leftover or o.smuggle_seen:
        fail["P5-no-desync"] = (f"unsolicited={o.unsolicited[:80]!r} "
                                f"leftover={o.leftover[:80]!r} "
                                f"smuggled-to-origin={o.smuggle_seen}")
    if err and o.stored != (0, 0):
        fail["P6-error-not-stored"] = (f"status={st} charged "
                                       f"used_bytes/markers={o.stored}")
    if o.sanitizer:
        fail["P7-sanitizer"] = o.sanitizer
    return fail


@dataclass
class Result:
    id: str
    failed: dict[str, str] = field(default_factory=dict)
    verdict: str = ""
    trace: dict[str, object] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Harness: one-worker nginx with its own origin.
# --------------------------------------------------------------------------- #

def _config(root, port: int, module, origin: int) -> str:
    load = f"load_module {module};\n" if module else ""
    common = (f"cache_turbo {ZONE}; cache_turbo_valid 60s; "
              "cache_turbo_lock off; "
              "add_header X-CT-Status $cache_turbo_status always; "
              f"proxy_pass http://127.0.0.1:{origin};")
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
        server_name {HOST};
        location = {ADMIN} {{ cache_turbo_admin {ZONE}; }}
        location /{LOC_RAW}/ {{ {common} }}
        location /{LOC_URI}/ {{ cache_turbo_key $uri; {common} }}
    }}
}}
"""


class _Rig:
    def __init__(self, ng: Nginx) -> None:
        base = ng.port
        self.origin = hl._Origin(base + PORT_OFFSETS["hostile_l2_origin"])
        self.tmp = ng.root.parent / "hostile-http"
        self.node = Nginx(ng.binary, ng.module, self.tmp,
                          base + PORT_OFFSETS["hostile_l2_node"],
                          self.origin.srv.server_address[1], ng.runner_raw,
                          ng.single_process)
        text = _config(self.tmp, self.node.port, ng.module,
                       self.origin.srv.server_address[1])

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

    def stats(self) -> tuple[int, int]:
        _, b, _ = fetch(self.node.port, ADMIN)
        d = json.loads(b)
        return int(d.get("used_bytes", 0)), int(d.get("markers", 0))

    def victim(self, loc: str, bound: float) -> Resp | None:
        c = Conn(self.node.port)
        try:
            c.send(victim_request(loc, close=True))
            return c.response(bound)
        finally:
            c.close()

    def prime(self, loc: str, bound: float) -> tuple[bool, bytes]:
        """Make the victim a HIT; (primed, cached body)."""
        for _ in range(3):
            r = self.victim(loc, bound)
            if r is not None and r.status == 200 and \
                    r.headers.get("x-ct-status") == "HIT":
                return True, r.body
            time.sleep(SETTLE_S)
        return False, b""


def _run_case(rig: _Rig, case: Case, tag: str) -> Result:
    res = Result(case.id)
    scale = sanitizer_time_scale()
    bound = READ_S * scale
    o = Obs()
    o.primed, o.victim_body = rig.prime(case.loc, bound)
    log0 = _errlog_window_start(rig.node)
    san0 = hl._sanitizer_count(rig)  # type: ignore[arg-type]
    workers0 = rig.workers()
    s0 = rig.stats()

    stats_error = ""
    conn = Conn(rig.node.port)
    try:
        conn.send(build_request(case, tag))
        if case.later:
            time.sleep(0.2 * scale)
            conn.send(case.later)
        try:
            r = conn.response(bound)
        except ValueError as exc:
            r = None
            res.trace["parse_error"] = str(exc)
        if r is not None:
            o.status, o.body = r.status, r.body
            o.cache = r.headers.get("x-ct-status", "")
        o.unsolicited = conn.quiet(QUIET_S * scale)
        o.closed = conn.eof or (r is not None and r.close)
        time.sleep(SETTLE_S * scale)
        try:
            s1 = rig.stats()
            o.stored = (s1[0] - s0[0], s1[1] - s0[1])
        except (OSError, ValueError) as exc:
            stats_error = f"stats unreachable: {exc}"

        victim_conn_ok = True
        if o.closed:
            conn.close()
            try:
                conn = Conn(rig.node.port)
            except OSError as exc:
                victim_conn_ok = False
                stats_error = stats_error or f"reconnect failed: {exc}"
        if victim_conn_ok and conn.send(victim_request(case.loc)):
            try:
                v = conn.response(bound)
            except ValueError as exc:
                v = None
                res.trace["victim_parse_error"] = str(exc)
            if v is not None:
                o.victim_status, o.victim_got = v.status, v.body
                o.victim_cache = v.headers.get("x-ct-status", "")
            o.leftover = conn.quiet(QUIET_S * scale)
    finally:
        conn.close()

    vp = victim_path(case.loc)
    o.origin_bodies = tuple(b.encode() for b in rig.origin.bodies(vp))
    o.smuggle_seen = bool(rig.origin.bodies(f"{SMUGGLE}-{tag}"))

    problems = []
    if stats_error:
        problems.append(stats_error)
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
        "status": o.status, "cache": o.cache, "closed": o.closed,
        "stored": list(o.stored), "body": o.body[:80].decode("latin-1"),
        "victim": [o.victim_status, o.victim_cache],
        "unsolicited": o.unsolicited[:120].decode("latin-1"),
        "leftover": o.leftover[:120].decode("latin-1"),
        "smuggle_seen": o.smuggle_seen,
        "log": [ln[:240] for ln in lines[:6]]})
    if not rig.alive():
        with contextlib.suppress(RuntimeError):
            rig.node.stop()
        rig.node.start()
    return res


def run_matrix(ng: Nginx, only: set[str] | None = None) -> list[Result]:
    ids = [c.id for c in build_cases()]
    unknown = sorted((only or set()) - set(ids))
    if unknown:
        raise ValueError(f"HOSTILE_HTTP_ONLY: unknown case id(s) {unknown}")
    known = known_red(ubsan_build(ng.binary))
    rig = _Rig(ng)
    rig.start()
    results: list[Result] = []
    try:
        for case in build_cases():
            if only and case.id not in only:
                continue
            tag = uuid.uuid4().hex[:8]
            res = _run_case(rig, case, tag)
            res.verdict = classify(case.id, set(res.failed), known)
            results.append(res)
            t = res.trace
            print(f"  hostile-http {res.verdict:<14} {case.id:<24} "
                  f"st={t['status']} cache={t['cache'] or '-'} "
                  f"closed={t['closed']} "
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


def test_hostile_http_matrix(ng: Nginx) -> None:
    """HARD-R1: hostile HTTP/1 request matrix plus the $uri-key negative
    control; see the module docstring."""
    only_env = os.environ.get("HOSTILE_HTTP_ONLY", "")
    only = {x.strip() for x in only_env.split(",") if x.strip()} or None
    results = run_matrix(ng, only)
    summary = summarize(results)
    print(f"  hostile-http summary: {json.dumps(summary, sort_keys=True)}")
    report = os.environ.get("HOSTILE_HTTP_REPORT")
    if report:
        with open(report, "w", encoding="utf-8") as fh:
            json.dump({"summary": summary, "cases": [
                {"id": r.id, "verdict": r.verdict, "failed": r.failed,
                 "trace": r.trace} for r in results]},
                fh, indent=1, sort_keys=True)
    if only is None:
        assert CONTROL_IDS <= {r.id for r in results}, "control did not run"
    bad = [r for r in results if r.verdict not in ACCEPTED]
    assert not bad, "hostile HTTP matrix: " + "; ".join(
        f"{r.id}={r.verdict} {r.failed}" for r in bad)
