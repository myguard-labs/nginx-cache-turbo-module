"""cache-turbo runtime tests -- request resource bounds on the lookup path
under nginx-legal hostile inputs (HARD-R4).

Inputs nginx itself accepts (``client_header_buffer_size`` and
``large_client_header_buffers`` are raised; ``max_headers`` is also raised on
nginx 1.29.8+ and Angie 1.8.0+, where that directive and its default 1000-line
limit exist) so 4096 Cookie lines are legal. Earlier releases have no
header-count limit, so the unsupported directive is omitted and the same cases
still run; ``HDR_BUF`` is the buffer size. A 4xx from nginx's own limits is not
the module's path and fails the case):

  args    10000 query args, on locations keyed ``$host$uri
          $cache_turbo_normalized_args`` with ``cache_turbo_normalize_max_args``
          at its compiled-in default (64), at 10000, at 1000 (lowered) and
          at 0 (unlimited).
  cookies 4096 cookies as 4096 Cookie lines and as one Cookie line, on a
          location with a session-bypass preset (``cache_turbo_backend
          wordpress``) that scans the cookies.
  vary    1000 values of each Vary-relevant request header the module folds
          into the variant key: Accept-Language, Origin and Accept-Encoding
          as 1000 lines, and Accept-Encoding as 1000 list tokens.
  uri     the longest request line nginx accepts (``HDR_BUF - 2``) on the
          default key (Host + unparsed URI).

MEASUREMENT.  The CI debug build carries ``--with-debug`` and
``-DNGX_DEBUG_PALLOC=1`` (ci/tools/ci-build.sh), so every ``ngx_palloc`` /
``ngx_pnalloc`` is a pool large-alloc, i.e. one ``ngx_alloc`` and one debug
line ``<conn> malloc: <ptr>:<size>`` at level ``debug_alloc`` (nginx 1.31.3
src/os/unix/ngx_alloc.c ``ngx_alloc``, src/core/ngx_palloc.c
``ngx_palloc_large``).  The error log of the node is set to ``debug_alloc``
(nothing else is logged, so a 10000-arg request costs a few hundred lines),
every request carries ``Connection: close`` on its own connection, and the
bytes of a request are the sum of the ``malloc:`` sizes on that connection's
``*<n>`` prefix (``$connection`` is echoed in ``X-B-Conn``): the request and
connection pools together.  ``memalign:`` (pool creation) and
the non-pool allocations carry no ``*<n>`` of a pool log or are constant per
request, so they cancel against the clean baseline.  The count is exact and
stable: the same request measured twice differs by 0 bytes (H-det).  The
verdict is on MODULE-attributable bytes: the request's count minus the same
request on a location without cache_turbo (``/by/`` plain proxy for the
MISS, ``/bz/`` plain ``return`` for the HIT), so nginx core steps (a request
line at the limit moves into a second large header buffer, doubling the
total) are not charged to the module; the raw totals are shaped too and
reported (``total-miss``/``total-hit``) but not asserted.  Pool
destruction (``free: <ptr>, unused: <n>``) is the settle signal.  When the
binary lacks ``--with-debug`` or ``-DNGX_DEBUG_PALLOC=1`` (the ASan+UBSan
build) the byte verdict is SKIPPED with that reason and the same inputs
still run for memory safety (P7).

GROWTH VERDICT.  Per input the request is sent at sizes N/4, N/2 and N (and
a clean baseline of the same shape at size 1 or a short URI), on a MISS and
on the HIT repeats.  ``growth()`` takes bytes over the baseline per unit at
each size: ``flat`` (all growth within FLAT_BYTES), ``linear`` (per-unit
bytes within a factor GROWTH_TOL of the first size), ``sublinear`` (falls
by more than that) or ``superlinear`` (rises by more).  A quadratic path
doubles its per-unit bytes with each doubling of N, far outside the
tolerance.  Time per request versus the clean baseline is reported in the
trace and printed, never asserted; the stored ``used_bytes`` per MISS is
shaped as ``stored`` (key-metadata growth, HARD-X1 input), also not asserted.

Properties:

  B-served     200 on every size (nginx's own limit is not the module's
               path), first request not a HIT, repeat a HIT.
  B-cap        args only: the normalized key is engaged exactly when the
               arg count is within the location's ``cache_turbo_normalize_max_args``
               (0 = unlimited, default 64); above it the module falls back
               to keying the raw arg string (the documented fallback, it
               does not bypass the cache).  Observed through ``$b_norm``
               (a ``map`` on ``$cache_turbo_normalized_args``): "sorted"
               when the smallest name leads, "raw" when the first sent leads.
  B-linear     bytes on the MISS and on the HIT grow at most linearly.
  H-det        two HIT repeats at the same size count the same bytes.
  H-bytes      on a debug build every clean request produced malloc lines.
  H-baseline   the plain-proxy / plain-return baselines answered 2xx (a 502
               baseline is a broken rig, so its bytes are not subtracted).
  H-settle     every measured request's pool was destroyed (connection and
               request pool) before the settle deadline.
  P7-sanitizer no sanitizer report, no crit/alert/emerg log line, nginx and
               its worker alive.

Negative control: CTRL-BOUNDS-CAP-LOWERED sends the 2500..10000-arg input to
a location whose cap is lowered to 1000 but judges it against the expectation
of the 10000 cap; B-cap MUST fail (the normalized key is not engaged: the
raw-key fallback).  A lowered cap in the location config of ARGS-CAP-10000
flips that case the same way (mutant run, see the evidence file).

Uncapped (no module cap, linear) inputs are green and recorded in
memory/labs/nginx-cache-turbo-module/hard-l2-evidence-20261118.md, section
HARD-R4, as HARD-R3 input (HARD-X1 for key-metadata growth: the stored
``used_bytes`` per MISS is reported per input).  A superlinear path would go
in BOUNDS_KNOWN_RED with a stable ID and never turns default CI red.

Environment: HOSTILE_BOUNDS_ONLY=ID[,ID...] runs a subset;
HOSTILE_BOUNDS_REPORT=path writes the per-case results as JSON.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import os
import re
import statistics
import subprocess
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field

from test_runtime_base import *
from test_runtime_base import _errlog_window_start

from areas import hostile_http as hh
from areas import hostile_l2 as hl

__all__ = ["test_hostile_bounds_matrix"]

HOST = "localhost"
HDR_BUF = 131072          # client_header_buffer_size and each large buffer
ZONE = "bb"
ADMIN = "/_bb"
READ_S = 5.0              # per-response read bound (sanitizer-scaled)
SETTLE_S = 0.05
DESTROY_WAIT_S = 5.0      # wait for the connection's pool destruction lines
MAX_HEADERS = 8192        # nginx `max_headers` (default 1000 header lines)
NGINX_MAX_HEADERS_SINCE = (1, 29, 8)
ANGIE_MAX_HEADERS_SINCE = (1, 8, 0)
DEFAULT_CAP = 64          # cache_turbo_normalize_max_args compiled-in default
GROWTH_TOL = 1.5          # per-unit bytes may rise/fall by this factor
FLAT_BYTES = 1024         # growth under this is "flat" (constant overhead)
URI_LINE = HDR_BUF - 2    # longest request line nginx accepts (see hostile_http)
URI_BASE = 64             # clean-baseline request line length

PROPS = ("B-served", "B-cap", "B-linear", "P7-sanitizer")
HARNESS_PROPS = ("H-det", "H-bytes", "H-baseline", "H-settle")

# Per-location arg cap (None: directive absent -> compiled-in default).
LOC_ARGS_DEFAULT = "ba"
LOC_ARGS_10000 = "bc"
LOC_ARGS_1000 = "bl"
LOC_ARGS_UNLIMITED = "bu"
LOC_COOKIE = "bk"
LOC_VARY = "bv"
LOC_URI = "bp"
LOC_PLAIN_PROXY = "by"    # no cache_turbo: nginx core + proxy only
LOC_PLAIN_RETURN = "bz"   # no cache_turbo: nginx core only
LOC_CAPS: dict[str, int] = {
    LOC_ARGS_DEFAULT: DEFAULT_CAP,
    LOC_ARGS_10000: 10000,
    LOC_ARGS_1000: 1000,
    LOC_ARGS_UNLIMITED: 0,
}


# --------------------------------------------------------------------------- #
# Pure helpers: debug-log parse, growth classifier, expectations.
# --------------------------------------------------------------------------- #

_MALLOC = re.compile(r"\*(\d+) malloc: [0-9A-Fa-fx]+:(\d+)\s*$")
_DESTROY = re.compile(r"\*(\d+) free: [0-9A-Fa-fx]+, unused: \d+\s*$")


def alloc_bytes(lines: Sequence[str], conn: int) -> tuple[int, int]:
    """(bytes, count) of the ``malloc: <ptr>:<size>`` debug lines logged on
    connection `conn` (``*<conn>`` prefix); other connections, ``memalign``,
    ``free`` and unrelated lines are ignored."""
    total = count = 0
    for ln in lines:
        m = _MALLOC.search(ln)
        if m and int(m.group(1)) == conn:
            total += int(m.group(2))
            count += 1
    return total, count


def pool_destroys(lines: Sequence[str], conn: int) -> int:
    """Number of pool destruction lines (``free: <ptr>, unused: <n>``) on
    connection `conn`: the request pool and the connection pool."""
    return sum(1 for ln in lines
               if (m := _DESTROY.search(ln)) and int(m.group(1)) == conn)


def growth(points: Sequence[tuple[int, int]], base: tuple[int, int],
           tol: float = GROWTH_TOL, flat: int = FLAT_BYTES
           ) -> tuple[str, list[float]]:
    """Growth shape of (size, bytes) `points` over the clean `base` point.

    Returns (shape, per-unit bytes at each point) where per-unit =
    (bytes - base bytes) / (size - base size).  Shapes: flat, linear,
    sublinear (fine) and superlinear (a defect: per-unit bytes grow with
    size).  Every point's size must exceed the baseline's."""
    n0, b0 = base
    deltas = []
    for n, b in points:
        if n <= n0:
            raise ValueError(f"size {n} not above the baseline {n0}")
        deltas.append((n - n0, b - b0))
    per = [db / dn for dn, db in deltas]
    if all(db <= flat for _, db in deltas):
        return "flat", per
    if per[0] <= 0:
        return "superlinear", per
    if max(per) / per[0] > tol:
        return "superlinear", per
    if min(per) / per[0] < 1 / tol:
        return "sublinear", per
    return "linear", per


def expected_norm(n: int, cap: int) -> str:
    """"sorted" when the normalized key is engaged for `n` kept args under a
    cap (0 = unlimited), "raw" for the documented over-cap raw-key fallback."""
    return "sorted" if cap == 0 or n <= cap else "raw"


def debug_alloc_available(version_text: str) -> tuple[bool, str]:
    """(usable, reason) from ``nginx -V``: the byte count needs a debug build
    where every pool allocation is a logged large alloc."""
    if "--with-debug" not in version_text:
        return False, "binary built without --with-debug (no debug log)"
    if "NGX_DEBUG_PALLOC=1" not in version_text:
        return False, ("binary lacks -DNGX_DEBUG_PALLOC=1: small pool "
                       "allocations are not logged, so the byte count "
                       "is not exact")
    return True, ""


def supports_max_headers(version_text: str) -> bool:
    """Whether the server has the max_headers directive and its default cap."""
    boundaries = (
        (r"Angie version: Angie/(\d+)\.(\d+)\.(\d+)", ANGIE_MAX_HEADERS_SINCE),
        (r"nginx version: nginx/(\d+)\.(\d+)\.(\d+)", NGINX_MAX_HEADERS_SINCE),
    )
    for pattern, boundary in boundaries:
        match = re.search(pattern, version_text)
        if match is not None:
            return tuple(int(part) for part in match.groups()) >= boundary
    return False


# --------------------------------------------------------------------------- #
# Cases and request builders.
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Case:
    id: str
    kind: str                      # args | cookie-lines | cookie-line |
    #                                vary-lang | vary-origin | vary-ae-lines |
    #                                vary-ae-tokens | uri
    loc: str
    base: int                      # clean baseline size
    sizes: tuple[int, ...]         # N/4, N/2, N
    control: bool = False
    expect_cap: int | None = None  # args: cap the verdict is judged against
    module_cap: str = ""           # documented module cap (evidence)
    note: str = ""

    @property
    def cap(self) -> int | None:
        """Cap of this case's location (args only)."""
        return LOC_CAPS.get(self.loc) if self.kind == "args" else None


def quarters(n: int) -> tuple[int, int, int]:
    return n // 4, n // 2, n


ARGS = quarters(10000)
COOKIES = quarters(4096)
VARY = quarters(1000)
URI = quarters(URI_LINE)

ARG_NOTE = ("cache_turbo_normalize_max_args; above it normalization is "
            "skipped and the raw arg string is keyed (no bypass)")
NO_CAP = "none in the module (nginx large_client_header_buffers bounds it)"


def build_cases() -> list[Case]:
    return [
        Case("ARGS-DEFAULT-CAP", "args", LOC_ARGS_DEFAULT, 1, ARGS,
             module_cap=f"{ARG_NOTE}; default {DEFAULT_CAP}"),
        Case("ARGS-CAP-10000", "args", LOC_ARGS_10000, 1, ARGS,
             module_cap=f"{ARG_NOTE}; set to 10000"),
        Case("ARGS-CAP-1000", "args", LOC_ARGS_1000, 1, ARGS,
             module_cap=f"{ARG_NOTE}; set to 1000"),
        Case("ARGS-UNLIMITED", "args", LOC_ARGS_UNLIMITED, 1, ARGS,
             module_cap=f"{ARG_NOTE}; 0 = unlimited (O(n^2) sort, time "
                        "advisory)"),
        Case("COOKIE-LINES-4096", "cookie-lines", LOC_COOKIE, 1, COOKIES,
             module_cap=NO_CAP),
        Case("COOKIE-ONE-LINE-4096", "cookie-line", LOC_COOKIE, 1, COOKIES,
             module_cap=NO_CAP),
        Case("VARY-LANG-LINES-1000", "vary-lang", LOC_VARY, 1, VARY,
             module_cap=NO_CAP),
        Case("VARY-ORIGIN-LINES-1000", "vary-origin", LOC_VARY, 1, VARY,
             module_cap=NO_CAP),
        Case("VARY-AE-LINES-1000", "vary-ae-lines", LOC_VARY, 1, VARY,
             module_cap=NO_CAP),
        Case("VARY-AE-TOKENS-1000", "vary-ae-tokens", LOC_VARY, 1, VARY,
             module_cap=NO_CAP),
        Case("URI-MAX", "uri", LOC_URI, URI_BASE, URI,
             module_cap=NO_CAP),
        # Negative control: the lowered-cap location judged against the
        # 10000 cap's expectation; B-cap MUST fail.
        Case("CTRL-BOUNDS-CAP-LOWERED", "args", LOC_ARGS_1000, 1, ARGS,
             control=True, expect_cap=10000,
             note="cap lowered to 1000, judged as 10000"),
    ]


CONTROL_EXPECTED: dict[str, frozenset[str]] = {
    "CTRL-BOUNDS-CAP-LOWERED": frozenset({"B-cap"}),
}
CONTROL_IDS = frozenset(CONTROL_EXPECTED)

# Known superlinear (or otherwise red) paths: id -> properties.  None found
# on the lookup path at the HARD-R4 sizes; see the evidence file.
BOUNDS_KNOWN_RED: dict[str, frozenset[str]] = {}
ACCEPTED = frozenset({"green", "known-red", "control-ok"})


def classify(case_id: str, failed: set[str] | frozenset[str],
             known: dict[str, frozenset[str]] | None = None) -> str:
    """green | known-red | control-ok are acceptable; red | xpass |
    known-red-drift | control-broken | harness-fail fail the matrix."""
    known = BOUNDS_KNOWN_RED if known is None else known
    if set(failed) & set(HARNESS_PROPS):
        return "harness-fail"
    if case_id in CONTROL_EXPECTED:
        ok = set(failed) == CONTROL_EXPECTED[case_id]
        return "control-ok" if ok else "control-broken"
    if case_id in known:
        if not failed:
            return "xpass"
        return "known-red" if set(failed) <= known[case_id] else \
            "known-red-drift"
    return "red" if failed else "green"


def target(case: Case, tag: str, n: int) -> str:
    """The request target for `case` at size `n`."""
    # One key per size: cookies and Vary headers are not in the default key.
    path = f"/{case.loc}/{tag}-{n}"
    if case.kind == "args":
        # Descending names: the normalized (sorted) key starts with p00001,
        # the raw fallback with the first name sent.
        return path + "?" + "&".join(f"p{i:05d}=v" for i in range(n, 0, -1))
    if case.kind == "uri":
        return hh.line_target(n, prefix=f"/{case.loc}/{tag}-")
    return path


def header_lines(case: Case, n: int) -> list[str]:
    """Extra request header lines for `case` at size `n`."""
    k = case.kind
    if k == "cookie-lines":
        return [f"Cookie: c{i:04d}=v" for i in range(n)]
    if k == "cookie-line":
        return ["Cookie: " + "; ".join(f"c{i:04d}=v" for i in range(n))]
    if k == "vary-lang":
        return [f"Accept-Language: l{i:04d}" for i in range(n)]
    if k == "vary-origin":
        return [f"Origin: http://o{i:04d}.example" for i in range(n)]
    if k == "vary-ae-lines":
        return [f"Accept-Encoding: c{i:04d}" for i in range(n)]
    if k == "vary-ae-tokens":
        return ["Accept-Encoding: " + ", ".join(f"c{i:04d}"
                                                for i in range(n))]
    return []


def build_request(case: Case, tag: str, n: int, loc: str = "") -> bytes:
    if loc:
        case = dataclasses.replace(case, loc=loc)
    lines = [f"GET {target(case, tag, n)} HTTP/1.1", f"Host: {HOST}",
             "Connection: close"]
    lines.extend(header_lines(case, n))
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


# --------------------------------------------------------------------------- #
# Oracle (pure).
# --------------------------------------------------------------------------- #

@dataclass
class Req:
    """One measured request."""
    status: int = 0
    cache: str = ""                # X-CT-Status
    norm: str = ""                 # X-B-Norm
    conn: int = 0
    bytes: int = 0                 # pool bytes (malloc: lines)
    mallocs: int = 0
    destroys: int = 0
    ms: float = 0.0
    settled: bool = True           # False: pool destroys <2 at the deadline


@dataclass
class Point:
    n: int
    miss: Req = field(default_factory=Req)
    hit: Req = field(default_factory=Req)
    hit2: Req = field(default_factory=Req)
    plain_proxy: Req = field(default_factory=Req)   # same request, no module
    plain_return: Req = field(default_factory=Req)  # same, no module/proxy
    stored: int = 0                # used_bytes delta of the MISS


@dataclass
class Judged:
    failed: dict[str, str] = field(default_factory=dict)
    shapes: dict[str, str] = field(default_factory=dict)
    per_unit: dict[str, list[float]] = field(default_factory=dict)
    bytes_note: str = ""


def judge(case: Case, base: Point, pts: Sequence[Point],
          bytes_ok: bool, reason: str = "") -> Judged:
    j = Judged()
    fail = j.failed
    for p in (base, *pts):
        if p.miss.status != 200 or p.miss.cache == "HIT":
            fail.setdefault("B-served",
                            f"n={p.n} first request status={p.miss.status} "
                            f"cache={p.miss.cache or '-'}")
        if p.hit.status != 200 or p.hit.cache != "HIT":
            fail.setdefault("B-served",
                            f"n={p.n} repeat status={p.hit.status} "
                            f"cache={p.hit.cache or '-'}")
        if p.hit2.status != 200 or p.hit2.cache != "HIT":
            fail.setdefault("B-served",
                            f"n={p.n} second repeat status={p.hit2.status} "
                            f"cache={p.hit2.cache or '-'}")
        # A non-2xx plain baseline is a broken rig whether or not bytes are
        # judged (a 502 from the plain proxy location).
        for name, b in (("plain proxy", p.plain_proxy),
                        ("plain return", p.plain_return)):
            if not 200 <= b.status < 300:
                fail["H-baseline"] = (f"n={p.n}: {name} baseline status="
                                      f"{b.status}")
    if case.kind == "args":
        cap = case.expect_cap if case.expect_cap is not None else case.cap
        assert cap is not None
        for p in pts:
            want = expected_norm(p.n, cap)
            if p.miss.norm != want or p.hit.norm != want:
                fail.setdefault(
                    "B-cap",
                    f"n={p.n} cap={cap}: normalized key {p.miss.norm!r}/"
                    f"{p.hit.norm!r}, want {want!r}")
    # Key-metadata growth (HARD-X1 input): bytes the MISS charged to the zone
    # per size.  Reported, not asserted.
    j.shapes["stored"], j.per_unit["stored"] = growth(
        [(p.n, p.stored) for p in pts], (base.n, base.stored))
    if not bytes_ok:
        j.bytes_note = f"byte verdict skipped: {reason}"
        return j
    for p in (base, *pts):
        for name in ("miss", "hit", "hit2", "plain_proxy", "plain_return"):
            if not getattr(p, name).settled:
                fail["H-settle"] = (f"n={p.n}: {name} request pool not "
                                    "destroyed before the settle deadline")
    if "H-settle" in fail or "H-baseline" in fail:
        return j
    for p in (base, *pts):
        if p.miss.mallocs == 0 or p.hit.mallocs == 0:
            fail["H-bytes"] = f"n={p.n}: no malloc debug lines for the request"
        if p.hit.bytes != p.hit2.bytes:
            fail["H-det"] = (f"n={p.n}: repeat HIT counted {p.hit.bytes} then "
                             f"{p.hit2.bytes} bytes")
    if "H-bytes" in fail or "H-det" in fail:
        return j
    for p in (base, *pts):
        if p.plain_proxy.mallocs == 0 or p.plain_return.mallocs == 0:
            fail["H-bytes"] = f"n={p.n}: no malloc lines for the plain request"
            return j
    # Module-attributable bytes: the request's bytes minus the same request
    # on a location without cache_turbo (the MISS against a plain proxy, the
    # HIT against a plain `return`), so nginx core steps (a request line at
    # the limit moves into a second large header buffer) are not charged to
    # the module.  The raw totals are reported too.
    series = {
        "miss": lambda p: p.miss.bytes - p.plain_proxy.bytes,
        "hit": lambda p: p.hit.bytes - p.plain_return.bytes,
        "total-miss": lambda p: p.miss.bytes,
        "total-hit": lambda p: p.hit.bytes,
    }
    for name, pick in series.items():
        shape, per = growth([(p.n, pick(p)) for p in pts],
                            (base.n, pick(base)))
        j.shapes[name] = shape
        j.per_unit[name] = per
        if shape == "superlinear" and not name.startswith("total"):
            fail["B-linear"] = (f"{name} module bytes superlinear: per-unit "
                                f"{[round(x, 2) for x in per]}")
    return j


@dataclass
class Result:
    id: str
    failed: dict[str, str] = field(default_factory=dict)
    verdict: str = ""
    bytes_skipped: bool = False
    trace: dict[str, object] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Harness: one-worker nginx with an in-process origin server block.
# --------------------------------------------------------------------------- #

def _config(root, port: int, module, origin: int, level: str,
            has_max_headers: bool) -> str:
    load = f"load_module {module};\n" if module else ""
    max_headers = (f"        max_headers {MAX_HEADERS};\n"
                   if has_max_headers else "")
    common = (f"cache_turbo {ZONE}; cache_turbo_valid 60s; "
              "cache_turbo_lock off; "
              "add_header X-CT-Status $cache_turbo_status always; "
              "add_header X-B-Conn $connection always; "
              "add_header X-B-Norm $b_norm always; "
              f"proxy_pass http://127.0.0.1:{origin};")
    nkey = "cache_turbo_key $host$uri$cache_turbo_normalized_args;"
    return f"""{load}worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/logs/error.log {level};
events {{ worker_connections 256; }}
http {{
    access_log off;
    client_header_buffer_size {HDR_BUF};
    large_client_header_buffers 4 {HDR_BUF};
    client_header_timeout 10s;
    keepalive_timeout 0;
    cache_turbo_zone name={ZONE} 16m;
    map $cache_turbo_normalized_args $b_norm {{
        default other;
        "~^\\?p00001=" sorted;
        "~^\\?p[0-9]+=" raw;
    }}
    server {{
        listen 127.0.0.1:{origin};
{max_headers}        client_header_buffer_size {HDR_BUF};
        large_client_header_buffers 4 {HDR_BUF};
        location / {{
            add_header Cache-Control "max-age=60";
            add_header Vary "Accept-Encoding, Accept-Language, Origin";
            return 200 "origin\\n";
        }}
    }}
    server {{
        listen 127.0.0.1:{port};
        server_name {HOST};
{max_headers}        location = {ADMIN} {{ cache_turbo_admin {ZONE}; }}
        location /{LOC_ARGS_DEFAULT}/ {{ {nkey} {common} }}
        location /{LOC_ARGS_10000}/ {{ {nkey} cache_turbo_normalize_max_args 10000; {common} }}
        location /{LOC_ARGS_1000}/ {{ {nkey} cache_turbo_normalize_max_args 1000; {common} }}
        location /{LOC_ARGS_UNLIMITED}/ {{ {nkey} cache_turbo_normalize_max_args 0; {common} }}
        location /{LOC_COOKIE}/ {{ cache_turbo_backend wordpress; {common} }}
        location /{LOC_VARY}/ {{ {common} }}
        location /{LOC_URI}/ {{ {common} }}
        location /{LOC_PLAIN_PROXY}/ {{
            add_header X-B-Conn $connection always;
            proxy_pass http://127.0.0.1:{origin};
        }}
        location /{LOC_PLAIN_RETURN}/ {{
            add_header X-B-Conn $connection always;
            return 200 "plain\\n";
        }}
    }}
}}
"""


class _Rig:
    def __init__(self, ng: Nginx, level: str, has_max_headers: bool) -> None:
        base = ng.port
        origin_port = base + PORT_OFFSETS["hostile_l2_origin"]
        self.tmp = ng.root.parent / "hostile-bounds"
        self.node = Nginx(ng.binary, ng.module, self.tmp,
                          base + PORT_OFFSETS["hostile_l2_node"],
                          origin_port, ng.runner_raw, ng.single_process)
        text = _config(self.tmp, self.node.port, ng.module, origin_port,
                       level, has_max_headers)

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
        self.node.stop()

    def workers(self) -> frozenset[int]:
        p = self.node.process
        return hl.descendants(p.pid) if p is not None else frozenset()

    def alive(self) -> bool:
        p = self.node.process
        return p is not None and p.poll() is None

    def used_bytes(self) -> int:
        _, b, _ = fetch(self.node.port, ADMIN)
        return int(json.loads(b).get("used_bytes", 0))

    def log_from(self, off: int) -> list[str]:
        return hl._log_from(self, off)  # type: ignore[arg-type]


def _request(rig: _Rig, raw: bytes, bytes_ok: bool, scale: float) -> Req:
    """Send `raw` on a fresh connection, read the answer and (debug build)
    count the connection's pool bytes from the debug_alloc log."""
    r = Req()
    off = _errlog_window_start(rig.node)
    conn = hh.Conn(rig.node.port)
    t0 = time.perf_counter()
    try:
        conn.send(raw)
        resp = conn.response(READ_S * scale)
        r.ms = (time.perf_counter() - t0) * 1000.0
        conn.quiet(0.2 * scale)       # until nginx closes (Connection: close)
    finally:
        conn.close()
    if resp is None:
        return r
    r.status = resp.status
    r.cache = resp.headers.get("x-ct-status", "")
    r.norm = resp.headers.get("x-b-norm", "")
    with contextlib.suppress(ValueError):
        r.conn = int(resp.headers.get("x-b-conn", "0"))
    if bytes_ok and r.conn:
        deadline = time.monotonic() + DESTROY_WAIT_S * scale
        while True:
            lines = rig.log_from(off)
            r.destroys = pool_destroys(lines, r.conn)
            if r.destroys >= 2:
                break
            if time.monotonic() > deadline:
                r.settled = False
                break
            time.sleep(0.02)
        r.bytes, r.mallocs = alloc_bytes(lines, r.conn)
    return r


def _measure(rig: _Rig, case: Case, tag: str, n: int, bytes_ok: bool,
             scale: float) -> Point:
    p = Point(n)
    raw = build_request(case, tag, n)
    u0 = rig.used_bytes()
    p.miss = _request(rig, raw, bytes_ok, scale)
    time.sleep(SETTLE_S * scale)
    p.stored = rig.used_bytes() - u0
    p.hit = _request(rig, raw, bytes_ok, scale)
    p.hit2 = _request(rig, raw, bytes_ok, scale)
    p.plain_proxy = _request(
        rig, build_request(case, tag, n, LOC_PLAIN_PROXY), bytes_ok, scale)
    p.plain_return = _request(
        rig, build_request(case, tag, n, LOC_PLAIN_RETURN), bytes_ok, scale)
    return p


def _point_json(p: Point) -> dict[str, object]:
    return {"n": p.n, "stored": p.stored,
            "miss": [p.miss.status, p.miss.cache, p.miss.norm, p.miss.bytes,
                     p.miss.mallocs, round(p.miss.ms, 2)],
            "hit": [p.hit.status, p.hit.cache, p.hit.norm, p.hit.bytes,
                    p.hit.mallocs, round(p.hit.ms, 2)],
            "hit2_bytes": p.hit2.bytes,
            "plain_proxy_bytes": p.plain_proxy.bytes,
            "plain_return_bytes": p.plain_return.bytes}


def _run_case(rig: _Rig, case: Case, bytes_ok: bool, reason: str) -> Result:
    res = Result(case.id, bytes_skipped=not bytes_ok)
    scale = sanitizer_time_scale()
    tag = uuid.uuid4().hex[:8]
    log0 = _errlog_window_start(rig.node)
    san0 = hl._sanitizer_count(rig)  # type: ignore[arg-type]
    workers0 = rig.workers()
    problems = []
    base = Point(case.base)
    pts: list[Point] = []
    try:
        base = _measure(rig, case, tag, case.base, bytes_ok, scale)
        pts = [_measure(rig, case, tag, n, bytes_ok, scale)
               for n in case.sizes]
    except (OSError, ValueError) as exc:
        problems.append(f"transport: {type(exc).__name__}: {exc}")
    if hl._sanitizer_count(rig) > san0:  # type: ignore[arg-type]
        problems.append("new sanitizer report")
    if not rig.alive():
        problems.append("nginx died")
    else:
        lost = hl.worker_loss(workers0, rig.workers())
        if lost:
            problems.append(f"worker(s) {sorted(lost)} exited")
    lines = rig.log_from(log0)
    other = [ln for ln in lines if any(f"[{lv}]" in ln for lv in (
        "info", "notice", "warn", "error", "crit", "alert", "emerg"))]
    fatal = [ln for ln in lines
             if any(f"[{lv}]" in ln for lv in ("crit", "alert", "emerg"))]
    if fatal:
        problems.append(fatal[0][:200])

    if len(pts) == len(case.sizes):
        j = judge(case, base, pts, bytes_ok, reason)
    else:
        j = Judged(failed={"B-served": "measurement aborted"})
    if problems:
        j.failed["P7-sanitizer"] = "; ".join(problems)
    res.failed = j.failed
    t_base = base.hit.ms or 1e-9
    res.trace = {
        "shapes": j.shapes,
        "per_unit": {k: [round(x, 3) for x in v]
                     for k, v in j.per_unit.items()},
        "bytes_note": j.bytes_note,
        "module_cap": case.module_cap,
        "log": [ln[:240] for ln in other[:6]],
        "baseline": _point_json(base),
        "points": [_point_json(p) for p in pts],
        "stored_per_unit": [round(p.stored / max(p.n - base.n, 1), 3)
                            for p in pts],
        "time_ratio_hit_advisory": [round(statistics.median(
            (p.hit.ms, p.hit2.ms)) / t_base, 2) for p in pts],
    }
    if not rig.alive():
        with contextlib.suppress(RuntimeError):
            rig.node.stop()
        rig.node.start()
    return res


def run_matrix(ng: Nginx, only: set[str] | None = None) -> list[Result]:
    ids = [c.id for c in build_cases()]
    unknown = sorted((only or set()) - set(ids))
    if unknown:
        raise ValueError(f"HOSTILE_BOUNDS_ONLY: unknown case id(s) {unknown}")
    proc = subprocess.run([str(ng.binary), "-V"], capture_output=True,
                          text=True, timeout=30, check=False)
    bytes_ok, reason = debug_alloc_available(proc.stdout + proc.stderr)
    rig = _Rig(ng, "debug_alloc" if bytes_ok else "info",
               supports_max_headers(proc.stdout + proc.stderr))
    rig.start()
    results: list[Result] = []
    try:
        for case in build_cases():
            if only and case.id not in only:
                continue
            res = _run_case(rig, case, bytes_ok, reason)
            res.verdict = classify(case.id, set(res.failed))
            results.append(res)
            t = res.trace
            per = t["per_unit"]
            assert isinstance(per, dict)
            print(f"  hostile-bounds {res.verdict:<14} {case.id:<26} "
                  f"shapes={t['shapes']} {t['bytes_note']} "
                  f"per-unit(hit)={per.get('hit', '-')} "
                  f"stored/unit={t['stored_per_unit']} "
                  f"time-x(advisory)={t['time_ratio_hit_advisory']} "
                  f"{'; '.join(f'{k}: {v}' for k, v in res.failed.items())}",
                  flush=True)
    finally:
        rig.stop()
    return results


def summarize(results: list[Result]) -> dict[str, int]:
    out: dict[str, int] = {"total": len(results)}
    for r in results:
        out[r.verdict] = out.get(r.verdict, 0) + 1
    out["bytes-skipped"] = sum(1 for r in results if r.bytes_skipped)
    return out


def test_hostile_bounds_matrix(ng: Nginx) -> None:
    """HARD-R4: request resource bounds under nginx-legal hostile inputs plus
    the lowered-cap negative control; see the module docstring."""
    only_env = os.environ.get("HOSTILE_BOUNDS_ONLY", "")
    only = {x.strip() for x in only_env.split(",") if x.strip()} or None
    results = run_matrix(ng, only)
    summary = summarize(results)
    print(f"  hostile-bounds summary: {json.dumps(summary, sort_keys=True)}")
    report = os.environ.get("HOSTILE_BOUNDS_REPORT")
    if report:
        with open(report, "w", encoding="utf-8") as fh:
            json.dump({"summary": summary, "cases": [
                {"id": r.id, "verdict": r.verdict, "failed": r.failed,
                 "trace": r.trace} for r in results]},
                fh, indent=1, sort_keys=True)
    if only is None:
        assert CONTROL_IDS <= {r.id for r in results}, "control did not run"
    bad = [r for r in results if r.verdict not in ACCEPTED]
    assert not bad, "hostile bounds matrix: " + "; ".join(
        f"{r.id}={r.verdict} {r.failed}" for r in bad)
