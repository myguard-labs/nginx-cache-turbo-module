"""cache-turbo runtime tests -- hostile L2 reply matrix (HARD-L2).

Scripted Redis and memcached peers (ci/tools/hostile_peer.py) answer every
command benignly except ONE armed command per case, which gets a hostile
reply: a bad ``$len``, a wrong reply type, a valid reply followed by a second
one, a reply for another key, a CRLF split across reads, a byte drip against
the read timeout, a close or RST mid-reply, or no reply at all.  Families:
Redis GET, SET, lock SET, the AUTH/SELECT preamble of a DSN backend (/ra/),
the admin purge commands DEL (?key=), SCAN (?all=1) and SSCAN (?tag=), and
memcached get/set (/m/: VALUE key mismatch, flags/bytes overflow,
SERVER_ERROR/CLIENT_ERROR...), and the read-deadline re-arm probes
GET-DRIP-REARM / MCGET-DRIP-REARM (/rs/, /ms/: timeout=900ms, a drip slower
than nginx's 300 ms timer lazy delay).

The admin families have their own request driver: a seed GET puts the case
key in L1 first, then the purge POST is the faulted request.  For them P1
means "the admin reply is honest" (Case.admin: a fault must not be reported
as a 200 success, a valid reply must be) and P2 means "no L2 hit, and the
purged key's next request is a fresh origin fetch" (SSCAN: the member list
is the peer's, so which L1 entries go is peer-chosen -- only "an origin
body" is asserted).  /ra/ runs without keepalive so every L2 op sends the
preamble and the armed AUTH/SELECT always fires; there is no pool to desync,
so its P4 reduces to "the faulted connection is closed".

Every case is judged on the same six properties (PROPS):

  P1-origin   the client gets the origin's latest body for the path, no
              X-Cache header (a planted L2 body is caught by its hash).
  P2-no-l1    no L2 hit was counted (zone l2_hits delta 0 over the case) and
              the repeat request returns an origin body for the path (the L1
              entry, when there is one, is the origin body).
  P3-sanitizer  no sanitizer report, nginx (and its worker) still alive.
  P4-closed   the faulted connection carries no later command and is closed
              by the time bound; a probe request with a fresh key goes out on
              another connection and gets its own origin body (keepalive
              desync).  Cases whose framing is clean (CRLF split, a valid
              reply for another key) may legitimately be pooled: only the "no
              later desync" half applies (Case.expect_close=False).
  P5-latency  request latency and fault-to-close time stay under the
              configured timeout (+ lock_timeout for the lock family) plus a
              fixed slack, scaled for sanitizer builds.
  P6-errlog   error.log lines written during the case stay under a cap, no
              line exceeds 2 KiB or echoes the hostile payload marker, and no
              crit/alert/emerg line appears.

Known defects are recorded in KNOWN_RED with the properties they fail; such a
case does not fail the run.  A known-red case that passes (XPASS), or fails a
property outside its declared set, fails the run.  HARD-L3 fixes a defect and
removes its KNOWN_RED row.  Red cases and traces:
memory/labs/nginx-cache-turbo-module/hard-l2-evidence-20261118.md.

CTRL-PLANTED-FRESH is the oracle's negative control: it serves a body that
nginx itself stored for the same key (harvested from a second zone) as a
perfectly valid GET reply, so the module rightly serves it as an L2 hit; P1
MUST report it.  If it does not, the body-hash oracle cannot tell planted from
origin bodies and the whole matrix fails.  CTRL-MC-PLANTED-FRESH does the same
over memcached (a well-formed VALUE reply), which also proves the harvested
blob is a valid memcached value, so a memcached case that differs from it in
one header field (key, flags, bytes) tests exactly that field.

Environment: HOSTILE_L2_ONLY=ID[,ID...] runs a subset; HOSTILE_L2_REPORT=path
writes the per-case results as JSON.
"""

from __future__ import annotations

import contextlib
import dataclasses
import http.server
import json
import os
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

import hostile_peer as hp
from test_runtime_base import *
from test_runtime_base import _admin_stat, _errlog_window_start

PROPS = ("P1-origin", "P2-no-l1", "P3-sanitizer", "P4-closed", "P5-latency",
         "P6-errlog")

TIMEOUT_MS = 300          # cache_turbo_redis timeout= on every location
#                           but the re-arm probes' /rs/ and /ms/
REARM_TIMEOUT_MS = 900    # timeout= on /rs/ and /ms/ (> 2 x the lazy delay)
LAZY_S = 0.3              # nginx NGX_TIMER_LAZY_DELAY (event/ngx_event_timer.h)
# Drip byte interval: 0.4 x timeout puts the bytes at 0.12/0.24/0.36 s, never
# within 60 ms of the 0.30 s deadline, so the drip cases measure the deadline
# itself and not the re-arm race the *-DRIP-REARM cases expose.
DRIP_S = TIMEOUT_MS / 1000 * 0.4
LOCK_TIMEOUT_S = 1.0      # cache_turbo_lock_timeout on /rl/
MAX_SIZE = 65536          # cache_turbo_max_size: the GET payload ceiling
SLACK_S = 0.3             # scheduling + close-detection slack on the bound
                          # (a dripping peer sees the close on its next send,
                          # one drip delay = DRIP_S, 0.4 x timeout, later)
ERRLOG_CAP = 12           # new error.log lines allowed per case
ERRLOG_LINE_MAX = 2048
MARK = b"HL2JUNK"         # payload marker: must never be echoed into the log
PREFIX = "hl:"

_FAMILY_LOC = {"get": "r", "set": "r", "lock": "rl", "ctrl": "r",
               "auth": "ra", "select": "ra", "mcget": "m", "mcset": "m",
               "mcctrl": "m", "del": "r", "scan": "r", "sscan": "r",
               "rearm": "rs", "mcrearm": "ms"}
ADMIN_FAMILIES = frozenset({"del", "scan", "sscan"})
MC_FAMILIES = frozenset({"mcget", "mcset", "mcctrl", "mcrearm"})
REARM_FAMILIES = frozenset({"rearm", "mcrearm"})
PREAMBLE_FAMILIES = frozenset({"auth", "select"})
AUTH_PW = "hl2pw"


@dataclass(frozen=True)
class Planted:
    """Harvested CTB5 blobs, framed as RESP bulk replies, plus the case's
    wire keys (always filled in by _run_case, planted or not)."""
    same: bytes      # stored for the case key itself
    other: bytes     # stored for an unrelated key
    probe: bytes     # stored for the case's probe key (desync target)
    key: bytes = b""         # wire key of the case ("hl:<sha>")
    other_key: bytes = b""   # wire key the `other` blob was stored for
    probe_key: bytes = b""   # wire key of the probe request


@dataclass(frozen=True)
class Case:
    id: str
    family: str      # get set lock ctrl auth select del scan sscan mcget
    #                  mcset mcctrl rearm mcrearm
    step: Callable[[Planted], hp.Step]
    expect_close: bool = True
    # TRAIL-LATE: the peer answers the request's NEXT command on the faulted
    # connection only after the late bytes, so that command (the same
    # request's store/unlock) was legitimately sent before the desync was
    # visible.  Only commands for other keys count as reuse.
    own_flow_ok: bool = False
    needs_planted: bool = False
    # Admin families only: the purge reply a correct module sends --
    # "ok" (200), "fail" (5xx: L2 state unknown, never a false success) or
    # "any" (the faulted page itself was valid; either answer is honest).
    admin: str = "ok"
    note: str = ""


@dataclass
class Result:
    id: str
    failed: dict[str, str] = field(default_factory=dict)
    latency: float = 0.0
    close_after: float | None = None
    verdict: str = ""
    log: list[str] = field(default_factory=list)
    wire: list[str] = field(default_factory=list)


def _bulk(b: bytes) -> bytes:
    return b"$%d\r\n%s\r\n" % (len(b), b)


def _raw(bulk: bytes) -> bytes:
    """The payload of a RESP bulk reply (the harvested blob itself)."""
    if not bulk:
        return b""
    head, _, rest = bulk.partition(b"\r\n")
    n = int(head[1:])
    return rest[:n]


def _value(key: bytes, bulk: bytes, flags: bytes = b"0",
           nbytes: bytes | None = None) -> bytes:
    """A memcached hit reply carrying the blob of `bulk`."""
    raw = _raw(bulk)
    n = b"%d" % len(raw) if nbytes is None else nbytes
    return b"VALUE %s %s %s\r\n%s\r\nEND\r\n" % (key, flags, n, raw)


_JUNK40 = (MARK * 6)[:40]
SCAN_OK = b"*2\r\n$1\r\n0\r\n*0\r\n"   # one page, cursor 0, no keys


def _s(reply: bytes, **kw) -> Callable[[Planted], hp.Step]:
    return lambda _p: hp.Step(reply=reply, **kw)


def _common(fam: str, ok: bytes) -> list[Case]:
    """Families shared by every Redis command: bad $len, wrong types,
    mid-reply close/RST, drip and never-reply.  `ok` is the command's valid
    reply."""
    up = fam.upper()
    # SET, the lock SET and the purge DEL read their reply through the
    # framing drain: a complete, cleanly framed reply -- `-ERR` included --
    # leaves the stream at a reply boundary and the connection poolable by
    # contract (src/ngx_http_cache_turbo_redis.c read_drain, the
    # TODO-UNLINK-REPLY-WINDOW comment at the `*p == '-'` arm).  The GET parser
    # and the SCAN/SSCAN walk close on any wrong type; the preamble fails the
    # op on `-` and /ra/ has no pool.  For a framed wrong type only the
    # desync half of P4 applies on the drain path.
    strict = fam not in ("set", "lock", "del")
    scan = fam in ("scan", "sscan")
    bulky = fam == "get"
    # A bad length header is sent where the command's reply has one: the
    # bulk itself for GET, the cursor for SCAN/SSCAN, top level elsewhere.
    wrap = (lambda b: b"*2\r\n" + b) if scan else (lambda b: b)
    fail = "fail" if scan else "ok"
    if bulky:
        drip = b"$40\r\n" + _JUNK40 + b"\r\n"
        mid = b"$40\r\n" + MARK
    elif scan:
        drip = b"*2\r\n$40\r\n" + _JUNK40 + b"\r\n*0\r\n"
        mid = b"*2\r\n$40\r\n" + MARK
    else:
        drip = b"+" + _JUNK40 + b"\r\n"
        mid = b"+O"
    cases = [
        Case(f"{up}-LEN-NEG2", fam, _s(wrap(b"$-2\r\n")), admin=fail),
        Case(f"{up}-LEN-NONDIGIT", fam, _s(wrap(b"$1a\r\n")), admin=fail),
        Case(f"{up}-LEN-EMPTY", fam, _s(wrap(b"$\r\n")), admin=fail),
        Case(f"{up}-LEN-OVER-INT64", fam,
             _s(wrap(b"$9223372036854775808\r\n")), admin=fail),
        Case(f"{up}-LEN-HUGE", fam, _s(wrap(b"$" + b"9" * 40 + b"\r\n")),
             admin=fail),
        # The module logs a server error's text, capped at 64 bytes (read_drain
        # "redis command error"): no marker in it, so P6's echo check holds.
        Case(f"{up}-TYPE-ERR", fam, _s(b"-ERR hostile\r\n"),
             expect_close=strict, admin=fail),
        # DEL's own reply is an integer: it gets a simple string instead.
        Case(f"{up}-TYPE-SIMPLE", fam, _s(b"+OK\r\n"), expect_close=False)
        if fam == "del" else
        Case(f"{up}-TYPE-INT", fam, _s(b":1\r\n"), expect_close=strict,
             admin=fail),
        Case(f"{up}-TYPE-NULLARR", fam, _s(b"*-1\r\n"), expect_close=strict,
             admin=fail),
        Case(f"{up}-TYPE-RESP3-NULL", fam, _s(b"_\r\n"), admin=fail),
        Case(f"{up}-TYPE-PUSH", fam,
             _s(b">2\r\n$7\r\nmessage\r\n$7\r\n" + MARK + b"\r\n"),
             admin=fail),
        Case(f"{up}-TYPE-MAP", fam, _s(b"%1\r\n$1\r\na\r\n$1\r\nb\r\n"),
             admin=fail),
        Case(f"{up}-CRLF-SPLIT", fam,
             _s(ok, chunk=len(ok) - 1, delay=0.05), expect_close=False,
             note="valid reply, LF in a second read: pooling allowed"),
        Case(f"{up}-DRIP", fam,
             _s(drip, chunk=1, delay=DRIP_S), admin=fail,
             note="each byte arrives well inside the read timeout"),
        Case(f"{up}-CLOSE-MID", fam, _s(mid, then=hp.CLOSE), admin=fail),
        Case(f"{up}-RST-MID", fam, _s(mid, then=hp.RST), admin=fail),
        Case(f"{up}-NEVER", fam, lambda _p: hp.Step(never=True), admin=fail),
        # A valid reply, then a second valid reply carrying a body nginx
        # stored for the probe key: in one write, and late on the idle
        # (possibly pooled) connection.
        Case(f"{up}-TRAIL", fam, lambda p, ok=ok: hp.Step(reply=ok + p.probe),
             needs_planted=True, admin="any"),
        Case(f"{up}-TRAIL-LATE", fam,
             lambda p, ok=ok: hp.Step(reply=ok, late=p.probe, late_delay=0.1),
             needs_planted=True, own_flow_ok=True,
             note="unsolicited reply on the idle connection"),
    ]
    if fam in ("set", "lock", "del", "scan", "sscan"):
        cases.append(Case(f"{up}-LEN-OVER-MAX", fam,
                          _s(wrap(b"$%d\r\n" % (MAX_SIZE + 4096))),
                          admin=fail))
    if fam in ("set", "del"):
        cases.append(Case(f"{up}-TYPE-NIL", fam, _s(b"$-1\r\n"),
                          expect_close=False))
    elif fam == "lock":
        cases.append(Case(f"{up}-TYPE-BULK", fam, _s(_bulk(b"OK")),
                          expect_close=False))
    elif scan:
        cases += [
            Case(f"{up}-TYPE-NIL", fam, _s(b"$-1\r\n"), admin=fail),
            Case(f"{up}-CURSOR-NONDIGIT", fam,
                 _s(b"*2\r\n$1\r\nx\r\n*0\r\n"), admin=fail),
            Case(f"{up}-KEYS-NOT-ARRAY", fam,
                 _s(b"*2\r\n$1\r\n0\r\n$1\r\nk\r\n"), admin=fail),
            Case(f"{up}-KEYS-BADLEN", fam,
                 _s(b"*2\r\n$1\r\n0\r\n*1\r\n$-2\r\n"), admin=fail),
            Case(f"{up}-ARRAY-3", fam,
                 _s(b"*3\r\n$1\r\n0\r\n*0\r\n*0\r\n"), admin=fail),
        ]
    elif fam == "auth":
        # The reply to AUTH answers SELECT too and appends a GET hit for the
        # case key before nginx has sent its GET: served = a sequencing bug.
        cases.append(Case(
            "AUTH-EARLY-HIT", fam,
            lambda p: hp.Step(reply=b"+OK\r\n+OK\r\n" + p.same),
            needs_planted=True,
            note="pre-answered SELECT + GET in the AUTH reply"))
    return cases


def _mc_get_cases() -> list[Case]:
    """memcached `get`: the reply is parsed by mc_parse (memcached.c), which
    closes on anything but a framed END or VALUE..END."""
    f = "mcget"

    def hdr(**kw) -> Callable[[Planted], hp.Step]:
        nb = kw.pop("nbytes")
        return lambda p: hp.Step(reply=b"VALUE %s 0 %s\r\n" % (p.key, nb),
                                 **kw)

    return [
        Case("MCGET-SERVER-ERROR", f, _s(b"SERVER_ERROR out of memory\r\n")),
        Case("MCGET-CLIENT-ERROR", f,
             _s(b"CLIENT_ERROR bad command line format\r\n")),
        Case("MCGET-ERROR", f, _s(b"ERROR\r\n")),
        Case("MCGET-TYPE-STORED", f, _s(b"STORED\r\n")),
        Case("MCGET-LF-ONLY", f, _s(b"END\n"),
             note="no CR: never a complete line, read timeout"),
        Case("MCGET-BYTES-NEG", f, hdr(nbytes=b"-1")),
        Case("MCGET-BYTES-NONDIGIT", f, hdr(nbytes=b"1a")),
        Case("MCGET-BYTES-OVER-INT64", f, hdr(nbytes=b"9223372036854775808")),
        Case("MCGET-BYTES-HUGE", f, hdr(nbytes=b"9" * 40)),
        Case("MCGET-BYTES-OVER-MAX", f, hdr(nbytes=b"%d" % (1024 * 1024 + 1))),
        Case("MCGET-BYTES-SHORT", f, lambda p: hp.Step(reply=_value(
            p.key, p.same, nbytes=b"%d" % (len(_raw(p.same)) - 1))),
             needs_planted=True, note="trailer misaligned by one byte"),
        Case("MCGET-BYTES-LONG", f, lambda p: hp.Step(reply=_value(
            p.key, p.same, nbytes=b"%d" % (len(_raw(p.same)) + 1))),
             needs_planted=True, note="waits for one byte more: timeout"),
        # The hit below differs from CTRL-MC-PLANTED-FRESH in one field only.
        Case("MCGET-FLAGS-OVER-U32", f,
             lambda p: hp.Step(reply=_value(p.key, p.same,
                                            flags=b"4294967296")),
             needs_planted=True, expect_close=False,
             note="flags is a 32-bit field"),
        Case("MCGET-FLAGS-HUGE", f,
             lambda p: hp.Step(reply=_value(p.key, p.same, flags=b"9" * 40)),
             needs_planted=True, expect_close=False),
        Case("MCGET-FLAGS-NONDIGIT", f,
             lambda p: hp.Step(reply=_value(p.key, p.same, flags=b"x1")),
             needs_planted=True, expect_close=False),
        Case("MCGET-VALUE-KEY-MISMATCH", f,
             lambda p: hp.Step(reply=_value(p.other_key, p.same)),
             needs_planted=True, expect_close=False,
             note="VALUE names another key, carries this key's blob"),
        Case("MCGET-VALUE-NO-END", f,
             lambda p: hp.Step(reply=_value(p.key, p.same)[:-5]),
             needs_planted=True, note="data block, no END line: timeout"),
        Case("MCGET-HIT-THEN-TRAIL", f,
             lambda p: hp.Step(reply=_value(p.key, p.same) + b"END\r\n"),
             needs_planted=True,
             note="a valid hit followed by an unsolicited END"),
        Case("MCGET-CRLF-SPLIT", f, _s(b"END\r\n", chunk=4, delay=0.05),
             expect_close=False, note="valid miss, LF in a second read"),
        Case("MCGET-DRIP", f, lambda p: hp.Step(
            reply=b"VALUE %s 0 40\r\n" % p.key, chunk=1, delay=DRIP_S)),
        Case("MCGET-CLOSE-MID", f, lambda p: hp.Step(
            reply=b"VALUE %s 0 40\r\n%s" % (p.key, MARK), then=hp.CLOSE)),
        Case("MCGET-RST-MID", f, lambda p: hp.Step(
            reply=b"VALUE %s 0 40\r\n%s" % (p.key, MARK), then=hp.RST)),
        Case("MCGET-NEVER", f, lambda _p: hp.Step(never=True)),
        Case("MCGET-TRAIL", f, lambda p: hp.Step(
            reply=b"END\r\n" + _value(p.probe_key, p.probe)),
             needs_planted=True),
        Case("MCGET-TRAIL-LATE", f, lambda p: hp.Step(
            reply=b"END\r\n", late=_value(p.probe_key, p.probe),
            late_delay=0.1),
             needs_planted=True, own_flow_ok=True,
             note="unsolicited hit on the idle connection"),
    ]


def _mc_set_cases() -> list[Case]:
    """memcached `set`: the ack is read by mc_read_drain, which pools only a
    lone STORED/DELETED/NOT_FOUND line and closes on anything else."""
    f = "mcset"
    return [
        Case("MCSET-SERVER-ERROR", f,
             _s(b"SERVER_ERROR object too large for cache\r\n")),
        Case("MCSET-CLIENT-ERROR", f, _s(b"CLIENT_ERROR bad data chunk\r\n")),
        Case("MCSET-ERROR", f, _s(b"ERROR\r\n")),
        Case("MCSET-NOT-STORED", f, _s(b"NOT_STORED\r\n")),
        Case("MCSET-EXISTS", f, _s(b"EXISTS\r\n")),
        Case("MCSET-TYPE-END", f, _s(b"END\r\n")),
        Case("MCSET-LF-ONLY", f, _s(b"STORED\n")),
        Case("MCSET-LONG-LINE", f, _s(b"STORED" + MARK * 30)),
        Case("MCSET-CRLF-SPLIT", f, _s(b"STORED\r\n", chunk=7, delay=0.05),
             expect_close=False, note="valid ack, LF in a second read"),
        Case("MCSET-DRIP", f, _s(b"STORED\r\n", chunk=1, delay=DRIP_S)),
        Case("MCSET-CLOSE-MID", f, _s(b"STO", then=hp.CLOSE)),
        Case("MCSET-RST-MID", f, _s(b"STO", then=hp.RST)),
        Case("MCSET-NEVER", f, lambda _p: hp.Step(never=True)),
        Case("MCSET-TRAIL", f, lambda p: hp.Step(
            reply=b"STORED\r\n" + _value(p.probe_key, p.probe)),
             needs_planted=True),
        Case("MCSET-TRAIL-LATE", f, lambda p: hp.Step(
            reply=b"STORED\r\n", late=_value(p.probe_key, p.probe),
            late_delay=0.1),
             needs_planted=True, own_flow_ok=True,
             note="unsolicited hit on the idle connection"),
    ]


def build_cases() -> list[Case]:
    cases = _common("get", b"$-1\r\n")
    cases += [
        Case("GET-TYPE-SIMPLE", "get", _s(b"+OK\r\n")),
        Case("GET-LEN-OVER-MAX", "get", _s(b"$%d\r\n" % (MAX_SIZE + 4096))),
        Case("GET-TRAIL-BULK-FIRST", "get",
             lambda p: hp.Step(reply=p.same + b"$-1\r\n"), needs_planted=True,
             note="a valid hit followed by a nil: must not be served"),
        Case("GET-WRONG-KEY", "get", lambda p: hp.Step(reply=p.other),
             expect_close=False, needs_planted=True,
             note="clean framing, body stored for another key"),
    ]
    cases += _common("set", b"+OK\r\n")
    cases += _common("lock", b"+OK\r\n")
    cases += _common("auth", b"+OK\r\n")
    cases += _common("select", b"+OK\r\n")
    cases += _common("del", b":1\r\n")
    cases += _common("scan", SCAN_OK)
    cases += _common("sscan", SCAN_OK)
    cases += _mc_get_cases()
    cases += _mc_set_cases()
    # The read deadline is re-armed while a reply drips in: every readiness
    # event also runs the connection's write handler, whose "fully sent" tail
    # calls ngx_add_timer(c->read, timeout) again (redis.c redis_write,
    # memcached.c mc_write).  nginx skips a re-add that moves the key by less
    # than NGX_TIMER_LAZY_DELAY (300 ms), so with timeout=900ms a byte every
    # 0.4 s pushes the deadline out on every byte and the drip is never cut.
    rd = LAZY_S + 0.1
    cases.append(Case("GET-DRIP-REARM", "rearm",
                      _s(b"$4\r\nabcd\r\n", chunk=1, delay=rd),
                      note="byte every 0.4 s against timeout=900ms"))
    cases.append(Case("MCGET-DRIP-REARM", "mcrearm",
                      lambda p: hp.Step(reply=b"VALUE %s 0 4\r\nabcd\r\nEND\r\n"
                                        % p.key, chunk=12, delay=rd),
                      note="12 bytes every 0.4 s against timeout=900ms"))
    cases.append(Case("CTRL-PLANTED-FRESH", "ctrl",
                      lambda p: hp.Step(reply=p.same), expect_close=False,
                      needs_planted=True,
                      note="negative control: P1 must fire"))
    cases.append(Case("CTRL-MC-PLANTED-FRESH", "mcctrl",
                      lambda p: hp.Step(reply=_value(p.key, p.same)),
                      expect_close=False, needs_planted=True,
                      note="negative control over memcached: P1 must fire"))
    return cases


# Known defects: case id -> the properties it fails today.  HARD-L3 removes a
# row when it fixes the defect; the evidence file holds the traces.
KNOWN_RED: dict[str, frozenset[str]] = {
    # A cleanly framed GET reply carrying a valid CTB5 blob that was stored
    # for ANOTHER key is served and promoted to L1: the blob has no key
    # binding (src/ngx_http_cache_turbo_internal.h CTB5 layout), so a
    # desynced or misrouted reply is indistinguishable from a hit.
    "GET-WRONG-KEY": frozenset({"P1-origin", "P2-no-l1"}),
    # The walk cursor is not validated: a non-digit cursor ("x") is echoed
    # into the next page's SCAN/SSCAN and the purge reports 200 success.
    "SCAN-CURSOR-NONDIGIT": frozenset({"P1-origin"}),
    "SSCAN-CURSOR-NONDIGIT": frozenset({"P1-origin"}),
    # memcached `get`: mc_parse skips the flags field (never parsed or range
    # checked), so a VALUE line with an out-of-range or non-digit flags field
    # still serves the blob.
    "MCGET-FLAGS-OVER-U32": frozenset({"P1-origin", "P2-no-l1"}),
    "MCGET-FLAGS-HUGE": frozenset({"P1-origin", "P2-no-l1"}),
    "MCGET-FLAGS-NONDIGIT": frozenset({"P1-origin", "P2-no-l1"}),
    # The VALUE line's key is not compared with the requested key.
    "MCGET-VALUE-KEY-MISMATCH": frozenset({"P1-origin", "P2-no-l1"}),
    # A hit followed by an unsolicited END is served (the connection is
    # closed, not pooled); Redis GET-TRAIL-BULK-FIRST refuses the same shape.
    "MCGET-HIT-THEN-TRAIL": frozenset({"P1-origin", "P2-no-l1"}),
    # The read deadline is re-armed by the write handler on every readiness
    # event (build_cases, *-DRIP-REARM): a slow drip is never cut, and the
    # reply that completes after 3-4 s leaves the connection poolable.
    "GET-DRIP-REARM": frozenset({"P4-closed", "P5-latency"}),
    "MCGET-DRIP-REARM": frozenset({"P4-closed", "P5-latency"}),
}

CONTROL_IDS = frozenset({"CTRL-PLANTED-FRESH", "CTRL-MC-PLANTED-FRESH"})


def classify(case_id: str, failed: set[str] | frozenset[str],
             known: dict[str, frozenset[str]] | None = None) -> str:
    """green | known-red | control-ok are acceptable; red | xpass |
    known-red-drift | control-broken fail the matrix."""
    known = KNOWN_RED if known is None else known
    if case_id in CONTROL_IDS:
        return "control-ok" if "P1-origin" in failed else "control-broken"
    if case_id in known:
        if not failed:
            return "xpass"
        return "known-red" if set(failed) <= known[case_id] else "known-red-drift"
    return "red" if failed else "green"


ACCEPTED = frozenset({"green", "known-red", "control-ok"})


# --------------------------------------------------------------------------- #
# Harness: a one-worker nginx, its own origin, the hostile and harvest peers.
# --------------------------------------------------------------------------- #

class _Origin:
    """Origin whose every body is unique: "origin <path> <uuid4>"."""

    def __init__(self, port: int) -> None:
        served: dict[str, list[str]] = {}
        lock = threading.Lock()

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                body = f"origin {self.path} {uuid.uuid4().hex}\n"
                with lock:
                    served.setdefault(self.path, []).append(body)
                raw = body.encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Cache-Control", "max-age=60")
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, format: str, *args: object) -> None:
                pass

        self.served = served
        self._lock = lock
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def bodies(self, path: str) -> list[str]:
        with self._lock:
            return list(self.served.get(path, []))

    def stop(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()


def _config(root, port: int, module, origin: int, redis: int,
            harvest: int, mc: int) -> str:
    load = f"load_module {module};\n" if module else ""
    ka = (f"timeout={TIMEOUT_MS}ms keepalive=4 keepalive_timeout=30s"
          " connect_backoff=0")  # a fault must not skip the next case's L2
    # /ra/: no keepalive, so every L2 op runs the AUTH/SELECT preamble.
    dsn = (f"redis://:{AUTH_PW}@127.0.0.1:{redis}/2 prefix={PREFIX} "
           f"timeout={TIMEOUT_MS}ms connect_backoff=0")
    mcka = (f"prefix={PREFIX} timeout={TIMEOUT_MS}ms keepalive=4 "
            "keepalive_timeout=30s connect_backoff=0")
    # /rs/ and /ms/: the same backends with the longer re-arm probe timeout.
    def slow(opts: str) -> str:
        return opts.replace(f"timeout={TIMEOUT_MS}ms",
                            f"timeout={REARM_TIMEOUT_MS}ms")
    common = (f"cache_turbo_key $arg_k; cache_turbo_valid 30s; "
              f"cache_turbo_max_size {MAX_SIZE}; ")
    return f"""{load}worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/logs/error.log info;
events {{ worker_connections 256; }}
http {{
    access_log off;
    cache_turbo_zone name=hl 4m;
    cache_turbo_zone name=hh 4m;
    server {{
        listen 127.0.0.1:{port};
        location = /_hl {{ cache_turbo_admin hl; }}
        location = /_hla {{ cache_turbo_admin hl; cache_turbo_key $arg_k;
            cache_turbo_redis 127.0.0.1:{redis} prefix={PREFIX} {ka}; }}
        location /r/ {{ cache_turbo hl; {common}cache_turbo_lock off;
            cache_turbo_redis 127.0.0.1:{redis} prefix={PREFIX} {ka};
            proxy_pass http://127.0.0.1:{origin}; }}
        location /rl/ {{ cache_turbo hl; {common}cache_turbo_lock on;
            cache_turbo_lock_timeout {int(LOCK_TIMEOUT_S * 1000)}ms;
            cache_turbo_redis 127.0.0.1:{redis} prefix={PREFIX} {ka};
            proxy_pass http://127.0.0.1:{origin}; }}
        location /ra/ {{ cache_turbo hl; {common}cache_turbo_lock off;
            cache_turbo_redis {dsn};
            proxy_pass http://127.0.0.1:{origin}; }}
        location /m/ {{ cache_turbo hl; {common}cache_turbo_lock off;
            cache_turbo_memcached 127.0.0.1:{mc} {mcka};
            proxy_pass http://127.0.0.1:{origin}; }}
        location /rs/ {{ cache_turbo hl; {common}cache_turbo_lock off;
            cache_turbo_redis 127.0.0.1:{redis} prefix={PREFIX} {slow(ka)};
            proxy_pass http://127.0.0.1:{origin}; }}
        location /ms/ {{ cache_turbo hl; {common}cache_turbo_lock off;
            cache_turbo_memcached 127.0.0.1:{mc} {slow(mcka)};
            proxy_pass http://127.0.0.1:{origin}; }}
        location /h/ {{ cache_turbo hh; {common}cache_turbo_lock off;
            cache_turbo_redis 127.0.0.1:{harvest} prefix={PREFIX} {ka};
            proxy_pass http://127.0.0.1:{origin}; }}
    }}
}}
"""


def _benign_mc(cmd: hp.Command) -> hp.Step:
    verb = cmd.args[0].lower() if cmd.args else b""
    if verb == b"get":
        return hp.Step(reply=b"END\r\n")
    if verb == b"set":
        return hp.Step(reply=b"STORED\r\n")
    if verb == b"delete":
        return hp.Step(reply=b"NOT_FOUND\r\n")
    return hp.Step(reply=b"ERROR\r\n")


def _benign(cmd: hp.Command) -> hp.Step:
    verb = cmd.args[0].upper() if cmd.args else b""
    if verb == b"GET":
        return hp.Step(reply=b"$-1\r\n")
    if verb in (b"SET", b"AUTH", b"SELECT"):
        return hp.Step(reply=b"+OK\r\n")
    if verb in (b"SCAN", b"SSCAN"):
        return hp.Step(reply=b"*2\r\n$1\r\n0\r\n*0\r\n")
    return hp.Step(reply=b":1\r\n")


@dataclass
class _Armed:
    family: str
    key: str
    step: hp.Step
    fired: hp.Command | None = None
    fired_at: float = 0.0


class _Rig:
    def __init__(self, ng: Nginx) -> None:
        base = ng.port
        self.origin = _Origin(base + PORT_OFFSETS["hostile_l2_origin"])
        self.lock = threading.Lock()
        self.armed: _Armed | None = None
        self.redis = hp.Peer(responder=lambda c: self._respond(c, _benign),
                             on_exhausted=hp.NONE,
                             port=base + PORT_OFFSETS["hostile_l2_redis"])
        self.mc = hp.Peer(responder=lambda c: self._respond(c, _benign_mc),
                          on_exhausted=hp.NONE, proto="memcached",
                          port=base + PORT_OFFSETS["hostile_l2_memcached"])
        self.harvest = hp.Peer(responder=_benign, on_exhausted=hp.NONE,
                               port=base + PORT_OFFSETS["hostile_l2_harvest"])
        root = ng.root.parent / "hostile-l2"
        self.node = Nginx(ng.binary, ng.module, root,
                          base + PORT_OFFSETS["hostile_l2_node"],
                          self.origin.srv.server_address[1], ng.runner_raw,
                          ng.single_process)
        text = _config(root, self.node.port, ng.module,
                       self.origin.srv.server_address[1], self.redis.port,
                       self.harvest.port, self.mc.port)

        def write_config(sr_off: bool = False) -> None:
            del sr_off
            (root / "conf").mkdir(parents=True, exist_ok=True)
            (root / "logs").mkdir(parents=True, exist_ok=True)
            (root / "conf" / "nginx.conf").write_text(text, encoding="ascii")

        self.node.write_config = write_config  # type: ignore[method-assign]
        self.restarts = 0

    def start(self) -> None:
        self.redis.start()
        self.mc.start()
        self.harvest.start()
        self.node.write_config()
        self.node.config_test()
        self.node.start()

    def stop(self) -> None:
        try:
            self.node.stop()     # raises on a non-clean exit (sanitizer/LSan)
        finally:
            self.redis.stop()
            self.mc.stop()
            self.harvest.stop()
            self.origin.stop()

    def alive(self) -> bool:
        p = self.node.process
        return p is not None and p.poll() is None

    def restart(self) -> None:
        self.restarts += 1
        with contextlib.suppress(RuntimeError):
            self.node.stop()
        self.node.start()

    # -- peer -----------------------------------------------------------------
    def _respond(self, cmd: hp.Command,
                 benign: Callable[[hp.Command], hp.Step]) -> hp.Step:
        with self.lock:
            a = self.armed
            if a is not None and a.fired is None and _targets(a, cmd):
                a.fired = cmd
                a.fired_at = time.monotonic()
                return a.step
        return benign(cmd)

    def peer_for(self, family: str) -> hp.Peer:
        return self.mc if family in MC_FAMILIES else self.redis

    def harvest_blob(self, key: str) -> bytes:
        """Let nginx store a body for `key` (zone hh, same prefix) and return
        the stored value as a RESP bulk reply."""
        want = (PREFIX + _sha(key)).encode()
        st, _, _ = fetch(self.node.port, f"/h/harvest?k={key}")
        assert st == 200, f"harvest {key}: {st}"
        found: list[bytes] = []

        def stored() -> bool:
            found[:] = [c.args[2] for c in self.harvest.commands()
                        if len(c.args) >= 3 and c.args[0].upper() == b"SET"
                        and c.args[1] == want]
            return bool(found)

        assert wait_for(stored, 3.0), f"harvest {key}: no SET seen"
        return _bulk(found[0])


def _sha(key: str) -> str:
    return l2_key(key, "")


def _wire(key: str) -> bytes:
    return (PREFIX + _sha(key)).encode()


def _targets(a: _Armed, cmd: hp.Command) -> bool:
    if len(cmd.args) < 2:
        return False
    verb, k = cmd.args[0].upper(), cmd.args[1]
    fam = a.family
    if fam in MC_FAMILIES:
        # memcached verbs are lower-case on the wire; the peer only sees
        # memcached traffic, so get/set never collide with Redis GET/SET.
        want = b"SET" if fam == "mcset" else b"GET"
        # (mcget, mcctrl and mcrearm all arm the case key's `get`.)
        return verb == want and k == _wire(a.key)
    if fam == "auth":
        return verb == b"AUTH"
    if fam == "select":
        return verb == b"SELECT"
    if fam == "del":
        return verb == b"DEL" and k == _wire(a.key)
    if fam == "scan":
        return verb == b"SCAN"
    if fam == "sscan":
        return verb == b"SSCAN" and k == (PREFIX + "tag:" + a.key).encode()
    if fam in ("get", "ctrl", "rearm"):
        return verb == b"GET" and k == (PREFIX + _sha(a.key)).encode()
    if a.family == "set":
        return (verb == b"SET" and k == (PREFIX + _sha(a.key)).encode()
                and b"NX" not in (x.upper() for x in cmd.args[3:]))
    return (verb == b"SET"
            and k == (PREFIX + "lock:" + _sha(a.key)).encode())


def _log_from(rig: _Rig, off: int) -> list[str]:
    path = rig.node.root / "logs" / "error.log"
    try:
        with path.open("rb") as fh:
            fh.seek(off)
            data = fh.read()
    except OSError:
        return []
    return data.decode("utf-8", "replace").splitlines()


def conns_seen(peer: hp.Peer, n_before: int) -> set[int]:
    """Connections the case touched: new ones plus any pooled one reused."""
    return set(range(max(n_before - 4, 0), peer.accepted))


def _sanitizer_count(rig: _Rig) -> int:
    text = rig.node.diagnostics()
    n = sum(text.count(m) for m in SANITIZER_MARKERS if m != "ERROR SUMMARY:")
    return n + len(rig.node.sanitizer_reports())


def _own_flow(case: Case, key: str, cmd: hp.Command) -> bool:
    """A later command on the faulted connection that is still part of the
    faulted request's own flow (not a reuse by another request)."""
    if len(cmd.args) < 2:
        return True
    if case.family in PREAMBLE_FAMILIES:
        # /ra/ has no pool: the preamble connection carries exactly one op,
        # so every later command on it (the variant-index GET, the case-key
        # GET, the other preamble half) is the faulted request's own flow.
        return True
    verb = cmd.args[0].upper()
    # The purge walk issues its next page on the same connection: a later
    # SCAN (SSCAN over the case's tag set) is the same walk, not a reuse.
    if case.family == "scan" and verb == b"SCAN":
        return True
    if case.family == "sscan" and verb == b"SSCAN":
        return cmd.args[1] == (PREFIX + "tag:" + key).encode()
    if not case.own_flow_ok:
        return False
    return cmd.args[1] in {_wire(key), (PREFIX + "lock:" + _sha(key)).encode()}


def _admin_request(rig: _Rig, case: Case, key: str,
                   bound: float) -> tuple[int, str, dict]:
    q = {"del": f"key={key}", "scan": "all=1", "sscan": f"tag={key}"}
    return fetch(rig.node.port, f"/_hla?{q[case.family]}", method="POST",
                 timeout=bound + 5.0)


def _run_case(rig: _Rig, case: Case, planted: Planted | None,
              tag: str) -> Result:
    res = Result(case.id)
    fail = res.failed
    key, probe_key = tag, tag + "-probe"
    admin = case.family in ADMIN_FAMILIES
    peer = rig.peer_for(case.family)
    loc = _FAMILY_LOC[case.family]
    # Admin cases: the case key is seeded into L1 through /r/, then purged.
    path = f"/{loc}/{'seed' if admin else case.id}?k={key}"
    probe_path = f"/{loc}/probe?k={probe_key}"
    tmo = (REARM_TIMEOUT_MS if case.family in REARM_FAMILIES
           else TIMEOUT_MS) / 1000
    bound = (tmo + (LOCK_TIMEOUT_S if case.family == "lock" else 0.0)
             + SLACK_S) * sanitizer_time_scale()
    if admin:
        st, body, _ = fetch(rig.node.port, path, timeout=bound + 5.0)
        assert st == 200, f"{case.id}: seed {path}: {st}"
    hits0 = _admin_stat(rig.node, "l2_hits", "/_hl")
    log0 = _errlog_window_start(rig.node)
    san0 = _sanitizer_count(rig)
    n_before = peer.accepted
    assert planted is not None or not case.needs_planted
    step = case.step(dataclasses.replace(
        planted or Planted(b"", b"", b""), key=_wire(key),
        other_key=_wire(key + "-other"), probe_key=_wire(probe_key)))
    armed = _Armed(case.family, key, step)
    with rig.lock:
        rig.armed = armed

    t0 = time.monotonic()
    if admin:
        # P1 (admin): the purge reply is honest about L2.
        st, body, hdrs = _admin_request(rig, case, key, bound)
        res.latency = time.monotonic() - t0
        want_ok = case.admin == "ok" or (case.admin == "any" and st == 200)
        if (st == 200) != want_ok or (not want_ok and st < 500):
            fail["P1-origin"] = (f"admin reply status={st} want="
                                 f"{case.admin} body={body[:120]!r}")
    else:
        st, body, hdrs = fetch(rig.node.port, path, timeout=bound + 5.0)
        res.latency = time.monotonic() - t0
        # P1: the origin body, byte for byte, and no cache serve.
        bodies = rig.origin.bodies(path)
        if st != 200 or not bodies or body != bodies[-1] or "x-cache" in hdrs:
            fail["P1-origin"] = (f"status={st} x-cache={hdrs.get('x-cache')} "
                                 f"body={body[:80]!r} "
                                 f"origin_bodies={len(bodies)}")
    # The L2 store (SET) is issued after the response: wait for the fault.
    deadline = time.monotonic() + bound
    while armed.fired is None and time.monotonic() < deadline:
        time.sleep(0.01)
    if armed.fired is None:
        fail["P4-closed"] = "armed command never sent (wire sequence changed)"

    # P4/P5: the faulted connection is closed within the bound.
    if armed.fired is not None:
        conn = armed.fired.conn

        def closed() -> bool:
            return peer.connections[conn].closed is not None

        if case.expect_close:
            deadline = armed.fired_at + bound
            while not closed() and time.monotonic() < deadline:
                time.sleep(0.02)
        rec = peer.connections[conn]
        if rec.closed is not None:
            res.close_after = max(0.0, rec.closed - armed.fired_at)
        if case.expect_close and rec.closed is None:
            fail["P4-closed"] = (f"faulted conn {conn} still open "
                                 f"{bound:.2f}s after the fault")

    # P2: repeat -- the L1 entry (if any) is an origin body.  Admin: the
    # purged key's next request is a fresh origin fetch (SSCAN: an origin
    # body; which entries a hostile page purges is the peer's choice).
    n_bodies = len(rig.origin.bodies(path))
    st2, body2, hdrs2 = fetch(rig.node.port, path, timeout=bound + 5.0)
    bodies = rig.origin.bodies(path)
    if admin:
        fresh = (len(bodies) > n_bodies and body2 == bodies[-1]
                 and "x-cache" not in hdrs2)
        if st2 != 200 or body2 not in bodies or (
                case.family != "sscan" and not fresh):
            fail["P2-no-l1"] = (f"after purge status={st2} x-cache="
                                f"{hdrs2.get('x-cache')} fresh={fresh} "
                                f"body={body2[:80]!r}")
    elif st2 != 200 or body2 not in bodies or (
            hdrs2.get("x-cache") == "HIT" and bodies and body2 != body
            and "P1-origin" not in fail):
        fail["P2-no-l1"] = (f"repeat status={st2} x-cache={hdrs2.get('x-cache')}"
                            f" body={body2[:80]!r}")

    # P4 desync half: a fresh-key probe gets its own origin body, on a
    # connection other than the faulted one.
    stp, bodyp, hdrsp = fetch(rig.node.port, probe_path, timeout=bound + 5.0)
    pb = rig.origin.bodies(probe_path)
    if stp != 200 or not pb or bodyp != pb[-1] or "x-cache" in hdrsp:
        fail["P4-closed"] = (f"probe desync: status={stp} "
                             f"x-cache={hdrsp.get('x-cache')} "
                             f"body={bodyp[:80]!r}")
    if armed.fired is not None:
        cmds = peer.connections[armed.fired.conn].commands
        idx = next(i for i, c in enumerate(cmds) if c is armed.fired)
        later = [c for c in cmds[idx + 1:] if not _own_flow(case, key, c)]
        if case.expect_close and later:
            fail["P4-closed"] = (f"conn {armed.fired.conn} reused after the "
                                 f"fault: {[c.line[:40] for c in later]}")

    hits1 = _admin_stat(rig.node, "l2_hits", "/_hl")
    if hits1 != hits0:
        fail.setdefault("P2-no-l1", f"l2_hits moved {hits0}->{hits1}")

    # P5: latency bounded by the configured timeout.
    worst = max(res.latency, res.close_after or 0.0)
    if worst > bound:
        fail["P5-latency"] = (f"latency={res.latency:.3f}s close_after="
                              f"{res.close_after} bound={bound:.2f}s")

    # P3: sanitizer and liveness.
    if _sanitizer_count(rig) > san0:
        fail["P3-sanitizer"] = "new sanitizer report"
    if not rig.alive():
        fail["P3-sanitizer"] = "nginx died"

    # P6: error-log rate and shape.
    lines = _log_from(rig, log0)
    bad = [ln for ln in lines if any(f"[{lv}]" in ln for lv in
                                     ("crit", "alert", "emerg"))]
    long_ = [ln for ln in lines if len(ln) > ERRLOG_LINE_MAX]
    echo = [ln for ln in lines if MARK.decode() in ln]
    if bad and "P3-sanitizer" not in fail and any(
            "exited on signal" in ln for ln in bad):
        fail["P3-sanitizer"] = bad[0][:200]
    if len(lines) > ERRLOG_CAP or bad or long_ or echo:
        fail["P6-errlog"] = (f"lines={len(lines)} fatal={bad[:2]} "
                             f"long={len(long_)} echo={[e[:160] for e in echo[:2]]}")
    res.log = [ln[:300] for ln in lines[:20]]
    res.wire = [f"key={key} {PREFIX}{_sha(key)[:12]} probe={_sha(probe_key)[:12]}"]
    res.wire += [f"conn{c.conn} {c.line[:24]!r}" for c in peer.commands()
                 if c.conn in conns_seen(peer, n_before)]
    with rig.lock:
        rig.armed = None
    if not rig.alive():
        rig.restart()
    return res


def run_matrix(ng: Nginx, only: set[str] | None = None) -> list[Result]:
    rig = _Rig(ng)
    rig.start()
    results: list[Result] = []
    try:
        for case in build_cases():
            if only and case.id not in only:
                continue
            tag = f"{case.id.lower()}-{uuid.uuid4().hex[:8]}"
            planted = None
            if case.needs_planted:
                planted = Planted(same=rig.harvest_blob(tag),
                                  other=rig.harvest_blob(tag + "-other"),
                                  probe=rig.harvest_blob(tag + "-probe"))
            res = _run_case(rig, case, planted, tag)
            res.verdict = classify(case.id, set(res.failed))
            results.append(res)
            print(f"  hostile-l2 {res.verdict:<15} {case.id:<24} "
                  f"lat={res.latency:.3f}s close={res.close_after} "
                  f"{'; '.join(f'{k}: {v}' for k, v in res.failed.items())}",
                  flush=True)
        errs = rig.redis.errors + rig.mc.errors + rig.harvest.errors
        assert not errs, f"peer responder errors: {errs}"
    finally:
        rig.stop()
    return results


def summarize(results: list[Result]) -> dict[str, int]:
    out: dict[str, int] = {"total": len(results)}
    for r in results:
        out[r.verdict] = out.get(r.verdict, 0) + 1
    return out


def test_hostile_l2_matrix(ng: Nginx) -> None:
    """HARD-L2: the hostile L2 reply matrix (Redis GET, SET, lock, AUTH/SELECT,
    DEL, SCAN, SSCAN; memcached get/set) plus the planted-body negative
    controls; see the module docstring."""
    only_env = os.environ.get("HOSTILE_L2_ONLY", "")
    only = {x.strip() for x in only_env.split(",") if x.strip()} or None
    results = run_matrix(ng, only)
    summary = summarize(results)
    print(f"  hostile-l2 summary: {json.dumps(summary, sort_keys=True)}")
    report = os.environ.get("HOSTILE_L2_REPORT")
    if report:
        with open(report, "w", encoding="utf-8") as fh:
            json.dump({"summary": summary, "cases": [
                {"id": r.id, "verdict": r.verdict, "latency": r.latency,
                 "close_after": r.close_after, "failed": r.failed,
                 "log": r.log, "wire": r.wire}
                for r in results]}, fh, indent=1, sort_keys=True)
    if only is None:
        assert any(r.id in CONTROL_IDS for r in results), "control did not run"
    bad = [r for r in results if r.verdict not in ACCEPTED]
    assert not bad, "hostile L2 matrix: " + "; ".join(
        f"{r.id}={r.verdict} {r.failed}" for r in bad)
