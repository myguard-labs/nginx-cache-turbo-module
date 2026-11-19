"""cache-turbo runtime tests -- hostile TLS L2 peer matrix (HARD-L4).

HARD-L1 gave the module bounded, fail-closed reply parsing over plain TCP.
This matrix puts the same expectation behind ``rediss://``: a scripted TLS
Redis endpoint (ci/tools/hostile_peer.py, ``Tls``) misbehaves at the TLS layer
and the module must treat every such fault as an L2 miss -- the client gets the
origin's body, the connection is closed, nothing is ever sent in the clear, and
the whole thing is bounded by the configured ``timeout=``.

Case families (Memcached has no TLS: Redis only):

  TLS-UNTRUSTED-CERT      a certificate chained to a CA nginx was not told to
                          trust, verification on.  The module verifies AFTER
                          the handshake, so the peer sees a completed
                          handshake and must then see NO command.
  TLS-HOSTNAME-MISMATCH   a certificate signed by the TRUSTED CA but valid for
                          another name than ``tls_name``; same expectation.
  TLS-STALL               the peer reads the ClientHello and never answers
                          (the handshake deadline is the op timeout).
  TLS-MID-REPLY-STALL     handshake completes, the GET gets half a reply, then
                          silence (the read deadline).
  TLS-PLAINTEXT-REPLY     a plaintext RESP reply (``$-1``) to the ClientHello.
  TLS-ALERT-HANDSHAKE     a fatal handshake_failure alert to the ClientHello.
  TLS-ALERT-MID-NOTIFY    half a reply, then a close_notify alert and FIN.
  TLS-ALERT-MID-RAW       half a reply, then a PLAINTEXT fatal alert record in
                          the middle of the encrypted stream (Python's ssl
                          cannot forge an encrypted fatal alert; a record the
                          client cannot decrypt is the closest wire fault).
  TLS-NO-CLOSE-NOTIFY     half a reply, then a bare FIN (truncation, no
                          close_notify); TLS-RST-MID the same with an RST.
  TLS-HELLO-CLOSE / -RST  the peer drops the connection after the ClientHello.

Every case is judged on (P1-P6 as in HARD-L2, P7/P8 are TLS-specific):

  P1-origin      the client gets the origin's latest body, no X-Cache header.
  P2-no-l1       no L2 hit counted; the repeat request returns an origin body
                 (the L1 entry, when there is one, is the origin body).  L1
                 promotion from the peer is observable only through these two:
                 the peer never carries a cache blob, so any L2 hit is a bug.
  P3-sanitizer   no sanitizer report, nginx and its worker alive.
  P4-closed      every connection nginx opened to the peer is closed within the
                 bound (a handshake that never completes, a rejected
                 certificate, a stalled read must not leave a socket open).
                 A connection the PEER closes proves nothing about nginx; the
                 cases where nginx is the closer are STALL, MID-REPLY-STALL,
                 UNTRUSTED-CERT and HOSTNAME-MISMATCH.
  P5-latency     the request returns within three timeouts (variant-index GET,
                 case GET, one slack op) and each connection lives at most one
                 timeout plus slack; both scaled for sanitizer builds.
  P6-errlog      error.log lines stay under a cap, none longer than 2 KiB,
                 none echoes the payload marker, no crit/alert/emerg.
  P7-no-plaintext  no connection to the TLS endpoint starts with anything but
                 a TLS handshake record: the module never falls back to
                 plaintext RESP after a TLS failure.
  P8-no-command  (cert / handshake rejects) no RESP command reached the peer,
                 not even over the completed TLS channel.

A case whose fault never ran fails H-fired (unwaivable): the peer must have
seen a ClientHello (hello cases), a completed handshake (certificate cases) or
the armed GET (reply cases).

Negative controls (verification must really be exercised): the SAME untrusted
and mismatched certificates behind a location with ``tls_verify=off`` MUST be
accepted -- the GET arrives over TLS and the request is served normally
(CTRL-TLS-UNTRUSTED-VERIFY-OFF, CTRL-TLS-MISMATCH-VERIFY-OFF), and
CTRL-TLS-TRUSTED proves the TLS peer itself is sound.  A control that is not
accepted is ``control-broken`` and fails the matrix.

Known defects live in TLS_KNOWN_RED with the properties they fail; such a case
does not fail the run, a known-red case that passes (xpass) does.  Red cases
and traces: memory/labs/nginx-cache-turbo-module/hard-l2-evidence-20261118.md,
section HARD-L4 (HARD-L3 input).

The TLS peer, the node and the origin reuse the HARD-L2 port offsets: both
matrices run sequentially and stop their rig before the next starts.

Environment: HOSTILE_L2_TLS_ONLY=ID[,ID...] runs a subset;
HOSTILE_L2_TLS_REPORT=path writes the per-case results as JSON.
"""

from __future__ import annotations

import contextlib
import json
import os
import pathlib
import ssl
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import hostile_peer as hp
from test_runtime_base import *
from test_runtime_base import _admin_stat, _errlog_window_start

from areas import hostile_l2 as hl

__all__ = ["test_hostile_l2_tls_matrix"]

PREFIX = "hlt:"
TIMEOUT_MS = 300
SLACK_S = 0.3
SERVER_NAME = "localhost"        # tls_name on the verifying location
ERRLOG_CAP = 12
ERRLOG_LINE_MAX = 2048
MARK = b"HL2JUNK"

PROPS = ("P1-origin", "P2-no-l1", "P3-sanitizer", "P4-closed", "P5-latency",
         "P6-errlog", "P7-no-plaintext", "P8-no-command")
HARNESS_PROP = "H-fired"

LOC_VERIFY = "tv"
LOC_NOVERIFY = "to"

# A half reply: a bulk header promising 40 bytes, then 7 of them.
HALF_REPLY = b"$40\r\n" + MARK


@dataclass(frozen=True)
class TlsCase:
    id: str
    cert: str = "trusted"          # trusted | untrusted | mismatch
    loc: str = LOC_VERIFY
    hello: str = hp.H_SERVE
    hello_reply: bytes = b""
    step: hp.Step | None = None    # armed on the case key's GET (serve only)
    control: bool = False
    # Certificate rejects: no command may reach the peer at all.
    no_command: bool = False
    # A completed handshake is part of the fault (the module verifies after
    # the handshake, so the peer sees it complete).
    needs_handshake: bool = False
    note: str = ""


def build_cases() -> list[TlsCase]:
    return [
        TlsCase("TLS-UNTRUSTED-CERT", cert="untrusted", no_command=True,
                needs_handshake=True,
                note="CA not trusted by tls_ca, verification on"),
        TlsCase("TLS-HOSTNAME-MISMATCH", cert="mismatch", no_command=True,
                needs_handshake=True,
                note="trusted CA, SAN is not tls_name"),
        TlsCase("TLS-STALL", hello=hp.H_STALL,
                note="ClientHello read, never answered"),
        TlsCase("TLS-MID-REPLY-STALL",
                step=hp.Step(reply=HALF_REPLY, then=hp.NONE),
                note="half a bulk reply, then silence: read deadline"),
        TlsCase("TLS-PLAINTEXT-REPLY", hello=hp.H_PLAINTEXT,
                hello_reply=b"$-1\r\n", no_command=True,
                note="plaintext RESP nil answers the ClientHello"),
        TlsCase("TLS-PLAINTEXT-ERR", hello=hp.H_PLAINTEXT,
                hello_reply=b"-ERR " + MARK + b"\r\n", no_command=True,
                note="plaintext RESP error answers the ClientHello"),
        TlsCase("TLS-ALERT-HANDSHAKE", hello=hp.H_ALERT, no_command=True,
                note="fatal handshake_failure alert to the ClientHello"),
        TlsCase("TLS-ALERT-MID-NOTIFY",
                step=hp.Step(reply=HALF_REPLY, then=hp.CLOSE_NOTIFY),
                note="half a reply, close_notify, FIN"),
        TlsCase("TLS-ALERT-MID-RAW",
                step=hp.Step(reply=HALF_REPLY, then=hp.RAW_ALERT),
                note="half a reply, plaintext fatal alert record, FIN"),
        TlsCase("TLS-NO-CLOSE-NOTIFY",
                step=hp.Step(reply=HALF_REPLY, then=hp.CLOSE),
                note="half a reply, bare FIN (truncation attack shape)"),
        TlsCase("TLS-RST-MID",
                step=hp.Step(reply=HALF_REPLY, then=hp.RST),
                note="half a reply, RST"),
        TlsCase("TLS-HELLO-CLOSE", hello=hp.H_CLOSE, no_command=True,
                note="FIN after the ClientHello"),
        TlsCase("TLS-HELLO-RST", hello=hp.H_RST, no_command=True,
                note="RST after the ClientHello"),
        # Negative controls: verification is what rejected the two cases above.
        TlsCase("CTRL-TLS-UNTRUSTED-VERIFY-OFF", cert="untrusted",
                loc=LOC_NOVERIFY, control=True,
                step=hp.Step(reply=b"$-1\r\n"),
                note="the SAME untrusted cert, tls_verify=off: accepted"),
        TlsCase("CTRL-TLS-MISMATCH-VERIFY-OFF", cert="mismatch",
                loc=LOC_NOVERIFY, control=True,
                step=hp.Step(reply=b"$-1\r\n"),
                note="the SAME mismatched cert, tls_verify=off: accepted"),
        TlsCase("CTRL-TLS-TRUSTED", control=True,
                step=hp.Step(reply=b"$-1\r\n"),
                note="trusted cert, verification on: accepted"),
    ]


# Known defects: case id -> the properties it fails today (filled from runs;
# see the evidence file).  HARD-L3 removes a row when it fixes the defect.
TLS_KNOWN_RED: dict[str, frozenset[str]] = {}

CONTROL_IDS = frozenset(c.id for c in build_cases() if c.control)
ACCEPTED = frozenset({"green", "known-red", "control-ok"})


def classify(case_id: str, failed: set[str] | frozenset[str],
             known: dict[str, frozenset[str]] | None = None,
             control_accepted: bool | None = None) -> str:
    """green | known-red | control-ok are acceptable; red | xpass |
    known-red-drift | control-broken | harness-fail fail the matrix.
    `control_accepted` (controls only): the GET reached the peer over TLS."""
    known = TLS_KNOWN_RED if known is None else known
    if HARNESS_PROP in failed:
        return "harness-fail"
    if case_id in CONTROL_IDS:
        ok = control_accepted is True and not failed
        return "control-ok" if ok else "control-broken"
    if case_id in known:
        if not failed:
            return "xpass"
        return "known-red" if set(failed) <= known[case_id] else "known-red-drift"
    return "red" if failed else "green"


@dataclass
class TlsResult:
    id: str
    failed: dict[str, str] = field(default_factory=dict)
    latency: float = 0.0
    verdict: str = ""
    control_accepted: bool | None = None
    conns: list[str] = field(default_factory=list)
    log: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Certificates, generated at runtime into a temp dir (no committed keys).
# --------------------------------------------------------------------------- #

def _openssl(*a: str) -> None:
    subprocess.run(["openssl", *a], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=30)


def _gen_leaf(d: pathlib.Path, ca: str, ca_key: str, san: str,
              cn: str) -> dict[str, str]:
    d.mkdir(parents=True, exist_ok=True)
    key, csr, crt, ext = (d / "leaf.key", d / "leaf.csr", d / "leaf.crt",
                          d / "leaf.ext")
    ext.write_text(f"subjectAltName={san}\n")
    _openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
             "-out", str(csr), "-subj", f"/CN={cn}")
    _openssl("x509", "-req", "-in", str(csr), "-CA", ca, "-CAkey", ca_key,
             "-CAcreateserial", "-out", str(crt), "-days", "1",
             "-extfile", str(ext))
    return {"cert": str(crt), "key": str(key)}


def gen_certs(d: pathlib.Path) -> dict[str, dict[str, str]]:
    """trusted (CA nginx trusts, SAN localhost/127.0.0.1), untrusted (same
    SAN, issued by a SECOND CA nginx is never told about) and mismatch (issued
    by the trusted CA, SAN for another name).  `ca` is the trusted CA file."""
    good = gen_tls_certs(d / "trusted")
    other = gen_tls_certs(d / "untrusted")
    mismatch = _gen_leaf(d / "mismatch", good["ca"], good["ca_key"],
                         "DNS:other.invalid", "other.invalid")
    return {"trusted": {"cert": good["cert"], "key": good["key"]},
            "untrusted": {"cert": other["cert"], "key": other["key"]},
            "mismatch": mismatch, "ca": {"path": good["ca"]}}


def server_ctx(paths: dict[str, str]) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(paths["cert"], paths["key"])
    return ctx


# --------------------------------------------------------------------------- #
# Harness: one-worker nginx, its own origin and one TLS peer per case.
# --------------------------------------------------------------------------- #

def _config(root, port: int, module, origin: int, tls_port: int,
            ca: str) -> str:
    load = f"load_module {module};\n" if module else ""
    common = ("cache_turbo_key $arg_k; cache_turbo_valid 30s; "
              "cache_turbo_lock off; ")
    opts = f"prefix={PREFIX} timeout={TIMEOUT_MS}ms connect_backoff=0"
    return f"""{load}worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/logs/error.log info;
events {{ worker_connections 256; }}
http {{
    access_log off;
    cache_turbo_zone name=hl 4m;
    server {{
        listen 127.0.0.1:{port};
        location = /_hl {{ cache_turbo_admin hl; }}
        location /{LOC_VERIFY}/ {{ cache_turbo hl; {common}
            cache_turbo_redis rediss://127.0.0.1:{tls_port}/0 tls_ca={ca} tls_name={SERVER_NAME} {opts};
            proxy_pass http://127.0.0.1:{origin}; }}
        location /{LOC_NOVERIFY}/ {{ cache_turbo hl; {common}
            cache_turbo_redis rediss://127.0.0.1:{tls_port}/0 tls_verify=off {opts};
            proxy_pass http://127.0.0.1:{origin}; }}
    }}
}}
"""


@dataclass
class _Armed:
    key: bytes
    step: hp.Step
    fire: tuple[hp.Command, float] | None = None


class _Rig:
    def __init__(self, ng: Nginx) -> None:
        base = ng.port
        self.origin = hl._Origin(base + PORT_OFFSETS["hostile_l2_origin"])
        self.tls_port = base + PORT_OFFSETS["hostile_l2_redis"]
        self.tmp = ng.root.parent / "hostile-l2-tls"
        self.certs = gen_certs(self.tmp / "certs")
        self.ctx = {n: server_ctx(self.certs[n])
                    for n in ("trusted", "untrusted", "mismatch")}
        self.lock = threading.Lock()
        self.armed: _Armed | None = None
        self.peer: hp.Peer | None = None
        self.node = Nginx(ng.binary, ng.module, self.tmp,
                          base + PORT_OFFSETS["hostile_l2_node"],
                          self.origin.srv.server_address[1], ng.runner_raw,
                          ng.single_process)
        text = _config(self.tmp, self.node.port, ng.module,
                       self.origin.srv.server_address[1], self.tls_port,
                       self.certs["ca"]["path"])

        def write_config(sr_off: bool = False) -> None:
            del sr_off
            (self.tmp / "conf").mkdir(parents=True, exist_ok=True)
            (self.tmp / "logs").mkdir(parents=True, exist_ok=True)
            (self.tmp / "conf" / "nginx.conf").write_text(text, encoding="ascii")

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
            self.node.stop()     # raises on a non-clean exit (sanitizer/LSan)
        finally:
            self.origin.stop()

    def workers(self) -> frozenset[int]:
        p = self.node.process
        return hl.descendants(p.pid) if p is not None else frozenset()

    def alive(self) -> bool:
        p = self.node.process
        return p is not None and p.poll() is None

    def respond(self, cmd: hp.Command) -> hp.Step:
        with self.lock:
            a = self.armed
            if (a is not None and a.fire is None and len(cmd.args) >= 2
                    and cmd.args[0].upper() == b"GET" and cmd.args[1] == a.key):
                a.fire = (cmd, time.monotonic())
                return a.step
        return hl._benign(cmd)

    def new_peer(self, case: TlsCase) -> hp.Peer:
        ctx = self.ctx[case.cert] if case.hello == hp.H_SERVE else None
        tls = hp.Tls(ctx=ctx, hello=case.hello, hello_reply=case.hello_reply)
        return hp.Peer(responder=self.respond, on_exhausted=hp.NONE,
                       port=self.tls_port, tls=tls).start()


def _as_l2(rig: _Rig) -> Any:
    """hostile_l2's helpers only need `rig.node`; this rig has one too."""
    return rig


def _wire(key: str) -> bytes:
    return (PREFIX + hl._sha(key)).encode()


def conn_problems(conns: list[hp.ConnRecord], bound_conn: float,
                  settled: bool) -> tuple[list[str], list[str]]:
    """(never-closed, over-long) descriptions of the peer's connections."""
    open_, long_ = [], []
    for c in conns:
        if c.closed is None:
            if settled:
                open_.append(f"conn{c.index}")
        elif c.closed - c.opened > bound_conn:
            long_.append(f"conn{c.index}={c.closed - c.opened:.2f}s")
    return open_, long_


def _settle(peer: hp.Peer, deadline: float) -> None:
    """Wait (bounded) until every connection the peer has seen is closed."""
    while time.monotonic() < deadline:
        conns = peer.connections
        if conns and all(c.closed is not None for c in conns):
            return
        time.sleep(0.02)


def _run_case(rig: _Rig, case: TlsCase, tag: str) -> TlsResult:
    res = TlsResult(case.id)
    fail = res.failed
    scale = sanitizer_time_scale()
    tmo = TIMEOUT_MS / 1000
    bound_conn = (tmo + SLACK_S) * scale
    bound_req = (3 * tmo + SLACK_S) * scale
    key, probe_key = tag, tag + "-probe"
    path = f"/{case.loc}/{case.id}?k={key}"
    probe_path = f"/{case.loc}/probe?k={probe_key}"

    peer = rig.new_peer(case)
    armed = None
    if case.step is not None:
        armed = _Armed(_wire(key), case.step)
    try:
        hits0 = _admin_stat(rig.node, "l2_hits", "/_hl")
        log0 = _errlog_window_start(rig.node)
        san0 = hl._sanitizer_count(_as_l2(rig))
        workers0 = rig.workers()
        with rig.lock:
            rig.armed = armed

        t0 = time.monotonic()
        st, body, hdrs = hl.safe_fetch(rig.node.port, path,
                                       timeout=bound_req + 5.0)
        res.latency = time.monotonic() - t0
        # P1: the origin body, byte for byte, and no cache serve.
        bodies = rig.origin.bodies(path)
        if st != 200 or not bodies or body != bodies[-1] or "x-cache" in hdrs:
            fail["P1-origin"] = (f"status={st} x-cache={hdrs.get('x-cache')} "
                                 f"body={body[:80]!r} "
                                 f"origin_bodies={len(bodies)}")
        # The L2 store is issued after the response: let it (and the fault)
        # play out before judging.
        _settle(peer, time.monotonic() + bound_conn)

        # P2: the repeat request; then the probe (a fresh key must still get
        # its own origin body: nothing is desynced or poisoned).
        st2, body2, hdrs2 = hl.safe_fetch(rig.node.port, path,
                                          timeout=bound_req + 5.0)
        bodies = rig.origin.bodies(path)
        if st2 != 200 or body2 not in bodies or (
                hdrs2.get("x-cache") == "HIT" and bodies and body2 != body
                and "P1-origin" not in fail):
            fail["P2-no-l1"] = (f"repeat status={st2} "
                                f"x-cache={hdrs2.get('x-cache')} "
                                f"body={body2[:80]!r}")
        stp, bodyp, hdrsp = hl.safe_fetch(rig.node.port, probe_path,
                                          timeout=bound_req + 5.0)
        pb = rig.origin.bodies(probe_path)
        if stp != 200 or not pb or bodyp != pb[-1] or "x-cache" in hdrsp:
            fail["P1-origin"] = (f"probe: status={stp} "
                                 f"x-cache={hdrsp.get('x-cache')} "
                                 f"body={bodyp[:80]!r}")
        hits1 = _admin_stat(rig.node, "l2_hits", "/_hl")
        if hits1 != hits0:
            fail.setdefault("P2-no-l1", f"l2_hits moved {hits0}->{hits1}")
        _settle(peer, time.monotonic() + bound_conn)

        conns = peer.connections
        cmds = [c for r in conns for c in r.commands]
        plain = [r for r in conns if r.plaintext]
        fire = armed.fire if armed is not None else None

        # H-fired: the fault ran.
        if case.hello != hp.H_SERVE:
            ran = any(r.hello_seen for r in conns)
        elif case.step is not None:
            ran = fire is not None
        else:
            ran = any(r.handshaked for r in conns)
        if case.needs_handshake:
            ran = ran and any(r.handshaked for r in conns)
        if not ran:
            fail[HARNESS_PROP] = ("fault never ran: "
                                  f"conns={[(r.hello_seen, r.handshaked) for r in conns]}")

        if case.control:
            res.control_accepted = (
                fire is not None and fire[0].conn is not None
                and any(r.handshaked and r.commands for r in conns)
                and not plain)
        else:
            # P4/P5: every connection closed, each within one timeout.
            open_, long_ = conn_problems(conns, bound_conn, settled=True)
            if open_:
                fail["P4-closed"] = (f"still open after {bound_conn:.2f}s: "
                                     f"{open_}")
            if long_ or res.latency > bound_req:
                fail["P5-latency"] = (f"latency={res.latency:.3f}s "
                                      f"(bound {bound_req:.2f}s) "
                                      f"long-conns={long_} "
                                      f"(bound {bound_conn:.2f}s)")
            if case.no_command and cmds:
                fail["P8-no-command"] = (
                    f"{len(cmds)} command(s) reached the peer: "
                    f"{[c.line[:40] for c in cmds[:3]]}")
        if plain:
            fail["P7-no-plaintext"] = (
                "plaintext client(s): "
                f"{[(r.index, r.plaintext[:40]) for r in plain[:3]]}")

        # P3: sanitizer and liveness.
        if hl._sanitizer_count(_as_l2(rig)) > san0:
            fail["P3-sanitizer"] = "new sanitizer report"
        if not rig.alive():
            fail["P3-sanitizer"] = "nginx died"
        else:
            lost = hl.worker_loss(workers0, rig.workers())
            if lost:
                fail["P3-sanitizer"] = (f"worker process(es) {sorted(lost)} "
                                        "exited during the case")

        # P6: error-log rate and shape.
        lines = hl._log_from(_as_l2(rig), log0)
        bad = [ln for ln in lines if any(f"[{lv}]" in ln for lv in
                                         ("crit", "alert", "emerg"))]
        long_lines = [ln for ln in lines if len(ln) > ERRLOG_LINE_MAX]
        echo = [ln for ln in lines if MARK.decode() in ln]
        if bad and "P3-sanitizer" not in fail and any(
                "exited on signal" in ln for ln in bad):
            fail["P3-sanitizer"] = bad[0][:200]
        if len(lines) > ERRLOG_CAP or bad or long_lines or echo:
            fail["P6-errlog"] = (f"lines={len(lines)} fatal={bad[:2]} "
                                 f"long={len(long_lines)} "
                                 f"echo={[e[:160] for e in echo[:2]]}")
        res.log = [ln[:300] for ln in lines[:20]]
        res.conns = [
            f"conn{r.index} hello={r.hello_seen} hs={r.handshaked} "
            f"cmds={[c.line[:24] for c in r.commands]} "
            f"life={'-' if r.closed is None else round(r.closed - r.opened, 3)}"
            f"{' err=' + r.tls_error if r.tls_error else ''}"
            f"{' PLAIN=' + repr(r.plaintext[:20]) if r.plaintext else ''}"
            for r in conns]
        if peer.errors:
            fail[HARNESS_PROP] = f"peer errors: {peer.errors[:2]}"
    finally:
        with rig.lock:
            rig.armed = None
        peer.stop()
    if not rig.alive():
        with contextlib.suppress(RuntimeError):
            rig.node.stop()
        rig.node.start()
    return res


def run_matrix(ng: Nginx, only: set[str] | None = None) -> list[TlsResult]:
    ids = [c.id for c in build_cases()]
    unknown = sorted((only or set()) - set(ids))
    if unknown:
        raise ValueError(f"HOSTILE_L2_TLS_ONLY: unknown case id(s) {unknown}")
    rig = _Rig(ng)
    rig.start()
    results: list[TlsResult] = []
    try:
        for case in build_cases():
            if only and case.id not in only:
                continue
            tag = f"{case.id.lower()}-{uuid.uuid4().hex[:8]}"
            res = _run_case(rig, case, tag)
            res.verdict = classify(case.id, set(res.failed),
                                   control_accepted=res.control_accepted)
            results.append(res)
            print(f"  hostile-l2-tls {res.verdict:<13} {case.id:<30} "
                  f"lat={res.latency:.3f}s "
                  f"{'; '.join(f'{k}: {v}' for k, v in res.failed.items())}",
                  flush=True)
    finally:
        rig.stop()
    return results


def summarize(results: list[TlsResult]) -> dict[str, int]:
    out: dict[str, int] = {"total": len(results)}
    for r in results:
        out[r.verdict] = out.get(r.verdict, 0) + 1
    return out


def test_hostile_l2_tls_matrix(ng: Nginx) -> None:
    """HARD-L4: hostile TLS L2 peer matrix plus the tls_verify=off negative
    controls; see the module docstring."""
    only_env = os.environ.get("HOSTILE_L2_TLS_ONLY", "")
    only = {x.strip() for x in only_env.split(",") if x.strip()} or None
    results = run_matrix(ng, only)
    summary = summarize(results)
    print(f"  hostile-l2-tls summary: {json.dumps(summary, sort_keys=True)}")
    report = os.environ.get("HOSTILE_L2_TLS_REPORT")
    if report:
        with open(report, "w", encoding="utf-8") as fh:
            json.dump({"summary": summary, "cases": [
                {"id": r.id, "verdict": r.verdict, "latency": r.latency,
                 "failed": r.failed, "control_accepted": r.control_accepted,
                 "conns": r.conns, "log": r.log} for r in results]},
                fh, indent=1, sort_keys=True)
    if only is None:
        assert any(r.id in CONTROL_IDS for r in results), "control did not run"
    bad = [r for r in results if r.verdict not in ACCEPTED]
    assert not bad, "hostile TLS L2 matrix: " + "; ".join(
        f"{r.id}={r.verdict} {r.failed}" for r in bad)
