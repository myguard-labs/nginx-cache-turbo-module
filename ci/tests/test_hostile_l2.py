"""Self-tests: the HARD-L2 matrix's case table and red/green classifier
(ci/tools/areas/hostile_l2.py).  The runtime oracle itself is exercised by the
matrix's CTRL-PLANTED-FRESH negative control on every run."""

import http.client
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from areas import hostile_l2 as hl

CASES = hl.build_cases()
IDS = [c.id for c in CASES]


def test_case_ids_unique_and_stable() -> None:
    assert len(IDS) == len(set(IDS))
    assert all(i == i.upper() and " " not in i for i in IDS)


COMMON = ["LEN-NEG2", "LEN-NONDIGIT", "LEN-OVER-INT64", "TYPE-ERR",
          "TYPE-NULLARR", "TYPE-RESP3-NULL", "TYPE-PUSH", "TYPE-MAP", "TRAIL",
          "TRAIL-LATE", "CRLF-SPLIT", "DRIP", "CLOSE-MID", "RST-MID", "NEVER"]


@pytest.mark.parametrize("fam", ["GET", "SET", "LOCK", "AUTH", "SELECT",
                                 "DEL", "SCAN", "SSCAN"])
def test_every_listed_family_present(fam: str) -> None:
    want = COMMON + (["LEN-OVER-MAX"] if fam != "AUTH" and fam != "SELECT"
                     else [])
    # DEL's own reply is an integer: it gets the simple-string wrong type.
    want.append("TYPE-SIMPLE" if fam in ("GET", "DEL") else "TYPE-INT")
    if fam in ("SCAN", "SSCAN"):
        want += ["TYPE-NIL", "CURSOR-NONDIGIT", "KEYS-NOT-ARRAY",
                 "KEYS-BADLEN", "ARRAY-3"]
    missing = [w for w in want if f"{fam}-{w}" not in IDS]
    assert not missing, missing
    assert "AUTH-EARLY-HIT" in IDS


def test_memcached_cases_present() -> None:
    want = {"MCGET-SERVER-ERROR", "MCGET-CLIENT-ERROR", "MCGET-BYTES-NEG",
            "MCGET-BYTES-OVER-INT64", "MCGET-FLAGS-OVER-U32",
            "MCGET-FLAGS-NONDIGIT", "MCGET-VALUE-KEY-MISMATCH",
            "MCGET-HIT-THEN-TRAIL", "MCGET-TRAIL", "MCGET-TRAIL-LATE",
            "MCSET-SERVER-ERROR", "MCSET-CLIENT-ERROR", "MCSET-NOT-STORED",
            "MCSET-TRAIL", "MCSET-TRAIL-LATE", "CTRL-MC-PLANTED-FRESH",
            "GET-DRIP-REARM", "MCGET-DRIP-REARM"}
    assert not want - set(IDS), want - set(IDS)
    for c in CASES:
        assert c.family in hl._FAMILY_LOC, c.id
        assert (c.family in hl.MC_FAMILIES) == c.id.startswith(
            ("MC", "CTRL-MC")), c.id


def test_drip_bytes_stay_clear_of_the_deadline() -> None:
    """The plain DRIP cases must not land a byte near the deadline (where a
    re-arm races the expiry); the re-arm probes must sit past the lazy delay
    and inside their own timeout, so every byte deterministically re-arms."""
    t = hl.TIMEOUT_MS / 1000
    arrivals = [hl.DRIP_S * i for i in range(1, 8)]
    assert min(abs(a - t) for a in arrivals) >= 0.05
    for cid in ("GET-DRIP-REARM", "MCGET-DRIP-REARM"):
        step = next(c for c in CASES if c.id == cid).step(
            hl.Planted(b"", b"", b"", key=b"hl:k"))
        assert hl.LAZY_S + 0.05 <= step.delay <= hl.REARM_TIMEOUT_MS / 2000
        assert hl.REARM_TIMEOUT_MS / 1000 >= 2 * hl.LAZY_S


def test_get_wrong_key_and_control_present() -> None:
    assert "GET-WRONG-KEY" in IDS
    assert hl.CONTROL_IDS <= set(IDS)


def test_known_red_rows_name_real_cases_and_props() -> None:
    for cid, props in hl.KNOWN_RED.items():
        assert cid in IDS, cid
        assert props and props <= set(hl.PROPS), (cid, props)
        assert cid not in hl.CONTROL_IDS


def test_planted_cases_get_their_bodies() -> None:
    planted = hl.Planted(same=b"$1\r\nS\r\n", other=b"$1\r\nO\r\n",
                         probe=b"$1\r\nP\r\n")
    for c in CASES:
        step = c.step(planted)
        assert isinstance(step, hl.hp.Step)
        if "TRAIL" in c.id and c.id not in ("GET-TRAIL-BULK-FIRST",
                                            "MCGET-HIT-THEN-TRAIL"):
            # memcached carries the blob itself, Redis the bulk reply.
            want = (hl._raw(planted.probe) if c.family in hl.MC_FAMILIES
                    else planted.probe)
            assert want in step.reply + step.late, c.id
    assert hl.Planted(b"", b"", b"").same == b""


KNOWN = {"K": frozenset({"P1-origin", "P2-no-l1"})}


@pytest.mark.parametrize(("cid", "failed", "verdict"), [
    ("X", set(), "green"),
    ("X", {"P4-closed"}, "red"),
    ("K", {"P1-origin"}, "known-red"),
    ("K", {"P1-origin", "P2-no-l1"}, "known-red"),
    ("K", set(), "xpass"),                                  # fixed: flip it
    ("K", {"P1-origin", "P5-latency"}, "known-red-drift"),  # new failure
    ("CTRL-PLANTED-FRESH", set(), "control-broken"),        # oracle blind
    ("CTRL-PLANTED-FRESH", {"P2-no-l1"}, "control-broken"),
    ("X", {"H-fired"}, "harness-fail"),
    ("K", {"H-fired", "P1-origin"}, "harness-fail"),        # never waivable
])
def test_classify(cid: str, failed: set[str], verdict: str) -> None:
    assert hl.classify(cid, failed, KNOWN) == verdict


@pytest.mark.parametrize(("failed", "served", "verdict"), [
    ({"P1-origin", "P2-no-l1"}, True, "control-ok"),
    ({"P1-origin"}, True, "control-ok"),
    # Negative controls for the old oracle (P1 in failed => control-ok): a
    # quick 500 trips P1 without the planted body being served.
    ({"P1-origin"}, False, "control-broken"),
    ({"P1-origin"}, None, "control-broken"),
    # The planted body was served but an unrelated property failed too.
    ({"P1-origin", "P6-errlog"}, True, "control-broken"),
    ({"P1-origin", "P3-sanitizer"}, True, "control-broken"),
])
def test_control_needs_planted_body_served(failed: set[str], served: bool | None,
                                           verdict: str) -> None:
    for cid in hl.CONTROL_IDS:
        assert hl.classify(cid, failed, KNOWN, planted_served=served) == verdict


def test_control_served_requires_exact_body_status_and_hit() -> None:
    assert hl.control_served(200, "b", "b", 1)
    assert not hl.control_served(500, "b", "b", 1)        # quick 500
    assert not hl.control_served(200, "origin", "b", 1)   # another body
    assert not hl.control_served(200, "b", "b", 0)        # no L2 hit counted
    assert not hl.control_served(200, "b", None, 1)       # nothing harvested


def test_unfired_known_red_case_is_not_waived() -> None:
    """Old oracle recorded a missing command as P4-closed, which the
    DRIP-REARM known-red row allows: the case went known-red without ever
    running its fault.  The new H-fired property is not waivable."""
    for cid in ("GET-DRIP-REARM", "MCGET-DRIP-REARM"):
        assert hl.classify(cid, {"P4-closed"}) == "known-red"      # old shape
        assert hl.classify(cid, {"H-fired"}) == "harness-fail"
        assert hl.classify(cid, {"H-fired", "P4-closed"}) == "harness-fail"
    assert "harness-fail" not in hl.ACCEPTED
    assert hl.HARNESS_PROP not in hl.PROPS


def test_lock_reply_verdict_cases() -> None:
    """HARD-L-READLOCK-BULK: SET NX PX answers "+OK" or the nil "$-1"; only
    the nil is "a peer holds the lock".  A non-nil bulk (and an integer or an
    array) is outside that grammar: not held, and not poolable."""
    lock = {c.id: c for c in CASES if c.family == "lock"}
    held = [cid for cid, c in lock.items() if c.lock_held]
    assert held == ["LOCK-HELD-NIL"]
    planted = hl.Planted(b"", b"", b"", key=b"hl:k")
    assert lock["LOCK-HELD-NIL"].step(planted).reply == b"$-1\r\n"
    assert lock["LOCK-ACQUIRED-OK"].step(planted).reply == b"+OK\r\n"
    for cid, reply in (("LOCK-TYPE-BULK", b"$2\r\nOK\r\n"),
                       ("LOCK-TYPE-BULK-EMPTY", b"$0\r\n\r\n")):
        assert lock[cid].step(planted).reply == reply
        assert lock[cid].expect_close, cid
    for cid in ("LOCK-TYPE-INT", "LOCK-TYPE-NULLARR", "LOCK-LEN-NEG2",
                "LOCK-LEN-NONDIGIT", "LOCK-LEN-OVER-INT64"):
        assert lock[cid].expect_close and not lock[cid].lock_held, cid
    # A framed -ERR stays poolable; SET/DEL wrong types keep the drain rule.
    assert not lock["LOCK-TYPE-ERR"].expect_close
    for fam in ("SET", "DEL"):
        assert not next(c for c in CASES
                        if c.id == f"{fam}-TYPE-NULLARR").expect_close
    assert not any(c.lock_held for c in CASES if c.family != "lock")
    assert "P7-lock" in hl.PROPS


def _wire_reads(step: hl.hp.Step) -> list[bytes]:
    """The reads the peer's chunked send hands nginx (one per chunk)."""
    n = step.chunk or len(step.reply) or 1
    return [step.reply[i:i + n] for i in range(0, len(step.reply), n)]


def test_lock_simple_string_verdict_cases() -> None:
    """HARD-L-READLOCK-PLUS: only the exact "+OK" is a lock win.  The win is
    observable only as a pooled connection, so the win cases demand reuse;
    every other simple string must close the connection and never park."""
    lock = {c.id: c for c in CASES if c.family == "lock"}
    planted = hl.Planted(b"", b"", b"", key=b"hl:k")
    for cid in ("LOCK-ACQUIRED-OK", "LOCK-ACQUIRED-OK-SPLIT"):
        c = lock[cid]
        assert c.step(planted).reply == b"+OK\r\n", cid
        assert c.expect_reuse and not c.expect_close and not c.lock_held, cid
    # Boundary: the win arrives as "+O" first, then the rest in later reads.
    split = lock["LOCK-ACQUIRED-OK-SPLIT"].step(planted)
    assert _wire_reads(split) == [b"+O", b"K\r", b"\n"]
    assert split.delay * len(_wire_reads(split)) < hl.TIMEOUT_MS / 1000
    for cid, reply in (("LOCK-SIMPLE-QUEUED", b"+QUEUED\r\n"),
                       ("LOCK-SIMPLE-QUEUED-SPLIT", b"+QUEUED\r\n"),
                       ("LOCK-SIMPLE-OKX", b"+OKX\r\n"),
                       ("LOCK-SIMPLE-OK-JUNK", b"+OK " + hl.MARK + b"\r\n")):
        c = lock[cid]
        assert c.step(planted).reply == reply, cid
        assert c.expect_close and not c.expect_reuse and not c.lock_held, cid
    # "+QUE" alone is not a complete reply: the verdict waits for the rest.
    queued = lock["LOCK-SIMPLE-QUEUED-SPLIT"].step(planted)
    assert _wire_reads(queued)[0] == b"+QUE"
    assert queued.delay * len(_wire_reads(queued)) < hl.TIMEOUT_MS / 1000


def test_wire_reads_helper() -> None:
    assert _wire_reads(hl.hp.Step(reply=b"+OK\r\n")) == [b"+OK\r\n"]
    assert _wire_reads(hl.hp.Step(reply=b"abcde", chunk=2)) == [
        b"ab", b"cd", b"e"]
    assert _wire_reads(hl.hp.Step(reply=b"")) == []


@pytest.mark.parametrize(("cid", "delta", "bad"), [
    ("LOCK-HELD-NIL", 1, False),        # nil honoured: parked for the fill
    ("LOCK-HELD-NIL", 0, True),         # fail-open: went to the origin
    ("LOCK-HELD-NIL", 2, True),         # one request counted twice
    ("LOCK-TYPE-BULK", 0, False),       # foreign reply: per-box regen
    ("LOCK-TYPE-BULK", 1, True),        # read as held (the old behaviour)
    ("LOCK-LEN-NEG2", 1, True),
    ("LOCK-ACQUIRED-OK", 0, False),
    ("LOCK-ACQUIRED-OK", 2, True),
    ("LOCK-SIMPLE-QUEUED", 0, False),   # failed channel: per-box regen
    ("LOCK-SIMPLE-QUEUED", 1, True),    # read as held
    ("SET-TYPE-NIL", 3, False),         # not a lock case: no verdict
])
def test_lock_verdict_problem(cid: str, delta: int, bad: bool) -> None:
    c = next(c for c in CASES if c.id == cid)
    assert (hl.lock_verdict_problem(c, delta) is not None) == bad


def test_mcget_crlf_split_must_be_accepted() -> None:
    c = next(c for c in CASES if c.id == "MCGET-CRLF-SPLIT")
    assert c.expect_reuse and not c.expect_close
    # Reuse is demanded only where accepting the reply is the property under
    # test: this split miss and the lock wins (HARD-L-READLOCK-PLUS).
    reuse = {x.id for x in CASES if x.expect_reuse}
    assert reuse == {c.id, "LOCK-ACQUIRED-OK", "LOCK-ACQUIRED-OK-SPLIT"}
    assert not any(x.expect_close for x in CASES if x.expect_reuse)


def test_fire_publishes_command_and_time_together() -> None:
    """The armed record carries command and timestamp as one value; there is
    no separate field a reader could see unset."""
    names = {f.name for f in hl.dataclasses.fields(hl._Armed)}
    assert "fire" in names and not names & {"fired", "fired_at"}
    rig: Any = object.__new__(hl._Rig)
    rig.lock = threading.Lock()
    cmd = _cmd(b"GET", hl._wire("k"))
    rig.armed = hl._Armed("get", "k", hl.hp.Step(reply=b"$-1\r\n"))
    t0 = time.monotonic()
    step = rig._respond(cmd, lambda _c: hl.hp.Step(reply=b"benign"))
    assert step.reply == b"$-1\r\n"
    fire = rig.armed.fire
    assert fire is not None and fire.cmd is cmd and fire.at >= t0 > 0
    # A second matching command is benign: the fault fires once.
    again = rig._respond(cmd, lambda _c: hl.hp.Step(reply=b"benign"))
    assert again.reply == b"benign" and rig.armed.fire is fire


def test_safe_fetch_records_dropped_connection(monkeypatch) -> None:
    def boom(*_a, **_k):
        raise http.client.RemoteDisconnected("closed without response")

    monkeypatch.setattr(hl, "fetch", boom)
    st, body, hdrs = hl.safe_fetch(1, "/x")
    assert st == 0 and "RemoteDisconnected" in body and hdrs == {}
    monkeypatch.setattr(hl, "fetch", lambda *_a, **_k: (200, "ok", {}))
    assert hl.safe_fetch(1, "/x") == (200, "ok", {})   # healthy path untouched
    # Negative control: the bare fetch the old runner used propagates.
    monkeypatch.setattr(hl, "fetch", boom)
    with pytest.raises(http.client.RemoteDisconnected):
        hl.fetch(1, "/x")


def test_worker_loss_and_descendants() -> None:
    assert hl.worker_loss(frozenset({1, 2}), frozenset({1, 2})) == frozenset()
    assert hl.worker_loss(frozenset({1, 2}), frozenset({1, 3})) == {2}  # replaced
    assert hl.worker_loss(frozenset({1}), frozenset({1, 9})) == frozenset()
    child = subprocess.Popen(["sleep", "30"])
    try:
        before = hl.descendants(os.getpid())
        assert child.pid in before
        # The old oracle looked at the master only: it stays alive here while
        # the child is gone; worker_loss sees the exit.
        child.kill()
        child.wait()
        after = hl.descendants(os.getpid())
        assert hl.worker_loss(before, after) >= {child.pid}
    finally:
        child.kill()
        child.wait()
    assert hl.descendants(2 ** 22 + 12345) == frozenset()   # no such pid


def _look(conn: int, key: bytes, verb: bytes = b"GET") -> hl.hp.Command:
    return hl.hp.Command(conn=conn, args=(verb, key))


def test_probe_wire_record_required() -> None:
    pw = hl._wire("p")
    other = [_look(0, hl._wire("zz"))]
    # Old oracle: a probe answered by the origin without any L2 lookup passed.
    assert "no wire record" in (hl.probe_wire_problem(other, pw, 0, True) or "")
    assert "no wire record" in (hl.probe_wire_problem([], pw, None, False) or "")
    # Closed faulted conn: the lookup must ride another connection.
    assert "faulted conn 0" in (hl.probe_wire_problem([_look(0, pw)], pw, 0, True) or "")
    assert hl.probe_wire_problem([_look(1, pw)], pw, 0, True) is None
    # Clean framing: reuse is fine, the lookup just has to exist.
    assert hl.probe_wire_problem([_look(0, pw)], pw, 0, False) is None
    assert hl.probe_wire_problem([_look(0, pw, b"get")], pw, 0, False) is None


def test_validate_only_rejects_unknown_ids() -> None:
    hl.validate_only(None, IDS)
    hl.validate_only({IDS[0], IDS[1]}, IDS)             # valid subset works
    with pytest.raises(ValueError, match="TYPO"):
        hl.validate_only({"TYPO"}, IDS)                 # typo only
    with pytest.raises(ValueError, match="NOPE"):
        hl.validate_only({IDS[0], "NOPE"}, IDS)         # one valid, one typo


def test_run_matrix_rejects_unknown_id_before_starting_anything() -> None:
    with pytest.raises(ValueError, match="BOGUS"):
        hl.run_matrix(None, {"BOGUS"})                  # type: ignore[arg-type]


class _Res:
    process = None

    def __init__(self, log: list[str], fail: str | None = None) -> None:
        self.log, self.fail = log, fail

    def start(self) -> None:
        self.log.append("start")
        if self.fail:
            raise OSError(self.fail)

    def stop(self) -> None:
        self.log.append("stop")

    def write_config(self) -> None:
        pass

    config_test = write_config


def test_partial_startup_failure_releases_started_resources() -> None:
    log: list[str] = []
    rig: Any = object.__new__(hl._Rig)
    rig.redis = _Res(log)
    rig.mc = _Res(log, fail="address in use")
    rig.harvest = _Res(log)
    rig.origin = _Res(log)
    rig.node = _Res(log)
    with pytest.raises(OSError, match="address in use"):
        rig.start()
    # redis started, mc failed -> every listener stopped, harvest never started.
    assert log.count("stop") == 5 and log.count("start") == 2


def test_cleanup_failure_does_not_mask_the_original_error() -> None:
    class _BadStop(_Res):
        def stop(self) -> None:
            raise RuntimeError("stop failed")

    log: list[str] = []
    rig: Any = object.__new__(hl._Rig)
    rig.redis = _Res(log, fail="original")
    rig.mc = rig.harvest = rig.origin = _Res(log)
    rig.node = _BadStop(log)
    with pytest.raises(OSError, match="original"):
        rig.start()


def _cmd(*args: bytes) -> hl.hp.Command:
    return hl.hp.Command(conn=0, args=args)


def _case(fam: str, own: bool = False) -> hl.Case:
    return hl.Case("X", fam, hl._s(b"+OK\r\n"), own_flow_ok=own)


def test_own_flow_preamble_takes_every_later_command() -> None:
    for fam in ("auth", "select"):
        c = _case(fam)
        assert hl._own_flow(c, "k", _cmd(b"GET", b"hl:variant-index"))
        assert hl._own_flow(c, "k", _cmd(b"SELECT", b"2"))


def test_own_flow_walk_page_vs_reuse() -> None:
    tag = (hl.PREFIX + "tag:k").encode()
    assert hl._own_flow(_case("scan"), "k", _cmd(b"SCAN", b"x"))
    assert not hl._own_flow(_case("scan"), "k", _cmd(b"GET", hl._wire("o")))
    assert hl._own_flow(_case("sscan"), "k", _cmd(b"SSCAN", tag, b"x"))
    assert not hl._own_flow(_case("sscan"), "k",
                            _cmd(b"SSCAN", b"hl:tag:other", b"0"))
    assert not hl._own_flow(_case("sscan"), "k", _cmd(b"SCAN", b"0"))


def test_own_flow_other_families() -> None:
    assert not hl._own_flow(_case("get"), "k", _cmd(b"SET", hl._wire("k")))
    late = _case("get", own=True)
    assert hl._own_flow(late, "k", _cmd(b"SET", hl._wire("k")))
    assert not hl._own_flow(late, "k", _cmd(b"GET", hl._wire("other")))
    assert hl._own_flow(_case("get"), "k", _cmd(b"PING"))   # no key arg


def test_only_green_known_red_and_control_ok_accepted() -> None:
    assert hl.ACCEPTED == {"green", "known-red", "control-ok"}


def test_summary_counts_verdicts() -> None:
    rs = [hl.Result("a", verdict="green"), hl.Result("b", verdict="green"),
          hl.Result("c", verdict="known-red")]
    assert hl.summarize(rs) == {"total": 3, "green": 2, "known-red": 1}
