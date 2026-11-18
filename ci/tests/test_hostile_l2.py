"""Self-tests: the HARD-L2 matrix's case table and red/green classifier
(ci/tools/areas/hostile_l2.py).  The runtime oracle itself is exercised by the
matrix's CTRL-PLANTED-FRESH negative control on every run."""

import sys
from pathlib import Path

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
    ("CTRL-PLANTED-FRESH", {"P1-origin", "P2-no-l1"}, "control-ok"),
    ("CTRL-PLANTED-FRESH", set(), "control-broken"),        # oracle blind
    ("CTRL-PLANTED-FRESH", {"P2-no-l1"}, "control-broken"),
])
def test_classify(cid: str, failed: set[str], verdict: str) -> None:
    assert hl.classify(cid, failed, KNOWN) == verdict


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
