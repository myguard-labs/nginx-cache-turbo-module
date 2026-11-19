"""Self-tests: the HARD-L4 TLS matrix's case table, classifier and helpers
(ci/tools/areas/hostile_l2_tls.py).  The runtime oracle itself is exercised on
every run by the CTRL-TLS-* negative controls (the same bad certificates with
tls_verify=off must be accepted)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import hostile_peer as hp
from areas import hostile_l2_tls as ht

CASES = ht.build_cases()
IDS = [c.id for c in CASES]


def test_case_ids_unique_stable_and_families_present() -> None:
    assert len(IDS) == len(set(IDS))
    assert all(i == i.upper() and " " not in i for i in IDS)
    want = {"TLS-UNTRUSTED-CERT", "TLS-HOSTNAME-MISMATCH", "TLS-STALL",
            "TLS-MID-REPLY-STALL", "TLS-PLAINTEXT-REPLY", "TLS-ALERT-HANDSHAKE",
            "TLS-ALERT-MID-NOTIFY", "TLS-ALERT-MID-RAW", "TLS-NO-CLOSE-NOTIFY",
            "CTRL-TLS-UNTRUSTED-VERIFY-OFF", "CTRL-TLS-MISMATCH-VERIFY-OFF",
            "CTRL-TLS-TRUSTED"}
    assert not want - set(IDS), want - set(IDS)


def test_controls_pair_with_the_rejected_certificates() -> None:
    by = {c.id: c for c in CASES}
    for bad, ctl in (("TLS-UNTRUSTED-CERT", "CTRL-TLS-UNTRUSTED-VERIFY-OFF"),
                     ("TLS-HOSTNAME-MISMATCH", "CTRL-TLS-MISMATCH-VERIFY-OFF")):
        assert by[bad].cert == by[ctl].cert != "trusted"
        assert by[bad].loc == ht.LOC_VERIFY and by[ctl].loc == ht.LOC_NOVERIFY
        assert by[bad].no_command and by[ctl].control
    assert ht.CONTROL_IDS == {c.id for c in CASES if c.control}
    assert len(ht.CONTROL_IDS) == 3


def test_serve_cases_have_a_certificate_and_known_hello() -> None:
    for c in CASES:
        assert c.cert in ("trusted", "untrusted", "mismatch"), c.id
        assert c.hello in hp._HELLOS, c.id
        if c.step is not None:
            assert c.hello == hp.H_SERVE, c.id
        if c.no_command and c.hello == hp.H_SERVE:
            assert c.needs_handshake, c.id


@pytest.mark.parametrize("cid,failed,ctl,want", [
    ("TLS-STALL", set(), None, "green"),
    ("TLS-STALL", {"P4-closed"}, None, "red"),
    ("TLS-STALL", {ht.HARNESS_PROP}, None, "harness-fail"),
    ("CTRL-TLS-TRUSTED", set(), True, "control-ok"),
    ("CTRL-TLS-TRUSTED", set(), False, "control-broken"),
    ("CTRL-TLS-TRUSTED", set(), None, "control-broken"),
    ("CTRL-TLS-TRUSTED", {"P1-origin"}, True, "control-broken"),
])
def test_classify(cid: str, failed: set[str], ctl: bool | None,
                  want: str) -> None:
    assert ht.classify(cid, failed, control_accepted=ctl) == want


def test_classify_known_red_states() -> None:
    known = {"TLS-STALL": frozenset({"P5-latency"})}
    assert ht.classify("TLS-STALL", set(), known) == "xpass"
    assert ht.classify("TLS-STALL", {"P5-latency"}, known) == "known-red"
    assert ht.classify("TLS-STALL", {"P5-latency", "P4-closed"},
                       known) == "known-red-drift"
    assert ht.TLS_KNOWN_RED.keys() <= set(IDS)
    assert {"xpass", "red", "harness-fail"}.isdisjoint(ht.ACCEPTED)


def test_conn_problems_open_and_long() -> None:
    mk = hp.ConnRecord
    conns = [mk(0, "a", 10.0, 10.1), mk(1, "a", 10.0, 11.0), mk(2, "a", 10.0)]
    open_, long_ = ht.conn_problems(conns, 0.5, settled=True)
    assert open_ == ["conn2"] and [x.split("=")[0] for x in long_] == ["conn1"]
    assert ht.conn_problems(conns, 0.5, settled=False)[0] == []


def test_run_matrix_rejects_unknown_only_id() -> None:
    with pytest.raises(ValueError, match="unknown case id"):
        ht.run_matrix(None, {"NOPE"})  # type: ignore[arg-type]


def test_runtime_log_cap_constants_are_sane() -> None:
    assert ht.TIMEOUT_MS < 1000 and ht.ERRLOG_CAP >= 8
