"""Self-tests: the HARD-R1 hostile HTTP/1 matrix's case table, request
builder, response parser, oracle and classifier
(ci/tools/areas/hostile_http.py).  The runtime oracle itself is exercised on
every run by CTRL-HR-URI-KEY (a $uri-keyed location must fail P3-own-key)
and CTRL-HR-CLEAN (a clean request must pass everything)."""

import dataclasses
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from areas import hostile_http as hh

CASES = hh.build_cases()
BY = {c.id: c for c in CASES}
TAG = "deadbeef"


def test_case_ids_unique_stable_and_families_present() -> None:
    ids = [c.id for c in CASES]
    assert len(ids) == len(set(ids))
    assert all(i == i.upper() and " " not in i for i in ids)
    want = {
        "HR-CL-TE", "HR-TE-CL", "HR-CL-DUP-DIFF", "HR-CL-DUP-SAME",
        "HR-CL-COMMA", "HR-CHUNK-SIZE-BAD", "HR-CHUNK-EXT-BAD", "HR-TE-GZIP",
        "HR-OBS-FOLD", "HR-NUL-VALUE", "HR-CTL-VALUE", "HR-BARE-CR-VALUE",
        "HR-BARE-LF", "HR-ABS-FORM-HOST", "HR-HOST-DUP", "HR-HOST-EMPTY",
        "HR-HTTP10-NOHOST", "HR-PATH-NUL", "HR-PATH-DOTDOT-ENC",
        "HR-PATH-PARAMS", "HR-PATH-FRAGMENT", "HR-PATH-OVERLONG-UTF8",
        "HR-URI-AT-LIMIT", "HR-URI-PAST-LIMIT", "HR-HDR-AT-LIMIT",
        "HR-HDR-PAST-LIMIT", "HR-GET-CL0", "HR-GET-CL-BODY",
        "HR-GET-CHUNKED-BODY", "HR-GET-EXPECT-100", "CTRL-HR-URI-KEY",
        "CTRL-HR-CLEAN"}
    assert not want - set(ids), want - set(ids)
    assert all(c.expect in hh.EXPECTS for c in CASES)


def test_controls() -> None:
    assert hh.CONTROL_IDS == {c.id for c in CASES if c.control}
    ctl = BY["CTRL-HR-URI-KEY"]
    assert ctl.loc == hh.LOC_URI and ctl.expect == "own"
    # the control is the path-confusion case moved to the $uri location
    assert ctl.target.replace("/u/", "/c/", 1) == BY["HR-PATH-DOTDOT-ENC"].target
    assert hh.CONTROL_EXPECTED["CTRL-HR-URI-KEY"] == {"P3-own-key"}
    assert "cache_turbo_key $uri" in hh._config("/r", 1, None, 2)


def test_known_red_rows_name_real_cases_and_props() -> None:
    for table in (hh.HTTP_KNOWN_RED, hh.HTTP_KNOWN_RED_UBSAN):
        for cid, props in table.items():
            assert cid in BY and cid not in hh.CONTROL_IDS, cid
            assert props and props <= set(hh.PROPS), cid
    assert hh.known_red(False) == hh.HTTP_KNOWN_RED
    assert set(hh.known_red(True)) >= set(hh.HTTP_KNOWN_RED_UBSAN)
    for cid, props in hh.HTTP_KNOWN_RED_UBSAN_SINGLE.items():
        assert cid in hh.HTTP_KNOWN_RED_UBSAN, cid
        assert hh.HTTP_KNOWN_RED_UBSAN[cid] < props <= set(hh.PROPS), cid


SINGLE_FAIL = {"P4-victim", "P7-sanitizer"}


def test_single_process_variant_classifies_known_red() -> None:
    known = hh.known_red(True, True)
    assert hh.classify("HR-HTTP10-NOHOST", SINGLE_FAIL, known) == "known-red"
    assert hh.classify("HR-HTTP10-NOHOST", {"P7-sanitizer"},
                       known) == "known-red"
    assert hh.classify("HR-HTTP10-NOHOST", set(), known) == "xpass"
    assert hh.classify("HR-HTTP10-NOHOST", SINGLE_FAIL | {"P3-own-key"},
                       known) == "known-red-drift"


def test_single_process_set_on_multi_worker_is_drift() -> None:
    known = hh.known_red(True, False)
    assert hh.classify("HR-HTTP10-NOHOST", SINGLE_FAIL,
                       known) == "known-red-drift"
    assert hh.classify("HR-HTTP10-NOHOST", {"P7-sanitizer"},
                       known) == "known-red"


def test_plain_build_has_no_known_red_row() -> None:
    for single in (False, True):
        known = hh.known_red(False, single)
        assert "HR-HTTP10-NOHOST" not in known
        assert hh.classify("HR-HTTP10-NOHOST", set(), known) == "green"


@pytest.mark.parametrize("text,want", [
    ("configure arguments: --with-cc-opt='-O1 -fsanitize=address,undefined'",
     {"address", "undefined"}),
    ("configure arguments: --with-cc-opt=-fsanitize=address", {"address"}),
    ("configure arguments: --with-debug", set()),
    ("", set()),
])
def test_sanitizers_of(text: str, want: set[str]) -> None:
    assert hh.sanitizers_of(text) == want


def test_boundary_helpers_are_exact() -> None:
    for n in (hh.URI_AT, hh.URI_AT + 1):
        assert len(f"GET {hh.line_target(n)} HTTP/1.1") == n
    for n in (hh.HDR_AT, hh.HDR_AT + 1):
        assert len(hh.header_line(n)) == n
    with pytest.raises(ValueError):
        hh.line_target(10)
    with pytest.raises(ValueError):
        hh.header_line(5)
    assert BY["HR-URI-PAST-LIMIT"].expect == "reject"
    assert BY["HR-HDR-PAST-LIMIT"].expect == "reject"


def test_smuggle_cases_disagree_only_on_framing() -> None:
    tail = hh.smuggled(TAG)
    for c in CASES:
        raw = hh.build_request(c, TAG)
        assert b"@" not in raw, c.id
        if not c.smuggle:
            assert tail not in raw, c.id
            continue
        head, _, body = raw.partition(b"\r\n\r\n")
        assert body.endswith(tail), c.id
        # every Content-Length that is not 0 covers the whole body: the tail
        # is body under that reading and a request under the other one.
        for ln in head.split(b"\r\n"):
            if ln.lower().startswith(b"content-length:"):
                for v in ln.split(b":", 1)[1].split(b","):
                    assert int(v) in (0, len(body)), (c.id, ln)


def test_build_request_shapes() -> None:
    lf = hh.build_request(BY["HR-BARE-LF"], TAG)
    assert b"\r" not in lf and lf.endswith(b"\n\n")
    h10 = hh.build_request(BY["HR-HTTP10-NOHOST"], TAG)
    assert h10.startswith(b"GET /c/victim HTTP/1.0\r\n") and b"Host" not in h10
    empty = hh.build_request(BY["HR-HOST-EMPTY"], TAG)
    assert b"\r\nHost: \r\n" in empty
    raw = hh.build_request(BY["HR-PATH-OVERLONG-RAW"], TAG)
    assert b"/c/\xc0\xafvictim" in raw
    assert BY["HR-GET-EXPECT-100"].later == b"hello"
    assert hh.victim_request("c").endswith(b"\r\n\r\n")
    assert b"Connection: close" in hh.victim_request("c", close=True)


def _resp(status: int = 200, hdrs: str = "Content-Length: 2", body: bytes = b"ok",
          version: str = "HTTP/1.1") -> bytes:
    return f"{version} {status} X\r\n{hdrs}\r\n\r\n".encode() + body


def _parse(buf: bytes, eof: bool = False) -> tuple[hh.Resp, bytes]:
    got = hh.parse_response(buf, eof)
    assert got is not None
    return got


def test_parse_response_content_length_and_rest() -> None:
    r, rest = _parse(_resp() + b"NEXT")
    assert (r.status, r.body, r.close, rest) == (200, b"ok", False, b"NEXT")
    assert hh.parse_response(_resp()[:-1]) is None
    assert hh.parse_response(b"HTTP/1.1 200 X\r\n") is None


def test_parse_response_chunked_interim_close_and_eof() -> None:
    chunked = _resp(hdrs="Transfer-Encoding: chunked",
                    body=b"2\r\nok\r\n3;x=1\r\nabc\r\n0\r\n\r\n")
    r, rest = _parse(b"HTTP/1.1 100 Continue\r\n\r\n" + chunked)
    assert (r.status, r.body, rest) == (200, b"okabc", b"")
    assert hh.parse_response(chunked[:-2]) is None
    r, _ = _parse(_resp(400, "Connection: close\r\nContent-Length: 2"))
    assert r.close and r.status == 400
    r, _ = _parse(_resp(version="HTTP/1.0"))
    assert r.close
    nolen = b"HTTP/1.1 200 X\r\nServer: s\r\n\r\nbody"
    assert hh.parse_response(nolen) is None
    r, _ = _parse(nolen, eof=True)
    assert r.body == b"body" and r.close
    r, rest = _parse(_resp(204, "Server: s", b"") + b"x")
    assert r.body == b"" and rest == b"x"
    with pytest.raises(ValueError):
        hh.parse_response(b"garbage\r\n\r\n")


VB = b"origin /c/victim v1\n"


def _good(**kw) -> hh.Obs:
    """A fully green observation for a victim-path case, then `kw` applied."""
    o = hh.Obs(status=200, cache="HIT", body=VB, victim_body=VB,
               origin_bodies=(VB,), victim_status=200, victim_cache="HIT",
               victim_got=VB)
    return dataclasses.replace(o, **kw)


def test_judge_green_shapes() -> None:
    assert hh.judge(BY["HR-CTL-VALUE"], _good()) == {}
    assert hh.judge(BY["HR-CL-TE"], _good(status=400, cache="", body=b"",
                                          closed=True)) == {}
    assert hh.judge(BY["HR-TE-GZIP"], _good(status=501, body=b"")) == {}
    assert hh.judge(BY["HR-HTTP10-NOHOST"], _good(status=0, body=b"",
                                                  closed=True)) == {}
    # own: a MISS that stores under its own key is fine
    own = _good(cache="MISS", body=b"origin /c/x/%2e%2e/victim z\n",
                stored=(300, 0))
    assert hh.judge(BY["HR-PATH-DOTDOT-ENC"], own) == {}
    # safe on the victim path: an origin body for that path (bypass)
    byp = _good(cache="BYPASS", body=b"origin /c/victim v2\n",
                origin_bodies=(VB, b"origin /c/victim v2\n"))
    assert hh.judge(BY["HR-GET-CL-BODY"], byp) == {}


@pytest.mark.parametrize("cid,obs,prop", [
    ("HR-CL-TE", _good(), "P1-reaction"),
    ("HR-CTL-VALUE", _good(status=502, body=b""), "P1-reaction"),
    ("HR-CTL-VALUE", _good(status=301, body=b""), "P1-reaction"),
    ("HR-GET-CL-BODY-MISS", _good(cache="MISS", body=b"o", stored=(10, 0)),
     "P2-no-store"),
    ("HR-GET-CL0", _good(stored=(0, 1)), "P2-no-store"),
    ("HR-PATH-DOTDOT-ENC", _good(), "P3-own-key"),
    ("HR-PATH-DOTDOT-ENC", _good(cache="MISS"), "P3-own-key"),
    ("HR-CTL-VALUE", _good(body=b"origin /c/other\n"), "P3-own-key"),
    ("HR-CTL-VALUE", _good(victim_status=400), "P4-victim"),
    ("HR-CTL-VALUE", _good(victim_cache="MISS"), "P4-victim"),
    ("HR-CTL-VALUE", _good(victim_got=b"origin /c/smuggled\n"), "P4-victim"),
    ("HR-CL-TE", _good(status=400, unsolicited=b"HTTP/1.1 200"),
     "P5-no-desync"),
    ("HR-CL-TE", _good(status=400, leftover=b"x"), "P5-no-desync"),
    ("HR-CL-TE", _good(status=400, smuggle_seen=True), "P5-no-desync"),
    ("HR-CL-TE", _good(status=400, stored=(200, 0)), "P6-error-not-stored"),
    ("HR-PATH-DOTDOT-ENC", _good(status=414, stored=(0, 1)),
     "P6-error-not-stored"),
    ("HR-CTL-VALUE", _good(sanitizer="nginx died"), "P7-sanitizer"),
    ("HR-CTL-VALUE", _good(primed=False), hh.HARNESS_PROP),
])
def test_judge_each_property_bites(cid: str, obs: hh.Obs, prop: str) -> None:
    assert prop in hh.judge(BY[cid], obs)


@pytest.mark.parametrize("cid,failed,known,want", [
    ("HR-CL-TE", set(), {}, "green"),
    ("HR-CL-TE", {"P5-no-desync"}, {}, "red"),
    ("HR-CL-TE", {hh.HARNESS_PROP}, {}, "harness-fail"),
    ("HR-CL-TE", {"P7-sanitizer"}, {"HR-CL-TE": frozenset({"P7-sanitizer"})},
     "known-red"),
    ("HR-CL-TE", set(), {"HR-CL-TE": frozenset({"P7-sanitizer"})}, "xpass"),
    ("HR-CL-TE", {"P4-victim"}, {"HR-CL-TE": frozenset({"P7-sanitizer"})},
     "known-red-drift"),
    ("CTRL-HR-URI-KEY", {"P3-own-key"}, {}, "control-ok"),
    ("CTRL-HR-URI-KEY", set(), {}, "control-broken"),
    ("CTRL-HR-URI-KEY", {"P3-own-key", "P4-victim"}, {}, "control-broken"),
    ("CTRL-HR-CLEAN", set(), {}, "control-ok"),
    ("CTRL-HR-CLEAN", {"P1-reaction"}, {}, "control-broken"),
])
def test_classify(cid: str, failed: set[str], known: dict, want: str) -> None:
    assert hh.classify(cid, failed, known) == want


def test_summarize_counts_verdicts() -> None:
    rs = [hh.Result("a", verdict="green"), hh.Result("b", verdict="green"),
          hh.Result("c", verdict="known-red")]
    assert hh.summarize(rs) == {"total": 3, "green": 2, "known-red": 1}


def test_on_victim() -> None:
    assert BY["HR-CL-TE"].on_victim
    assert not BY["HR-ABS-FORM-HOST"].on_victim
    assert not dataclasses.replace(BY["HR-CL-TE"], loc=hh.LOC_URI).on_victim
