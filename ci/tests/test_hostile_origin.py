"""Self-tests: the HARD-O1 hostile origin response replay matrix's case table,
response builder and parser, oracle and classifier
(ci/tools/areas/hostile_origin.py).  The runtime oracle itself is exercised
on every run by CTRL-HO-ACCEL-UNCACHED (an uncached X-Accel-Redirect must
fail P2-no-redirect) and CTRL-HO-CLEAN (a clean response must replay from L1
and L2 and pass everything)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from areas import hostile_origin as ho

CASES = ho.build_cases()
BY = {c.id: c for c in CASES}
P = "/c/HO-X/tag"


def leg(name: str, **kw) -> ho.Leg:
    base = {"status": 200, "body": b"B", "pairs": (("content-type", "t"),)}
    base.update(kw)
    return ho.Leg(name, **base)


def miss(**kw) -> ho.Leg:
    kw.setdefault("cache", "MISS")
    kw.setdefault("origin_hits", 1)
    return leg("MISS", **kw)


def hit(name: str, **kw) -> ho.Leg:
    kw.setdefault("cache", "HIT")
    return leg(name, **kw)


def fresh(name: str, **kw) -> ho.Leg:
    """A leg the origin answered (not a replay)."""
    kw.setdefault("cache", "MISS")
    kw.setdefault("origin_hits", 1)
    return leg(name, **kw)


def obs(*legs: ho.Leg, purge: int = 200, san: str = "") -> ho.Obs:
    return ho.Obs(list(legs), purge, san)


def case(cid: str = "HO-X", store: str = "may", **kw) -> ho.Case:
    return ho.Case(cid, store, lambda p, g: b"", **kw)


STORED = (miss(), hit("L1"), hit("L2", l2_hits=1))


# --------------------------------------------------------------------------- #
# Case table.
# --------------------------------------------------------------------------- #

def test_case_ids_unique_and_families_present() -> None:
    ids = [c.id for c in CASES]
    assert len(ids) == len(set(ids))
    assert all(i == i.upper() and " " not in i and "/" not in i for i in ids)
    want = {
        "CTRL-HO-CLEAN", "CTRL-HO-ACCEL-UNCACHED", "HO-101-UPGRADE",
        "HO-1XX-100", "HO-1XX-103", "HO-204-BODY", "HO-304-BODY",
        "HO-HEAD-BODY", "HO-CL-SHORT", "HO-CL-LONG", "HO-DUP-CC",
        "HO-DUP-VARY", "HO-DUP-SK", "HO-DUP-EXPIRES", "HO-DUP-AGE",
        "HO-VARY-STAR", "HO-SETCOOKIE-1000", "HO-CE-MISMATCH",
        "HO-XA-REDIRECT", "HO-XA-BUFFERING", "HO-XA-LIMIT-RATE",
        "HO-XA-EXPIRES", "HO-XA-CHARSET", "HO-LOCATION-200"}
    assert set(ids) == want
    assert all(c.store in ho.STORES for c in CASES)
    assert all(c.loc in (ho.LOC_CACHED, ho.LOC_UNCACHED) for c in CASES)


def test_policy_forbidden_cases() -> None:
    forbid = {c.id for c in CASES if c.store == "forbid"}
    assert forbid == {
        "HO-101-UPGRADE", "HO-204-BODY", "HO-304-BODY", "HO-HEAD-BODY",
        "HO-CL-LONG", "HO-DUP-CC", "HO-DUP-VARY", "HO-VARY-STAR",
        "HO-SETCOOKIE-1000", "HO-CE-MISMATCH"}


def test_controls() -> None:
    assert ho.CONTROL_IDS == {c.id for c in CASES if c.control}
    ctl = BY["CTRL-HO-ACCEL-UNCACHED"]
    assert ctl.loc == ho.LOC_UNCACHED and not ctl.must_replay
    # the control is the cached X-Accel-Redirect case on the uncached location
    assert ctl.respond(P, "g") == BY["HO-XA-REDIRECT"].respond(P, "g")
    assert ho.CONTROL_EXPECTED[ctl.id] == {"P2-no-redirect"}
    clean = BY["CTRL-HO-CLEAN"]
    assert clean.must_replay and ho.CONTROL_EXPECTED[clean.id] == frozenset()
    assert [c.id for c in CASES if c.must_replay] == [clean.id]


def test_known_red_rows_name_real_cases_and_props() -> None:
    for cid, props in ho.ORIGIN_KNOWN_RED.items():
        assert cid in BY and cid not in ho.CONTROL_IDS, cid
        assert props and props <= set(ho.PROPS), cid


def test_config_shape() -> None:
    text = ho._config("/r", 1, None, 2, 3)
    admin = text.split(f"location = {ho.ADMIN}", 1)[1].split("}", 1)[0]
    assert "cache_turbo_redis" not in admin          # L1-only purge
    cached = text.split(f"location /{ho.LOC_CACHED}/", 1)[1].split("}", 1)[0]
    assert "cache_turbo_redis 127.0.0.1:3 prefix=ho:" in cached
    assert "connect_backoff=0" in cached and "cache_turbo_key $uri" in cached
    unc = text.split(f"location /{ho.LOC_UNCACHED}/", 1)[1].split("}", 1)[0]
    assert "cache_turbo" not in unc and "proxy_pass" in unc
    assert f"location {ho.ACCEL}/ {{ internal;" in text
    assert "load_module" not in text
    assert "load_module /m.so;" in ho._config("/r", 1, "/m.so", 2, 3)


# --------------------------------------------------------------------------- #
# Origin bytes and the response parser.
# --------------------------------------------------------------------------- #

def test_raw_builder() -> None:
    assert ho.raw("200 OK", ["A: b"], b"xy") == \
        b"HTTP/1.1 200 OK\r\nA: b\r\nContent-Length: 2\r\n\r\nxy"
    assert ho.raw("200 OK", [], b"xy", cl=9).endswith(
        b"Content-Length: 9\r\n\r\nxy")
    assert b"Content-Length" not in ho.raw("101 X", [], b"", cl=None)


@pytest.mark.parametrize("cid", [c.id for c in CASES])
def test_every_case_response_parses(cid: str) -> None:
    c = BY[cid]
    data = c.respond(f"/{c.loc}/{cid}/t", "g1")
    r = ho.parse_response(data, c.method)
    assert r.status in (101, 200, 204, 304)
    if r.status == 200 and c.method == "GET":
        assert f"/{c.loc}/{cid}/t g1".encode() in r.body


def test_case_bytes_carry_the_hostile_shape() -> None:
    def hdrs(cid: str) -> list[tuple[str, str]]:
        return list(ho.parse_response(BY[cid].respond(P, "g")).pairs)

    assert [v for k, v in hdrs("HO-SETCOOKIE-1000")
            if k == "set-cookie"].__len__() == 1000
    assert ("cache-control", "no-store") in hdrs("HO-DUP-CC")
    assert [k for k, _ in hdrs("HO-DUP-AGE")].count("age") == 2
    assert ("x-accel-redirect", ho.accel_target(P)) in hdrs("HO-XA-REDIRECT")
    short = ho.parse_response(BY["HO-CL-SHORT"].respond(P, "g"))
    assert short.tail == b"SURPLUS-TAIL" and short.body == ho.origin_body(P, "g")
    long_ = ho.parse_response(BY["HO-CL-LONG"].respond(P, "g"))
    assert len(long_.body) < int(dict(long_.pairs)["content-length"])
    rate = ho.parse_response(BY["HO-XA-LIMIT-RATE"].respond(P, "g"))
    assert len(rate.body) == ho.RATE_BODY
    assert ho.RATE_BODY / ho.RATE > 2 * ho.RATE_SLOW_S


def test_parse_interim_chunked_head_and_errors() -> None:
    data = (b"HTTP/1.1 103 Early Hints\r\nLink: <x>\r\n\r\n"
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
            b"Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n"
            b"3\r\nabc\r\n2;e=1\r\nde\r\n0\r\n\r\nTAIL")
    r = ho.parse_response(data)
    assert r.status == 200 and r.body == b"abcde" and r.tail == b"TAIL"
    assert r.interim == (("1xx:103", ""), ("1xx:link", "<x>"))
    assert [v for k, v in r.pairs if k == "set-cookie"] == ["a=1", "b=2"]
    head = ho.parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
                             "HEAD")
    assert head.body == b"" and head.tail == b"abc"
    for st in (101, 204, 304):
        assert ho.parse_response(
            f"HTTP/1.1 {st} X\r\n\r\nzz".encode()).body == b""
    assert ho.parse_response(b"HTTP/1.1 200 OK\r\n\r\nto-eof").body == b"to-eof"
    with pytest.raises(ValueError):
        ho.parse_response(b"HTTP/1.1 200 OK\r\nX: y\r\n")   # no end of head
    with pytest.raises(ValueError):
        ho.parse_response(b"SMTP 220 hi\r\n\r\n")


# --------------------------------------------------------------------------- #
# Oracle.
# --------------------------------------------------------------------------- #

def test_replay_and_redirect_predicates() -> None:
    assert hit("L1").replay
    assert hit("L2", cache="STALE").replay
    assert leg("L2", cache="", l2_hits=1).replay
    assert not hit("L1", origin_hits=1).replay       # origin answered
    assert not hit("L1", status=0).replay            # no response
    assert not leg("L1", cache="MISS").replay
    assert not leg("L1", cache="").replay
    assert ho.redirected(leg("L1", accel_hits=1))
    assert ho.redirected(leg("L1", body=ho.ACCEL_MARK + b"/accel/x"))
    assert not ho.redirected(leg("L1", body=b"x" + ho.ACCEL_MARK))
    assert not ho.redirected(leg("L1"))


def test_new_lines() -> None:
    m = miss(pairs=(("set-cookie", "a"), ("x-k", "1")))
    assert ho.new_lines(m, hit("L1", pairs=(("x-k", "1"),))) == []
    # every volatile header is ignored
    vol = tuple((k, "v") for k in sorted(ho.REPLAY_VOLATILE))
    assert ho.new_lines(m, hit("L1", pairs=vol)) == []
    # a changed value, a new name, a repeated line and a new interim line
    assert ho.new_lines(m, hit("L1", pairs=(("x-k", "2"),))) == [("x-k", "2")]
    assert ho.new_lines(m, hit("L1", pairs=(("x-accel-redirect", "/a"),))) \
        == [("x-accel-redirect", "/a")]
    assert ho.new_lines(m, hit("L1", pairs=(("set-cookie", "a"),) * 2)) \
        == [("set-cookie", "a")]
    assert ho.new_lines(m, hit("L1", pairs=(), interim=(("1xx:link", "x"),))) \
        == [("1xx:link", "x")]


def test_judge_clean_stored_and_unstored() -> None:
    assert ho.judge(case(), obs(*STORED)) == {}
    assert ho.judge(case(store="forbid"),
                    obs(miss(), fresh("L1"), fresh("L2"))) == {}
    assert ho.judge(case(must_replay=True), obs(*STORED)) == {}


def test_judge_p1_no_store() -> None:
    f = ho.judge(case(store="forbid"), obs(*STORED))
    assert set(f) == {"P1-no-store"}
    assert "L1 replayed" in f["P1-no-store"] and "L2 replayed" in f["P1-no-store"]
    f = ho.judge(case(store="forbid"),
                 obs(miss(), fresh("L1"), leg("L2", cache="", l2_hits=1)))
    assert set(f) == {"P1-no-store"} and "L1" not in f["P1-no-store"]


def test_judge_p2_no_redirect() -> None:
    red = hit("L1", accel_hits=1)
    assert set(ho.judge(case(), obs(miss(), red, STORED[2]))) >= \
        {"P2-no-redirect"}
    # an origin-answered leg that redirects is nginx core, not a replay
    assert ho.judge(case(), obs(miss(accel_hits=1), fresh("L1", accel_hits=1),
                                fresh("L2", accel_hits=1))) == {}
    # a cache-served leg whose redirect target carries no X-CT-Status is not
    # a recognised replay, but the origin never saw it: still P2
    f = ho.judge(case(store="forbid"),
                 obs(miss(), leg("L1", cache="", accel_hits=1), fresh("L2")))
    assert set(f) == {"P2-no-redirect"} and "L1 redirected" in f["P2-no-redirect"]
    # an unanswered leg (status 0) is not judged as a redirect
    assert ho.judge(case(store="forbid"),
                    obs(miss(), leg("L1", status=0, accel_hits=1),
                        fresh("L2"))) == {}
    # ... except on a control, whose legs are judged as replays for P2
    f = ho.judge(case("CTRL-HO-ACCEL-UNCACHED", control=True),
                 obs(miss(), fresh("L1", accel_hits=1),
                     fresh("L2", body=ho.ACCEL_MARK + b"x")))
    assert set(f) == {"P2-no-redirect"}
    assert ho.classify("CTRL-HO-ACCEL-UNCACHED", set(f)) == "control-ok"
    # a control that does not redirect proves nothing
    f = ho.judge(case("CTRL-HO-ACCEL-UNCACHED", control=True),
                 obs(miss(), fresh("L1"), fresh("L2")))
    assert ho.classify("CTRL-HO-ACCEL-UNCACHED", set(f)) == "control-broken"


def test_judge_p3_p4_p5() -> None:
    m = miss(pairs=(("x-a", "1"),), body=b"same")
    f = ho.judge(case(), obs(m, hit("L1", pairs=(("x-a", "1"), ("x-b", "2")),
                                    body=b"same"),
                             hit("L2", l2_hits=1, pairs=(("x-a", "1"),),
                                 body=b"same")))
    assert set(f) == {"P3-no-new-header"} and "L1 sent" in f["P3-no-new-header"]
    f = ho.judge(case(), obs(m, hit("L1", pairs=m.pairs, body=b"other"),
                             hit("L2", l2_hits=1, pairs=m.pairs, body=b"same")))
    assert set(f) == {"P4-same-body"}
    # P3/P4/P5 apply only to replays: a fresh leg may differ
    assert ho.judge(case(), obs(m, fresh("L1", pairs=(("x-z", "9"),),
                                         body=b"new", seconds=9.0),
                                fresh("L2"))) == {}
    slow = ho.RATE_SLOW_S
    f = ho.judge(case(), obs(miss(), hit("L1", seconds=slow),
                             hit("L2", l2_hits=1, seconds=slow - 0.01)))
    assert set(f) == {"P5-no-rate"} and "L2" not in f["P5-no-rate"]


def test_judge_sanitizer_and_harness() -> None:
    assert set(ho.judge(case(), obs(*STORED, san="nginx died"))) == \
        {"P6-sanitizer"}
    f = ho.judge(case(), obs(miss(origin_hits=0, status=502), fresh("L1"),
                             fresh("L2")))
    assert set(f) == {"H-miss"}
    assert set(ho.judge(case(), obs(miss(), fresh("L1")))) == {"H-miss"}
    assert set(ho.judge(case(), obs(*STORED, purge=404))) == {"H-purge"}
    f = ho.judge(case(), obs(miss(), hit("L1"), hit("L2")))   # L1 served L2
    assert set(f) == {"H-purge"}
    # must_replay: L1 must be a pure L1 HIT and L2 an L2-promoted HIT
    for bad in ((miss(), fresh("L1"), hit("L2", l2_hits=1)),
                (miss(), hit("L1", l2_hits=1), hit("L2", l2_hits=1)),
                (miss(), hit("L1"), fresh("L2"))):
        assert "H-replay" in ho.judge(case(must_replay=True), obs(*bad))
    assert "H-replay" not in ho.judge(case(), obs(miss(), fresh("L1"),
                                                  fresh("L2")))


def test_classify() -> None:
    known = {"HO-K": frozenset({"P3-no-new-header", "P4-same-body"})}
    c = ho.classify
    assert c("HO-X", set()) == "green"
    assert c("HO-X", {"P1-no-store"}) == "red"
    assert c("HO-X", {"P1-no-store", "H-miss"}) == "harness-fail"
    assert c("HO-K", {"H-purge"}, known) == "harness-fail"
    assert c("CTRL-HO-CLEAN", {"H-replay"}) == "harness-fail"
    assert c("HO-K", {"P3-no-new-header"}, known) == "known-red"
    assert c("HO-K", {"P3-no-new-header", "P4-same-body"}, known) == "known-red"
    assert c("HO-K", set(), known) == "xpass"
    assert c("HO-K", {"P1-no-store"}, known) == "known-red-drift"
    assert c("CTRL-HO-CLEAN", set()) == "control-ok"
    assert c("CTRL-HO-CLEAN", {"P3-no-new-header"}) == "control-broken"
    assert c("CTRL-HO-ACCEL-UNCACHED", {"P2-no-redirect"}) == "control-ok"
    assert c("CTRL-HO-ACCEL-UNCACHED",
             {"P2-no-redirect", "P3-no-new-header"}) == "control-broken"
    assert c("CTRL-HO-ACCEL-UNCACHED", set()) == "control-broken"
    assert {"green", "known-red", "control-ok"} == ho.ACCEPTED


def test_summarize() -> None:
    rs = [ho.Result("a", verdict="green"), ho.Result("b", verdict="green"),
          ho.Result("c", verdict="control-ok")]
    assert ho.summarize(rs) == {"total": 3, "green": 2, "control-ok": 1}
