"""Self-tests: the HARD-R4 request resource-bound matrix's debug-log parse,
growth classifier, expectations, request builders, oracle and classifier
(ci/tools/areas/hostile_bounds.py).  The runtime oracle is exercised on every
run by CTRL-BOUNDS-CAP-LOWERED (a lowered cap judged as the 10000 cap must
fail B-cap)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from areas import hostile_bounds as hb

CASES = hb.build_cases()
BY = {c.id: c for c in CASES}


# --- debug-log parse --------------------------------------------------------

LOG = [
    "2026/11/19 09:00:00 [debug] 1#1: *7 malloc: 000055CCBBB10FC0:128",
    "2026/11/19 09:00:00 [debug] 1#1: *7 malloc: 000055CCBBB10FD0:4096",
    "2026/11/19 09:00:00 [debug] 1#1: *8 malloc: 000055CCBBB10FE0:999",
    "2026/11/19 09:00:00 [debug] 1#1: *7 posix_memalign: 000055CCBBB10F:512 @16",
    "2026/11/19 09:00:00 [debug] 1#1: *7 free: 000055CCBBB10FC0",
    "2026/11/19 09:00:00 [debug] 1#1: *7 free: 000055CCBBB10FC0, unused: 12",
    "2026/11/19 09:00:00 [debug] 1#1: *7 free: 000055CCBBB10FD0, unused: 0",
    "2026/11/19 09:00:00 [debug] 1#1: malloc: 000055CCBBB10FE0:77",
    "2026/11/19 09:00:00 [debug] 1#1: *70 malloc: 000055CCBBB10FE0:5",
]


def test_alloc_bytes_counts_only_the_connections_malloc_lines() -> None:
    assert hb.alloc_bytes(LOG, 7) == (4224, 2)
    assert hb.alloc_bytes(LOG, 8) == (999, 1)
    assert hb.alloc_bytes(LOG, 70) == (5, 1)       # *70 is not *7
    assert hb.alloc_bytes(LOG, 9) == (0, 0)


def test_alloc_bytes_ignores_malformed_lines() -> None:
    bad = ["*7 malloc: 0000:abc", "*7 malloc: :12", "*x malloc: 00:12", ""]
    assert hb.alloc_bytes(bad, 7) == (0, 0)


def test_pool_destroys_counts_unused_lines_only() -> None:
    assert hb.pool_destroys(LOG, 7) == 2
    assert hb.pool_destroys(LOG, 8) == 0


# --- growth classifier ------------------------------------------------------

BASE = (1, 1000)


def test_growth_linear_and_flat_and_sublinear() -> None:
    pts = [(2500, 1000 + 52 * 2499), (5000, 1000 + 52 * 4999),
           (10000, 1000 + 52 * 9999)]
    shape, per = hb.growth(pts, BASE)
    assert shape == "linear" and all(abs(x - 52) < 0.1 for x in per)
    assert hb.growth([(10, 1100), (20, 1200), (40, 1300)], BASE)[0] == "flat"
    sub = [(100, 1000 + 100 * 99), (200, 1000 + 100 * 99 + 10 * 100),
           (400, 1000 + 100 * 99 + 10 * 300)]
    assert hb.growth(sub, BASE)[0] == "sublinear"


def test_growth_quadratic_is_superlinear() -> None:
    pts = [(n, 1000 + 8 * (n - 1) ** 2 // 100) for n in (2500, 5000, 10000)]
    assert hb.growth(pts, BASE)[0] == "superlinear"


def test_growth_tolerance_boundary() -> None:
    pts = lambda r: [(101, 1000 + 100 * 100), (201, 1000 + int(100 * r * 200)),
                     (401, 1000 + int(100 * r * 400))]
    assert hb.growth(pts(1.4), BASE)[0] == "linear"
    assert hb.growth(pts(1.6), BASE)[0] == "superlinear"
    assert hb.growth(pts(1.4), BASE, tol=1.3)[0] == "superlinear"


def test_growth_convex_from_zero_and_flat_floor() -> None:
    assert hb.growth([(10, 1000), (20, 1000), (40, 40000)], BASE)[0] \
        == "superlinear"
    # growth under the flat floor is flat whatever its shape
    assert hb.growth([(10, 1000), (20, 1000), (40, 1000 + hb.FLAT_BYTES)],
                     BASE)[0] == "flat"
    assert hb.growth([(10, 1000), (20, 1000), (40, 2000 + hb.FLAT_BYTES)],
                     BASE)[0] == "superlinear"


def test_growth_rejects_size_not_above_baseline() -> None:
    with pytest.raises(ValueError):
        hb.growth([(1, 1000)], BASE)
    with pytest.raises(ValueError):
        hb.growth([(0, 1000)], BASE)


# --- expectations -----------------------------------------------------------

@pytest.mark.parametrize(("n", "cap", "want"), [
    (64, 64, "sorted"), (65, 64, "raw"), (10000, 10000, "sorted"),
    (10001, 10000, "raw"), (10**6, 0, "sorted"), (2500, 1000, "raw"),
    (1000, 1000, "sorted")])
def test_expected_norm_boundary(n: int, cap: int, want: str) -> None:
    assert hb.expected_norm(n, cap) == want


def test_debug_alloc_available() -> None:
    ok = "configure arguments: --with-debug --with-cc-opt='-DNGX_DEBUG_PALLOC=1'"
    assert hb.debug_alloc_available(ok) == (True, "")
    no_dbg = hb.debug_alloc_available("--with-cc-opt='-DNGX_DEBUG_PALLOC=1'")
    assert not no_dbg[0] and "--with-debug" in no_dbg[1]
    no_pal = hb.debug_alloc_available("--with-debug -fsanitize=address")
    assert not no_pal[0] and "NGX_DEBUG_PALLOC" in no_pal[1]


# --- cases and builders -----------------------------------------------------

def test_case_table() -> None:
    ids = [c.id for c in CASES]
    assert len(ids) == len(set(ids))
    assert hb.CONTROL_IDS == {c.id for c in CASES if c.control}
    for c in CASES:
        assert len(c.sizes) == 3 and c.base < c.sizes[0] < c.sizes[1] < c.sizes[2]
    assert BY["ARGS-DEFAULT-CAP"].cap == hb.DEFAULT_CAP
    assert BY["ARGS-UNLIMITED"].cap == 0
    assert BY["URI-MAX"].cap is None
    assert BY["ARGS-CAP-10000"].sizes[-1] == 10000
    assert BY["COOKIE-LINES-4096"].sizes[-1] == 4096
    assert BY["VARY-LANG-LINES-1000"].sizes[-1] == 1000
    ctl = BY["CTRL-BOUNDS-CAP-LOWERED"]
    assert ctl.cap == 1000 and ctl.expect_cap == 10000


def test_builders_hit_the_requested_sizes() -> None:
    raw = hb.build_request(BY["ARGS-CAP-10000"], "tag", 10000).decode()
    first = raw.split("\r\n", 1)[0]
    assert first.count("&") == 9999
    assert "p10000=v&p09999=v" in first and first.endswith("p00001=v HTTP/1.1")
    cl = hb.build_request(BY["COOKIE-LINES-4096"], "tag", 4096).decode()
    assert cl.count("\r\nCookie: ") == 4096
    one = hb.build_request(BY["COOKIE-ONE-LINE-4096"], "tag", 4096).decode()
    assert one.count("\r\nCookie: ") == 1 and one.count("; ") == 4095
    assert hb.build_request(BY["VARY-ORIGIN-LINES-1000"], "t", 1000
                            ).decode().count("\r\nOrigin: ") == 1000
    ae = hb.build_request(BY["VARY-AE-TOKENS-1000"], "t", 1000).decode()
    assert ae.count("\r\nAccept-Encoding: ") == 1 and ae.count(", ") == 999
    assert hb.build_request(BY["VARY-LANG-LINES-1000"], "t", 7
                            ).decode().count("\r\nAccept-Language: ") == 7


def test_uri_request_line_is_exactly_the_requested_length() -> None:
    case = BY["URI-MAX"]
    for n in (hb.URI_BASE, *case.sizes):
        line = hb.build_request(case, "abcd1234", n).split(b"\r\n", 1)[0]
        assert len(line) == n
    assert case.sizes[-1] == hb.HDR_BUF - 2


def test_each_size_gets_its_own_key_and_plain_locations_mirror_the_shape() -> None:
    c = BY["COOKIE-LINES-4096"]
    assert hb.target(c, "t", 1) != hb.target(c, "t", 1024)
    plain = hb.build_request(c, "t", 5, hb.LOC_PLAIN_RETURN).decode()
    assert plain.startswith(f"GET /{hb.LOC_PLAIN_RETURN}/t-5 ")
    assert plain.count("\r\nCookie: ") == 5
    a = BY["ARGS-CAP-10000"]
    assert hb.target(a, "t", 3).split("?", 1)[1] == "p00003=v&p00002=v&p00001=v"
    assert len(hb.LOC_PLAIN_PROXY) == len(hb.LOC_ARGS_10000)


def test_config_carries_the_caps_and_buffers() -> None:
    text = hb._config("/r", 1, None, 2, "debug_alloc")
    assert "error_log /r/logs/error.log debug_alloc;" in text
    assert f"max_headers {hb.MAX_HEADERS};" in text
    assert f"large_client_header_buffers 4 {hb.HDR_BUF};" in text
    assert "cache_turbo_normalize_max_args 10000;" in text
    assert "cache_turbo_normalize_max_args 1000;" in text
    assert "cache_turbo_normalize_max_args 0;" in text
    assert text.count("cache_turbo_normalize_max_args") == 3  # default has none
    assert hb.MAX_HEADERS > 4096 + 3


# --- oracle -----------------------------------------------------------------

def req(cache: str = "HIT", norm: str = "", b: int = 0, m: int = 5,
        status: int = 200) -> hb.Req:
    return hb.Req(status=status, cache=cache, norm=norm, bytes=b, mallocs=m)


def point(n: int, mod: int, norm: str = "", plain: int = 1000) -> hb.Point:
    """A point whose module-attributable bytes are `mod` over the plain."""
    return hb.Point(
        n, miss=req("MISS", norm, plain + mod), hit=req("HIT", norm, plain + mod),
        hit2=req("HIT", norm, plain + mod),
        plain_proxy=req("", "", plain), plain_return=req("", "", plain),
        stored=800)


def series(case: hb.Case, per_unit, norm: str = "") -> tuple[hb.Point, list[hb.Point]]:
    base = point(case.base, 100, norm)
    pts = [point(n, 100 + int(per_unit(n) * (n - case.base)), norm)
           for n in case.sizes]
    return base, pts


def test_judge_linear_green_and_cap_expectation() -> None:
    case = BY["ARGS-CAP-10000"]
    base, pts = series(case, lambda n: 50, "sorted")
    j = hb.judge(case, base, pts, True)
    assert j.failed == {} and j.shapes["hit"] == "linear"
    assert j.shapes["stored"] == "flat"
    # a lowered cap flips the verdict: raw where sorted was expected
    base, pts = series(case, lambda n: 50, "raw")
    assert set(hb.judge(case, base, pts, True).failed) == {"B-cap"}
    # the lowered-cap location judged as 10000 (the control) fails B-cap
    ctl = BY["CTRL-BOUNDS-CAP-LOWERED"]
    base, pts = series(ctl, lambda n: 50, "raw")
    assert set(hb.judge(ctl, base, pts, True).failed) == {"B-cap"}
    # ... and judged against its own cap it is green
    own = BY["ARGS-CAP-1000"]
    base, pts = series(own, lambda n: 50, "raw")
    assert hb.judge(own, base, pts, True).failed == {}


def test_judge_superlinear_module_bytes_is_b_linear() -> None:
    case = BY["URI-MAX"]
    base, pts = series(case, lambda n: n / 1000)
    j = hb.judge(case, base, pts, True)
    assert set(j.failed) == {"B-linear"} and j.shapes["hit"] == "superlinear"


def test_judge_core_step_is_not_charged_to_the_module() -> None:
    """The total doubles at the last size (core's second header buffer) but
    the module-attributable bytes stay linear: green."""
    case = BY["URI-MAX"]
    base = point(case.base, 100)
    pts = []
    for n in case.sizes:
        core = n if n < case.sizes[-1] else 5 * n
        p = point(n, n)
        for r in (p.miss, p.hit, p.hit2):
            r.bytes += core
        for r in (p.plain_proxy, p.plain_return):
            r.bytes += core
        pts.append(p)
    j = hb.judge(case, base, pts, True)
    assert j.failed == {} and j.shapes["hit"] == "linear"
    assert j.shapes["total-hit"] == "superlinear"


def test_judge_served_det_and_missing_log() -> None:
    case = BY["COOKIE-ONE-LINE-4096"]
    base, pts = series(case, lambda n: 0)
    pts[1].hit = req("MISS", "", 1100)
    assert "B-served" in hb.judge(case, base, pts, True).failed
    base, pts = series(case, lambda n: 0)
    pts[0].miss = req("MISS", "", 0, status=400)
    assert "B-served" in hb.judge(case, base, pts, True).failed
    base, pts = series(case, lambda n: 0)
    pts[2].hit2 = req("HIT", "", 1)
    assert set(hb.judge(case, base, pts, True).failed) == {"H-det"}
    base, pts = series(case, lambda n: 0)
    base.plain_return = req("", "", 1000, m=0)
    assert set(hb.judge(case, base, pts, True).failed) == {"H-bytes"}


def test_judge_skips_bytes_but_keeps_the_cap_check() -> None:
    case = BY["ARGS-CAP-10000"]
    base, pts = series(case, lambda n: 50, "raw")
    for p in (base, *pts):
        p.miss.bytes = p.hit.bytes = p.hit2.bytes = 0
        p.miss.mallocs = p.hit.mallocs = 0
    j = hb.judge(case, base, pts, False, "no debug log")
    assert set(j.failed) == {"B-cap"} and "no debug log" in j.bytes_note
    assert "hit" not in j.shapes


# --- classifier -------------------------------------------------------------

def test_classify() -> None:
    assert hb.classify("URI-MAX", set()) == "green"
    assert hb.classify("URI-MAX", {"B-linear"}) == "red"
    assert hb.classify("URI-MAX", {"H-det"}) == "harness-fail"
    assert hb.classify("CTRL-BOUNDS-CAP-LOWERED", {"B-cap"}) == "control-ok"
    assert hb.classify("CTRL-BOUNDS-CAP-LOWERED", set()) == "control-broken"
    assert hb.classify("CTRL-BOUNDS-CAP-LOWERED", {"B-cap", "B-linear"}) \
        == "control-broken"
    known = {"URI-MAX": frozenset({"B-linear"})}
    assert hb.classify("URI-MAX", {"B-linear"}, known) == "known-red"
    assert hb.classify("URI-MAX", set(), known) == "xpass"
    assert hb.classify("URI-MAX", {"B-linear", "B-served"}, known) \
        == "known-red-drift"
    assert not hb.BOUNDS_KNOWN_RED
