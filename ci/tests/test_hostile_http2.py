"""Self-tests: the HARD-R2 hostile HTTP/2 matrix's frame and HPACK helpers,
case tables, cookie shapes, oracles and classifier
(ci/tools/areas/hostile_http2.py).  The runtime oracle itself is exercised on
every run by CTRL-CK-NO-PRESET (a location without the preset must fail
C1-bypass) and CTRL-H2-CLEAN (a clean HTTP/2 request must pass
everything)."""

import dataclasses
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from areas import hostile_http2 as h2

CASES = h2.build_cases()
BY = {c.id: c for c in CASES}
COOKIES = h2.build_cookie_cases()


# --- HPACK / frames ---------------------------------------------------------

@pytest.mark.parametrize(("value", "prefix", "want"), [
    (10, 5, b"\x0a"),                 # RFC 7541 C.1.1
    (1337, 5, b"\x1f\x9a\x0a"),       # RFC 7541 C.1.2
    (42, 8, b"\x2a"),                 # RFC 7541 C.1.3
    (126, 7, b"\x7e"),                # last short form
    (127, 7, b"\x7f\x00"),            # first long form
    (1025, 7, b"\x7f\x82\x07"),
])
def test_hpack_int_matches_rfc_and_round_trips(value: int, prefix: int,
                                               want: bytes) -> None:
    assert h2.hpack_int(value, prefix) == want
    assert h2.hpack_decode_int(want, 0, prefix) == (value, len(want))


def test_hpack_field_is_raw_literal_without_indexing() -> None:
    got = h2.hpack_field(b"X-Foo", b"a\r\nb")
    assert got == b"\x00\x05X-Foo\x04a\r\nb"
    big = h2.hpack_field(b"x", b"a" * 1025)
    assert big[:2] == b"\x00\x01" and big[3:6] == b"\x7f\x82\x07"
    assert len(big) == 3 + 3 + 1025


def test_frame_round_trip_and_short_buffer() -> None:
    f = h2.frame(h2.HEADERS, h2.FLAG_END_HEADERS, 3, b"abc")
    assert f[:9] == b"\x00\x00\x03\x01\x04\x00\x00\x00\x03"
    assert h2.parse_frame(f + b"x") == (h2.HEADERS, h2.FLAG_END_HEADERS, 3,
                                        b"abc", b"x")
    assert h2.parse_frame(f[:8]) is None
    assert h2.parse_frame(f[:-1]) is None


@pytest.mark.parametrize(("block", "want"), [
    (b"\x88", 200), (b"\x8c", 400), (b"\x8d", 404),
    (b"\x20\x88", 200),                       # table size update first
    (b"\x48\x03414", 414),                    # literal, incremental indexing
    (b"\x08\x03502", 502),                    # literal without indexing
    (b"\x48\x83abc", 0),                      # Huffman: not nginx's shape
    (b"\x41\x03abc", 0),                      # name index is not :status
    (b"\x48\x0341", 0),                       # truncated digits
    (b"", 0), (b"\x20", 0),
])
def test_h2_status_decodes_nginx_status_shapes(block: bytes, want: int) -> None:
    assert h2.h2_status(block) == want


# --- case tables -------------------------------------------------------------

def test_case_ids_unique_stable_and_families_present() -> None:
    ids = h2.all_ids()
    assert len(ids) == len(set(ids))
    assert all(i == i.upper() and " " not in i for i in ids)
    want = {
        "H2-PSEUDO-DUP-PATH", "H2-PSEUDO-DUP-METHOD", "H2-PSEUDO-AFTER-REGULAR",
        "H2-PSEUDO-UNKNOWN", "H2-UPPER-NAME", "H2-CONN-CONNECTION",
        "H2-CONN-KEEPALIVE", "H2-CONN-TE-CHUNKED", "H2-CONN-UPGRADE",
        "H2-CONN-TE-GZIP", "H2-AUTH-HOST-CONFLICT", "H2-FIELD-AT-LIMIT",
        "H2-FIELD-PAST-LIMIT", "CTRL-H2-CLEAN", "CTRL-CK-NO-PRESET",
        "CK-WORDPRESS", "H3-ARM"}
    assert not want - set(ids), want - set(ids)
    assert all(c.expect in h2.EXPECTS for c in CASES)
    assert h2.CONTROL_IDS <= set(ids)


def test_case_fields_are_what_the_ids_say() -> None:
    names = {c.id: [n for n, _ in c.fields] for c in CASES}
    assert names["H2-PSEUDO-DUP-PATH"].count(":path") == 2
    order = names["H2-PSEUDO-AFTER-REGULAR"]
    assert order.index("x-a") < order.index(":path")
    assert ":path" not in names["H2-PSEUDO-NO-PATH"]
    assert "X-Foo" in names["H2-UPPER-NAME"]
    assert ("te", "trailers") in BY["H2-CONN-TE-TRAILERS"].fields
    at = dict(BY["H2-FIELD-AT-LIMIT"].fields)["x-pad"]
    past = dict(BY["H2-FIELD-PAST-LIMIT"].fields)["x-pad"]
    assert len(at) == h2.HDR_BUF and len(past) == h2.HDR_BUF + 1
    assert all(c.smuggle == (b"@SMUGGLE@" in c.data) for c in CASES)
    assert not BY["CTRL-H2-CLEAN"].on_victim
    assert BY["H2-AUTH-HOST-CONFLICT"].on_victim


def test_request_data_substitutes_the_tagged_smuggle() -> None:
    data = h2.request_data(BY["H2-CL0-DATA-SMUGGLE"], "cafe")
    assert data == h2.smuggled("cafe")
    assert data.startswith(b"GET /c/h2-smuggled-cafe HTTP/1.1\r\n")


def test_header_block_encodes_every_field_in_order() -> None:
    block = h2.header_block(BY["H2-UPPER-NAME"].fields)
    assert block.index(b":method") < block.index(b":path") \
        < block.index(b"X-Foo")


def test_cookie_cases_cover_every_needle_preset_and_the_control() -> None:
    presets = {c.preset for c in COOKIES if not c.control}
    assert presets == set(h2.preset_needles())
    ctrl = [c for c in COOKIES if c.control]
    assert len(ctrl) == 1 and ctrl[0].preset is None
    assert ctrl[0].loc == h2.LOC_NONE
    assert ctrl[0].needle == h2.preset_needles()[h2.CONTROL_PRESET]
    assert all(c.loc == f"p-{c.preset}" for c in COOKIES if c.preset)


def test_cookie_shapes_carry_the_same_crumbs() -> None:
    cs = h2.crumbs("wordpress_logged_in_")
    assert cs[1] == "wordpress_logged_in_zzz=1" and len(cs) == 3
    crumbs = h2.cookie_fields("h2-crumbs", cs)
    line = h2.cookie_fields("h1-line", cs)
    dup = h2.cookie_fields("h1-dup", cs)
    assert crumbs == [("cookie", x) for x in cs]
    assert line == [("Cookie", "; ".join(cs))]
    assert dup == [("Cookie", x) for x in cs]
    with pytest.raises(ValueError):
        h2.cookie_fields("h3", cs)
    raw = h2.h1_request("/p-x/victim", dup)
    assert raw.count(b"\r\nCookie: ") == 3 and raw.endswith(b"\r\n\r\n")


@pytest.mark.parametrize(("status", "body", "stored", "want"), [
    (200, b"fresh", (0, 0), "bypass"),
    (200, b"primed", (0, 0), "hit"),
    (200, b"fresh", (120, 1), "store"),
    (400, b"err", (0, 0), "status-400"),
    (0, b"", (0, 0), "status-0"),
])
def test_cookie_verdict(status: int, body: bytes, stored: tuple[int, int],
                        want: str) -> None:
    assert h2.cookie_verdict(status, body, b"primed", stored) == want


def test_judge_cookie() -> None:
    ok = dict.fromkeys(h2.SHAPES, "bypass")
    assert h2.judge_cookie(ok, True) == {}
    hits = dict.fromkeys(h2.SHAPES, "hit")
    assert set(h2.judge_cookie(hits, True)) == {"C1-bypass"}
    mixed = {**ok, "h1-dup": "hit"}
    assert set(h2.judge_cookie(mixed, True)) == {"C2-same-verdict"}
    missing = {"h2-crumbs": "bypass", "h1-line": "bypass"}
    assert set(h2.judge_cookie(missing, True)) == {"C2-same-verdict"}
    assert h2.HARNESS_PROP in h2.judge_cookie(ok, False)
    assert set(h2.judge_cookie(ok, True, "asan")) == {"P7-sanitizer"}
    # no-preset control: only an all-hit result is a valid control
    assert set(h2.judge_cookie(hits, True, control=True)) == {"C1-bypass"}
    uniform_err = dict.fromkeys(h2.SHAPES, "status-400")
    assert set(h2.judge_cookie(uniform_err, True, control=True)) == {
        "C1-bypass", "C3-control-hit"}
    assert h2.classify("CTRL-CK-NO-PRESET", set(
        h2.judge_cookie(uniform_err, True, control=True))) == "control-broken"
    assert h2.classify("CTRL-CK-NO-PRESET", set(
        h2.judge_cookie(hits, True, control=True))) == "control-ok"


# --- H2 oracle ---------------------------------------------------------------

def clean() -> h2.Obs:
    return h2.Obs(victim_body=b"V", victim_status=200, victim_got=b"V")


def test_judge_reject_accepts_400_rst_and_goaway_only() -> None:
    case = BY["H2-PSEUDO-DUP-PATH"]
    assert h2.judge(case, dataclasses.replace(clean(), status=400)) == {}
    assert h2.judge(case, dataclasses.replace(clean(), rst=1)) == {}
    assert h2.judge(case, dataclasses.replace(clean(), goaway=11)) == {}
    assert h2.judge(case, dataclasses.replace(clean(), closed=True)) == {}
    served = dataclasses.replace(clean(), status=200, body=b"V")
    assert set(h2.judge(case, served)) == {"P1-reaction"}
    assert set(h2.judge(case, clean())) == {"P1-reaction"}   # no answer


def test_judge_safe_store_error_store_and_bad_status() -> None:
    case = BY["H2-CONN-TE-TRAILERS"]
    hit = dataclasses.replace(clean(), status=200, body=b"V")
    assert h2.judge(case, hit) == {}
    stored = dataclasses.replace(hit, stored=(10, 1))
    assert set(h2.judge(case, stored)) == {"P2-no-store"}
    err_stored = dataclasses.replace(clean(), status=400, stored=(10, 1))
    assert set(h2.judge(case, err_stored)) == {"P6-error-not-stored"}
    for st in (302, 502):
        assert "P1-reaction" in h2.judge(
            case, dataclasses.replace(clean(), status=st))
    assert h2.judge(case, dataclasses.replace(clean(), status=501)) == {}


def test_judge_own_key_and_either() -> None:
    own = BY["H2-HOST-ONLY-OTHER"]
    mine = dataclasses.replace(clean(), status=200, body=b"O", stored=(9, 1))
    assert h2.judge(own, mine) == {}
    theirs = dataclasses.replace(mine, body=b"V")
    assert set(h2.judge(own, theirs)) == {"P3-own-key"}
    either = BY["H2-AUTH-HOST-CONFLICT"]
    fresh = dataclasses.replace(mine, origin_bodies=(b"O",))
    assert h2.judge(either, fresh) == {}            # own key: store allowed
    foreign = dataclasses.replace(mine, body=b"X")
    assert set(h2.judge(either, foreign)) == {"P3-own-key"}


def test_judge_victim_desync_sanitizer_and_harness() -> None:
    case = BY["CTRL-H2-CLEAN"]
    base = dataclasses.replace(clean(), status=200, body=b"C")
    assert h2.judge(case, base) == {}
    # the clean control must be served 2xx, never rejected
    for bad in (dataclasses.replace(base, status=400),
                dataclasses.replace(base, rst=1)):
        assert set(h2.judge(case, bad)) == {"P1-reaction"}
        assert h2.classify(case.id, set(h2.judge(case, bad))) == "control-broken"
    assert set(h2.judge(case, dataclasses.replace(
        base, victim_got=b"X"))) == {"P4-victim"}
    assert set(h2.judge(case, dataclasses.replace(
        base, victim_status=0))) == {"P4-victim"}
    assert set(h2.judge(case, dataclasses.replace(
        base, unsolicited=("type=1 stream=2",)))) == {"P5-no-desync"}
    assert set(h2.judge(case, dataclasses.replace(
        base, smuggle_seen=True))) == {"P5-no-desync"}
    assert set(h2.judge(case, dataclasses.replace(
        base, sanitizer="nginx died"))) == {"P7-sanitizer"}
    assert h2.HARNESS_PROP in h2.judge(case, dataclasses.replace(
        base, primed=False))


# --- classification ----------------------------------------------------------

def test_classify() -> None:
    known = {"H2-X": frozenset({"P4-victim"})}
    assert h2.classify("H2-Y", set(), known) == "green"
    assert h2.classify("H2-Y", {"P1-reaction"}, known) == "red"
    assert h2.classify("H2-X", {"P4-victim"}, known) == "known-red"
    assert h2.classify("H2-X", set(), known) == "xpass"
    assert h2.classify("H2-X", {"P1-reaction"}, known) == "known-red-drift"
    assert h2.classify("H2-Y", {h2.HARNESS_PROP}, known) == "harness-fail"
    assert h2.classify("CTRL-CK-NO-PRESET", {"C1-bypass"}) == "control-ok"
    assert h2.classify("CTRL-CK-NO-PRESET", set()) == "control-broken"
    assert h2.classify("CTRL-H2-CLEAN", set()) == "control-ok"
    assert h2.classify("CTRL-H2-CLEAN", {"P4-victim"}) == "control-broken"
    for v in ("red", "xpass", "known-red-drift", "control-broken",
              "harness-fail"):
        assert v not in h2.ACCEPTED


def test_known_red_ubsan_gating() -> None:
    assert h2.known_red(False) == h2.H2_KNOWN_RED
    assert set(h2.known_red(True)) == set(h2.H2_KNOWN_RED) | set(
        h2.H2_KNOWN_RED_UBSAN)


def test_h3_skip_reason() -> None:
    assert "without" in h2.h3_skip_reason("configure arguments: "
                                          "--with-http_v2_module")
    assert "no QUIC client" in h2.h3_skip_reason("--with-http_v3_module")


def test_summarize_counts_verdicts() -> None:
    rs = [h2.Result("a", verdict="green"), h2.Result("b", verdict="green"),
          h2.Result("c", verdict="skip")]
    assert h2.summarize(rs) == {"total": 3, "green": 2, "skip": 1}


def test_config_has_h2_listener_and_every_preset_location(tmp_path) -> None:
    presets = sorted(h2.preset_needles())
    on = h2._config(tmp_path, 1, 2, "on", None, 3, presets)
    assert "listen 127.0.0.1:2;" in on and "http2 on;" in on
    legacy = h2._config(tmp_path, 1, 2, "listen", "/m.so", 3, presets)
    assert "listen 127.0.0.1:2 http2;" in legacy and "http2 on" not in legacy
    assert legacy.startswith("load_module /m.so;")
    for p in presets:
        assert f"location /p-{p}/ {{ cache_turbo_backend {p};" in on
    assert f"location /{h2.LOC_NONE}/ {{ cache_turbo " in on
