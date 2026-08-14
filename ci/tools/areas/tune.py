"""cache-turbo runtime tests — tune area.

Split out of ci/tools/test_runtime.py (MAINT-T1). Tests live here; the fixtures,
Origin/Nginx harness and helpers stay in test_runtime_base. test_runtime
star-imports this module, so every test stays reachable as
``test_runtime.<name>`` (run_named.py) and as a bare name inside run_all()
(lint-orphan-tests.py).
"""

from __future__ import annotations

# Underscore-prefixed names are NOT re-exported by `import *`, so the
# private helpers this module actually calls are imported explicitly.
from test_runtime_base import *
from test_runtime_base import (
    _config_test_result,
)


def test_normalize_arg_order(ng: Nginx, origin: Origin) -> None:
    """v3-1: ?b=2&a=1 and ?a=1&b=2 normalize to one cache slot — the reordered
    second request is a HIT serving the first body, origin hit exactly once."""
    base = origin.hits_for("/order")
    s1, b1, h1 = fetch(ng.port, "/n/order?b=2&a=1")
    assert s1 == 200 and "x-cache" not in h1, "first request should miss to origin"
    _s2, b2, h2 = fetch(ng.port, "/n/order?a=1&b=2")
    assert h2.get("x-cache") == "HIT", \
        f"reordered args should HIT, got X-Cache={h2.get('x-cache')}"
    assert b2 == b1, "reordered request served a different body"
    assert origin.hits_for("/order") == base + 1, \
        f"origin hit {origin.hits_for('/order') - base} times (args not normalized to one key)"


def test_normalize_strips_tracking(ng: Nginx, origin: Origin) -> None:
    """Built-in denylist: utm_* and fbclid are dropped, so ?p=1&utm_source=x&
    fbclid=y collapses onto the same slot as a bare ?p=1."""
    base = origin.hits_for("/track")
    _, b1, h1 = fetch(ng.port, "/n/track?p=1")
    assert "x-cache" not in h1, "prime should miss to origin"
    _, b2, h2 = fetch(ng.port, "/n/track?p=1&utm_source=news&utm_medium=cpc&fbclid=z")
    assert h2.get("x-cache") == "HIT", \
        f"tracking-only diff should HIT, got X-Cache={h2.get('x-cache')}"
    assert b2 == b1, "tracking-laden request served a different body"
    assert origin.hits_for("/track") == base + 1, "tracking params were not stripped from the key"


def test_normalize_strip_custom(ng: Nginx, origin: Origin) -> None:
    """cache_turbo_normalize_strip adds exact ("sid") and prefix ("tmp_*")
    patterns on top of the defaults; a request differing only in those HITs."""
    base = origin.hits
    _, b1, h1 = fetch(ng.port, "/ns/page?keep=1")
    assert "x-cache" not in h1, "prime should miss to origin"
    _, b2, h2 = fetch(ng.port, "/ns/page?sid=abc&keep=1&tmp_foo=9&utm_source=x")
    assert h2.get("x-cache") == "HIT", \
        f"custom-stripped diff should HIT, got X-Cache={h2.get('x-cache')}"
    assert b2 == b1, "custom-stripped request served a different body"
    assert origin.hits == base + 1, "custom strip patterns not applied"


def test_normalize_strip_all(ng: Nginx, origin: Origin) -> None:
    """cache_turbo_normalize_strip "*" drops EVERY arg (a bare '*' is a
    zero-length prefix that matches every name), so wholly different query
    strings on the same path share one cache slot."""
    base = origin.hits
    _, b1, h1 = fetch(ng.port, "/na/x?anything=1&here=2")
    assert "x-cache" not in h1, "prime should miss to origin"
    _, b2, h2 = fetch(ng.port, "/na/x?totally=different&set=ofargs")
    assert h2.get("x-cache") == "HIT", \
        f"strip_all should collapse all args to one slot, got {h2.get('x-cache')}"
    assert b2 == b1, "strip_all served a different body"
    assert origin.hits == base + 1, "strip_all did not drop all args"


def test_normalize_distinct_args_differ(ng: Nginx, origin: Origin) -> None:
    """Guard against over-normalizing: a meaningful arg difference (a=1 vs a=2)
    must remain two distinct cache slots, not collapse to one."""
    base = origin.hits_for("/distinct")
    _, b1, h1 = fetch(ng.port, "/n/distinct?a=1")
    assert "x-cache" not in h1, "first should miss"
    _, b2, h2 = fetch(ng.port, "/n/distinct?a=2")
    assert "x-cache" not in h2, \
        f"a different value must MISS, got X-Cache={h2.get('x-cache')}"
    assert b2 != b1, "distinct args wrongly served the same cached body"
    assert origin.hits_for("/distinct") == base + 2, "both distinct args should reach origin"


# UA strings whose device class is unambiguous for the substring matcher.
_UA_MOBILE = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
              "AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1")
_UA_DESKTOP = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
               "Chrome/124.0 Safari/537.36")


def test_normalize_vary_encoding(ng: Nginx, origin: Origin) -> None:
    """v3-4: cache_turbo_normalize_vary encoding splits the key by Accept-Encoding
    CLASS (br/gzip/identity). br and gzip get separate slots (each its own origin
    fetch); two br requests share one slot. The raw header still collapses to the
    class, so 'br, deflate' HITs the 'br' entry."""
    base = origin.hits
    _, b1, h1 = fetch(ng.port, "/ve/p", headers={"Accept-Encoding": "br"})
    assert "x-cache" not in h1, "first (br) request should miss to origin"
    _, b2, h2 = fetch(ng.port, "/ve/p", headers={"Accept-Encoding": "gzip"})
    assert "x-cache" not in h2, \
        f"gzip must be a separate slot from br, got X-Cache={h2.get('x-cache')}"
    assert b2 != b1, "gzip slot served the br body"
    assert origin.hits == base + 2, "br and gzip should each reach origin once"
    _, b3, h3 = fetch(ng.port, "/ve/p", headers={"Accept-Encoding": "br, deflate"})
    assert h3.get("x-cache") == "HIT", \
        f"second br request should HIT, got X-Cache={h3.get('x-cache')}"
    assert b3 == b1, "two br requests must share one slot"
    assert origin.hits == base + 2, "second br request wrongly hit origin"


def test_normalize_vary_device(ng: Nginx, origin: Origin) -> None:
    """v3-4: cache_turbo_normalize_vary device splits the key by User-Agent device
    class (mobile/desktop). A mobile and a desktop UA get separate slots; a second
    mobile UA (different mobile token) shares the mobile slot."""
    base = origin.hits
    _, b1, h1 = fetch(ng.port, "/vd/p", headers={"User-Agent": _UA_MOBILE})
    assert "x-cache" not in h1, "first (mobile) request should miss to origin"
    _, b2, h2 = fetch(ng.port, "/vd/p", headers={"User-Agent": _UA_DESKTOP})
    assert "x-cache" not in h2, \
        f"desktop must be a separate slot from mobile, got {h2.get('x-cache')}"
    assert b2 != b1, "desktop slot served the mobile body"
    assert origin.hits == base + 2, "mobile and desktop should each reach origin"
    # a different mobile UA (Android) still classes as mobile -> HIT the slot
    _, b3, h3 = fetch(ng.port, "/vd/p",
                      headers={"User-Agent": "Mozilla/5.0 (Linux; Android 13) Mobile"})
    assert h3.get("x-cache") == "HIT", \
        f"second mobile UA should HIT the mobile slot, got {h3.get('x-cache')}"
    assert b3 == b1, "two mobile UAs must share one slot"
    assert origin.hits == base + 2, "second mobile request wrongly hit origin"


def test_normalize_vary_both(ng: Nginx, origin: Origin) -> None:
    """v3-4: encoding and device compose — (br,mobile) and (gzip,desktop) are two
    distinct slots, and each repeats as a HIT of its own slot."""
    base = origin.hits
    br_mob = {"Accept-Encoding": "br", "User-Agent": _UA_MOBILE}
    gz_desk = {"Accept-Encoding": "gzip", "User-Agent": _UA_DESKTOP}
    _, b1, h1 = fetch(ng.port, "/vb/p", headers=br_mob)
    assert "x-cache" not in h1, "(br,mobile) should miss"
    _, b2, h2 = fetch(ng.port, "/vb/p", headers=gz_desk)
    assert "x-cache" not in h2, \
        f"(gzip,desktop) must be its own slot, got {h2.get('x-cache')}"
    assert b2 != b1, "(gzip,desktop) served the (br,mobile) body"
    assert origin.hits == base + 2, "both compose-buckets should reach origin"
    _, b3, h3 = fetch(ng.port, "/vb/p", headers=br_mob)
    assert h3.get("x-cache") == "HIT" and b3 == b1, "(br,mobile) repeat should HIT"
    _, b4, h4 = fetch(ng.port, "/vb/p", headers=gz_desk)
    assert h4.get("x-cache") == "HIT" and b4 == b2, "(gzip,desktop) repeat should HIT"
    assert origin.hits == base + 2, "compose-bucket repeats wrongly hit origin"


def test_normalize_vary_off_by_default(ng: Nginx, origin: Origin) -> None:
    """v3-4 regression guard: WITHOUT cache_turbo_normalize_vary (location /n/),
    differing Accept-Encoding and User-Agent must NOT split the key — the v3-1
    normalized key is byte-identical, so the second request HITs the first slot."""
    base = origin.hits_for("/voff")
    _, b1, h1 = fetch(ng.port, "/n/voff",
                      headers={"Accept-Encoding": "br", "User-Agent": _UA_MOBILE})
    assert "x-cache" not in h1, "prime should miss to origin"
    _, b2, h2 = fetch(ng.port, "/n/voff",
                      headers={"Accept-Encoding": "gzip", "User-Agent": _UA_DESKTOP})
    assert h2.get("x-cache") == "HIT", \
        ("vary off: differing encoding/device must still HIT one slot, "
         f"got X-Cache={h2.get('x-cache')}")
    assert b2 == b1, "vary off served a different body (key wrongly split)"
    assert origin.hits_for("/voff") == base + 1, "vary off must keep one slot regardless of headers"


def test_normalize_vary_encoding_zstd(ng: Nginx, origin: Origin) -> None:
    """v4-3 (issues V6): the encoding bucket ranks zstd ABOVE br — we ship
    http-zstd, which serves zstd whenever the client advertises it (winning over
    brotli/gzip). So zstd / br / gzip are three distinct slots, two zstd requests
    share one, and a zstd-only client never reads the identity slot. 'zstd, br'
    collapses to the zstd class (HITs the zstd entry, not br)."""
    base = origin.hits
    _, bz, hz = fetch(ng.port, "/ve/z", headers={"Accept-Encoding": "zstd"})
    assert "x-cache" not in hz, "first (zstd) request should miss to origin"
    _, bb, hb = fetch(ng.port, "/ve/z", headers={"Accept-Encoding": "br"})
    assert "x-cache" not in hb, \
        f"br must be a separate slot from zstd, got X-Cache={hb.get('x-cache')}"
    _, bg, hg = fetch(ng.port, "/ve/z", headers={"Accept-Encoding": "gzip"})
    assert "x-cache" not in hg, \
        f"gzip must be a separate slot, got X-Cache={hg.get('x-cache')}"
    assert len({bz, bb, bg}) == 3, "zstd/br/gzip must be three distinct slots"
    assert origin.hits == base + 3, "zstd/br/gzip should each reach origin once"

    # identity client (no Accept-Encoding) must not read the zstd entry
    _, bi, hi = fetch(ng.port, "/ve/z")
    assert "x-cache" not in hi, \
        f"zstd-only entry must not serve an identity client, got {hi.get('x-cache')}"
    assert bi not in (bz, bb, bg), "identity slot served an encoded-class body"

    # two zstd share one slot; 'zstd, br' collapses to the zstd class
    _, bz2, hz2 = fetch(ng.port, "/ve/z", headers={"Accept-Encoding": "zstd, br"})
    assert hz2.get("x-cache") == "HIT", \
        f"second zstd request should HIT the zstd slot, got X-Cache={hz2.get('x-cache')}"
    assert bz2 == bz, "two zstd requests must share one slot"


def test_invalid_normalize_vary_token(ng: Nginx) -> None:
    """v3-4: an unknown cache_turbo_normalize_vary token is rejected at config
    time (nginx -t fails) with a clear message, not silently ignored."""
    bad = ng.root.parent / "bad-vary"
    (bad / "conf").mkdir(parents=True, exist_ok=True)
    (bad / "logs").mkdir(parents=True, exist_ok=True)
    cfg = nginx_config(bad, ng.port, ng.module, ng.origin_port, 1)
    cfg = cfg.replace("cache_turbo_normalize_vary encoding;",
                      "cache_turbo_normalize_vary bogus;")
    (bad / "conf" / "nginx.conf").write_text(cfg, encoding="ascii")
    cmd = ng.runner + [str(ng.binary), "-p", str(bad),
                       "-c", str(bad / "conf" / "nginx.conf"), "-t"]
    r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=20)
    assert r.returncode != 0, \
        f"invalid vary token 'bogus' was accepted by nginx -t:\n{r.stdout}"
    assert "invalid cache_turbo_normalize_vary" in r.stdout, \
        f"missing/odd diagnostic for bad vary token:\n{r.stdout}"


def test_auto_vary_encoding(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary: a response `Vary: Accept-Encoding` makes the module split
    by the Accept-Encoding class automatically (no operator config). Same class
    collapses onto one slot; a different class is a distinct slot."""
    base = origin.hits
    p = "/av/enc?v=ae"
    _, b1, _ = fetch(ng.port, p, {"Accept-Encoding": "gzip"})  # cold -> origin
    _, b2, _ = fetch(ng.port, p, {"Accept-Encoding": "gzip"})  # marker -> HIT
    assert b1 == b2, (b1, b2)
    _, b3, _ = fetch(ng.port, p, {"Accept-Encoding": "br"})    # new variant
    _, b4, _ = fetch(ng.port, p, {"Accept-Encoding": "br"})    # HIT
    assert b3 == b4, (b3, b4)
    assert b1 != b3, ("gzip and br shared a slot", b1, b3)
    _, b5, _ = fetch(ng.port, p, {"Accept-Encoding": "gzip"})  # still its slot
    assert b5 == b1, (b5, b1)
    assert origin.hits - base == 2, origin.hits - base


def test_auto_vary_marker_probe_selects_correct_variant(ng: Nginx,
                                                          origin: Origin) -> None:
    """S231-PERF-VARYLOCK pin: the vary-marker probe now runs inside the SAME
    zone-mutex critical section as the main L1 lookup (previously its own
    separate lock/unlock pair). Re-assert the marker probe's actual job —
    correct HIT/MISS + variant selection across THREE distinct Accept-Encoding
    classes on one URL, interleaved so a wrong fold (e.g. always resolving to
    whichever variant happened to be looked up last, or the base key never
    updating) would show up as a MISS where a HIT is expected or as one
    variant's body leaking into another's slot. X-CT-Status is the canary
    (not just body equality — see test_auto_vary_language_primary_subtag_shares
    for why body-only assertions are not a real oracle here)."""
    base = origin.hits_for("/vlock?v=ae")
    p = "/av/vlock?v=ae"
    gz = {"Accept-Encoding": "gzip"}
    br = {"Accept-Encoding": "br"}
    zs = {"Accept-Encoding": "zstd"}

    # First touch of each variant: no marker yet (or a marker for a DIFFERENT
    # variant) -> MISS, one origin hit each.
    _, gz1, hgz1 = fetch(ng.port, p, gz)
    assert hgz1.get("x-ct-status") == "MISS", \
        f"gzip cold fetch must MISS, got {hgz1.get('x-ct-status')}"
    _, br1, _ = fetch(ng.port, p, br)
    _, zs1, _ = fetch(ng.port, p, zs)
    assert origin.hits_for("/vlock?v=ae") - base == 3, \
        origin.hits_for("/vlock?v=ae") - base

    # Re-probe each variant, interleaved (not sequential re-hits of the same
    # one) so the marker lookup must resolve the RIGHT variant key every time,
    # not just "the last one resolved". Each must now HIT its own slot and
    # never cross-serve another variant's body.
    _, gz2, hgz2 = fetch(ng.port, p, gz)
    _, zs2, hzs2 = fetch(ng.port, p, zs)
    _, br2, hbr2 = fetch(ng.port, p, br)

    assert hgz2.get("x-ct-status") == "HIT", f"gzip re-fetch must HIT, got {hgz2}"
    assert hbr2.get("x-ct-status") == "HIT", f"br re-fetch must HIT, got {hbr2}"
    assert hzs2.get("x-ct-status") == "HIT", f"zstd re-fetch must HIT, got {hzs2}"

    assert gz1 == gz2, ("gzip slot changed body across HIT", gz1, gz2)
    assert br1 == br2, ("br slot changed body across HIT", br1, br2)
    assert zs1 == zs2, ("zstd slot changed body across HIT", zs1, zs2)

    assert gz1 != br1 and gz1 != zs1 and br1 != zs1, \
        ("two variants shared a slot", gz1, br1, zs1)

    # No new origin hits: every second-round request must have resolved via
    # its own marker + variant key, not fallen back to the base key.
    assert origin.hits_for("/vlock?v=ae") - base == 3, (
        "a marker-probe/main-lookup fold regression sent a HIT-eligible "
        "variant back to origin",
        origin.hits_for("/vlock?v=ae") - base)


def test_auto_vary_encoding_same_class_shares(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary: two Accept-Encoding headers in the same bucket (gzip and
    'gzip, deflate' both classify gzip) share one slot -> one origin hit."""
    base = origin.hits_for("/encsame?v=ae")
    p = "/av/encsame?v=ae"
    _, b1, _ = fetch(ng.port, p, {"Accept-Encoding": "gzip"})
    _, b2, _ = fetch(ng.port, p, {"Accept-Encoding": "gzip, deflate"})
    assert b1 == b2, (b1, b2)
    assert origin.hits_for("/encsame?v=ae") - base == 1, origin.hits_for("/encsame?v=ae") - base


def test_auto_vary_device(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary: `Vary: User-Agent` splits by the coarse device class."""
    base = origin.hits_for("/dev?v=ua")
    p = "/av/dev?v=ua"
    mob = {"User-Agent": "Mozilla/5.0 (iPhone; CPU) Mobile"}
    dsk = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
    _, m1, _ = fetch(ng.port, p, mob)
    _, m2, _ = fetch(ng.port, p, mob)
    _, d1, _ = fetch(ng.port, p, dsk)
    _, d2, _ = fetch(ng.port, p, dsk)
    assert m1 == m2 and d1 == d2, (m1, m2, d1, d2)
    assert m1 != d1, ("mobile and desktop shared a slot", m1, d1)
    assert origin.hits_for("/dev?v=ua") - base == 2, origin.hits_for("/dev?v=ua") - base


def test_auto_vary_language(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary: `Vary: Accept-Language` splits by the LANG axis class
    (S7: primary-subtag class, not the raw header)."""
    base = origin.hits_for("/lang?v=al")
    p = "/av/lang?v=al"
    _, e1, _ = fetch(ng.port, p, {"Accept-Language": "en"})
    _, e2, _ = fetch(ng.port, p, {"Accept-Language": "en"})
    _, f1, _ = fetch(ng.port, p, {"Accept-Language": "fr"})
    assert e1 == e2, (e1, e2)
    assert e1 != f1, ("en and fr shared a slot", e1, f1)
    assert origin.hits_for("/lang?v=al") - base == 2, origin.hits_for("/lang?v=al") - base


def test_auto_vary_language_primary_subtag_shares(ng: Nginx,
                                                    origin: Origin) -> None:
    """S7: LANG folds to the primary-subtag CLASS, so `en-US,en;q=0.9` and
    `en-GB,en;q=0.8` -- distinct raw headers, same primary subtag `en` -- now
    SHARE one slot -> a single origin hit. This is the actual fix: before S7
    the raw fold gave each browser locale string its own variant, blowing up
    the keyspace on an i18n site for representations that are byte-identical.
    Canary: $cache_turbo_status (echoed as X-CT-Status) is HIT on the second
    request, not just "body matches"."""
    base = origin.hits_for("/langshare?v=al")
    p = "/av/langshare?v=al"
    s1, b1, h1 = fetch(ng.port, p, {"Accept-Language": "en-US,en;q=0.9"})
    s2, b2, h2 = fetch(ng.port, p, {"Accept-Language": "en-GB,en;q=0.8"})
    assert s1 == 200 and s2 == 200, (s1, s2)
    assert b1 == b2, ("en-US and en-GB did not share a slot", b1, b2)
    # The canary the docstring promises. Body identity alone is equally
    # satisfied by two independent origin misses returning the same bytes;
    # only the HIT proves en-GB landed on the slot en-US filled.
    assert h1.get("x-ct-status") == "MISS", \
        f"en-US should prime the 'en' class slot, got {h1.get('x-ct-status')}"
    assert h2.get("x-ct-status") == "HIT", \
        ("en-GB must HIT the slot en-US filled, not re-fetch an identical body",
         h2.get("x-ct-status"))
    assert origin.hits_for("/langshare?v=al") - base == 1, \
        ("en-US and en-GB should fold to one 'en' class -> one origin hit",
         origin.hits_for("/langshare?v=al") - base)


def test_auto_vary_language_different_primary_splits(ng: Nginx,
                                                       origin: Origin) -> None:
    """S7 negative guard: `en` and `de` are DIFFERENT primary subtags and must
    still SPLIT into distinct slots -- proves the fold isn't over-collapsing
    everything to one class."""
    base = origin.hits_for("/langsplit?v=al")
    p = "/av/langsplit?v=al"
    _, en1, _ = fetch(ng.port, p, {"Accept-Language": "en-US,en;q=0.9"})
    _, en2, _ = fetch(ng.port, p, {"Accept-Language": "en-GB,en;q=0.8"})
    _, de1, _ = fetch(ng.port, p, {"Accept-Language": "de-DE,de;q=0.9"})
    assert en1 == en2, ("en variants should still share", en1, en2)
    assert en1 != de1, ("en and de shared a slot", en1, de1)
    assert origin.hits_for("/langsplit?v=al") - base == 2, origin.hits_for("/langsplit?v=al") - base


def test_auto_vary_language_absent_splits_from_class(ng: Nginx,
                                                       origin: Origin) -> None:
    """S7: an absent Accept-Language header folds to its OWN empty class "" --
    it must still split from a present `en` header, not collide with it (the
    empty class is skip-shaped but must NOT be skipped: skipping the axis
    would collide a present-but-empty header with an absent one)."""
    base = origin.hits_for("/langabsent?v=al")
    p = "/av/langabsent?v=al"
    s1, absent1, _h1 = fetch(ng.port, p)  # no Accept-Language header at all
    s2, absent2, _h2 = fetch(ng.port, p)
    s3, en1, _h3 = fetch(ng.port, p, {"Accept-Language": "en-US,en;q=0.9"})
    assert s1 == 200 and s2 == 200 and s3 == 200, (s1, s2, s3)
    assert absent1 == absent2, ("absent header should share its own slot",
                                 absent1, absent2)
    assert absent1 != en1, ("absent Accept-Language shared a slot with 'en'",
                             absent1, en1)
    assert origin.hits_for("/langabsent?v=al") - base == 2, origin.hits_for("/langabsent?v=al") - base


def test_auto_vary_origin(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary: `Vary: Origin` splits by the raw Origin header value.
    ORIGIN is a CORS security boundary and is NEVER class-folded (S7 touches
    LANG only) -- two distinct Origins must still split into distinct slots."""
    base = origin.hits_for("/org?v=or")
    p = "/av/org?v=or"
    _, a1, _ = fetch(ng.port, p, {"Origin": "https://a.example"})
    _, a2, _ = fetch(ng.port, p, {"Origin": "https://a.example"})
    _, c1, _ = fetch(ng.port, p, {"Origin": "https://b.example"})
    assert a1 == a2, (a1, a2)
    assert a1 != c1, ("two Origins shared a slot", a1, c1)
    assert origin.hits_for("/org?v=or") - base == 2, origin.hits_for("/org?v=or") - base


def test_auto_vary_origin_not_class_folded(ng: Nginx, origin: Origin) -> None:
    """S7 regression guard: ORIGIN must stay RAW and is NEVER class-folded like
    LANG. Two distinct origins that share the same first 8 bytes (the LANG fold
    length, NGX_HTTP_CACHE_TURBO_LANG_CLASS_MAX) and the same "scheme + first
    label up to a '-'" shape -- i.e. exactly what a primary-subtag-style fold
    would collapse -- must still split into distinct slots and cause TWO
    origin hits. If ORIGIN were ever folded the way LANG is (cut at a
    delimiter, lowercase, cap at 8 bytes), these two would collide into one
    slot: both start with the identical 8-byte prefix "https://" and share the
    same leading label "a-one" / "a-two" up to a hyphen-cut point that overlaps
    ("a"), so a class-fold bug reusing the lang-style cut would alias them.
    Folding https://a-one.example with https://a-two.example would serve one
    origin's CORS headers to the other -- a real security bug, not just a
    cache-efficiency regression."""
    base = origin.hits_for("/orgnofold?v=or")
    p = "/av/orgnofold?v=or"
    o1 = "https://a-one.example"
    o2 = "https://a-two.example"
    s1, b1, _h1 = fetch(ng.port, p, {"Origin": o1})
    s2, b2, _h2 = fetch(ng.port, p, {"Origin": o1})
    s3, b3, _h3 = fetch(ng.port, p, {"Origin": o2})
    assert s1 == 200 and s2 == 200 and s3 == 200, (s1, s2, s3)
    assert b1 == b2, ("same Origin should share a slot", b1, b2)
    assert b1 != b3, (
        "ORIGIN got class-folded -- two distinct origins sharing an 8-byte "
        "prefix collapsed onto one slot; this is a CORS cross-origin leak",
        b1, b3)
    assert origin.hits_for("/orgnofold?v=or") - base == 2, (
        "ORIGIN must stay raw: two distinct origins => two origin hits, "
        "not one folded class", origin.hits_for("/orgnofold?v=or") - base)


def test_auto_vary_star_uncacheable(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary: `Vary: *` is uncacheable -> every request hits origin."""
    base = origin.hits_for("/star?v=star")
    p = "/av/star?v=star"
    _, b1, _ = fetch(ng.port, p)
    _, b2, _ = fetch(ng.port, p)
    assert b1 != b2, ("Vary: * was cached", b1, b2)
    assert origin.hits_for("/star?v=star") - base == 2, origin.hits_for("/star?v=star") - base


def test_auto_vary_cookie_uncacheable(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary: `Vary: Cookie` is refused (per-user) -> not cached."""
    base = origin.hits_for("/ck?v=ck")
    p = "/av/ck?v=ck"
    _, b1, _ = fetch(ng.port, p)
    _, b2, _ = fetch(ng.port, p)
    assert b1 != b2, ("Vary: Cookie was cached", b1, b2)
    assert origin.hits_for("/ck?v=ck") - base == 2, origin.hits_for("/ck?v=ck") - base


def test_auto_vary_mixed_refused_wins(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary: `Vary: Accept-Encoding, Cookie` -> the refused Cookie axis
    wins over the safe encoding axis, so the response is not cached at all."""
    base = origin.hits_for("/mix?v=mix")
    p = "/av/mix?v=mix"
    _, b1, _ = fetch(ng.port, p, {"Accept-Encoding": "gzip"})
    _, b2, _ = fetch(ng.port, p, {"Accept-Encoding": "gzip"})
    assert b1 != b2, ("mixed safe+refused Vary was cached", b1, b2)
    assert origin.hits_for("/mix?v=mix") - base == 2, origin.hits_for("/mix?v=mix") - base


def test_auto_vary_off_ignores_vary(ng: Nginx, origin: Origin) -> None:
    """S231-VARY: `cache_turbo_auto_vary off;` (explicit, no longer the shipped
    default -- see test_auto_vary_shipped_default_* below) still ignores the
    response Vary header, so two different Accept-Encodings collapse onto one
    slot (back-compat for an operator who opts back out)."""
    base = origin.hits
    p = "/avoff/enc?v=ae"
    _, b1, _ = fetch(ng.port, p, {"Accept-Encoding": "gzip"})
    _, b2, _ = fetch(ng.port, p, {"Accept-Encoding": "br"})
    assert b1 == b2, ("auto_vary off still split by Vary", b1, b2)
    assert origin.hits - base == 1, origin.hits - base


def test_auto_vary_shipped_default_splits_encoding(ng: Nginx, origin: Origin) -> None:
    """S231-VARY: `/avdefault/` sets NO cache_turbo_auto_vary directive at all
    -- proves the compiled-in merge default is 1, not just that `on;` works
    when written out. A safe axis (Accept-Encoding) must still split, exactly
    like the explicit-`on;` /av/ location does in test_auto_vary_encoding."""
    base = origin.hits
    p = "/avdefault/enc?v=ae"
    _, b1, _ = fetch(ng.port, p, {"Accept-Encoding": "gzip"})
    _, b2, _ = fetch(ng.port, p, {"Accept-Encoding": "gzip"})
    assert b1 == b2, (b1, b2)
    _, b3, _ = fetch(ng.port, p, {"Accept-Encoding": "br"})
    assert b1 != b3, ("shipped default: gzip and br shared a slot", b1, b3)
    assert origin.hits - base == 2, origin.hits - base


def test_auto_vary_shipped_default_cookie_refused(ng: Nginx, origin: Origin) -> None:
    """S231-VARY: with NO cache_turbo_auto_vary directive, `Vary: Cookie` must
    still be refused (the veto at ~:7918 only fires when clcf->auto_vary is
    true). This is the privacy defect the shipped-default flip closes: while
    the default was off, this veto was dead code on the stale-serve path.

    Two DIFFERENT cookies, so this asserts the per-user case the veto exists
    for and not merely "the second request missed": if the response were ever
    stored under the Vary-blind base key, user b would be served user a's body.
    The veto keys on the RESPONSE's Vary header, so the cookie values only have
    to differ -- they are what makes a wrong-serve observable."""
    base = origin.hits
    p = "/avdefault/ck?v=ck"
    _, b1, _ = fetch(ng.port, p, headers={"Cookie": "ct_user=a"})
    _, b2, _ = fetch(ng.port, p, headers={"Cookie": "ct_user=b"})
    assert b1 != b2, ("shipped default: Vary: Cookie was cached", b1, b2)
    assert origin.hits - base == 2, origin.hits - base


def test_preset_window_differs(ng: Nginx, origin: Origin) -> None:
    """v3-2: a preset sets the stale-window multiplier. With cache_turbo_valid
    pinned to 1s on both locations, the only difference is the preset: the
    conservative band (x2) makes the entry serveable for 2s, the aggressive band
    (x8) for 8s. At t=3s the conservative copy is hard-expired (a MISS, re-fetch)
    while the aggressive copy is still serveable as stale. This asserts the
    PRESET'S effect, not its stored value, and proves the band reaches the
    runtime stale math (stale_mult threaded through shm_store)."""
    fetch(ng.port, "/pc/win")                          # prime conservative
    # H3c: the aggressive band is min_uses=2, so the FIRST request to a cold key
    # under /pa/ is gated to the origin without storing. Prime twice -- the
    # second request is the one that actually stores the entry whose stale
    # window this test measures. (Conservative is min_uses=1, one prime is
    # enough.) Without this the aggressive arm has nothing cached at t=3s and
    # the STALE assertion below fails for a reason unrelated to stale_mult.
    fetch(ng.port, "/pa/win")                          # aggressive: gated miss
    fetch(ng.port, "/pa/win")                          # aggressive: stores
    time.sleep(3.0)                                     # cons expired, aggr stale

    # conservative: past stale_until -> a true MISS (no X-Cache, hits origin)
    sc, _, hc = fetch(ng.port, "/pc/win")
    assert sc == 200, f"conservative re-read status {sc}"
    assert "x-cache" not in hc, \
        ("conservative (stale_mult=2) should hard-expire by t=3s and MISS, "
         f"got X-Cache={hc.get('x-cache')}")

    # aggressive: still within its 8s window. Burst so single-flight forces the
    # losers to serve stale (the lone dice-winner may regenerate); at least one
    # STALE proves the entry is still serveable, i.e. the wider band took effect.
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: fetch(ng.port, "/pa/win"), range(16)))
    assert {r[0] for r in results} == {200}, \
        f"aggressive stale burst returned {set(r[0] for r in results)}"
    assert any(h.get("x-cache") == "STALE" for _, _, h in results), \
        ("aggressive (stale_mult=8) should still serve STALE at t=3s; "
         "got " + repr(sorted(str(h.get('x-cache')) for _, _, h in results)))
    drain_origin(origin)       # v8: settle async bg refreshes before the next test


def test_stale_mult_directive_beats_preset(ng: Nginx, origin: Origin) -> None:
    """H5: an explicit cache_turbo_stale_mult overrides the resolved preset's
    band multiplier, the same way cache_turbo_valid/_beta/_lock_ttl already do.

    /psm/ carries `cache_turbo_preset aggressive` (band stale_mult=8) plus
    `cache_turbo_stale_mult 1`. The paired assertion is what makes this
    load-bearing: /pa/ is the SAME preset and the SAME 1s fresh TTL and is
    still serveable as STALE at t=3s, so if the directive were ignored /psm/
    would behave identically. It must instead hard-expire and MISS -- proving
    the raw value reached the runtime stale math and beat the band, not merely
    that some window exists."""
    # H3c: both locations resolve the aggressive band, whose min_uses is 2, so
    # the first request to each cold key is gated to the origin without storing.
    # Prime twice -- the second request is the one that stores the entry whose
    # stale window this test measures. This is admission, orthogonal to the
    # stale_mult precedence under test.
    fetch(ng.port, "/psm/win")                         # gated miss
    fetch(ng.port, "/psm/win")                         # prime (stores)
    fetch(ng.port, "/pa/win2")                         # gated miss
    fetch(ng.port, "/pa/win2")                         # control prime (stores)
    time.sleep(3.0)

    # directive wins: stale_mult=1 -> stale_until == fresh_until -> hard MISS
    s, _, h = fetch(ng.port, "/psm/win")
    assert s == 200, f"stale_mult=1 re-read status {s}"
    assert "x-cache" not in h, \
        ("explicit cache_turbo_stale_mult 1 should hard-expire at 1s and MISS, "
         f"got X-Cache={h.get('x-cache')} -- the directive lost to the "
         "aggressive band (stale_mult=8), i.e. the raw/effective split is "
         "not wired")

    # control: same preset, no directive -> the band's 8s window still applies,
    # so the difference above is attributable to the directive alone.
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: fetch(ng.port, "/pa/win2"), range(16)))
    assert any(h.get("x-cache") == "STALE" for _, _, h in results), \
        ("control /pa/ (aggressive band, no directive) should still serve "
         "STALE at t=3s; got "
         + repr(sorted(str(h.get('x-cache')) for _, _, h in results)))
    drain_origin(origin)


def test_stale_mult_rejects_out_of_range(ng: Nginx) -> None:
    """H5: cache_turbo_stale_mult is range-checked at config time.

    `0` is the arm that matters: ngx_http_cache_turbo_stale_ttl() coerces a
    non-positive multiplier back to the BALANCED default of 4, so accepting a
    literal 0 would silently give the operator a 4x stale window instead of the
    "no stale window" they asked for. Rejecting it at parse is what keeps the
    directive honest. The boundaries 1 and 8 must still be accepted, so an
    off-by-one range check fails here rather than passing unnoticed."""
    anchor = "cache_turbo_stale_mult  1;"
    assert anchor in nginx_config(
        ng.root, ng.port, ng.module, ng.origin_port, 1, ng.redis_port,
        ng.redis_auth_port, ng.redis_password, ng.redis_tls_port,
        ng.redis_tls_ca, ng.memcached_port), \
        f"test fixture missing anchor {anchor!r}"

    # in-range-check arm: parses fine as a number, refused by the bounds
    for bad in ("0", "9"):
        r = _config_test_result(
            ng, lambda c, b=bad: c.replace(
                anchor, f"cache_turbo_stale_mult  {b};", 1))
        assert r.returncode != 0, \
            f"cache_turbo_stale_mult {bad} was accepted by nginx -t:\n{r.stdout}"
        assert "out of range" in r.stdout, \
            f"missing/odd range diagnostic for {bad}:\n{r.stdout}"

    # parse arm: ngx_atoi has no sign handling, so a negative never reaches the
    # bounds check and surfaces as "bad value" -- still rejected, different
    # diagnostic. Pinned so the two paths can't be collapsed by a later editor.
    for bad in ("-1", "abc"):
        r = _config_test_result(
            ng, lambda c, b=bad: c.replace(
                anchor, f"cache_turbo_stale_mult  {b};", 1))
        assert r.returncode != 0, \
            f"cache_turbo_stale_mult {bad} was accepted by nginx -t:\n{r.stdout}"
        assert "bad value" in r.stdout, \
            f"missing/odd bad-value diagnostic for {bad}:\n{r.stdout}"

    # both boundaries stay legal
    for good in ("1", "8"):
        r = _config_test_result(
            ng, lambda c, g=good: c.replace(
                anchor, f"cache_turbo_stale_mult  {g};", 1))
        assert r.returncode == 0, \
            f"cache_turbo_stale_mult {good} (a legal boundary) was rejected:\n{r.stdout}"


def test_preset_micro_default_ttl(ng: Nginx, origin: Origin) -> None:
    """micro preset: with NO explicit cache_turbo_valid the band's own 1s fresh
    TTL takes effect (stale_mult=2 -> entry hard-expires at ~2s). An immediate
    re-read is a fresh HIT; by t=3s the entry is gone and the next read MISSes.
    A >=30s default (any other preset's band) would still HIT at t=3s, so this
    proves micro's 1s default-valid band reaches the runtime freshness math
    without an explicit knob."""
    sc, _, hc = fetch(ng.port, "/pm/win")              # prime (MISS, no X-Cache)
    assert sc == 200 and "x-cache" not in hc, \
        f"micro prime should be a MISS, got {sc} X-Cache={hc.get('x-cache')}"

    sc, _, hc = fetch(ng.port, "/pm/win")              # immediate -> fresh HIT
    assert sc == 200 and hc.get("x-cache") == "HIT", \
        ("micro within its 1s fresh window should HIT, got "
         f"{sc} X-Cache={hc.get('x-cache')}")

    time.sleep(3.0)                                     # past fresh+stale (~2s)
    sc, _, hc = fetch(ng.port, "/pm/win")
    assert sc == 200, f"micro re-read status {sc}"
    assert "x-cache" not in hc, \
        ("micro (default valid 1s, stale_mult=2) should hard-expire by t=3s and "
         f"MISS; a >=30s default would still HIT. Got X-Cache={hc.get('x-cache')}")
    drain_origin(origin)       # settle any async bg refresh before the next test


def test_invalid_preset_name(ng: Nginx) -> None:
    """v3-2: an unknown cache_turbo_preset value is rejected at config time
    (nginx -t fails) with a clear message, not silently ignored."""
    bad = ng.root.parent / "bad-preset"
    (bad / "conf").mkdir(parents=True, exist_ok=True)
    (bad / "logs").mkdir(parents=True, exist_ok=True)
    cfg = nginx_config(bad, ng.port, ng.module, ng.origin_port, 1)
    cfg = cfg.replace("cache_turbo_preset   conservative;",
                      "cache_turbo_preset   bogus;")
    (bad / "conf" / "nginx.conf").write_text(cfg, encoding="ascii")
    cmd = ng.runner + [str(ng.binary), "-p", str(bad),
                       "-c", str(bad / "conf" / "nginx.conf"), "-t"]
    r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=20)
    assert r.returncode != 0, \
        f"invalid preset 'bogus' was accepted by nginx -t:\n{r.stdout}"
    assert "invalid cache_turbo_preset" in r.stdout, \
        f"missing/odd diagnostic for bad preset:\n{r.stdout}"


# --------------------------------------------------------------------------- #
# Live autotune within preset bands (v4-3)
# --------------------------------------------------------------------------- #

def _fire_misses(ng: Nginx, prefix: str, n: int) -> None:
    """Fire n distinct-key GETs concurrently so a window fills fast. Re-calling
    with the same prefix re-reads the same keys (refreshes, not misses)."""
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=16) as ex:
        list(ex.map(lambda i: fetch(ng.port, f"{prefix}{i}"), range(n)))


# A forced recompute (admin ?autotune=1) windows over everything since the last
# recompute and returns the stats incl. the fresh verdict. The autotune locations
# use a huge interval so the throttled per-request recompute fires only on the
# seed (snapshotting ~0) and never splits the measured window — the force does the
# real measurement, making these tests independent of wall-clock timing.

def _autotune_force(ng: Nginx, admin: str) -> dict:
    import json
    s, b, _ = fetch(ng.port, f"{admin}?autotune=1")
    assert s == 200, f"{admin}?autotune=1 status {s}"
    return json.loads(b)


def test_autotune_raises_beta_within_band(ng: Nginx, origin: Origin) -> None:
    """A window of slow misses makes the zone autotune its beta UP from the live
    miss-cost (beta = cost_ms/20, ×1000). The verdict is published per-zone (admin
    autotuned_beta) and re-clamped to each location's preset band ($cache_turbo_beta):
    balanced /at/ [500,2000] shows the verdict, conservative /atc/ [500,1000] shows
    it capped at its band max and strictly lower."""
    origin.delay = 0.04          # ~40ms regen -> target beta ~ 40*1000/20 = 2000
    try:
        fetch(ng.port, "/at/seed")               # first request snapshots ~0
        _fire_misses(ng, "/at/k", 110)           # 110 distinct slow misses
        st = _autotune_force(ng, "/_cache_at")   # recompute over the whole window

        # Lower bound is the real oracle: a 40ms origin MUST show up as a
        # measured cost, so 0/garbage still fails. The upper bound only rejects
        # an absurd reading -- a loaded runner (ASan, shared CI) inflates the
        # observed regen well past the nominal 40ms without the module being
        # wrong (cost_ms=488 seen on run 31537424551). Beta is asserted below
        # against the module's own clamp, which is what actually pins the
        # behaviour, so the band here does not need to be tight.
        assert 25 <= st["cost_ms"] <= 2000, f"cost not measured sanely: {st}"
        # beta = clamp(500, cost_ms*1000/20, 3000): any cost_ms >= 60 saturates
        # at BETA_MAX, so the expected verdict is derived, not hardcoded -- it
        # stays exact under a stall instead of flaking.
        beta = st["autotuned_beta"]
        expect_beta = max(500, min(st["cost_ms"] * 1000 // 20, 3000))
        assert beta == expect_beta, \
            f"autotuned beta {beta} != clamp(500, cost_ms*1000/20, 3000)={expect_beta}: {st}"
        assert beta >= 1500, f"autotuned beta not raised: {st}"

        _, _, hb = fetch(ng.port, "/at/probe")
        _, _, hc = fetch(ng.port, "/atc/probe")
        bal = int(hb["x-ct-beta"])
        con = int(hc["x-ct-beta"])
        assert bal == max(500, min(beta, 2000)), \
            f"balanced effective beta {bal} not clamped to its band from {beta}"
        assert con == max(500, min(beta, 1000)), \
            f"conservative effective beta {con} not clamped to its band from {beta}"
        assert con < bal, f"conservative ({con}) should be below balanced ({bal})"
    finally:
        origin.reset_delay()
        drain_origin(origin)   # v8: settle async bg refreshes before next test


def test_autotune_load_factor_under_load(ng: Nginx, origin: Origin) -> None:
    """v4-4: the same slow-miss window that raises beta also publishes a LOAD
    FACTOR (×1000) the request path uses to widen the stale window + lock_ttl.
    load = clamp(1000, cost_ms×100, 4000); a ~40ms regen saturates it at the 4000
    cap. A subsequent high-hit-rate window (not under load) snaps it back to the
    1000 baseline — proving the factor adapts down, not just up."""
    origin.delay = 0.04          # ~40ms regen -> cost×100 >= 4000 -> capped
    try:
        fetch(ng.port, "/at/lseed")              # snapshot the window start
        _fire_misses(ng, "/at/lk", 110)          # 110 distinct slow misses
        st = _autotune_force(ng, "/_cache_at")
        assert 25 <= st["cost_ms"] <= 500, f"cost not measured sanely: {st}"
        load = st["autotuned_load"]
        # cost_ms >= 40 (a real 40ms sleep) => cost×100 >= 4000 => hits the cap.
        assert load == 4000, \
            f"load factor should saturate at the 4000 cap for a ~40ms origin: {st}"
    finally:
        origin.reset_delay()
        drain_origin(origin)

    # Snap-back: a window dominated by HITS (few misses, hit-rate >= 95%) does not
    # qualify as under-load, so the verdict republishes the 1000 baseline. Uses a
    # hit-heavy window (not a fast-miss one) so it is robust under ASan timing.
    fetch(ng.port, "/at/hot")                    # prime (1 miss)
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(lambda _: fetch(ng.port, "/at/hot"), range(130)))   # 130 hits
    st2 = _autotune_force(ng, "/_cache_at")
    assert st2["autotuned_load"] == 1000, \
        f"load factor did not snap back to baseline on a non-load window: {st2}"


def test_autotune_load_widens_stale_window(ng: Nginx, origin: Origin) -> None:
    """v4-4 behaviour: with the zone load factor pumped to the cap, an entry that
    is hard-expired by its STATIC stale window (conservative ×2: fresh 1s + stale
    1s = serveable 2s) is still STALE-serveable at t=3s, because the load factor
    widened the serveable stale span (fresh window is NOT touched). Mirror of
    test_preset_window_differs, but here the wider window comes from live load, not
    a preset."""
    origin.delay = 0.04
    try:
        fetch(ng.port, "/atl/seed")
        _fire_misses(ng, "/atl/k", 110)          # pump the zone load factor
        st = _autotune_force(ng, "/_cache_atl")
        assert st["autotuned_load"] >= 2000, f"load not pumped: {st}"
        origin.delay = 0.0   # deliberate, NOT a restore: the probe prime must be
                             # instant so it lands well inside the 1s fresh window.
                             # The finally below does the real restore.
        fetch(ng.port, "/atl/probe")             # prime the probe (fresh 1s)
    finally:
        origin.reset_delay()

    time.sleep(3.0)                              # past static 2s, within widened ~5s

    # Burst so single-flight forces losers to serve stale (the dice winner may
    # regenerate); at least one STALE proves the load-widened window held.
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        res = list(pool.map(lambda _: fetch(ng.port, "/atl/probe"), range(16)))
    assert {r[0] for r in res} == {200}, \
        f"load-widen stale burst returned {set(r[0] for r in res)}"
    assert any(h.get("x-cache") == "STALE" for _, _, h in res), \
        ("load-widened stale window should still serve STALE at t=3s (a static "
         "conservative ×2 window would hard-expire and MISS); got "
         + repr(sorted(str(h.get("x-cache")) for _, _, h in res)))
    drain_origin(origin)


def test_autotune_off_by_default(ng: Nginx) -> None:
    """A location WITHOUT cache_turbo_autotune ignores the zone's live verdict and
    always reports its static preset beta (balanced = 1000), even though /ato/
    shares the zone /at/ just autotuned up."""
    _, _, h = fetch(ng.port, "/ato/x")
    assert int(h["x-ct-beta"]) == 1000, \
        f"autotune-off location should show static beta 1000, got {h.get('x-ct-beta')}"


def test_autotune_insufficient_data(ng: Nginx, origin: Origin) -> None:
    """Below MISSES_FLOOR (100) traffic in a window, no verdict is published — the
    fresh zone's autotuned_beta stays 0 (fall back to preset)."""
    origin.delay = 0.04
    try:
        fetch(ng.port, "/ati/seed")              # first request snapshots ~0
        _fire_misses(ng, "/ati/k", 10)           # only 10 < floor
        st = _autotune_force(ng, "/_cache_ati")  # recompute: thin window -> no verdict
        assert st["autotuned_beta"] == 0, f"thin data wrongly tuned: {st}"
    finally:
        origin.reset_delay()
        drain_origin(origin)   # v8: settle async bg refreshes before next test


def test_autotune_churn_disqualifies(ng: Nginx, origin: Origin) -> None:
    """A refresh-dominated window (refreshes/misses > 2) is vetoed by the churn gate
    even though cost+hit-rate would otherwise qualify (cf. test_autotune_raises_*),
    so no verdict is published (autotuned_beta stays 0). The /atch/ location uses an
    aggressive preset (8s entry life), 1s TTL + 1s lock + beta 5.0 so a stale read
    deep in the window certainly refreshes; re-reading the 110 keys for 4 cycles
    drives well over 220 refreshes (> 2x the 110 cold misses) with margin even when
    valgrind slows a cycle. One forced recompute windows the whole run."""
    origin.delay = 0.012         # ~12ms >= COST_MOD (10ms): cost would qualify
    try:
        fetch(ng.port, "/atch/seed")             # first request snapshots ~0
        _fire_misses(ng, "/atch/k", 110)         # 110 cold misses (floor + low hit-rate)
        for _ in range(4):                        # 4 stale refresh cycles
            time.sleep(2.7)                       # past fresh + lock, deep in stale
            _fire_misses(ng, "/atch/k", 110)      # same keys -> refreshes, not misses

        st = _autotune_force(ng, "/_cache_atch")  # recompute over the whole window
        assert st["refreshes"] > 2 * max(1, st["misses"]), \
            f"setup failed to drive churn ratio > 2: {st}"
        assert st["autotuned_beta"] == 0, \
            f"churn-heavy window should be vetoed, got {st}"
    finally:
        origin.reset_delay()
        drain_origin(origin)   # v8: settle async bg refreshes before next test


# --------------------------------------------------------------------------- #
# v13 memcached L2 backend
# --------------------------------------------------------------------------- #

def test_l2_memcached_write_through(ng: Nginx, origin: Origin,
                                    mc: MemcachedServer) -> None:
    """v13: a store under /mc/ writes through to memcached. After caching, the
    blob is present under the mc: key and contains the response body bytes, and
    the L1 hot path still serves the HIT byte-identically."""
    uri = "/mc/store"
    key = l2_key(uri, prefix="mc:")
    mc.command(b"delete " + key.encode() + b"\r\n")

    s, body, h = fetch(ng.port, uri)               # miss -> origin -> store
    assert s == 200, f"mc store status {s}"
    assert "x-cache" not in h, "first request should be a miss"

    # write-through is async/fire-and-forget; give it a moment to land
    assert wait_for(lambda: mc.exists(key)), \
        f"L2 key {key} never appeared in memcached"
    stored = mc.get(key)
    assert stored is not None and len(stored) > len(body), \
        f"stored blob ({len(stored or b'')}B) smaller than body"
    assert b"gen-" in stored, "stored blob missing response body"

    # L1 still serves the hit (write-through must not disturb the hot path)
    _, b2, h2 = fetch(ng.port, uri)
    assert h2.get("x-cache") == "HIT" and b2 == body, "L1 hit broken after L2 set"


def test_l2_memcached_cross_instance_fill(ng: Nginx, origin: Origin,
                                          mc: MemcachedServer) -> None:
    """v13: an L1 miss fills from memcached. A second, independent nginx with a
    cold L1 but the same memcached serves the object the first node cached,
    without hitting the origin again."""
    uri = "/mc/p2"
    key = l2_key(uri, prefix="mc:")
    mc.command(b"delete " + key.encode() + b"\r\n")

    # Instance A: cold -> origin -> writes L1 + L2
    s, body_a, ha = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in ha, "A should miss to origin first"
    assert wait_for(lambda: mc.exists(key)), "A never wrote the object to L2"
    drain_origin(origin)
    origin_after_a = origin.hits

    # Instance B: separate nginx, cold L1, same memcached + same origin
    b = Nginx(ng.binary, ng.module, ng.root.parent / "server-b-mc",
              ng.port + PORT_OFFSETS["l2_memcached_cross_instance_fill_b"],
              ng.origin_port, ng.runner_raw,
              ng.single_process, memcached_port=ng.memcached_port)
    b.write_config()
    b.config_test()
    b.start()
    try:
        s2, body_b, hb = fetch(b.port, uri)
        assert s2 == 200, f"B status {s2}"
        assert body_b == body_a, f"B body {body_b!r} != A body {body_a!r}"
        assert hb.get("x-cache") == "HIT", \
            f"B X-Cache={hb.get('x-cache')} (expected an L2-fill HIT)"
        assert origin.hits == origin_after_a, \
            f"origin was hit on the L2 fill ({origin.hits} vs {origin_after_a})"

        # B now has it in L1 too: second read is a plain L1 HIT
        _, body_b2, hb2 = fetch(b.port, uri)
        assert hb2.get("x-cache") == "HIT" and body_b2 == body_a
        assert origin.hits == origin_after_a, "origin hit on B's L1 hit"

        time.sleep(0.2)
        b.stop()
        b.assert_clean_logs()
    finally:
        b.stop()


def test_l2_memcached_purge_key_drops_l2(ng: Nginx, origin: Origin,
                                         mc: MemcachedServer) -> None:
    """v13: a single-key purge on the memcached-aware admin endpoint also deletes
    the entry from memcached (not just L1), so the next miss cannot be silently
    refilled from L2."""
    uri = "/mc/purgekey"
    key = l2_key(uri, prefix="mc:")
    mc.command(b"delete " + key.encode() + b"\r\n")

    s, body_a, h = fetch(ng.port, uri)             # miss -> origin -> L1 + L2
    assert s == 200 and "x-cache" not in h, "prime should miss to origin"
    assert wait_for(lambda: mc.exists(key)), "write-through never reached L2"

    # purge the key via the memcached-aware admin endpoint
    s, _, _ = fetch(ng.port, f"/_cache_mc?key={uri}", method="POST")
    assert s == 200, f"purge status {s}"

    # the L2 entry must actually be gone (fire-and-forget delete)
    assert wait_for(lambda: not mc.exists(key)), \
        "single-key purge did not drop the entry from memcached"

    # next read misses to a fresh origin generation, not an L2 refill
    origin_before = origin.hits
    s, body_b, h3 = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in h3, \
        f"post-purge read should miss to origin, got {h3.get('x-cache')}"
    assert origin.hits == origin_before + 1, \
        "origin not consulted after purge (L2 still served)"
    assert body_b != body_a, "post-purge body should be a fresh generation"


def test_l2_backend_inheritance_child_redis_over_parent_memcached(
        ng: Nginx, origin: Origin, redis: RedisServer,
        mc: MemcachedServer) -> None:
    """Precedence regression (bug FIXED 2026-06-12): a child location naming
    cache_turbo_redis, enclosed by a parent naming cache_turbo_memcached, must
    drive its OWN address with the Redis backend — not inherit the parent's
    memcached=1 at merge (which would select the memcached driver for a redis://
    address). The redis directive pins memcached=0 for this reason; this locks it.

    Assertion: a store under the child writes through to REDIS (ct: key) and NOT
    to memcached (mc: key). If the fix regressed, the blob would land in memcached
    (parent's inherited backend) and the Redis key would never appear."""
    uri = "/mcinh/child/store"
    r_key = l2_key(uri, prefix="ct:")   # where it must land (child = Redis)
    m_key = l2_key(uri, prefix="mc:")   # where it must NOT land (parent memcached)
    redis.cli("DEL", r_key)
    mc.command(b"delete " + m_key.encode() + b"\r\n")

    s, _body, h = fetch(ng.port, uri)               # miss -> origin -> store
    assert s == 200, f"child store status {s}"
    assert "x-cache" not in h, "first request should be a miss"

    # write-through is async; the child's own (Redis) backend must receive it
    assert wait_for(lambda: redis.cli("EXISTS", r_key) == "1"), \
        f"child cache_turbo_redis store never reached Redis ({r_key}) — the child " \
        "likely inherited the parent's memcached backend (precedence regression)"
    # and the parent's memcached backend must stay untouched by the child
    assert not mc.exists(m_key), \
        f"child store leaked into the parent's memcached backend ({m_key})"

    # sanity: the parent location itself still uses memcached (not poisoned by
    # the child's redis override the other way around)
    puri = "/mcinh/parent-x"
    pm_key = l2_key(puri, prefix="mc:")
    pr_key = l2_key(puri, prefix="ct:")
    redis.cli("DEL", pr_key)
    mc.command(b"delete " + pm_key.encode() + b"\r\n")
    ps, _, ph = fetch(ng.port, puri)
    assert ps == 200 and "x-cache" not in ph, "parent prime should miss"
    assert wait_for(lambda: mc.exists(pm_key)), \
        "parent cache_turbo_memcached store never reached memcached"
    assert redis.cli("EXISTS", pr_key) == "0", \
        "parent store leaked into Redis (backend identity crossed)"


def test_mc_keepalive_reuse(ng: Nginx, origin: Origin,
                            mc: MemcachedServer) -> None:
    """D-O1 primary crash path: a memcached L2 op GET-pools its connection, and
    the very next op (the write-through SET) REUSES it, then re-pools it. Before
    the fix, mc_connect's reuse branch left op->peer.name NULL, so the SET's
    re-pool (op_done -> ka_save, which dereferences op->peer.name) SIGSEGV'd the
    worker on a plain L1 miss. This exercises that exact GET-pool -> SET-reuse
    -> re-pool cycle across a burst and proves (a) the worker survives it and
    (b) the pool actually reuses connections (few new accepts vs connect-per-op).

    /mcka/ has keepalive=4; /mc/ connects per op. We measure memcached's accept
    count across an identical burst on each and assert the pool cut the churn --
    the same connect-per-op vs reuse contrast the Redis test_l2_keepalive_reuse
    makes, but on the driver the fix touched.
    """
    n = 40
    stamp = time.time()

    def burst(prefix: str) -> int:
        # Subtract our OWN stats connection once, on the closing reading only.
        # total_connections() opens a connection to ask, so the closing probe is
        # inside its own answer while the opening probe's is already inside
        # `before`. Subtracting on both readings cancels out and leaves every
        # burst reporting nginx's accepts + 1 -- which `warm <= pool_size` below
        # has no headroom to absorb.
        before = mc.total_connections()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            list(ex.map(lambda i: fetch(ng.port, f"{prefix}reuse-{stamp}-{i}"),
                        range(n)))
        time.sleep(0.6)   # let fire-and-forget SETs finish + conns settle
        return mc.total_connections() - 1 - before

    workers_before = ng.worker_pids()

    off = burst("/mc/")      # connect-per-op memcached location: ~2N accepts
    on = burst("/mcka/")     # keepalive on: a small bounded number, then reuse

    # The worker must have survived the GET-pool -> SET-reuse -> re-pool cycle.
    if not ng.single_process:
        assert ng.worker_pids() == workers_before, (
            "worker PID set changed during a keepalive reuse burst -- a worker "
            "crashed (D-O1 NULL op->peer.name on the mc_connect reuse path)")

    assert off > n, f"connect-per-op baseline too low ({off}); expected > {n}"
    assert on * 2 < off, \
        f"memcached keepalive did not cut connection churn (on={on}, off={off})"

    # pool kept a live conn: a subsequent op still hits + serves
    _, _, h = fetch(ng.port, f"/mcka/reuse-{stamp}-0")   # now an L1 HIT
    assert h.get("x-cache") == "HIT", "keepalive location broke the hot path"


def test_mc_keepalive_zero_does_not_drain_pool(ng: Nginx, origin: Origin,
                                               mc: MemcachedServer) -> None:
    """MC-A2: a location with keepalive=0 must neither borrow from nor drain the
    pool a DIFFERENT location filled for the SAME memcached peer. /mcka/ has
    keepalive=4 and /mcka0/ points at the same address with keepalive=0.

    Prime /mcka/ so idle sockets sit in the pool, run a burst through /mcka0/,
    then run a burst through /mcka/ again. If the zero location borrowed pooled
    sockets it would close each one after its op (ka_save refuses to re-pool at
    keepalive=0), so the second /mcka/ burst would have to re-dial and its accept
    count would jump to the connect-per-op level. With the fix the zero location
    dials its own connections and /mcka/'s pool is untouched."""
    n = 12
    stamp = time.time()

    def burst(prefix: str, tag: str) -> int:
        before = mc.total_connections() - 1
        for i in range(n):
            fetch(ng.port, f"{prefix}drain-{tag}-{stamp}-{i}")
        time.sleep(0.6)          # let fire-and-forget SETs settle
        return mc.total_connections() - 1 - before

    workers_before = ng.worker_pids()

    burst("/mcka/", "prime")             # fill the pool
    zero = burst("/mcka0/", "zero")      # keepalive=0: fresh conn per op
    warm = burst("/mcka/", "warm")       # pool must still be warm

    if not ng.single_process:
        assert ng.worker_pids() == workers_before, \
            "worker crashed during the mixed keepalive=0 / keepalive=4 burst"

    assert zero >= 2 * n - 2, \
        f"keepalive=0 location did not dial per op (accepts={zero}, ops={n})"
    # The pool holds 4 idle sockets. If /mcka0/ borrowed them it closed each one
    # after its op (ka_save refuses to re-pool at keepalive=0), so a drained pool
    # re-dials essentially per op and `warm` climbs to the connect-per-op level
    # `zero` (~2N). Untouched, the warm burst reuses what is already pooled.
    #
    # Bound is the pool size, not an exact count: the earlier `warm <= 1` form
    # was over-tight, because `warm` counts accepts across a 4-socket pool shared
    # with the fire-and-forget SET path, so under ASan a burst can legitimately
    # re-dial more than one without the pool having been drained. 4 is still far
    # below the drain level, so the defect this was written for (D-O1 ka_save at
    # keepalive=0) fails just as loudly.
    pool_size = 4                # /mcka/ in test_runtime_base nginx_config(): keepalive=4
    assert warm <= pool_size, (
        "the keepalive=0 location drained the shared peer's pool: the warm "
        f"burst re-dialled {warm} connection(s), at/above the pooled-socket count "
        f"{pool_size} (zero={zero}, ops={n})")


def test_mc_keepalive_idle_timeout_drops(ng: Nginx, origin: Origin,
                                         mc: MemcachedServer) -> None:
    """D-O1 idle-timer branch of mc_ka_close_handler (ev->timedout): a pooled
    memcached connection left idle past keepalive_timeout must be dropped by the
    timer handler, not leak or crash the worker. /mckashort/ has a 1s idle
    timeout. Prime a pooled conn, wait past it, and assert the worker survives
    and the next op still serves (re-dialing a fresh conn transparently).

    The peer-event branch is covered by test_mc_keepalive_server_close_survives;
    this covers the timedout branch the server-close test never reaches."""
    uri = "/mckashort/idle"
    key = l2_key(uri, prefix="mcks:")
    mc.command(b"delete " + key.encode() + b"\r\n")

    s, body, _ = fetch(ng.port, uri)
    assert s == 200, "prime should miss to origin"
    assert wait_for(lambda: mc.exists(key)), \
        "write-through never reached memcached (no conn to pool)"

    workers_before = ng.worker_pids()

    # Idle timeout is 1s; wait comfortably past it so the read timer fires and
    # mc_ka_close_handler drops the pooled slot via the ev->timedout path.
    time.sleep(2.0)

    if not ng.single_process:
        assert ng.worker_pids() == workers_before, (
            "worker PID set changed while a pooled conn idle-timed-out -- the "
            "idle-timer close handler crashed (D-O1 timedout branch)")

    # A fresh op re-dials transparently and still serves from L1.
    s2, body2, h2 = fetch(ng.port, uri)
    assert s2 == 200 and h2.get("x-cache") == "HIT" and body2 == body, \
        "worker no longer serves the L1 hit after the pooled conn idle-timeout"


def test_mc_dirty_reply_not_pooled(ng: Nginx, origin: Origin) -> None:
    """D-O2: a memcached reply that does not end at a clean protocol boundary
    (trailing junk past END / STORED) must NOT be returned to the keepalive pool.
    The connection is closed instead, so a later reuse can never resume in the
    middle of a stale reply and desync the stream.

    /mcdirty/ (keepalive=4) points at a fake memcached that appends garbage after
    every framed reply. We drive a burst of DISTINCT cold keys -- each is an L1
    miss -> memcached GET (miss) -> origin -> L1 store + write-through memcached
    SET, i.e. two memcached ops per key. With the clean gate, every one of those
    connections is closed (the reply had trailing bytes), so the fake sees about
    one accept per op. The pre-fix driver pooled those unclean connections and
    reused them, collapsing the accept count far below the op count.

    Negative control (PROVEN by reverting op->clean + its gate in the driver and
    rebuilding the .so): dirty conns get pooled -> `accepts` drops ~10x -> the
    assertion below fires. The worker-PID check also catches a crash on the
    unclean path."""
    dirty = DirtyMemcached(ng.port + PORT_OFFSETS["mc_dirty_reply"])
    dirty.start()
    try:
        n = 30
        stamp = time.time()
        workers_before = ng.worker_pids()

        def one(i: int) -> int:
            s, _, _ = fetch(ng.port, f"/mcdirty/d-{stamp}-{i}")
            return s

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            statuses = list(ex.map(one, range(n)))
        time.sleep(0.6)   # let fire-and-forget SETs land + connections settle

        assert all(s == 200 for s in statuses), \
            f"a /mcdirty/ request failed (worker wedged on an unclean conn?): {statuses}"

        if not ng.single_process:
            assert ng.worker_pids() == workers_before, (
                "worker PID set changed during the dirty-reply burst -- a worker "
                "crashed handling an unclean memcached connection (D-O2)")

        # ~2N ops, each on its own fresh connection when the clean gate closes the
        # unclean ones. `>= n` sits ~2x under the pooled-none expectation (~2N) and
        # well above the reuse case (~pool size). Generous slack for scheduling.
        assert dirty.accepts >= n, (
            f"dirty memcached connections were reused ({dirty.accepts} accepts for "
            f"{n} cold keys / ~{2 * n} ops) -- an unclean reply was pooled (D-O2)")
    finally:
        dirty.stop()


def test_mc_keepalive_server_close_survives(ng: Nginx, origin: Origin,
                                            mc: MemcachedServer) -> None:
    """D-O1: an idle memcached keepalive connection whose server drops it must
    NOT crash the worker.

    The /mcka/ location runs the memcached L2 backend with a keepalive pool.
    After a write-through SET the driver parks the connection idle in the pool.
    When the memcached server then closes that idle connection, epoll wakes
    c->read; the pooled slot must carry a close-on-readable handler that drops
    it. The driver used to leave c->read->handler == NULL there, so the wakeup
    dereferenced NULL and SIGSEGV'd the worker. We detect a crash by watching
    the worker PID set: a segfaulting worker is replaced by the master, so the
    set changes; a healthy worker keeps its PID and keeps serving the L1 hit.

    Multi-worker mode only (single_process has no worker to lose + no PID set).
    """
    if ng.single_process:
        return

    uri = "/mcka/keepme"
    key = l2_key(uri, prefix="mck:")
    mc.command(b"delete " + key.encode() + b"\r\n")

    # Miss -> origin -> L1 + write-through SET. The SET op pools its connection
    # idle when it finishes (op_done -> ka_save).
    s, body, h = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in h, "prime should miss to origin"
    assert wait_for(lambda: mc.exists(key)), \
        "write-through never reached memcached (no conn to pool)"

    workers_before = ng.worker_pids()
    assert workers_before, "expected at least one worker in multi-process mode"

    # Server drops every connection, including the idle pooled one. This is what
    # wakes the pooled conn's read event on the worker.
    mc.stop()

    # Give epoll a moment to deliver the readable/closed event to the worker and
    # run its handler. On the unpatched (NULL-handler) driver the worker would
    # SIGSEGV here and the master would fork a replacement with a new PID.
    deadline = time.time() + 2.0
    while time.time() < deadline:
        if ng.worker_pids() != workers_before:
            break
        time.sleep(0.05)

    assert ng.worker_pids() == workers_before, (
        "worker PID set changed after the memcached server dropped an idle "
        "pooled connection -- a worker crashed (D-O1 NULL close handler)")

    # And the worker is still healthy: the already-cached object still serves
    # from L1 without the (now dead) memcached backend.
    s2, body2, h2 = fetch(ng.port, uri)
    assert s2 == 200 and h2.get("x-cache") == "HIT" and body2 == body, \
        "worker no longer serves the L1 hit after the pooled-conn close event"
