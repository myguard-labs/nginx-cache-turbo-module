"""cache-turbo runtime tests — http area.

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
    _admin_lock_waits,
    _admin_stat,
    _admin_str,
    _errlog_window_start,
)


def test_nocache_breaker_open_honours_cache(ng: Nginx, origin: Origin) -> None:
    """S231-NOCACHE-OUTAGE: a client Cache-Control: no-cache must NOT force an
    origin trip while the breaker for this zone is OPEN -- honour the cache
    instead. /s231nc/ (own zone s231ncz, threshold=1) is primed, expired past
    its 1s window, then the origin is killed: the first dead-origin request
    trips CLOSED -> OPEN and still surfaces the raw failure (not a serve), the
    SECOND finds the breaker OPEN. A no-cache request sent to THAT state must
    be served STALE-BREAKER from cache with zero further origin contact,
    exactly like an ordinary request would (see the pre-origin breaker gate at
    module.c ~5891 that this fall-through now reaches instead of the early
    NGX_DECLINED at ~4749)."""
    s0, b0, _ = fetch(ng.port, "/s231nc/oc1")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    time.sleep(1.3)   # past fresh (1s), stale_mult 1 -> 1s window: L1-expired
    origin.fail = True
    try:
        s_trip, _, _ = fetch(ng.port, "/s231nc/oc1")
        assert s_trip != 200, \
            (f"tripping request was answered 200 -- expected it to reach "
             f"the dead origin and fail, got {s_trip}")

        before = origin.hits_for("/oc1")
        s_nc, b_nc, h_nc = fetch(ng.port, "/s231nc/oc1",
                                  headers={"Cache-Control": "no-cache"})
        assert s_nc == 200 and b_nc == b0, \
            (f"breaker OPEN + client no-cache should serve the cached body, "
             f"got {s_nc} {b_nc!r}")
        assert h_nc.get("x-ct-reason") == "STALE-BREAKER", \
            (f"breaker OPEN + no-cache should report STALE-BREAKER, got "
             f"{h_nc.get('x-ct-reason')}")
        assert origin.hits_for("/oc1") == before, \
            ("breaker OPEN + client no-cache must NOT trip a further origin "
             "request -- honour the cache instead")
    finally:
        origin.fail = False
        drain_origin(origin)


def test_nocache_breaker_closed_still_revalidates(ng: Nginx, origin: Origin) -> None:
    """S231-NOCACHE-OUTAGE negative control: with the breaker CLOSED (origin
    healthy, never tripped), a client Cache-Control: no-cache on a warmed
    /s231ncc/ key must still go to the origin -- today's behaviour, unchanged.
    Without this control the fix above is indistinguishable from "always
    ignore no-cache", which would silently serve stale content while the
    origin is perfectly reachable."""
    s0, b0, _ = fetch(ng.port, "/s231ncc/oc2")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    _, _, h1 = fetch(ng.port, "/s231ncc/oc2")
    assert h1.get("x-cache") == "HIT", "entry should be primed"

    before = origin.hits_for("/oc2")
    _, b_nc, h_nc = fetch(ng.port, "/s231ncc/oc2",
                           headers={"Cache-Control": "no-cache"})
    assert "x-cache" not in h_nc, \
        (f"breaker CLOSED + no-cache must still reach the origin, got "
         f"X-Cache={h_nc.get('x-cache')}")
    assert origin.hits_for("/oc2") == before + 1, \
        (f"breaker CLOSED + no-cache must consult the origin exactly once, "
         f"got {origin.hits_for('/oc2')} vs before={before}")
    assert b_nc != b0, "no-cache response should be a fresh origin generation"


def test_nocache_only_if_cached_still_504(ng: Nginx, origin: Origin) -> None:
    """S231-NOCACHE-OUTAGE regression pin: the req_only_if_cached arm at
    module.c ~4751-4759 (returns 504 GATEWAY_TIMEOUT) is explicitly OUT OF
    SCOPE for this item and must be byte-for-byte unchanged -- a client that
    both revalidates (no-cache) and forbids origin contact (only-if-cached) on
    a key with nothing cached still gets 504, breaker state notwithstanding."""
    before = origin.hits_for("/oic-miss")
    s, _, _ = fetch(ng.port, "/s231ncc/oic-miss",
                     headers={"Cache-Control": "no-cache, only-if-cached"})
    assert s == 504, f"no-cache + only-if-cached miss must still be 504, got {s}"
    assert origin.hits_for("/oic-miss") == before, \
        "only-if-cached must never reach the origin"


def test_nocache_breaker_open_varying_url_serves_correct_variant(
        ng: Nginx, origin: Origin) -> None:
    """S231-NOCACHE-OUTAGE ordering-hazard regression: the no-cache/breaker
    gate at module.c ~4749 runs BEFORE ngx_http_cache_turbo_vary_resolve()
    (~4762) and the bypass predicate (~4776). Falling through on a
    breaker-OPEN no-cache request must reach vary_resolve() before any cache
    lookup, exactly like every other request -- otherwise the gate would probe
    the BASE key and silently serve the wrong (or no) variant on a URL that
    varies, or miss it entirely.

    /s231ncv/ (own zone s231ncvz, cache_turbo_valid 30s) auto-Vary-splits by
    Origin ("v=or" query marker). /s231ncvbrk/ shares the SAME zone (so it
    shares the SAME breaker state) but has its OWN short cache_turbo_valid
    (1s) and is used ONLY to trip the breaker via an unrelated key (/dead) --
    letting the tripping key expire and trip fast while the two Origin
    variants (primed first, on their 30s window) stay comfortably fresh for
    the rest of the test. With the zone breaker OPEN, a no-cache request for
    the fresh "b" variant must still resolve to ITS OWN key and serve the "b"
    body from cache (a plain HIT, since a fresh entry never reaches the
    pre-origin breaker gate at all) -- not the "a" variant, not a miss to
    origin. Serving the "a" body here would mean the gate probed the BASE
    key instead of the variant (the ordering hazard); forcing an origin trip
    would mean the no-cache fix isn't reached at all for varying URLs.

    P1-1: this used to split by Accept-Encoding (gzip vs br); the encoding
    axis now collapses for an unencoded body (see
    test_auto_vary_encoding_collapses_when_body_unencoded), so gzip and br
    would land on the SAME slot here and the "variants did not split"
    assertion below would trip on every run, not just a real regression.
    Origin (an unbounded raw-value axis, unaffected by P1-1) exercises the
    identical vary_resolve()/breaker-gate ordering this test targets."""
    p = "/s231ncv/k1?v=or"
    hdr_a = {"Origin": "https://a.example"}
    hdr_b = {"Origin": "https://b.example"}

    # Prime the two Origin variants FIRST, breaker still CLOSED -- their 30s
    # window comfortably outlives the whole breaker-tripping sequence below.
    s_gz0, b_gz0, _ = fetch(ng.port, p, hdr_a)
    assert s_gz0 == 200 and b_gz0, f"origin-a prime failed: {s_gz0} {b_gz0!r}"
    s_br0, b_br0, _ = fetch(ng.port, p, hdr_b)
    assert s_br0 == 200 and b_br0, f"origin-b prime failed: {s_br0} {b_br0!r}"
    assert b_gz0 != b_br0, \
        ("origin-a and origin-b primed to the same body -- variants did not "
         "split, the ordering regression this test targets cannot be proven")
    _, b_gz1, h_gz1 = fetch(ng.port, p, hdr_a)
    assert h_gz1.get("x-cache") == "HIT" and b_gz1 == b_gz0, \
        (f"origin-a variant not a fresh HIT: X-Cache={h_gz1.get('x-cache')} "
         f"body_match={b_gz1 == b_gz0} headers={h_gz1}")
    _, b_br1, h_br1 = fetch(ng.port, p, hdr_b)
    assert h_br1.get("x-cache") == "HIT" and b_br1 == b_br0, \
        (f"origin-b variant not a fresh HIT: X-Cache={h_br1.get('x-cache')} "
         f"body_match={b_br1 == b_br0} headers={h_br1}")

    # Trip THIS ZONE's breaker OPEN via /s231ncvbrk/dead -- own 1s window on
    # the same zone, so tripping it flips /s231ncv/'s view of the breaker too
    # without ever touching the gzip/br keys above (different location AND
    # different $request_uri).
    dead = "/s231ncvbrk/dead"
    s_prime, b_prime, _ = fetch(ng.port, dead)
    assert s_prime == 200 and b_prime, f"breaker-trip prime failed: {s_prime} {b_prime!r}"
    time.sleep(1.3)   # past fresh (1s), stale_mult 1 -> 1s window: L1-expired
    origin.fail = True
    try:
        s_trip, _, _ = fetch(ng.port, dead)
        assert s_trip != 200, \
            (f"tripping request was answered 200 -- expected it to reach "
             f"the dead origin and fail, got {s_trip}")
        s_open, _, _ = fetch(ng.port, dead)
        assert s_open == 200, \
            f"breaker did not report OPEN via /dead's own fallback, got {s_open}"
    finally:
        origin.fail = False
        drain_origin(origin)

    before = origin.hits_for("/k1?v=or")
    s_nc, b_nc, h_nc = fetch(
        ng.port, p,
        {**hdr_b, "Cache-Control": "no-cache"})
    assert s_nc == 200 and b_nc == b_br0, \
        (f"breaker OPEN + no-cache on a varying URL must serve the "
         f"REQUESTED variant's cached body (origin-b), got {b_nc!r}, "
         f"expected {b_br0!r} -- the base/origin-a key was probed instead "
         f"(ordering hazard), or the request forced an origin trip")
    assert h_nc.get("x-cache") == "HIT", \
        (f"a fresh origin-b variant, once correctly resolved, should serve "
         f"as an ordinary HIT, got X-Cache={h_nc.get('x-cache')}")
    assert origin.hits_for("/k1?v=or") == before, \
        "breaker OPEN + no-cache must not trip a further origin request"


def test_request_cc_serve_verdict_fresh(ng: Nginx, origin: Origin) -> None:
    """RFC-1 request Cache-Control against a FRESH entry (req_serve_verdict,
    module.c:1403-1409). A client's own max-age/min-fresh can refuse an entry
    the cache considers fresh: fresh_ok clears, no max-stale means stale_ok is
    also 0, so both serve paths are refused and the entry is revalidated
    (refetched from origin) instead of served HIT.

    The counting origin returns a unique body per hit, so a refetch yields a
    body distinct from the primed one — that difference is the proof the cache
    did NOT serve the stored copy."""
    # prime a fresh 30s entry, confirm the plain second read HITs
    _, base, _ = fetch(ng.port, "/reqcc/f")
    _, b2, h2 = fetch(ng.port, "/reqcc/f")
    assert h2.get("x-ct-status") == "HIT", \
        f"plain second read should HIT, got {h2.get('x-ct-status')}"
    assert b2 == base, "fresh HIT must replay the stored body"

    # max-age=0: client demands an entry no older than 0s. The 30s entry has
    # age>0 -> fresh_ok=0; no max-stale -> stale_ok=0 -> refused -> refetch.
    _, bm, hm = fetch(ng.port, "/reqcc/f",
                      headers={"Cache-Control": "max-age=0"})
    assert hm.get("x-ct-status") != "HIT", \
        f"max-age=0 must refuse the fresh HIT, got {hm.get('x-ct-status')}"
    assert bm != base, "max-age=0 must be revalidated from origin (new body)"

    # min-fresh=999: client wants >=999s of remaining freshness; the entry has
    # at most 30s left -> fresh_ok=0 -> refused -> refetch.
    fetch(ng.port, "/reqcc/g")
    fetch(ng.port, "/reqcc/g")   # ensure a fresh stored entry
    _, _, hg = fetch(ng.port, "/reqcc/g",
                      headers={"Cache-Control": "min-fresh=999"})
    assert hg.get("x-ct-status") != "HIT", \
        f"min-fresh=999 must refuse the 30s entry, got {hg.get('x-ct-status')}"

    # max-stale (bare) on a fresh entry still serves the fresh HIT (fresh_ok=1),
    # while exercising the bare-max-stale parse (req_max_stale_any). module.c:1367
    _, _, hs = fetch(ng.port, "/reqcc/f",
                     headers={"Cache-Control": "max-stale"})
    assert hs.get("x-ct-status") == "HIT", \
        f"bare max-stale must still serve the fresh HIT, got {hs.get('x-ct-status')}"
    drain_origin(origin)


def test_request_cc_serve_verdict_stale(ng: Nginx, origin: Origin) -> None:
    """RFC-1 request Cache-Control against a STALE entry (req_serve_verdict
    stale_ok arm, module.c:1411-1421). /reqccst/ has a 1s fresh window + the
    default 4x stale window and beta 1 (dice ~never), so after ~1.3s the entry
    is stale-but-serveable. The client's max-stale decides whether the cache may
    serve that stale copy."""
    # default (no request CC): a stale entry is served per cache policy (stale_ok
    # default arm, module.c:1421).
    fetch(ng.port, "/reqccst/a")
    time.sleep(1.3)
    _, _, hd = fetch(ng.port, "/reqccst/a")
    assert hd.get("x-ct-status") == "STALE", \
        f"default request must serve STALE, got {hd.get('x-ct-status')}"

    # max-stale=0: no staleness tolerated. staleness>0 -> stale_ok=0; no max-age
    # so fresh_ok stays 1 but the entry is not fresh -> refused -> refetch.
    # Sleep 2.3s (not 1.3s) so staleness = now-fresh_until is unambiguously >=1s:
    # ngx_time() has 1s granularity, and at ~0.3s past a 1s window the rounded
    # staleness can land on 0, making `staleness <= max_stale(0)` true and the
    # copy STALE-served (the 1s-granularity SWR flake class). 2.3s clears it.
    fetch(ng.port, "/reqccst/b")
    time.sleep(2.3)
    _, _, hz = fetch(ng.port, "/reqccst/b",
                     headers={"Cache-Control": "max-stale=0"})
    assert hz.get("x-ct-status") != "STALE", \
        f"max-stale=0 must refuse the stale copy, got {hz.get('x-ct-status')}"

    # max-stale=100: 100s of staleness tolerated; the ~0.3s-stale entry is well
    # within it -> stale_ok=1 -> STALE served (module.c:1416, valued branch).
    fetch(ng.port, "/reqccst/c")
    time.sleep(1.3)
    _, _, hp = fetch(ng.port, "/reqccst/c",
                     headers={"Cache-Control": "max-stale=100"})
    assert hp.get("x-ct-status") == "STALE", \
        f"max-stale=100 must permit the stale copy, got {hp.get('x-ct-status')}"

    # max-stale=abc: unparseable value falls back to "accept any staleness"
    # (req_max_stale_any, module.c:1375) -> STALE served.
    fetch(ng.port, "/reqccst/d")
    time.sleep(1.3)
    _, _, hu = fetch(ng.port, "/reqccst/d",
                     headers={"Cache-Control": "max-stale=abc"})
    assert hu.get("x-ct-status") == "STALE", \
        f"unparseable max-stale must be lenient (STALE), got {hu.get('x-ct-status')}"
    drain_origin(origin)


def test_cc_mode_inheritance_child_preset_overrides_parent_ignore(
        ng: Nginx, origin: Origin) -> None:
    """cc_mode (cache_turbo_cache_control) merge precedence: a child with a CMS
    backend preset (cc_mode defaults to honor) under a parent that set `ignore`
    must resolve to HONOR, not inherit the parent's ignore. honor respects the
    cacheability floor so the origin's `private` response is NOT cached at the
    child; the parent (ignore) DOES cache it. Differential proves the child did
    not inherit ignore (the old two-flag model would have cached the child too)."""
    # parent (ignore): the private floor is bypassed -> cached -> HIT on re-read
    fetch(ng.port, "/ccinh/ccprivate")
    _, _, hp = fetch(ng.port, "/ccinh/ccprivate")
    assert hp.get("x-cache") == "HIT", \
        f"parent ignore must cache a private response; got {hp.get('x-cache')}"
    # child (preset honor): the private floor is honored -> NOT cached -> no HIT
    fetch(ng.port, "/ccinh/wp/ccprivate")
    _, _, hc = fetch(ng.port, "/ccinh/wp/ccprivate")
    assert hc.get("x-cache") != "HIT", \
        ("child CMS-preset must resolve to honor (private NOT cached), not "
         f"inherit parent ignore; got X-Cache={hc.get('x-cache')}")


def test_no_store(ng: Nginx) -> None:
    """v9: cache_turbo_no_store keeps a flagged response out of the cache."""
    _, _, h1 = fetch(ng.port, "/nost/y?private=1")
    assert "x-cache" not in h1, "first should miss"
    _, _, h2 = fetch(ng.port, "/nost/y?private=1")
    assert "x-cache" not in h2, "no_store response must not be cached"
    # without the flag it caches normally (same $uri key)
    _, _, h3 = fetch(ng.port, "/nost/y")
    assert "x-cache" not in h3, "first un-flagged read is still a miss"
    _, _, h4 = fetch(ng.port, "/nost/y")
    assert h4.get("x-cache") == "HIT", "un-flagged response should cache"


def test_native_cache_headers_stripped(ng: Nginx) -> None:
    """When a native nginx cache (proxy_cache) sits behind us, its per-response
    Age / X-Cache-Status must NOT be frozen into our blob and replayed on every
    L1 hit. Our own X-Cache stays."""
    fetch(ng.port, "/c/nativecache")                   # prime (origin Age=123)
    _, _, h = fetch(ng.port, "/c/nativecache")         # HIT from shm
    assert h.get("x-cache") == "HIT", "should be an L1 hit"
    # The upstream's frozen Age:123 must not be replayed; we emit our OWN Age
    # (seconds since WE stored it, so small) computed in serve().
    assert "age" in h, "our own Age header should be present on a HIT"
    assert int(h["age"]) < 100, \
        f"upstream Age=123 leaked instead of our computed Age: {h.get('age')}"
    assert "x-cache-status" not in h, \
        f"upstream X-Cache-Status leaked: {h.get('x-cache-status')}"


def test_warm_rejects_traversal(ng: Nginx, origin: Origin) -> None:
    """AUD3-WARM-URI-NORM: ngx_http_subrequest() does not run
    ngx_http_parse_complex_uri() on a hand-built URI, so a percent-decoded
    "?url=" value that resolves to a ".." segment must be rejected before it
    ever reaches location matching -- otherwise "/%2e%2e/%2e%2e/etc/x" decodes
    to "/../../etc/x" and is matched un-normalized. The bad entry must simply
    not be warmed (warmed count excludes it); a comma-separated list with a
    good entry alongside it must still warm the good one."""
    import json
    good = "/c/warm-trav-ok"
    base = origin.hits_for("warm-trav-ok")
    s, b, _ = fetch(ng.port, "/_cache?url=/%2e%2e/%2e%2e/etc/x", method="POST")
    assert s == 200, f"warm status {s}"
    assert json.loads(b)["warmed"] == 0, \
        f"traversal url must not be warmed: {b}"

    # a bad entry alongside a good one must not kill the good one.
    s2, b2, _ = fetch(
        ng.port, f"/_cache?url=/%2e%2e/%2e%2e/etc/x,{good}", method="POST")
    assert s2 == 200, f"warm status {s2}"
    assert json.loads(b2)["warmed"] == 1, \
        f"good url in the same list must still warm: {b2}"
    assert wait_for(lambda: origin.hits_for("warm-trav-ok") == base + 1), \
        "the good warm subrequest never reached origin"


def test_warm_rejects_embedded_nul(ng: Nginx, origin: Origin) -> None:
    """AUD3-WARM-URI-NORM: a percent-decoded %00 produces an embedded NUL in
    sr->uri; downstream ngx_str_t-vs-C-string consumers (proxy_pass URI
    construction, $uri in a log format) would truncate at it. Reject and skip
    rather than warm."""
    import json
    s, b, _ = fetch(ng.port, "/_cache?url=/c/warm-nul%00trunc", method="POST")
    assert s == 200, f"warm status {s}"
    assert json.loads(b)["warmed"] == 0, \
        f"NUL-containing url must not be warmed: {b}"


def test_warm_normal_url_still_warms(ng: Nginx, origin: Origin) -> None:
    """AUD3-WARM-URI-NORM guard: the new URI-safety check must not over-reject
    an ordinary valid warm target. Same shape as test_warm_populates, kept
    separate so the traversal/NUL fix has its own positive control."""
    import json
    uri = "/c/warm-norm-ok"
    base = origin.hits_for("warm-norm-ok")
    s, b, _ = fetch(ng.port, f"/_cache?url={uri}", method="POST")
    assert s == 200, f"warm status {s}"
    assert json.loads(b)["warmed"] == 1, f"warmed count: {b}"
    assert wait_for(lambda: origin.hits_for("warm-norm-ok") == base + 1), \
        "warm subrequest never hit the origin"


def test_stale_serves_stale(ng: Nginx, origin: Origin) -> None:
    """R3: once fresh TTL passes, the cache serves the stale copy (not a miss),
    and a refresh eventually lands (the served body advances to a new gen)."""
    s0, b0, _ = fetch(ng.port, "/swr/serve")       # prime
    assert s0 == 200
    time.sleep(1.3)                                # now stale (fresh=1s)
    # first stale read: must still be 200 and the SAME (stale) body or a fresh
    # regenerated one — never an error, never empty.
    s1, b1, h1 = fetch(ng.port, "/swr/serve")
    assert s1 == 200 and b1, f"stale serve failed: {s1} {b1!r}"
    assert h1.get("x-cache") in ("STALE", None), \
        f"expected STALE or fresh-regen, got {h1.get('x-cache')}"
    if h1.get("x-cache") == "STALE":
        # S231-PERF-BGSNAP: this is the single-box background-update arm that
        # now pins the shm blob instead of memcpy'ing it under the zone
        # mutex (ngx_http_cache_turbo_module.c, the `refresh == NGX_OK` /
        # `clcf->background_update` site). Byte-exact match proves the
        # pinned pointer served the right bytes, not stale/corrupted slab
        # data from a use-after-release.
        assert b1 == b0, \
            f"STALE serve returned a wrong body: {b1!r} != {b0!r}"
    # within the stale window the entry refreshes to a new generation
    deadline = time.time() + 2.0
    advanced = False
    while time.time() < deadline:
        _, b, h = fetch(ng.port, "/swr/serve")
        if b != b0 and h.get("x-cache") == "HIT":
            advanced = True
            break
        time.sleep(0.1)
    assert advanced, "stale entry never refreshed to a new generation"
    drain_origin(origin)       # v8: settle async bg refreshes before the next test


def test_single_flight(ng: Nginx, origin: Origin) -> None:
    """R4: a burst of readers on a stale key triggers far fewer origin regens
    than readers (single-flight), and never a per-reader stampede."""
    fetch(ng.port, "/swr/sf")                      # prime
    base = origin.hits
    time.sleep(1.3)                                # stale
    # Fire a burst; the hard lock + dice must collapse this to a handful of
    # origin regens, not one-per-reader. Poll a moment for in-flight refreshes.
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: fetch(ng.port, "/swr/sf"),
                                range(40)))
    assert {r[0] for r in results} == {200}, \
        f"stale burst returned {set(r[0] for r in results)}"
    time.sleep(0.5)
    regens = origin.hits - base
    # Single-flight property: nowhere near 40. A small number is fine (dice can
    # let a few through before the lock is visible across event-loop turns).
    assert regens <= 8, \
        f"single-flight failed: {regens} origin regens for 40 readers"
    drain_origin(origin)       # v8: settle async bg refreshes before the next test


def test_stale_if_error(ng: Nginx, origin: Origin) -> None:
    """v8: when an entry is stale and the background refresh hits a 5xx origin,
    the client keeps getting the stale copy — the error is never surfaced and
    the stale entry is not overwritten (stale-if-error)."""
    s0, b0, _ = fetch(ng.port, "/sie/x")           # prime: 200, cached fresh
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    base = origin.hits
    time.sleep(2.3)                                # past fresh (2s), inside the
                                                   # stale window (×4 = 8s)
    origin.fail = True
    try:
        for _ in range(8):
            s, b, h = fetch(ng.port, "/sie/x")
            assert s == 200, f"stale-if-error served {s}, expected stale 200"
            assert b == b0, f"served {b!r}, expected stale {b0!r}"
            assert h.get("x-cache") == "STALE", \
                f"expected STALE serve, got x-cache={h.get('x-cache')}"
            time.sleep(0.1)
        # the background refresh did reach the (failing) origin at least once.
        # bg-refresh is async; under a loaded (valgrind ×2) runner it can lag the
        # 0.8s serve loop, so poll to a generous deadline instead of asserting once.
        deadline = time.monotonic() + 5.0
        while origin.hits <= base and time.monotonic() < deadline:
            fetch(ng.port, "/sie/x")   # keep prodding the stale entry
            time.sleep(0.1)
        assert origin.hits > base, \
            "no background refresh reached the origin during the stale window"
    finally:
        origin.fail = False
        drain_origin(origin)   # settle the failing bg refreshes before next test


def test_stale_serves_stale_origin_hard_dead(ng: Nginx, origin: Origin) -> None:
    """Goal-2: serve-stale-on-dead-upstream. Within the stale window a read is
    answered from shm WITHOUT contacting the origin, so a hard upstream failure
    (connection dropped, not a clean 503) still yields a stale 200 — the error
    is never surfaced. This is the transport-level (502) counterpart to
    test_stale_if_error's clean-5xx case, and exercises the bg-refresh path
    against an origin that resets the connection.

    Boundary (intentional): this v8 path holds for the SWR window with
    background_update on (the default). A cold key, or background_update=off,
    surface the live origin error by design. A key already PAST its stale_until
    is no longer surfaced unconditionally — RFC-2 stale-if-error (CTB4) replays it
    when the response carried stale-if-error=N and now < created + sie_ttl (see
    test_sie_serve_on_error); without that window the expired entry still surfaces
    the error."""
    s0, b0, _ = fetch(ng.port, "/sie/x2")          # prime: 200, cached fresh
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    base = origin.hits
    time.sleep(2.3)                                # past fresh (2s), inside the
                                                   # stale window (×4 = 8s)
    origin.drop = True
    try:
        for _ in range(8):
            s, b, h = fetch(ng.port, "/sie/x2")
            assert s == 200, f"hard-dead origin served {s}, expected stale 200"
            assert b == b0, f"served {b!r}, expected stale {b0!r}"
            assert h.get("x-cache") == "STALE", \
                f"expected STALE serve, got x-cache={h.get('x-cache')}"
            time.sleep(0.1)
        # the background refresh did reach the dropped-connection origin. async +
        # loaded runner can lag the serve loop → poll to a deadline, not once.
        deadline = time.monotonic() + 5.0
        while origin.hits <= base and time.monotonic() < deadline:
            fetch(ng.port, "/sie/x2")
            time.sleep(0.1)
        assert origin.hits > base, \
            "no background refresh reached the origin during the stale window"
    finally:
        origin.drop = False
        drain_origin(origin)   # settle the failing bg refreshes before next test


def test_cold_wait_loser_serves_stale_on_lock_timeout(
        ng: Nginx, origin: Origin) -> None:
    """P1-8: a cold-miss LOSER that times out waiting on the single-flight
    winner (cache_turbo_lock_timeout) must serve an already-armed
    stale-if-error snapshot instead of falling through to a (possibly slow)
    origin itself -- the exact moment a stampede hurts most.

    /coldwaitsie/ (valid 1s, stale_mult 1) primes with the "sieserve" origin
    marker so the stored blob carries a stale-if-error=30 window. After the
    entry fully expires (~1.3s), the SAME key is fetched with the origin
    made slow (origin.delay >> lock_timeout 1s): the first request becomes
    the CLAIM_WINNER and blocks in the slow origin fetch; a second,
    concurrent request on the same key is a genuine CLAIM_LOSER and parks in
    cold_wait(). Its lock_timeout (1s) expires long before the winner's slow
    origin fetch returns, so with the fix it must serve the armed SIE
    snapshot (x-cache: STALE-IF-ERROR) rather than issuing its own origin
    request.

    The oracle is origin.hits_for(), not just status/body: with the bug, the
    timed-out loser falls through to NGX_DECLINED and issues a SECOND origin
    request of its own (a genuine stampede) even though its body would
    still equal the primed body once the slow winner eventually returns --
    an equality-only assertion could not tell "served the loser's own
    origin fetch" from "served the stashed snapshot" since both eventually
    produce the same bytes here. Counting origin contacts for this key
    distinguishes them: exactly one (the winner's) with the fix, at least
    two without it.

    Negative-control sibling below (test_cold_wait_loser_no_snapshot_goes_to_origin)
    proves the ordinary give-up-to-origin behaviour is unchanged when no SIE
    snapshot is armed."""
    key = "sieserve-cw1"
    uri = f"/coldwaitsie/sieserve-{key}"

    s0, b0, _ = fetch(ng.port, uri)
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    time.sleep(1.3)   # past fresh (1s) + stale (stale_mult 1 -> 1s): expired

    base = origin.hits_for(key)
    sie_before = _admin_stat(ng, "sie_serves")
    origin.delay = 3.0   # >> lock_timeout (1s), << fetch()'s 5s client timeout
    try:
        results: list[tuple[int, str, dict]] = [None, None]  # type: ignore[list-item]

        def _winner() -> None:
            results[0] = fetch(ng.port, uri)

        def _loser() -> None:
            results[1] = fetch(ng.port, uri)

        t_winner = threading.Thread(target=_winner)
        t_winner.start()
        time.sleep(0.15)   # let the winner claim the stub before the loser arrives
        t_loser = threading.Thread(target=_loser)
        t_loser.start()
        t_loser.join(timeout=4.0)
        assert not t_loser.is_alive(), \
            "loser did not return within lock_timeout + margin"

        sl, bl, hl = results[1]
        assert sl == 200, f"loser expected 200 stale serve, got {sl}"
        assert bl == b0, f"loser served {bl!r}, expected stale {b0!r}"
        assert hl.get("x-cache") == "STALE-IF-ERROR", \
            (f"loser should serve the armed SIE snapshot, got "
             f"x-cache={hl.get('x-cache')}")

        # S7.1: the dedicated sie_serves counter must move for this delivery
        # site too, not just the generic stale_serves -- same discipline the
        # header-filter SIE serve and the breaker-fallback serve both follow.
        assert _admin_stat(ng, "sie_serves") - sie_before == 1, \
            "sie_serves did not move for the cold-wait-timeout SIE delivery"

        # THE assertion: the loser must not have made its own origin request.
        # With the bug it falls through to NGX_DECLINED at lock_timeout and
        # issues a second origin fetch for this key; the fix serves the
        # snapshot with zero extra origin contact from the loser.
        hits_after_loser = origin.hits_for(key)
        assert hits_after_loser - base == 0, \
            (f"loser reached the origin ({hits_after_loser - base} extra "
             "hit(s)) instead of serving the armed SIE snapshot -- cold-wait "
             "timeout stampeded the slow origin")

        t_winner.join(timeout=6.0)
        assert not t_winner.is_alive(), "winner never returned"
        sw, bw, _ = results[0]
        assert sw == 200 and bw, f"winner (slow origin) failed: {sw} {bw!r}"

        # Exactly one origin contact total for this key: the winner's own
        # (slow) regen. The loser contributed none.
        assert origin.hits_for(key) - base == 1, \
            (f"expected exactly 1 origin contact for {key} (the winner's), "
             f"got {origin.hits_for(key) - base}")
    finally:
        origin.reset_delay()
        drain_origin(origin)


def test_cold_wait_loser_no_snapshot_goes_to_origin(
        ng: Nginx, origin: Origin) -> None:
    """P1-8 negative control: a cold-miss LOSER whose key has NO armed SIE
    snapshot (a plain expired-with-no-stale-if-error entry, same shape as
    /sieserve/'s "plain" control) must still give up at lock_timeout and go
    to the origin itself, exactly as before this change -- the byte-identical
    fall-through path for the common case (no snapshot armed) must not
    regress."""
    key = "plain-cw1"
    uri = f"/coldwaitsie/plain-{key}"

    s0, b0, _ = fetch(ng.port, uri)
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    time.sleep(1.3)   # expired; no stale-if-error on this marker -> sie_ttl == 0

    base = origin.hits_for(key)
    sie_before = _admin_stat(ng, "sie_serves")
    # Unlike the positive test, this control's loser does NOT serve a
    # snapshot: it gives up at lock_timeout (~1s) and then makes its OWN
    # origin request, so its total wall time is lock_timeout + whatever the
    # origin takes, not just lock_timeout. A shorter delay than the positive
    # test's (still comfortably longer than lock_timeout, so the winner is
    # provably still in flight when the loser's wait expires) keeps the
    # loser's own fetch well under fetch()'s 5s client ceiling.
    origin.delay = 1.5
    try:
        results: list[tuple[int, str, dict]] = [None, None]  # type: ignore[list-item]

        def _winner() -> None:
            results[0] = fetch(ng.port, uri)

        def _loser() -> None:
            results[1] = fetch(ng.port, uri)

        t_winner = threading.Thread(target=_winner)
        t_winner.start()
        time.sleep(0.15)
        t_loser = threading.Thread(target=_loser)
        t_loser.start()
        t_loser.join(timeout=4.0)
        assert not t_loser.is_alive(), \
            "loser did not return within lock_timeout + its own origin delay"

        sl, _bl, hl = results[1]
        assert sl == 200, f"loser expected 200 (its own origin fetch), got {sl}"
        assert hl.get("x-cache") != "STALE-IF-ERROR", \
            ("no SIE snapshot was armed for this key; the loser must not "
             f"serve one, got x-cache={hl.get('x-cache')}")

        # Unchanged behaviour: the timed-out loser makes its OWN origin
        # request when nothing is armed to serve instead.
        assert origin.hits_for(key) - base >= 1, \
            "loser with no armed snapshot should have gone to the origin " \
            "itself at lock_timeout, but made no origin contact"

        # sie_serves must NOT move: no snapshot was armed, so this delivery
        # is not an SIE serve by any path.
        assert _admin_stat(ng, "sie_serves") - sie_before == 0, \
            "sie_serves moved even though no SIE snapshot was armed"

        t_winner.join(timeout=6.0)
        assert not t_winner.is_alive(), "winner never returned"
    finally:
        origin.reset_delay()
        drain_origin(origin)


def test_sie_serve_on_error(ng: Nginx, origin: Origin) -> None:
    """RFC-2 (CTB4) stale-if-error serve-on-error: a FULLY EXPIRED entry (past its
    stale window) whose blob carries a serve-on-error window (created + sie_ttl) is
    replayed when the origin revalidation returns 5xx — the error is replaced by
    the stale body with X-Cache: STALE-IF-ERROR. This is the past-stale_until case
    the v8 SWR path deliberately did NOT cover (see
    test_stale_serves_stale_origin_hard_dead).

    Negative control in the same test: a sibling key whose response carries NO
    stale-if-error has sie_ttl == 0, so the same expired-origin-5xx surfaces the
    error instead of serving stale."""
    # Positive: origin emits stale-if-error=30 (request suffix marker "sieserve").
    s0, b0, _ = fetch(ng.port, "/sieserve/sieserve-k1")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    # Negative control: no stale-if-error in the response (sie_ttl == 0).
    sn, bn, _ = fetch(ng.port, "/sieserve/plain-k1")
    assert sn == 200 and bn, f"control prime failed: {sn} {bn!r}"

    time.sleep(1.3)     # past fresh (1s), stale_mult 1 -> 1s window: expired
    origin.fail = True
    try:
        s, b, h = fetch(ng.port, "/sieserve/sieserve-k1")
        assert s == 200, f"SIE serve-on-error returned {s}, expected stale 200"
        assert b == b0, f"served {b!r}, expected stale {b0!r}"
        assert h.get("x-cache") == "STALE-IF-ERROR", \
            f"expected STALE-IF-ERROR, got x-cache={h.get('x-cache')}"

        # Negative control: no SIE window -> the 5xx is surfaced, not replaced.
        sc, _, hc = fetch(ng.port, "/sieserve/plain-k1")
        assert sc == 503, f"no-SIE expired entry served {sc}, expected origin 503"
        assert hc.get("x-cache") != "STALE-IF-ERROR", \
            "a no-SIE expired entry must not serve-on-error"
    finally:
        origin.fail = False
        drain_origin(origin)




def _errlog_sie_unconsumed_in_window(ng: Nginx, start: int) -> list[int]:
    """AUD-SIE-BODY oracle: every `cache_turbo: test_sie_unconsumed=<N>` value
    logged strictly after byte offset `start`, in emission order.

    The module emits these at NOTICE, so they clear the harness's default log
    level with no TEST_CT_ERRLOG and no per-location debug error_log (see the
    long note in test_sie_serve_on_error_unbuffered for why debug is not an
    option here). Callers must still assert the list is non-empty before
    trusting any 0 in it: a missing line means the sie_serving block was never
    entered, or TEST_FAULTS was not compiled in -- not evidence of a fixed
    bug."""
    log = ng.root / "logs" / "error.log"
    try:
        with log.open("rb") as f:
            f.seek(start)
            tail = f.read()
    except OSError as exc:
        raise AssertionError(f"error.log unreadable: {exc}") from None
    text = tail.decode("utf-8", errors="replace")
    return [int(m) for m in
            re.findall(r"cache_turbo: test_sie_unconsumed=(\d+)", text)]


def test_sie_serve_on_error_unbuffered(ng: Nginx, origin: Origin) -> None:
    """AUD-SIE-BODY regression: same scenario as test_sie_serve_on_error (a
    fully expired /sieserve/-style entry replayed from its stale-if-error
    snapshot when the origin 5xxs) but through /siebuf/, which sets
    proxy_buffering off.

    A client-visible hang is the WRONG oracle for this bug: /siebuf/'s
    upstream has no keepalive pool, so ngx_http_upstream_finalize_request()
    unconditionally close()s the upstream connection on request teardown,
    which reclaims any stuck buffers as an OS side effect regardless of
    whether the module marked them consumed -- the request completes either
    way (proven: an earlier version of this test used a raw keep-alive socket
    with a bounded recv() timeout and did not reliably discriminate fix from
    revert). Only the module's INTERNAL buffer accounting differs, so this
    test asserts that directly via ctx->test_sie_unconsumed (TEST_FAULTS-only,
    see the field comment in ngx_http_cache_turbo_module.h): the count of
    incoming upstream buffers left with buf->pos != buf->last at the point the
    sie_serving block in the body filter returns, on both of its exits. With
    the fix this is always 0; reverting the two consume loops (pos = last /
    file_pos = file_last / sync = 1) leaves the discarded error-body buffers
    un-advanced and it is > 0.

    A response header cannot carry this value: by the time the body filter
    runs, ngx_http_next_header_filter() has already returned for this request
    (the sie_serving header-filter exit at :7807 calls it unconditionally,
    and nginx's header filter chain serializes r->headers_out.headers into
    the wire buffer synchronously with no postponement contract) -- a header
    stamped from the body filter would always read 0, which is the exact
    vacuous-pass shape this test must not have. Instead the module logs
    `cache_turbo: test_sie_unconsumed=<N>` at NOTICE level (not debug) and
    this test reads it out of logs/error.log, bracketed by byte offset so a
    line is provably attributable to this test's own triggering request and
    not a neighbour's.

    NOTICE, not ngx_log_debug1(), is deliberate. The line has to be readable
    at the harness's default level because CI never sets TEST_CT_ERRLOG, and
    the obvious alternative -- a location-scoped `error_log ... debug` on
    /siebuf/ -- kills the ASan job: debug logging in the proxy path trips a
    PRE-EXISTING UBSan null-pointer report in nginx core
    (src/core/ngx_string.c:586, "null pointer passed as argument 2"), and the
    sanitizer workflow runs with halt_on_error=1, so the worker aborts on the
    very first request. That reproduces on unmodified upstream code with a
    debug error_log added to the existing /sieserve/ location, so it is not
    this module's bug -- but it does make debug-level logging unusable inside
    a CI-visible fixture. The counter is TEST_FAULTS-only, so NOTICE costs
    production nothing.

    The origin's "sieserve-unbuf" marker (see Origin.do_GET) answers `fail`
    with an 8192-byte body written as two flushed chunks: a zero-length or
    single-recv error body leaves nothing behind for the sie_serving block to
    fail to consume, so the bug does not reproduce without it."""
    s0, b0, _ = fetch(ng.port, "/siebuf/sieserve-unbuf-k1")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    time.sleep(1.3)     # past fresh (1s), stale_mult 1 -> 1s window: expired
    origin.fail = True
    try:
        window_start = _errlog_window_start(ng)

        s, b, h = fetch(ng.port, "/siebuf/sieserve-unbuf-k1")
        assert s == 200, f"unbuffered SIE serve-on-error returned {s}"
        assert b == b0, f"served {b!r}, expected stale {b0!r}"
        assert h.get("x-cache") == "STALE-IF-ERROR", \
            f"expected STALE-IF-ERROR, got x-cache={h.get('x-cache')}"

        values = _errlog_sie_unconsumed_in_window(ng, window_start)
        assert values, (
            "no 'cache_turbo: test_sie_unconsumed=' line found in this "
            "request's error.log window -- the oracle line is MISSING, which "
            "must fail (never silently read as 0): either TEST_FAULTS is not "
            "actually compiled in, or the sie_serving block was not entered "
            "at all for this request")
        assert all(v == 0 for v in values), \
            (f"sie_serving left unconsumed upstream buffers on the fixed "
             f"build: test_sie_unconsumed values in window = {values} "
             f"(expected all 0)")
    finally:
        origin.fail = False
        drain_origin(origin)


def test_unbuf_streamed_store_and_hit(ng: Nginx) -> None:
    """proxy_buffering off coverage gap: ordinary capture/store + HIT serve
    when the origin body arrives as MANY flushed body-filter invocations
    instead of one coalesced chain. /siebuf/ only drives the SIE
    serve-on-error consume path; this proves the everyday store path is
    correct under the same multi-call streaming, exercising
    ctx->body_last append-cursor accumulation and last_buf detection across
    calls. A truncated or reordered capture must fail: assert full length
    AND byte-identity, not just non-empty."""
    s0, b0, h0 = fetch(ng.port, "/unbuf/unbuf-stream-k1")
    assert s0 == 200, f"prime fetch returned {s0}"
    assert "x-cache" not in h0, f"prime should MISS, got {h0.get('x-cache')}"
    assert len(b0) > 60000, f"prime body suspiciously short: {len(b0)} bytes"

    s1, b1, h1 = fetch(ng.port, "/unbuf/unbuf-stream-k1")
    assert s1 == 200, f"second fetch returned {s1}"
    assert h1.get("x-cache") == "HIT", \
        f"expected HIT after streamed store, got x-cache={h1.get('x-cache')}"
    assert len(b1) == len(b0), \
        f"HIT body length {len(b1)} != origin body length {len(b0)} " \
        f"-- streamed capture was truncated or padded"
    assert b1 == b0, "HIT body differs from the primed origin body byte-for-byte"


def test_unbuf_oversize_abort_mid_stream(ng: Nginx, origin: Origin) -> None:
    """proxy_buffering off + cache_turbo_max_size: the oversize origin body
    (~64 KiB, streamed as 16 flushed chunks) crosses the 8k cap on a LATER
    body-filter invocation, not the first buffer -- unlike test_max_size_not_
    cached's /big/ (single-buffer, buffered upstream). Delegation must still
    deliver the response COMPLETE and byte-correct to the client (no
    truncation), and the entry must never be cached."""
    s0, b0, h0 = fetch(ng.port, "/unbufbig/unbuf-big-k1")
    assert s0 == 200, f"oversize streamed fetch returned {s0}"
    assert "x-cache" not in h0, \
        f"oversize response must not be served from cache: {h0.get('x-cache')}"
    assert len(b0) > 60000, \
        f"oversize body truncated by the mid-stream abort: {len(b0)} bytes"
    assert b0.startswith("big-"), "oversize body missing its origin marker"
    assert b0.endswith("\n"), \
        "oversize body does not end cleanly -- looks truncated mid-chunk"
    # Every chunk, not just the length and the end markers: the delegated path
    # hands each buffer downstream individually, so a lost, duplicated or
    # reordered INTERIOR chunk is exactly the failure mode this test exists to
    # catch -- and a length-plus-first-and-last-marker assertion accepts all
    # three. `gen` is constant within one response, so the expected body is
    # reconstructible from the first chunk's generation.
    gen0 = b0.split("-")[1]
    expected0 = "".join(f"big-{gen0}-{i:02d}-" + "Z" * 4000 + "\n"
                        for i in range(16))
    assert b0 == expected0, \
        ("delegated oversize body is not the origin's byte stream -- a chunk "
         "was lost, duplicated or reordered mid-stream")

    # Re-fetch: must still be a live MISS (never cached), and origin must be
    # contacted again (distinct generation-tagged body).
    hits_before = origin.hits
    s1, b1, h1 = fetch(ng.port, "/unbufbig/unbuf-big-k1")
    assert s1 == 200, f"second oversize fetch returned {s1}"
    assert "x-cache" not in h1, \
        f"oversize entry must not have been cached: {h1.get('x-cache')}"
    assert origin.hits > hits_before, \
        "second fetch did not reach the origin -- oversize entry may have " \
        "been served from a cache after all"
    assert len(b1) == len(b0), \
        f"second oversize body length {len(b1)} != first {len(b0)}"
    gen1 = b1.split("-")[1]
    expected1 = "".join(f"big-{gen1}-{i:02d}-" + "Z" * 4000 + "\n"
                        for i in range(16))
    assert b1 == expected1, \
        ("second delegated oversize body is not the origin's byte stream -- a "
         "chunk was lost, duplicated or reordered mid-stream")


def test_sie_midbody_rescue(ng: Nginx, origin: Origin) -> None:
    """S231-SIE-MIDBODY: the header-filter SIE trigger (module.c ~:7948) only
    fires on the ORIGIN'S STATUS -- it can never see a mid-body origin death,
    because that arrives with headers already sent as an ordinary 200. This
    is the body filter's own pre-flush rescue: cache_turbo_test_midbody_abort
    makes the body filter treat the FIRST arriving buffer as that failure,
    deterministically, without depending on real connection-teardown timing.

    /midbody/ shares the /sieserve/ fixture shape (1s fresh, stale_mult 1,
    the "sieserve" request-suffix marker that makes the origin emit
    stale-if-error=30) so a warmed key both fully expires past its stale
    window AND stays inside its SIE window. The assertion is on the BODY,
    per the row's own done criterion, not the status: the rescue is body-only
    (headers were already 200 by the time the body filter can act -- see the
    long comment at the rescue site in ngx_http_cache_turbo_body_filter for
    why rewriting r->headers_out here would be invisible to the client), so
    the client-visible status stays 200. What must NOT happen is a truncated
    prefix -- the body must equal the full warmed snapshot exactly.

    Negative control (mandatory, S231-SIE-MIDBODY's own requirement): the
    same fault directive on /midbodycold/, where no "sieserve" marker is ever
    sent so sie_armed stays 0 for every request -- the fault must not
    fabricate a body out of nothing; the (fault-truncated) response passes
    through unchanged."""
    # Prime /midbody/ with a real (non-fault) response so a snapshot lands
    # armed with an SIE window, exactly as /sieserve/'s own prime does.
    s0, b0, _ = fetch(ng.port, "/midbody/sieserve-mb1")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    time.sleep(1.3)     # past fresh (1s), stale_mult 1 -> 1s window: expired

    s, b, _ = fetch(ng.port, "/midbody/sieserve-mb1")
    assert s == 200, f"mid-body rescue returned {s}, expected 200"
    assert b == b0, \
        (f"mid-body rescue served {b!r} ({len(b)} bytes), expected the full "
         f"warmed snapshot {b0!r} ({len(b0)} bytes) -- a truncated prefix "
         "means the rescue did not replace the fault-truncated body")

    # Negative control: no SIE window ever armed on this key -> the rescue's
    # own `ctx->sie_armed` guard must refuse, and the fault must not fabricate
    # a body out of nothing.
    #
    # ⚠ The assertion is on the FIRST (cold-miss) fetch, not a follow-up. This
    # location caches for 30s with no "sieserve" marker, so a second fetch is
    # an ordinary HIT that never re-enters the rescue guard at all -- asserting
    # there would be vacuous. The cold miss is the only request on this key
    # where the fault fires AND the guard is evaluated, so it is the only one
    # that can falsify "the fault fabricates a snapshot".
    sc0, bc0, hc0 = fetch(ng.port, "/midbodycold/cold-mb1")
    assert sc0 == 200, f"cold control returned {sc0}"
    assert hc0.get("x-cache") != "STALE-IF-ERROR", \
        "no SIE window was ever armed on this key -- the fault must not " \
        "fabricate a STALE-IF-ERROR serve"
    # The origin numbers every body ("gen-<n>"), and the warmed /midbody/
    # snapshot above is a DIFFERENT counter value, so this also proves the
    # rescue did not splice some other key's snapshot in here.
    assert bc0 != b0, \
        (f"cold control served {bc0!r}, the same bytes as the /midbody/ "
         "snapshot -- with nothing armed on this key the rescue must not "
         "produce a snapshot body at all")


def test_sie_midbody_rescue_declines_on_length_mismatch(ng: Nginx,
                                                          origin: Origin) -> None:
    """S231-SIE-MIDBODY / framing: by the time the body filter can act, the
    header filter chain has ALREADY serialised r->headers_out.content_length_n
    onto the wire for this 200 -- the client is committed to that framing
    before the rescue ever gets a chance to run. If the warmed snapshot's body
    is a DIFFERENT length than what the origin's (fault-truncated) response
    advertised, splicing the snapshot in anyway corrupts the framing: the
    client either hangs waiting for bytes that will never arrive, or desyncs a
    kept-alive connection. That is worse than the truncated body the rescue
    exists to fix, so the module must decline the rescue whenever the lengths
    cannot be proven equal, and let the (fault-truncated) response through
    unchanged instead -- exactly like the /midbodycold/ negative control in
    test_sie_midbody_rescue, but here sie_armed IS true and the only thing
    that differs is the length.

    /midbody/ is keyed on $uri, which excludes the query string, so priming
    with a plain body and then re-requesting with the `midbody-mismatch`
    marker hits the SAME cache key but drives the origin to advertise a
    DIFFERENT Content-Length on the abort-triggering request.

    ⚠ The key MUST carry the "sieserve" marker. Without it the origin never
    emits stale-if-error, so no snapshot ever arms, `ctx->sie_armed` stays 0
    and the rescue is refused by the ARMING guard — which would make this
    test a duplicate of the /midbodycold/ control and vacuous as a framing
    oracle. Mutation-verified: with the framing check forced to always-pass,
    this test must FAIL."""
    key = "/midbody/sieserve-mismatch-mb1"

    s0, b0, _ = fetch(ng.port, key)
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    time.sleep(1.3)     # past fresh (1s), stale_mult 1 -> 1s window: expired

    # Same cache key ($uri has no query string), but the origin's live
    # response for this request now carries a body of a different length --
    # the mismatch the rescue must detect and decline.
    s, b, h = fetch(ng.port, key + "?midbody-mismatch=1")
    assert h.get("x-cache") != "STALE-IF-ERROR", \
        ("the rescue served the warmed snapshot despite a Content-Length "
         "mismatch with the origin's live response -- this corrupts response "
         "framing for the client")
    assert b != b0, \
        (f"declined-rescue response {b!r} unexpectedly equals the warmed "
         f"snapshot {b0!r} -- the rescue must not have spliced the snapshot "
         "in when framing could not be proven safe")
    # The fault still truncates the FIRST buffer of the live response to
    # nothing forwarded before the abort fires, so the client sees a short
    # (possibly empty-prefix) body -- assert what must NOT happen (the full
    # snapshot leaking through), not a specific truncated byte count, since
    # that is an artifact of exactly where the fault trips relative to
    # buffering and is not this test's contract.
    assert s in (200, 502, 504), \
        f"declined-rescue mid-body fault surfaced unexpected status {s}"


def test_sie_serves_counter(ng: Nginx, origin: Origin) -> None:
    """S7.1: sie_serves counts responses actually served from a stale-if-error
    snapshot -- ngx_http_cache_turbo_sie_rewrite() winning inside the header
    filter -- not every armed-SIE request or every 5xx origin response.

    Same fixture shape as test_sie_serve_on_error (a fully expired /sieserve/
    entry whose response carried stale-if-error=30, replayed with
    X-Cache: STALE-IF-ERROR when the origin then 5xxs), but reads the admin
    counter delta around the exact triggering fetch instead of only checking
    the header.

    Negative control (mandatory): the sibling /sieserve/plain-* key carries no
    stale-if-error window, so the same expired-origin-5xx sequence surfaces
    the origin's 503 directly (proven by test_sie_serve_on_error) instead of
    taking the sie_rewrite() path -- sie_serves must NOT move for it, proving
    the counter is pinned to the rewrite succeeding, not to "any 5xx on an
    expired SIE-eligible location"."""
    s0, b0, _ = fetch(ng.port, "/sieserve/sieserve-cnt-pos")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    sn0, bn0, _ = fetch(ng.port, "/sieserve/plain-cnt-neg")
    assert sn0 == 200 and bn0, f"control prime failed: {sn0} {bn0!r}"

    time.sleep(1.3)     # past fresh (1s), stale_mult 1 -> 1s window: expired
    origin.fail = True
    try:
        before = _admin_stat(ng, "sie_serves")

        s, _b, h = fetch(ng.port, "/sieserve/sieserve-cnt-pos")
        assert s == 200, f"SIE serve-on-error returned {s}, expected stale 200"
        assert h.get("x-cache") == "STALE-IF-ERROR", \
            f"expected STALE-IF-ERROR, got x-cache={h.get('x-cache')}"
        after_pos = _admin_stat(ng, "sie_serves")
        assert after_pos - before > 0, \
            "sie_serves did not move on an actual SIE serve-on-error"

        # Negative control: no SIE window on this key -> 503 surfaced directly,
        # no sie_rewrite() call, counter must stay put.
        sc, _, hc = fetch(ng.port, "/sieserve/plain-cnt-neg")
        assert sc == 503, f"no-SIE expired entry served {sc}, expected origin 503"
        assert hc.get("x-cache") != "STALE-IF-ERROR"
        after_neg = _admin_stat(ng, "sie_serves")
        assert after_neg == after_pos, \
            ("sie_serves moved on a plain 503 with no armed SIE snapshot -- "
             f"{after_pos} -> {after_neg}")
    finally:
        origin.fail = False
        drain_origin(origin)


def test_sie_origin_recovers_serves_fresh(ng: Nginx, origin: Origin) -> None:
    """RFC-2 serve-on-error must NOT hijack a SUCCESSFUL revalidation: when the
    expired entry's origin comes back 200, the client gets the FRESH new body and
    the entry is re-stored (the normal store path stays intact), not the stale
    snapshot."""
    s0, b0, _ = fetch(ng.port, "/sieserve/sieserve-k2")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    time.sleep(1.3)                                # fully expired (stale_mult 1: 1s window)
    s, b, h = fetch(ng.port, "/sieserve/sieserve-k2")
    assert s == 200, f"recovered origin served {s}, expected fresh 200"
    assert b != b0, f"served stale {b!r}, expected a fresh new gen"
    assert h.get("x-cache") != "STALE-IF-ERROR", \
        "a successful revalidation must not be a serve-on-error"
    # Re-stored fresh: an immediate re-read returns the same NEW body from cache.
    s2, b2, _ = fetch(ng.port, "/sieserve/sieserve-k2")
    assert s2 == 200 and b2 == b, "expected the fresh re-store to be re-served"


def test_keep_stale_serves_dead_origin(ng: Nginx, origin: Origin) -> None:
    """S2.2: cache_turbo_keep_stale is the origin-independent serve-on-error
    fallback (D-1 precedence table) when the response carries no
    stale-if-error of its own. /keepstale/ origin emits no Cache-Control at
    all, so without keep_stale a fully-expired entry would have sie_window==0
    and surface the dead origin's error. With keep_stale 1h, sie_window =
    ttl (1s) + 3600, comfortably covering the test's expiry window -> a hard
    connection-drop on a fully expired entry still serves the cached body with
    X-Cache: STALE-IF-ERROR.

    Negative control (MANDATORY, same origin behaviour, sibling location with
    cache_turbo_keep_stale off): the identical dead-origin request against
    /keepstaleoff/ must surface a 502 -- proving the 200 above is caused by
    keep_stale, not some other widening (SWR/stale_mult) leaking into the
    expired path."""
    s0, b0, _ = fetch(ng.port, "/keepstale/x")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    sn0, bn0, _ = fetch(ng.port, "/keepstaleoff/x")
    assert sn0 == 200 and bn0, f"control prime failed: {sn0} {bn0!r}"

    time.sleep(1.3)     # past fresh (1s), stale_mult 1 -> 1s window: expired
    origin.drop = True
    try:
        # Positive: keep_stale covers the outage -> stale body served.
        s, b, h = fetch(ng.port, "/keepstale/x")
        assert s == 200, f"keep_stale dead-origin served {s}, expected stale 200"
        assert b == b0, f"served {b!r}, expected stale {b0!r}"
        assert h.get("x-cache") == "STALE-IF-ERROR", \
            f"expected STALE-IF-ERROR, got x-cache={h.get('x-cache')}"

        # Negative control: keep_stale off -> no fallback window -> the dead
        # origin's connection-drop surfaces as 502, proven BY THIS ASSERTION.
        sc, _, hc = fetch(ng.port, "/keepstaleoff/x")
        assert sc == 502, \
            f"keep_stale off served {sc}, expected 502 (no serve-on-error window)"
        assert hc.get("x-cache") != "STALE-IF-ERROR", \
            "keep_stale off must not serve-on-error"
    finally:
        origin.drop = False
        drain_origin(origin)


def test_keep_stale_shipped_default_serves_dead_origin(ng: Nginx, origin: Origin) -> None:
    """S231-DEFAULTS: `/ksdefault/` sets NO cache_turbo_keep_stale directive at
    all -- proves the compiled-in merge default is a non-zero grace window
    (24h), not just that `cache_turbo_keep_stale 24h;` works when written out
    explicitly (test_keep_stale_serves_dead_origin above covers the explicit
    case). Same shape: prime, expire past the 1s fresh/stale window, drop the
    connection, and expect the cached body back with X-Cache: STALE-IF-ERROR
    instead of a surfaced 502. Before S231-DEFAULTS this location would have
    behaved exactly like /keepstaleoff/ (merge default was 0/off)."""
    s0, b0, _ = fetch(ng.port, "/ksdefault/x")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    time.sleep(1.3)     # past fresh (1s), stale_mult 1 -> 1s window: expired
    origin.drop = True
    try:
        s, b, h = fetch(ng.port, "/ksdefault/x")
        assert s == 200, \
            f"shipped keep_stale default: dead-origin served {s}, expected stale 200"
        assert b == b0, f"served {b!r}, expected stale {b0!r}"
        assert h.get("x-cache") == "STALE-IF-ERROR", \
            f"expected STALE-IF-ERROR, got x-cache={h.get('x-cache')}"
    finally:
        origin.drop = False
        drain_origin(origin)


def test_use_stale_http_404(ng: Nginx, origin: Origin) -> None:
    """S4.2: cache_turbo_use_stale selects WHICH upstream statuses fall back to
    a stale copy, replacing the hardcoded "any 5xx" trigger in the header
    filter. /usestale404/ names http_404 and nothing else.

    Four assertions, and the three negatives are the point (S4.1-b: the S4.1
    parse tests cannot observe the mask at all, so every mutation below survives
    them unchanged):

      1. 404 on /usestale404/ -> stale served. The mask read works and a
         non-5xx status can now trigger, which was impossible before S4.2.
      2. 503 on /usestale404/ -> surfaces as 503. Kills a mask read that
         triggers unconditionally, and kills "http_404 also sets the 5xx bits".
      3. 404 on /usestaledefault/ -> surfaces as 404. Kills a widened
         USE_STALE_DEFAULT and proves the merge default is not simply "all
         bits". This is the assertion that fails if UNSET-vs-0 merging breaks
         in the direction of over-triggering.
      4. 503 on /usestaledefault/ -> stale served. The default still reproduces
         the pre-S4.2 behaviour byte-for-byte; without this, dropping the 5xx
         bits from the default would read as a pass.

    Both locations carry keep_stale 1h, so the serve-on-error window itself is
    identical and the mask is the only variable."""
    s0, b0, _ = fetch(ng.port, "/usestale404/x")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    sd0, bd0, _ = fetch(ng.port, "/usestaledefault/x")
    assert sd0 == 200 and bd0, f"default-location prime failed: {sd0} {bd0!r}"

    time.sleep(1.3)     # past fresh (1s), stale_mult 1 -> 1s window: expired
    origin.fail = True
    try:
        # 1. named status triggers.
        origin.fail_status = 404
        s, b, h = fetch(ng.port, "/usestale404/x")
        assert s == 200, f"use_stale http_404 served {s}, expected stale 200"
        assert b == b0, f"served {b!r}, expected stale {b0!r}"
        assert h.get("x-cache") == "STALE-IF-ERROR", \
            f"expected STALE-IF-ERROR, got x-cache={h.get('x-cache')}"

        # A stale serve fires a background refresh subrequest, which hits the
        # (still failing) origin asynchronously. Settle it before the next
        # request: otherwise the following fetch races that in-flight refresh on
        # the shared keepalive connection and can time out rather than fail an
        # assertion. Same reason the keep_stale tests drain before returning.
        drain_origin(origin)

        # 2. an unnamed status does NOT trigger, even though it is a 5xx and
        #    would have triggered under the pre-S4.2 hardcoded condition.
        origin.fail_status = 503
        s2, _, h2 = fetch(ng.port, "/usestale404/x")
        assert s2 == 503, \
            f"use_stale http_404 served {s2} on a 503, expected the origin's 503"
        assert h2.get("x-cache") != "STALE-IF-ERROR", \
            "a status outside the mask must not serve-on-error"

        # 3. default mask does NOT cover 404.
        origin.fail_status = 404
        s3, _, h3 = fetch(ng.port, "/usestaledefault/x")
        assert s3 == 404, \
            f"default use_stale served {s3} on a 404, expected the origin's 404"
        assert h3.get("x-cache") != "STALE-IF-ERROR", \
            "the default mask must not serve-on-error for 404"

        # 4. default mask still covers 5xx exactly as it did before S4.2.
        origin.fail_status = 503
        s4, b4, h4 = fetch(ng.port, "/usestaledefault/x")
        assert s4 == 200, f"default use_stale served {s4} on a 503, expected stale 200"
        assert b4 == bd0, f"served {b4!r}, expected stale {bd0!r}"
        assert h4.get("x-cache") == "STALE-IF-ERROR", \
            f"expected STALE-IF-ERROR, got x-cache={h4.get('x-cache')}"
    finally:
        origin.fail = False
        origin.fail_status = 503
        drain_origin(origin)


def test_use_stale_any_5xx_bit(ng: Nginx, origin: Origin) -> None:
    """S4.2 / S4.1-b: pins the ANY_5XX bit, which no config token can set and
    which the parse tests cannot observe.

    USE_STALE_DEFAULT is the four named 5xx bits PLUS ANY_5XX, together
    reproducing "every 5xx" -- including the ones no bit names (506, 507, 508,
    510, 511). Drop ANY_5XX from the default and the four named bits still
    cover 500/502/503/504, so every other test in this file keeps passing while
    a 507 silently stops serving stale.

      - 507 on /usestaledefault/ -> stale served (ANY_5XX present in default).
      - 507 on /usestale500/ (mask = http_500 only) -> surfaces as 507. Proves
        the 507 above is caused by ANY_5XX specifically and not by the trigger
        falling back to a 5xx range check that ignores the mask."""
    s0, b0, _ = fetch(ng.port, "/usestaledefault/y")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    s500, b500, _ = fetch(ng.port, "/usestale500/y")
    assert s500 == 200 and b500, f"http_500-location prime failed: {s500} {b500!r}"

    time.sleep(1.3)     # fully expired (stale_mult 1: 1s window)
    origin.fail = True
    origin.fail_status = 507
    try:
        s, b, h = fetch(ng.port, "/usestaledefault/y")
        assert s == 200, \
            f"default use_stale served {s} on a 507, expected stale 200 (ANY_5XX)"
        assert b == b0, f"served {b!r}, expected stale {b0!r}"
        assert h.get("x-cache") == "STALE-IF-ERROR", \
            f"expected STALE-IF-ERROR, got x-cache={h.get('x-cache')}"

        # Stale serve -> background refresh against the failing origin; settle
        # it before the next request (see test_use_stale_http_404).
        drain_origin(origin)

        s2, _, h2 = fetch(ng.port, "/usestale500/y")
        assert s2 == 507, \
            f"use_stale http_500 served {s2} on a 507, expected the origin's 507"
        assert h2.get("x-cache") != "STALE-IF-ERROR", \
            "http_500 alone must not cover an unnamed 5xx"
    finally:
        origin.fail = False
        origin.fail_status = 503
        drain_origin(origin)


def test_use_stale_off(ng: Nginx, origin: Origin) -> None:
    """S4.2: `cache_turbo_use_stale off` means an EMPTY mask -- no status
    triggers a stale serve, including the 5xx the default covers.

    /usestaleoff/ carries keep_stale 1h exactly like /usestaledefault/, so the
    serve-on-error window is armed and identical; only the mask differs. A 503
    must therefore surface as 503 here while the same request against the
    default location serves stale. Without this, an `off` that merged as UNSET
    (i.e. silently fell back to the default) would look identical to a working
    `off` in every other test."""
    s0, b0, _ = fetch(ng.port, "/usestaleoff/z")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    sd0, bd0, _ = fetch(ng.port, "/usestaledefault/z")
    assert sd0 == 200 and bd0, f"default-location prime failed: {sd0} {bd0!r}"

    time.sleep(1.3)     # fully expired (stale_mult 1: 1s window)
    origin.fail = True
    try:
        s, _, h = fetch(ng.port, "/usestaleoff/z")
        assert s == 503, \
            f"use_stale off served {s} on a 503, expected the origin's 503"
        assert h.get("x-cache") != "STALE-IF-ERROR", \
            "use_stale off must never serve-on-error"

        # Same request, same window, default mask -> stale. Proves the 503
        # above is caused by `off` and not by a missing or short SIE window.
        s2, b2, h2 = fetch(ng.port, "/usestaledefault/z")
        assert s2 == 200, f"default use_stale served {s2}, expected stale 200"
        assert b2 == bd0, f"served {b2!r}, expected stale {bd0!r}"
        assert h2.get("x-cache") == "STALE-IF-ERROR", \
            f"expected STALE-IF-ERROR, got x-cache={h2.get('x-cache')}"
    finally:
        origin.fail = False
        drain_origin(origin)


def test_use_stale_403_429(ng: Nginx, origin: Origin) -> None:
    """S4.2: the remaining explicit non-5xx tokens. `cache_turbo_use_stale
    http_403 http_429` must trigger on both statuses it names and on nothing
    else -- in particular not on a 503, which the DEFAULT would have covered.

    This is the multi-token arm: it also proves the parser's accumulation
    across tokens reaches the trigger intact, which the S4.1 parse tests could
    only prove as far as `nginx -t`."""
    s0, b0, _ = fetch(ng.port, "/usestale403429/w")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    time.sleep(1.3)     # fully expired (stale_mult 1: 1s window)
    origin.fail = True
    try:
        for status in (403, 429):
            origin.fail_status = status
            s, b, h = fetch(ng.port, "/usestale403429/w")
            assert s == 200, \
                f"use_stale http_403 http_429 served {s} on a {status}, expected stale 200"
            assert b == b0, f"served {b!r} on a {status}, expected stale {b0!r}"
            assert h.get("x-cache") == "STALE-IF-ERROR", \
                f"expected STALE-IF-ERROR on {status}, got x-cache={h.get('x-cache')}"
            # Settle the background refresh this serve fired before the next
            # iteration reuses the connection (see test_use_stale_http_404).
            drain_origin(origin)

        # A 5xx is NOT in this mask, even though the default covers it.
        origin.fail_status = 503
        s2, _, h2 = fetch(ng.port, "/usestale403429/w")
        assert s2 == 503, \
            f"use_stale http_403 http_429 served {s2} on a 503, expected the origin's 503"
        assert h2.get("x-cache") != "STALE-IF-ERROR", \
            "a status outside the mask must not serve-on-error"
    finally:
        origin.fail = False
        origin.fail_status = 503
        drain_origin(origin)


def test_keep_stale_loses_to_response_sie(ng: Nginx, origin: Origin) -> None:
    """S2.2 / D-1: a HONORED response stale-if-error wins over
    cache_turbo_keep_stale when both are available -- NOT max(). /keepstalewins/
    has keep_stale 1h (3600s) configured; the "sieshort" request-suffix marker
    makes the origin emit stale-if-error=5 for this request, a short-window
    sibling of the "sieserve" convention used by /sieserve/ (deliberately past
    the location's own stale window -- stale_mult default 4 x 1s fresh = 4s --
    so phase 1 below lands inside the SIE window, not the ordinary stale one).
    If the precedence were max(), sie_window would be ttl+3600 and a request
    timed at ttl+~7.5s (well past the response SIE window but nowhere near the
    keep_stale window) would still serve stale. The correct precedence
    (response SIE wins outright, keep_stale is not consulted at all) makes that
    same request surface the dead origin's error instead."""
    s0, b0, _ = fetch(ng.port, "/keepstalewins/sieshort-p1")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    # Phase 1 -- past the ordinary stale window (4s) but inside the response's
    # own SIE window (1+5=6s). Serves stale via SIE, not the ordinary stale path.
    # NB this assertion is NOT the discriminating one: it passes identically
    # whether the precedence is "response SIE wins" (window ~6s) or a max()
    # bug (window ~3601s). It only establishes that a window exists at all.
    time.sleep(4.6)     # past fresh (1s) and the 4s stale window: fully expired,
                        # but still inside the sie window (1+5=6s)
    origin.fail = True
    try:
        s, b, h = fetch(ng.port, "/keepstalewins/sieshort-p1")
        assert s == 200, f"within response-SIE window served {s}, expected 200"
        assert b == b0, f"served {b!r}, expected stale {b0!r}"
        assert h.get("x-cache") == "STALE-IF-ERROR", \
            f"expected STALE-IF-ERROR, got x-cache={h.get('x-cache')}"
    finally:
        origin.fail = False
        drain_origin(origin)

    # Phase 2 -- THE DISCRIMINATING ASSERTION. Past the response's own SIE
    # window (fresh 1s + sie 5s = ~6s) but far short of keep_stale's 3600s.
    # Correct precedence: sie_window ended at ~6s, keep_stale was never
    # consulted -> the dead origin surfaces as 502. Under a max() bug the
    # window would run to ~3601s and this would still serve a stale 200, so
    # this assertion is what fails if anyone "reconciles" the precedence into
    # a max(). Re-prime first: phase 1 left the entry untouched (a stale serve
    # does not re-store), so its absolute sie deadline is still ~6s from the
    # ORIGINAL store -- sleeping the remainder is what crosses it.
    # 2.9s (not the bare 1.4s that would just clear 6s): overshooting the sie
    # deadline is free -- keep_stale runs to 3600s, so any time between 6s and
    # 3600s discriminates identically. The margin is deliberate; this box runs
    # loaded and a 0.5s cushion turns a correct test into a flake.
    time.sleep(2.9)    # ~7.5s total since the store: response SIE expired
    origin.fail = True
    try:
        s2, _, h2 = fetch(ng.port, "/keepstalewins/sieshort-p1")
        # 503 (not 502): origin.fail returns an upstream 503, which passes
        # through once no serve-on-error window covers the request.
        # origin.drop is the transport-level failure that yields 502.
        assert s2 == 503, (
            f"past the response stale-if-error window served {s2}, expected 503. "
            "A 200 here means keep_stale (3600s) widened the window the response "
            "had already scoped to 5s -- i.e. the precedence became max(), which "
            "D-1 explicitly rejects."
        )
        assert h2.get("x-cache") != "STALE-IF-ERROR", \
            "keep_stale must not extend a response-scoped stale-if-error window"
    finally:
        origin.fail = False
        drain_origin(origin)


def test_5xx_never_overwrites_cached_body(ng: Nginx, origin: Origin) -> None:
    """O6/S3.1: a legitimate negative-cache rule (cache_turbo_valid 503 1m)
    must never let an error blob overwrite a still-serveable good body -- the
    exact inverse of outage resilience. /noclobber/ has a 1s fresh TTL (x4 =
    4s stale window) plus `cache_turbo_valid 503 1m`, `background_update off`
    (the dice-winning reader regenerates INLINE/synchronously instead of
    firing a background subrequest -- deterministic, no async race to wait
    out) and a cranked `cache_turbo_beta 100000` so the very first stale-path
    request wins the refresh dice for certain (threshold saturates to
    guaranteed almost immediately after fresh_until, see
    ngx_http_cache_turbo_should_refresh's elapsed_frac*beta model).

    Sequence: warm with a 200, sleep past fresh_until (1s) but well inside
    the stale window (4s) -- entry is stale-but-serveable, exactly the case
    the guard predicate's `now < stale_until` branch protects. The dice
    winner goes straight to origin inline; origin answers a clean 503 (NOT
    origin.drop -- that is a transport-level 502, a different code path).
    That 503 is what `cache_turbo_valid 503 1m` would normally negative-cache
    -- clobbering the good entry without the guard. A second request right
    after must still see the ORIGINAL 200 body from cache. Once the origin
    recovers a 200 must still be served, though NOT necessarily the original
    body: the entry is past fresh_until, so a healthy refresh may legitimately
    replace it (the guard blocks ERROR stores, it does not freeze good ones)."""
    s0, b0, _ = fetch(ng.port, "/noclobber/x")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    time.sleep(2.5)     # past fresh (1s), well inside stale window (fresh+4=5s)
    origin.fail = True
    try:
        # The stale-but-serveable dice winner regenerates inline (background_
        # update off) and gets the origin's 503 back. Without the guard this
        # STORES the 503 into L1, clobbering the good body.
        s1, _, _ = fetch(ng.port, "/noclobber/x")
        assert s1 == 503, f"expected the origin's 503 to pass through, got {s1}"

        # THE DISCRIMINATING ASSERTION: a second request right after must
        # still see the ORIGINAL 200 body, not a cached 503. If the guard is
        # missing/disabled, the first request's 503 got stored and this
        # request is served straight from cache as a 503 with no body match.
        s2, b2, _ = fetch(ng.port, "/noclobber/x")
        assert s2 == 200, (
            f"second stale-path request got {s2}, expected 200 -- the prior "
            "503 was allowed to overwrite the cached body"
        )
        assert b2 == b0, f"served {b2!r}, expected original body {b0!r}"
    finally:
        origin.fail = False
        drain_origin(origin)

    # After the origin recovers, a 200 must be served -- either the retained
    # original or a fresh regeneration.
    #
    # ⚠ Deliberately NOT `b3 == b0`. The entry is past fresh_until, so once the
    # origin is healthy again a refresh legitimately stores a NEW body: that is
    # the cache working, not the guard failing. Asserting the original body
    # survives recovery would demand the entry never refresh again, and the
    # assertion DID fail that way (`gen-5356` != `gen-5354`) while the guard
    # itself was working correctly. The guard's contract is "an ERROR must not
    # replace a good body", never "a good body is frozen".
    s3, b3, _ = fetch(ng.port, "/noclobber/x")
    assert s3 == 200, f"post-recovery request got {s3}, expected 200"
    assert b3, "post-recovery served an empty body"


def test_5xx_cta_bypass_never_overwrites_cached_body(ng: Nginx,
                                                      origin: Origin) -> None:
    """AUD-5XX-CTA: the "refuse to overwrite a good cached body with an error
    status" guard used to be a separate check-then-act -- lock, lookup,
    decide `protect`, unlock, THEN store re-locked later. cache_turbo_bypass
    is the one path that skips BOTH the lookup and the single-flight claim
    while still permitting a store, so a bypassed request has no earlier
    serialization point at all and drives the guard's predicate and its write
    through two independent lock acquisitions -- exactly the window
    AUD-5XX-CTA closes by folding both into shm_store_if() under ONE lock.

    /cta5xx/ seeds a normal 200 (cacheable 30s), then every further request
    goes through ?nocache=1 (cache_turbo_bypass), which always reaches the
    origin and always attempts a store on the way back regardless of cache
    state. With the origin forced to answer 503 (negative-cacheable via
    `cache_turbo_valid 503 1m`), the guard must refuse to let that 503
    displace the still-fresh 200 seeded above. A subsequent NON-bypassed read
    must still return the original 200 body -- under the pre-fix bug the 503
    clobbers the entry and this read comes back as a cached 503 (or a
    mismatched body from a second store race)."""
    s0, b0, _ = fetch(ng.port, "/cta5xx/x")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    origin.fail = True
    origin.fail_status = 503
    try:
        # Bypass: skips lookup + single-flight, still stores. This is the
        # store-path call that must be refused by the guard.
        s1, _, _ = fetch(ng.port, "/cta5xx/x?nocache=1")
        assert s1 == 503, \
            f"bypassed request should reach origin's 503, got {s1}"

        # A second bypass for good measure -- makes a single successful
        # refusal insufficient if the guard only holds up once.
        s1b, _, _ = fetch(ng.port, "/cta5xx/x?nocache=1")
        assert s1b == 503, \
            f"second bypassed request should also reach origin's 503, got {s1b}"
    finally:
        origin.fail = False
        drain_origin(origin)

    # THE DISCRIMINATING ASSERTION: a plain (non-bypass) read must still HIT
    # the original 200 body. Under the pre-fix check-then-act bug, the
    # bypassed store above overwrote the entry with the negative-cached 503,
    # and this read would come back 503 with an empty/mismatched body.
    s2, b2, h2 = fetch(ng.port, "/cta5xx/x")
    assert s2 == 200, (
        f"post-bypass plain read got {s2}, expected 200 -- the bypassed 5xx "
        "store was allowed to overwrite the cached body (AUD-5XX-CTA)"
    )
    assert b2 == b0, f"served {b2!r}, expected original body {b0!r}"
    assert h2.get("x-cache") == "HIT", \
        f"post-bypass plain read expected a cache HIT, got {h2.get('x-cache')!r}"


def test_keep_stale_no_reaper_lru_only_reclaim(ng: Nginx, origin: Origin) -> None:
    """S2.3 CONTRACT: an L1 node past its stale deadline but still inside its
    cache_turbo_keep_stale window is reclaimed ONLY by LRU/max_size pressure --
    there is no time-based reaper proactively evicting it. Verified against
    src/ngx_http_cache_turbo_shm.c: the only eviction path is
    ngx_http_cache_turbo_shm_evict_one(), called exclusively from
    ngx_http_cache_turbo_shm_alloc_evict() on an allocation failure inside
    store()/claim()/count_miss()/l2_neg_set(). No ngx_add_timer/event-driven
    sweep touches the LRU queues anywhere in the module. This is deliberate,
    not a gap -- do not "fix" it with a reaper.

    /ksev/ (zone ksevz, 8m->64k, the enforced minimum) has cache_turbo_valid 1s
    and cache_turbo_keep_stale 1h, so an entry is fresh for ~1s and then sits
    deep inside a 3600s keep-stale window for the rest of this test.

    Phase 1 (retention across an idle gap): prime one key, let it go stale,
    wait past the stale deadline with NOTHING else touching the zone, then
    kill the origin and confirm the key still serves a stale 200.

    ⚠ SCOPE OF THIS PHASE -- do not over-trust it. The idle gap is only ~2.3s,
    so it does NOT rule out a time-based reaper in general: any plausible
    sweep cadence (seconds to minutes) could hide inside this window and the
    assertion would still pass. What phase 1 actually proves is narrower and
    still worth having -- that an expired-but-inside-keep_stale node is
    RETAINED and SERVEABLE rather than dropped at its stale deadline, which is
    the behaviour keep_stale exists to provide. The real evidence for the
    no-reaper contract is the source read recorded in the first paragraph
    (there is no ngx_add_timer sweep to find), not this sleep. Lengthening the
    wait would buy very little and cost the suite real wall-clock; if you ever
    need the stronger claim, assert it against the source, not the clock.

    Phase 2 (discriminates "LRU is what DOES reclaim it"): with the same key
    still resident, flood the same tiny zone with enough distinct keys to
    force real max_size eviction. The original key must now be gone (a fresh
    MISS body, not the stale one) -- proving reclaim genuinely happens, just
    triggered by capacity pressure rather than a clock. Without this phase,
    phase 1 alone can't distinguish "no reaper" from "eviction is broken
    entirely"."""
    key = "/ksev/no-reaper"

    # Prime, then let TTL (1s) elapse so the entry is genuinely stale.
    s0, b0, h0 = fetch(ng.port, key)
    assert s0 == 200, f"prime {key} -> {s0}"
    assert h0.get("x-ct-status") == "MISS", f"prime not a MISS: {h0.get('x-ct-status')}"
    time.sleep(1.3)   # cross the 1s valid window -> now stale, deep in keep_stale

    # Nothing touches ksevz here. If a reaper swept expired-but-keep-stale
    # nodes on a timer, this idle gap is exactly where it would fire.
    time.sleep(1.0)

    origin.fail = True
    try:
        s1, b1, _ = fetch(ng.port, key)
        # A time-based reaper would have removed this node already, so the
        # request would MISS, hit the dead origin, and surface an error (503)
        # instead of serving the retained stale body.
        assert s1 == 200, (
            f"{key} returned {s1} with origin down after an idle wait -- "
            "expected a stale 200. A non-200 here means the entry was reaped "
            "by something other than LRU/max_size pressure, violating the "
            "no-reaper contract."
        )
        assert b1 == b0, (
            f"{key} body changed ({b0!r} -> {b1!r}) with origin down -- "
            "expected the SAME retained stale node, not a refill"
        )
    finally:
        origin.fail = False
        drain_origin(origin)

    # Phase 2: force real LRU/max_size eviction in the SAME tiny zone by
    # flooding it with enough distinct keys to overflow 64k. The original key
    # must be gone afterward -- reclaim happens, just via capacity, not time.
    for i in range(120):
        fetch(ng.port, f"/ksev/flood-{i}")

    s2, b2, h2 = fetch(ng.port, key)
    assert s2 == 200, f"post-flood {key} -> {s2}"
    assert h2.get("x-ct-status") == "MISS", (
        f"{key} still resident after flooding ksevz to capacity "
        f"(status={h2.get('x-ct-status')}) -- LRU/max_size pressure is "
        "supposed to be the actual reclaim mechanism; if it never evicts "
        "either, entries would accumulate in a keep_stale zone forever."
    )
    assert b2 != b0, (
        f"{key} served the SAME stale body ({b0!r}) after eviction pressure -- "
        "the old node should have been reclaimed and this should be a fresh refill"
    )


def test_background_update_off_regenerates_inline(ng: Nginx,
                                                  origin: Origin) -> None:
    """v8: cache_turbo_background_update off restores the pre-v8 winner — the
    stale dice-winner regenerates INLINE and serves the freshly regenerated body
    on that same request (live origin response, no X-Cache header), rather than
    serving stale and refreshing in the background."""
    s0, b0, _ = fetch(ng.port, "/noswr/x")         # prime
    assert s0 == 200 and b0
    time.sleep(2.3)                                # stale
    # aggressive beta -> a stale read wins the dice; bg-off -> it regenerates
    # inline and the response is the live origin body (no X-Cache), a NEW gen.
    deadline = time.time() + 3.0
    got_fresh_inline = False
    while time.time() < deadline:
        s, b, h = fetch(ng.port, "/noswr/x")
        assert s == 200
        if b != b0 and "x-cache" not in h:
            got_fresh_inline = True
            break
        time.sleep(0.1)
    assert got_fresh_inline, \
        "bg-off winner should serve a freshly regenerated body inline"


def test_swr_refresh_injects_stored_validators(ng: Nginx,
                                               origin: Origin) -> None:
    """P1-4: a stale-while-revalidate background refresh must carry the
    entry's stored ETag/Last-Modified as If-None-Match/If-Modified-Since,
    instead of an unconditional GET every stale cycle -- the largest
    origin-offload lever in PLAN-optimize.md.

    /swrval/ (beta 5000) deterministically wins the refresh dice on the very
    first stale read; the origin's "vldecho" marker stamps a stable ETag on
    the PRIMING response and echoes back whatever If-None-Match it received
    on every hit, including the background refresh. The refreshed body (which
    the bg subrequest's capture overwrites the stale entry with) is later
    served as a HIT and its echoed inm=[...] is asserted against the ETag the
    prime itself received.
    """
    uri = "/swrval/vldecho-a"
    s0, b0, _ = fetch(ng.port, uri)                # prime: MISS, stores ETag
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    assert "inm=[none]" in b0, \
        f"prime itself should be unconditional (no prior entry): {b0!r}"

    time.sleep(1.3)                                 # past the 1s valid window

    # beta 5000 wins the dice on the first stale read; that request also
    # serves stale immediately, so poll a LATER hit for the refreshed body
    # instead of asserting on this one.
    s1, b1, h1 = fetch(ng.port, uri)
    assert s1 == 200 and h1.get("x-cache") == "STALE", \
        f"expected the dice-winning read itself to serve STALE, got {s1} " \
        f"x-cache={h1.get('x-cache')}: {b1!r}"
    assert b1 == b0, f"stale serve should be the ORIGINAL body: {b1!r} vs {b0!r}"

    deadline = time.monotonic() + 5.0
    refreshed_body = None
    while time.monotonic() < deadline:
        s, b, _h = fetch(ng.port, uri)
        assert s == 200
        if b != b0:
            refreshed_body = b
            break
        time.sleep(0.1)
    assert refreshed_body is not None, \
        "background refresh never landed a new generation within 5s"
    assert 'inm=[' + '"vldechoetag"' + ']' in refreshed_body, (
        "background-refresh subrequest did not carry the stored ETag as "
        f"If-None-Match: {refreshed_body!r}"
    )


def test_swr_refresh_no_validator_stays_unconditional(ng: Nginx,
                                                       origin: Origin) -> None:
    """P1-4 negative control: an entry stored WITHOUT an ETag and WITHOUT a
    Last-Modified (origin never emits either for a "vldechonone" path) must
    still produce an UNCONDITIONAL background refresh, exactly as before this
    change -- there is nothing to inject."""
    uri = "/swrvalnone/vldechonone-a"
    s0, b0, _ = fetch(ng.port, uri)                # prime: MISS, no validator
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    assert "inm=[none]" in b0 and "ims=[none]" in b0, \
        f"prime itself should be unconditional: {b0!r}"

    time.sleep(1.3)                                  # past the 1s valid window

    s1, b1, h1 = fetch(ng.port, uri)                 # wins the dice, serves stale
    assert s1 == 200 and h1.get("x-cache") == "STALE", \
        f"expected STALE serve, got {s1} x-cache={h1.get('x-cache')}: {b1!r}"

    deadline = time.monotonic() + 5.0
    refreshed_body = None
    while time.monotonic() < deadline:
        s, b, _h = fetch(ng.port, uri)
        assert s == 200
        if b != b0:
            refreshed_body = b
            break
        time.sleep(0.1)
    assert refreshed_body is not None, \
        "background refresh never landed a new generation within 5s"
    assert "inm=[none]" in refreshed_body and "ims=[none]" in refreshed_body, (
        "background refresh injected a validator for an entry that stored "
        f"neither: {refreshed_body!r}"
    )






def test_cold_single_flight(ng: Nginx, origin: Origin) -> None:
    """v10: a burst of first-hits on ONE virgin (never-cached) key collapses to a
    single origin fetch — the first request regenerates, the rest WAIT for the
    fill and then serve it, instead of every reader stampeding the origin."""
    uri = "/cold/sf"                               # never fetched before
    base = origin.hits
    waits0 = _admin_lock_waits(ng)

    # Rendezvous before the burst for the same reason as
    # test_l2_unserveable_giveup_still_single_flights: a reader that arrives
    # after the winner's fill lands takes the CLAIM_FRESH path and serves from
    # L1 without entering cold_wait(), so it never increments lock_waits. Left
    # unsynchronised, a staggered thread start can drive the delta to 0 while
    # the collapse itself was correct.
    readers = 40
    barrier = threading.Barrier(readers)

    def _burst_reader(_i: int) -> tuple[int, bytes, dict]:
        barrier.wait()
        return fetch(ng.port, uri)

    with concurrent.futures.ThreadPoolExecutor(max_workers=readers) as pool:
        results = list(pool.map(_burst_reader, range(readers)))
    assert {r[0] for r in results} == {200}, \
        f"cold burst returned {set(r[0] for r in results)}"
    # All readers must agree on one body (the single regenerated copy).
    bodies = {r[1] for r in results}
    assert len(bodies) == 1, f"cold burst served {len(bodies)} distinct bodies"
    regens = origin.hits - base
    assert regens <= 3, \
        f"cold single-flight failed: {regens} origin fetches for 40 readers"
    # The collapse must have happened via the wait path (not just lucky timing).
    assert _admin_lock_waits(ng) - waits0 > 0, \
        "no requests waited — single-flight did not engage"
    drain_origin(origin)


def test_cold_lock_off_stampedes(ng: Nginx, origin: Origin) -> None:
    """v10 gate: with cache_turbo_lock off, the same cold burst is NOT collapsed —
    far more than one reader reaches the origin (proves the lock is what coalesces,
    not some other serialisation)."""
    uri = "/coldoff/sf"
    base = origin.hits
    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
        results = list(pool.map(lambda _: fetch(ng.port, uri), range(40)))
    assert {r[0] for r in results} == {200}, \
        f"cold(off) burst returned {set(r[0] for r in results)}"
    regens = origin.hits - base
    assert regens > 3, \
        f"lock-off should stampede; only {regens} origin fetches for 40 readers"
    drain_origin(origin)


def test_store_failure_cleans_up_cold_stub(ng: Nginx, origin: Origin) -> None:
    """AUD-STORE-ERR-STUB: a failed store() must NOT leave ctx->cold_stored set,
    or the cold-miss winner's pool cleanup (armed only while !cold_stored) never
    runs and the stub it left behind blocks every waiter until lock_timeout.

    /storefail/ forces l1->store() to fail deterministically
    (cache_turbo_test_store_fail) on a virgin key. Request 1 is the cold-miss
    winner: its store fails, so with the bug (ctx->cold_stored set
    unconditionally) the winner's pool cleanup sees cold_stored=1, skips
    unstub(), and the stub is never reclaimed. Request 2 then finds that live
    stub and PARKS in cold_wait().

    The oracle is cache_turbo's own lock_waits counter, not wall-clock time.
    An earlier version of this test asserted `elapsed < 1.0` and passed against
    a deliberately reintroduced bug: with a short lock_ttl the leaked stub's
    lease is already expired by the time request 2 arrives, so claim() ADOPTS
    it (module.c:5942) instead of waiting, and the buggy build is just as fast
    as the fixed one. lock_waits increments at module.c:6003, on entry to
    cold_wait() -- exactly and only when a request parks on a stub that should
    not exist. lock_ttl is 30s here so the lease cannot expire out from under
    the assertion and turn a park into an adopt.

    /storefail/ binds its OWN zone (storefailz), not `main` -- `main` is
    shared by 166 other test locations, including test_cold_single_flight's
    40 deliberately-parking concurrent readers, and a straggler from that
    (or any other) test landing between this test's w0/w1 samples used to
    break the exact-equality assert on an unrelated build. Reading
    lock_waits off /_cache_storefail (storefailz's own admin endpoint)
    instead of /_cache (zone `main`) makes the delta observe only
    /storefail/'s own traffic, so the exact-equality assert is meaningful
    again.

    Fixed build: request 1's cleanup unstubs (store failed => cold_stored
    stays 0), request 2 claims a virgin key, lock_waits does not move.
    Buggy build: the stub survives with a live lease, request 2 parks,
    lock_waits increments."""
    uri = f"/storefail/stub-{time.time()}"

    w0 = _admin_lock_waits(ng, "/_cache_storefail")
    s1, b1, _ = fetch(ng.port, uri)
    assert s1 == 200 and b1, f"cold-miss winner (store forced to fail) failed: {s1}"

    # Settle barrier (S231, cycle 14 -- the THIRD distinct defect in this test;
    # PR #242's private-zone fix was the first).
    #
    # Request 1's leftover stub is removed by ngx_http_cache_turbo_cold_cleanup,
    # registered with ngx_pool_cleanup_add(r->pool, ...). An r->pool cleanup
    # runs at ngx_http_free_request(), which fires AFTER the response body has
    # already been written to the socket. So fetch() returning request 1's body
    # is NOT proof the stub is gone: firing request 2 immediately lands in the
    # window between "body on the wire" and "pool destroyed", finds the stub
    # still live, parks in cold_wait(), and moves lock_waits 0 -> 1 on a FIXED
    # build. That is a defect in this test's timing, not in the module.
    #
    # There is no stub-count or key-count field on the admin JSON (checked:
    # hits/misses/stale_serves/refreshes/evictions/l2_*/lock_waits/... carry no
    # per-key observable), so the barrier waits for the zone to go QUIESCENT
    # instead: two consecutive reads of storefailz's own counters that agree.
    # Request 1 is the only traffic this zone has seen, so once its accounting
    # has stopped moving, its request has been fully torn down -- which is
    # exactly the event that runs the pool cleanup.
    #
    # Why this cannot mask the bug: the barrier runs BEFORE request 2 is issued,
    # so it observes only request 1. On a buggy build the stub survives its
    # owner's teardown by design (that IS the bug), the counters still go
    # quiescent, request 2 still parks, and the assert below still fires. The
    # barrier polls the admin endpoint only -- it never touches /storefail/,
    # which would risk resolving the very stub under test with a third request.
    # The exact-equality assert below is unchanged.
    _settle: dict[str, tuple[int, int] | None] = {"prev": None}

    def _storefailz_quiescent() -> bool:
        cur = (_admin_lock_waits(ng, "/_cache_storefail"),
               _admin_stat(ng, "misses", "/_cache_storefail"))
        stable = (cur == _settle["prev"])
        _settle["prev"] = cur
        return stable

    assert wait_for(_storefailz_quiescent, timeout=5.0, interval=0.05), \
        "storefailz counters never went quiescent after request 1 -- the zone " \
        "saw traffic other than this test's, so the exact-equality oracle below " \
        "would be measuring someone else's park"

    s2, b2, _ = fetch(ng.port, uri)
    assert s2 == 200 and b2, f"second request after failed store got {s2}"
    w1 = _admin_lock_waits(ng, "/_cache_storefail")

    assert w1 == w0, (
        f"lock_waits moved {w0} -> {w1}: the second request parked in "
        "cold_wait() on the cold-miss stub left behind by the failed store "
        "(AUD-STORE-ERR-STUB: ctx->cold_stored was set even though store() "
        "returned NGX_ERROR, so the pool cleanup skipped unstub())")
    drain_origin(origin)


def _evblind_trip_breaker(ng: Nginx, origin: Origin) -> None:
    """Prime one /evblind/ key then trip its breaker OPEN, same two-fetch
    shape as /s71brk/ (test_breaker_counters): threshold=1, so the tripping
    fetch itself reaches the dead origin (must NOT be 200) and leaves the
    zone's breaker OPEN for every call after it. Callers run this ONCE per
    test on a freshly-relevant key; evblindz's breaker state persists for the
    rest of the suite once tripped, same as every other private-zone breaker
    fixture in this file.

    ⚠ The tripping key is "_trip_plain", deliberately NOT one of the
    "sieserve"-marked keys the rest of this test uses. Every /evblind/ key
    proxies through /sieserve/ upstream (so the eviction candidates are
    SIE-live), but a key WITH an armed serve-on-error window answers a dead
    origin with a 200 STALE-IF-ERROR replay instead of surfacing the error --
    that is RFC-2 working as designed (see test_sie_serve_on_error), not a
    breaker trip. Tripping needs the origin's raw failure to actually reach
    the response, so it must go through a key /sieserve/ has nothing to arm
    for. "_trip_plain" still lands on evblindz/the breaker under test; only
    its own SIE arming is what must not fire."""
    s0, b0, _ = fetch(ng.port, "/evblind/_trip_plain")
    assert s0 == 200 and b0, f"evblind prime failed: {s0} {b0!r}"

    time.sleep(1.3)   # past fresh (1s), stale_mult 1 -> 1s window: L1-expired
    origin.fail = True
    try:
        s_trip, _, _ = fetch(ng.port, "/evblind/_trip")
        assert s_trip != 200, (
            f"evblind: tripping request itself was answered 200 -- expected "
            f"it to reach the dead origin and fail, got {s_trip}")
    finally:
        origin.fail = False
        drain_origin(origin)

    state = _admin_str(ng, "breaker_state", "/_cache_evblind")
    assert state == "open", (
        f"evblind: breaker did not trip OPEN after the threshold=1 failure "
        f"(breaker_state={state!r})")


def test_evict_blind_second_chance(ng: Nginx, origin: Origin) -> None:
    """S231-EVICT-BLIND reachability smoke test.

    ⚠ SCOPE NOTE: the actual second-chance MECHANISM (spare-once,
    evict-on-the-next-pass, bounded by n_entries so it can never wedge) is
    proven at the C level by ci/tests/unit/test_shm_state.c's
    test_evict_blind_second_chance_unit() and its paired mutation control --
    that harness drives the real, sliced production evict_one() directly
    against a fabricated live-SIE node and a forced breaker_state word, which
    is the only way to observe "spared exactly once" at all (see below for
    why the black-box surface cannot).

    What THIS test covers instead: a virgin (never-cached) key behind an
    ALREADY-OPEN breaker with no armed snapshot legitimately 503s at the
    pre-origin gate (breaker_unavailable(), module.c ~6044) -- a store is
    never attempted for it, by design, regardless of second-chance. That
    means the black-box surface has NO reachable path that stores a brand
    new key while the breaker is OPEN, so a black-box fill-the-zone-while-
    OPEN test (this function's previous shape) was asserting against a
    scenario the request path cannot produce, and its "must always 200"
    loop failed with 503 on the very first fill key -- not a bug, a fixture
    that assumed an unreachable route. This test instead proves the
    REACHABLE half: entries stored while the breaker is CLOSED survive a
    later transition to OPEN and continue to serve normally (STALE-BREAKER
    fallback, no hang, no request-path regression) even once the zone has
    been filled past capacity and second-chance has been exercised for real
    by ordinary churn -- end-to-end evidence that wiring the feature in did
    not break the ordinary request path it shares evict_one() with."""
    tracked = "/evblind/sieserve/tracked"

    # Fill the (tiny, 64k) zone first, all while the breaker is still CLOSED
    # (the only state a virgin key can be stored in at all) -- this is what
    # exercises real eviction/second-chance churn under ordinary conditions.
    for i in range(120):
        s, _, _ = fetch(ng.port, f"/evblind/sieserve/fill1-{i}")
        assert s == 200, f"evblind: fill wave key {i} returned {s}"

    # Store the tracked key LAST, so it is the most-recently-used entry and
    # therefore still resident (not yet aged to the LRU tail) when the
    # breaker below trips OPEN.
    s, _, h = fetch(ng.port, tracked)
    assert s == 200, f"evblind: tracked-key store returned {s}"
    assert h.get("x-ct-status") == "MISS", (
        f"evblind: tracked-key initial store should MISS, got "
        f"{h.get('x-ct-status')}")

    _evblind_trip_breaker(ng, origin)

    # Re-fetching an already-cached key while OPEN must not hang or error --
    # this is the STALE-BREAKER fallback path (ACT_SERVE), which shares
    # evict_one()'s zone and mutex but never itself calls it (a HIT/STALE
    # serve replays existing bytes, no allocation). The assertion is
    # therefore reachability/no-regression, not a second-chance proof.
    s, _, h = fetch(ng.port, tracked)
    assert s == 200, (
        f"evblind: an already-cached key behind an OPEN breaker must still "
        f"be served (STALE-BREAKER fallback), got {s}")
    st = h.get("x-ct-status", "")
    assert st in ("HIT", "STALE"), (
        f"evblind: expected a cache-served status while OPEN, got {st!r}")


def test_evict_blind_negative_control_closed_breaker_evicts_normally(
        ng: Nginx) -> None:
    """S231-EVICT-BLIND negative control: with the breaker CLOSED (its
    default state -- this test runs standalone against evblindz and never
    trips it), a live-SIE-shaped entry gets NO second chance at all -- it is
    evicted on the very first pass, exactly like the pre-S231-EVICT-BLIND
    behaviour. This isolates that the spare is conditioned on breaker_open,
    not on "this key looks like it could carry an SIE window" alone -- a
    build that always spares a live-SIE candidate (breaker state ignored)
    would fail this control by keeping the tracked key resident.

    Deliberately evblindz (not /e/'s shared `tiny` 8m zone, which needs
    ~200 keys to force eviction and is shared with test_lru_eviction and
    test_p1_coarse_lru_splice_keeps_hot_key_resident -- a borderline fill
    count on an already-populated shared zone risks the control passing for
    the wrong reason). evblindz's own /evblind/sieserve/ location DOES carry
    a live stale-if-error window, so this control also proves the
    SIE-liveness half is insufficient alone: the entries here ARE live-SIE,
    and still get no spare, because the breaker was never tripped."""
    tracked = "/evblind/sieserve/control-tracked"

    s, _, h = fetch(ng.port, tracked)
    assert s == 200, f"control: tracked-key store returned {s}"

    for i in range(120):
        s, _, _ = fetch(ng.port, f"/evblind/sieserve/control-fill-{i}")
        assert s == 200, f"control: fill key {i} returned {s}"

    s, _, h = fetch(ng.port, tracked)
    st = h.get("x-ct-status", "")
    assert s == 200 and st == "MISS", (
        f"control: tracked key survived a single eviction pass under a "
        f"CLOSED breaker (status={st!r}, expected MISS) -- no second chance "
        "should apply here at all")


def _admin_l2_misses(ng: Nginx) -> int:
    import json
    _, b, _ = fetch(ng.port, "/_cache")
    return int(json.loads(b).get("l2_misses", 0))


def test_cross_node_winner_owner_token_preserved(ng: Nginx, origin: Origin,
                                                 redis: RedisServer) -> None:
    """AUD-NXLOCK-OWNER: the cross-node NX-lock resume path must hand
    cold_mark_winner() the SAME L1 owner token claim() issued before the park,
    not a literal 0.

    Mechanism: claim() at the top of the `if (clcf->lock)` block takes an L1
    lease (a stack local claim_owner, non-zero) before firing the cross-node
    Redis NX lock and parking (NGX_AGAIN). On resume (ctx->lock_done), the
    request is unconditionally a former CLAIM_WINNER -- an L1 lease WAS taken
    -- yet the pre-fix code passed a literal 0 to cold_mark_winner(), because
    the stack local does not survive the park/resume. shm_unstub() is a no-op
    when owner == 0 (ngx_http_cache_turbo_shm.c ~913), so a winner whose
    response turns out non-cacheable can never release its stub: the header
    filter's immediate unstub() (module.c ~7861) and the pool-cleanup backstop
    both pass owner=0 and both silently no-op, leaving the node `refreshing`
    with a lease nobody can ever match (CTXRDR-ADOPT-LEASE's owner identity
    check requires refresh_owner == owner, and 0 is rejected outright).

    Oracle: lock_waits (bumped only on ENTRY to cold_wait()), not wall clock.
    A leaked stub only delays a later request while the lease is still live;
    with a short lock_ttl the lease would simply expire and the next claim()
    would ADOPT the stub instead of parking, making a buggy build exactly as
    fast as a fixed one. /coldl2ns/ uses a 30s lock_ttl so that cannot happen
    inside this test's timeframe.

    Why the second probe is a SEPARATE, redis-less location and not a second
    /coldl2ns/ request: the cross-node Redis NX lock is deliberately never
    unlock()ed (module.c ~6015 -- unlocking early would re-open the fleet-wide
    dogpile window), so it stays SET for the full lock_ttl regardless of this
    bug. A second /coldl2ns/ request always parks on THAT lock, which would
    make lock_waits move on a fixed build too and give a vacuous test. The two
    locations share the `main` zone and a FIXED cache_turbo_key (not $uri), so
    they hash to the identical L1 node -- but /coldl2ns_probe/ has no L2
    backend configured, so its claim() can only ever see the shared L1 state
    and can never itself touch or park on Redis.

    /coldl2ns/ (cache_turbo_no_store $arg_private, lock default ON, L2-backed)
    makes the FIRST request for a virgin key a non-cacheable cross-node
    winner: it takes the L1 claim, fires+wins the uncontested NX lock, resumes
    with lock_result == NGX_OK, and its no_store response never reaches the
    body-filter store -- forcing the header-filter unstub() at ~7861 to be the
    ONLY thing that can release the L1 lease. A probe request against the SAME
    key on /coldl2ns_probe/ must then find the L1 stub already released
    (claim() sees `refreshing == 0` -> CLAIM_WINNER, straight to origin) and
    must NOT park in cold_wait(), because parking there is only reachable via
    CLAIM_LOSER, which requires the stub to still read `refreshing` -- exactly
    the leak this test targets."""
    key = "aud-nxlock-owner-probe"
    redis.cli("DEL", l2_key(key), lock_key(key))

    waits0 = _admin_lock_waits(ng)

    s1, _, h1 = fetch(ng.port, "/coldl2ns/owner?private=1")
    assert s1 == 200, f"cross-node winner status {s1}"
    assert "x-cache" not in h1, \
        f"no_store response must not be a HIT: {h1.get('x-cache')}"

    # The winner's own request must not have parked (it IS the winner).
    assert _admin_lock_waits(ng) - waits0 == 0, \
        (f"lock_waits moved by {_admin_lock_waits(ng) - waits0} on the winner's "
         "own request -- fixture defect, not the bug under test")

    # THE assertion. The probe location shares the L1 zone + key with the
    # winner above but has no L2 backend of its own, so it can only observe
    # -- never touch -- the shared L1 stub. If owner==0 leaked past unstub(),
    # the L1 node is still `refreshing` and this probe's claim() returns
    # CLAIM_LOSER, parking in cold_wait() and bumping lock_waits.
    s2, _, _ = fetch(ng.port, "/coldl2ns_probe/owner")
    assert s2 == 200, f"probe request status {s2}"
    assert _admin_lock_waits(ng) - waits0 == 0, \
        (f"lock_waits moved by {_admin_lock_waits(ng) - waits0}: the probe "
         "request for the same L1 key PARKED in cold_wait() instead of "
         "finding the L1 stub already released -- the cross-node resume path "
         "handed cold_mark_winner() owner=0 instead of the stashed L1 lease "
         "token (ctx->pending_l1_owner), so shm_unstub() no-opped and the "
         "lease leaked (AUD-NXLOCK-OWNER)")

    drain_origin(origin)


def test_l2_miss_counted_once_on_cold_park(ng: Nginx, origin: Origin) -> None:
    """metrics: a single cold miss on an L2-backed, lock-ON location parks TWICE
    (once on the async L2 GET, once on the v4-2 NX lock) and re-enters the access
    handler from the top on each resume. The l2_misses counter must rise by
    exactly 1 across the whole request, not once per re-entry — guarded by
    ctx->l2_miss_counted (issues.md 'l2_misses double-count on the cold path').
    /coldl2/ is L2-backed with cache_turbo_lock default ON, so a virgin key
    exercises both parks."""
    uri = "/coldl2/misscount"                      # virgin key, lock default ON
    misses0 = _admin_l2_misses(ng)
    s, _, h = fetch(ng.port, uri)
    assert s == 200, f"cold L2 fetch status {s}"
    assert "x-cache" not in h, \
        f"first cold fetch must reach origin, not HIT: {h.get('x-cache')}"
    delta = _admin_l2_misses(ng) - misses0
    assert delta == 1, \
        f"l2_misses rose by {delta}, expected exactly 1 (cold-path double-count)"
    drain_origin(origin)
