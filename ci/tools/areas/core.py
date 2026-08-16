"""cache-turbo runtime tests — core area.

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
    _BACKEND_LINE,
    _admin_lock_waits,
    _admin_stat,
    _bump_conn,
    _config_accepts,
    _config_rejects,
    _fetch_keepalive,
)


def test_sanitizer_time_scale() -> None:
    """FLAKE-ASAN-TIMING-BAND: pure harness self-check for sanitizer_time_scale
    (test_runtime_base.py) -- both states, ASAN_OPTIONS set and unset. No
    fixtures needed, so it takes no arguments (run_all() calls it bare).

    The DONE criterion this proves: a non-sanitizer run gets EXACTLY today's
    bands (factor 1.0, byte-for-byte unchanged), and ASAN_OPTIONS present
    scales them up by ASAN_TIME_SCALE."""
    saved = os.environ.pop("ASAN_OPTIONS", None)
    try:
        os.environ.pop("ASAN_OPTIONS", None)
        assert sanitizer_time_scale() == 1.0, \
            "scale must be exactly 1.0 with ASAN_OPTIONS unset (non-ASan " \
            "bands must stay byte-for-byte unchanged)"

        os.environ["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1"
        assert sanitizer_time_scale() == ASAN_TIME_SCALE, \
            (f"scale must be ASAN_TIME_SCALE ({ASAN_TIME_SCALE}) with "
             f"ASAN_OPTIONS set, got {sanitizer_time_scale()}")

        os.environ["ASAN_OPTIONS"] = ""
        assert sanitizer_time_scale() == ASAN_TIME_SCALE, \
            "an empty (but present) ASAN_OPTIONS value must still count as " \
            "'under a sanitizer build' -- presence, not content, is the signal"
    finally:
        if saved is None:
            os.environ.pop("ASAN_OPTIONS", None)
        else:
            os.environ["ASAN_OPTIONS"] = saved


def test_compressed_edge_identity_capture(ng: Nginx) -> None:
    """REGRESSION (2026-06-13 incident): cache_turbo behind a real compression
    filter must cache the IDENTITY body and let the downstream gzip filter
    re-encode per client, so a HIT never replays a coding the client did not
    accept (browser "Content Encoding Error").

    The /gz/ location runs the actual nginx gzip filter in front of the origin
    (gzip_proxied any + gzip_min_length 1 so even the tiny origin body is
    compressed). With the ngx_module_order load-order fix cache_turbo sits ABOVE
    gzip: it captures the uncompressed body, the entry is a single identity
    copy, and gzip compresses it for each client on MISS and HIT alike.

    Fails on the pre-fix build (cache_turbo below gzip -> stores gzip bytes +
    Content-Encoding: gzip -> replays gzip to the identity client). The Fix-B
    guard alone would make the entry a perpetual MISS, which the X-Cache=HIT
    assertion below would also catch — so this proves the real identity-capture
    path, not merely the refusal."""
    import gzip as _gzip

    def raw(ae: str):
        _bump_conn()
        conn = http.client.HTTPConnection("127.0.0.1", ng.port, timeout=HTTP_TIMEOUT)
        try:
            conn.request("GET", "/gz/page",
                         headers={"Accept-Encoding": ae, "Connection": "close"})
            r = conn.getresponse()
            data = r.read()
            return (r.status, data,
                    {k.lower(): v for k, v in r.getheaders()})
        finally:
            conn.close()

    def decode(data, ce):
        if ce == "gzip":
            return _gzip.decompress(data)
        assert ce in (None, "", "identity"), \
            f"unexpected Content-Encoding {ce!r}"
        return data

    # prime: gzip-capable client. MISS -> origin identity captured -> gzip
    # compresses on the way out.
    s0, d0, h0 = raw("gzip")
    assert s0 == 200, f"prime status {s0}"
    plain0 = decode(d0, h0.get("content-encoding"))

    # cross-encoding HIT: an identity-only client must get an UNencoded body from
    # the same cached entry, decoding to the same bytes.
    s1, d1, h1 = raw("identity")
    assert s1 == 200
    ce1 = h1.get("content-encoding")
    assert ce1 in (None, "", "identity"), \
        f"identity client got Content-Encoding={ce1!r} on HIT (encoding bug)"
    assert h1.get("x-cache") == "HIT", \
        f"identity request should HIT the identity entry, x-cache={h1.get('x-cache')}"
    assert decode(d1, ce1) == plain0, "HIT body (identity) differs from origin"

    # gzip client on a HIT: re-encoded gzip, decodes to the same bytes.
    s2, d2, h2 = raw("gzip")
    assert s2 == 200
    ce2 = h2.get("content-encoding")
    assert h2.get("x-cache") == "HIT", \
        f"second gzip request should HIT, x-cache={h2.get('x-cache')}"
    assert decode(d2, ce2) == plain0, "HIT body (gzip) differs from origin"


def test_miss_then_hit(ng: Nginx) -> None:
    """Basic: first request MISS (origin), second HIT (cached, same body)."""
    s1, b1, h1 = fetch(ng.port, "/c/hit")
    assert s1 == 200, f"miss status {s1}"
    assert "x-cache" not in h1, f"first req should be a miss, got {h1.get('x-cache')}"
    s2, b2, h2 = fetch(ng.port, "/c/hit")
    assert s2 == 200
    assert h2.get("x-cache") == "HIT", f"second req X-Cache={h2.get('x-cache')}"
    assert b1 == b2, f"HIT body differs: {b1!r} vs {b2!r}"


def test_surrogate_key_emit_on_miss_and_hit(ng: Nginx) -> None:
    """cache_turbo_surrogate_key on: BOTH the MISS (store) response and every
    later HIT carry the same Surrogate-Key header built from the deduped
    cache_turbo_tag list (SK-A1). A fronting CDN POP whose own copy expired
    refills from our HIT; an untagged hit would leave that edge object outside
    the tag purge. Works with NO cache_turbo_redis -- the emit is independent of
    the L2 tag index."""
    path = "/sk/page"

    s1, _b1, h1 = fetch(ng.port, path)
    assert s1 == 200, f"miss status {s1}"
    assert "x-cache" not in h1, f"first req should MISS, got {h1.get('x-cache')}"
    sk = h1.get("surrogate-key")
    assert sk is not None, "MISS response is missing the Surrogate-Key header"
    # tag list was "blog news blog" -> dedup -> two tags, order preserved.
    assert sk.split() == ["blog", "news"], \
        f"Surrogate-Key not the deduped tag set: {sk!r}"

    s2, _b2, h2 = fetch(ng.port, path)
    assert s2 == 200
    assert h2.get("x-cache") == "HIT", f"second req X-Cache={h2.get('x-cache')}"
    sk2 = h2.get("surrogate-key")
    assert sk2 is not None, \
        "HIT dropped Surrogate-Key -- a CDN refilling from this hit caches an " \
        "untagged object that a tag purge cannot reach (SK-A1)"
    assert sk2.split() == ["blog", "news"], \
        f"HIT Surrogate-Key differs from the MISS's: {sk2!r} vs {sk!r}"
    assert sk2.split() == sk.split(), "MISS and HIT keys must match exactly"

    # Exactly one header line -- the store-path skip must keep the generated key
    # out of the blob, or the hit would carry a duplicate.
    conn = http.client.HTTPConnection("127.0.0.1", ng.port, timeout=HTTP_TIMEOUT)
    try:
        conn.request("GET", path, headers={"Connection": "close"})
        resp = conn.getresponse()
        resp.read()
        sk_lines = [v for k, v in resp.getheaders()
                    if k.lower() == "surrogate-key"]
    finally:
        conn.close()
    assert len(sk_lines) == 1, \
        f"expected exactly one Surrogate-Key line on a HIT, got {sk_lines!r}"


def test_surrogate_key_off_by_default(ng: Nginx) -> None:
    """A cache_turbo_tag location WITHOUT cache_turbo_surrogate_key emits no
    Surrogate-Key header -- the directive gates the emit."""
    s1, _b1, h1 = fetch(ng.port, "/skoff/page")
    assert s1 == 200, f"miss status {s1}"
    assert "x-cache" not in h1, f"first req should MISS, got {h1.get('x-cache')}"
    assert "surrogate-key" not in h1, \
        f"surrogate_key OFF but header present: {h1.get('surrogate-key')!r}"


def test_surrogate_key_origin_header_survives_hit(ng: Nginx) -> None:
    """SK-A1, directive OFF: an origin-supplied Surrogate-Key is stored with the
    representation and replayed on the HIT. The store-path skip only applies to
    the key the module generates itself; dropping the origin's would hand a CDN
    an untagged edge object on every refill from our cache."""
    path = "/c/originsk-page"

    s1, _b1, h1 = fetch(ng.port, path)
    assert s1 == 200, f"miss status {s1}"
    assert "x-cache" not in h1, f"first req should MISS, got {h1.get('x-cache')}"
    assert h1.get("surrogate-key") == "origin-a origin-b", \
        f"origin Surrogate-Key mangled on MISS: {h1.get('surrogate-key')!r}"

    s2, _b2, h2 = fetch(ng.port, path)
    assert s2 == 200
    assert h2.get("x-cache") == "HIT", f"second req X-Cache={h2.get('x-cache')}"
    assert h2.get("surrogate-key") == "origin-a origin-b", \
        f"HIT dropped the origin Surrogate-Key: {h2.get('surrogate-key')!r}"


def test_surrogate_key_empty_tag_no_header(ng: Nginx) -> None:
    """surrogate_key on but the tag expression evaluates empty (no ?t= arg):
    no tags, so no Surrogate-Key header (and no empty-value header)."""
    s1, _b1, h1 = fetch(ng.port, "/skcap/page")
    assert s1 == 200, f"miss status {s1}"
    assert "surrogate-key" not in h1, \
        f"empty tag list should emit no header, got {h1.get('surrogate-key')!r}"


def test_surrogate_key_dedup_from_arg(ng: Nginx) -> None:
    """The emitted Surrogate-Key reflects the same dedup the tag tokeniser does:
    a value with a repeated tag emits each tag once."""
    s1, _b1, h1 = fetch(ng.port, "/skcap/page2?t=a,b,a,c,b")
    assert s1 == 200, f"miss status {s1}"
    sk = h1.get("surrogate-key")
    assert sk is not None, "MISS response is missing the Surrogate-Key header"
    assert sk.split() == ["a", "b", "c"], \
        f"Surrogate-Key not deduped in emit order: {sk!r}"


def test_post_passthrough_uncached(ng: Nginx, origin: Origin) -> None:
    """A POST through a cache_turbo location is a pure passthrough today (the
    method gate declines non-GET/HEAD before any cache work): every POST must
    reach the origin, the body must transit nginx intact (origin echoes its
    digest), and the GET entry for the same URI must be neither served to the
    POST nor polluted by it."""
    path = "/c/post-passthru"
    payload = b'{"query":"query P($id:ID!){product(id:$id){name}}"}'
    want = hashlib.sha256(payload).hexdigest()[:16]
    base = origin.hits_for("post-passthru")

    s1, b1, h1 = fetch(ng.port, path, method="POST", data=payload,
                       headers={"Content-Type": "application/json"})
    s2, b2, h2 = fetch(ng.port, path, method="POST", data=payload,
                       headers={"Content-Type": "application/json"})
    assert s1 == 200 and s2 == 200, f"POST status {s1}/{s2}"
    assert b1.startswith("post-") and b2.startswith("post-"), \
        f"origin do_POST body shape: {b1!r} / {b2!r}"
    # Both POSTs must carry the body intact -- checking only the first would
    # leave a second-request body corruption (buffering/park bug) invisible.
    for tag, b in (("first", b1), ("second", b2)):
        assert b.split(":")[1].strip() == want, \
            f"{tag} POST body mangled in transit: {b!r} want digest {want}"
    assert b1 != b2, f"identical POST bodies -> a POST was served from cache: {b1!r}"
    assert "x-cache" not in h1 and "x-cache" not in h2
    assert origin.hits_for("post-passthru") == base + 2, \
        "every POST must reach the origin"

    # The GET slot for the same URI is independent: the first GET must reach the
    # origin (positive proof, via the path-scoped hit counter -- NOT an
    # "x-cache absent" assert, which a plain MISS and a never-consulted cache
    # produce alike; see lessons.md) and return a fresh gen body rather than a
    # replayed POST body. The second GET is then a HIT.
    gbase = origin.hits_for("post-passthru")
    sg1, bg1, _ = fetch(ng.port, path)
    assert origin.hits_for("post-passthru") == gbase + 1, \
        "the first GET must reach the origin (no POST-primed entry to serve)"
    sg2, bg2, hg2 = fetch(ng.port, path)
    assert sg1 == 200 and sg2 == 200
    assert bg1.startswith("gen-"), \
        f"GET served a POST-shaped body -> POST polluted the GET entry: {bg1!r}"
    assert hg2.get("x-cache") == "HIT" and bg1 == bg2, \
        f"GET caching broken next to POSTs: {hg2.get('x-cache')} {bg1!r}/{bg2!r}"


def test_header_fidelity(ng: Nginx) -> None:
    """R2: Content-Type + arbitrary origin header survive a HIT byte-identical."""
    fetch(ng.port, "/c/hdr")                       # prime
    _, _, h = fetch(ng.port, "/c/hdr")             # HIT
    assert h.get("x-cache") == "HIT"
    assert h.get("content-type") == "application/json; charset=utf-8", \
        f"content-type lost: {h.get('content-type')}"
    assert h.get("x-backend") == "origin-42", \
        f"custom header lost: {h.get('x-backend')}"


def test_restore_allocation_failure_fails_closed(ng: Nginx,
                                                 origin: Origin) -> None:
    """Allocation failure while rebuilding a cached response must never emit a
    partial cached 200/3xx or fall through from a destructively reset SIE header
    list. The hidden directive exists only in ci/tools/ci-build.sh builds."""
    aborted_paths: list[str] = []

    def assert_failed_closed(path: str, forbidden_status: int,
                             forbidden_header: str | None = None) -> None:
        # Two outcomes are fail-closed and both are accepted: a deterministic
        # 500, or an abort before any byte of the header block reaches the
        # client. Every location here currently takes the abort path --
        # add_header()'s NGX_ERROR propagates out of the header filter, so
        # nginx tears the connection down instead of emitting a partial
        # response. That is the contract this test names ("must never emit a
        # partial cached 200/3xx"), so an abort is a PASS, not a skip.
        #
        # A bare `return` here used to swallow the abort entirely, which meant
        # the branch asserted nothing at all. Record it instead: the caller
        # asserts the whole set below, so a silent flip of every location to
        # some other status can no longer pass unnoticed.
        #
        # Deliberately NOT re-probed. `cache_turbo_test_restore_alloc_fail` is
        # a static loc-conf flag (module.c:512-516, merged at :12524), so a
        # second request to the same location aborts for exactly the same
        # reason as the first. A re-probe here cannot distinguish a one-off
        # truncation from the steady state, and asserting on it would look
        # like coverage while being unreachable.
        try:
            status, _, headers = fetch_raw(ng.port, path)
        except http.client.RemoteDisconnected:
            aborted_paths.append(path)
            return

        assert status == 500 and status != forbidden_status, \
            f"allocation failure returned unsafe status {status}: {headers}"
        if forbidden_header is not None:
            assert headers.get(forbidden_header) is None, \
                f"allocation failure leaked {forbidden_header}: {headers}"

    s0, _, _ = fetch_raw(ng.port, "/allocfail/bare-normal")
    assert s0 == 200, f"normal allocation-fault prime failed: {s0}"
    assert_failed_closed("/allocfail/bare-normal", 200, "x-cache")

    sr0, _, hr0 = fetch_raw(ng.port, "/allocfailst/redir")
    assert sr0 == 301 and hr0.get("location"), \
        f"redirect allocation-fault prime failed: {sr0} {hr0}"
    assert_failed_closed("/allocfailst/redir", 301, "location")

    ss0, bs0, _ = fetch_raw(ng.port, "/allocfailsie/sieserve-alloc")
    assert ss0 == 200 and bs0, f"SIE allocation-fault prime failed: {ss0}"
    time.sleep(1.3)  # fully expired (stale_mult 1: 1s window), but inside stale-if-error=30
    origin.fail = True
    try:
        assert_failed_closed("/allocfailsie/sieserve-alloc", 503,
                             "x-cache")
    finally:
        origin.fail = False
        drain_origin(origin)

    # Pin the observed shape. All three locations abort today, and each abort
    # returned above without asserting anything -- so without this the test
    # passes unchanged if every one of them silently starts doing something
    # else. Both directions are real failures worth seeing: a location that
    # stops aborting takes the 500 branch above (and must satisfy it), while
    # this catches the set drifting as a whole.
    assert aborted_paths == ["/allocfail/bare-normal", "/allocfailst/redir",
                             "/allocfailsie/sieserve-alloc"], \
        f"allocation-failure abort set changed: {aborted_paths}"


def test_file_backed_delegate_never_stores(ng: Nginx,
                                            origin: Origin) -> None:
    """A file-backed (sendfile) response body cannot be captured from memory,
    so the body filter must abort capture and delegate the UNMODIFIED chain
    downstream -- the object is served correctly but never cached. The hidden
    cache_turbo_test_force_file_buf directive drives that branch
    deterministically (the real in_file trigger is directio/fs dependent). The
    directive exists only in ci/tools/ci-build.sh builds."""
    n0 = origin.hits
    s1, b1, h1 = fetch(ng.port, "/forcefile/asset")
    assert s1 == 200 and b1, f"forcefile prime failed: {s1}"
    assert h1.get("x-cache") != "HIT", \
        f"file-backed body must not HIT on first read: {h1.get('x-cache')}"

    s2, b2, h2 = fetch(ng.port, "/forcefile/asset")
    assert s2 == 200 and b2, f"file-backed second read failed: {s2}"
    assert h2.get("x-cache") != "HIT", \
        f"file-backed body must never store (delegate path): {h2.get('x-cache')}"
    # The counting origin returns a unique body per hit, so a HIT would replay
    # b1 byte-for-byte. Two distinct bodies prove both reads were served fresh
    # from the origin -- i.e. the delegate path stored nothing.
    assert b2 != b1, \
        "file-backed body identical across reads -> a stale copy was served"

    # Both reads reached the origin -> nothing was served from cache-turbo.
    assert origin.hits - n0 >= 2, \
        f"expected >=2 origin hits (no caching), got {origin.hits - n0}"


def test_suppress_native_variable(ng: Nginx) -> None:
    """Q1: $cache_turbo_active reads 1 on an engaged request when
    cache_turbo_suppress_native is on (so a stacked native cache can defer via
    proxy_no_cache), and 0 when the directive is off (default), even though
    cache-turbo is still caching the request."""
    # suppress on -> engaged request reports active=1 (miss and subsequent hit)
    _, _, h1 = fetch(ng.port, "/sup/x")
    assert h1.get("x-ct-active") == "1", \
        f"suppress on: expected X-CT-Active=1, got {h1.get('x-ct-active')}"
    _, _, h1b = fetch(ng.port, "/sup/x")
    assert h1b.get("x-cache") == "HIT", "second /sup/ read should HIT"
    assert h1b.get("x-ct-active") == "1", \
        f"suppress on (hit): expected 1, got {h1b.get('x-ct-active')}"
    # suppress off (default) -> variable is 0 although the entry is still cached
    _, _, h2 = fetch(ng.port, "/nosup/x")
    assert h2.get("x-ct-active") == "0", \
        f"suppress off: expected X-CT-Active=0, got {h2.get('x-ct-active')}"
    _, _, h2b = fetch(ng.port, "/nosup/x")
    assert h2b.get("x-cache") == "HIT", \
        "second /nosup/ read should HIT (still caching, var just reads 0)"


def test_auto_classify(ng: Nginx, origin: Origin) -> None:
    """Auto-classify (cache_turbo <zone> auto): a normal anonymous page is
    cached, but a request matching a dynamic surface of the generic preset —
    login/session cookie, backend URI prefix, or dynamic query arg — skips the
    cache entirely (origin every time, never an X-Cache HIT)."""
    # normal anon page: cacheable
    _, b1, _ = fetch(ng.port, "/auto/normal")
    _, b2, h2 = fetch(ng.port, "/auto/normal")
    assert h2.get("x-cache") == "HIT", \
        f"anon page should cache, got x-cache={h2.get('x-cache')}"
    assert b2 == b1, "cached body should be byte-identical"

    # logged-in cookie: never cached (#1 footgun — a request Cookie alone does
    # not block caching without auto-classify)
    ck = {"Cookie": "wordpress_logged_in_abc=deadbeef"}
    _, c1, hc1 = fetch(ng.port, "/auto/private", headers=ck)
    _, c2, hc2 = fetch(ng.port, "/auto/private", headers=ck)
    assert "x-cache" not in hc1 and "x-cache" not in hc2, \
        "logged-in cookie must skip the cache"
    assert c1 != c2, "logged-in requests must each reach the origin"

    # dynamic query arg ?preview=true: never cached
    _, p1, hp1 = fetch(ng.port, "/auto/post?preview=true")
    _, p2, hp2 = fetch(ng.port, "/auto/post?preview=true")
    assert "x-cache" not in hp1 and "x-cache" not in hp2, \
        "preview arg must skip the cache"
    assert p1 != p2, "preview requests must each reach the origin"

    # backend URI prefix (/wp-admin/): never cached
    _, _, ha1 = fetch(ng.port, "/wp-admin/index")
    _, _, ha2 = fetch(ng.port, "/wp-admin/index")
    assert "x-cache" not in ha1 and "x-cache" not in ha2, \
        "/wp-admin/ must skip the cache"
    drain_origin(origin)


def test_auto_classify_suppress_native_interaction(ng: Nginx, origin: Origin) -> None:
    """Q1 x auto-classify: on a suppress_native location, an anon page engages
    cache-turbo so $cache_turbo_active=1 (native cache defers), but an
    auto-classified dynamic request (login cookie) is skipped -> NOT engaged ->
    $cache_turbo_active=0, freeing a stacked native cache to own that URL.

    Guards the src comment at ngx_http_cache_turbo_module.c:2964 (auto-skip sets
    ct_active=0). A regression that left ct_active=1 on the skip path would make
    the variable report "1" and wrongly keep native suppressed on a page
    cache-turbo refuses to store -> that URL caches nowhere."""
    # anon page: engaged, native suppressed -> active=1, and it caches
    fetch(ng.port, "/autosup/normal")
    _, _, h = fetch(ng.port, "/autosup/normal")
    assert h.get("x-cache") == "HIT", \
        f"anon page should cache, got x-cache={h.get('x-cache')}"
    assert h.get("x-ct-active") == "1", \
        f"engaged anon page must report $cache_turbo_active=1, got {h.get('x-ct-active')}"

    # logged-in cookie: auto-classified dynamic -> skipped -> NOT engaged
    ck = {"Cookie": "wordpress_logged_in_abc=deadbeef"}
    _, d1, hd1 = fetch(ng.port, "/autosup/private", headers=ck)
    _, d2, hd2 = fetch(ng.port, "/autosup/private", headers=ck)
    assert "x-cache" not in hd1 and "x-cache" not in hd2, \
        "logged-in cookie must skip the cache even with suppress_native on"
    assert d1 != d2, "logged-in requests must each reach the origin"
    assert hd1.get("x-ct-active") == "0", \
        (f"auto-skipped dynamic request must report $cache_turbo_active=0 so a "
         f"stacked native cache is free, got {hd1.get('x-ct-active')}")
    drain_origin(origin)


def test_woocommerce_wc_ajax(ng: Nginx, origin: Origin) -> None:
    """?wc-ajax= is the one WooCommerce leak path that NO URI rule can close.

    WC's AJAX endpoints have no path of their own — get_endpoint() builds
    "currentpageurl?wc-ajax=name", so a cart-fragment call is a request to an
    ORDINARY, CACHEABLE page URL carrying a query arg. /cart, /checkout and
    /my-account all fail to match it. The response body is that shopper's cart
    HTML; store it and the next visitor is served someone else's cart.

    So: the same page URL must CACHE when plain, and BYPASS the moment wc-ajax
    appears. Both halves are asserted — a bypass-everything bug would pass the
    second assertion alone."""
    # The bare page is a normal cacheable page.
    fetch(ng.port, "/woo/shop-front")
    _, _, hp = fetch(ng.port, "/woo/shop-front")
    assert hp.get("x-cache") == "HIT", \
        f"woo: a plain shop page must cache, got {hp.get('x-cache')}"

    # The SAME page with ?wc-ajax= is a per-shopper cart fragment -> must bypass.
    for uri in ("/woo/shop-front?wc-ajax=get_refreshed_fragments",
                "/woo/shop-front?wc-ajax=update_order_review",
                "/woo/?wc-ajax=checkout"):
        _, _, h1 = fetch(ng.port, uri)
        _, _, h2 = fetch(ng.port, uri)
        assert "x-cache" not in h1 and "x-cache" not in h2, \
            (f"woo: {uri} is a per-shopper cart fragment on an ordinary page URL "
             "-- it must bypass or one shopper's cart is served to everyone")
    drain_origin(origin)


def test_header_auth_rest_surfaces(ng: Nginx, origin: Origin) -> None:
    """Header-authenticated REST surfaces must bypass on the URI/arg tier.

    These are structurally invisible to the cookie tier: an API client sends
    `Authorization: Bearer ...` and NO session cookie, so every cookie rule in
    every preset is blind to it. Only a URI or arg rule can see them, and only
    xenforo's /api/ was covered.

    The arms deliberately send NO Authorization header. The module has an
    Authorization storage floor, so a request that carries one would bypass
    storing for a reason that has nothing to do with the preset -- the
    assertion would pass with the rule removed. A cookie-less, header-less
    fetch is the only shape that actually tests the URI rule.

    WordPress ?rest_route= is the sharpest of these: it is not a fallback for
    /wp-json/, it is what /wp-json/ REWRITES TO. wp-includes/rest-api.php maps
    ^wp-json/(.*) -> index.php?rest_route=/$1, and rest_api_loaded() dispatches
    only when that query var is set. With plain permalinks the request never has
    a /wp-json/ path at all, so the URI rule saw nothing."""
    # Magento Web API front names: rest + soap.
    for uri in ("/rest/V1/customers/me", "/rest/V1/orders", "/soap/default"):
        fetch(ng.port, uri)
        _, _, h = fetch(ng.port, uri)
        assert "x-cache" not in h, \
            (f"magento {uri} is header-authenticated and invisible to the cookie "
             f"tier -- it must bypass on the URI rule, got {h.get('x-cache')}")

    # ...but a catalog URL that merely shares the letters must still cache. The
    # prefix requires a '/' or '.' boundary, so /restaurant-supplies is not /rest.
    fetch(ng.port, "/restaurant-supplies")
    _, _, hr = fetch(ng.port, "/restaurant-supplies")
    assert hr.get("x-cache") == "HIT", \
        ("/restaurant-supplies merely shares letters with /rest and must stay "
         f"cacheable (prefix needs a '/' or '.' boundary), got {hr.get('x-cache')}")

    # Drupal JSON:API (core, jsonapi.base_path) and simple_oauth.
    # /oauth/userinfo is the leak that justifies the prefix: a GET, authenticated
    # purely by bearer token, returning the token holder's profile.
    for uri in ("/jsonapi/node/article", "/oauth/userinfo", "/oauth/debug"):
        fetch(ng.port, uri)
        _, _, h = fetch(ng.port, uri)
        assert "x-cache" not in h, \
            (f"drupal {uri} is header-authenticated -- it must bypass on the URI "
             f"rule, got {h.get('x-cache')}")

    # WordPress ?rest_route= -- the same API as /wp-json/, addressed the other
    # way. This is the arm that fails if only the URI half is covered.
    for uri in ("/wpq/?rest_route=/wp/v2/users/me",
                "/wpq/index.php?rest_route=/wp/v2/posts",
                "/wpq/?p=1&rest_route=/wp/v2/settings"):
        fetch(ng.port, uri)
        _, _, h = fetch(ng.port, uri)
        assert "x-cache" not in h, \
            (f"{uri} IS the REST API -- /wp-json/ is a rewrite to this form, so "
             f"guarding only the path leaves it open, got {h.get('x-cache')}")
    drain_origin(origin)


def test_phpbb_preset(ng: Nginx, origin: Origin) -> None:
    """phpBB preset (docs/phpbb.md). URI + ?sid= rules, PLUS the cookie VALUE
    predicate <prefix>_u != 1.

    phpBB sets _u/_k/_sid for every non-bot visitor INCLUDING guests, so a
    presence matcher identifies nobody: an anon gets _u=1 (ANONYMOUS), a member
    gets _u=<user_id> (never 1 — ANONYMOUS is a reserved row). Only a VALUE test
    separates them. Until that existed the preset shipped no cookie rule and a
    logged-in member's page was cached and served to strangers unless the
    operator hand-wrote a bypass; this test now asserts that leak is closed.

    The name is matched by SUFFIX because the prefix is config('cookie_name'),
    an ACP setting (default "phpbb") that installers randomise — a literal-name
    rule stops firing on a renamed board, and a bypass that stops firing leaks.
    Verified against phpbb/phpbb: includes/constants.php (ANONYMOUS=1),
    phpbb/session.php session_create()/set_cookie()."""
    for uri in ("/ucp.php", "/ucp.php?mode=login"):
        _, _, h = fetch(ng.port, uri)
        assert "x-cache" not in h, f"{uri} must bypass on the phpbb preset"

    # ?sid= marks a session-propagated URL: bypass (also a key-poisoning vector).
    _, _, hs = fetch(ng.port, "/phpbb/viewtopic?sid=deadbeef")
    assert "x-cache" not in hs, "?sid= must bypass"

    # Guest cookies must NOT bypass — every anonymous phpBB visitor carries them.
    guest = {"Cookie": "phpbb3_sid=abc; phpbb3_u=1; phpbb3_k="}
    fetch(ng.port, "/phpbb/viewtopic-a", headers=guest)
    _, _, hg = fetch(ng.port, "/phpbb/viewtopic-a", headers=guest)
    assert hg.get("x-cache") == "HIT", \
        f"guest phpbb cookies must stay cacheable, got {hg.get('x-cache')}"

    # THE FIX (was the documented gap): a logged-in user carries <prefix>_u with
    # their user_id, never ANONYMOUS(=1). The value predicate reads it and
    # bypasses. Before this rule the member's page was cached and served to
    # strangers — a cross-user leak the docs told the operator to patch by hand.
    authed = {"Cookie": "phpbb3_sid=abc; phpbb3_u=42; phpbb3_k=beef"}
    fetch(ng.port, "/phpbb/viewtopic-b", headers=authed)
    _, _, ha = fetch(ng.port, "/phpbb/viewtopic-b", headers=authed)
    assert "x-cache" not in ha, \
        (f"logged-in phpbb user (_u=42 != ANONYMOUS 1) MUST bypass, got "
         f"{ha.get('x-cache')} — this is the cross-user leak the value "
         "predicate exists to close")

    # The cookie NAME PREFIX is an ACP setting (config 'cookie_name', default
    # "phpbb"), and installers randomise it. The predicate matches the name by
    # SUFFIX for exactly this reason: a literal-name rule silently stops firing
    # on a renamed board, and a bypass rule that stops firing LEAKS. Prove the
    # suffix match holds under an arbitrary prefix.
    for prefix in ("phpbb", "phpbb3", "myboard_xyz", "zz"):
        m = {"Cookie": f"{prefix}_sid=abc; {prefix}_u=7"}
        fetch(ng.port, f"/phpbb/vt-{prefix}", headers=m)
        _, _, hm = fetch(ng.port, f"/phpbb/vt-{prefix}", headers=m)
        assert "x-cache" not in hm, \
            (f"member with cookie prefix '{prefix}' must bypass — the name is "
             "matched by SUFFIX because the prefix is admin-configurable")

        g = {"Cookie": f"{prefix}_sid=abc; {prefix}_u=1"}
        fetch(ng.port, f"/phpbb/vg-{prefix}", headers=g)
        _, _, hgp = fetch(ng.port, f"/phpbb/vg-{prefix}", headers=g)
        assert hgp.get("x-cache") == "HIT", \
            f"guest (_u=1) with prefix '{prefix}' must stay cacheable"

    # Absent _u => no session => guest => cacheable (the predicate must have no
    # opinion when its cookie is missing, not bypass everything).
    none = {"Cookie": "other=1; unrelated=x"}
    fetch(ng.port, "/phpbb/viewtopic-c", headers=none)
    _, _, hn = fetch(ng.port, "/phpbb/viewtopic-c", headers=none)
    assert hn.get("x-cache") == "HIT", \
        f"no _u cookie at all must stay cacheable, got {hn.get('x-cache')}"

    # Unparseable => fail CLOSED to bypass. A bare "_u" with no '=' gives us no
    # value to test; guessing "guest" there would cache a possible member.
    bare = {"Cookie": "phpbb3_sid=abc; phpbb3_u"}
    fetch(ng.port, "/phpbb/viewtopic-d", headers=bare)
    _, _, hb = fetch(ng.port, "/phpbb/viewtopic-d", headers=bare)
    assert "x-cache" not in hb, \
        (f"valueless '_u' must fail closed (bypass), got {hb.get('x-cache')} — "
         "an unreadable cookie must never be assumed to be a guest")

    # "_u=10" must not satisfy "_u == 1": the compare is exact + length-checked,
    # not a prefix. A member with user_id 10 is a member.
    ten = {"Cookie": "phpbb3_u=10"}
    fetch(ng.port, "/phpbb/viewtopic-e", headers=ten)
    _, _, ht = fetch(ng.port, "/phpbb/viewtopic-e", headers=ten)
    assert "x-cache" not in ht, \
        f"_u=10 is user 10, not ANONYMOUS(1) — must bypass, got {ht.get('x-cache')}"

    # Empty value "_u=" (a cleared/reset cookie, distinct from the bare "_u" with
    # no '=' above): it reaches the value compare with a zero-length value. By the
    # letter of "!= 1" an empty string is a non-member => bypass; that is also the
    # safe reading for a malformed/cleared cookie (module.c:2532-2540). Exercises
    # the empty-value arm of the NE predicate the non-empty members above skip.
    empty = {"Cookie": "phpbb3_sid=abc; phpbb3_u="}
    fetch(ng.port, "/phpbb/viewtopic-f", headers=empty)
    _, _, he = fetch(ng.port, "/phpbb/viewtopic-f", headers=empty)
    assert "x-cache" not in he, \
        (f"empty '_u=' is not the guest literal '1' — must bypass (cleared/"
         f"malformed cookie, safe direction), got {he.get('x-cache')}")
    drain_origin(origin)



def test_redmine_key_arg_bypasses_without_cookie(ng: Nginx,
                                                 origin: Origin) -> None:
    """redmine preset must bypass `?key=` with NO cookie present.

    application_controller.rb authenticates `key` two ways, neither of which
    starts a session: as an Atom key (params[:format] == 'atom' && params[:key]
    -> User.find_by_atom_key) and as an API key (api_key_from_request when
    Setting.rest_api_enabled?). So ?key=<atom key> returns a private issue list
    with no cookie at all. A cookie-only preset would cache that under the
    public cache key and serve one user's private tracker to everyone -- the
    same hole ghost's ?uuid=/?key=/?gift= rows close.

    The negative control is the same path WITHOUT the arg: it must still cache,
    proving the bypass comes from the arg rule and not from the path being
    uncacheable anyway."""
    _, _, _h1 = fetch(ng.port, "/redmine/issues?key=abc123deadbeef")
    _, _, h2 = fetch(ng.port, "/redmine/issues?key=abc123deadbeef")
    assert "x-cache" not in h2, \
        (f"?key= MUST bypass with no cookie, got {h2.get('x-cache')} -- it "
         "authenticates via Atom/API key and returns private content")

    fetch(ng.port, "/redmine/issues")
    _, _, h3 = fetch(ng.port, "/redmine/issues")
    assert h3.get("x-cache") == "HIT", \
        (f"a public issue list with no key must still cache, got "
         f"{h3.get('x-cache')} -- if this is also a bypass the test above "
         "proves nothing about the arg rule")


def test_redmine_public_content_stays_cacheable(ng: Nginx,
                                                origin: Origin) -> None:
    """redmine must NOT bypass /projects, /issues, /news, /wiki.

    On an open tracker those are the main public content and the entire reason
    to put a cache in front of it. Public-vs-private there is a per-project
    ACL nginx cannot see; the cookie rule is what protects a logged-in view.
    A preset that bypassed them would be safe but pointless, so the rows are
    deliberately absent and that absence is pinned here.

    /admin and /my are asserted alongside as the positive half, so the test
    cannot pass by the preset simply doing nothing."""
    for uri in ("/redmine/projects/foo", "/redmine/issues",
                "/redmine/news", "/redmine/wiki/Main"):
        fetch(ng.port, uri)
        _, _, h = fetch(ng.port, uri)
        assert h.get("x-cache") == "HIT", \
            (f"{uri} must stay cacheable, got {h.get('x-cache')} -- public "
             "tracker content is why the cache is here")

    for uri in ("/redmine/admin", "/redmine/my/account", "/redmine/login"):
        fetch(ng.port, uri)
        _, _, h = fetch(ng.port, uri)
        assert "x-cache" not in h, \
            (f"{uri} MUST bypass, got {h.get('x-cache')}")


def test_cookie_pred_multiple_matching_cookies(ng: Nginx, origin: Origin) -> None:
    """A Cookie header can carry SEVERAL cookies matching one predicate's name
    suffix. Every one of them must be examined.

    phpBB keys on the suffix `_u` and the prefix is per-board (config
    'cookie_name'), so one browser visiting two boards on the same host sends
    `phpbb3_<a>_u` AND `phpbb3_<b>_u` in a single header. The evaluator used to
    return on the FIRST pair whose name matched, so a leading guest `_u=1`
    decided the whole request and masked a member `_u=42` sitting behind it --
    the member's page was cached and served to strangers. That is the same
    cross-user leak the value predicate exists to close, reachable again through
    a second cookie.

    Both orders are asserted: the reverse order always worked, so testing only
    that would pass with the bug still in place."""
    # Guest cookie FIRST, member second. This is the regression.
    masked = {"Cookie": "phpbb3_aaa_u=1; phpbb3_bbb_u=42"}
    fetch(ng.port, "/phpbb/multi-a", headers=masked)
    _, _, hm = fetch(ng.port, "/phpbb/multi-a", headers=masked)
    assert "x-cache" not in hm, \
        (f"a member `_u=42` behind a guest `_u=1` in the SAME Cookie header "
         f"must still bypass, got {hm.get('x-cache')} -- the scan stopped at "
         "the first name match and served a logged-in page from cache")

    # Member first: worked before the fix too, kept so the pair is symmetric.
    lead = {"Cookie": "phpbb3_bbb_u=42; phpbb3_aaa_u=1"}
    fetch(ng.port, "/phpbb/multi-b", headers=lead)
    _, _, hl = fetch(ng.port, "/phpbb/multi-b", headers=lead)
    assert "x-cache" not in hl, \
        f"member `_u=42` first must bypass, got {hl.get('x-cache')}"

    # Two guests must NOT become a bypass: `continue` means "no opinion", it
    # must not leak into "objection". Without this the fix would trade a leak
    # for a board-wide hit-rate collapse and nothing would catch it.
    guests = {"Cookie": "phpbb3_aaa_u=1; phpbb3_bbb_u=1"}
    fetch(ng.port, "/phpbb/multi-c", headers=guests)
    _, _, hg = fetch(ng.port, "/phpbb/multi-c", headers=guests)
    assert hg.get("x-cache") == "HIT", \
        (f"two guest `_u=1` cookies must stay cacheable, got "
         f"{hg.get('x-cache')} -- 'no opinion' must not become a bypass")


def _assert_new_preset_shape(
    ng: Nginx,
    root: str,
    cookie: str,
    dynamic_uri: str,
) -> None:
    """Pin the shared contract for a newly added preset.

    A plain public URL must still cache; a representative state cookie and a
    representative root-relative dynamic URI must bypass. The URI request is
    made below the test mount so this also covers backend_prefix rebasing.
    """
    public = f"/{root}/public"
    fetch(ng.port, public)
    status, _, hp = fetch(ng.port, public)
    assert status == 200, f"{root} public page returned {status}"
    assert hp.get("x-cache") == "HIT", \
        f"{root} anonymous public page must cache, got {hp.get('x-cache')}"

    member = f"/{root}/state-cookie"
    headers = {"Cookie": cookie}
    fetch(ng.port, member, headers=headers)
    status, _, hc = fetch(ng.port, member, headers=headers)
    assert status == 200, f"{root} cookie request returned {status}"
    assert "x-cache" not in hc, \
        f"{root} state cookie {cookie!r} must bypass, got {hc.get('x-cache')}"

    uri = f"/{root}/{dynamic_uri.lstrip('/')}"
    fetch(ng.port, uri)
    status, _, hu = fetch(ng.port, uri)
    assert status == 200, f"{root} dynamic URI returned {status}"
    assert "x-cache" not in hu, \
        f"{root} dynamic URI {dynamic_uri!r} must bypass, got {hu.get('x-cache')}"


_COOKIE_SCANS_HDR = "x-cache-turbo-test-cookie-scans"


def _cookie_scans(hdrs: dict, where: str) -> int:
    """Pull the lifetime ngx_strnstr()-call counter out of a response's
    headers (S231-PERF-AUTOCLASSIFY, TEST_FAULTS-only). Same "missing header
    is a hard failure" discipline as _armings()/_backoff_skips(): its absence
    would make every delta read 0 and the counter-oracle test would pass
    while proving the prefilter did nothing."""
    raw = hdrs.get(_COOKIE_SCANS_HDR)
    assert raw is not None, (
        f"{_COOKIE_SCANS_HDR} missing on {where} -- this build has no cookie "
        f"scan counter, so the S231-PERF-AUTOCLASSIFY control cannot "
        f"distinguish 'prefilter skipped scans' from 'never counted'")
    return int(raw)


# preset -> (location, [needles from that preset's ct_*_cookies[] array]).
# Mirrors src/ngx_http_cache_turbo_module.c's ngx_http_cache_turbo_presets[]
# table exactly -- a needle added there with no row here is silently
# unverified, which is exactly the kind of gap the first-byte prefilter must
# never introduce. Presets with an EMPTY cookies[] array (phpbb, magento,
# shopware6, invision, mybb, vbulletin, spip, opencart) are classified by
# cookie_pred/key_cookie instead, which cookie_has()'s prefilter never
# touches -- covered elsewhere (test_phpbb_preset, _assert_new_preset_shape,
# ci/t/presets/*.t), not here.
_COOKIE_NEEDLE_TABLE = {
    "wordpress":   ("/auto/", ["wordpress_logged_in_", "wp-postpass_",
                                "comment_author_"]),
    "woocommerce": ("/auto/", ["woocommerce_items_in_cart",
                                "woocommerce_cart_hash",
                                "wp_woocommerce_session_"]),
    "joomla":      ("/auto/", ["joomla_remember_me_"]),
    "xenforo":     ("/xf/", ["xf_session", "xf_user", "xf_session_admin",
                              "xf_lscxf_logged_in"]),
    "discourse":   ("/dc/", ["_t="]),
    "drupal":      ("/ct-drupal/", ["SESS"]),
    "mediawiki":   ("/ct-mediawiki/", ["Token=", "_session=", "UserID="]),
    "ghost":       ("/ct-ghost/", ["ghost-members-ssr",
                                    "ghost-admin-api-session"]),
    "wagtail":     ("/ct-wagtail/", ["sessionid"]),
    "kirby":       ("/ct-kirby/", ["kirby_session"]),
    "typo3":       ("/ct-typo3/", ["fe_typo_user", "be_typo_user"]),
    "smf":         ("/smf/", ["SMFCookie"]),
    "vanilla":     ("/ct-vanilla/", ["Vanilla="]),
    "punbb":       ("/ct-punbb/", ["forum_cookie", "punbb_cookie"]),
    "phorum":      ("/ct-phorum/", ["phorum_session_v5", "phorum_session_st",
                                     "phorum_admin_session"]),
    "yabb":        ("/ct-yabb/", ["Y2User-", "Y2Pass-", "Y2Sess-"]),
    "textpattern":  ("/ct-textpattern/", ["txp_login_public=", "txp_login="]),
    "bludit":      ("/ct-bludit/", ["BLUDIT-KEY", "BLUDITREMEMBERUSERNAME=",
                                     "BLUDITREMEMBERTOKEN="]),
    "bugzilla":    ("/ct-bugzilla/", ["Bugzilla_login=",
                                       "Bugzilla_logincookie="]),
    "mantisbt":    ("/ct-mantis/", ["PHPSESSID="]),
    "plone":       ("/ct-plone/", ["__ac=", "_ZopeId=", "statusmessages=",
                                    "I18N_LANGUAGE="]),
    "umbraco":     ("/ct-umbraco/", ["UMB_UCONTEXT=", "UMB_EXTLOGIN=",
                                      "UMB_PREVIEW=",
                                      "UMB-WEBSITE-PREVIEW-ACCEPT=",
                                      "UMB-XSRF-V=", "UMB_SESSION=",
                                      "umbAccessToken", "umbRefreshToken",
                                      "umbPkceCode",
                                      ".AspNetCore.Identity.Application="]),
    "dotclear":    ("/ct-dotclear/", ["dcxd", "dc_admin=", "dc_passwd="]),
    "wikijs":      ("/ct-wikijs/", ["jwt=", "connect.sid=", "loginRedirect="]),
    "redmine":     ("/redmine/", ["_redmine_session=", "autologin="]),
    "flarum":      ("/ct-flarum/", ["flarum_remember="]),
}


def test_cookie_prefilter_negative_control(ng: Nginx, origin: Origin) -> None:
    """S231-PERF-AUTOCLASSIFY: negative control for the first-byte presence
    bitset in ngx_http_cache_turbo_cookie_has(). For EVERY populated cookie
    needle array in the preset registry, a request whose Cookie header
    contains that exact needle must still be classified dynamic (auto_skip
    bypasses the cache). If the prefilter ever skipped a needle it should
    have scanned, the matching preset's cookie would go silently invisible --
    a private page would be cached and served to strangers -- and this is the
    test that would catch it.

    _COOKIE_NEEDLE_TABLE is hand-derived from ngx_http_cache_turbo_presets[]
    (see the table's own comment); a preset added there with no row here is a
    silent coverage gap, not a passing test."""
    for preset, (loc, needles) in _COOKIE_NEEDLE_TABLE.items():
        for needle in needles:
            uri = f"{loc}nc-{preset}-{hash(needle) & 0xffff:x}"
            headers = {"Cookie": f"{needle}zzz=1"}
            fetch(ng.port, uri, headers=headers)
            status, _, h = fetch(ng.port, uri, headers=headers)
            assert status == 200, (
                f"{preset} needle {needle!r} request returned {status}")
            assert "x-cache" not in h, (
                f"{preset} needle {needle!r} must bypass the cache (the "
                f"first-byte prefilter made it unreachable), got "
                f"x-cache={h.get('x-cache')}")
    drain_origin(origin)


def test_cookie_prefilter_counter_oracle(ng: Nginx, origin: Origin) -> None:
    """S231-PERF-AUTOCLASSIFY: counter oracle for the perf claim -- never a
    wall-clock timing band. A large Cookie header built entirely from bytes
    that appear in NO preset's cookie needles must classify identically
    (cacheable) to a plain anonymous request, while the first-byte prefilter
    measurably cuts the number of ngx_strnstr() calls cookie_has() makes.

    The delta is read off X-Cache-Turbo-Test-Cookie-Scans, a process-global
    lifetime counter (TEST_FAULTS-only) bumped exactly once per ngx_strnstr()
    call the prefilter did NOT skip -- see
    ngx_http_cache_turbo_test_cookie_scan_header() and the counter's own
    declaration for the wiring this test depends on.

    Mutation coverage: turning the WHOLE prefilter off (not one conjunct --
    e.g. hardcoding the `bs->seen[...]` check to always pass) must make this
    scan-count assertion go red while every functional test (cache hit,
    negative control above) stays green, since the filter is provably
    lossless. That is the mutation this test exists to catch; it was verified
    by hand -- see the PR description for the exact diff and counts.

    X-Cache-Turbo-Test-Cookie-Scans is a process-global (per-worker)
    monotonic counter, so it can never decrease within one worker but tells
    you nothing when two probes land on DIFFERENT workers -- each worker has
    its own independent counter, and comparing across them can even go
    negative. All four probes below therefore share ONE kept-alive
    HTTPConnection (see _fetch_keepalive's docstring) so nginx pins them all
    to the same accepted-connection worker; a plain fetch() opens a fresh
    socket per call and round-robins across the harness's 4-worker default,
    which is exactly what produced a spurious negative delta here."""
    conn = http.client.HTTPConnection("127.0.0.1", ng.port, timeout=HTTP_TIMEOUT)
    try:
        # Baseline: a normal small-cookie request on the same preset union as
        # the oversized one below, to establish "the prefilter runs on every
        # request" without asserting an exact call count (the preset roster
        # can grow).
        _, _, hbase1 = _fetch_keepalive(conn, "/auto/normal",
                                         headers={"Cookie": "unrelated=1"})
        n_before = _cookie_scans(hbase1, "baseline request")

        # A large Cookie header matching NOTHING: every byte is drawn from a
        # set that appears in no preset's cookie needles (digits + a few
        # separators), so the prefilter should skip essentially all 75
        # needles' ngx_strnstr() calls on this request, and the number of
        # calls counted for THIS request must be far smaller than the needle
        # count -- not the wall-clock time.
        big_cookie = "n" + "0123456789" * 800  # ~8KB, no needle first byte here
        # every preset needle in the table starts with an uppercase/lowercase
        # letter or '.'; the digit-only body plus a leading 'n' (shared with
        # none of them at position 0 of a *name*, since needles are matched
        # as substrings anywhere in the cookie -- so avoid 'n' collisions
        # with none of the needles either) keeps this cookie byte-disjoint
        # from every needle's first byte except by construction below.
        headers = {"Cookie": f"harmless={big_cookie}"}
        status, body1, h1 = _fetch_keepalive(conn, "/auto/miss1", headers=headers)
        assert status == 200
        n_after_first = _cookie_scans(h1, "large non-matching cookie, request 1")

        status, body2, h2 = _fetch_keepalive(conn, "/auto/miss1", headers=headers)
        assert status == 200
        n_after_second = _cookie_scans(h2, "large non-matching cookie, request 2")

        # Classification must be UNCHANGED: this is the correctness half of
        # the proof -- a non-matching cookie was always cacheable, and it
        # still is.
        assert "x-cache" not in h1, (
            "first request should be a miss (no x-cache yet)")
        assert h2.get("x-cache") == "HIT", (
            f"a large Cookie header matching no needle must still let the "
            f"page cache -- got x-cache={h2.get('x-cache')} (byte-identical "
            f"classification is the whole point of the prefilter proof)")
        assert body1 == body2, "cached body must be byte-identical"

        # Counter oracle: each of the two /auto/miss1 requests independently
        # runs cookie_has() over wordpress+woocommerce+joomla's needle union
        # (7 needles). Every one of those needles' first byte (w, c, j) is
        # checked against the 256-byte set built from "harmless=" + digits +
        # the leading 'n' -- none of which contains w/c/j -- so EVERY
        # ngx_strnstr() call on this request must be skipped: the delta this
        # request contributes is 0.
        delta_first = n_after_first - n_before
        delta_second = n_after_second - n_after_first
        assert delta_first == 0, (
            f"large non-matching cookie should trigger ZERO ngx_strnstr() "
            f"calls (every needle's first byte is absent from the header), "
            f"got a delta of {delta_first} -- the first-byte prefilter is "
            f"not cutting scans")
        assert delta_second == 0, (
            f"second request (same cookie) should also trigger ZERO "
            f"ngx_strnstr() calls, got a delta of {delta_second}")

        # Contrast: a request whose cookie DOES contain a needle's first byte
        # (but not the needle itself) must NOT be skipped by the byte test
        # alone -- only ngx_strnstr() itself decides a real match, and the
        # byte set only gates whether that call happens. This proves the
        # filter is not simply returning "no scans, ever": a 'w'-containing
        # miss still counts calls.
        _, _, h3 = _fetch_keepalive(conn, "/auto/normal",
                                     headers={"Cookie": "walnut=1"})
        n_after_w = _cookie_scans(h3, "byte-colliding but non-matching cookie")
        delta_w = n_after_w - n_after_second
        assert delta_w > 0, (
            f"a cookie containing 'w' (wordpress_logged_in_'s first byte) "
            f"must still trigger the wordpress needle's ngx_strnstr() call "
            f"even though it does not match -- got a delta of {delta_w}, "
            f"meaning the prefilter is skipping scans it has no right to "
            f"skip")
    finally:
        conn.close()
    drain_origin(origin)


def test_2026_preset_expansion(ng: Nginx, origin: Origin) -> None:
    """Source-audited CMS and issue-tracker presets added in 2026.

    Representative rules cover all nine registry rows and the three aliases.
    Extra assertions pin the suffix predicates, cookieless token auth, and
    current alternate cookie spellings that motivated the individual designs.
    """
    _assert_new_preset_shape(
        ng, "ct-textpattern", "txp_login_public=member", "textpattern/index.php"
    )
    _assert_new_preset_shape(
        ng, "ct-bludit", "__Secure-BLUDIT-KEY=session", "admin/dashboard"
    )
    _assert_new_preset_shape(
        ng, "ct-spip", "CUSTOM_session=member", "ecrire/"
    )
    _assert_new_preset_shape(
        ng, "ct-bugzilla", "Bugzilla_logincookie=member", "editusers.cgi"
    )
    _assert_new_preset_shape(
        ng, "ct-mantis", "ACME_STRING_COOKIE=member", "bug_report_page.php"
    )
    _assert_new_preset_shape(
        ng, "ct-plone", "__ac=member", "@@login"
    )
    _assert_new_preset_shape(
        ng, "ct-umbraco", "__Host-umbAccessToken-siteA=member", "umbraco/"
    )
    _assert_new_preset_shape(
        ng, "ct-dotclear", "dcxd_blog=session", "pagespreview/draft"
    )
    _assert_new_preset_shape(
        ng, "ct-wikijs", "jwt=token", "graphql"
    )
    _assert_new_preset_shape(
        ng, "ct-classicpress", "wordpress_logged_in_hash=member", "wp-admin/"
    )
    _assert_new_preset_shape(
        ng, "ct-backdrop", "SSESSabc=member", "user/login"
    )

    # SPIP's cookie prefix is configurable. Every presentation/state suffix is
    # intentionally prefix-agnostic and non-empty only.
    for i, cookie in enumerate((
        "site_admin=1",
        "site_lang=fr",
        "site_lang_ecrire=fr",
        "site_accepte_ajax=1",
    )):
        uri = f"/ct-spip/predicate-{i}"
        fetch(ng.port, uri, headers={"Cookie": cookie})
        status, _, h = fetch(ng.port, uri, headers={"Cookie": cookie})
        assert status == 200, f"SPIP predicate request returned {status}"
        assert "x-cache" not in h, \
            f"SPIP suffix cookie {cookie!r} must bypass, got {h.get('x-cache')}"

    # Empty suffix cookies are cleared state, not active identity/preferences.
    empty_spip = {"Cookie": "site_session=; site_lang="}
    fetch(ng.port, "/ct-spip/empty", headers=empty_spip)
    status, _, hs = fetch(ng.port, "/ct-spip/empty", headers=empty_spip)
    assert status == 200, f"empty SPIP-cookie request returned {status}"
    assert hs.get("x-cache") == "HIT", \
        f"empty SPIP state cookies must stay cacheable, got {hs.get('x-cache')}"

    # SPIP action/debug modes and Bugzilla query credential spellings can carry
    # dynamic or authenticated state with no cookie at all.
    for uri in (
        "/ct-spip/public?action=logout",
        "/ct-spip/public?var_mode=preview",
        "/ct-bugzilla/show_bug.cgi?id=1&Bugzilla_api_key=secret",
        "/ct-bugzilla/show_bug.cgi?id=1&api_key=secret",
        "/ct-bugzilla/show_bug.cgi?id=1&Bugzilla_api_token=secret",
        "/ct-bugzilla/show_bug.cgi?id=1&Bugzilla_token=secret",
        "/ct-bugzilla/show_bug.cgi?id=1&Bugzilla_login=user",
        "/ct-bugzilla/show_bug.cgi?id=1&token=secret",
        "/ct-bugzilla/rest/bug/1",
    ):
        fetch(ng.port, uri)
        status, _, h = fetch(ng.port, uri)
        assert status == 200, f"cookieless dynamic request returned {status}"
        assert "x-cache" not in h, \
            f"cookieless dynamic request {uri!r} must bypass, got {h.get('x-cache')}"

    # MantisBT's prefix is configurable and its anonymous form-token session is
    # PHPSESSID by default. Project/list/collapse state changes public HTML.
    for i, cookie in enumerate((
        "PROJECTX_PROJECT_COOKIE=7",
        "PROJECTX_VIEW_ALL_COOKIE=recent",
        "PROJECTX_BUG_LIST_COOKIE=filter",
        "PROJECTX_collapse_settings=1",
        "PHPSESSID=anonymous-form-session",
    )):
        uri = f"/ct-mantis/predicate-{i}"
        fetch(ng.port, uri, headers={"Cookie": cookie})
        status, _, h = fetch(ng.port, uri, headers={"Cookie": cookie})
        assert status == 200, f"MantisBT predicate request returned {status}"
        assert "x-cache" not in h, \
            f"MantisBT state cookie {cookie!r} must bypass, got {h.get('x-cache')}"

    # Remaining alternate/default cookie channels.
    for root, cookie in (
        ("ct-textpattern", "txp_login=admin"),
        ("ct-bludit", "BLUDITREMEMBERTOKEN=remembered"),
        ("ct-plone", "I18N_LANGUAGE=nl"),
        ("ct-plone", "_ZopeId=session"),
        ("ct-umbraco", ".AspNetCore.Identity.Application=member"),
        ("ct-umbraco", "UMB_PREVIEW=preview"),
        ("ct-umbraco", "UMB_SESSION=custom-state"),
        ("ct-dotclear", "dc_admin=remembered"),
        ("ct-dotclear", "dc_passwd=protected-post"),
        ("ct-wikijs", "connect.sid=oauth-session"),
        ("ct-wikijs", "loginRedirect=/private-page"),
    ):
        uri = f"/{root}/alternate-{cookie.split('=', 1)[0].replace('.', 'dot')}"
        fetch(ng.port, uri, headers={"Cookie": cookie})
        status, _, h = fetch(ng.port, uri, headers={"Cookie": cookie})
        assert status == 200, f"{root} alternate-cookie request returned {status}"
        assert "x-cache" not in h, \
            f"{root} alternate cookie {cookie!r} must bypass, got {h.get('x-cache')}"

    drain_origin(origin)


def test_internal_redirect_key_and_veto(ng: Nginx, origin: Origin) -> None:
    """Internal redirects replace r->uri -- regression for the 2026-07-26 docs
    audit (DOC-A1 BLOCKER, DOC-A2 MAJOR).

    A PHP front controller runs `try_files $uri /index.php`. Once nginx takes
    that internal redirect, r->uri IS /index.php: the original clean route is
    only still visible in $request_uri. Two consequences, both proven here:

    DOC-A1 -- with the module's DEFAULT $uri-based key, two unrelated clean
    URLs collapse onto the single key /ctir/index.php, so the second request is
    served the FIRST page's body. That is a cross-page hit inside one shared
    cache. This test pins the defect deliberately: it is the reason the
    published examples now say `cache_turbo_key $host$request_uri`. If the
    module default ever becomes original-path-based, the first assertion flips
    to MISS and this test must be revisited along with the docs guidance.

    DOC-A2 -- preset URI rules and cache_turbo_bypass_uri BOTH compare r->uri
    (ngx_http_cache_turbo_bypass_uri_match, module.c:4059), so a route-only
    guard for a private path silently stops matching after the redirect.
    cache_turbo_bypass_uri cannot be the fix -- it reads the same rewritten
    r->uri. The working pattern, which docs/xenforo.md prescribes, is a
    `map $request_uri` feeding cache_turbo_bypass + cache_turbo_no_store.
    XenForo's /api/ is the sharpest case: it authenticates with XF-Api-Key,
    not a preset cookie, so nothing else catches it.

    NEGATIVE CONTROL: the /ctir-fixed/ assertions must FAIL if the key reverts
    to $uri -- distinct routes would share one entry, so the second GET would
    report HIT and replay alpha's body instead of MISSing with its own. The
    origin answers every GET with a unique `gen-<n>` body, so body identity
    across two different routes is positive proof of a shared entry; asserting
    status alone would pass for free whenever both routes rendered alike."""
    # -- DOC-A1: default $uri key collapses distinct routes onto index.php --
    s1, b1, h1 = fetch(ng.port, "/ctir/alpha")
    assert s1 == 200 and h1.get("x-ct-status") == "MISS", \
        f"first clean URL should MISS, got {s1}/{h1.get('x-ct-status')}"

    # A DIFFERENT clean URL, same front controller. Under the $uri key this
    # hits the entry stored for /ctir/alpha.
    _, b2, h2 = fetch(ng.port, "/ctir/beta")
    assert h2.get("x-ct-status") == "HIT", \
        ("DOC-A1 regression: with the default $uri key both clean URLs key on "
         f"/ctir/index.php, so the 2nd route must HIT the 1st entry, got "
         f"{h2.get('x-ct-status')} -- if this now MISSes the module default key "
         "changed and the docs guidance must be revisited")
    assert b2 == b1, \
        ("DOC-A1 regression: /ctir/beta must be served ALPHA's cached body "
         f"under the $uri key, got {b2!r} vs {b1!r}")

    # -- DOC-A1 fixed: $request_uri keeps the routes distinct ---------------
    _, bf1, hf1 = fetch(ng.port, "/ctir-fixed/alpha")
    assert hf1.get("x-ct-status") == "MISS", \
        f"first fixed route should MISS, got {hf1.get('x-ct-status')}"

    _, bf2, hf2 = fetch(ng.port, "/ctir-fixed/beta")
    # THE discriminating assertion: MISS, not HIT. A revert to $uri makes this
    # a HIT replaying alpha's body -- exactly the defect being guarded.
    assert hf2.get("x-ct-status") == "MISS", \
        ("$host$request_uri must keep distinct clean URLs on distinct keys "
         f"across the internal redirect, got {hf2.get('x-ct-status')}")
    assert bf2 != bf1, \
        ("/ctir-fixed/beta must get its OWN origin body, not alpha's cached "
         f"one, got {bf2!r} == {bf1!r}")

    # Each fixed route caches independently on its own second request.
    _, ba, ha = fetch(ng.port, "/ctir-fixed/alpha")
    assert ha.get("x-ct-status") == "HIT" and ba == bf1, \
        f"fixed alpha should HIT its own entry, got {ha.get('x-ct-status')}/{ba!r}"

    # -- DOC-A2: route veto must survive the internal redirect --------------
    _, bp1, hp1 = fetch(ng.port, "/ctir-fixed/api/me")
    assert hp1.get("x-ct-status") == "BYPASS", \
        ("DOC-A2: the private /api/ route must BYPASS even though the internal "
         f"redirect rewrote r->uri to the front controller, got "
         f"{hp1.get('x-ct-status')}")

    # ... and must never have been STORED, not merely skipped on lookup: a
    # fresh origin body on every request is what proves nothing was cached.
    _, bp2, hp2 = fetch(ng.port, "/ctir-fixed/api/me")
    assert hp2.get("x-ct-status") == "BYPASS", \
        f"private route must BYPASS on every request, got {hp2.get('x-ct-status')}"
    assert bp2 != bp1, \
        ("private route must come from origin each time -- an identical body "
         f"means it was stored and replayed, got {bp2!r}")


def test_bypass_uri_inert_after_internal_redirect(ng: Nginx,
                                                  origin: Origin) -> None:
    """AUD-DOC1: cache_turbo_bypass_uri matches r->uri, so it stops guarding a
    route the moment a front controller rewrites r->uri -- the same blind spot
    DOC-A2 pins for the preset URI tier, on the tier operators are told to use
    for private paths.

    This asserts the CURRENT, intended behaviour rather than a defect: the
    matcher deliberately reads r->uri, and rebasing it onto $request_uri would
    change what every existing config matches. The value of the test is that
    the behaviour is now written down in two places that must agree -- here and
    in the directive's documentation -- so a later change to either is caught.

    /ctir-bu/ is guarded ONLY by cache_turbo_bypass_uri /ctir-bu/api/. If the
    directive fired, the route would BYPASS and every request would come from
    origin. It does not fire, so the second request is a HIT replaying the
    first response: a private page served from a shared cache, which is exactly
    why the docs now say a route-only guard is not enough behind a front
    controller."""
    s1, b1, h1 = fetch(ng.port, "/ctir-bu/api/me")
    assert s1 == 200, f"front-controller route did not answer 200: {s1}"
    assert h1.get("x-ct-status") != "BYPASS", \
        ("cache_turbo_bypass_uri matched a URI the internal redirect had "
         "already rewritten -- if this now BYPASSes, the matcher was changed "
         "to read the original path and docs/README.md plus the README "
         f"synopsis row must be updated with it (got {h1.get('x-ct-status')})")

    _, b2, h2 = fetch(ng.port, "/ctir-bu/api/me")
    assert h2.get("x-ct-status") == "HIT" and b2 == b1, \
        ("the unguarded private route must be cached and replayed -- that is "
         f"the documented blind spot (got {h2.get('x-ct-status')}, "
         f"{b2!r} vs {b1!r})")

    # Control: the directive is wired up and does work on a URI the redirect
    # leaves alone. Without this the assertions above pass just as well for a
    # cache_turbo_bypass_uri that is broken outright or spelled wrong.
    _, _, hc1 = fetch(ng.port, "/bu/panel")
    assert hc1.get("x-ct-status") == "BYPASS", \
        ("cache_turbo_bypass_uri does not match even without a redirect, so "
         f"the test above proves nothing: got {hc1.get('x-ct-status')}")


def test_ctx_survives_error_page_internal_redirect(ng: Nginx,
                                                   origin: Origin) -> None:
    """CTXRDR: an error_page internal redirect memzeros r->ctx MID-REQUEST,
    after the access handler has already built one. The module must treat the
    second pass as a fresh request and must not strand the first ctx's
    registered teardown.

    Why this shape and not the /ctir* ones: try_files redirects in the REWRITE
    phase, i.e. BEFORE the PRECONTENT access handler ever runs, so those tests
    only ever exercise a single ctx built on the post-redirect URI. error_page
    redirects off the ORIGIN's 404 -- after the access handler built ctx and
    after the header filter ran. ngx_http_internal_redirect() then does an
    unconditional `ngx_memzero(r->ctx, ...)` (ngx_http_core_module.c:2614). The
    one-module-preserving variant in special_response.c:547 is the
    filter_finalize path and does NOT apply here.

    What that makes safe, and what this pins:

    1. r->pool is NOT reset by the redirect, so the first ctx's pool cleanups
       (cold_cleanup's stub unstub, blob_cleanup's shm reference drop) and its
       EMBEDDED cold_wait_ev timer stay registered against memory that is still
       allocated. They key off the ctx pointer captured in cln->data, never off
       r->ctx, so dropping r->ctx cannot orphan them -- the cleanups still run
       at pool destroy and still see the right ctx.
    2. The second pass re-enters the access handler, finds r->ctx NULL, and
       pcallocs a FRESH ctx (module.c:4515). No state leaks across the two
       passes: the fallback must report its own outcome, not the 404 pass's.

    The variable getters read r->ctx directly, which is what makes pass 2's ctx
    observable from the wire at all."""
    # Pass 1 404s at the origin -> error_page -> internal redirect -> pass 2
    # serves the fallback. The client sees the fallback body under the 404's
    # status-code-preserving redirect.
    # THE oracle for "did pass 2 park?". Timing alone cannot carry this test:
    # `elapsed < 2.0` goes vacuous the moment cache_turbo_lock_timeout is
    # configured below 2s, and it is a proxy for the symptom rather than the
    # mechanism. lock_waits is bumped once per request that actually ENTERS
    # cold_wait(), which is precisely the thing CTXRDR must prevent, so an exact
    # "did not move" is both stronger and immune to a slow runner.
    waits0 = _admin_lock_waits(ng)

    t0 = time.monotonic()
    s1, b1, _ = fetch(ng.port, "/ctxrdr/ctxrdr-missing")
    elapsed1 = time.monotonic() - t0
    assert s1 == 200, \
        (f"error_page did not take the internal redirect (got {s1}); the "
         "fixture, not the module, is wrong -- the rest of this test would be "
         "vacuous")
    assert b1, "fallback served an empty body"

    # CTXRDR, the defect this test was written for. $request_uri does not change
    # across an internal redirect, so BOTH passes hash to the same key. Pass 1
    # won the cold-miss claim and planted a stub; the redirect then memzeroed
    # r->ctx, so pass 2's fresh ctx has cold_winner = 0 and used to read that
    # stub as another request's in-flight fill -- parking in cold_wait() for the
    # FULL cache_turbo_lock_timeout (5s by default) before giving up and
    # re-winning. It answered correctly, so only the clock showed it.
    #
    # None of the three header/body-filter unstub sites can prevent that: an
    # intercepted upstream error is finalized inside
    # ngx_http_upstream_intercept_errors() without traversing the output filter
    # chain, leaving only the pool cleanup, which runs at teardown -- long after
    # pass 2 has parked. The fix is _cold_adopt_own_stub(): on CLAIM_LOSER the
    # request looks for a stub an earlier ctx of ITSELF still owns and adopts it.
    #
    # Timing is the assertion because latency IS the symptom. The threshold is
    # far below the 5s timeout and far above a normal redirect (measured ~8ms),
    # so it cannot flake into passing on a slow runner the way a tight bound
    # would.
    # THE assertion. Not one request may enter cold_wait(): pass 2 adopting its
    # own stub is exactly the difference between "went straight to origin" and
    # "parked on itself for the full lock_timeout".
    assert _admin_lock_waits(ng) - waits0 == 0, \
        (f"lock_waits moved by {_admin_lock_waits(ng) - waits0}: the "
         "post-redirect pass PARKED on the cold-miss stub its OWN first pass "
         "planted. _cold_adopt_own_stub() should have adopted it on "
         "CLAIM_LOSER instead")

    # Timing is kept as a loose diagnostic only -- it is the client-visible
    # symptom and makes a failure obvious, but lock_waits above is what proves
    # the mechanism. Threshold far below the 5s timeout and far above a normal
    # redirect (~8ms) so it cannot flake on a slow runner.
    assert elapsed1 < 2.0, \
        (f"the post-redirect pass took {elapsed1:.2f}s: it parked on the "
         "cold-miss stub its OWN first pass planted and waited out "
         "cache_turbo_lock_timeout. _cold_adopt_own_stub() should have adopted "
         "it on CLAIM_LOSER instead")

    # One origin contact for the FALLBACK body, not two: adoption must make the
    # second pass the WINNER that goes to origin, not a waiter that eventually
    # times out and then also goes to origin.
    #
    # ⚠ Counted on the fallback's own upstream marker. The obvious spelling --
    # hits_for("ctxrdr-missing") -- observes only pass 1's 404, because the
    # fallback location proxies as /ctxrdr-fb-page; it would read 1 no matter
    # what the fallback leg did.
    assert origin.hits_for("ctxrdr-fb-") == 1, \
        ("the fallback leg hit the origin "
         f"{origin.hits_for('ctxrdr-fb-')} times, expected exactly 1")

    # The post-memzero ctx must have STORED, not merely answered. Note the key
    # is $host$request_uri and $request_uri is NOT rewritten by the redirect, so
    # the entry lands under the ORIGINAL /ctxrdr/ctxrdr-missing key -- repeating
    # that same request is what reads it back, not a direct fetch of the
    # rewritten /ctxrdr-fallback/page URI (a different key entirely).
    t1 = time.monotonic()
    s2, b2, h2 = fetch(ng.port, "/ctxrdr/ctxrdr-missing")
    elapsed2 = time.monotonic() - t1
    assert s2 == 200, f"second redirecting request failed: {s2}"
    assert h2.get("x-ct-status") == "HIT" and b2 == b1, \
        ("the ctx rebuilt after the r->ctx memzero did not store, so the "
         "adopted stub never became a real entry (got "
         f"{h2.get('x-ct-status')}, {b2!r} vs {b1!r})")
    assert h2.get("x-ct-reason") == "FRESH", \
        ("$cache_turbo_serve_reason reads r->ctx; a HIT must report FRESH, got "
         f"{h2.get('x-ct-reason')!r}")
    assert elapsed2 < 2.0, \
        f"the cached redirecting request took {elapsed2:.2f}s"

    # Serving that HIT cost no further origin work: still exactly one contact.
    assert origin.hits_for("ctxrdr-fb-") == 1, \
        ("the HIT went to the origin anyway: "
         f"{origin.hits_for('ctxrdr-fb-')} contacts, expected 1")

    # Negative control. The assertions above are only meaningful if the
    # variables are genuinely sourced from a per-request ctx that this fixture
    # can move. A location with no cache-turbo ctx at all must report "-": if
    # this returned MISS/HIT the getters would be answering from something
    # other than r->ctx and every assertion above would be reading a constant.
    _, _, hc = fetch(ng.port, "/ctxrdr-off/page")
    assert hc.get("x-ct-status") in (None, "-"), \
        ("$cache_turbo_status reports a value on a location where the module "
         f"never engaged, so it is not reading r->ctx: got "
         f"{hc.get('x-ct-status')!r}")
    # Both variables, not just the status one. The HIT above asserts
    # x-ct-reason == "FRESH", so $cache_turbo_serve_reason carries real weight
    # here; a getter answering a constant for the reason would sail through
    # every assertion in this test if only the status arm were controlled.
    assert hc.get("x-ct-reason") in (None, "-"), \
        ("$cache_turbo_serve_reason reports a value on a location where the "
         f"module never engaged, so it is not reading r->ctx: got "
         f"{hc.get('x-ct-reason')!r}")


def test_auto_classify_more(ng: Nginx, origin: Origin) -> None:
    """Auto-classify breadth: the search query arg (?s=), the comment_author_
    cookie, the joomla /administrator/ URI prefix, and a two-backend stack
    (wordpress woocommerce) where BOTH cookie families skip."""
    # ?s= search -> does NOT skip. This assertion is INVERTED: `s` was a
    # bare-name row in ct_wp_args and every site search bypassed. It bought no
    # safety (a logged-out visitor's results are anonymous-identical; a
    # logged-in editor is bypassed by wordpress_logged_in_ on the cookie tier)
    # and it removed miss-collapsing from the most expensive query WordPress
    # runs. Full coverage is in ci/t/presets/wordpress.t (TEST 8-9), which uses
    # a location whose key carries the query string; /auto/ keys on $uri alone,
    # so all that can be asserted here is that ?s= no longer classifies as
    # dynamic.
    fetch(ng.port, "/auto/results-s?s=widgets")
    _, _, hs2 = fetch(ng.port, "/auto/results-s?s=widgets")
    assert hs2.get("x-cache") == "HIT", \
        (f"?s= must no longer classify as dynamic, got {hs2.get('x-cache')}")

    # comment_author_ cookie -> skip
    cc = {"Cookie": "comment_author_email_x=foo%40bar"}
    _, _, hc1 = fetch(ng.port, "/auto/comment", headers=cc)
    _, _, hc2 = fetch(ng.port, "/auto/comment", headers=cc)
    assert "x-cache" not in hc1 and "x-cache" not in hc2, \
        "comment_author_ cookie must skip"

    # joomla /administrator/ URI prefix -> skip
    _, _, ha1 = fetch(ng.port, "/administrator/index.php")
    _, _, ha2 = fetch(ng.port, "/administrator/index.php")
    assert "x-cache" not in ha1 and "x-cache" not in ha2, \
        "/administrator/ must skip"

    # two backends stacked: a WP cookie AND a Woo cookie both skip on /multi/
    _, _, hm1 = fetch(ng.port, "/multi/a",
                      headers={"Cookie": "wordpress_logged_in_z=1"})
    assert "x-cache" not in hm1, "stacked WP cookie must skip on /multi/"
    _, _, hm2 = fetch(ng.port, "/multi/b",
                      headers={"Cookie": "woocommerce_cart_hash=z"})
    assert "x-cache" not in hm2, "stacked Woo cookie must skip on /multi/"
    # a plain anon page on the stacked location still caches
    fetch(ng.port, "/multi/plain")
    _, _, hm3 = fetch(ng.port, "/multi/plain")
    assert hm3.get("x-cache") == "HIT", \
        f"anon page on /multi/ should cache, got {hm3.get('x-cache')}"
    drain_origin(origin)


_ARG_SCANS_HDR = "x-cache-turbo-test-arg-scans"


def _arg_scans(hdrs: dict, where: str) -> int:
    """Pull the lifetime qs_eq()-NAME-comparison counter out of a response's
    headers (S231-PERF-AUTOCLASSIFY args half, TEST_FAULTS-only). Same
    "missing header is a hard failure" discipline as _cookie_scans()/
    _armings()/_backoff_skips(): its absence would make every delta read 0
    and the counter-oracle test would pass while proving the prefilter did
    nothing."""
    raw = hdrs.get(_ARG_SCANS_HDR)
    assert raw is not None, (
        f"{_ARG_SCANS_HDR} missing on {where} -- this build has no arg scan "
        f"counter, so the S231-PERF-AUTOCLASSIFY args-half control cannot "
        f"distinguish 'prefilter skipped scans' from 'never counted'")
    return int(raw)


# preset -> (location, [(query-string suffix, needle-name-first-byte)]) for
# the negative control below. Mirrors src/ngx_http_cache_turbo_module.c's
# ngx_http_cache_turbo_presets[] table exactly -- ENUMERATED by reading every
# non-empty ct_*_args[] array in the source directly (15 of the 34 declared
# args arrays are non-empty; the other 19 are `{ NULL }` and carry no query-
# arg tier at all, classified by cookie/URI/cookie_pred instead -- not a gap
# here since there is nothing to prefilter). A preset added here with a
# non-empty args[] row and no entry below is a silent coverage gap.
_ARG_NEEDLE_TABLE = {
    "wordpress":   ("/auto/", ["preview", "rest_route"]),
    "woocommerce": ("/auto/", ["wc-ajax"]),
    "xenforo":     ("/xf/", ["_xfToken"]),
    "discourse":   ("/dc/", ["api_key", "api_username"]),
    "phpbb":       ("/phpbb/", ["sid"]),
    "mediawiki":   ("/ct-mediawiki-args/", ["veaction", "returnto"]),
    "ghost":       ("/ct-ghost-args/", ["uuid", "key", "token", "gift"]),
    "invision":    ("/ips/", ["do=compose", "do=post", "do=reply",
                               "do=report", "module=messaging"]),
    "smf":         ("/smf/", ["action=admin", "action=login",
                               "action=logout", "action=post"]),
    "yabb":        ("/ct-yabb-args/", ["action=post", "action=login",
                                        "action=register"]),
    "mybb":        ("/mybb/", ["action=login", "action=logout",
                                "action=register"]),
    "spip":        ("/ct-spip/", ["action", "var_mode"]),
    "bugzilla":    ("/ct-bugzilla/", ["Bugzilla_api_key", "api_key",
                                       "Bugzilla_login", "token"]),
    "redmine":     ("/redmine/", ["key"]),
    "opencart":    ("/opencart/", ["route=checkout/cart", "user_token",
                                    "customer_token"]),
}


def test_arg_prefilter_negative_control(ng: Nginx, origin: Origin) -> None:
    """S231-PERF-AUTOCLASSIFY (args half): negative control for the
    pre-parsed-span array + mangled-first-byte presence set in
    ngx_http_cache_turbo_arg_match(). For EVERY preset with a non-empty
    args[] row, a request carrying that exact needle in the query string
    must still be classified dynamic (auto_skip bypasses the cache). If the
    prefilter ever skipped a needle it should have scanned, the matching
    preset's dynamic route would go silently invisible -- a private page
    would be cached and served to strangers -- and this is the test that
    would catch it.

    _ARG_NEEDLE_TABLE is hand-derived from ngx_http_cache_turbo_presets[]
    (see the table's own comment); a preset added there with a non-empty
    args[] row and no row here is a silent coverage gap, not a passing
    test."""
    for preset, (loc, needles) in _ARG_NEEDLE_TABLE.items():
        for needle in needles:
            path = f"nc-{preset}-{hash(needle) & 0xffff:x}"
            if "=" in needle:
                qs = needle
            else:
                qs = f"{needle}=1"
            uri = f"{loc}{path}?{qs}"
            fetch(ng.port, uri)
            status, _, h = fetch(ng.port, uri)
            assert status == 200, (
                f"{preset} needle {needle!r} request returned {status}")
            assert "x-cache" not in h, (
                f"{preset} needle {needle!r} must bypass the cache (the "
                f"first-byte prefilter made it unreachable), got "
                f"x-cache={h.get('x-cache')}")
    drain_origin(origin)


def test_arg_prefilter_mangling_regression(ng: Nginx, origin: Origin) -> None:
    """S231-PERF-AUTOCLASSIFY (args half): regression test for the trap this
    item exists to prevent -- a first-byte set built over RAW query-string
    bytes instead of the byte ngx_http_cache_turbo_qs_eq() would actually
    compare. `_xfToken` (xenforo) starts with '_', which qs_eq() reaches
    from several different raw spellings via percent-decoding and PHP's
    register_globals-derived key mangling (literal '+', '.', ' ' all fold to
    '_' for argument NAMES). A prefilter keyed on the raw first byte would
    set bit '.'/'+'/' '/etc. instead of '_', never see '_xfToken's needle
    bit satisfied by any of these, and skip a scan that qs_eq() would have
    matched -- caching a private xenforo response. Each spelling below must
    still classify dynamic.

    "%20xfToken" exercises the SAME post-decode mangling branch
    (`c == '.' || c == ' '`) an unencoded literal space would -- a raw space
    byte in a URI query string is not a spelling any HTTP client library
    used here will emit unencoded, so %20 is the reachable way to drive that
    branch; ".xfToken" and " " share qs_eq()'s decoded-then-mangled
    codepath, so both are exercised by this set.

    "%2BxfToken" is DELIBERATELY EXCLUDED: qs_eq()'s mangling rule only folds
    a LITERAL '+' (the `!decoded` guard), never a percent-decoded one -- a
    decoded '+' is a real plus sign PHP leaves alone, so "%2BxfToken" compares
    as "+xfToken", not "_xfToken", and correctly does NOT match. Asserting a
    bypass there would pin the WRONG behaviour and fight the real qs_eq()
    semantics, not the prefilter."""
    for spelling in (".xfToken", "+xfToken",
                      "%5FxfToken", "%2ExfToken", "%20xfToken"):
        uri = f"/xf/nc-mangle-{hash(spelling) & 0xffff:x}?{spelling}=1"
        fetch(ng.port, uri)
        status, _, h = fetch(ng.port, uri)
        assert status == 200, f"{spelling!r} request returned {status}"
        assert "x-cache" not in h, (
            f"query spelling {spelling!r} must still be recognised as "
            f"_xfToken and bypass the cache, got x-cache={h.get('x-cache')} "
            f"-- a raw-byte first-byte prefilter would fail exactly this "
            f"case")
    drain_origin(origin)


def test_arg_prefilter_counter_oracle(ng: Nginx, origin: Origin) -> None:
    """S231-PERF-AUTOCLASSIFY (args half): counter oracle for the perf claim
    -- never a wall-clock timing band. A query string built entirely from
    bytes that appear in NO preset's arg-needle NAME first byte (after
    mangling) must classify identically (cacheable) to a plain anonymous
    request, while the pre-parsed-span/first-byte prefilter measurably cuts
    the number of qs_eq() NAME comparisons arg_match() makes.

    The delta is read off X-Cache-Turbo-Test-Arg-Scans, a process-global
    lifetime counter (TEST_FAULTS-only) bumped exactly once per qs_eq() NAME
    comparison the prefilter did NOT skip -- see
    ngx_http_cache_turbo_test_arg_scan_header() and the counter's own
    declaration.

    X-Cache-Turbo-Test-Arg-Scans is a process-global (per-worker) monotonic
    counter, so all probes below share ONE kept-alive HTTPConnection (see
    _fetch_keepalive's docstring) so nginx pins them all to the same
    accepted-connection worker -- a plain fetch() opens a fresh socket per
    call and round-robins across workers, which produced an impossible
    negative delta on the cookie half's equivalent oracle (#278) and is the
    exact trap this test is built to avoid."""
    conn = http.client.HTTPConnection("127.0.0.1", ng.port, timeout=HTTP_TIMEOUT)
    try:
        # Baseline on /auto/ (wordpress+woocommerce+joomla: 3 arg needles --
        # preview, rest_route, wc-ajax).
        _, _, hbase = _fetch_keepalive(conn, "/auto/argbaseline?zz=1")
        n_before = _arg_scans(hbase, "baseline request")

        # A query string matching NOTHING: every arg NAME's first byte
        # (after mangling) is a digit, which is not the mangled first byte
        # of "preview", "rest_route" or "wc-ajax" (p / r / w). The prefilter
        # should skip essentially all needle comparisons for this request.
        big_qs = "n9=1&" + "&".join(f"z{i}=1" for i in range(400))
        status, body1, h1 = _fetch_keepalive(conn, f"/auto/argmiss1?{big_qs}")
        assert status == 200
        n_after_first = _arg_scans(h1, "large non-matching query, request 1")

        status, body2, h2 = _fetch_keepalive(conn, f"/auto/argmiss1?{big_qs}")
        assert status == 200
        n_after_second = _arg_scans(h2, "large non-matching query, request 2")

        # Correctness half: classification is UNCHANGED -- a non-matching
        # query string was always cacheable, and it still is.
        assert "x-cache" not in h1, (
            "first request should be a miss (no x-cache yet)")
        assert h2.get("x-cache") == "HIT", (
            f"a large query string matching no needle must still let the "
            f"page cache -- got x-cache={h2.get('x-cache')} (byte-identical "
            f"classification is the whole point of the prefilter proof)")
        assert body1 == body2, "cached body must be byte-identical"

        # Counter oracle: each of the two /auto/argmiss1 requests
        # independently runs arg_match() over wordpress+woocommerce+joomla's
        # 3-needle union (preview, rest_route, wc-ajax; joomla has none).
        # None of their first bytes (p, r, w) collide with the digit/'z'
        # bytes in big_qs's argument NAMES, so EVERY qs_eq() NAME comparison
        # on this request must be skipped: the delta this request
        # contributes is 0.
        delta_first = n_after_first - n_before
        delta_second = n_after_second - n_after_first
        assert delta_first == 0, (
            f"large non-matching query string should trigger ZERO qs_eq() "
            f"NAME comparisons (every needle's first byte is absent from "
            f"the query), got a delta of {delta_first} -- the first-byte "
            f"prefilter is not cutting scans")
        assert delta_second == 0, (
            f"second request (same query) should also trigger ZERO qs_eq() "
            f"NAME comparisons, got a delta of {delta_second}")

        # Anti-vacuity arm: a query string whose arg NAME DOES start with a
        # needle's first byte ('p', from "preview") but is not the needle
        # itself must NOT be skipped by the byte test alone -- only qs_eq()
        # itself decides a real match, and the byte set only gates whether
        # that comparison happens. This proves the filter is not simply
        # returning "no scans, ever": a 'p'-colliding miss still counts.
        _, _, h3 = _fetch_keepalive(conn, "/auto/argnormal?plum=1")
        n_after_p = _arg_scans(h3, "byte-colliding but non-matching query")
        delta_p = n_after_p - n_after_second
        assert delta_p > 0, (
            f"a query arg starting with 'p' (preview's first byte) must "
            f"still trigger at least one qs_eq() comparison, got delta="
            f"{delta_p} -- a filter that skips everything would pass the "
            f"zero-delta assertions above for the wrong reason")
    finally:
        conn.close()
    drain_origin(origin)


def test_arg_span_overflow_boundary(ng: Nginx, origin: Origin) -> None:
    """AUD4-PERF-ARG64: the 64-span inline fast path must extend without
    falling back to one whole-query rescan per enabled needle.

    The three dynamic cases pin the private ``preview`` argument at the last
    inline slot, the first overflow slot, and the last slot of a longer query.
    The non-matching control proves that a long query is not blanket-bypassed.
    The scan-counter arm is a deterministic cliff oracle: with only ``p``
    names present, /auto/ must compare only WordPress's ``preview`` needle, so
    N pairs cost exactly N name comparisons at both sides of the boundary.
    The former rescan fallback instead compared all 65 pairs independently
    against preview, rest_route, and wc-ajax (195 comparisons)."""

    def query_with_private(total: int, position: int) -> str:
        pairs = [f"z{i}=1" for i in range(total)]
        pairs[position - 1] = "preview=1"
        return "&".join(pairs)

    for label, total, position in (
            ("inline-last", 64, 64),
            ("overflow-first", 65, 65),
            ("overflow-last", 96, 96)):
        uri = f"/auto/argspan-{label}?{query_with_private(total, position)}"
        for attempt in (1, 2):
            status, _, headers = fetch(ng.port, uri)
            assert status == 200, (
                f"private arg at position {position}/{total}, attempt "
                f"{attempt}, returned {status}")
            assert "x-cache" not in headers, (
                f"private arg at position {position}/{total} must bypass the "
                f"cache, got x-cache={headers.get('x-cache')} on attempt "
                f"{attempt}")

    public_qs = "&".join(f"z{i}=1" for i in range(96))
    public_uri = f"/auto/argspan-public?{public_qs}"
    fetch(ng.port, public_uri)
    _, _, public_headers = fetch(ng.port, public_uri)
    assert public_headers.get("x-cache") == "HIT", (
        "a long query with no private argument must remain cacheable; "
        f"got x-cache={public_headers.get('x-cache')}")

    conn = http.client.HTTPConnection("127.0.0.1", ng.port,
                                      timeout=HTTP_TIMEOUT)
    try:
        _, _, baseline_headers = _fetch_keepalive(
            conn, "/auto/argspan-counter-baseline?zz=1")
        before = _arg_scans(baseline_headers, "arg-span cliff baseline")

        qs64 = "&".join(f"p{i}=1" for i in range(64))
        _, _, headers64 = _fetch_keepalive(
            conn, f"/auto/argspan-counter-64?{qs64}")
        after64 = _arg_scans(headers64, "64-pair arg-span query")

        qs65 = "&".join(f"p{i}=1" for i in range(65))
        _, _, headers65 = _fetch_keepalive(
            conn, f"/auto/argspan-counter-65?{qs65}")
        after65 = _arg_scans(headers65, "65-pair arg-span query")

        assert after64 - before == 64, (
            "64 pairs should cost exactly 64 cached-span name comparisons, "
            f"got {after64 - before}")
        assert after65 - after64 == 65, (
            "crossing from 64 to 65 pairs must add one comparison, not fall "
            "off the per-needle rescan cliff; got "
            f"{after65 - after64} comparisons")
    finally:
        conn.close()
    drain_origin(origin)


def test_q2_multibuffer_oversize(ng: Nginx, origin: Origin) -> None:
    """Q2: a ~200 KB response (streamed in several buffers) over a 1k max_size
    must early-abort capture mid-stream — never cached, body intact, no error,
    across repeats (the abort path runs each time)."""
    first = None
    for _ in range(3):
        s, b, h = fetch(ng.port, "/qbig/bigbody-media")
        assert s == 200, f"oversize multibuffer served {s}, expected 200"
        assert len(b) > 100000, f"body truncated: {len(b)} bytes"
        assert "x-cache" not in h, "multibuffer oversize must not be cached"
        if first is not None:
            assert b != first, "served a cached copy of an oversize body"
        first = b
    drain_origin(origin)


def test_suppress_native_inert_on_plain_location(ng: Nginx) -> None:
    """Q1: $cache_turbo_active is "0" on a location with no cache_turbo (no ctx
    / disabled) — the variable's defensive default, so wiring it into an
    unrelated location can never accidentally read 1."""
    _, _, h = fetch(ng.port, "/plain/x")
    assert h.get("x-ct-active") == "0", \
        f"plain location: expected X-CT-Active=0, got {h.get('x-ct-active')}"


def test_suppress_native_e2e_proxy_cache(ng: Nginx) -> None:
    """Q1 end-to-end: with cache_turbo_suppress_native on plus the documented
    proxy_no_cache/proxy_cache_bypass wiring, a stacked proxy_cache never writes
    (its on-disk cache dir stays empty). With suppress off the identical wiring
    is inert ($cache_turbo_active=0) and proxy_cache stores as usual. Proves the
    variable gates native caching for real, not just as a header value."""
    import os

    # proxy_cache writes go through nginx's cache-manager process, which is not
    # spawned under `master_process off`; the multi-process Runtime job covers
    # this end-to-end. Skip in single-process mode (the ASan run uses it).
    #
    # Also skip under sanitizers (CI-3 multi-worker ASan/UBSan smoke): this is the
    # only test that drives nginx's CORE proxy_cache file-WRITE path, and that path
    # trips a known nginx-core UBSan false positive
    # (src/http/ngx_http_file_cache.c: "null pointer passed as argument 2" — a
    # zero-length ngx_memcpy with a NULL src, harmless, same class as the OpenSSL
    # ASan baseline noise). It is nginx-core code, not cache-turbo; the plain
    # multi-worker Runtime job still exercises it fully without sanitizers.
    if ng.single_process or ng.sanitizer:
        return

    def file_count(d: pathlib.Path) -> int:
        return sum(len(files) for _, _, files in os.walk(d))

    on_dir = ng.root / "pcache_on"
    off_dir = ng.root / "pcache_off"

    # suppress ON: cache-turbo owns it; proxy_cache must stay empty.
    fetch(ng.port, "/supcache/a")
    fetch(ng.port, "/supcache/b")
    time.sleep(0.4)                       # let the cache manager settle
    n_on = file_count(on_dir)
    assert n_on == 0, \
        f"suppress on: proxy_cache wrote {n_on} files, expected 0 (native not suppressed)"

    # suppress OFF (control): the same wiring is inert, proxy_cache stores.
    fetch(ng.port, "/nosupcache/a")
    fetch(ng.port, "/nosupcache/b")
    time.sleep(0.4)
    n_off = file_count(off_dir)
    assert n_off > 0, \
        "suppress off: proxy_cache should have stored (wiring inert), but dir is empty"


def test_invalid_backend_name(ng: Nginx) -> None:
    """An unknown cache_turbo_backend value is rejected at config time."""
    bad = ng.root.parent / "bad-backend"
    (bad / "conf").mkdir(parents=True, exist_ok=True)
    (bad / "logs").mkdir(parents=True, exist_ok=True)
    cfg = nginx_config(bad, ng.port, ng.module, ng.origin_port, 1)
    cfg = cfg.replace("cache_turbo_backend woocommerce;",
                      "cache_turbo_backend bogus;")
    (bad / "conf" / "nginx.conf").write_text(cfg, encoding="ascii")
    cmd = ng.runner + [str(ng.binary), "-p", str(bad),
                       "-c", str(bad / "conf" / "nginx.conf"), "-t"]
    r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=20)
    assert r.returncode != 0, \
        f"invalid backend 'bogus' was accepted by nginx -t:\n{r.stdout}"
    assert "unknown cache_turbo_backend" in r.stdout, \
        f"missing/odd diagnostic for bad backend:\n{r.stdout}"




def test_invalid_cache_turbo_mode(ng: Nginx) -> None:
    """cache_turbo takes a zone name and nothing else. Any 2nd token is rejected
    (the `auto` shorthand is gone -- see test_auto_and_generic_are_removed)."""
    _config_rejects(ng, "bad-mode",
                    "cache_turbo         main;\n            cache_turbo_backend wordpress;",
                    "cache_turbo         main bogusmode;",
                    "invalid cache_turbo mode")


def test_auto_and_generic_are_removed(ng: Nginx) -> None:
    """The `generic`/`auto` preset union was removed because it was never a safe
    default: it never covered every backend, `woocommerce` in it left /wp-admin/
    cacheable unless stacked with `wordpress`, and `joomla` in it then shipped
    no cookie rule at all.

    All three dead spellings must be a HARD CONFIG ERROR, not a silent no-op.
    That distinction is the entire point: accepting the name and enabling nothing
    would leave an existing WordPress config with no preset active and quietly
    start caching /wp-admin/. nginx must refuse to start so the operator looks."""
    # cache_turbo_backend generic;
    _config_rejects(ng, "dead-generic", _BACKEND_LINE,
                    "cache_turbo_backend generic;", "has been removed")
    # cache_turbo_backend auto;
    _config_rejects(ng, "dead-backend-auto", _BACKEND_LINE,
                    "cache_turbo_backend auto;", "has been removed")
    # cache_turbo <zone> auto;  -- the old shorthand
    _config_rejects(ng, "dead-shorthand-auto",
                    "cache_turbo         main;\n            cache_turbo_backend wordpress;",
                    "cache_turbo         main auto;",
                    "no longer supported")




def _config_warns(ng: Nginx, tag: str, old: str, new: str, want: str) -> None:
    """Swap `old`->`new` and assert nginx -t both ACCEPTS the config (exit 0)
    AND prints `want` on stdout. For warn-not-reject checks (O4.4-d): a config
    that loads successfully today must keep loading, but the operator still
    needs to see the diagnostic."""
    warn = ng.root.parent / tag
    (warn / "conf").mkdir(parents=True, exist_ok=True)
    (warn / "logs").mkdir(parents=True, exist_ok=True)
    cfg = nginx_config(warn, ng.port, ng.module, ng.origin_port, 1)
    assert old in cfg, f"{tag}: pattern to replace not found: {old!r}"
    cfg = cfg.replace(old, new, 1)
    (warn / "conf" / "nginx.conf").write_text(cfg, encoding="ascii")
    cmd = ng.runner + [str(ng.binary), "-p", str(warn),
                       "-c", str(warn / "conf" / "nginx.conf"), "-t"]
    r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=20)
    assert r.returncode == 0, \
        f"{tag}: config was REJECTED by nginx -t but must still load:\n{r.stdout}"
    assert want in r.stdout, \
        f"{tag}: missing/odd diagnostic (want {want!r}):\n{r.stdout}"


def test_breaker_policy_divergence_warns(ng: Nginx) -> None:
    """O4.4-d: breaker STATE/counters are per-ZONE but the five breaker
    directives are per-LOCATION. Two sibling locations sharing one zone
    (`brkpolz`) with divergent EFFECTIVE breaker tuples (open=30s vs open=5m)
    must load successfully (WARN, not reject -- a hard reject would break
    configs that work today) and must print the divergence diagnostic added
    at merge_loc_conf just after the shm_zone inheritance block."""
    _config_warns(ng, "breaker-policy-diverge",
        "        location /forever/ {\n"
        "            cache_turbo          main;\n"
        "            cache_turbo_key      $uri;\n"
        "            cache_turbo_valid    0;\n"
        "            proxy_pass http://127.0.0.1:{origin_port}/;\n"
        "        }\n".replace("{origin_port}", str(ng.origin_port)),
        "        location /forever/ {\n"
        "            cache_turbo          main;\n"
        "            cache_turbo_key      $uri;\n"
        "            cache_turbo_valid    0;\n"
        "            proxy_pass http://127.0.0.1:%d/;\n"
        "        }\n"
        "\n"
        "        location /brkpolicy1/ {\n"
        "            cache_turbo                   brkpolz;\n"
        "            cache_turbo_key                $uri;\n"
        "            cache_turbo_valid              30s;\n"
        "            cache_turbo_breaker            on;\n"
        "            cache_turbo_breaker_threshold  3;\n"
        "            cache_turbo_breaker_window     10s;\n"
        "            cache_turbo_breaker_open       30s;\n"
        "            proxy_pass http://127.0.0.1:%d/;\n"
        "        }\n"
        "\n"
        "        location /brkpolicy2/ {\n"
        "            cache_turbo                   brkpolz;\n"
        "            cache_turbo_key                $uri;\n"
        "            cache_turbo_valid              30s;\n"
        "            cache_turbo_breaker            on;\n"
        "            cache_turbo_breaker_threshold  3;\n"
        "            cache_turbo_breaker_window     10s;\n"
        "            cache_turbo_breaker_open       5m;\n"
        "            proxy_pass http://127.0.0.1:%d/;\n"
        "        }\n"
        % (ng.origin_port, ng.origin_port, ng.origin_port),
        "circuit breaker")


def test_breaker_policy_identical_no_warning(ng: Nginx) -> None:
    """NEGATIVE CONTROL (a): two siblings on the same zone with an IDENTICAL
    effective breaker tuple must produce NO warning -- the divergence check
    must not fire unconditionally. See test_breaker_policy_divergence_warns
    for the positive arm; the always-true-mutation falsification (b) is
    manual (documented in the O4.4-d ledger), since it requires rebuilding
    the module with a deliberately broken comparison."""
    good = ng.root.parent / "breaker-policy-identical"
    (good / "conf").mkdir(parents=True, exist_ok=True)
    (good / "logs").mkdir(parents=True, exist_ok=True)
    cfg = nginx_config(good, ng.port, ng.module, ng.origin_port, 1)
    old = ("        location /forever/ {\n"
           "            cache_turbo          main;\n"
           "            cache_turbo_key      $uri;\n"
           "            cache_turbo_valid    0;\n"
           "            proxy_pass http://127.0.0.1:%d/;\n"
           "        }\n") % ng.origin_port
    assert old in cfg, "pattern to replace not found"
    new = (old +
        "\n"
        "        location /brkpolicy1/ {\n"
        "            cache_turbo                   brkpolz;\n"
        "            cache_turbo_key                $uri;\n"
        "            cache_turbo_valid              30s;\n"
        "            cache_turbo_breaker            on;\n"
        "            cache_turbo_breaker_threshold  3;\n"
        "            cache_turbo_breaker_window     10s;\n"
        "            cache_turbo_breaker_open       30s;\n"
        "            proxy_pass http://127.0.0.1:%d/;\n"
        "        }\n"
        "\n"
        "        location /brkpolicy2/ {\n"
        "            cache_turbo                   brkpolz;\n"
        "            cache_turbo_key                $uri;\n"
        "            cache_turbo_valid              30s;\n"
        "            cache_turbo_breaker            on;\n"
        "            cache_turbo_breaker_threshold  3;\n"
        "            cache_turbo_breaker_window     10s;\n"
        "            cache_turbo_breaker_open       30s;\n"
        "            proxy_pass http://127.0.0.1:%d/;\n"
        "        }\n"
        % (ng.origin_port, ng.origin_port))
    cfg = cfg.replace(old, new, 1)
    (good / "conf" / "nginx.conf").write_text(cfg, encoding="ascii")
    cmd = ng.runner + [str(ng.binary), "-p", str(good),
                       "-c", str(good / "conf" / "nginx.conf"), "-t"]
    r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=20)
    assert r.returncode == 0, \
        f"identical breaker tuples: config was REJECTED:\n{r.stdout}"
    assert "circuit breaker" not in r.stdout, \
        f"identical breaker tuples must NOT warn, but got:\n{r.stdout}"


def test_breaker_directives_accepted(ng: Nginx) -> None:
    """O4.4: the four breaker directives parse. Each is appended standalone
    after the zone's cache_turbo_valid line (present verbatim in every
    generated config) so the test does not depend on any one location block's
    exact directive set."""
    _config_accepts(ng, "breaker-flag-on",
                    "cache_turbo_valid    0;",
                    "cache_turbo_valid    0;\n"
                    "            cache_turbo_breaker on;")
    _config_accepts(ng, "breaker-flag-off",
                    "cache_turbo_valid    0;",
                    "cache_turbo_valid    0;\n"
                    "            cache_turbo_breaker off;")
    _config_accepts(ng, "breaker-threshold",
                    "cache_turbo_valid    0;",
                    "cache_turbo_valid    0;\n"
                    "            cache_turbo_breaker_threshold 5;")
    _config_accepts(ng, "breaker-window",
                    "cache_turbo_valid    0;",
                    "cache_turbo_valid    0;\n"
                    "            cache_turbo_breaker_window 30s;")
    _config_accepts(ng, "breaker-open-nonzero",
                    "cache_turbo_valid    0;",
                    "cache_turbo_valid    0;\n"
                    "            cache_turbo_breaker_open 15s;")
    _config_accepts(ng, "breaker-retry-after",
                    "cache_turbo_valid    0;",
                    "cache_turbo_valid    0;\n"
                    "            cache_turbo_breaker_retry_after 20s;")


def test_breaker_open_zero_rejected(ng: Nginx) -> None:
    """O4.3-a / O4.4 regression pin: `cache_turbo_breaker_open 0` MUST be a
    hard config error, not accepted as a disable. Every sibling breaker field
    treats 0 as inert/off; this one is the exception because
    ngx_http_cache_turbo_shm_breaker_state()'s timed reopen is guarded on
    `open_for > 0` -- with 0 an OPEN breaker would never promote a probe, and
    with no origin contact while OPEN, no success could ever close it either.
    The breaker would wedge OPEN until reload. See memory issues.md O4.3-a."""
    _config_rejects(ng, "breaker-open-zero",
                    "cache_turbo_valid    0;",
                    "cache_turbo_valid    0;\n"
                    "            cache_turbo_breaker_open 0;",
                    "must be greater than 0")


def test_breaker_arming_gated_on_breaker_enable(ng: Nginx, origin: Origin) -> None:
    """O4.4 wiring pin: cache_turbo_breaker off must be a genuine, independent
    off-switch black-box-observable end to end (arming call site through the
    pre-origin gate) -- a dead origin behind a disabled breaker must never be
    answered from a stale snapshot.

    ⚠ This end-to-end shape cannot isolate WHICH of the two should_consult()
    call sites (arming vs. the pre-origin gate) is doing the gating: the
    pre-origin gate alone already blocks BRK_ACT_SERVE when breaker_enable is
    off, regardless of whether arming itself is correctly gated -- verified by
    injecting a bare `breaker_threshold > 0` at the arming site alone (dropping
    should_consult() there) and observing this test still passes. Isolating
    the arming site specifically needs a white-box check (e.g. a debug counter
    or log line asserting brk_armed stayed 0), not a black-box HTTP fetch
    through both sites.

    /breakeron/ and /breakeroff/ are identical apart from the flag itself.

    threshold=1 means one failing response trips CLOSED -> OPEN, but that
    trip is recorded by the header filter AFTER the response is already
    built, so the failing request that does the tripping still gets the raw
    origin error itself; only the NEXT request finds the breaker OPEN at the
    pre-origin gate and can be served the fallback. Hence two dead-origin
    fetches per location below: the first trips (and is asserted to reach
    the dead origin, i.e. NOT 200), the second observes the tripped state."""
    for path in ("/breakeron/dead", "/breakeroff/dead"):
        s0, b0, _ = fetch(ng.port, path)
        assert s0 == 200, f"prime failed for {path}: {s0}"
        assert b0, f"prime returned an empty body for {path}"

    time.sleep(1.3)   # past fresh (1s), stale_mult 1 -> 1s window: L1-expired
    origin.fail = True
    try:
        s_trip, _, _ = fetch(ng.port, "/breakeron/dead")
        assert s_trip != 200, \
            (f"breaker ON: the tripping request itself was answered 200 -- "
             f"expected it to reach the (dead) origin and fail, got {s_trip}")

        s_on, _b_on, _ = fetch(ng.port, "/breakeron/dead")
        assert s_on == 200, \
            (f"breaker ON: expired entry + dead origin did not fall back to "
             f"the breaker's any-age snapshot after tripping, got {s_on}")

        s_off_trip, _, _ = fetch(ng.port, "/breakeroff/dead")
        assert s_off_trip != 200, \
            f"breaker OFF: tripping request unexpectedly 200: {s_off_trip}"

        s_off, _, _ = fetch(ng.port, "/breakeroff/dead")
        assert s_off != 200, \
            ("breaker OFF: a dead origin was still answered 200 from a stale "
             "snapshot -- cache_turbo_breaker off did not disable arming at "
             "the L1-expired call site")
    finally:
        origin.fail = False
        drain_origin(origin)


def test_breaker_shipped_default_trips_and_serves_stale(ng: Nginx, origin: Origin) -> None:
    """S231-DEFAULTS: `/brkdefault/` sets NO cache_turbo_breaker/threshold/
    window directives at all -- proves the compiled-in merge defaults are
    breaker_enable=1, breaker_threshold=5, breaker_window=10s, not just that
    writing them out explicitly works (test_breaker_arming_gated_on_breaker_enable
    above covers the explicit threshold=1 case). Before S231-DEFAULTS this
    location would have behaved like /breakeroff/ (breaker_enable merge
    default was 0/off) -- a dead origin behind it would never fall back to a
    stale snapshot, no matter how many times it failed.

    threshold=5 means FIVE failing responses are needed to trip CLOSED ->
    OPEN, one more than /breakeron/'s threshold=1 -- so this drives five
    tripping fetches (all still reaching the dead origin, i.e. NOT 200)
    before the sixth observes the tripped state and gets the breaker's
    any-age stale fallback instead of the origin's error.

    /brkdefault/ pins `cache_turbo_keep_stale off` explicitly: keep_stale is
    ALSO on by default now (S231-DEFAULTS, 24h), and left at ITS default it
    would serve the expired entry back via S2.2's serve-on-error fallback on
    every one of the five tripping fetches, so none of them would ever reach
    the origin and the breaker would never see a failure to count. Pinning it
    off isolates the breaker default from the keep_stale default -- confirmed
    by the first version of this test failing exactly that way (200 on the
    very first tripping fetch) before this override was added."""
    s0, b0, _ = fetch(ng.port, "/brkdefault/dead")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    time.sleep(1.3)   # past fresh (1s), stale_mult 1 -> 1s window: L1-expired
    origin.fail = True
    try:
        for i in range(5):
            s_trip, _, _ = fetch(ng.port, "/brkdefault/dead")
            assert s_trip != 200, \
                (f"shipped breaker default: tripping request {i + 1}/5 was "
                 f"answered 200 -- expected it to reach the (dead) origin and "
                 f"fail, got {s_trip}")

        s_open, b_open, _ = fetch(ng.port, "/brkdefault/dead")
        assert s_open == 200, \
            (f"shipped breaker default: expired entry + dead origin did not "
             f"fall back to the breaker's any-age snapshot after 5 failures "
             f"tripped it, got {s_open}")
        assert b_open == b0, f"served {b_open!r}, expected stale {b0!r}"
    finally:
        origin.fail = False
        drain_origin(origin)


def test_breaker_counters(ng: Nginx, origin: Origin) -> None:
    """S7.1: breaker_serves counts responses actually delivered from the
    breaker's armed fallback (STALE-BREAKER), and origin_failures counts
    origin responses recorded as a failure by the breaker -- not every
    request through a breaker-enabled location.

    Same two-fetch trip sequence as test_breaker_arming_gated_on_breaker_enable
    (threshold=1, so the FIRST dead-origin request trips CLOSED->OPEN and
    still surfaces the raw origin failure itself; the SECOND finds the
    breaker OPEN and is served the fallback), but on the private s71z zone
    with its own admin endpoint so the deltas cannot be polluted by
    /breakeron/ or /brkion/, which have already tripped their own breakers by
    the time this runs in run_all()'s ordering.

    origin_failures must move on the FIRST (tripping) fetch -- that is the
    request whose 5xx status actually reaches ngx_http_cache_turbo_breaker_is_
    origin_failure() and feeds _breaker_record(). breaker_serves must NOT
    move on that fetch (nothing is armed/served from the breaker yet -- the
    origin's own error passes through) and MUST move on the second."""
    s0, b0, _ = fetch(ng.port, "/s71brk/dead")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    time.sleep(1.3)   # past fresh (1s), stale_mult 1 -> 1s window: L1-expired
    origin.fail = True
    try:
        of_before = _admin_stat(ng, "origin_failures", "/_cache_s71")
        bs_before = _admin_stat(ng, "breaker_serves", "/_cache_s71")

        s_trip, _, _ = fetch(ng.port, "/s71brk/dead")
        assert s_trip != 200, \
            (f"tripping request was answered 200 -- expected it to reach "
             f"the dead origin and fail, got {s_trip}")

        of_trip = _admin_stat(ng, "origin_failures", "/_cache_s71")
        bs_trip = _admin_stat(ng, "breaker_serves", "/_cache_s71")
        assert of_trip - of_before > 0, \
            "origin_failures did not move on the origin failure that tripped the breaker"
        assert bs_trip == bs_before, \
            (f"breaker_serves moved on the TRIPPING request, which surfaces "
             f"the raw origin error and serves nothing from the breaker -- "
             f"{bs_before} -> {bs_trip}")

        s_on, _, _ = fetch(ng.port, "/s71brk/dead")
        assert s_on == 200, \
            f"breaker OPEN did not fall back to the any-age snapshot, got {s_on}"

        bs_after = _admin_stat(ng, "breaker_serves", "/_cache_s71")
        assert bs_after - bs_trip > 0, \
            "breaker_serves did not move on the STALE-BREAKER fallback serve"
    finally:
        origin.fail = False
        drain_origin(origin)


def test_breaker_retry_after_auto_tracks_breaker_open(ng: Nginx, origin: Origin) -> None:
    """BRK-RA1 regression pin: cache_turbo_breaker_retry_after, left unset,
    must track the EFFECTIVE cache_turbo_breaker_open for that location, not
    the module-wide 30s default.

    The bug: ngx_conf_merge_sec_value(conf->breaker_retry_after,
    prev->breaker_retry_after, conf->breaker_open) only falls back to
    conf->breaker_open when prev->breaker_retry_after is itself UNSET. nginx
    merges the enclosing server{} loc_conf against http FIRST, before any
    location merge. Nothing in this config sets breaker_retry_after at
    server scope, so that level resolves to http's breaker_open default
    (30) -- NOT UNSET. Every child location that also leaves it unset (like
    /ra1/ here, breaker_open 2s) then inherits prev->breaker_retry_after ==
    30, not UNSET, so its own breaker_open is never consulted and the
    BREAKER-503 sends Retry-After: 30 instead of 2.

    Own zone (raz), same two-fetch trip shape as test_breaker_counters /
    test_serve_reason_variable (threshold=1: the first dead-origin fetch
    trips CLOSED->OPEN and still surfaces the raw origin failure; only the
    SECOND finds the breaker OPEN). /ra1/never is a COLD url -- never
    primed -- so once the breaker is OPEN it has no snapshot of any age and
    falls straight into ngx_http_cache_turbo_breaker_unavailable(), the
    local 503 whose Retry-After header is under test.

    /ra1exp/ is the positive control: identical shape, but with an EXPLICIT
    cache_turbo_breaker_retry_after 7s. That must still win -- proves the
    fix resolves the UNSET case lazily without disturbing the explicit
    path."""
    s0, b0, _ = fetch(ng.port, "/ra1/dead")
    assert s0 == 200 and b0, f"prime failed for /ra1/dead: {s0} {b0!r}"

    time.sleep(1.3)   # past fresh (1s), stale_mult 1 -> 1s window: L1-expired
    origin.fail = True
    try:
        s_trip, _, _ = fetch(ng.port, "/ra1/dead")
        assert s_trip != 200, \
            (f"tripping request was answered 200 -- expected it to reach "
             f"the dead origin and fail, got {s_trip}")

        s_503, _, h_503 = fetch(ng.port, "/ra1/never")
        assert s_503 == 503, \
            f"breaker OPEN + no cached copy should 503, got {s_503}"
        assert h_503.get("retry-after") == "2", \
            (f"auto-tracked Retry-After should equal this location's own "
             f"cache_turbo_breaker_open (2s), got "
             f"{h_503.get('retry-after')!r} -- BRK-RA1: breaker_retry_after "
             f"inherited the module-wide 30s default instead of tracking "
             f"the effective breaker_open")
    finally:
        origin.fail = False
        drain_origin(origin)

    # Positive control: explicit cache_turbo_breaker_retry_after still wins.
    s0e, b0e, _ = fetch(ng.port, "/ra1exp/dead")
    assert s0e == 200 and b0e, f"prime failed for /ra1exp/dead: {s0e} {b0e!r}"

    time.sleep(1.3)   # past fresh (1s), stale_mult 1 -> 1s window: L1-expired
    origin.fail = True
    try:
        s_trip_e, _, _ = fetch(ng.port, "/ra1exp/dead")
        assert s_trip_e != 200, \
            (f"tripping request was answered 200 -- expected it to reach "
             f"the dead origin and fail, got {s_trip_e}")

        s_503e, _, h_503e = fetch(ng.port, "/ra1exp/never")
        assert s_503e == 503, \
            f"breaker OPEN + no cached copy should 503, got {s_503e}"
        assert h_503e.get("retry-after") == "7", \
            (f"explicit cache_turbo_breaker_retry_after must win over the "
             f"derived default, got {h_503e.get('retry-after')!r}")
    finally:
        origin.fail = False
        drain_origin(origin)


def test_prometheus_breaker_metrics(ng: Nginx, origin: Origin) -> None:
    """H7.3a: cache_turbo_breaker_opens_total and cache_turbo_breaker_state
    are emitted on the Prometheus surface, not just the admin JSON.

    Own private zone (h73z) and admin endpoint (/_cache_h73), same shape as
    /s71brk/ + /_cache_s71 (test_breaker_counters above) -- NOT a reuse of
    s71z, because s71z's breaker is already OPEN by the time run_all() gets
    here (test_breaker_counters trips it and never resets it), which would
    make this test's own prime fetch fail before the assertions under test
    even run.

    Two claims:
      1. cache_turbo_breaker_opens_total{zone="h73z"} moves by exactly one
         on the tripping request (CLOSED -> OPEN, threshold=1).
      2. cache_turbo_breaker_state{zone="h73z"} reads the OPEN numeric value
         (NGX_HTTP_CACHE_TURBO_BREAKER_OPEN == 1, module.h) while OPEN, and
         is back to CLOSED (0) beforehand.
    """
    import re

    def _prom_int(body: str, metric: str, zone: str = "h73z") -> int:
        m = re.search(
            r'cache_turbo_%s\{zone="%s"\} (\d+)' % (re.escape(metric), zone),
            body)
        assert m, f"no {metric} sample for zone={zone}:\n{body[:400]}"
        return int(m.group(1))

    s0, b0, _ = fetch(ng.port, "/h73brk/prom")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    time.sleep(1.3)   # past fresh (1s), stale_mult 1 -> 1s window: L1-expired
    origin.fail = True
    try:
        _, prom_before, _ = fetch(ng.port, "/_cache_h73?format=prometheus")
        opens_before = _prom_int(prom_before, "breaker_opens_total")
        state_before = _prom_int(prom_before, "breaker_state")
        assert state_before == 0, (
            f"breaker_state should read CLOSED (0) before the trip, got "
            f"{state_before}")

        s_trip, _, _ = fetch(ng.port, "/h73brk/prom")
        assert s_trip != 200, \
            (f"tripping request was answered 200 -- expected it to reach "
             f"the dead origin and fail, got {s_trip}")

        _, prom_after, _ = fetch(ng.port, "/_cache_h73?format=prometheus")
        opens_after = _prom_int(prom_after, "breaker_opens_total")
        state_after = _prom_int(prom_after, "breaker_state")

        assert opens_after - opens_before == 1, (
            f"cache_turbo_breaker_opens_total did not move by exactly one "
            f"on the CLOSED->OPEN trip: {opens_before} -> {opens_after}")
        assert state_after == 1, (
            f"cache_turbo_breaker_state should report OPEN (1) once tripped, "
            f"got {state_after}")

        s_on, _, _ = fetch(ng.port, "/h73brk/prom")
        assert s_on == 200, \
            f"breaker OPEN did not fall back to the any-age snapshot, got {s_on}"
    finally:
        origin.fail = False
        drain_origin(origin)
