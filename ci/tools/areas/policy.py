"""cache-turbo runtime tests — policy area.

Split out of ci/tools/test_runtime.py (MAINT-T1). Tests live here; the fixtures,
Origin/Nginx harness and helpers stay in test_runtime_base. test_runtime
star-imports this module, so every test stays reachable as
``test_runtime.<name>`` (run_named.py) and as a bare name inside run_all()
(lint-orphan-tests.py).
"""

from __future__ import annotations

# Underscore-prefixed names are NOT re-exported by `import *`, so the
# private helpers this module actually calls are imported explicitly.
from test_runtime_base import *  # noqa: F401,F403
from test_runtime_base import (  # noqa: F401
    _bump_conn,
)


def test_no_cache_set_cookie(ng: Nginx) -> None:
    """RFC 9111 floor: a Set-Cookie response is never stored (it carries
    per-client state) — repeated reads keep hitting the origin."""
    s1, b1, h1 = fetch(ng.port, "/cc/setcookie")
    assert s1 == 200 and "x-cache" not in h1, "first read should be a miss"
    _s2, b2, h2 = fetch(ng.port, "/cc/setcookie")
    assert "x-cache" not in h2, "Set-Cookie response must not be cached"
    assert b1 != b2, "both reads should have gone to the origin"


def test_no_cache_cc_private(ng: Nginx) -> None:
    """RFC 9111 floor: Cache-Control: private is not stored in a shared cache."""
    _, b1, h1 = fetch(ng.port, "/cc/ccprivate")
    assert "x-cache" not in h1
    _, b2, h2 = fetch(ng.port, "/cc/ccprivate")
    assert "x-cache" not in h2, "Cache-Control: private must not be cached"
    assert b1 != b2


def test_no_cache_cc_nostore(ng: Nginx) -> None:
    """RFC 9111 floor: Cache-Control: no-store is never stored."""
    _, b1, h1 = fetch(ng.port, "/cc/ccnostore")
    assert "x-cache" not in h1
    _, b2, h2 = fetch(ng.port, "/cc/ccnostore")
    assert "x-cache" not in h2, "Cache-Control: no-store must not be cached"
    assert b1 != b2


def test_no_cache_authorization(ng: Nginx) -> None:
    """RFC 9111 floor: a request carrying Authorization yields a per-user
    response that must not be stored in or served from the shared cache,
    including when an anonymous representation was already primed."""
    hdr = {"Authorization": "Bearer secrettoken"}

    # Prime an anonymous representation first. A store-only Authorization guard
    # misses this case and would replay the anonymous HIT to the credentialed
    # request.
    _, anon, _ = fetch(ng.port, "/c/authreq-primed")
    _, anon_hit, hp = fetch(ng.port, "/c/authreq-primed")
    assert hp.get("x-cache") == "HIT" and anon_hit == anon
    _, auth_body, ha = fetch(ng.port, "/c/authreq-primed", headers=hdr)
    assert "x-cache" not in ha, \
        "Authorization request was served a primed anonymous cache entry"
    assert auth_body != anon, "authorized request did not reach the origin"

    # A cold authorized request must also remain uncacheable.
    _, b1, h1 = fetch(ng.port, "/c/authreq-cold", headers=hdr)
    assert "x-cache" not in h1
    _, b2, h2 = fetch(ng.port, "/c/authreq-cold", headers=hdr)
    assert "x-cache" not in h2, "Authorization request must not be cached"
    assert b1 != b2


def test_default_key_varies_by_host(ng: Nginx) -> None:
    """Default key (no cache_turbo_key) is $host$request_uri: the same path
    under two Host headers must NOT collide (cross-vhost poisoning guard)."""
    s1, b1, h1 = fetch(ng.port, "/dk/hostvary", headers={"Host": "a.example"})
    assert s1 == 200 and "x-cache" not in h1, "first read should be a miss"
    _, b2, h2 = fetch(ng.port, "/dk/hostvary", headers={"Host": "a.example"})
    assert h2.get("x-cache") == "HIT" and b2 == b1, "same Host should HIT"
    _, b3, h3 = fetch(ng.port, "/dk/hostvary", headers={"Host": "b.example"})
    assert "x-cache" not in h3, "different Host must not collide"
    assert b3 != b1, "second Host served the first Host's cached body"


def test_admin_purge_post_with_body(ng: Nginx) -> None:
    """A purge POST carrying a request body must succeed (the handler discards
    the body) — otherwise the unread bytes would desync a keepalive socket."""
    import json
    fetch(ng.port, "/c/bodypurge")                     # miss -> cached
    _, _, h = fetch(ng.port, "/c/bodypurge")
    assert h.get("x-cache") == "HIT", "should be cached before purge"
    req = urllib.request.Request(
        f"http://127.0.0.1:{ng.port}/_cache?key=/c/bodypurge",
        data=b"x" * 256, method="POST",
        headers={"Connection": "close"})
    _bump_conn()
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
        assert r.status == 200, f"purge-with-body status {r.status}"
        assert json.loads(r.read())["purged"] == 1
    _, _, h2 = fetch(ng.port, "/c/bodypurge")
    assert "x-cache" not in h2, "entry should be gone after purge (a MISS)"


def test_default_key_normalizes(ng: Nginx) -> None:
    """The default key (no cache_turbo_key) is $host$uri$cache_turbo_normalized_args,
    so tracking params and the built-in sid/sessionid are stripped: a junk-laden
    URL shares the clean slot."""
    _, b1, h1 = fetch(ng.port, "/dk/norm?utm_source=x&sid=42&sessionid=abc")
    assert "x-cache" not in h1, "first should miss"
    _, b2, h2 = fetch(ng.port, "/dk/norm")
    assert h2.get("x-cache") == "HIT" and b2 == b1, \
        "default key should strip tracking + sid/sessionid to one slot"


def test_cache_redirect(ng: Nginx) -> None:
    """v6: a 301 (empty body) is cached and replayed with its Location intact."""
    s1, _, h1 = fetch_raw(ng.port, "/st/redir")
    assert s1 == 301 and "x-cache" not in h1, f"first 301 should miss: {s1} {h1}"
    loc1 = h1.get("location")
    s2, _, h2 = fetch_raw(ng.port, "/st/redir")
    assert s2 == 301 and h2.get("x-cache") == "HIT", \
        f"second 301 should be a HIT: {s2} {h2.get('x-cache')}"
    assert h2.get("location") == loc1, \
        f"Location not preserved on cached 301: {h2.get('location')} vs {loc1}"


def test_cache_negative_404(ng: Nginx) -> None:
    """v6: a 404 is cached (negative caching) — the body is preserved on HIT."""
    s1, b1, h1 = fetch_raw(ng.port, "/st/notfound")
    assert s1 == 404 and "x-cache" not in h1, f"first 404 should miss: {s1}"
    s2, b2, h2 = fetch_raw(ng.port, "/st/notfound")
    assert s2 == 404 and h2.get("x-cache") == "HIT", "second 404 should HIT"
    assert b1 == b2 and b2, f"404 body not preserved: {b1!r} vs {b2!r}"


def test_head_not_stored(ng: Nginx) -> None:
    """v6: a HEAD must never populate the cache as the GET entry — the following
    GET is still a MISS (and then caches normally)."""
    sh, _, hh = fetch_raw(ng.port, "/c/headonly", method="HEAD")
    assert sh == 200, f"HEAD status {sh}"
    assert "x-cache" not in hh, "HEAD should not be served from cache here"
    _, _, h1 = fetch_raw(ng.port, "/c/headonly", method="GET")
    assert "x-cache" not in h1, "GET after HEAD should still be a MISS"
    _, _, h2 = fetch_raw(ng.port, "/c/headonly", method="GET")
    assert h2.get("x-cache") == "HIT", "GET should cache normally after the HEAD"


def test_honor_cache_control(ng: Nginx) -> None:
    """v7: with cache_turbo_cache_control honor, the origin's max-age=1 shortens
    the fresh TTL below the configured 60s — so the entry is stale at ~2s."""
    _, _, h0 = fetch(ng.port, "/cc7/ttl1")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/cc7/ttl1")
    assert h1.get("x-cache") == "HIT", "second should be a fresh HIT (<1s)"
    time.sleep(2.0)                               # past max-age=1, within stale
    _, _, h2 = fetch(ng.port, "/cc7/ttl1")
    assert h2.get("x-cache") == "STALE", \
        ("honor_cache_control: entry should be STALE at 2s (max-age=1 < 60s), "
         f"got {h2.get('x-cache')}")


def test_honor_expires_absolute_ttl(ng: Nginx) -> None:
    """upstream_ttl ladder step 4 (module.c Expires branch): a response with NO
    Cache-Control/CDN-CC/Surrogate-Control, only an absolute Expires ~2s out,
    must derive its fresh TTL from Expires-minus-now — NOT from the configured
    cache_turbo_valid 60s (which would keep it fresh). STALE at ~3.5s (past the
    2s Expires window, staleness >=1s so the 1s-granularity check is unambiguous)
    proves the Expires arm set the window."""
    _, _, h0 = fetch(ng.port, "/cc7/expabs")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/cc7/expabs")
    assert h1.get("x-cache") == "HIT", "second should be a fresh HIT (<2s)"
    time.sleep(3.5)                               # past the 2s Expires, staleness >=1s
    _, _, h2 = fetch(ng.port, "/cc7/expabs")
    assert h2.get("x-cache") == "STALE", \
        ("Expires-derived TTL (~2s) must win over cache_turbo_valid 60s: "
         f"entry should be STALE at ~3.5s, got {h2.get('x-cache')}")


def test_cdn_cache_control_ttl_outranks_cache_control(ng: Nginx) -> None:
    """RFC 9213: CDN-Cache-Control sets the shared-cache TTL and must OUTRANK the
    browser-facing Cache-Control. Origin: CC max-age=60, CDN-CC max-age=1 (via the
    /cc7/ honor location). The entry must be STALE at ~2s (the 1s CDN TTL won),
    not fresh (which the 60s CC would give)."""
    _, _, h0 = fetch(ng.port, "/cc7/cdnttl")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/cc7/cdnttl")
    assert h1.get("x-cache") == "HIT", "second should be a fresh HIT (<1s)"
    time.sleep(2.0)                               # past CDN max-age=1, within stale
    _, _, h2 = fetch(ng.port, "/cc7/cdnttl")
    assert h2.get("x-cache") == "STALE", \
        ("CDN-Cache-Control max-age=1 must outrank Cache-Control max-age=60: "
         f"entry should be STALE at 2s, got {h2.get('x-cache')}")


def test_surrogate_control_ttl_outranks_cdn_and_cache_control(ng: Nginx) -> None:
    """RFC 9213: Surrogate-Control (Fastly/Akamai) is the highest-priority TTL
    source, above CDN-Cache-Control and Cache-Control. Origin: SC max-age=1,
    CDN-CC max-age=60, CC max-age=60. STALE at ~2s proves SC's 1s won."""
    _, _, h0 = fetch(ng.port, "/cc7/scttl")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/cc7/scttl")
    assert h1.get("x-cache") == "HIT", "second should be a fresh HIT (<1s)"
    time.sleep(2.0)
    _, _, h2 = fetch(ng.port, "/cc7/scttl")
    assert h2.get("x-cache") == "STALE", \
        ("Surrogate-Control max-age=1 must outrank CDN-CC=60 and CC=60: entry "
         f"should be STALE at 2s, got {h2.get('x-cache')}")


def test_surrogate_control_split_header_ttl(ng: Nginx) -> None:
    """AUD2-CC-TARGETED: Surrogate-Control split across TWO field-lines
    (/cc7/scsplit) -- stale-while-revalidate=30 on the first, max-age=1 on the
    SECOND. header_find() only sees the first occurrence; a single-line TTL
    read would miss max-age entirely and fall through to Cache-Control's 60s,
    caching far longer than Surrogate-Control authorized. STALE at ~2s proves
    the second SC line's max-age=1 won, not CC's 60s."""
    _, _, h0 = fetch(ng.port, "/cc7/scsplit")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/cc7/scsplit")
    assert h1.get("x-cache") == "HIT", "second should be a fresh HIT (<1s)"
    time.sleep(2.0)                               # past SC max-age=1 (2nd line)
    _, _, h2 = fetch(ng.port, "/cc7/scsplit")
    assert h2.get("x-cache") == "STALE", \
        ("Surrogate-Control max-age on a later field-line must not be ignored: "
         f"entry should be STALE at 2s (SC max-age=1), got {h2.get('x-cache')} "
         "(a single-line reader would wrongly stay fresh on CC max-age=60)")


def test_cdn_cache_control_split_header_ttl(ng: Nginx) -> None:
    """AUD2-CC-TARGETED: CDN-Cache-Control split across TWO field-lines
    (/cc7/cdnsplit) -- stale-while-revalidate=30 on the first, max-age=1 on the
    SECOND. Same defect as scsplit but for ladder arm 2. STALE at ~2s proves
    the second CDN-CC line's max-age=1 won over Cache-Control's 60s."""
    _, _, h0 = fetch(ng.port, "/cc7/cdnsplit")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/cc7/cdnsplit")
    assert h1.get("x-cache") == "HIT", "second should be a fresh HIT (<1s)"
    time.sleep(2.0)                               # past CDN-CC max-age=1 (2nd line)
    _, _, h2 = fetch(ng.port, "/cc7/cdnsplit")
    assert h2.get("x-cache") == "STALE", \
        ("CDN-Cache-Control max-age on a later field-line must not be ignored: "
         f"entry should be STALE at 2s (CDN-CC max-age=1), got "
         f"{h2.get('x-cache')} (a single-line reader would wrongly stay fresh "
         "on CC max-age=60)")


def test_cdn_cache_control_no_store_refuses(ng: Nginx) -> None:
    """RFC 9213: a targeted CDN-Cache-Control: no-store must veto the shared store
    even though plain Cache-Control (max-age=60) would permit it. The /cc7/ honor
    location reads both; the response must never become a HIT."""
    _, _, h0 = fetch(ng.port, "/cc7/cdnnostore")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/cc7/cdnnostore")
    assert "x-cache" not in h1, \
        ("CDN-Cache-Control: no-store must refuse the shared store despite "
         f"Cache-Control max-age=60, got X-Cache={h1.get('x-cache')}")


def test_targeted_cache_control_stripped_from_serve(ng: Nginx) -> None:
    """RFC 9213: the shared cache is the intended consumer of CDN-Cache-Control /
    Surrogate-Control, so they must be stripped before store and never replayed to
    a downstream client on a HIT (same as the Age strip). Origin sends both on a
    cacheable response; the cached HIT must carry neither."""
    _, _, h0 = fetch(ng.port, "/cc7/cdnstrip")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/cc7/cdnstrip")
    assert h1.get("x-cache") == "HIT", f"second should be a HIT, got {h1}"
    assert "cdn-cache-control" not in h1, \
        "CDN-Cache-Control must be stripped from the served HIT"
    assert "surrogate-control" not in h1, \
        "Surrogate-Control must be stripped from the served HIT"


def test_age_header(ng: Nginx) -> None:
    """RFC 9111 5.1: a cache HIT carries an Age header counting seconds since the
    representation was stored. It must grow with wall-clock age."""
    _, _, h0 = fetch(ng.port, "/c/age-test")
    assert "x-cache" not in h0, "first should miss"
    time.sleep(1.2)
    _, _, h1 = fetch(ng.port, "/c/age-test")
    assert h1.get("x-cache") == "HIT", f"second should be a HIT, got {h1}"
    assert "age" in h1, "cache HIT must carry an Age header"
    age = int(h1["age"])
    assert age >= 1, f"Age should be >=1s after a 1.2s wait, got {age}"


def test_must_revalidate_split_header(ng: Nginx) -> None:
    """AUD-CC-FIRST-LINE: same must-revalidate collapse as test_must_revalidate,
    but the origin (/ccsplit/, splitmrev marker) emits max-age and
    must-revalidate on TWO separate Cache-Control field-lines. HTTP allows a
    field to repeat across field-lines (RFC 9110 SS5.3), equivalent to one
    comma-joined line -- a reader that only inspects the first Cache-Control
    line would miss the must-revalidate token on the second and wrongly
    stale-serve past freshness."""
    _, _, h0 = fetch(ng.port, "/ccsplit/splitmrev")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/ccsplit/splitmrev")
    assert h1.get("x-cache") == "HIT", f"second should be a fresh HIT, got {h1}"
    time.sleep(2.0)                               # past max-age=1
    _, _, h2 = fetch(ng.port, "/ccsplit/splitmrev")
    assert h2.get("x-cache") != "STALE", \
        ("must-revalidate on a later Cache-Control field-line must NOT be "
         f"ignored, got {h2.get('x-cache')}")
    assert "x-cache" not in h2, \
        "must-revalidate (2nd field-line) should re-fetch from origin once stale"


def test_request_no_cache(ng: Nginx, origin: Origin) -> None:
    """RFC 9111 5.2.1.4: a request Cache-Control: no-cache skips the stored copy
    and revalidates at the origin (the fresh response still refreshes the entry).
    Pragma: no-cache behaves the same."""
    _, b0, _ = fetch(ng.port, "/c/nocache-req")            # miss -> origin
    _, _, h1 = fetch(ng.port, "/c/nocache-req")
    assert h1.get("x-cache") == "HIT", "entry should be primed"
    before = origin.hits
    _, b2, h2 = fetch(ng.port, "/c/nocache-req",
                      headers={"Cache-Control": "no-cache"})
    assert "x-cache" not in h2, \
        f"request no-cache must reach origin, got X-Cache={h2.get('x-cache')}"
    assert origin.hits == before + 1, "request no-cache must consult the origin"
    assert b2 != b0, "no-cache response should be a fresh origin generation"
    _, _, h3 = fetch(ng.port, "/c/nocache-req",
                     headers={"Pragma": "no-cache"})
    assert "x-cache" not in h3, "Pragma: no-cache must also reach the origin"


def test_must_revalidate(ng: Nginx) -> None:
    """RFC 9111: a must-revalidate response is served fresh until its deadline
    then re-fetched — never stale-served. Same setup as /cc7/ (which DOES stale-
    serve), proving the must-revalidate token collapses the stale window."""
    _, _, h0 = fetch(ng.port, "/mrev/mustrev")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/mrev/mustrev")
    assert h1.get("x-cache") == "HIT", f"second should be a fresh HIT, got {h1}"
    time.sleep(2.0)                               # past max-age=1
    _, _, h2 = fetch(ng.port, "/mrev/mustrev")
    assert h2.get("x-cache") != "STALE", \
        f"must-revalidate must NOT stale-serve past freshness, got {h2.get('x-cache')}"
    assert "x-cache" not in h2, \
        "must-revalidate should re-fetch from origin once stale"


def test_proxy_revalidate(ng: Nginx) -> None:
    """RFC 9111: proxy-revalidate is the shared-cache synonym of must-revalidate
    and MUST collapse the stale window identically. Exercises the OR-arm of
    response_must_revalidate (module.c:1142) that must-revalidate alone leaves
    uncovered. Same /mrev/ location, "proxyrev" origin arm emits
    "max-age=1, proxy-revalidate"."""
    _, _, h0 = fetch(ng.port, "/mrev/proxyrev")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/mrev/proxyrev")
    assert h1.get("x-cache") == "HIT", f"second should be a fresh HIT, got {h1}"
    time.sleep(2.0)                               # past max-age=1
    _, _, h2 = fetch(ng.port, "/mrev/proxyrev")
    assert h2.get("x-cache") != "STALE", \
        f"proxy-revalidate must NOT stale-serve past freshness, got {h2.get('x-cache')}"
    assert "x-cache" not in h2, \
        "proxy-revalidate should re-fetch from origin once stale"


def test_precise_maxage_token_parse(ng: Nginx) -> None:
    """Full-token Cache-Control parse: max-age=01000 is 1000s (cacheable), it must
    NOT trip the old substring 'max-age=0' uncacheable check; max-age=0 is still
    refused."""
    _, _, h0 = fetch(ng.port, "/cc/ccpad")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/cc/ccpad")
    assert h1.get("x-cache") == "HIT", \
        f"max-age=01000 must be cacheable (1000s), got X-Cache={h1.get('x-cache')}"

    fetch(ng.port, "/cc/ccmaxage0")                        # prime attempt
    _, _, h2 = fetch(ng.port, "/cc/ccmaxage0")
    assert "x-cache" not in h2, "max-age=0 must not be stored in a shared cache"


def test_ignore_cache_control_overrides_floor(ng: Nginx, origin: Origin) -> None:
    """cache_turbo_cache_control ignore makes the response Cache-Control floor
    a no-op: a max-age=0 response (the ccmaxage0 marker) that /cc/ refuses to
    store is STORED under /ccign/ and served as a HIT at cache_turbo_valid.
    Mirrors nginx `proxy_ignore_headers Cache-Control`. The Set-Cookie floor is
    unaffected (covered by the /cc/ccsetcookie case)."""
    fetch(ng.port, "/ccign/ccmaxage0")                     # prime (miss, stores)
    _, _, h = fetch(ng.port, "/ccign/ccmaxage0")
    assert h.get("x-cache") == "HIT", \
        ("ignore_cache_control must store a max-age=0 response and HIT; got "
         f"X-Cache={h.get('x-cache')}")


def test_ignore_cc_must_revalidate_keeps_stale_window(ng: Nginx,
                                                      origin: Origin) -> None:
    """cache_turbo_cache_control ignore must neutralise the WHOLE response
    Cache-Control, including the must-revalidate token that would otherwise
    collapse the stale window at store. The origin emits
    "max-age=1, must-revalidate"; under /ccignmr/ (ignore_cc on, valid 2s, default
    stale_mult 4 => 8s total serve life = 2s fresh + 6s stale) the entry must
    still be STALE-served at ~4s. Without the fix (must-revalidate parsed despite
    ignore_cc) the serve deadline collapses to the 2s fresh deadline and the 4s
    read is a hard miss to origin. Inverse of test_must_revalidate (the /mrev/
    honor_cc case).

    !! The 2s fresh TTL is deliberate and paired with the 4s sleep below; see
    the /ccignmr/ fixture comment. Do not shrink either one independently."""
    uri = "/ccignmr/mustrev"
    fetch(ng.port, uri)                                    # prime (miss, stores)
    _, _, h1 = fetch(ng.port, uri)
    assert h1.get("x-cache") == "HIT", \
        f"ignore_cc must store the must-revalidate response; got {h1.get('x-cache')}"
    time.sleep(4.0)                                        # past 2s fresh, < 8s deadline
    before = origin.hits
    _, _, h2 = fetch(ng.port, uri)
    assert h2.get("x-cache") == "STALE", \
        ("ignore_cc must keep the stale window (must-revalidate ignored): expected "
         f"STALE at 4s, got X-Cache={h2.get('x-cache')} — window was collapsed")
    assert origin.hits == before, \
        "stale serve under ignore_cc unexpectedly hit origin (window collapsed?)"


def test_hits_for_exact_beyond_ring_size(ng: Nginx, origin: Origin) -> None:
    """hits_for() must be an EXACT per-path count, not an approximation that
    degrades once a window spans more than 64 origin contacts.

    Origin._paths is a diagnostics-only ring hard-trimmed to the last 64
    entries (do_GET/do_POST: `if len(origin._paths) > 64: del
    origin._paths[:-64]`; do_HEAD counts but does not append) for
    _recent_memo_skips()/the SUITE-1 dump. Before
    hits_for() was backed by a real Counter, it summed that ring directly, so
    any window driving more than 64 TOTAL origin contacts (this path or any
    other -- the ring is global, not per-path) silently undercounted: the
    oldest hits on THIS path fall off the ring the moment other traffic pushes
    the ring past 64 entries.

    This drives 80 direct GETs at the origin on one unique path (bypassing
    nginx entirely -- we're proving a property of the Origin test double
    itself, not the module) inside one window, i.e. 16 more contacts than the
    ring can hold, and asserts the exact delta. Under the old ring-summing
    implementation the delta reads <= 64 (16 short); under the Counter it is
    exactly 80."""
    needle = "hitsforring-" + uuid.uuid4().hex[:8]
    path = f"/{needle}"
    base = origin.hits_for(needle)
    n_contacts = 80
    assert n_contacts > 64, "control requires more contacts than the ring holds"
    # Borrow the delay to zero: 80 serial GETs at the suite's 0.05s baseline
    # would add ~4s to every full-suite run, and nothing here depends on a
    # regeneration window. Restored via reset_delay() in the finally, NOT to a
    # hardcoded 0.0 -- see reset_delay()'s docstring for the SUITE-8 bug that
    # shipped from exactly that mistake.
    origin.delay = 0
    try:
        for _ in range(n_contacts):
            status, _, _ = fetch(origin.port, path)
            assert status == 200, f"origin direct GET failed: status={status}"
    finally:
        origin.reset_delay()
    delta = origin.hits_for(needle) - base
    assert delta == n_contacts, (
        f"hits_for({needle!r}) delta must be exact: expected {n_contacts}, got "
        f"{delta}. A delta <= 64 means hits_for() is summing the trimmed "
        "diagnostics ring instead of a real per-path counter.")


def test_valid_zero_is_forever(ng: Nginx, origin: Origin) -> None:
    """cache_turbo_valid 0 == "cache forever": the stored entry must stay FRESH
    (a HIT), not become instantly stale. Pre-fix a literal 0 fresh TTL made the
    very next request a STALE serve and broke L2; now it resolves to a long
    finite TTL and behaves as a normal long-lived HIT."""
    # Path-scoped, NOT origin.hits: the global counter sees every other test's
    # traffic (and async bg-refresh subrequests) landing between the base capture
    # and the assertion below, which fails an equality bound that has nothing to
    # do with this location. That is a real failure mode, not a hypothetical --
    # it took down the ASan multi-worker arm on 28ae802 (SUITE-3), the slowest arm
    # and so the one with the widest window. Same fix as test_206_never_cached and
    # test_honor_ttl_clamped_to_max directly below.
    #
    # /!\ The needle is in the FILENAME, not the location prefix. /forever/ uses
    # `proxy_pass http://.../;` WITH a trailing slash, so nginx strips the prefix
    # and the origin only ever sees "/forever-f" -- hits_for("/forever/") matches
    # nothing and the assertion fails with the entry behaving perfectly. Same trap
    # as the /l2sie/ fixture (s121). This is why ttlclamp works: its needle is the
    # filename too.
    base = origin.hits_for("forever-f")
    _, b0, h0 = fetch(ng.port, "/forever/forever-f")
    assert "x-cache" not in h0, "first should miss to origin"
    _, b1, h1 = fetch(ng.port, "/forever/forever-f")
    assert h1.get("x-cache") == "HIT", \
        f"valid 0 must serve a FRESH HIT, got X-Cache={h1.get('x-cache')}"
    assert b1 == b0, "HIT served a different body"
    time.sleep(2.0)
    _, b2, h2 = fetch(ng.port, "/forever/forever-f")
    assert h2.get("x-cache") == "HIT", \
        f"valid 0 must still be fresh after a delay, got X-Cache={h2.get('x-cache')}"
    assert b2 == b0, "the 'forever' entry served a different body after the delay"
    assert origin.hits_for("forever-f") == base + 1, \
        "a 'forever' entry must not re-hit the origin while fresh"


def test_honor_ttl_clamped_to_max(ng: Nginx, origin: Origin) -> None:
    """STAB-5 TTL clamp (module.c:4873): honor mode reads an unbounded upstream
    max-age (~3170 years, > TTL_MAX 0xFFFFFFFF). The clamp caps it before the
    uint32 fresh_ttl cast and the stale-window multiply; without the clamp those
    could overflow/wrap the fresh window to a small or instantly-stale value.
    Observable proof: the entry stays a FRESH HIT (no re-hit to origin) rather
    than going stale — a wrapped TTL would surface as a STALE serve here."""
    base = origin.hits_for("ttlclamp")           # path-scoped: immune to bg-refresh noise
    _, _b0, h0 = fetch(ng.port, "/cc7/ttlclamp")
    assert "x-cache" not in h0, "first should miss to origin"
    _, _b1, h1 = fetch(ng.port, "/cc7/ttlclamp")
    assert h1.get("x-cache") == "HIT", \
        f"clamped huge max-age must serve a FRESH HIT, got {h1.get('x-cache')}"
    time.sleep(2.0)
    _, _b2, h2 = fetch(ng.port, "/cc7/ttlclamp")
    assert h2.get("x-cache") == "HIT", \
        ("clamped max-age must still be fresh after a delay (no overflow-to-stale), "
         f"got {h2.get('x-cache')}")
    assert origin.hits_for("ttlclamp") == base + 1, \
        "a TTL_MAX-clamped entry must not re-hit the origin while fresh"


def test_vary_encoding_qvalue(ng: Nginx, origin: Origin) -> None:
    """Accept-Encoding is tokenised, not substring-matched: `gzip;q=0` (the client
    REFUSES gzip) must NOT bucket as gzip, while `gzip;q=0.001` still does. Pre-fix
    the substring scan re-keyed a never-gzip client onto a gzip body."""
    base = origin.hits
    _, bg, hg = fetch(ng.port, "/ve/q", headers={"Accept-Encoding": "gzip"})
    assert "x-cache" not in hg, "first (gzip) request should miss"
    # gzip;q=0 => client refuses gzip => identity bucket => SEPARATE slot (miss)
    _, bz, hz = fetch(ng.port, "/ve/q",
                      headers={"Accept-Encoding": "gzip;q=0"})
    assert "x-cache" not in hz, \
        f"gzip;q=0 must NOT hit the gzip slot, got X-Cache={hz.get('x-cache')}"
    assert bz != bg, "gzip;q=0 was served the gzip body"
    assert origin.hits == base + 2, "gzip and gzip;q=0 should be distinct slots"
    # a positive q (even tiny) is still gzip => HIT the original gzip slot
    _, bq, hq = fetch(ng.port, "/ve/q",
                      headers={"Accept-Encoding": "gzip;q=0.001"})
    assert hq.get("x-cache") == "HIT", \
        f"gzip;q=0.001 must HIT the gzip slot, got X-Cache={hq.get('x-cache')}"
    assert bq == bg, "gzip;q=0.001 should share the gzip slot"
    assert origin.hits == base + 2, "gzip;q=0.001 wrongly hit origin"


def test_auto_vary_unknown_axis_uncacheable(ng: Nginx, origin: Origin) -> None:
    """auto-Vary: a response `Vary: Accept-Charset` names an axis the whitelist
    cannot key on (and is not *, Cookie, or Authorization). It must force the
    response uncacheable rather than serve one representation for every value
    (RFC 9110 12.5.5)."""
    base = origin.hits_for("/u?v=cs")
    _, _, h0 = fetch(ng.port, "/av/u?v=cs")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/av/u?v=cs")
    assert "x-cache" not in h1, \
        f"Vary on an un-keyable axis must stay uncacheable, got {h1.get('x-cache')}"
    assert origin.hits_for("/u?v=cs") == base + 2, "un-keyable Vary axis was wrongly cached"


def test_auto_vary_stale_marker_reachable(ng: Nginx, origin: Origin) -> None:
    """auto-Vary: once the variant and its L1 vary marker go stale (but are still
    inside the stale window), a request must still resolve to the variant via the
    stale marker and serve it from cache — not fall back to the base key and miss
    to origin (codex follow-up)."""
    ae = {"Accept-Encoding": "gzip"}
    _, _, h0 = fetch(ng.port, "/avs/m?v=ae", headers=ae)
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/avs/m?v=ae", headers=ae)
    assert h1.get("x-cache") == "HIT", f"second should HIT, got {h1.get('x-cache')}"
    time.sleep(2.5)                          # past the 2s fresh TTL, inside stale
    _, _, h2 = fetch(ng.port, "/avs/m?v=ae", headers=ae)
    assert "x-cache" in h2, \
        ("a stale-but-serveable variant must stay reachable via its stale marker, "
         f"got X-Cache={h2.get('x-cache')} (base-key fallback missed to origin)")


def test_206_never_cached(ng: Nginx, origin: Origin) -> None:
    """206 Partial Content must never be cached: the key carries no Range, so a
    stored partial could be replayed for a different/whole range. Every request
    reaches the origin.

    Uses a unique URL ("partial" substring still triggers the 206 branch) and a
    path-scoped hit count so a prior test's async background_update refresh can
    bump the global origin counter without polluting this exact-count assert
    (the historical CI flake)."""
    url = "/c/partial-206flake"
    base = origin.hits_for("partial-206flake")
    s0, _, h0 = fetch(ng.port, url)
    assert s0 == 206, f"origin should answer 206, got {s0}"
    assert "x-cache" not in h0, "first 206 should miss"
    s1, _, h1 = fetch(ng.port, url)
    assert s1 == 206 and "x-cache" not in h1, \
        f"206 must never be cached, got X-Cache={h1.get('x-cache')}"
    assert origin.hits_for("partial-206flake") == base + 2, \
        "206 was wrongly served from cache"


def test_range_hit_matches_miss(ng: Nginx, origin: Origin) -> None:
    """AUD-RANGE1: r->allow_ranges was never set on the restore/HIT path, so a
    Range request against a cached (<= max_size) entry silently fell back to a
    full 200 instead of the 206 a MISS to the same Range-capable origin
    returns. Warm one URL (plain GET, MISS, stores), then Range-GET it (HIT)
    and compare against Range-GET-ing a NEVER-cached URL (a fresh MISS that
    reaches the Range-capable origin directly) -- status, Content-Range and
    body bytes must match."""
    range_hdr = {"Range": "bytes=0-99"}

    # MISS reference: a URL never requested before, fetched WITH the Range
    # header. cache-turbo has nothing cached for it, so this reaches the
    # Range-capable origin directly and its 206 is relayed verbatim.
    s_miss, b_miss, h_miss = fetch_raw(ng.port, "/range/rngsrc-miss",
                                       headers=range_hdr)
    assert s_miss == 206, f"MISS with Range should be 206, got {s_miss}"
    assert "x-cache" not in h_miss, f"reference fetch should not HIT: {h_miss}"
    assert h_miss.get("content-range"), "MISS 206 must carry Content-Range"

    # Warm a SEPARATE url with a plain GET (no Range) so it gets cached as a
    # normal 200, Accept-Ranges: bytes included (the origin always sends it).
    s0, _, h0 = fetch_raw(ng.port, "/range/rngsrc-warm")
    assert s0 == 200 and "x-cache" not in h0, f"prime should miss: {s0} {h0}"
    assert h0.get("accept-ranges") == "bytes", \
        f"origin should advertise Accept-Ranges: {h0}"

    # Now Range-GET the warmed URL: cache-turbo serves it from cache (HIT).
    s_hit, b_hit, h_hit = fetch_raw(ng.port, "/range/rngsrc-warm",
                                    headers=range_hdr)
    assert h_hit.get("x-cache") == "HIT", f"second fetch should HIT: {h_hit}"
    assert s_hit == 206, \
        f"a Range request against a cache-turbo HIT must answer 206 like a " \
        f"MISS does, got {s_hit} (Accept-Ranges was replayed but the range " \
        f"was not honoured)"
    assert s_hit == s_miss, f"HIT status {s_hit} != MISS status {s_miss}"
    assert h_hit.get("content-range") == h_miss.get("content-range"), \
        f"HIT Content-Range {h_hit.get('content-range')!r} != " \
        f"MISS Content-Range {h_miss.get('content-range')!r}"
    assert b_hit == b_miss, \
        f"HIT partial body {b_hit!r} != MISS partial body {b_miss!r}"
    assert len(b_hit) == 100, f"bytes=0-99 should be 100 bytes, got {len(b_hit)}"


def test_range_suffix_hit_matches_miss(ng: Nginx, origin: Origin) -> None:
    """AUD-RANGE1, suffix form. test_range_hit_matches_miss covers only the
    prefix form (bytes=0-99). A suffix range (bytes=-N = the LAST N bytes) takes
    a different path through core's range parser, and the module's allow_ranges
    permit at module.c:6563 is what lets core answer it at all on a HIT. Same
    HIT-must-equal-MISS oracle: warm one URL with a plain GET, then suffix-Range
    it (HIT) and compare against suffix-Range-ing a never-cached URL (MISS).

    The comparison is against a MISS rather than a hardcoded expectation on
    purpose -- it pins HIT to whatever core+origin genuinely do for a suffix
    range, so this cannot pass by both paths being wrong the same way."""
    range_hdr = {"Range": "bytes=-50"}

    s_miss, b_miss, h_miss = fetch_raw(ng.port, "/range/rngsrc-sfxmiss",
                                       headers=range_hdr)
    assert s_miss == 206, f"MISS with suffix Range should be 206, got {s_miss}"
    assert "x-cache" not in h_miss, f"reference fetch should not HIT: {h_miss}"

    s0, _, h0 = fetch_raw(ng.port, "/range/rngsrc-sfxwarm")
    assert s0 == 200 and "x-cache" not in h0, f"prime should miss: {s0} {h0}"

    s_hit, b_hit, h_hit = fetch_raw(ng.port, "/range/rngsrc-sfxwarm",
                                    headers=range_hdr)
    assert h_hit.get("x-cache") == "HIT", f"second fetch should HIT: {h_hit}"
    assert s_hit == 206, \
        f"a suffix Range against a HIT must answer 206 like a MISS does, " \
        f"got {s_hit}"
    assert h_hit.get("content-range") == h_miss.get("content-range"), \
        f"HIT Content-Range {h_hit.get('content-range')!r} != " \
        f"MISS Content-Range {h_miss.get('content-range')!r}"
    assert b_hit == b_miss, \
        f"HIT suffix body {b_hit!r} != MISS suffix body {b_miss!r}"
    # The LAST 50 bytes, not the first 50: a mis-sliced suffix that still
    # returned 50 bytes would pass a length-only assert.
    assert len(b_hit) == 50, f"bytes=-50 should be 50 bytes, got {len(b_hit)}"
    assert h_hit.get("content-range") == "bytes 150-199/200", \
        f"bytes=-50 of a 200-byte body is 150-199, got " \
        f"{h_hit.get('content-range')!r}"


def test_range_unsatisfiable_hit_matches_miss(ng: Nginx,
                                              origin: Origin) -> None:
    """A Range wholly past the end of a cached body must be refused with a real
    416 response.

    Found a live defect. ngx_http_cache_turbo_serve() did:

        if (ngx_http_send_header(r) != NGX_OK) { return NGX_ERROR; }

    but a header filter may return a STATUS CODE, not just NGX_OK/NGX_ERROR:
    ngx_http_range_header_filter answers an unsatisfiable Range with
    NGX_HTTP_RANGE_NOT_SATISFIABLE (416), expecting the caller to finalize it
    into a 416. Collapsing that into NGX_ERROR produced
    ngx_http_finalize_request(r, -1) -- observed as the connection being CLOSED
    WITH NO RESPONSE AT ALL, while the same request against a MISS answered
    normally. Fixed to mirror the core contract in ngx_http_upstream.c
    (`rc == NGX_ERROR || rc > NGX_OK` -> finalize with rc).

    ⚠ This does NOT compare HIT against MISS, unlike its sibling Range tests.
    The test origin ignores an unsatisfiable Range and answers 200 with the full
    body, so a MISS here is a FIXTURE artifact, not the contract -- asserting
    HIT == MISS would pin the module to the stub origin's behaviour. 416 is
    asserted directly because it is what RFC 9110 6.5.4 requires and what core
    produces once the return value is honoured."""
    # The rngsrc body is 200 bytes, so bytes=500-599 cannot be satisfied.
    range_hdr = {"Range": "bytes=500-599"}

    s0, _, h0 = fetch_raw(ng.port, "/range/rngsrc-unsatwarm")
    assert s0 == 200 and "x-cache" not in h0, f"prime should miss: {s0} {h0}"

    s_hit, b_hit, _ = fetch_raw(ng.port, "/range/rngsrc-unsatwarm",
                                headers=range_hdr)
    assert s_hit == 416, \
        f"an unsatisfiable Range against a cached entry must answer 416, got " \
        f"{s_hit} (before the send_header fix this was not a wrong status but " \
        f"NO RESPONSE -- the connection was closed mid-request)"
    assert "200" not in b_hit[:200] or "416" in b_hit, \
        f"416 body should be the range-not-satisfiable page, got {b_hit[:120]!r}"

    # The entry must still be intact and servable after the refusal: a 416 is a
    # client error, not a reason to drop or poison the cached representation.
    s_after, b_after, h_after = fetch_raw(ng.port, "/range/rngsrc-unsatwarm")
    assert s_after == 200 and h_after.get("x-cache") == "HIT", \
        f"the cached entry must survive a 416, got {s_after} {h_after}"
    assert len(b_after) == 200, \
        f"the cached body must be intact after a 416, got {len(b_after)} bytes"


def test_range_not_offered_on_304(ng: Nginx, origin: Origin) -> None:
    """AUD-RANGE1, the exclusion. module.c:6563 sets r->allow_ranges only for a
    200 serve with a known length, deliberately NOT for the conditional-304
    branch immediately above it (a 304 has no body to range over, and
    header_only is already set). Nothing asserted that exclusion, so a future
    edit moving the permit above the 304 branch would be silent.

    A 304 carrying Accept-Ranges would invite a client to issue a Range request
    against a representation this response never delivered."""
    # The rngcond marker makes the Range-capable origin branch emit an ETag, so
    # this one key is both range-capable and revalidatable.
    url = "/range/rngsrc-rngcond-k1"
    s0, _, h0 = fetch_raw(ng.port, url)
    assert s0 == 200 and "x-cache" not in h0, f"prime should miss: {s0} {h0}"
    etag = h0.get("etag")
    assert etag == '"rngetag"', \
        f"fixture is wrong, not the module: rngcond must emit an ETag, got " \
        f"{etag!r}"

    # Positive half first, and it must depend on the PERMIT, not on the blob.
    # Accept-Ranges is replayed from the stored headers (the origin sent it), so
    # asserting that header would pass even with module.c:6563 deleted --
    # measured: it survived that exact mutation. Issuing a real Range and
    # requiring 206 is what the permit actually gates.
    s_hit, b_hit, h_hit = fetch_raw(ng.port, url,
                                    headers={"Range": "bytes=0-9"})
    assert h_hit.get("x-cache") == "HIT", f"ranged fetch should HIT: {h_hit}"
    assert s_hit == 206, \
        f"a cached 200 must be range-servable (the permit at module.c:6563), " \
        f"got {s_hit}"
    assert len(b_hit) == 10, f"bytes=0-9 should be 10 bytes, got {len(b_hit)}"

    s304, b304, h304 = fetch_raw(ng.port, url,
                                 headers={"If-None-Match": etag})
    assert s304 == 304, f"conditional against a HIT should be 304, got {s304}"
    assert b304 == "", f"a 304 must carry no body, got {b304!r}"
    assert "content-range" not in h304, \
        f"a 304 must never carry Content-Range: {h304}"


def test_range_on_sie_serve(ng: Nginx, origin: Origin) -> None:
    """AUD-RANGE1 on the STALE-IF-ERROR path. r->allow_ranges is set inside
    ngx_http_cache_turbo_restore_response() (module.c:6563), and
    sie_rewrite() (module.c:7104) calls that same function to replay a snapshot
    when the origin errors -- so a serve-on-error response is range-capable by
    construction. Only the live-HIT path was ever tested.

    This matters because sie_rewrite() rebuilds headers_out from scratch
    (ngx_list_init at module.c:7090). A future change to that rebuild that
    dropped Accept-Ranges, or that reordered the restore so the permit no longer
    ran, would regress Range on exactly the path a client is most likely to be
    retrying against.

    Fixture: /rangesie/ keys carry both the rngsrc marker (Range-capable body)
    and the rngsie marker (stale-if-error=30), so the entry can fully expire and
    still be replayed when the origin then 5xxs."""
    url = "/rangesie/rngsrc-rngsie-k1"
    range_hdr = {"Range": "bytes=0-99"}

    s0, _, h0 = fetch_raw(ng.port, url)
    assert s0 == 200 and "x-cache" not in h0, f"prime failed: {s0} {h0}"

    time.sleep(1.3)     # past fresh (1s), stale_mult 1 -> 1s window
    origin.fail = True
    try:
        s, b, h = fetch_raw(ng.port, url, headers=range_hdr)
        assert h.get("x-cache") == "STALE-IF-ERROR", \
            f"expected a serve-on-error replay, got x-cache={h.get('x-cache')} " \
            f"status={s} (the fixture, not the Range, is wrong)"
        assert s == 206, \
            f"a Range against a STALE-IF-ERROR serve must answer 206 like a " \
            f"HIT does, got {s} -- the client asked for a slice and got the " \
            f"whole body"
        assert h.get("content-range") == "bytes 0-99/200", \
            f"Content-Range on the SIE serve is {h.get('content-range')!r}, " \
            f"expected bytes 0-99/200"
        assert len(b) == 100, f"bytes=0-99 should be 100 bytes, got {len(b)}"
        assert b == "R" * 100, \
            f"the SIE serve returned the wrong 100 bytes: {b!r}"
    finally:
        origin.fail = False
        drain_origin(origin)


def test_safe_key_distinct_sessionids(ng: Nginx, origin: Origin) -> None:
    """Raw-key migration (was cache_turbo_safe_key): an explicit
    cache_turbo_key $scheme$host$request_uri keeps the full raw query, so two
    distinct sessionid values get DISTINCT cache entries instead of aliasing onto
    one normalized key (which could serve user A's page to user B). The same
    sessionid still HITs its own entry."""
    base = origin.hits
    _, ba, ha = fetch(ng.port, "/safekey/p?sessionid=AAA")
    assert "x-cache" not in ha, "first (sessionid=AAA) should miss"
    _, bb, hb = fetch(ng.port, "/safekey/p?sessionid=BBB")
    assert "x-cache" not in hb, \
        f"a different sessionid must NOT alias, got X-Cache={hb.get('x-cache')}"
    assert bb != ba, "two sessionids shared one cache entry (cross-user leak)"
    assert origin.hits == base + 2, "the two sessionids should each reach origin"
    _, ba2, ha2 = fetch(ng.port, "/safekey/p?sessionid=AAA")
    assert ha2.get("x-cache") == "HIT" and ba2 == ba, \
        "the same sessionid must HIT its own entry"



def test_conditional_inm_304(ng: Nginx, origin: Origin) -> None:
    """v11: a HIT whose stored ETag matches If-None-Match is answered 304 with no
    body, served from cache (the origin is not hit again)."""
    s0, _, h0 = fetch_raw(ng.port, "/cond/cond-inm")
    assert s0 == 200 and "x-cache" not in h0, f"prime should miss: {s0} {h0}"
    assert h0.get("etag") == '"v11etag"', f"etag not surfaced: {h0.get('etag')}"
    before = origin.hits_for("cond-inm")
    s1, b1, h1 = fetch_raw(ng.port, "/cond/cond-inm",
                           headers={"If-None-Match": '"v11etag"'})
    assert s1 == 304, f"matching If-None-Match should be 304, got {s1}"
    assert b1 == "", f"304 must have no body, got {b1!r}"
    assert h1.get("x-cache") == "HIT", f"304 should be a cache HIT: {h1}"
    assert origin.hits_for("cond-inm") == before, "304 must be served from cache, not origin"


def test_conditional_inm_list_short_first(ng: Nginx, origin: Origin) -> None:
    """COR-11: an If-None-Match LIST whose FIRST tag is shorter than the cached
    ETag must still match a later equal tag — the parser skips to the next comma
    instead of bailing on the whole header."""
    s0, _, h0 = fetch_raw(ng.port, "/cond/cond-list")
    assert s0 == 200 and h0.get("etag") == '"v11etag"', f"prime: {s0} {h0}"
    before = origin.hits_for("cond-list")
    s1, b1, h1 = fetch_raw(ng.port, "/cond/cond-list",
                           headers={"If-None-Match": '"x", "v11etag"'})
    assert s1 == 304, f"a later matching tag must 304, got {s1}"
    assert b1 == "", f"304 must have no body, got {b1!r}"
    assert h1.get("x-cache") == "HIT" and origin.hits_for("cond-list") == before, \
        "304 from the list must be served from cache"


def test_conditional_inm_star(ng: Nginx) -> None:
    """v11: If-None-Match: * matches any cached representation -> 304."""
    fetch_raw(ng.port, "/cond/cond-star")                          # prime
    s, b, h = fetch_raw(ng.port, "/cond/cond-star",
                        headers={"If-None-Match": "*"})
    assert s == 304 and b == "", f"INM '*' should be 304/no-body: {s} {b!r}"
    assert h.get("x-cache") == "HIT"


def test_conditional_inm_mismatch_full(ng: Nginx) -> None:
    """v11: a non-matching If-None-Match serves the full cached body (200 HIT)."""
    _, b0, _ = fetch_raw(ng.port, "/cond/cond-miss")               # prime
    s, b, h = fetch_raw(ng.port, "/cond/cond-miss",
                        headers={"If-None-Match": '"other"'})
    assert s == 200, f"non-matching INM should be 200, got {s}"
    assert b == b0 and b, f"full body expected on mismatch: {b!r} vs {b0!r}"
    assert h.get("x-cache") == "HIT"


def test_conditional_ims_304(ng: Nginx) -> None:
    """v11: If-Modified-Since later than the stored Last-Modified -> 304."""
    fetch_raw(ng.port, "/cond/cond-ims")                           # prime (LM=2015-10-21)
    s, b, h = fetch_raw(ng.port, "/cond/cond-ims",
                        headers={"If-Modified-Since":
                                 "Thu, 22 Oct 2015 07:28:00 GMT"})
    assert s == 304 and b == "", f"IMS-after-LM should be 304: {s} {b!r}"
    assert h.get("x-cache") == "HIT"


def test_conditional_ims_old_full(ng: Nginx) -> None:
    """v11: If-Modified-Since earlier than Last-Modified means the client's copy
    is stale -> serve the full body (200 HIT), not 304."""
    _, b0, _ = fetch_raw(ng.port, "/cond/cond-imsold")             # prime
    s, b, h = fetch_raw(ng.port, "/cond/cond-imsold",
                        headers={"If-Modified-Since":
                                 "Tue, 20 Oct 2015 07:28:00 GMT"})
    assert s == 200, f"IMS-before-LM should be 200, got {s}"
    assert b == b0 and b, "full body expected when client copy is older"
    assert h.get("x-cache") == "HIT"


def test_conditional_inm_beats_ims(ng: Nginx) -> None:
    """v11 / RFC 7232 precedence: when both are present, If-None-Match decides.
    A matching INM yields 304 even though the IMS is older than Last-Modified."""
    fetch_raw(ng.port, "/cond/cond-prec")                          # prime
    s, b, _ = fetch_raw(ng.port, "/cond/cond-prec",
                        headers={"If-None-Match": '"v11etag"',
                                 "If-Modified-Since":
                                 "Tue, 20 Oct 2015 07:28:00 GMT"})
    assert s == 304 and b == "", \
        f"INM match must win over older IMS (304 expected): {s} {b!r}"


def test_rfc6_stale_conditional_full(ng: Nginx, origin: Origin) -> None:
    """RFC-6: a 304 may only be answered from a FRESH entry. Once the entry is
    stale (served while a refresh is pending) a conditional request gets the
    full 200 body, never a 304 from an unvalidated stale copy.

    /condst/ has a 1s TTL (shared with test_rfc1_request_max_stale and
    test_p4_multi_directive_single_resolve, which sleep past it to exercise the
    STALE path deliberately - do not widen it here). The fresh-conditional leg
    below must be primed and read back before that 1s elapses; on a loaded CI
    runner the two requests can straddle the boundary and the entry goes stale
    before the "fresh" leg is evaluated. That is an expired test precondition,
    not a product defect - retry with a fresh cache key (so a stale prior
    attempt's entry is never misread as this attempt's result), bounded.

    KNOWN SENSITIVITY COST: a real "entries go stale too early" regression (a
    TTL-computation bug shortening the effective window) produces the SAME
    200 + x-cache: STALE signature as a lost race, so it now has to reproduce on
    all 3 attempts to fail the build instead of failing on the first. Each
    swallowed attempt therefore prints a note rather than retrying silently -
    a run that logs these repeatedly across an UNLOADED runner is a product
    signal, not flake, and must be investigated rather than shrugged off.
    """
    last_fresh_state = None
    for attempt in range(3):
        key = f"/condst/cond-x-{attempt}"
        s0, _, h0 = fetch_raw(ng.port, key)                         # prime, fresh 1s
        assert s0 == 200 and h0.get("etag") == '"v11etag"', f"prime: {s0} {h0}"
        # while still fresh, a matching INM is a 304 (the existing fresh behaviour)
        sf, bf, hf = fetch_raw(ng.port, key,
                               headers={"If-None-Match": '"v11etag"'})
        if sf == 200 and hf.get("x-cache") == "STALE":
            # setup raced its own 1s TTL before the fresh leg could be read;
            # not a product failure - re-prime under a new key and retry.
            # Printed, never silent: see KNOWN SENSITIVITY COST above.
            print(f"    note: {key} went stale before the fresh conditional leg "
                  f"(attempt {attempt + 1}, age={hf.get('age')}); re-priming",
                  flush=True)
            last_fresh_state = (sf, bf, hf)
            continue
        assert sf == 304 and bf == "" and hf.get("x-cache") == "HIT", \
            f"fresh conditional should 304: {sf} {bf!r} {hf}"
        break
    else:
        raise AssertionError(
            "harness-timing precondition: /condst/ entry kept going stale "
            f"before the fresh conditional leg could run (last: {last_fresh_state})"
        )

    time.sleep(1.4)                                                # now stale
    s1, b1, h1 = fetch_raw(ng.port, key,
                           headers={"If-None-Match": '"v11etag"'})
    assert s1 == 200, f"stale conditional must serve full body, not 304: {s1}"
    assert b1, "stale conditional must carry the full body"
    assert h1.get("x-cache") == "STALE", \
        f"stale serve expected (beta 1, no refresh): {h1.get('x-cache')}"


def test_rfc3_date_stable_across_hits(ng: Nginx) -> None:
    """RFC-3: the Date emitted for a cached representation is stable across hits
    (it does not advance to "now" on every request) and Age tracks elapsed time
    consistently with it."""
    fetch_raw(ng.port, "/cond/date")                               # prime (miss)
    _, _, ha = fetch_raw(ng.port, "/cond/date")                    # HIT A
    assert ha.get("x-cache") == "HIT", f"second read should be a HIT: {ha}"
    assert ha.get("date"), "a cached HIT must carry a Date"
    age_a = int(ha.get("age", "0"))
    time.sleep(1.4)
    _, _, hb = fetch_raw(ng.port, "/cond/date")                    # HIT B (later)
    assert hb.get("x-cache") == "HIT", f"third read should be a HIT: {hb}"
    assert hb.get("date") == ha.get("date"), \
        f"Date must be stable across hits: {ha.get('date')} -> {hb.get('date')}"
    assert int(hb.get("age", "0")) > age_a, \
        f"Age must advance while Date holds: {age_a} -> {hb.get('age')}"


def test_rfc1_only_if_cached_miss_504(ng: Nginx, origin: Origin) -> None:
    """RFC-1 (§5.2.1.7): only-if-cached on a key in neither L1 nor L2 returns
    504 Gateway Timeout and never contacts the origin."""
    before = origin.hits
    s, _, _ = fetch_raw(ng.port, "/cond/oic-miss",
                        headers={"Cache-Control": "only-if-cached"})
    assert s == 504, f"only-if-cached miss must be 504, got {s}"
    assert origin.hits == before, "only-if-cached must not reach the origin"


def test_rfc1_only_if_cached_hit(ng: Nginx, origin: Origin) -> None:
    """RFC-1: only-if-cached is satisfied by a cache HIT (no origin contact)."""
    fetch_raw(ng.port, "/cond/oic-hit")                            # prime
    before = origin.hits
    s, b, h = fetch_raw(ng.port, "/cond/oic-hit",
                        headers={"Cache-Control": "only-if-cached"})
    assert s == 200 and b, f"only-if-cached HIT should serve the body: {s} {b!r}"
    assert h.get("x-cache") == "HIT" and origin.hits == before, \
        "only-if-cached HIT must be served from cache"


def test_rfc1_request_no_store(ng: Nginx, origin: Origin) -> None:
    """RFC-1 (§5.2.1.5): a request Cache-Control: no-store runs to the origin and
    its response is NOT stored — a following plain GET still misses."""
    before = origin.hits_for("/rns")
    s, _, h = fetch_raw(ng.port, "/cond/rns",
                        headers={"Cache-Control": "no-store"})
    assert s == 200, f"no-store request should still serve 200: {s}"
    assert "x-cache" not in h, "a no-store request is an origin miss, not a HIT"
    assert origin.hits_for("/rns") == before + 1, "no-store must reach the origin"
    # nothing was stored: the next plain GET is itself a miss (origin hit again)
    _s2, _, h2 = fetch_raw(ng.port, "/cond/rns")
    assert "x-cache" not in h2 and origin.hits_for("/rns") == before + 2, \
        f"no-store response must not have been cached: {h2}"


def test_rfc1_request_max_age_zero_revalidates(ng: Nginx, origin: Origin) -> None:
    """RFC-1 (§5.2.1.1): a request max-age=0 (browser force-refresh) forces a
    revalidation — the cached entry is bypassed to the origin and refreshed."""
    fetch_raw(ng.port, "/cond/ma0")                                # prime
    _, _, hhit = fetch_raw(ng.port, "/cond/ma0")
    assert hhit.get("x-cache") == "HIT", "entry should be cached before refresh"
    before = origin.hits_for("/ma0")
    s, _, h = fetch_raw(ng.port, "/cond/ma0",
                        headers={"Cache-Control": "max-age=0"})
    assert s == 200, f"max-age=0 should still serve 200: {s}"
    assert "x-cache" not in h, "max-age=0 must revalidate at origin, not HIT"
    assert origin.hits_for("/ma0") == before + 1, "max-age=0 must reach the origin"


def test_rfc1_request_max_age_n(ng: Nginx, origin: Origin) -> None:
    """RFC-1 (§5.2.1.1): request max-age=N rejects an entry older than N seconds
    (revalidate at origin); a generous N still HITs the same entry."""
    fetch_raw(ng.port, "/cond/man")                                # prime
    time.sleep(2.2)
    before = origin.hits_for("/man")
    _s0, _, h0 = fetch_raw(ng.port, "/cond/man",
                          headers={"Cache-Control": "max-age=30"})
    assert h0.get("x-cache") == "HIT" and origin.hits_for("/man") == before, \
        f"max-age=30 on a ~2s entry should HIT: {h0}"
    s1, _, h1 = fetch_raw(ng.port, "/cond/man",
                          headers={"Cache-Control": "max-age=1"})
    assert s1 == 200 and "x-cache" not in h1, \
        f"max-age=1 on a ~2s entry must revalidate at origin: {h1}"
    assert origin.hits_for("/man") == before + 1, "tight max-age must reach the origin"


def test_rfc1_request_min_fresh(ng: Nginx, origin: Origin) -> None:
    """RFC-1 (§5.2.1.3): request min-fresh=N rejects an entry that will not stay
    fresh for at least N more seconds."""
    fetch_raw(ng.port, "/cond/mf")                                 # prime, fresh 30s
    before = origin.hits_for("/mf")
    _s0, _, h0 = fetch_raw(ng.port, "/cond/mf",
                          headers={"Cache-Control": "min-fresh=5"})
    assert h0.get("x-cache") == "HIT" and origin.hits_for("/mf") == before, \
        f"min-fresh=5 with ~30s left should HIT: {h0}"
    s1, _, h1 = fetch_raw(ng.port, "/cond/mf",
                          headers={"Cache-Control": "min-fresh=600"})
    assert s1 == 200 and "x-cache" not in h1, \
        f"min-fresh=600 with ~30s left must revalidate: {h1}"
    assert origin.hits_for("/mf") == before + 1, "unmet min-fresh must reach the origin"


def test_rfc1_request_max_stale(ng: Nginx, origin: Origin) -> None:
    """RFC-1 (§5.2.1.2): on a stale entry, a client sending max-age WITHOUT
    max-stale gets a revalidation; adding max-stale re-permits the stale serve."""
    fetch_raw(ng.port, "/condst/cond-ms")                          # prime, fresh 1s
    time.sleep(1.5)                                                # now stale
    before = origin.hits_for("/cond-ms")
    # max-stale present -> accept the stale copy (beta 1, no refresh)
    s0, b0, h0 = fetch_raw(ng.port, "/condst/cond-ms",
                           headers={"Cache-Control": "max-age=1, max-stale=30"})
    assert s0 == 200 and b0 and h0.get("x-cache") == "STALE", \
        f"max-stale must permit the stale serve: {s0} {h0}"
    assert origin.hits_for("/cond-ms") == before, "max-stale stale serve must not hit origin"
    # same tight max-age but NO max-stale -> no stale tolerance -> revalidate
    s1, _, h1 = fetch_raw(ng.port, "/condst/cond-ms",
                          headers={"Cache-Control": "max-age=1"})
    assert s1 == 200 and "x-cache" not in h1, \
        f"max-age without max-stale must revalidate a stale entry: {h1}"
    assert origin.hits_for("/cond-ms") == before + 1, "no-max-stale revalidation must hit origin"


def test_p4_multi_directive_single_resolve(ng: Nginx, origin: Origin) -> None:
    """P4: the request Cache-Control header is resolved ONCE per request and read
    by every RFC-1 predicate (revalidate / only-if-cached / no-store / freshness
    bounds), instead of each predicate re-scanning the header list. Prove the one
    resolve feeds MULTIPLE predicates by exercising two different ones:

    (a) no-store predicate: a cold request with `Cache-Control: no-store, max-age=99`
        must reach origin AND not store the response, so the next plain GET is a
        MISS (origin hit again). This drives req_no_store off the same resolve
        that also parsed the max-age bound.
    (b) max-stale predicate: `Cache-Control: no-store, max-stale=30` on a stale
        entry serves the stale copy (max-stale honoured off the same resolve)."""
    # (a) no-store on a fresh cold key: not stored -> second GET re-hits origin.
    before = origin.hits_for("/p4-nostore")
    s0, _, _h0 = fetch_raw(ng.port, "/condst/p4-nostore",
                          headers={"Cache-Control": "no-store, max-age=99"})
    assert s0 == 200 and origin.hits_for("/p4-nostore") == before + 1, \
        f"no-store request must reach origin: {s0} hits={origin.hits_for('/p4-nostore')}"
    s1, _, h1 = fetch_raw(ng.port, "/condst/p4-nostore")           # plain GET
    assert s1 == 200 and h1.get("x-cache") != "HIT" \
        and origin.hits_for("/p4-nostore") == before + 2, \
        f"no-store must have suppressed storage -> second GET MISSes: {h1}"

    # (b) max-stale half of a combined directive on a stale entry.
    fetch_raw(ng.port, "/condst/p4-multi")                         # prime, fresh 1s
    time.sleep(1.5)                                                # now stale
    before = origin.hits_for("/p4-multi")
    s2, b2, h2 = fetch_raw(ng.port, "/condst/p4-multi",
                           headers={"Cache-Control": "no-store, max-stale=30"})
    assert s2 == 200 and b2 and h2.get("x-cache") == "STALE", (
        f"max-stale half of the combined directive must permit the stale "
        f"serve: {s2} {h2}")
    assert origin.hits_for("/p4-multi") == before, "combined-directive stale serve must not hit origin"


def test_rfc2_swr_duration_extends_stale(ng: Nginx, origin: Origin) -> None:
    """RFC-2: a response stale-while-revalidate=10 extends the stale window past
    the cache_turbo_stale_mult default (which would expire the 1s entry at ~4s),
    so the copy is still STALE-serveable at ~5s."""
    fetch_raw(ng.port, "/swrdur/swrdur-x")                         # prime, fresh 1s
    time.sleep(5)                                                  # > default 4s window
    before = origin.hits_for("/swrdur-x")
    s, b, h = fetch_raw(ng.port, "/swrdur/swrdur-x")
    assert s == 200 and b, f"SWR-extended entry should still serve: {s}"
    assert h.get("x-cache") == "STALE", \
        f"stale-while-revalidate must keep it serveable past the default: {h}"
    assert origin.hits_for("/swrdur-x") == before, "SWR stale serve (beta 1) must not hit origin"


def test_purge_method(ng: Nginx) -> None:
    """v14: a PURGE request drops that URI's entry; the next GET is a MISS."""
    import json
    fetch(ng.port, "/pg/x")                          # miss -> cached
    _, _, h = fetch(ng.port, "/pg/x")
    assert h.get("x-cache") == "HIT", "should be cached before PURGE"
    s, b, _ = fetch_raw(ng.port, "/pg/x", method="PURGE")
    assert s == 200, f"PURGE status {s}"
    assert json.loads(b)["purged"] == 1, f"purge count: {b}"
    _, _, h2 = fetch(ng.port, "/pg/x")
    assert "x-cache" not in h2, "entry should be gone after PURGE (a MISS)"


def test_cor5_l1only_variant_purge(ng: Nginx, origin: Origin) -> None:
    """COR-5 (L1-only): a PURGE of an auto-Vary base URI must invalidate EVERY
    variant, not just the base key. With no L2 backend the module bumps the
    marker generation, orphaning every old-generation variant. Two language
    variants are primed (HIT), then one PURGE of the base must make BOTH miss."""
    import json
    en = {"Accept-Language": "en"}
    fr = {"Accept-Language": "fr"}
    # prime + confirm two distinct, independently-cached variants
    _, en0, _ = fetch(ng.port, "/cor5l1/p?v=al", headers=en)
    _, en1, he1 = fetch(ng.port, "/cor5l1/p?v=al", headers=en)
    assert he1.get("x-cache") == "HIT" and en1 == en0, "en variant should cache"
    _, fr0, _ = fetch(ng.port, "/cor5l1/p?v=al", headers=fr)
    _, fr1, hf1 = fetch(ng.port, "/cor5l1/p?v=al", headers=fr)
    assert hf1.get("x-cache") == "HIT" and fr1 == fr0, "fr variant should cache"
    assert fr0 != en0, "en and fr must be distinct variant slots"
    # one PURGE of the base URI (no Accept-Language => base key)
    s, b, _ = fetch_raw(ng.port, "/cor5l1/p?v=al", method="PURGE")
    assert s == 200, f"PURGE status {s}"
    assert json.loads(b)["purged"] >= 1, f"purge should report >=1: {b}"
    # BOTH variants must now miss to origin (new bodies)
    _, en2, he2 = fetch(ng.port, "/cor5l1/p?v=al", headers=en)
    assert "x-cache" not in he2 and en2 != en0, \
        f"en variant survived PURGE: X-Cache={he2.get('x-cache')} body={en2!r}"
    _, fr2, hf2 = fetch(ng.port, "/cor5l1/p?v=al", headers=fr)
    assert "x-cache" not in hf2 and fr2 != fr0, \
        f"fr variant survived PURGE: X-Cache={hf2.get('x-cache')} body={fr2!r}"


def test_cor5_l1only_variant_purge_gen_wrap(ng: Nginx, origin: Origin) -> None:
    """AUD-GEN1: the L1-only auto-Vary purge marker's generation is a
    one-byte counter (module.c marker_store). The 256th PURGE of the same
    base used to wrap the stored byte back to 0 -- the value ALSO used by a
    never-purged base -- so a variant purged exactly 256 times could resolve
    back to whatever was still resident under the pre-purge/never-purged
    key and resurrect as a live HIT. Runs the base through a real 256-purge
    cycle (the wrap boundary) and asserts the variant is still a genuine
    MISS afterward, not a resurrected stale HIT."""
    import json
    en = {"Accept-Language": "en"}
    # prime one variant so a marker (gen=0) exists for this base.
    _, en0, _ = fetch(ng.port, "/cor5l1/gen?v=al", headers=en)
    _, en1, he1 = fetch(ng.port, "/cor5l1/gen?v=al", headers=en)
    assert he1.get("x-cache") == "HIT" and en1 == en0, "en variant should cache"
    # 256 PURGEs: #1..#255 bump the marker through the normal (non-wrapping)
    # range; #256 is the wrap (256 & 0xFF == 0, the defect boundary).
    for i in range(1, 257):
        s, b, _ = fetch_raw(ng.port, "/cor5l1/gen?v=al", method="PURGE")
        assert s == 200, f"PURGE #{i} status {s}"
        # Only #1 has a live variant to drop; #2.. bump the marker generation
        # with nothing resident, so they legitimately report 0. Assert the
        # count is present and well-formed rather than `>= 0`, which no
        # response can fail.
        purged = json.loads(b)["purged"]
        if i == 1:
            assert purged >= 1, f"PURGE #1 should drop the primed variant: {b}"
    # post-wrap: the variant must be a genuine MISS (fresh origin body), never
    # a HIT on the pre-purge #1 body that AUD-GEN1's wrap would resurrect.
    _, en2, he2 = fetch(ng.port, "/cor5l1/gen?v=al", headers=en)
    assert "x-cache" not in he2, \
        (f"AUD-GEN1: variant resolved as a HIT immediately after the 256th "
         f"PURGE (marker generation wrap) -- X-Cache={he2.get('x-cache')}")
    assert en2 != en0, \
        "AUD-GEN1: post-wrap body matches the pre-purge #1 body -- purged " \
        "variant resurrected"


def test_cor5_redis_variant_purge(ng: Nginx, origin: Origin,
                                  redis: RedisServer) -> None:
    """COR-5 (Redis-backed): a PURGE of an auto-Vary base URI must drop every
    variant from BOTH tiers via the per-base variant-index set (SADD at store,
    SMEMBERS+DEL at purge). Two language variants are primed (HIT), then one
    PURGE of the base must make both miss to origin."""
    import json
    en = {"Accept-Language": "en"}
    fr = {"Accept-Language": "fr"}
    _, en0, _ = fetch(ng.port, "/cor5/p?v=al", headers=en)
    _, en1, he1 = fetch(ng.port, "/cor5/p?v=al", headers=en)
    assert he1.get("x-cache") == "HIT" and en1 == en0, "en variant should cache"
    _, fr0, _ = fetch(ng.port, "/cor5/p?v=al", headers=fr)
    _, fr1, hf1 = fetch(ng.port, "/cor5/p?v=al", headers=fr)
    assert hf1.get("x-cache") == "HIT" and fr1 == fr0, "fr variant should cache"
    assert fr0 != en0, "en and fr must be distinct variant slots"
    s, b, _ = fetch_raw(ng.port, "/cor5/p?v=al", method="PURGE")
    assert s == 200, f"PURGE status {s}"
    # the index held 2 variant members
    assert json.loads(b)["purged"] >= 2, f"purge should report >=2 variants: {b}"
    _, en2, he2 = fetch(ng.port, "/cor5/p?v=al", headers=en)
    assert "x-cache" not in he2 and en2 != en0, \
        f"en variant survived PURGE: X-Cache={he2.get('x-cache')} body={en2!r}"
    _, fr2, hf2 = fetch(ng.port, "/cor5/p?v=al", headers=fr)
    assert "x-cache" not in hf2 and fr2 != fr0, \
        f"fr variant survived PURGE: X-Cache={hf2.get('x-cache')} body={fr2!r}"


def test_cache_and_purge_respect_access_control(ng: Nginx) -> None:
    """A cached GET and PURGE must run after allow/deny. Both locations share
    one cache key, proving the denied request cannot serve or delete the entry
    that the allowed location primed."""
    key = f"acl-{time.time_ns()}"
    seed = f"/acl-seed/x?k={key}"
    denied = f"/acl-denied/x?k={key}"

    _, body, _ = fetch(ng.port, seed)
    _, hit_body, hh = fetch(ng.port, seed)
    assert hh.get("x-cache") == "HIT" and hit_body == body, \
        "failed to prime shared access-control test entry"

    s, _, hd = fetch(ng.port, denied)
    assert s == 403, f"denied cached GET returned {s}, expected 403"
    assert "x-cache" not in hd, "denied GET was served from cache"

    s, _, _ = fetch_raw(ng.port, denied, method="PURGE")
    assert s == 403, f"denied PURGE returned {s}, expected 403"

    _, body_after, ha = fetch(ng.port, seed)
    assert ha.get("x-cache") == "HIT" and body_after == body, \
        "denied PURGE deleted the protected cache entry"


def test_bypass(ng: Nginx) -> None:
    """v9: cache_turbo_bypass skips the lookup (forces origin) but still stores,
    so a bypassing request refreshes the entry."""
    _, b0, h0 = fetch(ng.port, "/bp/x")
    assert "x-cache" not in h0, "first should miss"
    _, b1, h1 = fetch(ng.port, "/bp/x")
    assert h1.get("x-cache") == "HIT" and b1 == b0, "second should HIT"
    # bypass: must go to origin (new body), not served from cache
    _, b2, h2 = fetch(ng.port, "/bp/x?nocache=1")
    assert "x-cache" not in h2, "bypass should not be served from cache"
    assert b2 != b1, "bypass should hit the origin (fresh body)"
    # the bypass refreshed the entry: a plain read now returns the bypass body
    _, b3, h3 = fetch(ng.port, "/bp/x")
    assert h3.get("x-cache") == "HIT" and b3 == b2, \
        "bypass should have refreshed the cached entry"


def test_bypass_uri(ng: Nginx) -> None:
    """v15: cache_turbo_bypass_uri gives a DIY user the preset segment-boundary
    URI matcher without a preset. A matching prefix bypasses (origin, never
    captured, X-CT-Status=BYPASS); a non-boundary continuation ("/bu/panel-x")
    does NOT match and caches normally; an unlisted URI caches. This is the gap
    a plain nginx `location` prefix cannot close (it anchors at position 0 and
    has no '/'-or-'.' boundary check)."""
    # exact segment match -> bypass
    _, _, h = fetch(ng.port, "/bu/panel")
    assert h.get("x-ct-status") == "BYPASS", \
        f"/bu/panel must bypass (exact segment), got {h.get('x-ct-status')}"
    # boundary continuation -> still bypass ("/bu/panel/sub", "/bu/panel.json")
    _, _, h = fetch(ng.port, "/bu/panel/sub")
    assert h.get("x-ct-status") == "BYPASS", \
        f"/bu/panel/sub must bypass (segment boundary '/'), got {h.get('x-ct-status')}"
    _, _, h = fetch(ng.port, "/bu/panel.json")
    assert h.get("x-ct-status") == "BYPASS", \
        f"/bu/panel.json must bypass (segment boundary '.'), got {h.get('x-ct-status')}"
    # trailing-slash needle: any continuation is inside the subtree
    _, _, h = fetch(ng.port, "/bu/admin/users")
    assert h.get("x-ct-status") == "BYPASS", \
        f"/bu/admin/users must bypass, got {h.get('x-ct-status')}"

    # NON-boundary continuation -> NOT a match -> caches. This is the whole point
    # of the segment matcher: "/bu/panel-x" is a different resource from "/bu/panel".
    _, _, h0 = fetch(ng.port, "/bu/panel-x")
    assert h0.get("x-ct-status") == "MISS", \
        f"/bu/panel-x must NOT match /bu/panel (letters continue), got {h0.get('x-ct-status')}"
    _, _, h1 = fetch(ng.port, "/bu/panel-x")
    assert h1.get("x-ct-status") == "HIT", \
        f"/bu/panel-x must cache (not bypassed), got {h1.get('x-ct-status')}"

    # an entirely unlisted URI caches normally
    _, _, h0 = fetch(ng.port, "/bu/public")
    assert h0.get("x-ct-status") == "MISS", "unlisted URI first fetch MISS"
    _, _, h1 = fetch(ng.port, "/bu/public")
    assert h1.get("x-ct-status") == "HIT", \
        f"unlisted /bu/public must cache, got {h1.get('x-ct-status')}"


def test_key_cookie(ng: Nginx) -> None:
    """v15: cache_turbo_key_cookie value-keys a cookie into the cache key for a
    DIY user, the same tier-3 engine the magento preset uses. Different values
    are different entries; the same value shares one; an absent cookie is its
    own anonymous bucket. EXACT-name match and all-Cookie-headers scan are the
    same anti-bucket-selection guarantees the preset carries."""
    seg_a = {"Cookie": "seg=aaaa1111bbbb2222"}
    _, ba1, _ = fetch(ng.port, "/kc/page", headers=seg_a)
    _, ba2, ha2 = fetch(ng.port, "/kc/page", headers=seg_a)
    assert ha2.get("x-ct-status") == "HIT" and ba1 == ba2, \
        "same seg value must key to its own entry and HIT"

    # a DIFFERENT value must not see A's body -- the value is in the KEY
    seg_b = {"Cookie": "seg=cccc3333dddd4444"}
    _, bb1, _ = fetch(ng.port, "/kc/page", headers=seg_b)
    assert bb1 != ba1, \
        "a different seg value was served another segment's body -- cross-user leak"

    # OVER-LONG values (> 256 bytes) collapse to ONE bucket, marked by the
    # reserved 0xffffffff length field and no value bytes. Two DIFFERENT
    # over-long values must therefore share an entry -- that is the cap doing
    # its job. The only requests in that bucket are other over-long ones.
    big_x = {"Cookie": "seg=" + ("x" * 300)}
    big_y = {"Cookie": "seg=" + ("y" * 400)}
    _, bx1, _ = fetch(ng.port, "/kc/page", headers=big_x)
    _, by1, hy1 = fetch(ng.port, "/kc/page", headers=big_y)
    assert hy1.get("x-ct-status") == "HIT" and by1 == bx1, \
        ("two distinct over-long key-cookie values must collapse to ONE bucket "
         f"-- otherwise the cap does not bound anything, got {hy1.get('x-ct-status')}")

    # ...but that bucket must be DISTINCT from the anonymous (absent-cookie)
    # one, or an over-long value poisons the entry every cookie-less visitor
    # reads. This is the assertion that fails if the cap is implemented by
    # simply dropping the fold.
    _, banon, _ = fetch(ng.port, "/kc/page")
    assert banon != bx1, \
        ("an over-long value must NOT land in the anonymous bucket -- dropping "
         "the fold instead of marking it poisons every cookie-less visitor")

    # ...and distinct from an in-range value's bucket.
    assert bx1 != ba1 and bx1 != bb1, \
        "the oversize bucket must not collide with an in-range segment's entry"

    # A value at exactly the cap is still folded VERBATIM -- the boundary is
    # inclusive, so a legitimate 256-byte fingerprint keeps its own entry.
    at_cap = {"Cookie": "seg=" + ("z" * 256)}
    _, bz1, _ = fetch(ng.port, "/kc/page", headers=at_cap)
    assert bz1 != bx1, \
        ("a value of exactly 256 bytes is at the cap, not over it -- it must "
         "still key to its own entry, not the oversize bucket")
    _, bb2, hb2 = fetch(ng.port, "/kc/page", headers=seg_b)
    assert hb2.get("x-ct-status") == "HIT" and bb2 == bb1, \
        "each seg value must warm and HIT its own entry"

    # the cookie-less anonymous entry is a third, separate bucket
    _, ban, _ = fetch(ng.port, "/kc/page")
    _, ban2, han2 = fetch(ng.port, "/kc/page")
    assert han2.get("x-ct-status") == "HIT" and ban2 == ban, "anonymous entry caches"
    assert ban != ba1 and ban != bb1, "anonymous is its own bucket, not a segment's"

    # EXACT-name: a cookie whose name merely ends with "seg" is a different
    # cookie and must not select seg's bucket.
    _, bd, _ = fetch(ng.port, "/kc/decoy",
                     headers={"Cookie": "notseg=aaaa1111bbbb2222"})
    _, bda, _ = fetch(ng.port, "/kc/decoy")
    assert bd == bda, \
        "notseg must not be read as seg -- exact-name keeps the bucket out of client hands"

    # ALL Cookie headers scanned: the real cookie hidden in a SECOND header must
    # key identically to the same cookie in one header (else attacker-chosen).
    _, bs, _ = fetch_dup(ng.port, "/kc/split",
                         [("Cookie", "other=x"),
                          ("Cookie", "seg=eeee5555ffff6666")])
    _, bs2, hs2 = fetch(ng.port, "/kc/split",
                        headers={"Cookie": "other=x; seg=eeee5555ffff6666"})
    assert hs2.get("x-ct-status") == "HIT" and bs2 == bs, \
        "a seg cookie in a second Cookie header must key identically"


def test_require_header(ng: Nginx) -> None:
    """PR-A: cache_turbo_require_header inverts the store default on a location
    from "cacheable unless vetoed" to "uncacheable unless the origin affirms
    it". Only the application can decide for an origin like GraphQL, which
    answers queries and mutations on the same URI+method and returns errors as
    HTTP 200. Every assert is on a POSITIVE X-CT-Status: each refusal case is a
    plain MISS, and a MISS carries no x-cache, so an absence assert here would
    pass even if the gate never ran."""
    # affirmative -> stored and served. "yes"/"1"/"on" each on their own URI so
    # one value's entry can never satisfy another's assert.
    for i, val in enumerate(("yes", "1", "on", "YES", "On")):
        p = f"/gql/ok{i}"
        _, b1, h1 = fetch(ng.port, p, headers={"X-Want-Cacheable": val})
        assert h1.get("x-ct-status") == "MISS", \
            f"cold fetch of {p} should be MISS, got {h1.get('x-ct-status')}"
        _, b2, h2 = fetch(ng.port, p, headers={"X-Want-Cacheable": val})
        assert h2.get("x-ct-status") == "HIT" and b2 == b1, \
            f"{val!r} is affirmative -> must store and HIT, got {h2.get('x-ct-status')}"
        # STRIPPED before store, asserted per value rather than once after the
        # loop: this cache is the header's intended consumer, and a HIT must not
        # replay the origin's internal store signal downstream. Checked inside
        # the loop so every affirmative proves its own strip -- a single assert
        # after the loop would silently only ever test the last value.
        assert "x-graphql-cacheable" not in {k.lower() for k in h2}, \
            f"{val!r}: the store opt-in header must be stripped, not replayed"

    # every non-affirmative value refuses the store -> the second fetch is a
    # fresh origin body, never a HIT. "note"/"1x"/"onward" specifically catch a
    # prefix compare that would read them as affirmative.
    # No "" case here: nginx drops an empty-valued response header in the proxy
    # layer, so it never reaches the gate at all -- an "" row would silently be
    # a second copy of the /gql/absent case below, not an empty-value test. The
    # gate's own len-based checks still refuse an empty value if one ever does
    # arrive (a non-proxy content phase, say); it just isn't reachable here.
    for i, val in enumerate(("no", "0", "note", "1x", "onward", "yes-but")):
        p = f"/gql/no{i}"
        _, b1, _ = fetch(ng.port, p, headers={"X-Want-Cacheable": val})
        _, b2, h2 = fetch(ng.port, p, headers={"X-Want-Cacheable": val})
        assert h2.get("x-ct-status") == "MISS" and b2 != b1, \
            f"{val!r} is not affirmative -> must never store, got {h2.get('x-ct-status')}"

    # Pins WHY there is no "" row above, on the ungated control location so the
    # proxy layer's own behaviour is what's observed: nginx does not forward an
    # empty-valued response header (the origin demonstrably sends
    # "X-GraphQL-Cacheable: "). If a future nginx starts forwarding it, this
    # fails and the "" case becomes worth testing on the gate directly.
    _, _, he = fetch(ng.port, "/nogql/empty", headers={"X-Want-Cacheable": ""})
    assert he.get("X-GraphQL-Cacheable") is None, \
        "nginx now forwards an empty-valued header -- add an empty-value case " \
        "to the refusal loop above, it is no longer just /gql/absent"

    # header ABSENT entirely -> refuse (the fail-closed default of the gate)
    _, ba1, _ = fetch(ng.port, "/gql/absent")
    _, ba2, ha2 = fetch(ng.port, "/gql/absent")
    assert ha2.get("x-ct-status") == "MISS" and ba2 != ba1, \
        "no opt-in header at all must refuse the store"

    # DUPLICATED + conflicting ("yes" and "no") -> ambiguous -> refuse, in BOTH
    # orders: the gate scans the whole headers_out list, so a first-match-wins
    # implementation would store the yes-first case and leak an uncacheable body.
    for order in ("yes|no", "no|yes"):
        p = f"/gql/dup{order.split('|')[0]}"
        _, bd1, _ = fetch(ng.port, p, headers={"X-Want-Cacheable": order})
        _, bd2, hd2 = fetch(ng.port, p, headers={"X-Want-Cacheable": order})
        assert hd2.get("x-ct-status") == "MISS" and bd2 != bd1, \
            f"conflicting duplicate opt-in ({order}) is ambiguous -> must refuse"

    # UNSET on a location => gate inert => the module's normal path is untouched.
    # Without this, a gate that refused everything everywhere would still pass
    # every refusal assert above.
    _, bn1, _ = fetch(ng.port, "/nogql/page")
    _, bn2, hn2 = fetch(ng.port, "/nogql/page")
    assert hn2.get("x-ct-status") == "HIT" and bn2 == bn1, \
        "an unset require_header must leave normal caching alone"


def test_status_variable(ng: Nginx) -> None:
    """$cache_turbo_status (echoed as X-CT-Status): MISS on the cold fetch,
    HIT on the second, BYPASS when a cache_turbo_bypass predicate trips. Also
    confirms the bypass bumped the cache_turbo_bypasses_total counter."""
    import re
    _, _, h0 = fetch(ng.port, "/ctstatus/s")
    assert h0.get("x-ct-status") == "MISS", \
        f"cold fetch should be MISS, got {h0.get('x-ct-status')}"
    _, _, h1 = fetch(ng.port, "/ctstatus/s")
    assert h1.get("x-ct-status") == "HIT", \
        f"second fetch should be HIT, got {h1.get('x-ct-status')}"

    _, b, _ = fetch(ng.port, "/_cache?format=prometheus")
    m = re.search(r'cache_turbo_bypasses_total\{zone="main"\} (\d+)', b)
    assert m, f"no bypasses_total sample:\n{b[:300]}"
    before = int(m.group(1))

    _, _, h2 = fetch(ng.port, "/ctstatus/s?nocache=1")
    assert h2.get("x-ct-status") == "BYPASS", \
        f"bypass fetch should be BYPASS, got {h2.get('x-ct-status')}"

    _, b2, _ = fetch(ng.port, "/_cache?format=prometheus")
    after = int(re.search(r'cache_turbo_bypasses_total\{zone="main"\} (\d+)',
                          b2).group(1))
    assert after == before + 1, \
        f"bypasses_total should increment on a bypass: {before} -> {after}"


def test_status_stale(ng: Nginx, origin: Origin) -> None:
    """$cache_turbo_status = STALE while serving a stale copy. /ctstale/ has
    beta 1 so the refresh dice ~never fires (the read stays a clean STALE serve
    rather than flipping to a fresh HIT). Locks the ST_STALE arm of the var."""
    fetch(ng.port, "/ctstale/s")                  # prime: MISS, fresh 1s
    time.sleep(1.3)                               # past fresh, within the 4s stale
    _, _, h = fetch(ng.port, "/ctstale/s")
    assert h.get("x-ct-status") == "STALE", \
        f"stale serve should report STALE, got {h.get('x-ct-status')}"
    drain_origin(origin)       # settle any async bg refresh before the next test


def test_status_expired(ng: Nginx, origin: Origin) -> None:
    """$cache_turbo_status = EXPIRED when a cached entry is found past its whole
    serveable window and refetched from origin — distinct from a cold MISS
    (which test_status_variable covers). Locks the ST_EXPIRED arm + the
    nginx-aligned semantics (EXPIRED != only-if-cached-504)."""
    fetch(ng.port, "/ctstale/e")                  # prime: MISS, fresh 1s, stale to 4s
    time.sleep(4.5)                               # past the entire 4s window
    _, _, h = fetch(ng.port, "/ctstale/e")
    assert h.get("x-ct-status") == "EXPIRED", \
        f"expired-refetch should report EXPIRED, got {h.get('x-ct-status')}"
    drain_origin(origin)


def test_serve_reason_variable(ng: Nginx, origin: Origin) -> None:
    """S7.2: $cache_turbo_serve_reason (echoed as X-CT-Reason) is the UNFOLDED
    per-request serve outcome. Drives all five values on the private sr72z
    zone, kept separate from s71z/brkiz/etc. so this test's own breaker
    priming (expects CLOSED, then trips it itself) is not polluted by another
    test's already-tripped breaker.

    FRESH  : /sr72/ second fetch, within the 1s fresh window.
    STALE  : /sr72/ third fetch, past fresh (1s) but within the x4=4s stale
             window (beta 1 keeps the refresh dice from firing, same
             discipline as test_status_stale).
    STALE-IF-ERROR : /sr72sie/ fully expired (past the stale_mult-1 1s stale window) with
             the origin down; the "sieserve" request-suffix marker armed a
             serve-on-error snapshot on priming (same convention as
             test_sie_serve_on_error).
    STALE-BREAKER  : /sr72brk/dead, primed then origin killed. threshold=1
             means the FIRST dead-origin request trips CLOSED->OPEN and still
             surfaces the raw origin error (not a serve at all, so it does
             NOT report STALE-BREAKER); the SECOND request finds the breaker
             OPEN and is served the armed fallback -- that is the one this
             test asserts on (same two-fetch shape as test_breaker_counters).
    BREAKER-503    : /sr72brk/never -- NEVER primed, so once the breaker above
             is OPEN this key has no snapshot of any age and falls into
             ngx_http_cache_turbo_breaker_unavailable(), the local 503 that
             never touches the origin.
    """
    # FRESH
    fetch(ng.port, "/sr72/k1")                    # prime: MISS (SR_NONE, no
                                                    # unfolded reason for a cold
                                                    # miss -- not asserted here)
    _, _, h_fresh = fetch(ng.port, "/sr72/k1")
    assert h_fresh.get("x-ct-reason") == "FRESH", \
        f"fresh serve should report FRESH, got {h_fresh.get('x-ct-reason')}"

    # STALE
    time.sleep(1.3)                                # past fresh, within 4s stale
    _, _, h_stale = fetch(ng.port, "/sr72/k1")
    assert h_stale.get("x-ct-reason") == "STALE", \
        f"stale serve should report STALE, got {h_stale.get('x-ct-reason')}"
    drain_origin(origin)

    # STALE-IF-ERROR
    s0, b0, _ = fetch(ng.port, "/sr72sie/sieserve-k1")   # arms sie window
    assert s0 == 200 and b0, f"sie prime failed: {s0} {b0!r}"
    time.sleep(1.3)                                # past fresh (1s), stale_mult 1 -> 1s window
    origin.fail = True
    try:
        s_sie, b_sie, h_sie = fetch(ng.port, "/sr72sie/sieserve-k1")
        assert s_sie == 200 and b_sie == b0, \
            f"SIE serve-on-error returned {s_sie} {b_sie!r}, expected stale 200 {b0!r}"
        assert h_sie.get("x-ct-reason") == "STALE-IF-ERROR", \
            (f"SIE serve should report STALE-IF-ERROR, got "
             f"{h_sie.get('x-ct-reason')}")
    finally:
        origin.fail = False
        drain_origin(origin)

    # STALE-BREAKER + BREAKER-503
    s_prime, b_prime, _ = fetch(ng.port, "/sr72brk/dead")
    assert s_prime == 200 and b_prime, f"breaker prime failed: {s_prime} {b_prime!r}"

    time.sleep(1.3)   # past fresh (1s), stale_mult 1 -> 1s window: L1-expired
    origin.fail = True
    try:
        s_trip, _, _ = fetch(ng.port, "/sr72brk/dead")
        assert s_trip != 200, \
            (f"tripping request was answered 200 -- expected it to reach "
             f"the dead origin and fail, got {s_trip}")

        s_brk, _, h_brk = fetch(ng.port, "/sr72brk/dead")
        assert s_brk == 200, \
            f"breaker OPEN did not fall back to the any-age snapshot, got {s_brk}"
        assert h_brk.get("x-ct-reason") == "STALE-BREAKER", \
            (f"breaker fallback serve should report STALE-BREAKER, got "
             f"{h_brk.get('x-ct-reason')}")

        s_503, _, h_503 = fetch(ng.port, "/sr72brk/never")
        assert s_503 == 503, \
            f"breaker OPEN + no cached copy should 503, got {s_503}"
        assert h_503.get("x-ct-reason") == "BREAKER-503", \
            (f"breaker refusal should report BREAKER-503, got "
             f"{h_503.get('x-ct-reason')}")
    finally:
        origin.fail = False
        drain_origin(origin)
