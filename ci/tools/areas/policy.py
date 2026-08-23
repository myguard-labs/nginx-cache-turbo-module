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
from test_runtime_base import *
from test_runtime_base import (
    _admin_stat,
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


def test_p58_default_off_set_cookie_still_refused(ng: Nginx) -> None:
    """P5-8 NEGATIVE CONTROL. Without cache_turbo_ignore_set_cookie the floor is
    byte-identical to before the directive existed: /scdefault/ has no ignore
    list, so a response setting a cookie whose name IS on the /scign/ list is
    still refused.

    This is the test that proves the COMPILED-IN default is OFF, and it is
    deliberately NOT /cc/: that location inherits the server-level wordpress
    preset, so its refusal is over-determined by the preset veto and would stay
    green even if the relax shipped on by default. /scdefault/ sets
    `cache_turbo_backend none`, so the ONLY thing refusing the store here is the
    directive's own default. Every other P5-8 case opts in explicitly and would
    pass even if the relax were unconditional."""
    _, b1, h1 = fetch(ng.port, "/scdefault/p58listed")
    assert "x-cache" not in h1, "first read should be a miss"
    _, b2, h2 = fetch(ng.port, "/scdefault/p58listed")
    assert "x-cache" not in h2, \
        ("default-off: a Set-Cookie response must not be stored without "
         f"cache_turbo_ignore_set_cookie; got X-Cache={h2.get('x-cache')}")
    assert b1 != b2, "both reads should have gone to the origin"


def test_p58_listed_cookie_is_stored(ng: Nginx) -> None:
    """P5-8: one Set-Cookie, name on the list, no key cookie configured => the
    response IS stored and the second read is a HIT."""
    fetch(ng.port, "/scign/p58listed")                     # prime (miss, stores)
    _, _, h = fetch(ng.port, "/scign/p58listed")
    assert h.get("x-cache") == "HIT", \
        ("a Set-Cookie naming a listed cookie must be storable; got "
         f"X-Cache={h.get('x-cache')}")


def test_p58_stored_blob_carries_no_set_cookie(ng: Nginx) -> None:
    """P5-8, the security assertion: the relax changes WHETHER the body is
    stored, never WHAT is stored. The HIT served from the blob must carry NO
    Set-Cookie at all — otherwise one visitor's cookie replays to every other
    client from a SHARED entry.

    Asserted on the HIT (served from the stored bytes), not on the MISS: the miss
    is a pass-through from the origin and legitimately carries the cookie."""
    _, _, hm = fetch(ng.port, "/scign/p58multi")           # prime (miss, stores)
    assert "set-cookie" in hm, \
        "fixture check: the origin MISS must carry Set-Cookie, else this proves nothing"
    _, _, h = fetch(ng.port, "/scign/p58multi")
    assert h.get("x-cache") == "HIT", \
        f"expected a HIT to inspect the stored bytes; got X-Cache={h.get('x-cache')}"
    assert "set-cookie" not in h, \
        ("the stored blob must NOT replay Set-Cookie to another client; got "
         f"{h.get('set-cookie')!r} — cross-user cookie disclosure")


def test_p58_all_listed_multi_is_stored(ng: Nginx) -> None:
    """P5-8: SEVERAL Set-Cookie fields, every one on the list => stored. Pairs
    with test_p58_one_unlisted_refuses: same multi-header shape, opposite
    verdict, so the difference is the unlisted NAME and nothing else."""
    fetch(ng.port, "/scign/p58multi")                      # prime (miss, stores)
    _, _, h = fetch(ng.port, "/scign/p58multi")
    assert h.get("x-cache") == "HIT", \
        ("several Set-Cookie fields, all listed, must be storable; got "
         f"X-Cache={h.get('x-cache')}")


def test_p58_one_unlisted_refuses(ng: Nginx) -> None:
    """P5-8, THE assertion that matters most. Three Set-Cookie fields: _ga
    (listed), sessionid (NOT listed), ab_bucket (listed). One unlisted name
    among several listed ones must refuse the whole store.

    This is what a guard that stops at the first Set-Cookie, that ORs the per-
    header verdicts instead of ANDing them, or that checks only the last field,
    gets wrong — and getting it wrong stores a real session cookie's response
    into a SHARED entry."""
    _, b1, h1 = fetch(ng.port, "/scign/p58mixed")
    assert "x-cache" not in h1, "first read should be a miss"
    _, b2, h2 = fetch(ng.port, "/scign/p58mixed")
    assert "x-cache" not in h2, \
        ("ONE unlisted Set-Cookie (sessionid) among listed ones must refuse the "
         f"store; got X-Cache={h2.get('x-cache')} — a per-user session cookie's "
         "response was cached in a shared entry")
    assert b1 != b2, "both reads should have gone to the origin"


def test_p58_key_cookie_vetoes_the_relax(ng: Nginx) -> None:
    """P5-8 HARD VETO. /scignkc/ carries the SAME ignore list as /scign/ plus a
    DIY cache_turbo_key_cookie. Value-keying means a request without the cookie
    hashes to the ANONYMOUS entry while the response establishes the segment —
    the transition race the unconditional floor was protecting. With any key
    cookie configured the relax must be off entirely, so the case that STORES
    under /scign/ must be REFUSED here.

    The veto is on the configuration, not on which cookie this response sets:
    an operator whose ignore list omits a key cookie must not silently reopen
    the race."""
    _, b1, h1 = fetch(ng.port, "/scignkc/p58listed")
    assert "x-cache" not in h1, "first read should be a miss"
    _, b2, h2 = fetch(ng.port, "/scignkc/p58listed")
    assert "x-cache" not in h2, \
        ("a configured key cookie must veto the Set-Cookie relax regardless of "
         f"the ignore list; got X-Cache={h2.get('x-cache')} — the key-cookie "
         "transition race was reopened")
    assert b1 != b2, "both reads should have gone to the origin"


def test_p58_backend_preset_vetoes_the_relax(ng: Nginx) -> None:
    """P5-8 HARD VETO, preset arm. /scignpreset/ carries the same ignore list as
    /scign/ but omits `cache_turbo_backend none`, so it inherits the server-level
    wordpress preset. Any active backend preset vetoes the relax.

    The veto is on a preset being ACTIVE rather than on the preset declaring key
    cookies today: presets gain key cookies over time, and a relax that silently
    switches itself back on when a preset is extended is exactly the regression
    this veto exists to prevent.

    Pairs with test_p58_listed_cookie_is_stored: identical URI marker, identical
    ignore list, opposite verdict, and the only difference is the preset."""
    _, b1, h1 = fetch(ng.port, "/scignpreset/p58listed")
    assert "x-cache" not in h1, "first read should be a miss"
    _, b2, h2 = fetch(ng.port, "/scignpreset/p58listed")
    assert "x-cache" not in h2, \
        ("an active backend preset must veto the Set-Cookie relax; got "
         f"X-Cache={h2.get('x-cache')}")
    assert b1 != b2, "both reads should have gone to the origin"


def test_p58_malformed_set_cookie_fails_closed(ng: Nginx) -> None:
    """P5-8 fail-closed parsing. Every Set-Cookie shape the strict RFC 6265
    cookie-name extractor cannot resolve to exactly one token name must refuse
    the store, even under an enabled ignore list.

    p58attrname is the important one: an UNLISTED session cookie whose
    ATTRIBUTES contain the listed name (`Path=/_ga; Domain=_ga`). A substring
    search over the header value, or a parser that reuses the request-Cookie
    grammar (where `;` separates PAIRS rather than attributes), matches `_ga`
    there and stores a real session cookie's response."""
    for marker, why in (
        ("p58noeq", "no '=' at all: not a cookie-pair"),
        ("p58emptyname", "empty cookie name"),
        ("p58attrname", "listed name appears only in the ATTRIBUTES"),
        ("p58quoted", "quoted name is not an RFC 6265 token"),
        ("p58spacedname", "embedded space is not an RFC 6265 token"),
    ):
        uri = f"/scign/{marker}"
        _, b1, h1 = fetch(ng.port, uri)
        assert "x-cache" not in h1, f"{marker}: first read should be a miss"
        _, b2, h2 = fetch(ng.port, uri)
        assert "x-cache" not in h2, \
            (f"{marker} ({why}) must fail closed and refuse the store; got "
             f"X-Cache={h2.get('x-cache')}")
        assert b1 != b2, f"{marker}: both reads should have gone to the origin"


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


def test_serve_authorized_reads_public_anonymous_entry(
        ng: Nginx, origin: Origin) -> None:
    """P3-4: with cache_turbo_serve_authorized on (/sauth/), a credentialed
    request may READ an anonymously-stored entry whose response carried an RFC
    9111 SS3.5 reuse authorisation (`Cache-Control: public` via the ccpublic
    marker). This is the whole point of the row: hit ratio on an API that
    authenticates every call to a shareable public endpoint is exactly zero
    under the default-off LOOKUP refusal.

    Prime ANONYMOUSLY, then read WITH Authorization and require a real HIT.
    The HIT is proved by the origin counter, not by body equality alone: the
    origin body embeds a per-hit counter, so an unchanged origin hit count is
    what distinguishes a cache HIT from a second origin contact that happened
    to look similar."""
    base = origin.hits_for("ccpublic-read")
    p = "/sauth/ccpublic-read"
    _, b1, h1 = fetch(ng.port, p)
    assert "x-cache" not in h1, f"cold anonymous read should MISS, got {h1}"
    assert origin.hits_for("ccpublic-read") - base == 1, origin.hits_for("ccpublic-read") - base

    _, b2, h2 = fetch(ng.port, p, headers={"Authorization": "Bearer tok"})
    assert h2.get("x-cache") == "HIT", (
        "a credentialed request must be served the anonymously-stored public "
        f"entry when serve_authorized is on, got x-cache={h2.get('x-cache')}")
    assert b2 == b1, ("HIT served a different body than the primed entry",
                      b1, b2)
    assert origin.hits_for("ccpublic-read") - base == 1, (
        "the credentialed read must be served from cache, not the origin",
        origin.hits_for("ccpublic-read") - base)


def test_serve_authorized_refuses_non_shareable_entry(
        ng: Nginx, origin: Origin) -> None:
    """P3-4 MANDATORY NEGATIVE CONTROL: a response that is storable but carries
    NO RFC 9111 SS3.5 reuse authorisation (no public / s-maxage /
    must-revalidate -- the plain /sauth/ marker, cacheable only via
    cache_turbo_valid) must still be REFUSED to a credentialed requester, even
    though serve_authorized is on for this location.

    Without the BLOBF_AUTH_SHAREABLE serve gate this would HIT, which is
    exactly the over-relaxation the row must not ship: SS3.5 permits reuse for
    an authenticated request only when the RESPONSE authorised it, not merely
    because the stored copy happens to be anonymous.

    The anonymous prime + anonymous HIT first proves the entry really IS
    stored and serveable -- otherwise the credentialed miss below would pass
    vacuously against an empty cache."""
    base = origin.hits_for("plain-nonshareable")
    p = "/sauth/plain-nonshareable"
    _, b1, h1 = fetch(ng.port, p)
    assert "x-cache" not in h1, f"cold anonymous read should MISS, got {h1}"
    _, b2, h2 = fetch(ng.port, p)
    assert h2.get("x-cache") == "HIT" and b2 == b1, (
        ("the entry must be stored and anonymously serveable, or the "
         "credentialed assertion below proves nothing"), h2)
    assert origin.hits_for("plain-nonshareable") - base == 1, origin.hits_for("plain-nonshareable") - base

    _, b3, h3 = fetch(ng.port, p, headers={"Authorization": "Bearer tok"})
    assert h3.get("x-cache") != "HIT", (
        "a credentialed request was served an entry with NO RFC 9111 SS3.5 "
        "reuse authorisation -- the BLOBF_AUTH_SHAREABLE serve gate failed "
        f"open, x-cache={h3.get('x-cache')}")
    assert b3 != b1, (
        "the credentialed request received the stored non-shareable body",
        b1, b3)
    assert origin.hits_for("plain-nonshareable") - base == 2, (
        "the refused credentialed request must fall through to the origin",
        origin.hits_for("plain-nonshareable") - base)


def test_serve_authorized_never_stores_under_credentials(
        ng: Nginx, origin: Origin) -> None:
    """P3-4 MANDATORY CROSS-PRINCIPAL CONTROL: a response produced FOR a
    credentialed request is never stored, so it can never be served to a
    different principal -- even on a location with serve_authorized on, and
    even when the origin marks it `public`.

    This pins the guarantee the whole relaxation rests on: serve_authorized
    lifts only the LOOKUP gate in access_eligible(). The STORE floor
    (response_cacheable()'s Authorization arm) is the function's first test,
    ungated by any directive, and ctx->captured -- the sole trigger for the
    body filter's store -- is only set when it returns true.

    Principal A fetches COLD with credentials (nothing cached). If that
    response were stored, principal B (a different token, and then an
    anonymous client) would be served A's bytes. Both must instead reach the
    origin and get their own distinct body."""
    base = origin.hits_for("ccpublic-cold-auth")
    p = "/sauth/ccpublic-cold-auth"
    _, a_body, ha = fetch(ng.port, p, headers={"Authorization": "Bearer AAA"})
    assert "x-cache" not in ha, f"cold credentialed read must MISS, got {ha}"
    assert origin.hits_for("ccpublic-cold-auth") - base == 1, origin.hits_for("ccpublic-cold-auth") - base

    _, b_body, hb = fetch(ng.port, p, headers={"Authorization": "Bearer BBB"})
    assert hb.get("x-cache") != "HIT", (
        "principal B was served a cache HIT on a URL only ever fetched under "
        f"principal A's credentials -- the store floor leaked, x-cache={hb.get('x-cache')}")
    assert b_body != a_body, (
        "principal B received principal A's credentialed response body",
        a_body, b_body)

    _, anon_body, hanon = fetch(ng.port, p)
    assert hanon.get("x-cache") != "HIT", (
        "an anonymous client was served a cache HIT on a URL only ever "
        f"fetched under credentials, x-cache={hanon.get('x-cache')}")
    assert anon_body != a_body, (
        "an anonymous client received a credentialed response body",
        a_body, anon_body)
    assert origin.hits_for("ccpublic-cold-auth") - base == 3, (
        ("every one of the three requests must reach the origin (nothing "
         "was ever stored)"), origin.hits_for("ccpublic-cold-auth") - base)


def test_serve_authorized_off_by_default_still_refuses_lookup(
        ng: Nginx, origin: Origin) -> None:
    """P3-4: the COMPILED-IN DEFAULT. /c/ sets no cache_turbo_serve_authorized
    directive at all, so this exercises the merge default rather than an
    explicit `off` -- a location that opted out explicitly would pass even if
    the default had been flipped to on, so only a directive-free location can
    prove the default is still off.

    Same shape as test_no_cache_authorization's primed arm, kept separate so
    the P3-4 default has its own named guard: prime anonymously, then a
    credentialed request must NOT be served that entry.

    The path carries the `ccpublic` marker DELIBERATELY. Two independent
    guards can refuse a credentialed serve -- this LOOKUP gate, and the
    RFC 9111 SS3.5 BLOBF_AUTH_SHAREABLE gate at the serve chokepoint -- and a
    plain (non-public) entry is refused by the SECOND one no matter what the
    first does. Against such a path this test passes even with the default
    flipped to on, i.e. it would assert nothing: verified by mutation, the row
    SURVIVED. Priming with `public` satisfies the SS3.5 gate, so the lookup
    gate is the only thing left to fail, and the assertion becomes reachable."""
    base = origin.hits_for("p34-default-off-ccpublic")
    p = "/c/p34-default-off-ccpublic"
    _, anon, _ = fetch(ng.port, p)
    _, anon_hit, hp = fetch(ng.port, p)
    assert hp.get("x-cache") == "HIT" and anon_hit == anon, (
        ("the anonymous entry must be primed, or the assertion below is "
         "vacuous"), hp)
    assert origin.hits_for("p34-default-off-ccpublic") - base == 1, origin.hits_for("p34-default-off-ccpublic") - base

    _, auth_body, ha = fetch(ng.port, p, headers={"Authorization": "Bearer x"})
    assert "x-cache" not in ha, (
        "with no cache_turbo_serve_authorized directive the LOOKUP refusal "
        f"must still apply, got x-cache={ha.get('x-cache')}")
    assert auth_body != anon, "the credentialed request did not reach the origin"
    assert origin.hits_for("p34-default-off-ccpublic") - base == 2, origin.hits_for("p34-default-off-ccpublic") - base


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


def test_origin_method_hits_falsifiable(ng: Nginx, origin: Origin) -> None:
    """P5-6-r1a: `hits_for()` sums a Counter keyed on path ONLY, so it cannot
    distinguish a HEAD from a GET to the same path -- any test asserting "this
    HEAD-only URL was never touched by a GET" via `hits_for` would silently
    pass no matter what. This test proves the new `hits_for_method()` accessor
    (method, path)-keyed and does NOT share that blind spot: it demonstrates
    the assertion it exists to make CAN go red.

    It also verifies distinctness AT THE ORIGIN, not just in the client-side
    URL: /c/ and /st/ both `proxy_pass http://.../;` (trailing slash) to the
    SAME origin root, which strips each location's prefix -- so two distinct
    client paths can collapse onto the same origin path. A unique marker
    embedded in the URL tail (surviving the prefix strip either way) is what
    actually proves the origin-side path used by this test is unique."""
    tag = "p56r1a-headonly-marker"
    url = f"/c/{tag}"

    # 1. A HEAD-only fetch must be visible to hits_for_method("HEAD", ...)
    #    and invisible to hits_for_method("GET", ...) -- the assertion this
    #    row exists to make possible.
    s0, _, _ = fetch(ng.port, url, method="HEAD")
    assert s0 == 200, f"HEAD should reach the origin cleanly, got {s0}"
    assert origin.hits_for_method("HEAD", tag) > 0, \
        "hits_for_method('HEAD', ...) must see the HEAD that just landed"
    assert origin.hits_for_method("GET", tag) == 0, \
        "no GET has been issued yet -- hits_for_method('GET', ...) must be 0"

    # 2. Confirm distinctness is established AT THE ORIGIN (not merely in the
    #    client-side URL): the origin must have recorded a path that still
    #    carries the unique tag after nginx's proxy_pass prefix-strip, i.e.
    #    hits_for(tag) (path-only, pre-existing accessor) agrees.
    assert origin.hits_for(tag) == 1, \
        ("origin-side path must carry the unique marker post proxy_pass "
         f"rewrite; hits_for(tag)={origin.hits_for(tag)}")

    # 3. THE FALSIFIABILITY PROOF: point an ordinary GET at the exact same
    #    URL, then re-check the SAME "no GET here" assertion from step 1. A
    #    structurally sound accessor must now flip to a NONZERO count and
    #    fail that assertion -- this is what distinguishes hits_for_method
    #    from the method-blind hits_for, which cannot see a GET at all and so
    #    could never catch this regardless of what actually happened. We
    #    don't re-run the literal `assert ... == 0` (that would just fail the
    #    whole test); instead capture the value and assert on IT going
    #    nonzero. NOTE: in the failing branch below (post_get_count == 0),
    #    the step-1 assertion would still wrongly PASS -- that IS the bug
    #    this row exists to remove, so the failure message must say so
    #    plainly instead of claiming a contradiction ("now False" while the
    #    value is 0).
    fetch(ng.port, url, method="GET")
    post_get_count = origin.hits_for_method("GET", tag)
    assert post_get_count > 0, (
        f"EXPECTED-RED PROOF FAILED: a GET was issued against the HEAD-only "
        f"URL {url!r}, but hits_for_method('GET', {tag!r}) still reports 0 "
        "-- the accessor did not observe the GET, so the 'no GET here' "
        "assertion in step 1 would wrongly keep passing. That is the "
        "method-blindness this row exists to remove."
    )
    assert post_get_count == 1, \
        f"expected exactly one GET recorded, got {post_get_count}"


def test_store_head_populates_head_only_url(ng: Nginx, origin: Origin) -> None:
    """P5-6: with cache_turbo_store_head on, a URL that only ever receives HEAD
    stops being a permanent 100% miss. The first HEAD misses and fires an
    internal warm subrequest (a real GET at the origin); a later HEAD is a HIT.

    The /shoff/ half is the gate-off control: the SAME request sequence against
    the SAME location shape with the directive at its default must NOT produce
    an entry. Without it, a HIT on the second HEAD could not be attributed to
    the directive rather than to some pre-existing behaviour."""
    tag = "p56r2-store-head"

    # --- directive ON ---
    s0, _, h0 = fetch(ng.port, f"/sh/{tag}", method="HEAD")
    assert s0 == 200, f"first HEAD status {s0}"
    assert "x-cache" not in h0, f"first HEAD must miss, got {h0.get('x-cache')}"

    # The warm subrequest is a BACKGROUND subrequest: it completes
    # asynchronously, so poll rather than assuming it has landed.
    assert wait_for(
        lambda: origin.hits_for_method("GET", f"/sh/{tag}") > 0
    ), ("the HEAD miss must have fired a warm subrequest that reaches the "
        "origin as a GET; hits_for_method('GET', ...) stayed 0")

    assert wait_for(
        lambda: fetch(ng.port, f"/sh/{tag}", method="HEAD")[2].get("x-cache")
        == "HIT"
    ), "a later HEAD on the same URL must be served from cache"

    # --- directive OFF (control) ---
    off = "p56r2-store-head-off"
    s1, _, h1 = fetch(ng.port, f"/shoff/{off}", method="HEAD")
    assert s1 == 200, f"control HEAD status {s1}"
    assert "x-cache" not in h1, "control first HEAD must miss"
    time.sleep(0.3)
    assert origin.hits_for_method("GET", f"/shoff/{off}") == 0, (
        "with cache_turbo_store_head off no warm GET may be fired; "
        f"got {origin.hits_for_method('GET', f'/shoff/{off}')}"
    )
    _s2, _, h2 = fetch(ng.port, f"/shoff/{off}", method="HEAD")
    assert h2.get("x-cache") != "HIT", (
        "with the directive off a HEAD-only URL must stay a miss -- a HIT "
        "here means the store happened without the directive"
    )


def test_store_head_fixture_no_method_collapse(
    ng: Nginx, origin: Origin
) -> None:
    """P5-6-r1, HALF TWO: prove the /sh/ fixture does NOT collapse HEAD and GET
    onto the same origin path.

    This is the half that actually failed in cycle 6. The implementation and
    its assertions were not what produced the false green -- the FIXTURE was:
    `/c/` proxy_passes with a TRAILING SLASH, nginx strips the location prefix,
    and so a HEAD to /c/<tag> and a GET to /c2/<tag> (or any other stripping
    location) both arrive at the origin as /<tag>. An entry the test believed
    was HEAD-derived had in fact been stored by a real GET, and every assertion
    downstream was measuring the wrong object.

    DONE CRITERION: a HEAD-only URL is verified NEVER touched by a GET. The
    oracle MUST be hits_for_method() (P5-6-r1a, PR #391); hits_for() is
    method-blind and structurally cannot make this statement -- asserting on it
    would reproduce the false green rather than detect it."""
    tag = "p56r1-no-collapse"
    url = f"/shoff/{tag}"

    # /shoff/ has cache_turbo_store_head OFF, so NOTHING this module does can
    # issue a GET on this path -- no warm subrequest is fired. Any GET the
    # origin records here therefore comes from path collapse, which is exactly
    # what this test is looking for.
    for _ in range(3):
        s0, _, _ = fetch(ng.port, url, method="HEAD")
        assert s0 == 200, f"HEAD status {s0}"

    # 1. The origin saw the HEADs on this exact path -- so the path really is
    #    the one under test and the assertion below is not vacuous on an
    #    empty counter.
    assert origin.hits_for_method("HEAD", url) == 3, (
        f"expected 3 origin HEADs on {url!r}, got "
        f"{origin.hits_for_method('HEAD', url)} -- if this is 0 the origin "
        "never saw this path verbatim and the no-collapse assertion below "
        "would pass vacuously"
    )

    # 2. THE DONE CRITERION: no GET has ever touched this HEAD-only path.
    assert origin.hits_for_method("GET", url) == 0, (
        f"FIXTURE COLLAPSE: a GET reached the HEAD-only origin path {url!r} "
        f"({origin.hits_for_method('GET', url)} recorded). HEAD and GET are "
        "not distinguishable at this origin, so any HEAD-vs-GET assertion "
        "built on this fixture is false green -- the cycle-6 defect."
    )

    # 3. NEGATIVE CONTROL ON THE ORACLE ITSELF: issue a real GET on the same
    #    path and require the counter to move. Without this, assertion 2
    #    proves only that the counter is stuck at zero -- a broken accessor,
    #    a wrong path spelling or a typo'd method string would all satisfy it.
    fetch(ng.port, url, method="GET")
    assert origin.hits_for_method("GET", url) == 1, (
        "ORACLE PROOF FAILED: a GET was issued against "
        f"{url!r} and hits_for_method('GET', ...) still reports "
        f"{origin.hits_for_method('GET', url)} -- assertion 2 above cannot be "
        "trusted, since the counter it reads does not move when the thing it "
        "watches for actually happens."
    )

    # 4. And the HEAD counter did NOT move, confirming the two methods are
    #    accounted separately at the origin rather than summed.
    assert origin.hits_for_method("HEAD", url) == 3, (
        "the GET must not have been recorded as a HEAD; "
        f"hits_for_method('HEAD', {url!r}) = "
        f"{origin.hits_for_method('HEAD', url)}, expected 3"
    )


def test_head_derived_entry_never_served_to_get(
    ng: Nginx, origin: Origin
) -> None:
    """P5-6-r1 -- THE MANDATORY NEGATIVE CONTROL for the serve-side guard.

    THE INVARIANT: a HEAD-derived entry (BLOBF_HEAD_DERIVED, 0x0040) must NEVER
    be served to a GET. The guard lives at the serve chokepoint,
    ngx_http_cache_turbo_serve() in module.c, beside the BLOBF_BREAKER_ONLY /
    BLOBF_AUTH_SHAREABLE / BLOBF_ORIGIN_ENCODED guards.

    ⚠⚠ WHY THIS TEST IS SHAPED THE WAY IT IS. Cycle 6 shipped a full
    implementation of this feature whose serve-side guard was DEAD CODE, and
    both of its tests were FALSE GREEN -- they still passed with the guard
    mutated to `if (0 && ...)`. The root cause was the FIXTURE, not the
    assertions: `/c/` proxy_passes with a TRAILING SLASH, which strips the
    location prefix, so the HEAD-only URL and an ordinary GET collapsed onto
    the same origin path and the entry under test was actually stored by a real
    GET. Two structural properties defend against a repeat:

      1. `/sh/` proxy_passes WITHOUT a trailing slash (see nginx_config.py), so
         the origin sees "/sh/<tag>" verbatim and cannot be reached by any
         other location's traffic.
      2. The oracle is `hits_for_method()` (P5-6-r1a, PR #391), which is keyed
         on (method, path). The older `hits_for()` is METHOD-BLIND and cannot
         distinguish a HEAD from a GET to the same path -- an assertion built
         on it would pass no matter what happened, which is precisely the
         false-green shape.

    The assertion that must go red under the mutation is the x-cache one: with
    the guard compiled out, the stamped entry IS served and the GET reports
    HIT."""
    tag = "p56r1-never-to-get"
    url = f"/sh/{tag}"

    # 1. Establish a head-derived entry, and prove it is head-derived by
    #    construction: the ONLY client request against this URL is a HEAD.
    s0, _, h0 = fetch(ng.port, url, method="HEAD")
    assert s0 == 200, f"HEAD status {s0}"
    assert "x-cache" not in h0, "first HEAD must miss"

    assert wait_for(lambda: fetch(ng.port, url, method="HEAD")[2].get("x-cache")
                    == "HIT"), \
        "the head-derived entry must exist before the GET is issued -- " \
        "without it this test would prove nothing (nothing to refuse)"

    # 2. FIXTURE PROOF, part one: the origin has seen exactly ONE GET on this
    #    path (the warm subrequest), and no GET from any client. Recorded here,
    #    BEFORE the client GET, so step 4 can attribute the increment.
    warm_gets = origin.hits_for_method("GET", url)
    assert warm_gets >= 1, (
        f"expected at least one origin GET on {url!r} (the warm subrequest), "
        f"got {warm_gets}"
    )
    #    Every GET the origin has seen on this path so far is a WARM
    #    subrequest -- no client GET has been issued yet. (More than one is
    #    normal and not a fixture collapse: the HEAD poll above can re-miss
    #    while the first warm is still in flight and fire its own.) Step 4
    #    asserts on the DELTA from this baseline, so the exact number here
    #    does not matter; what matters is that it is fixed before the GET.
    head_hits = origin.hits_for_method("HEAD", url)
    assert head_hits >= 1, (
        f"the origin must have seen the client HEAD on {url!r}; "
        f"hits_for_method('HEAD', ...) = {head_hits}"
    )

    # 3. THE GUARDED ASSERTION. A GET against the head-derived entry must be
    #    REFUSED by the serve chokepoint and go to the origin as a miss.
    #    ⚠ This is the line that must go RED when the guard is mutated to
    #    `if (0 && ...)`: with the guard compiled out the entry is served and
    #    x-cache reads HIT.
    sg, _, hg = fetch(ng.port, url, method="GET")
    assert sg == 200, f"GET status {sg}"
    assert hg.get("x-cache") != "HIT", (
        "INVARIANT VIOLATED: a GET was served from a HEAD-derived entry "
        f"(x-cache={hg.get('x-cache')!r}). BLOBF_HEAD_DERIVED must be refused "
        "at the serve chokepoint for every non-HEAD request."
    )

    # 4. FIXTURE PROOF, part two: the refusal really did reach the origin --
    #    a SECOND GET is now recorded on this exact path. This is what makes
    #    step 3 an observable behaviour rather than merely a missing header:
    #    a response could lack x-cache for other reasons, but only a genuine
    #    pass-through to the origin bumps this counter.
    assert wait_for(
        lambda: origin.hits_for_method("GET", url) > warm_gets
    ), (
        "the refused GET must have gone to the origin; "
        f"hits_for_method('GET', {url!r}) = "
        f"{origin.hits_for_method('GET', url)}, expected > {warm_gets}"
    )

    # 5. And the store performed by that GET replaces the stamped entry with
    #    an ordinary one, so the guard costs at most one extra fetch per URL
    #    rather than pinning it into permanent misses.
    assert wait_for(lambda: fetch(ng.port, url, method="GET")[2].get("x-cache")
                    == "HIT"), \
        "after the refused GET repopulated the entry, a further GET must HIT"


def test_honor_cache_control(ng: Nginx) -> None:
    """v7: with cache_turbo_cache_control honor, the origin's max-age=1 shortens
    the fresh TTL below the configured 60s — so the entry is stale at ~2s.

    TEST-MICROTTL-ORACLE (2026-08-23): the immediate re-read below only proves
    the entry was STORED (accepting HIT or STALE), not that it is still inside
    the 1s fresh window -- the module never promised the two live HTTP round
    trips complete in under 1s, and under ASan multi-worker load they sometimes
    don't (PR #414's run 32620522765). The fresh-vs-stale distinction this test
    exists to make is the deterministic STALE-at-2s check below, which has a
    full 1s of margin over the max-age=1 boundary and needs no race. The same
    relaxation is applied to every sibling TTL-precedence test in this file
    (test_honor_expires_absolute_ttl and the CDN-Cache-Control / Surrogate-
    Control precedence and split-header tests immediately below) since they
    share this exact shape against the same /cc7/ honor location."""
    _, _, h0 = fetch(ng.port, "/cc7/ttl1")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/cc7/ttl1")
    assert h1.get("x-cache") in ("HIT", "STALE"), \
        f"second should be served from cache (HIT or a raced STALE), got {h1.get('x-cache')}"
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
    # TEST-MICROTTL-ORACLE: HIT or a raced STALE both prove storage; see
    # test_honor_cache_control.
    assert h1.get("x-cache") in ("HIT", "STALE"), \
        f"second should be served from cache, got {h1.get('x-cache')}"
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
    # TEST-MICROTTL-ORACLE: HIT or a raced STALE both prove storage; see
    # test_honor_cache_control.
    assert h1.get("x-cache") in ("HIT", "STALE"), \
        f"second should be served from cache, got {h1.get('x-cache')}"
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
    # TEST-MICROTTL-ORACLE: HIT or a raced STALE both prove storage; see
    # test_honor_cache_control.
    assert h1.get("x-cache") in ("HIT", "STALE"), \
        f"second should be served from cache, got {h1.get('x-cache')}"
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
    # TEST-MICROTTL-ORACLE: HIT or a raced STALE both prove storage; see
    # test_honor_cache_control.
    assert h1.get("x-cache") in ("HIT", "STALE"), \
        f"second should be served from cache, got {h1.get('x-cache')}"
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
    # TEST-MICROTTL-ORACLE: HIT or a raced STALE both prove storage; see
    # test_honor_cache_control.
    assert h1.get("x-cache") in ("HIT", "STALE"), \
        f"second should be served from cache, got {h1.get('x-cache')}"
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
    stale-serve past freshness.

    TEST-MICROTTL-ORACLE (2026-08-23): unlike the /cc7/ honor-mode TTL tests,
    a must-revalidate entry never shows an intermediate STALE state, so
    "accept HIT or STALE" cannot make the immediate re-read race-tolerant here
    -- past the deadline it collapses straight to a revalidate that looks
    identical to "never stored". origin.py widened this marker's max-age from
    1s to 4s so the live round trip has real margin; see test_must_revalidate
    for the full rationale."""
    _, _, h0 = fetch(ng.port, "/ccsplit/splitmrev")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/ccsplit/splitmrev")
    assert h1.get("x-cache") == "HIT", f"second should be a fresh HIT, got {h1}"
    time.sleep(6.0)                               # past max-age=4, generous margin
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
    serve), proving the must-revalidate token collapses the stale window.

    TEST-MICROTTL-ORACLE (2026-08-23): the immediate re-read still asserts a
    strict fresh HIT (not "HIT or STALE" like the /cc7/ tests) because a
    must-revalidate entry has no observable STALE state to fall back to --
    past the deadline it collapses straight to an origin revalidate, which is
    indistinguishable from "was never stored" by X-Cache alone. That makes the
    live round trip's own margin the only lever: origin.py widened this
    marker's Cache-Control from max-age=1 to max-age=4 (was flagged racing the
    1s window under ASan multi-worker, e.g. PR #414's run 32620522765 on the
    sibling test_honor_cache_control), giving two quick HTTP round trips ample
    slack to complete before the deadline even under a slow sanitizer build.
    The post-deadline sleep below is widened to match (was 2.0 past max-age=1,
    now 6.0 past max-age=4 -- 2s of margin, and there is no upper-bound risk to
    overshoot since must-revalidate has no stale window to fall out of the far
    side of)."""
    _, _, h0 = fetch(ng.port, "/mrev/mustrev")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/mrev/mustrev")
    assert h1.get("x-cache") == "HIT", f"second should be a fresh HIT, got {h1}"
    time.sleep(6.0)                               # past max-age=4, generous margin
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
    "max-age=4, proxy-revalidate" (widened from 1s; see test_must_revalidate's
    TEST-MICROTTL-ORACLE note for why the immediate HIT check needs the extra
    margin here and cannot fall back to accepting STALE)."""
    _, _, h0 = fetch(ng.port, "/mrev/proxyrev")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/mrev/proxyrev")
    assert h1.get("x-cache") == "HIT", f"second should be a fresh HIT, got {h1}"
    time.sleep(6.0)                               # past max-age=4, generous margin
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


def test_vary_ignore_makes_named_axis_cacheable(ng: Nginx, origin: Origin) -> None:
    """P3-3: `cache_turbo_vary_ignore Accept` drops the Accept token BEFORE
    classify_vary()'s whitelist/unknown-axis check. `Vary: Accept` is a real-
    world killer (very common on APIs/image CDNs) that the built-in whitelist
    has no bit for, so /av/ (no vary_ignore) permanently refuses it -- see
    test_auto_vary_unknown_axis_uncacheable. On /avi/ (vary_ignore Accept) the
    SAME response must become cacheable and serve a HIT on re-fetch."""
    base = origin.hits_for("/u?v=acc")
    _, _, h0 = fetch(ng.port, "/avi/u?v=acc")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/avi/u?v=acc")
    assert h1.get("x-cache") == "HIT", \
        f"vary_ignore Accept should make this cacheable, got {h1.get('x-cache')}"
    assert origin.hits_for("/u?v=acc") == base + 1, \
        "vary_ignore Accept did not actually collapse to one origin hit"


def test_vary_ignore_negative_control_without_directive(ng: Nginx,
                                                          origin: Origin) -> None:
    """P3-3 negative control: the SAME `Vary: Accept` response against /av/
    (identical config MINUS cache_turbo_vary_ignore) must stay uncacheable --
    proving the directive, not something else (a different URL, a different
    origin behaviour), is what changed the outcome in the sibling test."""
    base = origin.hits_for("/u?v=acc")
    _, _, h0 = fetch(ng.port, "/av/u?v=acc")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/av/u?v=acc")
    assert "x-cache" not in h1, \
        f"without vary_ignore, Vary: Accept must stay uncacheable, got {h1.get('x-cache')}"
    assert origin.hits_for("/u?v=acc") == base + 2, \
        "un-keyable Vary: Accept was wrongly cached without the directive"


def test_vary_ignore_axis_excluded_from_variant_key(ng: Nginx,
                                                      origin: Origin) -> None:
    """P3-3: an ignored axis must not enter the variant key. Two requests
    differing ONLY in the ignored header (Accept) must hit the SAME cache
    entry -- i.e. the second request, with a DIFFERENT Accept value, still
    HITs the first request's slot instead of missing to a distinct one."""
    base = origin.hits_for("/u?v=acc&t=key")
    p = "/avi/u?v=acc&t=key"
    _, b1, h1 = fetch(ng.port, p, {"Accept": "text/html"})
    assert "x-cache" not in h1, "first should miss"
    _, b2, h2 = fetch(ng.port, p, {"Accept": "application/json"})
    assert h2.get("x-cache") == "HIT", \
        ("a different Accept value must still hit the SAME slot once the "
         f"axis is ignored, got {h2.get('x-cache')}")
    assert b1 == b2, (("ignored axis leaked into the variant key -- two "
                       "different Accept values produced two different "
                       "bodies"), b1, b2)
    assert origin.hits_for("/u?v=acc&t=key") == base + 1, \
        "ignored Accept axis wrongly caused a second origin hit"


def test_vary_ignore_does_not_disable_other_unknown_axes(ng: Nginx,
                                                           origin: Origin) -> None:
    """P3-3: cache_turbo_vary_ignore Accept must not accidentally disable the
    unknown-axis refusal arm generally -- a DIFFERENT un-whitelisted, non-
    ignored axis (Accept-Charset, same as test_auto_vary_unknown_axis_uncacheable)
    on the SAME /avi/ location must still refuse to cache."""
    base = origin.hits_for("/u?v=cs")
    _, _, h0 = fetch(ng.port, "/avi/u?v=cs")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/avi/u?v=cs")
    assert "x-cache" not in h1, \
        ("vary_ignore Accept must not disable the unknown-axis refusal for "
         f"OTHER un-ignored axes, got {h1.get('x-cache')}")
    assert origin.hits_for("/u?v=cs") == base + 2, \
        "un-keyable, non-ignored Vary axis was wrongly cached on /avi/"


def test_auto_vary_stale_marker_reachable(ng: Nginx, origin: Origin) -> None:
    """auto-Vary: once the variant and its L1 vary marker go stale (but are still
    inside the stale window), a request must still resolve to the variant via the
    stale marker and serve it from cache — not fall back to the base key and miss
    to origin (codex follow-up)."""
    ae = {"Accept-Encoding": "gzip"}
    _, _, h0 = fetch(ng.port, "/avs/m?v=ae", headers=ae)
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/avs/m?v=ae", headers=ae)
    # TEST-MICROTTL-ORACLE (2026-08-23): HIT or a raced STALE both prove the
    # variant was stored, without racing the 2s fresh window over two live
    # HTTP round trips under a slow sanitizer build; see test_honor_cache_control
    # (policy.py) for the full rationale. The stale-marker-reachability property
    # this test exists to prove is the deterministic post-sleep check below.
    assert h1.get("x-cache") in ("HIT", "STALE"), \
        f"second should be served from cache, got {h1.get('x-cache')}"
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


def test_refuse_partial_counter(ng: Nginx, origin: Origin) -> None:
    """P0-1: cache_turbo_refuse_partial_total rises by exactly one per 206
    response, the same fixture as test_206_never_cached but observing the new
    per-reason counter instead of the store outcome."""
    url = "/c/partial-206ctr"
    r0 = _admin_stat(ng, "refuse_partial")
    s0, _, _ = fetch(ng.port, url)
    assert s0 == 206
    assert _admin_stat(ng, "refuse_partial") - r0 == 1, \
        "refuse_partial_total must rise by 1 for a single 206 response"
    fetch(ng.port, url)
    assert _admin_stat(ng, "refuse_partial") - r0 == 2, \
        "refuse_partial_total must rise once per 206, not just the first"


def test_refuse_head_counter(ng: Nginx, origin: Origin) -> None:
    """P0-1: cache_turbo_refuse_head_total rises once per HEAD request that
    reaches the header filter's capture gate -- HEAD's empty body must never
    overwrite the stored GET entry, so it always trips this counter."""
    url = "/c/headctr"
    r0 = _admin_stat(ng, "refuse_head")
    s0, _, _ = fetch(ng.port, url, method="HEAD")
    assert s0 == 200, f"HEAD should reach the origin cleanly, got {s0}"
    assert _admin_stat(ng, "refuse_head") - r0 == 1, \
        "refuse_head_total must rise by 1 for a single HEAD request"
    # A GET on the SAME url must not itself trip refuse_head -- proves the
    # counter is keyed on the request method, not the URL.
    fetch(ng.port, url)
    assert _admin_stat(ng, "refuse_head") - r0 == 1, \
        "a GET must not bump refuse_head_total"


def test_refuse_set_cookie_counter(ng: Nginx, origin: Origin) -> None:
    """P0-1: cache_turbo_refuse_set_cookie_total rises once per Set-Cookie
    response refused by the store floor -- same fixture as
    test_no_cache_set_cookie, observing the new counter."""
    url = "/cc/setcookiectr"
    r0 = _admin_stat(ng, "refuse_set_cookie")
    fetch(ng.port, url)
    assert _admin_stat(ng, "refuse_set_cookie") - r0 == 1, \
        "refuse_set_cookie_total must rise by 1 for a single Set-Cookie response"
    fetch(ng.port, url)
    assert _admin_stat(ng, "refuse_set_cookie") - r0 == 2, \
        "refuse_set_cookie_total must rise once per refused response"


def test_refuse_cache_control_counter(ng: Nginx, origin: Origin) -> None:
    """P0-1: cache_turbo_refuse_cache_control_total rises once per response
    vetoed by Cache-Control (no-store/no-cache/private/max-age=0/s-maxage=0)
    -- same fixture as test_no_cache_cc_private / test_no_cache_cc_nostore."""
    r0 = _admin_stat(ng, "refuse_cache_control")
    fetch(ng.port, "/cc/ccprivatectr")
    assert _admin_stat(ng, "refuse_cache_control") - r0 == 1, \
        "Cache-Control: private must bump refuse_cache_control_total"
    fetch(ng.port, "/cc/ccnostorectr")
    assert _admin_stat(ng, "refuse_cache_control") - r0 == 2, \
        "Cache-Control: no-store must also bump refuse_cache_control_total"


def test_refuse_authorization_counter(ng: Nginx, origin: Origin) -> None:
    """P0-1: cache_turbo_refuse_authorization_total rises once per request
    that carried Authorization -- same fixture as test_no_cache_authorization.
    Bumped in access_eligible()'s LOOKUP-side gate (access.c), not the header
    filter's response_cacheable() call: an Authorization request never
    allocates ctx (access_eligible() declines before ctx exists), so the
    header filter bails on ctx==NULL before response_cacheable()'s own
    AUTHORIZATION reason could ever fire on this path."""
    r0 = _admin_stat(ng, "refuse_authorization")
    fetch(ng.port, "/c/authreq-ctr", headers={"Authorization": "Bearer x"})
    assert _admin_stat(ng, "refuse_authorization") - r0 == 1, \
        "refuse_authorization_total must rise by 1 for a single Authorization request"


def test_refuse_require_header_counter(ng: Nginx, origin: Origin) -> None:
    """P0-1: cache_turbo_refuse_require_header_total rises once per response
    refused by cache_turbo_require_header (absent or non-affirmative) --
    same /gql/ fixture as test_require_header."""
    r0 = _admin_stat(ng, "refuse_require_header")
    # header absent entirely
    fetch(ng.port, "/gql/absentctr")
    assert _admin_stat(ng, "refuse_require_header") - r0 == 1, \
        "an absent require_header must bump refuse_require_header_total"
    # non-affirmative value
    fetch(ng.port, "/gql/noctr", headers={"X-Want-Cacheable": "no"})
    assert _admin_stat(ng, "refuse_require_header") - r0 == 2, \
        "a non-affirmative require_header value must also bump the counter"
    # affirmative value must NOT bump it
    fetch(ng.port, "/gql/okctr", headers={"X-Want-Cacheable": "yes"})
    assert _admin_stat(ng, "refuse_require_header") - r0 == 2, \
        "an affirmative require_header value must not bump refuse_require_header_total"


def test_refuse_encoded_counter(ng: Nginx, origin: Origin) -> None:
    """P0-1: cache_turbo_refuse_encoded_total rises once per response that
    arrives already Content-Encoding'd (origin pre-compression). Uses the
    "precompressed" origin marker added alongside this counter."""
    url = "/c/precompressedctr"
    r0 = _admin_stat(ng, "refuse_encoded")
    s0, _, h0 = fetch(ng.port, url)
    assert s0 == 200 and h0.get("content-encoding") == "gzip", \
        f"origin should answer pre-encoded, got status={s0} headers={h0}"
    assert "x-cache" not in h0, "a pre-encoded response must never be a HIT"
    assert _admin_stat(ng, "refuse_encoded") - r0 == 1, \
        "refuse_encoded_total must rise by 1 for a single pre-encoded response"
    fetch(ng.port, url)
    assert _admin_stat(ng, "refuse_encoded") - r0 == 2, \
        "a pre-encoded response is refused every time, never cached"


def test_refuse_vary_unsafe_counter(ng: Nginx, origin: Origin) -> None:
    """P0-1: cache_turbo_refuse_vary_unsafe_total rises once per response
    whose Vary header names an axis outside the whitelist -- same fixture as
    test_auto_vary_unknown_axis_uncacheable. Does NOT fire for Vary: Cookie /
    Authorization / "*" (see test_refuse_vary_unsafe_excludes_named_vetoes),
    since those are separately attributable causes."""
    r0 = _admin_stat(ng, "refuse_vary_unsafe")
    fetch(ng.port, "/av/unsafectr?v=cs")
    assert _admin_stat(ng, "refuse_vary_unsafe") - r0 == 1, \
        "an un-whitelisted Vary axis must bump refuse_vary_unsafe_total"


def test_refuse_vary_unsafe_excludes_named_vetoes(ng: Nginx,
                                                   origin: Origin) -> None:
    """P0-1: Vary: Cookie / Authorization / "*" are already attributable to a
    NAMED cause elsewhere (the request-side Authorization counter, or -- for
    Cookie/"*" -- they are RFC 9111 floors distinct from 'axis we don't
    recognise'). refuse_vary_unsafe must stay at 0 for these so it measures
    only the genuinely-unknown-axis case test_refuse_vary_unsafe_counter
    drives, not every auto-Vary veto."""
    r0 = _admin_stat(ng, "refuse_vary_unsafe")
    fetch(ng.port, "/av/starctr?v=star")
    fetch(ng.port, "/av/cookiectr?v=ck")
    assert _admin_stat(ng, "refuse_vary_unsafe") - r0 == 0, \
        "Vary: * / Cookie must not bump refuse_vary_unsafe_total (named vetoes)"


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
    assert s_hit == 206, (
        f"a Range request against a cache-turbo HIT must answer 206 like a "
        f"MISS does, got {s_hit} (Accept-Ranges was replayed but the range "
        f"was not honoured)")
    assert s_hit == s_miss, f"HIT status {s_hit} != MISS status {s_miss}"
    assert h_hit.get("content-range") == h_miss.get("content-range"), (
        f"HIT Content-Range {h_hit.get('content-range')!r} != "
        f"MISS Content-Range {h_miss.get('content-range')!r}")
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
    assert s_hit == 206, (
        f"a suffix Range against a HIT must answer 206 like a MISS does, "
        f"got {s_hit}")
    assert h_hit.get("content-range") == h_miss.get("content-range"), (
        f"HIT Content-Range {h_hit.get('content-range')!r} != "
        f"MISS Content-Range {h_miss.get('content-range')!r}")
    assert b_hit == b_miss, \
        f"HIT suffix body {b_hit!r} != MISS suffix body {b_miss!r}"
    # The LAST 50 bytes, not the first 50: a mis-sliced suffix that still
    # returned 50 bytes would pass a length-only assert.
    assert len(b_hit) == 50, f"bytes=-50 should be 50 bytes, got {len(b_hit)}"
    assert h_hit.get("content-range") == "bytes 150-199/200", (
        f"bytes=-50 of a 200-byte body is 150-199, got "
        f"{h_hit.get('content-range')!r}")


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
    assert s_hit == 416, (
        f"an unsatisfiable Range against a cached entry must answer 416, got "
        f"{s_hit} (before the send_header fix this was not a wrong status but "
        f"NO RESPONSE -- the connection was closed mid-request)")
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
    assert etag == '"rngetag"', (
        f"fixture is wrong, not the module: rngcond must emit an ETag, got "
        f"{etag!r}")

    # Positive half first, and it must depend on the PERMIT, not on the blob.
    # Accept-Ranges is replayed from the stored headers (the origin sent it), so
    # asserting that header would pass even with module.c:6563 deleted --
    # measured: it survived that exact mutation. Issuing a real Range and
    # requiring 206 is what the permit actually gates.
    s_hit, b_hit, h_hit = fetch_raw(ng.port, url,
                                    headers={"Range": "bytes=0-9"})
    assert h_hit.get("x-cache") == "HIT", f"ranged fetch should HIT: {h_hit}"
    assert s_hit == 206, (
        f"a cached 200 must be range-servable (the permit at module.c:6563), "
        f"got {s_hit}")
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
        assert h.get("x-cache") == "STALE-IF-ERROR", (
            f"expected a serve-on-error replay, got x-cache={h.get('x-cache')} "
            f"status={s} (the fixture, not the Range, is wrong)")
        assert s == 206, (
            f"a Range against a STALE-IF-ERROR serve must answer 206 like a "
            f"HIT does, got {s} -- the client asked for a slice and got the "
            f"whole body")
        assert h.get("content-range") == "bytes 0-99/200", (
            f"Content-Range on the SIE serve is {h.get('content-range')!r}, "
            f"expected bytes 0-99/200")
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

    /condst/ has a 1s TTL (shared with test_p4_multi_directive_single_resolve,
    which sleeps past it to exercise the STALE path deliberately - do not
    widen it here; test_rfc1_request_max_stale moved to its own /maxstale/
    location with a wider stale window, see STALE-WINDOW-OVERSHOOT there).
    The fresh-conditional leg
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
    max-stale gets a revalidation; adding max-stale re-permits the stale serve.

    TTL-REVAL-RACE (2026-08-17, failed twice on shared CI runners): the entry
    has a 1s TTL. A fixed `time.sleep(1.5)` measures elapsed time from the
    TEST's clock, not from when the server actually saw the prime request --
    on a loaded runner the prime itself can take non-trivial wall-clock time,
    shrinking the real margin to well under 0.5s. Anchor the wait to the
    moment the prime response is OBSERVED, and wait past the TTL by a
    generous fixed SLACK on top of it -- not just past the TTL itself -- so
    that skew between "server started the TTL clock" and "client observed
    the response" cannot eat the whole margin the way it did before. This is
    a plain sleep (there is no system state to poll here: staleness is not
    independently observable from outside except by making the very request
    that then IS the assertion), so it is written as one rather than dressed
    up as wait_for(). The primary oracle is the ORIGIN HIT COUNT (did the
    request actually reach the origin to revalidate), not the x-cache header
    alone -- a re-primed entry can also read back as a fresh HIT with age=0,
    which is indistinguishable from "still fresh" if x-cache is the only
    signal.

    STALE-WINDOW-OVERSHOOT (2026-08-20, failed under both ASan lanes on an
    innocent PR): #379 fixed the too-SMALL lower margin above but only
    checked the lower bound. The stale window is FINITE -- it also has an
    upper bound where the entry expires outright and falls through to
    origin, which trips the very "must not hit origin" assertion this test
    is making. `sanitizer_time_scale()` returns 2.0 under ASan, so the sleep
    is `(ttl + slack) * scale`:
        non-ASan: (1.0 + 0.75) * 1.0 = 1.75s
        ASan:     (1.0 + 0.75) * 2.0 = 3.50s
    On /condst/ (default stale_mult 4 -> stale window 1s-4s) the ASan sleep
    of 3.5s left only 0.5s before the 4s expiry -- easily eaten by the
    prime request's own wall-clock time plus scheduling jitter on a loaded
    runner, so the entry EXPIRED instead of going STALE and the request fell
    through to origin. The wait must land INSIDE a window with margin on
    BOTH sides, not merely past a single deadline.

    Fix: use a dedicated location, /maxstale/, with stale_mult 8 (the
    module's max) instead of widening /condst/'s window out from under its
    other two consumers (test_rfc6_stale_conditional_full,
    test_p4_multi_directive_single_resolve). The proxied key is
    /maxstale/cond-max-ms: it keeps the "cond" substring origin.py requires
    to emit ETag/Last-Modified (dropping it would silently downgrade this
    test's coverage to a validator-less origin -- caught in review) while
    staying distinct from /cond-ms and /condst/'s other keys so this test's
    origin.hits_for() oracle is never shared with another test's traffic.
    That gives a stale window of 1s-8s:
        non-ASan sleep 1.75s -> 0.75s clear of the 1s lower bound,
                                 6.25s clear of the 8s upper bound
        ASan     sleep 3.50s -> 2.50s clear of the 1s lower bound,
                                 4.50s clear of the 8s upper bound
    Both lanes land comfortably inside the window with multi-second margin
    on each side. If ttl, slack or stale_mult ever change here, recompute
    both margins and keep them positive under the 2.0 ASan scale."""
    # "cond" in the proxied path is LOAD-BEARING: origin.py gates ETag /
    # Last-Modified emission on that substring (see the /maxstale/ location
    # comment in nginx_config.py), and this test's coverage previously
    # depended on the entry carrying validators. Assert it below rather than
    # merely assuming the substring worked.
    sp, _, hp = fetch_raw(ng.port, "/maxstale/cond-max-ms")        # prime, fresh 1s
    assert sp == 200 and hp.get("etag") == '"v11etag"', \
        f"prime must carry the origin's conditional validator: {sp} {hp}"
    ttl = 1.0
    slack = 0.75                    # generous margin: a long wait is cheap,
                                     # a flake is not -- see TTL-REVAL-RACE
    time.sleep((ttl + slack) * sanitizer_time_scale())
    before = origin.hits_for("/cond-max-ms")
    # max-stale present -> accept the stale copy (beta 1, no refresh)
    s0, b0, h0 = fetch_raw(ng.port, "/maxstale/cond-max-ms",
                           headers={"Cache-Control": "max-age=1, max-stale=30"})
    assert origin.hits_for("/cond-max-ms") == before, \
        f"max-stale stale serve must not hit origin: {s0} {h0}"
    assert s0 == 200 and b0 and h0.get("x-cache") == "STALE", \
        f"max-stale must permit the stale serve: {s0} {h0}"
    # same tight max-age but NO max-stale -> no stale tolerance -> revalidate
    s1, _, h1 = fetch_raw(ng.port, "/maxstale/cond-max-ms",
                          headers={"Cache-Control": "max-age=1"})
    assert origin.hits_for("/cond-max-ms") == before + 1, \
        f"no-max-stale revalidation must hit origin: {s1} {h1}"
    assert s1 == 200 and "x-cache" not in h1, \
        f"max-age without max-stale must revalidate a stale entry: {h1}"


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
    assert en2 != en0, (
        "AUD-GEN1: post-wrap body matches the pre-purge #1 body -- purged "
        "variant resurrected")


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


def test_cor5_varidx_selfheal_after_dropped_index_write(
        ng: Nginx, origin: Origin, redis: RedisServer) -> None:
    """COR-5(b): a variant-index write DROPPED before the wire must self-heal.

    The defect (PR #379 run 32379308752, job 96459248737: `ERROR: purge should
    report >=2 variants: {"purged":1}`): the store path called tag_add() and
    threw the return value away, so a SADD refused by redis_launch() -- an
    armed S231 connect-backoff window, a failed connect -- left the object in
    L1 and L2 while the per-base variant-index set never learned about it. A
    later PURGE of the base enumerates that set with SMEMBERS, cannot see the
    variant, and reports success while the variant keeps serving a stale
    representation until its own TTL. Nothing anywhere said the write was lost.

    Scenario, on /cor5sh/ (cache_turbo_test_varidx_fail on):

      1. prime the `en` variant normally -- its index entry lands;
      2. prime the `fr` variant with X-Cache-Turbo-Test-Varidx-Drop: 1, so its
         SADD is skipped and the node is marked varidx_pending. The response
         still HITs from L1 -- nothing observable says the index is short;
      3. HIT the `fr` variant again with the drop header OFF. access_l1 finds
         varidx_pending, clears it and re-issues the SADD after unlocking;
      4. PURGE the base. It must now enumerate BOTH variants.

    ORACLE. The assertion is `purged >= 2` PLUS the reissues counter, not just
    the two post-purge misses: with the self-heal removed the base marker is
    still purged, so BOTH variants re-miss to origin anyway on a single-node
    box and the miss assertions alone stay green. `{"purged":N}` counts the
    SMEMBERS enumeration itself, which is the only thing the dropped write
    actually changes, and X-Cache-Turbo-Test-Varidx (drops/reissues) is the
    marker only this path emits.
    """
    import json
    en = {"Accept-Language": "en"}
    fr = {"Accept-Language": "fr"}
    fr_drop = {"Accept-Language": "fr", "X-Cache-Turbo-Test-Varidx-Drop": "1"}

    # 1. en variant, index write allowed through.
    _, en0, _ = fetch(ng.port, "/cor5sh/p?v=al", headers=en)
    _, en1, he1 = fetch(ng.port, "/cor5sh/p?v=al", headers=en)
    assert he1.get("x-cache") == "HIT" and en1 == en0, "en variant should cache"

    # 2. fr variant, index write DROPPED. The object still caches -- that is
    #    the whole problem: the drop is invisible to the client.
    _, fr0, hf0 = fetch(ng.port, "/cor5sh/p?v=al", headers=fr_drop)
    drops0 = _varidx(hf0)["drops"]
    _, fr1, hf1 = fetch(ng.port, "/cor5sh/p?v=al", headers=fr)
    assert hf1.get("x-cache") == "HIT" and fr1 == fr0, \
        "fr variant should cache even though its index write was dropped"
    assert fr0 != en0, "en and fr must be distinct variant slots"
    assert _varidx(hf1)["drops"] > drops0, \
        f"the dropped index write was not detected: {hf0.get('x-cache-turbo-test-varidx')!r}"

    # 3. the HIT at step 2 (drop header absent) is itself the self-heal
    #    trigger: it found varidx_pending set. Take one more HIT so the
    #    re-issue counter is readable on a response we have in hand.
    _, _, hf2 = fetch(ng.port, "/cor5sh/p?v=al", headers=fr)
    assert _varidx(hf2)["reissues"] >= 1, \
        ("self-heal never re-issued the dropped index write: "
         f"{hf2.get('x-cache-turbo-test-varidx')!r}")

    # 4. the index must now list BOTH variants.
    s, b, _ = fetch_raw(ng.port, "/cor5sh/p?v=al", method="PURGE")
    assert s == 200, f"PURGE status {s}"
    assert json.loads(b)["purged"] >= 2, \
        (f"self-heal did not restore the fr variant to the index: {b} "
         "(purged==1 means SMEMBERS saw only the en variant)")

    _, en2, he2 = fetch(ng.port, "/cor5sh/p?v=al", headers=en)
    assert "x-cache" not in he2 and en2 != en0, "en variant survived PURGE"
    _, fr3, hf3 = fetch(ng.port, "/cor5sh/p?v=al", headers=fr)
    assert "x-cache" not in hf3 and fr3 != fr0, "fr variant survived PURGE"


def test_cor5_purge_reports_degraded_enumeration(
        ng: Nginx, origin: Origin, redis: RedisServer) -> None:
    """c-1: `{"purged":N}` must distinguish a COMPLETE SMEMBERS enumeration
    from a DEGRADED one instead of silently under-reporting while still
    returning 200.

    This is a REPORTING defect only -- staleness itself is already covered
    by the marker delete in purge_auto_vary regardless of what SMEMBERS saw,
    so this test does not re-check post-purge misses (test_cor5_redis_variant_
    purge and the self-heal test above already do). What it checks is that an
    operator scripting on `purged` can tell "the index set was short a
    variant when I enumerated it" from "the index set genuinely held every
    variant" -- the two cases used to be wire-identical.

    Uses the SAME fault injection as the self-heal test
    (X-Cache-Turbo-Test-Varidx-Drop on /cor5sh/), but WITHOUT the healing HIT
    the self-heal test takes afterward -- the dropped variant's
    varidx_pending bit is still armed and un-reissued at PURGE time, which is
    exactly the state that leaves SMEMBERS short a variant.

    ORACLE: the reply must carry "complete":false when a drop is
    outstanding, and must NOT carry "complete":false (a fully-enumerated
    purge, the normal case) when every variant's index write reached the
    wire. The mutation that breaks this test: deleting the
    `tp->is_auto_vary && tp->pending_at_launch != 0` check (or hardcoding it
    false) in ngx_http_cache_turbo_tag_purge_complete -- every purge would
    then report unconditionally as if complete, which is precisely the
    silent-under-report defect this item exists to close.
    """
    import json
    en = {"Accept-Language": "en"}
    fr = {"Accept-Language": "fr"}
    fr_drop = {"Accept-Language": "fr", "X-Cache-Turbo-Test-Varidx-Drop": "1"}

    # Use a URI distinct from /cor5sh/p to avoid any state the self-heal test
    # (which runs earlier against the same location) leaves behind.
    _, en0, _ = fetch(ng.port, "/cor5sh/degraded?v=al", headers=en)
    _, en1, he1 = fetch(ng.port, "/cor5sh/degraded?v=al", headers=en)
    assert he1.get("x-cache") == "HIT" and en1 == en0, "en variant should cache"

    # fr variant primed with the index SADD dropped, and NOT healed before
    # the purge below (no follow-up HIT without the drop header) -- the
    # index set is missing this variant when SMEMBERS runs.
    #
    # The drops counter is bumped from the BODY filter, which runs after the
    # header filter has already stamped X-Cache-Turbo-Test-Varidx onto this
    # SAME response -- so hf0 (the drop request's own response) still reads
    # the pre-drop count. Read it off a SECOND request instead, same as the
    # self-heal test's drops0/hf1 pair: any request against this zone (a
    # plain miss/HIT elsewhere on /cor5sh/) sees the bumped counter because
    # it is zone-, not response-, scoped.
    _, _fr0, _ = fetch(ng.port, "/cor5sh/degraded?v=al", headers=fr_drop)
    _, _, hf_confirm = fetch(ng.port, "/cor5sh/degraded-confirm?v=al",
                              headers=en)
    drops0 = _varidx(hf_confirm)["drops"]
    assert drops0 >= 1, f"fault injection did not record a drop: {hf_confirm}"

    s, b, _ = fetch_raw(ng.port, "/cor5sh/degraded?v=al", method="PURGE")
    assert s == 200, f"PURGE status {s}"
    reply = json.loads(b)
    assert reply["purged"] >= 1, f"purge should still report the seen variant: {b}"
    assert reply.get("complete") is False, \
        (f"PURGE with an outstanding, un-healed varidx drop must report "
         f"complete:false -- got {b}")

    # Heal the drop before the baseline check below: pending_at_launch is a
    # ZONE-scoped drops/reissues gap (see the purge.c comment), so an
    # unrelated outstanding drop anywhere in the zone -- including the one
    # this test itself just made -- would otherwise make every subsequent
    # purge in this zone read degraded too, which is correct behaviour but
    # would make the baseline assertion below meaningless (it needs a
    # genuinely gap-free zone to prove "complete" is not unconditional).
    # A HIT on the dropped fr variant WITHOUT the drop header is the same
    # self-heal trigger the COR-5(b) test uses: it finds varidx_pending set,
    # clears it and re-issues the SADD.
    # (matches the COR-5(b) test's own step 2->3 shape: the HIT that FINDS
    # varidx_pending set is the one that consumes it and launches the
    # re-issue, but the reissues counter this SAME response's header filter
    # stamps was read before that launch -- so it reports on the NEXT hit.)
    fetch(ng.port, "/cor5sh/degraded?v=al", headers=fr)
    _, _, hf_heal = fetch(ng.port, "/cor5sh/degraded?v=al", headers=fr)
    counts = _varidx(hf_heal)
    assert counts["reissues"] >= counts["drops"], \
        f"self-heal did not catch up before the baseline check: {counts}"

    # Baseline (no outstanding drop anywhere in the zone): a fully-enumerated
    # purge must NOT claim degraded.
    en_full = {"Accept-Language": "en"}
    fr_full = {"Accept-Language": "fr"}
    _, g0, _ = fetch(ng.port, "/cor5sh/full?v=al", headers=en_full)
    _, g1, hg1 = fetch(ng.port, "/cor5sh/full?v=al", headers=en_full)
    assert hg1.get("x-cache") == "HIT" and g1 == g0, "en variant should cache"
    _, h0, _ = fetch(ng.port, "/cor5sh/full?v=al", headers=fr_full)
    _, h1, hh1 = fetch(ng.port, "/cor5sh/full?v=al", headers=fr_full)
    assert hh1.get("x-cache") == "HIT" and h1 == h0, "fr variant should cache"

    s2, b2, _ = fetch_raw(ng.port, "/cor5sh/full?v=al", method="PURGE")
    assert s2 == 200, f"PURGE status {s2}"
    reply2 = json.loads(b2)
    assert reply2["purged"] >= 2, f"purge should report both variants: {b2}"
    assert reply2.get("complete") is not False, \
        (f"a fully-enumerated purge (no outstanding drop) must not report "
         f"complete:false -- got {b2}")


def _varidx(headers: dict) -> dict:
    """Parse X-Cache-Turbo-Test-Varidx ("drops=<n>,reissues=<n>", TEST_FAULTS
    only) into ints. A MISSING header is a hard failure, never a silent zero --
    a test-only counter that vanished would otherwise read as "nothing
    happened" and turn every assertion above into a tautology."""
    raw = headers.get("x-cache-turbo-test-varidx")
    assert raw, "X-Cache-Turbo-Test-Varidx header absent (non-TEST_FAULTS build?)"
    out = {}
    for field in raw.split(","):
        k, _, v = field.partition("=")
        out[k.strip()] = int(v)
    assert "drops" in out and "reissues" in out, f"malformed varidx header: {raw!r}"
    return out


def test_l9_tag_index_drop_is_observable(ng: Nginx, origin: Origin,
                                         redis: RedisServer) -> None:
    """SILENT-INDEX-DROP option (a): the L9 purge-by-tag index write
    (tag_add/tag_add_many for cache_turbo_tag) is fire-and-forget the same
    way the COR-5(b) variant-index SADD is (see
    test_cor5_varidx_selfheal_after_dropped_index_write above), but until now
    the store site did not even inspect the return value -- a write dropped
    before the wire (armed S231 connect-backoff, failed connect, alloc
    failure) left the object cached while the tag set silently never learned
    about it, and a later purge-by-tag would report success while leaving
    that object stale until its own TTL. Nothing counted it and nothing
    logged it.

    This item is observability ONLY -- unlike COR-5(b) there is no self-heal
    (no per-node pending bit, no natural re-issue point for a tag write), so
    the oracle here is the zone's tag_index_drops admin counter, not a
    "purged" enumeration count. /tagidxdrop/ reuses the COR-5(b) fault
    injection (cache_turbo_test_varidx_fail / X-Cache-Turbo-Test-Varidx-Drop)
    against a cache_turbo_tag location instead of an auto-Vary one -- own
    redis prefix (tvd:) so the injected drop cannot perturb ct:tag:* counts
    other L2 tests assert exact values on. Reads land on /_cache (zone
    `main`), the same admin endpoint test_sie_serves_counter etc. use.

    MUTATION THIS CATCHES: reverting the filters.c change back to discarding
    tag_add()/tag_add_many()'s return value (or dropping the counter bump)
    makes tag_index_drops never move and this test goes red on the positive
    leg while the clean-store negative control stays green -- proving the
    delta is pinned to an actual dropped write, not to every tagged store."""
    drop_hdr = {"X-Cache-Turbo-Test-Varidx-Drop": "1"}

    # Positive leg: the tag-index write is dropped before the wire.
    before = _admin_stat(ng, "tag_index_drops")
    s0, b0, _h0 = fetch(ng.port, "/tagidxdrop/p1", headers=drop_hdr)
    assert s0 == 200 and b0, f"prime (dropped) failed: {s0} {b0!r}"
    # Object still caches -- that is the whole defect: the drop is invisible
    # to the client. The counter is zone-scoped, so read it off a second
    # request against the same zone rather than this response's own headers
    # (see the drops0/hf1 pattern in the COR-5(b) self-heal test above).
    s1, b1, h1 = fetch(ng.port, "/tagidxdrop/p1", headers=drop_hdr)
    assert s1 == 200 and h1.get("x-cache") == "HIT" and b1 == b0, \
        "tagged object should still cache even though its index write was dropped"
    after = _admin_stat(ng, "tag_index_drops")
    assert after - before >= 1, \
        (f"tag_index_drops did not move for a dropped L9 index write: "
         f"{before} -> {after}")

    # Negative control: a clean store (drop header absent) on a DIFFERENT
    # key/tag must NOT move the counter. Distinct key from the positive leg
    # so this fetch cannot itself hit the already-primed dropped entry.
    before2 = _admin_stat(ng, "tag_index_drops")
    s2, b2, _ = fetch(ng.port, "/tagidxdrop/p2")
    assert s2 == 200 and b2, f"clean prime failed: {s2} {b2!r}"
    after2 = _admin_stat(ng, "tag_index_drops")
    assert after2 == before2, \
        (f"tag_index_drops moved on a clean store with no fault armed: "
         f"{before2} -> {after2}")


def test_tagidx_purge_reports_degraded_after_dropped_index_write(
        ng: Nginx, origin: Origin, redis: RedisServer) -> None:
    """SILENT-INDEX-DROP option (c) for the L9 tag index: a purge-by-tag must
    report "complete":false once this zone has an outstanding tag-index drop,
    instead of reporting plain success while a still-resident object keeps
    serving stale.

    Option (a) (test_l9_tag_index_drop_is_observable above) made the drop
    OBSERVABLE in the admin counter. It did not change the purge REPLY, so the
    live defect stayed: an operator issues a purge-by-tag, gets
    {"purged":N} with no error, and a variant that was never indexed keeps
    being served until its TTL. The wire could not distinguish "I enumerated
    everything" from "I enumerated what the index happened to list".

    Option (b) (re-issue on a later hit, as COR-5(b) does for the variant
    index) is deliberately NOT implemented for tags and this test does not
    assume it: the tag set comes from a cache_turbo_tag COMPLEX VALUE
    evaluated against the ORIGIN RESPONSE in the body filter, so a later cache
    hit has no upstream to re-derive it from and a re-issue would index the
    object under the WRONG tags. Hence there is no tag_index_reissues counter
    and the gap never closes on its own -- once this zone drops a tag-index
    write, every subsequent purge-by-tag in it honestly reports degraded.

    ORDERING IS LOAD-BEARING: tag_index_drops only ever increases and is
    ZONE-scoped, so the clean "complete absent" leg MUST run BEFORE the fault
    is injected. Reversing the two legs would make the clean leg unsatisfiable
    and is not a flake but a permanent red.

    MUTATION THIS CATCHES: restoring the `tp->is_auto_vary &&` conjunct in
    ngx_http_cache_turbo_tag_purge_complete (purge.c), or dropping the
    pending_at_launch snapshot in ngx_http_cache_turbo_admin_purge_tag
    (admin.c), makes the degraded leg report a bare {"purged":N} and this test
    goes red there while the clean leg stays green.
    """
    import json
    drop_hdr = {"X-Cache-Turbo-Test-Varidx-Drop": "1"}
    tag = "tagidxdrop-t1"
    # Mirrors areas/l2.py's tag_key(name, prefix): <prefix>tag:<name>. Inlined
    # rather than imported -- areas are siblings loaded as `areas.*` by
    # test_runtime.py and do not import each other. /tagidxdrop/ is configured
    # with its own redis prefix (tvd:) so this cannot collide with ct:tag:*.
    tag_set_key = f"tvd:tag:{tag}"

    # ---- Leg 1 (MUST come first): healthy purge does NOT claim degraded.
    # No fault armed anywhere in this zone yet, so tag_index_drops is still 0
    # and the reply must be byte-compatible with the pre-change contract.
    # TAG-CAP-SILENT-DROP: pending_at_launch now sums tag_index_drops AND
    # tag_cap_drops (both feed the same "complete":false decision -- see
    # admin.c's ngx_http_cache_turbo_admin_purge_tag), so leg 1 needs BOTH
    # at zero. tag_cap_drops is expected to be 0 here: the cap-overflowing
    # L2 tests (test_l2_tag_truncation_warns, test_l2_tag_cap_and_dedup,
    # test_l2_tag_cap_purge_reports_degraded) all still run before this one
    # in run_all() -- the first two overflow /l2tcap/'s cap on `main` itself.
    # If a future test moves the cap onto `main` before this point, THAT
    # is the bug this assertion is designed to catch, not something to
    # relax by dropping this check.
    assert _admin_stat(ng, "tag_index_drops") == 0, \
        ("this test must observe a zone with no prior tag-index drop; a "
         "non-zero count here means an earlier test in this zone injected "
         "one and leg 1 can no longer be satisfied (see ORDERING above)")
    assert _admin_stat(ng, "tag_cap_drops") == 0, \
        ("this test must observe a zone with no prior tag-cap drop; a "
         "non-zero count here means an earlier test overflowed cache_turbo_"
         "tag's MAX_TAGS cap on THIS zone (`main`) and leg 1 can no longer "
         "be satisfied (see ORDERING above)")

    s, b, _ = fetch(ng.port, "/tagidxdrop/clean1")
    assert s == 200 and b, f"clean prime failed: {s} {b!r}"
    assert wait_for(lambda: redis.cli("SCARD", tag_set_key) == "1"), \
        "cleanly-stored object should be listed in its tag set"

    s, b, _ = fetch(ng.port, f"/_cache_l2tvd?tag={tag}", method="POST")
    assert s == 200, f"clean tag purge status {s}"
    reply = json.loads(b)
    assert reply["purged"] == 1, f"clean purge should report 1: {b}"
    assert "complete" not in reply, \
        (f"a fully-enumerated purge must not carry the additive 'complete' "
         f"field at all (backward compatibility): {b}")

    # ---- Leg 2: inject a real dropped tag-index write, then purge.
    s, b0, _ = fetch(ng.port, "/tagidxdrop/dropped", headers=drop_hdr)
    assert s == 200 and b0, f"dropped-index prime failed: {s} {b0!r}"
    # The object caches anyway -- that IS the defect being reported on.
    s, b1, h1 = fetch(ng.port, "/tagidxdrop/dropped", headers=drop_hdr)
    assert s == 200 and h1.get("x-cache") == "HIT" and b1 == b0, \
        "object should still cache even though its tag-index write was dropped"
    assert _admin_stat(ng, "tag_index_drops") >= 1, \
        "fault injection did not record a tag-index drop"

    # Also store a cleanly-indexed object under the same tag, so the purge has
    # something to enumerate and "purged" stays meaningful -- the point is that
    # the count is SHORT, not that it is zero.
    s, b2, _ = fetch(ng.port, "/tagidxdrop/alsotagged")
    assert s == 200 and b2, f"second clean prime failed: {s} {b2!r}"
    assert wait_for(lambda: redis.cli("SCARD", tag_set_key) == "1"), \
        "only the cleanly-stored object should be in the tag set"

    s, b, _ = fetch(ng.port, f"/_cache_l2tvd?tag={tag}", method="POST")
    assert s == 200, f"degraded tag purge status {s}"
    reply = json.loads(b)
    assert reply.get("complete") is False, \
        (f"purge-by-tag must report 'complete':false while a tag-index drop "
         f"is outstanding in this zone -- otherwise it claims success while "
         f"/tagidxdrop/dropped keeps serving stale: {b}")

    # The unindexed object is exactly what the degraded report is warning
    # about: the purge could not reach it, and it is STILL SERVING.
    s, b3, h3 = fetch(ng.port, "/tagidxdrop/dropped")
    assert s == 200 and h3.get("x-cache") == "HIT" and b3 == b0, \
        ("the dropped-index object should have survived the purge -- if it "
         "did not, the tag index was not actually short and this test is no "
         "longer exercising the degraded case")


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
    assert he.get("X-GraphQL-Cacheable") is None, (
        "nginx now forwards an empty-valued header -- add an empty-value case "
        "to the refusal loop above, it is no longer just /gql/absent")

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
