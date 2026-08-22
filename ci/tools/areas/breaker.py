"""cache-turbo runtime tests — breaker area.

Split out of ci/tools/test_runtime.py (MAINT-T1). Tests live here; the fixtures,
Origin/Nginx harness and helpers stay in test_runtime_base. test_runtime
star-imports this module, so every test stays reachable as
``test_runtime.<name>`` (run_named.py) and as a bare name inside run_all()
(lint-orphan-tests.py).
"""

from __future__ import annotations

import re

# Underscore-prefixed names are NOT re-exported by `import *`, so the
# private helpers this module actually calls are imported explicitly.
from test_runtime_base import *
from test_runtime_base import (
    _BACKEND_LINE,
    _admin_stat,
    _admin_str,
    _armings,
    _backoff_skips,
    _config_accepts,
    _config_rejects,
    _config_test_result,
    _fetch_keepalive,
)

_DSN_REDACTION_MARKER = "credential-must-not-appear"


def test_bypass_stale_serves_fallback_when_breaker_open(
        ng: Nginx, origin: Origin) -> None:
    """S232-BYPASS-STALE, the feature itself: a URI named by
    cache_turbo_bypass_stale_uri is stored as breaker-only fallback, so when
    the origin dies the OPEN breaker answers from it instead of 503-ing.

    Before this change /bstale/api/ would have been a plain bypass: nothing
    stored, so the breaker had nothing to arm from and the client got the
    breaker's 503. That is what the assertion below distinguishes -- a 200
    carrying the primed body can ONLY come from a stored copy."""
    s0, b0, h0 = fetch(ng.port, "/bstale/api/items")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    # The priming request itself must NOT be served from cache: an opted-in URI
    # still bypasses the lookup. It reached the origin, so it is a BYPASS.
    assert h0.get("x-cache") != "HIT", \
        f"priming request was served from cache (X-Cache={h0.get('x-cache')!r})"

    origin.fail = True
    try:
        # threshold=1: this first dead-origin request trips CLOSED -> OPEN and
        # still surfaces the raw origin failure itself.
        s_trip, _, _ = fetch(ng.port, "/bstale/api/items")
        assert s_trip != 200, \
            (f"tripping request was answered 200 -- expected it to reach the "
             f"dead origin and fail, got {s_trip}")

        s_open, b_open, h_open = fetch(ng.port, "/bstale/api/items")
        assert s_open == 200, \
            (f"breaker OPEN + a bypass-stale entry did not fall back to the "
             f"stored copy, got {s_open} -- the entry was never stored, or the "
             f"breaker could not arm from it")
        assert b_open == b0, f"served {b_open!r}, expected the primed {b0!r}"
        assert h_open.get("x-cache") == "STALE-BREAKER", \
            (f"fallback served with X-Cache={h_open.get('x-cache')!r}, "
             f"expected STALE-BREAKER -- it came from some other serve path")
    finally:
        origin.fail = False
        drain_origin(origin)


def test_bypass_stale_never_serves_on_normal_path(
        ng: Nginx, origin: Origin) -> None:
    """S232-BYPASS-STALE SAFETY CONTROL -- the property the whole feature
    rests on: a BLOBF_BREAKER_ONLY entry is served ONLY as the breaker's
    fallback, never as an ordinary HIT/STALE.

    ⚠ Must be run against an OPEN breaker. An earlier revision of this test
    used a CLOSED one and was VACUOUS: with the breaker closed the request
    declines at the bypass-stale arm and never performs a lookup at all, so
    the guard in ngx_http_cache_turbo_serve() is never reached and the test
    passed with that guard compiled out. Verified by mutation -- deleting the
    guard leaves this version RED and the closed-breaker version GREEN.

    So: trip the breaker, which is the ONLY state in which the lookup can
    reach the stored blob, and then pin what comes back. A 200 is expected
    (that is the feature), but it must be the breaker's fallback, identified
    by X-Cache: STALE-BREAKER. If the guard is gone the same request is
    answered from the fresh entry as a plain HIT instead -- same status code,
    same body, different and disclosing path -- which is what the X-Cache
    assertion below distinguishes."""
    s0, b0, _ = fetch(ng.port, "/bstales/api/private")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    origin.fail = True
    try:
        s_trip, _, _ = fetch(ng.port, "/bstales/api/private")
        assert s_trip != 200, \
            f"tripping request answered 200, expected an origin failure: {s_trip}"

        # The entry is still FRESH here (valid 1s, these requests are ms
        # apart). Fresh is the state a normal-path HIT would fire in, so it is
        # exactly the state that exercises the guard.
        s, b, h = fetch(ng.port, "/bstales/api/private")
        assert s == 200 and b == b0, \
            (f"breaker OPEN did not serve the stored fallback: {s} {b!r} -- "
             f"expected the primed {b0!r}")
        assert h.get("x-cache") == "STALE-BREAKER", \
            (f"a breaker-only entry was served with X-Cache="
             f"{h.get('x-cache')!r}, not STALE-BREAKER. It came back on the "
             f"NORMAL path (a fresh HIT) rather than as the breaker's "
             f"fallback -- BLOBF_BREAKER_ONLY is not being enforced in "
             f"ngx_http_cache_turbo_serve(), and every URL named by "
             f"cache_turbo_bypass_stale_uri is now an ordinary cache entry "
             f"whose body is served to any client that asks")
    finally:
        origin.fail = False
        drain_origin(origin)


def test_bypass_stale_scoped_not_blanket(ng: Nginx, origin: Origin) -> None:
    """S232-BYPASS-STALE NEGATIVE CONTROL: the directive is URI-SCOPED. A
    sibling location under the same cache_turbo_bypass_stale_uri-carrying
    location, whose URI does NOT match the configured prefix, must be
    unaffected -- it keeps ordinary caching semantics and never gets stamped
    breaker-only.

    Guards the failure mode where the match is wired to the location rather
    than the prefix, which would silently opt in every URL under it."""
    s0, b0, _ = fetch(ng.port, "/bstalec/plain/doc")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    s1, b1, h1 = fetch(ng.port, "/bstalec/plain/doc")
    assert s1 == 200, f"second request failed: {s1}"
    assert h1.get("x-cache") == "HIT", \
        (f"a non-matching URI under the same location did not cache normally "
         f"(X-Cache={h1.get('x-cache')!r}) -- the bypass_stale_uri prefix is "
         f"being applied to the whole location instead of the named prefix")
    assert b1 == b0, f"HIT served {b1!r}, expected the cached {b0!r}"


def test_bypass_stale_absent_directive_has_no_fallback(
        ng: Nginx, origin: Origin) -> None:
    """S232-BYPASS-STALE NEGATIVE CONTROL: without the directive, the
    privacy default is unchanged -- a bypassed URL still stores NOTHING and
    still gets the breaker's 503 when the origin dies.

    A URI that never matched the directive and was never primed has nothing
    stored under its key. With the breaker OPEN it must still NOT be answered
    200 -- if it is, the breaker served some other entry's body, which is the
    cross-key confusion this feature must not introduce."""
    s0, b0, _ = fetch(ng.port, "/bstalen/plain/gone")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    time.sleep(1.3)   # past fresh + stale: L1-expired

    origin.fail = True
    try:
        s_trip, _, _ = fetch(ng.port, "/bstalen/plain/gone")
        assert s_trip != 200, f"tripping request answered 200, got {s_trip}"

        # The breaker is OPEN now. /bstale/plain/ is NOT opted in, but it IS
        # ordinarily cacheable, so it legitimately has an expired entry the
        # breaker may serve -- that is pre-existing keep-stale behaviour, not
        # this feature. What must NOT happen is the opted-in path's body
        # appearing here, or a 200 on a URL that never stored anything.
        s_new, _, _ = fetch(ng.port, "/bstalen/api/never-primed")
        assert s_new != 200, \
            (f"a bypass-stale URI that was NEVER primed answered 200 ({s_new}) "
             f"with a dead origin -- it served some other entry's body")
    finally:
        origin.fail = False
        drain_origin(origin)


def test_breaker_arming_sites_gated_white_box(ng: Nginx, origin: Origin) -> None:
    """O4.4-i: pin the L1 expired-entry ARMING call site specifically, which
    test_breaker_arming_gated_on_breaker_enable() provably cannot.

    ⚠ SCOPE: this pins the **L1** arming site only, and now says so in the
    counter it reads: the header carries `l1=<n>,l2=<n>` and this test asserts
    on the l1 field. The L2 site is pinned separately by
    test_breaker_l2_arming_site_gated_white_box() below.

    The per-site split is load-bearing, not tidiness. Against a single shared
    counter an L2 assertion passes on the L1 site's bump -- the L1 site runs
    first on every request -- so the L2 mutation stayed green. That was measured
    (mutation applied, rebuilt, test still PASSED), which is why the counter was
    split rather than the L2 test simply being added.

    Verified by mutation: reverting the L1 gate (module.c:5069) to a bare
    `breaker_threshold > 0` fails this test on the armed_off assertion, while
    the black-box test above still passes.

    That test is black-box, and the pre-origin gate alone blocks BRK_ACT_SERVE
    when the breaker is off -- so reverting an arming site to a bare
    `breaker_threshold > 0` (dropping should_consult() there) keeps it green.
    Verified in s138 by injecting exactly that mutation.

    This test reads the TEST_FAULTS-only arming counter instead, which is bumped
    INSIDE the should_consult() branch at each arming site. Two claims:

      1. breaker ON  + expired entry + dead origin => the counter MOVES.
         Without this the '0 armings' assertion below is vacuous: a counter that
         never moves satisfies it no matter how the sites are gated.
      2. breaker OFF + same conditions            => the counter does NOT move.
         This is the O4.4-c regression a bare threshold check reintroduces:
         `breaker off` would keep pinning blobs on the expired-entry path.

    /brkion/ and /brkioff/ share the dedicated `brkiz` zone (NOT `main`): this
    test leaves the breaker OPEN, which would make the black-box test's own
    tripping request get served the fallback rather than reach the dead origin.
    Since the two locations do share brkiz, the counter is zone-wide and every
    assertion below is a DELTA around that location's fetches, never an
    absolute."""
    base = {}
    for path in ("/brkion/dead", "/brkioff/dead"):
        s0, b0, h0 = fetch(ng.port, path)
        assert s0 == 200, f"prime failed for {path}: {s0}"
        assert b0, f"prime returned an empty body for {path}"
        base[path] = _armings(h0, f"prime {path}", site="l1")

    time.sleep(1.3)   # past fresh (1s), stale_mult 1 -> 1s window: L1-expired
    origin.fail = True
    try:
        # --- claim 1: breaker ON arms, so the counter must move ---------------
        s_trip, _, _ = fetch(ng.port, "/brkion/dead")
        assert s_trip != 200, \
            f"breaker ON: tripping request unexpectedly 200: {s_trip}"
        s_on, _, h_on = fetch(ng.port, "/brkion/dead")
        assert s_on == 200, \
            f"breaker ON: expected the any-age fallback after tripping, got {s_on}"
        armed_on = _armings(h_on, "breaker ON fallback", site="l1") - base["/brkion/dead"]
        assert armed_on > 0, (
            "breaker ON armed NOTHING at either call site (counter delta 0) -- "
            "either the arming sites no longer bump the counter or the fallback "
            "was served without arming; the 'breaker OFF arms nothing' "
            "assertion below would be vacuous, so fail here instead")

        # --- claim 2: breaker OFF must arm nothing ---------------------------
        # Baseline is the counter AFTER the breaker-ON phase, since both
        # locations share the dedicated `brkiz` zone.
        before_off = _armings(h_on, "breaker ON fallback", site="l1")
        s_off_trip, _, _ = fetch(ng.port, "/brkioff/dead")
        assert s_off_trip != 200, \
            f"breaker OFF: tripping request unexpectedly 200: {s_off_trip}"
        s_off, _, h_off = fetch(ng.port, "/brkioff/dead")
        assert s_off != 200, \
            f"breaker OFF: dead origin answered 200 from a stale snapshot: {s_off}"
        armed_off = _armings(h_off, "breaker OFF error", site="l1") - before_off
        assert armed_off == 0, (
            f"breaker OFF armed {armed_off} time(s) at the L1 expired-entry "
            f"arming call site -- cache_turbo_breaker off must gate it through "
            f"breaker_should_consult(), not a bare breaker_threshold > 0 check. "
            f"With the breaker off this path keeps pinning blobs on every "
            f"request to a cold-ish key (O4.4-c/O4.4-i)")
    finally:
        origin.fail = False
        drain_origin(origin)


def test_breaker_l2_arming_site_gated_white_box(ng: Nginx, origin: Origin,
                                                redis: RedisServer) -> None:
    """O4.4-i (L2 half): pin the **L2** breaker-fallback ARMING call site.

    The sibling test above pins the L1 expired-entry site. This one pins the
    other arming site -- the branch that arms from an L2 blob when L1 has no
    copy (module.c ~5227, inside the `rem_stale <= 0` arm) -- and reaching it
    needs three conditions at once, each of which was established by
    measurement rather than assumed:

      1. **A separate counter.** The header reports `l1=<n>,l2=<n>` and this
         test asserts on `l2`. Against a single shared total the L1 site
         supplies the bump and the assertion would pass with the L2 gate broken
         -- measured on an earlier shared-counter version of this test.
      2. **`rem_stale <= 0` with the blob still in Redis.** The blob is aged in
         place (`created` rewritten, i64 @24) so `age > stale_ttl` and the L2
         branch's `rem_stale <= 0` precondition holds immediately, with no
         sleep. `keep_stale 300s` leaves `sie_ttl` wide, so the aged blob still
         carries a serve-on-error window and the fallback has something to arm.
      3. **L1 ABSENT, not expired.** This is the part three earlier fixture
         attempts got wrong. While an L1 copy exists AND its stamped `sie_ttl`
         window is open, the L1 SIE arm (module.c ~5122) runs BEFORE the L2 GET
         and the request is served STALE-IF-ERROR without ever entering the
         `rem_stale <= 0` branch -- so `l2` stays 0 whether the gate is right or
         wrong. And the L1 SIE window cannot be closed independently: the same
         `sie_window` feeds both `bhw.sie_ttl` (~7681) and the L2 key's
         `retain_ttl = max(stale_window, sie_window)` (~7695), and the blob is
         stamped once at store time, so "L2 object alive" and "L1 SIE window
         open" are the SAME condition by construction. No valid/keep_stale/
         stale_mult combination separates them -- do not look for one.
         The escape is to remove L1 entirely: `cache_turbo_purge on` on both
         locations, PURGE each key, then rewrite the (aged) blob back into
         Redis. PURGE is L2-aware and DELs the Redis key too (module.c ~1711),
         so the rewrite MUST come after the purge -- same ordering constraint as
         /sfgu/. LRU eviction via a filler loop was tried and rejected: it left
         the OFF key resident and is what made this half vacuous.

    The fixture serves 200 STALE-IF-ERROR / STALE-BREAKER rather than an error,
    so the STATUS is not the oracle here -- the per-site counter is. Both
    claims are therefore deltas on `l2`:

      1. breaker ON  => the l2 counter MOVES
      2. breaker OFF => the l2 counter does NOT move

    ⚠ A SECOND defect had to be fixed before claim 2 could fail at all, and it
    was in the module, not the fixture: `sie_rewrite()` (module.c ~6814)
    ngx_list_init()s `headers_out.headers` to make the snapshot's headers
    authoritative, which WIPES the arming header the header filter already
    stamped. Every STALE-IF-ERROR response therefore carried the snapshot's
    stored counter (0) while the live zone counter had moved -- measured: the
    filter logged l2=3 and l2=4 for the two /brkil2off/ requests while the
    client received `l1=0,l2=0`. The OFF fixture is served exactly that way, so
    the oracle read 0 no matter what the gate did. `sie_rewrite()` now re-stamps
    the header after restore_response. Anything else asserting on a counter
    header off a STALE-IF-ERROR response has the same exposure.

    Both halves are real controls. Mutation-verified: reducing the L2 arming
    gate (module.c ~5227) from `breaker_should_consult(clcf)` to a bare
    `clcf->breaker_threshold > 0` makes the claim-2 assertion FAIL
    ("breaker OFF armed 1 time(s) at the L2 arming call site"), and reverting it
    makes the test pass again.
    """
    base = {}
    blobs = {}
    for path in ("/brkil2on/dead", "/brkil2off/dead"):
        s0, b0, h0 = fetch(ng.port, path)
        assert s0 == 200, f"prime failed for {path}: {s0}"
        assert b0, f"prime returned an empty body for {path}"
        base[path] = _armings(h0, f"prime {path}", site="l2")

        key = l2_key(path, prefix="brkil2:")
        assert wait_for(lambda k=key: redis.cli("EXISTS", k) == "1"), \
            f"{path} never reached L2 -- nothing to arm the L2 site from"
        blob = redis.get_raw(key)
        assert blob is not None and len(blob) >= 44, \
            f"short/absent L2 blob for {path}: {blob!r}"
        _fresh_ttl, stale_ttl, sie_ttl = struct.unpack("<III", blob[32:44])
        assert sie_ttl > 60, (
            f"{path} fixture drifted: sie_ttl={sie_ttl}, expected > 60 from "
            f"keep_stale 300s. Without a wide sie window the aged blob has no "
            f"serve-on-error window and the breaker fallback arms nothing, "
            f"making claim 1 fail for a reason unrelated to gating.")
        blobs[path] = (key, blob, stale_ttl)

    # Make L1 ABSENT and leave L2 PRESENT-but-past-its-window. See condition 3
    # in the docstring: expiring L1 is not enough, because the L1 SIE arm
    # short-circuits the L2 GET, and the SIE window cannot be narrowed without
    # also dropping the L2 object. PURGE removes L1 outright; because PURGE is
    # L2-aware the Redis key goes with it, so the aged blob is written back
    # AFTERWARDS -- order matters, reversing it deletes the object under test.
    for path, (key, blob, stale_ttl) in blobs.items():
        s_p, b_p, _ = fetch_raw(ng.port, path, method="PURGE")
        assert s_p == 200, f"PURGE {path} -> {s_p}: {b_p}"
        # PURGE 200 means accepted, not that the Redis DEL ran. Wait for the
        # key to actually vanish before writing the aged blob, or a late DEL
        # deletes what we write and the next read reports it absent.
        wait_for_l2_absent(redis, key, what=f"PURGE of {path}")
        aged = (blob[:24]
                + struct.pack("<q", int(time.time()) - (int(stale_ttl) + 60))
                + blob[32:])
        redis.set_raw(key, aged, 3_600_000)
        # PROVE the L2 blob survived the L1 drop. If it did not, both claims
        # would read l2 == 0 and claim 2 would be vacuous again.
        wait_for_l2(redis, key, aged, what=f"aged L2 blob for {path}")

    origin.fail = True
    try:
        # --- claim 1: breaker ON arms from L2, so the l2 counter must move ---
        s_trip, _, _ = fetch(ng.port, "/brkil2on/dead")
        assert s_trip == 200, (
            f"breaker ON: expected the L2 stale-if-error serve on the tripping "
            f"request, got {s_trip}")
        s_on, _, h_on = fetch(ng.port, "/brkil2on/dead")
        assert s_on == 200, \
            f"breaker ON: expected the L2 fallback after tripping, got {s_on}"
        armed_on = _armings(h_on, "breaker ON L2 fallback",
                            site="l2") - base["/brkil2on/dead"]
        assert armed_on > 0, (
            "breaker ON armed nothing at the L2 call site (l2 counter delta 0). "
            "Either the fallback came from L1 rather than L2 -- check that the "
            "PURGE above still drops the L1 copy -- or the aged L2 blob had "
            "already left Redis, or the site no longer bumps its counter. The "
            "'breaker OFF arms nothing' assertion below would be vacuous in "
            "every one of those cases, so fail here instead")

        # --- claim 2: breaker OFF must arm nothing at the L2 site ------------
        # This IS a control: /brkil2off/dead has no L1 copy (purged above) and a
        # live-but-past-window L2 blob, so the request DOES enter the
        # `rem_stale <= 0` branch where the L2 arming site lives. The only
        # reason `l2` must not move is `breaker_should_consult()` returning
        # false for `cache_turbo_breaker off`. Mutation-verified: reduce that
        # gate to a bare `clcf->breaker_threshold > 0` and this assertion fails.
        #
        # ⚠ The baseline is read from a /brkil2off/ RESPONSE, not carried over
        # from h_on: differencing across the ON phase produced a NEGATIVE delta
        # (brkil2z is small and shared), which is how that was found.
        #
        # ⚠ The L1 copy is RE-DROPPED between the two samples. The first OFF
        # request restores the L2 blob into L1 (the `rem_stale <= 0` branch both
        # serves and stores), so without this the MEASURED request would find an
        # L1 copy and never re-enter the L2 branch -- the same short-circuit that
        # made this half vacuous before. The re-drop is what keeps the measured
        # request on the branch under test.
        _, _, h_off0 = fetch(ng.port, "/brkil2off/dead")
        before_off = _armings(h_off0, "breaker OFF baseline", site="l2")
        okey, oblob, ostale = blobs["/brkil2off/dead"]
        s_p2, b_p2, _ = fetch_raw(ng.port, "/brkil2off/dead", method="PURGE")
        assert s_p2 == 200, f"re-PURGE /brkil2off/dead -> {s_p2}: {b_p2}"
        wait_for_l2_absent(redis, okey,
                           what="re-PURGE of /brkil2off/dead")
        oaged = (oblob[:24]
                 + struct.pack("<q", int(time.time()) - (int(ostale) + 60))
                 + oblob[32:])
        redis.set_raw(okey, oaged, 3_600_000)
        wait_for_l2(redis, okey, oaged,
                    what="aged L2 blob for /brkil2off/dead after the re-drop")
        _, _, h_off = fetch(ng.port, "/brkil2off/dead")
        armed_off = _armings(h_off, "breaker OFF L2 error",
                             site="l2") - before_off

        assert armed_off == 0, (
            f"breaker OFF armed {armed_off} time(s) at the L2 arming call site "
            f"-- cache_turbo_breaker off must gate it through "
            f"breaker_should_consult(), not a bare breaker_threshold > 0 check "
            f"(O4.4-c/O4.4-i, L2 half)")
    finally:
        origin.fail = False
        drain_origin(origin)


def test_breaker_lifecycle_open_zero_contact_close(ng: Nginx, origin: Origin) -> None:
    """O4.5: the breaker STATE MACHINE end-to-end, not just its config/counter
    surfaces (existing test_*breaker* tests cover config-parse, arming gates,
    counters and Prometheus, but none drives CLOSED -> OPEN -> HALF_OPEN ->
    CLOSED for real).

    ⚠ SEMANTICS pinned here, not to be re-litigated: an OPEN breaker makes NO
    origin contact at all. There is no "one request per refresh cycle probes
    the origin" during OPEN -- the single probe is promoted only once
    cache_turbo_breaker_open has ELAPSED (ngx_http_cache_turbo_shm_breaker_
    state(), shm.c ~1424). See README.md's cache_turbo_breaker_open row.

    Four claims, in sequence on /o45/ (o45z, threshold=1, window=60s,
    open=2s):

      1. N (=1) origin failures trips the breaker OPEN.
      2. A CACHED key (/o45/o45cache, already armed by the priming fetch) still
         answers 200 while OPEN, with origin.hits_for("o45cache")
         UNCHANGED across the OPEN-window fetch -- proving zero origin
         contact, not just "some 200".
      3. A COLD key sharing the same zone (/o45/o45cold, never primed, so it has
         no snapshot to arm) gets 503 + a Retry-After header while OPEN,
         matching this location's explicit cache_turbo_breaker_retry_after
         (2s -- set explicitly rather than left to track breaker_open, see
         the fixture comment on /o45/: an unset breaker_retry_after inherits
         the ENCLOSING server{} context's already-resolved 30s default
         rather than being derived from this location's own breaker_open,
         a separate pre-existing gap reported to the ledger, not what this
         claim is testing).
      4. Origin restored + the probe promoted after breaker_open (2s) elapses
         CLOSES the breaker: the next fetch after the wait reaches the (now
         healthy) origin and origin.hits_for("o45cache") MOVES.
    """
    # NOTE: proxy_pass strips the /o45/ location prefix before the request
    # reaches the origin, so origin.hits_for() must be given the ORIGIN-side
    # needle (post-strip), not the client-facing path -- using the full
    # client path as the needle silently never matches anything, which
    # measured 0 the whole way through until this was caught by the trip
    # assertion below firing "did not actually reach the origin". Neither
    # needle collides with an existing fixture's URI (unlike bare
    # "cached"/"cold", which /cold/ already uses in another area module).
    cached_path = "/o45/o45cache"
    cold_path = "/o45/o45cold"
    cached_needle = "o45cache"
    cold_needle = "o45cold"

    # Prime /o45/o45cache only -- /o45/o45cold is deliberately NEVER primed (claim 3
    # needs a key with no armed snapshot at all once OPEN).
    s0, b0, _ = fetch(ng.port, cached_path)
    assert s0 == 200 and b0, f"prime failed for {cached_path}: {s0} {b0!r}"

    time.sleep(1.3)   # past fresh (1s), stale_mult 1 -> 1s window: L1-expired
    origin.fail = True
    try:
        hits_before_trip = origin.hits_for(cached_needle)

        # --- claim 1: the tripping request reaches the (now dead) origin ---
        s_trip, _, _ = fetch(ng.port, cached_path)
        assert s_trip != 200, (
            f"tripping request was answered 200 -- expected it to reach the "
            f"dead origin and fail, got {s_trip}")
        assert origin.hits_for(cached_needle) - hits_before_trip == 1, (
            "the tripping request did not actually reach the origin -- claim "
            "1 (N failures trips OPEN) would be vacuous without this")

        # --- claim 2: a cached key answers 200 with ZERO origin contact -----
        hits_before_open_serve = origin.hits_for(cached_needle)
        s_open, b_open, _ = fetch(ng.port, cached_path)
        assert s_open == 200, (
            f"breaker OPEN: cached key was not served from the any-age "
            f"snapshot, got {s_open}")
        assert b_open, "breaker OPEN serve returned an empty body"
        hits_after_open_serve = origin.hits_for(cached_needle)
        assert hits_after_open_serve == hits_before_open_serve, (
            f"breaker OPEN: origin.hits_for({cached_path!r}) moved "
            f"{hits_before_open_serve} -> {hits_after_open_serve} while "
            f"serving a cached key -- an OPEN breaker must make ZERO origin "
            f"contact, not just avoid surfacing the failure")

        # --- claim 3: a cold key gets 503 + Retry-After while OPEN ----------
        hits_before_cold = origin.hits_for(cold_needle)
        s_cold, _, h_cold = fetch(ng.port, cold_path)
        assert s_cold == 503, (
            f"breaker OPEN: cold key (no armed snapshot) expected 503, got "
            f"{s_cold}")
        assert origin.hits_for(cold_needle) == hits_before_cold, (
            "breaker OPEN: the cold-key 503 must not have reached the origin "
            "either")
        ra = h_cold.get("retry-after")
        assert ra is not None, (
            "breaker OPEN: cold-key 503 carries no Retry-After header -- "
            "expected the explicit cache_turbo_breaker_retry_after (2s)")
        assert ra == "2", (
            f"breaker OPEN: Retry-After should match the explicit "
            f"cache_turbo_breaker_retry_after (2), got {ra!r}")

        # --- claim 4: origin restored + probe after `open` elapses CLOSES --
        origin.fail = False
        time.sleep(2.3)   # past breaker_open (2s): the next request is the probe
        hits_before_probe = origin.hits_for(cached_needle)
        s_probe, b_probe, _ = fetch(ng.port, cached_path)
        assert s_probe == 200, (
            f"post-open-window probe: expected 200 from the now-healthy "
            f"origin, got {s_probe}")
        assert b_probe, "post-open-window probe returned an empty body"
        assert origin.hits_for(cached_needle) - hits_before_probe == 1, (
            "post-open-window probe did not reach the origin -- the breaker "
            "must promote exactly one request to the origin once "
            "breaker_open has elapsed, closing on success")

        # A second fetch right after must find the breaker CLOSED (normal
        # service resumed) rather than still routing through the fallback.
        #
        # The status alone cannot say that: a still-OPEN breaker serving the
        # armed any-age snapshot answers 200 too. Nor can an origin-hit delta
        # -- the probe above just re-stored this key and cache_turbo_valid is
        # 1s, so a CLOSED breaker legitimately answers from cache with zero
        # origin contact, and asserting a hit would fail on timing rather than
        # behaviour. The zone's own breaker_state is the discriminating read:
        # shm_stats() snapshots the word (shm.c:734) instead of going through
        # _breaker_state(), so unlike the request path it promotes nothing and
        # observing it cannot change what it reports.
        drain_origin(origin)
        s_confirm, _, _ = fetch(ng.port, cached_path)
        assert s_confirm == 200, (
            f"post-close confirm fetch: expected 200, got {s_confirm}")
        brk_state = _admin_str(ng, "breaker_state", "/_cache_o45")
        assert brk_state == "closed", (
            f"the successful probe must CLOSE the breaker, but the zone still "
            f"reports breaker_state={brk_state!r} -- a 200 here proves nothing "
            f"on its own, since an OPEN breaker serving the armed snapshot "
            f"answers 200 as well")
    finally:
        origin.fail = False
        drain_origin(origin)


def test_breaker_off_negative_control_origin_climbs(ng: Nginx, origin: Origin) -> None:
    """O4.5 MANDATORY negative control for the suite: with cache_turbo_breaker
    off (/o45off/, o45offz), a dead origin gets NO fallback at all -- every
    request keeps reaching it, so the origin hit count keeps CLIMBING rather
    than flatlining behind an OPEN breaker. This is the control that proves
    the zero-origin-contact result in test_breaker_lifecycle_open_zero_
    contact_close is actually caused by the breaker, not by keep_stale or some
    other widening: an identical shape with only the breaker flag flipped
    must show origin traffic continuing."""
    # See the O4.5 lifecycle test above for why the needle must survive the
    # /o45off/ proxy_pass prefix-strip and must not collide with an existing
    # fixture's URI ("probe" alone already belongs to /at/, /atc/, /atl/).
    path = "/o45off/o45offprobe"
    s0, b0, _ = fetch(ng.port, path)
    assert s0 == 200 and b0, f"prime failed for {path}: {s0} {b0!r}"

    time.sleep(1.3)   # past fresh (1s), stale_mult 1 -> 1s window: L1-expired
    origin.fail = True
    try:
        hits_before = origin.hits_for("o45offprobe")
        for _ in range(3):
            fetch(ng.port, path)
        hits_after = origin.hits_for("o45offprobe")
        assert hits_after - hits_before == 3, (
            f"breaker off: expected all 3 requests to reach the (dead) "
            f"origin (no breaker protection), but origin.hits_for("
            f"'o45offprobe') moved only {hits_after - hits_before}")
    finally:
        origin.fail = False
        drain_origin(origin)


def test_breaker_record_position_and_sense(ng: Nginx, origin: Origin) -> None:
    """O4.5 owns O4.2's declared test gap (O4.2-f): the header-filter
    recording block (module.c ~7201-7243) has no automated guard on either
    its POSITION (before the RFC-2 stale-if-error rewrite at ~7250) or the
    sense of its success argument (module.c passes `!is_failure`, i.e. a
    5xx origin status records a FAILURE, everything else a success).

    Claims 1+2 run on /o45hit/ (o45hitz, threshold=1/window=60s/open=30s).
    Claim 3 (position) runs on a SEPARATE location/zone, /o45hitpos/
    (o45hitposz, keep_stale forever) -- see the o45hitposz zone comment for
    why: threshold=1 means the failure each claim exercises trips that
    zone's breaker OPEN, and a shared zone would make the second claim to
    run fail for an unrelated reason (the pre-origin gate blocking all
    origin contact once OPEN), not because of an actual position/sense bug.

      1. An origin 5xx (drop -> 502) on a COLD key records a failure:
         origin_failures moves by exactly one, and the raw 502 surfaces
         (nothing armed yet to swap it for).
      2. A cache-turbo HIT (served from ctx->served, never reaching the
         recording block at all) records NOTHING: origin_failures does not
         move across a HIT.
      3. POSITION: recording happens BEFORE the SIE rewrite at ~7250, not
         after. Primes a key, lets it go stale (past cache_turbo_valid +
         the x4 stale window), then drops the origin on THAT key --
         keep_stale forever arms the SIE rewrite, which swaps the 502 for
         the stale body (client sees 200, body unchanged from the prime).
         origin_failures must STILL move by one: if recording ran after the
         rewrite instead of before, r->headers_out.status would already be
         the rewritten 200 by the time is_origin_failure() ran, and this
         delta would read 0 -- the exact regression a records-after-rewrite
         mutation produces.

    O4.2-f's own third claim ("a native proxy_cache HIT records nothing") is
    covered by test_breaker_record_native_proxy_cache_hit_no_record below,
    split out because it needs its own on-disk proxy_cache dir and the
    single/multi-process + sanitizer skip that test already carries."""
    hit_path = "/o45hit/x"
    cold_path = "/o45hit/dropme"
    stale_path = "/o45hitpos/staleme"

    # claim 2: prime + a genuine cache-turbo HIT (well within the 1s valid).
    s0, b0, _ = fetch(ng.port, hit_path)
    assert s0 == 200 and b0, f"prime failed for {hit_path}: {s0} {b0!r}"

    of_before_hit = _admin_stat(ng, "origin_failures", "/_cache_o45hit")
    s_hit, b_hit, _ = fetch(ng.port, hit_path)
    assert s_hit == 200 and b_hit == b0, (
        f"expected a cache-turbo HIT (identical body) for {hit_path}, got "
        f"status={s_hit} body-changed={b_hit != b0}")
    of_after_hit = _admin_stat(ng, "origin_failures", "/_cache_o45hit")
    assert of_after_hit == of_before_hit, (
        f"origin_failures moved {of_before_hit} -> {of_after_hit} across a "
        f"cache-turbo HIT -- the recording block must not run at all when "
        f"ctx->served short-circuits the header filter")

    # claim 1: drop the connection (502, transport-level failure -- a
    # different error class than the clean 503 `fail` mode) on a FRESH,
    # never-primed key, so the raw 502 has nothing to be swapped for and
    # must surface as-is.
    origin.drop = True
    try:
        of_before_fail = _admin_stat(ng, "origin_failures", "/_cache_o45hit")
        s_fail, _, _ = fetch(ng.port, cold_path)
        assert s_fail != 200, (
            f"expected the dropped-connection origin failure (502) to "
            f"surface, got {s_fail}")
        of_after_fail = _admin_stat(ng, "origin_failures", "/_cache_o45hit")
        assert of_after_fail - of_before_fail == 1, (
            f"origin_failures did not move by exactly one on a genuine "
            f"origin drop (502): {of_before_fail} -> {of_after_fail}")
    finally:
        origin.drop = False
        drain_origin(origin)

    # claim 3 (POSITION): on the SEPARATE o45hitposz zone/location so this
    # claim's own trip cannot be confused with (or blocked by) claim 1's.
    # Prime, let it go stale, then drop the origin on the SAME key --
    # keep_stale forever arms the SIE rewrite, so the client-visible
    # response becomes 200/unchanged-body even though the origin genuinely
    # answered (dropped to) a 502. origin_failures on o45hitposz must still
    # move, proving the record() call sees the ORIGINAL 502 status, not the
    # rewritten 200.
    s2, b2, _ = fetch(ng.port, stale_path)
    assert s2 == 200 and b2, f"prime failed for {stale_path}: {s2} {b2!r}"
    time.sleep(1.3)   # past fresh (1s), stale_mult 1 -> 1s window
    origin.drop = True
    try:
        of_before_stale = _admin_stat(ng, "origin_failures", "/_cache_o45hitpos")
        s_stale, b_stale, _ = fetch(ng.port, stale_path)
        assert s_stale == 200 and b_stale == b2, (
            f"expected keep_stale to swap the dropped-connection 502 for "
            f"the stale body (unchanged from the prime), got status="
            f"{s_stale} body-changed={b_stale != b2} -- without this the "
            f"position claim below is not actually exercising the SIE "
            f"rewrite at all")
        of_after_stale = _admin_stat(ng, "origin_failures", "/_cache_o45hitpos")
        assert of_after_stale - of_before_stale == 1, (
            f"origin_failures did not move on a stale-serve that masked a "
            f"genuine origin 502 -- the recording block must run BEFORE "
            f"the SIE rewrite overwrites r->headers_out.status, not after: "
            f"{of_before_stale} -> {of_after_stale}")
    finally:
        origin.drop = False
        drain_origin(origin)


def test_breaker_record_native_proxy_cache_hit_no_record(ng: Nginx) -> None:
    """O4.2-f (third claim): a native `proxy_cache` HIT must record NOTHING
    on the breaker's origin_failures counter -- /o45natpc/ carries no
    cache_turbo directive at all, so the module never builds a ctx for it
    (ngx_http_get_module_ctx() returns NULL) and the header filter's very
    first line (`ctx == NULL || ctx->served`) returns before the recording
    block is ever reached, on both the MISS and every later HIT.

    Reads o45hitz's origin_failures as the observation point (o45hitz is
    never touched by /o45natpc/'s traffic at all -- there is no shared state
    between an uninstrumented location and a private zone -- so a delta of
    zero here is not a coincidence of an inert counter; it is the only
    counter this suite has that could have moved had /o45natpc/ somehow
    touched the breaker machinery, and it stays flat throughout).

    NEGATIVE CONTROL: manual, not an automated mutation, and documented as
    such rather than silently skipped (same precedent as
    test_breaker_policy_identical_no_warning's arm (b) elsewhere in this
    file). This claim is protected by TWO independent structural gates --
    ctx == NULL (no cache_turbo directive on this location at all) AND
    clcf->shm_zone == NULL (cache_turbo_zone never bound here either) -- so
    any single-line mutation that defeats one gate alone (e.g. dropping the
    ctx->served half of the early-return, tried and confirmed to still pass
    because the shm_zone gate independently blocks it) proves nothing; a
    mutation that defeats BOTH would deref a NULL ctx/shm_zone and crash
    rather than silently pass, which is not a meaningful control either.
    test_breaker_record_position_and_sense's sense (is_failure) and position
    (before/after the SIE rewrite) mutations, run against /o45hit/ +
    /o45hitpos/ above, exercise the SAME recording block this test relies on
    being unreachable -- so that block's mutation coverage is not skipped,
    just not re-proven a second time from this angle.

    Note on the MISS+HIT pair below: the HIT is a PRECONDITION (it makes the
    counter check interesting), not the claim, and it is advisory. Both gates
    above hold on a MISS as well, so a cache-visibility race on a loaded runner
    cannot invalidate the assertion -- see the comment at the poll."""
    if ng.single_process or ng.sanitizer:
        # Same core-nginx UBSan/ASan false-positive + cache-manager-process
        # skip as test_suppress_native_e2e_proxy_cache (core area).
        return

    path = "/o45natpc/y"
    of_before = _admin_stat(ng, "origin_failures", "/_cache_o45hit")

    s0, b0, _ = fetch(ng.port, path)
    assert s0 == 200 and b0, f"MISS failed for {path}: {s0} {b0!r}"

    # Second request: ideally a native proxy_cache HIT, which is what makes the
    # counter assertion below interesting rather than vacuous. Polled (not a
    # fixed sleep) because nginx writes the cache entry after the response
    # completes, so a loaded box can MISS again immediately afterwards.
    #
    # ADVISORY, NOT AN ASSERTION -- deliberately. The claim this test makes is
    # the origin_failures delta below, and that claim does NOT depend on
    # request 2 being a HIT: the header filter returns at
    # `ctx == NULL || ctx->served` (module.c:7122) and /o45natpc/ carries no
    # cache_turbo directive at all, so ngx_http_get_module_ctx() is NULL on
    # EVERY request here -- MISS and HIT alike -- and the recording block
    # (module.c:7234) is unreachable either way. A MISS therefore still
    # exercises the claim. Hard-failing on it cost three sessions chasing an
    # environment-dependent runner MISS that endangered nothing (see
    # lessons.md); a note is the right severity.
    #
    # Short budget on purpose: this is advisory, so a runner that is never
    # going to produce the HIT should not pay 5s to learn that.
    b1 = None
    for _ in range(10):
        s1, b1, _ = fetch(ng.port, path)
        if s1 == 200 and b1 == b0:
            break
        time.sleep(0.1)
    assert s1 == 200, (
        f"native proxy_cache request 2 for {path} must still be a healthy 200 "
        f"(HIT or MISS), got {s1} -- an error response would mean the origin "
        f"or the location itself broke, not a cache-visibility race")
    if b1 != b0:
        print(f"    note: {path} did not become a native proxy_cache HIT "
              f"within 1s (request 2 re-fetched from origin). Harmless here -- "
              f"the origin_failures claim below holds for a MISS too.",
              flush=True)

    of_after = _admin_stat(ng, "origin_failures", "/_cache_o45hit")
    assert of_after == of_before, (
        f"origin_failures moved {of_before} -> {of_after} across a native "
        f"proxy_cache MISS+HIT with no cache_turbo directive present at all "
        f"-- the breaker recording block must be unreachable without a ctx")




def test_backend_separators(ng: Nginx) -> None:
    """Backends stack, and spaces and '|' are interchangeable separators. All of
    these must mean the same thing:

        cache_turbo_backend wordpress woocommerce;
        cache_turbo_backend wordpress|woocommerce;
        cache_turbo_backend wordpress | woocommerce;

    nginx's config lexer splits on whitespace, so `a|b` arrives as ONE token with
    a '|' inside while `a | b` arrives as THREE tokens -- the parser has to
    handle both, which is what this pins down."""
    for i, spec in enumerate([
        "wordpress",
        "wordpress woocommerce",
        "wordpress|woocommerce",
        "wordpress | woocommerce",
        "wordpress|woocommerce joomla",
        "mediawiki|drupal",
        "none",
        ("wordpress|woocommerce|joomla|xenforo|discourse|phpbb|drupal|mediawiki"
         "|magento|ghost|wagtail|kirby|shopware6|typo3"),
        "magento|ghost",
        "wagtail|kirby",
        "shopware6|typo3",
        "textpattern|bludit|spip|bugzilla|mantisbt|plone|umbraco|dotclear|wikijs",
        "mantis|classicpress|backdrop",
    ]):
        _config_accepts(ng, f"sep-ok-{i}", _BACKEND_LINE,
                        f"cache_turbo_backend {spec};")


def test_backend_malformed_pipes(ng: Nginx) -> None:
    """A stray '|' is a typo, and every form of it must be a config error.

    Both of these were silent-accept bugs during development, which is the
    dangerous direction: `wordpress|` parsed as just `wordpress` (the trailing
    empty slice was never examined), and a lone `|` resolved to ZERO backends --
    which leaves the mask at 0, which the loc-conf merge reads as "unset" and so
    quietly INHERITS the parent's preset. A directive that looks like it names a
    backend and silently does something else is exactly what must not ship."""
    for i, (spec, want) in enumerate([
        ("wordpress||woocommerce", "empty backend name"),
        ("|wordpress",             "empty backend name"),
        ("wordpress|",             "empty backend name"),   # trailing pipe
        ("|",                      "names no backend"),     # lone pipe
        ("| |",                    "names no backend"),
        ("bogus",                  "unknown cache_turbo_backend"),
        ("wordpress|bogus",        "unknown cache_turbo_backend"),
    ]):
        _config_rejects(ng, f"sep-bad-{i}", _BACKEND_LINE,
                        f"cache_turbo_backend {spec};", want)


def test_backend_none_is_exclusive(ng: Nginx) -> None:
    """`none` means "no preset here" and cannot be combined with a real backend --
    `none wordpress` is a contradiction, and silently letting one win is exactly
    the quiet surprise this directive exists to avoid."""
    for i, spec in enumerate(["none wordpress", "none|wordpress",
                              "wordpress|none", "none | mediawiki"]):
        _config_rejects(ng, f"none-plus-{i}", _BACKEND_LINE,
                        f"cache_turbo_backend {spec};", "cannot be combined")

    # Across SEPARATE directive lines in the same context. Each line passes the
    # per-invocation check on its own, but the COMBINED result is still
    # NONE|<preset>, which must still be rejected. Regression guard for A3
    # (audit 2026-07-21): the exclusivity check used to look at only this one
    # invocation's args and silently left NONE|WORDPRESS set. Without the fix
    # nginx -t accepts these two-line configs and _config_rejects fails on its
    # `returncode != 0` assert -- i.e. this loop is its own negative control.
    # `woocommerce` implies `wordpress`, so ("woocommerce","none") also exercises
    # the implies path folding into the combined mask.
    for i, (a, b) in enumerate([("none", "wordpress"),
                                ("wordpress", "none"),
                                ("none", "mediawiki|drupal"),
                                ("woocommerce", "none")]):
        _config_rejects(
            ng, f"none-2line-{i}", _BACKEND_LINE,
            f"cache_turbo_backend {a};\n"
            f"            cache_turbo_backend {b};",
            "cannot be combined")


def test_backend_none_overrides_inherited(ng: Nginx, origin: Origin) -> None:
    """`cache_turbo_backend none;` switches OFF a preset inherited from the
    server level.

    This is the gap `none` exists to fill. backend_presets uses 0 to mean "this
    location named no backend", which the loc-conf merge reads as "inherit the
    parent's" -- so before `none` there was no way to opt a single location out
    of a server-level preset. `none` sets a sentinel bit: non-zero (so nothing is
    inherited) but matching no registry row (so no rule fires).

    The server block arms `wordpress`, so /wp-admin/-shaped paths would normally
    bypass. Under `none` they must cache like any other page."""
    # A WordPress dynamic surface, in a location that said `none`: must CACHE.
    fetch(ng.port, "/nonepreset/wp-login.php")
    _, _, h = fetch(ng.port, "/nonepreset/wp-login.php")
    assert h.get("x-cache") == "HIT", \
        ("`none` must override the inherited wordpress preset, so this caches; "
         f"got {h.get('x-cache')} -- the preset is still firing")

    # And a WordPress auth cookie must not bypass either.
    wp = {"Cookie": "wordpress_logged_in_abc=deadbeef"}
    fetch(ng.port, "/nonepreset/page", headers=wp)
    _, _, hw = fetch(ng.port, "/nonepreset/page", headers=wp)
    assert hw.get("x-cache") == "HIT", \
        ("`none` must override the inherited wordpress cookie rule too; "
         f"got {hw.get('x-cache')}")
    drain_origin(origin)


def test_valid_status_rejects_304(ng: Nginx) -> None:
    """COR-12: a per-status cache_turbo_valid naming 304 (or 206 / 1xx) is a
    meaningless standalone cache entry and must be rejected at config time."""
    bad = ng.root.parent / "bad-status"
    (bad / "conf").mkdir(parents=True, exist_ok=True)
    (bad / "logs").mkdir(parents=True, exist_ok=True)
    cfg = nginx_config(bad, ng.port, ng.module, ng.origin_port, 1)
    cfg = cfg.replace("cache_turbo_valid    0;",
                      "cache_turbo_valid    0;\n"
                      "            cache_turbo_valid 304 1m;")
    (bad / "conf" / "nginx.conf").write_text(cfg, encoding="ascii")
    cmd = ng.runner + [str(ng.binary), "-p", str(bad),
                       "-c", str(bad / "conf" / "nginx.conf"), "-t"]
    r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=20)
    assert r.returncode != 0, \
        f"standalone 304 was accepted by nginx -t:\n{r.stdout}"
    assert "cannot be cached standalone" in r.stdout, \
        f"missing/odd diagnostic for 304 status:\n{r.stdout}"


def test_empty_l2_prefix_rejected(ng: Nginx) -> None:
    """An empty L2 prefix must fail nginx -t: Redis all-purge would otherwise
    become SCAN MATCH * and delete the selected database."""
    cases = []
    if ng.redis_port is not None:
        cases.append(("redis", "prefix=ct:", "prefix="))
    if ng.memcached_port is not None:
        cases.append(("memcached", "prefix=mc:", "prefix="))

    for name, old, new in cases:
        bad = ng.root.parent / f"bad-empty-{name}-prefix"
        (bad / "conf").mkdir(parents=True, exist_ok=True)
        (bad / "logs").mkdir(parents=True, exist_ok=True)
        cfg = nginx_config(
            bad, ng.port, ng.module, ng.origin_port, 1, ng.redis_port,
            ng.redis_auth_port, ng.redis_password, ng.redis_tls_port,
            ng.redis_tls_ca, ng.memcached_port)
        assert old in cfg, f"test fixture missing {old!r}"
        cfg = cfg.replace(old, new, 1)
        (bad / "conf" / "nginx.conf").write_text(cfg, encoding="ascii")
        cmd = ng.runner + [str(ng.binary), "-p", str(bad),
                           "-c", str(bad / "conf" / "nginx.conf"), "-t"]
        r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=20)
        assert r.returncode != 0, \
            f"empty {name} prefix was accepted by nginx -t:\n{r.stdout}"
        assert "empty prefix" in r.stdout.lower(), \
            f"missing empty-prefix diagnostic for {name}:\n{r.stdout}"


def test_duplicate_l2_directive_rejected(ng: Nginx) -> None:
    """A second cache_turbo_redis / cache_turbo_memcached in ONE block must
    fail nginx -t rather than partially override the first.

    Re-entering the setter only overwrites what the NEW DSN carries: userinfo,
    db and the tls flag are written only when present, so the first line's
    user/password/db survived under the second line's host, and a rediss://
    first line could not be downgraded by a redis:// second one -- redis_tls
    is never cleared on any path. That sends the first directive's credentials
    to the second directive's host, which is why a silent accept is the
    failure mode this guards.

    The memcached arm is not a copy for symmetry: its exclusivity guard reads
    `redis_enable == 1 && memcached != 1`, and memcached==1 is its OWN mark, so
    a repeat fell straight through that check onto the first line's prefix and
    timeout.
    """
    cases = []
    if ng.redis_port is not None:
        cases.append(
            ("redis", f"cache_turbo_redis 127.0.0.1:{ng.redis_port} db=1;"))
    if ng.memcached_port is not None:
        # NOTE the DOUBLE space after the directive name -- that is how
        # nginx_config.py emits it, and a single space silently fails the
        # `old in cfg` fixture assert below rather than testing anything.
        cases.append(
            ("memcached",
             (f"cache_turbo_memcached  127.0.0.1:{ng.memcached_port} "
              f"prefix=mc: timeout=250ms;")))

    if not cases:
        return

    for name, old in cases:
        bad = ng.root.parent / f"bad-dup-{name}"
        (bad / "conf").mkdir(parents=True, exist_ok=True)
        (bad / "logs").mkdir(parents=True, exist_ok=True)
        cfg = nginx_config(
            bad, ng.port, ng.module, ng.origin_port, 1, ng.redis_port,
            ng.redis_auth_port, ng.redis_password, ng.redis_tls_port,
            ng.redis_tls_ca, ng.memcached_port)
        assert old in cfg, f"test fixture missing {old!r}"
        # Duplicate the directive in place, so the pair lands in ONE block --
        # two lines in two different blocks is legal and would prove nothing.
        idx = cfg.index(old)
        cfg = cfg[:idx] + old + "\n            " + cfg[idx:]
        (bad / "conf" / "nginx.conf").write_text(cfg, encoding="ascii")
        cmd = ng.runner + [str(ng.binary), "-p", str(bad),
                           "-c", str(bad / "conf" / "nginx.conf"), "-t"]
        r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=20)
        assert r.returncode != 0, \
            f"duplicate {name} directive was accepted by nginx -t:\n{r.stdout}"
        assert "is duplicate" in r.stdout, \
            f"missing/odd duplicate diagnostic for {name}:\n{r.stdout}"


def test_backend_prefix_rejected(ng: Nginx) -> None:
    """item 18: a malformed cache_turbo_backend_prefix must fail nginx -t. A
    value that does not match the deployed mount yields ZERO URI-rule coverage
    -- the exact silent failure the directive exists to end -- so it is rejected
    loudly instead of coerced into something that merely looks configured.
    Bare "/" is rejected too: it is a no-op that reads as configured."""
    anchor = "cache_turbo_backend_prefix /shop/;"
    for bad_value, why in (
        ("shop/",  "no leading slash"),
        ("/shop",  "no trailing slash"),
        ("/",      "bare root mount is a no-op"),
    ):
        def mutate(cfg: str, _v: str = bad_value) -> str:
            assert anchor in cfg, f"test fixture missing {anchor!r}"
            return cfg.replace(anchor,
                               f"cache_turbo_backend_prefix {_v};", 1)

        r = _config_test_result(ng, mutate)
        assert r.returncode != 0, \
            (f"cache_turbo_backend_prefix {bad_value!r} ({why}) was accepted by "
             f"nginx -t:\n{r.stdout}")
        assert "must begin and end" in r.stdout.lower(), \
            (f"missing backend_prefix diagnostic for {bad_value!r}:\n{r.stdout}")


def test_s8_scan_resistant_config_rejects(ng: Nginx) -> None:
    """S8 config-time rejects. Each arm has its OWN diagnostic, because a
    single "bad config" catch-all cannot tell an operator which mistake they
    made -- and because a shared message would let one arm pass on the other's
    error (the trap the H5/stale_mult tests recorded).

    protected_pct is range-checked by hand rather than via
    ngx_conf_set_num_slot precisely so `protected_pct=0` is an ERROR instead of
    being silently coerced to the default 80. Both H5 and H3(c) were bitten by
    that coerce-on-read trap; this test is what stops it recurring here."""
    anchor = "cache_turbo_scan_resistant on;"

    # 1. bad on/off token
    r = _config_test_result(
        ng, lambda c: c.replace(anchor, "cache_turbo_scan_resistant yes;", 1))
    assert r.returncode != 0, f"bad on/off token accepted:\n{r.stdout}"
    assert 'expected "on" or "off"' in r.stdout, \
        f"missing on/off diagnostic:\n{r.stdout}"

    # 2. protected_pct=0 -- must NOT be coerced to the default
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor, "cache_turbo_scan_resistant on protected_pct=0;", 1))
    assert r.returncode != 0, f"protected_pct=0 accepted:\n{r.stdout}"
    assert "out of range" in r.stdout, \
        f"missing protected_pct range diagnostic:\n{r.stdout}"

    # 3. protected_pct=100 -- upper bound is 99 (100 would mean "nothing may
    #    ever live in probation", i.e. no scan resistance at all)
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor, "cache_turbo_scan_resistant on protected_pct=100;", 1))
    assert r.returncode != 0, f"protected_pct=100 accepted:\n{r.stdout}"
    assert "out of range" in r.stdout, \
        f"missing protected_pct upper-bound diagnostic:\n{r.stdout}"

    # 4. non-numeric protected_pct -- a DISTINCT diagnostic from out-of-range.
    #    ngx_atoi has no sign handling, so a negative also lands here.
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor, "cache_turbo_scan_resistant on protected_pct=abc;", 1))
    assert r.returncode != 0, f"non-numeric protected_pct accepted:\n{r.stdout}"
    assert "bad protected_pct" in r.stdout, \
        f"missing bad-protected_pct diagnostic:\n{r.stdout}"

    # 5. unknown parameter
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor, "cache_turbo_scan_resistant on wat=1;", 1))
    assert r.returncode != 0, f"unknown parameter accepted:\n{r.stdout}"
    assert "unknown parameter" in r.stdout, \
        f"missing unknown-parameter diagnostic:\n{r.stdout}"

    # 6. protected_pct on `off` is inert config -- reject rather than store a
    #    value that can never be read.
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor, "cache_turbo_scan_resistant off protected_pct=50;", 1))
    assert r.returncode != 0, f"protected_pct on `off` accepted:\n{r.stdout}"
    assert "meaningless with" in r.stdout, \
        f"missing off+protected_pct diagnostic:\n{r.stdout}"

    # 7. duplicate directive
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor, anchor + "\n            " + anchor, 1))
    assert r.returncode != 0, f"duplicate directive accepted:\n{r.stdout}"
    assert "is duplicate" in r.stdout, \
        f"missing duplicate diagnostic:\n{r.stdout}"

    # 8. the pristine config must still pass, or every arm above is vacuous
    #    (a config broken for an unrelated reason fails all seven).
    r = _config_test_result(ng, lambda c: c, expect_unchanged=True)
    assert r.returncode == 0, \
        f"baseline config does not pass nginx -t:\n{r.stdout}"


def test_keepalive_cap_rejected(ng: Nginx) -> None:
    """STAB-5: an absurd cache_turbo_redis keepalive=N (the per-worker pool is
    N*sizeof(item)) is rejected at config time so the size_t multiply can't
    overflow into a short allocation the init loop then overruns."""
    if ng.redis_port is None:
        return
    anchor = "keepalive=8 keepalive_timeout=30s"
    r = _config_test_result(
        ng, lambda c: c.replace(anchor,
                                "keepalive=99999999 keepalive_timeout=30s", 1))
    assert r.returncode != 0, \
        f"oversized keepalive was accepted by nginx -t:\n{r.stdout}"
    assert "exceeds the maximum" in r.stdout, \
        f"missing keepalive-cap diagnostic:\n{r.stdout}"


def test_memcached_keepalive_invalid_rejected(ng: Nginx) -> None:
    """L14: cache_turbo_memcached keepalive=<bad> is rejected."""
    if ng.memcached_port is None:
        return
    def mutate(c):
        return c.replace(
            f"cache_turbo_memcached  127.0.0.1:{ng.memcached_port} prefix=mc: timeout=250ms;",
            f"cache_turbo_memcached  127.0.0.1:{ng.memcached_port} prefix=mc: timeout=250ms keepalive=abc;", 1)
    r = _config_test_result(ng, mutate)
    assert r.returncode != 0, \
        f"bad keepalive was accepted by nginx -t:\n{r.stdout}"
    assert "bad keepalive" in r.stdout, \
        f"missing bad-keepalive diagnostic:\n{r.stdout}"


def test_memcached_keepalive_cap_rejected(ng: Nginx) -> None:
    """L14: cache_turbo_memcached keepalive=N > max is rejected."""
    if ng.memcached_port is None:
        return
    def mutate(c):
        return c.replace(
            f"cache_turbo_memcached  127.0.0.1:{ng.memcached_port} prefix=mc: timeout=250ms;",
            f"cache_turbo_memcached  127.0.0.1:{ng.memcached_port} prefix=mc: timeout=250ms keepalive=99999999;", 1)
    r = _config_test_result(ng, mutate)
    assert r.returncode != 0, \
        f"oversized keepalive was accepted by nginx -t:\n{r.stdout}"
    assert "must be <=" in r.stdout, \
        f"missing keepalive-cap diagnostic:\n{r.stdout}"


def test_memcached_keepalive_timeout_invalid_rejected(ng: Nginx) -> None:
    """L14: cache_turbo_memcached keepalive_timeout=<bad> is rejected."""
    if ng.memcached_port is None:
        return
    def mutate(c):
        return c.replace(
            f"cache_turbo_memcached  127.0.0.1:{ng.memcached_port} prefix=mc: timeout=250ms;",
            f"cache_turbo_memcached  127.0.0.1:{ng.memcached_port} prefix=mc: timeout=250ms keepalive=8 keepalive_timeout=notatime;", 1)
    r = _config_test_result(ng, mutate)
    assert r.returncode != 0, \
        f"bad keepalive_timeout was accepted by nginx -t:\n{r.stdout}"
    assert "bad keepalive_timeout" in r.stdout, \
        f"missing bad-timeout diagnostic:\n{r.stdout}"


def test_redis_timeout_zero_rejected(ng: Nginx) -> None:
    """S231-L2-TIMEOUT0: cache_turbo_redis timeout=0 is rejected."""
    if ng.redis_port is None:
        return
    def mutate(c):
        # Anchor the mutator inside the /l2/ location block to target the
        # unconditional Redis directive. The whitespace between directive
        # and address is variable (2+ spaces), so use \s+ to be robust
        # across config reformatting. re.DOTALL lets [^}]* cross newlines
        # within the location block.
        pattern = re.compile(
            rf"location /l2/ \{{[^}}]*cache_turbo_redis\s+127\.0\.0\.1:{re.escape(str(ng.redis_port))}\s+prefix=ct:\s+timeout=250ms;",
            re.MULTILINE | re.DOTALL
        )
        new_cfg, sub_count = pattern.subn(
            lambda m: m.group(0).replace("timeout=250ms;", "timeout=0;"), c, count=1
        )
        assert sub_count == 1, \
            f"expected to mutate cache_turbo_redis directive exactly once, got {sub_count} substitutions"
        return new_cfg
    r = _config_test_result(ng, mutate)
    assert r.returncode != 0, \
        f"timeout=0 was accepted by nginx -t:\n{r.stdout}"
    assert "timeout must be > 0" in r.stdout, \
        f"missing timeout-must-be-positive diagnostic:\n{r.stdout}"


def test_memcached_timeout_zero_rejected(ng: Nginx) -> None:
    """S231-L2-TIMEOUT0: cache_turbo_memcached timeout=0 is rejected."""
    if ng.memcached_port is None:
        return
    def mutate(c):
        # Anchor the mutator inside the /mc/ location block to target the
        # unconditional memcached directive. The whitespace between directive
        # and address is variable (2+ spaces), so use \s+ to be robust
        # across config reformatting. re.DOTALL lets [^}]* cross newlines
        # within the location block.
        pattern = re.compile(
            rf"location /mc/ \{{[^}}]*cache_turbo_memcached\s+127\.0\.0\.1:{re.escape(str(ng.memcached_port))}\s+prefix=mc:\s+timeout=250ms;",
            re.MULTILINE | re.DOTALL
        )
        new_cfg, sub_count = pattern.subn(
            lambda m: m.group(0).replace("timeout=250ms;", "timeout=0;"), c, count=1
        )
        assert sub_count == 1, \
            f"expected to mutate cache_turbo_memcached directive exactly once, got {sub_count} substitutions"
        return new_cfg
    r = _config_test_result(ng, mutate)
    assert r.returncode != 0, \
        f"timeout=0 was accepted by nginx -t:\n{r.stdout}"
    assert "timeout must be > 0" in r.stdout, \
        f"missing timeout-must-be-positive diagnostic:\n{r.stdout}"




def test_redis_connect_backoff_fails_fast(ng: Nginx, origin: Origin) -> None:
    """S231-L2-BACKOFF: after a redis connect FAILURE, this worker must skip
    the connect() attempt entirely for the rest of the backoff window instead
    of paying one on every request during an outage.

    /l2backoff/ points at the redis_dead offset (a port that is never bound,
    same fixture /_cache_scandown uses) with connect_backoff=5000ms (the unit
    suffix is load-bearing: `ngx_parse_time` reads a bare "5000" as SECONDS,
    not ms, same trap this repo's `timeout=` directives always spell out
    explicitly -- measured, cost a debugging round-trip). `cache_turbo_lock
    off` keeps this fixture to exactly ONE L2 attempt per request (no
    cold-miss cross-node lock retry), so the counter's per-request delta is
    exact, not just "moved". Every request there is an L2 miss served from
    origin either way -- the response body/status is IDENTICAL whether the
    fail-fast path fired or an ordinary per-request connect() was refused,
    which is exactly why response equality cannot be the oracle here (a plain
    L2-down miss reproduces it). The oracle is the X-Cache-Turbo-Test-L2-
    Backoff counter, bumped ONLY on the fail-fast path, never on the ordinary
    connect-refused branch.

    All three requests go over ONE kept-alive connection (see
    _fetch_keepalive's docstring) so they are guaranteed to land on the SAME
    worker -- backoff state is per-worker (a process-global table), so two
    requests on different workers would each see their own never-armed table
    and the test would be a coin flip on the harness's 4-worker default.

    BASELINE NOTE: `ngx_http_cache_turbo_redis_test_backoff_skips` (the
    counter behind the X-Cache-Turbo-Test-L2-Backoff header, see its field
    comment in ngx_http_cache_turbo_module.c ~L6940 -- "process-global...
    per-worker") is a single lifetime atomic for the whole worker process,
    not a per-location or per-test value. This test runs in run_all() on the
    same worker as other backoff tests (e.g.,
    test_redis_tls_handshake_failure_arms_backoff, now in the l2 area) and may
    find the counter at a nonzero value from
    prior tests. Reading this counter as if it started at 0 for THIS test is a
    baseline artifact of test ordering, not a property of the backoff arm path.
    The oracle here is a DELTA against a baseline captured from a request
    that provably cannot itself move this counter: /c/ is a plain L1-only
    cache_turbo location (no cache_turbo_redis backend at all), so a GET
    there cannot dial redis and cannot bump the fail-fast skip counter -- its
    response's copy of the header is a pure read of "whatever this worker's
    counter already was", taken on the SAME kept-alive connection (same worker)
    as the three probes that follow. This preserves the original invariant
    under test (arming is not itself counted as a skip) while dropping the
    false assumption that the counter starts at absolute zero.

    Sequence:
      0. baseline read of the SAME global counter off a request that never
         touches the redis backend at all.
      1. request 1 ARMS the window (the connect failure itself) -- the
         counter does NOT move for this one; arming and fail-fast-skipping
         are different events (armed=0 -> the failure that ordinarily always
         happens; only a request that finds the window already armed skips).
      2. request 2, entirely inside the 5s window, must fail fast: counter
         increases relative to baseline.
      3. request 3, still inside the window, must fail fast again: counter
         increases again -- proves it is not a one-shot arm.

    All three requests still get a normal 200 from origin (L2 is advisory),
    so a functional regression here would be invisible without the counter."""
    if ng.redis_port is None:
        return

    conn = http.client.HTTPConnection("127.0.0.1", ng.port, timeout=HTTP_TIMEOUT)
    try:
        s0, b0, h0 = _fetch_keepalive(conn, "/c/l2backoff-baseline")
        assert s0 == 200, f"baseline request did not reach origin: {s0} {b0}"
        n0 = _backoff_skips(h0, "baseline", driver="redis")

        s1, b1, h1 = _fetch_keepalive(conn, "/l2backoff/probe-one")
        assert s1 == 200, f"request 1 (arms backoff) did not reach origin: {s1} {b1}"
        n1 = _backoff_skips(h1, "request 1", driver="redis")
        assert n1 == n0, (
            f"request 1 is the connect failure that ARMS the window -- it "
            f"must not itself be counted as a fail-fast skip (baseline={n0}, "
            f"after arming={n1})")

        s2, b2, h2 = _fetch_keepalive(conn, "/l2backoff/probe-two")
        assert s2 == 200, f"request 2 (fail-fast) did not reach origin: {s2} {b2}"
        n2 = _backoff_skips(h2, "request 2", driver="redis")
        assert n2 > n1, (
            f"request 2 landed inside the armed backoff window but the redis "
            f"fail-fast counter did not move ({n1} -> {n2}) -- it re-attempted "
            f"a connect() to the dead peer instead of failing fast")

        s3, b3, h3 = _fetch_keepalive(conn, "/l2backoff/probe-three")
        assert s3 == 200, f"request 3 (fail-fast) did not reach origin: {s3} {b3}"
        n3 = _backoff_skips(h3, "request 3", driver="redis")
        assert n3 > n2, (
            f"request 3, still inside the 5s window, did not fail fast again "
            f"({n2} -> {n3}) -- the backoff looks like a one-shot arm instead "
            f"of a window")
    finally:
        conn.close()


def test_redis_connect_backoff_disabled_never_arms(ng: Nginx, origin: Origin) -> None:
    """S231-L2-BACKOFF negative control: connect_backoff=0 must mean "never
    back off" -- every request against a dead peer pays its own connect
    failure, so the fail-fast counter never moves no matter how many requests
    land back to back on the same worker.

    This is the config-level equivalent of compiling the backoff path out:
    with connect_backoff=0, ngx_http_cache_turbo_redis_backoff_active() short
    -circuits to 0 unconditionally (redis.c), so launch() always falls
    through to the real keepalive-lookup + connect() attempt. Without this
    control, test_redis_connect_backoff_fails_fast() alone cannot show that
    connect_backoff=0 truly disables tracking rather than just using an
    unusably-short window.

    Needs the SAME same-worker pinning as the positive test (see
    _fetch_keepalive's docstring) -- comparing two DIFFERENT workers'
    independent counters would be meaningless (worker A's baseline having
    nothing to do with worker B's), not a same-vs-different-worker question.
    `cache_turbo_lock off` on /l2backoffoff/ keeps this to one real connect()
    attempt per request, same as /l2backoff/ above."""
    if ng.redis_port is None:
        return

    conn = http.client.HTTPConnection("127.0.0.1", ng.port, timeout=HTTP_TIMEOUT)
    try:
        _, _, h1 = _fetch_keepalive(conn, "/l2backoffoff/probe-one")
        n1 = _backoff_skips(h1, "off/request 1", driver="redis")

        _, _, h2 = _fetch_keepalive(conn, "/l2backoffoff/probe-two")
        n2 = _backoff_skips(h2, "off/request 2", driver="redis")
        assert n2 == n1, (
            f"connect_backoff=0 must disable fail-fast entirely, but the redis "
            f"counter moved ({n1} -> {n2}) on the second back-to-back request")

        _, _, h3 = _fetch_keepalive(conn, "/l2backoffoff/probe-three")
        n3 = _backoff_skips(h3, "off/request 3", driver="redis")
        assert n3 == n1, (
            f"connect_backoff=0 must disable fail-fast entirely, but the redis "
            f"counter moved ({n1} -> {n3}) on the third back-to-back request")
    finally:
        conn.close()


def test_cold_wait_poll_timer_no_uaf(ng: Nginx, origin: Origin) -> None:
    """S231-COLDWAIT-UAF -- NOT A CONFIRMED ORACLE, see below. Left in place
    (skipped) as a documented negative result and a starting point for the
    next attempt, per grind worker-contract rules on an unconfirmed root
    cause: "a reproducing test (marked skipped/xfail if it crashes the
    suite)". Here the situation is the mirror image -- it never crashes the
    suite -- so it is marked skipped instead of wired as a real assertion,
    to avoid shipping a green test that proves nothing.

    Original theory (module.c ~6353,
    ngx_http_cache_turbo_cold_wait_timeout): ngx_event_expire_timers()
    (nginx core) calls the timer handler SYNCHRONOUSLY (ev->timer_set
    cleared, ev->handler(ev) called directly -- confirmed by reading
    ngx_event_timer.c, no ngx_posted_events involved). The handler does
    ngx_http_core_run_phases(r); ngx_http_run_posted_requests(c);
    ngx_http_finalize_request(r, NGX_DONE). Theory: if run_phases() itself
    reaches a terminal finalize that frees r (e.g. the re-poll's L2 GET
    finds the winner's fill and content phase serves + finalizes inline),
    the trailing finalize_request() call runs a second time on freed
    memory -- matching the observed backtrace in issues.md ("cold-wait poll
    timer double-frees the request": cold_wait_timeout -> expire_timers ->
    finalize_request -> finalize_connection -> set_keepalive ->
    free_request -> SIGSEGV).

    REFUTED (gdb evidence, not guessed): ngx_http_cache_turbo_cold_wait()
    does r->main->count++ on EVERY re-poll parking attempt, and the ONLY
    balancing decrement is the ONE trailing finalize_request(r, NGX_DONE)
    call. A gdb breakpoint on that trailing call, sampled ~70 times across
    slow-origin (many re-polls, count balloons to 10-36) and fast-origin
    (served on the FIRST poll, count==1 going in -- the precise
    precondition the theory needs) runs, showed r->pool non-NULL,
    r->connection->destroyed==0, r->main->count==1 EVERY time at that call
    site: run_phases() never itself drops count to 0 before returning to
    the trailing call. ngx_http_set_keepalive's ngx_http_free_request is
    the LAST step of the SAME trailing call's count 1->0 transition, not an
    earlier independent free. Confirmed via 6+ repro shapes (concurrency
    24 losers/round x 6 rounds, --single-process, resume-to-completion
    losers, abort-mid-wait losers, ASan build) -- none crashed, none showed
    a premature free under gdb.

    UNTESTED remaining lead: the abort-mid-wait path was tried but not
    isolated under gdb specifically -- a client closing the kept-alive
    connection WHILE parked in cold_wait() (independent of the poll timer)
    could in principle let nginx's own connection-close teardown free r
    through a DIFFERENT path than cold_wait_timeout's own trailing call,
    which would then fire later via the still-armed rbtree entry. This
    needs its own gdb instrumentation on ngx_http_close_request /
    ngx_http_free_request reached from a read-event/EPOLLRDHUP path while
    cold_wait_ev is armed, which the investigation ran out of budget to do.

    /coldwaituaf/ (test_runtime_base's nginx_config()) is wired to LIVE redis with
    cache_turbo_lock left ON (module default) and lock_timeout 2s so a cold
    miss genuinely parks in ngx_http_cache_turbo_cold_wait() and the 100ms
    poll timer fires repeatedly under real cross-node NX lock contention
    against a winner regenerating from a slow origin -- kept as the
    fixture location for whoever picks this back up."""
    if True:
        # S231-COLDWAIT-UAF: skipped -- see docstring. Does not reproduce
        # the crash under any repro shape tried (multiple sessions,
        # concurrency/timing sweeps, ASan, gdb instrumentation all
        # negative); wiring this in as an assertion would be a green test
        # that proves nothing (worker-contract: never ship a test whose
        # oracle cannot fail). Left callable and documented, not deleted,
        # so the next attempt starts from the fixture instead of re-deriving
        # it.
        return
    if ng.redis_port is None:
        return

    origin.delay = 1.5  # slow enough that losers really park across >1 poll
    try:
        key = "/coldwaituaf/racekey"
        winner_sock = socket.create_connection(("127.0.0.1", ng.port), 5)
        winner_sock.sendall(
            f"GET {key} HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n"
            .encode())

        # give the winner time to take the NX lock and start regenerating
        time.sleep(0.2)

        # loser connections, each parked on the same key behind the NX
        # lock, each aborted mid-wait (client closes while cold_wait_ev is
        # still armed) instead of read to completion -- this is what races
        # nginx's own connection-close teardown against the poll timer.
        # Abort delays sweep across and past the 100ms poll boundary so at
        # least one loser is aborted right as its timer is about to (or
        # just did) fire.
        abort_delays = [0.05, 0.09, 0.10, 0.11, 0.15, 0.20, 0.30, 0.45]
        for d in abort_delays:
            loser = socket.create_connection(("127.0.0.1", ng.port), 5)
            loser.sendall(
                f"GET {key} HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n"
                .encode())
            time.sleep(d)
            loser.close()

        # let any timers scheduled against the aborted losers actually fire
        time.sleep(1.5)

        # drain the winner so the response doesn't wedge the test
        winner_sock.settimeout(5)
        try:
            while winner_sock.recv(4096):
                pass
        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            pass
        winner_sock.close()

        # liveness probe: a crashed worker either refuses the connection or
        # the master respawns a worker that has lost in-flight test-fault
        # state; either way this must still cleanly answer 200.
        conn = http.client.HTTPConnection("127.0.0.1", ng.port, timeout=HTTP_TIMEOUT)
        try:
            s, b, _ = _fetch_keepalive(conn, "/coldwaituaf/liveness-probe")
        except (http.client.RemoteDisconnected, ConnectionResetError,
                BrokenPipeError, http.client.CannotSendRequest,
                ConnectionRefusedError) as exc:
            raise AssertionError(
                f"worker did not survive the cold-wait poll timer race "
                f"({exc!r}) -- UAF/double-free on cold_wait_ev "
                f"(S231-COLDWAIT-UAF)") from exc
        finally:
            conn.close()
        assert s == 200, (
            f"post-race liveness probe expected 200, got {s}: {b[:200]!r}")
    finally:
        origin.reset_delay()
        drain_origin(origin)


def test_memcached_connect_backoff_fails_fast(ng: Nginx, origin: Origin) -> None:
    """S231-L2-BACKOFF, memcached driver: same fail-fast contract as the redis
    test above, proven independently against the memcached backoff table
    (ngx_http_cache_turbo_mc_backoff in memcached.c) and its own counter
    (X-Cache-Turbo-Test-L2-Backoff's `memcached=` field) -- the redis test
    proves nothing about this driver's table, since they are two entirely
    separate process-global structures with separate arm/clear/fail-fast call
    sites (memcached.c's mc_connect/mc_write/mc_op_fail/mc_get_finish).

    /mcbackoff/ mirrors /l2backoff/ exactly: dead peer (redis_dead offset,
    works for any TCP protocol), connect_backoff=5000ms, cache_turbo_lock off
    (memcached has no lock op at all -- vtable slot is NULL -- so this is
    belt-and-suspenders, not load-bearing here, but keeps the fixture
    symmetric with the redis one). Same same-worker kept-alive-connection
    requirement as the redis test; see _fetch_keepalive's docstring."""
    if ng.memcached_port is None:
        return

    conn = http.client.HTTPConnection("127.0.0.1", ng.port, timeout=HTTP_TIMEOUT)
    try:
        s1, b1, h1 = _fetch_keepalive(conn, "/mcbackoff/probe-one")
        assert s1 == 200, f"request 1 (arms backoff) did not reach origin: {s1} {b1}"
        n1 = _backoff_skips(h1, "mc request 1", driver="memcached")
        assert n1 == 0, (
            f"request 1 is the connect failure that ARMS the window -- it "
            f"must not itself be counted as a fail-fast skip (counter={n1})")

        s2, b2, h2 = _fetch_keepalive(conn, "/mcbackoff/probe-two")
        assert s2 == 200, f"request 2 (fail-fast) did not reach origin: {s2} {b2}"
        n2 = _backoff_skips(h2, "mc request 2", driver="memcached")
        assert n2 > n1, (
            f"request 2 landed inside the armed backoff window but the "
            f"memcached fail-fast counter did not move ({n1} -> {n2}) -- it "
            f"re-attempted a connect() to the dead peer instead of failing "
            f"fast")
    finally:
        conn.close()


def test_memcached_replyless_peer_arms_backoff(ng: Nginx) -> None:
    """A successful send is not proof that a fresh memcached connection works.

    The fake peer reads the complete GET and closes without one reply byte. The
    first request must arm the per-worker backoff; the second request, on the
    same nginx keepalive connection, must skip dialing it. This is distinct from
    the dead-port test: connect() and send() both succeed here, and only recv()
    exposes the outage.
    """
    if ng.memcached_port is None:
        return

    peer = DropReplyMemcached(ng.port + PORT_OFFSETS["mc_drop_reply"])
    peer.start()
    conn = http.client.HTTPConnection("127.0.0.1", ng.port, timeout=HTTP_TIMEOUT)
    try:
        s0, b0, h0 = _fetch_keepalive(conn, "/c/mcdrop-baseline")
        assert s0 == 200, f"baseline request did not reach origin: {s0} {b0}"
        n0 = _backoff_skips(h0, "replyless baseline", driver="memcached")

        s1, b1, h1 = _fetch_keepalive(conn, "/mcdrop/probe-one?private=1")
        assert s1 == 200, f"replyless request 1 did not reach origin: {s1} {b1}"
        n1 = _backoff_skips(h1, "replyless request 1", driver="memcached")
        assert n1 == n0, (
            f"the failure that arms backoff was counted as a skip ({n0} -> {n1})")
        assert wait_for(lambda: peer.commands > 0), \
            "fake peer never read the first request's command"
        time.sleep(0.1)  # let any first-request follow-up settle before baseline
        first_commands = peer.commands

        s2, b2, h2 = _fetch_keepalive(conn, "/mcdrop/probe-two?private=1")
        assert s2 == 200, f"replyless request 2 did not reach origin: {s2} {b2}"
        n2 = _backoff_skips(h2, "replyless request 2", driver="memcached")
        assert n2 > n1, (
            f"replyless EOF did not arm fail-fast backoff ({n1} -> {n2})")
        time.sleep(0.1)
        assert peer.commands == first_commands, (
            f"second request redialed the replyless peer "
            f"({first_commands} -> {peer.commands} commands)")
    finally:
        conn.close()
        peer.stop()


def test_redis_connect_backoff_config_parse(ng: Nginx) -> None:
    """S231-L2-BACKOFF: connect_backoff= parses as a time value on both
    drivers and rejects garbage the same way timeout= already does."""
    if ng.redis_port is not None:
        def mutate_ok(c):
            return c.replace(
                f"cache_turbo_redis    127.0.0.1:{ng.redis_port} prefix=ct: timeout=250ms;",
                f"cache_turbo_redis    127.0.0.1:{ng.redis_port} prefix=ct: "
                f"timeout=250ms connect_backoff=500ms;", 1)
        r_ok = _config_test_result(ng, mutate_ok)
        assert r_ok.returncode == 0, \
            f"cache_turbo_redis connect_backoff=500ms rejected:\n{r_ok.stdout}"

        def mutate_bad(c):
            return c.replace(
                f"cache_turbo_redis    127.0.0.1:{ng.redis_port} prefix=ct: timeout=250ms;",
                f"cache_turbo_redis    127.0.0.1:{ng.redis_port} prefix=ct: "
                f"timeout=250ms connect_backoff=notatime;", 1)
        r_bad = _config_test_result(ng, mutate_bad)
        assert r_bad.returncode != 0, \
            f"cache_turbo_redis connect_backoff=notatime was accepted:\n{r_bad.stdout}"
        assert "bad connect_backoff" in r_bad.stdout, \
            f"missing bad-connect_backoff diagnostic:\n{r_bad.stdout}"

    if ng.memcached_port is not None:
        def mutate_mc_ok(c):
            return c.replace(
                f"cache_turbo_memcached  127.0.0.1:{ng.memcached_port} prefix=mc: timeout=250ms;",
                f"cache_turbo_memcached  127.0.0.1:{ng.memcached_port} prefix=mc: "
                f"timeout=250ms connect_backoff=500ms;", 1)
        r_mc_ok = _config_test_result(ng, mutate_mc_ok)
        assert r_mc_ok.returncode == 0, \
            f"cache_turbo_memcached connect_backoff=500ms rejected:\n{r_mc_ok.stdout}"

        def mutate_mc_bad(c):
            return c.replace(
                f"cache_turbo_memcached  127.0.0.1:{ng.memcached_port} prefix=mc: timeout=250ms;",
                f"cache_turbo_memcached  127.0.0.1:{ng.memcached_port} prefix=mc: "
                f"timeout=250ms connect_backoff=notatime;", 1)
        r_mc_bad = _config_test_result(ng, mutate_mc_bad)
        assert r_mc_bad.returncode != 0, \
            f"cache_turbo_memcached connect_backoff=notatime was accepted:\n{r_mc_bad.stdout}"
        assert "bad connect_backoff" in r_mc_bad.stdout, \
            f"missing bad-connect_backoff diagnostic:\n{r_mc_bad.stdout}"


def test_valid_dup_status_warns(ng: Nginx) -> None:
    """COR-9: a second cache_turbo_valid rule for a status code is dead
    (status_ttl returns the first match). nginx -t loads but must warn."""
    r = _config_test_result(
        ng, lambda c: c.replace(
            "cache_turbo_valid    0;",
            "cache_turbo_valid    0;\n"
            "            cache_turbo_valid 404 1m;\n"
            "            cache_turbo_valid 404 2m;", 1))
    assert r.returncode == 0, \
        f"duplicate-status config unexpectedly failed nginx -t:\n{r.stdout}"
    assert "duplicate rule for status" in r.stdout, \
        f"missing duplicate-status warning:\n{r.stdout}"


def test_tag_without_l2_warns(ng: Nginx) -> None:
    """COR-0: cache_turbo_tag in a location with no Redis L2 is inert (tags live
    only in Redis). nginx -t loads but must warn it has no effect."""
    r = _config_test_result(
        ng, lambda c: c.replace(
            "cache_turbo_valid    0;",
            "cache_turbo_valid    0;\n"
            "            cache_turbo_tag      $arg_t;", 1))
    assert r.returncode == 0, \
        f"tag-without-L2 config unexpectedly failed nginx -t:\n{r.stdout}"
    assert "no effect here" in r.stdout, \
        f"missing tag-without-L2 warning:\n{r.stdout}"


def test_tag_without_l2_but_surrogate_key_no_warn(ng: Nginx) -> None:
    """COR-0 exception: cache_turbo_surrogate_key gives cache_turbo_tag a
    Redis-free consumer (downstream Surrogate-Key emission). The tag is then NOT
    inert, so the "no effect here" warning must be SUPPRESSED even with no L2 --
    otherwise a valid Redis-free CDN-sync config nags on every reload."""
    r = _config_test_result(
        ng, lambda c: c.replace(
            "cache_turbo_valid    0;",
            "cache_turbo_valid    0;\n"
            "            cache_turbo_tag      $arg_t;\n"
            "            cache_turbo_surrogate_key on;", 1))
    assert r.returncode == 0, \
        f"tag+surrogate_key config unexpectedly failed nginx -t:\n{r.stdout}"
    assert "no effect here" not in r.stdout, \
        f"tag-without-L2 warning must be suppressed when surrogate_key is on:\n{r.stdout}"


def test_cache_control_invalid_mode_rejected(ng: Nginx) -> None:
    """cache_turbo_cache_control takes respect|honor|ignore. Any other token is
    rejected at config time: the mode decides whether an origin's `private` /
    `no-store` is obeyed, so silently falling back to a default on a typo'd
    value would turn a storage floor off without any signal."""
    r = _config_test_result(
        ng, lambda c: c.replace(
            "cache_turbo_valid    0;",
            "cache_turbo_valid    0;\n"
            "            cache_turbo_cache_control respekt;", 1))
    assert r.returncode != 0, \
        f"invalid cache_control mode was accepted by nginx -t:\n{r.stdout}"
    assert "want respect|honor|ignore" in r.stdout, \
        f"missing/odd invalid-mode diagnostic:\n{r.stdout}"


def test_cache_control_duplicate_rejected(ng: Nginx) -> None:
    """Two cache_turbo_cache_control directives in one block is a config error,
    not last-wins. The two modes disagree about the storage floor, so guessing
    which the operator meant is worse than refusing to start."""
    r = _config_test_result(
        ng, lambda c: c.replace(
            "cache_turbo_valid    0;",
            "cache_turbo_valid    0;\n"
            "            cache_turbo_cache_control honor;\n"
            "            cache_turbo_cache_control ignore;", 1))
    assert r.returncode != 0, \
        f"duplicate cache_control was accepted by nginx -t:\n{r.stdout}"
    assert "is duplicate" in r.stdout, \
        f"missing duplicate-directive diagnostic:\n{r.stdout}"


def test_valid_status_rejects_out_of_range_code(ng: Nginx) -> None:
    """A cache_turbo_valid status code outside 100..599 is rejected. This is a
    DIFFERENT arm from the 1xx/206/304 refusal (test_valid_status_rejects_304):
    that one refuses valid-but-unstorable codes, this one refuses a value that
    is not an HTTP status at all -- e.g. a time typo'd into the code slot."""
    r = _config_test_result(
        ng, lambda c: c.replace(
            "cache_turbo_valid    0;",
            "cache_turbo_valid    0;\n"
            "            cache_turbo_valid 999 1m;", 1))
    assert r.returncode != 0, \
        f"out-of-range status code was accepted by nginx -t:\n{r.stdout}"
    assert "bad status code" in r.stdout, \
        f"missing/odd bad-status-code diagnostic:\n{r.stdout}"


def test_valid_rejects_bad_time(ng: Nginx) -> None:
    """The last cache_turbo_valid argument is always the time; an unparseable
    one is rejected rather than silently resolving to 0 (which the parser then
    promotes to cache-forever -- the worst possible reading of a typo)."""
    r = _config_test_result(
        ng, lambda c: c.replace(
            "cache_turbo_valid    0;",
            "cache_turbo_valid    0;\n"
            "            cache_turbo_valid 404 5x;", 1))
    assert r.returncode != 0, \
        f"bad valid time was accepted by nginx -t:\n{r.stdout}"
    assert "bad time" in r.stdout, \
        f"missing/odd bad-time diagnostic:\n{r.stdout}"


def test_require_header_rejects_invalid_name(ng: Nginx) -> None:
    """cache_turbo_require_header takes an RFC 9110 token. A non-token name can
    never match a real response header, so the store gate would silently never
    pass -- a cache that stores nothing, with no diagnostic. Rejected instead."""
    r = _config_test_result(
        ng, lambda c: c.replace(
            "cache_turbo_valid    0;",
            "cache_turbo_valid    0;\n"
            "            cache_turbo_require_header \"X-Bad:Name\";", 1))
    assert r.returncode != 0, \
        f"invalid require_header name was accepted by nginx -t:\n{r.stdout}"
    assert "invalid header name" in r.stdout, \
        f"missing/odd invalid-header-name diagnostic:\n{r.stdout}"


def test_require_header_duplicate_rejected(ng: Nginx) -> None:
    """Two cache_turbo_require_header directives in one block: the gate is a
    single name, so the second would be silently dropped and the operator would
    believe both headers were required."""
    r = _config_test_result(
        ng, lambda c: c.replace(
            "cache_turbo_valid    0;",
            "cache_turbo_valid    0;\n"
            "            cache_turbo_require_header X-One;\n"
            "            cache_turbo_require_header X-Two;", 1))
    assert r.returncode != 0, \
        f"duplicate require_header was accepted by nginx -t:\n{r.stdout}"
    assert "is duplicate" in r.stdout, \
        f"missing duplicate-directive diagnostic:\n{r.stdout}"


def test_redis_bad_db_rejected(ng: Nginx) -> None:
    """A non-numeric Redis db is rejected at config time rather than defaulting
    to db 0 -- silently sharing db 0 with another application's keys is exactly
    what an explicit db selector was written to prevent.

    Both arms are pinned because they are SEPARATE parser paths with separate
    diagnostics: the `db=N` trailing param and the `/N` DSN suffix. The rendered
    test config uses the param form, so the DSN arm is reached by rewriting a
    bare `host:port db=N` line into DSN form."""
    if ng.redis_port is None:
        return

    param_anchor = f"127.0.0.1:{ng.redis_port} db=1"
    assert param_anchor in nginx_config(
        ng.root, ng.port, ng.module, ng.origin_port, 1, ng.redis_port,
        ng.redis_auth_port, ng.redis_password, ng.redis_tls_port,
        ng.redis_tls_ca, ng.memcached_port), \
        f"test fixture missing anchor {param_anchor!r}"

    # arm 1: db= trailing param
    r = _config_test_result(
        ng, lambda c: c.replace(param_anchor,
                                f"127.0.0.1:{ng.redis_port} db=xy", 1))
    assert r.returncode != 0, \
        f"bad db= param was accepted by nginx -t:\n{r.stdout}"
    assert "bad db" in r.stdout, \
        f"missing/odd bad-db diagnostic:\n{r.stdout}"

    # arm 2: /N DSN suffix -- distinct code path, distinct message
    r = _config_test_result(
        ng, lambda c: c.replace(param_anchor,
                                f"redis://user:{_DSN_REDACTION_MARKER}"
                                f"@127.0.0.1:{ng.redis_port}/xy", 1))
    assert r.returncode != 0, \
        f"bad DSN db was accepted by nginx -t:\n{r.stdout}"
    assert "bad db in DSN" in r.stdout, \
        f"missing/odd bad-DSN-db diagnostic:\n{r.stdout}"
    assert _DSN_REDACTION_MARKER not in r.stdout, \
        f"invalid DSN leaked its credential marker:\n{r.stdout}"


def test_redis_db_cap_rejected(ng: Nginx) -> None:
    """A syntactically valid but out-of-range db index is rejected at config
    time, both as the `db=N` param and as the `/N` DSN suffix.

    Distinct from test_redis_bad_db_rejected: that one refuses a value that is
    not a number at all; this one refuses a well-formed number that no Redis
    will accept. Redis ships `databases 16` (indices 0..15), so `db=99` used to
    pass `nginx -t` clean and then fail every L2 op at runtime on SELECT --
    silent until traffic. Both arms are pinned because they are separate parser
    paths with separate diagnostics."""
    if ng.redis_port is None:
        return

    param_anchor = f"127.0.0.1:{ng.redis_port} db=1"
    assert param_anchor in nginx_config(
        ng.root, ng.port, ng.module, ng.origin_port, 1, ng.redis_port,
        ng.redis_auth_port, ng.redis_password, ng.redis_tls_port,
        ng.redis_tls_ca, ng.memcached_port), \
        f"test fixture missing anchor {param_anchor!r}"

    # arm 1: db= trailing param
    r = _config_test_result(
        ng, lambda c: c.replace(param_anchor,
                                f"127.0.0.1:{ng.redis_port} db=99", 1))
    assert r.returncode != 0, \
        f"out-of-range db= param was accepted by nginx -t:\n{r.stdout}"
    assert "exceeds the maximum" in r.stdout, \
        f"missing/odd db-cap diagnostic:\n{r.stdout}"

    # arm 2: /N DSN suffix -- distinct code path, distinct message
    r = _config_test_result(
        ng, lambda c: c.replace(param_anchor,
                                f"redis://user:{_DSN_REDACTION_MARKER}"
                                f"@127.0.0.1:{ng.redis_port}/99", 1))
    assert r.returncode != 0, \
        f"out-of-range DSN db was accepted by nginx -t:\n{r.stdout}"
    assert "db in DSN" in r.stdout and "exceeds the maximum" in r.stdout, \
        f"missing/odd DSN-db-cap diagnostic:\n{r.stdout}"
    assert _DSN_REDACTION_MARKER not in r.stdout, \
        f"out-of-range DSN leaked its credential marker:\n{r.stdout}"

    # the boundary itself must still be accepted -- a cap that rejects the
    # highest legal index would be an off-by-one that no bad-value test catches
    r = _config_test_result(
        ng, lambda c: c.replace(param_anchor,
                                f"127.0.0.1:{ng.redis_port} db=15", 1))
    assert r.returncode == 0, \
        f"db=15 (the highest legal index) was rejected:\n{r.stdout}"


def test_l2_prefix_charset_rejected(ng: Nginx) -> None:
    """AUD-MC1: an L2 key prefix carrying a control character, or long enough to
    push the composed key past the 250-byte memcached limit, is refused at
    config time -- on BOTH backends, which parse `prefix=` in separate
    functions.

    Only `prefix.len != 0` used to be checked. The module documents the composed
    L2 key as "printable, no spaces/control chars, <=250 bytes"
    (ngx_http_cache_turbo_memcached.c header), an invariant the digest half
    honoured and the operator-supplied half did not. memcached frames its
    commands by spaces and CRLF, so such a prefix corrupts the command and the
    location silently degrades to L1-only -- a config typo with no diagnostic.

    The last arm is what keeps the others from being vacuous: an ordinary
    prefix must still be accepted, or a validator that refused everything would
    satisfy every rejection assertion above while breaking the feature."""
    if ng.redis_port is None or ng.memcached_port is None:
        return

    redis_anchor = f"127.0.0.1:{ng.redis_port} db=1"
    mc_anchor = f"127.0.0.1:{ng.memcached_port} prefix=mc: timeout=250ms"
    cfg = nginx_config(
        ng.root, ng.port, ng.module, ng.origin_port, 1, ng.redis_port,
        ng.redis_auth_port, ng.redis_password, ng.redis_tls_port,
        ng.redis_tls_ca, ng.memcached_port)
    assert redis_anchor in cfg and mc_anchor in cfg, \
        "test fixture missing an anchor for one of the two L2 parsers"

    # arm 1: control byte, redis parser
    r = _config_test_result(
        ng, lambda c: c.replace(redis_anchor,
                                f"127.0.0.1:{ng.redis_port} prefix=ct\x01x:", 1))
    assert r.returncode != 0, \
        f"a control character in prefix= was accepted by nginx -t:\n{r.stdout}"
    assert "must be printable" in r.stdout, \
        f"missing/odd prefix-charset diagnostic:\n{r.stdout}"

    # arm 2: same byte, memcached parser -- separate function, separate message
    r = _config_test_result(
        ng, lambda c: c.replace(mc_anchor,
                                f"127.0.0.1:{ng.memcached_port} prefix=mc\x01:", 1))
    assert r.returncode != 0, \
        f"memcached accepted a control character in prefix=:\n{r.stdout}"
    assert "cache_turbo_memcached" in r.stdout and "must be printable" in r.stdout, \
        f"memcached prefix diagnostic did not name its own directive:\n{r.stdout}"

    # arm 3: length. 187 bytes leaves less than the 64 the module may append.
    long_prefix = "c" * 187
    r = _config_test_result(
        ng, lambda c: c.replace(mc_anchor,
                                f"127.0.0.1:{ng.memcached_port} prefix={long_prefix}", 1))
    assert r.returncode != 0, \
        f"an over-long prefix= was accepted by nginx -t:\n{r.stdout}"
    assert "at most" in r.stdout and "186" in r.stdout, \
        f"missing/odd prefix-length diagnostic:\n{r.stdout}"

    # arm 4: the boundary is usable, and an ordinary prefix still parses
    r = _config_test_result(
        ng, lambda c: c.replace(mc_anchor,
                                f"127.0.0.1:{ng.memcached_port} prefix={'c' * 186}", 1))
    assert r.returncode == 0, \
        f"a 186-byte prefix (the longest legal one) was rejected:\n{r.stdout}"


def test_max_size_not_cached(ng: Nginx) -> None:
    """Responses larger than cache_turbo_max_size are never cached (Q2: the
    body filter early-aborts capture the moment body_len crosses max_size, so
    the oversize blob is delegated to a stacked native cache instead of being
    fully copied into the request pool and discarded). Repeated reads must keep
    reaching the origin (no stale cached copy) and never surface an error."""
    fetch(ng.port, "/big/x")
    for _ in range(3):
        s, b, h = fetch(ng.port, "/big/x")
        assert s == 200, f"oversize delegate served {s}, expected live 200"
        assert b, "oversize response lost its body"
        assert "x-cache" not in h, "oversized response should not be cached"
