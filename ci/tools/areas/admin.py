"""cache-turbo runtime tests — admin area.

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
    _admin_min_uses_skips,
    _config_test_result,
    _errlog_level,
    _redis_conns_received,
)


def test_min_uses_lock_merged_concurrent_claim(ng: Nginx, origin: Origin) -> None:
    """S231-PERF-MISSLOCKS: count_miss() + claim() now run under ONE zone-mutex
    hold (clcf->l1->resolve_miss()) instead of two back-to-back acquisitions on
    the min_uses>1 && cache_turbo_lock-on cold path. This pins the merged
    behaviour, including the concurrent case the two-lock version had to
    handle across its (now closed) gap between the two acquisitions: a second
    worker claiming the key in between.

    /mmulock/ (private zone mmulockz) sets min_uses 3 with cache_turbo_lock on
    (its default). Prime the key to 2/3 -- one below the threshold that flips
    count_miss() from NGX_DECLINED to NGX_OK -- then fire a CONCURRENT burst.
    Every burst request's count_miss() sees the SAME already-2 counter and
    crosses to 3 (min_uses counts every miss on a body-less node, not just the
    winner's), so all of them proceed into claim() on this pass. Exactly one
    must become the CLAIM_WINNER regenerator; the rest must take CLAIM_LOSER
    (or, once the winner's store lands, CLAIM_FRESH) and wait rather than each
    independently reaching the origin -- collapsing the burst to the SAME
    small number of origin fetches test_cold_single_flight requires, proving
    the merge did not reopen the single-flight window between the counting
    decision and the claim decision. A regression that ran claim() against a
    STALE pre-merge lookup (the seam resolve_miss()'s contract comment calls
    out: re-resolving ctn after count_miss_locked() may have just inserted a
    counter node) would let a second burst request also see the key "absent"
    and allocate a SECOND stub, breaking single-flight — this test's origin
    fetch bound catches that the same way test_cold_single_flight's bound
    catches the classic v10 stampede."""
    uri = f"/mmulock/mmu-{time.time()}"          # never fetched before
    base = origin.hits_for("/mmu-")
    skips0 = _admin_min_uses_skips(ng, "/_cache_mmulock")
    waits0 = _admin_lock_waits(ng, "/_cache_mmulock")

    # Prime to 2/3, serially, so the fixture starts from a known counter state
    # (mirrors test_min_uses's own priming) before the concurrent burst below
    # exercises the merged resolve_miss() at the exact miss that crosses the
    # threshold and enters claim() for the first time.
    for i in (1, 2):
        s, _, h = fetch(ng.port, uri)
        assert s == 200, f"priming req{i} status {s}"
        assert "x-cache" not in h, f"priming req{i} must not be a HIT: {h}"
    assert origin.hits_for("/mmu-") == base + 2, "both priming misses must reach origin"
    assert _admin_min_uses_skips(ng, "/_cache_mmulock") - skips0 == 2, \
        "priming misses must both be counted as min_uses skips"

    # Rendezvous burst on the threshold-crossing request, same discipline as
    # test_cold_single_flight: unsynchronised starts let a straggler arrive
    # after the winner's fill and take CLAIM_FRESH without ever parking,
    # driving lock_waits to 0 while single-flight still worked correctly.
    readers = 24
    barrier = threading.Barrier(readers)

    def _burst_reader(_i: int) -> tuple[int, bytes, dict]:
        barrier.wait()
        return fetch(ng.port, uri)

    with concurrent.futures.ThreadPoolExecutor(max_workers=readers) as pool:
        results = list(pool.map(_burst_reader, range(readers)))
    assert {r[0] for r in results} == {200}, \
        f"threshold-crossing burst returned {set(r[0] for r in results)}"

    # All readers must agree on one body: exactly one regenerated copy, not
    # one per request (which is what a reopened window between count_miss()
    # and claim() would produce -- see test_cold_lock_off_stampedes for the
    # contrast when single-flight is genuinely off).
    bodies = {r[1] for r in results}
    assert len(bodies) == 1, \
        f"threshold-crossing burst served {len(bodies)} distinct bodies " \
        f"(single-flight window reopened between count_miss and claim)"

    regens = origin.hits_for("/mmu-") - base - 2   # minus the 2 priming misses
    assert regens <= 3, \
        f"merged min_uses+lock single-flight failed: {regens} origin fetches " \
        f"for {readers} concurrent threshold-crossing readers"

    # The collapse must have happened via the wait path, not just lucky
    # timing -- same liveness proof test_cold_single_flight requires.
    assert _admin_lock_waits(ng, "/_cache_mmulock") - waits0 > 0, \
        "no requests waited on the merged claim -- single-flight did not engage"

    # No further min_uses skip: the threshold was already crossed by the first
    # burst request's count_miss(), so every subsequent one in the burst takes
    # the NGX_OK arm (proceeds into claim()), never the NGX_DECLINED short-
    # circuit resolve_miss() also has to reproduce.
    assert _admin_min_uses_skips(ng, "/_cache_mmulock") - skips0 == 2, \
        "the burst must not add any further min_uses skip past the threshold"
    drain_origin(origin)


def test_min_uses(ng: Nginx, origin: Origin) -> None:
    """v15 cache_turbo_min_uses N: a response is cached only after its key has
    cold-missed N times. /minuses/ sets N=3 — the first two misses run to the
    origin without storing, the third stores, the fourth is a HIT served from
    cache. The min_uses_skips counter rises by exactly the two skipped misses."""
    uri = "/minuses/page1"                       # never fetched before
    base = origin.hits_for("/page1")
    skips0 = _admin_min_uses_skips(ng)

    # Below threshold: misses 1 and 2 both reach the origin, neither is cached.
    for i in (1, 2):
        s, _, h = fetch(ng.port, uri)
        assert s == 200, f"sub-threshold req{i} status {s}"
        assert "x-cache" not in h, \
            f"req{i} must NOT be a HIT (below min_uses): {h.get('x-cache')}"
    assert origin.hits_for("/page1") == base + 2, \
        f"both sub-threshold reqs must hit origin: {origin.hits_for('/page1') - base}"

    # The third miss reaches the threshold: THIS request stores (still served
    # from the origin, no X-Cache), so its body is what later HITs return.
    s, b3, h3 = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in h3, \
        "the threshold-reaching miss is served from origin, then stored"
    assert origin.hits_for("/page1") == base + 3, "the storing miss must reach the origin"

    # The fourth request is now a cache HIT — no further origin traffic.
    s, b4, h4 = fetch(ng.port, uri)
    assert h4.get("x-cache") == "HIT", f"req4 X-Cache={h4.get('x-cache')}"
    assert origin.hits_for("/page1") == base + 3, "req4 must be served from cache, not origin"
    assert b4 == b3, "the HIT body must match the response that was stored"

    # Exactly the two sub-threshold misses were skipped (origin, no store).
    assert _admin_min_uses_skips(ng) - skips0 == 2, \
        f"min_uses_skips delta {_admin_min_uses_skips(ng) - skips0} != 2"


def test_min_uses_off_by_default(ng: Nginx) -> None:
    """A location with no cache_turbo_min_uses stores on the first miss (the
    feature is off by default) — proving min_uses doesn't change the baseline."""
    s, _, h1 = fetch(ng.port, "/c/minuses-default")    # /c/ has no min_uses
    assert s == 200 and "x-cache" not in h1, "first miss must reach origin"
    s, _, h2 = fetch(ng.port, "/c/minuses-default")
    assert h2.get("x-cache") == "HIT", \
        f"second req must HIT (min_uses default 1): {h2.get('x-cache')}"


def test_min_uses_band_aggressive(ng: Nginx, origin: Origin) -> None:
    """H3c: the AGGRESSIVE band raises min_uses to 2, with NO directive present.

    This is the band column doing the work: /pab/ carries only
    `cache_turbo_preset aggressive`, so the gate can only be armed by the band's
    min_uses=2. The first miss must therefore go to the origin WITHOUT storing,
    and the second must also reach the origin (it is the one that stores), so
    the third is the first HIT.

    Contrast with min_uses=1, where request 2 would already be a HIT -- that
    single difference is what distinguishes 'the band value reached the runtime'
    from 'some caching happened'. Paired with test_min_uses_band_balanced_is_1,
    which runs the identical sequence against the default preset and DOES get a
    HIT on request 2; if the column were wired to every band, that test fails."""
    uri = "/pab/band-minuses"                    # never fetched before
    base = origin.hits
    skips0 = _admin_min_uses_skips(ng)

    # Request 1: below the band threshold -> origin, not stored.
    s, _, h1 = fetch(ng.port, uri)
    assert s == 200, f"req1 status {s}"
    assert "x-cache" not in h1, \
        f"req1 must not be a HIT: {h1.get('x-cache')}"

    # Request 2: reaches min_uses=2 -> served from origin, and THIS one stores.
    s, b2, h2 = fetch(ng.port, uri)
    assert s == 200, f"req2 status {s}"
    assert "x-cache" not in h2, \
        ("req2 must still be served from the origin under the aggressive band "
         f"(min_uses=2), got X-Cache={h2.get('x-cache')} -- the band's min_uses "
         "did not reach the runtime, i.e. the H3c column is not wired")
    assert origin.hits == base + 2, \
        f"both sub-threshold reqs must reach the origin: {origin.hits - base}"

    # Request 3: the entry stored on req2 is now serveable.
    s, b3, h3 = fetch(ng.port, uri)
    assert h3.get("x-cache") == "HIT", f"req3 X-Cache={h3.get('x-cache')}"
    assert origin.hits == base + 2, "req3 must come from cache, not the origin"
    assert b3 == b2, "the HIT body must match the response that was stored"

    # Exactly one sub-threshold miss was skipped (req1); req2 stored.
    assert _admin_min_uses_skips(ng) - skips0 == 1, \
        f"min_uses_skips delta {_admin_min_uses_skips(ng) - skips0} != 1"


def test_min_uses_band_balanced_is_1(ng: Nginx, origin: Origin) -> None:
    """H3c: BALANCED -- the DEFAULT preset -- keeps min_uses=1, so adding the
    band column changed no existing user's caching behaviour.

    /pbb/ is `cache_turbo_preset balanced` with no min_uses directive. Request 2
    must be a HIT, exactly as it was before H3c. This is the semver guard: if a
    later edit flips the BALANCED row to 2 (the change that was explicitly NOT
    signed off), this test fails rather than silently changing the first-request
    store behaviour for every default-preset deployment."""
    uri = "/pbb/band-minuses-default"            # never fetched before
    base = origin.hits_for("/band-minuses-default")

    s, _, h1 = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in h1, "first miss must reach the origin"

    s, _, h2 = fetch(ng.port, uri)
    assert h2.get("x-cache") == "HIT", \
        ("the balanced band must store on the FIRST miss (min_uses=1); got "
         f"X-Cache={h2.get('x-cache')} -- a band row other than aggressive was "
         "given min_uses > 1, which is a semver-visible default change")
    assert origin.hits_for("/band-minuses-default") == base + 1, "req2 must be served from cache"


def test_min_uses_directive_beats_band(ng: Nginx, origin: Origin) -> None:
    """H3c: an explicit cache_turbo_min_uses overrides the resolved preset band,
    the same raw/effective split as valid/beta/lock_ttl/stale_mult.

    /pmu/ is `cache_turbo_preset aggressive` (band min_uses=2) plus an explicit
    `cache_turbo_min_uses 1`. The directive must win, so request 2 is a HIT --
    whereas /pab/ (same preset, no directive) needs three requests to get one.
    Without the raw/effective wiring the band would win and req2 would miss."""
    uri = "/pmu/beats-band"                      # never fetched before
    base = origin.hits_for("/beats-band")

    s, _, h1 = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in h1, "first miss must reach the origin"

    s, _, h2 = fetch(ng.port, uri)
    assert h2.get("x-cache") == "HIT", \
        ("explicit cache_turbo_min_uses 1 must beat the aggressive band's 2, so "
         f"req2 is a HIT; got X-Cache={h2.get('x-cache')} -- the directive lost "
         "to the band, i.e. min_uses_raw is not resolving ahead of band->min_uses")
    assert origin.hits_for("/beats-band") == base + 1, "req2 must be served from cache"


def test_min_uses_rejects_out_of_range(ng: Nginx) -> None:
    """H3c: cache_turbo_min_uses is range-checked at config time.

    `0` is the arm that matters: merge_loc_conf used to coerce a value < 1 up to
    1, so accepting a literal 0 would silently mean "store on the first miss"
    rather than whatever the operator intended by it. Rejecting at parse keeps
    the directive honest -- the same lesson as stale_mult. Boundaries 1 and 32
    must stay accepted so an off-by-one range check fails here."""
    anchor = "cache_turbo_min_uses 3;"
    assert anchor in nginx_config(
        ng.root, ng.port, ng.module, ng.origin_port, 1, ng.redis_port,
        ng.redis_auth_port, ng.redis_password, ng.redis_tls_port,
        ng.redis_tls_ca, ng.memcached_port), \
        f"test fixture missing anchor {anchor!r}"

    # in-range-check arm: parses as a number, refused by the bounds
    for bad in ("0", "33"):
        r = _config_test_result(
            ng, lambda c, b=bad: c.replace(
                anchor, f"cache_turbo_min_uses {b};", 1))
        assert r.returncode != 0, \
            f"cache_turbo_min_uses {bad} was accepted by nginx -t:\n{r.stdout}"
        assert "out of range" in r.stdout, \
            f"missing/odd range diagnostic for {bad}:\n{r.stdout}"

    # parse arm: ngx_atoi has no sign handling, so a negative never reaches the
    # bounds check and surfaces as "bad value" -- rejected, different diagnostic.
    # Pinned separately so a later editor cannot collapse the two paths.
    for bad in ("-1", "abc"):
        r = _config_test_result(
            ng, lambda c, b=bad: c.replace(
                anchor, f"cache_turbo_min_uses {b};", 1))
        assert r.returncode != 0, \
            f"cache_turbo_min_uses {bad} was accepted by nginx -t:\n{r.stdout}"
        assert "bad value" in r.stdout, \
            f"missing/odd bad-value diagnostic for {bad}:\n{r.stdout}"

    # both boundaries stay legal
    for good in ("1", "32"):
        r = _config_test_result(
            ng, lambda c, g=good: c.replace(
                anchor, f"cache_turbo_min_uses {g};", 1))
        assert r.returncode == 0, \
            f"cache_turbo_min_uses {good} (a legal boundary) was rejected:\n{r.stdout}"


def _recent_memo_skips(ng: Nginx, limit: int = 8) -> str:
    """Tail the URIs most recently skipped by a negative memo, for diagnostics.

    Reads the module's own `L2 GET skipped by negative memo "<uri>"` debug line
    out of logs/error.log. Only produces anything when the harness ran with
    TEST_CT_ERRLOG=debug (see _errlog_level) -- otherwise those lines are below
    the log level and this returns a hint saying so.

    Diagnostic only: never assert on this. It exists so that a failure of a
    ZONE-GLOBAL counter assertion names the uri that actually bumped the
    counter, rather than leaving the reader to bisect the suite.
    """
    log = ng.root / "logs" / "error.log"
    try:
        text = log.read_text(errors="replace")
    except OSError as exc:
        return f"<error.log unreadable: {exc}>"
    hits = re.findall(r'L2 GET skipped by negative memo "([^"]*)"', text)
    if not hits:
        return ("<none logged -- re-run with TEST_CT_ERRLOG=debug>"
                if _errlog_level() != "debug" else "<none logged at debug>")
    return ", ".join(hits[-limit:])


def _admin_l2_neg_skips(ng: Nginx, endpoint: str = "/_cache") -> int:
    """L13: count of L2 GETs skipped by a live negative memo (admin stats).

    ⚠ `l2_neg_skips` is PER-ZONE (z->sh->l2_neg_skips) and the admin handler
    emits exactly ONE zone's stats, so `endpoint` must name the admin location
    bound to the zone the location under test uses -- /_cache is
    `cache_turbo_admin main`, /_cache_l2neg is `cache_turbo_admin l2negz`.
    Reading the wrong one yields a counter the test never writes, which turns
    an `== 0` assertion permanently true (SUITE-1)."""
    import json
    _, b, _ = fetch(ng.port, endpoint)
    return int(json.loads(b).get("l2_neg_skips", 0))


def test_l2_negative_ttl_skips_repeat_get(ng: Nginx, origin: Origin,
                                          redis: RedisServer) -> None:
    """L13: after an L2 GET misses, a memo makes the next cold request for the
    same key skip the round-trip entirely.

    This measures the thing that actually changed -- the number of Redis
    connections the module opens -- NOT merely that the response is still
    correct. A test asserting only status/body would pass with or without the
    memo (the L9 lesson: a perf change needs a test that observes the op count).

    /l2neg/ has no keepalive, so each L2 op is exactly one accepted connection,
    and its min_uses 4 keeps the key below the store threshold -- so both
    requests stay on the cold-miss path that consults L2, rather than the second
    becoming an L1 HIT that trivially avoids Redis for the wrong reason."""
    uri = f"/l2neg/nomemo-{time.time()}"

    # Request 1 primes the memo: a real L2 GET that misses. Measure it alone --
    # redis.cli() shells out and opens its OWN connection, so any bookkeeping
    # between two readings would be counted as module traffic.
    before = _redis_conns_received(redis)
    s1, _, _ = fetch(ng.port, uri)
    assert s1 == 200, f"req1 status {s1}"
    time.sleep(0.4)                       # let the write-through SET settle
    first = _redis_conns_received(redis) - before
    assert first >= 1, \
        f"req1 must actually consult L2 (Redis conns delta {first} < 1)"

    # Request 2 is inside the 3s window: the memo must suppress the GET. A
    # write-through SET may still occur, so assert strictly fewer ops, not zero.
    # /_cache_l2neg, not /_cache: /l2neg/ lives in the private `l2negz` zone and
    # l2_neg_skips is per-zone, so /_cache (bound to `main`) would report a
    # counter this location never touches -- making this `>= 1` permanently
    # FALSE rather than trivially true (SUITE-1).
    skips0 = _admin_l2_neg_skips(ng, "/_cache_l2neg")
    before = _redis_conns_received(redis)
    s2, _, _ = fetch(ng.port, uri)
    assert s2 == 200, f"req2 status {s2}"
    time.sleep(0.4)
    second = _redis_conns_received(redis) - before

    assert second < first, \
        (f"req2 opened {second} Redis connections vs req1's {first} -- the "
         "negative memo did not suppress the repeat L2 GET")
    assert _admin_l2_neg_skips(ng, "/_cache_l2neg") - skips0 >= 1, \
        ("l2_neg_skips did not rise: the request avoided Redis for some other "
         "reason than the memo, so this test is not measuring the memo")


def test_l2_negative_ttl_expires(ng: Nginx, origin: Origin,
                                 redis: RedisServer) -> None:
    """L13: the memo is a BOUNDED-staleness window, not a permanent off-switch.

    The whole coherence story for this feature is "the memo expires", so the
    expiry is the load-bearing assertion: once cache_turbo_l2_negative_ttl
    seconds pass, the next request must consult L2 for real again and pick up
    anything a peer stored meanwhile. Without expiry (or with the window sliding
    forward on every memoed request) L2 would stay switched off for a hot-but-
    absent key forever -- the exact failure the re-arm guard prevents."""
    # /l2neglife/ + a "ccnostore" URI: DEFAULT min_uses (1) so the full cold path
    # including claim() runs -- claim() is what marks the node `refreshing` and is
    # the mechanism the memo-masking bug rode on, so a location with a raised
    # min_uses cannot exercise it at all (see the location comment). The
    # uncacheable origin response is what keeps the key off the store path so
    # later requests do not turn into L1 HITs.
    uri = f"/l2neglife/ccnostore-expiry-{time.time()}"

    fetch(ng.port, uri)                   # arm the memo with a real GET
    time.sleep(0.4)

    skips0 = _admin_l2_neg_skips(ng, "/_cache_l2neglife")
    fetch(ng.port, uri)                   # inside the window: skipped
    assert _admin_l2_neg_skips(ng, "/_cache_l2neglife") - skips0 >= 1, \
        "the second request should have been memo-skipped (window is 3s)"

    # Keep requesting ACROSS the whole window. Each of these is memo-skipped, and
    # each is therefore a chance for a buggy build to re-stamp l2_neg_until from
    # a miss it only "knew about" because of the memo -- which would slide the
    # window forward indefinitely and never let the expiry below happen. A single
    # mid-window request cannot detect that: the window would slide by only the
    # sleep length and the final wait would still clear it.
    # Hammer the key for LONGER than the 3s window, faster than the window, so
    # every request lands while the memo is still live. In a correct build the
    # memo is armed once and expires 3s after that first REAL miss -- mid-burst
    # -- so the tail of this loop is already consulting L2 again. In a build
    # that re-arms from memoed misses, l2_neg_until is pushed forward by every
    # request and the memo never dies while traffic continues.
    #
    # The detection therefore has to happen DURING the burst, not after it:
    # once requests stop, even a slid window lapses within one TTL, so any
    # "sleep then check" ending would pass on both builds.
    # The memo was armed once, at the first real miss. It must therefore DIE
    # mid-burst, ~3s in, and every later request in the burst must consult L2 for
    # real. Record when skips stop rising: that is the memo's true death.
    #
    # This assertion is what makes the !l2_neg_skipped re-arm guard testable. It
    # was impossible before the L13-fix (memo lifetime collapsed to ~1 request, so
    # the window was re-armed from a REAL miss every time and a guard-removed
    # Measure the memo's lifetime by counting GET COMMANDS ON THE WIRE.
    #
    # ⚠ Neither of the obvious signals works here, and both were tried:
    #
    # 1. l2_neg_skips is NOT a per-request counter. It is bumped on the skip
    #    branch in the request handler, which only runs on a request's FIRST entry
    #    with !l2_done. Measured directly (2026-07-19) it rises exactly ONCE for a
    #    key and then stays flat for the whole window while the memo keeps
    #    declining every GET -- so "skips stopped rising" means "the first skip
    #    happened", not "the memo died". Existing assertions on it are all `>= 1`
    #    liveness checks, which is why the flatness never surfaced before.
    #
    # 2. Redis CONNECTION count cannot see it either: with the memo working a
    #    request does 0 GETs + 1 write-through SET, and with the memo dead it does
    #    1 GET + 0 SETs. Both are exactly one connection on a keepalive-less
    #    location, so the metric is blind to the thing under test.
    #
    # MONITOR is the instrument that distinguishes them -- the same reason the
    # keepalive tests use it: a wire-level negative that a state query cannot show.
    with redis.start_monitor() as mon:
        t_start = time.time()
        t_end = t_start + 5.0
        samples = []      # (elapsed, GET commands issued for that request)
        statuses = []
        # 0.3s pacing: ~17 requests over 5s, enough samples to locate the memo's
        # death inside a 3s window. The key never stores (uncacheable origin
        # response), so request count is not bounded by min_uses here.
        while time.time() < t_end:
            mon.checkpoint()
            _s, _b, hdrs = fetch(ng.port, uri)
            time.sleep(0.3)   # let the request's L2 ops reach the wire
            samples.append((time.time() - t_start,
                            mon.commands_seen().count("GET")))
            statuses.append((hdrs.get("x-cache") or hdrs.get("X-Cache") or "-"))

    # ⚠ GUARD: prove the burst stayed on the path under test before reading
    # anything into its L2 traffic. If the key gets STORED mid-burst, every later
    # request is a plain L1 HIT that issues no L2 GET -- which is indistinguishable
    # from "the memo is alive" by GET count alone, and would make this test pass
    # for entirely the wrong reason. That is exactly what happened on the original
    # /l2neg/ location (min_uses 4 < burst length); see the location comment.
    assert "HIT" not in statuses, (
        f"the key was CACHED during the burst (X-Cache sequence: {statuses}) -- "
        "later requests never reached the L2 path, so the GET counts below say "
        "nothing about the memo. Raise min_uses on this location above the "
        "request count.")

    # While the memo is live the module issues NO GET; once it expires, GETs
    # resume. The last silent sample marks the memo's death.
    quiet = [t for t, n in samples if n == 0]
    talked = [t for t, n in samples if n > 0]
    memo_lifetime = max(quiet) if quiet else 0.0

    assert quiet, (
        f"every request in the burst issued an L2 GET ({samples}) -- the memo "
        "never suppressed a single GET, so it is not working at all")

    # It must have lived a MEANINGFUL fraction of its 3s window, not ~1 request.
    # This is the direct regression test for the memo-lifetime defect: before the
    # L13-fix the memo covered about ONE request (~0.2s) instead of ~3s.
    assert memo_lifetime > 1.5, (
        f"the memo stopped suppressing L2 GETs after only {memo_lifetime:.1f}s of a "
        f"3s window (per-request GET counts: {samples}) -- it is being destroyed "
        "or masked early, so the feature is largely a no-op (CodeRabbit CR-A / "
        "Codex #4 on PR #77)")

    # ...and it must actually DIE inside the burst. A build that re-arms from
    # memoed misses slides l2_neg_until forward on every request, so L2 stays
    # switched off for a hot-but-absent key indefinitely. Detection has to happen
    # DURING the burst: once traffic stops, even a slid window lapses within one
    # TTL and a "sleep then check" ending would pass on both builds. This is the
    # assertion that finally makes the !l2_neg_skipped re-arm guard testable -- it
    # was impossible while the memo only survived ~1 request.
    assert talked, (
        f"no request in a 5s burst issued an L2 GET (per-request GET counts: "
        f"{samples}) -- the 3s memo never expired, so l2_neg_until is sliding "
        "forward on memoed misses and L2 is effectively disabled for this key "
        "(the !l2_neg_skipped re-arm guard is not working)")

    time.sleep(3.5)
    skips1 = _admin_l2_neg_skips(ng, "/_cache_l2neglife")
    before = _redis_conns_received(redis)
    s, _, _ = fetch(ng.port, uri)
    assert s == 200, f"post-expiry status {s}"
    time.sleep(0.4)
    # _redis_conns_received() opens its OWN redis-cli connection, counted in
    # Redis' total_connections_received. The `before` probe's connection cancels
    # (it is in both reads); THIS probe's does not, so it inflates the delta by
    # exactly 1. Subtract it -- otherwise `>= 1` can never fail even when nginx
    # opened ZERO L2 connections, i.e. the "memo never expires, L2 stays off"
    # bug this is meant to catch ([[feedback-negative-control-or-it-isnt-a-test]]).
    nginx_l2_conns = _redis_conns_received(redis) - before - 1

    assert nginx_l2_conns >= 1, \
        (f"after the memo expired the request opened {nginx_l2_conns} Redis "
         "connections -- the memo is not expiring, so L2 is effectively disabled "
         "for this key")
    assert _admin_l2_neg_skips(ng, "/_cache_l2neglife") - skips1 == 0, \
        ("an expired memo must not count as a skip"
         "\n  NOTE l2_neg_skips is per-zone and /l2neglife/ has a PRIVATE zone"
         " (l2neglifez, s128), read here via /_cache_l2neglife. It is the only"
         " location that can WRITE that counter, so a non-zero delta is this"
         " uri's own memo -- it cannot be a sibling memo test bleeding into the"
         " window, which is what this assertion used to fail on while"
         " /l2neglife/ and /l2negmu/ both sat in `main`."
         f"\n  recently skipped keys: {_recent_memo_skips(ng, limit=8)}"
         "\n  ⚠ That key list is tailed from the WHOLE error.log, not this"
         " assertion's window, so an unrelated uri in it may predate the test"
         " entirely -- a hint, not evidence. Re-run with TEST_CT_ERRLOG=debug.")


def test_l2_negative_ttl_with_min_uses(ng: Nginx, origin: Origin,
                                       redis: RedisServer) -> None:
    """L13: the memo and min_uses share ONE counter node, so they must not
    clobber each other.

    /l2negmu/ sets min_uses 3 plus a 3s memo. Both requests below stay BELOW the
    threshold, so each one both counts a min_uses skip and (after the first)
    consults the memo -- the two features writing to the same node on the same
    request, which is the state that would break if l2_neg_set overwrote
    miss_count or count_miss reset l2_neg_until.

    The threshold must exceed the request count: with min_uses 2 the second
    request PASSES the gate and stores, so it legitimately records no skip and
    the interaction never gets exercised."""
    uri = f"/l2negmu/shared-node-{time.time()}"

    fetch(ng.port, uri)                   # miss 1: arms memo, counts 1
    time.sleep(0.4)

    skips0 = _admin_l2_neg_skips(ng, "/_cache_l2negmu")
    mu0 = _admin_min_uses_skips(ng, "/_cache_l2negmu")

    s, _, _ = fetch(ng.port, uri)         # miss 2 within the window
    assert s == 200, f"req2 status {s}"

    assert _admin_l2_neg_skips(ng, "/_cache_l2negmu") - skips0 >= 1, \
        "the memo stopped working once min_uses shared the node"
    assert _admin_min_uses_skips(ng, "/_cache_l2negmu") - mu0 >= 1, \
        "min_uses stopped counting once the memo shared the node"


def test_l2_negative_ttl_not_armed_by_outage(ng: Nginx, origin: Origin,
                                             redis: RedisServer) -> None:
    """L13-fix (Codex #5): an L2 OUTAGE must not arm the negative memo.

    The memo asserts "L2 does not have this key". A failed round-trip does not
    establish that -- it establishes nothing. Arming on failure is fail-slow
    amplification: every failed GET arms a memo, the memos then suppress the very
    GETs that would notice L2 coming back, and the cache stays switched off for up
    to l2_negative_ttl PAST recovery.

    So: take Redis down, drive requests (each one a connect failure, formerly
    indistinguishable from a miss), bring it back, and require that the next
    request consults L2 for real. A build that memoes transport failures skips it
    instead, and l2_neg_skips rises.

    This is precisely the scenario 5/5 green CI could not see before: the suite
    never induced an L2 outage, so the defect passed every existing assertion."""
    uri = f"/l2negout/outage-{time.time()}"

    redis.stop()
    outage_start = time.monotonic()
    try:
        # Each request now fails to reach L2. Formerly every one of these armed a
        # memo asserting the key was absent.
        for _ in range(3):
            s, _, _ = fetch(ng.port, uri)
            assert s == 200, \
                f"request during L2 outage returned {s}; origin must still serve"
    finally:
        redis.start()

    # Redis is back. The next request MUST consult it -- that is how recovery is
    # noticed. Assert on the skip counter (did the memo suppress it?), not merely
    # on the status, which is 200 either way.
    skips0 = _admin_l2_neg_skips(ng, "/_cache_l2negout")
    s, _, _ = fetch(ng.port, uri)
    assert s == 200, f"post-recovery status {s}"
    elapsed = time.monotonic() - outage_start

    # ⚠ Codex MAJOR-1: delta == 0 is only EVIDENCE while a memo armed by the
    # outage would still be live. If the restart outran the memo, a build WITH
    # the arm-on-failure bug also reports 0 -- the assertion below would pass
    # for the wrong reason and this test would silently stop guarding anything.
    # /l2negout/ uses a 60s memo precisely so this cannot happen; if it ever
    # does, fail LOUDLY here rather than reporting a meaningless pass.
    assert elapsed < 30, (
        f"outage window + restart took {elapsed:.1f}s, which is close enough to "
        "/l2negout/'s 60s l2_negative_ttl that a memo armed by the outage could "
        "have expired on its own. The delta assertion below would then pass even "
        "with the bug present, so this run proves nothing -- treat it as "
        "INCONCLUSIVE and raise the memo, do not relax the check.")

    delta = _admin_l2_neg_skips(ng, "/_cache_l2negout") - skips0
    assert delta == 0, (
        "an L2 outage armed the negative memo: the post-recovery request was "
        "memo-skipped instead of re-consulting L2, so a transient outage keeps L2 "
        "switched off for up to l2_negative_ttl afterwards (Codex #5)"
        f"\n  l2_neg_skips delta={delta} (expected 0), this test's uri={uri}"
        f"\n  recently skipped keys: {_recent_memo_skips(ng, limit=8)}"
        "\n  NOTE l2_neg_skips is per-zone and /l2negout/ has a PRIVATE zone"
        " (l2negoutz), read here via /_cache_l2negout. /l2negout/ is the only"
        " location that can WRITE that counter (the admin location is bound to"
        " the same zone but only reads it), so a non-zero delta is this uri's"
        " own memo and cannot be another location bleeding into the window."
        "\n  ⚠ The key list above is tailed from the WHOLE error.log, not from"
        " this assertion's window, so an unrelated uri in it may predate the"
        " test entirely -- it is a hint, not evidence. Re-run with"
        " TEST_CT_ERRLOG=debug to populate it.")


def test_min_uses_counter_survives_uncacheable(ng: Nginx, origin: Origin,
                                               redis: RedisServer) -> None:
    """L13-fix (CodeRabbit CR-B): an uncacheable response must not reset the
    min_uses counter.

    unstub() frees the leftover cold-miss stub when a winner's response turns out
    non-cacheable. A min_uses counter node has the same body-less shape as that
    stub, so a shape-based predicate freed it too -- silently discarding the
    accumulated miss_count and restarting the threshold from zero. A key that is
    requested repeatedly would then never reach min_uses and never get cached.

    /l2negmu/ sets min_uses 3. The URI contains "ccnostore", which makes the test
    origin answer `Cache-Control: no-store` -- a genuinely uncacheable response,
    so every request runs the non-cacheable winner teardown in unstub(). Then
    assert the counter still climbs: the min_uses skips must stop once the
    threshold is crossed. If the counter were being reset by that teardown, every
    request would keep skipping forever."""
    uri = f"/l2negmu/ccnostore-{time.time()}"

    # Five requests against a min_uses 3 location. In a correct build the counter
    # survives each uncacheable teardown, crosses 3, and the LAST requests record
    # no further min_uses skip. In a resetting build every request skips.
    # 0.3s between requests: each uncacheable response runs the cold-miss teardown,
    # and the next request must not race the winner's unstub(). At 0.1s this test
    # intermittently hit a still-claimed stub and parked, timing the suite out on
    # roughly one run in three.
    #
    # !! The sleep is a NUISANCE REDUCER, not the thing that makes this safe, and
    # it never was: lock_ttl on /l2negmu/ is 1s, so a 0.3s gap still lands well
    # inside the previous request's claim window by construction. Parking here is
    # REACHABLE and expected -- count_miss() returns NGX_OK (not NGX_DECLINED) when
    # it finds a live stub, precisely so claim() can turn this request into a
    # waiter (shm.c, "Proceed so the caller's claim() makes this request a
    # waiter"). No concurrency is needed to get a waiter in this serial test.
    # What keeps that park from failing the test is cache_turbo_lock_timeout 2s
    # on the location, which bounds the park strictly under fetch()'s 5s client
    # timeout. Both were 5s until 2026-07-20, which is the real source of the
    # "1 in N" red on slow CI runners -- not the sleep, and not unstub().
    skips_seen = []
    for _ in range(5):
        mu0 = _admin_min_uses_skips(ng, "/_cache_l2negmu")
        s, _, _ = fetch(ng.port, uri)
        assert s == 200, f"status {s}"
        skips_seen.append(_admin_min_uses_skips(ng, "/_cache_l2negmu") - mu0)
        time.sleep(0.3)

    assert skips_seen[0] >= 1, (
        f"first request recorded no min_uses skip ({skips_seen}) -- min_uses is "
        "not gating this location, so this test is not measuring the counter")
    assert skips_seen[-1] == 0, (
        f"min_uses skips per request across 5 requests: {skips_seen}. The counter "
        "never crossed its threshold of 3, i.e. it is being reset by the "
        "uncacheable-response teardown in unstub() (CodeRabbit CR-B on PR #77)")


def test_l2_negative_ttl_rejects_out_of_range(ng: Nginx) -> None:
    """L13: cache_turbo_l2_negative_ttl is range-checked at config time.

    Unlike min_uses/stale_mult, `0` is LEGAL here and means off (it is the
    default, and merge does not coerce it), so 0 is pinned as accepted -- if a
    later edit copies the min_uses setter wholesale it would start rejecting the
    documented way to disable the feature, and this test catches that. 61 is
    rejected because the memo has no invalidation channel: the cap is what keeps
    a typo from disabling L2 for a long window."""
    anchor = "cache_turbo_l2_negative_ttl  3;"
    assert anchor in nginx_config(
        ng.root, ng.port, ng.module, ng.origin_port, 1, ng.redis_port,
        ng.redis_auth_port, ng.redis_password, ng.redis_tls_port,
        ng.redis_tls_ca, ng.memcached_port), \
        f"test fixture missing anchor {anchor!r}"

    # in-range-check arm: parses as a number, refused by the bounds
    for bad in ("61", "3600"):
        r = _config_test_result(
            ng, lambda c, b=bad: c.replace(
                anchor, f"cache_turbo_l2_negative_ttl {b};", 1))
        assert r.returncode != 0, \
            f"cache_turbo_l2_negative_ttl {bad} was accepted by nginx -t:\n{r.stdout}"
        assert "out of range" in r.stdout, \
            f"missing/odd range diagnostic for {bad}:\n{r.stdout}"

    # parse arm: ngx_atoi has no sign handling, so a negative surfaces as a
    # "bad value" rather than reaching the bounds check. Pinned separately so a
    # later editor cannot collapse the two diagnostics into one.
    for bad in ("-1", "abc"):
        r = _config_test_result(
            ng, lambda c, b=bad: c.replace(
                anchor, f"cache_turbo_l2_negative_ttl {b};", 1))
        assert r.returncode != 0, \
            f"cache_turbo_l2_negative_ttl {bad} was accepted by nginx -t:\n{r.stdout}"
        assert "bad value" in r.stdout, \
            f"missing/odd bad-value diagnostic for {bad}:\n{r.stdout}"

    # 0 (off, the default) and both real boundaries stay legal
    for good in ("0", "1", "60"):
        r = _config_test_result(
            ng, lambda c, g=good: c.replace(
                anchor, f"cache_turbo_l2_negative_ttl {g};", 1))
        assert r.returncode == 0, \
            (f"cache_turbo_l2_negative_ttl {good} (legal) was rejected:\n{r.stdout}")


def test_keep_stale_config_parse(ng: Nginx) -> None:
    """S2.1: cache_turbo_keep_stale <off|time|forever> -- PARSER ONLY, no
    runtime read yet (that is S2.2). Cover every accept/reject arm named in
    the plan: off, a plain time, forever, an invalid token, and a duplicate
    directive in one block. The negative control for each reject case is the
    literal expected diagnostic string, not merely a nonzero exit -- nginx -t
    failing for the WRONG reason would pass a bare-returncode assertion."""
    anchor = "cache_turbo_valid 30s;"
    assert anchor in nginx_config(
        ng.root, ng.port, ng.module, ng.origin_port, 1), \
        f"test fixture missing anchor {anchor!r}"

    # accept: off (the default spelling)
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor, anchor + "\n            cache_turbo_keep_stale off;", 1))
    assert r.returncode == 0, \
        f"cache_turbo_keep_stale off was rejected:\n{r.stdout}"

    # accept: bare 0 as a synonym for off (NOT forever -- see handler comment)
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor, anchor + "\n            cache_turbo_keep_stale 0;", 1))
    assert r.returncode == 0, \
        f"cache_turbo_keep_stale 0 was rejected:\n{r.stdout}"

    # accept: a plain time value
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor, anchor + "\n            cache_turbo_keep_stale 1h;", 1))
    assert r.returncode == 0, \
        f"cache_turbo_keep_stale 1h was rejected:\n{r.stdout}"

    # accept: forever
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor, anchor + "\n            cache_turbo_keep_stale forever;",
            1))
    assert r.returncode == 0, \
        f"cache_turbo_keep_stale forever was rejected:\n{r.stdout}"

    # reject: invalid token (neither off/forever nor a parseable time)
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor, anchor + "\n            cache_turbo_keep_stale bogus;",
            1))
    assert r.returncode != 0, \
        f"cache_turbo_keep_stale bogus was accepted by nginx -t:\n{r.stdout}"
    assert "bad value" in r.stdout, \
        f"missing/odd bad-value diagnostic:\n{r.stdout}"

    # reject: duplicate directive in the same block
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor,
            anchor
            + "\n            cache_turbo_keep_stale 1h;"
              "\n            cache_turbo_keep_stale 2h;",
            1))
    assert r.returncode != 0, \
        f"duplicate cache_turbo_keep_stale was accepted:\n{r.stdout}"
    assert "is duplicate" in r.stdout, \
        f"missing duplicate diagnostic:\n{r.stdout}"

    # negative control: the pristine (unmutated) config must still pass, or
    # every reject arm above is vacuous (a config broken for an unrelated
    # reason fails all of them regardless of this directive).
    r = _config_test_result(ng, lambda c: c)
    assert r.returncode == 0, \
        f"pristine config (no mutation) failed nginx -t:\n{r.stdout}"


def test_use_stale_config_parse(ng: Nginx) -> None:
    """S4.1: cache_turbo_use_stale <off|error|timeout|http_NNN...> --
    PARSER ONLY, no runtime read yet (that is S4.2). Cover every token
    individually, a multi-token combination, off, an invalid token, and a
    duplicate directive. Each reject case asserts the literal diagnostic
    string, not just a nonzero exit, so a config broken for the wrong reason
    cannot pass as "correctly rejected"."""
    anchor = "cache_turbo_valid 30s;"
    assert anchor in nginx_config(
        ng.root, ng.port, ng.module, ng.origin_port, 1), \
        f"test fixture missing anchor {anchor!r}"

    def with_directive(cfg: str, directive: str) -> str:
        assert anchor in cfg, f"test fixture missing {anchor!r}"
        return cfg.replace(anchor, anchor + "\n            " + directive, 1)

    # accept: each individual token
    for token in ("off", "error", "timeout", "http_403", "http_404",
                  "http_429", "http_500", "http_502", "http_503",
                  "http_504"):
        r = _config_test_result(
            ng, lambda c, _t=token: with_directive(
                c, f"cache_turbo_use_stale {_t};"))
        assert r.returncode == 0, \
            f"cache_turbo_use_stale {token} was rejected:\n{r.stdout}"

    # accept: multi-token combination
    r = _config_test_result(
        ng, lambda c: with_directive(
            c, "cache_turbo_use_stale error timeout http_404 http_500;"))
    assert r.returncode == 0, \
        f"multi-token cache_turbo_use_stale was rejected:\n{r.stdout}"

    # reject: off combined with another token
    r = _config_test_result(
        ng, lambda c: with_directive(c, "cache_turbo_use_stale off http_500;"))
    assert r.returncode != 0, \
        f"cache_turbo_use_stale off + http_500 was accepted:\n{r.stdout}"
    assert "cannot be combined" in r.stdout, \
        f"missing off-combination diagnostic:\n{r.stdout}"

    # reject: invalid token
    r = _config_test_result(
        ng, lambda c: with_directive(c, "cache_turbo_use_stale bogus;"))
    assert r.returncode != 0, \
        f"cache_turbo_use_stale bogus was accepted by nginx -t:\n{r.stdout}"
    assert "invalid value" in r.stdout, \
        f"missing invalid-value diagnostic:\n{r.stdout}"

    # reject: duplicate directive in the same block
    r = _config_test_result(
        ng, lambda c: with_directive(
            c,
            "cache_turbo_use_stale http_500;"
            "\n            cache_turbo_use_stale http_502;"))
    assert r.returncode != 0, \
        f"duplicate cache_turbo_use_stale was accepted:\n{r.stdout}"
    assert "is duplicate" in r.stdout, \
        f"missing duplicate diagnostic:\n{r.stdout}"

    # accept: server-level directive inherited by a location that does not
    # override it, and a location-level override alongside it. This is the
    # only part of the create/merge path observable from a config test.
    r = _config_test_result(
        ng, lambda c: with_directive(c, "cache_turbo_use_stale http_404;"))
    assert r.returncode == 0, \
        f"server-scope cache_turbo_use_stale was rejected:\n{r.stdout}"

    # reject: tokens are matched by exact bytes, so a case variant is not a
    # silently-accepted synonym.
    for bad in ("HTTP_500", "Off", "Error"):
        r = _config_test_result(
            ng, lambda c, _b=bad: with_directive(
                c, f"cache_turbo_use_stale {_b};"))
        assert r.returncode != 0, \
            f"cache_turbo_use_stale {bad} was accepted (case folding?):\n{r.stdout}"
        assert "invalid value" in r.stdout, \
            f"missing invalid-value diagnostic for {bad}:\n{r.stdout}"

    # negative control: the pristine (unmutated) config must still pass, or
    # every reject arm above is vacuous.
    r = _config_test_result(ng, lambda c: c)
    assert r.returncode == 0, \
        f"pristine config (no mutation) failed nginx -t:\n{r.stdout}"

    # ⚠ KNOWN COVERAGE GAP -- do not read this test as validating the mask.
    # Nothing reads clcf->use_stale yet (that is S4.2), so no config test can
    # observe the VALUE any token produces. These arms prove only that the
    # grammar accepts/rejects the right strings. Mutations that survive this
    # test unchanged: mapping every token to the same bit, swapping two token
    # bits, dropping ANY_5XX from USE_STALE_DEFAULT, or breaking the
    # UNSET-vs-0 merge. Those invariants become observable only once S4.2
    # gives the mask a behavioural effect, and the S4.2 tests -- not these --
    # are what must pin them down. See the S4.1 entry in issues.md.


def test_lru_eviction(ng: Nginx) -> None:
    """R6: with a tiny zone, old entries are evicted, not 500s."""
    # hammer many distinct keys through the tiny zone; must all 200, no errors
    for i in range(200):
        s, _, _ = fetch(ng.port, f"/e/{i}")
        assert s == 200, f"/e/{i} returned {s}"


def test_p1_coarse_lru_splice_keeps_hot_key_resident(ng: Nginx) -> None:
    """P1: the LRU head-splice on a HIT is coarse-gated (re-splice only when
    now - last_access >= 1s) so a key hammered many times per second does not
    re-write the shared LRU list every hit. The gate must NOT let a genuinely
    hot key drift toward the eviction tail: after being hammered fast and then
    surviving a burst of cold-key eviction churn, the hot key must still be
    resident (X-CT-Status HIT), proving the coarse splice still promotes it.

    Positive assertion on $cache_turbo_status (HIT), never header-absence -- a
    vanished status header would read as a pass otherwise. Sabotage check: if
    the coarse gate wrongly skipped ALL splices, the hot key would age to the
    LRU tail and the post-churn fetch would MISS."""
    import time
    hot = "/e/p1-hot"

    # Prime the hot key, then hammer it fast so almost every hit lands inside the
    # same 1s window and exercises the coarse-splice SKIP path (the whole point
    # of P1 -- these hits must NOT re-splice the LRU list).
    s, _, _ = fetch(ng.port, hot)
    assert s == 200, f"prime {hot} -> {s}"
    for _ in range(300):
        s, _, _ = fetch(ng.port, hot)
        assert s == 200, f"hot hammer {hot} -> {s}"

    # Cold-key churn in waves, each wave preceded by a real >1s gap then a hot
    # touch. The sleep is load-bearing: the coarse gate splices only when
    # now - last_access >= 1, and a new node starts at last_access = now, so
    # WITHOUT the gap fast-loopback re-touches would fall in the same time_t
    # second, skip every promotion, and the test could pass without ever
    # exercising the splice. With the gap each hot touch genuinely re-promotes.
    # /e/ is a tiny zone (R6: eviction at ~200 keys); each wave overflows it.
    for wave in range(3):
        time.sleep(1.2)                  # cross a 1s boundary -> splice fires
        s, _, _ = fetch(ng.port, hot)    # re-promote to LRU head
        assert s == 200, f"hot re-touch {hot} -> {s}"
        for i in range(250):
            fetch(ng.port, f"/e/p1-cold-{wave}-{i}")

    # The hot key was re-promoted before each eviction wave, so a correct coarse
    # splice kept it RESIDENT. The property under test is non-eviction, so both
    # HIT (still fresh) and STALE (present-but-expired; the many cold fetches +
    # 1.2s sleeps can push total runtime past /e/'s 30s valid window) prove the
    # node survived. A broken gate that skipped ALL splices would have aged it to
    # the LRU tail and evicted it -> the re-fetch would MISS (cold origin fill).
    s, _, h = fetch(ng.port, hot)
    assert s == 200, f"post-churn {hot} -> {s}"
    assert h.get("x-ct-status") in ("HIT", "STALE"), (
        f"hot key evicted despite promotion: X-CT-Status={h.get('x-ct-status')}")


def _s8_scan(ng: Nginx, prefix: str, tag: str, n: int = 400) -> None:
    """Walk n unique keys once each -- a crawler. Every one is a one-hit
    wonder, so under a segmented LRU they all stay in probation and can only
    evict each other."""
    for i in range(n):
        fetch(ng.port, f"{prefix}scan-{tag}-{i}")


def _s8_hot_status(ng: Nginx, prefix: str, tag: str) -> str:
    """Prime a hot key so it is PROTECTED-eligible, run a scan, then report the
    hot key's status. Promotion needs a SECOND hit, and the P1 coarse gate only
    splices when now - last_access >= 1s, so the two priming hits straddle a
    real 1s boundary. Without that sleep the second hit is swallowed by the
    gate, the node never promotes, and the test would measure nothing."""
    import time
    hot = f"{prefix}hot-{tag}"

    s, _, _ = fetch(ng.port, hot)                 # store (probation)
    assert s == 200, f"prime {hot} -> {s}"
    time.sleep(1.2)
    s, _, h = fetch(ng.port, hot)                 # 1st touch
    assert s == 200, f"touch1 {hot} -> {s}"
    assert h.get("x-ct-status") == "HIT", (
        f"priming touch1 should HIT: {h.get('x-ct-status')}")
    time.sleep(1.2)
    s, _, h = fetch(ng.port, hot)                 # 2nd touch -> PROMOTES
    assert s == 200, f"touch2 {hot} -> {s}"
    assert h.get("x-ct-status") == "HIT", (
        f"priming touch2 should HIT: {h.get('x-ct-status')}")

    _s8_scan(ng, prefix, tag)

    s, _, h = fetch(ng.port, hot)
    assert s == 200, f"post-scan {hot} -> {s}"
    return h.get("x-ct-status", "")


def test_s8_scan_resistant_keeps_hot_key(ng: Nginx) -> None:
    """S8 test 1 -- THE ACTUAL FIX. With cache_turbo_scan_resistant on, a key
    that was hit twice is PROTECTED, so a crawler walking a large unique
    keyspace through a small zone cannot evict it: every scan key is a one-hit
    wonder that never leaves PROBATION, and evict_one() takes probation tails
    first.

    Positive assertion on $cache_turbo_status (HIT), never header-absence.

    NEGATIVE CONTROL (verified by hand, see the PR body): with evict_one()
    reverted to the flat `ngx_queue_last(&z->sh->lru)` this assertion fails --
    the hot key is evicted by the scan and comes back MISS."""
    st = _s8_hot_status(ng, "/sr/", "on")
    assert st == "HIT", (
        f"S8: scan evicted the protected hot key (X-CT-Status={st}); "
        "promote-on-second-hit or the probation-first victim pick is broken")


def test_s8_default_off_is_unchanged(ng: Nginx) -> None:
    """S8 test 2 -- OFF BY DEFAULT, and off means genuinely unchanged.

    Same location shape, same zone size, same traffic, directive ABSENT. The
    flat LRU has no notion of protection, so the scan walks the hot key out of
    the zone exactly as it did before S8 and the post-scan fetch MISSes.

    This is the off-by-default regression guard: if a future edit ever makes
    segmentation apply unconditionally, this test flips to HIT and fails. It is
    also the inverse arm of test 1 -- the two together show the behavioural
    difference is caused by the directive and by nothing else, since the only
    difference between /sr/ and /sroff/ is that one line of config."""
    st = _s8_hot_status(ng, "/sroff/", "off")
    assert st == "MISS", (
        f"S8: default-off behaviour CHANGED (X-CT-Status={st}, expected MISS). "
        "Scan resistance must not apply unless cache_turbo_scan_resistant is on")


def test_s8_explicit_off_matches_absent(ng: Nginx) -> None:
    """S8: `cache_turbo_scan_resistant off` must be identical to omitting it --
    not merely accepted by the parser. Pins that `off` stores 0 rather than
    falling through to the default-on-when-present trap."""
    st = _s8_hot_status(ng, "/srexpoff/", "expoff")
    assert st == "MISS", (
        f"S8: explicit `off` did not match absent (X-CT-Status={st})")


def test_s8_reload_on_to_off_drains_protected(ng: Nginx) -> None:
    """S8 reload arm -- THE BUG CLASS THE SUITE COULD NOT REACH.

    Every other S8 test starts from a fresh zone, so an entry can only ever be
    PROTECTED under a config that is currently `on`. The interesting state is
    the one that only a reload can produce: a zone whose shared memory SURVIVES
    (init_zone inherits the live `sh`) being handed to a worker whose effective
    protected_pct is now 0. That is how the `on` -> `off` inherited-PROTECTED
    bug reached CI green -- it was unreachable by construction, not merely
    untested. (Found by CodeRabbit on PR #81; see lessons.md.)

    Sequence: promote a hot key to PROTECTED while `on`, reload the SAME zone to
    `off`, then touch the hot key (which must DEMOTE it to probation) and run a
    scan. With `off` genuinely restoring pre-S8 behaviour the scan walks the key
    out of the zone exactly as in test_s8_default_off_is_unchanged -> MISS.

    NEGATIVE CONTROL (required by TODO, verified by hand -- see the PR body):
    delete the `ctn->seg = ...SEG_PROBATION;` demote in
    ngx_http_cache_turbo_shm_touch_lru() (shm.c, the `protected_pct == 0` arm)
    and this test FAILS by its own assertion with X-CT-Status=HIT: the node
    stays on lru_protected across the reload and the scan cannot evict it.

    Skipped in single-process mode (`master_process off`), which has no master
    and therefore cannot reload at all -- the ASan run uses it.
    """
    if ng.single_process:
        return

    prefix, tag = "/sr/", "reload"
    hot = f"{prefix}hot-{tag}"

    # 1. Promote to PROTECTED while the directive is still `on`. Two touches,
    #    each straddling a real 1s boundary so the P1 coarse gate lets the
    #    splice through (the same priming _s8_hot_status does).
    s, _, _ = fetch(ng.port, hot)
    assert s == 200, f"prime {hot} -> {s}"
    for n in (1, 2):
        time.sleep(1.2)
        s, _, h = fetch(ng.port, hot)
        assert s == 200, f"touch{n} {hot} -> {s}"
        assert h.get("x-ct-status") == "HIT", (
            f"priming touch{n} should HIT: {h.get('x-ct-status')}")

    # 2. Prove the promotion actually took, BEFORE the reload. Without this the
    #    test could pass for the wrong reason: if priming silently failed the
    #    key would never be PROTECTED, the post-reload MISS would be trivially
    #    true, and the test would assert nothing about `off` at all.
    _s8_scan(ng, prefix, f"{tag}-pre")
    s, _, h = fetch(ng.port, hot)
    assert s == 200, f"pre-reload {hot} -> {s}"
    assert h.get("x-ct-status") == "HIT", (
        f"S8 reload: hot key was not PROTECTED before the reload "
        f"(X-CT-Status={h.get('x-ct-status')}); priming is broken, so the "
        "post-reload assertion below would prove nothing")

    try:
        # 3. The real reload: same zone, directive flipped to `off`.
        ng.reload(sr_off=True)

        # 4. Touch the surviving node under the new config. This is the demote:
        #    protected_pct is now 0, so touch_lru must move it back to
        #    probation. Straddle the 1s gate or the splice never runs.
        time.sleep(1.2)
        s, _, h = fetch(ng.port, hot)
        assert s == 200, f"post-reload touch {hot} -> {s}"
        assert h.get("x-ct-status") in ("HIT", "STALE"), (
            f"S8 reload: entry did not survive the reload at all "
            f"(X-CT-Status={h.get('x-ct-status')}); the zone was re-created "
            "rather than inherited, so this test is not measuring the "
            "inherited-state path it exists to cover")

        # 5. Now the scan must be able to evict it, exactly as it does in the
        #    never-was-on case.
        _s8_scan(ng, prefix, f"{tag}-post")
        s, _, h = fetch(ng.port, hot)
        assert s == 200, f"post-scan {hot} -> {s}"
        st = h.get("x-ct-status", "")
        assert st == "MISS", (
            f"S8 reload: `off` did not drain the inherited PROTECTED node "
            f"(X-CT-Status={st}, expected MISS). Turning scan resistance off "
            "must ACTIVELY DEMOTE nodes promoted while it was on, not merely "
            "decline to promote new ones -- the zone outlives the reload")
    finally:
        # Restore `on` for whatever runs next: the conf and the srz zone are
        # shared, and leaving the directive off would silently invert
        # test_s8_scan_resistant_keeps_hot_key if it ran after this one.
        ng.reload(sr_off=False)


def test_s8_scan_still_stores_and_evicts(ng: Nginx) -> None:
    """S8 test 4 -- the anti-hang / anti-wedge arm at the HTTP level.

    Drive far more unique keys through the scan-resistant zone than it can
    hold, so the protected segment fills, the cap demotes, and eviction must
    keep finding victims on BOTH queues. Every request must still complete with
    a 200: a zone that could not evict would fail stores (or, with the
    evict_one() hazard, wedge the worker holding the mutex and time this out).

    The C-level test pins the spin deterministically with a watchdog; this arm
    proves the same property through the real request path under real slab
    pressure, which is where a both-queues-consistency bug would actually
    surface."""
    for i in range(1500):
        s, _, _ = fetch(ng.port, f"/sr/churn-{i}")
        assert s == 200, f"/sr/churn-{i} returned {s} (store or eviction wedged)"

    # And the zone is still serving: a fresh key stores and then HITs, proving
    # eviction left the structure usable rather than merely not crashing.
    s, _, _ = fetch(ng.port, "/sr/after-churn")
    assert s == 200
    s, _, h = fetch(ng.port, "/sr/after-churn")
    assert s == 200 and h.get("x-ct-status") == "HIT", (
        f"zone unusable after churn: X-CT-Status={h.get('x-ct-status')}")


def test_perf7_zero_copy_serve_under_eviction(ng: Nginx) -> None:
    """PERF-7: a HIT serves the blob zero-copy DIRECTLY out of the shm slab
    (no per-hit copy into r->pool), holding a refcount on the buffer until the
    response drains. Hammer a working set far larger than the tiny zone in
    parallel so blobs are evicted/refreshed by one worker while other in-flight
    requests are still serving them. If the refcount is wrong (frees a buffer a
    serve still points into, or double-frees), the multi-worker ASan run trips a
    use-after-free / double-free here; the plain run still asserts no 5xx. Every
    request must succeed."""
    import random
    keys = 300                       # > what the 8m tiny zone holds (see R6)
    reqs = 4000
    for i in range(keys):            # prime, forcing continuous eviction
        fetch(ng.port, f"/e/p7-{i}")

    def hit(_: int) -> int:
        # STRESS_TIMEOUT, not the default: 4000 requests across 48 threads means
        # a descheduled worker can exceed the plain ceiling on a loaded runner
        # while the server is healthy. The assertion here is "HTTP 200", not
        # "answered within 5s".
        return fetch(ng.port, f"/e/p7-{random.randint(0, keys - 1)}",
                     timeout=STRESS_TIMEOUT)[0]

    with concurrent.futures.ThreadPoolExecutor(max_workers=48) as pool:
        codes = list(pool.map(hit, range(reqs)))
    bad = sorted({c for c in codes if c != 200})
    assert not bad, f"non-200 under serve/eviction churn: {bad}"


def test_shm_refresh_under_pressure(ng: Nginx) -> None:
    """R6b: refresh-store races with eviction under concurrency. The /shmref/
    location uses a tiny zone (8m) with a 1s fresh window + aggressive beta +
    background_update, so a working set far larger than the zone is
    CONTINUOUSLY going stale and refreshing (SWR store back into the shm slab)
    while OTHER entries are being evicted to make room. This overlaps the
    slab alloc/free/evict path with the refresh-store path -- the combination
    that neither the eviction-only test (/e/, valid 30s, never stale) nor the
    serve-under-eviction test (PERF-7, valid 30s, never refreshes) exercises.

    The high-value assertion is delivered by the sanitizer CI run (the asan job
    runs the full suite): a UAF / double-free / heap-overflow in store-under-
    eviction trips ASan/UBSan and aborts the worker, which this test observes as
    a 5xx or a dead server. The plain run asserts liveness + no corruption.

    NOT timing-fragile: it does not assert an exact regeneration count (the
    dice is ngx_time()-driven at 1s granularity and per-worker, so an exact
    count would flake under slow/sanitized runs). It asserts (a) every request
    succeeds, (b) the server is still alive and serving afterwards, and (c) the
    refresh machinery actually engaged at least once (refreshes counter > 0),
    so a run where nothing ever went stale -- which would silently cover
    nothing -- fails loudly instead of passing vacuously."""
    import json
    import random

    # A small HOT set stays resident in the zone across the 1s fresh window, so a
    # re-request after expiry lands on a stale-but-present entry and drives the
    # refresh-store path (which increments `refreshes` only for a stale HIT that
    # wins the dice -- an entry EVICTED before re-hit never refreshes, so a large
    # working set alone covers nothing). Interleaved COLD keys create the
    # concurrent slab eviction pressure, so refresh-store races with eviction --
    # the combination /e/ (never stale) and PERF-7 (never refreshes) miss.
    # Hot set is re-touched every wave so it stays MRU and survives eviction (it
    # must persist to go stale and drive refresh). The larger cold set overflows
    # the zone's ~key capacity and is evicted continuously, so slab evict runs
    # concurrently with the hot set's refresh-store. (A 16m zone holds a few
    # hundred of these small entries; R6 shows 8m evicting at ~200 keys, so cold
    # is sized well past that to guarantee churn without touching the MRU hot set.)
    hot = 40
    cold = 800                       # >> zone capacity -> continuous eviction
    reqs = 4000

    # refreshes counter baseline. Read the shmref zone's OWN admin endpoint --
    # /_cache is bound to zone "main" (cache_turbo_admin main), so it would
    # report main's counters, never shmref's, and the refresh assertion below
    # would read 0 forever regardless of what the module did.
    base = json.loads(fetch(ng.port, "/_cache_shmref")[1]).get("refreshes", 0)

    for i in range(hot):             # prime the hot set (must survive to go stale)
        s, _, _ = fetch(ng.port, f"/shmref/hot-{i}")
        assert s == 200, f"/shmref/hot-{i} prime returned {s}"

    # Sleep past fresh_until AND past the ngx_time() one-second-granularity dead
    # zone. The refresh dice threshold is elapsed/window * beta with elapsed in
    # whole seconds; at elapsed == 0 (the first ~1s after fresh_until) it is 0 and
    # the dice CANNOT fire whatever beta is (documented on test_lock_redis_outage
    # and the /atch/ churn test, which sleeps 2.7). fresh window is 2s; sleeping
    # 3.2s puts the hot set >= ~1.2s into the stale window, so elapsed >= 1s for
    # the entire hammer below and the dice fires from its first request.
    time.sleep(3.2)

    def hit(n: int) -> int:
        # ~70% hot (stale -> refresh), ~30% cold (fresh miss -> eviction churn),
        # so the refresh-store path and the slab evict path run concurrently.
        if n % 10 < 7:
            uri = f"/shmref/hot-{random.randint(0, hot - 1)}"
        else:
            uri = f"/shmref/cold-{random.randint(0, cold - 1)}"
        # STRESS_TIMEOUT, not the default -- see test_perf7_zero_copy_serve_
        # under_eviction. A slow read here is 48-thread scheduling contention,
        # not the module; the assertions are liveness + refreshes > base.
        return fetch(ng.port, uri, timeout=STRESS_TIMEOUT)[0]

    with concurrent.futures.ThreadPoolExecutor(max_workers=48) as pool:
        codes = list(pool.map(hit, range(reqs)))
    bad = sorted({c for c in codes if c != 200})
    assert not bad, f"non-200 under refresh/eviction churn: {bad}"

    # Server still alive and serving (an ASan abort in a worker would show here).
    s, body, _ = fetch(ng.port, "/_cache_shmref")
    assert s == 200, f"admin stats unreachable after churn: {s}"
    refreshes = json.loads(body).get("refreshes", 0)
    assert refreshes > base, \
        f"refresh path never engaged (refreshes {base} -> {refreshes}); " \
        "test covered no refresh-under-pressure"


def test_concurrent_hits_no_deadlock(ng: Nginx) -> None:
    """R1: many parallel HITs on one key do not serialise/deadlock."""
    fetch(ng.port, "/c/conc")                      # prime
    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(lambda _: fetch(ng.port, "/c/conc"),
                                range(500)))
    elapsed = time.time() - start
    assert all(r[0] == 200 for r in results), "some concurrent HITs failed"
    assert all(r[2].get("x-cache") == "HIT" for r in results), \
        "some concurrent reads were not HITs"
    # 500 cached HITs should be fast; serialising under a held lock would blow
    # this. Scaled by ASAN_TIME_SCALE: an ASan build is slow enough on a loaded
    # runner to make the fixed 10s band marginal even with no lock stall
    # (FLAKE-ASAN-TIMING-BAND); unscaled (factor 1.0) outside a sanitizer run.
    budget = 10 * sanitizer_time_scale()
    assert elapsed < budget, \
        f"concurrent HITs took {elapsed:.1f}s (possible lock stall, budget {budget:.1f}s)"


def test_admin_stats(ng: Nginx) -> None:
    """GET /_cache returns JSON counters that reflect observed traffic."""
    import json
    fetch(ng.port, "/c/stat1")           # miss
    fetch(ng.port, "/c/stat1")           # hit
    s, b, h = fetch(ng.port, "/_cache")
    assert s == 200, f"admin stats status {s}"
    assert "application/json" in h.get("content-type", ""), h.get("content-type")
    data = json.loads(b)
    for field in ("hits", "misses", "stale_serves", "refreshes", "evictions"):
        assert field in data, f"stats missing {field}: {data}"
    assert data["hits"] >= 1 and data["misses"] >= 1, f"counters look wrong: {data}"


def test_admin_prometheus(ng: Nginx) -> None:
    """GET /_cache?format=prometheus renders the Prometheus text exposition
    format: right content-type, HELP/TYPE lines, zone-labelled samples."""
    import re
    fetch(ng.port, "/c/prom1")           # miss
    fetch(ng.port, "/c/prom1")           # hit -> hits_total >= 1
    s, b, h = fetch(ng.port, "/_cache?format=prometheus")
    assert s == 200, f"metrics status {s}"
    ct = h.get("content-type", "")
    assert "text/plain" in ct and "0.0.4" in ct, f"bad content-type: {ct}"
    for line in ("# TYPE cache_turbo_hits_total counter",
                 "# TYPE cache_turbo_misses_total counter",
                 "# TYPE cache_turbo_stale_serves_total counter",
                 "# TYPE cache_turbo_refreshes_total counter",
                 "# TYPE cache_turbo_evictions_total counter",
                 "# TYPE cache_turbo_l2_hits_total counter",
                 "# TYPE cache_turbo_l2_misses_total counter",
                 "# TYPE cache_turbo_lock_waits_total counter",
                 "# TYPE cache_turbo_min_uses_skips_total counter",
                 "# TYPE cache_turbo_l2_neg_skips_total counter",
                 "# TYPE cache_turbo_bypasses_total counter",
                 "# TYPE cache_turbo_regen_cost_ms gauge",
                 "# TYPE cache_turbo_autotuned_beta gauge"):
        assert line in b, f"metrics missing line: {line!r}"
    m = re.search(r'cache_turbo_hits_total\{zone="main"\} (\d+)', b)
    assert m, f"no zone-labelled hits sample:\n{b[:300]}"
    assert int(m.group(1)) >= 1, "hits_total should be >= 1"


def test_admin_purge_key(ng: Nginx) -> None:
    """POST /_cache?key=<uri> drops that entry; next read is a MISS again."""
    import json
    fetch(ng.port, "/c/purgeme")                       # miss -> cached
    _, _, h = fetch(ng.port, "/c/purgeme")
    assert h.get("x-cache") == "HIT", "should be cached before purge"
    # key is the cache_turbo_key for this location, which is $uri
    s, b, _ = fetch(ng.port, "/_cache?key=/c/purgeme", method="POST")
    assert s == 200, f"purge status {s}"
    assert json.loads(b)["purged"] == 1, f"purge count: {b}"
    _, _, h2 = fetch(ng.port, "/c/purgeme")
    assert "x-cache" not in h2, "entry should be gone after purge (a MISS)"


def test_admin_all_zero_does_not_purge(ng: Nginx) -> None:
    """COR-10: only the exact ?all=1 purges; ?all=0 (a typo) must NOT destroy the
    zone — the entry stays cached."""
    fetch(ng.port, "/c/azkeep")                        # miss -> cached
    _, _, h = fetch(ng.port, "/c/azkeep")
    assert h.get("x-cache") == "HIT", "should be cached before the ?all=0 attempt"
    fetch(ng.port, "/_cache?all=0", method="POST")     # must purge nothing
    _, _, h2 = fetch(ng.port, "/c/azkeep")
    assert h2.get("x-cache") == "HIT", "?all=0 wrongly purged the entry"


def test_admin_purge_all(ng: Nginx) -> None:
    """POST /_cache?all=1 empties the zone."""
    import json
    fetch(ng.port, "/c/a1")
    fetch(ng.port, "/c/a2")
    fetch(ng.port, "/c/a3")
    s, b, _ = fetch(ng.port, "/_cache?all=1", method="POST")
    assert s == 200, f"purge-all status {s}"
    assert json.loads(b)["purged"] >= 1, f"purge-all count: {b}"
    # everything is now a miss
    _, _, h = fetch(ng.port, "/c/a1")
    assert "x-cache" not in h, "purge-all should have emptied the zone"


def test_admin_gating(ng: Nginx) -> None:
    """A deny-all admin location returns 403 (gating works)."""
    s, _, _ = fetch(ng.port, "/_cache_denied")
    assert s == 403, f"deny-all admin returned {s}, expected 403"


def test_warm_populates(ng: Nginx, origin: Origin) -> None:
    """v3-3: POST /_cache?url=<u> fires a background subrequest that hits origin
    once and stores the result, so a never-before-fetched URL is a HIT on its
    first real visit — without that visit touching the origin again."""
    import json
    uri = "/c/warm-pop"
    base = origin.hits_for("warm-pop")
    s, b, _ = fetch(ng.port, f"/_cache?url={uri}", method="POST")
    assert s == 200, f"warm status {s}"
    assert json.loads(b)["warmed"] == 1, f"warmed count: {b}"
    # the bg subrequest reaching origin is our completion signal
    assert wait_for(lambda: origin.hits_for("warm-pop") == base + 1), \
        "warm subrequest never hit the origin"
    time.sleep(0.2)                     # let the store settle after the response
    after = origin.hits_for("warm-pop")
    # first real visit must be served from the warm-populated entry
    s2, _, h2 = fetch(ng.port, uri)
    assert s2 == 200
    assert h2.get("x-cache") == "HIT", \
        f"warm did not populate the cache (X-Cache={h2.get('x-cache')})"
    assert origin.hits_for("warm-pop") == after, \
        f"GET after warm hit the origin ({origin.hits_for('warm-pop')} vs {after})"


def test_warm_multi(ng: Nginx, origin: Origin) -> None:
    """v3-3: a comma-separated ?url=a,b warms both; both HIT afterwards."""
    import json
    a, b_uri = "/c/warm-m1", "/c/warm-m2"
    base = origin.hits_for("warm-m")
    s, body, _ = fetch(ng.port, f"/_cache?url={a},{b_uri}", method="POST")
    assert s == 200, f"warm-multi status {s}"
    assert json.loads(body)["warmed"] == 2, f"warmed count: {body}"
    assert wait_for(lambda: origin.hits_for("warm-m") == base + 2), \
        "both warm subrequests never reached origin"
    time.sleep(0.2)
    after = origin.hits_for("warm-m")
    for u in (a, b_uri):
        _, _, h = fetch(ng.port, u)
        assert h.get("x-cache") == "HIT", f"{u} not warmed (X-Cache={h.get('x-cache')})"
    assert origin.hits_for("warm-m") == after, "a warmed GET still hit origin"


def test_warm_no_url(ng: Nginx) -> None:
    """v3-3: POST /_cache with no recognised arg is a 400 with a JSON error."""
    import json
    s, b, h = fetch(ng.port, "/_cache", method="POST")
    assert s == 400, f"no-arg admin POST returned {s}, expected 400"
    assert "application/json" in h.get("content-type", ""), h.get("content-type")
    assert "error" in json.loads(b), f"expected an error body, got {b!r}"


def test_warm_strips_key_cookie(ng: Nginx, origin: Origin) -> None:
    """B-S4: a warm subrequest fetches ANONYMOUSLY even when the admin POST
    carries a segment/key cookie.

    ngx_http_subrequest copies headers_in shallowly, so the warm sr inherits the
    admin request's Cookie header. On a preset location (magento here) that would
    (a) fold X-Magento-Vary into the cache key -> the warmed body lands under a
    SEGMENTED key no cookieless visitor reaches (wasted warm), and (b) forward the
    cookie upstream -> the origin returns that segment's private body. warm_one
    now strips every Cookie from the sr, so both the key and the upstream request
    are the cookieless anonymous variant.

    Negative control: without the strip, (a) makes the cookieless GET below a MISS
    (asserted HIT), and (b) leaks the cookie into the served body (asserted absent).
    """
    import json
    uri = "/mg/ckecho-warm"
    seg = {"Cookie": "X-Magento-Vary=deadbeefdeadbeefdeadbeefdeadbeef"}
    base = origin.hits_for("ckecho-warm")
    s, b, _ = fetch(ng.port, f"/_cache?url={uri}", method="POST", headers=seg)
    assert s == 200, f"warm status: {s} {b!r}"
    assert json.loads(b)["warmed"] == 1, f"warm body: {b!r}"
    assert wait_for(lambda: origin.hits_for("ckecho-warm") == base + 1), \
        "warm subrequest never reached origin"
    time.sleep(0.2)                     # let the store settle
    after = origin.hits_for("ckecho-warm")

    # (a) the cookieless anonymous lookup HITs the warmed entry -> key went anon.
    s2, body2, h2 = fetch(ng.port, uri)          # no cookie
    assert s2 == 200
    assert h2.get("x-cache") == "HIT", \
        ("warm keyed to the X-Magento-Vary segment, not the anonymous bucket a "
         f"cookieless visitor looks up (X-Cache={h2.get('x-cache')})")
    assert origin.hits_for("ckecho-warm") == after, \
        f"the anonymous GET hit origin instead of the warm entry ({origin.hits_for('ckecho-warm')} vs {after})"

    # (b) the served (warm-stored) body proves the origin saw NO cookie -> no leak.
    assert "cookie=[none]" in body2, \
        f"warm forwarded the operator cookie to origin (leak): {body2!r}"
    assert "X-Magento-Vary" not in body2, \
        f"warm leaked the segment cookie into the anonymous entry: {body2!r}"


def test_l2_write_through(ng: Nginx, origin: Origin, redis: RedisServer) -> None:
    """P4: a store writes through to L2. After caching /l2/<k>, the blob is
    present in Redis under the expected key, carries a PX TTL, and contains the
    actual response body bytes."""
    uri = "/l2/store"
    redis.cli("DEL", l2_key(uri))
    s, body, h = fetch(ng.port, uri)               # miss -> origin -> store
    assert s == 200, f"l2 store status {s}"
    assert "x-cache" not in h, "first request should be a miss"

    key = l2_key(uri)
    # write-through is async/fire-and-forget; give it a moment to land
    assert wait_for(lambda: redis.cli("EXISTS", key) == "1"), \
        f"L2 key {key} never appeared in Redis"

    pttl = int(redis.cli("PTTL", key))
    # PX applied: a positive TTL no larger than the stale window (valid*4 = 120s)
    assert 0 < pttl <= 120_000, f"unexpected PTTL {pttl}"

    strlen = int(redis.cli("STRLEN", key))
    assert strlen > len(body), f"stored blob ({strlen}B) smaller than body"

    raw = redis.cli("--no-raw", "GET", key)
    assert "gen-" in raw, f"stored blob missing response body: {raw[:80]!r}"

    # L1 still serves the hit (L2 write-through must not disturb the hot path)
    _, b2, h2 = fetch(ng.port, uri)
    assert h2.get("x-cache") == "HIT" and b2 == body, "L1 hit broken after L2 set"




def test_l2_keepalive_reuse(ng: Nginx, origin: Origin,
                            redis: RedisServer) -> None:
    """v15: the keepalive pool reuses Redis connections across L2 ops. A burst
    of distinct-URI misses opens one L2 GET + one L2 SET each. Under /l2ka/
    (keepalive=4) the pool reuses connections, so Redis accepts far fewer new
    connections than the same burst under /l2/ (no keepalive), where every op
    dials a fresh socket and closes it."""
    n = 60
    stamp = time.time()

    def burst(prefix: str) -> int:
        before = _redis_conns_received(redis)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            # 4 concurrent (<= pool cap) so reuse can dominate; unique keys so
            # every request is an L1+L2 miss (GET then write-through SET).
            list(ex.map(lambda i: fetch(ng.port, f"{prefix}ka-{stamp}-{i}"),
                        range(n)))
        # let the fire-and-forget SETs complete + pooled conns settle
        time.sleep(0.6)
        return _redis_conns_received(redis) - before

    off = burst("/l2/")      # no keepalive: ~2N fresh connections
    on = burst("/l2ka/")     # keepalive on: a small bounded number, then reuse

    assert off > n, f"no-keepalive baseline too low ({off}); expected > {n}"
    assert on * 2 < off, \
        f"keepalive did not cut Redis connection churn (on={on}, off={off})"

    # the pool keeps connections live: a subsequent op still hits + serves
    _, _, h = fetch(ng.port, f"/l2ka/ka-{stamp}-0")   # now an L1 HIT
    assert h.get("x-cache") == "HIT", "keepalive location broke the hot path"


def test_l2_keepalive_db_isolation(ng: Nginx, origin: Origin,
                                   redis: RedisServer) -> None:
    """Pooled Redis connections must not cross SELECT state. Alternate two
    locations sharing one address/pool but selecting DB 0 and DB 1; every key
    must land only in its configured database."""
    stamp = time.time_ns()

    for i in range(8):
        k0 = f"ka-db0-{stamp}-{i}"
        k1 = f"ka-db1-{stamp}-{i}"
        key0 = l2_key(k0, prefix="kais:")
        key1 = l2_key(k1, prefix="kais:")
        redis.cli("-n", "0", "DEL", key0, key1)
        redis.cli("-n", "1", "DEL", key0, key1)

        fetch(ng.port, f"/l2ka0/x?k={k0}")
        assert wait_for(
            # noqa: B023 -- late binding is safe here: wait_for consumes the
            # lambda before this iteration ends, so key0 cannot have been
            # rebound. Do not "fix" with a default arg; it would hide a real
            # deferred-closure bug if one is ever introduced below.
            lambda: redis.cli("-n", "0", "EXISTS", key0) == "1",  # noqa: B023
            timeout=4.0), f"DB 0 keepalive write missing for {k0}"
        assert redis.cli("-n", "1", "EXISTS", key0) == "0", \
            f"DB 0 key leaked into DB 1 through keepalive reuse: {k0}"

        fetch(ng.port, f"/l2ka1/x?k={k1}")
        assert wait_for(
            # noqa: B023 -- same as the DB 0 case above: consumed within the
            # iteration, so the late binding cannot observe a rebound key1.
            lambda: redis.cli("-n", "1", "EXISTS", key1) == "1",  # noqa: B023
            timeout=4.0), f"DB 1 keepalive write missing for {k1}"
        assert redis.cli("-n", "0", "EXISTS", key1) == "0", \
            f"DB 1 key leaked into DB 0 through keepalive reuse: {k1}"


def test_l2_cross_instance_fill(ng: Nginx, origin: Origin,
                                redis: RedisServer) -> None:
    """P2: an L1 miss fills from L2. A second, independent nginx with a cold L1
    but the same Redis serves the object another node cached, without hitting
    the origin again."""
    uri = "/l2/p2"
    redis.cli("DEL", l2_key(uri))

    # Instance A (the main server): cold -> origin -> writes L1 + L2
    s, body_a, ha = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in ha, "A should miss to origin first"
    assert wait_for(lambda: redis.cli("EXISTS", l2_key(uri)) == "1"), \
        "A never wrote the object to L2"
    drain_origin(origin)           # absorb any stray async bg before counting
    origin_after_a = origin.hits

    # Instance B: separate nginx, cold L1, same Redis + same origin
    b = Nginx(ng.binary, ng.module, ng.root.parent / "server-b",
              ng.port + PORT_OFFSETS["l2_cross_instance_fill_b"],
              ng.origin_port, ng.runner_raw,
              ng.single_process, ng.redis_port)
    b.write_config()
    b.config_test()
    b.start()
    try:
        s2, body_b, hb = fetch(b.port, uri)
        assert s2 == 200, f"B status {s2}"
        assert body_b == body_a, f"B body {body_b!r} != A body {body_a!r}"
        assert hb.get("x-cache") == "HIT", \
            f"B X-Cache={hb.get('x-cache')} (expected an L2-fill HIT)"
        if origin.hits != origin_after_a:
            recent = [(round(t, 2), p) for t, p in origin._paths[-15:]]
            raise AssertionError(
                f"origin was hit on the L2 fill ({origin.hits} vs "
                f"{origin_after_a}); recent origin paths: {recent}")

        # B now has it in L1 too: second read is a plain L1 HIT
        _, body_b2, hb2 = fetch(b.port, uri)
        assert hb2.get("x-cache") == "HIT" and body_b2 == body_a
        assert origin.hits == origin_after_a, "origin hit on B's L1 hit"

        time.sleep(0.2)
        b.stop()
        b.assert_clean_logs()
    finally:
        b.stop()




def test_l2_dsn_auth_db(ng: Nginx, origin: Origin,
                        redis_auth: RedisServer) -> None:
    """v5 DSN: redis://:pass@host/2 drives an AUTH + SELECT preamble, then the
    write-through SET lands in the AUTHED instance's db 2."""
    fetch(ng.port, "/l2auth/k1")                   # miss -> store via preamble
    key = l2_key("/l2auth/k1")
    assert wait_for(lambda: redis_auth.cli("-n", "2", "EXISTS", key) == "1",
                    timeout=4.0), \
        "object not in authed redis db 2 (AUTH/SELECT preamble failed?)"
    _, _, h = fetch(ng.port, "/l2auth/k1")
    assert h.get("x-cache") == "HIT", "second read should be an L1 hit"


def test_l2_keepalive_no_auth_replay(ng: Nginx, origin: Origin,
                                     redis_auth: RedisServer) -> None:
    """Deferred enhancement: prove a pooled Redis connection does NOT replay the
    AUTH/SELECT preamble on reuse (ngx_http_cache_turbo_redis.c: op->reused skips
    ngx_http_cache_turbo_redis_preamble() entirely — see redis_launch()). A
    state-inspection assertion (EXISTS/PTTL) cannot show this: the object lands
    in the right db either way, whether or not the preamble ran on every op. Only
    a wire-level trace (Redis MONITOR) tells the difference between "no replay"
    and "replayed harmlessly by hitting the same already-authed session".

    /l2authka/ pairs the v5 AUTH+SELECT DSN with a keepalive pool. A burst of
    DISTINCT-URI misses each open one L2 GET + one L2 SET; with keepalive the
    same handful of pooled connections serve the whole burst, so the preamble
    runs once per connection ACTUALLY OPENED, never once per op.

    NOTE on what is (and is not) asserted. As of the per-fingerprint pool (v16)
    this location gets its OWN keepalive bucket, sized from its OWN keepalive=4,
    independent of any other location's cap and of test execution order (each
    distinct connection profile is bucketed separately -- ka_bucket() in
    ngx_http_cache_turbo_redis.c). So the configured cap IS now honoured. We
    still assert the ORDER-INDEPENDENT property rather than a magic number,
    because it is the stronger claim and is robust to worker count: the preamble
    count does not SCALE with the op count. A pool of any size >= 1 that skips
    the preamble on reuse yields auths << n; a preamble replayed on every op
    yields auths == n exactly. That gap is the property under test, and
    `auths < n` discriminates it soundly for any cap the bucket holds."""
    stamp = time.time_ns()
    n = 20

    with redis_auth.start_monitor() as mon:
        mon.checkpoint()          # drop the monitor connection's own AUTH
        for i in range(n):
            fetch(ng.port, f"/l2authka/auth-{stamp}-{i}")
        time.sleep(0.6)           # let fire-and-forget L2 SETs land
        cmds = mon.commands_seen()

    auths = cmds.count("AUTH")
    selects = cmds.count("SELECT")
    gets = cmds.count("GET")
    sets = cmds.count("SET")

    ops = gets + sets
    assert ops >= n, \
        f"burst did not reach redis as expected (GET={gets} SET={sets}, n={n})"

    # The preamble must have run at least once: a pooled conn is only exempt
    # because SOME earlier op authenticated it. Zero AUTH would mean the monitor
    # never saw the traffic (a broken harness), not a passing module.
    assert auths > 0 and selects > 0, \
        f"no preamble seen at all (AUTH={auths} SELECT={selects}) -- the " \
        f"monitor likely missed the burst; the test proves nothing"

    # THE property: the preamble is not replayed per-op. Replay-on-every-op is
    # AUTH == SELECT == ops (one preamble per GET and per SET). Skip-on-reuse is
    # one per connection opened -- a small constant, independent of `ops`. These
    # are far apart for any pool cap >= 1, so `< ops` needs no magic number and
    # holds whatever cap the process-global pool latched (see docstring).
    assert auths < ops, \
        f"AUTH replayed on reuse: {auths} AUTH for {ops} L2 ops -- the " \
        f"preamble count scales with op count, so pooled conns are " \
        f"re-authenticating instead of reusing an authed session"
    assert selects < ops, \
        f"SELECT replayed on reuse: {selects} SELECT for {ops} L2 ops -- the " \
        f"preamble count scales with op count, so pooled conns are " \
        f"re-SELECTing instead of reusing an already-SELECTed session"

    # the pooled channel still serves correctly after the burst
    _, _, h = fetch(ng.port, f"/l2authka/auth-{stamp}-0")
    assert h.get("x-cache") == "HIT", "keepalive+auth location broke the hot path"


def test_l2_db_select(ng: Nginx, origin: Origin,
                      redis: RedisServer) -> None:
    """SELECT-only preamble (db=1, no auth): the object lands in db 1, not 0."""
    fetch(ng.port, "/l2db/k1")
    key = l2_key("/l2db/k1")
    assert wait_for(lambda: redis.cli("-n", "1", "EXISTS", key) == "1",
                    timeout=4.0), "object not written to db 1 (SELECT preamble?)"
    assert redis.cli("-n", "0", "EXISTS", key) == "0", \
        "object leaked into db 0 — SELECT did not take effect"


def test_l2_tls(ng: Nginx, origin: Origin,
                redis_tls: RedisServer) -> None:
    """rediss:// with server-cert verification against the test CA: the
    write-through SET reaches the TLS redis over an encrypted connection."""
    fetch(ng.port, "/l2tls/k1")
    key = l2_key("/l2tls/k1")
    assert wait_for(lambda: redis_tls.cli("EXISTS", key) == "1", timeout=4.0), \
        "object not in TLS redis (handshake/verify failed?)"
    _, _, h = fetch(ng.port, "/l2tls/k1")
    assert h.get("x-cache") == "HIT", "second read should be an L1 hit"
