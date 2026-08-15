"""cache-turbo runtime tests — l2 area.

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
    _backoff_skips,
    _bump_conn,
    _config_test_result,
    _errlog_window_start,
    _fetch_keepalive,
    _redis_conns_received,
)


def test_redis_param_reject_keeps_own_diagnostic(ng: Nginx) -> None:
    """MAINT-C1b regression: a REJECTED redis parameter must keep its own
    config-time diagnostic.

    cache_turbo_redis's trailing-parameter chain is split across several
    handlers that pass an unmatched name down the chain via a NOMATCH
    sentinel. If that sentinel aliases NGX_CONF_ERROR -- which nginx defines
    as (void *) -1, so a `(char *) -1` sentinel DOES alias it -- then a
    handler that owned the parameter and rejected its VALUE is misread by the
    dispatcher as "I did not match this name". The parameter then falls
    through to the last handler in the chain, whose else-branch replaces the
    specific message with the generic "invalid parameter".

    ⚠ The oracle is the ABSENCE of the generic message, not the presence of
    the specific one. Measured against a deliberately-broken build: the owning
    handler logs its diagnostic and THEN returns, so the specific message is
    still emitted; the sentinel collision merely appends a second, bogus
    "invalid parameter" line before the config test fails. A returncode check
    passes on both builds, and so does a substring check for the specific
    message -- which is exactly why the pre-existing
    test_redis_timeout_zero_rejected stayed green through this regression.
    """
    for bad, want in (
        ("timeout=0", "timeout must be > 0"),
        ("db=-1", "bad db"),
        ("keepalive=-1", "bad keepalive"),
    ):
        def mutate(cfg: str, bad: str = bad) -> str:
            marker = "cache_turbo_redis 127.0.0.1:"
            i = cfg.index(marker)
            end = cfg.index(";", i)
            return cfg[:end] + " " + bad + cfg[end:]

        r = _config_test_result(ng, mutate)
        assert r.returncode != 0, \
            f"cache_turbo_redis {bad} was ACCEPTED by nginx -t:\n{r.stdout}"
        assert want in r.stdout, (
            f"cache_turbo_redis {bad}: the owning handler's diagnostic "
            f"({want!r}) is missing entirely:\n{r.stdout}")
        assert "invalid parameter" not in r.stdout, (
            f"cache_turbo_redis {bad}: a rejected value ALSO produced the "
            f"generic \"invalid parameter\" error -- the handler's "
            f"NGX_CONF_ERROR was misread as the NOMATCH sentinel and fell "
            f"through the rest of the parameter chain:\n{r.stdout}")


def test_redis_tls_untrusted_ca_rejected(
        ng: Nginx, origin: Origin,
        redis_tls_untrusted: RedisServer) -> None:
    """AUD-TLS1: /l2tlsuntrusted/ trusts the SAME CA as /l2tls/, but this
    backend's cert is signed by a DIFFERENT CA. A working
    SSL_CTX_set_verify(PEER) must fail the handshake's chain check, so the
    fire-and-forget L2 write-through must NEVER land -- the key must stay
    absent no matter how long we wait. Before the fix, verify mode stays
    SSL_VERIFY_NONE (the ngx_ssl_trusted_certificate call only loads a store,
    it never flips the mode), the handshake succeeds anyway, and the key
    shows up -- so this assertion is exactly what should currently FAIL."""
    fetch(ng.port, "/l2tlsuntrusted/k1")
    key = l2_key("/l2tlsuntrusted/k1")
    assert not wait_for(
        lambda: redis_tls_untrusted.cli("EXISTS", key) == "1", timeout=2.0), \
        "L2 write-through reached a Redis whose cert chains to an UNTRUSTED " \
        "CA -- SSL_CTX_set_verify(PEER) is not being applied (AUD-TLS1)"


def test_redis_tls_handshake_failure_arms_backoff(
        ng: Nginx, origin: Origin,
        redis_tls_untrusted: RedisServer) -> None:
    """S231-L2-BACKOFF TLS follow-up: a TERMINAL TLS handshake failure
    (bad cert chain here; the same code path also covers wrong SNI, protocol
    mismatch, or the peer closing mid-handshake) must arm the SAME
    per-worker connect backoff a plain TCP connect() refusal arms. Before
    the fix, ngx_http_cache_turbo_redis_tls_handshake_done()'s three failure
    branches (not c->ssl->handshaked, verify-result != X509_V_OK, SNI/host
    mismatch) called op_fail() without op->clcf carrying the backoff
    context far enough for the arm to survive to op_fail() -- so every
    request kept re-dialing and re-handshaking a doomed TLS peer forever
    instead of failing fast after the first failure.

    /l2tlsbackoff/ points at redis_tls_untrusted (cert signed by a CA nginx
    does not trust for this location -- see /l2tlsuntrusted/ above), with
    connect_backoff=5000ms. Unlike /l2backoff/'s plain-TCP fixture, this
    location cannot use `cache_turbo_lock off` + a raw connection-count
    oracle to get an exact "one L2 attempt per request" delta: a MISS here
    still fires a fire-and-forget write-through SET as a SECOND, independent
    L2 op alongside the GET (measured -- a single client request produces
    TWO separate "cache_turbo: redis connect" attempts against
    redis_tls_untrusted, one per op), so raw connection counts are not a
    precise 1:1 oracle. Instead this reuses the SAME oracle
    test_redis_connect_backoff_fails_fast() uses for the plain-TCP case:
    the X-Cache-Turbo-Test-L2-Backoff header's redis fail-fast-skip counter,
    bumped exactly once per op that finds the window already armed
    (_launch()'s choke point), regardless of whether that op is the GET or
    the write-through SET -- so it stays exact no matter how many L2 ops one
    client request fans out into.

    All three requests share ONE kept-alive connection so they land on the
    same worker (per-worker backoff table -- see _fetch_keepalive's
    docstring):
      0. baseline read of the SAME global counter off a request that never
         touches this backend at all (see baseline note below).
      1. request 1 ARMS the window (the handshake failure itself) -- it must
         add exactly ZERO to the counter measured from the baseline.
      2. request 2, inside the 5s window, must fail fast: counter increases.
      3. request 3, still inside the window, must fail fast again: counter
         increases again -- proves it is not a one-shot arm.

    BASELINE NOTE: `ngx_http_cache_turbo_redis_test_backoff_skips` (the
    counter behind the X-Cache-Turbo-Test-L2-Backoff header, see its field
    comment in ngx_http_cache_turbo_module.c ~L6940 -- "process-global...
    per-worker") is a single lifetime atomic for the whole worker process,
    not a per-location or per-test value. `test_redis_connect_backoff_fails_fast`
    (this file, ~L8344) runs EARLIER in run_all() against the SAME worker
    (both tests land on worker 0 under the suite's ordinary scheduling) and
    deliberately leaves it at a nonzero value (its own n2/n3 assertions
    require 2 fail-fast skips to have landed). Reading this counter as if it
    started at 0 for THIS test is a baseline artifact of test ordering, not a
    property of the TLS arm path -- CI's own failure shows the counter at 3
    (Runtime + both ASan jobs, at this exact n1==0 assertion) after
    test_redis_connect_backoff_fails_fast's own n2/n3 sequence left it at 2,
    while a fresh-process, single-test run against this same backend
    measures n1==0 every time -- the counter genuinely starts wherever the
    process's history left it, never per-location zero. So the oracle here
    is a DELTA against a baseline captured from a request
    that provably cannot itself move this counter: /c/ is a plain L1-only
    cache_turbo location (no cache_turbo_redis backend at all), so a GET
    there cannot dial redis and cannot bump the fail-fast skip counter --
    its response's copy of the header is a pure read of "whatever this
    worker's counter already was", taken on the SAME kept-alive connection
    (same worker) as the three probes that follow. This preserves the
    original invariant under test (arming is not itself counted as a skip)
    while dropping the false assumption that the counter starts at absolute
    zero."""
    if ng.redis_port is None:
        return

    conn = http.client.HTTPConnection("127.0.0.1", ng.port, timeout=HTTP_TIMEOUT)
    try:
        s0, b0, h0 = _fetch_keepalive(conn, "/c/l2tlsbackoff-baseline")
        assert s0 == 200, f"baseline request did not reach origin: {s0} {b0}"
        n0 = _backoff_skips(h0, "TLS baseline", driver="redis")

        s1, b1, h1 = _fetch_keepalive(conn, "/l2tlsbackoff/probe-one")
        assert s1 == 200, f"request 1 (arms backoff) did not reach origin: {s1} {b1}"
        n1 = _backoff_skips(h1, "TLS request 1", driver="redis")
        assert n1 == n0, (
            f"request 1 is the TLS handshake failure that ARMS the window "
            f"-- it must not itself be counted as a fail-fast skip "
            f"(baseline={n0}, after arming={n1})")

        s2, b2, h2 = _fetch_keepalive(conn, "/l2tlsbackoff/probe-two")
        assert s2 == 200, f"request 2 (fail-fast) did not reach origin: {s2} {b2}"
        n2 = _backoff_skips(h2, "TLS request 2", driver="redis")
        assert n2 > n1, (
            f"request 2 landed inside the window armed by request 1's TLS "
            f"handshake failure, but the redis fail-fast counter did not "
            f"move ({n1} -> {n2}) -- a TLS handshake failure did not arm "
            f"the connect backoff, so this worker re-dialed and "
            f"re-handshaked a peer already known to be rejecting us")

        s3, b3, h3 = _fetch_keepalive(conn, "/l2tlsbackoff/probe-three")
        assert s3 == 200, f"request 3 (fail-fast) did not reach origin: {s3} {b3}"
        n3 = _backoff_skips(h3, "TLS request 3", driver="redis")
        assert n3 > n2, (
            f"request 3, still inside the 5s window, did not fail fast "
            f"again ({n2} -> {n3}) -- the TLS handshake-failure arm looks "
            f"like a one-shot instead of a window")
    finally:
        conn.close()


def test_redis_tls_expired_cert_rejected(
        ng: Nginx, origin: Origin,
        redis_tls_expired: RedisServer) -> None:
    """AUD-TLS1, second mode: /l2tlsexpired/ trusts the correct CA (chain
    trust is fine) but the leaf cert's own validity window is already
    expired. A working verify must still reject it via the standard OpenSSL
    time check. Same vacuous-guard failure mode as the untrusted-CA test."""
    fetch(ng.port, "/l2tlsexpired/k1")
    key = l2_key("/l2tlsexpired/k1")
    assert not wait_for(
        lambda: redis_tls_expired.cli("EXISTS", key) == "1", timeout=2.0), \
        "L2 write-through reached a Redis with an EXPIRED cert -- " \
        "verification is not actually checking anything (AUD-TLS1)"


def test_l2_tls_keepalive_reuse(ng: Nginx, origin: Origin,
                                redis_tls: RedisServer) -> None:
    """v15-2: the keepalive pool reuses TLS Redis connections across L2 ops, so
    a TLS handshake + AUTH/SELECT is paid once per pooled conn, not per op. A
    distinct-URI burst opens one L2 GET + one L2 SET each; under /l2tlska/
    (keepalive=4) Redis accepts far fewer new TLS connections than the same burst
    under /l2tls/ (no keepalive), where every op dials + handshakes a fresh
    socket. A passing TLS HIT after the burst proves the pooled (already-
    handshaked) channel still serves correctly."""
    n = 60
    stamp = time.time()

    def burst(prefix: str) -> int:
        before = _redis_conns_received(redis_tls)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            list(ex.map(lambda i: fetch(ng.port, f"{prefix}tka-{stamp}-{i}"),
                        range(n)))
        # let the fire-and-forget SETs complete + pooled conns settle
        time.sleep(0.6)
        return _redis_conns_received(redis_tls) - before

    off = burst("/l2tls/")     # no keepalive: ~2N fresh TLS connections
    on = burst("/l2tlska/")    # keepalive=4: a small bounded number, then reuse

    assert off > n, f"no-keepalive TLS baseline too low ({off}); expected > {n}"
    assert on * 2 < off, \
        f"TLS keepalive did not cut Redis connection churn (on={on}, off={off})"

    # the pool keeps the TLS channel live: a subsequent op still hits + serves
    _, _, h = fetch(ng.port, f"/l2tlska/tka-{stamp}-0")   # now an L1 HIT
    assert h.get("x-cache") == "HIT", "TLS keepalive location broke the hot path"


def test_l2_keepalive_per_profile_no_starvation(
        ng: Nginx, origin: Origin,
        redis: RedisServer, redis_tls: RedisServer) -> None:
    """v16 per-fingerprint pool: two mutually-unreusable connection profiles
    (plain /l2ka/ and TLS /l2tlska/, distinct sockaddr + tls bit) each keep their
    OWN keepalive bucket and reuse connections, neither starving the other.

    Before v16 the pool was one process-global struct with a single cap latched
    by whichever profile inited first; the loser's conns could saturate that one
    cap and shut the other profile out (documented in lessons.md: /l2tlska/ was
    deterministically starved under single-process ASan, worked around by summing
    both working sets into /l2ka/'s cap). With per-profile buckets that coupling
    is gone: each server sees its own bounded new-connection churn.

    We hammer BOTH profiles concurrently (interleaved so both are hot at once)
    and measure each Redis instance's total_connections_received independently
    (plain and TLS are separate servers on separate ports, so their counters do
    not mix). Each profile opening its working set once and then reusing means
    each counter stays well below the per-op ceiling. A starved profile would
    instead dial a fresh conn per op -> ~2N new connections on that server."""
    n = 40
    stamp = time.time_ns()

    plain_before = _redis_conns_received(redis)
    tls_before = _redis_conns_received(redis_tls)

    def hit(i: int) -> None:
        # interleave the two profiles so both pools are under load simultaneously
        if i % 2 == 0:
            fetch(ng.port, f"/l2ka/pp-{stamp}-{i}")
        else:
            fetch(ng.port, f"/l2tlska/pp-{stamp}-{i}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(hit, range(n)))
    time.sleep(0.6)   # let fire-and-forget L2 SETs + pool settle

    plain_new = _redis_conns_received(redis) - plain_before
    tls_new = _redis_conns_received(redis_tls) - tls_before

    ops_per_profile = n // 2                 # ~20 requests each -> ~2 L2 ops each

    # Each profile reuses: new conns stay a small bounded number (its own cap +
    # slack), far below one-per-op. If either were starved of pool slots it would
    # dial per op and land near ops_per_profile.
    assert 0 < plain_new < ops_per_profile, \
        f"plain profile did not keep its own pool (new conns={plain_new}, " \
        f"ops~={ops_per_profile}) -- starved by the TLS profile?"
    assert 0 < tls_new < ops_per_profile, \
        f"TLS profile did not keep its own pool (new conns={tls_new}, " \
        f"ops~={ops_per_profile}) -- starved by the plain profile?"

    # both channels still serve correctly after the concurrent load
    _, _, hp = fetch(ng.port, f"/l2ka/pp-{stamp}-0")
    assert hp.get("x-cache") == "HIT", "plain keepalive broke after mixed load"
    _, _, ht = fetch(ng.port, f"/l2tlska/pp-{stamp}-1")
    assert ht.get("x-cache") == "HIT", "TLS keepalive broke after mixed load"


def test_l2_purge_key_drops_l2(ng: Nginx, origin: Origin,
                               redis: RedisServer) -> None:
    """P6: a single-key admin purge on an L2-aware endpoint removes the entry
    from BOTH tiers, so it cannot be silently refilled from Redis."""
    uri = "/l2/purgekey"
    redis.cli("DEL", l2_key(uri))

    s, body_a, h = fetch(ng.port, uri)             # miss -> origin -> L1 + L2
    assert s == 200 and "x-cache" not in h, "prime should miss to origin"
    assert wait_for(lambda: redis.cli("EXISTS", l2_key(uri)) == "1"), \
        "write-through never reached L2"
    _, _, h2 = fetch(ng.port, uri)
    assert h2.get("x-cache") == "HIT", "should be an L1 hit before purge"

    # purge via the L2-aware admin endpoint
    s, b, _ = fetch(ng.port, f"/_cache_l2?key={uri}", method="POST")
    assert s == 200 and json.loads(b)["purged"] == 1, f"purge result: {s} {b}"

    # L2 entry must be gone (DEL fired); fire-and-forget, so allow a beat
    assert wait_for(lambda: redis.cli("EXISTS", l2_key(uri)) == "0"), \
        "admin purge did not DEL the entry from L2 (P6 regression)"

    # next read is a true miss to the origin (a NEW gen), not an L2 refill — and
    # it must NOT stall: purge clears the cross-node single-flight lock too, so the
    # cold-miss winner re-acquires the NX and goes straight to origin. Before the
    # fix a stale lock made it wait the full lock_timeout (~5s) = the V-HANG.
    origin_before = origin.hits
    t0 = time.monotonic()
    s, body_b, h3 = fetch(ng.port, uri)
    elapsed = time.monotonic() - t0
    assert s == 200 and "x-cache" not in h3, \
        f"post-purge read should miss to origin, got {h3.get('x-cache')}"
    # Scaled by ASAN_TIME_SCALE (FLAKE-ASAN-TIMING-BAND): unscaled outside a
    # sanitizer run.
    budget = 2.0 * sanitizer_time_scale()
    assert elapsed < budget, \
        f"post-purge cold miss stalled {elapsed:.1f}s (stale single-flight " \
        f"lock?, budget {budget:.1f}s)"
    assert origin.hits == origin_before + 1, "origin was not consulted after purge"
    assert body_b != body_a, "post-purge body should be a fresh generation"


def test_l2_expired_consults_l2(ng: Nginx, origin: Origin,
                                redis: RedisServer) -> None:
    """P6: once the L1 copy is fully expired (past its stale window), a read
    consults L2 before the origin. Seed L2 with a fresh blob after L1 expires
    and prove the request serves it as a HIT without hitting the origin."""
    uri = "/l2e/expired"
    redis.cli("DEL", l2_key(uri))

    fetch(ng.port, uri)                            # prime: L1 (valid=1s) + L2
    time.sleep(1.3)                                # past stale_until (stale_mult 1 -> 1s)
    # both L1 and L2 are expired now; reseed ONLY L2 with a fresh, valid blob
    seeded = b"l2-seeded\n"
    blob = make_ctb4_blob(seeded, headers={"Content-Type": "text/plain"})
    redis.set_raw(l2_key(uri), blob, 60_000)       # binary-safe raw RESP SET
    assert redis.cli("EXISTS", l2_key(uri)) == "1", "failed to seed L2"

    origin_before = origin.hits
    s, body, h = fetch(ng.port, uri)
    assert s == 200, f"expired+L2 read status {s}"
    assert h.get("x-cache") == "HIT", \
        f"expired L1 should serve from L2 as HIT, got {h.get('x-cache')}"
    assert body == seeded.decode(), f"served body {body!r} != seeded L2 blob"
    assert origin.hits == origin_before, \
        "origin was hit even though L2 held a fresh copy (P6 regression)"


def test_l2_preserves_original_freshness(ng: Nginx, origin: Origin,
                                         redis: RedisServer) -> None:
    """An L2 hit restores remaining freshness instead of resetting the location
    TTL. Seed an already-stale object with one second left in its original
    stale window: first read is STALE, then it expires and the origin is used."""
    uri = "/l2e/original-lifetime"
    key = l2_key(uri)
    redis.cli("DEL", key, lock_key(uri))
    seeded = b"l2-aged\n"
    blob = make_ctb4_blob(
        seeded, created=int(time.time()) - 2, fresh_ttl=1, stale_ttl=4)
    redis.set_raw(key, blob, 60_000)

    origin_before = origin.hits
    s, body, h = fetch(ng.port, uri)
    assert s == 200 and body == seeded.decode()
    assert h.get("x-cache") == "STALE", \
        f"aged L2 object was re-promoted as {h.get('x-cache')}, expected STALE"
    assert origin.hits == origin_before, "stale L2 hit unexpectedly used origin"

    time.sleep(2.3)
    origin_before_expired = origin.hits_for("/original-lifetime")
    s, body2, h2 = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in h2, \
        f"expired L2 object was still served as {h2.get('x-cache')}"
    assert origin.hits_for("/original-lifetime") == origin_before_expired + 1, \
        "expired L2 object did not fall through to origin"
    assert body2 != seeded.decode()


def _wire_response(port: int, path: str) -> tuple[bytes, bytes]:
    """Read one response off the socket with no parsing client in between.
    Returns (raw_head, body).

    Header injection is a WIRE defect and http.client is the wrong instrument
    for it: it normalises the header block, and a value an attacker split into
    two lines comes back through .getheaders() looking exactly like a header the
    module chose to emit. The raw bytes are the only place the difference is
    visible."""
    _bump_conn()
    s = socket.create_connection(("127.0.0.1", port), timeout=HTTP_TIMEOUT)
    try:
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                  f"Connection: close\r\n\r\n".encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            rest += chunk
        return head, rest
    finally:
        s.close()


def test_l2_forged_blob_cannot_inject_headers(ng: Nginx, origin: Origin,
                                              redis: RedisServer) -> None:
    """AUD-BLOBE2E1: the AUD-HDR1 restore-side header gate is mutation-proven at
    the UNIT layer (ci/fuzz/fuzz_blob.c -DCT_BLOB_FIXTURES drives
    header_admissible()/blob_validate() directly). What that cannot show is the
    WIRING -- that restore_response() consults the gate on the LIVE serve path.

    Seed L2 with a blob carrying all four AUD-HDR1 primitives at once, then read
    it twice: the first read is the L2-fill serve, the second is the L1 HIT
    promoted from it. Both must be clean. Nothing here reimplements the gate;
    the assertions are on the bytes the client actually receives."""
    uri = "/l2e/forged-headers"
    key = l2_key(uri)
    redis.cli("DEL", key, lock_key(uri))

    seeded = b"forged-l2-body\n"
    blob = make_ctb4_blob(seeded, headers={
        # benign, and the POSITIVE CONTROL: it must SURVIVE. Without it a gate
        # that dropped every stored header -- or a serve that quietly fell
        # through to the origin -- would satisfy every assertion below.
        "Content-Type":       "text/plain",
        # 1. CR/LF in a value -> response splitting.
        "X-Split":            "ok\r\nInjected: yes",
        # 2. a header NAME that is not a token and carries its own CRLF.
        "X-Bad\r\nEvil:":     "1",
        # 3. Transfer-Encoding -> smuggling against a downstream proxy/CDN.
        "Transfer-Encoding":  "chunked",
        # 4. Set-Cookie -> session fixation from a poisoned cache entry.
        "Set-Cookie":         "sess=attacker",
    })
    redis.set_raw(key, blob, 60_000)
    assert redis.cli("EXISTS", key) == "1", "failed to seed the forged blob"

    origin_before = origin.hits

    def assert_clean(stage: str) -> bytes:
        head, body = _wire_response(ng.port, uri)
        low = head.lower()
        assert b"injected" not in low, \
            f"{stage}: CRLF in a stored header value SPLIT into a new response " \
            f"header -- restore_response() did not consult header_admissible()" \
            f"\n{head!r}"
        assert b"evil" not in low, \
            f"{stage}: a non-token stored header name reached the wire\n{head!r}"
        assert b"\nset-cookie:" not in low, \
            f"{stage}: Set-Cookie survived restore (session fixation); it is on " \
            f"the store-side skip list and restore must mirror it\n{head!r}"
        assert b"\ntransfer-encoding:" not in low, \
            f"{stage}: Transfer-Encoding survived restore (smuggling)\n{head!r}"
        # positive control -- the response really is the restored blob
        assert b"\ncontent-type: text/plain" in low, \
            f"{stage}: benign stored header did NOT survive, so the clean " \
            f"assertions above prove nothing\n{head!r}"
        assert body == seeded, \
            f"{stage}: served body {body!r} is not the seeded blob's body"
        return low

    # 1st read: no L1 entry exists, so this is the L2-fill serve.
    first = assert_clean("L2-fill serve")
    assert b"x-cache: hit" in first, \
        "seeded L2 object was not served from L2 -- this test never reached " \
        "the restore path at all"
    assert origin.hits == origin_before, \
        "origin was consulted, so the response is not the forged blob"

    # 2nd read: served from the L1 copy the fill above promoted. Same
    # restore_response() call site (module.c:6738) -- what this second stage
    # actually pins is that L1 holds the RAW forged blob and is re-filtered on
    # every serve, rather than caching a once-sanitised copy at fill time. A
    # future "filter once on the way in" optimisation would leave the first
    # stage green and break this one.
    # NOT covered here: the SIE-snapshot restore at module.c:7093, which is a
    # genuinely separate call site and still has no e2e forged-blob test.
    second = assert_clean("L1 HIT serve")
    assert b"x-cache: hit" in second, "second read should be an L1 HIT"
    assert origin.hits == origin_before, "L1 HIT unexpectedly used the origin"


def test_l2_restore_href_array_alignment_ubsan(ng: Nginx, origin: Origin,
                                               redis: RedisServer) -> None:
    """S231-HDRWALK-VALIDATE-STRICTER regression: blob_validate()'s
    S231-PERF-HDRWALK refs array (ngx_http_cache_turbo_blob_href_t, which holds
    two `const u_char *` members) was allocated with ngx_pnalloc() -- nginx's
    UNALIGNED byte allocator -- instead of ngx_palloc(). Under UBSan this was
    caught immediately on the very first L2-fill restore carrying a header:

        ngx_http_cache_turbo_module.c:990:26: runtime error: member access
        within misaligned address ... which requires 8 byte alignment

    and the worker exited (code 1) mid-response, which is why
    test_breaker_l2_arming_site_gated_white_box (an unrelated test that merely
    happens to exercise an L2-fill restore) died with a bare
    RemoteDisconnected under the ASan/UBSan job with no other signal. This
    test pins the actual defect directly rather than relying on that
    coincidence: seed a real multi-header L2 blob, restore it (L2-fill serve,
    then the promoted L1 HIT), and require BOTH the response bytes to be
    correct AND the worker to still be alive afterward. A misaligned refs[]
    write/read either crashes the worker outright (caught by assert_clean_logs
    -> nginx exiting non-zero) or, under plain ASan without UBSan, is silently
    tolerated by x86's relaxed alignment -- so the byte-correctness assertions
    below are the fallback oracle for a non-UBSan build, and assert_clean_logs
    at suite teardown is what actually proves the worker survived.
    """
    uri = "/l2e/href-align"
    key = l2_key(uri)
    redis.cli("DEL", key, lock_key(uri))

    # Multiple headers so the refs[] array holds more than one entry -- a
    # single-entry array can land on an accidentally-aligned offset and hide
    # the bug. Values are distinct so a misaligned/garbage read is visible as
    # wrong bytes even if the worker does not outright crash.
    seeded = b"href-align-body\n"
    blob = make_ctb4_blob(seeded, headers={
        "Content-Type": "text/plain",
        "X-Align-A":    "alpha",
        "X-Align-B":    "bravo-bravo",
        "X-Align-C":    "charlie-charlie-charlie",
    })
    redis.set_raw(key, blob, 60_000)
    assert redis.cli("EXISTS", key) == "1", "failed to seed the alignment blob"

    origin_before = origin.hits

    # 1st read: L2-fill restore (the call site that allocates refs[] via
    # blob_validate(..., r->pool, &refs)).
    s1, body1, h1 = fetch(ng.port, uri)
    assert s1 == 200, f"L2-fill serve: status {s1}"
    assert h1.get("x-cache") == "HIT", \
        f"L2-fill serve: expected HIT from the seeded L2 blob, got " \
        f"x-cache={h1.get('x-cache')!r} (status {s1})"
    assert body1 == seeded.decode(), \
        f"L2-fill serve: body corrupted -- {body1!r} != {seeded!r}"
    assert h1.get("x-align-a") == "alpha", \
        f"L2-fill serve: X-Align-A corrupted: {h1.get('x-align-a')!r}"
    assert h1.get("x-align-b") == "bravo-bravo", \
        f"L2-fill serve: X-Align-B corrupted: {h1.get('x-align-b')!r}"
    assert h1.get("x-align-c") == "charlie-charlie-charlie", \
        f"L2-fill serve: X-Align-C corrupted: {h1.get('x-align-c')!r}"
    assert origin.hits == origin_before, \
        "origin was consulted; response is not the seeded L2 blob"

    # 2nd read: L1 HIT promoted from the fill above -- same restore_response()
    # call site, second walk of the same refs-array allocation path.
    s2, body2, h2 = fetch(ng.port, uri)
    assert s2 == 200 and h2.get("x-cache") == "HIT", \
        f"L1 HIT serve: status {s2}, x-cache={h2.get('x-cache')!r}"
    assert body2 == seeded.decode(), \
        f"L1 HIT serve: body corrupted -- {body2!r} != {seeded!r}"
    assert h2.get("x-align-a") == "alpha", \
        f"L1 HIT serve: X-Align-A corrupted: {h2.get('x-align-a')!r}"
    assert h2.get("x-align-b") == "bravo-bravo", \
        f"L1 HIT serve: X-Align-B corrupted: {h2.get('x-align-b')!r}"
    assert h2.get("x-align-c") == "charlie-charlie-charlie", \
        f"L1 HIT serve: X-Align-C corrupted: {h2.get('x-align-c')!r}"
    assert origin.hits == origin_before, "L1 HIT unexpectedly used the origin"


def test_sie_forged_blob_cannot_inject_headers(ng: Nginx, origin: Origin,
                                               redis: RedisServer) -> None:
    """AUD-SIEBLOB1: test_l2_forged_blob_cannot_inject_headers pins the L2-fill
    and L1-HIT serve paths, both of which call
    ngx_http_cache_turbo_restore_response() from module.c:6738. There is a
    SECOND, genuinely separate call site at module.c:7093
    (ngx_http_cache_turbo_sie_rewrite(), the stale-if-error snapshot replay
    that fires when a fully-expired entry's origin revalidation returns a
    5xx) that was never driven with a forged blob -- so the header-admissible
    gate's wiring on THAT path was unproven at runtime.

    Seed L2 directly with a blob that is already past its serveable window
    (rem_stale <= 0) but still inside its stale-if-error window (RFC-2 CTB4
    sie_ttl), carrying the same AUD-HDR1 forged-header primitives as the L2
    test. With no L1 entry present, a read consults L2, finds the object
    EXPIRED, arms ctx->sie_snap from the L2 blob (the L2-arm branch, not the
    L1 one), and falls through to the origin -- which is forced to answer
    5xx, driving ngx_http_cache_turbo_sie_rewrite() -> restore_response()
    over the forged snapshot. Assertions are on the RAW WIRE BYTES, exactly
    like the L2 test."""
    uri = "/l2e/forged-sie-headers"
    key = l2_key(uri)
    redis.cli("DEL", key, lock_key(uri))

    seeded = b"forged-sie-body\n"
    now = int(time.time())
    blob = make_ctb4_blob(
        seeded,
        headers={
            # benign positive control -- must SURVIVE, see the L2 test for why.
            "Content-Type":       "text/plain",
            # 1. CR/LF in a value -> response splitting.
            "X-Split":            "ok\r\nInjected: yes",
            # 2. a header NAME that is not a token and carries its own CRLF.
            "X-Bad\r\nEvil:":     "1",
            # 3. Transfer-Encoding -> smuggling against a downstream proxy/CDN.
            "Transfer-Encoding":  "chunked",
            # 4. Set-Cookie -> session fixation from a poisoned cache entry.
            "Set-Cookie":         "sess=attacker",
        },
        # created far enough in the past that the object is already outside
        # its serveable window (rem_stale = stale_ttl - age <= 0)...
        created=now - 100,
        fresh_ttl=1,
        stale_ttl=10,
        # ...but sie_ttl still covers "now": now < created + sie_ttl.
        sie_ttl=300,
    )
    redis.set_raw(key, blob, 60_000)
    assert redis.cli("EXISTS", key) == "1", "failed to seed the forged SIE blob"

    origin_before = origin.hits_for("forged-sie-headers")
    origin.fail = True
    try:
        head, body = _wire_response(ng.port, uri)
        low = head.lower()
        assert b"injected" not in low, \
            f"SIE replay: CRLF in a stored header value SPLIT into a new " \
            f"response header -- ngx_http_cache_turbo_sie_rewrite() did not " \
            f"consult header_admissible() on the SIE snapshot path\n{head!r}"
        assert b"evil" not in low, \
            f"SIE replay: a non-token stored header name reached the wire " \
            f"on the SIE snapshot path\n{head!r}"
        assert b"\nset-cookie:" not in low, \
            f"SIE replay: Set-Cookie survived the SIE snapshot restore " \
            f"(session fixation)\n{head!r}"
        assert b"\ntransfer-encoding:" not in low, \
            f"SIE replay: Transfer-Encoding survived the SIE snapshot " \
            f"restore (smuggling)\n{head!r}"
        # positive control -- a truncated/short read cannot vacuously satisfy
        # the assertions above.
        assert b"\ncontent-type: text/plain" in low, \
            f"SIE replay: benign stored header did NOT survive, so the " \
            f"clean assertions above prove nothing\n{head!r}"
        assert b"x-cache: stale-if-error" in low, \
            "seeded blob was not replayed via the SIE snapshot path -- this " \
            f"test never reached ngx_http_cache_turbo_sie_rewrite() at all\n{head!r}"
        assert body == seeded, \
            f"SIE replay: served body {body!r} is not the seeded blob's body"
        assert origin.hits_for("forged-sie-headers") == origin_before + 1, \
            "the failing-origin revalidation was not actually consulted -- " \
            "this test would pass even without a real SIE rewrite"
    finally:
        origin.fail = False
        drain_origin(origin)


def test_l2_malformed_blob_rejected(ng: Nginx, origin: Origin,
                                    redis: RedisServer) -> None:
    """STAB-4: a malformed L2 blob must be fully validated and REJECTED before it
    is inserted into L1 (the old code stored first and only failed in serve(),
    poisoning the L1 slot). Each bad blob => a clean MISS to origin, a real body,
    and a subsequent request that is a legitimate HIT (no poisoned L1, no crash).
    The origin serves a dynamic gen-<n> body."""
    cases = {
        "wrong-magic":   make_ctb4_blob(b"x", magic=0x43544232),     # CTB2
        "wrong-version": make_ctb4_blob(b"x", version=2),
        # CTB3 (prior wire format): a stale on-disk blob from the pre-RFC-2 build
        # must miss-to-origin once (self-heal), not be parsed at a shifted layout.
        "old-ctb3":      make_ctb4_blob(b"x", magic=0x43544233, version=3),
        # valid magic+version but headers_len lies past the buffer end
        "hdrlen-overflow": (
            struct.pack("<IHHIIIIqIII", 0x43544234, 4, 0, 200, 1,
                        0xFFFF, 1, int(time.time()), 60, 240, 0) + b"\x01"),
        # body_len lies past the buffer end
        "bodylen-overflow": (
            struct.pack("<IHHIIIIqIII", 0x43544234, 4, 0, 200, 0,
                        0, 0xFFFF, int(time.time()), 60, 240, 0)),
    }

    for name, blob in cases.items():
        uri = f"/l2/bad-{name}"
        key = l2_key(uri)
        redis.cli("DEL", key, lock_key(uri))
        redis.set_raw(key, blob, 60_000)

        before = origin.hits_for("/bad-")
        s, body, h = fetch(ng.port, uri)
        assert s == 200, f"{name}: status {s}"
        assert body.startswith("gen-"), \
            f"{name}: served garbage body {body!r} from a malformed L2 blob"
        assert "x-cache" not in h, \
            f"{name}: malformed blob served as {h.get('x-cache')} (not a miss)"
        assert origin.hits_for("/bad-") == before + 1, \
            f"{name}: malformed blob did not fall through to origin"

        # Second read must succeed AND be a real HIT — the rejected blob must not
        # have poisoned L1, and the origin response is now legitimately cached.
        s2, body2, h2 = fetch(ng.port, uri)
        assert s2 == 200 and body2 == body and h2.get("x-cache") == "HIT", \
            f"{name}: L1 poisoned/uncacheable after reject (2nd read {s2}, " \
            f"x-cache={h2.get('x-cache')})"


def test_sie_ttl_stored_in_blob(ng: Nginx, origin: Origin,
                                redis: RedisServer) -> None:
    """RFC-2 (CTB4): a response Cache-Control: stale-if-error=N is recorded as an
    ABSOLUTE serve-on-error window (fresh_ttl + N) in the blob's sie_ttl field at
    wire offset 40. Origin under /siettl/ emits max-age=60, stale-if-error=30;
    cache_turbo_valid 60s (honor_cc off, so fresh_ttl is the location 60s), so the
    stored blob carries fresh_ttl=60 and sie_ttl=90. This locks the CTB4 wire
    format + the response_sie parse; the serve-on-error consumer of sie_ttl lands
    in a follow-up."""
    # proxy_pass strips the /siettl/ location prefix, so the origin marker must
    # ride the request SUFFIX (origin sees /siettl-k1, not /k1).
    uri = "/siettl/siettl-k1"
    key = l2_key(uri)
    redis.cli("DEL", key)
    fetch(ng.port, uri)                            # miss -> store L1 + L2
    assert wait_for(lambda: redis.cli("EXISTS", key) == "1"), \
        "object never written to L2"

    blob = redis.get_raw(key)
    assert blob is not None and len(blob) >= 44, f"short/absent blob: {blob!r}"
    magic, version = struct.unpack("<IH", blob[:6])
    assert magic == 0x43544234, f"blob magic {magic:#x} != CTB4 (0x43544234)"
    assert version == 4, f"blob version {version} != 4"
    fresh_ttl, stale_ttl, sie_ttl = struct.unpack("<III", blob[32:44])
    assert fresh_ttl == 60, f"fresh_ttl {fresh_ttl} != 60 (location valid)"
    assert sie_ttl == 90, f"sie_ttl {sie_ttl} != fresh_ttl+30 (90)"
    assert stale_ttl >= fresh_ttl, \
        f"stale_ttl {stale_ttl} < fresh_ttl {fresh_ttl}"

    # A response WITHOUT stale-if-error carries sie_ttl == 0 (no serve-on-error
    # window beyond the normal stale window).
    uri2 = "/l2e/no-sie"
    key2 = l2_key(uri2)
    redis.cli("DEL", key2)
    fetch(ng.port, uri2)
    assert wait_for(lambda: redis.cli("EXISTS", key2) == "1"), \
        "control object never written to L2"
    blob2 = redis.get_raw(key2)
    assert blob2 is not None and len(blob2) >= 44
    (sie_ttl2,) = struct.unpack("<I", blob2[40:44])
    assert sie_ttl2 == 0, f"sie_ttl {sie_ttl2} != 0 for a no-SIE response"


def test_l2_retain_ttl_covers_sie(ng: Nginx, origin: Origin,
                                  redis: RedisServer) -> None:
    """S1.2: the L2 key's own retention (PX) must cover max(stale_window,
    sie_window), not stale_window alone. /l2sie/ sets stale_mult=1 (stale_window
    == fresh_ttl == 1s) and origin emits stale-if-error=3600 (sie_ttl = 3601s).
    Before the fix, retain_ttl was computed as stale_ttl(fresh_ttl, stale_mult)
    -- 1s here -- so the L2 key would already be gone (or close to it) by the
    time an origin failure past 1s needs to serve it from L2, even though the
    blob's own sie_ttl field says the object should still be servable. Negative
    control: reverting the retain_ttl fix in ngx_http_cache_turbo_module.c
    (passing stale_ttl(ttl, stale_mult) again instead of max(stale_window,
    sie_window)) makes this PTTL assertion fail (~1000ms instead of >3000s)."""
    uri = "/l2sie/l2sie-k1"
    key = l2_key(uri)
    redis.cli("DEL", key)
    fetch(ng.port, uri)                            # miss -> store L1 + L2
    assert wait_for(lambda: redis.cli("EXISTS", key) == "1"), \
        "object never written to L2"

    pttl = int(redis.cli("PTTL", key))
    # sie_ttl = fresh_ttl(1) + 3600 = 3601s; allow generous slack for test
    # wall-clock but stay far above the pre-fix ~1000ms stale_window truncation.
    assert pttl > 3000_000, \
        f"L2 key PTTL {pttl}ms truncated to stale_window, not covering " \
        f"stale-if-error window (expected >3,000,000ms, i.e. close to 3601s)"


def test_l2_sie_serve_survives_l1_purge(ng: Nginx, origin: Origin,
                                        redis: RedisServer) -> None:
    """S1.2 (behavioural complement to test_l2_retain_ttl_covers_sie, which only
    asserts the Redis PTTL): prove a user actually gets served during an origin
    outage once L1 is gone. Reuses the /l2sie/ marker (max-age=1,
    cache_turbo_stale_mult 1, origin stale-if-error=3600) -- a 3600s SIE window
    is far past this test's runtime, so it also satisfies the plan's "sleep past
    the stale window; ... within stale-if-error=30" shape without a fragile 30s
    sleep budget.

    Sequence: prime L1+L2 -> sleep past the 1s stale window (L1 now expired) ->
    purge L1 ONLY via the non-L2-aware /_cache admin endpoint (zone "main" has
    no cache_turbo_redis directive, so this purge cannot reach Redis) -> the L2
    key must still exist -> origin.fail = True -> a read must still get a 200
    with X-Cache: STALE-IF-ERROR, served out of L2.

    Negative control: revert S1.2 (retain_ttl back to stale_ttl(ttl,
    stale_mult) instead of max(stale_window, sie_window)) and the L2 key is
    already gone by the time of the purge/origin-fail step -> 502."""
    import json
    uri = "/l2sie/l2sie-sie1"
    key = l2_key(uri)
    redis.cli("DEL", key)

    s0, body0, h0 = fetch(ng.port, uri)            # miss -> store L1 + L2
    assert s0 == 200 and "x-cache" not in h0, "prime should miss to origin"
    assert wait_for(lambda: redis.cli("EXISTS", key) == "1"), \
        "object never written to L2"

    time.sleep(1.3)                                # past the 1s stale window

    # L1-only purge: /_cache (zone "main") has no cache_turbo_redis directive,
    # so it cannot touch the L2 key -- only the L1 slot is dropped.
    s, b, _ = fetch(ng.port, f"/_cache?key={uri}", method="POST")
    assert s == 200 and json.loads(b)["purged"] == 1, f"L1 purge result: {s} {b}"
    assert redis.cli("EXISTS", key) == "1", \
        "L1-only purge must not have deleted the L2 key (test setup broken)"

    origin.fail = True
    try:
        s2, body2, h2 = fetch(ng.port, uri)
        assert s2 == 200, \
            f"origin down + L1 purged should still serve 200 from L2, got {s2}"
        assert h2.get("x-cache") == "STALE-IF-ERROR", \
            f"expected X-Cache: STALE-IF-ERROR from L2, got {h2.get('x-cache')}"
        assert body2 == body0, \
            f"served {body2!r}, expected the original primed body {body0!r}"
    finally:
        origin.fail = False
        drain_origin(origin)


def test_l2_stale_refetch_does_not_stall_on_lock(ng: Nginx, origin: Origin,
                                                 redis: RedisServer) -> None:
    """V-HANG-2: a request that finds an entry past its stored stale window must
    go to the origin PROMPTLY, not sit in the cold-miss wait loop until the
    cross-node NX lock expires.

    The trap: the winner takes `SET <prefix>lock:<hex> NX PX <lock_ttl*1000>`
    (default 5s) and it is released ONLY by PX expiry -- `unlock` is
    deliberately NULL (module.h), because an early unlock would re-open the
    dogpile window. That is fine as long as waiters can serve the fill. But
    /l2sie/ sets cache_turbo_stale_mult 1, so stale_window == fresh_ttl == 1s:
    ~1s after the winner stores, the object is UNSERVEABLE while its lock is
    still alive for ~4s more. Every request in that gap lost the NX, entered
    ngx_http_cache_turbo_cold_wait(), re-polled L2 every 100ms
    (LOCK_POLL_MS), got the same unserveable blob back each time, and only
    reached the origin after the full lock_timeout (default 5000ms).

    That is a ~5s user-visible stall on a healthy origin with a healthy cache.
    It also made test_l2_sie_serve_survives_l1_purge look like a flaky timeout,
    because HTTP_TIMEOUT is also 5s -- the client lost that dead heat.

    ⚠ ASSERT ON WALL-CLOCK, not just status. With the bug present this request
    still returns 200, just ~5.05s later, so a status-only assertion passes
    with the bug fully restored.

    Negative control: revert the `ctx->l2_present_unserveable` give-up in
    cold_wait (module.c) -- e.g. `if (0 && ctx->waiting && ...)` -- and the
    elapsed assertion below fails at ~5.0s while every other assertion here
    still passes."""
    uri = "/l2sie/l2sie-nostall"
    key = l2_key(uri)
    redis.cli("DEL", key)

    s0, _, _ = fetch(ng.port, uri)              # miss -> store L1 + L2, takes NX
    assert s0 == 200, f"prime should reach origin, got {s0}"
    assert wait_for(lambda: redis.cli("EXISTS", key) == "1"), \
        "object never written to L2"

    # Past the 1s stale window but well inside the 5s lock PX: the exact gap
    # where the winner's lock is still held and its object is unserveable.
    time.sleep(1.3)

    # sleep() only guarantees a LOWER bound. If the box stalls long enough for
    # the 5s lock PX to expire before the fetch below, the request no longer
    # meets a held lock and the test passes without exercising the window it
    # exists to cover. Assert the lock is still alive, with enough margin left
    # that a stall could not be mistaken for a healthy sub-2s response.
    lock_pttl = int(redis.cli("PTTL", lock_key(uri)))
    assert lock_pttl > 2000, (
        f"cross-node lock has only {lock_pttl}ms left (or is gone: -2). The "
        f"unserveable-object/held-lock window has already closed, so this run "
        f"would not exercise V-HANG-2 at all.")

    t0 = time.time()
    s1, _, _ = fetch(ng.port, uri)
    elapsed = time.time() - t0

    assert s1 == 200, f"stale refetch should serve 200 from origin, got {s1}"
    # lock_timeout defaults to 5000ms; the stall was the FULL window. A healthy
    # refetch is ~50ms here, so 2s is far above real latency and far below the
    # 5s bug -- it cannot pass with the give-up removed. Scaled by
    # ASAN_TIME_SCALE (FLAKE-ASAN-TIMING-BAND): unscaled outside a sanitizer
    # run; ASAN_TIME_SCALE is kept low enough (2.0) that the scaled budget
    # (4.0s) still stays below the 5s bug window it must distinguish from.
    budget = 2.0 * sanitizer_time_scale()
    assert elapsed < budget, (
        f"stale refetch took {elapsed:.2f}s -- it stalled in the cold-miss wait "
        f"loop waiting out the cross-node NX lock (V-HANG-2). Expected "
        f"<{budget:.1f}s; the bug parks for the full lock_timeout (~5s).")

    drain_origin(origin)


def test_l2_unserveable_giveup_still_single_flights(
        ng: Nginx, origin: Origin, redis: RedisServer) -> None:
    """V-HANG-2 guard rail: the give-up must not defeat cold-miss single-flight.

    The V-HANG-2 fix lets a cold-miss waiter stop parking once it sees the key
    PRESENT in L2 but past its stored stale window -- the fill it was waiting
    for has already landed, so further polling only burns lock_timeout.

    ⚠ That inference is valid ONLY on a cold-wait RE-POLL. The set site
    (module.c, the L2-hit-but-expired branch) fires on ANY L2 lookup, including
    the very first one. If the give-up is gated on `ctx->waiting`, it guards
    nothing: cold_wait() sets `waiting = 1` a few lines ABOVE the check, so it
    is unconditionally true on first entry too. A CLAIM_LOSER then reads the
    same expired blob on its FIRST pass -- before the winner has written
    anything -- gives up immediately, and goes straight to the origin. Every
    loser in a burst does the same, so the whole burst stampedes.

    Hence the real gate is `ctx->wait_polled`, set at the park site only after
    the timer is armed.

    ⚠ It deliberately does NOT reuse /l2sie/. That location sets
    cache_turbo_valid 1s, so a regenerated entry is stale again within the
    burst and 40 origin fetches is CORRECT behaviour there -- verified by
    running this exact burst against stock: identical counts (40 regens, 40
    lock_waits). A stampede assertion on /l2sie/ would fail on fixed and stock
    alike and prove nothing.

    /sfgu/ instead has fresh_ttl 30s with stale_mult 1, so once the primed entry
    is unserveable, any regen stays fresh for the whole burst -- every extra
    origin fetch is then a genuine single-flight failure. The entry is aged by
    rewriting the blob's `created` field (i64 at offset 24) rather than by
    sleeping 30s.

    Negative control: relax the gate back to `ctx->waiting` in cold_wait
    (module.c) and the `regens` assertion below fails, while
    test_l2_stale_refetch_does_not_stall_on_lock above still passes -- the two
    tests pin opposite edges of the same branch."""
    uri = "/sfgu/sfgu-k1"
    key = l2_key(uri)
    redis.cli("DEL", key)

    s0, _, _ = fetch(ng.port, uri)              # miss -> store L1 + L2, takes NX
    assert s0 == 200, f"prime should reach origin, got {s0}"
    assert wait_for(lambda: redis.cli("EXISTS", key) == "1"), \
        "object never written to L2"

    # Age the L2 blob past its stale window WITHOUT waiting for it: rewrite
    # `created` (i64 @24) to 60s ago. fresh_ttl is 30 and stale_mult 1 makes
    # stale_ttl 30, so the object is now PRESENT-but-UNSERVEABLE -- exactly the
    # state that arms l2_present_unserveable on the very first L2 lookup.
    blob = redis.get_raw(key)
    assert blob is not None and len(blob) >= 44, f"short/absent blob: {blob!r}"
    fresh_ttl, stale_ttl, _sie = struct.unpack("<III", blob[32:44])
    assert fresh_ttl == 30 and stale_ttl == 30, (
        f"/sfgu/ fixture drifted: fresh_ttl={fresh_ttl} stale_ttl={stale_ttl}, "
        f"expected 30/30 (valid 30s + stale_mult 1). Without stale_ttl == "
        f"fresh_ttl the aged blob is still serveable and this test is vacuous.")

    # ⚠ ORDER MATTERS. PURGE is L2-aware -- it DELETEs the Redis key too -- so
    # the L1 drop has to happen BEFORE the aged blob is written, or the setup
    # deletes the very object under test and the burst sees a plain cold miss.
    s_p, b_p, _ = fetch_raw(ng.port, uri, method="PURGE")
    assert s_p == 200, f"PURGE status {s_p}: {b_p}"
    wait_for_l2_absent(redis, key, what="PURGE of /sfgu/ before the aged write")
    aged = blob[:24] + struct.pack("<q", int(time.time()) - 60) + blob[32:]
    redis.set_raw(key, aged, 3_600_000)
    wait_for_l2(redis, key, aged, what="aged blob for /sfgu/ give-up")

    base = origin.hits
    waits0 = _admin_lock_waits(ng)

    # ⚠ PRECONDITION, not decoration. The lock_waits assert at the end of this
    # test is a LIVENESS proxy ("someone actually parked"), and it is only
    # meaningful while the winner's origin fetch is still in flight when the
    # stragglers arrive. With an INSTANT origin the winner fills L1 first, the
    # rest take CLAIM_FRESH without ever entering cold_wait(), and the delta
    # decays toward 0 -- a test-harness artefact that looks exactly like a
    # single-flight defect (SUITE-8).
    #
    # Measured on this burst, pinned to 2 cores: delay=0.05 gives a lock_waits
    # delta of 39/39/39, delay=0.0 gives 39/23/8 -- same regens==1 (the module
    # is correct either way), but the margin erodes to near-zero. CI's slower
    # single-process ASan arm is where 8 becomes 0.
    #
    # This tripped because the autotune tests upstream in run_all() borrow
    # origin.delay and used to restore it to a hardcoded 0.0 instead of the
    # suite baseline. Origin.reset_delay() now restores the real default; this
    # assert makes a regression of that fail HERE, loudly, instead of showing up
    # as a rare unexplained flake in the assertion below.
    assert origin.delay > 0, (
        f"origin.delay is {origin.delay}: an instant origin leaves no "
        f"regeneration window for the losers to park in, making the lock_waits "
        f"liveness assert below vacuous. An upstream test borrowed origin.delay "
        f"and did not restore it via origin.reset_delay().")

    # All 40 readers rendezvous at the barrier before hitting the key, so they
    # reach the cold-miss claim inside the same window. Without this the burst
    # can legitimately produce ZERO waiters: a regen here stays fresh for 30s,
    # so once the winner's fill lands in L1 every later reader takes the
    # CLAIM_FRESH path (module.c) and serves from L1 *without entering
    # cold_wait()* -- the only site that increments lock_waits. On a loaded
    # runner, thread start-up is staggered enough for the winner to finish
    # before any other thread reaches the claim, leaving regens == 1 (a correct
    # collapse) but the lock_waits delta at 0 -- failing the liveness assert
    # below for a race in the test rather than a defect in the module.
    readers = 40
    barrier = threading.Barrier(readers)

    def _burst_reader(_i: int) -> tuple[int, bytes, dict]:
        barrier.wait()
        return fetch(ng.port, uri)

    with concurrent.futures.ThreadPoolExecutor(max_workers=readers) as pool:
        results = list(pool.map(_burst_reader, range(readers)))

    assert {r[0] for r in results} == {200}, \
        f"expired-L2 burst returned {set(r[0] for r in results)}"

    # A regen here stays fresh for 30s, so after the first one every other
    # reader can be served: extra origin fetches are genuine single-flight
    # failures, not re-expiry. The give-up may still legitimately cost a few
    # (a waiter that re-polls and finds the blob unserveable regenerates), so
    # the bound is loose -- but with the gate wrongly on ctx->waiting all 40
    # bypass the wait loop and reach the origin.
    regens = origin.hits - base
    assert regens <= 5, (
        f"expired-L2 burst stampeded: {regens} origin fetches for 40 readers. "
        f"The V-HANG-2 give-up fired on the FIRST pass instead of on a re-poll, "
        f"so every cold-miss loser bypassed the wait loop.")

    # ...and it must collapse VIA the wait path, not by luck: at least one
    # request has to have actually parked. Without this the assertion above
    # could pass on a run where the requests merely serialised.
    assert _admin_lock_waits(ng) - waits0 > 0, \
        "no requests waited — single-flight did not engage on the expired-L2 burst"

    drain_origin(origin)


def _errlog_l2_promote_rc_in_window(ng: Nginx, start: int) -> list[int]:
    """AUD-L2-PROMOTE-RACE oracle: every `cache_turbo: test_l2_promote_rc=<N>`
    value logged strictly after byte offset `start`, in emission order. NGX_OK
    is 0 and NGX_DECLINED is -5 in nginx's ngx_int_t space, so this also
    accepts a leading '-'. Mirrors _errlog_sie_unconsumed_in_window's
    window-bracketing discipline exactly (see that function's docstring for
    why: attributing a debug/notice line to the wrong concurrent request is
    the failure mode this guards against)."""
    log = ng.root / "logs" / "error.log"
    try:
        with log.open("rb") as f:
            f.seek(start)
            tail = f.read()
    except OSError as exc:
        raise AssertionError(f"error.log unreadable: {exc}") from None
    text = tail.decode("utf-8", errors="replace")
    return [int(m) for m in
            re.findall(r"cache_turbo: test_l2_promote_rc=(-?\d+)", text)]


def test_l2_promote_race_never_overwrites_newer_l1_entry(
        ng: Nginx, origin: Origin, redis: RedisServer) -> None:
    """AUD-L2-PROMOTE-RACE: the L2 GET is async -- it parks the request (zone
    mutex NOT held) and resumes it when the redis reply lands. On resume, the
    pre-fix code promoted the L2 blob into L1 unconditionally, so a slow L2
    reply could overwrite a NEWER origin response that landed in L1 while the
    first request was parked. store_if(..., STORE_IF_NEWER) closes that by
    deciding "is the resident entry newer?" and writing under ONE lock hold.

    WHY NOT A PLAIN BLACK-BOX TIMING RACE: the actual window this fix closes
    is the gap between the resumed handler's own (already-unlocked) L1
    re-check and its store_if() call -- pure CPU, no I/O, no yield point in
    between (confirmed: firing a concurrent write any time before the L2
    reply arrives is simply seen by that SAME re-check on resume and short-
    circuits the promote call entirely, producing "L1 HIT (fresh)" and never
    reaching the vulnerable line -- that dead end was tried and measured
    before landing on this design). No amount of delaying the L2 GET itself
    (redis DEBUG SLEEP, a slow origin, etc.) can widen a gap with no yield
    point in it. cache_turbo_test_l2_promote_hold_ms (TEST_FAULTS-only, module.c
    ~L2-promote site) blocks the CURRENT worker for a bounded, deterministic
    window at EXACTLY that gap via a plain ngx_msleep -- it stalls only this
    worker's own event loop, so with 4 workers configured a concurrent
    request lands on a different worker and is unaffected.

    Two-part oracle, matching the item's explicit requirement to distinguish
    "declined" from "never reached": the NOTICE-level `test_l2_promote_rc=`
    line (module.c, right after the store_if() call, inside TEST_FAULTS) is
    asserted PRESENT (an absent line fails, never reads as anything) and
    equal to NGX_DECLINED. A black-box read of the final L1 body is used
    alongside it, since it is independently reachable here (unlike the
    unconsumed-buffer case _errlog_sie_unconsumed_in_window's sibling
    docstring explains): the body proves the DECLINED promote was correct
    behaviour (the newer entry, not the stale L2 blob, is what gets served),
    while the log line proves the guarded branch, specifically, is what
    produced it -- a passing body check with an absent/wrong log line would
    mean the assertion is passing for an unrelated reason and must fail.

    Sequence:
      1. Seed L2 (only) with body A by writing it through the module on a
         throwaway URI sharing /l2promo/'s config, then copying the raw blob
         bytes into THIS test's key via redis.set_raw() -- keeps the exact
         on-wire blob format (module-produced) while leaving /l2promo/x's own
         L1 slot virgin, so the very first real read of it is a guaranteed
         cold L1 miss that must consult L2.
      2. Fire the L2-bound read in the background; it parks on the L2 GET,
         resumes, and -- because /l2promo/ sets
         cache_turbo_test_l2_promote_hold_ms -- blocks its own worker for
         2000ms immediately before the promote decision.
      3. While it is held, fire the bypass read on the SAME key (never
         touches redis, reaches origin fast, stores body B into L1 via a
         plain unconditional store() -- on a different nginx worker).
      4. The held worker wakes, decides (L1 now holds B, newer than the L2
         blob) and must DECLINE the promote. A follow-up plain read must
         still see body B, never body A; the NOTICE line must read
         NGX_DECLINED.

    Skipped in single-process mode (the ASan single-process job), which runs
    `workers = 1`. Step 3 requires the concurrent bypass write to land on a
    DIFFERENT worker while this one is inside its ngx_msleep; with one worker
    that write cannot be serviced until the hold expires, by which point the
    promote has already been decided against an L1 slot that still holds
    nothing newer -- the promote is then correctly allowed and the oracle
    reads NGX_OK. That is the harness losing the race setup, not the fix
    regressing, so asserting it here would be asserting a property this
    configuration cannot express. The multi-worker Runtime and ASan
    multi-worker jobs both exercise it for real."""
    if ng.single_process:
        return

    uri = "/l2promo/x"
    seed_uri = "/l2promo/seed-for-x"
    key = l2_key(uri)
    redis.cli("DEL", key)

    # Produce a module-correct blob for body A on a THROWAWAY key (own L2
    # slot), then copy its raw bytes into uri's L2 slot directly -- this
    # leaves /l2promo/x's L1 completely virgin (never touched), which is what
    # forces the first real read of it through the cold-L1-miss -> L2-consult
    # path rather than serving a live L1 HIT.
    s0, bodyA, _ = fetch(ng.port, seed_uri)
    assert s0 == 200 and bodyA, f"seed prime failed: {s0} {bodyA!r}"
    seed_key = l2_key(seed_uri)
    assert wait_for(lambda: redis.cli("EXISTS", seed_key) == "1"), \
        "seed body never reached L2"
    blobA = redis.get_raw(seed_key)
    assert blobA is not None, "could not read back the seed L2 blob"

    # AGE the blob's `created` stamp (u64 LE at byte offset 24, per
    # ngx_http_cache_turbo_blob_hdr_write / blob_validate -- no checksum
    # covers the header, so a direct byte patch is safe and does not need to
    # re-derive anything else) by 25s BEFORE seeding it into L2. This is what
    # makes STORE_IF_NEWER's comparison unambiguous regardless of scheduling
    # jitter: the promoted blob's remaining freshness (rem_fresh = fresh_ttl -
    # age) is forced to ~5s while the bypass write's fresh_until (anchored
    # fresh, cache_turbo_valid 30s from ITS OWN write time) is ~30s out -- a
    # >20s margin, immune to any sub-second timing wobble. Without this the
    # seed and the bypass write land within a few hundred ms of each other
    # (both use the same 30s TTL), so "is the resident entry newer" turns on
    # exactly the race's own jitter and the assertion flakes both ways
    # (measured: NGX_OK observed on an unaged blob in ~2 of 5 runs).
    assert len(blobA) >= 32, f"seed blob too short to carry a header: {blobA!r}"
    created = int.from_bytes(blobA[24:32], "little")
    aged_created = created - 25
    blobA = blobA[:24] + aged_created.to_bytes(8, "little") + blobA[32:]

    redis.set_raw(key, blobA, 30_000)
    wait_for_l2(redis, key, blobA, what="L2 seed for /l2promo/x")

    window_start = _errlog_window_start(ng)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        # Parked read: /l2promo/x's L1 slot is virgin, so this is a
        # guaranteed cold L1 miss -> L2 GET -> resume -> held for 2000ms
        # (cache_turbo_test_l2_promote_hold_ms) right before the promote
        # decision.
        held_fut = pool.submit(fetch, ng.port, uri)

        # Give the held request time to actually park on L2, resume, and
        # enter the hold -- comfortably under the 2000ms hold itself (wide
        # margin against redis round-trip / scheduler jitter on a loaded CI
        # box), so the bypass write below reliably lands INSIDE the window.
        time.sleep(0.5)

        # Concurrent newer write: bypass never touches redis or the hold
        # (different code path entirely), so it proceeds immediately on
        # whichever worker picks it up -- almost certainly a different one
        # from the held request, since that worker's event loop is blocked.
        s_bp, bodyB, _h_bp = fetch(ng.port, uri + "?nocache=1")
        assert s_bp == 200 and bodyB, f"bypass write failed: {s_bp} {bodyB!r}"
        assert bodyB != bodyA, \
            "bypass must hit the origin for a fresh body, not replay bodyA"

        s_held, _b_held, _h_held = held_fut.result(timeout=10)

    assert s_held == 200, f"held L2 read returned {s_held}, expected 200"

    # Oracle part 1: the NOTICE line must be PRESENT and read NGX_DECLINED.
    # Absent is a FAIL, never read as 0/NGX_OK -- see the docstring on why an
    # absent line cannot be trusted as "the guard passed".
    rcs = _errlog_l2_promote_rc_in_window(ng, window_start)
    assert rcs, (
        "no 'cache_turbo: test_l2_promote_rc=' line found in this request's "
        "error.log window -- the oracle line is MISSING, which must fail "
        "(never silently read as declined): either TEST_FAULTS is not "
        "actually compiled in, or the L2-promote branch was never entered "
        "for this request")
    NGX_DECLINED = -5
    assert all(v == NGX_DECLINED for v in rcs), (
        f"L2 promote was not declined: test_l2_promote_rc values in window = "
        f"{rcs} (NGX_DECLINED == {NGX_DECLINED}) -- the race was not closed, "
        f"a slow L2 reply was allowed to promote over a newer L1 entry")

    # Oracle part 2 (black-box, reachable here unlike the SIE-buffer case):
    # a follow-up plain read must see bodyB (the newer L1 entry), never
    # bodyA (the stale L2 blob). Under the pre-fix bug this comes back with
    # bodyA instead -- exactly the race AUD-L2-PROMOTE-RACE exists to close.
    s_final, b_final, _h_final = fetch(ng.port, uri)
    assert s_final == 200, f"final read returned {s_final}, expected 200"
    assert b_final == bodyB, (
        f"final L1 body was overwritten by the slow L2 promote: "
        f"got {b_final!r}, expected the newer bypass body {bodyB!r} "
        f"(bodyA was {bodyA!r})"
    )


def test_request_cc_serve_verdict_l2(ng: Nginx, origin: Origin,
                                     redis: RedisServer) -> None:
    """C-S5-a: RFC-1 request Cache-Control serve verdict evaluated on the L2
    (Redis) arm at module.c:5296, NOT the L1 site at :4813 the existing
    /reqcc/ + /reqccst/ tests exercise (neither location there carries
    cache_turbo_redis, so the L2 branch has zero runtime coverage otherwise).

    An L2 entry can be younger than the L1 copy (a peer refreshed it), so its
    own age (bh.created / bh.fresh_ttl) has to be re-verdicted independently.

    PURGE on /reqccl2/ is L2-AWARE (it DELs the Redis key too, see
    ngx_http_cache_turbo_purge_request / module.c:1711), so it cannot be used
    to drop L1 while leaving L2 populated -- it empties both. Instead: prime,
    capture the stored blob's raw bytes via GET, PURGE to clear both tiers,
    then write the SAME blob bytes back into L2 only via raw SET (mirrors the
    /sfgu/ precedent's "aged blob written directly to L2" technique). L1 is
    now empty and L2 holds the object, so any read is forced through the L2
    verdict at module.c:5296.

    Two-sided: a Cache-Control bound the L2 entry FAILS must revalidate at
    origin (req_reval, observable as a body change / non-HIT status); a
    request that does not conflict must still serve the stored L2 copy."""
    uri = "/reqccl2/reqccl2-k1"
    key = l2_key(uri)
    redis.cli("DEL", key)

    # prime: miss -> stored in both L1 and L2
    s0, base, _ = fetch(ng.port, uri)
    assert s0 == 200, f"prime should reach origin, got {s0}"
    assert wait_for(lambda: redis.cli("EXISTS", key) == "1"), \
        "object never written to L2"
    blob = redis.get_raw(key)
    assert blob is not None and len(blob) >= 44, f"short/absent blob: {blob!r}"

    def _drop_l1_keep_l2() -> None:
        """PURGE clears L1 AND L2 (module.c:1711); re-write the captured blob
        straight into L2 afterwards so only L1 stays empty.

        ⚠ The PURGE-side L2 DEL is FIRE-AND-FORGET: the 200 is written from the
        L1 count and does not await Redis (see the purge completion comment,
        "L2 deletions are fire-and-forget and not reflected in {"purged":N}").
        So the DEL can land AFTER our set_raw() and delete the very blob under
        test -- an unrecoverable loss that wait_for_l2() below can only report
        as `observed (absent): None`, never wait out. Observed as an ASan
        single-process red on run 31464424090. Wait for the DEL to be OBSERVED
        (key gone) before writing, so the two operations cannot interleave."""
        s_p, b_p, _ = fetch_raw(ng.port, uri, method="PURGE")
        assert s_p == 200, f"PURGE status {s_p}: {b_p}"
        assert wait_for(lambda: redis.cli("EXISTS", key) == "0"), \
            "PURGE's fire-and-forget L2 DEL never landed; writing the blob " \
            "back now would race it and could be deleted after the fact"
        redis.set_raw(key, blob, 3_600_000)
        wait_for_l2(redis, key, blob,
                    what="L2 restore after PURGE on /reqccl2/")

    _drop_l1_keep_l2()

    # plain read (no request Cache-Control): must still be served from the
    # stored L2 copy -- proves the passing/no-bound arm fills L1 from L2
    # rather than always refetching.
    s1, b1, h1 = fetch(ng.port, uri)
    assert s1 == 200 and b1 == base, \
        f"plain re-read after L1 drop should replay the L2-stored body, " \
        f"got status={s1} body_changed={b1 != base}"
    assert h1.get("x-ct-status") in ("HIT", "STALE"), \
        f"plain re-read should be served from L2 (HIT/STALE), got " \
        f"{h1.get('x-ct-status')}"

    # drop L1 again (the read above refilled it) so the next read is also
    # forced through the L2 verdict.
    _drop_l1_keep_l2()

    # min-fresh=999: client wants >=999s of remaining freshness. NOTE: this
    # (not max-age=0) is the correct failing bound here -- max-age=0 is
    # intercepted unconditionally by ngx_http_cache_turbo_request_revalidate()
    # at module.c:4473, BEFORE the L1 lookup even runs, so it never reaches
    # the L2 verdict site at :5296 at all (confirmed via error.log: it logs
    # "request no-cache -> origin (revalidate)", not an L2 verdict line). The
    # L2 entry has at most 30s of remaining freshness -> l2_fresh_ok=0; no
    # max-stale -> l2_stale_ok=0 -> req_reval=1 -> refetch from origin instead
    # of serving the rejected L2 copy.
    s2, b2, h2 = fetch(ng.port, uri,
                       headers={"Cache-Control": "min-fresh=999"})
    assert s2 == 200, f"revalidated read should still be 200, got {s2}"
    assert b2 != base, \
        "min-fresh=999 must revalidate the L2 copy at origin (new body), " \
        "not replay the rejected stored blob"
    assert h2.get("x-ct-status") != "HIT", \
        f"min-fresh=999 must refuse the L2-served HIT, got " \
        f"{h2.get('x-ct-status')}"

    drain_origin(origin)


def tag_key(name: str, prefix: str = "ct:") -> str:
    """Mirror the module's tag-set key: <prefix>tag:<name>."""
    return f"{prefix}tag:{name}"


def test_l2_tag_truncation_warns(ng: Nginx, origin: Origin,
                                 redis: RedisServer) -> None:
    """MAX_TAGS (16) is a deliberate DoS bound -- the tag value is
    upstream-controlled, and each tag costs its own Redis op, so an unbounded list
    would let one response fire a connection storm (PERF-2). The bound stays.

    But hitting it SILENTLY is a correctness trap, and a real one: a Magento
    category page emits one cat_p_<id> tag PER PRODUCT, so a 40-product page
    overflows 16 and the tags past the cap are never indexed. A later purge of one
    of those tags then does NOT invalidate the page -- the operator gets stale
    content with no signal anywhere. This pins the WARNING that makes the
    truncation diagnosable.

    Asserted positively (see lessons.md): we require the warning TEXT to appear,
    and we require it NOT to appear for an exactly-at-the-cap value -- a warning
    that always fires is as useless as one that never does."""
    logf = ng.root / "logs" / "error.log"

    def log_text() -> str:
        return (logf.read_text(encoding="utf-8", errors="replace")
                if logf.exists() else "")

    # Exactly 16 tags -- at the cap, nothing dropped, must NOT warn. Append a
    # trailing separator so this also exercises the "skip trailing separators
    # before deciding s < e" arm -- without it, a value ending right after the
    # 16th tag never reaches that code path and the arm goes unexercised.
    before = len(log_text())
    at_cap = ",".join(f"t{i}" for i in range(16)) + ", "
    fetch(ng.port, f"/l2tcap/at-cap?t={at_cap}")
    time.sleep(0.3)
    new = log_text()[before:]
    assert "tag list truncated" not in new, \
        ("a value with exactly MAX_TAGS tags drops nothing and must NOT warn -- "
         "a warning that always fires teaches the operator to ignore it")

    # 17 tags -- one over. The 17th is silently unindexed, so it MUST warn.
    before = len(log_text())
    over = ",".join(f"x{i}" for i in range(17))
    fetch(ng.port, f"/l2tcap/over-cap?t={over}")
    time.sleep(0.3)
    new = log_text()[before:]
    assert "tag list truncated" in new, \
        ("17 tags overflow the 16-tag cap: the 17th is NOT indexed and a purge of "
         "it will NOT invalidate the entry. That must be logged, or the operator "
         "sees stale content with no signal. Missing warning in:\n" + new[-800:])
    assert "/l2tcap/over-cap" in new, \
        "the truncation warning must name the URI it dropped tags for"

    # And the dropped tag really is absent from the index -- the warning is not
    # cosmetic, it is reporting a real loss of purgeability.
    assert redis.cli("EXISTS", tag_key("x16")) == "0", \
        "the 17th tag must not be indexed (it is past the cap)"
    assert redis.cli("EXISTS", tag_key("x0")) == "1", \
        "tags within the cap must still be indexed"
    drain_origin(origin)


def test_l2_tag_overlong_warns(ng: Nginx, origin: Origin,
                               redis: RedisServer) -> None:
    """CR297-TAGLEN: a single tag longer than MAX_TAG_LEN (128) is silently
    dropped by _tag_split() -- unlike the MAX_TAGS count cap, this drop still
    advances the tokeniser's cursor past the whole token, so the caller's
    `s < e` count-cap check structurally cannot see it. The entry becomes
    unpurgeable on that tag with no signal anywhere. This pins the warning
    that makes the drop diagnosable, at the point it actually happens."""
    logf = ng.root / "logs" / "error.log"

    def log_text() -> str:
        return (logf.read_text(encoding="utf-8", errors="replace")
                if logf.exists() else "")

    # A normal, well-within-limit tag alongside one long tag must NOT warn
    # for the short tag and must NOT drop it.
    before = len(log_text())
    redis.cli("DEL", tag_key("short"))
    fetch(ng.port, "/l2tcap/overlong-ok?t=short")
    time.sleep(0.3)
    new = log_text()[before:]
    assert "exceeds NGX_HTTP_CACHE_TURBO_MAX_TAG_LEN" not in new, \
        "a tag within the length limit must not warn"
    assert wait_for(
        lambda: redis.cli("SISMEMBER", tag_key("short"),
                           l2_key("/l2tcap/overlong-ok")) == "1"), \
        "in-limit tag must still be indexed"

    # One tag of 129 bytes (one over MAX_TAG_LEN=128) -- silently dropped
    # pre-fix, must now warn naming the length and the limit.
    before = len(log_text())
    long_tag = "y" * 129
    redis.cli("DEL", tag_key(long_tag))
    fetch(ng.port, f"/l2tcap/overlong-drop?t={long_tag}")
    time.sleep(0.3)
    new = log_text()[before:]
    assert "exceeds NGX_HTTP_CACHE_TURBO_MAX_TAG_LEN=128" in new, \
        ("a 129-byte tag exceeds the 128-byte MAX_TAG_LEN and is dropped -- "
         "that must be logged, or the operator sees stale content with no "
         "signal. Missing warning in:\n" + new[-800:])
    assert "length 129" in new, \
        "the warning must name the tag's own length, not just the limit"
    assert "/l2tcap/overlong-drop" in new, \
        "the warning must name the URI it dropped the tag for"
    assert redis.cli("EXISTS", tag_key(long_tag)) == "0", \
        "the over-long tag must not be indexed"
    drain_origin(origin)


def test_l2_tag_add_on_store(ng: Nginx, origin: Origin,
                             redis: RedisServer) -> None:
    """v2c: a tagged store SADDs the object's L2 key into every tag set named by
    cache_turbo_tag, and bounds the set's lifetime with an EXPIRE."""
    redis.cli("DEL", tag_key("blog"), tag_key("news"))
    uri = "/l2t/article"
    s, _, h = fetch(ng.port, uri)                  # miss -> origin -> store+tag
    assert s == 200 and "x-cache" not in h, "tagged prime should miss to origin"

    okey = l2_key(uri)
    # SADD is fire-and-forget; let it land
    assert wait_for(lambda: redis.cli("SISMEMBER", tag_key("blog"), okey) == "1"), \
        "object key never joined tag set 'blog'"
    assert redis.cli("SISMEMBER", tag_key("news"), okey) == "1", \
        "object key missing from second tag set 'news'"
    # EXPIRE applied to the tag set (bounded lifetime)
    pttl = int(redis.cli("PTTL", tag_key("blog")))
    assert pttl > 0, f"tag set has no TTL (PTTL={pttl})"


def test_l2_tag_purge(ng: Nginx, origin: Origin, redis: RedisServer) -> None:
    """P4: purge-by-tag drops every tagged object from BOTH tiers and removes
    the tag set. Two objects share tag 'news'; one POST clears them all."""
    redis.cli("DEL", tag_key("blog"), tag_key("news"))
    u1, u2 = "/l2t/p1", "/l2t/p2"
    body1, body2 = {}, {}
    for u, store in ((u1, body1), (u2, body2)):
        _, b, _ = fetch(ng.port, u)                # miss -> origin -> store+tag
        store["body"] = b
        _, _, h = fetch(ng.port, u)
        assert h.get("x-cache") == "HIT", f"{u} should be cached (L1) before purge"
    assert wait_for(lambda: redis.cli("SCARD", tag_key("news")) == "2"), \
        "both objects should be in tag set 'news'"

    s, b, _ = fetch(ng.port, "/_cache_l2?tag=news", method="POST")
    assert s == 200, f"tag purge status {s}"
    assert json.loads(b)["purged"] == 2, f"expected 2 purged, got {b}"

    # both objects gone from L2, and the tag set itself deleted
    assert wait_for(lambda: redis.cli("EXISTS", l2_key(u1)) == "0"
                    and redis.cli("EXISTS", l2_key(u2)) == "0"), \
        "tagged objects not removed from L2"
    assert wait_for(lambda: redis.cli("EXISTS", tag_key("news")) == "0"), \
        "emptied tag set was not deleted"

    # both gone from L1: next reads miss to a fresh origin generation, and must
    # not stall — tag purge clears each member's single-flight lock too (V-HANG).
    origin_before = origin.hits
    t0 = time.monotonic()
    _, nb1, h1 = fetch(ng.port, u1)
    _, nb2, h2 = fetch(ng.port, u2)
    elapsed = time.monotonic() - t0
    assert "x-cache" not in h1 and "x-cache" not in h2, \
        "tagged objects should be a MISS in L1 after purge"
    # Scaled by ASAN_TIME_SCALE (FLAKE-ASAN-TIMING-BAND): unscaled outside a
    # sanitizer run.
    budget = 2.0 * sanitizer_time_scale()
    assert elapsed < budget, \
        f"post-tag-purge cold misses stalled {elapsed:.1f}s (stale lock?, " \
        f"budget {budget:.1f}s)"
    assert origin.hits == origin_before + 2, "both reads should reach origin"
    assert nb1 != body1["body"] and nb2 != body2["body"], \
        "post-purge bodies should be fresh generations"


def test_l2_tag_purge_large(ng: Nginx, origin: Origin,
                            redis: RedisServer) -> None:
    """STAB-3 + PERF-1/2: a tag set with enough members that the SMEMBERS reply
    spans multiple recv()s (>16 KiB), and whose purge drops every member across
    both tiers. Pre-PERF this fired ~2N fire-and-forget DEL connections at once
    and exhausted worker_connections; now the purge collects all keys into ONE
    pipelined UNLINK connection, so the whole set is deleted cleanly. Asserts
    both the framed member count (STAB-3) and full cross-tier deletion (PERF)."""
    # ⚠ The tag SADD is fire-and-forget, so the PRECEDING test's trailing
    # /l2t/p1 + /l2t/p2 cold misses (test_l2_tag_purge) can still have their
    # re-tagging SADDs in flight when we get here. DELeting once races them: a
    # straggler lands after the DEL and this test counts 351 instead of 350.
    # Drain to a stable empty state first -- DEL, then confirm it STAYS empty
    # across a settle window -- so the count below is only our own members.
    def _drained() -> bool:
        # Re-DEL each poll so a straggler that lands between our DEL and our
        # read is absorbed rather than merely detected, then require the set to
        # STAY empty across a settle window before we trust it.
        redis.cli("DEL", tag_key("blog"), tag_key("news"))
        time.sleep(0.25)
        return redis.cli("SCARD", tag_key("news")) == "0"

    assert wait_for(_drained, timeout=10.0), \
        (f"tag set 'news' never drained before priming; a previous test's "
         f"fire-and-forget SADD is still landing after 10s "
         f"(SCARD={redis.cli('SCARD', tag_key('news'))})")

    n = 350                                        # ~25 KiB SMEMBERS reply
    for i in range(n):
        s, _, _ = fetch(ng.port, f"/l2t/big-{i}")  # miss -> store + tag
        assert s == 200, f"prime /l2t/big-{i} status {s}"
    assert wait_for(lambda: redis.cli("SCARD", tag_key("news")) == str(n),
                    timeout=10.0), \
        f"expected {n} members in 'news', got {redis.cli('SCARD', tag_key('news'))}"

    s, b, _ = fetch(ng.port, "/_cache_l2?tag=news", method="POST")
    assert s == 200, f"large tag purge status {s}"
    # STAB-3: the whole multi-recv SMEMBERS array was framed + parsed once.
    assert json.loads(b)["purged"] == n, f"expected {n} purged, got {b}"
    # PERF-1/2: the pipelined UNLINK dropped every member + the tag set itself.
    assert wait_for(lambda: redis.cli("EXISTS", tag_key("news")) == "0",
                    timeout=10.0), "emptied tag set survived the large purge"
    assert wait_for(lambda: redis.cli("EXISTS", l2_key("/l2t/big-0")) == "0"
                    and redis.cli("EXISTS", l2_key(f"/l2t/big-{n-1}")) == "0",
                    timeout=10.0), "purged members survived in L2"


def test_l2_tag_cap_and_dedup(ng: Nginx, origin: Origin,
                              redis: RedisServer) -> None:
    """PERF-2: the upstream-controlled cache_turbo_tag value is bounded. A
    request naming more than MAX_TAGS (16) distinct tags indexes only the first
    16; duplicate tags in one value are SADD'd once (idempotent + no extra
    connection). Guards against a hostile origin fanning out unbounded SADDs."""
    obj = l2_key("/l2tcap/x")
    # 30 distinct tags -> only the first 16 should index the object.
    tags = ",".join(f"cap{i}" for i in range(30))
    for i in range(30):
        redis.cli("DEL", tag_key(f"cap{i}"))
    s, _, _ = fetch(ng.port, f"/l2tcap/x?t={tags}")
    assert s == 200, f"cap prime status {s}"
    assert wait_for(lambda: redis.cli("SISMEMBER", tag_key("cap0"), obj) == "1"), \
        "first tag was not indexed"
    indexed = sum(1 for i in range(30)
                  if redis.cli("SISMEMBER", tag_key(f"cap{i}"), obj) == "1")
    assert indexed == 16, f"expected exactly 16 tags indexed (cap), got {indexed}"

    # dedup: the same tag repeated still yields one membership.
    obj2 = l2_key("/l2tcap/y")
    redis.cli("DEL", tag_key("dup"))
    s, _, _ = fetch(ng.port, "/l2tcap/y?t=dup,dup,dup,dup")
    assert s == 200
    assert wait_for(lambda: redis.cli("SISMEMBER", tag_key("dup"), obj2) == "1"), \
        "deduped tag was not indexed"
    assert redis.cli("SCARD", tag_key("dup")) == "1", \
        "duplicate tag produced more than one membership"


def test_l2_tag_purge_arg_validation(ng: Nginx, origin: Origin,
                                     redis: RedisServer) -> None:
    """AUD-TAG1: the ?tag= purge argument is taken raw from ngx_http_arg with
    no length/charset check of its own, unlike cache_turbo_tag's own tokeniser
    (test_l2_tag_cap_and_dedup et al) which caps each tag at MAX_TAG_LEN (128)
    and splits on space/tab/comma/CR/LF. The purge arg must mirror those SAME
    rules so a purge request can never even ask about a byte string the
    tokeniser could not have produced as a tag.

    ngx_http_arg does not URL-decode, and a literal space/tab/CR/LF in the
    request-target is invalid HTTP grammar -- nginx's own core parser 400s the
    request before it ever reaches our handler (verified: a raw socket sending
    '?tag=news<TAB>blog' gets nginx's stock text/html 400 page, not our JSON
    error body). So those bytes can never actually reach ngx_http_arg; the
    check against them is defense-in-depth against a DISTANT parser rather
    than something a live request can exercise, exactly like the ledger's
    note on the plain space case. Comma is the one separator byte that IS
    valid in a request-target and reaches ngx_http_arg intact, so it is what
    proves the charset check fires for real; length is proven directly since
    an over-long ASCII tag is ordinary, well-formed HTTP. Rejections take the
    existing bad-input shape for this handler: 400 with a JSON {"error": ...}
    body (see the sibling 'requires cache_turbo_redis' 400 a few lines above
    the validation)."""
    # over-length: 129 bytes, one past MAX_TAG_LEN (128).
    s, b, _ = fetch(ng.port, f"/_cache_l2?tag={'a' * 129}", method="POST")
    assert s == 400, f"129-byte tag should be rejected, got {s}: {b}"
    assert "invalid tag" in json.loads(b)["error"], \
        f"expected an 'invalid tag' error for an over-length tag, got {b}"

    # exactly at the cap (128 bytes) must NOT be rejected by the length check
    # -- proves the check is > not >=. (Backend absent path already covered by
    # the 'requires cache_turbo_redis' test elsewhere; this only needs to get
    # past the length gate, so any redis-backed status other than the
    # over-length 400 proves it.)
    s, b, _ = fetch(ng.port, f"/_cache_l2?tag={'b' * 128}", method="POST")
    assert s == 200, f"exactly-128-byte tag should pass validation, got {s}: {b}"

    # comma: a real, unencoded query byte that reaches ngx_http_arg intact.
    s, b, _ = fetch(ng.port, "/_cache_l2?tag=news,blog", method="POST")
    assert s == 400, f"comma in tag should be rejected, got {s}: {b}"
    assert "invalid tag" in json.loads(b)["error"], \
        f"expected an 'invalid tag' error for a comma-bearing tag, got {b}"

    # Positive control: an ordinary legitimate tag purges exactly as before --
    # proves the new check does not over-reject real traffic. /l2tcap/ takes
    # its tag from $arg_t so a custom tag name can be primed here.
    redis.cli("DEL", tag_key("valtest"))
    path = "/l2tcap/valtest-obj"
    fetch(ng.port, f"{path}?t=valtest")               # miss -> origin -> store+tag
    obj = l2_key(path)
    assert wait_for(lambda: redis.cli("SISMEMBER", tag_key("valtest"),
                                       obj) == "1"), \
        "object never joined tag set 'valtest'"
    s, b, _ = fetch(ng.port, "/_cache_l2?tag=valtest", method="POST")
    assert s == 200, f"legitimate tag purge should succeed, got {s}: {b}"
    assert json.loads(b)["purged"] == 1, f"expected 1 purged, got {b}"
    assert wait_for(lambda: redis.cli("EXISTS", tag_key("valtest")) == "0"), \
        "legitimate tag purge should still remove the tag set"


def test_l2_tag_add_batched_one_op(ng: Nginx, origin: Origin,
                                   redis: RedisServer) -> None:
    """L9: a store naming N tags indexes them in ONE pipelined Redis op, not N.

    /l2tcap/ carries no keepalive=, so every op dials a fresh socket and Redis'
    total_connections_received tracks the op count directly. A 12-tag store
    costs 1 SET + 1 batched tag op; before L9 it cost 1 SET + 12 tag ops, so
    the pre-L9 tree fails this by roughly an order of magnitude.

    Membership is asserted too: batching must not lose a tag (the existing
    cap/dedup tests would pass either way, since they only check membership)."""
    ntags = 12
    stamp = time.time()
    uri = f"/l2tcap/batch-{stamp}"
    obj = l2_key(uri)
    tags = [f"b{stamp}-{i}" for i in range(ntags)]
    for t in tags:
        redis.cli("DEL", tag_key(t))

    # NOTE: redis.cli() shells out to redis-cli and opens its OWN connection
    # per call, so NOTHING may touch redis between the two _redis_conns_received
    # readings -- a SISMEMBER poll inside the window counts as module traffic
    # and inflates the result. Measure the fetch alone; verify membership after.
    before = _redis_conns_received(redis)
    s, _, _ = fetch(ng.port, f"{uri}?t={','.join(tags)}")
    assert s == 200, f"batch prime status {s}"
    time.sleep(0.6)          # let the fire-and-forget ops settle
    conns = _redis_conns_received(redis) - before

    # every tag must still be indexed -- batching must not drop one
    assert wait_for(lambda: all(
        redis.cli("SISMEMBER", tag_key(t), obj) == "1" for t in tags)), \
        "batched tag_add did not index every tag"

    # 1 GET (miss) + 1 SET (write-through) + 1 batched tag op = ~3. Allow slack
    # for retries/probes but stay far below the pre-L9 1 + 1 + ntags.
    assert conns < ntags, \
        f"tag_add was not batched: {conns} connections for {ntags} tags " \
        f"(pre-L9 cost ~{ntags + 2}; batched should be ~3)"


def _spawn_node(ng: Nginx, name: str, port_offset: int) -> Nginx:
    """Start a second, independent nginx (own root, same Redis + origin) so a
    cross-node test can observe two cache instances sharing one L2."""
    b = Nginx(ng.binary, ng.module, ng.root.parent / name,
              ng.port + port_offset, ng.origin_port, ng.runner_raw,
              ng.single_process, ng.redis_port)
    b.write_config()
    b.config_test()
    b.start()
    return b


def test_multinode_lock(ng: Nginx, origin: Origin, redis: RedisServer) -> None:
    """v4-2: two nginx nodes sharing one Redis collapse a stale-key refresh to a
    SINGLE origin regen via the cross-node SET NX PX lock. Without the lock both
    nodes' dice would each reach origin (== 2)."""
    uri = "/lock/mn"
    redis.cli("DEL", l2_key(uri), lock_key(uri))

    # Node A primes the key: origin -> L1_A + L2 fresh.
    sa, body_a, ha = fetch(ng.port, uri)
    assert sa == 200 and "x-cache" not in ha, "A should miss to origin first"
    assert wait_for(lambda: redis.cli("EXISTS", l2_key(uri)) == "1"), \
        "A never wrote the object to L2"

    b = _spawn_node(ng, "server-mn", 6)
    try:
        # Node B fills its L1 from the shared L2 (HIT, no origin) -> both hold it.
        sb, body_b, hb = fetch(b.port, uri)
        assert sb == 200 and body_b == body_a, "B should L2-fill A's body"
        assert hb.get("x-cache") == "HIT", \
            f"B fill X-Cache={hb.get('x-cache')} (expected an L2-fill HIT)"

        # Wait until the entry is stale on BOTH nodes. Each node's L1 is fresh
        # for valid=2s from its own store; B stored its copy last (~now), so a
        # 2.5s sleep puts both past fresh yet well inside the 8s stale window.
        time.sleep(2.5)                            # stale on both, still < 8s
        drain_origin(origin)       # absorb any stray async bg before counting
        base = origin.hits

        # Hammer both nodes through the stale window. The dice fires a refresh on
        # at least one; the NX lock lets exactly one node reach origin.
        deadline = time.time() + 1.5
        while time.time() < deadline:
            fetch(ng.port, uri)
            fetch(b.port, uri)
            time.sleep(0.05)
        time.sleep(0.4)                            # let any in-flight regen land

        regens = origin.hits - base
        assert regens == 1, \
            f"cross-node single-flight failed: {regens} origin regens (want 1)"

        time.sleep(0.2)
        b.stop()
        b.assert_clean_logs()
    finally:
        b.stop()
        drain_origin(origin)   # v8: settle async bg refreshes before next test


def test_cross_node_won_stale_body(ng: Nginx, origin: Origin,
                                   redis: RedisServer) -> None:
    """S231-PERF-BGSNAP: the cross-node lock-WINNER's background-update stale
    serve (ngx_http_cache_turbo_module.c, the `ctx->lock_done && (lock_result
    == NGX_OK || NGX_ERROR)` arm under `clcf->background_update`) now pins the
    shm blob instead of memcpy'ing the full body under the zone mutex. A single
    node with no contention wins the Redis SET NX PX lock uncontested on its
    first stale read, so that read is guaranteed to take the WON arm.

    Proves: (1) the served body is byte-exact -- a use-after-release or a
    pointer into freed/reused slab would show up here, not just as a crash;
    (2) the background refresh still lands and a later read sees the NEW
    generation, i.e. the entry is still evictable/replaceable afterward --
    a leaked reference from this arm would pin the OLD generation forever."""
    uri = "/lock/won"
    redis.cli("DEL", l2_key(uri), lock_key(uri))

    # nginx strips the /lock/ prefix before proxying, so the origin logs
    # "/won" -- hits_for() must scope on the slug that actually lands, same
    # as test_lock_redis_outage_fallback and test_lock_self_heal below.
    slug = "won"

    s0, body0, h0 = fetch(ng.port, uri)
    assert s0 == 200 and "x-cache" not in h0, "prime should miss to origin"
    assert wait_for(lambda: redis.cli("EXISTS", l2_key(uri)) == "1"), \
        "prime never wrote L2"
    # Assert the prime's own origin contact landed, path-scoped, BEFORE the
    # stale read -- inferring it later from the global `hits` counter races
    # this async count against the stale-window sleep below: if the prime's
    # bump has not landed by the time `base` is snapshotted, `base` is off by
    # one and the WON-arm assertion after it can never resolve within its
    # 2.0s window (measured: every such failure has origin.hits == 1 at drain
    # time, every pass has 2 -- the missing contact is here, not in the
    # background-refresh arm the old failure message named).
    assert wait_for(lambda: origin.hits_for(slug) >= 1, timeout=2.0), \
        "prime phase never registered its own origin contact"

    time.sleep(2.5)                     # stale (fresh=2s), still < 8s window
    drain_origin(origin)                # absorb any stray async bg before counting
    base = origin.hits_for(slug)

    # Single node, uncontended: the first stale read wins the cross-node NX
    # lock and takes the WON arm (background_update default ON) -- serve
    # stale now, refresh in the background.
    s1, body1, h1 = fetch(ng.port, uri)
    assert s1 == 200, f"cross-node WON stale serve status {s1}"
    assert h1.get("x-cache") == "STALE", \
        f"expected STALE from the cross-node WON arm, got {h1.get('x-cache')}"
    assert body1 == body0, \
        f"cross-node WON stale serve returned a wrong body: " \
        f"{body1!r} != {body0!r}"

    # the background refresh reaches the origin and a later read is fresh.
    assert wait_for(lambda: origin.hits_for(slug) > base, timeout=2.0), \
        "cross-node WON arm never fired the background refresh"

    def _got_refreshed() -> bool:
        _, b, h = fetch(ng.port, uri)
        return b != body0 and h.get("x-cache") == "HIT"

    # wait_for() applies sanitizer_time_scale() internally -- unscaled (2.0s)
    # outside a sanitizer run, matching this call site's old raw deadline loop.
    assert wait_for(_got_refreshed, timeout=2.0, interval=0.1), \
        "stale entry never refreshed to a new generation"

    # No refcount leak: a subsequent read must see the NEW generation, proving
    # the node was genuinely overwritten and not pinned on the old blob.
    s2, body2, _h2 = fetch(ng.port, uri)
    assert s2 == 200 and body2 != body0, \
        "entry still serving the OLD generation after refresh -- possible " \
        "refcount leak from the cross-node WON pin"
    drain_origin(origin)   # v8: settle async bg refreshes before the next test


def test_lock_self_heal(ng: Nginx, origin: Origin, redis: RedisServer) -> None:
    """v4-2: a held cross-node lock (a peer mid-regen) makes other nodes serve
    stale without piling on origin; once the lock PX-expires (the peer 'died'
    before storing) a node re-acquires it and regenerates EXACTLY once. Uses the
    short-lock_ttl /lockh/ location so the node's own per-box L1 refresh lock
    (also lock_ttl) clears in step with the cross-node lock.

    NB: losing the NX still arms this node's local refresh_lock_until for
    lock_ttl, so the self-heal cannot fire until BOTH the peer's PX and this
    node's local lock have expired — the foreign PX is set a touch longer than
    lock_ttl so it is the gating one."""
    uri = "/lockh/heal"
    redis.cli("DEL", l2_key(uri), lock_key(uri))

    s, _body_a, h = fetch(ng.port, uri)             # prime -> origin -> L1 + L2
    assert s == 200 and "x-cache" not in h, "prime should miss to origin"
    assert wait_for(lambda: redis.cli("EXISTS", l2_key(uri)) == "1"), \
        "prime never wrote L2"

    time.sleep(2.4)                                # now stale (fresh=2s)

    # A peer node 'holds' the regen lock (set now that the key is stale, PX 2500
    # > lock_ttl 2000), then crashes — the lock is freed only by PX expiry.
    redis.cli("SET", lock_key(uri), "peer-node", "PX", "2500")
    drain_origin(origin)           # absorb any stray async bg before counting
    base = origin.hits

    # Phase 1 — lock held by the peer: refresh attempts lose the NX, so reads
    # serve stale and origin is NOT hit. Short, well inside the 2.5s PX.
    for _ in range(6):
        s, _, _ = fetch(ng.port, uri)
        assert s == 200, f"stale read status {s}"
        time.sleep(0.05)
    assert origin.hits == base, \
        f"origin was hit while the lock was held by a peer ({origin.hits - base})"

    # Phase 2 — let the peer's lock PX-expire (and with it, past this node's own
    # 2s local lock), then read: a node self-heals by acquiring the freed NX and
    # regenerating exactly once. Still inside the 8s stale window.
    assert wait_for(lambda: redis.cli("EXISTS", lock_key(uri)) == "0",
                    timeout=4.0), "foreign lock never PX-expired"
    deadline = time.time() + 1.5
    heal_before = origin.hits_for("heal")
    while time.time() < deadline and origin.hits_for("heal") == heal_before:
        fetch(ng.port, uri)
        time.sleep(0.05)
    time.sleep(0.4)

    regens = origin.hits_for("heal") - heal_before
    if regens != 1:
        recent = [(round(t, 2), p) for t, p in origin._paths[-15:]]
        raise AssertionError(
            f"self-heal: want exactly 1 regen after lock expiry, got {regens}; "
            f"recent origin paths: {recent}")
    drain_origin(origin)       # v8: settle async bg refreshes before the next test


def test_lock_redis_outage_fallback(ng: Nginx, origin: Origin,
                                    redis: RedisServer) -> None:
    """Deferred enhancement: deterministic mid-flight Redis outage coverage for
    the lock NGX_ERROR fallback (ngx_http_cache_turbo_module.c ~3166-3206). When
    the cross-node SET NX PX lock channel itself fails (Redis down, not merely
    "peer holds the lock" == NGX_DECLINED), the module must NOT treat that the
    same as a peer holding the lock (which would serve stale forever with no
    regen) — it degrades to per-box single-flight and regenerates locally, since
    `ctx->lock_result == NGX_OK || ctx->lock_result == NGX_ERROR` both fall into
    the "we own the regen" branch, only NGX_DECLINED (genuine peer-holds) serves
    stale without regenerating.

    This is a REAL, distinct branch from test_lock_self_heal (which exercises a
    PEER holding a live lock that later PX-expires — NGX_DECLINED then NGX_OK).
    Here the lock channel never even completes: Redis is stopped between the
    prime and the stale read, so the NX attempt itself gets ECONNREFUSED
    (immediate, deterministic — no timeout hang, since this is a plain TCP
    connect failure, not a slow-loris). Uses /lock/ (cache_turbo_lock off
    isolates the stale-path NX under test, same as test_multinode_lock).

    Readers are BARRIER-SYNCHRONISED and concurrent, which is what makes the
    single-flight claim provable. A sequential hammer loop could not: each fetch
    completes before the next begins, so even a COLLAPSED single-flight yields
    one regen — the first reader's refresh fills L1, and every later read is a
    plain fresh hit that never reaches the dice. Such a test passes with the
    mechanism it claims to test removed. Only readers that are all inside the
    SAME regeneration window (origin delay = 50ms) can distinguish "one reader
    regenerates and the rest ride the claim" from "each reader regenerates".

    Latency is asserted PER REQUEST, not aggregated over the loop: an aggregate
    bound hides one multi-second stall inside a budget sized for the whole burst,
    and a stall is exactly what the NGX_ERROR path would produce if it waited on
    the dead lock channel instead of failing fast.

    Two harness constraints that are easy to get wrong (both cost a debug round):

    1. `slug`, not `uri`, is what the origin counter matches. proxy_pass strips
       the /lock/ prefix, so the origin logs "/<slug>" -- `hits_for(uri)` would
       match NOTHING and read 0 regens forever, which is indistinguishable from
       the canary's genuine failure signature. Scope on the slug, which is unique
       per run (so the count is immune to another test's async bg traffic, per
       the drain_origin boundary lesson) AND is what actually lands in the log.
    2. The refresh dice is driven by ngx_time(), which has ONE-SECOND
       granularity (swr.c: `elapsed = now - fresh_until`, threshold =
       elapsed/window * beta). At elapsed == 0 the threshold is 0 and the dice
       CANNOT fire, whatever beta is. sleep(2.4) puts the first read ~0.4s past
       fresh_until, i.e. still elapsed == 0 for up to ~0.6s more; the barrier
       burst then rides the wait_for below rather than assuming an instant regen.
       Do not "optimise" the wait_for into a fixed short sleep -- a burst that
       lands entirely inside elapsed == 0 legitimately produces zero regens until
       the clock ticks."""
    slug = f"redis-outage-{time.time_ns()}"
    uri = f"/lock/{slug}"
    redis.cli("DEL", l2_key(uri), lock_key(uri))

    s, _body_a, h = fetch(ng.port, uri)             # prime -> origin -> L1 + L2
    assert s == 200 and "x-cache" not in h, "prime should miss to origin"
    assert wait_for(lambda: redis.cli("EXISTS", l2_key(uri)) == "1"), \
        "prime never wrote L2"

    time.sleep(2.4)                                # now stale (fresh=2s)

    # Simulate the outage: Redis goes away mid-flight, AFTER the prime succeeded
    # and BEFORE any refresh's lock NX is attempted. Every subsequent lock
    # attempt on this key fails at connect(), i.e. NGX_ERROR, never NGX_DECLINED.
    redis.stop()
    try:
        drain_origin(origin)           # absorb any stray async bg before counting
        base = origin.hits_for(slug)

        # All readers rendezvous at the barrier, then hit the stale key at once.
        # beta=5000 makes the dice fire on the first of them; the rest arrive
        # while that regen is still in flight (origin delay 50ms), so they can
        # only be absorbed by the single-flight claim -- not by an already-filled
        # L1. Losing Redis for the lock must not (a) hang a request, (b) serve
        # stale forever with zero regen, or (c) regen once per reader (that would
        # mean single-flight collapsed entirely, not "degraded to per-box").
        readers = 24
        barrier = threading.Barrier(readers)

        def _reader(_i: int) -> tuple[int, float]:
            barrier.wait()
            t = time.monotonic()
            st, _, _ = fetch(ng.port, uri)
            return st, time.monotonic() - t

        with concurrent.futures.ThreadPoolExecutor(max_workers=readers) as pool:
            results = list(pool.map(_reader, range(readers)))

        bad = [st for st, _ in results if st != 200]
        assert not bad, f"stale reads during redis outage returned {set(bad)}"

        # PER-REQUEST latency: no single reader may park on the dead lock
        # channel. The NGX_ERROR path is a connect() refusal (immediate), and a
        # loser rides the local claim and is served stale at once -- neither
        # waits on Redis. The real failure mode this guards is a lock_timeout
        # park (~5s, the V-HANG class), so the bound is generous enough to
        # survive valgrind/slow-CI scheduling while still catching that stall.
        worst = max(d for _, d in results)
        assert worst < 3.0, \
            f"a stale read during the redis outage stalled {worst:.1f}s -- the " \
            f"NGX_ERROR lock path parked instead of failing fast " \
            f"(latencies: {sorted(round(d, 2) for _, d in results)})"

        # 5s literal, NOT HTTP_TIMEOUT. This is a semantic deadline -- "the
        # NGX_ERROR fallback regenerated at all" -- not a socket read ceiling,
        # and the two only ever coincided numerically. Borrowing the client
        # timeout meant any future widening of it would silently grant a broken
        # fallback path more time to look correct.
        assert wait_for(
            lambda: origin.hits_for(slug) > base, timeout=5.0), \
            "lock NGX_ERROR fallback failed: 0 origin regens during a redis " \
            "outage -- the NGX_ERROR lock channel was treated like a peer " \
            "holding the lock (NGX_DECLINED), so the key is stuck stale forever"
        drain_origin(origin)           # let every in-flight regen land + settle

        regens = origin.hits_for(slug) - base
        # Path-scoped (hits_for), so another test's async bg traffic cannot
        # inflate this. Upper bound allows the multi-worker debug build: the
        # claim is per-WORKER shm state, so up to one regen per worker can race
        # in before the claim is visible -- but 24 readers collapsing to a small
        # constant is still categorically "single-flight held", whereas a
        # collapse reads ~24.
        assert regens <= 4, \
            f"lock NGX_ERROR fallback failed: {regens} origin regens from " \
            f"{readers} concurrent stale readers during a redis outage (want a " \
            f"small constant -- per-box single-flight degrade; ~{readers} means " \
            f"single-flight collapsed entirely)"
    finally:
        redis.start()                  # restore for cleanup / assert_clean_logs
        drain_origin(origin)


def test_cold_single_flight_cross_node(ng: Nginx, origin: Origin,
                                       redis: RedisServer) -> None:
    """v10 cross-node: two nodes sharing one Redis collapse a CONCURRENT cold
    burst to ~1 origin fetch. The node that wins the SET NX PX regenerates and
    write-throughs to L2; the other node's local winner loses the NX and waits
    for that L2 fill instead of going to origin too."""
    uri = "/coldl2/sf"
    redis.cli("DEL", l2_key(uri), lock_key(uri))

    b = _spawn_node(ng, "server-cold", 7)
    try:
        base = origin.hits
        ports = [ng.port, b.port]
        # 40 concurrent first-hits split across both cold nodes.
        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
            results = list(pool.map(
                lambda i: fetch(ports[i % 2], uri), range(40)))
        assert {r[0] for r in results} == {200}, \
            f"cross-node cold burst returned {set(r[0] for r in results)}"
        bodies = {r[1] for r in results}
        assert len(bodies) == 1, \
            f"cross-node cold burst served {len(bodies)} distinct bodies"
        time.sleep(0.4)                            # let any in-flight regen land
        regens = origin.hits - base
        # One node regenerates; the other L2-fills. Allow a little slack for the
        # NX-resolution window across two event loops.
        assert regens <= 3, \
            f"cross-node cold single-flight failed: {regens} origin fetches"
        time.sleep(0.2)
        b.stop()
        b.assert_clean_logs()
    finally:
        b.stop()
        drain_origin(origin)


def test_purge_all_clears_l2(ng: Nginx, origin: Origin,
                             redis: RedisServer) -> None:
    """v4-2: POST ?all=1 on an L2-aware admin endpoint clears the whole L2
    keyspace (SCAN MATCH <prefix>* + DEL), so a purged object cannot be refilled
    from Redis on the next miss. Pre-v4-2 ?all=1 emptied L1 only."""
    uri = "/l2/purgeall"
    redis.cli("DEL", l2_key(uri))

    s, body_a, h = fetch(ng.port, uri)             # miss -> origin -> L1 + L2
    assert s == 200 and "x-cache" not in h, "prime should miss to origin"
    assert wait_for(lambda: redis.cli("EXISTS", l2_key(uri)) == "1"), \
        "write-through never reached L2"
    _, _, h2 = fetch(ng.port, uri)
    assert h2.get("x-cache") == "HIT", "should be an L1 hit before purge"

    # all-purge via the L2-aware admin endpoint
    s, b, _ = fetch(ng.port, "/_cache_l2?all=1", method="POST")
    assert s == 200 and "purged" in json.loads(b), f"all-purge result: {s} {b}"

    # the L2 entry must actually be gone (SCAN+DEL fired, fire-and-forget)
    assert wait_for(lambda: redis.cli("EXISTS", l2_key(uri)) == "0"), \
        "?all=1 did not clear the entry from L2 (v4-2 regression)"

    # next read is a true miss to a NEW origin generation, not an L2 refill
    origin_before = origin.hits_for("purgeall")
    s, body_b, h3 = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in h3, \
        f"post-all-purge read should miss to origin, got {h3.get('x-cache')}"
    assert origin.hits_for("purgeall") == origin_before + 1, \
        "origin was not consulted after all-purge (L2 still served)"
    assert body_b != body_a, "post-purge body should be a fresh generation"


def test_purge_all_escapes_redis_prefix_glob(ng: Nginx,
                                             redis: RedisServer) -> None:
    """SCAN MATCH must treat glob metacharacters in the configured prefix
    literally. Purging prefix 'ct*:' deletes 'ct*:owned' but not 'ctX:foreign'."""
    owned = f"ct*:owned:{time.time_ns()}"
    foreign = owned.replace("ct*:", "ctX:", 1)
    redis.cli("-n", "0", "SET", owned, "owned")
    redis.cli("-n", "0", "SET", foreign, "foreign")

    s, b, _ = fetch(ng.port, "/_cache_l2glob?all=1", method="POST")
    assert s == 200 and "purged" in json.loads(b), \
        f"glob-prefix all-purge failed: {s} {b}"

    # !! The 200 does NOT mean the keys are gone yet. The SCAN loop hands each
    # page to redis_del_many(), which opens its OWN connection and pipelines
    # UNLINKs fire-and-forget (redis.c: launch(..., read_drain)); the SCAN loop
    # never waits for those replies, and smembers_finish() emits this response
    # as soon as the CURSOR completes. So an UNLINK can still be in flight here.
    # Asserting EXISTS immediately is a race that only loses on a slow build --
    # which is why it went red under ASan (instrumented nginx is ~10-20x slower)
    # while passing every plain run. Poll for absence instead of sampling once.
    assert wait_for(lambda: redis.cli("-n", "0", "EXISTS", owned) == "0",
                    timeout=10.0), \
        "literal glob-prefix key was not purged (waited 10s after the 200)"

    # !! `owned` disappearing does NOT mean the purge has finished. del_many()
    # runs ONCE PER SCAN PAGE (redis.c:2584), each opening its own connection,
    # and there is no completion ordering between them. With the escaping defect
    # restored, `ct*:*` can put `owned` and `foreign` on DIFFERENT pages -- so a
    # single EXISTS sample here can observe foreign==1 simply because the page
    # that would delete it has an UNLINK still in flight, and the cleanup DEL
    # below then erases the evidence. That is a green run with the regression
    # present, which is the exact failure mode this whole PR exists to remove.
    #
    # So assert the forbidden transition NEVER happens across a drain window
    # wider than the 250ms redis op timeout, rather than sampling once.
    assert not wait_for(lambda: redis.cli("-n", "0", "EXISTS", foreign) == "0",
                        timeout=1.5), \
        "glob prefix widened SCAN and deleted an unrelated key"
    redis.cli("-n", "0", "DEL", foreign)


def _scan_fill(redis: RedisServer, n: int, tag: str) -> None:
    """Pipeline n `ctscan:` keys onto one socket. One redis-cli per key would
    be ~n process spawns; the SCAN-walk tests need thousands of keys, so the
    SETs go out as a single RESP pipeline and only the reply count is checked."""
    with socket.create_connection(("127.0.0.1", redis.port), 5) as s:
        s.settimeout(20)
        # The scan endpoints are configured with db=7; this raw socket starts on
        # db 0, so it must SELECT the same db or the walk sees nothing.
        s.sendall(b"*2\r\n$6\r\nSELECT\r\n$1\r\n7\r\n")
        if not s.recv(4096).startswith(b"+OK"):
            raise RuntimeError("redis SELECT 7 failed")
        # Chunked, and each chunk's replies are drained before the next is sent:
        # one giant sendall() can deadlock against a peer that stops reading
        # once ITS output buffer to us is full.
        for base in range(0, n, 500):
            batch = range(base, min(base + 500, n))
            cmd = bytearray()
            for i in batch:
                args = (b"SET", f"ctscan:{tag}:{i}".encode(), b"v",
                        b"EX", b"300")
                cmd += b"*%d\r\n" % len(args)
                for a in args:
                    cmd += b"$%d\r\n%s\r\n" % (len(a), a)
            s.sendall(cmd)
            buf = b""
            while buf.count(b"\r\n") < len(batch):
                chunk = s.recv(65536)
                if not chunk:
                    raise RuntimeError("redis closed mid-pipeline")
                buf += chunk


def _scan_purge(ng: Nginx, loc: str) -> tuple[int, dict]:
    """POST an ?all=1 all-purge at `loc` and return (status, parsed JSON)."""
    s, b, _ = fetch(ng.port, f"{loc}?all=1", method="POST")
    return s, json.loads(b)


def test_scan_walk_pool_is_o1_in_pages(ng: Nginx, redis: RedisServer) -> None:
    """AUD-SCAN1 (a): the SCAN-based L2 all-purge must hold a CONSTANT amount of
    memory regardless of how many SCAN pages the walk takes.

    read_scan drove the whole cursor loop off ONE op pool: every page allocated
    a fresh keys array, a rebuilt SCAN command and (on a big reply) a doubled
    receive buffer out of it, and `op->rlen = 0` reset only the LENGTH -- nothing
    was released until the walk ended. A large keyspace therefore grew the worker
    monotonically for the whole purge.

    The oracle is `scan_pool_blocks` (TEST_FAULTS-only): the live pool blocks the
    walk still holds when it finishes. Two purges of the SAME keyspace shape, one
    short walk and one an order of magnitude longer, must report the same figure.
    Asserting an absolute number would be brittle across pool tunings and
    NGX_DEBUG_PALLOC builds; asserting that it does not TRACK page count is the
    actual property, and it is the one that fails when the per-page pool is
    removed (blocks then rise by at least one large block per page).

    No test drove a multi-page SCAN walk at all before this one -- the archived
    purge tests all fit inside a single COUNT 256 page."""
    # FLUSHDB, not a KEYS/DEL sweep: deleting keys leaves the db's hash table
    # sized for the biggest fill it ever held, and SCAN COUNT walks BUCKETS, so
    # a stale oversized table makes a 5-key walk span many pages.
    redis.cli("-n", "7", "FLUSHDB")

    _scan_fill(redis, 300, "small")
    s, small = _scan_purge(ng, "/_cache_scanwalk")
    assert s == 200, f"short walk should complete: {s} {small}"
    assert "l2" not in small, f"short walk reported incomplete: {small}"

    _scan_fill(redis, 6000, "big")
    s, big = _scan_purge(ng, "/_cache_scanwalk")
    assert s == 200, f"long walk should complete: {s} {big}"
    assert "l2" not in big, f"long walk reported incomplete: {big}"

    # The comparison is only meaningful if the two walks really differ in
    # length. Without this the blocks assertion is vacuous: two one-page walks
    # hold the same memory whether or not the pool is rotated.
    assert big["scan_pages"] >= small["scan_pages"] + 8, \
        f"the two walks were not different lengths: {small} vs {big}"

    # +2 of slack, not 0: the reply buffer is only re-grown on a page whose
    # reply exceeds 4 pagesize, so the two walks can legitimately differ by a
    # block or two. Pre-fix the gap is >= one block PER EXTRA PAGE.
    assert big["scan_pool_blocks"] <= small["scan_pool_blocks"] + 2, \
        ("AUD-SCAN1: walk memory tracks page count -- "
         f"{small['scan_pages']} pages held {small['scan_pool_blocks']} blocks, "
         f"{big['scan_pages']} pages held {big['scan_pool_blocks']}")


def test_all_purge_reports_l2_unavailable_when_backend_is_down(
        ng: Nginx, redis: RedisServer) -> None:
    """AUD-PURGE-HONESTY1: an all-purge whose L2 walk never STARTS must not
    answer a bare success.

    scan_del returning NGX_ERROR (connect refused, L2 never reached) used to
    fall through to the synchronous 200 {"purged":<L1 count>} -- on the wire
    that is indistinguishable from a purge that emptied both tiers. An operator
    purging before a config rollout reads 200 and believes L2 is empty; it is
    entirely intact. Same dishonesty class as AUD-SCAN1, which #174 fixed for
    the walk that STARTS and ends early. Contract chosen 2026-08-01: 500 plus an
    explicit "l2":"unavailable" -- non-2xx like the incomplete walk, a distinct
    value because nothing was walked at all.

    Two claims, and the first keeps the second from being vacuous:

      1. NEGATIVE CONTROL -- the SAME request shape against a LIVE L2
         (/_cache_scanwalk) answers 200 with no "l2" key. An endpoint that
         reported unavailable unconditionally would satisfy claim 2 while
         breaking every healthy purge.
      2. Against the dead backend the reply is 500 AND carries
         "l2":"unavailable". Asserting only "not 200" would pass on any
         unrelated error path (a 404 from a misspelled location, a 400 from a
         rejected arg), so both status and field are pinned.

    "purged" must still be present and numeric in the failure body: L1 really
    was purged, and dropping the count would understate what happened."""
    # 1. control: identical request shape, live backend
    redis.cli("-n", "7", "FLUSHDB")
    _scan_fill(redis, 5, "down-ctrl")
    s_ok, ok = _scan_purge(ng, "/_cache_scanwalk")
    assert s_ok == 200, f"control purge against a LIVE L2 failed: {s_ok} {ok}"
    assert "l2" not in ok, f"control purge reported an L2 problem: {ok}"
    redis.cli("-n", "7", "FLUSHDB")

    # 2. the claim: L2 down, nothing walked
    s, down = _scan_purge(ng, "/_cache_scandown")
    assert s == 500, \
        f"purge with L2 down must not report success: {s} {down}"
    assert down.get("l2") == "unavailable", \
        f"purge with L2 down did not disclose the L2 state: {down}"
    # "unavailable" must mean literally nothing was walked -- if a page had been
    # consumed, part of L2 WOULD be purged and "incomplete" is the honest word.
    assert down.get("scan_pages") == 0, \
        f"reported unavailable after walking pages: {down}"
    assert isinstance(down.get("purged"), int), \
        f"failure body dropped the L1 purge count: {down}"


def test_scan_walk_page_cap_reports_incomplete(ng: Nginx,
                                               redis: RedisServer) -> None:
    """AUD-SCAN1 (b): read_scan used to terminate ONLY on cursor "0". A backend
    that never returns it (broken, hostile, or simply a keyspace larger than the
    walk can finish) looped forever -- the per-page read timeout does not bound
    the walk, because each page's write re-arms the timer.

    The walk is now capped. Two claims, and the first is what keeps the second
    from being vacuous:

      1. NEGATIVE CONTROL -- a keyspace that fits inside the cap completes
         normally at the SAME endpoint (200, no "l2" key). A cap that fired on
         every purge would satisfy claim 2 while destroying the feature.
      2. Past the cap the request FINALIZES (no hang) and reports the purge as
         INCOMPLETE with a non-2xx status -- never as a success. Silently
         truncating and answering 200 would trade the memory bug for a
         correctness bug: the operator is told L2 is empty when it is not."""
    # FLUSHDB, not a KEYS/DEL sweep: deleting keys leaves the db's hash table
    # sized for the biggest fill it ever held, and SCAN COUNT walks BUCKETS, so
    # a stale oversized table makes a 5-key walk span many pages.
    redis.cli("-n", "7", "FLUSHDB")

    # 1. under the cap -> ordinary completion
    _scan_fill(redis, 5, "cap-ok")
    s, ok = _scan_purge(ng, "/_cache_scancap")
    assert s == 200, f"a walk inside the cap must complete: {s} {ok}"
    assert "l2" not in ok, f"cap fired on a one-page walk: {ok}"

    # 2. past the cap -> abandoned, reported INCOMPLETE
    _scan_fill(redis, 6000, "cap-over")
    s, over = _scan_purge(ng, "/_cache_scancap")
    assert s == 500, f"an abandoned purge must not report success: {s} {over}"
    assert over.get("l2") == "incomplete" and over.get("reason") == "page-cap", \
        f"abandoned purge did not report the page cap: {over}"
    assert over["scan_pages"] == 2, \
        f"walk did not stop AT the cap (2 pages): {over}"

    # The abandoned walk must have left L2 partially populated -- that is the
    # state the INCOMPLETE report exists to disclose. If everything were gone,
    # the report would be describing a purge that actually finished.
    assert int(redis.cli("-n", "7", "EVAL",
                         "return #redis.call('KEYS','ctscan:*')",
                         "0") or 0) > 0, \
        "cap-abandoned purge somehow emptied the keyspace"

    redis.cli("-n", "7", "FLUSHDB")


def test_scan_walk_deadline_reports_incomplete(ng: Nginx,
                                               redis: RedisServer) -> None:
    """S231-L2-SCANTIME: SCAN_MAX_PAGES bounds MEMORY, not TIME -- each page's
    read re-arms redis_timeout (redis.c:1766), so a backend that always hands
    back a non-zero cursor just under that timeout can park a purge request for
    up to SCAN_MAX_PAGES pages (hours), never tripping the page cap. A
    wall-clock deadline across the WHOLE walk, checked at every page boundary
    alongside the page cap, closes that gap.

    Oracle: this must NOT be "the purge finished" or "the request returned" --
    an ordinary fast SCAN reproduces both. The observable marker unique to this
    path is reason=="deadline" in the failure body (page-cap abandonment
    reports reason=="page-cap" at the same status/l2 values -- see
    test_scan_walk_page_cap_reports_incomplete). Two claims:

      1. NEGATIVE CONTROL -- the identical multi-page keyspace against
         /_cache_scandeadlineoff (scan_deadline=0, disabled) completes
         normally: 200, no "l2" key. Proves the deadline check itself, not
         some other abort path, is what fires below.
      2. Against /_cache_scandeadline (scan_deadline=1ms -- unmeetable by any
         real page round-trip) the walk is abandoned with reason=="deadline",
         distinct from "page-cap", at fewer than SCAN_MAX_PAGES pages."""
    redis.cli("-n", "7", "FLUSHDB")

    # 1. negative control: deadline disabled, same multi-page keyspace, same
    # location shape -> ordinary completion.
    _scan_fill(redis, 6000, "dl-ctrl")
    s_off, off = _scan_purge(ng, "/_cache_scandeadlineoff")
    assert s_off == 200, f"deadline=0 must not abort a normal walk: {s_off} {off}"
    assert "l2" not in off, f"disabled deadline still reported an L2 problem: {off}"
    redis.cli("-n", "7", "FLUSHDB")

    # 2. the claim: an unmeetable wall-clock deadline aborts the walk.
    _scan_fill(redis, 6000, "dl-over")
    s, over = _scan_purge(ng, "/_cache_scandeadline")
    assert s == 500, f"a deadline-abandoned purge must not report success: {s} {over}"
    assert over.get("l2") == "incomplete" and over.get("reason") == "deadline", \
        f"deadline abort did not report reason=deadline: {over}"
    # Distinct from the page-cap path: this location never lowers the page cap,
    # so an abort at a small page count can only be explained by the deadline.
    assert 0 < over.get("scan_pages", 0) < 100, \
        f"walk did not abort quickly on the deadline: {over}"
    assert isinstance(over.get("purged"), int), \
        f"failure body dropped the L1 purge count: {over}"

    # The abandoned walk must have left L2 partially populated, same disclosure
    # contract as the page-cap path.
    assert int(redis.cli("-n", "7", "EVAL",
                         "return #redis.call('KEYS','ctscan:*')",
                         "0") or 0) > 0, \
        "deadline-abandoned purge somehow emptied the keyspace"

    redis.cli("-n", "7", "FLUSHDB")
