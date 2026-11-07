"""BP-C2: allocation-failure sweep.

For each scenario, count the module allocations of one request (the BP-C1
fault_alloc funnel, ``fault_alloc=0`` = count only), then fail allocation
N = 1..count in turn. Every step must leave nginx alive and sanitizer-clean,
answer the failed request with a 5xx, a clean decline (the request falls
through to the origin and is served in full) or a dropped connection, and
serve the next normal request on a fresh connection.

The scenario table is the extension point: a row is a ``_Scenario`` with a
name, a ``uri`` factory (called once per step, so a MISS row can hand out a
fresh key every time), a ``ready`` hook that puts the cache into the state the
measured request needs, and the ``measured_hit`` flag (does a clean request
for the row report X-Cache: HIT). Hit rows also take the expected body from
``probe`` or ``_Sweep.expect``.

Sampling: by default (PR mode) each row fails a seeded, deterministic sample of
N (always N=1 and N=count) so the whole sweep stays within ~60 s on the ASan
build; the seed is printed in the summary and overridable with
CT_ALLOC_SWEEP_SEED. ``CT_ALLOC_SWEEP=full`` fails every N.

The sweep runs its own nginx root (``fault-alloc-sweep``), so its error log is
never shared with test_fault_alloc_countdown, which asserts on exact notices
in its own log: the two pass in either order in one process.
"""

from __future__ import annotations

import http.client
import os
import random
import time
from collections.abc import Callable
from dataclasses import dataclass

from test_runtime_base import (
    Nginx,
    RedisServer,
    fetch_raw,
    l2_key,
    lock_key,
    wait_for,
    wait_for_l2_absent,
)

from areas.core import _fault_alloc_config, _fault_alloc_nginx, _FaultAlloc

# Per-row sample size in PR mode, besides the always-included N=1 and N=count.
_PR_SAMPLE = 10
_DEFAULT_SEED = "1"


@dataclass
class _Scenario:
    name: str
    # uri for step ``i`` (i = 0 is the measuring run); a MISS row returns a
    # fresh key every call, a HIT row returns the same primed one.
    uri: Callable[[int], str]
    # Bring the cache to the state the request under test needs.
    ready: Callable[[_Sweep, str], None]
    # Does a clean (unarmed) request for this scenario report X-Cache: HIT?
    measured_hit: bool
    # HTTP method of the measured request (PURGE for the purge row).
    method: str = "GET"
    # True: take the expected body from a clean extra request (an L1 HIT).
    # False: ``ready`` records it in ``_Sweep.expect`` (an L2 HIT, where the
    # extra request would promote the entry to L1 and change the path).
    probe: bool = True
    # False: a declined L2 consult falls through to the origin, whose body is
    # a new generation, so a 200 only has to carry a body, not the L2 one.
    strict_body: bool = True
    # Needs the Redis fixture and the /fa2/ L2 location.
    needs_l2: bool = False
    # Request headers of every request of the row (the key-cookie row).
    headers: dict[str, str] | None = None
    # X-Cache the unarmed measured request must report, when the row only
    # reaches its target path in one state (stale-if-error).
    expect_xcache: str | None = None


class _Sweep(_FaultAlloc):
    """_FaultAlloc plus the per-URI helpers the sweep needs."""

    redis: RedisServer | None = None

    def __init__(self, port: int) -> None:
        super().__init__(port)
        self.expect: dict[str, str] = {}
        self.slow: list[str] = []  # follow-ups that waited out a lock
        # PURGE follow-ups that stalled after the PURGE itself reported the
        # failure (non-200: the dropped lock DEL left a previous fill's lock,
        # bounded by lock_timeout). Reported, not failed: the caller was told.
        # A PURGE that answered 200 with a key left already failed in
        # assert_purge_l2_state (CT-PURGE-L2-DEL-SILENT).
        self.purge_lock_left: list[str] = []

    def get_uri(self, uri: str, method: str = "GET",
                headers: dict[str, str] | None = None):
        try:
            return fetch_raw(self.port, uri, method=method, headers=headers)
        except (http.client.RemoteDisconnected, ConnectionResetError,
                http.client.BadStatusLine) as e:
            return (None, "", {"error": repr(e)})

    def count(self, scn: _Scenario, i: int) -> int:
        """Module allocations of one measured request, under a far arm."""
        uri = scn.uri(i)
        scn.ready(self, uri)
        self.ctl(f"?n={self.FAR}")
        try:
            st, _, h = self.get_uri(uri, scn.method, scn.headers)
        finally:
            r = self.ctl("?n=0")  # never leave the far arm set
        assert st == 200, f"{scn.name}: unarmed count run: {st} {h}"
        assert r["fired"] == "0", f"{scn.name}: far arm fired: {r}"
        assert scn.expect_xcache is None \
            or h.get("x-cache") == scn.expect_xcache, \
            f"{scn.name}: wanted X-Cache {scn.expect_xcache}, got {h}"
        calls = int(r["calls"])
        assert calls > 0, f"{scn.name}: request made no funnel call: {r}"
        return calls

    def assert_purge_l2_state(self, scn: _Scenario, uri: str, st: int | None,
                              where: str) -> None:
        """CT-PURGE-L2-DEL-SILENT: a PURGE that answers 200 has handed BOTH
        L2 DELs (object key and lock key) to the transport, so neither key may
        survive; a PURGE whose DEL was dropped before the wire answers 503
        (any 5xx / dropped connection is also acceptable, it did not claim
        success). The DELs are fire-and-forget, so give them a moment to
        land before judging. Asserted by key state, not by allocation index,
        so the seeded PR-mode sample needs no fixed N."""
        redis = self.redis
        if scn.method != "PURGE" or redis is None or st != 200:
            return
        assert wait_for(lambda: redis.get_raw(l2_key(uri)) is None,
                        timeout=1.0), \
            f"{where}: PURGE answered 200 but the L2 object key is left"
        assert wait_for(lambda: redis.get_raw(lock_key(uri)) is None,
                        timeout=1.0), \
            f"{where}: PURGE answered 200 but the L2 lock key is left"

    def note_stall(self, n: int, r: dict[str, str], scn: _Scenario,
                   st: int | None) -> None:
        """Record a follow-up that waited out a lock, with its fault site.
        Only a PURGE that did not answer 200 is tolerated; every other stall
        is a failure."""
        site = r.get("site", "-").rsplit("/", 1)[-1]
        tolerated = scn.method == "PURGE" and st != 200
        (self.purge_lock_left if tolerated else self.slow).append(
            f"N={n}@{site}")


def _ready_nothing(sw: _Sweep, uri: str) -> None:
    del sw, uri


def _ready_hit(sw: _Sweep, uri: str) -> None:
    """Make uri a cached entry: fill it, then confirm a clean HIT."""
    for _ in range(4):
        st, _, h = sw.get_uri(uri)
        if st == 200 and h.get("x-cache") == "HIT":
            return
    raise AssertionError(f"could not prime a HIT for {uri}")


def _ready_l2_only(sw: _Sweep, uri: str) -> None:
    """Leave uri in Redis (L2) only: fill both tiers through the module, take
    the blob, PURGE (L2-aware: empties both tiers), put the blob back. The
    measured request is then an L1 miss that L2 answers."""
    assert sw.redis is not None
    st, body, _ = sw.get_uri(uri)
    assert st == 200, f"L2 fill of {uri}: {st}"
    key = l2_key(uri)
    assert wait_for(lambda: sw.redis.get_raw(key) is not None, timeout=10), \
        f"write-through of {uri} never reached L2"
    blob = sw.redis.get_raw(key)
    assert blob is not None
    st, _, h = sw.get_uri(uri, "PURGE")
    assert st == 200, f"PURGE of {uri}: {st} {h}"
    wait_for_l2_absent(sw.redis, key, what=uri)
    sw.redis.set_raw(key, blob, 60_000)
    sw.expect[uri] = body


def _ready_sie(sw: _Sweep, uri: str) -> None:
    """Stale-if-error row: store uri's key through the live origin (its path
    carries the "sieserve" marker: stale-if-error=30, fresh 1s, stale window
    1s), then let it expire. The measured request goes to a location with the
    same key and a dead upstream, so the revalidation fails and the module
    rewrites the 502 into the stored snapshot (sie_rewrite)."""
    key = uri.split("k=", 1)[1]
    st, _, h = sw.get_uri(f"/fa-sieprime/{key}?k={key}")
    assert st == 200, f"stale-if-error prime of {key}: {st} {h}"
    time.sleep(1.4)  # past fresh (1s) and the stale window (mult 1)


def _ready_purge(sw: _Sweep, uri: str) -> None:
    """A cached entry (L1 and L2) for the PURGE under test to remove."""
    assert sw.redis is not None
    st, _, _ = sw.get_uri(uri)
    assert st == 200, f"fill of {uri}: {st}"
    assert wait_for(lambda: sw.redis.get_raw(l2_key(uri)) is not None,
                    timeout=10), f"write-through of {uri} never reached L2"


_SWEEP_URI_SEQ = [0]


def _fresh_uri(prefix: str) -> Callable[[int], str]:
    def make(i: int) -> str:
        del i
        _SWEEP_URI_SEQ[0] += 1
        return f"{prefix}{_SWEEP_URI_SEQ[0]}"
    return make


def _fresh_sie_uri(i: int) -> str:
    del i
    _SWEEP_URI_SEQ[0] += 1
    return f"/fa-sie/x?k=sieserve-{_SWEEP_URI_SEQ[0]}"


_SCENARIOS = (
    _Scenario("MISS", _fresh_uri("/fa/sweep-miss-"), _ready_nothing,
              measured_hit=False),
    _Scenario("L1 HIT", lambda i: "/fa/sweep-hit", _ready_hit,
              measured_hit=True),
    _Scenario("L2 HIT", _fresh_uri("/fa2/sweep-l2hit-"), _ready_l2_only,
              measured_hit=True, probe=False, strict_body=False,
              needs_l2=True),
    _Scenario("L2 MISS+store", _fresh_uri("/fa2/sweep-l2miss-"),
              _ready_nothing, measured_hit=False, needs_l2=True),
    _Scenario("PURGE", _fresh_uri("/fa2/sweep-purge-"), _ready_purge,
              measured_hit=False, method="PURGE", needs_l2=True),
    # CT-ALLOC-FUNNEL-INLINE-INIT: the key-cookie slot array (module.c).
    _Scenario("key cookie", _fresh_uri("/fa-kc/sweep-kc-"), _ready_nothing,
              measured_hit=False, headers={"Cookie": "seg=aaaa1111bbbb2222"}),
    # CT-ALLOC-FUNNEL-INLINE-INIT: stale-if-error rewrite (sie_rewrite).
    _Scenario("stale-if-error", _fresh_sie_uri, _ready_sie,
              measured_hit=False, strict_body=False,
              expect_xcache="STALE-IF-ERROR"),
    # GET of the admin stats endpoint (cache_turbo_admin fa).
    _Scenario("admin status", lambda i: "/fa-admin", _ready_nothing,
              measured_hit=False),
)


def _stable_count(sw: _Sweep, scn: _Scenario) -> int:
    """The first requests after a fill do one-off work (HIT: 25 then 19), so
    the count is taken once two measurements in a row agree."""
    counts = [sw.count(scn, 0), sw.count(scn, 1)]
    while counts[-1] != counts[-2]:
        assert len(counts) < 6, \
            f"{scn.name}: allocation count unstable: {counts}"
        counts.append(sw.count(scn, len(counts)))
    return counts[-1]


def _sweep_ns(name: str, count: int, seed: str, full: bool) -> list[int]:
    """The N values to fail: all of 1..count in full mode, otherwise N=1,
    N=count and a seeded sample of the rest (deterministic per seed+row)."""
    if full or count <= _PR_SAMPLE + 2:
        return list(range(1, count + 1))
    rng = random.Random(f"{seed}:{name}")
    mid = rng.sample(range(2, count), _PR_SAMPLE)
    return sorted({1, count, *mid})


def _assert_alive(fa: Nginx, where: str) -> None:
    assert fa.process is not None and fa.process.poll() is None, \
        f"{where}: nginx exited"
    log = (fa.root / "logs" / "error.log").read_text(encoding="utf-8",
                                                    errors="replace")
    assert "exited on signal" not in log, f"{where}: a worker crashed"
    fa.assert_clean_logs()


def _step(sw: _Sweep, fa: Nginx, scn: _Scenario, n: int, count: int) -> bool:
    """Fail allocation n of one request; True if the injection fired."""
    where = f"{scn.name} N={n}/{count}"
    uri = scn.uri(n)
    scn.ready(sw, uri)
    expect_body = None
    if scn.measured_hit:
        expect_body = (sw.get_uri(uri, "GET", scn.headers)[1] if scn.probe
                       else sw.expect[uri])
    sw.ctl(f"?n={n}")
    try:
        st, body, h = sw.get_uri(uri, scn.method, scn.headers)
    except TimeoutError:
        sw.ctl("?n=0")
        raise AssertionError(f"{where}: request hung") from None
    r = sw.ctl("?n=0")  # disarm before anything else allocates
    _assert_alive(fa, where)
    if r["fired"] == "1":
        assert r["fired_at"] == str(n), f"{where}: {r}"
    # 5xx, a dropped connection, or a clean decline (served in full).
    assert st is None or st >= 500 or st == 200, \
        f"{where}: unclean answer {st} {h}"
    if st == 200 and expect_body is not None and scn.strict_body:
        assert body == expect_body, f"{where}: declined answer has a wrong body"
    sw.assert_purge_l2_state(scn, uri, st, where)
    # Next normal request, fresh connection (fetch_raw opens one).
    t0 = time.monotonic()
    try:
        st2, body2, h2 = sw.get_uri(uri, "GET", scn.headers)
    except TimeoutError:
        raise AssertionError(f"{where}: follow-up request hung") from None
    if time.monotonic() - t0 > 0.9:
        sw.note_stall(n, r, scn, st)
    assert st2 == 200 and body2, \
        f"{where}: follow-up request not served: {st2} {h2}"
    if expect_body is not None and scn.strict_body:
        assert body2 == expect_body, f"{where}: follow-up body"
    return r["fired"] == "1"


def _fault_alloc_l2_nginx(ng: Nginx, redis_port: int | None) -> Nginx:
    """The BP-C1 fault nginx plus /fa2/: the same zone with a Redis L2 and
    PURGE enabled (core.py's config has neither)."""
    base = _fault_alloc_nginx(ng)
    # Own root (and so error log): see the module docstring.
    root = ng.root.parent / "fault-alloc-sweep"
    fa = Nginx(ng.binary, ng.module, root, base.port, ng.origin_port,
               ng.runner_raw, ng.single_process)

    def write_config(sr_off: bool = False) -> None:
        del sr_off
        (root / "conf").mkdir(parents=True, exist_ok=True)
        (root / "logs").mkdir(parents=True, exist_ok=True)
        text = _fault_alloc_config(root, fa.port, fa.module, fa.origin_port)
        conf = root / "conf" / "nginx.conf"
        anchor = "        location /fa/ {"
        assert text.count(anchor) == 1, "fault config layout changed"
        admin = """        location = /fa-admin {
            cache_turbo_admin fa;
        }

"""
        # CT-ALLOC-FUNNEL-INLINE-INIT rows. /fa-kc/ folds a cookie into the
        # key. /fa-sieprime/ stores a stale-if-error entry from the origin
        # under key $arg_k; /fa-sie/ shares that key but its upstream is a
        # closed port, so once the entry expires the revalidation fails and
        # the stored snapshot replaces the 502. keep_stale is off, else the
        # 24h default would serve the expired entry before the rewrite runs.
        admin += f"""        location /fa-kc/ {{
            cache_turbo          fa;
            cache_turbo_key      $uri;
            cache_turbo_key_cookie seg;
            cache_turbo_valid    300s;
            proxy_pass http://127.0.0.1:{fa.origin_port}/;
        }}

        location /fa-sieprime/ {{
            cache_turbo          fa;
            cache_turbo_key      $arg_k;
            cache_turbo_valid    1s;
            cache_turbo_stale_mult 1;
            cache_turbo_keep_stale off;
            proxy_pass http://127.0.0.1:{fa.origin_port}/;
        }}

        location /fa-sie/ {{
            cache_turbo          fa;
            cache_turbo_key      $arg_k;
            cache_turbo_valid    1s;
            cache_turbo_stale_mult 1;
            cache_turbo_keep_stale off;
            proxy_pass http://127.0.0.1:1/;
        }}

"""
        l2 = admin
        if redis_port is not None:
            l2 += f"""        location /fa2/ {{
            cache_turbo          fa;
            cache_turbo_key      $uri;
            cache_turbo_valid    300s;
            cache_turbo_purge    on;
            # An injected failure after the cross-node lock is taken leaves
            # that lock held; the next cold miss then waits lock_timeout (5s
            # by default = the client timeout) before going to the origin. A
            # 1s wait keeps that bounded stall inside the follow-up budget.
            cache_turbo_lock_timeout 1s;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=1s;
            proxy_pass http://127.0.0.1:{fa.origin_port}/;
        }}

"""
        conf.write_text(text.replace(anchor, l2 + anchor), encoding="ascii")

    fa.write_config = write_config  # type: ignore[method-assign]
    return fa


def test_alloc_fail_sweep(ng: Nginx, redis: RedisServer | None = None) -> None:
    """BP-C2: fail every module allocation of a MISS, an L1 HIT, an L2 HIT,
    an L2 MISS+store and a PURGE in turn (see the module docstring for the
    per-step contract). The L2 rows need the Redis fixture and are skipped,
    loudly, without it."""
    fa = _fault_alloc_l2_nginx(ng, redis.port if redis is not None else None)
    full = os.environ.get("CT_ALLOC_SWEEP", "") == "full"
    seed = os.environ.get("CT_ALLOC_SWEEP_SEED") or _DEFAULT_SEED
    t_start = time.monotonic()
    fa.write_config()
    fa.config_test()
    fa.start()
    try:
        sw = _Sweep(fa.port)
        sw.redis = redis
        for scn in _SCENARIOS:
            if scn.needs_l2 and redis is None:
                print(f"alloc sweep {scn.name}: SKIPPED (no redis fixture)")
                continue
            count = _stable_count(sw, scn)
            assert count >= 5, \
                f"{scn.name}: implausibly few allocations: {count}"
            ns = _sweep_ns(scn.name, count, seed, full)
            fired = sum(_step(sw, fa, scn, n, count) for n in ns)
            print(f"alloc sweep {scn.name}: count={count} tried={len(ns)} "
                  f"fired={fired} mode={'full' if full else 'pr'} "
                  f"seed={seed} lock-stalled follow-ups: "
                  f"{sw.slow or 'none'}"
                  + (f" purge-reported-failure stalls (tolerated): "
                     f"{sw.purge_lock_left}" if sw.purge_lock_left else ""))
            # CT-ALLOC-FAIL-LOCK-HELD: a winner whose store fails releases
            # its cross-node lock, so no follow-up may wait it out.
            assert not sw.slow, \
                f"{scn.name}: follow-ups waited out a held cross-node lock " \
                f"(lock_timeout): {sw.slow}"
            sw.purge_lock_left.clear()
            # A step that never reaches its Nth call would hide a hole.
            assert fired >= len(ns) - 2, \
                f"{scn.name}: only {fired}/{len(ns)} injections fired"
        print(f"alloc sweep total: {time.monotonic() - t_start:.1f}s "
              f"mode={'full' if full else 'pr'} seed={seed}")
        fa.stop()
        fa.assert_clean_logs()
    finally:
        fa.stop()
