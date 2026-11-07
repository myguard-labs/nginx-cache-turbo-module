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
measured request needs, and the stable ``expect_x_cache`` of the follow-up.
"""

from __future__ import annotations

import http.client
import time
from collections.abc import Callable
from dataclasses import dataclass

from test_runtime_base import (
    Nginx,
    RedisServer,
    fetch_raw,
    l2_key,
    wait_for,
    wait_for_l2_absent,
)

from areas.core import _fault_alloc_nginx, _FaultAlloc


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


class _Sweep(_FaultAlloc):
    """_FaultAlloc plus the per-URI helpers the sweep needs."""

    redis: RedisServer | None = None

    def __init__(self, port: int) -> None:
        super().__init__(port)
        self.expect: dict[str, str] = {}
        self.slow: list[str] = []  # follow-ups that waited out a lock

    def get_uri(self, uri: str, method: str = "GET"):
        try:
            return fetch_raw(self.port, uri, method=method)
        except (http.client.RemoteDisconnected, ConnectionResetError,
                http.client.BadStatusLine) as e:
            return (None, "", {"error": repr(e)})

    def count(self, scn: _Scenario, i: int) -> int:
        """Module allocations of one measured request, under a far arm."""
        uri = scn.uri(i)
        scn.ready(self, uri)
        self.ctl(f"?n={self.FAR}")
        st, _, h = self.get_uri(uri, scn.method)
        r = self.ctl("?n=0")
        assert st == 200, f"{scn.name}: unarmed count run: {st} {h}"
        assert r["fired"] == "0", f"{scn.name}: far arm fired: {r}"
        calls = int(r["calls"])
        assert calls > 0, f"{scn.name}: request made no funnel call: {r}"
        return calls


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


# PACKET 2b adds the L2 HIT, L2 MISS+store and PURGE rows; 2c adds admin
# status and the seeded PR sample.
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


def _sweep_ns(count: int) -> list[int]:
    """The N values to fail. Packet 2 swaps in the seeded PR sample."""
    return list(range(1, count + 1))


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
        expect_body = (sw.get_uri(uri)[1] if scn.probe
                       else sw.expect[uri])
    sw.ctl(f"?n={n}")
    try:
        st, body, h = sw.get_uri(uri, scn.method)
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
    # Next normal request, fresh connection (fetch_raw opens one).
    t0 = time.monotonic()
    try:
        st2, body2, h2 = sw.get_uri(uri)
    except TimeoutError:
        raise AssertionError(f"{where}: follow-up request hung") from None
    if time.monotonic() - t0 > 0.9:
        sw.slow.append(f"N={n}")
    assert st2 == 200 and body2, \
        f"{where}: follow-up request not served: {st2} {h2}"
    if expect_body is not None and scn.strict_body:
        assert body2 == expect_body, f"{where}: follow-up body"
    return r["fired"] == "1"


def _fault_alloc_l2_nginx(ng: Nginx, redis_port: int) -> Nginx:
    """The BP-C1 fault nginx plus /fa2/: the same zone with a Redis L2 and
    PURGE enabled (core.py's config has neither)."""
    fa = _fault_alloc_nginx(ng)
    base_write = fa.write_config

    def write_config(sr_off: bool = False) -> None:
        base_write(sr_off)
        conf = fa.root / "conf" / "nginx.conf"
        text = conf.read_text(encoding="ascii")
        anchor = "        location /fa/ {"
        assert text.count(anchor) == 1, "fault config layout changed"
        l2 = f"""        location /fa2/ {{
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
    fa = (_fault_alloc_l2_nginx(ng, redis.port) if redis is not None
          else _fault_alloc_nginx(ng))
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
            fired = sum(_step(sw, fa, scn, n, count) for n in _sweep_ns(count))
            print(f"alloc sweep {scn.name}: count={count} fired={fired} "
                  f"lock-stalled follow-ups: {sw.slow or 'none'}")
            sw.slow.clear()
            # A step that never reaches its Nth call would hide a hole.
            assert fired >= count - 2, \
                f"{scn.name}: only {fired}/{count} injections fired"
        fa.stop()
        fa.assert_clean_logs()
    finally:
        fa.stop()
