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
from collections.abc import Callable
from dataclasses import dataclass

from test_runtime_base import Nginx, fetch_raw

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


class _Sweep(_FaultAlloc):
    """_FaultAlloc plus the per-URI helpers the sweep needs."""

    def get_uri(self, uri: str):
        try:
            return fetch_raw(self.port, uri)
        except (http.client.RemoteDisconnected, ConnectionResetError,
                http.client.BadStatusLine) as e:
            return (None, "", {"error": repr(e)})

    def count(self, scn: _Scenario, i: int) -> int:
        """Module allocations of one measured request, under a far arm."""
        uri = scn.uri(i)
        scn.ready(self, uri)
        self.ctl(f"?n={self.FAR}")
        st, _, h = self.get_uri(uri)
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


_SWEEP_URI_SEQ = [0]


def _fresh_miss_uri(i: int) -> str:
    del i
    _SWEEP_URI_SEQ[0] += 1
    return f"/fa/sweep-miss-{_SWEEP_URI_SEQ[0]}"


# PACKET 2 adds rows here (L2 HIT, L2 MISS+store, PURGE, admin status).
_SCENARIOS = (
    _Scenario("MISS", _fresh_miss_uri, _ready_nothing, measured_hit=False),
    _Scenario("L1 HIT", lambda i: "/fa/sweep-hit", _ready_hit,
              measured_hit=True),
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
    expect_body = sw.get_uri(uri)[1] if scn.measured_hit else None
    sw.ctl(f"?n={n}")
    st, body, h = sw.get_uri(uri)
    r = sw.ctl("?n=0")  # disarm before anything else allocates
    _assert_alive(fa, where)
    if r["fired"] == "1":
        assert r["fired_at"] == str(n), f"{where}: {r}"
    # 5xx, a dropped connection, or a clean decline (served in full).
    assert st is None or st >= 500 or st == 200, \
        f"{where}: unclean answer {st} {h}"
    if st == 200 and expect_body is not None:
        assert body == expect_body, f"{where}: declined answer has a wrong body"
    # Next normal request, fresh connection (fetch_raw opens one).
    st2, body2, h2 = sw.get_uri(uri)
    assert st2 == 200 and body2, \
        f"{where}: follow-up request not served: {st2} {h2}"
    if expect_body is not None:
        assert body2 == expect_body, f"{where}: follow-up body"
    return r["fired"] == "1"


def test_alloc_fail_sweep(ng: Nginx) -> None:
    """BP-C2: fail every module allocation of a MISS and of an L1 HIT in
    turn (see the module docstring for the per-step contract)."""
    fa = _fault_alloc_nginx(ng)
    fa.write_config()
    fa.config_test()
    fa.start()
    try:
        sw = _Sweep(fa.port)
        for scn in _SCENARIOS:
            count = _stable_count(sw, scn)
            assert count >= 5, \
                f"{scn.name}: implausibly few allocations: {count}"
            fired = sum(_step(sw, fa, scn, n, count) for n in _sweep_ns(count))
            print(f"alloc sweep {scn.name}: count={count} fired={fired}")
            # A step that never reaches its Nth call would hide a hole.
            assert fired >= count - 2, \
                f"{scn.name}: only {fired}/{count} injections fired"
        fa.stop()
        fa.assert_clean_logs()
    finally:
        fa.stop()
