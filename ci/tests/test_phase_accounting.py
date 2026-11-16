#!/usr/bin/env python3
"""CI-L10d-T0: opt-in per-test PHASE attribution under --timings.

The accounting lives in origin.py (PhaseAccounting, Origin handler hooks, the
time.sleep wrapper) and test_runtime_base.py (_instrument span, Nginx
start/reload/stop timing). These tests drive the REAL Origin server and the
REAL _instrument() wrapper; only the nginx lifecycle methods are replaced by
sleeping fakes so no nginx binary is needed.
"""

import contextlib
import http.client
import importlib
import io
import os
import pathlib
import re
import socket
import sys
import threading
import time
import types
import unittest
import urllib.request

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "ci" / "tools"))

import origin as origin_mod

_AREA = "areas._phase_selftest"


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get(port, path):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
            return r.status
    except (OSError, http.client.HTTPException):
        # the error control expects a reply dropped by the dying handler
        return None


class _Base(unittest.TestCase):
    def setUp(self):
        self._saved_sleep = time.sleep
        self._saved_phases = origin_mod.PHASES
        os.environ.pop("CT_TEST_BREADCRUMB", None)
        import test_runtime_base

        self.trb = importlib.reload(test_runtime_base)
        # Sleeping fakes: the real Nginx methods need a binary.
        self.trb.Nginx.start = lambda self_: time.sleep(0.05)
        self.trb.Nginx.reload = lambda self_, *a, **k: time.sleep(0.05)
        self.trb.Nginx.stop = lambda self_: time.sleep(0.05)
        self.port = _free_port()
        self.origin = origin_mod.Origin(self.port, delay=0.05)
        self.origin.start()
        self.mod = types.ModuleType(_AREA)
        sys.modules[_AREA] = self.mod

    def tearDown(self):
        sys.modules.pop(_AREA, None)
        try:
            self.origin.stop()
        finally:
            time.sleep = self._saved_sleep
            origin_mod.PHASES = self._saved_phases
            # Drop the sleeping Nginx fakes: a reload rebuilds the real class.
            importlib.reload(self.trb)

    def run_instrumented(self, timings, *tests):
        for fn in tests:
            setattr(self.mod, fn.__name__, fn)
        self.trb._instrument(self.origin, timings)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            for fn in tests:
                try:
                    getattr(self.mod, fn.__name__)()
                except RuntimeError:
                    pass
        return out.getvalue().splitlines()


def _parse(line):
    m = re.fullmatch(
        r"PHASE (\S+) origin_delay=([\d.]+)s gets=(\d+) sleeps=([\d.]+)s "
        r"lifecycle=([\d.]+)s", line)
    assert m, line
    return m.group(1), float(m.group(2)), int(m.group(3)), float(m.group(4)), float(m.group(5))


class TestPhasePositive(_Base):
    def test_known_test_reports_expected_counts(self):
        port = self.port
        nginx = self.trb.Nginx.__new__(self.trb.Nginx)

        def test_three_gets():
            for i in range(3):
                _get(port, f"/p{i}")
            time.sleep(0.2)
            nginx.start()
            nginx.reload()
            nginx.stop()

        def test_one_get():
            _get(port, "/solo")

        lines = self.run_instrumented([], test_three_gets, test_one_get)
        phases = {p[0]: p for p in map(_parse, [x for x in lines if x.startswith("PHASE ")])}
        _, delay, gets, sleeps, life = phases["test_three_gets"]
        self.assertEqual(gets, 3)
        self.assertGreaterEqual(delay, 0.15 - 0.01)
        self.assertGreaterEqual(sleeps, 0.2 - 0.01)
        # three fake lifecycle calls of 0.05s; their sleeps also appear in `sleeps`
        self.assertGreaterEqual(life, 0.15 - 0.01)
        # Attribution: the second span must not inherit the first span's GETs.
        self.assertEqual(phases["test_one_get"][2], 1)
        self.assertLess(phases["test_one_get"][4], 0.01)
        # PHASE follows its TIMING line, TIMING format unchanged.
        i = lines.index(next(x for x in lines if x.startswith("PHASE test_three_gets")))
        self.assertRegex(lines[i - 1], r"^TIMING test_three_gets \d+\.\d{6}s$")

    def test_nested_lifecycle_counted_once(self):
        nginx = self.trb.Nginx.__new__(self.trb.Nginx)
        # start() calls the (wrapped) stop() through the instance, as the real
        # start() does on a failed wait_port().
        self.trb.Nginx.start = lambda self_: (time.sleep(0.05), self_.stop())

        def test_nested():
            nginx.start()

        real_add = origin_mod.PhaseAccounting.add
        updates = []

        def spy(self_, **kw):
            if kw.get("lifecycle"):
                updates.append(kw["lifecycle"])
            return real_add(self_, **kw)

        origin_mod.PhaseAccounting.add = spy
        try:
            self.run_instrumented([], test_nested)
        finally:
            origin_mod.PhaseAccounting.add = real_add
        # Exactly one update, for the outer start(); a double count would add
        # a second one for the inner stop().
        self.assertEqual(len(updates), 1, f"lifecycle updates: {updates}")
        self.assertGreaterEqual(updates[0], 0.09)

    def test_thread_safe_totals(self):
        acct = origin_mod.PhaseAccounting()

        def work():
            for _ in range(500):
                acct.add(gets=1, origin_delay=0.001)

        threads = [threading.Thread(target=work) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        d, g, _, _ = acct.snapshot()
        self.assertEqual(g, 4000)
        self.assertAlmostEqual(d, 4.0, places=6)


class TestPhaseDisabled(_Base):
    def test_disabled_emits_nothing_and_patches_nothing(self):
        sleep_before = time.sleep
        origin_mod.PHASES = None
        port = self.port

        def test_a():
            _get(port, "/a")

        def test_b():
            time.sleep(0.01)

        lines = self.run_instrumented(None, test_a, test_b)
        self.assertEqual(lines, [])
        self.assertIsNone(origin_mod.PHASES)
        self.assertIs(time.sleep, sleep_before)
        self.assertFalse(getattr(self.trb.Nginx.start, "_ct_phase_wrapped", False))
        # same test inventory: both tests are wrapped exactly as with timings on
        self.assertTrue(getattr(self.mod.test_a, "_ct_instrumented", False))
        self.assertTrue(getattr(self.mod.test_b, "_ct_instrumented", False))

    def test_enabled_wraps_the_same_inventory(self):
        def test_a():
            pass

        def test_b():
            pass

        self.run_instrumented([], test_a, test_b)
        ns = vars(self.mod)
        wrapped = sorted(n for n in ns
                         if n.startswith("test_") and getattr(ns[n], "_ct_instrumented", False))
        self.assertEqual(wrapped, ["test_a", "test_b"])

    def test_workflow_runtime_step_turns_timings_on(self):
        # PHASE rides on --timings; the runtime step's tee'd log is the profile.
        text = (REPO / ".github" / "workflows" / "build-test.yml").read_text(encoding="utf-8")
        self.assertRegex(text, r"(?s)ci/tools/test_runtime\.py.*?--timings.*?runtime-suite\.log")


class TestPhaseError(_Base):
    def test_origin_handler_exception_still_counted(self):
        port = self.port

        def test_bad_handler():
            self.origin.delay = "bad"   # time.sleep("bad") raises in the handler thread
            with contextlib.redirect_stderr(io.StringIO()):
                _get(port, "/boom")
            self.origin.delay = 0.05

        lines = self.run_instrumented([], test_bad_handler)
        _, _, gets, _, _ = _parse(next(x for x in lines if x.startswith("PHASE ")))
        self.assertEqual(gets, 1, "GET that raised inside the handler was not reported")

    def test_failing_test_still_emits_phase(self):
        port = self.port

        def test_raises():
            _get(port, "/x")
            raise RuntimeError("test body failed")

        lines = self.run_instrumented([], test_raises)
        phase = [x for x in lines if x.startswith("PHASE test_raises ")]
        self.assertEqual(len(phase), 1)
        self.assertEqual(_parse(phase[0])[2], 1)


if __name__ == "__main__":
    unittest.main()
