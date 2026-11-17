"""Exercise the stale-marker test oracle without a native nginx build.

The cache transport supplies the two allowed background-refresh schedules;
origin requests and persistent path counters use the real HTTP fixture.
"""

import __future__

import ast
import importlib.util
import threading
import unittest
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "ci/tools/areas/policy.py"
SPEC = importlib.util.spec_from_file_location(
    "stale_refresh_origin", ROOT / "ci/tools/origin.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load the origin fixture")
origin_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(origin_module)


def stale_marker_test(fetch, sleep):
    # Execute the actual function while excluding unrelated runtime imports.
    tree = ast.parse(POLICY.read_text())
    function = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef)
                    and node.name == "test_auto_vary_stale_marker_reachable")
    namespace = {"fetch": fetch, "time": SimpleNamespace(sleep=sleep)}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(POLICY),
                 "exec", flags=__future__.annotations.compiler_flag), namespace)
    return namespace[function.name]


class StaleMarkerOracleTests(unittest.TestCase):
    def run_schedule(self, *, refresh_before, stale_header="STALE"):
        origin = origin_module.Origin(0)
        # The server binds port 0 before starting its thread; use its assigned
        # port rather than probing the literal port 0 in Origin.start().
        with mock.patch.object(origin_module, "wait_port"):
            origin.start()
        self.addCleanup(origin.stop)
        port = origin._server.server_address[1]
        release = threading.Event()
        calls = []
        sleep = mock.Mock()
        cached_body = None
        pending = None

        def origin_get():
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/m?v=ua", timeout=5) as response:
                return response.read().decode()

        def refresh():
            if not release.wait(5):
                raise AssertionError("refresh schedule was not released")
            return origin_get()

        with ThreadPoolExecutor(max_workers=1) as executor:
            def fetch(_port, path, headers=None):
                nonlocal cached_body, pending
                self.assertEqual(path, "/avs1/m?v=ua")
                self.assertEqual(headers,
                                 {"User-Agent": "Mozilla/5.0 (iPhone; CPU) Mobile"})
                calls.append(path)
                if len(calls) == 1:
                    cached_body = origin_get()
                    return 200, cached_body, {}
                if len(calls) == 2:
                    return 200, cached_body, {"x-cache": "HIT"}
                self.assertEqual(len(calls), 3)
                if stale_header is None:
                    # Model the stale-marker guard rejecting its stale marker:
                    # the base key misses and the origin supplies the response.
                    return 200, origin_get(), {}
                pending = executor.submit(refresh)
                if refresh_before:
                    release.set()
                    pending.result(timeout=5)
                return 200, cached_body, {"x-cache": stale_header}

            try:
                stale_marker_test(fetch, sleep)(SimpleNamespace(port=0), origin)
                self.assertEqual(origin.hits_for("/m?v=ua"),
                                 2 if refresh_before else 1)
            finally:
                release.set()
                if pending is not None:
                    pending.result(timeout=5)
        self.assertEqual(origin.hits_for("/m?v=ua"), 2)
        self.assertEqual(len(calls), 3)
        sleep.assert_called_once_with(1.3)

    def test_refresh_before_assertion(self):
        self.run_schedule(refresh_before=True)

    def test_refresh_after_assertion(self):
        self.run_schedule(refresh_before=False)

    def test_missing_stale_marker_rejected(self):
        with self.assertRaisesRegex(
                AssertionError, "base-key fallback missed to origin"):
            self.run_schedule(refresh_before=True, stale_header=None)

    def test_fresh_hit_is_not_a_stale_marker_proof(self):
        with self.assertRaisesRegex(
                AssertionError, "a stale-but-serveable variant must stay reachable"):
            self.run_schedule(refresh_before=True, stale_header="HIT")


if __name__ == "__main__":
    unittest.main()
