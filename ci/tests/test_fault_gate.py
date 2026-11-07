#!/usr/bin/env python3
"""Tests for the pre-commit fault-injection capability gate
(CT-HOOK-AREA-FAULT-ONLY-TESTS).

- fault_only_tests.py derives the tests run_all() calls only under
  `if ng.fault_injection:`.
- precommit-tests.sh drops them (visible SKIP) on a build without the
  TEST_FAULTS define and passes --fault-injection on a build with it.
- lint-fault-gate.py fails when a selector does not gate an @area entry.

Selector cases run against a throwaway PRECOMMIT_ROOT with a stub nginx (whose
`-V` output decides fault capability) and a stub run_named.py that records its
argv, so no real build is needed.
"""

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
TOOLS = REPO / "ci" / "tools"
SELECTOR = TOOLS / "precommit-tests.sh"
LINT = TOOLS / "lint-fault-gate.py"
DERIVE = TOOLS / "fault_only_tests.py"

RUNTIME = '''
def run_all(ng, origin):
    test_plain(ng)
    if ng.fault_injection:
        test_fault_a(ng)
        test_fault_b(ng)
        test_also_plain(ng)
    else:
        test_else_branch(ng)
    test_also_plain(ng)
    if ng.fault_injection and ng.other:
        test_fault_and(ng)
    if ng.something_else:
        test_cond(ng)
'''
AREA = '''
def test_plain(ng):
    pass


def test_fault_a(ng):
    pass


def test_fault_b(ng):
    pass
'''
MAP = "ci/tools/areas/x.py\tbuild\t@area x\n"
STUB_RUN_NAMED = ("import sys\n"
                  "print('ARGV ' + ' '.join(sys.argv[1:]))\n")


def make_root(td, faults):
    root = pathlib.Path(td)
    (root / "ci/tools/areas").mkdir(parents=True)
    (root / "ci/tools/test_runtime.py").write_text(RUNTIME)
    (root / "ci/tools/areas/x.py").write_text(AREA)
    (root / "ci/tools/run_named.py").write_text(STUB_RUN_NAMED)
    (root / "ci/tools/precommit-test-map.tsv").write_text(MAP)
    objs = root / ".build" / "nginx-1.0.0" / "objs"
    objs.mkdir(parents=True)
    cc = "-DNGX_HTTP_CACHE_TURBO_TEST_FAULTS=1" if faults else "-O0"
    nginx = objs / "nginx"
    nginx.write_text("#!/bin/sh\necho \"configure arguments: "
                     f"--with-cc-opt='{cc}'\" >&2\n")
    nginx.chmod(0o755)
    return root


def run_sel(root, *args):
    env = dict(os.environ, PRECOMMIT_ROOT=str(root),
               PRECOMMIT_BUILD_DIR=str(root / ".build"))
    env.pop("PRECOMMIT_TESTS", None)
    return subprocess.run(["bash", str(SELECTOR), *args], capture_output=True,
                          text=True, env=env, check=False)


class Derive(unittest.TestCase):
    def test_fixture_set(self):
        with tempfile.TemporaryDirectory() as td:
            root = make_root(td, True)
            r = subprocess.run([sys.executable, str(DERIVE),
                                str(root / "ci/tools/test_runtime.py")],
                               capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        # not test_also_plain (also called ungated), not the else branch,
        # not a non-fault condition; an `and` containing the gate counts.
        self.assertEqual(r.stdout.split(),
                         ["test_fault_a", "test_fault_b", "test_fault_and"])

    def test_missing_run_all_is_error(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "t.py"
            p.write_text("def test_a(ng):\n    pass\n")
            r = subprocess.run([sys.executable, str(DERIVE), str(p)],
                               capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 2)

    def test_real_tree_nonempty(self):
        r = subprocess.run([sys.executable, str(DERIVE),
                            str(TOOLS / "test_runtime.py")],
                           capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("test_alloc_fail_sweep", r.stdout.split())


class Selector(unittest.TestCase):
    def test_no_fault_build_skips_fault_only_visibly(self):
        with tempfile.TemporaryDirectory() as td:
            root = make_root(td, False)
            r = run_sel(root, "--files", "ci/tools/areas/x.py")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("SKIP fault-only test_fault_a", r.stdout)
        self.assertIn("SKIP fault-only test_fault_b", r.stdout)
        argv = next(l for l in r.stdout.splitlines() if l.startswith("ARGV"))
        self.assertIn("test_plain", argv)
        self.assertNotIn("test_fault", argv)
        self.assertNotIn("--fault-injection", argv)

    def test_fault_build_runs_them_with_flag(self):
        with tempfile.TemporaryDirectory() as td:
            root = make_root(td, True)
            r = run_sel(root, "--files", "ci/tools/areas/x.py")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("SKIP", r.stdout)
        argv = next(l for l in r.stdout.splitlines() if l.startswith("ARGV"))
        self.assertIn("--fault-injection", argv)
        for name in ("test_plain", "test_fault_a", "test_fault_b"):
            self.assertIn(name, argv)

    def test_derivation_failure_fails_not_ungated(self):
        with tempfile.TemporaryDirectory() as td:
            root = make_root(td, False)
            (root / "ci/tools/test_runtime.py").write_text("x = 1\n")
            r = run_sel(root, "--files", "ci/tools/areas/x.py")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("ARGV", r.stdout)

    def test_dry_run_reports_fault_only_count(self):
        with tempfile.TemporaryDirectory() as td:
            root = make_root(td, False)
            r = run_sel(root, "--dry-run", "--files", "ci/tools/areas/x.py")
        self.assertIn("fault-only=2", r.stdout)


class Lint(unittest.TestCase):
    def lint(self, root, selector=None):
        cmd = [sys.executable, str(LINT), "--root", str(root)]
        if selector:
            cmd += ["--selector", str(selector)]
        return subprocess.run(cmd, capture_output=True, text=True, check=False)

    def fixture_with_selector(self, td):
        return make_root(td, False)

    def test_real_tree_green(self):
        r = subprocess.run([sys.executable, str(LINT)], capture_output=True,
                           text=True, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("OK", r.stdout)

    def test_gated_selector_green_on_fixture(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.fixture_with_selector(td)
            r = self.lint(root, SELECTOR)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_ungated_selector_red_names_area_and_tests(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.fixture_with_selector(td)
            stub = root / "ungated.sh"
            stub.write_text('#!/bin/bash\n'
                            'echo "PLAN [build] run_named.py '
                            'ci/tools/areas/x.py (3 tests)"\n')
            r = self.lint(root, stub)
        self.assertEqual(r.returncode, 1)
        self.assertIn("@area x", r.stderr)
        self.assertIn("test_fault_a", r.stderr)
        self.assertIn("test_fault_b", r.stderr)

    def test_empty_derivation_red(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.fixture_with_selector(td)
            (root / "ci/tools/test_runtime.py").write_text(
                "def run_all(ng, origin):\n    test_plain(ng)\n")
            r = self.lint(root, SELECTOR)
        self.assertEqual(r.returncode, 1)
        self.assertIn("no fault-only", r.stderr)


if __name__ == "__main__":
    unittest.main()
