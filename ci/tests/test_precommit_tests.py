#!/usr/bin/env python3
"""Tests for the pre-commit test selector and its map-completeness lint (CI-P4).

The selector (ci/tools/precommit-tests.sh) must run ONLY the tests the reviewed
map names for the changed paths, SKIP loudly when a needed build is missing
(and fail under PRECOMMIT_TESTS=require), and never fall back to a whole suite.
The lint (ci/tools/lint-precommit-map.py) must fail when a src/*.c has no row.

Selector cases run against a throwaway repo root (PRECOMMIT_ROOT) with a
purpose-built map whose commands just echo a marker, so "ran / did not run" is
observable without any build. Real-map cases use --dry-run only.
"""

import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
SELECTOR = REPO / "ci" / "tools" / "precommit-tests.sh"
LINT = REPO / "ci" / "tools" / "lint-precommit-map.py"
REAL_MAP = REPO / "ci" / "tools" / "precommit-test-map.tsv"


def sh(*args, root=None, env=None, cwd=None):
    e = dict(os.environ)
    e.pop("PRECOMMIT_TESTS", None)
    if root is not None:
        e["PRECOMMIT_ROOT"] = str(root)
        e["PRECOMMIT_BUILD_DIR"] = str(root / ".build")
    e.update(env or {})
    return subprocess.run(
        ["bash", str(SELECTOR), *args],
        capture_output=True, text=True, env=e, cwd=cwd, check=False,
    )


class FakeRepo(unittest.TestCase):
    MAP = (
        "# comment\n"
        "src/a.c\tnone\techo RAN-A\n"
        "src/b.c\tnone\techo RAN-B\n"
        "src/a.c|src/b.c\tnone\techo RAN-SHARED\n"
        "src/needs_build.c\tbuild\techo RAN-BUILD\n"
        "ci/linter/*\tnone\techo RAN-LINTER\n"
        "src/bad.c\tnone\tfalse\n"
    )

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.root = pathlib.Path(self._td.name)
        (self.root / "map.tsv").write_text(self.MAP)

    def run_sel(self, *files, **kw):
        return sh("--map", str(self.root / "map.tsv"), "--files", *files,
                  root=self.root, **kw)

    def test_mapped_runs_only_its_rows(self):
        r = self.run_sel("src/a.c")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("RAN-A", r.stdout)
        self.assertIn("RAN-SHARED", r.stdout)
        self.assertNotIn("RAN-B", r.stdout)
        self.assertNotIn("RAN-LINTER", r.stdout)

    def test_duplicate_selection_runs_once(self):
        r = self.run_sel("src/a.c", "src/b.c")
        self.assertEqual(r.stdout.count("RAN-SHARED"), 2)  # RUN line + echo, not 4
        self.assertEqual(r.stdout.count("RAN-A"), 2)

    def test_glob_directory_row(self):
        r = self.run_sel("ci/linter/lint-c.sh")
        self.assertIn("RAN-LINTER", r.stdout)
        self.assertNotIn("RAN-A", r.stdout)

    def test_docs_only_runs_nothing(self):
        r = self.run_sel("README.md", "docs/x.md", ".github/workflows/ci.yml")
        self.assertEqual(r.returncode, 0)
        self.assertIn("nothing to run", r.stdout)
        self.assertNotIn("RAN-", r.stdout)

    def test_unmapped_src_falls_back_to_make_check_only(self):
        r = sh("--map", str(self.root / "map.tsv"), "--dry-run",
               "--files", "src/never_mapped.c", root=self.root)
        self.assertEqual(r.returncode, 0, r.stderr)
        plan = [ln for ln in r.stdout.splitlines() if ln.startswith("PLAN")]
        self.assertEqual(plan, ["PLAN [build] @make-check"])

    def test_missing_build_is_loud_skip(self):
        r = self.run_sel("src/needs_build.c")
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("RAN-BUILD", r.stdout)
        self.assertIn("SKIP", r.stderr)
        self.assertIn("NOT RUN", r.stderr)
        self.assertIn("coverage NOT provided", r.stderr)

    def test_missing_build_require_fails(self):
        r = self.run_sel("src/needs_build.c", env={"PRECOMMIT_TESTS": "require"})
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("RAN-BUILD", r.stdout)
        self.assertIn("PRECOMMIT_TESTS=require", r.stderr)

    def test_present_build_runs_build_row(self):
        d = self.root / ".build" / "nginx-9.9.9" / "objs"
        d.mkdir(parents=True)
        nginx = d / "nginx"
        nginx.write_text("#!/bin/sh\n")
        nginx.chmod(0o755)
        r = self.run_sel("src/needs_build.c", env={"PRECOMMIT_TESTS": "require"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("RAN-BUILD", r.stdout)

    def test_failing_command_fails_selector(self):
        r = self.run_sel("src/bad.c")
        self.assertEqual(r.returncode, 1)
        self.assertIn("FAIL", r.stderr)

    def test_off_mode_runs_nothing(self):
        r = self.run_sel("src/a.c", env={"PRECOMMIT_TESTS": "off"})
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("RAN-A", r.stdout)

    def test_bad_mode_is_usage_error(self):
        r = self.run_sel("src/a.c", env={"PRECOMMIT_TESTS": "bogus"})
        self.assertEqual(r.returncode, 2)

    def test_dry_run_runs_nothing(self):
        r = sh("--map", str(self.root / "map.tsv"), "--dry-run",
               "--files", "src/a.c", root=self.root)
        self.assertIn("PLAN [none] echo RAN-A", r.stdout)
        self.assertNotIn("precommit-tests: RUN", r.stdout)

    def test_staged_mode_reads_git_index(self):
        env = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}
        subprocess.run(["git", "init", "-q", str(self.root)], check=True, env={**os.environ, **env})
        (self.root / "src").mkdir()
        (self.root / "src" / "b.c").write_text("x\n")
        (self.root / "notes.md").write_text("x\n")
        subprocess.run(["git", "-C", str(self.root), "add", "src/b.c", "notes.md"],
                       check=True, env={**os.environ, **env})
        r = sh("--map", str(self.root / "map.tsv"), "--staged", root=self.root, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("RAN-B", r.stdout)
        self.assertNotIn("RAN-A", r.stdout)


class RealMap(unittest.TestCase):
    def plan(self, *files):
        r = sh("--dry-run", "--files", *files)
        self.assertEqual(r.returncode, 0, r.stderr)
        return [ln for ln in r.stdout.splitlines() if ln.startswith("PLAN")]

    def test_one_src_file_selects_only_its_mapped_tests(self):
        plan = self.plan("src/ngx_http_cache_turbo_vary.c")
        self.assertEqual(len(plan), 2, plan)
        self.assertIn("ut marker_store_key", plan[0])
        self.assertIn("variant_gen", plan[0])
        self.assertIn("areas/policy.py", plan[1])
        for line in plan:
            self.assertNotIn("areas/core.py", line)
            self.assertNotIn("areas/l2.py", line)

    def test_docs_only_selects_nothing(self):
        r = sh("--dry-run", "--files", "README.md", "docs/anything.md", "CHANGES")
        self.assertIn("nothing to run", r.stdout)
        self.assertNotIn("PLAN", r.stdout)

    def test_area_edit_selects_that_area_only(self):
        plan = self.plan("ci/tools/areas/admin.py")
        self.assertEqual(len(plan), 1)
        self.assertIn("areas/admin.py", plan[0])

    def test_linter_edit_selects_selftest(self):
        self.assertEqual(self.plan("ci/linter/lint-c.sh"),
                         ["PLAN [none] bash ci/linter/selftest.sh"])

    def test_unit_check_edit_selects_that_check(self):
        plan = self.plan("ci/tests/unit/check_ttl_width.sh")
        self.assertEqual(plan, ["PLAN [none] bash ci/tests/unit/check_ttl_width.sh"])

    def test_every_src_file_selects_something_and_never_a_whole_suite(self):
        whole = re.compile(r"run_all|test_runtime\.py|tests/unit/run\.sh")
        for src in sorted((REPO / "src").glob("*.c")):
            plan = self.plan(f"src/{src.name}")
            self.assertTrue(plan, f"{src.name}: nothing selected")
            for line in plan:
                self.assertIsNone(whole.search(line), line)

    def test_no_whole_suite_in_selector_or_map(self):
        # Selector may only reach the runtime suite through run_named.py, and
        # may never invoke run_all() or the monolithic unit driver.
        code = [ln for ln in SELECTOR.read_text().splitlines()
                if not ln.lstrip().startswith("#")]
        body = "\n".join(code)
        self.assertNotIn("run_all", body)
        self.assertNotIn("tests/unit/run.sh", body)
        self.assertNotRegex(body, r"test_runtime\.py")
        self.assertIn("run_named.py", body)
        rows = [ln for ln in REAL_MAP.read_text().splitlines()
                if ln.strip() and not ln.startswith("#")]
        for ln in rows:
            self.assertNotRegex(ln, r"run_all|test_runtime\.py|tests/unit/run\.sh")


class MapCompleteness(unittest.TestCase):
    def lint(self, map_path=None):
        args = [sys.executable, "-I", str(LINT)]
        if map_path:
            args += ["--map", str(map_path)]
        return subprocess.run(args, capture_output=True, text=True, check=False)

    def test_real_map_is_complete(self):
        r = self.lint()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_removed_src_row_fails(self):
        with tempfile.TemporaryDirectory() as td:
            kept = [ln for ln in REAL_MAP.read_text().splitlines(keepends=True)
                    if not ln.startswith("src/ngx_http_cache_turbo_access.c\t")]
            self.assertLess(len(kept), len(REAL_MAP.read_text().splitlines()))
            m = pathlib.Path(td) / "map.tsv"
            m.write_text("".join(kept))
            r = self.lint(m)
            self.assertEqual(r.returncode, 1)
            self.assertIn("src/ngx_http_cache_turbo_access.c", r.stderr)

    def test_whole_suite_row_fails(self):
        with tempfile.TemporaryDirectory() as td:
            m = pathlib.Path(td) / "map.tsv"
            m.write_text(
                REAL_MAP.read_text() + "src/x.c\tbuild\tpython3 ci/tools/test_runtime.py\n"
            )
            r = self.lint(m)
            self.assertEqual(r.returncode, 1)
            self.assertIn("whole suite", r.stderr)

    def test_unknown_needs_and_area_fail(self):
        with tempfile.TemporaryDirectory() as td:
            m = pathlib.Path(td) / "map.tsv"
            m.write_text(REAL_MAP.read_text()
                         + "src/x.c\tmaybe\techo hi\nsrc/y.c\tbuild\t@area nosuch\n")
            r = self.lint(m)
            self.assertEqual(r.returncode, 1)
            self.assertIn("unknown needs 'maybe'", r.stderr)
            self.assertIn("no such area 'nosuch'", r.stderr)

    def test_malformed_row_fails(self):
        with tempfile.TemporaryDirectory() as td:
            m = pathlib.Path(td) / "map.tsv"
            m.write_text(REAL_MAP.read_text() + "src/x.c only-two-cols\n")
            self.assertEqual(self.lint(m).returncode, 1)

    def test_missing_map_is_usage_error(self):
        self.assertEqual(self.lint("/nonexistent/map.tsv").returncode, 2)


class AreaL2(unittest.TestCase):
    """L2 signature detection and server-override resolution (fake root)."""

    AREA = (
        "def test_first(\n"
        "    redis,  # note\n"
        "):  # note\n"
        "    pass\n"
        "def test_second():\n"
        "    pass\n"
    )

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.root = pathlib.Path(self._td.name)
        areas = self.root / "ci" / "tools" / "areas"
        areas.mkdir(parents=True)
        (areas / "fx.py").write_text(self.AREA)
        (self.root / "ci" / "tools" / "run_named.py").write_text(
            "import sys\nprint('RUN', *sys.argv[1:])\n")
        (self.root / "map.tsv").write_text("src/x.c\tbuild\t@area fx\n")
        objs = self.root / ".build" / "nginx-9.9.9" / "objs"
        objs.mkdir(parents=True)
        ngx = objs / "nginx"
        ngx.write_text("#!/bin/sh\n")
        ngx.chmod(0o755)
        self.bindir = self.root / "bin"
        self.bindir.mkdir()
        for n in ("fake-redis", "fake-mc"):
            f = self.bindir / n
            f.write_text("#!/bin/sh\n")
            f.chmod(0o755)
        self.path = f"{self.bindir}:{os.environ['PATH']}"

    def run_sel(self, env):
        e = {"PATH": self.path, "PRECOMMIT_TESTS": "require"}
        e.update(env)
        return sh("--map", str(self.root / "map.tsv"), "--files", "src/x.c",
                  root=self.root, env=e)

    def test_policy_clean_tag_index_precedes_drop_in_area_selection(self):
        # Exercise the actual selector with the real policy source and a stub
        # runner; no nginx or Redis state is needed to inspect its arguments.
        policy = REPO / "ci/tools/areas/policy.py"
        (self.root / "ci/tools/areas/fx.py").write_text(policy.read_text())
        ngx = self.root / ".build/nginx-9.9.9/objs/nginx"
        ngx.write_text("#!/bin/sh\necho NGX_HTTP_CACHE_TURBO_TEST_FAULTS=1\n")
        r = self.run_sel({"PRECOMMIT_REDIS_SERVER": "fake-redis",
                          "PRECOMMIT_MEMCACHED_SERVER": "fake-mc"})
        self.assertEqual(r.returncode, 0, r.stderr)
        args = next(line for line in r.stdout.splitlines()
                    if line.startswith("RUN ")).split()
        clean = "test_tagidx_purge_reports_degraded_after_dropped_index_write"
        mutator = "test_l9_tag_index_drop_is_observable"
        self.assertLess(args.index(clean), args.index(mutator))

    def test_trailing_comment_after_signature_still_lists_test(self):
        r = self.run_sel({"PRECOMMIT_REDIS_SERVER": "fake-redis",
                          "PRECOMMIT_MEMCACHED_SERVER": "fake-mc"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("--redis-server", r.stdout)

    def test_bare_name_override_on_path_is_accepted(self):
        r = self.run_sel({"PRECOMMIT_REDIS_SERVER": "fake-redis",
                          "PRECOMMIT_MEMCACHED_SERVER": "fake-mc"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"--redis-server {self.bindir}/fake-redis", r.stdout)
        self.assertIn(f"--memcached-server {self.bindir}/fake-mc", r.stdout)

    def test_nonexistent_override_is_loud_failure(self):
        r = self.run_sel({"PRECOMMIT_REDIS_SERVER": "no-such-redis-bin",
                          "PRECOMMIT_MEMCACHED_SERVER": "fake-mc"})
        self.assertEqual(r.returncode, 1)
        self.assertIn("redis-server is not available", r.stderr)


if __name__ == "__main__":
    unittest.main()
