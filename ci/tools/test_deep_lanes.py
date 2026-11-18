#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Check Deep's retained inventory and execute its lane verdict controls.

Inventory hashes cover original commands, step environments, actions and inputs.
Only lane wiring (paths, resolved matrix values and the registry-derived fuzz
partition) and comments in the fuzz step normalize away. --baseline proves the manifest against a pre-regroup workflow.
The local runner models GitHub outcome guards; it does not run runtime checks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
LANES = {
    "D-soak": ["asan-soak"],
    "D-fuzz-a": ["fuzz-a", "coverage"],
    "D-fuzz-b": ["fuzz-b", "scanbench", "clang-analyze"],
    "D-compat": [
        "compat-mainline",
        "compat-stable",
        "compat-angie",
        "legacy-runtime",
        "memcheck",
        "testkit-sanitizer",
        "testkit-angie",
        "scanners",
    ],
}
PARSER = argparse.ArgumentParser(description=__doc__)
PARSER.add_argument(
    "--workflow", type=Path, default=ROOT / ".github/workflows/ci-deep.yml"
)
PARSER.add_argument("--baseline", type=Path)
PARSER.add_argument("--write-inventory", type=Path)
ARGS, REST = PARSER.parse_known_args()
WORKFLOW = yaml.safe_load(ARGS.workflow.read_text(encoding="utf-8"))
MANIFEST = ROOT / "ci/tools/deep-check-inventory.json"


def protected(step, group, original_env=None):
    """Canonicalize only the documented lane-wiring substitutions."""
    data = {
        key: step[key] for key in ("run", "uses", "with", "env", "shell") if key in step
    }
    data = json.loads(json.dumps(data))
    env = {**(original_env or {}), **data.get("env", {})}
    for key in ("TEST_BASE_PORT", "BUILD_ROOT", "FUZZ_JOBS"):
        env.pop(key, None)
    if env:
        data["env"] = env
    else:
        data.pop("env", None)
    if group.startswith("compat-"):
        label = group.removeprefix("compat-")
        flavor = "angie" if label == "angie" else "nginx"
        version = {
            "mainline": "NGINX_MAINLINE",
            "stable": "NGINX_STABLE",
            "angie": "ANGIE_VERSION",
        }[label]
        for values in (data.get("env", {}), data.get("with", {})):
            for key, value in values.items():
                if isinstance(value, str):
                    values[key] = value.replace("${{ matrix.flavor }}", flavor).replace(
                        "${{ matrix.version_key }}", version
                    )
    if "run" in data:
        run = data["run"].replace("$GITHUB_WORKSPACE/.build/", "${BUILD_ROOT}/")
        run = run.replace('build=".build/', 'build="${BUILD_ROOT}/')
        if step["name"].endswith("Fuzz targets concurrently"):
            run = re.sub(r"bash run-concurrent.sh[^\n]*", "bash run-concurrent.sh", run)
            # The registry-derived partition (specs/guard/mapfile lines) is lane
            # wiring, like the explicit list it replaced, and comments carry no
            # behaviour; test_fuzz_partition_reaches_the_runner executes the
            # guard and checks the arguments the runner receives instead.
            run = re.sub(
                r'^[ \t]*(#[^\n]*|specs=[^\n]*|\[ -n "\$specs" \][^\n]*'
                r"|mapfile -t specs[^\n]*)\n",
                "",
                run,
                flags=re.MULTILINE,
            )
        data["run"] = run
    for key, value in data.get("env", {}).items():
        if isinstance(value, str):
            data["env"][key] = value.replace("/.testkit-" + group, "/.testkit")
    if step["name"].endswith("Check out nginx-module-testkit"):
        data["with"]["path"] = ".testkit"
    if step["name"].endswith(("Upload crash artifacts", "Upload minimized corpus")):
        data["with"]["name"] = data["with"]["name"].removesuffix("-" + group)
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def inventory(document, original=False):
    records = {}
    for lane, groups in LANES.items():
        for group in groups:
            if original:
                source = (
                    "build-flavors"
                    if group.startswith("compat-")
                    else "fuzz"
                    if group.startswith("fuzz-")
                    else group
                )
                job = document["jobs"][source]
                steps = [
                    s
                    for s in job["steps"]
                    if s["name"] not in ("Checkout module", "Notify Discord on failure")
                ]
                env = job.get("env", {})
            else:
                steps = [
                    s
                    for s in document["jobs"][lane]["steps"]
                    if s["name"].startswith(group + " / ")
                    and not s["name"].endswith(
                        ("Isolate build outputs", "Reset previous check environment")
                    )
                ]
                env = None
            records[group] = [
                {
                    "name": s["name"].split(" / ", 1)[-1],
                    "sha256": protected(s, group, env),
                }
                for s in steps
            ]
    return records


def enabled(condition, outcomes):
    """Interpret the deliberately narrow status-expression subset in Deep."""
    if condition == "always()":
        return True
    if not condition.startswith("always() && "):
        raise AssertionError("independent steps must use always(): " + condition)
    matches = re.findall(r"steps\.([\w-]+)\.outcome == '(success|failure)'", condition)
    if condition != "always() && " + " && ".join(
        f"steps.{sid}.outcome == '{value}'" for sid, value in matches
    ):
        raise AssertionError(condition)
    return all(outcomes.get(sid) == value for sid, value in matches)


def simulate(job, failure=None):
    outcomes = {}
    for step in job["steps"]:
        if step.get("id") == "verdict":
            break
        sid = step["id"]
        outcomes[sid] = (
            ("failure" if sid == failure else "success")
            if enabled(step.get("if", "always()"), outcomes)
            else "skipped"
        )
    return outcomes


def verdict(job, outcomes):
    step = next(s for s in job["steps"] if s.get("id") == "verdict")
    with tempfile.TemporaryDirectory() as tmp:
        output = Path(tmp) / "output"
        summary = Path(tmp) / "summary"
        script = Path(tmp) / "verdict.py"
        script.write_text(step["run"], encoding="utf-8")
        python3 = shutil.which("python3")
        if not python3:
            raise RuntimeError("python3 is required for the verdict control")
        (Path(tmp) / "python3").symlink_to(python3)
        shell = step["shell"]
        if shell == "python":
            shell = "python {0}"  # GitHub Actions built-in shell template.
        command = [part.replace("{0}", str(script)) for part in shlex.split(shell)]
        result = subprocess.run(
            command,
            env={
                **os.environ,
                **step["env"],
                "PATH": tmp,
                "GITHUB_OUTPUT": str(output),
                "GITHUB_STEP_SUMMARY": str(summary),
                "LANE_STEPS": json.dumps(
                    {sid: {"outcome": value} for sid, value in outcomes.items()}
                ),
            },
            text=True,
            capture_output=True,
            check=False,
        )
        return (
            result.returncode,
            output.read_text(encoding="utf-8"),
            summary.read_text(encoding="utf-8"),
            result.stdout,
        )


def failed_checks(output):
    """Return the verdict's failed= value; a missing key is a contract break."""
    if not output.startswith("failed="):
        raise AssertionError("verdict output lacks failed= prefix: " + repr(output))
    return output.removeprefix("failed=").strip()


def notify_step(job):
    """Find the Discord notification step by name, not by position."""
    return next(s for s in job["steps"] if s["name"].startswith("Notify Discord"))


class DeepLanes(unittest.TestCase):
    def test_workflow_loaded(self):
        # Probe selected by test_reads_are_utf8 under a non-UTF-8 locale.
        self.assertIn("jobs", WORKFLOW)

    def test_reads_are_utf8(self):
        # Without explicit encodings the C locale decodes the workflow as ASCII.
        with tempfile.TemporaryDirectory() as tmp:
            workflow = Path(tmp) / "wf.yml"
            workflow.write_text("jobs:\n  x: sch\u00f6n\n", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    "-X",
                    "utf8=0",
                    str(Path(__file__).resolve()),
                    "--workflow",
                    str(workflow),
                    "DeepLanes.test_workflow_loaded",
                ],
                env={
                    **os.environ,
                    "LC_ALL": "C",
                    "PYTHONCOERCECLOCALE": "0",
                    "PYTHONUTF8": "0",
                },
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_verdict_prefix_and_notify_lookup_controls(self):
        self.assertEqual(failed_checks("failed=a (failure)\n"), "a (failure)")
        with self.assertRaises(AssertionError):
            failed_checks("fail=a (failure)\n")
        job = {"steps": [{"name": "Notify Discord on lane failure"}, {"name": "x"}]}
        self.assertEqual(notify_step(job)["name"], "Notify Discord on lane failure")
        with self.assertRaises(StopIteration):
            notify_step({"steps": [{"name": "x"}]})

    def test_workflow_sync_stamps(self):
        # Use the shipped predicate (ci/tools/sync-stamp.sh:151-157), so the
        # focused pre-review controls catch generated metadata drift too.
        result = subprocess.run(
            ["bash", "ci/tools/sync-stamp.sh", "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_original_inventory(self):
        expected = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(inventory(WORKFLOW), expected)
        if ARGS.baseline:
            self.assertEqual(
                inventory(
                    yaml.safe_load(ARGS.baseline.read_text(encoding="utf-8")), True
                ),
                expected,
            )

    def test_soak_uses_full_allocation_sweep(self):
        step = next(
            s
            for s in WORKFLOW["jobs"]["D-soak"]["steps"]
            if s["name"].endswith(
                "Run multi-worker fault-injection suite N times (fail-fast)"
            )
        )
        self.assertEqual(step["env"].get("CT_ALLOC_SWEEP"), "full")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            record = root / "invocation.json"
            stub = root / "python3"
            stub.write_text(
                "#!/usr/bin/python3\n"
                "import json, os, sys\n"
                "with open(os.environ['RECORD'], 'w') as output:\n"
                "    json.dump([os.environ.get('CT_ALLOC_SWEEP'), sys.argv[1:]], output)\n",
                encoding="utf-8",
            )
            stub.chmod(0o755)
            fuser = root / "fuser"
            fuser.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fuser.chmod(0o755)
            env = {
                **os.environ,
                **step["env"],
                "PATH": tmp + os.pathsep + os.environ["PATH"],
                "BUILD_ROOT": tmp,
                "NGINX_VERSION": "test",
                "SOAK_ITERATIONS": "1",
                "TEST_BASE_PORT": "10000",
                "RECORD": str(record),
            }
            result = subprocess.run(
                ["bash", "-e", "-c", step["run"]],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            sweep, arguments = json.loads(record.read_text(encoding="utf-8"))
            self.assertEqual(sweep, "full")
            self.assertEqual(arguments[0], "ci/tools/test_runtime.py")
            self.assertIn("--fault-injection", arguments)

    def test_four_lanes_and_budgets(self):
        self.assertEqual(list(WORKFLOW["jobs"]), list(LANES))
        dispatch = WORKFLOW[True]["workflow_dispatch"]["inputs"]
        self.assertEqual(dispatch["soak_iterations"]["default"], 8)
        self.assertEqual(dispatch["fuzz_seconds"]["default"], 3600)
        self.assertEqual(WORKFLOW["jobs"]["D-soak"]["timeout-minutes"], 240)
        self.assertEqual(
            WORKFLOW["concurrency"],
            {"group": "ci-deep-${{ github.ref }}", "cancel-in-progress": False},
        )
        # Always the checked-in registry: drop any inherited override.
        env = {k: v for k, v in os.environ.items() if k != "FUZZ_TARGETS_TSV"}

        def specs(part):
            return subprocess.run(
                ["bash", str(ROOT / "ci/fuzz/targets.sh"), "specs", part],
                check=True, capture_output=True, text=True, env=env,
            ).stdout.split()

        registry = specs("all")
        half = (len(registry) + 1) // 2
        for lane, part in {"D-fuzz-a": "a", "D-fuzz-b": "b"}.items():
            job = WORKFLOW["jobs"][lane]
            step = next(
                s
                for s in job["steps"]
                if s["name"].endswith("Fuzz targets concurrently")
            )
            # The lane derives its targets from the registry: no hard-coded list.
            self.assertIn("targets.sh specs " + part, step["run"])
            self.assertNotIn("fuzz_resp_parser", step["run"])
            self.assertEqual(
                {"a": registry[:half], "b": registry[half:]}[part], specs(part)
            )
            self.assertEqual(step["env"]["FUZZ_JOBS"], "3")
            self.assert_fuzz_timeout(job, len(specs(part)), int(step["env"]["FUZZ_JOBS"]))

    def assert_fuzz_timeout(self, job, targets, jobs):
        """Each lane fits ceil(targets/jobs) sequential waves of the full per-target
        budget plus the non-fuzz steps, at the smallest and the largest input."""
        match = re.fullmatch(
            r"\$\{\{ inputs\.fuzz_seconds > (\d+) && (\d+) \|\| (\d+) \}\}",
            job["timeout-minutes"],
        )
        self.assertIsNotNone(match, job["timeout-minutes"])
        threshold, long_limit, short_limit = map(int, match.groups())
        waves = -(-targets // jobs)
        overhead = 120  # setup, corpus merge and (lane a) coverage, minutes
        # fuzz_seconds is capped at 14400 by the "Select fuzz duration" step.
        for seconds in (3600, 3601, 14400):
            limit = long_limit if seconds > threshold else short_limit
            self.assertGreaterEqual(
                limit, waves * seconds / 60 + overhead,
                f"{waves} wave(s) of {seconds}s do not fit {limit}m",
            )
        # An unset input (schedule) resolves to the short limit and 3600s.
        self.assertGreaterEqual(short_limit, waves * 60 + overhead)

    def test_fuzz_partition_reaches_the_runner(self):
        """Run each lane's real step with a stub run-concurrent.sh and compare the
        arguments it receives with the registry partition."""
        env = {k: v for k, v in os.environ.items() if k != "FUZZ_TARGETS_TSV"}
        fuzz = ROOT / "ci/fuzz"
        for lane, part in {"D-fuzz-a": "a", "D-fuzz-b": "b"}.items():
            step = next(
                s
                for s in WORKFLOW["jobs"][lane]["steps"]
                if s["name"].endswith("Fuzz targets concurrently")
            )
            expected = subprocess.run(
                ["bash", str(fuzz / "targets.sh"), "specs", part],
                check=True, capture_output=True, text=True, env=env,
            ).stdout.split()
            with self.subTest(lane=lane), tempfile.TemporaryDirectory() as tmp:
                work = Path(tmp)
                (work / "ci/fuzz").mkdir(parents=True)
                for entry in fuzz.iterdir():
                    if entry.name != "run-concurrent.sh":
                        (work / "ci/fuzz" / entry.name).symlink_to(entry)
                record = work / "args"
                (work / "ci/fuzz/run-concurrent.sh").write_text(
                    '#!/bin/sh\nprintf "%s\\n" "$@" > "$RECORD"\n', encoding="utf-8"
                )
                result = subprocess.run(
                    ["bash", "-e", "-c", step["run"]],
                    cwd=work, env={**env, "RECORD": str(record)},
                    text=True, capture_output=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(record.read_text(encoding="utf-8").split(), expected)
                # Negative control: a registry the step cannot list stops the lane
                # before the runner is reached.
                record.unlink()
                result = subprocess.run(
                    ["bash", "-e", "-c", step["run"]],
                    cwd=work,
                    env={**env, "RECORD": str(record),
                         "FUZZ_TARGETS_TSV": str(work / "missing.tsv")},
                    text=True, capture_output=True, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(record.exists(), "runner ran with no target list")

    def test_fuzz_manifest_digests_match(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        digest = {
            g: next(r["sha256"] for r in manifest[g] if r["name"] == "Fuzz targets concurrently")
            for g in ("fuzz-a", "fuzz-b")
        }
        self.assertEqual(digest["fuzz-a"], digest["fuzz-b"])

    def test_actions_and_private_outputs(self):
        for lane, job in WORKFLOW["jobs"].items():
            self.assertEqual(job["steps"][0]["with"]["persist-credentials"], False)
            if lane == "D-compat":
                self.assertEqual(job["steps"][0]["with"]["fetch-depth"], 0)
            for step in job["steps"]:
                if "uses" in step and not step["uses"].startswith("./"):
                    self.assertRegex(step["uses"], r"@[0-9a-f]{40}$")
                if " / " not in step["name"]:
                    continue
                group = step["name"].split(" / ")[0]
                self.assertEqual(
                    step["env"]["BUILD_ROOT"],
                    "${{ github.workspace }}/.build/deep/" + group,
                )
                if "TESTKIT_ROOT" in step["env"]:
                    self.assertEqual(
                        step["env"]["TESTKIT_ROOT"],
                        "${{ github.workspace }}/.testkit-" + group,
                    )
                if step["name"].endswith("Check out nginx-module-testkit"):
                    self.assertEqual(step["with"]["path"], ".testkit-" + group)
                if step["name"].endswith(
                    "Restore build caches"
                ) and not group.startswith("fuzz-"):
                    index = job["steps"].index(step)
                    isolate = job["steps"][index + 1]
                    self.assertTrue(isolate["name"].endswith("Isolate build outputs"))
                    self.assertIn(
                        'ln -s "$GITHUB_WORKSPACE/.build/$archive"', isolate["run"]
                    )

    def test_success_failure_skip_missing_and_notification(self):
        for lane, job in WORKFLOW["jobs"].items():
            with self.subTest(lane=lane):
                steps = job["steps"]
                final = next(s for s in steps if s.get("id") == "verdict")
                required = set(final["env"]["LANE_REQUIRED"].split())
                ids = {s["id"] for s in steps if "id" in s and s["id"] != "verdict"}
                optional = {
                    s["id"]
                    for s in steps
                    if s["name"].endswith(
                        ("Upload crash artifacts", "Upload minimized corpus")
                    )
                }
                self.assertEqual(required, ids - optional)
                self.assertEqual(set(final["env"]["LANE_OPTIONAL"].split()), optional)
                self.assertEqual(final["if"], "always()")
                notifications = [
                    s for s in steps if s["name"].startswith("Notify Discord")
                ]
                self.assertEqual(len(notifications), 1)
                self.assertEqual(
                    notifications[0]["if"],
                    "failure() && github.event_name == 'schedule'",
                )
                self.assertIn(
                    "steps.verdict.outputs.failed",
                    notifications[0]["env"]["FAILED_CHECKS"],
                )
                good = simulate(job)
                self.assertEqual(verdict(job, good)[0], 0)
                for sid in optional:
                    changed = {**good, sid: "failure"}
                    self.assertEqual(verdict(job, changed)[0], 1)
                for outcome in ("failure", "skipped", "missing"):
                    changed = dict(good)
                    changed["checkout"] = outcome
                    rc, output, _, _ = verdict(job, changed)
                    self.assertEqual(rc, 1)
                    self.assertIn("checkout (" + outcome + ")", output)
                # Every setup/check failure must leave later independent groups
                # enabled, while prerequisite chains must skip stale artifacts.
                for sid in required:
                    outcomes = simulate(job, sid)
                    self.assertEqual(outcomes[sid], "failure")
                    rc, output, _, _ = verdict(job, outcomes)
                    self.assertEqual(rc, 1, sid)
                    self.assertIn(sid + " (failure)", output)
                    if sid == "checkout":
                        self.assertTrue(
                            all(
                                v == "skipped"
                                for k, v in outcomes.items()
                                if k != "checkout"
                            )
                        )
                    else:
                        group = sid.rsplit("_", 1)[0]
                        for other in required - {"checkout"}:
                            if other.rsplit("_", 1)[0] != group:
                                self.assertEqual(
                                    outcomes[other], "success", (sid, other)
                                )
                # Each protected prerequisite edge must actually prevent execution.
                for step in steps:
                    if " / " in step["name"]:
                        self.assertIs(step["continue-on-error"], True)
                        for dependency in re.findall(
                            r"steps\.([\w-]+)\.outcome == 'success'", step["if"]
                        ):
                            outcomes = simulate(job, dependency)
                            self.assertEqual(outcomes[step["id"]], "skipped")

    def test_archive_links_and_environment_reset(self):
        for job in WORKFLOW["jobs"].values():
            for step in job["steps"]:
                if step["name"].endswith("Isolate build outputs"):
                    with tempfile.TemporaryDirectory() as tmp:
                        workspace = Path(tmp)
                        build = workspace / ".build/deep/check"
                        env = {
                            **os.environ,
                            "BUILD_ROOT": str(build),
                            "GITHUB_WORKSPACE": tmp,
                            "ARCHIVE_FLAVOR": "nginx",
                            "ARCHIVE_VERSION": "1.31.3",
                        }
                        subprocess.run(
                            ["bash", "-euo", "pipefail", "-c", step["run"]],
                            env=env,
                            check=True,
                            capture_output=True,
                        )
                        archive = build / "nginx-1.31.3.tar.gz"
                        self.assertTrue(archive.is_symlink())
                        archive.write_text("verified source fixture", encoding="utf-8")
                        self.assertEqual(
                            (workspace / ".build/nginx-1.31.3.tar.gz").read_text(
                                encoding="utf-8"
                            ),
                            "verified source fixture",
                        )
                if step["name"].endswith("Reset previous check environment"):
                    with tempfile.TemporaryDirectory() as tmp:
                        output = Path(tmp) / "env"
                        subprocess.run(
                            ["bash", "-euo", "pipefail", "-c", step["run"]],
                            env={**os.environ, "GITHUB_ENV": str(output)},
                            check=True,
                            capture_output=True,
                        )
                        self.assertEqual(
                            dict(
                                line.split("=", 1)
                                for line in output.read_text(
                                    encoding="utf-8"
                                ).splitlines()
                            ),
                            dict.fromkeys(
                                (
                                    "MATRIX_VERSION",
                                    "TEST_NGINX_BINARY",
                                    "TEST_NGINX_LOAD_MODULES",
                                    "NGINX_BINARY",
                                    "MODULE_SO",
                                    "NGINX_SRC_TREE",
                                ),
                                "",
                            ),
                        )

    def test_one_notification_names_checks_and_escapes_payload(self):
        for lane, job in WORKFLOW["jobs"].items():
            step = notify_step(job)
            with tempfile.TemporaryDirectory() as tmp:
                bindir = Path(tmp)
                curl = bindir / "curl"
                capture = bindir / "calls"
                curl.write_text(
                    "#!/usr/bin/env python3\nimport json, os, sys\n"
                    "with open(os.environ['CAPTURE'], 'a') as out:\n"
                    "    out.write(json.dumps(sys.argv[1:]) + '\\n')\n",
                    encoding="utf-8",
                )
                curl.chmod(0o755)
                env = {
                    **os.environ,
                    "PATH": tmp + ":" + os.environ["PATH"],
                    "CAPTURE": str(capture),
                    "DISCORD_BOT_TOKEN": "fixture",
                    "DISCORD_CHANNEL_BUILDS": "fixture",
                    "GH_REPO": "owner/repo",
                    "GH_SERVER_URL": "https://example.test",
                    "GH_RUN_ID": "123",
                    "LANE_NAME": lane,
                    "FAILED_CHECKS": 'first (failure), second "quoted" (skipped)',
                }
                subprocess.run(
                    ["bash", "-euo", "pipefail", "-c", step["run"]],
                    env=env,
                    check=True,
                    capture_output=True,
                )
                calls = capture.read_text(encoding="utf-8").splitlines()
                self.assertEqual(len(calls), 1)
                args = json.loads(calls[0])
                content = json.loads(args[args.index("-d") + 1])["content"]
                self.assertIn(lane + " FAILED: " + env["FAILED_CHECKS"], content)
                self.assertIn("/owner/repo/actions/runs/123", content)
                # Checkout failure produces the largest prerequisite-skip list.
                rc, output, summary, _ = verdict(job, simulate(job, "checkout"))
                self.assertEqual(rc, 1)
                env["FAILED_CHECKS"] = failed_checks(output)
                subprocess.run(
                    ["bash", "-euo", "pipefail", "-c", step["run"]],
                    env=env,
                    check=True,
                    capture_output=True,
                )
                calls = capture.read_text(encoding="utf-8").splitlines()
                self.assertEqual(len(calls), 2)
                args = json.loads(calls[-1])
                content = json.loads(args[args.index("-d") + 1])["content"]
                self.assertLessEqual(
                    len(content), 2000, "Discord rejects oversized content"
                )
                self.assertIn("checkout (failure)", content)
                self.assertTrue(content.endswith("/owner/repo/actions/runs/123"))
                self.assertIn("checkout: failure", summary)
                if lane == "D-compat":
                    self.assertRegex(
                        content, r"; [1-9][0-9]* more checks in run summary"
                    )
                    self.assertIn("scanners_10: skipped", summary)
                env["DISCORD_BOT_TOKEN"] = ""
                subprocess.run(
                    ["bash", "-euo", "pipefail", "-c", step["run"]],
                    env=env,
                    check=True,
                    capture_output=True,
                )
                self.assertEqual(
                    len(capture.read_text(encoding="utf-8").splitlines()), 2
                )

    def test_analyzer_advisory_is_accounted_and_independent(self):
        job = WORKFLOW["jobs"]["D-compat"]
        step = next(
            s
            for s in job["steps"]
            if s["name"] == "scanners / gcc -fanalyzer (advisory)"
        )
        self.assertEqual(step["id"], "scanners_analyzer")
        self.assertEqual(
            step["if"], "always() && steps.scanners_06.outcome == 'success'"
        )
        final = next(s for s in job["steps"] if s.get("id") == "verdict")
        self.assertIn(step["id"], final["env"]["LANE_REQUIRED"].split())
        good = simulate(job)
        self.assertEqual(good[step["id"]], "success")
        self.assertEqual(verdict(job, good)[0], 0)
        failed = simulate(job, step["id"])
        self.assertEqual(failed["scanners_09"], "success")
        self.assertEqual(failed["scanners_10"], "success")
        self.assertEqual(verdict(job, failed)[0], 1)
        self.assertEqual(simulate(job, "scanners_06")[step["id"]], "skipped")
        missing = dict(good)
        del missing[step["id"]]
        self.assertEqual(verdict(job, missing)[0], 1)
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp) / "bash"
            stub.write_text(
                '#!/bin/sh\necho analyzer-ran\nexit "$STUB_EXIT"\n', encoding="utf-8"
            )
            stub.chmod(0o755)
            for exit_code in ("0", "1"):
                result = subprocess.run(
                    ["/bin/bash", "-euo", "pipefail", "-c", step["run"]],
                    env={
                        **os.environ,
                        "PATH": tmp,
                        "GITHUB_WORKSPACE": tmp,
                        "STUB_EXIT": exit_code,
                    },
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("analyzer-ran", result.stdout)
                self.assertEqual("::warning::" in result.stdout, exit_code == "1")

    def test_scanners_and_angie_controls_are_independent(self):
        job = WORKFLOW["jobs"]["D-compat"]
        siblings = [
            s
            for s in job["steps"]
            if s["name"].split(" / ")[-1]
            in (
                "gitleaks (full history scan)",
                "flawfinder (gate on >=4)",
                "clang-tidy (cert-*, security.*)",
                "semgrep (gate on >=WARNING)",
                "Representative scenario asserts on Angie",
                "Representative scenario SKIPs on an unstaged Angie tree",
            )
        ]
        for step in siblings:
            outcomes = simulate(job, step["id"])
            for other in siblings:
                if other != step:
                    self.assertEqual(outcomes[other["id"]], "success")
        configure = next(
            s
            for s in job["steps"]
            if s["name"].endswith("Configure nginx src tree (clang-tidy headers)")
        )
        outcomes = simulate(job, configure["id"])
        for step in siblings:
            if "clang-tidy (" not in step["name"]:
                self.assertEqual(outcomes[step["id"]], "success")


if __name__ == "__main__":
    if ARGS.write_inventory:
        if ARGS.baseline is None:
            PARSER.error("--write-inventory needs --baseline")
        ARGS.write_inventory.write_text(
            json.dumps(
                inventory(
                    yaml.safe_load(ARGS.baseline.read_text(encoding="utf-8")), True
                ),
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    else:
        unittest.main(argv=[sys.argv[0], *REST])
