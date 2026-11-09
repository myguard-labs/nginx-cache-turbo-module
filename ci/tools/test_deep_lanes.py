#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Check Deep's retained inventory and execute its lane verdict controls.

Inventory hashes cover original commands, step environments, actions and inputs.
Only lane wiring (paths, resolved matrix values and the explicit fuzz partition)
normalizes away. --baseline proves the manifest against a pre-regroup workflow.
The local runner models GitHub outcome guards; it does not run runtime checks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
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
WORKFLOW = yaml.safe_load(ARGS.workflow.read_text())
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
        result = subprocess.run(
            [sys.executable, "-c", step["run"]],
            env={
                **os.environ,
                **step["env"],
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
        return result.returncode, output.read_text(), summary.read_text(), result.stdout


class DeepLanes(unittest.TestCase):
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
        expected = json.loads(MANIFEST.read_text())
        self.assertEqual(inventory(WORKFLOW), expected)
        if ARGS.baseline:
            self.assertEqual(
                inventory(yaml.safe_load(ARGS.baseline.read_text()), True), expected
            )

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
        for lane, targets in {
            "D-fuzz-a": [
                "fuzz_resp_parser:corpus:fuzz.dict",
                "fuzz_norm_args:corpus_norm_args:",
                "fuzz_mc_parser:corpus_mc:fuzz_mc.dict",
            ],
            "D-fuzz-b": ["fuzz_auto_classify:corpus_auto:", "fuzz_blob:corpus_blob:"],
        }.items():
            job = WORKFLOW["jobs"][lane]
            self.assertEqual(
                job["timeout-minutes"],
                "${{ inputs.fuzz_seconds > 3600 && 420 || 180 }}",
            )
            step = next(
                s
                for s in job["steps"]
                if s["name"].endswith("Fuzz targets concurrently")
            )
            self.assertEqual(
                step["run"].split("bash run-concurrent.sh ")[1].strip().split(), targets
            )
            self.assertEqual(step["env"]["FUZZ_JOBS"], "3")

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
                        archive.write_text("verified source fixture")
                        self.assertEqual(
                            (workspace / ".build/nginx-1.31.3.tar.gz").read_text(),
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
                                for line in output.read_text().splitlines()
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
            step = job["steps"][-1]
            with tempfile.TemporaryDirectory() as tmp:
                bindir = Path(tmp)
                curl = bindir / "curl"
                capture = bindir / "calls"
                curl.write_text(
                    "#!/usr/bin/env python3\nimport json, os, sys\n"
                    "with open(os.environ['CAPTURE'], 'a') as out:\n"
                    "    out.write(json.dumps(sys.argv[1:]) + '\\n')\n"
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
                calls = capture.read_text().splitlines()
                self.assertEqual(len(calls), 1)
                args = json.loads(calls[0])
                content = json.loads(args[args.index("-d") + 1])["content"]
                self.assertIn(lane + " FAILED: " + env["FAILED_CHECKS"], content)
                self.assertIn("/owner/repo/actions/runs/123", content)
                # Checkout failure produces the largest prerequisite-skip list.
                rc, output, summary, _ = verdict(job, simulate(job, "checkout"))
                self.assertEqual(rc, 1)
                env["FAILED_CHECKS"] = output.removeprefix("failed=").strip()
                subprocess.run(
                    ["bash", "-euo", "pipefail", "-c", step["run"]],
                    env=env,
                    check=True,
                    capture_output=True,
                )
                calls = capture.read_text().splitlines()
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
                self.assertEqual(len(capture.read_text().splitlines()), 2)

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
                inventory(yaml.safe_load(ARGS.baseline.read_text()), True), indent=2
            )
            + "\n"
        )
    else:
        unittest.main(argv=[sys.argv[0], *REST])
