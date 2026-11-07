#!/usr/bin/env python3
"""CI-L1: the `CI / gate` verdict is fail-closed and treats skipped as pass."""

import json
import pathlib
import re
import subprocess
import sys
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
TOOL = REPO / "ci" / "tools" / "ci-gate-verdict.py"
CI_YML = REPO / ".github" / "workflows" / "ci.yml"


def run(stdin, *args):
    return subprocess.run([sys.executable, str(TOOL), *args], input=stdin,
                          capture_output=True, text=True).returncode


def needs(**results):
    return json.dumps({k: {"result": v, "outputs": {}} for k, v in results.items()})


class Verdict(unittest.TestCase):
    def test_all_success_green(self):
        self.assertEqual(run(needs(changes="success", lint="success")), 0)

    def test_success_and_skipped_green(self):
        self.assertEqual(run(needs(changes="success", asan="skipped",
                                   fuzzing="skipped", lint="success")), 0)

    def test_failure_red(self):
        self.assertEqual(run(needs(changes="success", lint="failure")), 1)

    def test_cancelled_red(self):
        self.assertEqual(run(needs(changes="success", lint="cancelled")), 1)

    def test_unknown_result_red(self):
        self.assertEqual(run(needs(changes="success", lint="weird")), 1)

    def test_changes_failure_with_downstream_skipped_red(self):
        # changes failed, so its dependents are skipped: still red.
        self.assertEqual(run(needs(changes="failure", asan="skipped",
                                   **{"build-test": "skipped"})), 1)

    def test_changes_skipped_red(self):
        self.assertEqual(run(needs(changes="skipped", lint="success")), 1)

    def test_changes_missing_red(self):
        self.assertEqual(run(needs(lint="success")), 1)

    def test_require_override(self):
        self.assertEqual(run(needs(lint="success"), "--require", "lint"), 0)

    def test_empty_and_malformed_red(self):
        for bad in ("", "   ", "{}", "[]", "null", "not json", '{"a": 1}',
                    '{"changes": {"outputs": {}}}', '"success"'):
            with self.subTest(bad=bad):
                self.assertEqual(run(bad), 1)


class Workflow(unittest.TestCase):
    """ci.yml's gate job must list every other job in needs."""

    def test_gate_needs_every_job(self):
        text = CI_YML.read_text()
        jobs_block = text.split("\njobs:\n", 1)[1]
        jobs = re.findall(r"^  ([a-z][a-z0-9_-]*):\s*$", jobs_block, re.M)
        self.assertIn("gate", jobs)
        m = re.search(r"^  gate:\n(.*?)(?=^  [a-z][a-z0-9_-]*:\s*$|\Z)",
                      jobs_block, re.M | re.S)
        body = m.group(1)
        nm = re.search(r"needs:\s*\[([^\]]*)\]", body)
        self.assertIsNotNone(nm, "gate needs: must be an inline list")
        listed = {x.strip() for x in nm.group(1).split(",") if x.strip()}
        self.assertEqual(listed, set(jobs) - {"gate"})
        self.assertRegex(body, r"if:\s*\$\{\{\s*always\(\)\s*\}\}")


if __name__ == "__main__":
    unittest.main()
