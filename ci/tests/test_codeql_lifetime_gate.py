"""The lifetime gate rejects new findings and incomplete evidence."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "ci/tools/codeql-lifetime-gate.py"
FIRST = "myguard/nginx-lifetime/use-after-request-release"
SECOND = "myguard/nginx-lifetime/park-callback-unchecked"


def result(rule=FIRST, line=4):
    return {"ruleId": rule, "message": {"text": "unsafe read"}, "locations": [{
        "physicalLocation": {"artifactLocation": {"uri": "src/a.c"},
                             "region": {"startLine": line, "startColumn": 2}}}]}


def sarif(results):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"rules": [
        {"id": FIRST}, {"id": SECOND}]}}, "results": results}]}


def run(document, baseline, *args):
    with tempfile.TemporaryDirectory() as temp:
        a, b = Path(temp) / "a", Path(temp) / "b"
        a.write_text(json.dumps(document))
        b.write_text(json.dumps(baseline))
        return subprocess.run([sys.executable, str(GATE), str(a), str(b), *args],
                              capture_output=True, text=True, check=False)


class Gate(unittest.TestCase):
    def test_empty_and_exact_baseline_pass(self):
        self.assertEqual(run(sarif([]), []).returncode, 0)
        self.assertEqual(run(sarif([result()]), [result()]).returncode, 0)

    def test_new_and_duplicate_findings_fail(self):
        self.assertEqual(run(sarif([result(line=5)]), [result()]).returncode, 1)
        self.assertEqual(run(sarif([result(), result()]), [result()]).returncode, 1)
        self.assertEqual(run(sarif([result(SECOND)]), []).returncode, 1)

    def test_fixture_control_requires_real_expected_rule(self):
        self.assertEqual(run(sarif([result()]), [], "--expect-rule", FIRST).returncode, 1)
        self.assertEqual(run(sarif([]), [], "--expect-rule", FIRST).returncode, 2)
        self.assertEqual(run(sarif([result(SECOND)]), [], "--expect-rule", FIRST).returncode, 2)

    def test_missing_inventory_and_failed_analysis_error(self):
        document = sarif([])
        document["runs"][0]["tool"]["driver"]["rules"].pop()
        self.assertEqual(run(document, []).returncode, 2)
        document = sarif([])
        document["runs"][0]["invocations"] = [{"executionSuccessful": False}]
        self.assertEqual(run(document, []).returncode, 2)
        document["runs"][0]["invocations"] = ["invalid"]
        self.assertEqual(run(document, []).returncode, 2)
        self.assertEqual(run({}, []).returncode, 2)
        self.assertEqual(run(sarif([{}]), []).returncode, 2)
        self.assertEqual(run(sarif([]), {}).returncode, 2)
        self.assertEqual(run(sarif([]), [result("invalid-rule")]).returncode, 2)

    def test_missing_files_error(self):
        proc = subprocess.run([sys.executable, str(GATE), "/missing", "/missing"],
                              capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 2)


class ImpactFilter(unittest.TestCase):
    def test_version_inputs_trigger_and_docs_skip(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        start = workflow.index("          lifetime_paths='")
        end = workflow.index("          # code: detect changes", start)
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "output"
            for name, expected in ((".github/versions.env", "true"),
                                   (".github/scripts/load-versions.sh", "true"),
                                   ("src/a.c", "true"), ("README.md", "false"),
                                   ("src/a.c\n" + "docs/long-name.md\n" * 20000, "true")):
                with self.subTest(path=name[:40]):
                    output.write_text("")
                    changed = Path(temp) / "changed"
                    changed.write_text(name)
                    env = dict(os.environ, CHANGED_FILE=str(changed), GITHUB_OUTPUT=str(output))
                    script = 'changed=$(cat "$CHANGED_FILE")\n' + workflow[start:end]
                    subprocess.run(["bash", "-euo", "pipefail", "-c", script],
                                   env=env, check=True)
                    self.assertEqual(output.read_text().strip(), "lifetime=" + expected)


class FixtureOracle(unittest.TestCase):
    def test_requires_expected_new_row_and_finding_status(self):
        workflow = (ROOT / ".github/workflows/codeql-lifetime.yml").read_text()
        start = workflow.index('          test "$status" -eq 1')
        end = workflow.index("      - name: Upload lifetime SARIF", start)
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / "lifetime-fixture-gate.txt"
            cases = ((1, "NEW 1 " + FIRST + " file 1 1 message\n", 0),
                     (1, "NEW 1 " + SECOND + " file 1 1 message\n", 1),
                     (1, "", 1), (2, "NEW 1 " + FIRST + " file 1 1 message\n", 1))
            for status, content, expected in cases:
                with self.subTest(status=status, content=content):
                    report.write_text(content)
                    script = 'status=$1\n' + workflow[start:end]
                    proc = subprocess.run(["bash", "-e", "-c", script, "oracle", str(status)],
                                          env=dict(os.environ, RUNNER_TEMP=temp), check=False)
                    self.assertEqual(proc.returncode, expected)


if __name__ == "__main__":
    unittest.main()
