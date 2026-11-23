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


def result(rule=FIRST, line=4, message="unsafe read in f", column=2, uri="src/a.c"):
    return {"ruleId": rule, "message": {"text": message}, "locations": [{
        "physicalLocation": {"artifactLocation": {"uri": uri},
                             "region": {"startLine": line, "startColumn": column}}}]}


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
    def test_action_extension_inventory(self):
        document = json.loads((ROOT / "ci/tests/codeql-lifetime-action.sarif").read_text())
        baseline = json.loads((ROOT / "ci/codeql/nginx-lifetime/baseline.json").read_text())
        self.assertEqual(run(document, baseline).returncode, 0)
        self.assertEqual(run(document, []).returncode, 1)
        for field in ("path", "message"):
            with self.subTest(field=field):
                changed = json.loads(json.dumps(document))
                item = changed["runs"][0]["results"][0]
                location = item["locations"][0]["physicalLocation"]
                if field == "path":
                    location["artifactLocation"]["uri"] += "x"
                else:
                    item["message"]["text"] += "x"
                self.assertEqual(run(changed, baseline).returncode, 1)
        document["runs"][0]["results"].append(result())
        self.assertEqual(run(document, baseline).returncode, 1)

    def test_invalid_rule_references_and_inventories(self):
        original = json.loads((ROOT / "ci/tests/codeql-lifetime-action.sarif").read_text())
        for mutation in ("duplicate", "missing", "index", "id", "component", "malformed"):
            with self.subTest(mutation=mutation):
                document = json.loads(json.dumps(original))
                run_data = document["runs"][0]
                rules = run_data["tool"]["extensions"][1]["rules"]
                if mutation == "duplicate":
                    rules.append(rules[0])
                elif mutation == "missing":
                    rules.pop()
                elif mutation == "index":
                    run_data["results"][0]["rule"]["index"] = 1
                elif mutation == "id":
                    run_data["results"][0]["rule"]["id"] = FIRST
                elif mutation == "component":
                    run_data["results"][0]["rule"]["toolComponent"]["index"] = 0
                else:
                    run_data["tool"]["extensions"] = {}
                self.assertEqual(run(document, []).returncode, 2)

    def test_empty_and_exact_baseline_pass(self):
        self.assertEqual(run(sarif([]), []).returncode, 0)
        self.assertEqual(run(sarif([result()]), [result()]).returncode, 0)

    def test_shifted_line_and_column_keep_accepted_finding(self):
        for shift in (1, 22, 5000):
            with self.subTest(shift=shift):
                moved = result(line=4 + shift, column=9)
                self.assertEqual(run(sarif([moved]), [result()]).returncode, 0)
                self.assertEqual(run(sarif([result()]), [moved]).returncode, 0)
        document = json.loads((ROOT / "ci/tests/codeql-lifetime-action.sarif").read_text())
        baseline = json.loads((ROOT / "ci/codeql/nginx-lifetime/baseline.json").read_text())
        for item in document["runs"][0]["results"]:
            item["locations"][0]["physicalLocation"]["region"]["startLine"] += 22
        self.assertEqual(run(document, baseline).returncode, 0)

    def test_same_file_new_finding_still_fails_after_shift(self):
        accepted = result(message="read in lock_finish")
        added = result(line=90, message="read in other_finish")
        proc = run(sarif([result(line=30, message="read in lock_finish"), added]), [accepted])
        self.assertEqual(proc.returncode, 1)
        self.assertIn("other_finish", proc.stdout)
        self.assertNotIn("lock_finish", proc.stdout)
        # same rule/message in another file is not accepted by this baseline
        moved_file = result(uri="src/b.c", message="read in lock_finish")
        self.assertEqual(run(sarif([moved_file]), [accepted]).returncode, 1)
        # a different rule with the same message is not accepted either
        self.assertEqual(run(sarif([result(SECOND)]), [accepted]).returncode, 1)

    def test_multiplicity_survives_line_shift(self):
        shifted = [result(line=40), result(line=50)]
        self.assertEqual(run(sarif(shifted), [result()]).returncode, 1)
        self.assertEqual(run(sarif(shifted), [result(), result(line=9)]).returncode, 0)
        self.assertEqual(run(sarif([result(line=40)]), [result(), result(line=9)]).returncode, 0)

    def test_malformed_identity_errors(self):
        cases = {"line0": result(line=0), "column0": result(column=0),
                 "line-bool": result(line=True), "line-str": result(line="4"),
                 "message-empty": result(message=""), "uri-empty": result(uri="")}
        for name, bad in cases.items():
            with self.subTest(case=name):
                self.assertEqual(run(sarif([bad]), []).returncode, 2)
                self.assertEqual(run(sarif([]), [bad]).returncode, 2)

    def test_new_and_duplicate_findings_fail(self):
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
