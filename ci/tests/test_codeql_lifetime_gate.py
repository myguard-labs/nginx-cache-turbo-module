"""The lifetime gate rejects new findings and incomplete evidence."""

import hashlib
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


TEXT = "use(r);"


def digest(text):
    return hashlib.sha256(" ".join(text.split()).encode()).hexdigest()


def accepted(text=TEXT, **kwargs):
    """A baseline entry: a result plus the stored source-context hash."""
    return dict(result(**kwargs), contextHash=digest(text))


def tree(root, files):
    """Write each uri with 6000 filler lines, then the given {line: text}."""
    for uri, lines in files.items():
        path = Path(root) / uri
        path.parent.mkdir(parents=True, exist_ok=True)
        body = ["// filler %d" % n for n in range(1, 6001)]
        for number, text in lines.items():
            body[number - 1] = text
        path.write_text("\n".join(body) + "\n")


def run(document, baseline, *args, files=None, root=None):
    files = files if files is not None else {
        "src/a.c": {4: TEXT, 9: TEXT, 30: TEXT, 40: TEXT, 50: TEXT, 90: "use2(r);",
                    27: TEXT, 5004: TEXT, 5: TEXT},
        "src/b.c": {4: TEXT}}
    with tempfile.TemporaryDirectory() as temp:
        a, b = Path(temp) / "a", Path(temp) / "b"
        src = Path(temp) / "src-root"
        tree(src, files)
        a.write_text(json.dumps(document))
        b.write_text(json.dumps(baseline))
        return subprocess.run([sys.executable, str(GATE), str(a), str(b),
                               "--source-root", str(root or src), *args],
                              capture_output=True, text=True, check=False)


class Gate(unittest.TestCase):
    def test_action_extension_inventory(self):
        document = json.loads((ROOT / "ci/tests/codeql-lifetime-action.sarif").read_text())
        baseline = json.loads((ROOT / "ci/codeql/nginx-lifetime/baseline.json").read_text())
        self.assertEqual(run(document, baseline, root=ROOT).returncode, 0)
        self.assertEqual(run(document, [], root=ROOT).returncode, 1)
        for field in ("path", "message"):
            with self.subTest(field=field):
                changed = json.loads(json.dumps(document))
                item = changed["runs"][0]["results"][0]
                location = item["locations"][0]["physicalLocation"]
                if field == "path":
                    location["artifactLocation"]["uri"] = "src/ngx_http_cache_turbo_redis.c"
                else:
                    item["message"]["text"] += "x"
                self.assertEqual(run(changed, baseline, root=ROOT).returncode, 1)
        document["runs"][0]["results"].append(result(
            uri="src/ngx_http_cache_turbo_memcached.c", line=1336, message="new"))
        self.assertEqual(run(document, baseline, root=ROOT).returncode, 1)

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
                self.assertEqual(run(document, [], root=ROOT).returncode, 2)

    def test_empty_and_exact_baseline_pass(self):
        self.assertEqual(run(sarif([]), []).returncode, 0)
        self.assertEqual(run(sarif([result()]), [accepted()]).returncode, 0)

    def test_shifted_source_and_sarif_keep_accepted_finding(self):
        for shift in (1, 22, 5000):
            with self.subTest(shift=shift):
                files = {"src/a.c": {4 + shift if shift < 5000 else 5004: TEXT}}
                moved = result(line=4 + shift, column=9)
                self.assertEqual(run(sarif([moved]), [accepted()], files=files).returncode, 0)
        document = json.loads((ROOT / "ci/tests/codeql-lifetime-action.sarif").read_text())
        baseline = json.loads((ROOT / "ci/codeql/nginx-lifetime/baseline.json").read_text())
        with tempfile.TemporaryDirectory() as temp:
            for name in ("memcached", "redis"):
                text = (ROOT / ("src/ngx_http_cache_turbo_%s.c" % name)).read_text()
                (Path(temp) / "src").mkdir(exist_ok=True)
                (Path(temp) / ("src/ngx_http_cache_turbo_%s.c" % name)).write_text(
                    "/* shifted */\n" * 22 + text)
            for item in document["runs"][0]["results"]:
                item["locations"][0]["physicalLocation"]["region"]["startLine"] += 22
            self.assertEqual(run(document, baseline, root=temp).returncode, 0)

    def test_replacement_in_same_function_fails(self):
        # An accepted site is fixed; a new site with the same rule, file and
        # message (names only the variable and callee) appears elsewhere. The
        # counts are equal, so only the source-context hash tells them apart.
        message = "'r' is used after release by ngx_http_finalize_request"
        old = accepted(message=message, line=4)
        new = result(message=message, line=90)
        proc = run(sarif([new]), [old])
        self.assertEqual(proc.returncode, 1)
        self.assertIn("NEW 1 " + FIRST + " src/a.c " + message, proc.stdout)
        # the unmoved accepted site alone still passes
        self.assertEqual(run(sarif([result(message=message, line=4)]), [old]).returncode, 0)

    def test_edited_accepted_line_is_new(self):
        edited = {"src/a.c": {4: "use(r, extra);"}}
        self.assertEqual(run(sarif([result()]), [accepted()], files=edited).returncode, 1)
        # whitespace-only edits do not change the identity
        spaced = {"src/a.c": {4: "   use(r);   "}}
        self.assertEqual(run(sarif([result()]), [accepted()], files=spaced).returncode, 0)

    def test_same_file_new_finding_still_fails_after_shift(self):
        base = accepted(message="read in lock_finish")
        added = result(line=90, message="read in other_finish")
        proc = run(sarif([result(line=30, message="read in lock_finish"), added]), [base])
        self.assertEqual(proc.returncode, 1)
        self.assertIn("other_finish", proc.stdout)
        self.assertNotIn("lock_finish", proc.stdout)
        # same rule/message in another file is not accepted by this baseline
        moved_file = result(uri="src/b.c", message="read in lock_finish")
        self.assertEqual(run(sarif([moved_file]), [base]).returncode, 1)
        # a different rule with the same message is not accepted either
        self.assertEqual(run(sarif([result(SECOND)]), [base]).returncode, 1)

    def test_multiplicity_survives_line_shift(self):
        shifted = [result(line=40), result(line=50)]
        self.assertEqual(run(sarif(shifted), [accepted()]).returncode, 1)
        self.assertEqual(run(sarif(shifted), [accepted(), accepted(line=9)]).returncode, 0)
        self.assertEqual(run(sarif([result(line=40)]),
                             [accepted(), accepted(line=9)]).returncode, 0)

    def test_unreadable_or_out_of_range_source_errors(self):
        self.assertEqual(run(sarif([result(uri="src/missing.c")]), []).returncode, 2)
        self.assertEqual(run(sarif([result(line=6001)]), [accepted()]).returncode, 2)
        self.assertEqual(run(sarif([result()]), [accepted()], files={}).returncode, 2)
        self.assertEqual(run(sarif([result(uri="../outside.c")]), []).returncode, 2)

    def test_line_numbers_follow_codeql_separators(self):
        # a form feed or U+2028 above the site must not shift the line index
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / "src").mkdir()
            (Path(temp) / "src/a.c").write_bytes(
                b"int a;\n\x0c\nx\xe2\x80\xa8y\r\nz\rpad;\n" + TEXT.encode() + b"\n")
            # CodeQL lines: 1 int a; 2 FF 3 x<LS>y 4 z 5 pad; 6 use(r);
            self.assertEqual(run(sarif([result(line=6)]), [accepted()], root=temp).returncode, 0)
            self.assertEqual(run(sarif([result(line=7)]), [accepted()], root=temp).returncode, 2)

    def test_malformed_identity_errors(self):
        cases = {"line0": result(line=0), "column0": result(column=0),
                 "line-bool": result(line=True), "line-str": result(line="4"),
                 "message-empty": result(message=""), "uri-empty": result(uri="")}
        for name, bad in cases.items():
            with self.subTest(case=name):
                self.assertEqual(run(sarif([bad]), []).returncode, 2)
                self.assertEqual(run(sarif([]), [dict(bad, contextHash=digest(TEXT))]).returncode, 2)
        for name, value in (("missing", None), ("short", "abc"), ("upper", "A" * 64),
                            ("int", 7)):
            with self.subTest(hash=name):
                entry = result()
                if value is not None:
                    entry["contextHash"] = value
                self.assertEqual(run(sarif([]), [entry]).returncode, 2)

    def test_new_and_duplicate_findings_fail(self):
        self.assertEqual(run(sarif([result(), result()]), [accepted()]).returncode, 1)
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
        self.assertEqual(run(sarif([]), [accepted(rule="invalid-rule")]).returncode, 2)

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
