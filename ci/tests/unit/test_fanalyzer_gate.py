#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Contract controls for the counted analyzer gate."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location(
    "gate", ROOT / "ci/tools/fanalyzer_gate.py"
)
assert spec is not None and spec.loader is not None
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class GateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "src").mkdir()
        self.source = self.root / "src/a.c"
        self.source.touch()
        self.db = self.root / "db.json"
        self.db.write_text(
            json.dumps(
                [
                    {
                        "directory": str(self.root),
                        "file": str(self.source),
                        "arguments": ["gcc", "-c", str(self.source)],
                    }
                ]
            )
        )
        self.base = self.root / "baseline.json"
        self.base.write_text("[]")

    def record(self, option):
        return {
            "option": option,
            "path": "src/a.c",
            "line": 3,
            "column": 4,
            "message": "bad thing",
            "count": 1,
        }

    def output(self, option):
        return f"{self.source}:3:4: warning: bad thing [{option}]\n"

    def execute(self, output="", returncode=0, produce_object=True):
        class Result:
            stdout = "gcc test\n"
            stderr = ""

            def __init__(self, out, rc):
                self.stdout = out
                self.returncode = rc

        calls = []

        def compile_command(cmd, **_kwargs):
            calls.append(cmd)
            if len(calls) == 1:
                return Result("gcc test\n", 0)
            if produce_object:
                Path(cmd[-1]).touch()
            return Result(output, returncode)

        with patch.object(gate.subprocess, "run", side_effect=compile_command):
            result = gate.run(self.root, self.db, self.base)
        self.commands = calls
        return result

    def test_zero_known_new_and_duplicates(self):
        self.assertEqual(self.execute(), 0)
        for option in gate.OPTIONS:
            with self.subTest(option=option):
                self.base.write_text("[]")
                self.assertEqual(self.execute(self.output(option)), 1)
                self.base.write_text(json.dumps([self.record(option)]))
                self.assertEqual(self.execute(self.output(option)), 0)
                self.assertEqual(self.execute(self.output(option) * 2), 1)

    def test_malformed_and_outside_paths(self):
        option = next(iter(gate.OPTIONS))
        for output in (
            f"broken [{option}]",
            f"{self.root}/../escape.c:3:4: warning: bad [{option}]",
        ):
            with self.assertRaises(ValueError):
                self.execute(output)
        self.base.write_text("[{}]")
        with self.assertRaises(ValueError):
            self.execute()

    def test_workflow_wiring(self):
        static = (ROOT / ".github/workflows/static.yml").read_text()
        deep = (ROOT / ".github/workflows/ci-deep.yml").read_text()
        self.assertEqual(len(list((ROOT / "src").glob("*.c"))), 16)
        self.assertIn("python3 ci/tools/fanalyzer_gate.py", static)
        self.assertIn("python3 ci/tests/unit/test_fanalyzer_gate.py", static)
        self.assertNotIn("gcc -fanalyzer (advisory)", static)
        self.assertIn("scanners / gcc -fanalyzer (advisory)", deep)
        self.assertIn("python3 ci/tools/record_compile.py --merge", deep)
        baseline = gate.baseline(ROOT / "ci/tools/fanalyzer-baseline.json")
        for item in baseline:
            self.assertTrue((ROOT / item[1]).is_file())

    def test_warning_flags(self):
        entry = json.loads(self.db.read_text())
        entry[0]["arguments"][1:1] = [
            "-Werror",
            "-Werror=analyzer-malloc-leak",
            "-Wno-analyzer-null-dereference",
        ]
        self.db.write_text(json.dumps(entry))
        self.assertEqual(self.execute(), 0)
        cmd = self.commands[1]
        self.assertNotIn("-Werror", cmd)
        self.assertNotIn("-Werror=analyzer-malloc-leak", cmd)
        self.assertIn("-Wanalyzer-malloc-leak", cmd)
        self.assertGreater(
            cmd.index("-Wanalyzer-null-dereference"),
            cmd.index("-Wno-analyzer-null-dereference"),
        )
        self.assertIn("-Wno-error", cmd)

    def test_infrastructure_failures(self):
        with self.assertRaises(ValueError):
            self.execute(produce_object=False)
        with self.assertRaises(ValueError):
            self.execute(returncode=1)
        self.db.write_text("[]")
        with self.assertRaises(ValueError):
            self.execute()
        self.db.write_text("{")
        with self.assertRaises(ValueError):
            self.execute()


if __name__ == "__main__":
    unittest.main()
