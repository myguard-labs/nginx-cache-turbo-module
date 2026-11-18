#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Controls for the parser-file warning baseline gate (real gcc and clang)."""

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location(
    "wgate", ROOT / "ci/tools/warning_baseline_gate.py"
)
assert spec is not None and spec.loader is not None
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

CLEAN = "unsigned long f(unsigned long n) { unsigned long m = n; return m; }\n"
TRUNC = "int f(unsigned long n) { int m = n; return m; }\n"


class GateTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / "src").mkdir()
        self.name = "src/ngx_http_cache_turbo_redis.c"
        self.source = self.root / self.name
        self.base = self.root / "baseline.json"
        self.db = self.root / "db.json"
        self.db.write_text(
            json.dumps(
                [
                    {
                        "directory": str(self.root),
                        "file": str(self.source),
                        "arguments": ["cc", "-c", "-Wall", "-Werror", str(self.source)],
                    }
                ]
            )
        )
        patcher = patch.object(gate, "FILES", (self.name,))
        patcher.start()
        self.addCleanup(patcher.stop)

    def write(self, text):
        self.source.write_text(text)

    def update(self):
        self.assertEqual(self.execute(update=True)[0], 0)

    def execute(self, update=False):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = gate.run(self.root, self.db, self.base, update)
        return rc, out.getvalue()

    def test_clean_baseline_passes(self):
        self.write(CLEAN)
        self.update()
        doc = json.loads(self.base.read_text())
        self.assertEqual(doc["per_file_counts"]["gcc"][self.name], 0)
        self.assertEqual(doc["per_file_counts"]["clang"][self.name], 0)
        self.assertEqual(self.execute()[0], 0)

    def test_new_int_truncation_fails_and_names_it(self):
        self.write(CLEAN)
        self.update()
        self.write(TRUNC)
        rc, out = self.execute()
        self.assertEqual(rc, 1)
        self.assertIn(f"new: gcc {self.name} -Wconversion", out)
        self.assertIn("new: clang", out)
        self.assertIn("to 'int' may change value", out)
        self.assertIn("-Wshorten-64-to-32", out)

    def test_known_passes_and_fixed_is_reported(self):
        self.write(TRUNC)
        self.update()
        doc = json.loads(self.base.read_text())
        self.assertGreater(doc["per_file_counts"]["gcc"][self.name], 0)
        self.assertEqual(self.execute()[0], 0)
        # line drift must not matter
        self.write("\n\n\n" + TRUNC)
        self.assertEqual(self.execute()[0], 0)
        self.write(CLEAN)
        rc, out = self.execute()
        self.assertEqual(rc, 0)
        self.assertIn("fixed:", out)

    def test_second_identical_warning_fails(self):
        self.write(TRUNC)
        self.update()
        self.write(TRUNC + TRUNC.replace("f(", "g("))
        self.assertEqual(self.execute()[0], 1)

    def test_error_paths(self):
        self.write("int f( {\n")
        with self.assertRaises(ValueError):
            self.execute(update=True)
        self.write(CLEAN)
        self.update()
        doc = json.loads(self.base.read_text())
        doc["compilers"]["gcc"]["major"] += 1
        self.base.write_text(json.dumps(doc))
        with self.assertRaises(ValueError):
            self.execute()
        self.db.write_text("[]")
        with self.assertRaises(ValueError):
            self.execute()

    def test_duplicate_database_entry_rejected(self):
        entries = json.loads(self.db.read_text())
        self.db.write_text(json.dumps(entries * 2))
        self.write(CLEAN)
        with self.assertRaises(ValueError):
            self.execute(update=True)

    def test_baseline_count_mismatch_rejected(self):
        self.write(TRUNC)
        self.update()
        doc = json.loads(self.base.read_text())
        doc["per_file_counts"]["gcc"][self.name] += 1
        self.base.write_text(json.dumps(doc))
        with self.assertRaises(ValueError):
            self.execute()


class RepoTests(unittest.TestCase):
    def test_committed_baseline_is_valid(self):
        recorded, allowed = gate.read_baseline(ROOT / "ci/tools/warning-baseline.json")
        self.assertEqual(set(recorded), set(gate.COMPILERS))
        for _c, tu, src, _o, _m in allowed:
            self.assertTrue((ROOT / tu).is_file())
            self.assertTrue((ROOT / src).is_file())
        for name in gate.FILES:
            self.assertTrue((ROOT / name).is_file(), name)

    def test_workflow_wiring(self):
        static = (ROOT / ".github/workflows/static.yml").read_text()
        self.assertIn("python3 ci/tools/warning_baseline_gate.py", static)
        self.assertIn("python3 ci/tests/unit/test_warning_baseline_gate.py", static)
        self.assertIn("ci/tools/warning-baseline.json", static)


if __name__ == "__main__":
    unittest.main()
