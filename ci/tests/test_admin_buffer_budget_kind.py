# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause

"""Exercise descriptor kind validation against disposable schema copies."""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LINTER = Path(os.environ.get("ADMIN_BUDGET_LINTER", ROOT / "ci/tools/lint-admin-buffer-budget.py"))
SCHEMA = Path("src/ngx_http_cache_turbo_stats_schema.h")


class DescriptorKindTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for path in (SCHEMA, Path("src/ngx_http_cache_turbo_admin.c"),
                     Path("ci/tests/stats-contract.json")):
            dest = self.root / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, dest)
        dest = self.root / "ci/tools/lint-admin-buffer-budget.py"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(LINTER, dest)

    def run_linter(self):
        return subprocess.run([sys.executable, str(self.root / "ci/tools/lint-admin-buffer-budget.py")],
                              capture_output=True, text=True, check=False)

    def change_kind(self, key, kind):
        path = self.root / SCHEMA
        schema = path.read_text()
        pattern = (r'(\{ ngx_string\("' + re.escape(key) + r'"\),.*?CT_STATS_)'
                   r'(COUNTER|GAUGE|STATE)(, offsetof\(ngx_http_cache_turbo_stats_t, '
                   + re.escape(key) + r'\))')
        changed, count = re.subn(pattern, lambda match: match[1] + kind + match[3],
                                 schema, count=1, flags=re.DOTALL)
        self.assertEqual(count, 1)
        path.write_text(changed)

    def test_baseline_accepts_counter_gauge_and_breaker_state(self):
        result = self.run_linter()
        self.assertEqual(result.returncode, 0, result.stderr)
        schema = (self.root / SCHEMA).read_text()
        self.assertIn("CT_STATS_COUNTER, offsetof", schema)
        self.assertIn("CT_STATS_GAUGE, offsetof", schema)

    def test_breaker_state_rejects_non_state_kinds(self):
        original = (self.root / SCHEMA).read_text()
        for kind in ("GAUGE", "COUNTER", "INVALID"):
            with self.subTest(kind=kind):
                (self.root / SCHEMA).write_text(original)
                self.change_kind("breaker_state", kind)
                result = self.run_linter()
                self.assertNotEqual(result.returncode, 0, kind)
                self.assertIn(f"breaker_state: unrecognized descriptor type {kind}", result.stderr)

    def test_nonbreaker_rejects_state(self):
        self.change_kind("hits", "STATE")
        result = self.run_linter()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("hits: unrecognized descriptor type STATE", result.stderr)


if __name__ == "__main__":
    unittest.main()
