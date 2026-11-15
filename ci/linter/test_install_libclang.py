# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise installer decisions with a controlled libclang loader and apt stub."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "ci/linter/install-linters.sh"


class InstallerLibclangTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.bin = root / "bin"
        self.bin.mkdir()
        self.state = root / "state"
        self.log = root / "apt.log"
        self.site = root / "sitecustomize.py"
        self.site.write_text("""import ctypes, ctypes.util, os
class Function:
    def __call__(self, *args): return 1
class Library:
    def __getattr__(self, name): return Function()
def find(name):
    return None if open(os.environ["LIBCLANG_STATE"]).read() == "missing" else "fake-libclang"
def load(name):
    if open(os.environ["LIBCLANG_STATE"]).read() == "unusable": raise OSError("broken runtime")
    return Library()
ctypes.util.find_library = find
ctypes.CDLL = load
""")
        tools = [
            "shellcheck",
            "cppcheck",
            "flawfinder",
            "yamllint",
            "clang-tidy",
            "bear",
            "perlcritic",
            "perl",
            "ruff",
            "zizmor",
            "semgrep",
            "codespell",
            "pre-commit",
            "ast-grep",
            "gitleaks",
            "pipx",
            "cpanm",
        ]
        for name in tools:
            self.stub(name, "exit 0")
        self.stub("id", "echo 0")
        self.stub("sudo", 'echo "unexpected sudo invocation" >&2; exit 99')
        self.stub("actionlint", "echo 1.7.7")
        self.stub(
            "clang",
            'case "$1" in -dumpversion) echo 91.2.3;; *) echo libclang.so.1;; esac',
        )
        self.stub(
            "apt-get",
            """echo "$*" >> "$APT_LOG"
case "$*" in *libclang1-91*) [ "${APT_REPAIR:-yes}" = no ] || echo usable > "$LIBCLANG_STATE";; esac
exit 0""",
        )
        self.env = dict(
            os.environ,
            PATH=f"{self.bin}:/usr/bin:/bin",
            HOME=str(root),
            PYTHONPATH=str(root),
            LIBCLANG_STATE=str(self.state),
            APT_LOG=str(self.log),
        )

    def stub(self, name, body):
        path = self.bin / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)

    def run_installer(self, state, *args, repair="yes"):
        self.state.write_text(state)
        self.log.unlink(missing_ok=True)
        env = dict(self.env, APT_REPAIR=repair)
        return subprocess.run(
            ["bash", str(INSTALLER), *args],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_check_distinguishes_runtime_states(self):
        for state in ("missing", "unusable", "usable"):
            with self.subTest(state=state):
                result = self.run_installer(state, "--check")
                if state == "usable":
                    self.assertIn("libclang       ok", result.stdout)
                    self.assertEqual(
                        result.returncode, 0, result.stdout + result.stderr
                    )
                else:
                    self.assertIn("libclang       MISSING or unusable", result.stdout)
                    self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.log.exists())

    def test_provision_and_recheck(self):
        for state in ("missing", "unusable"):
            with self.subTest(state=state):
                result = self.run_installer(state)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("libclang1-91", self.log.read_text())
        result = self.run_installer("usable")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.log.exists())
        result = self.run_installer("unusable", repair="no")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("matching libclang runtime is missing or unusable", result.stderr)


if __name__ == "__main__":
    unittest.main()
