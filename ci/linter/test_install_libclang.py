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
    state = open(os.environ["LIBCLANG_STATE"]).read()
    return None if state == "missing" or name in state.split(",") else "fake-libclang"
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
            "alternate-clang",
            'case "$1" in -dumpversion) echo 92.4.0;; *) echo libclang.so.1;; esac',
        )
        self.stub(
            "apt-get",
            """echo "$*" >> "$APT_LOG"
case "$*" in *libclang1-91*|*libclang1-92*) [ "${APT_REPAIR:-yes}" = no ] || echo usable > "$LIBCLANG_STATE";; esac
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

        self.env.pop("SIZEOF_POINTER_CLANG", None)

    def stub(self, name, body):
        path = self.bin / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)

    def run_installer(self, state, *args, repair="yes", compiler=None):
        self.state.write_text(state)
        self.log.unlink(missing_ok=True)
        env = dict(self.env, APT_REPAIR=repair)
        if compiler is not None:
            env["SIZEOF_POINTER_CLANG"] = compiler
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

    def test_selected_compiler_rejects_hardcoded_default(self):
        result = self.run_installer("clang-91", "--check", compiler="alternate-clang")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("libclang       ok", result.stdout)

        result = self.run_installer("clang-92", "--check", compiler="alternate-clang")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("libclang       MISSING or unusable", result.stdout)

        result = self.run_installer("clang-92", "--check")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("libclang       ok", result.stdout)

    def test_selected_compiler_package_major(self):
        result = self.run_installer("clang-92", compiler="alternate-clang")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("libclang1-92", self.log.read_text())
        self.assertNotIn("libclang1-91", self.log.read_text())

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
