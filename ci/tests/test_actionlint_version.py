"""Check the actionlint pin against the actual executable selected by PATH."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

CHECKER = Path(__file__).resolve().parents[1] / "linter/actionlint-version.sh"


class ActionlintVersionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.first = self.root / "first"
        self.second = self.root / "second"
        self.first.mkdir()
        self.second.mkdir()

    def executable(self, directory, body):
        path = directory / "actionlint"
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o755)

    def check(self):
        env = dict(os.environ, PATH=f"{self.first}:{self.second}")
        return subprocess.run(
            ["/bin/bash", "-c", '. "$1"; actionlint_version_ok', "check", str(CHECKER)],
            env=env, capture_output=True, text=True, check=False,
        )

    def test_correct(self):
        self.executable(self.first, "printf '1.7.7\\nextra information\\n'")
        self.assertEqual(self.check().returncode, 0)

    def test_absent(self):
        self.assertNotEqual(self.check().returncode, 0)

    def test_wrong(self):
        self.executable(self.first, "echo 1.7.8")
        self.assertNotEqual(self.check().returncode, 0)

    def test_failure(self):
        self.executable(self.first, "echo 1.7.7; exit 1")
        self.assertNotEqual(self.check().returncode, 0)

    def test_shadowed(self):
        self.executable(self.first, "echo 1.7.8")
        self.executable(self.second, "echo 1.7.7")
        self.assertNotEqual(self.check().returncode, 0)


if __name__ == "__main__":
    unittest.main()
