"""Exercise the real Git diff based 32-bit CI selector."""
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools/width-impact-filter.py"


class WidthImpactTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test")
        (self.root / "initial").write_text("base")
        self.git("add", ".")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True)

    def check_path(self, path, expected):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("change")
        self.git("add", "--", path)
        self.git("commit", "-qm", "change")
        result = subprocess.check_output(
            ["python3", str(SCRIPT), self.base], cwd=self.root, text=True
        )
        self.assertEqual(result.strip(), expected)

    def test_source(self):
        self.check_path("src/example.c", "true")

    def test_unit(self):
        self.check_path("ci/tests/unit/run.sh", "true")

    def test_workflow(self):
        self.check_path(".github/workflows/static.yml", "true")

    def test_unrelated(self):
        self.check_path("README.md", "false")

    def test_newline_in_name(self):
        self.check_path("src/name\nwith-newline.c", "true")

    def test_invalid_base_fails(self):
        result = subprocess.run(
            ["python3", str(SCRIPT), "bad-base"], cwd=self.root, capture_output=True, check=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b"false", result.stdout)

    def test_missing_base_runs(self):
        result = subprocess.check_output(["python3", str(SCRIPT), ""], cwd=self.root, text=True)
        self.assertEqual(result.strip(), "true")


if __name__ == "__main__":
    unittest.main()
