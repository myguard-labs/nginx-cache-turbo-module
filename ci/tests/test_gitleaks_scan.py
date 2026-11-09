"""Exercise both scanner modes against disposable Git history."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools/gitleaks-scan.sh"


class GitleaksScanTest(unittest.TestCase):
    def test_pr_bounds_and_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            def git(*args):
                return subprocess.check_output(["git", *args], cwd=tmp, text=True).strip()

            git("init", "-q")
            git("config", "user.name", "Fixture")
            git("config", "user.email", "fixture@example.invalid")
            path = Path(tmp) / "fixture.txt"
            # Public synthetic value; assembled to avoid triggering repository scans.
            path.write_text("token = " + "ghp_" + "A1b2C3d4" * 5 + "\n")
            git("add", "fixture.txt")
            git("commit", "-qm", "historical fixture")
            path.write_text("clean\n")
            git("commit", "-qam", "remove fixture")
            base = git("rev-parse", "HEAD")
            path.write_text("clean change\n")
            git("commit", "-qam", "clean change")
            head = git("rev-parse", "HEAD")

            def scan(event, lower=base, upper=head):
                env = dict(os.environ, GITHUB_EVENT_NAME=event,
                           PR_BASE_SHA=lower, PR_HEAD_SHA=upper)
                return subprocess.run(["bash", str(SCRIPT)], cwd=tmp, env=env,
                                      capture_output=True,
                                      text=True, check=False).returncode

            self.assertEqual(scan("pull_request"), 0)
            self.assertNotEqual(scan("push"), 0, "full history must find removed fixture")
            self.assertNotEqual(scan("pull_request", "", head), 0)
            self.assertNotEqual(scan("pull_request", base, "bad"), 0)
            self.assertNotEqual(scan("pull_request", "0" * 40, head), 0)
            path.write_text("token = " + "ghp_" + "A1b2C3d4" * 5 + "\n")
            git("commit", "-qam", "introduce fixture")
            self.assertNotEqual(scan("pull_request", base, git("rev-parse", "HEAD")), 0,
                                "PR scan must find introduced fixture")


if __name__ == "__main__":
    unittest.main()
