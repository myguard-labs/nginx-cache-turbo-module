"""Exercise both scanner modes against disposable Git history."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools/gitleaks-scan.sh"


class GitleaksScanTest(unittest.TestCase):
    def test_pr_merge_resolution_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            def git(*args):
                return subprocess.run(["git", *args], cwd=tmp, text=True,
                                      capture_output=True, check=True).stdout.strip()

            git("init", "-q")
            git("config", "user.name", "Fixture")
            git("config", "user.email", "fixture@example.invalid")
            path = Path(tmp) / "fixture.txt"
            path.write_text("clean common ancestor\n")
            git("add", "fixture.txt")
            git("commit", "-qm", "common ancestor")
            git("branch", "side")
            path.write_text("clean first parent\n")
            git("commit", "-qam", "first parent")
            base = git("rev-parse", "HEAD")
            git("checkout", "-q", "side")
            path.write_text("clean second parent\n")
            git("commit", "-qam", "second parent")
            git("checkout", "-q", "--detach", base)
            merge = subprocess.run(["git", "merge", "--no-commit", "side"], cwd=tmp,
                                   capture_output=True, text=True, check=False)
            self.assertEqual(merge.returncode, 1, "fixture must create a merge conflict")
            self.assertEqual(git("diff", "--name-only", "--diff-filter=U"), "fixture.txt")
            # Neither parent contains this public synthetic credential.
            path.write_text("token = " + "ghp_" + "A1b2C3d4" * 5 + "\n")
            git("add", "fixture.txt")
            git("commit", "-qm", "resolve conflict with fixture")
            head = git("rev-parse", "HEAD")
            self.assertEqual(len(git("show", "-s", "--format=%P", head).split()), 2)
            env = dict(os.environ, GITHUB_EVENT_NAME="pull_request",
                       PR_BASE_SHA=base, PR_HEAD_SHA=head)
            scan = subprocess.run(["bash", str(SCRIPT)], cwd=tmp, env=env,
                                  capture_output=True, text=True, check=False)
            self.assertEqual(scan.returncode, 1,
                             "PR scan must find the merge-resolution fixture")
            self.assertIn("leaks found", scan.stderr)

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
