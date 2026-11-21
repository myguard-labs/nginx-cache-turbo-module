"""Exercise the real capture shell against an isolated process-filesystem fixture."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GUARD = ROOT / "ci/tools/ci-hang-guard.sh"


class HangCaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="guard-capture-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.proc = self.root / "proc"
        self.bindir = self.root / "bin"
        self.bindir.mkdir()
        for name, body in {
            "sudo": 'exec "$@"',
            "gdb": 'printf "fixture backtrace\\n"',
            "sleep": ":",
        }.items():
            tool = self.bindir / name
            tool.write_text("#!/bin/sh\n" + body + "\n")
            tool.chmod(0o755)
        self.process(100, 1, "shell")
        self.process(101, 100, "nginx")
        self.owned = self.root / "owned instance/logs/error.log"
        self.owned.parent.mkdir(parents=True)
        self.owned.write_text("owned diagnostic\n")
        (self.proc / "101/fd/4").symlink_to(self.owned)
        # A neighbouring nginx is outside the wrapped command's tree.
        self.process(200, 1, "nginx")
        neighbour = self.root / "neighbour/logs/error.log"
        neighbour.parent.mkdir(parents=True)
        neighbour.write_text("neighbour diagnostic\n")
        (self.proc / "200/fd/4").symlink_to(neighbour)

    def process(self, pid, parent, name):
        directory = self.proc / str(pid)
        (directory / "fd").mkdir(parents=True)
        (directory / "comm").write_text(name + "\n")
        (directory / "stat").write_text(f"{pid} ({name}) S {parent} 0\n")
        # nginx's setproctitle turns the original argv into one string.
        (directory / "cmdline").write_bytes(
            b"nginx: master process nginx -p /rewritten-prefix -c nginx.conf\0")

    def capture(self):
        # Replace only the kernel filesystem and process/debugger boundaries.
        # The actual production shell, including set -e and its orchestration,
        # runs unchanged against the private fixture.
        source = GUARD.read_text().replace("/proc/", str(self.proc) + "/")
        script = self.root / "capture.sh"
        script.write_text("kill() { :; }\n" + source)
        artifacts = self.root / "artifacts"
        result = subprocess.run(
            ["sh", str(script), "--capture", "100", str(artifacts), "1"],
            env={**os.environ, "PATH": str(self.bindir) + ":" + os.environ["PATH"]},
            capture_output=True, text=True, timeout=10)
        return result, artifacts

    def test_non_nginx_last_does_not_abort_capture(self):
        self.process(102, 100, "helper")
        result, artifacts = self.capture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((artifacts / "gdb-nginx-101.txt").read_text(),
                         "fixture backtrace\n")

    def test_rewritten_title_uses_owned_open_error_log(self):
        self.process(102, 101, "nginx")
        (self.proc / "102/fd/4").symlink_to(self.owned)
        (self.proc / "101/fd/5").symlink_to(self.owned)
        (self.proc / "101/fd/6").symlink_to(self.owned.parent)
        (self.proc / "101/fd/7").symlink_to(self.root / "missing/error.log")
        result, artifacts = self.capture()
        self.assertEqual(result.returncode, 0, result.stderr)
        logs = sorted(artifacts.glob("error-*.log"))
        self.assertTrue(logs, "rewritten nginx title hid its open error log")
        self.assertEqual(len(logs), 1, "master/worker descriptors duplicated the log")
        self.assertEqual({path.read_text() for path in logs}, {"owned diagnostic\n"})

    def test_missing_open_log_does_not_abort_nginx_capture(self):
        (self.proc / "101/fd/4").unlink()
        result, artifacts = self.capture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((artifacts / "gdb-nginx-101.txt").exists())
        self.assertEqual(list(artifacts.glob("error-*.log")), [])

    def test_missing_descriptors_and_empty_process_set_are_harmless(self):
        (self.proc / "101/fd/4").unlink()
        (self.proc / "101/comm").write_text("helper\n")
        result, artifacts = self.capture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no nginx under pid 100", result.stderr)
        self.assertEqual(list(artifacts.glob("error-*.log")), [])


if __name__ == "__main__":
    unittest.main()
