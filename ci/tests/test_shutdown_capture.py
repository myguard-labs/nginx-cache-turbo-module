"""Shutdown diagnostics must be bounded and must not obstruct cleanup."""
import pathlib
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
import test_runtime_base as base


class ShutdownCapture(unittest.TestCase):
    def server(self, root):
        server = base.Nginx.__new__(base.Nginx)
        server.root = root
        server.output_path = root / "output.log"
        server.process = mock.Mock(pid=123, returncode=-signal.SIGKILL)
        return server

    def test_timeout_captures_before_kill_and_preserves_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            server = self.server(pathlib.Path(tmp))
            events = []
            server.process.poll.return_value = None
            server.process.terminate.side_effect = lambda: events.append("term")
            server.process.wait.side_effect = [subprocess.TimeoutExpired("nginx", 15), None]
            server.process.kill.side_effect = lambda: events.append("kill")
            server._capture_shutdown = lambda: events.append("capture")
            server.diagnostics = lambda: ""
            process = server.process
            with self.assertRaisesRegex(RuntimeError, "nginx exited with -9"):
                server.stop()
            self.assertEqual(events, ["term", "capture", "kill"])
            self.assertEqual(process.wait.call_args_list, [mock.call(timeout=15), mock.call(timeout=5)])
            self.assertIsNone(server.process)

    def test_capture_error_still_kills_and_reaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            server = self.server(pathlib.Path(tmp))
            process = server.process
            process.poll.return_value = None
            process.wait.side_effect = [subprocess.TimeoutExpired("nginx", 15), None]
            server._capture_shutdown = mock.Mock(side_effect=OSError("failed"))
            server.diagnostics = lambda: ""
            with self.assertRaises(RuntimeError):
                server.stop()
            process.kill.assert_called_once_with()
            self.assertEqual(process.wait.call_count, 2)

    def test_normal_shutdown_does_not_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            server = self.server(pathlib.Path(tmp))
            server.process.poll.return_value = None
            server.process.returncode = -signal.SIGTERM
            server._capture_shutdown = mock.Mock()
            server.stop()
            server._capture_shutdown.assert_not_called()

    def test_allowlist_and_bounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            server = self.server(root)
            proc = root / "proc" / "123" / "task"
            for tid in range(70):
                task = proc / str(tid)
                task.mkdir(parents=True)
                (task / "status").write_text("Name:\tprivate\nState:\tS (sleeping)\n")
                (task / "wchan").write_text("safe_wait\n" if tid else "private secret!\n")
            server.output_path.write_bytes(b"secret " + b"x" * 16384 + b" exiting secret")
            (root / "logs").mkdir()
            (root / "logs" / "error.log").write_text("signal 15 (SIGTERM) received private")
            original_path = type(root)
            def path(value):
                return root / "proc" if value == "/proc" else original_path(value)
            with mock.patch.object(base, "_BREADCRUMB", str(root / "artifacts" / "current")), \
                 mock.patch.object(base.pathlib, "Path", side_effect=path):
                server._capture_shutdown()
            result = (root / "artifacts" / "shutdown-123.txt").read_text()
            self.assertEqual(result.count(" status=S"), 64)
            self.assertIn("exiting count=1", result)
            self.assertIn("signal 15 (SIGTERM) received count=1", result)
            self.assertNotIn("private", result)
            self.assertNotIn("secret", result)
            self.assertNotIn("tid=0 wchan=", result)
            self.assertLess(len(result), 10000)

    def test_disabled_capture_and_missing_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            server = self.server(root)
            with mock.patch.object(base, "_BREADCRUMB", None):
                server._capture_shutdown()
            self.assertEqual(list(root.iterdir()), [])
            original_path = type(root)
            def path(value):
                return root / "missing-proc" if value == "/proc" else original_path(value)
            with mock.patch.object(base, "_BREADCRUMB", str(root / "out" / "current")), \
                 mock.patch.object(base.pathlib, "Path", side_effect=path):
                server._capture_shutdown()
            self.assertEqual((root / "out" / "shutdown-123.txt").read_text(), "pid=123\n")

    def test_single_process_upload_runs_on_failure(self):
        workflow = (pathlib.Path(__file__).resolve().parents[2] / ".github/workflows/asan.yml").read_text()
        upload = workflow.split("- name: Upload hang-capture artifacts", 1)[1].split("\n  asan-multi:", 1)[0]
        self.assertIn("if: always()", upload)
        self.assertIn("path: ci-hang-artifacts/", upload)


if __name__ == "__main__":
    unittest.main()
