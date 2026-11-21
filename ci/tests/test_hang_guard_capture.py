"""Exercise the real capture shell against an isolated process-filesystem fixture."""

import contextlib
import io
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ci/tools'))
import ci_hang_capture as diagnostics


class HangCaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="guard-capture-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.proc = self.root / "proc"
        self.bindir = self.root / "bin"
        self.bindir.mkdir()
        for name, body in {
            "sudo": '[ "$1" != "-n" ] || shift; exec "$@"',
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
        (directory / "stat").write_text(
            f"{pid} ({name}) S {parent} " + "0 " * 17 + f"{pid}\n")
        # nginx's setproctitle turns the original argv into one string.
        (directory / "cmdline").write_bytes(
            b"nginx: master process nginx -p /rewritten-prefix -c nginx.conf\0")

    def capture(self, *, passive=False):
        artifacts = self.root / 'artifacts'
        stderr = io.StringIO()
        descriptors = {}
        signals = []

        def pin(pid):
            fd = os.open('/dev/null', os.O_RDONLY)
            descriptors[pid] = fd
            return fd

        with mock.patch.object(diagnostics, 'PROC', self.proc), \
                mock.patch.object(diagnostics.os, 'pidfd_open', side_effect=pin), \
                mock.patch.object(diagnostics.select, 'select', return_value=([], [], [])), \
                mock.patch.object(diagnostics.signal, 'pidfd_send_signal',
                                  side_effect=lambda fd, sig: signals.append((fd, sig))), \
                mock.patch.object(diagnostics.time, 'sleep'), \
                mock.patch.dict(os.environ, PATH=str(self.bindir) + ':' + os.environ['PATH'],
                                CT_HANG_QUIT='0' if passive else '1'), \
                contextlib.redirect_stderr(stderr):
            diagnostics.capture(100, artifacts, 1)
        self.signals = signals
        self.descriptors = descriptors
        return subprocess.CompletedProcess([], 0, '', stderr.getvalue()), artifacts

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

    def test_passive_capture_preserves_backtrace_and_log_without_shutdown(self):
        result, artifacts = self.capture(passive=True)
        self.assertEqual(result.returncode, 0)
        self.assertTrue((artifacts / 'gdb-nginx-101.txt').exists())
        self.assertEqual((artifacts / 'error-1.log').read_text(), 'owned diagnostic\n')
        self.assertEqual(self.signals, [], 'passive diagnostics stopped nginx')

    def test_debugger_timeout_preserves_signal_and_log_snapshot(self):
        with mock.patch.object(diagnostics.subprocess, 'run',
                               side_effect=subprocess.TimeoutExpired('gdb', .1)) as debugger:
            _, artifacts = self.capture()
        self.assertEqual(len(self.signals), 1)
        self.assertEqual((artifacts / 'error-1.log').read_text(), 'owned diagnostic\n')
        self.assertIn('exceeded capture budget',
                      (artifacts / 'gdb-nginx-101.txt').read_text())
        command = debugger.call_args.args[0]
        self.assertEqual(command[:4], ['sudo', '-n', 'timeout', '--foreground'])
        self.assertIn('--kill-after=0.1s', command)
        self.assertGreater(debugger.call_args.kwargs['timeout'], 0)

    def test_all_debuggers_share_remaining_capture_window(self):
        self.process(102, 101, 'nginx')
        clock = [100.]
        allowances = []

        def debugger(_command, **kwargs):
            allowances.append(kwargs['timeout'])
            clock[0] += kwargs['timeout']
            raise subprocess.TimeoutExpired('gdb', kwargs['timeout'])

        with mock.patch.object(diagnostics.time, 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.object(diagnostics.subprocess, 'run', side_effect=debugger), \
                mock.patch.dict(os.environ, CT_HANG_HARD_SECONDS='780'):
            # Use the real Build soft value while retaining this fixture's proc.
            original = diagnostics.capture
            with mock.patch.object(diagnostics, 'capture',
                                   side_effect=lambda root, directory, soft:
                                   original(root, directory, 768)):
                self.capture(passive=True)
        self.assertEqual(len(allowances), 2)
        self.assertLessEqual(sum(allowances), 7.5)
        self.assertEqual(self.signals, [])

    def test_only_discovered_identity_is_signalled(self):
        self.capture()
        self.assertEqual(self.signals, [(self.descriptors[101], signal.SIGQUIT)])
        for fd in self.descriptors.values():
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_replaced_discovery_identity_is_rejected(self):
        original = diagnostics.process_stat
        calls = 0

        def changed(path):
            nonlocal calls
            parent, start = original(path)
            if path.parent.name == '101':
                calls += 1
                if calls > 1:
                    start = 'replacement'
            return parent, start

        with mock.patch.object(diagnostics, 'process_stat', side_effect=changed):
            self.capture()
        self.assertEqual(self.signals, [])

    def test_exit_during_debugger_never_falls_back_to_numeric_signal(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
        fd = os.pidfd_open(child.pid)
        self.addCleanup(lambda: child.poll() is None and child.kill())
        self.addCleanup(child.wait)

        def debugger(*_args, **_kwargs):
            signal.pidfd_send_signal(fd, signal.SIGKILL)
            child.wait()

        with mock.patch.object(diagnostics, 'discover', return_value=[(child.pid, fd)]), \
                mock.patch.object(diagnostics, 'error_logs', return_value=[]), \
                mock.patch.object(diagnostics.subprocess, 'run', side_effect=debugger), \
                mock.patch.object(diagnostics.time, 'sleep'), \
                mock.patch.object(diagnostics.os, 'kill') as numeric_kill, \
                mock.patch.dict(os.environ, CT_HANG_QUIT='1'):
            diagnostics.capture(100, self.root / 'real-exit', 1)
            numeric_kill.assert_not_called()
        self.assertIsNotNone(child.returncode)


if __name__ == "__main__":
    unittest.main()
