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

    def capture(self, *, passive=False, hard=301, env=(), sleep=None):
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
                mock.patch.object(diagnostics.time, 'sleep', side_effect=sleep), \
                mock.patch.dict(os.environ, PATH=str(self.bindir) + ':' + os.environ['PATH'],
                                CT_HANG_QUIT='0' if passive else '1',
                                CT_HANG_HARD_SECONDS=str(hard), **dict(env)), \
                contextlib.redirect_stderr(stderr):
            if 'CT_HANG_CLEANUP_AT' not in dict(env):
                os.environ.pop('CT_HANG_CLEANUP_AT', None)  # Standalone fallback.
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
                self.capture(passive=True, hard=780)
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

    def test_changed_ancestor_identity_rejects_unchanged_nginx_child(self):
        original = diagnostics.process_stat
        calls = 0

        def replaced(path):
            nonlocal calls
            parent, start = original(path)
            if path.parent.name == '100':
                calls += 1
                if calls > 1:
                    start = 'reused-parent'
            return parent, start

        with mock.patch.object(diagnostics, 'process_stat', side_effect=replaced), \
                mock.patch.object(diagnostics.subprocess, 'run') as debugger:
            self.capture()
        debugger.assert_not_called()
        self.assertEqual(self.signals, [])

    def test_missing_or_exited_ancestor_rejects_nginx_child(self):
        for missing in (False, True):
            descriptors = []

            def pin(_pid, descriptors=descriptors):
                fd = os.open('/dev/null', os.O_RDONLY)
                descriptors.append(fd)
                return fd

            if missing:
                (self.proc / '100/stat').unlink()
            with self.subTest(missing=missing), \
                    mock.patch.object(diagnostics, 'PROC', self.proc), \
                    mock.patch.object(diagnostics.os, 'pidfd_open', side_effect=pin), \
                    mock.patch.object(diagnostics.select, 'select',
                                      side_effect=lambda fds, *_args: (fds, [], [])):
                self.assertEqual(diagnostics.discover(100), [])
            for fd in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_debugger_rechecks_start_identity_immediately_before_launch(self):
        original = diagnostics.process_stat
        calls = 0

        def replaced(path):
            nonlocal calls
            parent, start = original(path)
            if path.parent.name == '101':
                calls += 1
                # Snapshot, discovery recheck, pre-budget identity, launch recheck.
                if calls == 4:
                    start = 'reused-before-gdb'
            return parent, start

        with mock.patch.object(diagnostics, 'process_stat', side_effect=replaced), \
                mock.patch.object(diagnostics.subprocess, 'run') as debugger:
            _, artifacts = self.capture(passive=True)
        debugger.assert_not_called()
        self.assertIn('process identity changed',
                      (artifacts / 'gdb-nginx-101.txt').read_text())

    def test_rotation_during_debugger_preserves_selected_log_inode(self):
        opened = []
        original = diagnostics.error_logs

        def logs(processes):
            streams = original(processes)
            opened.extend(streams)
            return streams

        def debugger(*_args, **_kwargs):
            self.owned.rename(self.owned.with_suffix('.old'))
            self.owned.write_text('replacement log\n')

        with mock.patch.object(diagnostics, 'error_logs', side_effect=logs), \
                mock.patch.object(diagnostics.subprocess, 'run', side_effect=debugger):
            _, artifacts = self.capture(passive=True)
        self.assertEqual((artifacts / 'error-1.log').read_text(), 'owned diagnostic\n')
        self.assertTrue(opened)
        self.assertTrue(all(stream.closed for stream in opened))

    def test_log_read_failures_release_open_descriptors(self):
        (self.proc / '101/fd/5').symlink_to(self.owned)
        original_open = os.fdopen
        original_stat = os.fstat
        for error in (PermissionError, KeyboardInterrupt):
            opened = []

            def open_file(fd, *args, opened=opened, **kwargs):
                stream = original_open(fd, *args, **kwargs)
                opened.append(stream)
                return stream

            calls = []

            def stat(fd, error=error, calls=calls):
                # Fail the first log inode check, or the second after one is retained.
                calls.append(fd)
                if error is PermissionError or len(calls) == 2:
                    raise error('controlled log read failure')
                return original_stat(fd)

            with self.subTest(error=error), \
                    mock.patch.object(diagnostics, 'PROC', self.proc), \
                    mock.patch.object(diagnostics.select, 'select', return_value=([], [], [])), \
                    mock.patch.object(diagnostics.os, 'fdopen', open_file), \
                    mock.patch.object(diagnostics.os, 'fstat', side_effect=stat):
                if error is PermissionError:
                    self.assertEqual(diagnostics.error_logs([(101, -1, (100, '101'))]), [])
                else:
                    with self.assertRaises(KeyboardInterrupt):
                        diagnostics.error_logs([(101, -1, (100, '101'))])
            self.assertTrue(opened)
            self.assertTrue(all(stream.closed for stream in opened))

    def test_reused_pid_after_discovery_cannot_supply_logs(self):
        replacement = self.root / 'replacement/logs/error.log'
        replacement.parent.mkdir(parents=True)
        replacement.write_text('replacement diagnostic\n')
        original = diagnostics.discover

        def reuse(root):
            processes = original(root)
            # The discovered nginx is reaped; PID 101 now names another nginx.
            (self.proc / '101/stat').write_text('101 (nginx) S 100 ' + '0 ' * 17 + 'reused\n')
            (self.proc / '101/fd/4').unlink()
            (self.proc / '101/fd/4').symlink_to(replacement)
            return processes

        with mock.patch.object(diagnostics, 'discover', side_effect=reuse):
            _, artifacts = self.capture(passive=True)
        self.assertEqual(list(artifacts.glob('error-*.log')), [],
                         'a reused numeric PID supplied its error log')

    def test_real_proc_logs_follow_pinned_identity(self):
        log = self.root / 'real/logs/error.log'
        log.parent.mkdir(parents=True)
        log.write_text('real diagnostic\n')
        # comm comes from the executed name, so this interpreter is a real "nginx".
        (self.bindir / 'nginx').symlink_to(sys.executable)
        child = subprocess.Popen(
            [str(self.bindir / 'nginx'), '-c',
             'import sys,time; stream=open(sys.argv[1]); print(flush=True); time.sleep(60)',
             str(log)], stdout=subprocess.PIPE)
        self.addCleanup(self.stop_child, child)
        child.stdout.readline()
        child.stdout.close()
        processes = diagnostics.discover(child.pid)
        self.addCleanup(lambda: [os.close(fd) for _, fd, _ in processes])
        self.assertEqual([pid for pid, _, _ in processes], [child.pid])
        streams = diagnostics.error_logs(processes)
        try:
            self.assertEqual([stream.read() for stream in streams], [b'real diagnostic\n'])
        finally:
            for stream in streams:
                stream.close()
        # Changed identity and an exited (reaped) process both yield nothing.
        _, fd, (parent, _) = processes[0]
        self.assertEqual(diagnostics.error_logs([(child.pid, fd, (parent, 'other'))]), [])
        child.kill()
        child.wait(timeout=5)
        self.assertEqual(diagnostics.error_logs(processes), [])

    def test_late_capture_tail_ends_before_owner_cleanup(self):
        # soft=1s, hard=12s: owner cleanup starts at owner start + 8s.
        owner_start, cutoff = 1000., 1008.
        for latency, allowance in ((0., 1.5), (2., None), (9., None)):
            clock = [owner_start + 1 + latency]
            allowances = []

            def debugger(_command, clock=clock, allowances=allowances, **kwargs):
                allowances.append(kwargs['timeout'])
                clock[0] += kwargs['timeout']

            def sleep(seconds, clock=clock):
                self.assertGreaterEqual(seconds, 0)
                clock[0] += seconds

            with self.subTest(latency=latency), \
                    mock.patch.object(diagnostics.time, 'monotonic',
                                      side_effect=lambda c=clock: c[0]), \
                    mock.patch.object(diagnostics.subprocess, 'run', side_effect=debugger):
                _, artifacts = self.capture(hard=12, sleep=sleep,
                                            env={'CT_HANG_CLEANUP_AT': repr(cutoff)})
                self.assertLessEqual(clock[0], max(cutoff, owner_start + 1 + latency),
                                     'debugger or SIGQUIT tail passed owner cleanup')
                self.assertEqual(allowances, [] if allowance is None else [allowance])
                self.assertEqual((artifacts / 'error-1.log').read_text(), 'owned diagnostic\n')
                self.assertEqual(len(self.signals), 1)

    def test_invalid_owner_cutoff_uses_hard_deadline_fallback(self):
        for value in ('nan', 'inf', 'bogus', ''):
            clock = [100.]
            allowances = []

            def debugger(_command, allowances=allowances, **kwargs):
                allowances.append(kwargs['timeout'])

            with self.subTest(value=value), \
                    mock.patch.object(diagnostics.time, 'monotonic',
                                      side_effect=lambda c=clock: c[0]), \
                    mock.patch.object(diagnostics.subprocess, 'run', side_effect=debugger):
                self.capture(passive=True, hard=12, env={'CT_HANG_CLEANUP_AT': value})
            # Standalone budget: 12 - 1 soft - 4 owner reserve - .5 margin.
            self.assertEqual(allowances, [6.5])

    def test_exit_during_debugger_never_falls_back_to_numeric_signal(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
        fd = os.pidfd_open(child.pid)
        self.addCleanup(self.stop_child, child)

        def debugger(*_args, **_kwargs):
            signal.pidfd_send_signal(fd, signal.SIGKILL)
            child.wait()

        with mock.patch.object(diagnostics, 'discover', return_value=[(child.pid, fd, (1, 'x'))]), \
                mock.patch.object(diagnostics, 'error_logs', return_value=[]), \
                mock.patch.object(diagnostics.subprocess, 'run', side_effect=debugger), \
                mock.patch.object(diagnostics.time, 'sleep'), \
                mock.patch.object(diagnostics.os, 'kill') as numeric_kill, \
                mock.patch.dict(os.environ, CT_HANG_QUIT='1', CT_HANG_HARD_SECONDS='301'):
            diagnostics.capture(100, self.root / 'real-exit', 1)
            numeric_kill.assert_not_called()
        self.assertIsNotNone(child.returncode)

    @staticmethod
    def stop_child(child):
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)

    def test_child_cleanup_kills_before_bounded_wait(self):
        for status in (None, 0):
            with self.subTest(status=status):
                child = mock.Mock()
                child.poll.return_value = status
                self.stop_child(child)
                expected = [mock.call.poll()]
                if status is None:
                    expected.append(mock.call.kill())
                self.assertEqual(child.mock_calls, expected + [mock.call.wait(timeout=5)])

    def test_capture_helper_ignores_ambient_hard_deadline(self):
        with mock.patch.dict(os.environ, CT_HANG_HARD_SECONDS='1'):
            _, artifacts = self.capture(passive=True)
        self.assertEqual((artifacts / 'gdb-nginx-101.txt').read_text(),
                         'fixture backtrace\n')


if __name__ == "__main__":
    unittest.main()
