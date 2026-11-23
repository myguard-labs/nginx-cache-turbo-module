"""Exercise the real capture shell against an isolated process-filesystem fixture."""

import contextlib
import errno
import functools
import io
import os
import resource
import shutil
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


class Debugger:
    """Popen stand-in: its first wait(timeout) runs the test's debugger model."""

    def __init__(self, model, args, **_kwargs):
        self.model, self.args, self.returncode = model, args, None

    def wait(self, timeout=None):
        if self.returncode is None:
            self.model(self.args, timeout=timeout)
            self.returncode = 0
        return self.returncode

    def kill(self):
        if self.returncode is None:
            self.returncode = -signal.SIGKILL

    def terminate(self):
        if self.returncode is None:
            self.returncode = -signal.SIGTERM

    # subprocess.run() support keeps launch controls valid for a run() launcher.
    def communicate(self, _input=None, timeout=None):
        self.wait(timeout)
        return None, None

    def poll(self):
        return self.returncode

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.wait()


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
                mock.patch.object(diagnostics, 'exited', return_value=False), \
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

    @staticmethod
    def debugger(model):
        """Patch debugger launch; model(args, timeout=...) simulates one run."""
        def start(args, **kwargs):
            return Debugger(model, args, **kwargs)
        return mock.patch.object(diagnostics.subprocess, 'Popen', side_effect=start)

    def test_debugger_timeout_preserves_signal_and_log_snapshot(self):
        waits = []

        def hung(_args, timeout):
            waits.append(timeout)
            raise subprocess.TimeoutExpired('gdb', timeout)

        with self.debugger(hung) as debugger:
            _, artifacts = self.capture()
        self.assertEqual(len(self.signals), 1)
        self.assertEqual((artifacts / 'error-1.log').read_text(), 'owned diagnostic\n')
        self.assertIn('exceeded capture budget',
                      (artifacts / 'gdb-nginx-101.txt').read_text())
        command = debugger.call_args.args[0]
        self.assertEqual(command[:4], ['sudo', '-n', 'timeout', '--foreground'])
        self.assertIn('--kill-after=0.1s', command)
        self.assertEqual(len(waits), 1)
        self.assertGreater(waits[0], 0)

    def test_inner_timer_expiry_is_recorded(self):
        # timeout(1) can end gdb just before the outer wait raises TimeoutExpired.
        for status, marked in ((124, True), (137, True), (0, False), (1, False)):
            class Exits(Debugger):
                def wait(self, timeout=None, status=status):
                    if self.returncode is None:
                        self.returncode = status
                    return self.returncode

            def start(args, exits=Exits, **kwargs):
                return exits(None, args, **kwargs)

            with self.subTest(status=status), \
                    mock.patch.object(diagnostics.subprocess, 'Popen', side_effect=start):
                _, artifacts = self.capture(passive=True)
                output = (artifacts / 'gdb-nginx-101.txt').read_text()
                self.assertEqual('exceeded capture budget' in output, marked, output)
                self.assertEqual((artifacts / 'error-1.log').read_text(), 'owned diagnostic\n')

    def test_log_snapshot_keeps_a_bounded_tail_of_each_log(self):
        second = self.root / 'second instance/logs/error.log'
        second.parent.mkdir(parents=True)
        second.write_bytes(b'second diagnostic\n')  # Exactly the 18-byte bound.
        (self.proc / '101/fd/5').symlink_to(second)
        self.owned.write_bytes(b'x' * 40 + b'owned tail\n')
        with mock.patch.object(diagnostics, 'LOG_TAIL', 18):
            _, artifacts = self.capture(passive=True)
        self.assertEqual((artifacts / 'error-1.log').read_bytes(),
                         b'ci-hang-guard: first 33 bytes omitted\n' + b'x' * 7 + b'owned tail\n',
                         'a large log was copied beyond its tail bound')
        self.assertEqual((artifacts / 'error-2.log').read_bytes(), b'second diagnostic\n',
                         'a log at the bound lost bytes or gained a marker')

    def test_log_tail_bound_holds_when_the_log_grows_during_copy(self):
        self.owned.write_bytes(b'0123456789' * 3)
        target = io.BytesIO()
        with self.owned.open('rb') as source, \
                mock.patch.object(diagnostics, 'LOG_TAIL', 10), \
                mock.patch.object(diagnostics.os, 'fstat',
                                  return_value=os.stat_result((0,) * 10)):
            diagnostics.copy_tail(source, target)  # Size 0 at fstat; 30 bytes by copy.
        self.assertEqual(target.getvalue(), b'0123456789')

    def test_all_debuggers_share_remaining_capture_window(self):
        self.process(102, 101, 'nginx')
        clock = [100.]
        allowances = []

        def debugger(_command, **kwargs):
            # A hung debugger also spends the TERM grace before its deadline.
            allowances.append(kwargs['timeout'] + diagnostics.TERM_GRACE)
            clock[0] += allowances[-1]
            raise subprocess.TimeoutExpired('gdb', kwargs['timeout'])

        with mock.patch.object(diagnostics.time, 'monotonic', side_effect=lambda: clock[0]), \
                self.debugger(debugger), \
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
                mock.patch.object(diagnostics.subprocess, 'Popen') as debugger:
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
                    mock.patch.object(diagnostics, 'exited', return_value=True):
                self.assertEqual(diagnostics.discover(100), [])
            for fd in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_non_ascii_wrapper_name_keeps_live_nginx_child(self):
        # The kernel copies the task name's bytes into /proc/<pid>/stat as is.
        (self.bindir / 'nginx').symlink_to(sys.executable)
        for name in ('café'.encode(), b'\xff) x'):
            with self.subTest(name=name):
                wrapper = subprocess.Popen(
                    [sys.executable, '-c',
                     ('import ctypes,subprocess,sys; '
                      'ctypes.CDLL(None).prctl(15, bytes.fromhex(sys.argv[1]), 0, 0, 0); '
                      'subprocess.Popen(sys.argv[2:]).wait()'),
                     name.hex(), str(self.bindir / 'nginx'), '-c',
                     'import os,time; print(os.getpid(), flush=True); time.sleep(60)'],
                    stdout=subprocess.PIPE, text=True)
                self.addCleanup(self.stop_child, wrapper)
                pid = int(wrapper.stdout.readline())
                wrapper.stdout.close()
                pinned = os.pidfd_open(pid)  # The unreaped child cannot be a reused PID.
                self.addCleanup(os.close, pinned)
                self.addCleanup(signal.pidfd_send_signal, pinned, signal.SIGKILL)
                record = (Path('/proc') / str(wrapper.pid) / 'stat').read_bytes()
                self.assertIn(b'(' + name + b')', record, 'fixture did not rename the wrapper')
                processes = diagnostics.discover(os.getpid())
                try:
                    self.assertIn(pid, [item[0] for item in processes],
                                  'non-ASCII wrapper name lost its nginx child')
                finally:
                    for _, fd, _ in processes:
                        os.close(fd)

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
                mock.patch.object(diagnostics.subprocess, 'Popen') as debugger:
            _, artifacts = self.capture(passive=True)
        debugger.assert_not_called()
        self.assertIn('process identity changed',
                      (artifacts / 'gdb-nginx-101.txt').read_text())

    def test_unopenable_debugger_output_keeps_other_targets_and_logs(self):
        self.process(102, 101, 'nginx')  # Masters sort last, so 102 is debugged first.
        artifacts = self.root / 'artifacts'
        (artifacts / 'gdb-nginx-102.txt').mkdir(parents=True)
        result, artifacts = self.capture(passive=True)
        self.assertIn('gdb output unavailable pid=102', result.stderr)
        self.assertEqual((artifacts / 'gdb-nginx-101.txt').read_text(), 'fixture backtrace\n',
                         'an unopenable output skipped the next debugger')
        self.assertEqual((artifacts / 'error-1.log').read_text(), 'owned diagnostic\n',
                         'an unopenable output skipped the log snapshot')
        self.assertTrue((artifacts / 'gdb-nginx-102.txt').is_dir())

    def test_debugger_output_close_failure_keeps_other_targets_and_logs(self):
        self.process(102, 101, 'nginx')  # Masters sort last, so 102 is debugged first.
        original = diagnostics.Path.open

        class FailingClose:
            def __init__(self, stream):
                self.stream = stream

            def write(self, text):
                return self.stream.write(text)

            def fileno(self):  # Popen needs a real descriptor to start the debugger.
                return self.stream.fileno()

            def __enter__(self):
                return self

            def __exit__(self, *_exc):
                self.stream.close()
                raise OSError(errno.ENOSPC, 'No space left on device')

        def opened(path, *args, **kwargs):
            stream = original(path, *args, **kwargs)
            return FailingClose(stream) if path.name == 'gdb-nginx-102.txt' else stream

        with mock.patch.object(diagnostics.Path, 'open', opened):
            result, artifacts = self.capture(passive=True)
        self.assertIn('gdb output failed pid=102', result.stderr)
        self.assertEqual((artifacts / 'gdb-nginx-102.txt').read_text(), 'fixture backtrace\n',
                         'the failing target never ran its debugger')
        self.assertEqual((artifacts / 'gdb-nginx-101.txt').read_text(), 'fixture backtrace\n',
                         'a failed close skipped the next debugger')
        self.assertEqual((artifacts / 'error-1.log').read_text(), 'owned diagnostic\n',
                         'a failed close skipped the log snapshot')

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
                self.debugger(debugger):
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

            logs = []

            def open_log(name, *args, logs=logs, **kwargs):
                stream = open(name, *args, **kwargs)
                logs.append(stream)
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
                    mock.patch.object(diagnostics, 'exited', return_value=False), \
                    mock.patch.object(diagnostics.os, 'fdopen', open_file), \
                    mock.patch.object(diagnostics, 'open', open_log, create=True), \
                    mock.patch.object(diagnostics.os, 'fstat', side_effect=stat):
                if error is PermissionError:
                    self.assertEqual(diagnostics.error_logs([(101, -1, (100, '101'))]), [])
                else:
                    with self.assertRaises(KeyboardInterrupt):
                        diagnostics.error_logs([(101, -1, (100, '101'))])
            self.assertTrue(opened)
            self.assertTrue(logs, 'control did not open a log stream')
            self.assertTrue(all(stream.closed for stream in opened + logs))

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

    def test_fd_number_reused_after_readlink_cannot_supply_other_file(self):
        other = self.owned.with_name('access.log')
        other.write_text('access record\n')
        reused = self.proc / '101/fd/4'
        (self.proc / '101/fd/5').symlink_to(self.owned)
        # nginx closes error.log and reuses fd 4 after readlink: before the
        # stat that follows the number, or before the open that follows it.
        # 'aba': fd 4 names access.log, error.log during the readlink, and
        # access.log again before the open.
        for call in ('stat', 'open', 'aba'):
            reused.unlink()
            reused.symlink_to(other if call == 'aba' else self.owned)
            swaps = ({'readlink': self.owned, 'open': other} if call == 'aba'
                     else {call: other})
            fired = []

            def reuse(name, *args, original, target, fired=fired, **kwargs):
                if name == '4' and kwargs.get('dir_fd') is not None:
                    fired.append(original.__name__)
                    reused.unlink()
                    reused.symlink_to(target)
                return original(name, *args, **kwargs)

            with self.subTest(reused_before=call), \
                    mock.patch.object(diagnostics, 'PROC', self.proc), \
                    mock.patch.object(diagnostics, 'exited', return_value=False), \
                    contextlib.ExitStack() as stack:
                for function, target in swaps.items():
                    stack.enter_context(mock.patch.object(
                        diagnostics.os, function, side_effect=functools.partial(
                            reuse, original=getattr(os, function), target=target)))
                streams = diagnostics.error_logs([(101, -1, (100, '101'))])
                try:
                    contents = [stream.read() for stream in streams]
                finally:
                    for stream in streams:
                        stream.close()
                self.assertEqual(sorted(fired), sorted(swaps), 'control did not reuse fd 4')
                self.assertEqual(contents, [b'owned diagnostic\n'],
                                 'a reused fd number supplied a file other than error.log')

    def test_rotation_during_log_discovery_keeps_original_inode(self):
        rotated = self.owned.with_name('error.log.1')
        link = self.proc / '101/fd/4'
        original = os.open

        def rotate():
            # logrotate renames the file; procfs then names the inode error.log.1,
            # and nginx later reopens a new error.log on another descriptor.
            self.owned.rename(rotated)
            link.unlink()
            link.symlink_to(rotated)
            self.owned.write_text('replacement log\n')

        # Rotated before the name check, after it, after the open, or rotated
        # and then removed after the open (procfs appends " (deleted)").
        for when in ('already', 'before', 'after', 'deleted'):
            rotated.unlink(missing_ok=True)
            self.owned.write_text('owned diagnostic\n')
            link.unlink()
            link.symlink_to(self.owned)
            if when == 'already':
                rotate()
            rotations = []

            def opener(name, *args, when=when, rotations=rotations, **kwargs):
                if name != '4' or kwargs.get('dir_fd') is None:
                    return original(name, *args, **kwargs)
                rotations.append(when)
                if when == 'before':
                    rotate()
                fd = original(name, *args, **kwargs)
                if when in ('after', 'deleted'):
                    rotate()
                if when == 'deleted':
                    rotated.unlink()
                return fd

            with self.subTest(rotated=when), \
                    mock.patch.object(diagnostics, 'PROC', self.proc), \
                    mock.patch.object(diagnostics, 'exited', return_value=False), \
                    mock.patch.object(diagnostics.os, 'open', side_effect=opener):
                streams = diagnostics.error_logs([(101, -1, (100, '101'))])
                try:
                    contents = [stream.read() for stream in streams]
                finally:
                    for stream in streams:
                        stream.close()
                self.assertEqual(rotations, [when], 'control did not open the log fd')
                self.assertEqual(contents, [b'owned diagnostic\n'],
                                 'a log rotated during discovery was discarded')

    def test_error_log_name_accepts_only_error_log_and_its_rotations(self):
        for target in ('/l/error.log', '/l/error.log.1', '/l/error.log-20261122',
                       '/l/error.log.1 (deleted)', '/l/error.log (deleted)'):
            with self.subTest(target=target):
                self.assertTrue(diagnostics.error_log_name(target))
        for target in ('/l/access.log', '/l/error.logger', '/l/error.log1', '/l/xerror.log',
                       '/l/access.log.1', '/l/error.log (deleted) x', '/error.log/x', ''):
            with self.subTest(target=target):
                self.assertFalse(diagnostics.error_log_name(target))

    def test_fd_number_reused_as_directory_releases_opened_descriptor(self):
        reused = self.proc / '101/fd/4'
        (self.proc / '101/fd/5').symlink_to(self.owned)
        original = os.open
        opened = []

        def reuse(name, *args, **kwargs):
            if name == '4' and kwargs.get('dir_fd') is not None:
                # After the regular-file stat, nginx reuses fd 4 for a directory.
                reused.unlink()
                reused.symlink_to(self.owned.parent)
                fd = original(name, *args, **kwargs)
                status = os.fstat(fd)
                opened.append((fd, (status.st_dev, status.st_ino)))
                return fd
            return original(name, *args, **kwargs)

        def leaked():
            for fd, key in opened:
                try:
                    status = os.fstat(fd)
                except OSError:
                    continue
                if (status.st_dev, status.st_ino) == key:
                    yield fd

        self.addCleanup(lambda: [os.close(fd) for fd in list(leaked())])
        with mock.patch.object(diagnostics, 'PROC', self.proc), \
                mock.patch.object(diagnostics, 'exited', return_value=False), \
                mock.patch.object(diagnostics.os, 'open', side_effect=reuse):
            streams = diagnostics.error_logs([(101, -1, (100, '101'))])
        try:
            contents = [stream.read() for stream in streams]
        finally:
            for stream in streams:
                stream.close()
        self.assertEqual(len(opened), 1, 'control did not reuse the number as a directory')
        self.assertEqual(list(leaked()), [], 'a rejected directory descriptor stayed open')
        self.assertEqual(contents, [b'owned diagnostic\n'])

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
        # The tail cutoff is 1007.5: a capture reaching SIGQUIT at or after it sends none.
        for latency, allowance, quits in ((0., 1.5, 1), (2., None, 1), (6.4, None, 1),
                                          (6.5, None, 0), (9., None, 0)):
            clock = [owner_start + 1 + latency]
            allowances = []

            def debugger(_command, clock=clock, allowances=allowances, **kwargs):
                # The allowance runs from launch to the deadline, TERM grace included.
                allowances.append(kwargs['timeout'] + diagnostics.TERM_GRACE)
                clock[0] += kwargs['timeout']

            def sleep(seconds, clock=clock):
                self.assertGreaterEqual(seconds, 0)
                clock[0] += seconds

            with self.subTest(latency=latency), \
                    mock.patch.object(diagnostics.time, 'monotonic',
                                      side_effect=lambda c=clock: c[0]), \
                    self.debugger(debugger):
                _, artifacts = self.capture(hard=12, sleep=sleep,
                                            env={'CT_HANG_CLEANUP_AT': repr(cutoff)})
                self.assertLessEqual(clock[0], max(cutoff, owner_start + 1 + latency),
                                     'debugger or SIGQUIT tail passed owner cleanup')
                self.assertEqual([round(value, 6) for value in allowances],
                                 [] if allowance is None else [allowance])
                self.assertEqual((artifacts / 'error-1.log').read_text(), 'owned diagnostic\n')
                self.assertEqual(len(self.signals), quits, 'SIGQUIT after the tail cutoff')

    def test_debugger_allowance_charges_launch_preflight(self):
        # Passive capture with owner cleanup at 1008 lets debuggers run until 1007.5.
        original = diagnostics.process_stat
        for delay, expected in ((2., [.5]), (2.25, [])):
            clock = [1005.]
            allowances = []
            calls = []

            def slow(path, clock=clock, calls=calls, delay=delay):
                if path.parent.name == '101':
                    calls.append(path)
                    # Snapshot, discovery recheck, pre-budget identity, launch recheck.
                    if len(calls) == 4:
                        clock[0] += delay
                return original(path)

            def debugger(_command, clock=clock, allowances=allowances, **kwargs):
                # The allowance runs from launch to the deadline, TERM grace included.
                allowances.append(kwargs['timeout'] + diagnostics.TERM_GRACE)
                clock[0] += kwargs['timeout']

            with self.subTest(delay=delay), \
                    mock.patch.object(diagnostics.time, 'monotonic',
                                      side_effect=lambda c=clock: c[0]), \
                    mock.patch.object(diagnostics, 'process_stat', side_effect=slow), \
                    self.debugger(debugger):
                _, artifacts = self.capture(passive=True, hard=12,
                                            env={'CT_HANG_CLEANUP_AT': repr(1008.)})
                self.assertEqual(len(calls), 4, 'control did not delay the launch recheck')
                self.assertLessEqual(clock[0], 1007.5, 'debugger ran past its snapshot margin')
                self.assertEqual([round(value, 6) for value in allowances], expected)
                if not expected:
                    self.assertIn('capture budget exhausted',
                                  (artifacts / 'gdb-nginx-101.txt').read_text())

    def test_invalid_owner_cutoff_uses_hard_deadline_fallback(self):
        for value in ('nan', 'inf', 'bogus', ''):
            clock = [100.]
            allowances = []

            def debugger(_command, allowances=allowances, **kwargs):
                allowances.append(kwargs['timeout'] + diagnostics.TERM_GRACE)

            with self.subTest(value=value), \
                    mock.patch.object(diagnostics.time, 'monotonic',
                                      side_effect=lambda c=clock: c[0]), \
                    self.debugger(debugger):
                self.capture(passive=True, hard=12, env={'CT_HANG_CLEANUP_AT': value})
            # Standalone budget: 12 - 1 soft - 4 owner reserve - .5 margin.
            self.assertEqual([round(value, 6) for value in allowances], [6.5])

    def test_exit_during_debugger_never_falls_back_to_numeric_signal(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
        fd = os.pidfd_open(child.pid)
        self.addCleanup(self.stop_child, child)

        def debugger(*_args, **_kwargs):
            signal.pidfd_send_signal(fd, signal.SIGKILL)
            child.wait()

        with mock.patch.object(diagnostics, 'discover', return_value=[(child.pid, fd, (1, 'x'))]), \
                mock.patch.object(diagnostics, 'error_logs', return_value=[]), \
                self.debugger(debugger), \
                mock.patch.object(diagnostics.time, 'sleep'), \
                mock.patch.object(diagnostics.os, 'kill') as numeric_kill, \
                mock.patch.dict(os.environ, CT_HANG_QUIT='1', CT_HANG_HARD_SECONDS='301'):
            os.environ.pop('CT_HANG_CLEANUP_AT', None)  # An ambient cutoff skips the debugger.
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


    def test_debugger_launch_latency_is_charged_to_its_deadline(self):
        # Passive capture with owner cleanup at 1008 lets debuggers run until 1007.5.
        # The debugger ignores TERM, so the post-TERM wait spends its whole grace.
        # A launch inside the last grace (2.4) or at the deadline (2.5) stops one
        # grace after launch: the snapshot then uses part of the .5s margin.
        copy = shutil.copyfileobj
        for latency in (0., 1., 2.4, 2.5):
            clock = [1005.]
            waits = []
            snapshots = []

            class Stubborn(Debugger):
                def wait(self, timeout=None, clock=clock, waits=waits):
                    if self.returncode is None:
                        waits.append(timeout)
                        clock[0] += timeout
                        raise subprocess.TimeoutExpired('gdb', timeout)
                    return self.returncode

                def terminate(self):
                    pass  # TERM is ignored; only the KILL fallback ends it.

            def start(args, clock=clock, latency=latency, stubborn=Stubborn, **kwargs):
                clock[0] += latency  # Work before Popen returns.
                return stubborn(None, args, **kwargs)

            def snapshot(source, target, clock=clock, snapshots=snapshots):
                # shutil is shared: count only the error-log snapshot copies.
                if Path(target.name).name.startswith('error-'):
                    snapshots.append(clock[0])
                return copy(source, target)

            with self.subTest(latency=latency), \
                    mock.patch.object(diagnostics.time, 'monotonic',
                                      side_effect=lambda c=clock: c[0]), \
                    mock.patch.object(diagnostics.shutil, 'copyfileobj', side_effect=snapshot), \
                    mock.patch.object(diagnostics.subprocess, 'Popen',
                                      side_effect=start) as debugger:
                _, artifacts = self.capture(passive=True, hard=12,
                                            env={'CT_HANG_CLEANUP_AT': repr(1008.)})
                self.assertEqual(debugger.call_count, 1)
                # TERM at max(launch, end - grace), then the whole grace, then KILL.
                self.assertEqual(len(waits), 2)
                self.assertAlmostEqual(waits[0], max(0., 2.5 - diagnostics.TERM_GRACE - latency))
                self.assertAlmostEqual(waits[1], diagnostics.TERM_GRACE)
                stop = 1005. + max(latency, 2.5 - diagnostics.TERM_GRACE) + diagnostics.TERM_GRACE
                self.assertEqual(len(snapshots), 1)
                self.assertAlmostEqual(snapshots[0], stop)
                self.assertLessEqual(snapshots[0], 1007.5 + diagnostics.TERM_GRACE + 1e-9,
                                     'debugger stop consumed more than one grace of the margin')
                self.assertLess(snapshots[0], 1008., 'log snapshot passed owner cleanup')
                self.assertIn('exceeded capture budget',
                              (artifacts / 'gdb-nginx-101.txt').read_text())
                self.assertEqual((artifacts / 'error-1.log').read_text(), 'owned diagnostic\n')

    @unittest.skipUnless(shutil.which('timeout'), 'coreutils timeout unavailable')
    def test_debugger_deadline_reaps_the_wrapped_debugger(self):
        # A real timeout(1) wrapper: its inner timer outlives the outer deadline.
        record = self.root / 'debugger.pid'
        launched = []
        pinned = []
        real = subprocess.Popen

        def kill(fd):
            try:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            except ProcessLookupError:
                pass

        def start(*args, **kwargs):
            launched.append(real(*args, **kwargs))
            self.addCleanup(self.stop_child, launched[-1])
            # Pin the debugger while it is alive: nothing signals it before
            # debug() gets this Popen back, so its recorded PID is not reused.
            end = diagnostics.time.monotonic() + 5
            while not record.exists() or not record.read_text().endswith('\n'):
                self.assertLess(diagnostics.time.monotonic(), end, 'debugger PID not recorded')
                diagnostics.time.sleep(.01)
            pinned.append(os.pidfd_open(int(record.read_text())))
            self.addCleanup(os.close, pinned[-1])
            self.addCleanup(kill, pinned[-1])
            return launched[-1]

        command = ['timeout', '--foreground', '--signal=TERM', '--kill-after=0.1s', '30s',
                   'sh', '-c', 'echo $$ > "$1"; exec sleep 30', 'sh', str(record)]
        started = diagnostics.time.monotonic()
        with (self.root / 'gdb.txt').open('w') as stream, \
                mock.patch.object(diagnostics.subprocess, 'Popen', side_effect=start), \
                self.assertRaises(subprocess.TimeoutExpired):
            diagnostics.debug(command, stream, started + 1.5)
        # The wrapper reaps the debugger before exiting; fdinfo Pid -1 means reaped.
        reaped = Path('/proc/self/fdinfo/' + str(pinned[0])).read_text(encoding='ascii')
        self.assertIn('Pid:\t-1\n', reaped, 'the debugger outlived its deadline')
        self.assertNotEqual(launched[0].returncode, -signal.SIGKILL,
                            'the wrapper needed the KILL fallback')
        self.assertLess(diagnostics.time.monotonic() - started, 3)

    def test_debugger_ignoring_term_is_killed_after_grace(self):
        # A launch past end still gets the whole grace: stopping ends one grace later.
        real = subprocess.Popen
        for latency in (0., .4):
            launched = []

            def start(*args, latency=latency, launched=launched, **kwargs):
                diagnostics.time.sleep(latency)  # Work before Popen returns.
                # An ignored disposition survives exec, so TERM can never win a race.
                previous = signal.signal(signal.SIGTERM, signal.SIG_IGN)
                try:
                    launched.append(real(*args, **kwargs))
                finally:
                    signal.signal(signal.SIGTERM, previous)
                # A debug() that fails to kill the TERM-ignoring child must not leak it.
                self.addCleanup(self.stop_child, launched[-1])
                return launched[-1]

            started = diagnostics.time.monotonic()
            with self.subTest(latency=latency), \
                    (self.root / 'gdb.txt').open('w') as stream, \
                    mock.patch.object(diagnostics.subprocess, 'Popen', side_effect=start), \
                    self.assertRaises(subprocess.TimeoutExpired):
                diagnostics.debug(['sleep', '30'], stream, started + .3)
            elapsed = diagnostics.time.monotonic() - started
            self.assertEqual(launched[0].returncode, -signal.SIGKILL)
            # TERM at max(launch, end - grace); KILL one grace later.
            stop = max(latency, .3 - diagnostics.TERM_GRACE) + diagnostics.TERM_GRACE
            self.assertGreaterEqual(elapsed, stop - .05)
            self.assertLess(elapsed, stop + 2)

    def test_exited_reports_exit_and_closed_descriptor(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
        self.addCleanup(self.stop_child, child)
        fd = os.pidfd_open(child.pid)
        try:
            self.assertFalse(diagnostics.exited(fd))
            child.kill()
            child.wait(timeout=5)
            self.assertTrue(diagnostics.exited(fd))
        finally:
            os.close(fd)
        with self.assertRaises(OSError) as raised:
            diagnostics.exited(fd)
        self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_pidfds_above_select_limit_still_select_live_nginx(self):
        # select() rejects descriptors >= FD_SETSIZE (1024); pidfd checks must not.
        log = self.root / 'high/logs/error.log'
        log.parent.mkdir(parents=True)
        log.write_text('high diagnostic\n')
        (self.bindir / 'nginx').symlink_to(sys.executable)
        # A live intermediate parent gives discovery ancestor pidfds to check.
        parent = subprocess.Popen(
            [sys.executable, '-c', 'import subprocess,sys; subprocess.Popen(sys.argv[1:]).wait()',
             str(self.bindir / 'nginx'), '-c',
             ('import os,sys,time; stream=open(sys.argv[1]); print(os.getpid(), flush=True); '
              'time.sleep(60)'), str(log)], stdout=subprocess.PIPE, text=True)
        self.addCleanup(self.stop_child, parent)
        pid = int(parent.stdout.readline())
        parent.stdout.close()
        pinned = os.pidfd_open(pid)  # The unreaped child cannot be a reused PID.
        self.addCleanup(os.close, pinned)
        self.addCleanup(signal.pidfd_send_signal, pinned, signal.SIGKILL)
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        need = 1100
        if soft < need:
            if hard != resource.RLIM_INFINITY and hard < need:
                self.skipTest(f'RLIMIT_NOFILE hard limit {hard} < {need}')
            resource.setrlimit(resource.RLIMIT_NOFILE, (need, hard))
            self.addCleanup(resource.setrlimit, resource.RLIMIT_NOFILE, (soft, hard))
        filler = []
        self.addCleanup(lambda: [os.close(fd) for fd in filler])
        while not filler or filler[-1] < 1023:
            filler.append(os.open('/dev/null', os.O_RDONLY))  # Later fds are >= 1024.
        identity = diagnostics.process_stat(Path('/proc') / str(pid) / 'stat')
        with self.subTest(site='discovery ancestors'):
            processes = diagnostics.discover(os.getpid())
            try:
                self.assertIn(pid, [item[0] for item in processes])
                self.assertTrue(all(fd >= 1024 for _, fd, _ in processes))
            finally:
                for _, fd, _ in processes:
                    os.close(fd)
        with self.subTest(site='log enumeration'):
            fd = os.pidfd_open(pid)
            try:
                self.assertGreaterEqual(fd, 1024)
                streams = diagnostics.error_logs([(pid, fd, identity)])
                try:
                    self.assertEqual([stream.read() for stream in streams], [b'high diagnostic\n'])
                finally:
                    for stream in streams:
                        stream.close()
            finally:
                os.close(fd)
        with self.subTest(site='debugger launch'):
            launched = []
            fd = os.pidfd_open(pid)  # capture() closes the records it receives.
            self.assertGreaterEqual(fd, 1024)
            with mock.patch.object(diagnostics, 'discover', return_value=[(pid, fd, identity)]), \
                    self.debugger(lambda args, timeout: launched.append(args)), \
                    mock.patch.dict(os.environ, CT_HANG_QUIT='0', CT_HANG_HARD_SECONDS='301'), \
                    contextlib.redirect_stderr(io.StringIO()):
                os.environ.pop('CT_HANG_CLEANUP_AT', None)
                diagnostics.capture(os.getpid(), self.root / 'high-fd', 1)
            self.assertEqual(len(launched), 1, 'a live high-fd target lost its debugger')
            self.assertEqual((self.root / 'high-fd/error-1.log').read_text(), 'high diagnostic\n')


if __name__ == "__main__":
    unittest.main()
