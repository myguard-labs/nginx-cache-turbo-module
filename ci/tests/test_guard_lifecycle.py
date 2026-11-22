"""Harmless Linux process lifecycle controls; no nginx or diagnostic attachments."""

import ctypes
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from functools import partial
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
GUARD = ROOT / "ci/tools/ci-hang-guard.sh"
sys.path.insert(0, str(ROOT / "ci/tools"))
import ci_child_observer as observer
import ci_guard_lifecycle as lifecycle

FIXTURE = r"""
import json, os, pathlib, signal, subprocess, sys, time
if sys.argv[2] == 'stubborn':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
child = subprocess.Popen([sys.executable, '-c',
    'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)'],
    start_new_session=sys.argv[2] == 'escape')
ids = {'command': os.getpid(), 'descendant': child.pid, 'owner': os.getppid()}
ids['starts'] = {str(pid): pathlib.Path('/proc/' + str(pid) + '/stat').read_text()
                .split(') ')[1].split()[19] for pid in ids.values()}
target = pathlib.Path(sys.argv[1])
partial = target.with_suffix('.partial')
partial.write_text(json.dumps(ids))
partial.replace(target)
if sys.argv[2] == 'exit':
    raise SystemExit(23)
time.sleep(60)
"""


class GuardLifecycleTests(unittest.TestCase):
    def setUp(self):
        # Adopt only this test's orphaned fixture/guardian for cleanup even on RED.
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.prior = ctypes.c_int()
        self.assertEqual(self.libc.prctl(37, ctypes.byref(self.prior), 0, 0, 0), 0)
        self.assertEqual(self.libc.prctl(36, 1, 0, 0, 0), 0)
        self.tmp = tempfile.TemporaryDirectory(prefix='guard-lifecycle-')
        self.directory = Path(self.tmp.name)
        self.handles = {}
        self.processes = []
        self.logs = []

    def tearDown(self):
        for fd in self.handles.values():
            try:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for process in self.processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
        for pid, fd in self.handles.items():
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
            os.close(fd)
        for log in self.logs:
            log.close()
        self.libc.prctl(36, self.prior.value, 0, 0, 0)
        self.tmp.cleanup()

    def pin(self, pid, start=None):
        if pid not in self.handles:
            try:
                fd = os.pidfd_open(pid)
            except ProcessLookupError:
                return
            if start is not None:
                try:
                    actual = Path('/proc/' + str(pid) + '/stat').read_text().split(') ')[1]
                    matches = actual.split()[19] == start
                except FileNotFoundError:
                    matches = False
                if not matches:
                    os.close(fd)
                    return  # A reused PID never authorizes fixture cleanup.
            self.handles[pid] = fd

    def pin_fixture(self, ids):
        for key in ('command', 'descendant', 'owner'):
            self.pin(ids[key], ids['starts'][str(ids[key])])

    def until(self, predicate, message, timeout=5):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if predicate():
                return
            time.sleep(.01)
        self.fail(message)

    def start(self, mode='stubborn', *, soft=10, hard=20, enabled=True):
        identity = self.directory / ('ids-' + str(len(self.processes)) + '.json')
        log = (self.directory / ('guard-' + str(len(self.processes)) + '.log')).open('w+')
        self.logs.append(log)
        env = dict(os.environ, CT_OUTCOME_OBSERVE='1' if enabled else '0',
                   CT_HANG_HARD_SECONDS=str(hard))
        process = subprocess.Popen(['sh', str(GUARD), str(soft), str(self.directory), '--',
                                    sys.executable, '-c', FIXTURE, str(identity), mode],
                                   env=env, stdout=log, stderr=log)
        self.processes.append(process)
        self.pin(process.pid)
        self.until(identity.exists, 'command did not start')
        ids = json.loads(identity.read_text())
        self.pin_fixture(ids)
        return process, ids, log

    def gone(self, ids):
        # pidfd fdinfo distinguishes a reaped identity from a reused numeric PID.
        def reaped(key):
            fd = self.handles.get(ids[key])
            return fd is None or 'Pid:\t-1\n' in Path('/proc/self/fdinfo/' + str(fd)).read_text()

        self.until(lambda: all(reaped(k) for k in ('command', 'descendant')),
                   'owned command descendants survived or were not reaped')

    def test_guard_sigkill_cleans_owned_group_and_excludes_neighbour(self):
        neighbour = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
        self.processes.append(neighbour)
        self.pin(neighbour.pid)
        guard, ids, _ = self.start()
        guard.kill()
        guard.wait(timeout=5)
        self.gone(ids)
        self.assertIsNone(neighbour.poll(), 'cleanup signalled an unrelated neighbour')
        self.assertFalse(list(self.directory.glob('termination-*/termination.json')),
                         'killed observer published a completed observation')

    def test_term_and_int_preserve_signal_status_and_cleanup(self):
        for sig in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=sig):
                guard, ids, _ = self.start()
                guard.send_signal(sig)
                self.assertEqual(guard.wait(timeout=5), 128 + sig)
                self.gone(ids)

    def test_normal_error_exit_reaps_stubborn_leftover(self):
        guard, ids, _ = self.start('exit')
        self.assertEqual(guard.wait(timeout=5), 23)
        self.gone(ids)

    def test_hard_deadline_and_earlier_capture(self):
        breadcrumb = self.directory / 'breadcrumb'
        breadcrumb.write_text('test_inert')
        old = os.environ.get('CT_TEST_BREADCRUMB')
        os.environ['CT_TEST_BREADCRUMB'] = str(breadcrumb)
        try:
            guard, ids, log = self.start(soft=.1, hard=1)
        finally:
            if old is None:
                os.environ.pop('CT_TEST_BREADCRUMB')
            else:
                os.environ['CT_TEST_BREADCRUMB'] = old
        self.assertEqual(guard.wait(timeout=5), 124)
        self.gone(ids)
        self.assertEqual((self.directory / 'hanging-test.txt').read_text(), 'test_inert')
        log.seek(0)
        self.assertIn('soft timeout', log.read())
        record = json.loads(next(self.directory.glob('termination-*/termination.json')).read_text())
        self.assertEqual(record['returncode'], -signal.SIGKILL)

    def test_escaped_descendant_is_adopted_and_reaped(self):
        guard, ids, _ = self.start('escape', soft=.1, hard=1)
        self.assertEqual(guard.wait(timeout=5), 124)
        self.gone(ids)

    def test_caller_death_triggers_cleanup(self):
        identity = self.directory / 'parent-ids.json'
        parent = subprocess.Popen([sys.executable, '-c',
            ('import os,subprocess,sys,time; p=subprocess.Popen(sys.argv[1:]); '
             'print(p.pid,flush=True); time.sleep(60)'),
            'sh', str(GUARD), '10', str(self.directory), '--', sys.executable,
            '-c', FIXTURE, str(identity), 'stubborn'],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self.processes.append(parent)
        self.pin(parent.pid)
        guard_pid = int(parent.stdout.readline())
        self.pin(guard_pid)
        parent.stdout.close()
        self.until(identity.exists, 'command did not start')
        ids = json.loads(identity.read_text())
        self.pin_fixture(ids)
        parent.kill()
        parent.wait(timeout=5)
        self.gone(ids)
        status_file = Path('/proc/' + str(guard_pid) + '/stat')
        self.until(lambda: status_file.read_text(encoding='ascii').split(') ')[1][0] == 'Z',
                   'guard failed to finish after parent death')
        _, status = os.waitpid(guard_pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 125)

    def test_normal_exit_allows_capture_tail_and_preserves_status(self):
        command_script = ("import pathlib,sys,time\n"
                          "while not pathlib.Path(sys.argv[1]).exists(): time.sleep(.005)\n"
                          "raise SystemExit(int(sys.argv[2]))")
        capture_script = ("import pathlib,sys,time; pathlib.Path(sys.argv[1]).touch(); "
                          "time.sleep(.15); pathlib.Path(sys.argv[2]).write_text('complete')")
        for status in (0, 23):
            with self.subTest(status=status):
                ready = self.directory / ('tail-ready-' + str(status))
                snapshot = self.directory / ('tail-snapshot-' + str(status))
                result = lifecycle.run_owned(
                    [sys.executable, '-c', command_script, str(ready), str(status)],
                    None, self.pin, soft=0, hard=2,
                    capture=lambda pid, ready=ready, snapshot=snapshot: [
                        sys.executable, '-c', capture_script, str(ready), str(snapshot)])
                self.assertTrue(snapshot.exists(), 'normal command exit truncated diagnostic tail')
                self.assertEqual(snapshot.read_text(), 'complete')
                self.assertEqual(result['status'], status)
                self.assertEqual(result['code'], status)

    def test_capture_launch_failure_preserves_command_and_hard_bound(self):
        ready = self.directory / 'capture-failed-ready'
        waiting_command = ("import pathlib,sys,time\n"
                           "while not pathlib.Path(sys.argv[1]).exists(): time.sleep(.005)\n"
                           "raise SystemExit(23)")

        def capture(_pid):
            ready.touch()
            return [str(self.directory / 'missing-capture')]

        exited = lifecycle.OwnedProcess.exited

        def delayed_exited(process):
            if not getattr(process, 'scheduling_delayed', False):
                process.scheduling_delayed = True
                time.sleep(.2)  # The former .15s fixture could finish before capture.
            return exited(process)

        for command, expected, hard in (
                (waiting_command, 23, 2),
                ("import time; time.sleep(60)", 124, 1)):
            with self.subTest(expected=expected), \
                    mock.patch.object(lifecycle.OwnedProcess, 'exited', delayed_exited):
                result = lifecycle.run_owned(
                    [sys.executable, '-c', command, str(ready)], None, self.pin,
                    soft=0, hard=hard, capture=capture)
                self.assertEqual(result['status'], expected,
                                 'diagnostic launch failure replaced the command outcome')
                self.assertEqual(result['capture_error'], 'FileNotFoundError')
                self.assertEqual(result['code'], 23 if expected == 23 else -signal.SIGTERM)

    def test_stubborn_tail_is_bounded_and_preserves_exited_command_status(self):
        ready = self.directory / 'stubborn-tail-ready'
        command_script = ("import pathlib,sys,time\n"
                          "while not pathlib.Path(sys.argv[1]).exists(): time.sleep(.005)\n"
                          "raise SystemExit(23)")
        capture_script = ("import pathlib,signal,sys,time; "
                          "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                          "pathlib.Path(sys.argv[1]).touch(); time.sleep(60)")
        started = time.monotonic()
        result = lifecycle.run_owned(
            [sys.executable, '-c', command_script, str(ready)], None, self.pin,
            soft=0, hard=1,
            capture=lambda pid: [sys.executable, '-c', capture_script, str(ready)])
        self.assertLess(time.monotonic() - started, 30, 'stubborn tail exceeded capture deadline')
        self.assertTrue(ready.exists(), 'capture never started')
        self.assertEqual(result['reason'], 'command exit')
        self.assertEqual(result['status'], 23)
        self.assertEqual(result['code'], 23)

    def test_capture_receives_owner_cleanup_instant(self):
        record = self.directory / 'capture-clock.json'
        capture_script = ('import json,os,pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text('
                          'json.dumps([time.monotonic(), os.environ.get("CT_HANG_CLEANUP_AT")]))')
        soft, hard = .2, 2
        before = time.monotonic()
        result = lifecycle.run_owned(
            [sys.executable, '-c', 'import time; time.sleep(60)'], None, self.pin,
            soft=soft, hard=hard,
            capture=lambda pid: [sys.executable, '-c', capture_script, str(record)])
        after = time.monotonic()
        self.assertEqual(result['status'], 124)
        started, cutoff = json.loads(record.read_text())
        self.assertIsNotNone(cutoff, 'owner did not pass its cleanup instant')
        reserve = 2 * min(2., hard / 5)
        # Owner start lies after `before` and at least soft before capture start;
        # the capture budget therefore cannot absorb its own launch latency.
        self.assertGreaterEqual(float(cutoff), before + hard - reserve)
        self.assertLessEqual(float(cutoff), started - soft + hard - reserve)
        self.assertLessEqual(float(cutoff), after)

    def test_blocked_capture_is_isolated_and_cannot_extend_deadline(self):
        identity = self.directory / 'capture-command.json'
        capture_file = self.directory / 'capture.json'
        capture_script = (
            'import json,os,pathlib,sys,time; '
            'pathlib.Path(sys.argv[1]).write_text(json.dumps('
            '{"pid":os.getpid(),"start":pathlib.Path("/proc/self/stat").read_text()'
            '.rsplit(") ",1)[1].split()[19],"group":os.getpgrp(),"parent":os.getppid(),'
            '"command_group":os.getpgid(int(sys.argv[2]))})); time.sleep(60)')
        result = lifecycle.run_owned(
            [sys.executable, '-c', FIXTURE, str(identity), 'stubborn'], None, lambda pid: None,
            soft=0, hard=1,
            capture=lambda pid: [sys.executable, '-c', capture_script, str(capture_file), str(pid)])
        ids = json.loads(identity.read_text())
        diagnostic = json.loads(capture_file.read_text())
        self.pin_fixture(ids)
        self.pin(diagnostic['pid'], diagnostic['start'])
        self.assertEqual(result['status'], 124)
        self.assertEqual(result['code'], -signal.SIGKILL)
        self.assertEqual(diagnostic['parent'], ids['owner'])
        self.assertEqual(diagnostic['command_group'], ids['command'])
        self.assertEqual(diagnostic['group'], diagnostic['pid'])
        self.assertNotEqual(diagnostic['group'], diagnostic['command_group'])
        self.gone(ids)
        try:
            current = Path('/proc/' + str(diagnostic['pid']) + '/stat').read_text()
        except FileNotFoundError:
            current = None
        self.assertTrue(current is None or current.rsplit(') ', 1)[1].split()[19]
                        != diagnostic['start'], 'owned diagnostic survived cleanup')

    def test_owner_sigkill_fails_closed_without_cleanup_claim(self):
        guard, ids, log = self.start()
        # This is the explicit guarantee boundary: killing the cleanup owner
        # itself cannot be repaired by that owner. The test harness releases it.
        signal.pidfd_send_signal(self.handles[ids['owner']], signal.SIGKILL)
        self.assertEqual(guard.wait(timeout=5), 125)
        self.assertFalse(list(self.directory.glob('termination-*/termination.json')))
        log.seek(0)
        self.assertIn('TERMINATION UNKNOWN', log.read())

    def test_disabled_observation_still_cleans_up(self):
        guard, ids, _ = self.start(enabled=False, soft=.1, hard=1)
        self.assertEqual(guard.wait(timeout=5), 124)
        self.gone(ids)
        self.assertFalse(list(self.directory.glob('termination-*')))

    def test_owned_anchor_retained_until_group_signals_end(self):
        owned = lifecycle.OwnedProcess([sys.executable, '-c', 'pass'])
        self.pin(owned.pid)
        self.until(owned.exited, 'private child did not exit')
        self.assertTrue(Path('/proc/' + str(owned.pid)).exists(), 'wait identity released early')
        self.assertEqual(os.getpgid(owned.pid), owned.pid)
        owned.send(signal.SIGTERM)
        owned.send(signal.SIGKILL)
        self.assertEqual(owned.reap(), 0)
        with mock.patch.object(lifecycle.os, 'killpg') as kill:
            with self.assertRaisesRegex(RuntimeError, 'ownership released'):
                owned.send(signal.SIGTERM)
            kill.assert_not_called()
        self.assertTrue(owned.exited())

    def test_adoption_error_still_escalates_and_fails_closed(self):
        owned = lifecycle.OwnedProcess([sys.executable, '-c', 'pass'])
        self.pin(owned.pid)
        self.until(owned.exited, 'private child did not exit')
        with mock.patch.object(lifecycle, '_adopted', side_effect=OSError('proc unavailable')), \
                mock.patch.object(owned, 'send', wraps=owned.send) as sent:
            result = lifecycle._drain([owned], .01, time.monotonic() + .05)
        self.assertIsNone(result)
        self.assertEqual(sent.call_args_list,
                         [mock.call(signal.SIGTERM), mock.call(signal.SIGKILL)])
        self.assertTrue(owned.reaped)

    def test_exited_adopted_child_is_reaped_before_signal_permission_check(self):
        with mock.patch.object(lifecycle, '_children', return_value=[123]), \
                mock.patch.object(lifecycle.os, 'waitpid', return_value=(123, 0)) as wait, \
                mock.patch.object(lifecycle.os, 'pidfd_open', return_value=1234) as opened, \
                mock.patch.object(lifecycle.signal, 'pidfd_send_signal',
                                  side_effect=PermissionError('privileged zombie')), \
                mock.patch.object(lifecycle.os, 'close'):
            self.assertFalse(lifecycle._adopted(set(), signal.SIGTERM))
        wait.assert_called_once_with(123, os.WNOHANG)
        opened.assert_not_called()

    def test_signal_permission_failure_still_reaps_adopted_child(self):
        fd = os.pidfd_open(os.getpid())
        with mock.patch.object(lifecycle, '_children', return_value=[123]), \
                mock.patch.object(lifecycle.os, 'waitpid', side_effect=[(0, 0), (123, 0)]) as wait, \
                mock.patch.object(lifecycle.os, 'pidfd_open', return_value=fd), \
                mock.patch.object(lifecycle.signal, 'pidfd_send_signal',
                                  side_effect=PermissionError('privileged child')), \
                self.assertRaises(PermissionError):
            lifecycle._adopted(set(), signal.SIGTERM)
        self.assertEqual(wait.call_count, 2)

    def test_group_signal_failure_does_not_block_other_groups_or_reaping(self):
        denied = mock.Mock(pid=123, spec=['pid', 'send', 'exited', 'reap'])
        denied.send.side_effect = PermissionError('privileged group')
        denied.exited.return_value = True
        other = mock.Mock(pid=456, spec=['pid', 'send', 'exited', 'reap'])
        other.exited.return_value = True
        with mock.patch.object(lifecycle, '_adopted', return_value=False), \
                mock.patch.object(lifecycle, '_children', return_value=[123, 456]):
            result = lifecycle._drain([denied, other], .01, time.monotonic() + .1)
        self.assertIsNone(result)
        for process in (denied, other):
            self.assertEqual(process.send.call_args_list,
                             [mock.call(signal.SIGTERM), mock.call(signal.SIGKILL)])
            process.reap.assert_called_once_with()
        self.assertIn('PermissionError', denied.cleanup_error)

    def test_requested_signal_preserves_incomplete_cleanup_status(self):
        drain = lifecycle._drain

        def incomplete(*args):
            drain(*args)  # Release the real fixture before injecting failure.

        for sig in (signal.SIGTERM, signal.SIGINT):
            def started(pid, sig=sig):
                self.pin(pid)
                os.kill(os.getpid(), sig)

            with self.subTest(signal=sig), \
                    mock.patch.object(lifecycle, '_drain', side_effect=incomplete):
                result = lifecycle.run_owned([sys.executable, '-c', 'pass'], None, started, hard=1)
            self.assertEqual(result['status'], 125)
            self.assertIsNone(result['code'])
            self.assertEqual(result['reason'], 'cleanup incomplete')

    def test_requested_signal_distinguishes_owner_loss_from_command_exit_125(self):
        for sig in (signal.SIGTERM, signal.SIGINT):
            for record in (None, {'status': 125, 'code': 125, 'reason': 'command exit'}):
                def owner(wire, *_args, record=record):
                    wire.send(json.dumps({'child': os.getpid()}).encode())
                    wire.recv(1024)  # Wait until the guard has recorded the signal.
                    if record is not None:
                        wire.send(json.dumps(record).encode())

                def started(pid, sig=sig):
                    self.pin(pid)
                    os.kill(os.getpid(), sig)

                with self.subTest(signal=sig, record=record), \
                        mock.patch.object(lifecycle, '_owner', side_effect=owner):
                    result = lifecycle.run_owned(['never-started'], None, started, hard=1)
                self.assertEqual(result['status'], 125 if record is None else 128 + sig)
                self.assertEqual(result['code'], None if record is None else 125)
                expected_reason = 'owner lost' if record is None else 'command exit'
                self.assertEqual(result['reason'], expected_reason)

    def test_owner_setup_failure_does_not_launch(self):
        library = mock.Mock()
        library.prctl.return_value = -1
        with mock.patch.object(lifecycle.ctypes, 'CDLL', return_value=library):
            result = lifecycle.run_owned(['never-start'], None, lambda pid: None)
        self.assertEqual(result['status'], 125)
        self.assertIsNone(result['code'])

    def test_external_child_reaper_is_refused_before_launch(self):
        for handler in (signal.SIG_IGN, lambda number, frame: None):
            with self.subTest(handler=handler), \
                    mock.patch.object(lifecycle.signal, 'getsignal', return_value=handler):
                result = lifecycle.run_owned(['never-start'], None, lambda pid: None)
            self.assertEqual(result['status'], 125)
            self.assertIsNone(result['code'])
            self.assertEqual(result['reason'], 'external child reaper')

    def test_caller_identity_missing_or_changed_does_not_launch(self):
        with mock.patch.object(lifecycle.os, 'pidfd_open', side_effect=OSError('unavailable')):
            result = lifecycle.run_owned(['never-start'], None, lambda pid: None)
        self.assertEqual(result['status'], 125)
        self.assertIsNone(result['code'])
        fd = os.pidfd_open(os.getpid())
        with mock.patch.object(lifecycle.os, 'pidfd_open', return_value=fd), \
                mock.patch.object(lifecycle.os, 'getppid', side_effect=[1, 2]):
            result = lifecycle.run_owned(['never-start'], None, lambda pid: None)
        self.assertEqual(result['reason'], 'caller changed')
        self.assertEqual(result['status'], 125)
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_ownership_setup_failures_close_descriptors_and_report_unknown(self):
        for operation in ('socketpair', 'fork'):
            caller = os.pidfd_open(os.getpid())
            sockets = []
            original = lifecycle.socket.socketpair

            def socketpair(*args, operation=operation, original=original, sockets=sockets):
                if operation == 'socketpair':
                    raise OSError('controlled socketpair failure')
                pair = original(*args)
                sockets.extend(pair)
                return pair

            with self.subTest(operation=operation), \
                    mock.patch.object(lifecycle.os, 'pidfd_open', return_value=caller), \
                    mock.patch.object(lifecycle.socket, 'socketpair', side_effect=socketpair), \
                    mock.patch.object(lifecycle.os, 'fork',
                                      side_effect=OSError('controlled fork failure')) as fork, \
                    mock.patch.object(observer, '_report') as report:
                status = observer.observe(self.directory, ['never-start'])
            self.assertEqual(status, 125)
            self.assertIn('TERMINATION UNKNOWN', report.call_args.args[0])
            self.assertIn('ownership setup failed', report.call_args.args[0])
            self.assertFalse(list(self.directory.glob('termination-*/termination.json')))
            self.assertEqual(fork.call_count, int(operation == 'fork'))
            self.assertTrue(all(sock.fileno() == -1 for sock in sockets))
            with self.assertRaises(OSError):
                os.fstat(caller)

    def test_pin_rejects_changed_diagnostic_start_before_cleanup(self):
        fd = os.open('/dev/null', os.O_RDONLY)
        with mock.patch.object(lifecycle.os, 'pidfd_open', return_value=fd), \
                mock.patch.object(Path, 'read_text', return_value='1 (fixture) S ' +
                                  '0 ' * 19 + 'replacement'):
            self.pin(12345, 'original')
        self.assertNotIn(12345, self.handles)
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_deadline_api_boundary_and_nonfinite_rejection(self):
        lifecycle.validate_deadlines(0, 1)
        lifecycle.validate_deadlines(.599, 1)
        for soft, hard in ((.6, 1), (1, 1), (-1, 1), (float('nan'), 1),
                           (None, 0), (None, float('inf')), (None, float('nan'))):
            with self.subTest(soft=soft, hard=hard), \
                    self.assertRaisesRegex(ValueError, 'invalid guard deadline'):
                lifecycle.run_owned(['never-start'], None, lambda pid: None,
                                    soft=soft, hard=hard)

    def test_invalid_deadline_does_not_launch(self):
        marker = self.directory / 'should-not-run'
        for hard in ('nan', 'inf', '-1', '0', '.1', 'bad'):
            with self.subTest(hard=hard):
                env = dict(os.environ, CT_HANG_HARD_SECONDS=hard)
                result = subprocess.run(['sh', str(GUARD), '.1', str(self.directory), '--',
                                         sys.executable, '-c',
                                         'from pathlib import Path; Path(' +
                                         repr(str(marker)) + ').touch()'],
                                        env=env, capture_output=True, timeout=5, check=False)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(marker.exists())


class AdoptedCleanupTests(unittest.TestCase):
    def test_adopted_skips_anchors_and_tracks_waited_children(self):
        for first_wait in (0, 202):
            with (
                self.subTest(first_wait=first_wait),
                mock.patch.object(lifecycle, '_children', return_value=[101, 202, 303]),
                mock.patch.object(lifecycle.os, 'pidfd_open', side_effect=[1202, 1303]) as opened,
                mock.patch.object(lifecycle.signal, 'pidfd_send_signal') as sent,
                mock.patch.object(lifecycle.os, 'waitpid',
                                  side_effect=([(0, 0), (0, 0), (303, 0)] if first_wait == 0
                                               else [(202, 0), (303, 0)])) as waited,
                mock.patch.object(lifecycle.os, 'close') as closed,
            ):
                self.assertEqual(lifecycle._adopted({101}, signal.SIGKILL), first_wait == 0)
            expected_open = [mock.call(202)] if first_wait == 0 else []
            self.assertEqual(opened.call_args_list, expected_open)
            self.assertEqual(sent.call_args_list,
                             [mock.call(1202, signal.SIGKILL)] if first_wait == 0 else [])
            expected_wait = [mock.call(202, os.WNOHANG)] * (2 if first_wait == 0 else 1)
            self.assertEqual(waited.call_args_list, expected_wait + [mock.call(303, os.WNOHANG)])
            self.assertEqual(closed.call_args_list, [mock.call(1202)] if first_wait == 0 else [])

    def test_adopted_error_still_visits_and_reaps_later_child(self):
        for operation in ('open', 'signal', 'wait', 'close'):
            def fail(value, *_args, operation=operation, boundary=None):
                if value in (202, 1202) and operation == boundary:
                    raise PermissionError('controlled child failure')
                return value + 1000 if boundary == 'open' else (0, 0)

            with (
                self.subTest(operation=operation),
                mock.patch.object(lifecycle, '_children', return_value=[101, 202, 303]),
                mock.patch.object(lifecycle.os, 'pidfd_open',
                                  side_effect=partial(fail, boundary='open')) as opened,
                mock.patch.object(lifecycle.signal, 'pidfd_send_signal',
                                  side_effect=partial(fail, boundary='signal')) as sent,
                mock.patch.object(lifecycle.os, 'waitpid',
                                  side_effect=partial(fail, boundary='wait')) as waited,
                mock.patch.object(lifecycle.os, 'close',
                                  side_effect=partial(fail, boundary='close')) as closed,
                self.assertRaisesRegex(PermissionError, 'controlled child failure'),
            ):
                lifecycle._adopted({101}, signal.SIGKILL)
            self.assertEqual(opened.call_args_list,
                             ([mock.call(303)] if operation == 'wait'
                              else [mock.call(202), mock.call(303)]))
            sent.assert_any_call(1303, signal.SIGKILL)
            waited.assert_any_call(303, os.WNOHANG)
            closed.assert_any_call(1303)
            if operation in ('open', 'wait'):
                self.assertNotIn(mock.call(1202), closed.call_args_list)
            else:
                closed.assert_any_call(1202)

    def test_drain_retains_error_after_children_are_eventually_reaped(self):
        owned = mock.Mock(pid=101)
        owned.exited.return_value = True
        owned.reap.return_value = 0

        def pidfd(pid):
            if pid == 202:
                raise PermissionError('controlled child failure')
            return pid + 1000

        children = [[101, 202, 303], [101], [101], [101]]
        with mock.patch.object(lifecycle, '_children', side_effect=children), \
                mock.patch.object(lifecycle.os, 'pidfd_open', side_effect=pidfd), \
                mock.patch.object(lifecycle.signal, 'pidfd_send_signal') as sent, \
                mock.patch.object(lifecycle.os, 'waitpid',
                                  side_effect=[(0, 0), (0, 0), (303, 0)]) as waited, \
                mock.patch.object(lifecycle.os, 'close') as closed:
            result = lifecycle._drain([owned], 0, time.monotonic() + 1)
        self.assertIsNone(result)
        sent.assert_called_once_with(1303, signal.SIGTERM)
        self.assertEqual(waited.call_args_list, [mock.call(202, os.WNOHANG),
                                                 mock.call(303, os.WNOHANG),
                                                 mock.call(303, os.WNOHANG)])
        closed.assert_called_once_with(1303)
        self.assertEqual(owned.send.call_args_list,
                         [mock.call(signal.SIGTERM), mock.call(signal.SIGKILL)])
        owned.reap.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
