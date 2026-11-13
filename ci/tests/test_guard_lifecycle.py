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
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
GUARD = ROOT / "ci/tools/ci-hang-guard.sh"
sys.path.insert(0, str(ROOT / "ci/tools"))
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

    def test_blocked_capture_is_isolated_and_cannot_extend_deadline(self):
        identity = self.directory / 'capture-command.json'
        capture_file = self.directory / 'capture.json'
        capture_script = (
            'import json,os,pathlib,sys,time; '
            'pathlib.Path(sys.argv[1]).write_text(json.dumps('
            '{"pid":os.getpid(),"group":os.getpgrp(),"parent":os.getppid(),'
            '"command_group":os.getpgid(int(sys.argv[2]))})); time.sleep(60)')
        result = lifecycle.run_owned(
            [sys.executable, '-c', FIXTURE, str(identity), 'stubborn'], None, lambda pid: None,
            soft=0, hard=1,
            capture=lambda pid: [sys.executable, '-c', capture_script, str(capture_file), str(pid)])
        ids = json.loads(identity.read_text())
        diagnostic = json.loads(capture_file.read_text())
        self.pin_fixture(ids)
        self.pin(diagnostic['pid'])
        self.assertEqual(result['status'], 124)
        self.assertEqual(result['code'], -signal.SIGKILL)
        self.assertEqual(diagnostic['parent'], ids['owner'])
        self.assertEqual(diagnostic['command_group'], ids['command'])
        self.assertEqual(diagnostic['group'], diagnostic['pid'])
        self.assertNotEqual(diagnostic['group'], diagnostic['command_group'])
        self.gone(ids)
        self.assertFalse(Path('/proc/' + str(diagnostic['pid'])).exists())

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


if __name__ == '__main__':
    unittest.main()
