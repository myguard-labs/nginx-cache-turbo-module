"""Check the Build runtime command transports the outcome directory."""

import json
import math
import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class WorkflowOutcomeTest(unittest.TestCase):
    def test_asan_preserves_capture_with_finite_existing_job_bound(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/asan.yml').read_text())
        checked = 0
        for job in workflow['jobs'].values():
            for step in job.get('steps', []):
                command = step.get('run', '')
                if 'ci-hang-guard.sh 2700' in command:
                    checked += 1
                    args = shlex.split(command, comments=True)
                    self.assertEqual(args[:4], ['CT_HANG_HARD_SECONDS=3000', 'bash',
                                                'ci/tools/ci-hang-guard.sh', '2700'])
        self.assertEqual(checked, 2)

    def test_asan_budgets_cover_all_steps(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/asan.yml').read_text())
        for name, expected_other in (('asan-single', 37), ('asan-multi', 42)):
            with self.subTest(job=name):
                job = workflow['jobs'][name]
                steps = job['steps']
                guard = next(i for i, step in enumerate(steps)
                             if 'ci-hang-guard.sh 2700' in step.get('run', ''))
                upload = next(step for step in steps[guard + 1:]
                              if step.get('name', '').startswith('Upload hang-capture'))
                self.assertEqual(upload['if'], 'always()')
                # Every executable step outside the guarded command has a bound.
                other_steps = steps[:guard] + steps[guard + 1:]
                self.assertTrue(all(isinstance(step.get('timeout-minutes'), int)
                                    and step['timeout-minutes'] > 0 for step in other_steps))
                setup_and_after = sum(step['timeout-minutes'] for step in other_steps)
                self.assertEqual(setup_and_after, expected_other)
                args = shlex.split(steps[guard]['run'], comments=True)
                guard_minutes = math.ceil(float(args[0].split('=', 1)[1]) / 60)
                # Five minutes is an allowance for runner/action post-step overhead.
                self.assertGreaterEqual(job['timeout-minutes'],
                                        setup_and_after + guard_minutes + 5)

    def test_build_capture_preserves_measured_healthy_and_diagnostic_margins(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/build-test.yml').read_text())
        step = next(step for step in workflow['jobs']['build']['steps']
                    if step.get('name') == 'Run runtime suite')
        args = shlex.split(step['run'], comments=True)
        hard = int(args[0].split('=', 1)[1])
        soft = float(args[3])
        self.assertEqual(hard, 780)
        # Five qualified 588-test runs on 2026-11-17: max healthy step 761s.
        # The observed capture bound was 7.342588s, rounded up to eight.
        healthy_max = 761
        capture_window = math.ceil(7.342588)
        cleanup_at = hard - 2 * min(2., hard / 5)  # Owner reserves TERM/KILL grace.
        self.assertGreater(soft, healthy_max, 'capture overlaps a measured healthy run')
        self.assertGreaterEqual(cleanup_at - soft, capture_window,
                                'capture loses its measured diagnostic window')

    def test_build_runtime_outcome_and_status(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/build-test.yml').read_text())
        steps = workflow['jobs']['build']['steps']
        commands = [s['run'] for s in steps if 'test_runtime.py' in s.get('run', '')]
        self.assertEqual(len(commands), 1)
        command = commands[0]
        self.assertIn('set -o pipefail', command)
        self.assertIn('--outcome-dir "$GITHUB_WORKSPACE/ci-hang-artifacts"', command)
        args = shlex.split(command, comments=True)
        self.assertEqual(args[:3], ['CT_HANG_HARD_SECONDS=780', 'bash',
                                    'ci/tools/ci-hang-guard.sh'])
        with tempfile.TemporaryDirectory(prefix='workflow outcome ') as tmp:
            workspace = Path(tmp)
            tools_dir = workspace / 'ci/tools'
            tools_dir.mkdir(parents=True)
            (tools_dir / 'ci-hang-guard.sh').symlink_to(ROOT / 'ci/tools/ci-hang-guard.sh')
            bindir = workspace / 'bin'
            bindir.mkdir()
            producer = bindir / 'python3'
            producer.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
if pathlib.Path(args[0]).name == 'ci_child_observer.py':
    os.execv(sys.executable, [sys.executable, *args])
assert args[0] == 'ci/tools/test_runtime.py'
assert args.count('--outcome-dir') == 1
parent = args[args.index('--outcome-dir') + 1]
assert parent and pathlib.Path(parent).is_dir()
assert parent == os.path.join(os.environ['GITHUB_WORKSPACE'], 'ci-hang-artifacts')
pathlib.Path(os.environ['ARG_CAPTURE']).write_text(json.dumps(args))
sys.exit(int(os.environ['PRODUCER_STATUS']))
''')
            # Avoid resolving the stub again through its own PATH.
            producer.write_text(
                producer.read_text().replace('#!/usr/bin/env python3', '#!/usr/bin/python3')
            )
            producer.chmod(0o755)
            env = dict(os.environ, GITHUB_WORKSPACE=str(workspace), TEST_BASE_PORT='1234',
                       NGINX_VERSION='test', PATH=f'{bindir}:' + os.environ['PATH'],
                       ARG_CAPTURE=str(workspace / 'args.json'))
            for status in (0, 23):
                with self.subTest(status=status):
                    env['PRODUCER_STATUS'] = str(status)
                    result = subprocess.run(['bash', '-c', command], cwd=workspace, env=env,
                                            capture_output=True, timeout=20, check=False)
                    self.assertEqual(result.returncode, status, result.stderr.decode())
                    captured = json.loads((workspace / 'args.json').read_text())
                    self.assertIn('--timings', captured)
                    self.assertIn('--fault-injection', captured)
                    self.assertIn('--redis-server', captured)
                    self.assertIn('--memcached-server', captured)


if __name__ == '__main__':
    unittest.main()
