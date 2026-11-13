"""Check the Build runtime command transports the outcome directory."""

import json
import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class WorkflowOutcomeTest(unittest.TestCase):
    def test_build_runtime_outcome_and_status(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/build-test.yml').read_text())
        steps = workflow['jobs']['build']['steps']
        commands = [s['run'] for s in steps if 'test_runtime.py' in s.get('run', '')]
        self.assertEqual(len(commands), 1)
        command = commands[0]
        self.assertIn('set -o pipefail', command)
        self.assertIn('--outcome-dir "$GITHUB_WORKSPACE/ci-hang-artifacts"', command)
        args = shlex.split(command, comments=True)
        self.assertEqual(args[:3], ['bash', 'ci/tools/ci-hang-guard.sh', '2100'])
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
