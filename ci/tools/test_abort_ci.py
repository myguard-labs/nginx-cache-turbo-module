#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the actual abort-soak workflow commands with a failing stub."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class AbortWorkflow(unittest.TestCase):
    def test_abort_steps_and_failure_propagation(self):
        for filename, job in [("asan.yml", "asan-multi"), ("ci-deep.yml", "D-soak")]:
            with self.subTest(workflow=filename):
                workflow = yaml.safe_load(
                    (ROOT / ".github/workflows" / filename).read_text()
                )
                steps = workflow["jobs"][job]["steps"]
                step = next(s for s in steps if s.get("name") == "Run ASan abort soak")
                self.assertEqual(step["env"]["ABORT"], "1")
                self.assertEqual(
                    step["env"]["ASAN_OPTIONS"],
                    "detect_leaks=1:halt_on_error=1:abort_on_error=1",
                )
                if job == "D-soak":
                    verdict = next(s for s in steps if s.get("id") == "verdict")
                    self.assertIn(step["id"], verdict["env"]["LANE_REQUIRED"].split())
                    self.assertEqual(
                        step["if"],
                        "always() && steps.asan_soak_06.outcome == 'success'",
                    )
                else:
                    self.assertNotIn("continue-on-error", step)
                with tempfile.TemporaryDirectory() as tmp:
                    tmp = Path(tmp)
                    stub = tmp / "bash"
                    stub.write_text(
                        "#!/usr/bin/python3\nimport json, os, sys\n"
                        'data = [os.environ.get("ABORT"), '
                        'os.environ.get("ABORT_PORT_BASE"), sys.argv[1:]]\n'
                        'open(os.environ["RECORD"], "w").write(json.dumps(data))\n'
                        'sys.exit(int(os.environ["STUB_STATUS"]))\n'
                    )
                    stub.chmod(0o755)
                    env = {
                        **os.environ,
                        **step["env"],
                        "PATH": str(tmp),
                        "GITHUB_WORKSPACE": "/workspace",
                        "BUILD_ROOT": "/build",
                        "NGINX_VERSION": "1.2.3",
                        "TEST_BASE_PORT": "19136",
                        "RECORD": str(tmp / "record"),
                    }
                    for status in (0, 1, 17):
                        env["STUB_STATUS"] = str(status)
                        proc = subprocess.run(
                            ["/bin/bash", "-e", "-o", "pipefail", "-c", step["run"]],
                            cwd=ROOT,
                            env=env,
                            check=False,
                        )
                        self.assertEqual(proc.returncode, status)
                        abort, port, args = json.loads((tmp / "record").read_text())
                        self.assertEqual((abort, port), ("1", "19136"))
                        self.assertEqual(args[0], "ci/tools/soak.sh")
                        self.assertEqual(args[-1], "90")
                        self.assertTrue(args[1].endswith("/nginx-1.2.3/objs/nginx"))


if __name__ == "__main__":
    unittest.main()
