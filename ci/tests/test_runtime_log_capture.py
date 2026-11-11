"""Exercise the actual workflow pipelines with inert binary output producers."""

import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def pipelines():
    found = []
    for name in ("build-test.yml", "asan.yml"):
        workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
        for job, content in workflow["jobs"].items():
            for step in content.get("steps", []):
                command = step.get("run", "")
                if (
                    "test_runtime.py" not in command
                    or "| tee runtime-suite" not in command
                ):
                    continue
                args = shlex.split(command, comments=True)
                found.append((name, job, args[args.index("-c") + 1]))
    return found


class RuntimeLogCaptureTest(unittest.TestCase):
    def test_capture_and_failure_propagation(self):
        bodies = pipelines()
        self.assertEqual(len(bodies), 3)
        for name, job, body in bodies:
            self.assertIn("set -o pipefail", body)
            for status in (0, 23):
                with self.subTest(workflow=name, job=job, status=status):
                    producer = "python3 -c " + shlex.quote(
                        'import os,sys; os.write(1,b"OUT\\0\\n"); '
                        'os.write(2,b"ERR\\0\\n"); sys.exit(' + str(status) + ")"
                    )
                    probe, count = re.subn(
                        r"python3 ci/tools/test_runtime.py\s.*?(?=\| tee runtime-suite)",
                        lambda match, producer=producer: (
                            producer + (" 2>&1 " if "2>&1" in match.group() else " ")
                        ),
                        body,
                        flags=re.DOTALL,
                    )
                    self.assertEqual(count, 1)
                    with tempfile.TemporaryDirectory() as directory:
                        result = subprocess.run(
                            ["bash", "-c", probe],
                            cwd=directory,
                            capture_output=True,
                            check=False,
                        )
                        logs = list(Path(directory).glob("runtime-suite*.log"))
                        self.assertEqual(len(logs), 1)
                        self.assertEqual(result.returncode, status)
                        self.assertEqual(logs[0].read_bytes(), b"OUT\0\nERR\0\n")
                        self.assertEqual(result.stdout, b"OUT\0\nERR\0\n")
                        self.assertEqual(result.stderr, b"")

    def test_tee_failure_is_blocking(self):
        bodies = pipelines()
        self.assertEqual(len(bodies), 3)
        for name, job, body in bodies:
            with self.subTest(workflow=name, job=job):
                probe, count = re.subn(
                    r"python3 ci/tools/test_runtime.py\s.*?(?=\| tee runtime-suite)",
                    lambda match: (
                        "printf x " + ("2>&1 " if "2>&1" in match.group() else "")
                    ),
                    body,
                    flags=re.DOTALL,
                )
                self.assertEqual(count, 1)
                probe, count = re.subn(
                    r"tee runtime-suite[\w.-]*\.log", "tee /dev/full", probe
                )
                self.assertEqual(count, 1)
                result = subprocess.run(
                    ["bash", "-c", probe], capture_output=True, check=False
                )
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
