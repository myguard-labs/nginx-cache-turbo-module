"""Exercise the named runner's command-line timing rejection."""
import pathlib
import subprocess
import sys
import unittest

RUNNER = pathlib.Path(__file__).resolve().parents[1] / "tools" / "run_named.py"


class NamedTimingOption(unittest.TestCase):
    def run_named(self, *extra):
        return subprocess.run(
            [sys.executable, str(RUNNER), "--nginx-binary", "nonexistent-nginx",
             *extra, "test_sanitizer_time_scale"],
            capture_output=True, text=True, check=False,
        )

    def test_timings_rejected_before_binary_check(self):
        result = self.run_named("--timings")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("--timings is not supported by run_named.py", result.stderr)
        self.assertNotIn("FileNotFoundError", result.stderr)

    def test_without_timings_reaches_existing_binary_check(self):
        result = self.run_named()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FileNotFoundError", result.stderr)
        self.assertNotIn("--timings is not supported", result.stderr)


if __name__ == "__main__":
    unittest.main()
