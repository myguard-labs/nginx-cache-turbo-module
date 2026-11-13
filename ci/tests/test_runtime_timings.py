"""Focused checks for opt-in runtime timing instrumentation."""
import contextlib
import io
import pathlib
import shlex
import sys
import types
import unittest
from unittest import mock

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
import test_runtime
import test_runtime_base as base


class RuntimeTimings(unittest.TestCase):
    def instrument(self, fn, timings):
        mod = types.ModuleType("areas._timing_selftest")
        vars(mod)["test_timing_selftest"] = fn
        facade = {"test_timing_selftest": fn}
        with mock.patch.dict(sys.modules, {mod.__name__: mod}):
            base._instrument(mock.Mock(spec=base.Origin, hits=0), timings, facade)
        self.assertIs(facade["test_timing_selftest"], vars(mod)["test_timing_selftest"])
        return facade["test_timing_selftest"]

    def test_timing_records_failure_and_preserves_breadcrumb(self):
        timings = []
        def fail():
            raise ValueError("failure marker")
        wrapped = self.instrument(fail, timings)
        output = io.StringIO()
        with mock.patch.object(base.time, "monotonic", side_effect=[3.0, 5.5]), \
             mock.patch.object(base, "_write_breadcrumb") as breadcrumb, \
             contextlib.redirect_stdout(output), \
             self.assertRaisesRegex(ValueError, "failure marker"):
            wrapped()
        self.assertEqual(timings, [("test_timing_selftest", 2.5)])
        self.assertIn("TIMING test_timing_selftest 2.500000s", output.getvalue())
        self.assertEqual(breadcrumb.call_args_list[-1].args[0], "DONE test_timing_selftest")

    def test_disabled_has_no_output_or_clock(self):
        wrapped = self.instrument(lambda: 42, None)
        output = io.StringIO()
        with mock.patch.object(base.time, "monotonic", side_effect=AssertionError), \
             contextlib.redirect_stdout(output):
            self.assertEqual(wrapped(), 42)
        self.assertEqual(output.getvalue(), "")

    def test_summary_limits_and_orders_results(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            test_runtime._print_timings([(f"test_{i}", float(i)) for i in range(25)])
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 21)
        self.assertEqual(lines[1], "TIMING TOP test_24 24.000000s")
        self.assertEqual(lines[-1], "TIMING TOP test_5 5.000000s")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            test_runtime._print_timings([])
        self.assertEqual(output.getvalue(), "TIMING TOP 20\n")

    def test_cli_opt_in_and_workflow(self):
        argv = ["test_runtime.py", "--nginx-binary", "nginx"]
        with mock.patch.object(sys, "argv", argv):
            self.assertFalse(base.parse_args().timings)
        with mock.patch.object(sys, "argv", [*argv, "--timings"]):
            self.assertTrue(base.parse_args().timings)
        workflow = pathlib.Path(__file__).resolve().parents[2] / ".github/workflows/build-test.yml"
        data = yaml.safe_load(workflow.read_text())
        commands = [step["run"] for step in data["jobs"]["build"]["steps"]
                    if "test_runtime.py" in step.get("run", "")]
        self.assertEqual(len(commands), 1)
        outer = shlex.split(commands[0], comments=True)
        script = outer[outer.index("-c") + 1]
        args = shlex.split(script, comments=True)
        runtime = args.index("ci/tools/test_runtime.py")
        self.assertEqual(args[runtime - 1], "python3")
        self.assertIn("--timings", args[runtime + 1:args.index("|", runtime)])

    def test_clock_regression_is_nonnegative(self):
        timings = []
        wrapped = self.instrument(lambda: None, timings)
        with mock.patch.object(base.time, "monotonic", side_effect=[2.0, 1.0]), \
             contextlib.redirect_stdout(io.StringIO()):
            wrapped()
        self.assertEqual(timings[0][1], 0.0)


if __name__ == "__main__":
    unittest.main()
