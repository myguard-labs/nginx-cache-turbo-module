"""Inert owned-child and real caller identity transport controls; no nginx suite."""

import contextlib
import io
import json
import os
import pathlib
import runpy
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "ci/tools"))
import ci_child_observer as observer

IDENTITY = {"run_id": "a" * 32, "observer_pid": 12, "child_pid": 34}


class TerminationTests(unittest.TestCase):
    def test_consumer_requires_matching_complete_observation(self):
        record = {"version": 1, "identity": IDENTITY, "observed": True, "returncode": 0}
        for code, expected in ((0, "EXITED"), (7, "EXITED"), (137, "EXITED"),
                               (-signal.SIGKILL, "SIGNALED"), (-64, "SIGNALED"),
                               (255, "EXITED"), (256, "UNKNOWN"), (-65, "UNKNOWN"),
                               (True, "UNKNOWN"), (None, "UNKNOWN"), ("0", "UNKNOWN")):
            with self.subTest(code=code):
                self.assertEqual(observer.consume_termination(
                    json.dumps(dict(record, returncode=code)), IDENTITY), expected)
        for data in (None, b"\xff", "{", "null", "[]", "{}"):
            self.assertEqual(observer.consume_termination(data, IDENTITY), "UNKNOWN")
        for key, value in (("version", 2), ("version", True), ("observed", False), ("observed", None),
                           ("identity", dict(IDENTITY, run_id="b" * 32)),
                           ("identity", dict(IDENTITY, child_pid=35)),
                           ("identity", dict(IDENTITY, observer_pid=13)),
                           ("identity", dict(IDENTITY, child_pid=34.0))):
            self.assertEqual(observer.consume_termination(
                json.dumps(dict(record, **{key: value})), IDENTITY), "UNKNOWN")
        for identity in (None, {}, dict(IDENTITY, run_id="x" * 32),
                         dict(IDENTITY, run_id=1), dict(IDENTITY, run_id="a"),
                         dict(IDENTITY, child_pid=0), dict(IDENTITY, observer_pid=True)):
            self.assertEqual(observer.consume_termination(json.dumps(record), identity), "UNKNOWN")
        # A missing final file or a syntactically complete prefix cannot certify observation.
        self.assertEqual(observer.consume_termination(json.dumps(record)[:-1], IDENTITY), "UNKNOWN")

    def test_publish_failures_do_not_expose_final_receipt(self):
        for mode in ("open", "short", "write", "flush", "close", "link"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                path = pathlib.Path(directory) / "termination.json"
                original = pathlib.Path.open

                class Stream:
                    def __enter__(self):
                        return self

                    def write(self, data, mode=mode):
                        if mode == "write":
                            raise OSError("write")
                        return 0 if mode == "short" else len(data)

                    def flush(self, mode=mode):
                        if mode == "flush":
                            raise OSError("flush")

                    def __exit__(self, *_, mode=mode):
                        if mode == "close":
                            raise OSError("close")

                def opening(p, *args, mode=mode, original=original, **kwargs):
                    if mode == "open":
                        raise OSError("open")
                    if mode == "link":
                        return original(p, *args, **kwargs)
                    return Stream()

                with (mock.patch.object(pathlib.Path, "open", opening),
                      mock.patch.object(observer.os, "link", side_effect=OSError("link"))):
                    self.assertFalse(observer._publish(path, {"a": 1}))
                self.assertFalse(path.exists(), "failed publication exposed a receipt")
                self.assertEqual(observer.consume_termination(None, IDENTITY), "UNKNOWN")

    def test_publish_does_not_overwrite_existing_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "termination.json"
            path.write_text("old")
            self.assertFalse(observer._publish(path, {"new": True}))
            self.assertEqual(path.read_text(), "old")

    def test_normal_nonzero_exit_and_abrupt_child_are_observed(self):
        for script, code, decision in (("pass", 0, "EXITED"),
                                        ("raise SystemExit(7)", 7, "EXITED"),
                                        ("os._exit(0)", 0, "EXITED"),
                                        ("os._exit(23)", 23, "EXITED"),
                                        ("os.kill(os.getpid(), signal.SIGKILL)", 137, "SIGNALED")):
            with self.subTest(script=script), tempfile.TemporaryDirectory() as directory:
                child = [sys.executable, "-c", "import os,signal; " + script]
                result = subprocess.run([sys.executable, observer.__file__, directory, "--", *child],
                                        capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, code, result.stderr)
                run = next(pathlib.Path(directory).glob("termination-*"))
                identity = json.loads((run / "identity.json").read_text())
                self.assertTrue((run / "termination.json").exists(), "owned child termination receipt missing")
                data = (run / "termination.json").read_bytes()
                self.assertEqual(observer.consume_termination(data, identity), decision)
                self.assertEqual(identity["observer_pid"], json.loads(data)["identity"]["observer_pid"])
                self.assertNotIn("SUCCESS", result.stdout)

    def test_observe_and_entrypoint_in_process(self):
        for code in (0, 7, -signal.SIGKILL):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                script = ("import os,signal; os.kill(os.getpid(),signal.SIGKILL)" if code < 0
                          else f"import os; os._exit({code})")
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    result = observer.observe(directory, [sys.executable, "-c", script])
                self.assertEqual(result, 128 - code if code < 0 else code)
                self.assertIn("SIGNALED" if code < 0 else "EXITED", output.getvalue())
        with tempfile.TemporaryDirectory() as directory:
            argv = [observer.__file__, directory, "--", sys.executable, "-c", "pass"]
            with mock.patch.object(sys, "argv", argv), \
                    contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as error:
                runpy.run_path(observer.__file__, run_name="__main__")
            self.assertEqual(error.exception.code, 0)
        with mock.patch.object(sys, "argv", ["observer", "dir", "bad", "cmd"]), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(observer.main(), 2)

    def test_failed_or_missing_publication_stays_unknown_and_preserves_exit(self):
        for mode in ("directory", "identity", "termination"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                original = observer._publish

                def publish(path, record, mode=mode, original=original):
                    if path.name == mode + ".json":
                        return False
                    return original(path, record)

                target = directory + "/missing" if mode == "directory" else directory
                with mock.patch.object(observer, "_publish", publish), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    code = observer.observe(target, [sys.executable, "-c", "raise SystemExit(9)"])
                self.assertEqual(code, 9)
                self.assertIn("TERMINATION UNKNOWN", output.getvalue())
                self.assertFalse(list(pathlib.Path(directory).glob("*/termination.json")))

    def test_report_io_error_preserves_command_status(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch("builtins.print", side_effect=BrokenPipeError()):
            self.assertEqual(observer.observe(
                directory, [sys.executable, "-c", "raise SystemExit(7)"]), 7)

    def test_start_failure_and_cli_usage(self):
        with tempfile.TemporaryDirectory() as directory:
            for error, code in ((FileNotFoundError(), 127), (PermissionError(), 126)):
                with mock.patch("ci_guard_lifecycle.subprocess.Popen", side_effect=error), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(observer.observe(directory, ["missing"]), code)
                self.assertIn("UNKNOWN", output.getvalue())
            with mock.patch.object(sys, "argv", ["observer"]), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(observer.main(), 2)

    def test_guard_disabled_and_enabled_paths_preserve_exit(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled), tempfile.TemporaryDirectory() as directory:
                env = dict(os.environ, CT_OUTCOME_OBSERVE="1" if enabled else "0")
                result = subprocess.run(["sh", str(REPO / "ci/tools/ci-hang-guard.sh"),
                                         "999999", directory, "--", sys.executable,
                                         "-c", "raise SystemExit(7)"],
                                        env=env, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 7, result.stderr)
                receipts = list(pathlib.Path(directory).glob("termination-*/termination.json"))
                self.assertEqual(len(receipts), int(enabled))
                self.assertEqual("TERMINATION EXITED" in result.stdout, enabled)

    def test_real_caller_pipeline_shares_run_but_not_direct_child_pid(self):
        # Use the real _run_with_outcome and recorder with only inert wrapped calls.
        script = '''
import json, os, pathlib, sys, types
sys.path.insert(0, sys.argv[1] + '/ci/tools')
import test_runtime as runtime
runtime._expected_roots = lambda *args: ['test_inert']
def instrument(origin, timings, facade, journal):
    runtime.journal = journal
def run(*args):
    token = runtime.journal.enter('test_inert')
    runtime.journal.finish(token, 'test_inert', 'return')
runtime._instrument = instrument
runtime.run_all = run
decision, journal, status = runtime._run_with_outcome(
    sys.argv[2], types.SimpleNamespace(fault_injection=False), None, (None,) * 6, None)
print(json.dumps({'decision': decision, 'status': str(status), 'pid': os.getpid()}))
'''
        with tempfile.TemporaryDirectory() as directory:
            log = str(pathlib.Path(directory) / "caller.log")
            command = ["bash", "-c", 'set -o pipefail; "$@" | tee "$CT_CALLER_LOG"', "pipeline",
                       sys.executable, "-c", script, str(REPO), directory]
            env = dict(os.environ, CT_OUTCOME_RUN_ID="stale", CT_CALLER_LOG=log)
            result = subprocess.run([sys.executable, observer.__file__, directory, "--", *command],
                                    env=env, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            run = next(pathlib.Path(directory).glob("termination-*"))
            identity = json.loads((run / "identity.json").read_text())
            caller = json.loads(pathlib.Path(log).read_text())
            status = json.loads(pathlib.Path(caller["status"]).read_text())
            self.assertEqual(status["run_id"], identity["run_id"], "caller run identity diverged")
            self.assertNotEqual(status["run_id"], "stale")
            self.assertNotEqual(caller["pid"], identity["child_pid"])
            self.assertEqual(caller["decision"], "SUCCESS")
            self.assertEqual(observer.consume_termination(
                (run / "termination.json").read_bytes(), identity), "EXITED")
            self.assertTrue(all(json.loads(line)[1] == identity["run_id"]
                                for line in pathlib.Path(caller["status"]).with_name("journal").read_text().splitlines()))

    def test_pipeline_signal_is_shell_exit_not_descendant_signal(self):
        with tempfile.TemporaryDirectory() as directory:
            command = ["bash", "-c", 'set -o pipefail; "$@" | cat', "pipeline",
                       sys.executable, "-c", "import os,signal; os.kill(os.getpid(),signal.SIGKILL)"]
            result = subprocess.run([sys.executable, observer.__file__, directory, "--", *command],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 137)
            run = next(pathlib.Path(directory).glob("termination-*"))
            record = json.loads((run / "termination.json").read_bytes())
            self.assertEqual(record["returncode"], 137)
            self.assertEqual(observer.consume_termination(json.dumps(record), record["identity"]), "EXITED")

    def test_workflow_enables_outer_observation(self):
        text = (REPO / ".github/workflows/build-test.yml").read_text()
        step = text.split("      - name: Run runtime suite\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn('CT_OUTCOME_OBSERVE: "1"', step)
        self.assertIn('--outcome-dir "$GITHUB_WORKSPACE/ci-hang-artifacts"', step)


if __name__ == "__main__":
    unittest.main()
