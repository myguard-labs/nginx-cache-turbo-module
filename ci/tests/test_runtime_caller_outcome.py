"""Caller manifest and optional outcome lifecycle controls."""

import contextlib
import io
import itertools
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
import test_runtime as runtime


class CallerOutcomeTests(unittest.TestCase):
    def test_manifest_matches_real_caller_for_all_fixture_states(self):
        source = pathlib.Path(runtime.__file__).read_bytes()
        keys = (
            "redis",
            "redis_auth",
            "redis_tls",
            "mc",
            "redis_tls_untrusted",
            "redis_tls_expired",
        )
        full = runtime._expected_roots(source, dict.fromkeys((*keys, "fault_injection"), True))
        names = set(full)
        for bits in itertools.product((False, True), repeat=7):
            config = dict(zip((*keys, "fault_injection"), bits, strict=True))
            seen = []
            stubs = {
                name: (lambda *args, name=name, seen=seen: seen.append(name)) for name in names
            }
            refs = [object() if config[k] else None for k in keys]
            with mock.patch.multiple(runtime, **stubs):
                runtime.run_all(types.SimpleNamespace(fault_injection=bits[-1]), object(), *refs)
            self.assertEqual(runtime._expected_roots(source, config), seen)
        # These additions extend the current roster; the historical 588-call
        # qualification remains evidence for its original caller only.
        stats_roots = (
            "test_admin_wire_contract",
            "test_admin_raw_zone_labels",
            "test_admin_stats_reload_restart",
            "test_admin_expired_breaker_scrape",
        )
        for name in stats_roots:
            self.assertEqual(full.count(name), 1, name)
        self.assertEqual(len([name for name in full if name not in stats_roots]), 588)

    def test_manifest_rejects_unsupported_inactive_branch(self):
        source = b"def run_all():\n    if redis is not None:\n        arbitrary()\n"
        config = dict.fromkeys(
            (
                "redis",
                "redis_auth",
                "redis_tls",
                "mc",
                "redis_tls_untrusted",
                "redis_tls_expired",
                "fault_injection",
            ),
            False,
        )
        with self.assertRaises(ValueError):
            runtime._expected_roots(source, config)

    def test_lifecycle_success_failure_unknown_and_exception(self):
        ng = types.SimpleNamespace(fault_injection=False)
        refs = (None,) * 6
        roots = runtime._expected_roots(
            pathlib.Path(runtime.__file__).read_bytes(),
            dict.fromkeys(
                (
                    "redis",
                    "redis_auth",
                    "redis_tls",
                    "mc",
                    "redis_tls_untrusted",
                    "redis_tls_expired",
                    "fault_injection",
                ),
                False,
            ),
        )
        for mode in ("success", "inner", "incomplete", "exception", "io"):
            journal = []

            def instrument(origin, timings, facade, recorder, journal=journal):
                journal.append(recorder)

            def run(*args, journal=journal, mode=mode):
                j = journal[0]
                if j is None:
                    return
                for name in roots:
                    token = j.enter(name)
                    if mode == "inner" and name == roots[0]:
                        child = j.enter("test_inner")
                        j.finish(child, "test_inner", "exception")
                    j.finish(token, name, "return")
                if mode == "incomplete":
                    j.enter("extra")
                if mode == "exception":
                    raise LookupError("original")

            with (
                self.subTest(mode=mode),
                tempfile.TemporaryDirectory() as directory,
                mock.patch.object(runtime, "_instrument", instrument),
                mock.patch.object(runtime, "run_all", run),
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                target = directory + "/missing" if mode == "io" else directory
                if mode == "exception":
                    with self.assertRaisesRegex(LookupError, "original"):
                        runtime._run_with_outcome(target, ng, object(), refs, None)
                else:
                    result, _, _ = runtime._run_with_outcome(target, ng, object(), refs, None)
                    self.assertEqual(
                        result,
                        {
                            "success": "SUCCESS",
                            "inner": "FAILURE",
                            "incomplete": "UNKNOWN",
                            "io": "UNKNOWN",
                        }[mode],
                    )
                if mode == "exception":
                    self.assertIn("OUTCOME UNKNOWN", output.getvalue())

    def test_manifest_invalid_inputs(self):
        config = dict.fromkeys(
            (
                "redis",
                "redis_auth",
                "redis_tls",
                "mc",
                "redis_tls_untrusted",
                "redis_tls_expired",
                "fault_injection",
            ),
            False,
        )
        for source, flags in (
            (b"def run_all(): pass", {}),
            (b"def another(): pass", config),
            (b"def run_all():\n if redis:\n  test_a()", config),
        ):
            with self.subTest(source=source), self.assertRaises(ValueError):
                runtime._expected_roots(source, flags)

    def test_journal_read_failure_and_instrument_failure(self):
        ng = types.SimpleNamespace(fault_injection=False)
        refs = (None,) * 6
        original = pathlib.Path.read_bytes

        def read(path):
            if path.name == "journal":
                raise OSError("read failed")
            return original(path)

        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(pathlib.Path, "read_bytes", read),
            mock.patch.object(runtime, "_instrument"),
            mock.patch.object(runtime, "run_all"),
        ):
            self.assertEqual(
                runtime._run_with_outcome(directory, ng, object(), refs, None)[0], "UNKNOWN"
            )
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(runtime, "_instrument", side_effect=LookupError("instrument")),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            with self.assertRaisesRegex(LookupError, "instrument"):
                runtime._run_with_outcome(directory, ng, object(), refs, None)
            self.assertIn("OUTCOME UNKNOWN", output.getvalue())

    def test_caller_reports_once_on_run_exception(self):
        ng = types.SimpleNamespace(fault_injection=False)
        report = mock.Mock()
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(runtime, "_instrument"),
            mock.patch.object(runtime, "run_all", side_effect=LookupError("original")),
            self.assertRaisesRegex(LookupError, "original"),
        ):
            runtime._run_with_outcome(directory, ng, object(), (None,) * 6, None, report)
        report.assert_called_once()
        self.assertEqual(report.call_args.args[0], "UNKNOWN")

    def test_empty_outcome_dir_rejected_before_setup(self):
        import test_runtime_base as base

        with mock.patch.object(sys, "argv", ["runtime", "--nginx-binary", "/bin/true"]):
            self.assertIsNone(base.parse_args().outcome_dir)
        with (
            mock.patch.object(sys, "argv", ["runtime", "--nginx-binary", "/bin/true",
                                            "--outcome-dir", ""]),
            mock.patch.object(runtime, "_main") as setup,
            contextlib.redirect_stderr(io.StringIO()) as stderr,
            self.assertRaises(SystemExit) as error,
        ):
            runtime.main()
        self.assertEqual(error.exception.code, 2)
        self.assertIn("--outcome-dir", stderr.getvalue())
        setup.assert_not_called()

    def test_cli_option_and_actual_post_setup_fixtures(self):
        import test_runtime_base as base

        with mock.patch.object(
            sys,
            "argv",
            ["runtime", "--nginx-binary", "/bin/true", "--outcome-dir", "/tmp/outcomes"],
        ):
            self.assertEqual(base.parse_args().outcome_dir, "/tmp/outcomes")
        args = types.SimpleNamespace(
            nginx_binary="/bin/true",
            module=None,
            port=18880,
            redis_server="/bin/true",
            memcached_server="/bin/true",
            runner="",
            single_process=False,
            fault_injection=True,
            sanitizer=False,
            timings=False,
            outcome_dir="/tmp",
        )
        ng, origin, mc = mock.Mock(unsafe=True), mock.Mock(), mock.Mock()
        redis, auth, tls, untrusted, expired = (mock.Mock() for _ in range(5))
        runner = mock.Mock(return_value=("SUCCESS", "journal", "status"))
        certs = {"ca": "ca", "ca_key": "key"}
        with (
            mock.patch.multiple(
                runtime,
                parse_args=mock.Mock(return_value=args),
                Nginx=mock.Mock(return_value=ng),
                Origin=mock.Mock(return_value=origin),
                MemcachedServer=mock.Mock(return_value=mc),
                RedisServer=mock.Mock(side_effect=[redis, auth, tls, untrusted, expired]),
                gen_tls_certs=mock.Mock(return_value=certs),
                gen_tls_expired_cert=mock.Mock(),
                _start_tls_fixtures=mock.Mock(return_value=(None, None, None)),
                _run_with_outcome=runner,
            ),
            mock.patch.object(runtime.time, "sleep"),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(runtime.main(), 0)
        self.assertEqual(runner.call_args.args[3], (redis, auth, None, mc, None, None))
        self.assertIs(runner.call_args.args[1], ng)

    def test_real_instrumentation_and_receipt(self):
        observed = []

        def test_probe():
            observed.append("called")

        def run(*args):
            runtime.test_probe()

        modules = [
            m
            for name, m in sys.modules.copy().items()
            if m is not None and (name == "test_runtime" or name.startswith("areas."))
        ]
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            for module in modules:
                stack.enter_context(mock.patch.dict(vars(module)))
            stack.enter_context(mock.patch.object(runtime, "test_probe", test_probe, create=True))
            stack.enter_context(mock.patch.object(runtime, "run_all", run))
            stack.enter_context(
                mock.patch.object(runtime, "_expected_roots", return_value=["test_probe"])
            )
            ng = types.SimpleNamespace(fault_injection=False)
            origin = types.SimpleNamespace(hits=0)
            decision, journal, status = runtime._run_with_outcome(
                directory, ng, origin, (None,) * 6, None
            )
            self.assertEqual(decision, "SUCCESS")
            self.assertEqual(observed, ["called"])
            self.assertTrue(journal.is_file())
            self.assertTrue(status.is_file())
            self.assertEqual(journal.parent.stat().st_mode & 0o777, 0o700)

    def test_main_lifecycle_and_error_paths(self):
        for mode in (
            "disabled",
            "success",
            "failure",
            "unknown",
            "setup",
            "runerror",
            "posterror",
            "cleanup",
            "cleanup_disabled",
            "cleanup_multiple",
            "timings",
            "missing_binary",
        ):
            args = types.SimpleNamespace(
                nginx_binary="/nonexistent/c213" if mode == "missing_binary" else "/bin/true",
                module=None,
                port=18880,
                redis_server=None,
                memcached_server=None,
                runner="",
                single_process=False,
                fault_injection=False,
                sanitizer=False,
                timings=mode == "timings",
                outcome_dir=None if mode in ("disabled", "cleanup_disabled") else "/tmp",
            )
            ng, origin = mock.Mock(unsafe=True), mock.Mock()
            if mode == "setup":
                origin.start.side_effect = LookupError("setup")
            if mode == "posterror":
                ng.assert_clean_logs.side_effect = LookupError("post")
            if mode in ("cleanup", "cleanup_disabled", "cleanup_multiple"):
                origin.stop.side_effect = LookupError("cleanup")
            if mode == "cleanup_multiple":
                ng.stop.side_effect = [None, LookupError("first cleanup")]
            result = {"failure": "FAILURE", "unknown": "UNKNOWN"}.get(mode, "SUCCESS")
            runner = mock.Mock(return_value=(result, "journal", "status"))
            if mode == "runerror":
                runner.side_effect = LookupError("run")
            with (
                self.subTest(mode=mode),
                mock.patch.multiple(
                    runtime,
                    parse_args=mock.Mock(return_value=args),
                    Nginx=mock.Mock(return_value=ng),
                    Origin=mock.Mock(return_value=origin),
                    _run_with_outcome=runner,
                    _instrument=mock.Mock(),
                    run_all=mock.Mock(),
                ),
                mock.patch.object(runtime.time, "sleep"),
                contextlib.redirect_stdout(io.StringIO()) as output,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                if mode in ("failure", "unknown"):
                    with self.assertRaisesRegex(RuntimeError, result):
                        runtime.main()
                elif mode == "missing_binary":
                    with self.assertRaises(FileNotFoundError):
                        runtime.main()
                elif mode in (
                    "setup",
                    "runerror",
                    "posterror",
                    "cleanup",
                    "cleanup_disabled",
                    "cleanup_multiple",
                ):
                    with self.assertRaises(LookupError):
                        runtime.main()
                else:
                    self.assertEqual(runtime.main(), 0)
                if mode in (
                    "setup",
                    "runerror",
                    "posterror",
                    "cleanup",
                    "cleanup_multiple",
                    "missing_binary",
                ):
                    self.assertIn("OUTCOME UNKNOWN", output.getvalue())
                if mode in ("success", "failure", "unknown", "timings"):
                    self.assertIn("OUTCOME " + result, output.getvalue())
                self.assertEqual(
                    ng.stop.call_count,
                    0 if mode == "missing_binary" else 1 if mode in ("setup", "runerror") else 2,
                )
                self.assertLessEqual(output.getvalue().count("OUTCOME "), 1)


if __name__ == "__main__":
    unittest.main()
