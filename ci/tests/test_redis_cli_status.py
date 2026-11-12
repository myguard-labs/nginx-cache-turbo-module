"""Inert controls for RedisServer.cli subprocess status handling."""
import pathlib
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
import test_runtime_base as base


class RedisCliStatus(unittest.TestCase):
    def server(self, password=None, tls_certs=None):
        return base.RedisServer(pathlib.Path("redis-server"), pathlib.Path("."),
                                12345, password, tls_certs)

    def test_success_and_empty_output(self):
        for output, expected in (("  value\n", "value"), ("\n", "")):
            with self.subTest(output=output), mock.patch.object(
                    base.subprocess, "run", return_value=subprocess.CompletedProcess(
                        [], 0, stdout=output)) as run:
                self.assertEqual(self.server().cli("GET", "key"), expected)
                run.assert_called_once_with(
                    ["redis-cli", "-e", "-h", "127.0.0.1", "-p", "12345", "GET", "key"],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)

    def test_nonzero_status_is_raised_without_secret_or_output(self):
        secret = "inert-password-sentinel"
        with mock.patch.object(base.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 7, stdout=f"failure {secret}")) as run:
            with self.assertRaises(RuntimeError) as raised:
                self.server(password=secret, tls_certs={"ca": "ca-sentinel"}).cli("PING")
        self.assertIn("7", str(raised.exception))
        self.assertNotIn(secret, str(raised.exception))
        self.assertNotIn(secret, repr(raised.exception))
        run.assert_called_once_with(
            ["redis-cli", "-e", "-h", "127.0.0.1", "-p", "12345",
             "--tls", "--cacert", "ca-sentinel", "-a", secret, "--no-auth-warning", "PING"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)

    def test_redis_error_reply_is_failure_with_exit_error_option(self):
        def redis_cli(argv, **_kwargs):
            return subprocess.CompletedProcess(argv, 1 if "-e" in argv else 0,
                                               stdout="ERR command failed\n")

        with mock.patch.object(base.subprocess, "run", side_effect=redis_cli):
            with self.assertRaises(RuntimeError):
                self.server().cli("BADCOMMAND")

    def test_timeout_propagates(self):
        secret = "inert-password-sentinel"
        timeout = subprocess.TimeoutExpired(["redis-cli", "-a", secret], 10,
                                            output=secret)
        with mock.patch.object(base.subprocess, "run", side_effect=timeout):
            with self.assertRaises(subprocess.TimeoutExpired) as raised:
                self.server(password=secret).cli("PING")
        self.assertEqual(raised.exception.timeout, 10)
        self.assertNotIn(secret, str(raised.exception))
        self.assertNotIn(secret, repr(raised.exception))
        self.assertIsNone(raised.exception.output)


if __name__ == "__main__":
    unittest.main()
