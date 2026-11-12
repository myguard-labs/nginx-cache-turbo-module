"""Inert controls for administrative access to TLS Redis fixtures."""
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
import test_runtime_base as base


class RedisTlsCliFixture(unittest.TestCase):
    def test_fixture_group_and_expired_administration(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            with mock.patch.object(base.subprocess, "run"):
                trusted = base.gen_tls_certs(root / "trusted")
                untrusted = base.gen_tls_certs(root / "untrusted")
                expired = base.gen_tls_expired_cert(
                    root / "expired", trusted["ca_key"], trusted["ca"])

            servers = [base.RedisServer(pathlib.Path("redis-server"), root / str(i),
                                        12000 + i, tls_certs=certs)
                       for i, certs in enumerate((trusted, untrusted, expired))]
            calls = []

            def run(argv, **_kwargs):
                calls.append(argv)
                expired_peer = argv[argv.index("-p") + 1] == "12002"
                valid_admin = "--insecure" in argv
                return subprocess.CompletedProcess(
                    argv, int(expired_peer and not valid_admin), stdout="0\n")

            with mock.patch.object(base.subprocess, "run", side_effect=run), \
                 mock.patch.object(base.subprocess, "Popen"), \
                 mock.patch.object(base, "_track", side_effect=lambda proc: proc), \
                 mock.patch.object(base, "wait_port"):
                skip = mock.Mock()
                self.assertEqual(base._start_tls_fixtures(*servers, skip), tuple(servers))
                self.assertEqual(servers[2].cli("EXISTS", "key"), "0")
                skip.assert_not_called()
            self.assertEqual(["--insecure" in call for call in calls],
                             [False, False, True, True])
            self.assertEqual([call[-1] for call in calls[:3]], ["FLUSHALL"] * 3)
            self.assertTrue(all("-e" in call for call in calls))

    def test_expired_fixture_still_rejects_command_failure(self):
        certs = {"ca": "ca", "cert": "cert", "key": "key",
                 "cli_insecure": True}
        server = base.RedisServer(pathlib.Path("redis-server"), pathlib.Path("."),
                                  12345, tls_certs=certs)
        with mock.patch.object(base.subprocess, "run", return_value=
                               subprocess.CompletedProcess([], 1, stdout="ERR")):
            with self.assertRaises(RuntimeError):
                server.cli("FLUSHALL")

    def test_other_tls_failures_are_not_bypassed(self):
        for certs in ({"ca": "valid-ca", "cert": "cert", "key": "key"},
                      {"ca": "wrong-ca", "cert": "cert", "key": "key"}):
            server = base.RedisServer(pathlib.Path("redis-server"), pathlib.Path("."),
                                      12345, tls_certs=certs)
            with self.subTest(ca=certs["ca"]), mock.patch.object(
                    base.subprocess, "run", return_value=subprocess.CompletedProcess(
                        [], 1, stdout="certificate or configuration error")) as run:
                with self.assertRaises(RuntimeError):
                    server.cli("PING")
                self.assertNotIn("--insecure", run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
