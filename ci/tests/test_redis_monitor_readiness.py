"""Focused readiness and compatibility controls for Redis MONITOR startup."""
import pathlib
import socket
import sys
import threading
import types
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
import test_runtime_base as base


class RedisMonitorReadiness(unittest.TestCase):
    def monitor(self, password=None):
        return base.RedisMonitor(types.SimpleNamespace(port=12345, password=password))

    def test_complete_ack_skips_settling_sleep(self):
        mon = self.monitor()
        sock = mock.Mock()
        sock.recv.return_value = b"+OK\r\n"
        with mock.patch.object(base.socket, "create_connection", return_value=sock), \
             mock.patch.object(base.threading, "Thread") as thread, \
             mock.patch.object(base.time, "sleep") as sleep:
            self.assertIs(mon.__enter__(), mon)
        sock.sendall.assert_called_once_with(b"*1\r\n$7\r\nMONITOR\r\n")
        sock.settimeout.assert_called_once_with(0.2)
        thread.return_value.start.assert_called_once_with()
        sleep.assert_not_called()

    def test_partial_or_unexpected_reply_retains_delay(self):
        for reply in (b"+", b"+OK\r", b"-ERR denied\r\n", b"other"):
            with self.subTest(reply=reply):
                mon = self.monitor()
                sock = mock.Mock()
                sock.recv.return_value = reply
                with mock.patch.object(base.socket, "create_connection", return_value=sock), \
                     mock.patch.object(base.threading, "Thread"), \
                     mock.patch.object(base.time, "sleep") as sleep:
                    mon.__enter__()
                sleep.assert_called_once_with(0.1)

    def test_timeout_retains_deadline_and_delay(self):
        mon = self.monitor()
        sock = mock.Mock()
        sock.recv.side_effect = TimeoutError
        with mock.patch.object(base.socket, "create_connection", return_value=sock), \
             mock.patch.object(base.threading, "Thread"), \
             mock.patch.object(base.time, "time", side_effect=[10.0, 10.0, 11.0, 12.0]), \
             mock.patch.object(base.time, "sleep") as sleep:
            mon.__enter__()
        self.assertEqual(sock.recv.call_count, 2)
        sleep.assert_called_once_with(0.1)

    def test_eof_retries_until_deadline(self):
        mon = self.monitor()
        mon._sock = mock.Mock()
        mon._sock.recv.return_value = b""
        with mock.patch.object(
                base.time, "time", side_effect=[10.0, 10.0, 12.0]) as clock:
            self.assertFalse(mon._send(b"MONITOR"))
        mon._sock.recv.assert_called_once_with(4096)
        self.assertEqual(clock.call_count, 3)

    def test_socket_error_propagates_before_reader_starts(self):
        mon = self.monitor()
        sock = mock.Mock()
        sock.recv.side_effect = OSError("receive failed")
        with mock.patch.object(base.socket, "create_connection", return_value=sock), \
             mock.patch.object(base.threading, "Thread") as thread, \
             self.assertRaisesRegex(OSError, "receive failed"):
            mon.__enter__()
        thread.assert_not_called()

    def test_auth_precedes_monitor_and_only_monitor_ack_controls_delay(self):
        mon = self.monitor(password="fixture-only")
        sock = mock.Mock()
        sock.recv.side_effect = [b"+OK\r\n", b"+"]
        with mock.patch.object(base.socket, "create_connection", return_value=sock), \
             mock.patch.object(base.threading, "Thread"), \
             mock.patch.object(base.time, "sleep") as sleep:
            mon.__enter__()
        self.assertEqual(sock.sendall.call_args_list, [
            mock.call(b"*2\r\n$4\r\nAUTH\r\n$12\r\nfixture-only\r\n"),
            mock.call(b"*1\r\n$7\r\nMONITOR\r\n"),
        ])
        sleep.assert_called_once_with(0.1)

    def test_ack_prefix_with_trailing_data_is_ready(self):
        mon = self.monitor()
        mon._sock = mock.Mock()
        mon._sock.recv.return_value = b'+OK\r\n123 [0 client] "PING"\r\n'
        self.assertTrue(mon._send(b"MONITOR"))
        self.assertEqual(mon._pending, b'123 [0 client] "PING"\r\n')

    def test_checkpoint_excludes_complete_coalesced_lines(self):
        mon = self.monitor()
        sock = mock.Mock()
        sock.recv.side_effect = [
            b'+OK\r\n123 [0 client] "AUTH"\r\n124 [0 client] "GE',
            b'T" "key"\r\n',
            b'',
        ]
        with mock.patch.object(base.socket, "create_connection", return_value=sock), \
             mock.patch.object(base.threading, "Thread"):
            mon.__enter__()
            self.assertEqual(mon.commands_seen(), ["AUTH"])
            mon.checkpoint()
            mon._run()
        self.assertEqual(mon.commands_seen(), ["GET"])

    def test_socket_reader_captures_coalesced_traffic_and_closes(self):
        client, server = socket.socketpair()
        captured = threading.Event()
        errors = []
        mon = self.monitor()

        class Lines(list):
            def append(self, line):
                super().append(line)
                captured.set()

        mon._lines = Lines()

        def respond():
            try:
                server.settimeout(2)
                command = b""
                while not command.endswith(b"MONITOR\r\n"):
                    chunk = server.recv(4096)
                    if not chunk:
                        raise AssertionError("MONITOR was not sent")
                    command += chunk
                server.sendall(b'+OK\r\n123 [0 client] "GET" "key"\r\n')
            except (OSError, AssertionError) as exc:
                errors.append(exc)
            finally:
                server.close()

        responder = threading.Thread(target=respond)
        responder.start()
        try:
            with mock.patch.object(base.socket, "create_connection", return_value=client), mon:
                self.assertTrue(captured.wait(2), "immediate traffic was lost")
                self.assertEqual(mon.commands_seen(), ["GET"])
                mon.checkpoint()
                self.assertEqual(mon.commands_seen(), [])
            self.assertFalse(mon._thread.is_alive())
            self.assertEqual(client.fileno(), -1)
        finally:
            client.close()
            responder.join(3)
        self.assertFalse(responder.is_alive())
        self.assertEqual(errors, [])

    def test_reader_parses_chunk_received_during_shutdown(self):
        mon = self.monitor()
        mon._sock = mock.Mock()

        def receive(_size):
            mon._stop.set()
            return b'123 [0 client] "GET" "key"\r\n'

        mon._sock.recv.side_effect = receive
        mon._run()
        self.assertEqual(mon.commands_seen(), ["GET"])


if __name__ == "__main__":
    unittest.main()
