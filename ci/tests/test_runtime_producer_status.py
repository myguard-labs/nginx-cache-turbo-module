"""Focused producer completion and publication controls."""

import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
import test_runtime_base as base


class ProducerStatusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.journal = base._OutcomeJournal(str(self.root / "j"), "run", "source")
        self.addCleanup(lambda: self.journal.close() if not self.journal._closed else None)

    def record(self, name):
        token = self.journal.enter(name)
        self.journal.finish(token, name, "return")

    def test_complete_stream_and_identity(self):
        self.record("first")
        prefix = (self.root / "j").read_bytes()
        self.record("é-second")
        self.journal.close()
        receipt = self.journal.publish(str(self.root / "s"))
        status = receipt.status()
        data = (self.root / "j").read_bytes()
        self.assertEqual(status, json.loads((self.root / "s").read_bytes()))
        self.assertEqual(
            (status["version"], status["run_id"], status["source_id"]), (1, "run", "source")
        )
        self.assertEqual(status["length"], len(data))
        self.assertEqual(status["sha256"], hashlib.sha256(data).hexdigest())
        self.assertNotEqual(status["length"], len(prefix))
        self.assertNotEqual(status["sha256"], hashlib.sha256(prefix).hexdigest())
        self.assertTrue(status["complete"] and status["io_ok"])
        status["run_id"] = "changed"
        self.assertEqual(receipt.status()["run_id"], "run")

    def test_incomplete_and_identity(self):
        for mode in ("empty", "open", "run", "source", "unclosed"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                j = base._OutcomeJournal(
                    d + "/j", "" if mode == "run" else "r", "" if mode == "source" else "s"
                )
                if mode != "empty":
                    token = j.enter("a")
                    if mode != "open":
                        j.finish(token, "a", "return")
                if mode != "unclosed":
                    j.close()
                self.assertIsNone(j.publish(d + "/status"))
                if mode == "unclosed":
                    j.close()

    def test_late_calls_invalidate_receipt(self):
        for method in ("close", "enter", "finish", "publish"):
            with self.subTest(method=method), tempfile.TemporaryDirectory() as d:
                j = base._OutcomeJournal(d + "/j", "r", "s")
                token = j.enter("a")
                j.finish(token, "a", "return")
                j.close()
                receipt = j.publish(d + "/status")
                self.assertIsNotNone(receipt.status())
                if method == "close":
                    j.close()
                elif method == "enter":
                    j.enter("late")
                elif method == "finish":
                    j.finish(token, "a", "return")
                else:
                    j.publish(d + "/again")
                self.assertIsNone(receipt.status())

    def test_instrument_after_close_invalidates_receipt_and_preserves_result(self):
        self.record("a")
        self.journal.close()
        receipt = self.journal.publish(str(self.root / "status"))
        result = object()
        facade = {"test_late": lambda: result}
        base._instrument(mock.Mock(spec=base.Origin, hits=0), facade=facade, journal=self.journal)
        self.assertIs(facade["test_late"](), result)
        self.assertIsNone(receipt.status())

    def test_publication_io_failures(self):
        self.record("a")
        self.journal.close()
        for fault in ("open", "write", "short", "flush", "close"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as d:
                j = base._OutcomeJournal(d + "/j", "r", "s")
                token = j.enter("a")
                j.finish(token, "a", "return")
                j.close()
                real_fdopen = base.os.fdopen

                def fdopen(fd, mode, fault=fault, real_fdopen=real_fdopen):
                    stream = real_fdopen(fd, mode)

                    class Fault:
                        def __enter__(self):
                            return self

                        def __exit__(self, *args):
                            stream.close()
                            if fault == "close":
                                raise OSError("close")

                        def write(self, data):
                            if fault == "write":
                                raise OSError("write")
                            if fault == "short":
                                return stream.write(data[:-1])
                            return stream.write(data)

                        def flush(self):
                            stream.flush()
                            if fault == "flush":
                                raise OSError("flush")

                    return Fault()

                with (
                    mock.patch.object(base.os, "fdopen", side_effect=fdopen),
                    mock.patch.object(
                        base.os,
                        "open",
                        side_effect=OSError("open") if fault == "open" else base.os.open,
                    ),
                ):
                    self.assertIsNone(j.publish(d + "/status"))
                self.assertTrue(j.failed)
                if fault in ("flush", "close"):
                    self.assertEqual(
                        json.loads(pathlib.Path(d + "/status").read_bytes())["run_id"], "r"
                    )

    def test_publication_fdopen_failure_closes_descriptor(self):
        self.record("a")
        self.journal.close()
        descriptors = []
        real_open = base.os.open

        def capture(*args):
            fd = real_open(*args)
            descriptors.append(fd)
            return fd

        with (
            mock.patch.object(base.os, "open", side_effect=capture),
            mock.patch.object(base.os, "fdopen", side_effect=OSError("fdopen")),
        ):
            self.assertIsNone(self.journal.publish(str(self.root / "status")))
        with self.assertRaises(OSError):
            base.os.fstat(descriptors[0])

    def test_journal_io_failures(self):
        for fault in ("open", "write", "short", "flush", "close"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as d:
                with mock.patch.object(
                    base.os,
                    "open",
                    side_effect=OSError("open") if fault == "open" else base.os.open,
                ):
                    j = base._OutcomeJournal(d + "/j", "r", "s")
                if fault != "open":
                    j._file.close()
                    sink = mock.Mock()
                    sink.write.side_effect = lambda data: len(data)
                    if fault == "short":
                        sink.write.side_effect = lambda data: len(data) - 1
                    else:
                        getattr(sink, fault).side_effect = OSError(fault)
                    j._file = sink
                token = j.enter("a")
                j.finish(token, "a", "return")
                j.close()
                self.assertTrue(j.failed)
                self.assertIsNone(j.publish(d + "/status"))


if __name__ == "__main__":
    unittest.main()
