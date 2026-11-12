"""Focused serial outcome journal and noninterference controls."""
import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
import test_runtime_base as base


class OutcomeJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = pathlib.Path(self.tmp.name) / "journal"
        self.journal = base._OutcomeJournal(str(self.path), "unpredictable-test-id")
        self.addCleanup(self.journal.close)

    def wrap(self, functions, journal=None, timings=None):
        facade = {"test_" + name: fn for name, fn in functions.items()}
        base._instrument(mock.Mock(spec=base.Origin, hits=0), timings, facade, journal)
        return facade

    def records(self):
        return [json.loads(line) for line in self.path.read_text().splitlines()]

    def test_nested_caught_and_duplicate_wrapping(self):
        result = object()
        error = ValueError("private")
        def inner():
            raise error
        def outer():
            try:
                wrapped["test_inner"]()
            except ValueError as caught:
                self.assertIs(caught, error)
            return result
        wrapped = self.wrap({"inner": inner, "outer": outer}, self.journal)
        original = wrapped["test_outer"]
        base._instrument(mock.Mock(spec=base.Origin, hits=0), facade=wrapped,
                         journal=self.journal)
        self.assertIs(wrapped["test_outer"], original)
        self.assertIs(wrapped["test_outer"](), result)
        self.journal.close()
        self.assertEqual(self.records(), [
            [1, "unpredictable-test-id", 1, None, "test_outer", "entry"],
            [1, "unpredictable-test-id", 2, 1, "test_inner", "entry"],
            [1, "unpredictable-test-id", 2, 1, "test_inner", "exception"],
            [1, "unpredictable-test-id", 1, None, "test_outer", "return"],
        ])
        self.assertFalse(self.journal.failed)

    def test_propagated_exception_identity_and_base_exception(self):
        for error, event in ((ValueError(), "exception"), (KeyboardInterrupt(), "base_exception")):
            with self.subTest(event=event):
                def inner(error=error):
                    raise error
                def outer():
                    wrapped["test_inner"]()  # noqa: B023
                wrapped = self.wrap({"inner": inner, "outer": outer}, self.journal)
                with self.assertRaises(type(error)) as caught:
                    wrapped["test_outer"]()
                self.assertIs(caught.exception, error)
        self.journal.close()
        records = self.records()
        self.assertEqual([row[-1] for row in records],
                         ["entry", "entry", "exception", "exception",
                          "entry", "entry", "base_exception", "base_exception"])
        self.assertEqual([row[2] for row in records], [1, 2, 2, 1, 3, 4, 4, 3])

    def test_existing_path_and_disabled(self):
        self.path.write_text("original")
        other = base._OutcomeJournal(str(self.path), "other")
        self.assertTrue(other.failed)
        wrapped = self.wrap({"plain": lambda: 42}, other)
        self.assertEqual(wrapped["test_plain"](), 42)
        other.close()
        self.assertEqual(self.path.read_text(), "original")
        self.assertEqual(self.wrap({"plain": lambda: 43})["test_plain"](), 43)

    def test_open_failure_and_retained_file_ownership(self):
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        error = ValueError("identity")
        with mock.patch.object(base.os, "open", side_effect=OSError("open")):
            failed = base._OutcomeJournal(str(self.path.parent / "missing"), "id")
        def fail():
            raise error
        wrapped = self.wrap({"fail": fail}, failed)["test_fail"]
        with self.assertRaises(ValueError) as caught:
            wrapped()
        self.assertIs(caught.exception, error)
        self.assertTrue(failed.failed)
        failed.close()
        moved = self.path.parent / "owned"
        self.path.rename(moved)
        self.path.write_text("substitute")
        self.wrap({"ok": lambda: None}, self.journal)["test_ok"]()
        self.journal.close()
        self.assertEqual(self.path.read_text(), "substitute")
        self.assertEqual([json.loads(line)[-1] for line in moved.read_text().splitlines()],
                         ["entry", "return"])

    def test_fdopen_failure_closes_descriptor(self):
        descriptors = []
        real_open = base.os.open
        def capture_open(*args):
            descriptor = real_open(*args)
            descriptors.append(descriptor)
            return descriptor
        with mock.patch.object(base.os, "open", side_effect=capture_open), \
             mock.patch.object(base.os, "fdopen", side_effect=OSError("fdopen")):
            failed = base._OutcomeJournal(str(self.path.parent / "fdopen"), "id")
        self.assertTrue(failed.failed)
        self.assertEqual(len(descriptors), 1)
        with self.assertRaises(OSError):
            base.os.fstat(descriptors[0])
        failed.close()

    def test_disabled_preserves_exception_identity(self):
        for error in (ValueError(), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                def fail(error=error):
                    raise error
                wrapped = self.wrap({"fail": fail})["test_fail"]
                with self.assertRaises(type(error)) as caught:
                    wrapped()
                self.assertIs(caught.exception, error)

    def test_io_failures_are_sticky_and_do_not_mask_outcomes(self):
        for stage in ("write", "flush", "close", "short_write"):
            for raises in (False, True):
                with self.subTest(stage=stage, raises=raises):
                    sink = mock.Mock()
                    sink.write.side_effect = lambda data: len(data)
                    if stage == "short_write":
                        sink.write.return_value = 0
                        sink.write.side_effect = None
                    else:
                        getattr(sink, stage).side_effect = OSError(stage)
                    path = self.path.parent / (stage + str(raises))
                    journal = base._OutcomeJournal(str(path), "id")
                    journal._file.close()
                    journal._file = sink
                    error = ValueError("same object")
                    result = object()
                    def target(raises=raises, error=error, result=result):
                        if raises:
                            raise error
                        return result
                    wrapped = self.wrap({"target": target}, journal)["test_target"]
                    if raises:
                        with self.assertRaises(ValueError) as caught:
                            wrapped()
                        self.assertIs(caught.exception, error)
                    else:
                        self.assertIs(wrapped(), result)
                    journal.close()
                    self.assertTrue(journal.failed)
                    count = sink.write.call_count
                    functions = {"target": lambda result=result: result}
                    wrapped2 = self.wrap(functions, journal)["test_target"]
                    self.assertIs(wrapped2(), result)
                    self.assertEqual(sink.write.call_count, count)

    def test_original_order_and_timing(self):
        timings = []
        events = []
        wrapped = self.wrap({"target": lambda: events.append("call")}, self.journal, timings)
        with mock.patch.object(base, "_conn_cursor", return_value=7), \
             mock.patch.object(base, "_write_breadcrumb", side_effect=events.append), \
             mock.patch.object(base.time, "monotonic", side_effect=[3.0, 5.0]), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            wrapped["test_target"]()
        self.assertEqual(events, ["test_target 7", "call", "DONE test_target"])
        self.assertEqual(base._SPANS[-1], ("test_target", 7, 7))
        self.assertEqual(timings, [("test_target", 2.0)])
        self.assertEqual(output.getvalue(), "TIMING test_target 2.000000s\n")


if __name__ == "__main__":
    unittest.main()
