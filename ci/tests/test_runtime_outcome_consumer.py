"""Receipt-backed outcome consumer controls."""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import test_runtime_base as base


class ConsumerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.journal = base._OutcomeJournal(str(self.path / "j"), "run", "source")
        token = self.journal.enter("root")
        self.journal.finish(token, "root", "return")
        self.journal.close()
        self.receipt = self.journal.publish(str(self.path / "status"))
        self.data = (self.path / "j").read_bytes()

    def consume(self, data=None, receipt=None, **kwargs):
        args = {
            "expected_run": "run",
            "expected_source": "source",
            "expected_roots": ["root"],
        }
        args.update(kwargs)
        return base._consume_outcome(
            self.data if data is None else data,
            self.receipt if receipt is None else receipt,
            **args,
        )

    def records(self, records):
        data = b"".join((json.dumps(r) + "\n").encode() for r in records)
        self.receipt._status.update(
            length=len(data), sha256=hashlib.sha256(data).hexdigest()
        )
        return data

    def test_live_receipt_and_invalidation(self):
        self.assertEqual(self.consume(), "SUCCESS")
        self.journal.close()
        self.assertEqual(self.consume(), "UNKNOWN")
        self.assertEqual(self.consume(receipt={}), "UNKNOWN")

    def test_inputs_and_status(self):
        for args in (
            {"expected_run": ""},
            {"expected_run": 1},
            {"expected_run": "wrong"},
            {"expected_source": ""},
            {"expected_source": 1},
            {"expected_source": "wrong"},
            {"expected_roots": []},
            {"expected_roots": [""]},
            {"expected_roots": "root"},
        ):
            with self.subTest(args=args):
                self.assertEqual(self.consume(**args), "UNKNOWN")
        for data in (b"", "data"):
            self.assertEqual(self.consume(data=data), "UNKNOWN")
        original = self.receipt._status.copy()
        for key, value in [
            ("version", True),
            ("version", 2),
            ("run_id", 1),
            ("run_id", "x"),
            ("source_id", 1),
            ("source_id", "x"),
            ("complete", 1),
            ("io_ok", False),
            ("length", True),
            ("length", 0),
            ("length", 999),
            ("sha256", None),
            ("sha256", "x"),
            ("extra", 1),
        ]:
            self.receipt._status = original.copy()
            self.receipt._status[key] = value
            with self.subTest(key=key, value=value):
                self.assertEqual(self.consume(), "UNKNOWN")
        self.receipt._status = original
        self.assertEqual(self.consume(data=self.data[:-1]), "UNKNOWN")

    def test_structure_and_failure(self):
        r = lambda i, p, n, e: [1, "run", i, p, n, e]
        nested = [
            r(1, None, "root", "entry"),
            r(2, 1, "child", "entry"),
            r(2, 1, "child", "return"),
            r(1, None, "root", "return"),
        ]
        self.assertEqual(self.consume(data=self.records(nested)), "SUCCESS")
        for event in ("exception", "base_exception"):
            records = nested.copy()
            records[2] = r(2, 1, "child", event)
            self.assertEqual(self.consume(data=self.records(records)), "FAILURE")
        cases = [
            nested[:-1],
            nested + [nested[-1]],
            [r(2, None, "root", "entry")],
            [r(True, None, "root", "entry")],
            [r(1, True, "root", "entry")],
            [[True, "run", 1, None, "root", "entry"]],
            [[1, "bad", 1, None, "root", "entry"]],
            [[1, "run", 1, None, "", "entry"]],
            [[1, "run", 1, None, "root", 1]],
            [[1, "run", 1, None, "root"]],
            [r(1, None, "root", "bad")],
            [r(1, None, "root", "return")],
            [r(1, None, "root", "entry"), r(1, None, "other", "return")],
            [r(1, None, "root", "entry"), r(2, None, "child", "entry")],
        ]
        for records in cases:
            with self.subTest(records=records):
                self.assertEqual(self.consume(data=self.records(records)), "UNKNOWN")
        for data in (b"\xff\n", b"bad\n", b"\n", b"[]"):
            self.receipt._status.update(
                length=len(data), sha256=hashlib.sha256(data).hexdigest()
            )
            self.assertEqual(self.consume(data=data), "UNKNOWN")
        roots = [
            r(1, None, "a", "entry"),
            r(1, None, "a", "return"),
            r(2, None, "b", "entry"),
            r(2, None, "b", "return"),
        ]
        data = self.records(roots)
        self.assertEqual(self.consume(data=data, expected_roots=["a", "b"]), "SUCCESS")
        self.assertEqual(self.consume(data=data, expected_roots=["b", "a"]), "UNKNOWN")

    def test_full_byte_binding(self):
        prefix = self.data
        self.receipt._status["length"] += 1
        self.assertEqual(self.consume(data=prefix), "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
