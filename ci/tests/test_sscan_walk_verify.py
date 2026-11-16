"""Regression controls for the SSCAN abort fixture's follow-up purge."""

import pathlib
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
import test_runtime_base
from areas import l2


class FakeClock:
    """Virtual clock for test_runtime_base.wait_for: sleep() advances time
    instantly, so a bounded wait that times out costs no real seconds."""

    def __init__(self):
        self.now = 1000.0

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds

    def patched(self):
        return mock.patch.object(
            test_runtime_base, "time",
            types.SimpleNamespace(time=self.time, sleep=self.sleep))


class FakeRedis:
    port = 1

    def __init__(self, delayed_reads=0, retained=False, object_left=False):
        self.delayed_reads = delayed_reads
        self.retained = retained
        self.object_left = object_left
        self.tag_reads = 0

    def cli(self, *args):
        command, key = args[2:4]
        if command == "SMEMBERS":
            return "member-a\nmember-b"
        if command != "EXISTS":
            raise AssertionError(f"unexpected command: {args}")
        if ":tag:" in key:
            self.tag_reads += 1
            return "1" if self.retained or self.tag_reads <= self.delayed_reads else "0"
        return "1" if self.object_left else "0"


class SscanWalkVerify(unittest.TestCase):
    uri = "/ab/sscan-walk-reply-1"
    body = b'{"purged":4}'

    def verify(self, redis, status=200, body=None):
        l2._sscan_walk_abort_site(redis).verify(
            None, self.uri, status, self.body if body is None else body)

    def test_delayed_srem_eventually_passes(self):
        redis = FakeRedis(delayed_reads=3)
        self.verify(redis)
        self.assertGreater(redis.tag_reads, 1)

    def test_retained_tag_times_out_with_members(self):
        redis = FakeRedis(retained=True)
        clock = FakeClock()
        with clock.patched(), self.assertRaises(AssertionError) as caught:
            self.verify(redis)
        self.assertGreaterEqual(clock.now - 1000.0, 10.0)
        self.assertIn("ctabtag:tag:sscan-walk-reply-1", str(caught.exception))
        self.assertIn("member-a", str(caught.exception))
        self.assertGreater(redis.tag_reads, 1)

    def test_immediate_success_and_object_failure(self):
        self.verify(FakeRedis())
        with self.assertRaisesRegex(AssertionError, "tag purge left"):
            self.verify(FakeRedis(object_left=True))

    def test_bad_response_fails(self):
        with self.assertRaisesRegex(AssertionError, "status 500"):
            self.verify(FakeRedis(), status=500)
        with self.assertRaisesRegex(AssertionError, "purge answered"):
            self.verify(FakeRedis(), body=b'{"purged":3}')


if __name__ == "__main__":
    unittest.main()
