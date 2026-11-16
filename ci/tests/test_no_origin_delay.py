"""Regression check for areas/core.py `_no_origin_delay` (CI-L10d-T5a).

The helper borrows a zero-delay origin for serial classification loops and
must restore the suite baseline (Origin.reset_delay(), not a hardcoded 0.0)
on normal exit and when the block raises. No nginx, no network: the Origin is
constructed but never started.
"""

import pathlib
import sys
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "ci" / "tools"))

from areas import core
from origin import Origin

BASELINE = 0.05


class NoOriginDelayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.origin = Origin(0, delay=BASELINE)

    def test_zero_inside_and_restored_after_normal_exit(self) -> None:
        with core._no_origin_delay(self.origin):
            self.assertEqual(self.origin.delay, 0.0)
        self.assertEqual(self.origin.delay, BASELINE)

    def test_restored_after_exception_inside_block(self) -> None:
        with self.assertRaises(RuntimeError), core._no_origin_delay(self.origin):
            self.assertEqual(self.origin.delay, 0.0)
            raise RuntimeError("boom inside the zero-delay block")
        self.assertEqual(self.origin.delay, BASELINE)


if __name__ == "__main__":
    unittest.main()
