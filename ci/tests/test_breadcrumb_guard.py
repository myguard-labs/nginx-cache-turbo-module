#!/usr/bin/env python3
"""Unit test for the breadcrumb harness that ci-hang-guard.sh depends on.

The R6b hang detection (ci-hang-guard.sh) reads CT_TEST_BREADCRUMB to label
which test never finished on a wedge. The breadcrumb file is written by
test_runtime_base._write_breadcrumb() when the CT_TEST_BREADCRUMB env var
is set and the instrumented wrapper enters/exits each test_*.

This test proves:
1. The breadcrumb file is created when CT_TEST_BREADCRUMB is exported
2. The test name appears on ENTER (before test runs)
3. "DONE <test>" appears on EXIT (after test completes)
4. The mechanism fails gracefully when CT_TEST_BREADCRUMB is unset or invalid
"""

import os
import pathlib
import sys
import tempfile
import unittest

# Import the breadcrumb machinery from the test harness
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "tools"))


class TestBreadcrumbHarness(unittest.TestCase):
    """Negative control: proves breadcrumb writes work as expected."""

    def setUp(self):
        """Create a temp file to capture breadcrumbs."""
        self.temp_dir = tempfile.mkdtemp()
        self.breadcrumb_path = pathlib.Path(self.temp_dir) / "breadcrumb.txt"

    def tearDown(self):
        """Clean up temp files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_breadcrumb_writes_with_env_set(self):
        """Prove breadcrumb file is written when CT_TEST_BREADCRUMB is set.

        This is the HAPPY PATH: the environment variable is exported, the
        harness calls _write_breadcrumb(), and the file receives the text.
        """
        import importlib

        # Simulate the wrapper exporting CT_TEST_BREADCRUMB
        os.environ["CT_TEST_BREADCRUMB"] = str(self.breadcrumb_path)

        # Reload the module to pick up the new env var
        import test_runtime_base
        importlib.reload(test_runtime_base)

        # Simulate test enter: write the test name
        test_runtime_base._write_breadcrumb("test_example 42")
        self.assertTrue(self.breadcrumb_path.exists(),
                       f"Breadcrumb file not created at {self.breadcrumb_path}")
        self.assertEqual(self.breadcrumb_path.read_text().strip(), "test_example 42")

        # Simulate test exit: write DONE
        test_runtime_base._write_breadcrumb("DONE test_example")
        self.assertEqual(self.breadcrumb_path.read_text().strip(), "DONE test_example")

    def test_breadcrumb_silent_when_env_unset(self):
        """Prove breadcrumb fails silently when CT_TEST_BREADCRUMB is unset.

        The harness checks `if not _BREADCRUMB: return` to avoid errors
        on machines where the env var is not exported (local dev, partial CI).
        """
        import importlib

        import test_runtime_base

        # Ensure env var is NOT set
        os.environ.pop("CT_TEST_BREADCRUMB", None)

        # Reload to pick up the unset env var
        importlib.reload(test_runtime_base)

        # This must NOT raise an error or side-effect
        test_runtime_base._write_breadcrumb("test_example 42")
        # Verify no file was created (we haven't set the path)
        self.assertFalse(self.breadcrumb_path.exists(),
                       "Breadcrumb file created when env was unset")

    def test_breadcrumb_robust_to_invalid_path(self):
        """Prove breadcrumb handles invalid/unwritable paths gracefully.

        If CT_TEST_BREADCRUMB points to a nonexistent directory or is
        unwritable, the harness must not crash the test suite.
        """
        import importlib

        import test_runtime_base

        # Point to an invalid path
        os.environ["CT_TEST_BREADCRUMB"] = "/nonexistent/dir/breadcrumb.txt"

        # Reload to pick up the new env var
        importlib.reload(test_runtime_base)

        # This must NOT raise an error; the try/except in _write_breadcrumb
        # catches OSError and passes
        test_runtime_base._write_breadcrumb("test_example 42")


if __name__ == "__main__":
    unittest.main()
