#!/usr/bin/env python3
"""Guard: every ci-hang-guard.sh-wrapped suite must export CT_TEST_BREADCRUMB.

`ci-hang-guard.sh` names the test that never finished by reading the file at
`$CT_TEST_BREADCRUMB` (written by test_runtime_base._write_breadcrumb via the
_instrument() wrapper) and copying it to `$ARTDIR/hanging-test.txt`.

`_write_breadcrumb()` is a deliberate no-op when the variable is unset, so a
lane that forgets to export it loses hang attribution SILENTLY -- exactly the
failure observed on 2026-08-21, where a wedge produced a gdb backtrace but no
`hanging-test.txt`. The mechanism itself was never broken; the export was
missing. These tests therefore assert the WORKFLOW CONTRACT, not the writer:
a test that only calls _write_breadcrumb() with the variable set passes even on
a tree where every workflow forgot the export, and proves nothing.

Test 1 is the load-bearing one: it fails if any hang-guarded step drops the
export. Test 2 covers the enter/DONE pair through the real _instrument()
wrapper, which is what actually runs in the suite.
"""

import os
import pathlib
import re
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "ci" / "tools"))

VAR = "CT_TEST_BREADCRUMB"


def _hang_guard_steps(text):
    """Yield (line_no, block) for each `run:` block invoking ci-hang-guard.sh.

    A step is approximated as the run-block plus the lines above it back to the
    previous `- name:`, which is where a step-level `env:` legally sits.
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if "ci-hang-guard.sh" in line and not line.lstrip().startswith("#"):
            start = 0
            for j in range(i, -1, -1):
                if re.match(r"\s*-\s+name:", lines[j]):
                    start = j
                    break
            end = len(lines)
            for j in range(i + 1, len(lines)):
                if re.match(r"\s*-\s+name:", lines[j]):
                    end = j
                    break
            yield i + 1, "\n".join(lines[start:end])


class TestBreadcrumbExportedByWorkflows(unittest.TestCase):
    def test_every_hang_guarded_step_exports_breadcrumb(self):
        """THE control: a hang-guarded step without the export loses attribution."""
        workflows = sorted((REPO / ".github" / "workflows").glob("*.yml"))
        self.assertTrue(workflows, "no workflow files found")

        checked = 0
        missing = []
        for wf in workflows:
            for line_no, block in _hang_guard_steps(wf.read_text(encoding="utf-8")):
                checked += 1
                if VAR not in block:
                    missing.append(f"{wf.name}:{line_no}")

        self.assertGreater(
            checked, 0, "found no ci-hang-guard.sh steps -- the guard is not wired"
        )
        self.assertEqual(
            missing,
            [],
            f"ci-hang-guard.sh steps missing {VAR}: {missing}. Without it "
            f"_write_breadcrumb() no-ops and a wedge yields no hanging-test.txt.",
        )

    def test_every_hang_guarded_workflow_uploads_the_artifacts(self):
        """A capture nobody retrieves is as useless as one never written.

        ci-hang-guard.sh writes hanging-test.txt, the gdb backtrace and the
        nginx error.log into ARTDIR. If the job never uploads that directory the
        evidence dies with the runner -- which is how earlier wedges produced a
        job timeout and nothing else.
        """
        missing = []
        for wf in sorted((REPO / ".github" / "workflows").glob("*.yml")):
            text = wf.read_text(encoding="utf-8")
            if "ci-hang-guard.sh" not in text:
                continue
            artdirs = set(re.findall(r"([\w./-]*ci-hang-artifacts)/?", text))
            for artdir in artdirs:
                base = artdir.rsplit("/", 1)[-1]
                if not re.search(
                    r"upload-artifact.*?path:\s*[^\n]*" + re.escape(base),
                    text,
                    re.DOTALL,
                ):
                    missing.append(f"{wf.name}:{base}")

        missing = sorted(set(missing))
        self.assertEqual(
            missing,
            [],
            f"hang-guard artifact dirs never uploaded: {missing}. The capture "
            f"would be written and then discarded with the runner.",
        )


class TestBreadcrumbWrapper(unittest.TestCase):
    """The enter/DONE pair through the real _instrument() wrapper."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = pathlib.Path(self.tmp) / "current-test.txt"
        self._saved = os.environ.get(VAR)

    def tearDown(self):
        import shutil

        if self._saved is None:
            os.environ.pop(VAR, None)
        else:
            os.environ[VAR] = self._saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_instrument_writes_enter_then_done(self):
        import importlib

        os.environ[VAR] = str(self.path)
        import test_runtime_base

        importlib.reload(test_runtime_base)

        seen = {}

        def test_fake():
            seen["during"] = self.path.read_text(encoding="utf-8").strip()

        # _instrument() (MAINT-T1) only wraps modules named `test_runtime` or
        # `areas.*`, so register the fake in a synthetic area module -- that
        # exercises the real selection logic rather than bypassing it.
        import types

        mod = types.ModuleType("areas._breadcrumb_selftest")
        mod.test_fake = test_fake
        sys.modules[mod.__name__] = mod
        try:
            test_runtime_base._instrument(None)
            self.assertTrue(
                getattr(mod.test_fake, "_ct_instrumented", False),
                "_instrument() did not wrap the area test -- selection logic changed",
            )
            mod.test_fake()
        finally:
            sys.modules.pop(mod.__name__, None)

        self.assertIn("during", seen, "wrapped test never ran")
        self.assertTrue(
            seen["during"].startswith("test_fake "),
            f"breadcrumb on ENTER should name the test, got {seen['during']!r}",
        )
        self.assertEqual(
            self.path.read_text(encoding="utf-8").strip(),
            "DONE test_fake",
            "breadcrumb should record DONE on exit",
        )


if __name__ == "__main__":
    unittest.main()
