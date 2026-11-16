#!/usr/bin/env python3
"""Guard: the warm url_file fault window has one value on both sides.

A TEST_FAULTS build sleeps NGX_HTTP_CACHE_TURBO_WARM_FILE_TEST_DELAY_MS in the
admin warm thread task when the list name holds ".delay-<stage>"
(ngx_http_cache_turbo_warm_file_test_delay, src/ngx_http_cache_turbo_admin.c;
the macro lives in the TEST_FAULTS-only src/ngx_http_cache_turbo_testalloc.h).
The abort fixture does not observe the end of that sleep ahead of time: its
boundary arm aborts at open + WARM_FILE_TEST_DELAY (ci/tools/abort_fixture.py,
FileAnchor.wait_final_reply) and needs to land within a few ms of the reply.
A native window longer than the fixture's makes that arm abort a parked request
seconds early; a shorter one makes it abort an answered request. Either way
the arm stops testing the boundary, so the two values must be equal.

The check reads the macro from the header, requires the hook's ".delay-" branch
to sleep exactly that macro (no literal that could drift), and compares it with
the fixture's imported constant, the value the boundary arm really uses.
"""

from __future__ import annotations

import pathlib
import re
import sys
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "ci" / "tools"))

import abort_fixture as af

MACRO = "NGX_HTTP_CACHE_TURBO_WARM_FILE_TEST_DELAY_MS"
HEADER = REPO / "src" / "ngx_http_cache_turbo_testalloc.h"
ADMIN = REPO / "src" / "ngx_http_cache_turbo_admin.c"
HOOK = "ngx_http_cache_turbo_warm_file_test_delay"

_DEFINE = re.compile(r"^#define[ \t]+" + MACRO + r"[ \t]+(.+?)[ \t]*$",
                     re.MULTILINE)
# The hook's definition (return type on the line before, then the name at the
# start of a line) up to the first closing brace in column 0.
_HOOK_BODY = re.compile(r"^" + HOOK + r"\(\n.*?^\}$", re.MULTILINE | re.DOTALL)
_DELAY_BRANCH = re.compile(
    r'"\.delay-%s%Z", stage\);\s*'
    r"if \(ngx_strstr\(ctx->nul, marker\) != NULL\) \{\s*"
    r"ngx_msleep\(([^;]*)\);\s*return;\s*\}")


def check(header: str, admin: str, fixture_seconds: float) -> list[str]:
    """Every reason the native window and the fixture's copy can disagree."""
    problems: list[str] = []
    defines = _DEFINE.findall(header)
    native_ms: int | None = None
    if len(defines) != 1:
        problems.append(f"{HEADER.name}: want one #define {MACRO} <ms>, "
                        f"found {len(defines)}")
    elif not defines[0].isdigit():
        problems.append(f"{HEADER.name}: {MACRO} is {defines[0]!r}, "
                        "want a plain decimal millisecond count")
    else:
        native_ms = int(defines[0])

    bodies = _HOOK_BODY.findall(admin)
    if len(bodies) != 1:
        problems.append(f"{ADMIN.name}: want one TEST_FAULTS {HOOK}() "
                        f"definition, found {len(bodies)}")
    else:
        branch = _DELAY_BRANCH.search(bodies[0])
        if branch is None:
            problems.append(f"{ADMIN.name}: {HOOK}() has no recognisable "
                            '".delay-" branch sleeping ngx_msleep(...)')
        elif branch.group(1).strip() != MACRO:
            problems.append(f"{ADMIN.name}: the \".delay-\" branch sleeps "
                            f"ngx_msleep({branch.group(1).strip()}), "
                            f"want ngx_msleep({MACRO})")

    if native_ms is not None and fixture_seconds * 1000 != native_ms:
        problems.append(f"WARM_FILE_TEST_DELAY is {fixture_seconds!r}s but "
                        f"{MACRO} is {native_ms}ms: the boundary arm would "
                        f"abort {abs(fixture_seconds * 1000 - native_ms):g}ms "
                        "away from the reply")
    return problems


def _real() -> tuple[str, str]:
    return HEADER.read_text(), ADMIN.read_text()


class WarmWindowAgrees(unittest.TestCase):

    def test_tree_agrees(self) -> None:
        header, admin = _real()
        self.assertEqual(check(header, admin, af.WARM_FILE_TEST_DELAY), [])

    def test_fixture_value_is_the_one_the_anchor_uses(self) -> None:
        # The boundary arm's prediction: FileAnchor adds the module constant.
        anchor = af.FileAnchor.__new__(af.FileAnchor)
        anchor.wait_parked = lambda: 10.0  # type: ignore[method-assign]
        self.assertEqual(anchor.wait_final_reply(),
                         10.0 + af.WARM_FILE_TEST_DELAY)

    def test_fixture_drift_is_reported(self) -> None:
        header, admin = _real()
        problems = check(header, admin, af.WARM_FILE_TEST_DELAY + 4.0)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("WARM_FILE_TEST_DELAY", problems[0])

    def test_sub_millisecond_drift_is_reported(self) -> None:
        header, admin = _real()
        self.assertNotEqual(
            check(header, admin, af.WARM_FILE_TEST_DELAY + 0.0005), [])

    def test_native_drift_is_reported(self) -> None:
        header, admin = _real()
        drifted = _DEFINE.sub(f"#define {MACRO}  5000", header)
        self.assertNotEqual(drifted, header)
        problems = check(drifted, admin, af.WARM_FILE_TEST_DELAY)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("5000ms", problems[0])

    def test_literal_sleep_in_hook_is_rejected(self) -> None:
        header, admin = _real()
        literal = admin.replace(f"ngx_msleep({MACRO})", "ngx_msleep(1000)")
        self.assertNotEqual(literal, admin)
        problems = check(header, literal, af.WARM_FILE_TEST_DELAY)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("ngx_msleep(1000)", problems[0])

    def test_missing_or_duplicate_define_is_an_error(self) -> None:
        header, admin = _real()
        line = _DEFINE.search(header)
        assert line is not None
        self.assertNotEqual(check(_DEFINE.sub("", header), admin, 1.0), [])
        self.assertNotEqual(
            check(header + "\n" + line.group(0) + "\n", admin, 1.0), [])

    def test_non_numeric_define_is_an_error(self) -> None:
        header, admin = _real()
        odd = _DEFINE.sub(f"#define {MACRO}  (2 * 500)", header)
        problems = check(odd, admin, 1.0)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("plain decimal", problems[0])

    def test_missing_hook_is_an_error(self) -> None:
        header, admin = _real()
        gone = admin.replace(f"\n{HOOK}(\n", "\nrenamed_hook(\n")
        self.assertNotEqual(gone, admin)
        self.assertNotEqual(check(header, gone, af.WARM_FILE_TEST_DELAY), [])


if __name__ == "__main__":
    unittest.main()
