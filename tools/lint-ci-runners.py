#!/usr/bin/env python3
"""Reject pull-request workflows that can select persistent self-hosted runners."""

from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
TRUST_SPLIT = (
    "${{ github.event_name == 'pull_request' && 'ubuntu-24.04' || "
    "fromJSON('[\"self-hosted\",\"builder02\",\"lxc\"]') }}"
)
HOSTED = re.compile(r"ubuntu-(?:latest|[0-9]+\.[0-9]+)")


def main() -> int:
    errors: list[str] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        if re.search(r"(?m)^\s{2}pull_request_target\s*:", text):
            errors.append(f"{path.name}: pull_request_target is forbidden")
        if not re.search(r"(?m)^\s{2}pull_request\s*:", text):
            continue
        runners = re.findall(r"(?m)^\s{4}runs-on:\s*(.+?)\s*$", text)
        if not runners:
            errors.append(f"{path.name}: pull_request workflow has no jobs")
            continue
        for runner in runners:
            if runner == TRUST_SPLIT or HOSTED.fullmatch(runner):
                continue
            errors.append(
                f"{path.name}: PR job runner must be GitHub-hosted or the "
                f"approved trust split, got {runner!r}"
            )
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("CI runner policy: public pull requests use GitHub-hosted runners")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
