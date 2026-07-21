#!/usr/bin/env python3
"""Reject pull-request workflows that let UNTRUSTED (forked) PR code select the
persistent self-hosted runners.

Same-repo PRs (head.repo.full_name == github.repository) and pushes are trusted
and run self-hosted; fork PRs fall back to GitHub-hosted. pull_request_target is
forbidden outright (it would run with repo secrets against untrusted head)."""

from __future__ import annotations

import pathlib
import re
import sys


# This script lives at ci/tools/; repo root is two levels up (ci/ -> root).
ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
# Approved trust splits: both send fork PRs to a GitHub-hosted runner and keep
# same-repo PRs + pushes/dispatch on the self-hosted pool. The .fork form is the
# org skeleton's (fork is null on non-pull_request events -> self-hosted); the
# full_name form is the older equivalent. Either is safe; add a new form here
# only if it preserves that fork->hosted / trusted->self-hosted split.
TRUST_SPLITS = frozenset({
    (
        "${{ github.event.pull_request.head.repo.fork && 'ubuntu-latest' || "
        "fromJSON('[\"self-hosted\",\"builder02\",\"lxc\"]') }}"
    ),
    (
        "${{ (github.event_name != 'pull_request' || "
        "github.event.pull_request.head.repo.full_name == github.repository) && "
        "fromJSON('[\"self-hosted\",\"builder02\",\"lxc\"]') || 'ubuntu-24.04' }}"
    ),
})
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
            if runner in TRUST_SPLITS or HOSTED.fullmatch(runner):
                continue
            errors.append(
                f"{path.name}: PR job runner must be GitHub-hosted or the "
                f"approved trust split, got {runner!r}"
            )
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("CI runner policy: fork PRs run GitHub-hosted; same-repo PRs + pushes self-hosted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
