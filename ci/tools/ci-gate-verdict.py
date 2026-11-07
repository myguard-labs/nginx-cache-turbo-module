#!/usr/bin/env python3
"""Verdict for the `CI / gate` job (CI-L1).

Reads the `toJSON(needs)` blob on stdin: {"<job>": {"result": "...", ...}}.
Exit 0 only when every needed job is `success` or `skipped`; any other result
(failure, cancelled, an unknown value) or an unreadable/empty blob exits 1, so
the gate fails closed.

`skipped` is legitimate: change detection skips asan/fuzzing/testkit on
docs-only PRs. A job skipped because ITS OWN upstream failed is not hidden by
this, because that upstream is itself in the blob and reads `failure`. The
`changes` job is the root of every other job, and it is never legitimately
skipped, so it must be `success` (--require, default `changes`); this also
catches a blob in which the root silently went missing.
"""

import argparse
import json
import sys

OK = {"success", "skipped"}


def verdict(blob, required):
    """Return (ok, lines) for a decoded needs blob."""
    if not isinstance(blob, dict) or not blob:
        return False, ["needs blob is empty or not an object"]
    bad = []
    lines = []
    for name in sorted(blob):
        entry = blob[name]
        result = entry.get("result") if isinstance(entry, dict) else None
        lines.append("%s: %s" % (name, result))
        if result not in OK:
            bad.append("%s result=%r" % (name, result))
    for name in required:
        entry = blob.get(name)
        result = entry.get("result") if isinstance(entry, dict) else None
        if result != "success":
            bad.append("%s must be success, got %r" % (name, result))
    return not bad, lines + ["FAIL: " + b for b in bad]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--require", action="append", default=None,
                    help="job that must be exactly success (repeatable; default: changes)")
    args = ap.parse_args(argv)
    required = args.require if args.require is not None else ["changes"]
    try:
        blob = json.load(sys.stdin)
    except ValueError as exc:
        print("FAIL: needs blob is not valid JSON: %s" % exc)
        return 1
    ok, lines = verdict(blob, required)
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
