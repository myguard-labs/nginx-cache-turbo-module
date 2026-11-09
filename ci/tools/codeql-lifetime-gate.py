#!/usr/bin/env python3
"""Fail on new CodeQL lifetime findings or incomplete SARIF evidence."""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

RULES = {
    "myguard/nginx-lifetime/use-after-request-release",
    "myguard/nginx-lifetime/park-callback-unchecked",
}


def finding(result):
    rule = result["ruleId"]
    location = result["locations"][0]["physicalLocation"]
    region = location["region"]
    uri = location["artifactLocation"]["uri"]
    message = result["message"]["text"]
    line, column = region["startLine"], region["startColumn"]
    if rule not in RULES or not isinstance(uri, str) or not uri:
        raise ValueError("invalid finding identity")
    if not isinstance(message, str) or not message:
        raise ValueError("invalid finding identity")
    for position in (line, column):
        if not isinstance(position, int) or isinstance(position, bool) or position < 1:
            raise ValueError("invalid finding identity")
    return rule, uri, line, column, message


def evaluate(sarif, baseline, expected=None):
    if (sarif["version"] != "2.1.0" or not isinstance(sarif["runs"], list)
            or len(sarif["runs"]) != 1):
        raise ValueError("expected one SARIF 2.1.0 run")
    run = sarif["runs"][0]
    rules = {item["id"] for item in run["tool"]["driver"]["rules"]}
    if rules != RULES:
        raise ValueError("query inventory mismatch: " + repr(sorted(rules)))
    if any(not invocation.get("executionSuccessful", False)
           for invocation in run.get("invocations", [])):
        raise ValueError("analysis invocation failed")
    if not isinstance(run["results"], list) or not isinstance(baseline, list):
        raise TypeError("results and baseline must be lists")
    current = Counter(finding(result) for result in run["results"])
    accepted = Counter(finding(result) for result in baseline)
    if expected and not any(key[0] == expected for key in current):
        raise ValueError("expected fixture rule did not report: " + expected)
    return current - accepted


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sarif", type=Path)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("--expect-rule", choices=sorted(RULES))
    args = parser.parse_args()
    try:
        sarif = json.loads(args.sarif.read_text())
        baseline = json.loads(args.baseline.read_text())
        new = evaluate(sarif, baseline, args.expect_rule)
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError) as exc:
        print("ERROR: invalid or incomplete lifetime evidence:", exc, file=sys.stderr)
        return 2
    for identity, count in sorted(new.items()):
        print("NEW", count, *identity)
    return 1 if new else 0


if __name__ == "__main__":
    sys.exit(main())
