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


def inventory(tool):
    driver = tool["driver"]
    extensions = tool.get("extensions", [])
    if not isinstance(driver, dict) or not isinstance(extensions, list):
        raise TypeError("invalid tool components")
    components = [driver, *extensions]
    inventories = []
    for component in components:
        rules = component.get("rules", [])
        if not isinstance(rules, list):
            raise TypeError("invalid rule inventory")
        ids = [item["id"] for item in rules]
        if any(not isinstance(rule, str) or not rule for rule in ids):
            raise ValueError("invalid rule id")
        inventories.append(ids)
    all_rules = [rule for rules in inventories for rule in rules]
    if len(all_rules) != len(set(all_rules)) or set(all_rules) != RULES:
        raise ValueError("query inventory mismatch: " + repr(sorted(all_rules)))
    return inventories


def valid_index(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def component_index(reference, tool):
    component = reference.get("toolComponent")
    if component is None:
        return 0
    index = component["index"]
    if not valid_index(index):
        raise ValueError("invalid component index")
    selected = tool["extensions"][index]
    if any(component[key] != selected.get(key) for key in ("name", "guid")
           if key in component):
        raise ValueError("conflicting component reference")
    return index + 1


def validate_reference(result, inventories, tool):
    rule_id = result["ruleId"]
    reference = result.get("rule")
    if reference is None:
        if rule_id not in RULES:
            raise ValueError("invalid rule reference")
        if "ruleIndex" in result:
            index = result["ruleIndex"]
            if not valid_index(index) or inventories[0][index] != rule_id:
                raise ValueError("invalid legacy rule index")
        return
    if not isinstance(reference, dict) or reference.get("id", rule_id) != rule_id:
        raise ValueError("conflicting rule reference")
    index = reference["index"]
    if not valid_index(index):
        raise ValueError("invalid rule index")
    component_index_value = component_index(reference, tool)
    if inventories[component_index_value][index] != rule_id:
        raise ValueError("conflicting rule index")
    if "ruleIndex" in result and result["ruleIndex"] != index:
        raise ValueError("conflicting legacy rule index")


def evaluate(sarif, baseline, expected=None):
    if (sarif["version"] != "2.1.0" or not isinstance(sarif["runs"], list)
            or len(sarif["runs"]) != 1):
        raise ValueError("expected one SARIF 2.1.0 run")
    run = sarif["runs"][0]
    inventories = inventory(run["tool"])
    if any(not invocation.get("executionSuccessful", False)
           for invocation in run.get("invocations", [])):
        raise ValueError("analysis invocation failed")
    if not isinstance(run["results"], list) or not isinstance(baseline, list):
        raise TypeError("results and baseline must be lists")
    for result in run["results"]:
        validate_reference(result, inventories, run["tool"])
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
