#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/linter/lint-suite-docs.sh -- this module's own test-suite integrity gates.
#
# THREE CHECKS THAT ARE THIS MODULE'S OWN, with no counterpart in
# labs/nginx-skeleton-module. All three predate the ci/linter/ adoption and ran
# only from build-test.yml's validation job; this wrapper puts them behind the
# same entry point as every other checker, so they also fire from the commit
# hook. Adoption rule 2: a gate the target already had survives the rollout and
# goes back to the skeleton as a finding.
#
#   lint-orphan-tests.py       a .t file that no suite actually runs -- a test
#                              nobody executes is not coverage, and it reads as
#                              coverage in every count.
#   lint-doc-preset-count.py   the preset count quoted in the docs matches the
#                              presets that exist. Documentation drift here is
#                              a claim about what the module supports.
#   test-tls-fixture-cleanup.py  the TLS fixtures are torn down, so a failing
#                              run cannot leave state that makes the NEXT run
#                              pass (or fail) for the wrong reason.
#
# Grouped into one checker rather than three because they share a selector and
# a subject -- the test suite -- and run-all.sh reports per checker, so three
# wrappers would be three near-identical files and three lines of output for
# what is one question: is the suite still self-consistent?
#
# Whole-tree by nature: each is a property of the suite as a set, so the staged
# file list only decides whether this checker is relevant to the change.
#
# Usage: ci/linter/lint-suite-docs.sh [files...]   Env: LINT_MODE=staged|all
# Exit:  0 all clean, 1 any check reported, 2 could not run.
# Extend: the checks live in ci/tools/*.py; add one to CHECKS below.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

# Relevant to a change that touches the suite, its docs, or the module itself.
lint_files_into FILES '^(ci/t/|ci/tools/|docs/|src/|README\.md)' "$@"
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-suite-docs: nothing relevant to check"; exit 0; }

echo "lint-suite-docs: ${#FILES[@]} file(s)"

need python3 "apt-get install python3"

ROOT="$(repo_root)"
CHECKS=(
    lint-orphan-tests.py
    lint-doc-preset-count.py
    test-tls-fixture-cleanup.py
)

rc=0
for c in "${CHECKS[@]}"; do
    impl="$ROOT/ci/tools/$c"
    # Missing implementation is "could not run", never a clean pass -- the same
    # rule need() applies to a missing tool. A deleted checker must not be able
    # to report success by absence.
    [ -f "$impl" ] || die "$impl missing -- one of this repo's own suite gates is gone"
    say "$c"
    python3 "$impl" || rc=1
done

exit "$rc"
