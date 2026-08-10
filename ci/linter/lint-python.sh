#!/usr/bin/env bash
# ci/linter/lint-python.sh -- ruff lint + format check over tracked *.py.
#
# ruff replaces flake8/pyflakes/isort/black here: one binary, no venv, and it
# is what the superrepo's tools/ scripts are already checked with. It covers
# ci/linter/workflow_policy.py and ci/tools/test_runtime.py -- both gate logic,
# so an unlinted break here is a check that stops checking rather than a script
# that stops running.
#
# Keep this dispatched even when the count is low: an adopted module that adds
# its first ci/tools/ helper gets it checked from the first commit. Run an
# extension census (`git ls-files | sed -n 's/.*\.//p' | sort | uniq -c`) when
# deriving a linter set for a new module -- a tracked-but-unlinted language is
# a silent pass in exactly the way a selector matching zero files is.
#
# `ruff format --check` reports formatting WITHOUT rewriting: a linter that
# edits files behind a commit hook changes what you are about to commit.
#
# Usage: ci/linter/lint-python.sh [files...]   Env: LINT_MODE=staged|all
# Extend: per-rule config goes in a [tool.ruff] block in pyproject.toml at the
# repo root, not in flags here, so editors and CI see the same rules.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

mapfile -t FILES < <(lint_files '\.py$' "$@")
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-python: no Python files to check"; exit 0; }

echo "lint-python: ${#FILES[@]} file(s)"
need ruff "apt-get install ruff  (or: pipx install ruff)"
rc=0

# RETARGET (adoption step 32). Two changes from the skeleton's version, both
# required by step 33's "the same linters gate the hook and the PR" rule --
# this repo's .pre-commit-config.yaml already runs ruff, and two gates
# disagreeing about what blocks is worse than one.
#
# 1. --select F,B,I,PLE,RET,RUF059, not ruff's default rule set. The tiers are
#    this repo's measured choice, not a guess: RUF059 (unused-unpacked-variable)
#    is why the gate exists at all -- a captured-then-never-read variable is the
#    tell for the vacuous-assertion class that produced a test whose only
#    surviving assertion held in BOTH the pass and the fail state. I (import
#    sorting) was added once measured 100% safe-autofixable across the module
#    repos, so it could not land red on arrival. The nominally-cheap remainder
#    (N, C4, SIM, UP, PLW, RUF) measured 84 findings here with only 21
#    safe-autofixable, i.e. 63 hand-edits to the test driver for no correctness
#    gain -- out of scope for a CI rollout.
#
# 2. No `ruff format --check`. This repo has never adopted ruff's formatter;
#    running it here reported "6 files would be reformatted" on arrival, which
#    is a whole-tree reformat of ci/tools/test_runtime.py (~15.6k lines) that no
#    gate ever asked for and that would bury the next real diff. Adopting a
#    formatter is a repo decision, not something a CI adoption smuggles in.
#    Recorded in adoption-findings.md.
#
# Keep these flags identical to the ruff hook in .pre-commit-config.yaml; move
# one, move both.
RUFF_SELECT='F,B,I,PLE,RET,RUF059'
say "ruff check (--select $RUFF_SELECT)"
ruff check --force-exclude --select "$RUFF_SELECT" "${FILES[@]}" || rc=1
exit "$rc"
