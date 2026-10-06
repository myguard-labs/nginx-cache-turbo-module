#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/linter/lint-atomic-ordering.sh -- weak-ordering atomics tripwire
# (CI-ARM64-NO-LIVE-LANE).
#
# THIS CHECK IS THIS MODULE'S OWN and has no counterpart in
# labs/nginx-skeleton-module. src/ must not gain ngx_memory_barrier or a raw
# __atomic_* call with an explicit weak ordering: the accepted no-arm64-lane
# risk rests on nginx's full-barrier primitives being the only ordering source.
# The rule and its comment-stripping live in the implementation.
#
# Whole-tree by nature, like lint-shm-lock.sh: the staged file list only decides
# whether this checker is relevant, never which lines it reads.
#
# Usage: ci/linter/lint-atomic-ordering.sh [files...]   Env: LINT_MODE=staged|all
# Exit:  0 clean, 1 weak ordering found, 2 could not run.
# Extend: the banned tokens are in ci/tools/lint-atomic-ordering.sh, not here.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

lint_files_into FILES '^src/.*\.[ch]$' "$@"
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-atomic-ordering: no C files to check"; exit 0; }

echo "lint-atomic-ordering: ${#FILES[@]} file(s)"
say "weak-ordering atomics tripwire (CI-ARM64-NO-LIVE-LANE)"

ROOT="$(repo_root)"
IMPL="$ROOT/ci/tools/lint-atomic-ordering.sh"
# A missing implementation is exit 2 ("could not run"), never a clean pass.
[ -f "$IMPL" ] || die "$IMPL missing -- the atomic-ordering checker is gone"

exec bash "$IMPL"
