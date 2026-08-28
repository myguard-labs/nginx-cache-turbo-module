#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/linter/lint-shm-lock.sh -- the shm-mutex hold invariant (issue R7).
#
# THIS CHECK IS THIS MODULE'S OWN and has no counterpart in
# labs/nginx-skeleton-module. It predates the ci/linter/ adoption, where it ran
# only from build-test.yml's validation job; the wrapper puts it behind the
# same entry point as every other checker so it also fires from the commit
# hook, which is where it is cheapest to act on. Adoption rule 2: a gate the
# target already had survives the rollout, keeps its behaviour, and goes back
# to the skeleton as a finding.
#
# What it enforces, in one line: the zone mutex
# (`ngx_shmtx_lock(&...->mutex)`) may only be held across bounded, synchronous
# work -- slab alloc/free, rbtree/queue ops, memcpy -- and never across
# anything that yields to the event loop, parks the request, produces output,
# runs the phase engine or registers a timer. A worker that parks while holding
# the zone mutex stalls every other worker on the same zone until it comes
# back, which is a whole-server hang rather than a slow request. The reasoning
# and the full banned-call list live in the implementation.
#
# Whole-tree by nature, like lint-ci-ports.sh: the invariant is a property of
# the module's C as a set, so the staged file list only decides whether this
# checker is relevant to the change, never which lines it reads.
#
# Usage: ci/linter/lint-shm-lock.sh [files...]   Env: LINT_MODE=staged|all
# Exit:  0 clean, 1 the invariant is violated, 2 could not run.
# Extend: the banned-call list is in ci/tools/lint-shm-lock.sh, not here.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

lint_files_into FILES '^src/.*\.[ch]$' "$@"
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-shm-lock: no C files to check"; exit 0; }

echo "lint-shm-lock: ${#FILES[@]} file(s)"
say "shm-mutex hold invariant (R7)"

ROOT="$(repo_root)"
IMPL="$ROOT/ci/tools/lint-shm-lock.sh"
# A missing implementation is exit 2 ("could not run"), never a clean pass --
# the same rule lib.sh's need() applies to a missing tool. Without this the
# wrapper would report success for a checker that no longer exists.
[ -f "$IMPL" ] || die "$IMPL missing -- this repo's own R7 checker is gone"

exec bash "$IMPL"
