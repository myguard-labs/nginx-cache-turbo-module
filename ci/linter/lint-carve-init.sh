#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/linter/lint-carve-init.sh -- the shctx carve-init invariant (CARVE-INIT).
#
# THIS CHECK IS THIS MODULE'S OWN and has no counterpart in
# labs/nginx-skeleton-module. Wrapper over ci/tools/lint-carve-init.sh so the
# gate fires from the commit hook as well as CI, matching lint-shm-lock.sh.
#
# What it enforces, in one line: every ngx_http_cache_turbo_shctx_t member is
# explicitly initialised in shm_init_zone()'s carve block. ngx_slab_alloc()
# does not zero, but the fresh-carve path happens to land on kernel-zeroed
# anonymous pages -- so a forgotten member reads 0 anyway and no runtime test
# can see the omission. Same shape as lint-stripe-seam.sh: correct today only
# by an accident of the allocator, so it has to be caught structurally.
#
# Whole-tree by nature, like lint-shm-lock.sh: the invariant is a property of
# a fixed pair of files, so the staged file list only decides whether this
# checker is relevant to the change, never which lines it reads.
#
# Usage: ci/linter/lint-carve-init.sh [files...]   Env: LINT_MODE=staged|all
# Exit:  0 clean, 1 a member has no initialiser, 2 could not run.
# Extend: the parse and the _pad* exemption live in ci/tools/lint-carve-init.sh.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

# The mapfile-over-process-substitution below drops lint_files' exit status
# (semgrep pipeline-status-swallowed-by-substitution). It is the shared idiom of
# every ci/linter/ wrapper, and here it is not load-bearing: FILES only decides
# whether this checker is RELEVANT to the change. It never selects what gets
# read -- the implementation re-derives its inputs from two fixed paths and
# exits 2 rather than ok if either parse comes back empty. So a truncated FILES
# can only make this wrapper skip on a change it did not need to inspect; it can
# never produce a pass over a subset. Fixing the idiom belongs in lib.sh for all
# wrappers at once, not in one of three.
mapfile -t FILES < <(lint_files '^src/.*\.[ch]$' "$@")
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-carve-init: no C files to check"; exit 0; }

echo "lint-carve-init: ${#FILES[@]} file(s)"
say "shctx carve init (CARVE-INIT)"

ROOT="$(repo_root)"
IMPL="$ROOT/ci/tools/lint-carve-init.sh"
# A missing implementation is exit 2 ("could not run"), never a clean pass.
[ -f "$IMPL" ] || die "$IMPL missing -- the carve-init checker is gone"

exec bash "$IMPL"
