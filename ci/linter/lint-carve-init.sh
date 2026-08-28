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
# explicitly initialised in the carve block of
# ngx_http_cache_turbo_shm_init_zone(). ngx_slab_alloc()
# does not zero, but the fresh-carve path happens to land on kernel-zeroed
# anonymous pages -- so a forgotten member reads 0 anyway and no runtime test
# can see the omission. Same shape as lint-stripe-seam.sh: correct today only
# by an accident of the allocator, so it has to be caught structurally.
#
# Whole-tree by nature, like lint-shm-lock.sh: the invariant is a property of
# a fixed pair of files, so the staged file list only decides whether this
# checker is relevant to the change, never which lines it reads.
#
# NEEDS A CONFIGURED NGINX TREE. The implementation parses the module with
# clang rather than lexing it, so it requires a tree where ./configure has run
# (it reads ALL_INCS from objs/Makefile). Keep a configure-only tree away from
# .build/, which the unit suite treats as compiled:
#
#   BUILD_ROOT="$PWD/.carve-tree" bash ci/tools/ci-build.sh nginx "" configure
#   NGX_SRC_TREE="$PWD/.carve-tree/nginx-<version>" ci/linter/lint-carve-init.sh
#
# With no tree the gate exits 2 -- "could not run" -- and never reports clean:
# a parser that cannot parse must not look like a passing gate.
#
# Usage: ci/linter/lint-carve-init.sh [files...]   Env: LINT_MODE=staged|all
#        NGX_SRC_TREE=<dir> to pick the tree explicitly.
# Exit:  0 clean, 1 a member has no initialiser, 2 could not run.
# Extend: the parse and the _pad* exemption live in ci/tools/carve_init_ast.py.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

# Materialise before mapfile so a failing producer cannot leave a truncated
# prefix that looks like a complete, clean work list.
files_tmp="$(mktemp)"
trap 'rm -f "$files_tmp"' EXIT
lint_files '^src/.*\.[ch]$' "$@" > "$files_tmp" \
    || die "lint_files failed while selecting carve-init inputs"
mapfile -t FILES < "$files_tmp"
rm -f "$files_tmp"
trap - EXIT
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-carve-init: no C files to check"; exit 0; }

echo "lint-carve-init: ${#FILES[@]} file(s)"
say "shctx carve init (CARVE-INIT)"

ROOT="$(repo_root)"
IMPL="$ROOT/ci/tools/lint-carve-init.sh"
# A missing implementation is exit 2 ("could not run"), never a clean pass.
[ -f "$IMPL" ] || die "$IMPL missing -- the carve-init checker is gone"

exec bash "$IMPL"
