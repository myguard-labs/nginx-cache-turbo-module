#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/linter/lint-stripe-seam.sh -- the stripe seam (P4-2-s3b).
#
# THIS CHECK IS THIS MODULE'S OWN and has no counterpart in
# labs/nginx-skeleton-module. Wrapper over ci/tools/lint-stripe-seam.sh so the
# gate fires from the commit hook as well as CI, matching lint-shm-lock.sh.
#
# What it enforces, in one line: a zone's shm state lives in an array of
# stripes, and no site may reach a stripe's ngx_slab_pool_t except through
# ngx_http_cache_turbo_zone_sh() / _zone_pool() / _zone_mutex() or the
# key-directed ngx_http_cache_turbo_stripe_of(). A site that keeps a bare
# `z->shpool` silently pins stripe 0 while its neighbours ask the resolver, so
# once N > 1 the module locks one pool's mutex and frees into another pool's
# arena -- heap corruption under the wrong lock. At today's N == 1 both
# spellings behave identically, which is exactly why no runtime test can catch
# a stray site and it has to be caught structurally.
#
# Whole-tree by nature, like lint-shm-lock.sh: the invariant is a property of
# the module's C as a set, so the staged file list only decides whether this
# checker is relevant to the change, never which lines it reads.
#
# Usage: ci/linter/lint-stripe-seam.sh [files...]   Env: LINT_MODE=staged|all
# Exit:  0 clean, 1 a site bypasses the resolver, 2 could not run.
# Extend: the permitted-exception list is in ci/tools/lint-stripe-seam.sh.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

lint_files_into FILES '^src/.*\.[ch]$' "$@"
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-stripe-seam: no C files to check"; exit 0; }

echo "lint-stripe-seam: ${#FILES[@]} file(s)"
say "stripe seam (P4-2-s3b)"

ROOT="$(repo_root)"
IMPL="$ROOT/ci/tools/lint-stripe-seam.sh"
# A missing implementation is exit 2 ("could not run"), never a clean pass.
[ -f "$IMPL" ] || die "$IMPL missing -- the stripe-seam checker is gone"

exec bash "$IMPL"
