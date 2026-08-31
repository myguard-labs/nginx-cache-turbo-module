#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
# Prove the source guard rejects the former two-past-end expression.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

bash "$ROOT/ci/fuzz/extract_norm_args.sh" >/dev/null
sed 's/p = (amp < last) ? amp + 1 : amp;/p = amp + 1;/' \
    "$ROOT/ci/fuzz/generated_norm_args.inc" > "$TMP"

if bash "$DIR/check_norm_args_tail.sh" "$TMP" >/dev/null 2>&1; then
    echo "normalizer tail: former unbounded advance survived control" >&2
    exit 1
fi

echo "normalizer tail: negative control rejected"
