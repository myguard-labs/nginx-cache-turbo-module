#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
# Guard the final-token pointer bound in the extracted production normalizer.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../../.." && pwd)"
FILE="${1:-$ROOT/ci/fuzz/generated_norm_args.inc}"

if [ "$#" -eq 0 ]; then
    bash "$ROOT/ci/fuzz/extract_norm_args.sh" >/dev/null
fi

guard='p = (amp < last) ? amp + 1 : amp;'
if [ "$(grep -cF "$guard" "$FILE" || true)" -ne 1 ]; then
    echo "normalizer tail: missing exact bounded advance" >&2
    exit 1
fi
if grep -qF 'p = amp + 1;' "$FILE"; then
    echo "normalizer tail: unbounded amp + 1 advance remains" >&2
    exit 1
fi

echo "normalizer tail: final token keeps the one-past pointer in bounds"
