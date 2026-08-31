#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
# Prove the tracked clang-tidy policy and fanalyzer wrapper both go red.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CASE="$TMP/with space"
mkdir -p "$TMP/src" "$CASE/src"

printf '#include <stdlib.h>\nint f(void) { return rand(); }\n' \
    > "$TMP/src/clang_bad.c"
if clang-tidy --config-file="$ROOT/.clang-tidy" "$TMP/src/clang_bad.c" \
       -- -std=c11 > "$TMP/clang.out" 2>&1; then
    echo "analysis controls: clang-tidy accepted deliberate rand() defect" >&2
    exit 1
fi
grep -q 'cert-msc30-c' "$TMP/clang.out" || {
    echo "analysis controls: clang-tidy failed for the wrong reason" >&2
    exit 1
}

printf '#include <stdlib.h>\nvoid f(void) { void *p = malloc(8); (void) p; }\n' \
    > "$CASE/src/fanalyzer_bad.c"
printf '[{"directory":"%s","file":"%s","arguments":["gcc","-c","%s"]}]\n' \
    "$CASE" "$CASE/src/fanalyzer_bad.c" "$CASE/src/fanalyzer_bad.c" \
    > "$CASE/compile_commands.json"
if (cd "$CASE" && FANALYZER_SOURCE_ROOT="$CASE" FANALYZER_TOOL_ROOT="$ROOT" \
        bash "$ROOT/ci/tools/fanalyzer.sh" "$CASE") > "$TMP/fanalyzer.out" 2>&1; then
    echo "analysis controls: fanalyzer accepted deliberate leak" >&2
    exit 1
fi
grep -q 'Wanalyzer-malloc-leak' "$TMP/fanalyzer.out" || {
    echo "analysis controls: fanalyzer failed for the wrong reason" >&2
    exit 1
}

echo "analysis controls: clang-tidy and fanalyzer defects rejected"
