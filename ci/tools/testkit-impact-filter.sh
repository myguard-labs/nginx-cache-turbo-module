#!/usr/bin/env bash
set -euo pipefail

paths="$(cat)"
grep -qE '^(src/|ci/prober-scenarios/|\.github/actions/build-cache/)|^(ci/tools/testkit-(stage|run|scenarios|host-guard|impact-filter)\.sh|ci/tests/unit/check_testkit_contract\.sh|\.github/workflows/(testkit|testkit-valgrind|ci-deep|ci)\.yml)$' <<<"$paths"
