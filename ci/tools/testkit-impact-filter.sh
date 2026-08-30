#!/usr/bin/env bash
set -euo pipefail

paths="$(cat)"
grep -qE '^(src/|ci/prober-scenarios/|ci/tools/testkit-(stage|run|scenarios|host-guard|impact-filter)\.sh|ci/tests/unit/check_testkit_contract\.sh|\.github/actions/build-cache/|\.github/workflows/(testkit|testkit-valgrind|ci-deep|ci)\.yml)' <<<"$paths"
