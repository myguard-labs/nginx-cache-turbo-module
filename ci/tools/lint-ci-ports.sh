#!/usr/bin/env bash
#
# Enforce the per-job port-band split (AUD-CIPORT1).
#
# build-test.yml, asan.yml and ci-deep.yml all pin the SAME self-hosted
# runner (builder02) and have DISJOINT per-workflow concurrency groups, so
# nothing serialises them against each other. Every runtime-bearing job used
# to sweep stale test listeners over the same hardcoded 18870-18999 range and
# start test_runtime.py on the same default --port 18880: the later-starting
# job's sweep killed the running job's fixtures (observed on PR #167 as an
# ASan "Address already in use" and a Runtime "did not land in Redis" --
# same cause, two faces). The fix is one 64-wide port band per job, derived
# from a job-level TEST_BASE_PORT env var, with the sweep range computed from
# it instead of hardcoded.
#
# This lint fails the build if either invariant regresses:
#   1. A "Sweep stale test listeners" step's `seq` range uses a hardcoded
#      port literal instead of deriving from $TEST_BASE_PORT.
#   2. Two runtime-bearing jobs (jobs that declare TEST_BASE_PORT) share the
#      same base port value, across ALL scanned workflow files combined.
#
# Usage: ci/tools/lint-ci-ports.sh [workflow-file ...]
#   (defaults to .github/workflows/build-test.yml, asan.yml, ci-deep.yml)

set -euo pipefail

cd "$(dirname "$0")/../.."

if [ "$#" -gt 0 ]; then
    files=("$@")
else
    files=(.github/workflows/build-test.yml .github/workflows/asan.yml .github/workflows/ci-deep.yml)
fi

status=0

# --- Check 1: every `seq` in a sweep step must derive from $TEST_BASE_PORT,
# never a bare numeric literal. ---
for f in "${files[@]}"; do
    [ -f "$f" ] || continue
    while IFS=: read -r lineno line; do
        if [[ "$line" == *'$(seq '* ]]; then
            # Extract the seq(1) argument list.
            args="${line#*"\$(seq "}"
            args="${args%%)*}"
            if [[ "$args" =~ [0-9]{4,5} ]]; then
                echo "lint-ci-ports: $f:$lineno: sweep uses a hardcoded port literal instead of \$TEST_BASE_PORT: ${line#"${line%%[![:space:]]*}"}" >&2
                status=1
            fi
        fi
    done < <(grep -n '\$(seq ' "$f")
done

# --- Check 2: every job that declares TEST_BASE_PORT must have a value
# distinct from every other such job, across all scanned files. ---
# "job:port:file" rows, in file order. A job-level `env:` block is indented
# 4 spaces in every workflow here (2 for the job key + 2 for its children);
# TEST_BASE_PORT sits one level deeper (6 spaces) as a direct child of that
# env: block, not the job-env: block used by e.g. LEGACY_NGINX_VERSION's
# sibling lines -- so match on the key name, not on indentation depth, to
# stay robust to reindentation.
declare -A seen_port_job
declare -A seen_port_file

for f in "${files[@]}"; do
    [ -f "$f" ] || continue
    current_job=""
    while IFS= read -r line; do
        if [[ "$line" =~ ^\ \ ([A-Za-z0-9_-]+):[[:space:]]*$ ]]; then
            current_job="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ TEST_BASE_PORT:[[:space:]]*\"?([0-9]+)\"? ]]; then
            port="${BASH_REMATCH[1]}"
            job="${current_job:-<unknown>}"
            if [[ -n "${seen_port_job[$port]:-}" ]]; then
                echo "lint-ci-ports: TEST_BASE_PORT=$port is used by both '${seen_port_job[$port]}' (${seen_port_file[$port]}) and '$job' ($f) -- runtime-bearing jobs on the shared runner must have DISTINCT bands" >&2
                status=1
            else
                seen_port_job[$port]="$job"
                seen_port_file[$port]="$f"
            fi
        fi
    done < "$f"
done

if [ "$status" -eq 0 ]; then
    echo "lint-ci-ports: OK (${#seen_port_job[@]} distinct port bands across ${#files[@]} workflow files)"
fi

exit "$status"
