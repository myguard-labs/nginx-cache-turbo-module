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
# This lint fails the build if any invariant regresses:
#   1. A "Sweep stale test listeners" step's `seq` range must derive from
#      $TEST_BASE_PORT -- not a hardcoded literal, and not some other variable.
#   2. Two runtime-bearing jobs (jobs that declare TEST_BASE_PORT) share the
#      same base port value, across ALL scanned workflow files combined.
#   3. A job that starts the runtime suite must declare TEST_BASE_PORT and pass
#      it as --port. This is the check that matters most: a NEW job added later
#      with neither a sweep nor a band is invisible to checks 1 and 2, silently
#      takes test_runtime.py's default --port 18880, and reintroduces exactly
#      the collision this whole item fixed.
#
# Scans every .github/workflows/*.yml by default, NOT a hardcoded list -- a
# fourth workflow growing a runtime job must not be able to slip past unchecked.
#
# Usage: ci/tools/lint-ci-ports.sh [workflow-file ...]

set -euo pipefail

cd "$(dirname "$0")/../.."

if [ "$#" -gt 0 ]; then
    files=("$@")
else
    mapfile -t files < <(find .github/workflows -maxdepth 1 -name '*.yml' -o -maxdepth 1 -name '*.yaml' | sort)
fi

if [ "${#files[@]}" -eq 0 ]; then
    echo "lint-ci-ports: no workflow files found -- refusing to report OK on an empty scan" >&2
    exit 1
fi

status=0

# --- Check 1: every `seq` in a sweep step must derive from $TEST_BASE_PORT,
# never a bare numeric literal. ---
for f in "${files[@]}"; do
    [ -f "$f" ] || continue
    while IFS=: read -r lineno line; do
        # Only port sweeps. `for i in $(seq 1 "$n")` is a loop counter and has
        # nothing to do with ports; flagging it would train people to ignore
        # this lint, which is how a gate dies.
        sweep_body="$(sed -n "${lineno},$((lineno + 3))p" "$f")"
        [[ "$sweep_body" == *fuser* ]] || continue
        if [[ "$line" == *'$(seq '* ]]; then
            # Extract the seq(1) argument list.
            args="${line#*"\$(seq "}"
            args="${args%%)*}"
            trimmed="${line#"${line%%[![:space:]]*}"}"
            if [[ "$args" =~ [0-9]{4,5} ]]; then
                echo "lint-ci-ports: $f:$lineno: sweep uses a hardcoded port literal instead of \$TEST_BASE_PORT: $trimmed" >&2
                status=1
            elif [[ "$args" != *TEST_BASE_PORT* ]]; then
                # Absence of a literal is not presence of the right variable:
                # $(seq "$SOME_OTHER_VAR" ...) sweeps a band this lint cannot
                # reason about, which is the same failure with a nicer face.
                echo "lint-ci-ports: $f:$lineno: sweep range does not derive from \$TEST_BASE_PORT: $trimmed" >&2
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
declare -A job_declares_band     # "file:job" -> port
declare -A job_starts_suite      # "file:job" -> the invoking line, trimmed
declare -A job_passes_port       # "file:job" -> 1

for f in "${files[@]}"; do
    [ -f "$f" ] || continue
    current_job=""
    in_jobs=0
    while IFS= read -r line; do
        # Only treat 2-space keys as job names AFTER the top-level `jobs:` key.
        # Before it, `on:` has 2-space children too, and mistaking one for a job
        # misattributes every finding that follows it.
        if [[ "$line" =~ ^jobs:[[:space:]]*$ ]]; then
            in_jobs=1
            current_job=""
            continue
        fi
        if [[ "$in_jobs" -eq 1 && "$line" =~ ^\ \ ([A-Za-z0-9_-]+):[[:space:]]*$ ]]; then
            current_job="${BASH_REMATCH[1]}"
            continue
        fi

        job="${current_job:-<unknown>}"
        key="$f:$job"

        if [[ "$line" =~ TEST_BASE_PORT:[[:space:]]*\"?([0-9]+)\"? ]]; then
            port="${BASH_REMATCH[1]}"
            job_declares_band[$key]="$port"
            if [[ -n "${seen_port_job[$port]:-}" ]]; then
                echo "lint-ci-ports: TEST_BASE_PORT=$port is used by both '${seen_port_job[$port]}' (${seen_port_file[$port]}) and '$job' ($f) -- runtime-bearing jobs on the shared runner must have DISTINCT bands" >&2
                status=1
            else
                seen_port_job[$port]="$job"
                seen_port_file[$port]="$f"
            fi
        fi

        # A job that starts the runtime suite -- directly or through the
        # coverage wrapper -- is runtime-bearing and needs a band. Only inside
        # `jobs:`: `on.paths` lists test_runtime.py as a trigger filter, which
        # runs nothing.
        if [[ "$in_jobs" -eq 1 && -n "$current_job" ]]; then
            if [[ "$line" == *test_runtime.py* || "$line" == *coverage.sh* ]]; then
                # py_compile checks syntax and comments mention the path;
                # neither starts a suite or binds a port.
                if [[ "$line" != *py_compile* && "$line" != *"#"* ]]; then
                    job_starts_suite[$key]="${line#"${line%%[![:space:]]*}"}"
                    # coverage.sh reads TEST_BASE_PORT from the environment and
                    # passes --port itself, so the workflow line correctly has
                    # no --port of its own. Requiring one here would be a lint
                    # demanding a bug.
                    [[ "$line" == *coverage.sh* ]] && job_passes_port[$key]=1
                fi
            fi
            if [[ "$line" == *--port*TEST_BASE_PORT* ]]; then
                job_passes_port[$key]=1
            fi
        fi
    done < "$f"
done

# --- Check 3: a runtime-bearing job must declare a band AND pass it. ---
for key in "${!job_starts_suite[@]}"; do
    if [[ -z "${job_declares_band[$key]:-}" ]]; then
        echo "lint-ci-ports: ${key%%:*}: job '${key#*:}' starts the runtime suite but declares no TEST_BASE_PORT -- it would silently take test_runtime.py's default --port 18880 and collide with the build-test runtime job: ${job_starts_suite[$key]}" >&2
        status=1
    elif [[ -z "${job_passes_port[$key]:-}" ]]; then
        echo "lint-ci-ports: ${key%%:*}: job '${key#*:}' declares TEST_BASE_PORT=${job_declares_band[$key]} but never passes it as --port -- it sweeps one band and runs on another, which is worse than not banding at all: ${job_starts_suite[$key]}" >&2
        status=1
    fi
done

if [ "$status" -eq 0 ]; then
    echo "lint-ci-ports: OK (${#seen_port_job[@]} distinct port bands, ${#job_starts_suite[@]} runtime-bearing jobs, ${#files[@]} workflow files scanned)"
fi

exit "$status"
