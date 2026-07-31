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

# The literal text this lint searches for. Kept in a variable so the two match
# sites cannot drift apart, and so neither has to single-quote "$(seq " inline --
# which SC2016 reads as an unexpanded expression, and CI's validation step runs
# this file through shellcheck at DEFAULT severity, where info-level is fatal.
# (The pre-commit hook gates at -S warning, so that divergence hides locally.)
# shellcheck disable=SC2016
SEQ_LITERAL='$(seq '

# Single source of truth for the band width (AUD-CIPORT2). Both the overlap
# check (2) and the sweep-width check (1) measure against this constant so a
# sweep offset and an interval width cannot drift apart the way they did
# before this fix: check 1 verified only that a sweep MENTIONED
# $TEST_BASE_PORT, not that it stopped at the band edge, so a sweep of
# $((TEST_BASE_PORT + 200)) passed clean while reaching three neighbouring
# bands.
BAND_WIDTH=64

# --- Check 1: every `seq` in a sweep step must derive from $TEST_BASE_PORT,
# never a bare numeric literal, and must stop exactly at the band edge. ---
for f in "${files[@]}"; do
    [ -f "$f" ] || continue
    while IFS=: read -r lineno line; do
        # Only port sweeps. `for i in $(seq 1 "$n")` is a loop counter and has
        # nothing to do with ports; flagging it would train people to ignore
        # this lint, which is how a gate dies.
        sweep_body="$(sed -n "${lineno},$((lineno + 3))p" "$f")"
        [[ "$sweep_body" == *fuser* ]] || continue
        if [[ "$line" == *"$SEQ_LITERAL"* ]]; then
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
            elif [[ "$line" =~ TEST_BASE_PORT[[:space:]]*\+[[:space:]]*([0-9]+) ]]; then
                # Mentioning $TEST_BASE_PORT is not the same as staying inside
                # ITS band: $((TEST_BASE_PORT + 200)) derives from the right
                # variable and still sweeps three neighbouring bands off the
                # end of this job's own (AUD-CIPORT2).
                offset="${BASH_REMATCH[1]}"
                if [[ "$offset" -ne $((BAND_WIDTH - 1)) ]]; then
                    echo "lint-ci-ports: $f:$lineno: sweep reaches \$TEST_BASE_PORT+$offset, past this job's ${BAND_WIDTH}-wide band (expected +$((BAND_WIDTH - 1))): $trimmed" >&2
                    status=1
                fi
            else
                # $TEST_BASE_PORT is present but not as "+ N" -- e.g. summed
                # via an intermediate variable this lint cannot resolve. Can't
                # prove the band width is respected, so don't report OK on it.
                echo "lint-ci-ports: $f:$lineno: sweep upper bound is not a recognizable \$TEST_BASE_PORT + N offset: $trimmed" >&2
                status=1
            fi
        fi
    done < <(grep -n -F "$SEQ_LITERAL" "$f")
done

# --- Check 2: every job's [base, base+BAND_WIDTH-1] port INTERVAL must be
# disjoint from every other such job's interval, across all scanned files. ---
# Comparing bases for equality alone is not enough: bases 18880 and 18900 are
# distinct values, so an equality check reports OK, but their 64-wide
# intervals still share 44 ports and collide exactly as AUD-CIPORT1 did
# (AUD-CIPORT2). "job:port:file" rows, in file order. A job-level `env:`
# block is indented 4 spaces in every workflow here (2 for the job key + 2
# for its children); TEST_BASE_PORT sits one level deeper (6 spaces) as a
# direct child of that env: block, not the job-env: block used by e.g.
# LEGACY_NGINX_VERSION's sibling lines -- so match on the key name, not on
# indentation depth, to stay robust to reindentation.
declare -A job_declares_band     # "file:job" -> port
declare -A job_starts_suite      # "file:job" -> the invoking line, trimmed
declare -A job_passes_port       # "file:job" -> 1
interval_starts=()
interval_ends=()
interval_labels=()

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
            start="$port"
            end="$((port + BAND_WIDTH - 1))"
            for i in "${!interval_starts[@]}"; do
                other_start="${interval_starts[$i]}"
                other_end="${interval_ends[$i]}"
                if [[ "$start" -le "$other_end" && "$other_start" -le "$end" ]]; then
                    echo "lint-ci-ports: TEST_BASE_PORT=$port ([$start-$end]) for '$job' ($f) overlaps ${interval_labels[$i]} -- runtime-bearing jobs on the shared runner must have DISJOINT bands" >&2
                    status=1
                fi
            done
            interval_starts+=("$start")
            interval_ends+=("$end")
            interval_labels+=("'$job' ($f, [$start-$end])")
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
    echo "lint-ci-ports: OK (${#interval_starts[@]} distinct port bands, ${#job_starts_suite[@]} runtime-bearing jobs, ${#files[@]} workflow files scanned)"
fi

exit "$status"
