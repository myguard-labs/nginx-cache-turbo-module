#!/usr/bin/env bash
#
# Enforce the per-job port-band split (AUD-CIPORT1).
#
# build-test.yml, asan.yml and ci-deep.yml all pin the SAME self-hosted
# runner (builder) and have DISJOINT per-workflow concurrency groups, so
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
    # Do not feed discovery through process substitution: mapfile reports its
    # own status, so a find that wrote a plausible prefix and then failed used
    # to turn that prefix into a clean, partial inventory. Keep the transport
    # NUL-delimited so a valid workflow pathname cannot split into two rows.
    inventory_dir="$(mktemp -d)" || {
        echo "lint-ci-ports: cannot create workflow inventory directory" >&2
        exit 2
    }
    trap 'rm -rf "$inventory_dir"' EXIT
    inventory_raw="$inventory_dir/workflows.raw"
    inventory_sorted="$inventory_dir/workflows.sorted"
    if ! find .github/workflows -maxdepth 1 -type f \
        \( -name '*.yml' -o -name '*.yaml' \) -print0 >"$inventory_raw"; then
        echo "lint-ci-ports: workflow inventory failed -- refusing partial scan" >&2
        exit 2
    fi
    if ! LC_ALL=C sort -z "$inventory_raw" >"$inventory_sorted"; then
        echo "lint-ci-ports: workflow inventory sort failed -- refusing partial scan" >&2
        exit 2
    fi
    mapfile -t -d '' files <"$inventory_sorted"
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

# The CI band range, DERIVED from the bands the workflows actually declare
# rather than hardcoded -- a hand-typed range is the AUD-CIPORT4 defect one
# level up. Used only by check 3's fourth signal, to decide whether a bare
# port literal is squatting on CI territory or is some unrelated service.
# Falls back to a no-op empty range if nothing is declared; the empty-scan
# guard below is what refuses to report OK in that case.
BAND_MIN=""
BAND_MAX=""

# --- Check 1: every `seq` in a sweep step must derive from $TEST_BASE_PORT,
# never a bare numeric literal, and must stop exactly at the band edge. ---
for f in "${files[@]}"; do
    [ -f "$f" ] || continue
    # Buffer the file ONCE instead of re-reading it with sed per hit. The sed
    # form was flagged SC2094 (read-and-write the same file in one pipeline);
    # that particular instance was a false positive -- the loop is fed by a
    # process substitution, not by "$f" -- but the Validation gate runs the
    # linter at DEFAULT severity, where an info finding is fatal, so it cannot
    # simply be left. Buffering is also strictly cheaper: one read per file
    # instead of one sed per sweep hit.
    mapfile -t _flines < "$f"
    while IFS=: read -r lineno line; do
        # Only port sweeps. `for i in $(seq 1 "$n")` is a loop counter and has
        # nothing to do with ports; flagging it would train people to ignore
        # this lint, which is how a gate dies.
        # mapfile is 0-indexed, grep -n is 1-indexed: line N is _flines[N-1].
        sweep_body="$(printf '%s\n' "${_flines[@]:lineno-1:4}")"
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
declare -A job_starts_suite      # "file:job" -> the invoking line, trimmed (best-effort, for messages only)
declare -A job_passes_port       # "file:job" -> 1
declare -A job_has_sweep         # "file:job" -> 1 -- PROPERTY signal, not name-based (AUD-CIPORT3)
declare -A job_binds_literal     # "file:job" -> the offending line -- 4th signal, see check 3
interval_starts=()
interval_ends=()
interval_labels=()

for f in "${files[@]}"; do
    [ -f "$f" ] || continue
    current_job=""
    in_jobs=0
    lineno=0
    sweep_window=0
    sweep_key=""
    while IFS= read -r line; do
        lineno=$((lineno + 1))
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

        # PROPERTY signal, not a name allowlist (AUD-CIPORT3): a job that
        # sweeps stale listeners off its own band (the same `$(seq
        # ...TEST_BASE_PORT...` + nearby `fuser` shape check 1 already
        # verifies) is, by its own structure, asserting it is about to bind
        # ports in that band -- regardless of what script it later invokes to
        # do the actual binding. This is what lets check 3 (below) catch a
        # NEW runtime entry point without anyone having to name it here.
        # Implemented as a forward WINDOW carried on the stream rather than a
        # sed re-read of "$f": re-opening the file that this `while` loop is
        # already reading is SC2094, which the Validation gate treats as fatal
        # (it runs shellcheck at default severity, where info findings fail).
        # The window also keeps the scan single-pass.
        if [[ "$sweep_window" -gt 0 ]]; then
            sweep_window=$((sweep_window - 1))
            if [[ "$line" == *fuser* && -n "$sweep_key" ]]; then
                job_has_sweep[$sweep_key]=1
                sweep_window=0
            fi
        fi
        if [[ "$in_jobs" -eq 1 && -n "$current_job" && "$line" == *"$SEQ_LITERAL"* ]]; then
            # Look at the next 3 lines for the `fuser` that makes this a real
            # sweep; the seq literal alone is not enough.
            sweep_window=3
            sweep_key="$key"
        fi

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

        # A job that starts the runtime suite -- directly, through the coverage
        # wrapper, or as the Test::Nginx `prove` suite -- is runtime-bearing and
        # needs a band. Only inside `jobs:`: `on.paths` lists test_runtime.py as
        # a trigger filter, which runs nothing.
        #
        # `prove` counts for exactly the same reason test_runtime.py does: it
        # starts a real nginx that binds TEST_NGINX_PORT (and the origin port
        # beside it). It was invisible to this lint until ci/t/ existed, which
        # is the hole check 3's own comment predicted -- a new port-binding job
        # that neither sweeps nor bands, silently landing on another job's band.
        if [[ "$in_jobs" -eq 1 && -n "$current_job" ]]; then
            # Match against a COMMENT-STRIPPED copy, not the raw line. Two
            # failures share that root cause, and the second one fails OPEN:
            #
            #   1. skipping any line containing '#' drops a real invocation
            #      that carries a trailing comment (`prove -j4 -r ci/t/  # par`),
            #      so the job goes invisible to check 3;
            #   2. matching TEST_NGINX_RANDOMIZE / TEST_NGINX_PORT on the raw
            #      line lets PROSE satisfy the requirement. Verified: deleting
            #      the prove job's real `TEST_NGINX_RANDOMIZE: "1"` still left
            #      this lint reporting OK, because a band comment above it
            #      mentions the variable by name.
            #
            # Strip from the first '#' to end-of-line. YAML has no escape that
            # makes '#' start a comment mid-token here, and a '#' inside a
            # quoted scalar would only ever cost us a match (fail closed).
            code="${line%%#*}"

            # BEST-EFFORT ONLY, for error-message context -- NOT what gates
            # check 3 (AUD-CIPORT3). This used to be the check's sole
            # detector, keyed on exact script spelling: a runtime job through
            # any other entry point matched nothing here and sailed past
            # check 3 invisibly. Check 3 below now gates on the PROPERTY
            # signals (`job_declares_band`, `job_has_sweep`, `job_passes_port`)
            # recorded above and in the sweep scan, which do not name a
            # script and so cannot go stale the way this list did. This match
            # only supplies a human-readable "what line looked like the
            # runtime invocation" for the diagnostic text; a job that starts
            # a suite through some fifth script style still gets caught by
            # check 3 even though it matches nothing here.
            if [[ "$code" == *test_runtime.py* || "$code" == *coverage.sh* \
                  || "$code" == *testkit-run.sh* \
                  || "$code" =~ (^|[[:space:]])prove([[:space:]]|$) ]]; then
                # py_compile checks syntax; it starts no suite and binds no port.
                if [[ "$code" != *py_compile* ]]; then
                    job_starts_suite[$key]="${code#"${code%%[![:space:]]*}"}"
                fi
            fi
            if [[ "$code" == *--port*TEST_BASE_PORT* ]]; then
                job_passes_port[$key]=1
            fi
            # FOURTH signal, and the only one that needs NO mention of
            # TEST_BASE_PORT at all. The other three each require the job to
            # already be doing some port bookkeeping, so a brand-new runtime
            # entry point that does none -- no band, no sweep, just a bare
            # `--port 18880` or `TEST_NGINX_PORT: 18880` -- stayed invisible to
            # every one of them. That is precisely AUD-CIPORT3's "entry point
            # five" case, so gating on a port LITERAL in the CI band
            # range is what actually closes it. A literal outside that range is
            # somebody's unrelated service and is not our business.
            if [[ "$code" =~ (--port|TEST_NGINX_PORT|PORT=)[[:space:]:=]*\"?(1[89][0-9][0-9][0-9])\"? ]]; then
                # Recorded unconditionally here and range-filtered at check 3.
                # BAND_MIN/BAND_MAX are derived from the FULL declared set, so
                # they are not known until every file has been scanned; testing
                # them at this point would compare against a partial range.
                job_binds_literal[$key]="${BASH_REMATCH[2]}|${code#"${code%%[![:space:]]*}"}"
            fi
            # Test::Nginx takes its port from the environment, not argv, so the
            # band is passed as TEST_NGINX_PORT: <band> rather than --port.
            if [[ "$code" == *TEST_NGINX_PORT*TEST_BASE_PORT* ]]; then
                job_passes_port[$key]=1
            fi
            # TEST_NGINX_RANDOMIZE is the ONE case where a runtime-bearing job
            # legitimately does not run on its declared band. It is what makes
            # `prove -jN` safe: the scaffold picks a random port PER PARALLEL
            # JOB, so pinning TEST_NGINX_PORT would re-share the
            # resource randomization just separated and reintroduce the
            # collision. The band is still declared and still swept, which is
            # what reserves this job's territory on the shared runner.
            #
            # Do NOT restate this as "the scaffold binds only ports it has
            # proved free". It does not: gen_rand_port probes 127.0.0.1 while
            # the generated server binds 0.0.0.0, so a port can pass the probe
            # and still fail the bind (run 32075040354). The suite closes that
            # gap itself in ci/t/lib/CacheTurbo.pm -- wildcard probe plus
            # re-draw -- which is what this exemption now rests on.
            if [[ "$code" == *TEST_NGINX_RANDOMIZE* ]]; then
                job_passes_port[$key]=1
            fi
        fi
    done < "$f"
done

# --- Check 3: a job that binds ports must declare a band AND pass it. ---
#
# AUD-CIPORT3 durable fix: the job set this check gates is the UNION of every
# PROPERTY signal recorded above -- job_declares_band (declares
# TEST_BASE_PORT), job_has_sweep (clears a band of stale listeners before
# running), job_passes_port (an explicit --port/TEST_NGINX_PORT/
# TEST_NGINX_RANDOMIZE marker referencing TEST_BASE_PORT). None of the three
# names a script. A job showing ANY ONE of these signals is asserting, by its
# own structure, that it is runtime-bearing -- the check's job is to catch it
# missing one of the other two, i.e. the "declares TEST_BASE_PORT xor binds a
# port" defect the packet described, not to first recognise the script that
# does the binding.
#
# The one legitimate case where job_declares_band + job_has_sweep is present
# without an explicit port marker is a script that reads TEST_BASE_PORT from
# its own environment and defaults its own --port to it (coverage.sh,
# testkit-run.sh document this in their own headers) -- for that job,
# declaring the band via env IS passing it, by construction: it swept that
# band for itself and every runtime script in this repo enforces "PORT must be
# numeric" before doing anything with it, so a job that both declares a band
# AND sweeps it is never a job that quietly runs on some OTHER port. A job
# that declares a band but does NOT sweep it, and has no explicit marker
# either, gets no free pass -- that is exactly the "band declared, never
# passed" defect check 3 exists to catch.
# Both ends come from the declared set, widened by one band so the top band's
# own ports count as in-range.
for _p in "${job_declares_band[@]}"; do
    [[ -z "$BAND_MIN" || "$_p" -lt "$BAND_MIN" ]] && BAND_MIN="$_p"
    [[ -z "$BAND_MAX" || "$_p" -gt "$BAND_MAX" ]] && BAND_MAX="$_p"
done
[[ -n "$BAND_MAX" ]] && BAND_MAX=$((BAND_MAX + BAND_WIDTH - 1))

declare -A all_key_seen
for key in "${!job_declares_band[@]}" "${!job_has_sweep[@]}" "${!job_passes_port[@]}" "${!job_binds_literal[@]}"; do
    [ -n "$key" ] && all_key_seen["$key"]=1
done
all_keys=("${!all_key_seen[@]}")

for key in "${all_keys[@]}"; do
    label="${job_starts_suite[$key]:-<no matching invocation line found -- see job_declares_band/job_has_sweep/job_passes_port>}"
    lit_entry="${job_binds_literal[$key]:-}"
    lit_port="${lit_entry%%|*}"
    lit_line="${lit_entry#*|}"
    if [[ -n "$lit_entry" && -n "$BAND_MIN" \
          && "$lit_port" -ge "$BAND_MIN" && "$lit_port" -le "$BAND_MAX" \
          && -z "${job_declares_band[$key]:-}" ]]; then
        echo "lint-ci-ports: ${key%%:*}: job '${key#*:}' hardcodes a port in the CI band range ($BAND_MIN-$BAND_MAX) instead of declaring TEST_BASE_PORT -- a literal cannot be checked for band overlap and collides the moment another job is assigned that band: $lit_line" >&2
        status=1
    elif [[ -z "${job_declares_band[$key]:-}" ]]; then
        echo "lint-ci-ports: ${key%%:*}: job '${key#*:}' binds a port (sweeps and/or passes --port/TEST_NGINX_PORT/TEST_NGINX_RANDOMIZE) but declares no TEST_BASE_PORT -- it would silently take a default port and collide with a banded runtime job: $label" >&2
        status=1
    elif [[ -z "${job_passes_port[$key]:-}" && -z "${job_has_sweep[$key]:-}" ]]; then
        echo "lint-ci-ports: ${key%%:*}: job '${key#*:}' declares TEST_BASE_PORT=${job_declares_band[$key]} but never sweeps it and never passes it as --port/TEST_NGINX_PORT/TEST_NGINX_RANDOMIZE -- it declares a band it neither clears nor runs on, which is worse than not banding at all: $label" >&2
        status=1
    fi
done

# --- Check 4: no CI band may overlap a port a test file pins as a LITERAL. ---
#
# ci/t/core/breaker-retry-count.t pins fixed upstream ports (dead peers that
# must stay unlistened, plus a specific alive peer) because ct_origin_port()
# cannot express that for a multi-peer upstream group. Those ports are real
# reservations, but they lived ONLY in a comment inside the .t file, so
# nothing stopped a new CI lane being handed a band on top of them -- which
# is exactly what happened: band 19392-19455 was assigned while
# 19420-19490 was already claimed, and it stayed invisible only because
# build-test.yml's port fence was a stale hand-typed tuple that omitted the
# new band. Deriving that fence correctly (AUD-CIPORT4) turned a latent
# clash into 41 dead preset files in one run.
#
# Reading the literals out of the test files is what makes the reservation
# checkable instead of merely documented. A test file that stops pinning
# ports simply contributes nothing here.
pinned_ports=()
while IFS= read -r pinned; do
    [ -n "$pinned" ] && pinned_ports+=("$pinned")
done < <(grep -rhoE '^our \$[A-Za-z0-9_]+[[:space:]]*=[[:space:]]*[0-9]{4,5};' ci/t 2>/dev/null \
         | grep -oE '[0-9]{4,5}' | sort -un)

if [ "${#pinned_ports[@]}" -gt 0 ]; then
    for i in "${!interval_starts[@]}"; do
        b_start="${interval_starts[$i]}"
        b_end="${interval_ends[$i]}"
        for pinned in "${pinned_ports[@]}"; do
            if [[ "$pinned" -ge "$b_start" && "$pinned" -le "$b_end" ]]; then
                echo "lint-ci-ports: CI band [$b_start-$b_end] (${interval_labels[$i]}) contains port $pinned, which a test file under ci/t pins as a fixed literal -- the port fence will bind it and the test's nginx will fail with 'Address already in use'" >&2
                status=1
            fi
        done
    done
fi

if [ "$status" -eq 0 ]; then
    echo "lint-ci-ports: OK (${#interval_starts[@]} distinct port bands, ${#all_keys[@]} runtime-bearing jobs, ${#files[@]} workflow files scanned, ${#pinned_ports[@]} test-pinned port(s) clear of every band)"
fi

exit "$status"
