#!/usr/bin/env bash
# ci/linter/selftest.sh -- negative controls for the lint gate itself.
#
# The gate is the thing that decides whether everything else is allowed to
# land, so "the gate ran and said clean" has to be distinguishable from "the
# gate ran nothing and said clean". That distinction is not observable from a
# green lint job: a selector typo used to make run-all.sh print
# "== all linters clean ==" and exit 0 having executed zero checkers.
#
# Every case here asserts the FAILING direction -- a check that only ever
# asserts the passing direction cannot detect its own disarming.
#
# Usage:  ci/linter/selftest.sh
# Exit:   0 all controls held, 1 one or more did not.
#
# Runs in about seven seconds. The budget is stated as a ceiling
# on the whole suite, not per case: this is a commit-hook and CI gate, where a
# couple of seconds is immaterial next to the cost of a silent-green linter
# shipping. Controls are added when a class of malformed input is found
# unmodelled; the budget line moves with them rather than the suite being
# trimmed to fit it. The wrapper controls stop before external linters, and the
# three module-specific checker blocks run against generated fixture trees, so
# the suite needs no optional linter installation and stays inside the budget.
#
# Extend: add a case() line. Keep each case asserting a specific exit status,
# and prefer a case where the OLD, broken behaviour would have passed.

set -uo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT" || exit 2

rc=0

# case <expected-exit> <description> -- command...
case_() {
    local want="$1" desc="$2"; shift 2
    local out got
    out="$("$@" 2>&1)"; got=$?
    if [ "$got" -eq "$want" ]; then
        echo "ok   $desc (exit $got)"
    else
        echo "FAIL $desc: expected exit $want, got $got" >&2
        # Parameter expansion rather than sed (SC2001): CI validates this
        # file at the default severity, where style findings are fatal.
        printf '%s\n' "       | ${out//$'\n'/$'\n'       | }" >&2
        rc=1
    fi
}

# finding_case <description> <message-ere> -- command...
# Assert both the finding exit class and its diagnostic. Exit 1 alone is also
# how an awk crash or an unrelated invariant violation presents.
finding_case_() {
    local desc="$1" want_re="$2" out got
    shift 2
    out="$("$@" 2>&1)"; got=$?
    if [ "$got" -eq 1 ] && grep -qE -- "$want_re" <<< "$out"; then
        echo "ok   $desc (intended finding, exit $got)"
    else
        echo "FAIL $desc: expected exit 1 matching /$want_re/, got $got" >&2
        printf '%s\n' "       | ${out//$'\n'/$'\n'       | }" >&2
        rc=1
    fi
}

# The regression itself: an unmatched selector must be "could not run" (2),
# not "clean" (0).
case_ 2 "unknown LINT_ONLY exits 2" \
    env LINT_ONLY=nosuchchecker ci/linter/run-all.sh

# ...including when only SOME of the listed names are bogus in a way that
# leaves nothing selected.
case_ 2 "LINT_ONLY of only-bogus names exits 2" \
    env LINT_ONLY="c-lang shellscript" ci/linter/run-all.sh

# The error names the offending value and the known checkers, or nobody can
# act on it.
# Captured first, not piped into grep: `set -o pipefail` would otherwise hand
# the pipeline run-all.sh's exit 2 and the assertion would read as failed no
# matter what the message said.
msg="$(env LINT_ONLY=nosuchchecker ci/linter/run-all.sh 2>&1)"
if printf '%s\n' "$msg" | grep -q 'matched no checker; known: .*sh'; then
    echo "ok   unmatched-selector message names value and known checkers"
else
    echo "FAIL unmatched-selector message is not actionable" >&2
    rc=1
fi

# Positive control: the selector still selects. --list is used rather than a
# real run so this stays independent of which linters are installed.
case_ 0 "--list works" ci/linter/run-all.sh --list

# ----------------------------------------------------------------------------
# workflow_policy.py -- the red path of each policy check.
#
# Every fixture below encodes a bypass that VALID YAML used to walk straight
# through while the checks parsed workflows by regex. Each was verified in both
# directions when it was written: red on the current parser, green on the
# regex one. They are committed rather than planted in .github/workflows/ at
# runtime so no cleanup failure can leave a probe workflow in the live tree.
#
# Extend: add a fixture directory with its own .github/workflows/ and a README
# stating which bypass it encodes, then a policy_ line here.

policy_() {  # policy_ <expected-exit> <fixture> <subcommand>
    local want="$1" fixture="$2" cmd="$3"
    case_ "$want" "policy $cmd: $fixture" \
        env "WORKFLOW_POLICY_ROOT=ci/linter/fixtures/policy/$fixture" \
        python3 ci/linter/workflow_policy.py "$cmd"
}

# policy_msg_ <fixture> <subcommand> <grep-ere> -- red, and red for the STATED
# reason.
#
# Exit status alone cannot tell a finding from a crash: an uncaught
# AttributeError also exits 1, so a fixture asserting only `1` stays green when
# the branch it covers is replaced by a traceback. That is not hypothetical --
# deleting the `isinstance(spec, dict)` guard in check_secrets() made
# secrets-untyped die on `None.get()` and every exit-1 control still passed.
# Use this wherever the guard under test is what stops a crash.
#
# Captured first, not piped: pipefail would hand the pipeline the checker's
# exit 1 and the assertion would read as failed whatever the message said.
policy_msg_() {
    local fixture="$1" cmd="$2" want_re="$3" out got
    out="$(env "WORKFLOW_POLICY_ROOT=ci/linter/fixtures/policy/$fixture" \
        python3 ci/linter/workflow_policy.py "$cmd" 2>&1)"; got=$?
    if [ "$got" -eq 1 ] && printf '%s\n' "$out" | grep -qE "$want_re"; then
        echo "ok   policy $cmd: $fixture (finding, not a crash)"
    else
        echo "FAIL policy $cmd: $fixture: expected exit 1 matching /$want_re/, got $got" >&2
        printf '%s\n' "$out" | sed 's/^/       | /' >&2
        rc=1
    fi
}

# THE control that makes the rest mean anything: a fixture tree that is simply
# a valid workflow must be GREEN on all three. Without it, a red on any bypass
# fixture could be the fixture shape rather than the bypass.
policy_ 0 clean runners
policy_ 0 clean ports
policy_ 0 clean docs
# Deliberately NO `policy_ 0 clean cadence`: the clean fixture has no
# workflow_call member, so that line would assert green over an empty set --
# vacuous, and indistinguishable from the check being broken. The green control
# for cadence is member-with-push-ok below, which has a member to clear.

# A `.yaml` workflow was invisible to every check: unchecked runner, unchecked
# ports, undocumented gate.
policy_ 1 bypass-yaml-extension runners
policy_ 1 bypass-yaml-extension docs

# `on: [pull_request]` / `on: pull_request` are the same trigger as the mapping
# form; both used to skip the runner-trust check, as did an inline
# pull_request_target.
policy_ 1 bypass-inline-events runners

# `runtime:  # comment` used to yield zero jobs, so a runtime-bearing job with
# no port band reported "no runtime-bearing jobs" and exit 0.
policy_ 1 bypass-commented-job-key ports

# A band verifier placed BELOW the first binder. Declaration, pass-through and
# uniqueness all hold, so the presence checks stay green -- this repo's own
# build-test.yml sat in exactly this shape until 2026-08-02.
policy_ 1 verify-after-bind ports

# A job whose only binder is `prove` (not ci/tools/test_runtime.py) used to be
# exempt from the "declare TEST_BASE_PORT" requirement, even though `prove` is
# already a BINDERS member and the ordering check already treats it as one.
# Found downstream as a failed negative control: deleting a prove-only job's
# band left this check green.
policy_ 1 prove-only-binder-exempt ports

# The other half of the same defect: a prove job may declare a unique band,
# satisfy every check above, and still bind 1984, because Test::Nginx reads
# TEST_NGINX_PORT and has never heard of TEST_BASE_PORT. The driver's
# pass-through guard is keyed on starts_runtime, so it never covered `prove`.
policy_ 1 prove-band-not-passed-through ports

# A workflow_call member carrying its own `push:` runs twice per change and BOTH
# runs are green, so nothing else in the toolchain notices. Every member here is
# correct today, but only a per-file comment says so, and a comment does not
# survive the next workflow copied in. These run as a PAIR: the -ok fixture is
# the same file with `schedule:` (the intended shape), and without it the red
# above is equally consistent with "any second trigger is flagged".
policy_ 1 member-with-push cadence
policy_ 0 member-with-push-ok cadence

# The three ways a secret goes missing between a caller and a member, none of
# which fails anything at the time it is introduced. `inherit` is green and
# merely over-broad; an untyped declaration starts the call with an empty
# string; an undeclared secret is dropped at the boundary while both halves
# read as correct in isolation. These run as a GROUP with secrets-typed-ok:
# this repo declares no secrets, so without a green fixture that DOES, the
# three reds would be equally consistent with "any mention of a secret is
# flagged" -- and the live check would be asserting green over an empty set.
policy_ 1 secrets-inherit secrets
# The same defect one repository over. The caller loop filtered to local
# members BEFORE judging `inherit`, so a call to
# `owner/repo/.github/workflows/x.yml@ref` was skipped -- the case where
# `inherit` is WORST, since the secret set crosses a repository boundary to a
# moving ref. Distinct from secrets-inherit: reordering that filter back below
# the inherit branch leaves the local fixture red and only this one green.
policy_ 1 secrets-inherit-external secrets
# The third case that filter used to swallow: an external call whose `secrets:`
# is neither a mapping nor `inherit`. `inherit` was hoisted above the filter,
# but the SHAPE check stayed below it, so `secrets: false` on an external member
# reported clean over a caller GitHub refuses to start. Exit 2, not 1 -- an
# uninterpretable `secrets:` means the check did not run over that call, so
# policy_msg_ (which hardcodes exit 1) cannot assert this one. Moving the shape
# check back below `if not local` turns this fixture green while every other
# secrets fixture stays exactly as it is.
policy_ 2 secrets-malformed-external secrets
# Message-asserted: a null spec is exactly the input that crashes `.get()` if
# the isinstance guard is removed, and a traceback also exits 1.
policy_msg_ secrets-untyped secrets 'declares secret .* untyped'
# secrets-optional is NOT redundant with secrets-untyped. Disarming the
# `required is not True` test left secrets-untyped red anyway -- it trips the
# missing-key branch -- so the value test had no control of its own. A mutant
# that survives is a branch nothing is gating.
policy_ 1 secrets-optional secrets
# ...and secrets-no-required-key is not redundant with EITHER. `NAME:` with
# nothing under it parses to null, and null `is not True`, so the value branch
# covers secrets-untyped even when the missing-key branch is deleted. Only a
# spec that is a real mapping without the key separates the two.
policy_ 1 secrets-no-required-key secrets
policy_ 1 secrets-undeclared secrets
# The mirror of secrets-undeclared, and the direction the check missed when
# first written: member requires it, caller wires nothing.
policy_ 1 secrets-required-not-wired secrets
policy_ 0 secrets-typed-ok secrets

# A mistyped pool label in a schedule-only workflow. The trust half of the
# runners check does not apply to a workflow no fork can reach, and skipping it
# used to skip the LABEL membership test with it -- while actionlint, the only
# other thing that reads runner labels, stays silent on the `fromJSON(...)`
# selectors this repo uses everywhere. Six selectors in bump.yml and ci-deep.yml
# had no label checking at all. These two run as a PAIR: the -ok fixture is the
# same file spelled correctly, and without it the red below is equally
# consistent with "every non-PR-reachable workflow is now flagged".
policy_ 1 schedule-only-runner-labels runners
policy_ 0 schedule-only-runner-labels-ok runners

# WIRING CONTROLS. These assert that a checker is reachable at all, which is a
# weaker claim than "it goes red on a defect" -- the red-direction probes need
# real tools and live in each checker's header instead, so this file keeps its
# no-linter-required property. They exist because both failures below were
# silent: a checker nobody dispatches and a hook nobody runs look exactly like a
# clean tree.
#
# core.hooksPath REPLACES .git/hooks/, so `pre-commit install` writes a file git
# never reads. Measured 2026-08-02: trailing whitespace and a missing final
# newline committed clean past the hooks whose only job is those two things.
# .githooks/pre-commit therefore has to invoke pre-commit itself.
case_ 0 "the commit hook invokes the pre-commit-config hooks" \
    grep -q '^ *pre-commit run' .githooks/pre-commit

# run-all.sh dispatches by glob, so a checker that is not executable, or is
# named outside the lint-*.sh pattern, is silently not run.
# Every glob-discovered checker is named in lint.yml's LINT_ONLY.
#
# run-all.sh picks checkers up by glob, but CI narrows the run to an explicit
# allowlist, and nothing connected the two: a checker added to ci/linter/ ran
# locally and in the pre-commit hook while being silently absent from every PR.
# That is not a hypothetical -- ci-cadence shipped in 2026-08-06 and had never
# run remotely when this control was written. A gate that runs everywhere except
# the merge path is the one place it is load-bearing.
missing=""
only="$(sed -n 's/^ *LINT_ONLY: *//p' .github/workflows/lint.yml)"
for s in ci/linter/lint-*.sh; do
    n="${s#ci/linter/lint-}"; n="${n%.sh}"
    # "c" is deliberately excluded in CI (see lint.yml's header): the src/
    # scanners run in security-scanners.yml instead.
    [ "$n" = "c" ] && continue
    # In-process membership. `printf | grep -qx` can invert its verdict when
    # grep -q exits early and printf's write hits EPIPE -- same defect that
    # took the astgrep guard red on CI only; see lint-astgrep.sh.
    found=""
    for k in $only; do
        [ "$k" = "$n" ] && { found=1; break; }
    done
    [ -n "$found" ] || missing="$missing $n"
done
if [ -z "$missing" ]; then
    echo "ok   every checker is named in lint.yml LINT_ONLY"
else
    echo "FAIL checkers absent from lint.yml LINT_ONLY:$missing" >&2
    echo "       | they run locally and in the hook, but never on a PR" >&2
    rc=1
fi

case_ 0 "lint-spelling is dispatched by run-all.sh" \
    bash -c 'ci/linter/run-all.sh --list | grep -q lint-spelling.sh'

# The ast-grep gate is defined TWICE -- as PROMOTED in ci/linter/lint-astgrep.sh
# and as the --error= flags of the ast-grep hook in .pre-commit-config.yaml --
# because the two run by different mechanisms. Two lists that must agree and are
# only kept in step by a comment will drift, and the drift is invisible: the hook
# passes while CI fails (or worse, the reverse), and neither output mentions the
# other list. Compare them as sorted sets.
pc="$(sed -n '/id: ast-grep/,/pass_filenames/p' .pre-commit-config.yaml \
      | grep -oE '\-\-error=[a-z0-9-]+' | sed 's/--error=//' | sort -u)"
ck="$(sed -n '/^PROMOTED=(/,/^)/p' ci/linter/lint-astgrep.sh \
      | sed -nE 's/^[[:space:]]+([a-z0-9-]+)[[:space:]]*$/\1/p' | sort -u)"
if [ -z "$pc" ] || [ -z "$ck" ]; then
    # An empty side means a parse that stopped matching, not agreement. Two
    # empty strings compare equal, so without this the control passes vacuously
    # the moment either file is reformatted.
    echo "FAIL ast-grep promoted-list control parsed nothing (pre-commit:$(printf '%s' "$pc" | wc -l), checker:$(printf '%s' "$ck" | wc -l))" >&2
    rc=1
elif [ "$pc" = "$ck" ]; then
    echo "ok   ast-grep promoted set matches in lint-astgrep.sh and .pre-commit-config.yaml"
else
    echo "FAIL ast-grep promoted set differs between the hook and the checker" >&2
    diff <(printf '%s\n' "$pc") <(printf '%s\n' "$ck") | sed 's/^/       | /' >&2
    rc=1
fi

# Every PROMOTED name must be accepted by the guard against the REAL ruleset.
# This is the control for the CI-only inversion fixed 2026-08-14: the guard was
# built on `printf "%s\n" "${KNOWN[@]}" | grep -qx`, and when grep -q exited on
# its first match printf could take an EPIPE, whose non-zero status the `||`
# read as "this rule does not exist". c-format-string was condemned on the
# runner while its rule file sat in the tree, correctly tagged.
#
# Asserting "the checker exits 0 today" would NOT catch that -- it was green
# locally throughout. So drive the guard's own inputs: resolve the ids exactly
# as the checker does and require every promoted name to be found.
known_ids="$(grep -rhE '^id:[[:space:]]*' ci/ast-grep/rules/ \
             | sed -E 's/^id:[[:space:]]*//; s/[[:space:]]*$//' | sort -u)"
if [ -z "$known_ids" ]; then
    echo "FAIL promoted-resolves control: no rule ids parsed from ci/ast-grep/rules/" >&2
    rc=1
else
    unresolved=""
    for r in $ck; do
        hit=""
        for k in $known_ids; do
            [ "$k" = "$r" ] && { hit=1; break; }
        done
        [ -n "$hit" ] || unresolved="$unresolved $r"
    done
    if [ -z "$unresolved" ]; then
        echo "ok   every PROMOTED ast-grep rule resolves to a defined rule id"
    else
        echo "FAIL PROMOTED names with no defining rule id:$unresolved" >&2
        rc=1
    fi
fi

# Unparsable YAML is "could not run" (2), never "clean" -- GitHub may still
# read a file this parser rejects, so a verdict over the rest of the tree would
# be unsupported. Fixture is generated: a committed broken-YAML file would trip
# yamllint on the real tree.
badroot="$(mktemp -d)"
trap 'rm -rf "$badroot"' EXIT
mkdir -p "$badroot/.github/workflows"
printf 'on: [pull_request\njobs: {\n' > "$badroot/.github/workflows/broken.yml"
case_ 2 "policy runners: unparsable YAML is exit 2, not clean" \
    env "WORKFLOW_POLICY_ROOT=$badroot" python3 ci/linter/workflow_policy.py runners

# ----------------------------------------------------------------------------
# Every lint wrapper must observe failure from its file-list producer.
#
# Process substitution returns mapfile's status, not lint_files' status. The
# fake git below emits a plausible prefix and then fails, reproducing the
# dangerous case: a truncated/empty selection that used to look clean. Run the
# control through every wrapper that loads lint_files, including lint-sh.sh's
# two-list path. The matching empty-selection control preserves the legitimate
# no-relevant-files behavior.
listroot="$(mktemp -d)"
trap 'rm -rf "$badroot" "$listroot"' EXIT
mkdir -p "$listroot/bin"
cat > "$listroot/bin/git" <<'GITEOF'
#!/usr/bin/env bash
if [ "${1:-}" = "ls-files" ]; then
    if [ -n "${GIT_LS_FILES_OK:-}" ]; then
        printf '%s\n' src/ngx_http_cache_turbo_module.c
        exit 0
    fi
    if [ -n "${GIT_FAIL_SECOND_STATE:-}" ]; then
        call=0
        [ ! -f "$GIT_FAIL_SECOND_STATE" ] \
            || read -r call < "$GIT_FAIL_SECOND_STATE"
        printf '%s\n' "$((call + 1))" > "$GIT_FAIL_SECOND_STATE"
        printf '%s\n' config
        [ "$call" -eq 0 ] && exit 0
        exit 1
    fi
    printf '%s\n' src/ngx_http_cache_turbo_shm.c
    exit 1
fi
exec "${REAL_GIT:?}" "$@"
GITEOF
chmod +x "$listroot/bin/git"
cat > "$listroot/bin/grep" <<'GREPEOF'
#!/usr/bin/env bash
if [ -n "${GREP_FAIL_FILTER:-}" ] && [ "${1:-}" = "-Ev" ]; then
    printf '%s\n' src/ngx_http_cache_turbo_module.c
    : > "${GREP_FAIL_FILTER_MARKER:?}"
    exit 2
fi
if [ -n "${GREP_FAIL_YAML_SUBSET:-}" ] && [ "${1:-}" = "-E" ] \
   && [ "${2:-}" = '^\.github/workflows/' ]; then
    exit 2
fi
if [ -n "${GREP_FAIL_RULE_IDS:-}" ] && [ "${1:-}" = "-rhE" ]; then
    printf '%s\n' \
        'id: c-memcpy-sizeof-pointer' \
        'id: c-sizeof-wrong-operand' \
        'id: c-unbounded-string-copy' \
        'id: c-format-string' \
        'id: c-shell-exec'
    exit 1
fi
exec "${REAL_GREP:?}" "$@"
GREPEOF
chmod +x "$listroot/bin/grep"
cat > "$listroot/bin/ast-grep" <<'ASTEOF'
#!/usr/bin/env bash
exit 0
ASTEOF
chmod +x "$listroot/bin/ast-grep"
cat > "$listroot/bin/yamllint" <<'YAMLEOF'
#!/usr/bin/env bash
exit 0
YAMLEOF
chmod +x "$listroot/bin/yamllint"
for tool in actionlint zizmor; do
    cat > "$listroot/bin/$tool" <<'WORKFLOWEOF'
#!/usr/bin/env bash
[ -z "${YAML_REJECT_WORKFLOW_TOOLS:-}" ] || exit 99
for arg in "$@"; do
    [ "$arg" = "${YAML_EXPECT_WORKFLOW:-}" ] && exit 0
done
exit 1
WORKFLOWEOF
    chmod +x "$listroot/bin/$tool"
done

lint_file_wrappers=(
    ci/linter/lint-astgrep.sh
    ci/linter/lint-c.sh
    ci/linter/lint-ci-cadence.sh
    ci/linter/lint-ci-ports.sh
    ci/linter/lint-ci-runners.sh
    ci/linter/lint-ci-secrets.sh
    ci/linter/lint-docs-drift.sh
    ci/linter/lint-nginx.sh
    ci/linter/lint-perl.sh
    ci/linter/lint-python.sh
    ci/linter/lint-sh.sh
    ci/linter/lint-shm-lock.sh
    ci/linter/lint-spelling.sh
    ci/linter/lint-stripe-seam.sh
    ci/linter/lint-suite-docs.sh
    ci/linter/lint-sync-stamp.sh
    ci/linter/lint-yaml.sh
)

# Keep the test inventory equal to the wrappers that actually call the shared
# loader. Both sets are sorted before comparison; no producer runs behind
# process substitution, so an inventory-build failure cannot look like a match.
actual_wrappers=()
for wrapper in ci/linter/lint-*.sh; do
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*lint_files_into[[:space:]] ]]; then
            actual_wrappers+=("$wrapper")
            break
        fi
    done < "$wrapper"
done
if actual_sorted="$(printf '%s\n' "${actual_wrappers[@]}" | LC_ALL=C sort)" \
   && expected_sorted="$(printf '%s\n' "${lint_file_wrappers[@]}" | LC_ALL=C sort)"; then
    if [ "$actual_sorted" = "$expected_sorted" ]; then
        echo "ok   every lint_files_into wrapper has producer and empty controls"
    else
        echo "FAIL lint_files_into wrapper-control inventory differs" >&2
        printf 'actual wrappers:\n%s\nexpected wrappers:\n%s\n' \
            "$actual_sorted" "$expected_sorted" >&2
        rc=1
    fi
else
    echo "FAIL could not sort lint_files_into wrapper-control inventory" >&2
    rc=1
fi

for wrapper in "${lint_file_wrappers[@]}"; do
    case_ 2 "${wrapper##*/}: a failing file-list producer is exit 2" \
        env PATH="$listroot/bin:$PATH" REAL_GIT="$(command -v git)" \
        REAL_GREP="$(command -v grep)" \
        LINT_MODE=all "$wrapper"
    case_ 0 "${wrapper##*/}: a legitimate empty selection stays clean" \
        "$wrapper" ci/linter/no-such-selection
done

# lint-sh.sh has two independent selections. Prove the second one is not merely
# converted in the diff while the first return still determines the verdict.
rm -f -- "$listroot/second-call"
case_ 2 "lint-sh.sh: its second file-list producer also propagates failure" \
    env PATH="$listroot/bin:$PATH" REAL_GIT="$(command -v git)" \
    REAL_GREP="$(command -v grep)" \
    GIT_FAIL_SECOND_STATE="$listroot/second-call" LINT_MODE=all \
    ci/linter/lint-sh.sh

# Regex failure is "could not run", while a valid regex matching no selected
# file is the legitimate empty case. Both go through the shared helper itself.
case_ 2 "lint_files_into: an invalid filter regex is exit 2" \
    bash -c '. ci/linter/lib.sh; files=(); lint_files_into files "[" ci/linter/lib.sh'
# shellcheck disable=SC2016  # array expands in the inner bash, not this script
case_ 0 "lint_files_into: a valid no-match clears the target array" \
    bash -c '. ci/linter/lib.sh; files=(stale); lint_files_into files "^src/" ci/linter/lib.sh; [ "${#files[@]}" -eq 0 ]'

# Exact old-code probe: the former grep filter emitted a plausible source path,
# then exited 2; its trailing `|| true` masked that failure. The in-process
# matcher must not invoke the shim at all. If a future refactor restores an
# external filter, the marker makes the masked status observable.
rm -f -- "$listroot/filter-grep-ran"
# shellcheck disable=SC2016  # array/marker expand in the inner bash
case_ 0 "lint_files_into: a partial-output grep filter cannot be masked" \
    env PATH="$listroot/bin:$PATH" REAL_GIT="$(command -v git)" \
    REAL_GREP="$(command -v grep)" GIT_LS_FILES_OK=1 GREP_FAIL_FILTER=1 \
    GREP_FAIL_FILTER_MARKER="$listroot/filter-grep-ran" bash -c \
    '. ci/linter/lib.sh; files=(); lint_files_into files "^src/.*\\.[ch]$"; [ "${#files[@]}" -eq 1 ]; [ ! -e "$GREP_FAIL_FILTER_MARKER" ]'

# The ast-grep wrapper builds a second filesystem-backed work list from the
# vendored rule tree. A complete plausible promoted set must not turn a later
# traversal/read failure into a KNOWN array that passes the membership guard.
case_ 2 "lint-astgrep.sh: a failing rule-id producer is exit 2" \
    env PATH="$listroot/bin:$PATH" REAL_GIT="$(command -v git)" \
    REAL_GREP="$(command -v grep)" \
    GREP_FAIL_RULE_IDS=1 ci/linter/lint-astgrep.sh \
    src/ngx_http_cache_turbo_module.c

# lint-yaml's workflow subset is selected in-process. Pin both directions with
# real wrapper runs and fake external tools: a workflow path reaches both
# workflow linters, while an ordinary YAML path must not call either one.
case_ 0 "lint-yaml.sh: a workflow path reaches the workflow linters" \
    env PATH="$listroot/bin:$PATH" REAL_GIT="$(command -v git)" \
    YAML_EXPECT_WORKFLOW=.github/workflows/lint.yml \
    ci/linter/lint-yaml.sh .github/workflows/lint.yml
case_ 0 "lint-yaml.sh: a non-workflow YAML path leaves WF empty" \
    env PATH="$listroot/bin:$PATH" REAL_GIT="$(command -v git)" \
    YAML_REJECT_WORKFLOW_TOOLS=1 \
    ci/linter/lint-yaml.sh ci/ast-grep/sgconfig.yml

# Old-code mutation control: the former grep selector normalised grep's exit 2
# to an empty WF and skipped both workflow tools. The Bash case loop never
# calls grep, reaches the deliberately rejecting tools, and therefore exits 1.
case_ 1 "lint-yaml.sh: subset grep failure cannot become empty-clean" \
    env PATH="$listroot/bin:$PATH" REAL_GIT="$(command -v git)" \
    REAL_GREP="$(command -v grep)" GREP_FAIL_YAML_SUBSET=1 \
    YAML_REJECT_WORKFLOW_TOOLS=1 \
    ci/linter/lint-yaml.sh .github/workflows/lint.yml

# ----------------------------------------------------------------------------
# The shm-checker mutation controls.
#
# CARVE-INIT-NO-NEGATIVE-CONTROL: the three shm checkers (carve-init, shm-lock,
# stripe-seam) had every proof of efficacy living in a commit message. Each was
# hand-mutated once by a reviewer, proved red, and then nothing in the tree kept
# it red -- so a refactor that silently disarmed one would leave CI green and
# the disarming invisible. That is precisely the failure this file exists to
# catch, applied to the checkers rather than to the dispatcher.
#
# These cases DO invoke a real checker, unlike every case above. They stay
# within the suite budget by running against generated fixture trees rather
# than the real src/, so no build and no scan of the 34k-line source is
# involved.
#
# shm-lock and stripe-seam need no C parser, so one tiny textual fixture can
# drive both. stripe-seam's key-directed ledger is part of the real checker;
# define each ledgered function so its clean arm exercises that path too.
checkerroot="$(mktemp -d)"
trap 'rm -rf "$badroot" "$listroot" "$checkerroot"' EXIT
mkdir -p "$checkerroot/src" "$checkerroot/ci/tools"
cp ci/tools/lint-shm-lock.sh ci/tools/lint-stripe-seam.sh \
    "$checkerroot/ci/tools/"
: > "$checkerroot/src/control.c"
for fn in \
    ngx_http_cache_turbo_shm_lookup \
    ngx_http_cache_turbo_shm_store_locked \
    ngx_http_cache_turbo_shm_store \
    ngx_http_cache_turbo_shm_store_if \
    ngx_http_cache_turbo_shm_store_marker \
    ngx_http_cache_turbo_shm_purge_key \
    ngx_http_cache_turbo_shm_freshen \
    ngx_http_cache_turbo_shm_drop_locked \
    ngx_http_cache_turbo_shm_admit \
    ngx_http_cache_turbo_shm_claim \
    ngx_http_cache_turbo_shm_claim_locked \
    ngx_http_cache_turbo_shm_unstub \
    ngx_http_cache_turbo_shm_owns \
    ngx_http_cache_turbo_shm_resolve_miss \
    ngx_http_cache_turbo_shm_l2_neg_check \
    ngx_http_cache_turbo_shm_l2_neg_set \
    ngx_http_cache_turbo_shm_varidx_pending_set \
    ngx_http_cache_turbo_shm_touch_lru; do
    printf '%s(void)\n{\n}\n' "$fn" >> "$checkerroot/src/control.c"
done

# shellcheck disable=SC2329  # invoked indirectly, by name, via case_()
shm_lock_lint() {
    # shellcheck disable=SC2317
    env -C "$checkerroot" bash ci/tools/lint-shm-lock.sh
}

# shellcheck disable=SC2329  # invoked indirectly, by name, via case_()
stripe_seam_lint() {
    # shellcheck disable=SC2317
    env -C "$checkerroot" bash ci/tools/lint-stripe-seam.sh
}

case_ 0 "shm-lock: a clean lock discipline fixture passes" shm_lock_lint
cat >> "$checkerroot/src/control.c" <<'SHMEOF'
shm_lock_violation(void)
{
    ngx_shmtx_lock(&zone->mutex);
    ngx_http_finalize_request(r, rc);
    ngx_shmtx_unlock(&zone->mutex);
}
SHMEOF
finding_case_ "shm-lock: a yielding call under the mutex is caught" \
    'yielding call under shm mutex' shm_lock_lint

case_ 0 "stripe-seam: a resolver-only fixture passes" stripe_seam_lint
cat >> "$checkerroot/src/control.c" <<'STRIPEEOF'
stripe_seam_violation(void)
{
    zone->shpool = pool;
}
STRIPEEOF
finding_case_ "stripe-seam: a bare zone pool dereference is caught" \
    'bare zone shm dereference outside the stripe resolver' stripe_seam_lint
#
# THE FIXTURES ARE NOW COMPLETE, WELL-TYPED C. carve-init parses with clang
# rather than lexing with awk, and clang's error recovery replaces the
# statements of a function whose identifiers do not resolve with RecoveryExpr:
# the field list survives, every member store vanishes, and the harvest would
# see zero initialisers. A fixture that does not COMPILE therefore cannot test
# the initialiser half at all, so the header below declares every type and the
# source declares every object the carve block names. This is a real constraint
# the awk fixtures did not have, and it is load-bearing -- the checker exits 2
# on a fixture it cannot parse rather than guessing, so a fixture that drifts
# out of compiling turns its row red rather than quietly vacuous.
mutroot="$(mktemp -d)"
trap 'rm -rf "$badroot" "$listroot" "$checkerroot" "$mutroot"' EXIT
mkdir -p "$mutroot/src" "$mutroot/ci/tools"
cp ci/tools/lint-carve-init.sh ci/tools/carve_init_ast.py "$mutroot/ci/tools/"

# A minimal shctx and carve block: the smallest input that exercises the real
# member-harvest and initialiser-harvest paths.
#
# `ngx_queue_init` is spelled as a MACRO here because that is what it is in
# nginx. The distinction matters: after preprocessing there is no call left to
# match, so a checker that only looked for a CallExpr would find none of this
# module's four real helper-initialised members. The fixture reproduces the
# real shape rather than an easier one.
emit_fixture() {
    # $1 = extra member line, $2 = extra carve line
    cat > "$mutroot/src/ngx_http_cache_turbo_module.h" <<EOF
typedef unsigned char u_char;
typedef unsigned long ngx_uint_t;
typedef unsigned long ngx_atomic_t;
typedef unsigned long uint64_t;
#define NGX_ATOMIC_T ngx_atomic_t
#define NGX_ALIGNED(n) __attribute__((aligned(n)))
typedef struct ngx_queue_s { struct ngx_queue_s *prev, *next; } ngx_queue_t;
#define ngx_queue_init(q) (q)->prev = q; (q)->next = q
#define ngx_memzero(buf, n) __builtin_memset((buf), 0, (n))
typedef struct { ngx_uint_t x; } ngx_http_cache_turbo_stripe_t;
typedef u_char ct_u_char_pad_t[8];
typedef ngx_uint_t ct_uint_pad_t[8];
typedef struct ngx_http_cache_turbo_shctx_s {
    ngx_atomic_t             hits;
    u_char                   _pad_hits[24];
${1:-}
} ngx_http_cache_turbo_shctx_t;
EOF
    cat > "$mutroot/src/ngx_http_cache_turbo_shm.c" <<EOF
#include "ngx_http_cache_turbo_module.h"
typedef struct { ngx_http_cache_turbo_shctx_t *sh; } ngx_ht_st_t;
static ngx_ht_st_t *st, *other, *octx;
static void *pool;
void *ngx_slab_alloc(void *, unsigned long);
int memcmp(const void *, const void *, unsigned long);
void log(const char *);
void my_ngx_queue_init(void *);
static char ch;
int ngx_http_cache_turbo_shm_init_zone(void *shm_zone, void *data)
{
    st->sh = ngx_slab_alloc(pool, sizeof(ngx_http_cache_turbo_shctx_t));
    st->sh->hits = 0;
${2:-}
    return 0;
}
EOF
}

# The fixture is self-contained C -- it declares every type and object it uses
# -- so it is parsed with NO include set at all (NGX_SRC_TREE=-). That keeps
# these rows independent of whether this machine has a configured nginx
# checkout; otherwise every row below would report exit 2 on a fresh clone and
# the suite would be asserting "cannot run" rather than the invariant.
# shellcheck disable=SC2329  # invoked indirectly, by name, via case_()
carve_lint() {
    # SC2317: this IS reached -- every row passes it to case_, which runs it as
    # "$@". shellcheck cannot see an indirect invocation.
    # shellcheck disable=SC2317
    env -C "$mutroot" NGX_SRC_TREE=- CARVE_INIT_CONFIGS=default \
        CARVE_INIT_PIN_COUNT=0 \
        ./ci/tools/lint-carve-init.sh
}

# Baseline: the fixture as written must be CLEAN. Without this, every case
# below could be passing for the wrong reason (a fixture the checker cannot
# parse at all also "fails").
emit_fixture "" ""
case_ 0 "carve-init: well-formed fixture is clean" carve_lint

# The original MAJOR: a member initialised only outside the carve block. This
# is the mutation that passed before the scan window was narrowed.
emit_fixture "    ngx_uint_t               tag_cap_drops;" ""
case_ 1 "carve-init: member never initialised is caught" carve_lint

# The carve WINDOW itself. shm_init_zone() has early-return branches ABOVE the
# slab alloc -- the octx reload inherit and the shm.exists branch -- and a store
# in one of those is NOT carve initialisation: it never runs on a fresh carve,
# and on reload it overwrites inherited live state. So the window opens at the
# slab alloc, not at the function opener.
#
# This row exists because deleting the window bound entirely was caught by ZERO
# of the other controls: every one of them puts its store after the alloc, so
# widening the window leaves them all green. A member initialised only BEFORE
# the alloc is the input that separates the two, and without it the bound could
# be removed and CI would stay green -- the exact silent disarming this file
# exists to detect.
emit_fixture "    ngx_uint_t               tag_cap_drops;" ""
cat > "$mutroot/src/ngx_http_cache_turbo_shm.c" <<'PREEOF'
#include "ngx_http_cache_turbo_module.h"
typedef struct { ngx_http_cache_turbo_shctx_t *sh; } ngx_ht_st_t;
static ngx_ht_st_t *st, *other, *octx;
static void *pool;
void *ngx_slab_alloc(void *, unsigned long);
int memcmp(const void *, const void *, unsigned long);
void log(const char *);
void my_ngx_queue_init(void *);
static char ch;
int ngx_http_cache_turbo_shm_init_zone(void *shm_zone, void *data)
{
    /* the shm.exists reload branch, ABOVE the carve */
    st->sh->tag_cap_drops = 0;
    st->sh = ngx_slab_alloc(pool, sizeof(ngx_http_cache_turbo_shctx_t));
    st->sh->hits = 0;
    return 0;
}
PREEOF
case_ 1 "carve-init: a store BEFORE the slab alloc is not carve initialisation" \
    carve_lint

# An unrelated allocator call cannot open the carve window. Only the assignment
# of ngx_slab_alloc() to st->sh identifies the fresh object being initialised.
emit_fixture "    ngx_uint_t               tag_cap_drops;" ""
cat > "$mutroot/src/ngx_http_cache_turbo_shm.c" <<'ANCHOREOF'
#include "ngx_http_cache_turbo_module.h"
typedef struct { ngx_http_cache_turbo_shctx_t *sh; } ngx_ht_st_t;
static ngx_ht_st_t *st;
static void *pool;
void *ngx_slab_alloc(void *, unsigned long);
int ngx_http_cache_turbo_shm_init_zone(void *shm_zone, void *data)
{
    (void) ngx_slab_alloc(pool, 1);
    st->sh->tag_cap_drops = 0;
    st->sh = ngx_slab_alloc(pool, sizeof(ngx_http_cache_turbo_shctx_t));
    st->sh->hits = 0;
    return 0;
}
ANCHOREOF
case_ 1 "carve-init: an unrelated slab allocation cannot widen the window" \
    carve_lint

# Flattening the AST used to credit stores that did not execute on every carve.
emit_fixture "    ngx_uint_t               tag_cap_drops;" \
             "    if (data != shm_zone) { st->sh->tag_cap_drops = 0; }"
case_ 1 "carve-init: a conditional-only store is not initialisation" carve_lint

# A direct store after an early successful return does not dominate every
# successful path. Nonzero error returns (such as the real NULL-allocation
# guard) are safe; a zero or non-constant return is refused loudly.
emit_fixture "    ngx_uint_t               tag_cap_drops;" \
             "    if (data != shm_zone) { return 0; }
    st->sh->tag_cap_drops = 0;"
case_ 2 "carve-init: an early successful return cannot bypass initialisation" \
    carve_lint

# The top-level return closes the carve window; dead statements after it cannot
# satisfy the invariant.
emit_fixture "    ngx_uint_t               tag_cap_drops;" ""
cat > "$mutroot/src/ngx_http_cache_turbo_shm.c" <<'DEADEOF'
#include "ngx_http_cache_turbo_module.h"
typedef struct { ngx_http_cache_turbo_shctx_t *sh; } ngx_ht_st_t;
static ngx_ht_st_t *st;
static void *pool;
void *ngx_slab_alloc(void *, unsigned long);
int ngx_http_cache_turbo_shm_init_zone(void *shm_zone, void *data)
{
    st->sh = ngx_slab_alloc(pool, sizeof(ngx_http_cache_turbo_shctx_t));
    st->sh->hits = 0;
    return 0;
    st->sh->tag_cap_drops = 0;
}
DEADEOF
case_ 1 "carve-init: an unreachable store after return is not initialisation" \
    carve_lint

# Compound assignment must not read as initialisation.
emit_fixture "    ngx_uint_t               tag_cap_drops;" \
             "    st->sh->tag_cap_drops += 0;"
case_ 1 "carve-init: compound assignment is not initialisation" carve_lint

# Multi-declarator lines must register EVERY name, not only the last.
emit_fixture "    ngx_uint_t               zzz_a, zzz_b;" \
             "    st->sh->zzz_b = 0;"
case_ 1 "carve-init: multi-declarator hides no member" carve_lint

# Taking a member address for a pure READ is not initialisation.
emit_fixture "    ngx_uint_t               tag_cap_drops;" \
             "    (void) memcmp(&st->sh->tag_cap_drops, \"x\", 8);"
case_ 1 "carve-init: address-of in a non-initialiser call does not count" carve_lint

# The _pad* exemption is a TYPE decision: a _pad*-named member of a
# non-u_char-array type must FAIL rather than be silently exempted.
emit_fixture "    ngx_uint_t               _pad_but_real;" ""
case_ 1 "carve-init: _pad* exemption requires a u_char array type" carve_lint

# ...and a genuine pad must still be exempt, or the check above is just noise.
emit_fixture "    u_char                   _pad_legit[8];" ""
case_ 0 "carve-init: a genuine u_char pad stays exempt" carve_lint

# clang preserves a typedef-backed array's source spelling in qualType and
# records its semantic element type in desugaredQualType. The exemption must
# follow that semantic type so a genuine byte-array alias remains valid.
emit_fixture "    ct_u_char_pad_t           _pad_typedef;" ""
case_ 0 "carve-init: a typedef-backed u_char pad stays exempt" carve_lint

# The desugared fallback must not turn every typedef-backed array into padding:
# an alias whose real element type is ngx_uint_t is ordinary state and still
# requires explicit carve initialisation.
emit_fixture "    ct_uint_pad_t             _pad_typedef;" ""
case_ 1 "carve-init: a typedef-backed non-u_char pad is rejected" carve_lint

# Per-declarator, not per-line: an array pad and a SCALAR pad on one
# declaration line. The scalar must not inherit the array's exemption.
emit_fixture "    u_char                   _pad_a[8], _pad_b;" ""
case_ 1 "carve-init: _pad exemption is per-declarator, not per-line" carve_lint

# An allowlisted initialiser and an unrelated pure read on ONE line: the read
# must not borrow the initialiser's credit.
emit_fixture "    ngx_queue_t              lru;
    ngx_uint_t               tag_cap_drops;" \
             "    ngx_queue_init(&st->sh->lru); (void) memcmp(&st->sh->tag_cap_drops, \"x\", 8);"
case_ 1 "carve-init: address-of harvest is scoped to the call, not the line" carve_lint

# ...and an allowlisted initialiser alone must still count, or the scoping
# above is just a way to break every legitimate helper call.
emit_fixture "    ngx_queue_t              lru;" \
             "    ngx_queue_init(&st->sh->lru);"
case_ 0 "carve-init: an allowlisted initialiser still counts" carve_lint

# Only the destination argument counts, and a byte-zero helper must cover the
# complete declared member rather than merely mention it in another argument.
emit_fixture "    ngx_uint_t               tag_cap_drops;" \
             "    ngx_memzero(pool, sizeof(st->sh->tag_cap_drops));"
case_ 1 "carve-init: a member in ngx_memzero's size argument is not credited" \
    carve_lint

emit_fixture "    ngx_uint_t               tag_cap_drops;" \
             "    ngx_memzero(&st->sh->tag_cap_drops, 1);"
case_ 1 "carve-init: a partial ngx_memzero is not whole-member initialisation" \
    carve_lint

emit_fixture "    ngx_uint_t               tag_cap_drops;" \
             "    ngx_memzero(&st->sh->tag_cap_drops, sizeof(st->sh->tag_cap_drops));"
case_ 0 "carve-init: a full-size ngx_memzero initialises its destination" \
    carve_lint

# A wrapped initialiser call must still count.
emit_fixture "    ngx_queue_t              lru;" \
             "    ngx_queue_init(
        &st->sh->lru);"
case_ 0 "carve-init: a wrapped initialiser call still counts" carve_lint

# A pointer-to-array _pad is an 8-byte pointer, not filler, bracket regardless.
emit_fixture "    u_char                   (*_pad_pa)[8];" ""
case_ 1 "carve-init: pointer-to-array _pad is not layout filler" carve_lint

# INIT_HELPERS is name-exact: a helper merely CONTAINING an allowlisted name
# must not inherit its credit. Under the parser this is identification by the
# macro's own expansion record rather than a word-boundary regex, so the row
# now asserts something stronger than it used to.
emit_fixture "    ngx_uint_t               tag_cap_drops;" \
             "    my_ngx_queue_init(&st->sh->tag_cap_drops);"
case_ 1 "carve-init: INIT_HELPERS match is name-exact" carve_lint

# A structurally broken header is "could not run" (2), never clean.
printf 'struct something_else {\n    int x;\n};\n' \
    > "$mutroot/src/ngx_http_cache_turbo_module.h"
printf 'int main(void) { return 0; }\n' \
    > "$mutroot/src/ngx_http_cache_turbo_shm.c"
case_ 2 "carve-init: missing struct is exit 2, not clean" carve_lint

# The checker must never report ok when it could not parse at all. This is the
# single most important property of the parser backend: a gate that cannot run
# has to be loudly distinguishable from a gate that ran and found nothing.
emit_fixture "" ""
case_ 2 "carve-init: no configured nginx tree is exit 2, not clean" \
    env -C "$mutroot" NGX_SRC_TREE=/nonexistent ./ci/tools/lint-carve-init.sh

# A tree carrying objs/Makefile but no nginx sources is NOT usable. ci-build.sh
# leaves per-mode variant directories under .build/ that hold an objs/ and
# nothing else, and one of those is usually the NEWEST match -- selecting one
# produced a parse that died on ngx_config.h, an error a long way from its
# cause.
mkdir -p "$mutroot/objsonly/objs"
: > "$mutroot/objsonly/objs/Makefile"
case_ 2 "carve-init: an objs-only tree is rejected, not used" \
    env -C "$mutroot" NGX_SRC_TREE="$mutroot/objsonly" ./ci/tools/lint-carve-init.sh

# A missing clang is "could not run", never a fall back to a text scan -- the
# lexer this checker was rewritten to retire.
emit_fixture "" ""
case_ 2 "carve-init: a missing clang is exit 2, not a text-scan fallback" \
    env -C "$mutroot" NGX_SRC_TREE=- CARVE_INIT_CLANG=no-such-clang \
    ./ci/tools/lint-carve-init.sh

# The configuration selector is a fail-closed enum. A typo must not silently
# degrade the real two-configuration gate to production-only.
emit_fixture "" ""
case_ 2 "carve-init: an invalid configuration selector is exit 2" \
    env -C "$mutroot" NGX_SRC_TREE=- CARVE_INIT_CONFIGS=typo \
    ./ci/tools/lint-carve-init.sh

# The wrapper must observe a work-list producer that fails after emitting a
# plausible prefix. Process substitution used to discard that exit status and
# turn the truncated list into a clean skip.
mkdir -p "$mutroot/fakebin"
cat > "$mutroot/fakebin/git" <<'GITEOF'
#!/usr/bin/env bash
if [ "${1:-}" = "ls-files" ]; then
    printf '%s\n' src/ngx_http_cache_turbo_shm.c
    exit 1
fi
exec "${REAL_GIT:?}" "$@"
GITEOF
chmod +x "$mutroot/fakebin/git"
case_ 2 "carve-init wrapper: a failing file-list producer is exit 2" \
    env PATH="$mutroot/fakebin:$PATH" REAL_GIT="$(command -v git)" LINT_MODE=all \
    ci/linter/lint-carve-init.sh

# ----------------------------------------------------------------------------
# carve-init: the MALFORMED-INPUT TABLE.
#
# Round-by-round, this checker was fixed by generalising the one input a
# reviewer happened to name, and the next round found another member of the
# same class still open. So these controls are organised by CLASS rather than
# by finding: each row is one shape of hostile or awkward C, and the classes
# are swept across comments, string and char literals, declarator forms,
# wrong-object references, brace structure and preprocessor text.
#
# WHAT CHANGED WITH THE PARSER. Under the awk lexer each of these rows guarded
# a hand-written approximation of one C construct, and the row was the only
# thing standing between that construct and a silent-green gate. clang performs
# translation phases 1-8 itself, so most of these now pass trivially. They are
# KEPT anyway, and that is the point: they no longer prove the lexer got this
# shape right, they prove the class stays closed if anyone ever reaches for a
# text scan again. A row that passes trivially against a correct backend and
# red against a broken one is exactly what a regression control should be.
#
# Columns: expected-exit | description | member line | carve line
# A `%` in a member/carve field is a literal newline, so a row can carry a
# multi-line construct without breaking the table shape.
carve_row() {
    local want="$1" desc="$2" mem="$3" carve="$4"
    emit_fixture "${mem//%/$'\n'}" "${carve//%/$'\n'}"
    case_ "$want" "carve-init: $desc" carve_lint
}

# --- class: comments must never be parsed as code ---------------------------
# The exploit that forced the awk rewrite: a block comment naming a helper and
# carrying no `;` held the INIT_HELPERS window open for the rest of the block,
# crediting every later pure read.
carve_row 1 "block comment naming a helper does not open the helper window" \
    "    ngx_atomic_t             owner_seq;" \
    '    /* the LRU is set up by ngx_queue_init( further down */%    (void) memcmp(&st->sh->owner_seq, "x", 8);'

carve_row 1 "MULTI-LINE comment naming a helper does not open the window" \
    "    ngx_atomic_t             owner_seq;" \
    '    /* set up by%     * ngx_queue_init( and friends%     */%    (void) memcmp(&st->sh->owner_seq, "x", 8);'

carve_row 1 "line comment naming a helper does not open the window" \
    "    ngx_atomic_t             owner_seq;" \
    '    // done later by ngx_queue_init(%    (void) memcmp(&st->sh->owner_seq, "x", 8);'

# A comment carrying a `;` must not be able to TERMINATE a real statement
# either -- the splitter has to see the code semicolons only.
carve_row 1 "a semicolon inside a comment does not terminate a statement" \
    "    ngx_atomic_t             owner_seq;" \
    '    (void) memcmp(&st->sh->owner_seq /* ; ; ; */, "x", 8);'

# A commented-out initialiser is not an initialiser.
carve_row 1 "a commented-out assignment does not count as initialisation" \
    "    ngx_uint_t               tag_cap_drops;" \
    "    /* st->sh->tag_cap_drops = 0; */"

carve_row 1 "a line-commented assignment does not count as initialisation" \
    "    ngx_uint_t               tag_cap_drops;" \
    "    // st->sh->tag_cap_drops = 0;"

# A brace inside a comment must not move the brace depth and truncate the scan.
carve_row 0 "a brace inside a comment does not close the carve window" \
    "    ngx_atomic_t             owner_seq;" \
    "    /* } this brace is prose */%    st->sh->owner_seq = 0;"

# --- class: string and char literals must never be parsed as code -----------
carve_row 1 "a helper name inside a string does not open the helper window" \
    "    ngx_atomic_t             owner_seq;" \
    '    log("ngx_queue_init(");%    (void) memcmp(&st->sh->owner_seq, "x", 8);'

carve_row 0 "a semicolon inside a string does not terminate a statement" \
    "    ngx_atomic_t             owner_seq;" \
    '    log("a ; b");%    st->sh->owner_seq = 0;'

carve_row 0 "a brace inside a string does not close the carve window" \
    "    ngx_atomic_t             owner_seq;" \
    '    log("}");%    st->sh->owner_seq = 0;'

carve_row 0 "a brace inside a CHAR literal does not close the carve window" \
    "    ngx_atomic_t             owner_seq;" \
    "    ch = '}';%    st->sh->owner_seq = 0;"

# An escaped quote must not end the literal early and expose its tail as code.
carve_row 1 "an escaped quote does not end a string early" \
    "    ngx_atomic_t             owner_seq;" \
    '    log("\" ngx_queue_init( \"");%    (void) memcmp(&st->sh->owner_seq, "x", 8);'

# --- class: declarator forms are never silently dropped ---------------------
# A bitfield used to vanish from the member set entirely: no initialiser was
# ever demanded for it and the count still looked plausible.
carve_row 1 "a bitfield member is harvested, not silently dropped" \
    "    unsigned                 degraded:1;" ""

carve_row 0 "an initialised bitfield member satisfies the gate" \
    "    unsigned                 degraded:1;" \
    "    st->sh->degraded = 0;"

carve_row 1 "a spaced bitfield width is still harvested" \
    "    unsigned                 degraded : 3;" ""

# Input that is not C at all is a LOUD failure, never a silent drop. Under the
# lexer this was the script's own hand-written catch-all; under the parser it
# is clang rejecting the syntax error, and the gate refuses to report a verdict
# over a translation unit it could not read. Both answer exit 2 -- "could not
# run" -- which is the honest one: the member cannot vanish while the gate
# reads clean, which is the property the row exists for.
carve_row 2 "a declarator that is not valid C is a loud error, not a silent drop" \
    "    ngx_uint_t               123bad;" ""

# An array-of-struct member is an ordinary member with a bound.
carve_row 1 "an array-of-struct member is harvested" \
    "    ngx_http_cache_turbo_stripe_t  stripes[8];" ""

carve_row 1 "one array element does not initialise the whole member" \
    "    ngx_http_cache_turbo_stripe_t  stripes[8];" \
    "    st->sh->stripes[0].x = 0;"

carve_row 0 "a full-size helper initialises an array-of-struct member" \
    "    ngx_http_cache_turbo_stripe_t  stripes[8];" \
    "    ngx_memzero(&st->sh->stripes, sizeof(st->sh->stripes));"

# A trailing comment on a member declaration must not disturb the name parse.
carve_row 1 "a trailing comment on a member does not hide the member" \
    "    ngx_uint_t               tag_cap_drops;  /* counter ; { */" ""

# --- class: nested aggregates -----------------------------------------------
# A NAMED nested aggregate is an ordinary member: `st->sh->u = ...` is a
# perfectly good store, so the gate demands one. The awk lexer could not tell a
# named nested aggregate from an anonymous one and refused BOTH with exit 2 --
# over-broad, since only the anonymous case is genuinely unsatisfiable.
carve_row 1 "a NAMED nested union is an ordinary member, not a refusal" \
    "    union {%        ngx_uint_t           inner_a;%        ngx_uint_t           inner_b;%    } u;" ""

carve_row 1 "one union field does not initialise the whole member" \
    "    union {%        ngx_uint_t           inner_a;%    } u;" \
    "    st->sh->u.inner_a = 0;"

carve_row 0 "a full-size helper initialises a named nested union" \
    "    union {%        ngx_uint_t           inner_a;%    } u;" \
    "    ngx_memzero(&st->sh->u, sizeof(st->sh->u));"

# The ANONYMOUS case is the unsatisfiable one -- its members are reachable as
# `st->sh->inner_a` but the aggregate itself has no name to demand a store for.
# Demanding one anyway would be CI red on correct code, so it is refused
# loudly instead of answered wrongly.
carve_row 2 "an ANONYMOUS nested union is a loud error, not a false FAIL" \
    "    union {%        ngx_uint_t           inner_a;%        ngx_uint_t           inner_b;%    };" ""

carve_row 2 "an ANONYMOUS nested struct is a loud error, not a false FAIL" \
    "    struct {%        ngx_uint_t           inner_a;%    };" ""

# --- class: every match anchors on the real carve target --------------------
# An unrelated object whose expression merely ENDS in `sh->` must not be
# credited to the carved shctx.
carve_row 1 "a helper call on ANOTHER object does not credit the shctx" \
    "    ngx_queue_t              lru;" \
    "    ngx_queue_init(&other->sh->lru);"

carve_row 1 "an assignment on ANOTHER object does not credit the shctx" \
    "    ngx_uint_t               tag_cap_drops;" \
    "    other->sh->tag_cap_drops = 0;"

carve_row 1 "a longer identifier ending in sh-> does not credit the shctx" \
    "    ngx_uint_t               tag_cap_drops;" \
    "    octx->sh->tag_cap_drops = 0;"

# --- class: brace structure and preprocessor text ---------------------------
# The window closes where the braces BALANCE, not at the first column-0 `}`.
# A macro- or #if-introduced column-0 brace used to truncate the scan and
# report every later member forgotten -- a false FAIL on correct code.
carve_row 0 "a column-0 brace inside the function does not truncate the scan" \
    "    ngx_atomic_t             owner_seq;" \
    "    if (1) {%}%    st->sh->owner_seq = 0;"

carve_row 0 "an #if-gated block does not truncate the scan" \
    "    ngx_atomic_t             owner_seq;" \
    "#if (NGX_DEBUG)%    if (1) {%}%#endif%    st->sh->owner_seq = 0;"

# A member declared across a line continuation keeps its name visible. Phase 2
# is the compiler's own now, so this holds for every line ending -- see the
# CRLF rows at the end of the table.
carve_row 1 "a member declared across a line continuation is harvested" \
    "    ngx_uint_t \\%                             tag_cap_drops;" ""

# A parenthesised declarator is accounted for rather than dropped.
carve_row 1 "a parenthesised pointer declarator is harvested" \
    "    u_char                   (*_pad_pa)[8];" ""

# --- class: translation phase 2 -- line continuation ------------------------
# A trailing backslash splices the next physical line onto this one BEFORE
# comments and tokens are formed, so it applies in EVERY lexical state. The
# awk stripper terminated a line comment at end-of-line and fed the second
# physical line to both passes as live code; because the INIT_HELPERS window
# was sticky until a `;`, one continued comment could credit an arbitrary RUN
# of members. These rows sweep the construct across every state, in both
# directions.
carve_row 1 "a continued LINE COMMENT does not expose its tail as code" \
    "    ngx_queue_t              lru;" \
    '    // set up by \%    ngx_queue_init(&st->sh->lru);'

carve_row 0 "a continued BLOCK COMMENT still closes, and does not eat code" \
    "    ngx_uint_t               tag_cap_drops;" \
    '    /* note \%       still comment */%    st->sh->tag_cap_drops = 0;'

carve_row 0 "a continued DECLARATION/CALL is one statement, not two" \
    "    ngx_queue_t              lru;" \
    '    ngx_queue_init( \%        &st->sh->lru);'

# THE AWK LEXER HAD THIS BACKWARDS, and the parser is what exposed it. The old
# row asserted that an EVEN run of trailing backslashes does not continue the
# line, on the reasoning that the last backslash is itself escaped. That rule
# belongs to STRING literals; it is not translation phase 2. Phase 2 runs
# before tokens exist, so there is no escape processing to speak of -- it
# deletes ANY backslash-newline pair, whatever precedes it, and a `//` comment
# ending in `\\` therefore swallows the next line just as one ending in `\`
# does. Verified with the compiler directly: for
#
#     int main(void){
#     // a \\
#     return 1;
#     }
#
# clang warns `multi-line // comment` and `clang -E` shows the `return 1;`
# gone. The old row asserted exit 0 -- that the helper call on the next line
# still counted -- which is precisely the silent-green this checker exists to
# prevent, since in real C that call is commented out. The row now asserts the
# behaviour C actually has.
carve_row 1 "an EVEN backslash run STILL continues a line comment" \
    "    ngx_queue_t              lru;" \
    '    // harmless \\%    ngx_queue_init(&st->sh->lru);'

# --- class: declarator forms the header does not use yet, but may -----------
carve_row 1 "a function-pointer member is harvested, not a loud error" \
    "    void (*cb)(void *);" ""

carve_row 0 "an initialised function-pointer member satisfies the gate" \
    "    void (*cb)(void *);" \
    "    st->sh->cb = 0;"

# The parameter list carries a comma, which a naive declarator split cuts in
# half, leaving two halves that neither parse.
carve_row 1 "a function-pointer parameter list is not split on its comma" \
    "    void (*cb)(void *, int);" ""

carve_row 1 "an array-of-arrays member is harvested, not a loud error" \
    "    ngx_uint_t               m[2][3];" ""

carve_row 1 "one nested-array element does not initialise the whole member" \
    "    ngx_uint_t               m[2][3];" \
    "    st->sh->m[0][1] = 0;"

carve_row 0 "a full-size helper initialises an array-of-arrays member" \
    "    ngx_uint_t               m[2][3];" \
    "    ngx_memzero(&st->sh->m, sizeof(st->sh->m));"

# An attribute macro sits BETWEEN the type and the name; truncating at its
# parens harvests the MACRO as the member name.
carve_row 1 "an attribute-macro member yields the member name, not the macro" \
    "    ngx_uint_t NGX_ALIGNED(64) slot;" ""

carve_row 0 "an initialised attribute-macro member satisfies the gate" \
    "    ngx_uint_t NGX_ALIGNED(64) slot;" \
    "    st->sh->slot = 0;"

# A macro-spelled TYPE needs no special handling -- it is one more leading
# token -- but nothing asserted that until now.
carve_row 1 "a macro-typed member is harvested" \
    "    NGX_ATOMIC_T             mt;" ""

# Comma-separated bitfields: every name, not only the last.
carve_row 1 "comma-separated bitfields hide no member" \
    "    unsigned                 x:1, y:2;" \
    "    st->sh->x = 0;"

# Confirmed-correct forms that must STAY correct.
carve_row 1 "a const volatile member is harvested" \
    "    const volatile ngx_uint_t cv;" ""

# --- class: __attribute__ in EVERY position ---------------------------------
# The round-5 Major. `sub(/__attribute__.*/, "", line)` deleted the whole
# declaration including the member NAME whenever the attribute came FIRST, so
# the member vanished from the gate entirely -- nothing ever demanded an
# initialiser and the count silently dropped by one, which reads exactly like
# a passing gate. Verified against the pre-rewrite script: it reported
# `ok: all 67` where the correct answer is 68. The header's own comment names
# __attribute__((aligned(64))) as the intended pinning mechanism for the
# hot counters, so this is the shape the struct is documented to grow.
#
# All three positions C allows are swept, each in both directions.
carve_row 1 "a PREFIX __attribute__ member is harvested, not deleted" \
    "    __attribute__((aligned(64))) ngx_uint_t slotp;" ""

carve_row 0 "an initialised PREFIX __attribute__ member satisfies the gate" \
    "    __attribute__((aligned(64))) ngx_uint_t slotp;" \
    "    st->sh->slotp = 0;"

carve_row 1 "an INFIX __attribute__ member is harvested" \
    "    ngx_uint_t __attribute__((aligned(64))) sloti;" ""

carve_row 0 "an initialised INFIX __attribute__ member satisfies the gate" \
    "    ngx_uint_t __attribute__((aligned(64))) sloti;" \
    "    st->sh->sloti = 0;"

carve_row 1 "a SUFFIX __attribute__ member is harvested" \
    "    ngx_uint_t slots __attribute__((aligned(64)));" ""

carve_row 0 "an initialised SUFFIX __attribute__ member satisfies the gate" \
    "    ngx_uint_t slots __attribute__((aligned(64)));" \
    "    st->sh->slots = 0;"

# A prefix attribute must not swallow a LATER member on the same line either.
carve_row 1 "a prefix __attribute__ does not hide a second declarator" \
    "    __attribute__((aligned(64))) ngx_uint_t sa, sb;" \
    "    st->sh->sa = 0;"

# ----------------------------------------------------------------------------
# carve-init: LINE ENDINGS.
#
# The other round-5 Major. The awk phase-2 splice counted trailing backslashes
# on the RAW record, which under CRLF ends in `\r` -- so the backslash was
# never the last character, the splice never fired, and a continued line
# comment left its tail exposed as live code. Verified against the pre-rewrite
# script on the real tree: a CRLF checkout with a `// swallow \` before
# `st->sh->owner_seq = 0;` reported `ok: all 68` over a genuinely
# uninitialised member.
#
# This is REACHABLE, not hypothetical: .gitattributes pins *.sh/*.pl/*.py/*.t
# to eol=lf but leaves *.c/*.h unspecified, and explicitly anticipates
# core.autocrlf=true checkouts.
#
# Every row above runs LF. These re-run the phase-2 rows byte-for-byte with
# CRLF endings, which is the axis that made the defect invisible: 90 LF-only
# controls could not move on it.
crlf_row() {
    local want="$1" desc="$2" mem="$3" carve="$4"
    emit_fixture "${mem//%/$'\n'}" "${carve//%/$'\n'}"
    # Convert both fixture files in place. `printf %s` + parameter expansion
    # rather than a tool, so no unix2dos/sed dependency enters the suite.
    local f content
    for f in "$mutroot/src/ngx_http_cache_turbo_module.h" \
             "$mutroot/src/ngx_http_cache_turbo_shm.c"; do
        content="$(cat "$f")"
        printf '%s\r\n' "${content//$'\n'/$'\r\n'}" > "$f"
    done
    case_ "$want" "carve-init: [CRLF] $desc" carve_lint
}

# The baseline: a correct CRLF fixture must be CLEAN. Without it every red row
# below is equally consistent with "CRLF breaks the parse outright", which
# would be a false FAIL on correct code rather than the property being tested.
crlf_row 0 "a well-formed CRLF fixture is clean" "" ""

crlf_row 1 "an uninitialised member is caught under CRLF" \
    "    ngx_uint_t               tag_cap_drops;" ""

# THE round-5 defect, in the fixture that reproduces it.
crlf_row 1 "a continued LINE COMMENT does not expose its tail as code" \
    "    ngx_queue_t              lru;" \
    '    // set up by \%    ngx_queue_init(&st->sh->lru);'

crlf_row 0 "a continued DECLARATION/CALL is one statement under CRLF" \
    "    ngx_queue_t              lru;" \
    '    ngx_queue_init( \%        &st->sh->lru);'

crlf_row 0 "a continued BLOCK COMMENT still closes under CRLF" \
    "    ngx_uint_t               tag_cap_drops;" \
    '    /* note \%       still comment */%    st->sh->tag_cap_drops = 0;'

crlf_row 1 "a commented-out assignment does not count under CRLF" \
    "    ngx_uint_t               tag_cap_drops;" \
    "    // st->sh->tag_cap_drops = 0;"

crlf_row 1 "a PREFIX __attribute__ member is harvested under CRLF" \
    "    __attribute__((aligned(64))) ngx_uint_t slotp;" ""

# ----------------------------------------------------------------------------
# carve-init: THE MEMBER-COUNT PIN (CARVE_INIT_PIN_COUNT).
#
# EXPECTED_MEMBER_COUNT in carve_init_ast.py is the compensating control for
# AST-shape drift across clang majors: collect_initialised() only ever ADDS to
# `found`, so a member vanishing from the INITIALISER harvest fails closed
# (FAIL, or the empty-scan exit 2 if every initialiser vanishes) -- but a
# member vanishing from find_struct_fields() the same way would silently
# shrink the set of members DEMANDED, which is indistinguishable from a clean
# gate. This checks that direction: a member disappearing from the struct
# must fail the pin even though every remaining member is still, correctly,
# initialised -- the member-count assertion is what catches it, nothing else
# in this file does.
#
# The pin is gated on CARVE_INIT_PIN_COUNT=1 (set only by
# ci/tools/lint-carve-init.sh against the real module header) so it cannot
# fire against carve_lint's tiny same-named fixture struct by accident; these
# rows turn it on explicitly and patch EXPECTED_MEMBER_COUNT in the COPIED
# script under $mutroot to match the fixture's own field count, so the
# assertion is exercised without depending on the real module's 67/71.
# shellcheck disable=SC2329  # invoked indirectly, by name, via case_()
pin_lint() {  # pin_lint <expected-count>
    # SC2317: reached indirectly via case_, see carve_lint above.
    # shellcheck disable=SC2317
    env -C "$mutroot" NGX_SRC_TREE=- CARVE_INIT_PIN_COUNT=1 \
        python3 ci/tools/carve_init_ast.py clang src/ngx_http_cache_turbo_shm.c
}

patch_expected_count() {  # patch_expected_count <n>
    python3 - "$mutroot/ci/tools/carve_init_ast.py" "$1" <<'PYEOF'
import re, sys
path, n = sys.argv[1], int(sys.argv[2])
src = open(path).read()
src = re.sub(
    r"EXPECTED_MEMBER_COUNT = \{[^}]*\}",
    f"EXPECTED_MEMBER_COUNT = {{False: {n}, True: {n}}}",
    src,
    count=1,
)
open(path, "w").write(src)
PYEOF
}

# Baseline: `hits` + `_pad_hits` is 2 raw FieldDecls. Pinned to the true count,
# the well-formed fixture must still be clean.
emit_fixture "" ""
patch_expected_count 2
case_ 0 "carve-init: count pin holds when the count matches" pin_lint

# The control: remove a member from the DEMANDED set by pinning to one MORE
# than the fixture actually has (as if a member had disappeared from the AST).
# Every remaining member (hits) is still correctly initialised by
# `emit_fixture`'s own baseline carve body, so nothing else in this checker
# would flag this row -- only the count pin can.
patch_expected_count 3
case_ 1 "carve-init: a member vanishing from the struct fails the pin even though every remaining member is initialised" pin_lint

# Restore the true count so any row added below this block is not silently
# exercising a stale pin.
patch_expected_count 2
case_ 0 "carve-init: count pin restored to the true count is clean again" pin_lint

if [ "$rc" -eq 0 ]; then
    echo "== lint gate selftest: all controls held =="
else
    echo "== lint gate selftest: FAILED ==" >&2
fi
exit "$rc"
