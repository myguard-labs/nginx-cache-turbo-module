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
# Runs in about a second. Every case but the carve-init block at the end is
# dispatcher-level (LINT_ONLY values are either bogus or rejected before
# dispatch), so no linter needs to be installed for those. The carve-init cases
# DO invoke that one checker for real, against a generated two-file fixture
# tree rather than the real src/, which is what keeps them inside the budget.
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
mkdir -p "$badroot/.github/workflows"
printf 'on: [pull_request\njobs: {\n' > "$badroot/.github/workflows/broken.yml"
case_ 2 "policy runners: unparsable YAML is exit 2, not clean" \
    env "WORKFLOW_POLICY_ROOT=$badroot" python3 ci/linter/workflow_policy.py runners

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
# within the one-second budget by running against a generated fixture tree of
# two small files rather than the real src/, so no build and no scan of the
# 34k-line source is involved.
mutroot="$(mktemp -d)"
trap 'rm -rf "$badroot" "$mutroot"' EXIT
mkdir -p "$mutroot/src" "$mutroot/ci/tools"
cp ci/tools/lint-carve-init.sh "$mutroot/ci/tools/"

# A minimal shctx and carve block: the smallest input that exercises the real
# member-harvest and initialiser-harvest paths.
emit_fixture() {
    # $1 = extra member line, $2 = extra carve line
    cat > "$mutroot/src/ngx_http_cache_turbo_module.h" <<EOF
typedef struct ngx_http_cache_turbo_shctx_s {
    ngx_atomic_t             hits;
    u_char                   _pad_hits[24];
${1:-}
} ngx_http_cache_turbo_shctx_t;
EOF
    cat > "$mutroot/src/ngx_http_cache_turbo_shm.c" <<EOF
ngx_http_cache_turbo_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    st->sh = ngx_slab_alloc(pool, sizeof(ngx_http_cache_turbo_shctx_t));
    st->sh->hits = 0;
${2:-}
    return NGX_OK;
}
EOF
}

# Baseline: the fixture as written must be CLEAN. Without this, every case
# below could be passing for the wrong reason (a fixture the checker cannot
# parse at all also "fails").
emit_fixture "" ""
case_ 0 "carve-init: well-formed fixture is clean" \
    env -C "$mutroot" ./ci/tools/lint-carve-init.sh

# The original MAJOR: a member initialised only outside the carve block. This
# is the mutation that passed before the scan window was narrowed.
emit_fixture "    ngx_uint_t               tag_cap_drops;" ""
case_ 1 "carve-init: member never initialised is caught" \
    env -C "$mutroot" ./ci/tools/lint-carve-init.sh

# Compound assignment must not read as initialisation.
emit_fixture "    ngx_uint_t               tag_cap_drops;" \
             "    st->sh->tag_cap_drops += 0;"
case_ 1 "carve-init: compound assignment is not initialisation" \
    env -C "$mutroot" ./ci/tools/lint-carve-init.sh

# Multi-declarator lines must register EVERY name, not only the last.
emit_fixture "    ngx_uint_t               zzz_a, zzz_b;" \
             "    st->sh->zzz_b = 0;"
case_ 1 "carve-init: multi-declarator hides no member" \
    env -C "$mutroot" ./ci/tools/lint-carve-init.sh

# Taking a member address for a pure READ is not initialisation.
emit_fixture "    ngx_uint_t               tag_cap_drops;" \
             "    (void) memcmp(&st->sh->tag_cap_drops, \"x\", 8);"
case_ 1 "carve-init: address-of in a non-initialiser call does not count" \
    env -C "$mutroot" ./ci/tools/lint-carve-init.sh

# The _pad* exemption is a TYPE decision: a _pad*-named member of a
# non-u_char-array type must FAIL rather than be silently exempted.
emit_fixture "    ngx_uint_t               _pad_but_real;" ""
case_ 1 "carve-init: _pad* exemption requires a u_char array type" \
    env -C "$mutroot" ./ci/tools/lint-carve-init.sh

# ...and a genuine pad must still be exempt, or the check above is just noise.
emit_fixture "    u_char                   _pad_legit[8];" ""
case_ 0 "carve-init: a genuine u_char pad stays exempt" \
    env -C "$mutroot" ./ci/tools/lint-carve-init.sh

# Per-declarator, not per-line: an array pad and a SCALAR pad on one
# declaration line. The scalar must not inherit the array's exemption.
emit_fixture "    u_char                   _pad_a[8], _pad_b;" ""
case_ 1 "carve-init: _pad exemption is per-declarator, not per-line" \
    env -C "$mutroot" ./ci/tools/lint-carve-init.sh

# An allowlisted initialiser and an unrelated pure read on ONE line: the read
# must not borrow the initialiser's credit.
emit_fixture "    ngx_uint_t               tag_cap_drops;" \
             "    ngx_queue_init(&st->sh->lru); (void) memcmp(&st->sh->tag_cap_drops, \"x\", 8);"
case_ 1 "carve-init: address-of harvest is scoped to the call, not the line" \
    env -C "$mutroot" ./ci/tools/lint-carve-init.sh

# ...and an allowlisted initialiser alone must still count, or the scoping
# above is just a way to break every legitimate helper call.
emit_fixture "    ngx_queue_t              lru;" \
             "    ngx_queue_init(&st->sh->lru);"
case_ 0 "carve-init: an allowlisted initialiser still counts" \
    env -C "$mutroot" ./ci/tools/lint-carve-init.sh

# A structurally broken header is "could not run" (2), never clean.
printf 'struct something_else {\n    int x;\n};\n' \
    > "$mutroot/src/ngx_http_cache_turbo_module.h"
case_ 2 "carve-init: undelimitable struct is exit 2, not clean" \
    env -C "$mutroot" ./ci/tools/lint-carve-init.sh

if [ "$rc" -eq 0 ]; then
    echo "== lint gate selftest: all controls held =="
else
    echo "== lint gate selftest: FAILED ==" >&2
fi
exit "$rc"
