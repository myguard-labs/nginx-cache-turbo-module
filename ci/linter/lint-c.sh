#!/usr/bin/env bash
# ci/linter/lint-c.sh -- C static analysis for src/*.[ch].
#
# Mirrors .github/workflows/security-scanners.yml exactly:
#   flawfinder  gate at >=4   (below 4 is risky-API grep noise; gating on it
#                              trains everyone to --no-verify)
#   semgrep     gate at >=WARNING with p/c + p/security-audit
# plus cppcheck, which CI does not run and which is cheap enough locally.
#
# If a threshold moves in that workflow, move it here in the SAME commit --
# otherwise local-green stops predicting remote-green, which is the only
# reason this script exists.
#
# NOT here, deliberately:
#   clang-tidy -- needs ngx_auto_config.h, i.e. a configured nginx tree. A
#                 local hook cannot assume one, and a check that skips itself
#                 when the tree is missing is a vacuous gate. CI-only.
#
# Usage: ci/linter/lint-c.sh [files...]     (no args => LINT_MODE, default all)
# Env:   LINT_MODE=staged|all
#        LINT_SKIP_SEMGREP=1   explicit, loud opt-out for slow machines
#
# Extend: add a scanner as one more block below; keep the CI mirror comment
# accurate or the header above becomes a lie.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

mapfile -t FILES < <(lint_files '^src/.*\.[ch]$' "$@")
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-c: no C files to check"; exit 0; }

# SCOPED OUT OF HOOK MODE, and this is not a dropped gate (adoption step 35).
#
# All three scanners below -- flawfinder, cppcheck, semgrep -- also run as their
# own hooks in .pre-commit-config.yaml, at byte-identical thresholds and over the
# same '^src/.*\.[ch]$' selector. .githooks/pre-commit invokes BOTH gates (it has
# to: core.hooksPath replaces .git/hooks/, so the pre-commit config is only
# reachable because this hook calls it), which means a staged C commit was
# running each scanner TWICE.
#
# Measured 2026-08-10 on a one-file staged commit: 7.4s total, of which lint-c
# was 7.01s and semgrep alone 6.44s -- against step 35's ~2s budget. The cost is
# semgrep's rule-pack load, which is per-invocation and does not shrink with the
# file count, so --jobs/--metrics tuning (already applied) cannot recover it.
# Paying it twice for one verdict is the whole overrun.
#
# What does NOT change: LINT_MODE=all still runs everything (that is what
# `ci/linter/run-all.sh` does by hand and what `--all` means), and CI is
# unaffected -- security-scanners.yml owns these three on the PR, which is why
# lint.yml's LINT_ONLY excludes "c" in the first place. So every scanner still
# gates every commit and every PR; only the duplicate invocation is gone.
#
# If the pre-commit hooks are ever removed, delete this block in the same commit
# -- otherwise C stops being scanned at commit time and nothing says so.
if [ "${LINT_MODE:-all}" = "staged" ] && [ "$#" -eq 0 ] \
   && [ -f "$(repo_root)/.pre-commit-config.yaml" ] \
   && grep -q 'id: semgrep' "$(repo_root)/.pre-commit-config.yaml"; then
    echo "lint-c: ${#FILES[@]} file(s) -- deferred to the .pre-commit-config.yaml" \
         "hooks, which run flawfinder/cppcheck/semgrep at the same thresholds"
    exit 0
fi

echo "lint-c: ${#FILES[@]} file(s)"
rc=0

need flawfinder "apt-get install flawfinder"
say "flawfinder (gate >=4)"
flawfinder --minlevel=4 --error-level=4 --quiet "${FILES[@]}" || rc=1

need cppcheck "apt-get install cppcheck"
say "cppcheck (error,warning)"
# --error-exitcode=1 makes any reported id fail. missingInclude/unusedFunction
# are suppressed: this is a module compiled INTO nginx, so its headers and its
# ngx_http_* callbacks are never resolvable or called from this tree alone.
# RETARGET (adoption step 32): -I src -DNGX_PTR_SIZE=8 and the
# unusedStructMember suppression mirror the cppcheck hook already in this
# repo's .pre-commit-config.yaml. Both gates must run the SAME cppcheck
# invocation or local-green stops predicting remote-green (step 33's threshold
# mirror); move one, move both.
#
# -DNGX_PTR_SIZE=8 is load-bearing, not cosmetic. cppcheck parses each header
# standalone, without nginx's objs/ngx_auto_config.h, so the deliberate H-1
# guard at src/ngx_http_cache_turbo_module.h:644 (`#error "NGX_PTR_SIZE is not
# defined"`) fires and cppcheck reports it as a preprocessorErrorDirective.
# That #error is correct code doing its job -- the finding is an artifact of
# parsing outside a configured tree. Defining the macro is the honest fix; the
# alternative, --suppress=preprocessorErrorDirective, would also blind this
# gate to every OTHER #error in the module.
cppcheck --quiet --error-exitcode=1 \
    --enable=warning,performance,portability \
    --inline-suppr \
    -I src -DNGX_PTR_SIZE=8 \
    --suppress=missingInclude --suppress=missingIncludeSystem \
    --suppress=unusedFunction --suppress=unknownMacro \
    --suppress=unusedStructMember \
    --suppress=normalCheckLevelMaxBranches \
    "${FILES[@]}" || rc=1

if [ -n "${LINT_SKIP_SEMGREP:-}" ]; then
    warn "semgrep SKIPPED via LINT_SKIP_SEMGREP -- CI still gates on it"
else
    need semgrep "pipx install semgrep==1.169.0"
    say "semgrep (gate >=WARNING)"
    # --quiet is deliberately absent: it hides semgrep-core's own crash text
    # (io_uring/RLIMIT_MEMLOCK) and turns a diagnosable failure into a bare
    # exit 2 that reads like a real finding.
    #
    # --jobs=1 is a correctness flag, not a speed flag. semgrep-core defaults to
    # one OCaml domain per core (32 here), each of which opens its own io_uring
    # ring against the 8 MB RLIMIT_MEMLOCK this host shares with the self-hosted
    # CI runners. Under runner load it exhausts and semgrep-core dies with
    # `Unix_error: Cannot allocate memory io_uring_queue_init` -> exit 2, which
    # this script reports as a finding. Observed 3/3 crashed on a 3-file scan
    # while runners were busy, 0/3 on an idle box: a load-dependent false RED.
    # src/ is three files, so the parallelism was buying nothing to begin with.
    #
    # --metrics=off: no scan-summary POST to semgrep.dev. Measured 2.76s -> 1.27s
    # on this tree, i.e. more than half the wall clock was that upload.
    semgrep scan --config p/c --config p/security-audit \
        --severity=WARNING --severity=ERROR --error \
        --jobs=1 --metrics=off "${FILES[@]}" || rc=1
fi

exit "$rc"
