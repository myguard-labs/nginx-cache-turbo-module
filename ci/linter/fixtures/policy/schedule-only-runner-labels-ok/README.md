# fixture: schedule-only-runner-labels-ok

The positive control for `schedule-only-runner-labels`, and the reason that one
means anything.

Same shape — schedule-only, not reachable from any pull request — but the pool
labels are spelled correctly and the selector is an approved `TRUST_SPLITS`
entry. Expected: `runners` exit 0.

Retargeted for nginx-cache-turbo-module (adoption step 32): the selector here
is this repo's own `["self-hosted","builder02"]`, not the skeleton's
three-label `lxc` variant. `TRUST_SPLITS` in ci/linter/workflow_policy.py was
narrowed to the one selector this repo actually uses, so the skeleton's
spelling is correctly REJECTED here — carried over unedited this positive
control failed, which is the fixture doing its job.

Without this, a red on the typo fixture is equally consistent with "the label
check caught the typo" and "non-PR-reachable workflows are now flagged
unconditionally". Those are different checks and only one of them is wanted; the
pair separates them.

It is a separate fixture rather than a second workflow inside the red one
because `policy_` asserts an exit STATUS, not a finding count. A clean workflow
sitting beside a dirty one in the same tree changes nothing about the exit code
and would prove nothing.
