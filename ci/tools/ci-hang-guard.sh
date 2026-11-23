#!/bin/sh
# ci-hang-guard.sh — own a command with a finite deadline and early capture of a
# gdb all-thread backtrace + a SIGQUIT debug dump of the nginx process(es) THIS run
# spawned, before the outer job timeout kills the runner with no evidence.
#
# Motivation: the full ASan single-process suite intermittently wedges the event
# loop (originally suspected as test_shm_refresh_under_pressure/R6b-specific;
# 2026-08-21 showed it is suite-cumulative and lands wherever call ~150 happens
# to fall, not bound to R6b's own pool.map — see memory issues.md). It is rare
# but does reproduce locally, not only on CI. A plain job timeout leaves NO
# backtrace, so the refcount-leak-vs-loop-saturation question can never be
# answered. This guard turns the next occurrence into an uploaded artifact.
#
# Scope: the PID scan and the log snapshot are restricted to the process tree rooted
# at the wrapped command, so a NEIGHBOURING job on a shared self-hosted runner never
# leaks its backtraces/logs into this artifact (CWE-200).
#
# CT_HANG_HARD_SECONDS selects a finite hard bound (default: soft + 300s).
# The Python owner reserves escalation/reaping time within this bound.
# Usage: ci/tools/ci-hang-guard.sh <soft_timeout_s> <artifact_dir> -- <cmd...>
set -eu

# Exec preserves guard PID/signals. Python owns lifecycle even when observation
# is disabled; this shell is re-entered only as an isolated diagnostic child.
if [ "${1:-}" != "--capture" ]; then
    exec python3 "$(dirname "$(readlink -f "$0")")/ci_child_observer.py" --guard "$@"
fi
shift
exec python3 "$(dirname "$(readlink -f "$0")")/ci_hang_capture.py" "$@"
