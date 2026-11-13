#!/usr/bin/env python3
"""Observe the lifecycle owner's command child, never suite success.

States are UNKNOWN until the owner reports its Popen.wait over a private socket.
Only this observer writes identity/termination files, in a fresh private directory.
The unpredictable run ID is passed through the command environment to the runtime
journal; (run ID, observer PID, child PID) identifies the owned command even if
its PID is later reused. Shell/pipeline descendants share the run ID, but the
receipt describes the direct command only, not any descendant's wait status.
Publication closes a private partial file before exclusively linking its final
name: any open/write/flush/close/link failure leaves the receipt absent/UNKNOWN.
Missing or mismatched evidence stays UNKNOWN. Exit zero never certifies tests.
The lifecycle owner enforces bounded descendant cleanup and a hard deadline.
A killed observer cannot publish completion. Owner/host SIGKILL and kernel
uninterruptible waits remain outside the guarantee; missing evidence is UNKNOWN.
"""

import json
import os
import pathlib
import secrets
import sys
import tempfile

from ci_guard_lifecycle import run_owned, validate_deadlines


def _publish(path, record):
    """Expose a complete, successfully closed file without replacing old evidence."""
    partial = path.with_suffix(".partial")
    try:
        data = json.dumps(record, sort_keys=True).encode() + b"\n"
        with partial.open("xb") as stream:
            if stream.write(data) != len(data):
                return False
            stream.flush()
        os.link(partial, path)
    except OSError:
        return False
    return True


def consume_termination(data, identity):
    """Classify an observation against the parent's independently held identity."""
    try:
        record = json.loads(data)
    except (TypeError, ValueError, UnicodeError):
        return "UNKNOWN"
    if (not isinstance(identity, dict)
            or set(identity) != {"run_id", "observer_pid", "child_pid"}
            or not isinstance(identity["run_id"], str)
            or len(identity["run_id"]) != 32
            or any(c not in "0123456789abcdef" for c in identity["run_id"])
            or any(type(identity[key]) is not int or identity[key] <= 0
                   for key in ("observer_pid", "child_pid"))):
        return "UNKNOWN"
    if not isinstance(record, dict) or record.get("identity") != identity:
        return "UNKNOWN"
    code = record.get("returncode")
    if (type(record.get("version")) is not int or record["version"] != 1
            or any(type(record["identity"][key]) is not int
                   for key in ("observer_pid", "child_pid"))
            or record.get("observed") is not True
            or type(code) is not int or not -64 <= code <= 255):
        return "UNKNOWN"
    return "SIGNALED" if code < 0 else "EXITED"


def _report(message):
    try:
        print(message, flush=True)
    except OSError:
        pass  # A closed output pipe must not replace the command's exit status.


def observe(directory, command, *, enabled=True, soft=None, hard=600., capture=None):
    run_id = secrets.token_hex(16)
    env = dict(os.environ, CT_OUTCOME_RUN_ID=run_id) if enabled else None
    run_dir = None
    if enabled:
        try:
            run_dir = pathlib.Path(tempfile.mkdtemp(prefix="termination-", dir=directory))
        except OSError:
            pass  # Receipt failure must not prevent the original command from running.
    identity = None
    ready = False

    def started(pid):
        nonlocal identity, ready
        identity = {"run_id": run_id, "observer_pid": os.getpid(), "child_pid": pid}
        ready = run_dir is not None and _publish(run_dir / "identity.json", identity)

    result = run_owned(command, env, started, soft=soft, hard=hard, capture=capture)
    if enabled:
        decision = "UNKNOWN"
        record = {"version": 1, "identity": identity, "observed": True,
                  "returncode": result["code"]}
        if result["code"] is not None and ready and _publish(run_dir / "termination.json", record):
            decision = consume_termination(json.dumps(record), identity)
        _report(f"TERMINATION {decision} run={run_id} receipt={run_dir} reason={result['reason']}")
    return result["status"]


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--guard":
        try:
            soft = float(sys.argv[2])
            directory = sys.argv[3]
            hard = float(os.environ.get("CT_HANG_HARD_SECONDS", str(soft + 300)))
            validate_deadlines(soft, hard)
            if sys.argv[4] != "--" or not sys.argv[5:]:
                raise ValueError("invalid guard deadline or command")
        except (IndexError, ValueError):
            print("usage: ci-hang-guard.sh soft_seconds artifact_dir -- command; "
                  "finite hard deadline must leave time for capture and cleanup", file=sys.stderr)
            return 2
        pathlib.Path(directory).mkdir(parents=True, exist_ok=True)
        guard = pathlib.Path(__file__).with_name("ci-hang-guard.sh")
        return observe(directory, sys.argv[5:], enabled=os.environ.get("CT_OUTCOME_OBSERVE") == "1",
                       soft=soft, hard=hard,
                       capture=lambda pid: ["sh", str(guard), "--capture", str(pid),
                                            directory, str(soft)])
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        print("usage: ci_child_observer.py artifact_dir -- command [args...]", file=sys.stderr)
        return 2
    return observe(sys.argv[1], sys.argv[3:])


if __name__ == "__main__":
    sys.exit(main())
