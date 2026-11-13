#!/usr/bin/env python3
"""Observe only the command child owned by this parent, never suite success.

States are UNKNOWN until Popen.wait observes EXITED or SIGNALED. Only this
parent writes the identity and termination files, in a fresh private directory.
The unpredictable run ID is passed through the command environment to the runtime
journal; (run ID, observer PID, child PID) identifies the owned command even if
its PID is later reused. Shell/pipeline descendants share the run ID, but the
receipt describes the direct command only, not any descendant's wait status.
Publication closes a private partial file before exclusively linking its final
name: any open/write/flush/close/link failure leaves the receipt absent/UNKNOWN.
Missing or mismatched evidence stays UNKNOWN. Exit zero never certifies tests.
Parent death, descendant cleanup, deadlines and crash durability are separate.
"""

import json
import os
import pathlib
import secrets
import subprocess
import sys
import tempfile


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


def observe(directory, command):
    run_id = secrets.token_hex(16)
    env = dict(os.environ, CT_OUTCOME_RUN_ID=run_id)
    run_dir = None
    try:
        run_dir = pathlib.Path(tempfile.mkdtemp(prefix="termination-", dir=directory))
    except OSError:
        pass  # Receipt failure must not prevent the original command from running.
    try:
        child = subprocess.Popen(command, env=env)
    except OSError as error:
        _report("TERMINATION UNKNOWN (command not started)")
        return 127 if isinstance(error, FileNotFoundError) else 126
    identity = {"run_id": run_id, "observer_pid": os.getpid(), "child_pid": child.pid}
    ready = run_dir is not None and _publish(run_dir / "identity.json", identity)
    code = child.wait()  # Popen owns/reaps this child; no PID rediscovery or reuse race.
    record = {"version": 1, "identity": identity, "observed": True, "returncode": code}
    decision = "UNKNOWN"
    if ready and _publish(run_dir / "termination.json", record):
        decision = consume_termination(json.dumps(record), identity)
    _report(f"TERMINATION {decision} run={run_id} child={child.pid} receipt={run_dir}")
    return 128 - code if code < 0 else code


def main():
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        print("usage: ci_child_observer.py artifact_dir -- command [args...]", file=sys.stderr)
        return 2
    return observe(sys.argv[1], sys.argv[3:])


if __name__ == "__main__":
    sys.exit(main())
