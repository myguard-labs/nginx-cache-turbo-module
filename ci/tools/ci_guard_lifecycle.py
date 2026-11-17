"""Linux private command ownership for the CI guard.

RUNNING -> DRAINING on command exit, signal, caller/guard death or deadline;
DRAINING -> REAPED only after TERM/KILL and waits on owned children. A dedicated
subreaper owns the command and diagnostics in separate sessions. It watches a
CLOEXEC socket for guard death and a pidfd for caller death; neither is a PID
rediscovery. A nondefault SIGCHLD reaper is refused before launching anything.
Command/session leaders remain unreaped until the final group
signal, preventing PGID reuse. Adopted children are signalled through pidfds.
Diagnostics never become command descendants. On ordinary command exit, an
active capture may finish only until the reserved cleanup window; the command's
status remains authoritative. Signals/parent death abort that wait immediately.
Cleanup is bounded, including
stubborn/escaped descendants; inability to establish ownership fails closed.

SIGKILL of the guard is handled by the independent owner. SIGKILL of that owner,
both processes killed together, uninterruptible kernel waits and host death
cannot be guaranteed: absent completion stays UNKNOWN, never a cleanup receipt.
This is cooperative CI process cleanup, not containment of hostile fork bombs.
"""

import ctypes
import json
import math
import os
import select
import signal
import socket
import subprocess
import time
from pathlib import Path


def validate_deadlines(soft, hard):
    """Require finite capture time before the reserved escalation window."""
    if (not math.isfinite(hard) or hard <= 0
            or (soft is not None and (not math.isfinite(soft) or soft < 0
                                     or soft >= hard - 2 * min(2., hard / 5)))):
        raise ValueError("invalid guard deadline")


class OwnedProcess:
    """Retain the session leader's wait identity until group signalling ends."""

    def __init__(self, command, env=None):
        self.child = subprocess.Popen(command, env=env, start_new_session=True)
        self.pid = self.child.pid
        self.reaped = False

    def exited(self):
        if self.reaped:
            return True
        return os.waitid(os.P_PID, self.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None

    def send(self, sig):
        if self.reaped:
            raise RuntimeError("group ownership released")
        try:
            os.killpg(self.pid, sig)
        except ProcessLookupError:
            pass

    def reap(self):
        if not self.exited():
            return None
        code = self.child.wait()
        self.reaped = True
        return code


def _children():
    # Only the dedicated subreaper's children, never a global process scan.
    return [int(pid) for pid in Path(f"/proc/self/task/{os.getpid()}/children").read_text(encoding="ascii").split()]


def _adopted(anchors, sig):
    """Signal/reap adopted owned descendants without releasing group anchors."""
    pending = False
    for pid in _children():
        if pid in anchors:
            continue
        # A direct unreaped child cannot have its PID reused under this owner.
        fd = os.pidfd_open(pid)
        try:
            signal.pidfd_send_signal(fd, sig)
            waited, _ = os.waitpid(pid, os.WNOHANG)
            pending |= waited == 0
        finally:
            os.close(fd)
    return pending


def _drain(processes, grace, deadline):
    anchors = {p.pid for p in processes}
    failed = False

    def adopted(sig):
        nonlocal failed
        try:
            return _adopted(anchors, sig)
        except OSError:
            failed = True
            return True  # Still send KILL to retained groups after a /proc/pidfd error.

    # Keep every anchor (even a zombie) until both group signals are finished.
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for process in processes:
            process.send(sig)
        end = min(deadline, time.monotonic() + grace)
        while True:
            pending = adopted(sig)
            if all(p.exited() for p in processes) and not pending:
                # Other group members may still be alive even if the leader died.
                # Always perform the KILL phase before releasing its identity.
                break
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(.02, remaining))
    # KILL has now been sent while all PGID anchors were retained. Drain newly
    # adopted descendants until quiescence, then reap anchors LAST.
    while time.monotonic() < deadline:
        pending = adopted(signal.SIGKILL)
        if all(p.exited() for p in processes) and not pending:
            try:
                if set(_children()) <= anchors:
                    codes = [p.reap() for p in processes]
                    return None if failed else codes
            except OSError:
                failed = True
        time.sleep(min(.02, max(0, deadline - time.monotonic())))
    # Reap exited leaders even when adoption evidence failed. No group signal
    # is legal after this point; an incomplete cleanup cannot produce a receipt.
    for process in processes:
        process.reap()
    return None


def _owner(wire, caller_fd, command, env, soft, hard, capture):
    processes = []
    result = {"status": 125, "code": None, "reason": "ownership failure"}
    stop = []
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda number, frame: stop.append(number))
    starting = False
    start = time.monotonic()
    grace = min(2., hard / 5)
    deadline = start + hard
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
            raise OSError(ctypes.get_errno(), "cannot own orphaned descendants")
        # Do not launch if the caller/guard has already died during setup.
        if select.select([wire, caller_fd], [], [], 0)[0]:
            raise OSError("parent unavailable before launch")
        starting = True
        command_process = OwnedProcess(command, env)
        processes.append(command_process)
        wire.send(json.dumps({"child": command_process.pid}).encode())
        captured = False
        while True:
            now = time.monotonic()
            readable = select.select([wire, caller_fd], [], [], 0)[0]
            if stop:
                result.update(status=128 + stop[0], reason="owner signal")
                break
            if caller_fd in readable:
                result.update(reason="caller death")
                break
            if wire in readable:
                data = wire.recv(1024)
                if not data:
                    result.update(reason="guard death")
                else:
                    number = json.loads(data)["signal"]
                    result.update(status=128 + number, reason="guard signal")
                break
            command_exited = command_process.exited()
            # An already-started capture has a post-signal snapshot tail. Keep
            # its session owned until it finishes or cleanup must start; an
            # ordinary command exit must not truncate that evidence.
            cleanup_due = now >= deadline - 2 * grace
            if command_exited and (len(processes) == 1 or processes[-1].exited() or cleanup_due):
                result.update(reason="command exit")
                break
            # Reserve both escalation/reaping phases INSIDE the hard bound.
            if cleanup_due:
                result.update(status=124, reason="hard deadline")
                break
            if not command_exited and soft is not None and not captured and now >= start + soft:
                captured = True
                if capture is not None:
                    processes.append(OwnedProcess(capture(command_process.pid)))
            time.sleep(min(.02, max(0, deadline - 2 * grace - time.monotonic())))
    except OSError as error:
        if starting and not processes:
            result.update(status=127 if isinstance(error, FileNotFoundError) else 126,
                          reason="command not started")
        else:
            result.update(reason="owner I/O failure")
    finally:
        if processes:
            # Normal/signal cleanup also has a finite bound; never extend hard.
            codes = _drain(processes, grace, min(deadline, time.monotonic() + 2 * grace))
            if codes is not None:
                result["code"] = codes[0]
                if result["reason"] == "command exit":
                    result["status"] = 128 - codes[0] if codes[0] < 0 else codes[0]
            else:
                result.update(status=125, code=None, reason="cleanup incomplete")
        try:
            wire.send(json.dumps(result).encode())
        except OSError:
            pass  # Guard death: cleanup still ran, but no observer remains.


def run_owned(command, env, on_start, *, soft=None, hard=600., capture=None):
    """Return status plus the owner's direct-child wait observation, if complete."""
    validate_deadlines(soft, hard)
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        return {"status": 125, "code": None, "reason": "external child reaper"}
    # Acquire caller identity before forking; a changed parent is not equivalent.
    caller = os.getppid()
    try:
        caller_fd = os.pidfd_open(caller)
    except OSError:
        return {"status": 125, "code": None, "reason": "caller identity unavailable"}
    if caller != os.getppid():
        os.close(caller_fd)
        return {"status": 125, "code": None, "reason": "caller changed"}
    parent_wire, child_wire = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    previous = {}
    owner_pid = None
    result = {"status": 125, "code": None, "reason": "owner lost"}
    requested = []
    try:
        owner_pid = os.fork()
        if owner_pid == 0:
            parent_wire.close()
            try:
                _owner(child_wire, caller_fd, command, env, soft, hard, capture)
            finally:
                os._exit(0)
        child_wire.close()
        os.close(caller_fd)
        caller_fd = None

        def forward(number, _frame):
            if not requested:
                requested.append(number)
                try:
                    parent_wire.send(json.dumps({"signal": number}).encode())
                except OSError:
                    pass

        for sig in (signal.SIGTERM, signal.SIGINT):
            previous[sig] = signal.signal(sig, forward)
        while True:
            data = parent_wire.recv(4096)
            if not data:
                break
            record = json.loads(data)
            if "child" in record:
                on_start(record["child"])
            else:
                result = record
                break
    finally:
        parent_wire.close()  # Also requests cleanup on callback/error unwinding.
        child_wire.close()
        if caller_fd is not None:
            os.close(caller_fd)
        if owner_pid:
            os.waitpid(owner_pid, 0)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    if requested:
        result["status"] = 128 + requested[0]
    return result
