"""Capture owned nginx diagnostics; retain pidfds from discovery through SIGQUIT.

Discovery snapshots ancestry and start times. A pidfd is opened before checking
that start time again, so a replaced numeric PID cannot authorize signalling.
Log descriptors are enumerated through a /proc directory descriptor whose start
identity is rechecked after open, never through a later lookup of the number.
A log is retained only when the descriptor this process opened names error.log,
or a rotated or deleted error.log, so a rotation during discovery keeps it.
Each snapshot keeps at most LOG_TAIL bytes from the end of its log.
Build can select passive capture with CT_HANG_QUIT=0; its hard deadline remains
owned by ci_guard_lifecycle, independently of this best-effort diagnostic child.
The owner passes its absolute CLOCK_MONOTONIC cleanup instant in
CT_HANG_CLEANUP_AT; debuggers and the SIGQUIT tail finish before it.
"""

import contextlib
import errno
import math
import os
import select
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

PROC = Path('/proc')
SELF_FD = '/proc/self/fd'  # Our own descriptors: their targets cannot change.
TERM_GRACE = .2  # The last part of a debugger allowance: TERM, then KILL.
# timeout(1) reports its own timer as 124, or 128+KILL after --kill-after.
TIMER_EXPIRED = (124, 128 + signal.SIGKILL)
LOG_TAIL = 16 << 20  # Bytes kept per error log, so one large log cannot starve the rest.


def parse_stat(record):
    """Return (parent, start) from stat bytes; the task name may hold any bytes."""
    fields = record.rsplit(b') ', 1)[1].decode('ascii').split()
    return int(fields[1]), fields[19]


def process_stat(path):
    return parse_stat(path.read_bytes())


def read_at(directory, name):
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC, dir_fd=directory)
    with os.fdopen(fd, 'rb') as stream:
        return stream.read()


def exited(fd):
    """Report whether a pidfd's process exited; poll() has no FD_SETSIZE limit."""
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    events = poller.poll(0)
    # A closed descriptor raises like select() did; HUP/ERR count as exited.
    if any(mask & select.POLLNVAL for _, mask in events):
        raise OSError(errno.EBADF, 'pidfd closed')
    return bool(events)


def debug(command, stream, end):
    """Run one debugger whose launch and run share the absolute deadline end.

    The last TERM_GRACE seconds stop it: TERM makes the timeout(1) wrapper forward
    TERM to gdb, KILL it after --kill-after and exit only once gdb is reaped.
    KILL of the direct child is the fallback. A sudo leader does not relay a
    signal from its own process group, so under sudo timeout's timer bounds gdb.
    A launch that ends after end - TERM_GRACE still gets the full grace, so the
    wrapper can reap gdb: stopping may end TERM_GRACE after launch, inside the
    snapshot margin that capture() reserves before the owner's cleanup.
    """
    with subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT) as process:
        try:
            # Popen returns after exec; that launch latency is charged to end.
            return process.wait(timeout=max(0., end - TERM_GRACE - time.monotonic()))
        except BaseException as error:
            if isinstance(error, subprocess.TimeoutExpired):
                process.terminate()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=TERM_GRACE)
            process.kill()  # No-op once the wrapper has been reaped.
            process.wait()
            raise


class _Bounded:
    """Reader that returns at most limit bytes of the wrapped stream."""

    def __init__(self, stream, limit):
        self.stream, self.left = stream, limit

    def read(self, size=-1):
        size = self.left if size < 0 else min(size, self.left)
        data = self.stream.read(size) if size else b''
        self.left -= len(data)
        return data


def copy_tail(source, target):
    """Copy at most LOG_TAIL bytes from the end of source; mark what is omitted."""
    start = max(0, os.fstat(source.fileno()).st_size - LOG_TAIL)
    if start:
        target.write(f'ci-hang-guard: first {start} bytes omitted\n'.encode())
    source.seek(start)
    # The limit also bounds a log that keeps growing during the copy.
    shutil.copyfileobj(_Bounded(source, LOG_TAIL), target)


def discover(root):
    """Return pid/pidfd/identity records selected by one checked ancestry snapshot."""
    snapshot = {}
    for path in PROC.glob('[0-9]*/stat'):
        try:
            snapshot[int(path.parent.name)] = process_stat(path)
        except (OSError, ValueError, IndexError):
            continue
    owned = {root}
    while True:
        children = {pid for pid, (parent, _) in snapshot.items() if parent in owned}
        if children <= owned:
            break
        owned |= children
    selected = []
    try:
        for pid in sorted(owned & snapshot.keys()):
            fd = None
            ancestors = []
            try:
                fd = os.pidfd_open(pid)
                path = PROC / str(pid)
                if (process_stat(path / 'stat') != snapshot[pid]
                        or (path / 'comm').read_text(encoding='ascii').strip() != 'nginx'):
                    continue
                parent = pid
                while parent != root:
                    parent = snapshot[parent][0]
                    if parent not in snapshot:
                        raise ValueError('missing ancestry identity')
                    ancestor = os.pidfd_open(parent)
                    ancestors.append(ancestor)
                    if process_stat(PROC / str(parent) / 'stat') != snapshot[parent]:
                        raise ValueError('changed ancestry identity')
                if any(exited(ancestor) for ancestor in ancestors):
                    continue
                selected.append((pid, fd, snapshot[pid]))
                fd = None  # Ownership transfers to the returned record.
            except (OSError, ValueError, IndexError):
                continue
            finally:
                if fd is not None:
                    os.close(fd)
                for ancestor in ancestors:
                    os.close(ancestor)
        nginx = {pid for pid, _, _ in selected}
        return sorted(selected, key=lambda item: (snapshot[item[0]][0] not in nginx, item[0]))
    except BaseException:
        for _, fd, _ in selected:
            os.close(fd)
        raise


def error_log_name(target):
    """Whether a descriptor target is error.log, or that file rotated or deleted."""
    name = os.path.basename(target).removesuffix(' (deleted)')
    return name == 'error.log' or name.startswith(('error.log.', 'error.log-'))


def open_logs(descriptors, logs):
    """Retain unseen regular error.log inodes named by one pinned fd directory."""
    for name in sorted(os.listdir(descriptors)):
        stream = None
        try:
            if (not error_log_name(os.readlink(name, dir_fd=descriptors))
                    or not stat.S_ISREG(os.stat(name, dir_fd=descriptors).st_mode)):
                continue
            # The opener transfers ownership: a rejected fd (a directory) is closed.
            stream = open(name, 'rb', opener=lambda path, _flags: os.open(
                path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=descriptors))
            # nginx may reuse the number after readlink; judge the file we opened.
            # Its own name is one observation, so no reuse sequence can pass it;
            # a rotation renames it to a name that still qualifies.
            if not error_log_name(os.readlink(f'{SELF_FD}/{stream.fileno()}')):
                continue
            status = os.fstat(stream.fileno())
            key = (status.st_dev, status.st_ino)
            if stat.S_ISREG(status.st_mode) and key not in logs:
                logs[key] = stream
                stream = None
        except OSError:
            continue
        finally:
            if stream is not None:
                stream.close()


def error_logs(processes):
    logs = {}
    try:
        for pid, fd, identity in processes:
            directory = descriptors = None
            try:
                # This descriptor pins one process. Its start identity, name and
                # live pidfd prove that it is the discovered one, not a reused PID.
                directory = os.open(PROC / str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                if (parse_stat(read_at(directory, 'stat'))[1] != identity[1]
                        or read_at(directory, 'comm').strip() != b'nginx'
                        or exited(fd)):
                    continue
                descriptors = os.open('fd', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
                                      dir_fd=directory)
                open_logs(descriptors, logs)
            except (OSError, ValueError, IndexError, UnicodeError):
                continue
            finally:
                for handle in (descriptors, directory):
                    if handle is not None:
                        os.close(handle)
        return list(logs.values())
    except BaseException:
        for stream in logs.values():
            stream.close()
        raise


def cleanup_cutoff(started, soft):
    """Return the owner's cleanup instant; standalone use derives it from hard."""
    try:
        cutoff = float(os.environ.get('CT_HANG_CLEANUP_AT', 'nan'))
    except ValueError:
        cutoff = math.nan  # Malformed owner input selects the standalone bound.
    if math.isfinite(cutoff):
        return cutoff
    hard = float(os.environ.get('CT_HANG_HARD_SECONDS', str(float(soft) + 300)))
    return started + hard - float(soft) - 2 * min(2., hard / 5)


def capture(root, directory, soft):
    started = time.monotonic()
    directory.mkdir(parents=True, exist_ok=True)
    print(f'ci-hang-guard: soft timeout {soft}s hit — capturing nginx state', file=sys.stderr)
    breadcrumb = os.environ.get('CT_TEST_BREADCRUMB')
    if breadcrumb:
        try:
            shutil.copyfile(breadcrumb, directory / 'hanging-test.txt')
        except OSError:
            pass
    processes = discover(root)
    logs = []
    try:
        if not processes:
            print(f'ci-hang-guard: no nginx under pid {root}', file=sys.stderr)
        logs = error_logs(processes)  # Retain the selected inodes across rotation/shutdown.
        shutdown = os.environ.get('CT_HANG_QUIT', '1') != '0'
        # The owner's cleanup instant already reserves its TERM/KILL windows.
        # Reserve the optional dump tail and a snapshot margin before it. All
        # debuggers share this one deadline, measured from owner start.
        cutoff = cleanup_cutoff(started, soft) - .5
        until = cutoff - (5 if shutdown else 0)
        privilege = ['sudo', '-n'] if shutil.which('sudo') else []
        for index, (pid, fd, _) in enumerate(processes):
            if exited(fd):
                continue
            try:
                identity = process_stat(PROC / str(pid) / 'stat')
            except (OSError, ValueError, IndexError):
                continue
            print(f'ci-hang-guard: gdb pid={pid}', file=sys.stderr)
            try:
                stream = (directory / f'gdb-nginx-{pid}.txt').open('w')
            except OSError as error:
                # One unusable output path must not cost the other targets or logs.
                print(f'ci-hang-guard: gdb output unavailable pid={pid}: {error}',
                      file=sys.stderr)
                continue
            try:
                with stream:
                    try:
                        # GDB accepts only numeric PIDs. Recheck the retained pidfd
                        # and start identity immediately before launch; PID reuse
                        # during sudo/timeout/GDB startup remains a residual window.
                        if (exited(fd)
                                or process_stat(PROC / str(pid) / 'stat') != identity):
                            stream.write('debugger skipped: process identity changed\n')
                            continue
                        # Measure after preflight, so its latency is charged to the budget.
                        now = time.monotonic()
                        allowance = min(10., max(0., until - now) / (len(processes) - index))
                        if allowance <= .25:
                            stream.write('debugger skipped: capture budget exhausted\n')
                            continue
                        # timeout runs at gdb's privilege and --foreground retains
                        # the capture group. Killing only a sudo leader is not a
                        # cleanup mechanism for its privileged debugger child.
                        status = debug([
                            *privilege, 'timeout', '--foreground', '--signal=TERM',
                            '--kill-after=0.1s', f'{allowance - .2:.6f}s',
                            'gdb', '-batch', '-p', str(pid), '-ex', 'set pagination off',
                            '-ex', 'info threads', '-ex', 'thread apply all bt full',
                            '-ex', 'print ngx_cycle->free_connection_n',
                            '-ex', 'print ngx_cycle->connection_n', '-ex', 'detach', '-ex', 'quit',
                        ], stream, now + allowance)
                        # The inner timer can end gdb just before our own wait expires.
                        if status in TIMER_EXPIRED:
                            stream.write('debugger exceeded capture budget\n')
                    except subprocess.TimeoutExpired:
                        stream.write('debugger exceeded capture budget\n')
                    except OSError as error:
                        stream.write(f'debugger unavailable: {error}\n')
            except OSError as error:
                # A buffered write can fail at flush on close (for example ENOSPC).
                # Report on stderr: this stream is the one that just failed.
                print(f'ci-hang-guard: gdb output failed pid={pid}: {error}',
                      file=sys.stderr)
        # Every debugger completes before any shutdown signal. pidfds still name
        # the discovery identities even if a target exited and its PID was reused.
        if shutdown:
            for pid, fd, _ in processes:
                # Never start a shutdown after the tail cutoff; owner cleanup follows.
                if time.monotonic() >= cutoff:
                    print(f'ci-hang-guard: SIGQUIT skipped pid={pid}: cleanup cutoff passed',
                          file=sys.stderr)
                    continue
                try:
                    signal.pidfd_send_signal(fd, signal.SIGQUIT)
                    print(f'ci-hang-guard: SIGQUIT pid={pid}', file=sys.stderr)
                except OSError as error:
                    print(f'ci-hang-guard: SIGQUIT unavailable pid={pid}: {error}', file=sys.stderr)
            # A late capture shortens its dump wait; it never passes cleanup.
            time.sleep(max(0., min(5., cutoff - time.monotonic())))
        for index, source in enumerate(logs, 1):
            try:
                with (directory / f'error-{index}.log').open('wb') as target:
                    copy_tail(source, target)
            except OSError:
                pass
    finally:
        for source in logs:
            source.close()
        for _, fd, _ in processes:
            os.close(fd)


if __name__ == '__main__':
    capture(int(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])
