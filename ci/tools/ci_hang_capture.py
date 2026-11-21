"""Capture owned nginx diagnostics; retain pidfds from discovery through SIGQUIT.

Discovery snapshots ancestry and start times. A pidfd is opened before checking
that start time again, so a replaced numeric PID cannot authorize signalling.
Build can select passive capture with CT_HANG_QUIT=0; its hard deadline remains
owned by ci_guard_lifecycle, independently of this best-effort diagnostic child.
"""

import os
import select
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

PROC = Path('/proc')


def process_stat(path):
    fields = path.read_text(encoding='ascii').rsplit(') ', 1)[1].split()
    return int(fields[1]), fields[19]


def discover(root):
    """Return pid/role/pidfd records selected by one checked ancestry snapshot."""
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
            try:
                fd = os.pidfd_open(pid)
                path = PROC / str(pid)
                if (process_stat(path / 'stat') != snapshot[pid]
                        or (path / 'comm').read_text(encoding='ascii').strip() != 'nginx'):
                    continue
                selected.append((pid, fd))
                fd = None  # Ownership transfers to the returned record.
            except (OSError, ValueError, IndexError):
                continue
            finally:
                if fd is not None:
                    os.close(fd)
        nginx = {pid for pid, _ in selected}
        return sorted(selected, key=lambda item: (snapshot[item[0]][0] not in nginx, item[0]))
    except BaseException:
        for _, fd in selected:
            os.close(fd)
        raise


def error_logs(processes):
    logs = set()
    for pid, _ in processes:
        for descriptor in (PROC / str(pid) / 'fd').glob('*'):
            try:
                path = descriptor.resolve(strict=True)
                if path.name == 'error.log' and path.is_file():
                    logs.add(path)
            except OSError:
                continue
    return sorted(logs)


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
    try:
        if not processes:
            print(f'ci-hang-guard: no nginx under pid {root}', file=sys.stderr)
        logs = error_logs(processes)  # Resolve descriptors before shutdown.
        shutdown = os.environ.get('CT_HANG_QUIT', '1') != '0'
        hard = float(os.environ.get('CT_HANG_HARD_SECONDS', str(float(soft) + 300)))
        # Reserve the owner's TERM/KILL windows, optional dump tail, and a
        # snapshot margin. All debuggers share this one deadline.
        until = started + max(0., hard - float(soft) - 2 * min(2., hard / 5)
                              - (5 if shutdown else 0) - .5)
        privilege = ['sudo', '-n'] if shutil.which('sudo') else []
        for index, (pid, fd) in enumerate(processes):
            if select.select([fd], [], [], 0)[0]:
                continue
            allowance = min(10., max(0., until - time.monotonic()) / (len(processes) - index))
            print(f'ci-hang-guard: gdb pid={pid}', file=sys.stderr)
            with (directory / f'gdb-nginx-{pid}.txt').open('w') as stream:
                if allowance <= .25:
                    stream.write('debugger skipped: capture budget exhausted\n')
                    continue
                try:
                    # timeout runs at gdb's privilege and --foreground retains
                    # the capture group. Killing only a sudo leader is not a
                    # cleanup mechanism for its privileged debugger child.
                    subprocess.run([
                        *privilege, 'timeout', '--foreground', '--signal=TERM',
                        '--kill-after=0.1s', f'{allowance - .2:.6f}s',
                        'gdb', '-batch', '-p', str(pid), '-ex', 'set pagination off',
                        '-ex', 'info threads', '-ex', 'thread apply all bt full',
                        '-ex', 'print ngx_cycle->free_connection_n',
                        '-ex', 'print ngx_cycle->connection_n', '-ex', 'detach', '-ex', 'quit',
                    ], stdout=stream, stderr=subprocess.STDOUT, check=False,
                       timeout=allowance)
                except subprocess.TimeoutExpired:
                    stream.write('debugger exceeded capture budget\n')
                except OSError as error:
                    stream.write(f'debugger unavailable: {error}\n')
        # Every debugger completes before any shutdown signal. pidfds still name
        # the discovery identities even if a target exited and its PID was reused.
        if shutdown:
            for pid, fd in processes:
                try:
                    signal.pidfd_send_signal(fd, signal.SIGQUIT)
                    print(f'ci-hang-guard: SIGQUIT pid={pid}', file=sys.stderr)
                except OSError as error:
                    print(f'ci-hang-guard: SIGQUIT unavailable pid={pid}: {error}', file=sys.stderr)
            time.sleep(5)
        for index, path in enumerate(logs, 1):
            try:
                shutil.copyfile(path, directory / f'error-{index}.log')
            except OSError:
                pass
    finally:
        for _, fd in processes:
            os.close(fd)


if __name__ == '__main__':
    capture(int(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])
