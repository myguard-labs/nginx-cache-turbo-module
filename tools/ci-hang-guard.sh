#!/bin/sh
# ci-hang-guard.sh — run a command with a soft watchdog that, on hang, captures a
# gdb all-thread backtrace + a SIGQUIT debug dump of the nginx process(es) THIS run
# spawned, before the outer job timeout kills the runner with no evidence.
#
# Motivation: test_shm_refresh_under_pressure (R6b) intermittently wedges the
# single-process ASan nginx event loop on CI only (never reproduced locally in 46
# clean runs — see memory issues.md). A plain job timeout leaves NO backtrace, so
# the refcount-leak-vs-loop-saturation question can never be answered. This guard
# turns the next occurrence into an uploaded artifact.
#
# Scope: the PID scan and the log snapshot are restricted to the process tree rooted
# at the wrapped command, so a NEIGHBOURING job on a shared self-hosted runner never
# leaks its backtraces/logs into this artifact (CWE-200).
#
# Usage: tools/ci-hang-guard.sh <soft_timeout_s> <artifact_dir> -- <cmd...>
set -eu

SOFT="$1"; shift
ARTDIR="$1"; shift
[ "$1" = "--" ] && shift
mkdir -p "$ARTDIR"

# gdb needs to attach: on a hosted runner with ptrace_scope=1 a same-uid attach is
# refused, and sudo is passwordless there. Fall back to bare gdb if sudo is absent.
if command -v sudo >/dev/null 2>&1; then
    GDB="sudo gdb"
else
    GDB="gdb"
fi

# Collect the PIDs of every descendant of $root (inclusive) by walking PPID links in
# /proc. POSIX sh, no pgrep --ns / ps --ppid tree dependency.
descendants() {
    root=$1
    # field 4 of /proc/<pid>/stat is PPID; field 2 (comm) may contain spaces/parens,
    # so key off the ")" that terminates comm and count back from there.
    for st in /proc/[0-9]*/stat; do
        pid=$(basename "$(dirname "$st")")
        ppid=$(sed -e 's/^[0-9]* (.*) [A-Za-z] //' "$st" 2>/dev/null | cut -d' ' -f1)
        echo "$pid $ppid"
    done > /tmp/cihg-ppids.$$
    # BFS from root over the ppid map.
    frontier=$root
    seen=" $root "
    while [ -n "$frontier" ]; do
        next=""
        for p in $frontier; do
            kids=$(awk -v par="$p" '$2==par{print $1}' /tmp/cihg-ppids.$$)
            for k in $kids; do
                case "$seen" in *" $k "*) : ;; *) seen="$seen$k "; next="$next $k" ;; esac
            done
        done
        frontier=$next
    done
    rm -f /tmp/cihg-ppids.$$
    echo "$seen"
}

# nginx PIDs that are descendants of the wrapped command.
nginx_pids_under() {
    all=$(descendants "$1")
    for p in $all; do
        [ -r "/proc/$p/comm" ] || continue
        [ "$(cat "/proc/$p/comm" 2>/dev/null)" = "nginx" ] && echo "$p"
    done
}

# Run the real command in the background; watch its wall time.
"$@" &
CMD_PID=$!

captured=0
elapsed=0
while kill -0 "$CMD_PID" 2>/dev/null; do
    sleep 5
    elapsed=$((elapsed + 5))
    if [ "$elapsed" -ge "$SOFT" ] && [ "$captured" -eq 0 ]; then
        captured=1
        echo "ci-hang-guard: soft timeout ${SOFT}s hit — capturing nginx state" >&2
        pids=$(nginx_pids_under "$CMD_PID")
        [ -z "$pids" ] && echo "ci-hang-guard: no nginx under pid $CMD_PID" >&2
        roots=""
        for pid in $pids; do
            echo "ci-hang-guard: gdb + SIGQUIT pid=$pid" >&2
            # Record the -p prefix WHILE the proc is alive (SIGQUIT below may reap it;
            # cwd is unreliable — nginx may chdir to /). error.log = <prefix>/logs.
            root=$(tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null \
                   | awk 'p{print;exit} $0=="-p"{p=1}')
            [ -n "$root" ] && [ -d "$root" ] && roots="$roots $root"
            # -batch (NOT -batch-silent): -batch-silent suppresses the command output
            # (info threads / bt / print) that is the whole point of the capture.
            $GDB -batch -p "$pid" \
                -ex "set pagination off" \
                -ex "info threads" \
                -ex "thread apply all bt full" \
                -ex "print ngx_cycle->free_connection_n" \
                -ex "print ngx_cycle->connection_n" \
                -ex "detach" -ex "quit" \
                > "$ARTDIR/gdb-nginx-$pid.txt" 2>&1 || true
            # SIGQUIT makes a --with-debug nginx log posted-request / connection state.
            kill -QUIT "$pid" 2>/dev/null || true
        done
        sleep 5
        # Snapshot logs from ONLY our nginx' own prefix dirs (recorded above), so no
        # neighbouring job's /tmp logs are collected (CWE-200).
        n=0
        for root in $roots; do
            n=$((n + 1))
            find "$root" -maxdepth 4 -name error.log 2>/dev/null | while read -r f; do
                cp "$f" "$ARTDIR/error-$n.log" 2>/dev/null || true
            done
        done
    fi
done

wait "$CMD_PID"
