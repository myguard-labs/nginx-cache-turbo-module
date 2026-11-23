#!/usr/bin/env python3
"""Close nginx's single-process check->wait signal window in the ASan CI build.

ngx_single_process_cycle() tests ngx_terminate/ngx_quit after
ngx_process_events_and_timers() returns, with every signal unblocked. A
SIGTERM handled after that test and before the next epoll_wait(-1) only sets
the flag, and the wait never returns: the --single-process ASan suite then
hangs with "signal 15 ... exiting" logged and no "exit" (issue
CT-ASAN-SP-SIGTERM-STOP-HANG; master mode re-signals and SIGKILLs, so it hides
the same race).

This disposable CI correction blocks the stop/reload/reopen signals for the
single-process loop and lets the epoll wait unblock them atomically with
epoll_pwait(..., original mask): a signal is either handled before the flag
test or interrupts the wait. It is applied only by ci-build.sh's nginx `asan`
mode, never to a shipped build.

Event modules: only epoll gets the atomic wait. The loop blocks signals only
when the active module is epoll (NGX_USE_EPOLL_EVENT, set by ngx_epoll_init,
which init_process runs before the loop and a single-process reload never
re-runs). Under poll/select the loop is left exactly stock, because blocking
signals around a plain poll()/select() would lose them for good.

Every anchor is exact upstream text that must occur once. Unknown, drifted or
partially transformed sources are refused; an already transformed tree is
recognized without writes. Files are published by atomic replacement only
after all transforms succeeded in memory.
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
from pathlib import Path

CYCLE_C = Path("src/os/unix/ngx_process_cycle.c")
CYCLE_H = Path("src/os/unix/ngx_process_cycle.h")
EPOLL_C = Path("src/event/modules/ngx_epoll_module.c")

LOOP_ANCHOR = (
    "    for ( ;; ) {\n"
    '        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");\n'
    "\n"
    "        ngx_process_events_and_timers(cycle);\n"
    "\n"
    "        if (ngx_terminate || ngx_quit) {\n"
)

LOOP_BLOCK = (
    "    /*\n"
    "     * CI-only (cache-turbo ci/tools/single_process_sigmask.py): keep the\n"
    "     * stop/reload signals blocked between the flag tests below and let\n"
    "     * epoll_pwait() unblock them atomically, so a signal handled after the\n"
    "     * test can no longer be lost before an infinite wait. Other event\n"
    "     * modules keep the stock unblocked loop.\n"
    "     */\n"
    "\n"
    "    if (ngx_event_flags & NGX_USE_EPOLL_EVENT) {\n"
    "        sigset_t  set;\n"
    "\n"
    "        sigemptyset(&set);\n"
    "        sigaddset(&set, SIGINT);\n"
    "        sigaddset(&set, ngx_signal_value(NGX_RECONFIGURE_SIGNAL));\n"
    "        sigaddset(&set, ngx_signal_value(NGX_REOPEN_SIGNAL));\n"
    "        sigaddset(&set, ngx_signal_value(NGX_TERMINATE_SIGNAL));\n"
    "        sigaddset(&set, ngx_signal_value(NGX_SHUTDOWN_SIGNAL));\n"
    "\n"
    "        if (sigprocmask(SIG_BLOCK, &set, &ngx_single_wait_mask) == -1) {\n"
    "            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,\n"
    '                          "sigprocmask() failed");\n'
    "\n"
    "        } else {\n"
    "            ngx_single_wait_masked = 1;\n"
    "        }\n"
    "    }\n"
    "\n"
)

GLOBAL_ANCHOR = "ngx_uint_t    ngx_process;\n"
GLOBAL_LINES = (
    "sigset_t      ngx_single_wait_mask;\n"
    "ngx_uint_t    ngx_single_wait_masked;\n"
)

EXTERN_ANCHOR = "extern ngx_uint_t      ngx_process;\n"
EXTERN_LINES = (
    "extern sigset_t        ngx_single_wait_mask;\n"
    "extern ngx_uint_t      ngx_single_wait_masked;\n"
)

WAIT_ANCHOR = (
    "    events = epoll_wait(ep, event_list, (int) nevents, timer);\n"
    "\n"
    "    err = (events == -1) ? ngx_errno : 0;\n"
)
WAIT_REPLACEMENT = (
    "    if (ngx_single_wait_masked) {\n"
    "        events = epoll_pwait(ep, event_list, (int) nevents, timer,\n"
    "                             &ngx_single_wait_mask);\n"
    "\n"
    "    } else {\n"
    "        events = epoll_wait(ep, event_list, (int) nevents, timer);\n"
    "    }\n"
    "\n"
    "    err = (events == -1) ? ngx_errno : 0;\n"
)

# (file, exact upstream anchor, exact replacement). Each anchor occurs once in
# pristine source; each replacement occurs once in transformed source.
EDITS = (
    (CYCLE_C, GLOBAL_ANCHOR, GLOBAL_ANCHOR + GLOBAL_LINES),
    (CYCLE_C, LOOP_ANCHOR, LOOP_BLOCK + LOOP_ANCHOR),
    (CYCLE_H, EXTERN_ANCHOR, EXTERN_ANCHOR + EXTERN_LINES),
    (EPOLL_C, WAIT_ANCHOR, WAIT_REPLACEMENT),
)


def _read(source_root: Path, name: Path) -> str:
    target = source_root / name
    if target.is_symlink() or not target.is_file():
        raise ValueError(f"{name} must be a regular file")
    return target.read_text()


def _state(text: str, anchor: str, replacement: str) -> str:
    """Classify one edit as patched, pristine, or drift.

    Patched means the replacement occurs once and the anchor occurs only as
    often as the replacement itself contributes it (once for the retaining
    edits, zero for WAIT). Any extra pristine anchor elsewhere is drift.
    """
    if text.count(replacement) == 1:
        if text.count(anchor) == replacement.count(anchor):
            return "patched"
        return "drift"
    if replacement not in text and text.count(anchor) == 1:
        return "pristine"
    return "drift"


def _classify(texts: dict[Path, str]) -> str:
    """Return the tree state: pristine or patched; refuse drift or mixed trees."""
    states = [_state(texts[name], anchor, new) for name, anchor, new in EDITS]
    if "drift" in states:
        bad = [str(EDITS[i][0]) for i, s in enumerate(states) if s == "drift"]
        raise ValueError("anchor drift in " + ", ".join(bad) + "; refusing source")
    if len(set(states)) != 1:
        raise ValueError("partially transformed source; refusing mixed tree")
    return states[0]


def _publish(target: Path, text: str) -> None:
    """Atomically replace one file, keeping the extracted file's own mode."""
    fd, staged = tempfile.mkstemp(prefix=".sp-sigmask-", dir=target.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(text)
        os.chmod(staged, stat.S_IMODE(target.stat().st_mode))
        os.replace(staged, target)
    except BaseException:
        Path(staged).unlink(missing_ok=True)
        raise


def apply(source_root: Path) -> str:
    """Transform pristine source, or recognize an already transformed tree."""
    texts = {name: _read(source_root, name) for name in dict.fromkeys(e[0] for e in EDITS)}
    if _classify(texts) == "patched":
        return "already patched"
    for name, anchor, new in EDITS:
        texts[name] = texts[name].replace(anchor, new, 1)
    if _classify(texts) != "patched":
        raise ValueError("transform did not apply")
    # Publish only after every edit succeeded; each file swap is atomic and an
    # interrupted publication is a mixed tree, which the next run refuses.
    for name, text in texts.items():
        _publish(source_root / name, text)
    return "applied"


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: single_process_sigmask.py SOURCE_ROOT", file=sys.stderr)
        return 2
    try:
        verdict = apply(Path(sys.argv[1]))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"single-process sigmask correction: {exc}", file=sys.stderr)
        return 1
    print(f"single-process sigmask correction: {verdict}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
