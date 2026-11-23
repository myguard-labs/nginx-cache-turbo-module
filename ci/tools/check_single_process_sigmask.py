#!/usr/bin/env python3
"""Verify the single-process sigmask correction independently of its helper.

  check_single_process_sigmask.py --expect patched  SOURCE_ROOT
  check_single_process_sigmask.py --expect pristine SOURCE_ROOT

`patched` (ci-build.sh asan mode, after single_process_sigmask.py) inspects
the real function bodies, not the helper's own replacement table: the loop
must block the five stop/reload signals behind the epoll guard before
`for ( ;; )`, and ngx_epoll_process_events must wait with epoll_pwait() and
the saved mask when, and only when, that block succeeded. Nothing outside the
three edited files may reference the correction.

`pristine` (every other nginx mode) refuses a tree the asan build already
transformed, so a shared BUILD_ROOT cannot leak the CI-only core change into
a debug, coverage or benchmark binary.

Exit 0 when the tree matches, 1 with every finding otherwise, 2 on usage.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

CYCLE_C = Path("src/os/unix/ngx_process_cycle.c")
CYCLE_H = Path("src/os/unix/ngx_process_cycle.h")
EPOLL_C = Path("src/event/modules/ngx_epoll_module.c")
TOKEN = "ngx_single_wait_mask"

SINGLE_START = "void\nngx_single_process_cycle(ngx_cycle_t *cycle)\n{\n"
EPOLL_START = (
    "static ngx_int_t\n"
    "ngx_epoll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,"
    " ngx_uint_t flags)\n{\n"
)
GUARD_OPEN = "if (ngx_event_flags & NGX_USE_EPOLL_EVENT) {"
GUARD_BODY = (
    "sigprocmask(SIG_BLOCK, &set, &ngx_single_wait_mask) == -1",
    "ngx_single_wait_masked = 1;",
)
WAIT_OPEN = "if (ngx_single_wait_masked) {"
SIGNALS = (
    "SIGINT",
    "ngx_signal_value(NGX_RECONFIGURE_SIGNAL)",
    "ngx_signal_value(NGX_REOPEN_SIGNAL)",
    "ngx_signal_value(NGX_TERMINATE_SIGNAL)",
    "ngx_signal_value(NGX_SHUTDOWN_SIGNAL)",
)


def body(text: str, start: str) -> str | None:
    """Return one top-level C function body, or None when not exactly one."""
    if text.count(start) != 1:
        return None
    begin = text.index(start)
    end = text.find("\n}\n", begin)
    return None if end < 0 else text[begin:end]


def braced(text: str, opener: str, start: int = 0) -> tuple[str, int] | None:
    """Inner text and end offset of the brace block that `opener` ends with.

    `opener` must end in `{`. Returns None when it is absent or unbalanced.
    """
    begin = text.find(opener, start)
    if begin < 0:
        return None
    first = begin + len(opener)
    depth = 1
    for pos in range(first, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[first:pos], pos + 1
    return None


def ordered(text: str, parts: tuple[str, ...], unique: tuple[str, ...]) -> bool:
    """Parts occur in order; each `unique` string occurs exactly once."""
    if any(text.count(part) != 1 for part in unique):
        return False
    pos = 0
    for part in parts:
        pos = text.find(part, pos)
        if pos < 0:
            return False
        pos += len(part)
    return True


def _check_loop(cycle: str) -> list[str]:
    """The single-process loop blocks the five signals behind the epoll guard."""
    single = body(cycle, SINGLE_START)
    if single is None:
        return ["ngx_single_process_cycle() boundary not found once"]
    problems = []
    if not ordered(single, (
        "if (ngx_event_flags & NGX_USE_EPOLL_EVENT) {",
        "sigprocmask(SIG_BLOCK, &set, &ngx_single_wait_mask) == -1",
        "ngx_single_wait_masked = 1;",
        "    for ( ;; ) {",
        "ngx_process_events_and_timers(cycle);",
        "if (ngx_terminate || ngx_quit) {",
    ), unique=(
        "NGX_USE_EPOLL_EVENT",
        "sigprocmask(SIG_BLOCK,",
        "ngx_single_wait_masked = 1;",
        "    for ( ;; ) {",
    )):
        problems.append("single-process loop is not epoll-guarded and masked")
    guard = braced(single, GUARD_OPEN)
    inner = guard[0] if guard else ""
    # Token order alone accepts an empty guard followed by an unconditional
    # mask block: the mask operation must sit inside the guard braces.
    if guard is None or any(part not in inner for part in GUARD_BODY):
        problems.append("epoll guard does not contain the mask operation")
    for sig in SIGNALS:
        if inner.count(f"sigaddset(&set, {sig});") != 1:
            problems.append(f"single-process mask does not block {sig}")
    return problems


def _check_globals(cycle: str, header: str) -> list[str]:
    """The saved mask and its flag are defined once and declared extern once."""
    problems = []
    for decl in ("\nsigset_t      ngx_single_wait_mask;\n",
                 "\nngx_uint_t    ngx_single_wait_masked;\n"):
        if cycle.count(decl) != 1:
            problems.append(f"{CYCLE_C}: missing definition {decl.strip()}")
    for decl in ("extern sigset_t        ngx_single_wait_mask;\n",
                 "extern ngx_uint_t      ngx_single_wait_masked;\n"):
        if header.count(decl) != 1:
            problems.append(f"{CYCLE_H}: missing {decl.strip()}")
    return problems


def _check_wait(epoll_source: str) -> list[str]:
    """The epoll wait restores the saved mask atomically only when masked."""
    epoll = body(epoll_source, EPOLL_START)
    if epoll is None:
        return ["ngx_epoll_process_events() boundary not found once"]
    problems = []
    first = braced(epoll, WAIT_OPEN)
    if first is None or first[0].count("= epoll_pwait(") != 1 \
            or "&ngx_single_wait_mask);" not in first[0]:
        problems.append("epoll wait does not use the saved mask when masked")
    else:
        # The else must be the same conditional's, and the error assignment
        # must follow the whole conditional; a second unconditional wait or a
        # detached `if (0) {} else {}` breaks that.
        tail = epoll[first[1]:]
        other = braced(tail, " else {") if tail.startswith(" else {") else None
        if other is None or other[0].count("= epoll_wait(") != 1 \
                or not tail[other[1]:].lstrip().startswith(
                    "\n    err = (events == -1) ? ngx_errno : 0;".lstrip()) \
                or epoll.count("= epoll_wait(") != 1 \
                or epoll.count("= epoll_pwait(") != 1:
            problems.append("epoll wait does not use the saved mask when masked")
    return problems


def _references(root: Path) -> list[Path]:
    """Every source file under src/ that mentions the correction."""
    return [path for path in sorted((root / "src").rglob("*.[ch]"))
            if TOKEN in path.read_text(errors="replace")]


def check_patched(root: Path) -> list[str]:
    cycle = (root / CYCLE_C).read_text()
    problems = _check_loop(cycle)
    problems += _check_globals(cycle, (root / CYCLE_H).read_text())
    problems += _check_wait((root / EPOLL_C).read_text())
    allowed = {root / CYCLE_C, root / CYCLE_H, root / EPOLL_C}
    problems += [f"{path.relative_to(root)}: unexpected use of {TOKEN}"
                 for path in _references(root) if path not in allowed]
    return problems


def check_pristine(root: Path) -> list[str]:
    return [
        f"{path.relative_to(root)}: carries the CI-only asan sigmask correction;"
        " use a separate BUILD_ROOT or re-extract the tree"
        for path in _references(root)
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--expect", choices=("patched", "pristine"), required=True)
    parser.add_argument("source_root", type=Path)
    args = parser.parse_args()
    if not (args.source_root / "src").is_dir():
        print(f"single-process sigmask check: {args.source_root}/src missing",
              file=sys.stderr)
        return 1
    try:
        check = check_patched if args.expect == "patched" else check_pristine
        problems = check(args.source_root)
    except (OSError, UnicodeDecodeError) as exc:
        problems = [str(exc)]
    for problem in problems:
        print(f"single-process sigmask check: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"single-process sigmask check: {args.expect} ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
