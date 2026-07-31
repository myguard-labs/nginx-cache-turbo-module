#!/usr/bin/env python3
"""AUD-TLSLEAK1: prove a leaked TLS redis fixture cannot survive a later
sibling's .start() failure.

WHY THIS EXISTS
    ci/tools/test_runtime.py's main() starts redis_tls, redis_tls_untrusted
    and redis_tls_expired one after another. The old code shared one
    try/except across all three .start() calls and, on failure, set all
    three local names to None -- including any that had ALREADY started.
    That dropped the outer `finally:`'s only reference to the started
    server, so it never got .stop()'d and kept squatting its port. A
    leaked redis on a fixture port is exactly the failure class this repo
    has been bitten by twice: the NEXT run's redis.stop() silently no-ops
    against the wrong process and its failure reads as unrelated to its
    diff (see memory/labs/nginx-cache-turbo-module/lessons.md).

    The fix lives in test_runtime._start_tls_fixtures(): it tracks only
    what actually started and stops exactly that before disabling the
    group. This script calls that SHIPPED function directly (not a copy)
    against fake servers that bind/release real sockets, so "no listener
    survives" is checked against an actual free port, not a mock call
    count.

USAGE
    python3 ci/tools/test-tls-fixture-cleanup.py

    No nginx/redis binaries, no fixture ports from PORT_OFFSETS -- this is
    a pure unit check of the cleanup ordering and binds ephemeral (port 0)
    sockets, so it cannot collide with a live CI wave on this box.

INPUTS / OUTPUTS
    Exit 0 = the started leg was released and the failure was recorded via
    _skip(). Non-zero = assertion failure (traceback on stderr).

SIDE EFFECTS
    None outside this process: two short-lived loopback listening sockets,
    both closed before exit.
"""
from __future__ import annotations

import pathlib
import socket
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import test_runtime as T  # noqa: E402


class _FakeTLSServer:
    """Stand-in for RedisServer: start() binds a REAL listening socket on an
    OS-assigned loopback port, stop() closes it. Using a real socket (not a
    call-count mock) is what lets the test prove the port is actually free
    afterwards -- a mock stop() could be "called" while the fd stays open."""

    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.sock: socket.socket | None = None
        self.port: int | None = None

    def start(self) -> None:
        if self.fail:
            raise RuntimeError("simulated start() failure")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        self.sock = s
        self.port = s.getsockname()[1]

    def stop(self) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None


def _port_is_free(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def main() -> int:
    first = _FakeTLSServer()
    second = _FakeTLSServer(fail=True)
    skips: list[tuple[str, str]] = []

    def _skip(name: str, reason: str) -> None:
        skips.append((name, reason))

    # Drive the SHIPPED function, not a reimplementation of its logic.
    result = T._start_tls_fixtures(first, second, None, _skip)

    assert result == (None, None, None), (
        f"expected all three fixtures disabled after a mid-sequence "
        f"failure, got {result!r}")
    assert skips, "expected the failure to be recorded via _skip()"
    assert first.port is not None, "first fixture never actually started"
    assert first.sock is None, (
        "AUD-TLSLEAK1 regression: first fixture's socket handle survived "
        "the cleanup path")
    assert _port_is_free(first.port), (
        "AUD-TLSLEAK1 regression: first fixture's listener is still bound "
        f"on port {first.port} after the second fixture's start() raised")

    print("PASS test_start_tls_fixtures_releases_started_leg_on_failure")
    return 0


if __name__ == "__main__":
    sys.exit(main())
