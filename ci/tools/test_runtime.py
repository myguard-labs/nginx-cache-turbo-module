#!/usr/bin/env python3
"""End-to-end tests for ngx_http_cache_turbo_module.

REQUIRED: The module MUST be built with -DNGX_HTTP_CACHE_TURBO_TEST_FAULTS=1.
This script's config builder emits cache_turbo_test_* directives that are only
valid in TEST_FAULTS builds. Running the suite against a production (non-TEST_FAULTS)
module will fail at nginx startup with: unknown directive "cache_turbo_test_*".
See CONTRIBUTING.md § Tests for the correct build command.

Covers v1/v1.1 features and the regressions logged in
memory/nginx+angie/cache-turbo/issues.md:

  R1  serve must not hold the shm lock (concurrency does not serialise/deadlock)
  R2  header fidelity: Content-Type + arbitrary headers survive a HIT
  R3  background refresh subrequest reaches origin (origin counter advances)
  R4  single-flight: many readers of a stale key cause ~one origin regen
  R6  LRU eviction under a full zone
  B*  build issues are covered by the build job (strict -Werror compile)

Each request to the origin returns a unique, monotonic body so a HIT (same
body) is distinguishable from a MISS/regen (new body). The origin also counts
how many times it was actually hit, which is how we assert single-flight.
"""

from __future__ import annotations

import argparse
import atexit
import collections
import concurrent.futures
import email.utils
import hashlib
import http.client
import http.server
import json
import math
import os
import pathlib
import re
import shlex
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid

# A test that raises before stop() would orphan every child we spawned:
# an nginx master (or redis/memcached) keeps listening on its test port,
# which collides with later runs of any repo sharing the runner. Track
# every Popen and reap survivors at interpreter exit.
_SPAWNED: list[subprocess.Popen] = []


def _track(proc: subprocess.Popen) -> subprocess.Popen:
    _SPAWNED.append(proc)
    return proc


def _reap_spawned() -> None:
    for proc in _SPAWNED:
        if proc.poll() is None:
            proc.terminate()
    deadline = time.monotonic() + 5
    for proc in _SPAWNED:
        if proc.poll() is None:
            try:
                proc.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                proc.kill()


# AUD-CIPORT3: single registry every fixture port -- main()'s visible
# allocation block AND the ad-hoc ports a handful of test bodies stand up on
# their own (a second nginx instance, a fake dirty memcached) -- must draw
# from. All offsets are relative to args.port (== ng.port for the primary
# instance). A collision here is invisible to anyone reading only the
# allocation block in main(), which is exactly how #167 claimed +25 for
# redis_tls_untrusted while test_mc_dirty_reply_not_pooled() already owned it
# via `ng.memcached_port + 1` -- and only found out ~12 minutes into a CI run
# via "OSError: [Errno 98] Address already in use". _check_port_registry()
# turns that into an immediate, named startup failure instead.
PORT_OFFSETS: dict[str, int] = {
    "origin": 11,
    "redis": 21,
    "redis_auth": 22,
    "redis_tls": 23,
    "memcached": 24,
    "mc_dirty_reply": 25,  # test_mc_dirty_reply_not_pooled(): ng.port + this
    "l2_cross_instance_fill_b": 5,       # test_l2_cross_instance_fill()
    "l2_memcached_cross_instance_fill_b": 6,  # test_l2_memcached_cross_instance_fill()
    "redis_tls_untrusted": 27,
    "redis_tls_expired": 28,
    # AUD-PURGE-HONESTY1: deliberately NEVER bound. Reserved here so the
    # registry check keeps any future fixture off it -- the "L2 is down" test
    # needs a port that reliably REFUSES, and a port nobody reserved is a port
    # somebody eventually binds.
    "redis_dead": 29,
}


def _check_port_registry(offsets: dict[str, int]) -> None:
    """Abort loudly, at startup, if two named fixtures claim the same
    args.port offset -- instead of one of them silently failing to bind
    minutes later inside an unrelated test."""
    seen: dict[int, str] = {}
    dupes: list[str] = []
    for name, offset in offsets.items():
        if offset in seen:
            dupes.append(
                f"offset +{offset}: {seen[offset]!r} and {name!r}")
        else:
            seen[offset] = name
    if dupes:
        raise SystemExit(
            "FIXTURE PORT REGISTRY COLLISION -- refusing to start: "
            + "; ".join(dupes))


def _start_tls_fixtures(redis_tls, redis_tls_untrusted, redis_tls_expired,
                         _skip) -> tuple:
    """Start the three TLS redis fixtures, one at a time.

    AUD-TLSLEAK1: the old code shared one try/except across all three
    .start() calls and, on failure, unconditionally set all three names to
    None -- including any that HAD already started. That dropped the only
    reference the outer finally: needed to call .stop() on it, so an already
    -up TLS redis kept squatting its port for the rest of the process (and,
    on this box, into the NEXT run). Track only what actually started and
    stop exactly that on the way out, before disabling the whole TLS group.
    """
    started: list = []
    try:
        redis_tls.start()
        started.append(redis_tls)
        if redis_tls_untrusted is not None:
            redis_tls_untrusted.start()
            started.append(redis_tls_untrusted)
        if redis_tls_expired is not None:
            redis_tls_expired.start()
            started.append(redis_tls_expired)
        return redis_tls, redis_tls_untrusted, redis_tls_expired
    except Exception as e:
        _skip("redis_tls", f"start() failed: {e}")
        for srv in started:
            srv.stop()
        return None, None, None


atexit.register(_reap_spawned)


SANITIZER_MARKERS = (
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
    "ERROR SUMMARY:",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nginx-binary", required=True)
    parser.add_argument("--module")
    parser.add_argument("--runner", default="")
    parser.add_argument("--single-process", action="store_true")
    parser.add_argument("--fault-injection", action="store_true",
                        help="enable CI-only cached-header allocation failures")
    # CI-3: set when the binary is ASan/UBSan-instrumented. Lets a test opt out of
    # the run when it stresses nginx CORE code (not our module) that trips a known
    # core sanitizer false positive — e.g. the stacked proxy_cache file-write path.
    parser.add_argument("--sanitizer", action="store_true")
    parser.add_argument("--port", type=int, default=18880)
    parser.add_argument("--redis-server")  # accepted; used by v2 L2 tests
    parser.add_argument("--memcached-server")  # v13: memcached L2 backend tests
    return parser.parse_args()


# --------------------------------------------------------------------------- #
# DIAG: socket-flake attribution (see memory/labs/nginx-cache-turbo-module/
# issues.md, "open socket left in connection" at shutdown). nginx tags that
# alert with *NNNN = c->number, its cumulative connection counter, bumped once
# per accepted client connection AND once per upstream connect
# (ngx_event_accept.c / ngx_event_connect.c both fetch_add the SAME
# ngx_connection_counter). The harness is the only client and runs the origin,
# so it observes both increment sources: every client open we make bumps
# _NGX_CLIENT_CONNS, and Origin.hits counts the upstream requests nginx proxies
# (origin has no keepalive pool, so 1 request == 1 upstream connect). Their sum
# tracks c->number, letting a per-test snapshot bracket a shutdown *NNNN into
# the owning test. This is pure instrumentation: it never relaxes the guard.
_NGX_CLIENT_CONNS = 0


def _bump_conn() -> None:
    """Count one client-side connection opened to the nginx port."""
    global _NGX_CLIENT_CONNS
    _NGX_CLIENT_CONNS += 1


# (name, cum_before, cum_after) per instrumented test, where cum tracks
# c->number = client accepts + upstream connects. Populated by _instrument().
_SPANS: list[tuple[str, int, int]] = []
_ORIGIN_REF: "Origin | None" = None

# Breadcrumb file: the wrapper writes "<test> <cursor>" here on ENTER and
# "DONE <test>" on exit. If the suite hangs (R6b), the file names the test that
# never finished, so ci-hang-guard.sh can label the gdb backtrace with the
# culprit instead of only a nginx PID. Path from env so the guard can find it.
_BREADCRUMB = os.environ.get("CT_TEST_BREADCRUMB")


def _write_breadcrumb(text: str) -> None:
    if not _BREADCRUMB:
        return
    try:
        with open(_BREADCRUMB, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    except OSError:
        pass


def _conn_cursor() -> int:
    """Best estimate of nginx's current c->number: every client connection we
    opened plus every upstream request the origin served (no origin keepalive,
    so one served request == one upstream connect)."""
    origin_hits = _ORIGIN_REF.hits if _ORIGIN_REF is not None else 0
    return _NGX_CLIENT_CONNS + origin_hits


def _instrument(origin: "Origin") -> None:
    """Wrap every module-level test_* function so each records the c->number
    cursor before and after it runs. Nested test_* calls just produce nested
    spans; the narrowest span that brackets an alert is the most specific
    attribution. Idempotent-safe: called once from main() before run_all."""
    global _ORIGIN_REF
    _ORIGIN_REF = origin
    import inspect
    for _name, _fn in list(globals().items()):
        if not (_name.startswith("test_") and inspect.isfunction(_fn)):
            continue

        def _wrap(name, fn):
            def _runner(*a, **kw):
                before = _conn_cursor()
                _write_breadcrumb(f"{name} {before}")
                try:
                    return fn(*a, **kw)
                finally:
                    _SPANS.append((name, before, _conn_cursor()))
                    _write_breadcrumb(f"DONE {name}")
            return _runner
        globals()[_name] = _wrap(_name, _fn)


def _attribute_alert(conn_number: int) -> str:
    """Given a shutdown alert's *NNNN, return a human string naming the test(s)
    whose span brackets it, narrowest first. The cursor is an estimate, so also
    report the two nearest spans on either side when nothing brackets exactly."""
    exact = [(hi - lo, name, lo, hi) for (name, lo, hi) in _SPANS
             if lo < conn_number <= hi]
    exact.sort()   # narrowest span first
    if exact:
        lines = [f"    *{conn_number} falls in: {name} "
                 f"(conn cursor {lo}..{hi})"
                 for (_w, name, lo, hi) in exact[:3]]
        return "\n".join(lines)
    # No exact bracket (cursor drift / keepalive reuse): show nearest neighbours.
    nearest = sorted(_SPANS, key=lambda s: min(abs(conn_number - s[1]),
                                               abs(conn_number - s[2])))
    lines = [f"    *{conn_number}: no exact span; nearest {name} "
             f"(cursor {lo}..{hi})"
             for (name, lo, hi) in nearest[:3]]
    return "\n".join(lines)


# Per-request HTTP timeout, in seconds. Instrumented builds (ASan/UBSan,
# Valgrind) slow the server far enough that a request which is comfortably
# sub-second on a normal build can exceed a fixed 5s budget -- the suite then
# hard-fails with TimeoutError on a commit that is perfectly green untouched.
# Scale it from the environment instead of hardcoding; teardown waits
# (process reap, thread join) deliberately do NOT use this.
HTTP_TIMEOUT = float(os.environ.get("TEST_CT_TIMEOUT", "5"))

# Client read timeout for the CONCURRENCY-PRESSURE tests only (the 48-thread,
# thousands-of-requests ones). Those spend their budget on runner scheduling,
# not on the module: a single request crossing HTTP_TIMEOUT aborts the whole
# suite with a bare TimeoutError, which is a harness property rather than a
# defect. They need a ceiling well above scheduling noise.
#
# Deliberately SEPARATE from HTTP_TIMEOUT. Raising HTTP_TIMEOUT suite-wide would
# also raise it for the ~800 ordinary status-only requests, whose 5s ceiling is
# their only liveness guard -- a regression answering correctly but 10s late
# would start passing. Keep the plain ceiling tight; widen only where the
# contention is manufactured by the test itself.
STRESS_TIMEOUT = float(os.environ.get("TEST_CT_STRESS_TIMEOUT", "30"))


def _check_timeout(name: str, value: float) -> float:
    """A timeout reaches urlopen() directly, where a bad value fails obscurely:
    0 surfaces as `URLError: [Errno 115] Operation now in progress`, which reads
    as a network fault rather than a typo in the environment. Reject it here so
    the message names the variable."""
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a finite number > 0, got {value!r}")
    return value


_check_timeout("TEST_CT_TIMEOUT", HTTP_TIMEOUT)
_check_timeout("TEST_CT_STRESS_TIMEOUT", STRESS_TIMEOUT)


def wait_port(port: int, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.25):
                _bump_conn()   # a successful probe IS an accepted connection
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"port 127.0.0.1:{port} never came up")


def fetch(port: int, path: str, headers: dict | None = None,
          method: str | None = None, data: bytes | None = None,
          timeout: float | None = None):
    """Return (status, body_str, response_headers_dict). `data` sends a request
    body (method must be given explicitly; urllib would otherwise silently flip
    a GET into a POST the moment data is set).

    `timeout` overrides the default HTTP_TIMEOUT client read ceiling. Pass
    STRESS_TIMEOUT from the concurrency-pressure tests, where a slow read is
    runner scheduling rather than a defect. Do NOT widen it for ordinary
    requests: for most tests here the default ceiling is the only thing
    asserting the server answered promptly at all."""
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        headers={"Connection": "close", **(headers or {})},
        method=method,
    )
    if data is not None:
        assert method in ("POST", "PUT", "PATCH"), \
            f"fetch(data=...) needs an explicit body-carrying method, got {method}"
        req.data = data
    elif method in ("POST", "PUT", "DELETE"):
        req.data = b""
    try:
        _bump_conn()
        with urllib.request.urlopen(
                req, timeout=HTTP_TIMEOUT if timeout is None else timeout) as r:
            body = r.read().decode("utf-8", "replace")
            return r.status, body, {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        return exc.code, body, {k.lower(): v for k, v in exc.headers.items()}


def fetch_dup(port: int, path: str, headers: list[tuple[str, str]]):
    """Like fetch(), but sends a LIST of (name, value) pairs so the SAME header
    name can appear more than once. A client may legally split its cookies over
    several Cookie headers, and a cache that only looks at the first one lets the
    client choose which cache bucket it lands in. dict-based fetch() cannot
    express that request at all."""
    _bump_conn()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=HTTP_TIMEOUT)
    try:
        conn.putrequest("GET", path, skip_host=False,
                        skip_accept_encoding=True)
        conn.putheader("Connection", "close")
        for k, v in headers:
            conn.putheader(k, v)
        conn.endheaders()
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", "replace")
        return (resp.status, body,
                {k.lower(): v for k, v in resp.getheaders()})
    finally:
        conn.close()


def fetch_raw(port: int, path: str, method: str = "GET",
              headers: dict | None = None):
    """Like fetch(), but does NOT follow redirects and supports HEAD — returns
    (status, body_str, headers_dict). Uses http.client so a 3xx is observable."""
    _bump_conn()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=HTTP_TIMEOUT)
    try:
        conn.request(method, path, headers=headers or {})
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", "replace")
        return (resp.status, body,
                {k.lower(): v for k, v in resp.getheaders()})
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Counting origin: every GET returns a unique body and bumps a hit counter.
# --------------------------------------------------------------------------- #

class Origin:
    def __init__(self, port: int, delay: float = 0.0) -> None:
        self.port = port
        self.delay = delay
        # The suite-wide baseline (main() and run_named.main() both construct
        # the Origin with delay=0.05).
        # Tests that borrow `delay` for a slow-miss window MUST restore to this,
        # not to a hardcoded 0.0 -- several burst tests downstream depend on a
        # non-zero regeneration window to be non-vacuous. See reset_delay().
        self.default_delay = delay
        self.fail = False          # when True, every GET answers 503 (v8 SIE)
        self.fail_status = 503     # status `fail` answers with. 503 keeps every
                                   # pre-S4.2 caller byte-identical; S4.2's
                                   # use_stale tests set it to 404/403/429 to
                                   # drive a non-5xx trigger.
        self.drop = False          # when True, every GET drops the connection
                                   # with no response (transport-level failure:
                                   # nginx sees a 502, a different error class
                                   # than the clean 503 `fail` mode — Goal-2
                                   # hard-dead-upstream coverage)
        self._n = 0
        # ring: diagnostics only, trimmed to the last 64 entries -- NOT a
        # source of truth for hits_for(), which reads _path_hits below.
        self._paths: list[tuple[float, str]] = []
        self._path_hits: collections.Counter[str] = collections.Counter()
        self._lock = threading.Lock()
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def reset_delay(self) -> None:
        """Restore `delay` to the suite baseline after a test borrowed it.

        ⚠ Restoring to a hardcoded 0.0 instead is a SILENT test-weakening bug,
        and it shipped: the Origin is constructed with delay=0.05, the autotune
        tests set it to 0.04 and reset it to 0.0, and every burst test after
        them then ran against an INSTANT origin. With no regeneration window
        left, a single-flight winner fills L1 before the other threads issue, so
        they take CLAIM_FRESH and never park -- collapsing the lock_waits
        liveness assert to 0 (SUITE-8) and voiding the 50ms window
        test_lock_redis_outage_fallback's docstring claims to rely on."""
        self.delay = self.default_delay

    @property
    def hits(self) -> int:
        with self._lock:
            return self._n

    def hits_for(self, needle: str) -> int:
        """Count origin contacts whose path contains `needle` (substring
        match, not equality -- callers pass fragments like "forever-f" or
        "?sessionid=AAA"). Backed by an unbounded per-path Counter
        (`_path_hits`), incremented under `_lock` beside `_n` in EVERY request
        handler -- do_GET, do_HEAD and do_POST -- so the total is exact
        regardless of how many contacts happened across ALL paths in between,
        and matches `hits` in what it counts.

        Path-scoped, so a test using a unique URL is immune to other tests'
        async bg-refresh traffic bumping the global `hits` counter between its
        base capture and its assertion (the test_206_never_cached deflake).

        NOTE: `_paths` (the (time, path) ring, trimmed to the last 64 entries)
        is diagnostics-only -- used by `_recent_memo_skips()` and the SUITE-1
        dump -- and is NOT what backs this count. Before the Counter was
        added, hits_for() summed the trimmed ring directly, which silently
        undercounted any window spanning more than 64 total origin contacts."""
        with self._lock:
            return sum(c for p, c in self._path_hits.items() if needle in p)

    def start(self) -> None:
        origin = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_HEAD(self):  # noqa: N802
                # A HEAD must reach the origin (no body); the module must NOT
                # store it as the GET entry.
                with origin._lock:
                    origin._n += 1
                    origin._path_hits[self.path] += 1
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_POST(self):  # noqa: N802
                # GraphQL-shaped upstream: reads the request body and answers
                # with a body that is BOTH unique per origin hit (gen counter,
                # so a cached serve is detectable as a repeated body) AND
                # body-identifying (a digest of the received bytes, so a test
                # can prove the body actually transited nginx intact).
                #
                # Response headers are ECHO-driven: a test sets X-Want-Cacheable /
                # X-Want-Deps on the REQUEST (nginx forwards request headers to
                # the upstream) and the origin reflects them as the
                # X-GraphQL-Cacheable / X-GraphQL-Cache-Dependencies RESPONSE
                # headers the module reads. This keeps per-test control without
                # a path-marker per dependency list.
                if origin.delay:
                    time.sleep(origin.delay)
                clen = int(self.headers.get("Content-Length") or 0)
                req_body = self.rfile.read(clen) if clen else b""
                with origin._lock:
                    origin._n += 1
                    n = origin._n
                    origin._paths.append((time.time(), self.path))
                    if len(origin._paths) > 64:        # ring: diagnostics only
                        del origin._paths[:-64]
                    origin._path_hits[self.path] += 1
                if origin.drop:
                    self.close_connection = True
                    return
                if origin.fail:
                    self.send_response(origin.fail_status)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                digest = hashlib.sha256(req_body).hexdigest()[:16]
                body = f"post-{n}:{digest}\n".encode()
                self.send_response(200)
                self.send_header("Content-Type",
                                 "application/json; charset=utf-8")
                want_c = self.headers.get("X-Want-Cacheable")
                if want_c is not None:
                    self.send_header("X-GraphQL-Cacheable", want_c)
                want_d = self.headers.get("X-Want-Deps")
                if want_d is not None:
                    self.send_header("X-GraphQL-Cache-Dependencies", want_d)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except BrokenPipeError:
                    pass

            def do_GET(self):  # noqa: N802
                if origin.delay:
                    time.sleep(origin.delay)
                with origin._lock:
                    origin._n += 1
                    n = origin._n
                    origin._paths.append((time.time(), self.path))
                    if len(origin._paths) > 64:        # ring: diagnostics only
                        del origin._paths[:-64]
                    origin._path_hits[self.path] += 1
                # Hard upstream failure (Goal-2): drop the connection with no
                # response so nginx's upstream sees a transport error (502),
                # exercising a different error class than the clean 503 `fail`
                # mode. The hit is already counted above (proves the bg refresh
                # reached the origin); serving stale must not depend on it.
                if origin.drop:
                    self.close_connection = True
                    return
                # Origin failure injection (v8 stale-if-error): the hit is still
                # counted (so a test can prove the refresh reached the origin),
                # but the response is a 5xx the module must NOT cache or surface.
                if origin.fail:
                    # AUD-SIE-BODY: the "sieserve-unbuf" marker asks for a
                    # non-empty error body instead of the usual Content-Length:
                    # 0. The stuck-buffer regression this drives needs the
                    # discarded upstream chain to actually carry a data buffer
                    # -- a header-only, zero-length error response leaves
                    # nothing behind for the sie_serving block to fail to
                    # consume, so the bug does not reproduce without this.
                    if "sieserve-unbuf" in self.path:
                        # Many flushed chunks, well beyond proxy_buffer_size's
                        # default one 4k page: a body that arrives in a SINGLE
                        # recv() (a same-host, no-delay write easily coalesces
                        # into one) gets fully drained by nginx's upstream
                        # preread before the body filter ever runs, so there is
                        # no second read that needs the discarded buffer
                        # recycled and the bug does not reproduce. Splitting
                        # into many flushed writes forces multiple recv()
                        # cycles, each of which can only proceed once the
                        # PREVIOUS response buffer is released back to the
                        # upstream -- with enough of them, at least one lands
                        # as its own read even under scheduler/coalescing
                        # jitter, so the reproduction is not a one-shot race.
                        chunk = b"E" * 4096
                        n_chunks = 16   # 64 KiB total, ~16x proxy_buffer_size
                        err_body = chunk * n_chunks
                        self.send_response(origin.fail_status)
                        self.send_header("Content-Type", "text/plain")
                        self.send_header("Content-Length", str(len(err_body)))
                        self.end_headers()
                        try:
                            for _ in range(n_chunks):
                                self.wfile.write(chunk)
                                self.wfile.flush()
                                time.sleep(0.02)
                        except BrokenPipeError:
                            pass
                        return
                    self.send_response(origin.fail_status)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                # CTXRDR: a 404 the vhost turns into an `error_page` internal
                # redirect. Unlike try_files (which redirects during the REWRITE
                # phase, before our PRECONTENT access handler has ever run), an
                # error_page redirect fires from the ORIGIN's response status --
                # i.e. after the access handler has already built ctx and after
                # the header filter has run. ngx_http_internal_redirect() then
                # memzeros r->ctx unconditionally (ngx_http_core_module.c:2614;
                # the preserve-one-module dance at special_response.c:547 is the
                # filter_finalize path, NOT this one), so the second pass starts
                # with r->ctx[cache_turbo] == NULL while ctx's pool cleanups and
                # its embedded cold_wait timer are still live on r->pool.
                if "ctxrdr-missing" in self.path:
                    self.send_response(404)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                # 206 Partial Content must NEVER be cached (the key has no Range,
                # so a stored partial could be replayed for a different/whole
                # range). The module refuses it even with a per-status TTL.
                if "partial" in self.path:
                    body = f"part-{n}\n".encode()
                    self.send_response(206)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Range", f"bytes 0-{len(body)-1}/999")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    try:
                        self.wfile.write(body)
                    except BrokenPipeError:
                        pass
                    return
                # AUD-RANGE1: a real Range-capable origin (e.g. a static file
                # server) that both advertises Accept-Ranges: bytes AND honours
                # an incoming Range header with a genuine 206 + Content-Range +
                # sliced body. Body is well over 100 bytes so bytes=0-99 is a
                # true partial slice, not the whole response. Used to prove a
                # cache-turbo HIT answers Range identically to a MISS.
                if "rngsrc" in self.path:
                    # Fixed (not gen-N-prefixed) body: this marker drives a
                    # byte-for-byte comparison between a HIT's Range answer and
                    # a MISS's Range answer against a DIFFERENT URL, so the
                    # body must not depend on which request/URL produced it.
                    rbody = b"R" * 200
                    # This branch returns before the shared Cache-Control marker
                    # block below (:813), so a /rngsrc/ key can never pick up the
                    # "sieserve" stale-if-error marker the way other locations do.
                    # rngsie emits it HERE instead, so one key can be both
                    # Range-capable and serve-on-error armed -- the fixture
                    # test_range_on_sie_serve needs, because allow_ranges is set
                    # in restore_response(), which the SIE header-filter path
                    # shares with the live HIT path.
                    sie = "rngsie" in self.path
                    # Same reason as rngsie: the shared "cond" validator block
                    # (:835) is below this branch's return, so an rngsrc key can
                    # never carry an ETag. rngcond emits one here so a
                    # Range-capable entry can also be revalidated -- the fixture
                    # test_range_not_offered_on_304 needs to reach the 304 branch
                    # that module.c:6563 deliberately excludes from allow_ranges.
                    cond = "rngcond" in self.path
                    rng = self.headers.get("Range")
                    start, end = 0, len(rbody) - 1
                    partial = False
                    if rng and rng.startswith("bytes="):
                        try:
                            s, e = rng[len("bytes="):].split("-", 1)
                            if not s:
                                # Suffix range "bytes=-N" = the LAST N bytes,
                                # not the first N. Getting this wrong would
                                # silently mis-slice for any future test that
                                # reuses this origin with a suffix range.
                                start = max(0, len(rbody) - int(e))
                                end = len(rbody) - 1
                            else:
                                start = int(s)
                                end = int(e) if e else len(rbody) - 1
                            end = min(end, len(rbody) - 1)
                            partial = start <= end
                        except ValueError:
                            partial = False
                    if partial:
                        chunk = rbody[start:end + 1]
                        self.send_response(206)
                        self.send_header("Content-Type", "text/plain")
                        self.send_header("Accept-Ranges", "bytes")
                        self.send_header("Content-Range",
                                          f"bytes {start}-{end}/{len(rbody)}")
                        if sie:
                            self.send_header("Cache-Control",
                                             "stale-if-error=30")
                        if cond:
                            self.send_header("ETag", '"rngetag"')
                        self.send_header("Content-Length", str(len(chunk)))
                        self.end_headers()
                        try:
                            self.wfile.write(chunk)
                        except BrokenPipeError:
                            pass
                    else:
                        self.send_response(200)
                        self.send_header("Content-Type", "text/plain")
                        self.send_header("Accept-Ranges", "bytes")
                        if sie:
                            self.send_header("Cache-Control",
                                             "stale-if-error=30")
                        if cond:
                            self.send_header("ETag", '"rngetag"')
                        self.send_header("Content-Length", str(len(rbody)))
                        self.end_headers()
                        try:
                            self.wfile.write(rbody)
                        except BrokenPipeError:
                            pass
                    return
                # Per-status caching markers (v6): redirects + negative responses.
                if "redir" in self.path:
                    self.send_response(301)
                    self.send_header("Location", f"/dest-{n}")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if "notfound" in self.path:
                    body = f"missing-{n}\n".encode()
                    self.send_response(404)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    try:
                        self.wfile.write(body)
                    except BrokenPipeError:
                        pass
                    return
                if "bigbody" in self.path:
                    # ~200 KB body so nginx streams it to our body filter in
                    # several buffers/calls -> exercises the Q2 mid-stream
                    # oversize early-abort, not just a single-buffer case. The
                    # leading gen-N keeps each response distinct so a cached
                    # serve would be detectable.
                    body = (f"gen-{n}\n".encode()
                            + b"x" * 200000)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    try:
                        self.wfile.write(body)
                    except BrokenPipeError:
                        pass
                    return
                if "unbuf-stream" in self.path:
                    # UNBUF: streamed multi-call capture on the SUCCESS path
                    # (the "sieserve-unbuf" marker above only fires under
                    # origin.fail). Each chunk is distinct (an index-tagged
                    # line) so a truncated, reordered or short capture is
                    # detectable byte-for-byte, not just non-empty. Many
                    # flushed writes, well beyond proxy_buffer_size's default
                    # one 4k page, force the body filter to run across
                    # multiple invocations instead of nginx's upstream
                    # preread coalescing everything into one recv().
                    n_chunks = 16
                    chunks = [f"chunk-{n}-{i:02d}-".encode() + b"Q" * 4000
                              + b"\n" for i in range(n_chunks)]
                    body = b"".join(chunks)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    try:
                        for c in chunks:
                            self.wfile.write(c)
                            self.wfile.flush()
                            time.sleep(0.02)
                    except BrokenPipeError:
                        pass
                    return
                if "unbuf-big" in self.path:
                    # UNBUF oversize: same streamed-chunk shape as
                    # unbuf-stream, but ~64 KiB total against a small
                    # cache_turbo_max_size (see /unbufbig/) so the limit is
                    # crossed on a LATER filter invocation, not the first
                    # buffer -- exercising the mid-stream early-abort path
                    # instead of the single-buffer case /big/ already covers.
                    n_chunks = 16
                    chunks = [f"big-{n}-{i:02d}-".encode() + b"Z" * 4000
                              + b"\n" for i in range(n_chunks)]
                    body = b"".join(chunks)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    try:
                        for c in chunks:
                            self.wfile.write(c)
                            self.wfile.flush()
                            time.sleep(0.02)
                    except BrokenPipeError:
                        pass
                    return
                if "ckecho" in self.path:
                    # B-S4: echo the received Cookie header so a test can prove a
                    # warm subrequest reaches the origin ANONYMOUSLY (with none of
                    # the admin POST's inherited segment/identity cookies).
                    ck = self.headers.get("Cookie") or "none"
                    body = f"gen-{n} cookie=[{ck}]\n".encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    try:
                        self.wfile.write(body)
                    except BrokenPipeError:
                        pass
                    return
                body = f"gen-{n}\n".encode()
                self.send_response(200)
                self.send_header("Content-Type",
                                 "application/json; charset=utf-8")
                if "bare" not in self.path:
                    self.send_header("X-Backend", "origin-42")
                # Same request-echo contract as do_POST: a test drives the
                # cache_turbo_require_header gate by asking for an exact
                # response-header value, including a deliberately duplicated or
                # non-affirmative one, without a path marker per case.
                want_c = self.headers.get("X-Want-Cacheable")
                if want_c is not None:
                    for v in want_c.split("|"):
                        self.send_header("X-GraphQL-Cacheable", v)
                # Path-marker-driven response headers, so a test can drive the
                # RFC 9111 shared-cache floor (these responses must NOT be
                # stored). The marker is matched in the path so $uri keying still
                # collapses repeated requests onto one slot.
                if "setcookie" in self.path:
                    self.send_header("Set-Cookie", "sess=abc; Path=/")
                if "mgvary" in self.path:
                    # Magento's transition race: the request arrived with NO
                    # X-Magento-Vary (so it keyed to the ANONYMOUS entry) and the
                    # origin establishes the segment on the way back. Storing this
                    # body under the anonymous key poisons it for every anonymous
                    # visitor. Upstream's VCL marks exactly this uncacheable.
                    self.send_header(
                        "Set-Cookie",
                        "X-Magento-Vary=aaaabbbbccccdddd; Path=/; HttpOnly")
                if "swhash" in self.path:
                    # Shopware's transition race, identical in shape to magento's:
                    # the request carried NO sw-cache-hash (so it keyed to the
                    # ANONYMOUS entry) and the origin establishes the segment on
                    # the way back. Storing this body under the anonymous key
                    # poisons it for every anonymous visitor.
                    self.send_header(
                        "Set-Cookie",
                        "sw-cache-hash=aaaabbbbccccdddd; Path=/; HttpOnly")
                if "originsk" in self.path:
                    # SK-A1: an origin-supplied Surrogate-Key. With
                    # cache_turbo_surrogate_key OFF the module generates nothing,
                    # so this header is ordinary representation metadata: it must
                    # be stored and replayed on every HIT, or a CDN refilling
                    # from our hit caches an object outside its tag purge.
                    self.send_header("Surrogate-Key", "origin-a origin-b")
                if "ccprivate" in self.path:
                    self.send_header("Cache-Control", "private, max-age=60")
                if "ccnostore" in self.path:
                    self.send_header("Cache-Control", "no-store")
                if "nativecache" in self.path:
                    # mimic a native nginx cache (proxy_cache) sitting behind us
                    self.send_header("Age", "123")
                    self.send_header("X-Cache-Status", "HIT")
                if "ttl1" in self.path:
                    # upstream-declared 1s freshness (v7 honor_cache_control)
                    self.send_header("Cache-Control", "public, max-age=1")
                if "mustrev" in self.path:
                    # RFC 9111 must-revalidate: 1s fresh, then NO stale serving.
                    self.send_header("Cache-Control",
                                     "max-age=1, must-revalidate")
                if "proxyrev" in self.path:
                    # RFC 9111 proxy-revalidate: the shared-cache synonym of
                    # must-revalidate. Same window collapse (response_must_revalidate
                    # OR-arm), 1s fresh then NO stale serving.
                    self.send_header("Cache-Control",
                                     "max-age=1, proxy-revalidate")
                if "splitmrev" in self.path:
                    # AUD-CC-FIRST-LINE: HTTP allows a header field to be split
                    # across multiple field-lines (RFC 9110 SS5.3), equivalent to
                    # one line with the values comma-joined in order. Emit TWO
                    # separate Cache-Control lines -- max-age on the first,
                    # must-revalidate on the SECOND -- so a reader that only
                    # inspects the first occurrence would miss must-revalidate
                    # entirely and stale-serve past freshness.
                    self.send_header("Cache-Control", "max-age=1")
                    self.send_header("Cache-Control", "must-revalidate")
                if "expabs" in self.path:
                    # Expires-only freshness (upstream_ttl ladder step 4): NO
                    # Cache-Control/CDN-CC/Surrogate-Control, so the fresh TTL is
                    # derived purely from absolute Expires minus now. Emit a 2s
                    # future Expires; honor mode must cache with a ~2s window even
                    # though cache_turbo_valid is 60s.
                    self.send_header(
                        "Expires",
                        email.utils.formatdate(time.time() + 2, usegmt=True))
                if "ttlclamp" in self.path:
                    # STAB-5 TTL clamp (module.c:4873): an unbounded upstream
                    # max-age (here ~3170 years, > TTL_MAX 0xFFFFFFFF) must be
                    # clamped before it feeds the uint32 fresh_ttl cast, the
                    # stale-window multiply and the L2 PX. Unclamped, the cast /
                    # multiply overflow could wrap the fresh window to a small (or
                    # instantly-stale) value; clamped, the entry stays fresh.
                    self.send_header("Cache-Control", "public, max-age=99999999999")
                if "cdnttl" in self.path:
                    # RFC 9213: CDN-Cache-Control (edge TTL) must OUTRANK the
                    # browser-facing Cache-Control. CC says 60s fresh, CDN-CC says
                    # 1s — the shared cache must honour the 1s.
                    self.send_header("Cache-Control", "public, max-age=60")
                    self.send_header("CDN-Cache-Control", "max-age=1")
                if "scttl" in self.path:
                    # RFC 9213: Surgrogate-Control outranks BOTH CDN-CC and CC.
                    # SC=1s wins over CDN-CC=60s and CC=60s.
                    self.send_header("Cache-Control", "public, max-age=60")
                    self.send_header("CDN-Cache-Control", "max-age=60")
                    self.send_header("Surrogate-Control", "max-age=1")
                if "cdnnostore" in self.path:
                    # RFC 9213: a targeted no-store must veto the shared store even
                    # when plain Cache-Control would permit it (max-age=60).
                    self.send_header("Cache-Control", "public, max-age=60")
                    self.send_header("CDN-Cache-Control", "no-store")
                if "cdnstrip" in self.path:
                    # cacheable, carries both targeted headers: the served HIT must
                    # NOT replay them downstream (we are their intended consumer).
                    self.send_header("Cache-Control", "public, max-age=60")
                    self.send_header("CDN-Cache-Control", "max-age=30")
                    self.send_header("Surrogate-Control", "max-age=30")
                if "scsplit" in self.path:
                    # AUD2-CC-TARGETED: Surrogate-Control split across TWO
                    # field-lines, max-age on the SECOND. A single-line reader
                    # (header_find only sees the first occurrence) would see
                    # stale-while-revalidate=30 alone, find no max-age and fall
                    # through the ladder to Cache-Control's 60s -- the effective
                    # TTL must come from the second SC line's max-age=1, not
                    # from CC.
                    self.send_header("Cache-Control", "public, max-age=60")
                    self.send_header("Surrogate-Control",
                                     "stale-while-revalidate=30")
                    self.send_header("Surrogate-Control", "max-age=1")
                if "cdnsplit" in self.path:
                    # AUD2-CC-TARGETED: CDN-Cache-Control split across TWO
                    # field-lines, max-age on the SECOND (first line carries an
                    # unrelated directive only). Same defect as scsplit but for
                    # arm 2 of the ladder.
                    self.send_header("Cache-Control", "public, max-age=60")
                    self.send_header("CDN-Cache-Control",
                                     "stale-while-revalidate=30")
                    self.send_header("CDN-Cache-Control", "max-age=1")
                if "ccpad" in self.path:
                    # leading-zero max-age: precise token parse must read this as
                    # 1000s fresh (cacheable), NOT trip the substring "max-age=0".
                    self.send_header("Cache-Control", "max-age=01000")
                if "ccmaxage0" in self.path:
                    # max-age=0 = already stale: a shared cache must not store it.
                    self.send_header("Cache-Control", "max-age=0")
                if "swrdur" in self.path:
                    # RFC-2: response stale-while-revalidate=10 extends the stale
                    # window well past the cache_turbo_stale_mult default.
                    self.send_header("Cache-Control",
                                     "stale-while-revalidate=10")
                if "siettl" in self.path:
                    # RFC-2 (CTB4): response stale-if-error=30 records an absolute
                    # serve-on-error window (fresh + 30) in the blob's sie_ttl.
                    self.send_header("Cache-Control",
                                     "max-age=60, stale-if-error=30")
                if "l2sie" in self.path:
                    # S1.2: stale-if-error window (fresh + 3600) that is much
                    # WIDER than the location's stale window (stale_mult 1 =>
                    # stale_window == fresh_ttl == 1s). Drives
                    # test_l2_retain_ttl_covers_sie: the L2 key's own PX must
                    # cover the sie window, not just the (narrower) stale
                    # window, or an origin failure past 1s can never read the
                    # blob back from L2 even though sie_ttl says it should.
                    self.send_header("Cache-Control",
                                     "max-age=1, stale-if-error=3600")
                if "sieserve" in self.path:
                    # RFC-2 serve-on-error: short fresh window + a long
                    # stale-if-error so the entry can FULLY expire (past its stale
                    # window) yet stay inside the serve-on-error window. No max-age
                    # here -> the location's cache_turbo_valid (1s) sets the fresh
                    # TTL; sie_ttl = 1 + 30 = 31s. Drives test_sie_serve_on_error.
                    self.send_header("Cache-Control", "stale-if-error=30")
                if "cond" in self.path:
                    # v11 conditional-304: stable validators so a stored entry
                    # can answer If-None-Match / If-Modified-Since from cache.
                    self.send_header("ETag", '"v11etag"')
                    self.send_header("Last-Modified",
                                     "Wed, 21 Oct 2015 07:28:00 GMT")
                # auto-Vary (v11 other half): emit a response Vary driven by a
                # query marker so a test can prove the module splits (or refuses)
                # by the named request header. The body is the global gen-N, so a
                # new origin hit == a distinct body == a distinct variant slot.
                if "v=ae" in self.path:
                    self.send_header("Vary", "Accept-Encoding")
                if "v=ua" in self.path:
                    self.send_header("Vary", "User-Agent")
                if "v=al" in self.path:
                    self.send_header("Vary", "Accept-Language")
                if "v=or" in self.path:
                    self.send_header("Vary", "Origin")
                if "v=star" in self.path:
                    self.send_header("Vary", "*")
                if "v=cs" in self.path:
                    # a Vary on an axis the whitelist cannot key on (not *,
                    # Cookie, or Authorization, but still unsupported): the
                    # response must be refused, not silently mis-served.
                    self.send_header("Vary", "Accept-Charset")
                if "v=ck" in self.path:
                    self.send_header("Vary", "Cookie")
                if "v=mix" in self.path:
                    # safe axis + refused axis: the refused one must win (no cache)
                    self.send_header("Vary", "Accept-Encoding, Cookie")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except BrokenPipeError:
                    pass

            def log_message(self, *a):  # silence
                pass

        self._server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()
        wait_port(self.port)

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None


def _errlog_level() -> str:
    """error_log level for the harness nginx, overridable for diagnosis.

    Defaults to `notice`, which is what CI and every normal run want. Set
    TEST_CT_ERRLOG=debug to make the module's ngx_log_debug sites (memo skips,
    cold-wait give-ups, L2 verdicts) land in logs/error.log -- the cheap way to
    identify WHICH uri tripped a zone-global counter assertion in a long suite,
    instead of bisecting a couple of hundred tests by hand.

    The binary must be built --with-debug for `debug` to do anything; the
    harness build is (see objs/ngx_auto_config.h). Debug on a full suite is a
    large log, hence opt-in rather than the default.
    """
    lvl = os.environ.get("TEST_CT_ERRLOG", "notice").strip() or "notice"
    allowed = {"debug", "info", "notice", "warn", "error", "crit", "alert", "emerg"}
    if lvl not in allowed:
        raise SystemExit(f"TEST_CT_ERRLOG={lvl!r} is not an nginx log level "
                         f"(one of: {', '.join(sorted(allowed))})")
    return lvl


def nginx_config(root: pathlib.Path, port: int, module: pathlib.Path | None,
                 origin_port: int, workers: int,
                 redis_port: int | None = None,
                 redis_auth_port: int | None = None,
                 redis_password: str | None = None,
                 redis_tls_port: int | None = None,
                 redis_tls_ca: str | None = None,
                 memcached_port: int | None = None,
                 fault_injection: bool = False,
                 sr_off: bool = False,
                 redis_tls_untrusted_port: int | None = None,
                 redis_tls_expired_port: int | None = None) -> str:
    """Build the generated nginx.conf for the test server.

    !! ASCII ONLY -- everything returned here, INCLUDING COMMENTS, is written
    with encoding="ascii" (see Nginx.write_config). A single non-ASCII byte
    anywhere in this function (a stray arrow, dash, or warning sign pasted into
    a location comment) raises UnicodeEncodeError before a single test runs, and
    the traceback points at write_text, not at the comment you added. Use "!!",
    "->" and plain hyphens.
    """
    load = f"load_module {module};\n" if module else ""

    # S8 reload arm: the SAME zone (srz) with the directive flipped to `off`.
    # Written into the conf only for the post-reload pass, so a real
    # `nginx -s reload` hands the already-PROTECTED nodes in the surviving zone
    # to a worker whose effective protected_pct is now 0. See
    # test_s8_reload_on_to_off_drains_protected.
    sr_directive = ("cache_turbo_scan_resistant off;" if sr_off
                    else "cache_turbo_scan_resistant on;")

    # DSN auth+db (v5): a backend reached via a full redis://user:pass@host/db
    # DSN, and a plain SELECT-db (no auth) backend on the main instance.
    dsn_loc = ""
    if redis_auth_port is not None:
        dsn_loc += f"""
        # full DSN: AUTH (password) + SELECT db 2, two-reply preamble
        location /l2auth/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 30s;
            cache_turbo_redis redis://:{redis_password}@127.0.0.1:{redis_auth_port}/2;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # AUTH+SELECT DSN with a keepalive pool (v15 + v5 combined): a pooled
        # reused connection must skip the AUTH/SELECT preamble entirely (it was
        # already authenticated + SELECTed when first opened). See
        # test_l2_keepalive_no_auth_replay.
        location /l2authka/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 30s;
            cache_turbo_redis redis://:{redis_password}@127.0.0.1:{redis_auth_port}/2 keepalive=4 keepalive_timeout=30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
"""
    if redis_port is not None:
        dsn_loc += f"""
        # SELECT-only preamble (db 1, no auth) on the main instance
        location /l2db/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 30s;
            cache_turbo_redis 127.0.0.1:{redis_port} db=1;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
"""
    if redis_tls_port is not None:
        dsn_loc += f"""
        # rediss:// TLS, verifying the server cert against our test CA
        location /l2tls/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 30s;
            cache_turbo_redis rediss://127.0.0.1:{redis_tls_port}/0 tls_ca={redis_tls_ca} tls_name=localhost;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # v15-2: TLS keepalive pool -- idle TLS conns cached + reused across ops
        # (handshake + AUTH/SELECT skipped on reuse over the persistent channel).
        location /l2tlska/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 30s;
            cache_turbo_redis rediss://127.0.0.1:{redis_tls_port}/0 tls_ca={redis_tls_ca} tls_name=localhost keepalive=4 keepalive_timeout=30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
"""
    if redis_tls_untrusted_port is not None:
        # AUD-TLS1: nginx is told to trust the SAME CA as /l2tls/ (redis_tls_ca),
        # but this backend's cert is signed by a DIFFERENT CA. With a working
        # SSL_CTX_set_verify(PEER) the handshake must fail chain verification;
        # the L2 write-through must never reach this server.
        dsn_loc += f"""
        # rediss:// TLS, server cert signed by an UNTRUSTED CA (AUD-TLS1)
        location /l2tlsuntrusted/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 30s;
            cache_turbo_redis rediss://127.0.0.1:{redis_tls_untrusted_port}/0 tls_ca={redis_tls_ca} tls_name=localhost;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
"""
    if redis_tls_expired_port is not None:
        # Same trusted CA as /l2tls/ (chain trust is fine), but the leaf cert's
        # own validity window is already expired. Must also be rejected.
        dsn_loc += f"""
        # rediss:// TLS, server cert EXPIRED (chain-trusted CA) (AUD-TLS1)
        location /l2tlsexpired/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 30s;
            cache_turbo_redis rediss://127.0.0.1:{redis_tls_expired_port}/0 tls_ca={redis_tls_ca} tls_name=localhost;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
"""

    # SK-A2: the surrogate-key locations that carry NO cache_turbo_redis are
    # emitted unconditionally. They used to sit inside redis_loc, so a run
    # without --redis-server dropped them while run_all() still called their
    # tests -- the "works without an L2 tag index" claim was exactly the case
    # that never ran. /skoff/ stays in redis_loc (it needs Redis to consume the
    # tag and suppress the COR-0 "no effect" warning).
    sk_loc = f"""
        # cache_turbo_surrogate_key: emit the tag list downstream as a
        # Surrogate-Key header for a fronting CDN. Deliberately NO cache_turbo_redis
        # here -- the emit must work without an L2 tag index. SK-A1: BOTH the MISS
        # and every later HIT carry the header, because a CDN POP that lost its own
        # copy refills from our HIT and would otherwise cache an untagged object.
        location /sk/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_tag      "blog news blog";
            cache_turbo_surrogate_key on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # surrogate_key with the tag value from a query arg (upstream-controlled
        # stand-in) so the cap/dedup carries into the emitted header.
        location /skcap/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_tag      $arg_t;
            cache_turbo_surrogate_key on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
"""

    # L2 (v2b): a location wired to a Redis backend. Scoped to /l2/ only so the
    # L1-only tests (purge, eviction, ...) are unaffected. Emitted only when a
    # RedisServer is running, so the no-redis path still config-tests.
    redis_loc = ""
    if redis_port is not None:
        redis_loc = f"""
        # L2: write-through on store + sync fill on L1 miss
        location /l2/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # C-S5-a: RFC-1 request Cache-Control serve verdict evaluated against
        # the L2 (Redis) arm, not L1 (module.c:5296). An L2 entry can be
        # YOUNGER than the L1 copy (a peer refreshed it), so the verdict must
        # be re-run on the L2 blob's own created/fresh_ttl rather than reusing
        # the L1 verdict.
        #
        # NOTE: `cache_turbo_purge on` is NOT an L1-only drop. purge_request()
        # calls clcf->backend->del() unconditionally whenever a backend is
        # configured (module.c ~1711, "Drop from L2 too, so a purge can't be
        # silently refilled from Redis") -- and this location configures one,
        # so a PURGE here empties BOTH tiers. To leave L2 populated while
        # emptying L1 there is no directive: capture the blob with
        # redis.get_raw(), PURGE, then redis.set_raw() it back.
        location /reqccl2/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_purge    on;   # drops L1 AND L2 -- see the note above
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            add_header           X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # AUD-L2-PROMOTE-RACE: dedicated L2 location with NO cache_turbo_purge
        # (unlike /reqccl2/, whose PURGE would DEL the L2 key too -- this test
        # needs to seed L1 and L2 independently via raw redis writes, never
        # through the module's own PURGE) and cache_turbo_bypass on the SAME
        # key ($uri, so a bypassed and a non-bypassed request share one L1/L2
        # slot). A bypassed request on this URI never touches redis at all
        # (module.c: bypass returns NGX_DECLINED before the L1 lookup/lock,
        # straight to origin, straight to a plain store()), so it can land a
        # NEWER L1 write from a different worker while another request is
        # still inside the L2-promote critical section.
        #
        # cache_turbo_test_l2_promote_hold_ms is the load-bearing knob: the
        # actual race window (between the resumed L2-hit handler's own
        # already-unlocked L1 re-check and its store_if() call) is pure CPU
        # with no I/O or yield point in between -- unreachable from black-box
        # HTTP timing regardless of how the L2 GET itself is delayed. The hold
        # blocks the CURRENT worker for exactly that gap so a concurrent
        # bypass write from a DIFFERENT worker can land inside it
        # deterministically. TEST_FAULTS-only; see the field comment in
        # ngx_http_cache_turbo_module.h. Drives
        # test_l2_promote_race_never_overwrites_newer_l1_entry.
        location /l2promo/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=5s;
            cache_turbo_bypass   $arg_nocache;
            cache_turbo_test_l2_promote_hold_ms 2000;
            add_header           X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # L2 negative memo (L13). Same shape as /l2/ above (no keepalive, so
        # every L2 op is exactly one countable Redis connection) plus a 3s memo,
        # so a repeated cold miss on the same key skips the L2 GET entirely. The
        # window is deliberately longer than the test's request burst and
        # shorter than the suite, so expiry is observable within one test.
        #
        # min_uses 4 is load-bearing for the TEST, not for the feature: without
        # it request 1 stores the (cacheable) origin response and request 2 is a
        # plain L1 HIT that never reaches the L2 consult at all -- so the test
        # would "pass" by measuring zero Redis traffic for the wrong reason.
        # Keeping the key below the store threshold holds every request on the
        # cold-miss path, which is the only path the memo is on.
        location /l2neg/ {{
            cache_turbo                  l2negz;
            cache_turbo_key              $uri;
            cache_turbo_valid            30s;
            cache_turbo_min_uses         4;
            cache_turbo_l2_negative_ttl  3;
            cache_turbo_redis            127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # SUITE-1 / Codex MAJOR-1: the OUTAGE test gets its own location with a
        # deliberately LONG memo, and it cannot share /l2neg/'s 3s one.
        #
        # The outage test asserts that a post-recovery request was NOT memo-
        # skipped (delta == 0). That assertion only means anything while a memo
        # would still be live if the bug were present: the memo is stamped on
        # second-granularity ngx_time(), so `l2_negative_ttl 3` is 2-3s
        # effective, while redis.start() is Popen + wait_port() + a FLUSHALL
        # subprocess carrying a 10s timeout. If the restart outruns the memo,
        # the post-recovery request does a REAL GET and delta == 0 passes even
        # with the arm-on-failure bug restored -- the test goes green for the
        # wrong reason. That is not hypothetical: it is why the negative control
        # for this test passed in the first place.
        #
        # 60s is far longer than any plausible restart, so a delta of 0 is
        # attributable to the fix rather than to the memo having expired. The
        # sibling repeat-GET test still needs the SHORT window (it asserts
        # expiry within one test), which is why this is a separate location and
        # not a bump of /l2neg/.
        location /l2negout/ {{
            cache_turbo                  l2negoutz;
            cache_turbo_key              $uri;
            cache_turbo_valid            30s;
            cache_turbo_min_uses         4;
            cache_turbo_l2_negative_ttl  60;
            cache_turbo_redis            127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # L2 negative memo, LIFETIME arm. DEFAULT min_uses (1) on purpose.
        #
        # This location exists to measure the memo across its whole window in the
        # config the feature actually SHIPS in. Two traps had to be avoided at once,
        # and both were hit for real while writing this (2026-07-19):
        #
        # 1. A high min_uses (4, or 32) keeps the key uncached, but it ALSO stops
        #    the request before the v10 cold-miss claim(): count_miss returns
        #    NGX_DECLINED and the handler returns early. claim() is what marks the
        #    node `refreshing`, which is the mechanism that used to mask the memo --
        #    so on such a location the masking bug CANNOT occur and a negative
        #    control reintroducing it still passes. The test would assert nothing.
        #
        # 2. At min_uses 1 the cold path runs in full (claim() included), but a
        #    cacheable response STORES on request 1 and every later request is a
        #    plain L1 HIT that never reaches L2 -- zero GETs for the wrong reason.
        #
        # 3. min_uses 1 + an uncacheable response keeps every request cold, but with
        #    the v10 cold-miss lock ON the winner never stores (the response is
        #    uncacheable), so followers PARK on the stub and the cold-wait re-poll
        #    sets l2_neg_force -- which bypasses the memo by design. Measured
        #    2026-07-19: 2 requests in 5s, the second issuing 50 forced GETs.
        #
        # So: min_uses 1 (real cold path) + uncacheable origin (never stores) +
        # cache_turbo_lock off (no parking, no forced re-polls). This location
        # measures memo LIFETIME in the config the feature ships in.
        #
        # NOTE: there is deliberately NO test here for "the memo is consulted on a
        # node another request marked `refreshing`" (CodeRabbit CR-A / Codex #4).
        # That state is not reachable from outside the module: the memo is checked
        # once per request BEFORE the cold-miss single-flight, and a request that
        # arrives while a claim is held becomes a WAITER, whose re-poll sets
        # l2_neg_force and bypasses the memo by design. Six formulations were tried
        # (serial and 12-way concurrent, min_uses 1/4/32, lock on and off); every
        # one passed with the coupling deliberately restored. See issues.md.
        location /l2neglife/ {{
            cache_turbo                  l2neglifez;
            cache_turbo_key              $uri;
            cache_turbo_valid            30s;
            cache_turbo_lock             off;
            cache_turbo_l2_negative_ttl  3;
            cache_turbo_redis            127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # L2 negative memo, min_uses interaction: the memo rides on the SAME
        # counter node min_uses uses, so this location exercises both writing to
        # one node. min_uses 3 exceeds the test's request count, so every request
        # stays below the threshold and each one both counts a min_uses skip and
        # consults the memo -- the overlapping state that would hide a clobber.
        # The CR-B test drives UNCACHEABLE responses through here, so a winner
        # never stores and a follower can park on the single-flight. Two SEPARATE
        # deadlines govern that, and they are easy to confuse:
        #
        #   lock_ttl 1s      -- how long a CLAIM stays valid (when a stub goes
        #                       stale and may be taken over by a new winner).
        #   lock_timeout 2s  -- how long a WAITER parks before giving up and
        #                       going to origin itself (module.c: wait_deadline
        #                       = now + lock_timeout).
        #
        # !! lock_timeout MUST stay well under fetch()'s 5s client timeout. Both
        # defaulted to 5s, so a waiter that parked the full deadline released at
        # ~5.000s while the client aborted at 5.000s -- a photo finish decided by
        # scheduling jitter, which is exactly the 1-in-N red this test showed on
        # slower CI runners (PR #77, run 29708006339 attempt 1). Pinning it to 2s
        # makes the park end strictly before the client gives up, so a real
        # teardown regression surfaces as a legible assertion rather than a
        # timeout whose cause is ambiguous.
        location /l2negmu/ {{
            cache_turbo                  l2negmuz;
            cache_turbo_key              $uri;
            cache_turbo_valid            30s;
            cache_turbo_min_uses         3;
            cache_turbo_lock_ttl         1s;
            cache_turbo_lock_timeout     2s;
            cache_turbo_l2_negative_ttl  3;
            cache_turbo_redis            127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # L2 keepalive pool (v15): idle Redis connections cached per worker and
        # reused across ops, instead of connect()+close per op. As of the
        # per-fingerprint pool (v16), each distinct connection profile gets its
        # OWN bucket, cap and timeout -- so this plain location's keepalive value
        # is honoured for the plain profile regardless of what any TLS location
        # (/l2tlska/) or auth location (/l2authka/) configures, and no profile can
        # starve another out of a shared cap. (Before v16 the cap was latched
        # once per worker by the first keepalive-enabled location and the plain
        # and TLS working sets had to be summed into one value here -- that
        # workaround is retired.)
        location /l2ka/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms keepalive=8 keepalive_timeout=30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Keepalive security-context isolation: these locations share one Redis
        # address and pool but select different DBs. Separate L1 zones and the
        # same key shape ensure only Redis connection state distinguishes them.
        location /l2ka0/ {{
            cache_turbo          ka0;
            cache_turbo_key      $arg_k;
            cache_turbo_valid    30s;
            cache_turbo_redis    127.0.0.1:{redis_port} db=0 prefix=kais: timeout=250ms keepalive=8 keepalive_timeout=30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /l2ka1/ {{
            cache_turbo          ka1;
            cache_turbo_key      $arg_k;
            cache_turbo_valid    30s;
            cache_turbo_redis    127.0.0.1:{redis_port} db=1 prefix=kais: timeout=250ms keepalive=8 keepalive_timeout=30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # L2 with a short fresh TTL so the L1 copy expires in-test (stale window
        # = valid*4 = 4s), exercising the expired-L1 -> consult-L2 path (P6).
        location /l2e/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # RFC-2 (CTB4): origin emits stale-if-error=30; the store path records an
        # absolute serve-on-error window (fresh + 30) in the blob's sie_ttl. L2 so
        # the raw blob can be read back and the field unpacked. valid 60s => the
        # stored fresh_ttl is 60 and sie_ttl is 90.
        location /siettl/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    60s;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # V-HANG-2 single-flight guard rail. The give-up added for V-HANG-2 must
        # fire only on a cold-wait RE-POLL, never on a first pass -- otherwise
        # every cold-miss loser bypasses the wait loop and the burst stampedes.
        #
        # Reproducing that needs an L2 blob that is PRESENT but UNSERVEABLE while
        # a burst arrives, WITHOUT the regens being explainable by ordinary
        # re-expiry. /l2sie/ cannot do it: its cache_turbo_valid is 1s, so entries
        # legitimately re-expire mid-burst and 40 regens is correct behaviour
        # there (verified against stock -- identical counts).
        #
        # So: fresh_ttl 30s (a regen stays fresh for the whole burst, hence any
        # stampede is real) but stale_mult 1, so the FIRST entry is unserveable
        # 30s after it is stored. The test primes, expires the L2 object by hand,
        # and bursts -- see test_l2_unserveable_giveup_still_single_flights.
        location /sfgu/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_stale_mult 1;
            cache_turbo_lock_ttl 5s;
            # NOT an L1-only drop: purge_request() calls backend->del()
            # unconditionally when a backend is configured (module.c ~1711),
            # and this location configures one, so a PURGE empties BOTH tiers.
            # This comment previously claimed otherwise and is the documented
            # origin of that error (issues.md OBS-2, mis-scoped twice).
            cache_turbo_purge    on;

            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S1.2: stale_mult 1 collapses stale_window == fresh_ttl (1s), so a
        # stale-if-error=3600 response's sie window (3601s) is far wider than
        # the stale window. Proves the L2 key's retain_ttl covers sie, not
        # just stale_window. See test_l2_retain_ttl_covers_sie.
        location /l2sie/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_stale_mult 1;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # tagged objects: every response under /l2t/ joins the "blog" and
        # "news" tag sets, so a purge-by-tag can drop them across both tiers.
        location /l2t/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            cache_turbo_tag      "blog news";
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # PERF-2: tag value taken from a query arg (upstream-controlled stand-in)
        # so the cap/dedup on cache_turbo_tag can be exercised.
        location /l2tcap/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            cache_turbo_tag      $arg_t;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # surrogate_key OFF (default): tag set but no downstream header. Proves the
        # directive gates the emit -- a plain cache_turbo_tag user is unaffected.
        # Redis is attached so the tag has its normal purge-by-tag consumer and
        # the COR-0 "no effect" warning does not fire (an unconsumed tag would).
        # A DISTINCT prefix (sk:) + unique tag names keep this location's SADDs out
        # of the shared ct:tag:* sets other L2 tests assert exact counts on (the
        # truncation test fills ct:tag:news to exactly 350 -- a stray SADD from
        # here would race it to 351 under the multi-worker runner).
        location /skoff/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=sk: timeout=250ms;
            cache_turbo_tag      "skoff-a skoff-b";
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # COR-5 (Redis-backed): auto-Vary + PURGE with an L2 backend. Each variant
        # store SADDs its L2 key into a per-base variant-index set; a PURGE of the
        # base URI SMEMBERS that set and drops every variant from L1 + L2 + the
        # index set, then deletes the node-local marker. The next request for each
        # axis value misses to origin (proves cross-tier variant invalidation).
        location /cor5/ {{
            cache_turbo          main;
            cache_turbo_key      $request_uri;
            cache_turbo_valid    30s;
            cache_turbo_auto_vary on;
            cache_turbo_purge    on;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # cross-node dogpile (v4-2): fresh TTL 2s -> stale_until = valid*4 = 8s,
        # a wide window so both lock tests have timing slack; aggressive beta so
        # a stale read reliably rolls a refresh; lock_ttl 5s = the Redis SET NX
        # PX hold (long enough to cap a multinode burst, short enough to model a
        # crashed peer's lock self-healing by PX expiry).
        # cache_turbo_lock off isolates the STALE-path NX under test from the v10
        # cold-path NX (otherwise the cold prime's NX would linger for lock_ttl
        # into the stale burst). Cold-path cross-node single-flight is covered by
        # /coldl2/ below.
        location /lock/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    2s;     # stale window: serveable until t+8s
            cache_turbo_beta     5000;   # aggressive: refresh likely while stale
            cache_turbo_lock_ttl 5s;     # cross-node NX PX = 5000ms
            cache_turbo_lock     off;    # isolate stale-path NX (see comment)
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # self-heal variant: SHORT lock_ttl (2s) so BOTH the per-box L1 refresh
        # lock and the cross-node NX PX clear quickly once the 'crashed' peer's
        # lock expires; wide stale window (valid*4 = 8s) leaves room to observe
        # the post-expiry regen.
        location /lockh/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    2s;     # stale window: serveable until t+8s
            cache_turbo_beta     5000;
            cache_turbo_lock_ttl 2s;     # local + NX hold = 2000ms
            cache_turbo_lock     off;    # isolate stale-path NX (see /lock/)
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # cold-miss single-flight (v10), cross-node: two nginx nodes share this
        # Redis. A concurrent cold burst across both collapses to ~1 origin fetch
        # -- the node that wins the SET NX PX regenerates + writes L2; the other
        # node's local winner loses the NX and waits for the L2 write-through.
        location /coldl2/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_lock_ttl 5s;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # AUD-NXLOCK-OWNER: same shape as /coldl2/ (cold-miss, L2-backed, lock
        # default ON) but with cache_turbo_no_store so the cross-node NX winner's
        # response is non-cacheable and the header filter's unstub() fires
        # immediately (module.c ~7861) instead of waiting for the pool cleanup
        # backstop. lock_ttl is LONG (30s) so the leaked L1 lease -- if the fix
        # regresses -- cannot expire mid-test and mask the bug (a short TTL lets
        # claim() ADOPT the stub instead of parking, making a buggy build look
        # exactly as fast as a fixed one). cache_turbo_key is a FIXED string,
        # not $uri, so /coldl2ns_probe/ below can hash to the identical L1 node
        # while never touching Redis -- see that location's comment for why.
        location /coldl2ns/ {{
            cache_turbo           main;
            cache_turbo_key       "aud-nxlock-owner-probe";
            cache_turbo_valid     30s;
            cache_turbo_lock_ttl  30s;
            cache_turbo_no_store  $arg_private;
            cache_turbo_redis     127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # AUD-NXLOCK-OWNER probe: same zone (main) and the SAME fixed key as
        # /coldl2ns/, but no cache_turbo_redis / cache_turbo_lock_ttl override
        # of its own -- cache_turbo_lock stays default ON but there is no L2
        # backend configured here, so clcf->backend->lock is never armed and a
        # claim() on this location can never fire (or park on) the Redis NX
        # lock. It can only ever see the SHARED zone's L1 node for that key.
        # This is what lets the test tell "L1 stub still refreshing" (the bug)
        # apart from "Redis NX lock still held by design" (expected, and NOT
        # what this item is about -- unlock() is intentionally never called
        # for the cross-node lock, so a second /coldl2ns/ request always parks
        # on Redis regardless of the L1 fix).
        location /coldl2ns_probe/ {{
            cache_turbo           main;
            cache_turbo_key       "aud-nxlock-owner-probe";
            cache_turbo_valid     30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # admin endpoint that is itself L2-aware: a single-key purge here must
        # also DEL the entry from Redis (P6), not just drop L1.
        location = /_cache_l2 {{
            cache_turbo_admin    main;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            allow 127.0.0.1;
            deny all;
        }}

        # SUITE-1: stats endpoint for the /l2neg/ zone. l2_neg_skips is per-zone
        # and the admin handler emits exactly ONE zone's stats, so a test that
        # isolates /l2neg/ into `l2negz` must read the counter HERE -- reading
        # /_cache (which is `cache_turbo_admin main`) would report a zone this
        # location no longer writes, making `delta == 0` trivially true.
        location = /_cache_l2neg {{
            cache_turbo_admin    l2negz;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            allow 127.0.0.1;
            deny all;
        }}

        # SUITE-1: same pairing for the long-memo outage location. A zone
        # without its own admin endpoint cannot be measured at all.
        location = /_cache_l2negout {{
            cache_turbo_admin    l2negoutz;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            allow 127.0.0.1;
            deny all;
        }}

        # SUITE-1 (s128): the other half of the l2neglifez/l2negmuz split. A
        # private zone without its own admin endpoint cannot be measured at all
        # -- the helper would keep reading `main`, a zone the location no longer
        # writes, and every delta assertion would be trivially satisfied.
        location = /_cache_l2neglife {{
            cache_turbo_admin    l2neglifez;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            allow 127.0.0.1;
            deny all;
        }}

        # /l2negmu/ writes BOTH l2_neg_skips and min_uses_skips, so this endpoint
        # is what _admin_min_uses_skips() must read for that location too.
        location = /_cache_l2negmu {{
            cache_turbo_admin    l2negmuz;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            allow 127.0.0.1;
            deny all;
        }}

        # Literal Redis glob metacharacters in a prefix must stay literal during
        # SCAN-based all-purge; only the module-appended final '*' is a wildcard.
        location = /_cache_l2glob {{
            cache_turbo_admin    main;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct*: timeout=250ms;
            allow 127.0.0.1;
            deny all;
        }}

        # AUD-SCAN1. Two admin endpoints on their OWN Redis prefix (ctscan:) so
        # a multi-page SCAN walk can be driven without touching any other L2
        # test's keyspace. They also sit in their OWN redis db (7): SCAN pages
        # are buckets of the whole db's hash table, not matched keys, so a db
        # shared with other tests makes "5 keys fit in one page" depend on how
        # much everyone else left behind. db 7 is FLUSHDB'd by these tests,
        # which also resets the table to its initial size.
        # /_cache_scanwalk has the production page cap;
        # /_cache_scancap lowers it to 2 pages (TEST_FAULTS-only directive) so
        # the "abandon the walk, report INCOMPLETE" branch is reachable without
        # materialising a 268M-key keyspace. Same `main` zone: these tests
        # assert on the L2 walk, not on the L1 count.
        location = /_cache_scanwalk {{
            cache_turbo_admin    main;
            cache_turbo_redis    127.0.0.1:{redis_port} db=7 prefix=ctscan: timeout=2s;
            allow 127.0.0.1;
            deny all;
        }}

        location = /_cache_scancap {{
            cache_turbo_admin    main;
            cache_turbo_redis    127.0.0.1:{redis_port} db=7 prefix=ctscan: timeout=2s;
            cache_turbo_test_scan_max_pages 2;
            allow 127.0.0.1;
            deny all;
        }}

        # AUD-PURGE-HONESTY1: admin endpoint whose L2 is DOWN -- the registry's
        # redis_dead offset is reserved and never bound, so the connect is
        # refused and scan_del returns NGX_ERROR without ever walking a page.
        # Its own prefix so a stray success here cannot disturb another test.
        location = /_cache_scandown {{
            cache_turbo_admin    main;
            cache_turbo_redis    127.0.0.1:{port + PORT_OFFSETS["redis_dead"]} prefix=ctdown: timeout=250ms;
            allow 127.0.0.1;
            deny all;
        }}

        # O4.4-i L2 half. Mirrors /brkion/ and /brkioff/, but with a Redis L2
        # configured so the breaker fallback is served from the L2 blob path --
        # the arming call site the L1 pair above provably cannot reach. Their own
        # `brkil2z` zone: the L1 pair leaves its breaker OPEN, and a shared zone
        # would let that state decide these requests.
        location /brkil2on/ {{
            cache_turbo                    brkil2z;
            cache_turbo_key                $uri;
            # valid 1s + keep_stale 300s. The entry is past its x4 stale
            # window within ~4s (so rem_stale <= 0, which is the L2 arming
            # site's precondition -- module.c ~5203), while keep_stale
            # pushes the REDIS retention window out to 300s via sie_ttl
            # (retain_ttl = max(stale_window, sie_window), module.c ~7705)
            # so the blob is still in L2 to be armed from.
            #
            # `cache_turbo_purge on` is what makes the L1 copy ABSENT rather
            # than merely expired -- the test PURGEs both keys and rewrites
            # the blob back into Redis (PURGE is L2-aware and DELs the key
            # too, module.c ~1711, so the order matters). Eviction via a
            # filler loop was tried and rejected: brkil2z eviction is LRU and
            # left the OFF key resident, which is exactly what made the OFF
            # half of the test vacuous for three sessions.
            cache_turbo_valid               1s;
            cache_turbo_keep_stale        300s;
            cache_turbo_purge               on;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            cache_turbo_redis              127.0.0.1:{redis_port} prefix=brkil2: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        location /brkil2off/ {{
            cache_turbo                    brkil2z;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;   # see /brkil2on/
            cache_turbo_keep_stale        300s;
            cache_turbo_purge               on;   # see /brkil2on/
            cache_turbo_breaker            off;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            cache_turbo_redis              127.0.0.1:{redis_port} prefix=brkil2: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
"""

    # L2 memcached (v13): a location wired to the memcached backend instead of
    # Redis. Emitted only when a MemcachedServer is running; scoped to /mc/ so it
    # never disturbs the Redis or L1-only locations. Distinct prefix (mc:) so its
    # keys can't collide with the Redis suite's ct: namespace.
    mc_loc = ""
    if memcached_port is not None:
        mc_loc = f"""
        # L2 memcached: write-through on store + sync fill on L1 miss
        location /mc/ {{
            cache_turbo            main;
            cache_turbo_key        $uri;
            cache_turbo_valid      30s;
            cache_turbo_memcached  127.0.0.1:{memcached_port} prefix=mc: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # L2 memcached with a keepalive pool (D-O1): idle pooled conns must carry
        # a close-on-readable handler. When the memcached server drops an idle
        # pooled conn, epoll wakes c->read; a NULL handler there SIGSEGVs the
        # worker. Exercised by test_mc_keepalive_server_close_survives.
        location /mcka/ {{
            cache_turbo            main;
            cache_turbo_key        $uri;
            cache_turbo_valid      30s;
            cache_turbo_memcached  127.0.0.1:{memcached_port} prefix=mck: timeout=250ms keepalive=4 keepalive_timeout=30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # MC-A2: SAME memcached peer as /mcka/ but keepalive explicitly 0. The
        # documented contract is a fresh connection per op; before the fix
        # mc_connect looked the pool up by peer address only, so this location
        # borrowed (and, because ka_save does check zero, then CLOSED) sockets
        # /mcka/ had pooled -- draining another location's pool. Exercised by
        # test_mc_keepalive_zero_does_not_drain_pool.
        location /mcka0/ {{
            cache_turbo            main;
            cache_turbo_key        $uri;
            cache_turbo_valid      30s;
            cache_turbo_memcached  127.0.0.1:{memcached_port} prefix=mck0: timeout=250ms keepalive=0;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Short idle timeout (D-O1): a pooled conn left idle past 1s must be
        # dropped by mc_ka_close_handler's ev->timedout branch, not leak/crash.
        # Exercised by test_mc_keepalive_idle_timeout_drops.
        location /mckashort/ {{
            cache_turbo            main;
            cache_turbo_key        $uri;
            cache_turbo_valid      30s;
            cache_turbo_memcached  127.0.0.1:{memcached_port} prefix=mcks: timeout=250ms keepalive=4 keepalive_timeout=1s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # D-O2: a keepalive location pointed at a DELIBERATELY MISBEHAVING fake
        # memcached (PORT_OFFSETS["mc_dirty_reply"], stood up only by
        # test_mc_dirty_reply_not_pooled on the PRIMARY instance). The address is
        # derived from memcached_port, not from this instance's own `port`: a
        # second nginx (test_l2_memcached_cross_instance_fill's instance B) runs
        # on a different port but must still point at the one fake memcached.
        # A reply that does not frame cleanly at
        # a boundary (trailing junk past END/STORED, a server error, a timeout)
        # must NOT be returned to the pool -- the connection is closed instead, so
        # a reuse never resumes mid-reply. Same keepalive size as /mcka/.
        location /mcdirty/ {{
            cache_turbo            main;
            cache_turbo_key        $uri;
            cache_turbo_valid      30s;
            cache_turbo_memcached  127.0.0.1:{memcached_port + PORT_OFFSETS["mc_dirty_reply"] - PORT_OFFSETS["memcached"]} prefix=mcd: timeout=250ms keepalive=4 keepalive_timeout=30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # memcached-backed admin: a single-key purge here must also delete the
        # entry from memcached (not just drop L1).
        location = /_cache_mc {{
            cache_turbo_admin      main;
            cache_turbo_memcached  127.0.0.1:{memcached_port} prefix=mc: timeout=250ms;
            allow 127.0.0.1;
            deny all;
        }}
"""

    # Backend-inheritance regression (precedence bug FIXED 2026-06-12): a parent
    # location naming cache_turbo_memcached (memcached=1) enclosing a child that
    # names cache_turbo_redis. The child MUST drive its own address with the Redis
    # backend, not inherit the parent's memcached=1 (the merge would otherwise
    # select the memcached driver for a redis:// address). Needs BOTH L2 servers.
    mcinh_loc = ""
    if memcached_port is not None and redis_port is not None:
        mcinh_loc = f"""
        location /mcinh/ {{
            cache_turbo            main;
            cache_turbo_key        $uri;
            cache_turbo_valid      30s;
            cache_turbo_memcached  127.0.0.1:{memcached_port} prefix=mc: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;

            # child overrides the parent's memcached backend with Redis
            location /mcinh/child/ {{
                cache_turbo_redis  127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
                proxy_pass http://127.0.0.1:{origin_port}/;
            }}
        }}
"""
    mc_loc += mcinh_loc

    fault_loc = ""
    if fault_injection:
        fault_loc = f"""
        # CI-only allocation fault injection. These directives are compiled only
        # by ci/tools/ci-build.sh and are absent from production/package builds.
        location /allocfail/ {{
            cache_turbo                         main;
            cache_turbo_key                     $uri;
            cache_turbo_valid                   30s;
            cache_turbo_test_restore_alloc_fail on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        location /allocfailst/ {{
            cache_turbo                         main;
            cache_turbo_key                     $uri;
            cache_turbo_valid                   301 30s;
            cache_turbo_test_restore_alloc_fail on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        location /allocfailsie/ {{
            cache_turbo                         main;
            cache_turbo_key                     $uri;
            cache_turbo_valid                   1s;
            cache_turbo_test_restore_alloc_fail on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # CI-only: force the body filter onto the file-backed delegate path
        # (the sendfile-abort branch) deterministically, without depending on
        # directio/O_DIRECT fs alignment. Nothing must ever store here.
        location /forcefile/ {{
            cache_turbo                    main;
            cache_turbo_key                $uri;
            cache_turbo_valid              30s;
            cache_turbo_test_force_file_buf on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # AUD-STORE-ERR-STUB: force the body filter's l1->store() to fail
        # deterministically, so a cold-miss winner's stub cleanup path is
        # reachable without depending on real slab exhaustion timing.
        #
        # lock_ttl is LONG (30s) on purpose: the leaked stub must still hold a
        # LIVE lease when the second request arrives, or claim() adopts the
        # expired stub instead of parking on it and the test stops
        # discriminating (see test_store_failure_cleans_up_cold_stub). The
        # oracle is the lock_waits counter, so nothing here waits out a
        # timeout -- lock_timeout stays short to bound the buggy-build park.
        location /storefail/ {{
            cache_turbo                  storefailz;
            cache_turbo_key              $uri;
            cache_turbo_valid            30s;
            cache_turbo_lock_ttl         30s;
            cache_turbo_lock_timeout     2s;
            cache_turbo_test_store_fail  on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # AUD-STORE-ERR-STUB: admin endpoint for /storefail/'s private zone
        # (storefailz), same reasoning as /_cache_s71 -- /_cache is bound to
        # `main` and would read a lock_waits counter this zone never writes,
        # and (unlike s71z) `main` is never quiescent: it is shared by 166
        # other locations, so an exact-equality assert against it is
        # order-dependent on whatever else in the suite happens to park in
        # cold_wait() between this test's two samples.
        location = /_cache_storefail {{
            cache_turbo_admin    storefailz;
            allow 127.0.0.1;
            deny all;
        }}
"""

    return f"""{load}worker_processes {workers};
pid {root}/nginx.pid;
error_log {root}/logs/error.log {_errlog_level()};

events {{ worker_connections 512; }}

http {{
    access_log off;

    cache_turbo_zone name=main 16m;

    # DOC-A2: the front-controller redirect replaces r->uri, so preset URI rules
    # and cache_turbo_bypass_uri (both compare r->uri) stop seeing the real
    # route. $request_uri still carries it -- the pattern docs/xenforo.md now
    # prescribes for private routes behind a front controller.
    map $request_uri $ctir_private_route {{
        default 0;
        ~^/ctir-fixed/(?:api|login|account)(?:[/?]|$) 1;
    }}
    cache_turbo_zone name=tiny 8m;   # small zone for eviction test (R6)
    # S8: 32k == the enforced minimum (8 * pagesize). Deliberately the SMALLEST
    # legal zone so a few hundred unique keys genuinely overflow it and force
    # real eviction -- an 8m zone holds tens of thousands of these tiny bodies,
    # so the scan would evict nothing and every S8 assertion would pass for the
    # wrong reason.
    cache_turbo_zone name=srz 64k;    # S8 scan-resistant ON
    cache_turbo_zone name=sroffz 64k; # S8 default-off control (absent)
    cache_turbo_zone name=srexpz 64k; # S8 explicit `off` control
    cache_turbo_zone name=shmref 16m; # refresh-under-pressure (R6b)
    cache_turbo_zone name=at 16m;    # autotune raise/clamp/off (v4-3)
    cache_turbo_zone name=atl 16m;   # autotune load-adaptive stale widen (v4-4)
    cache_turbo_zone name=ati 16m;   # autotune insufficient-data (v4-3)
    cache_turbo_zone name=atch 16m;  # autotune churn-disqualify (v4-3)
    cache_turbo_zone name=ka0 8m;    # Redis keepalive DB-isolation test
    cache_turbo_zone name=ka1 8m;    # Redis keepalive DB-isolation test
    # S2.3: 64k == enforced minimum, same reasoning as S8's srz -- a handful of
    # unique keys genuinely overflow this zone and force real LRU eviction,
    # unlike an 8m/16m zone where the contract test would pass for the wrong
    # reason (nothing ever gets evicted). Drives the no-reaper contract test.
    cache_turbo_zone name=ksevz 64k; # keep_stale no-reaper / LRU-only-reclaim (S2.3)
    # O4.4-i arming-site control. Its OWN zone, not `main`: the test trips the
    # breaker and leaves it OPEN, which would make the older black-box
    # test_breaker_arming_gated_on_breaker_enable() (also on `main`) serve its
    # tripping request from the fallback instead of reaching the dead origin.
    cache_turbo_zone name=brkiz 16m;
    # O4.4-i L2 half. A SECOND private zone for the L2-backed arming pair
    # (/brkil2on/, /brkil2off/). Separate from brkiz because the L1 pair leaves
    # its own breaker OPEN and the two must not share a breaker state; separate
    # from `main` for the same reason brkiz is. Deliberately TINY (64k) so an
    # entry stored here is evicted from L1 promptly, which is what forces the
    # fallback to come from L2 rather than from an L1 hit -- an L1 hit would
    # bump the l1 counter and prove nothing about the L2 site.
    cache_turbo_zone name=brkil2z 64k;
    # O4.4-d: private zone for the breaker-policy-divergence config-time
    # warning tests. Its OWN zone, not `main` or `brkiz`: both already carry
    # a first-seen breaker policy from other locations, so reusing them would
    # make the "identical tuple, no warning" negative control depend on
    # matching an unrelated fixture's numbers instead of on the two injected
    # locations agreeing with each other.
    cache_turbo_zone name=brkpolz 16m;
    # S7.1: private zone for the breaker_serves/origin_failures counter tests.
    # Its OWN zone, not `brkiz` or `main` -- both already carry breaker trips
    # from other tests by the time these run, and a delta-based assertion
    # needs a breaker that starts CLOSED so the "tripping request reaches the
    # dead origin, the NEXT one is the counted breaker_serves" sequencing
    # (same two-fetch shape as test_breaker_arming_gated_on_breaker_enable) is
    # unambiguous. Its own admin endpoint (/_cache_s71) for the same reason
    # l2negz needed /_cache_l2neg: /_cache is bound to `main` and would read a
    # counter this zone never writes.
    cache_turbo_zone name=s71z 16m;
    # H7.3a: private zone for the Prometheus breaker_opens_total/breaker_state
    # coverage. NOT s71z -- s71z's breaker is left OPEN by test_breaker_counters
    # by the time this runs in run_all()'s ordering, which would make this
    # test's own prime fetch (expected 200, CLOSED) 503 instead. Same
    # "own zone" reasoning as brkiz/s71z above, just one more private zone
    # because s71z is already spent by the time H7.3a needs a CLOSED breaker.
    cache_turbo_zone name=h73z 16m;
    # S7.2: private zone for $cache_turbo_serve_reason coverage. NOT s71z --
    # s71z's breaker is already tripped OPEN by test_breaker_counters by the
    # time this runs in run_all()'s ordering, which would make this test's
    # own FRESH/STALE priming (expects a CLOSED breaker, 200s) collide with a
    # leftover OPEN state. Also needs its own zone for the BREAKER-503 arm: a
    # SECOND uri on the SAME zone, never primed, so it hits breaker_unavailable()
    # once the first uri's dead-origin fetch trips the breaker OPEN -- reusing
    # s71z would let /s71brk/'s trip leave it OPEN too early or too late
    # relative to this test's own sequencing.
    cache_turbo_zone name=sr72z 16m;
    # O4.5: private zone for the breaker LIFECYCLE runtime coverage (state
    # machine end-to-end: OPEN on N failures, zero origin contact while OPEN,
    # 503+Retry-After on a cold key, CLOSE via the post-open probe). Own zone,
    # not s71z/brkiz/h73z/sr72z -- every one of those is left in a tripped or
    # otherwise non-CLOSED state by an earlier test in run_all()'s ordering,
    # and this test needs to observe the FULL CLOSED->OPEN->(probe)->CLOSED
    # cycle from a known-clean start. A short 2s breaker_open (vs. the 30s
    # every other breaker fixture uses) keeps the CLOSE-via-probe assertion
    # fast without idling the suite.
    cache_turbo_zone name=o45z 16m;
    # O4.5 negative control: identical shape, breaker OFF -- proves the OPEN
    # zone's zero-origin-contact result above is caused by the breaker, not
    # some other widening (e.g. keep_stale). Own zone so its origin hit count
    # is never polluted by o45z's traffic.
    cache_turbo_zone name=o45offz 16m;
    # O4.5 / O4.2-f: private zone for the header-filter recording-block pins
    # (success/failure sense of the argument; a cache-turbo HIT records
    # nothing). Own zone so its origin_failures counter cannot be moved by
    # o45z's own trip.
    cache_turbo_zone name=o45hitz 16m;
    # O4.5 / O4.2-f: SEPARATE zone for the POSITION pin only (recording
    # happens before the SIE rewrite). Threshold=1 means the very failure
    # this claim exercises trips the zone's breaker OPEN, and a SECOND trip
    # on a shared zone would hit the pre-origin gate instead of the origin
    # -- own zone so o45hitz's own claim-1 trip (recorded separately) cannot
    # leave this claim's zone already OPEN, or vice versa.
    cache_turbo_zone name=o45hitposz 16m;
    # SUITE-1: private zone for /l2neg/. l2_neg_skips is PER-ZONE
    # (z->sh->l2_neg_skips, module.c:4832), and the outage test asserts a delta
    # of exactly 0 over one request, so any other location writing that counter
    # inside the window fails an assertion about a different URI.
    #
    # !! Scope of that risk, corrected: the increment at module.c:4832 is gated
    # on `clcf->l2_negative_ttl > 0` (module.c:4822), and only FOUR locations
    # in this config set it -- /l2neg/, /l2negout/, /l2neglife/, /l2negmu/.
    # The ~40 other locations sharing `main` are NOT counter writers and never
    # could be, so the "zone bleed from ~40 locations" story is wrong; the real
    # contention was always between these FOUR siblings.
    #
    # As of s128 all four sit in private zones, and the mechanism is PROVEN
    # rather than argued: with /l2neglife/ still in `main`, injecting one
    # memo-skipped /l2negmu/ request into the assertion window of
    # test_l2_negative_ttl_expires moves its delta 0 -> 1; the identical
    # injection against an already-isolated location leaves it at 0. Same
    # binary, same timing, only the zone differs. The harness bounded the
    # window by error.log byte offsets, so an in-window URI provably landed
    # between the two admin reads (unlike _recent_memo_skips(), which tails the
    # WHOLE log and can show a URI that predates the test -- that is most
    # likely what made the discarded ~40-location story look confirmed).
    #
    # !! Still NOT established: that this was the cause of the ORIGINAL SUITE-1
    # intermittency. No foreign write has been observed landing naturally in
    # that window -- only an injected one. A recurrence is therefore possible
    # and would NOT be a regression from this change.
    # NOTE Isolating the zone is only HALF the fix: /_cache is `cache_turbo_admin
    # main`, so a helper reading it after this move would read a counter this
    # location no longer writes and `delta == 0` would be trivially true forever.
    # The paired admin endpoint /_cache_l2neg below is the other half; the two
    # must be changed together or the test goes quiet instead of going correct.
    #
    # 1m, not 16m: these locations run min_uses 4 over a handful of unique keys
    # and store essentially nothing, so the zone only ever holds counter nodes.
    # Sizing them at 16m each cost 32m of shared memory for no coverage, which
    # matters under ASan where the redzone overhead per allocation is large.
    cache_turbo_zone name=l2negz 1m;
    # SUITE-1: private zone for the long-memo outage location (/l2negout/), kept
    # separate from l2negz so the 60s memo cannot bleed into the short-window
    # repeat-GET test's counter, and vice versa.
    cache_turbo_zone name=l2negoutz 1m;
    # SUITE-1 (s128): private zones for the last two memo locations. These were
    # left in `main` by the first split, which kept the defect alive at
    # test_l2_negative_ttl_expires' `delta == 0` -- /l2neglife/ and /l2negmu/ are
    # BOTH l2_neg_skips writers, so a request to one failed an assertion about
    # the other. PROVEN, not argued: same binary, same timing, inject a
    # memo-skipped request mid-window and the delta moves 0 -> 1 when the
    # injected location shares `main`, and stays 0 when it sits in a private
    # zone (see issues.md / HANDOFF for the log-offset-bounded harness).
    #
    # /l2negmu/ also sets min_uses, so this move additionally takes it out of the
    # min_uses_skips contention set that /minuses/ and /pmu/ still share in
    # `main` -- those two keep `== N` equality asserts and are now the only
    # remaining writers of that counter there.
    #
    # 1m for the same reason as l2negz: counter nodes only, and ASan redzones
    # make an oversized zone expensive.
    cache_turbo_zone name=l2neglifez 1m;
    cache_turbo_zone name=l2negmuz 1m;

    # BRK-RA1: private zones for the breaker_retry_after auto-track
    # regression pin. TWO zones, not one shared by /ra1/ and /ra1exp/ --
    # breaker STATE is per-zone (same O4.4-d reasoning as the policy-warn
    # block), so tripping /ra1/'s breaker OPEN would leave /ra1exp/'s own
    # prime fetch answered straight from breaker_unavailable() too, before
    # its own dead-origin trip ever runs. Own zones (not sr72z/s71z/brkiz/
    # etc.) so neither test's own CLOSED-breaker prime is polluted by
    # another test's already-tripped breaker by the time run_all() gets
    # here, same "own zone" reasoning as s71z/h73z/sr72z above.
    cache_turbo_zone name=raz 16m;
    cache_turbo_zone name=raexpz 16m;
    # AUD-STORE-ERR-STUB: private zone for /storefail/'s lock_waits oracle.
    # NOT `main` -- `main` is shared by 166 other test locations, including
    # test_cold_single_flight's 40 deliberately-parking concurrent readers,
    # whose stragglers can land between this test's w0/w1 samples and move
    # the exact-equality assert on an unrelated build (see
    # test_store_failure_cleans_up_cold_stub). Own zone + own admin endpoint
    # (/_cache_storefail) makes the assert observe only /storefail/ traffic.
    cache_turbo_zone name=storefailz 16m;

    # Q1 end-to-end: stacked native proxy_cache, one zone per suppress mode, so
    # a test can prove cache_turbo_suppress_native actually keeps the native
    # cache empty (vs the inert default where proxy_cache stores normally).
    proxy_cache_path {root}/pcache_on  keys_zone=ctpcon:1m  levels=1:2
                     inactive=10m max_size=64m;
    proxy_cache_path {root}/pcache_off keys_zone=ctpcoff:1m levels=1:2
                     inactive=10m max_size=64m;
    # O4.2-f: dedicated proxy_cache zone for /o45natpc/'s native-HIT-records-
    # nothing check. NOT ctpcon -- test_suppress_native_e2e_proxy_cache
    # asserts ctpcon stays EMPTY (proof cache_turbo_suppress_native
    # suppressed it), and /o45natpc/ deliberately stores through its own
    # proxy_cache normally, which would pollute that assertion.
    proxy_cache_path {root}/pcache_o45 keys_zone=ctpo45:1m levels=1:2
                     inactive=10m max_size=64m;

    server {{
        listen 127.0.0.1:{port};
{sk_loc}
{redis_loc}
{mc_loc}
{dsn_loc}
{fault_loc}

        # SERVER-level preset: inherited by every location that does not name a
        # backend of its own. /nonepreset/ overrides it with `none` -- that is
        # the whole point of `none`, and without an inherited preset here that
        # test would pass vacuously.
        cache_turbo_backend wordpress;

        # standard 30s-fresh cache
        location /c/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_max_size 1m;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # compressed-edge regression (2026-06-13 incident): a real nginx gzip
        # filter sits in front of cache_turbo. gzip_proxied any + gzip_min_length
        # 1 force compression even on the tiny origin body. With the dh_nginx
        # prio-80 load-order fix cache_turbo's body filter runs ABOVE gzip, so it
        # captures the IDENTITY body (no Content-Encoding) and gzip re-encodes per
        # client on MISS and HIT alike. Drives test_compressed_edge_identity_capture.
        location /gz/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            gzip                 on;
            gzip_types           application/json;
            gzip_min_length      1;
            gzip_proxied         any;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # cold-miss single-flight (v10), per-box: cache_turbo_lock is ON by
        # default, so a burst of first-hits on one cold key collapses to a
        # single origin fetch; the rest wait then serve the filled entry.
        location /cold/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_lock_ttl 5s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # cold-miss single-flight DISABLED: the gate-off control. The same burst
        # stampedes the origin (one hit per reader).
        location /coldoff/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_lock     off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # min_uses (v15): only cache after the key has cold-missed 3 times, so a
        # one-hit-wonder URL never occupies the cache. The first two misses go to
        # the origin without storing; the third stores; the fourth is a HIT.
        location /minuses/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_min_uses 3;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # cacheability floor (RFC 9111): origin emits Set-Cookie / Cache-Control
        # based on the path marker; such responses must never be stored. key=$uri
        # so repeated requests share a slot (proving the refusal, not just a key
        # split).
        location /cc/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ignore_cc: with cache_turbo_cache_control ignore, the response
        # Cache-Control floor (here max-age=0 via the ccmaxage0 path marker) is
        # ignored and the entry is stored at cache_turbo_valid. Mirrors nginx
        # proxy_ignore_headers Cache-Control. key=$uri to share a slot.
        location /ccign/ {{
            cache_turbo               main;
            cache_turbo_key           $uri;
            cache_turbo_valid         30s;
            cache_turbo_cache_control ignore;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # default cache key (no cache_turbo_key) = $host$request_uri, so two
        # Host headers on the same path must NOT collide.
        location /dk/ {{
            cache_turbo          main;
            cache_turbo_valid    30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # conditional requests (v11): origin emits ETag + Last-Modified; a HIT
        # whose stored validators satisfy If-None-Match / If-Modified-Since is
        # answered 304 (no body) straight from cache.
        location /cond/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # AUD-RANGE1: origin honours Range (rngsrc path marker); a HIT must
        # answer Range: identically to a MISS instead of always replaying 200.
        location /range/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Range over a STALE-IF-ERROR serve. r->allow_ranges is set in
        # restore_response(), which sie_rewrite() shares with the live HIT path,
        # so the SIE serve must range identically to a HIT. Same short-fresh
        # shape as /sieserve/ (1s fresh, stale window x4 = 4s, fully expired by
        # ~5s) but with the rngsrc+rngsie markers so the stored blob is
        # Range-capable AND carries stale-if-error=30. Drives
        # test_range_on_sie_serve.
        location /rangesie/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 1s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # RFC-6: short fresh TTL + ETag (the origin emits validators for any
        # path containing "cond") so a conditional request can be made against a
        # STALE entry. beta 1 ~ never rolls a refresh, so the read is a
        # deterministic STALE serve - and a 304 must NOT be answered from it.
        location /condst/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 1s;
            cache_turbo_beta  1;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # RFC-2: fresh 1s; default stale window would be 3s (stale_mult 4 ->
        # expire at 4s), but the origin's stale-while-revalidate=10 extends it,
        # so the entry is still STALE-serveable at 5s. beta 1 ~ no refresh.
        location /swrdur/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 1s;
            cache_turbo_beta  1;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # per-status caching (v6): cache redirects + negative responses too
        location /st/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 30s;
            cache_turbo_valid 301 302 308 30s;
            cache_turbo_valid 404 410 30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # honor upstream Cache-Control (v7): origin says max-age=1, so the entry
        # goes stale at ~1s even though cache_turbo_valid is 60s. beta 1 ~ never
        # refresh, so a read inside the stale window is deterministically STALE.
        location /cc7/ {{
            cache_turbo                    main;
            cache_turbo_key                $uri;
            cache_turbo_valid              60s;
            cache_turbo_beta               1;
            cache_turbo_cache_control       honor;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # must-revalidate (RFC 9111): honor_cc reads max-age=1 (fresh 1s); the
        # must-revalidate token collapses the stale window, so at ~2s the entry
        # is NOT stale-served (as /cc7/ would be) but re-fetched. beta 1 ~ never
        # rolls a refresh, isolating the must-revalidate behaviour.
        location /mrev/ {{
            cache_turbo                    main;
            cache_turbo_key                $uri;
            cache_turbo_valid              60s;
            cache_turbo_beta               1;
            cache_turbo_cache_control       honor;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # AUD-CC-FIRST-LINE: same must-revalidate collapse as /mrev/, but the
        # origin (splitmrev marker) sends max-age and must-revalidate on TWO
        # separate Cache-Control field-lines instead of one. Proves the fix
        # walks every Cache-Control line rather than only the first.
        location /ccsplit/ {{
            cache_turbo                    main;
            cache_turbo_key                $uri;
            cache_turbo_valid              60s;
            cache_turbo_beta               1;
            cache_turbo_cache_control       honor;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ignore_cc vs must-revalidate: cache_turbo_cache_control ignore must
        # make the ENTIRE response Cache-Control inert, not just the cacheability
        # floor. The origin emits "max-age=1, must-revalidate"; without ignore
        # the must-revalidate token collapses the stale window (like /mrev/), but
        # with ignore the window stays valid*stale_mult (2s*4 = 8s), so at ~4s
        # the entry is still STALE-served, not a hard miss. fresh = valid 2s
        # (ignore forces honor off). beta 1 ~never rolls a refresh, so the
        # stale read is a clean STALE serve (no dice regen polluting origin).
        #
        # !! valid is 2s, NOT the 1s the origin declares, and the test's sleep
        # is sized from it. At valid 1s the prime->HIT assert raced the 1s fresh
        # edge: a loaded runner (ASan, busy CI box) taking >1s between the two
        # fetches makes STALE the CORRECT answer and the test fails on box speed,
        # not on module behaviour (SUITE-4). Both edges scale together -- widening
        # valid alone would move the stale read back inside the FRESH window and
        # break the STALE assert instead.
        #
        # Total serve life is valid*stale_mult ABSOLUTE, not fresh + stale on top:
        # shm_store() sets stale_until = now + stale_ttl(valid, stale_mult), so
        # 2s*4 = 8s total == 2s fresh + 6s stale. When retuning, the sleep must
        # satisfy valid < sleep < valid*(stale_mult-1) -- the lower slack absorbs
        # the prime, and the upper one the elapsed time before the sleep starts.
        # Here that is 2 < 4 < 6.
        location /ccignmr/ {{
            cache_turbo               main;
            cache_turbo_key           $uri;
            cache_turbo_valid         2s;
            cache_turbo_beta          1;
            cache_turbo_cache_control ignore;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # PURGE method (v14): `PURGE /pg/x` drops that entry from L1 (+L2)
        location /pg/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 30s;
            cache_turbo_purge on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Access-phase regression: both locations use the same cache key, but
        # the denied location must reject a cached GET and PURGE before cache
        # lookup/side effects run.
        location /acl-seed/ {{
            cache_turbo       main;
            cache_turbo_key   $arg_k;
            cache_turbo_valid 30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /acl-denied/ {{
            cache_turbo       main;
            cache_turbo_key   $arg_k;
            cache_turbo_valid 30s;
            cache_turbo_purge on;
            deny all;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # bypass (v9): ?nocache=1 skips the cache lookup but still refreshes it
        location /bp/ {{
            cache_turbo        main;
            cache_turbo_key    $uri;
            cache_turbo_valid  30s;
            cache_turbo_bypass $arg_nocache;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # DIY manual URI bypass (cache_turbo_bypass_uri, v15): the preset
        # segment-boundary matcher exposed as a directive, for an app we ship no
        # preset for. "/bu/panel" bypasses on a segment boundary; "/bu/panel-x"
        # (letters continue past the needle) must NOT -- that boundary check is
        # exactly what a plain nginx location prefix cannot express. Mounted at a
        # subdir to prove the matcher is subdirectory-safe. X-CT-Status makes
        # BYPASS a POSITIVE signal (a plain MISS also lacks x-cache).
        location /bu/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_bypass_uri /bu/panel /bu/admin/;
            add_header           X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Subdirectory install (cache_turbo_backend_prefix, item 18): preset
        # uris[] are literals anchored at byte 0 ("/wp-admin/"), so a WordPress
        # mounted at /shop/ matches NO URI rule and its admin surface caches.
        # The directive rebases r->uri onto the mount before the preset URI tier
        # runs. /shop/ has it; /noshop/ is the SAME app WITHOUT it and exists to
        # pin that the bug is real -- if /noshop/wp-admin/ ever stops caching,
        # the /shop/ assertions below are passing for the wrong reason.
        location /shop/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_backend  wordpress;
            cache_turbo_backend_prefix /shop/;
            add_header           X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Directive value deliberately does NOT match this location's own path:
        # requests here reach the module with backend_prefix set to /shop/ while
        # r->uri starts with /elsewhere/, which is the ONLY way to exercise the
        # no-rebase branch (a request routed to /shop/ always starts with it).
        # A misconfigured mount must leave the URI alone, not force a match.
        location /elsewhere/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_backend  wordpress;
            cache_turbo_backend_prefix /shop/;
            add_header           X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        location /noshop/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_backend  wordpress;
            add_header           X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # DIY cookie value-keying (cache_turbo_key_cookie, v15): the tier-3
        # magento engine exposed as a directive. "seg" is value-keyed into the
        # cache key -- different values get different entries, the SAME value
        # shares one, and an absent cookie is its own anonymous bucket. Same
        # unforgeable length-prefixed fold, EXACT-name match, all Cookie headers
        # scanned -- but with NO preset.
        location /kc/ {{
            cache_turbo            main;
            cache_turbo_key        $uri;
            cache_turbo_valid      30s;
            cache_turbo_key_cookie seg;
            add_header             X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # $cache_turbo_status access-log variable: echoed into a header so the
        # test can read MISS -> HIT, and BYPASS when ?nocache=1 trips bypass.
        location /ctstatus/ {{
            cache_turbo        main;
            cache_turbo_key    $uri;
            cache_turbo_valid  30s;
            cache_turbo_bypass $arg_nocache;
            add_header         X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # $cache_turbo_status STALE + EXPIRED: short fresh TTL (1s) so the
        # default stale_mult 4 gives a 4s serveable window; beta 1 keeps the
        # refresh dice at ~0 so a stale read is a clean STALE serve (not a
        # refresh-to-HIT), and sleeping past 4s makes the entry EXPIRED.
        location /ctstale/ {{
            cache_turbo        main;
            cache_turbo_key    $uri;
            cache_turbo_valid  1s;
            cache_turbo_beta   1;
            add_header         X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # RFC-1 request Cache-Control serve verdict (req_serve_verdict): a
        # client's own max-age/min-fresh/max-stale bound the entry it will
        # accept. Long fresh window (30s) so the entry is unambiguously FRESH
        # for the max-age/min-fresh cases; a separate 1s+beta1 sibling (/reqccst/)
        # lets an entry go STALE so max-stale tolerance can be exercised.
        location /reqcc/ {{
            cache_turbo        main;
            cache_turbo_key    $uri;
            cache_turbo_valid  30s;
            add_header         X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /reqccst/ {{
            cache_turbo        main;
            cache_turbo_key    $uri;
            cache_turbo_valid  1s;
            cache_turbo_beta   1;
            add_header         X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # cc_mode (cache_turbo_cache_control) merge precedence: a child location
        # with a CMS backend preset (cc_mode defaults to honor) under a parent
        # that set `ignore` must resolve to HONOR, NOT inherit the parent ignore
        # (the merged tri-state cannot represent "both" the way the old two-flag
        # model accidentally did). honor respects the cacheability floor, so the
        # origin's `private` response is NOT cached at the child; the parent
        # (ignore) DOES cache it. Origin emits "private, max-age=60" for ccprivate.
        location /ccinh/ {{
            cache_turbo               main;
            cache_turbo_key           $uri;
            cache_turbo_valid         30s;
            cache_turbo_cache_control ignore;
            proxy_pass http://127.0.0.1:{origin_port}/;

            location /ccinh/wp/ {{
                cache_turbo         main;
                cache_turbo_backend wordpress;
                cache_turbo_key     $uri;
                cache_turbo_valid   30s;
                proxy_pass http://127.0.0.1:{origin_port}/;
            }}
        }}

        # no_store (v9): ?private=1 means the response is never stored
        location /nost/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_no_store $arg_private;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # short fresh TTL so the stale window is reachable in-test
        location /swr/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;     # stale window = 3s, expires at 4s
            cache_turbo_beta     5000;   # aggressive: refresh likely while stale
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # stale-if-error (v8): background_update is ON by default, so a stale
        # dice-winner serves stale + refreshes in the background. A failing
        # origin never overwrites the entry -> the stale copy persists.
        location /sie/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    2s;     # fresh 2s, stale window x4 -> 8s
            cache_turbo_beta     5000;   # aggressive: a stale read fires a refresh
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # RFC-2 stale-if-error serve-on-error (CTB4). Short fresh (1s -> stale
        # window x4 = 4s, fully expired by ~5s). The origin emits
        # stale-if-error=30 ONLY when the request suffix carries the "sieserve"
        # marker (proxy_pass strips the /sieserve/ prefix), so a /sieserve/sieserve-*
        # key gets a serve-on-error window and a /sieserve/plain-* key does NOT.
        # The plain-* key is the negative control: an expired entry with no SIE
        # window must surface the origin error. Drives test_sie_serve_on_error.
        location /sieserve/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # AUD-SIE-BODY regression: same fixture shape as /sieserve/ (the
        # "sieserve" request-suffix marker still reaches the origin, since
        # proxy_pass only strips the /siebuf/ prefix) but with proxy_buffering
        # off. The body filter's sie_serving block discards the incoming
        # upstream error chain without marking it consumed; under a buffered
        # upstream there is slack so the bug never reproduces, but with
        # buffering off the discarded buffers stay on the upstream's
        # busy_bufs forever and the request hangs. Drives
        # test_sie_serve_on_error_unbuffered.
        location /siebuf/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            proxy_buffering       off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # UNBUF: proxy_buffering off with an ordinary (non-error) streamed
        # multi-chunk origin body. /siebuf/ above only drives the SIE
        # serve-on-error body-filter consume path; this location covers the
        # ordinary capture/store + HIT-serve path under the SAME
        # multi-invocation body filter, exercising ctx->body_last append and
        # last_buf/last_in_chain accumulation across calls. Drives
        # test_unbuf_streamed_store_and_hit.
        location /unbuf/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            proxy_buffering       off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # UNBUF oversize: same proxy_buffering off + streamed multi-chunk
        # origin body as /unbuf/, but with a small cache_turbo_max_size so the
        # limit is crossed MID-STREAM on a later body-filter invocation
        # rather than on the first buffer. Drives
        # test_unbuf_oversize_abort_mid_stream.
        location /unbufbig/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_max_size 8k;
            proxy_buffering       off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S2.2: cache_turbo_keep_stale feeds sie_window when the response
        # carries NO stale-if-error of its own (D-1 precedence table). Origin
        # for this location sends no Cache-Control at all -> keep_stale is the
        # only thing standing between an expired entry and a surfaced error.
        # Short fresh (1s) / stale (x4 = 4s) window like /sieserve/ so the
        # entry is fully expired quickly. Drives test_keep_stale_serves_dead_origin.
        location /keepstale/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_keep_stale 1h;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S4.2: cache_turbo_use_stale decides WHICH upstream statuses fall back
        # to a stale copy. keep_stale 1h supplies the serve-on-error window (the
        # origin for these locations sends no Cache-Control), so the only
        # variable between the three locations below is the use_stale mask.
        #
        # http_404 alone: a 404 must serve stale, and a 503 must NOT (the mask
        # names 404 and nothing else). That second half is what makes this test
        # discriminating -- a broken mask read that just triggers on everything
        # passes the 404 arm on its own. Drives test_use_stale_http_404.
        location /usestale404/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_keep_stale 1h;
            cache_turbo_use_stale http_404;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Negative control for /usestale404/: identical apart from the missing
        # use_stale directive, i.e. the merge default (every 5xx, no 404). A 404
        # here must surface as a 404. If this location ever serves stale on a
        # 404, the default mask has been widened or the merge is broken.
        location /usestaledefault/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_keep_stale 1h;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S4.2 / S4.1-b: pins ANY_5XX down. The mask names http_500 only, so a
        # 500 serves stale while a 507 -- a 5xx no explicit bit covers -- must
        # surface. Dropping ANY_5XX from USE_STALE_DEFAULT is invisible to the
        # parse tests and to the two locations above; this one catches it via
        # /usestaledefault/ (default mask, 507 -> stale) versus here.
        location /usestale500/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_keep_stale 1h;
            cache_turbo_use_stale http_500;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S4.2: `off` is not "no directive" -- it is an EMPTY mask, so nothing
        # triggers a stale serve, not even the 5xx the default covers. Same
        # keep_stale 1h window as its siblings, so the window is not what
        # differs. Drives test_use_stale_off.
        location /usestaleoff/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_keep_stale 1h;
            cache_turbo_use_stale off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S4.2: the two non-5xx tokens that are not 404. Covers the remaining
        # explicit bits so no status token ships on parse-test evidence alone.
        # Drives test_use_stale_403_429.
        location /usestale403429/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_keep_stale 1h;
            cache_turbo_use_stale http_403 http_429;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # O4.4: the circuit breaker's own on/off switch (cache_turbo_breaker),
        # independent of the threshold/window off-switches the config-parse
        # tests already cover. NO keep_stale/use_stale window here on purpose:
        # once the entry is past its stale window (1s fresh, x4=4s stale) the
        # ONLY thing that can still answer a dead origin with a cached body is
        # the breaker's own any-age fallback (call site 1 in
        # ngx_http_cache_turbo_access_handler) -- so this isolates that call
        # site's routing through breaker_should_consult() rather than
        # overlapping RFC-2/keep_stale, which have their own coverage above.
        # Drives test_breaker_arming_gated_on_breaker_enable.
        location /breakeron/ {{
            cache_turbo                    main;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Negative control for /breakeron/: identical apart from
        # `cache_turbo_breaker off`. threshold/window/open are still set (an
        # operator who left the breaker off but configured the tuning knobs)
        # -- if breaker_enable were not an independent gate at the arming call
        # site, this location would ALSO fall back to the stale snapshot on a
        # dead origin, exactly like /breakeron/. It must instead surface the
        # origin failure, because with the breaker off nothing may EVER be
        # armed or consulted.
        location /breakeroff/ {{
            cache_turbo                    main;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_breaker             off;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # O4.4-i white-box arming control. Mirrors /breakeron/ and /breakeroff/
        # exactly, but on the dedicated `brkiz` zone so tripping the breaker here
        # cannot perturb the black-box test that shares `main`. Drives
        # test_breaker_arming_sites_gated_white_box, which reads the
        # TEST_FAULTS-only arming counter off these responses.
        location /brkion/ {{
            cache_turbo                    brkiz;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        location /brkioff/ {{
            cache_turbo                    brkiz;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_breaker            off;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S7.2: $cache_turbo_serve_reason coverage, FRESH/STALE arms. Same
        # shape as /ctstale/ (1s fresh -> x4=4s stale, beta 1 so the refresh
        # dice never fires) but on the private sr72z zone. Drives
        # test_serve_reason_variable.
        location /sr72/ {{
            cache_turbo        sr72z;
            cache_turbo_key    $uri;
            cache_turbo_valid  1s;
            cache_turbo_beta   1;
            add_header         X-CT-Reason $cache_turbo_serve_reason always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S7.2: $cache_turbo_serve_reason coverage, STALE-IF-ERROR arm. Same
        # shape as /sieserve/ (the "sieserve" request-suffix marker makes the
        # origin emit stale-if-error=30) but on sr72z so the breaker arm below
        # can trip that zone's breaker without disturbing this location's own
        # fully-expired-entry setup. Drives test_serve_reason_variable.
        location /sr72sie/ {{
            cache_turbo        sr72z;
            cache_turbo_key    $uri;
            cache_turbo_valid  1s;
            add_header         X-CT-Reason $cache_turbo_serve_reason always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S7.2: $cache_turbo_serve_reason coverage, STALE-BREAKER + BREAKER-503
        # arms. Same shape as /s71brk/ (1s fresh, x4=4s stale, threshold=1) but
        # on sr72z: the /dead key gets primed then trips the breaker OPEN, the
        # /never key is NEVER primed so once the breaker is OPEN it has no
        # armed copy at all and falls into breaker_unavailable() (BREAKER-503).
        # Drives test_serve_reason_variable.
        location /sr72brk/ {{
            cache_turbo                    sr72z;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            add_header         X-CT-Reason $cache_turbo_serve_reason always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # BRK-RA1 regression pin: cache_turbo_breaker_open set to a small,
        # non-30 value (2s) and NO explicit cache_turbo_breaker_retry_after
        # -- the auto-track path. Own zone (raz) so the CLOSED-breaker prime
        # is not polluted by any other test's already-tripped breaker.
        # /ra1/never is deliberately never primed so, once the breaker is
        # OPEN, it has no cached copy at all and falls straight into
        # ngx_http_cache_turbo_breaker_unavailable() -- same COLD-url shape as
        # /sr72brk/never above. Drives test_breaker_retry_after_auto_tracks_
        # breaker_open.
        location /ra1/ {{
            cache_turbo                    raz;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open        2s;
            cache_turbo_lock_timeout        2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # BRK-RA1 positive control: identical shape to /ra1/ but with an
        # EXPLICIT cache_turbo_breaker_retry_after that must still win over
        # the derived default -- proves the fix does not break the explicit
        # path while fixing the auto-track one.
        location /ra1exp/ {{
            cache_turbo                    raexpz;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open        2s;
            cache_turbo_breaker_retry_after 7s;
            cache_turbo_lock_timeout        2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S7.1: breaker_serves / origin_failures counter coverage. Same shape
        # as /breakeron/ (1s fresh, x4=4s stale, threshold=1) but on its own
        # zone (s71z) so the admin JSON delta is not polluted by /breakeron/'s
        # or /brkion/'s already-tripped breaker. Drives test_breaker_counters.
        location /s71brk/ {{
            cache_turbo                    s71z;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S7.1: admin endpoint for /s71brk/'s private zone (s71z). This must NOT
        # sit in the redis-gated block because it carries no cache_turbo_redis
        # directive -- placing it here alongside /s71brk/ ensures it exists even
        # when Redis is unavailable, so test_breaker_counters can query the counters.
        location = /_cache_s71 {{
            cache_turbo_admin    s71z;
            allow 127.0.0.1;
            deny all;
        }}

        # O4.5: breaker LIFECYCLE end-to-end. /o45/o45cache is primed then
        # tripped (same 1s-fresh/x4=4s-stale/threshold=1 shape as /s71brk/) so
        # a re-fetch while OPEN proves zero origin contact (origin.hits_for
        # unchanged) by serving the armed any-age snapshot. /o45/o45cold shares
        # the zone but is NEVER primed, so once OPEN it has no snapshot to
        # arm and falls into breaker_unavailable() (503 + Retry-After) --
        # same "second, never-primed uri on the same zone" shape as
        # /sr72brk/'s BREAKER-503 arm. breaker_open is 2s (vs. the 30s other
        # fixtures use) so the CLOSE-via-probe assertion does not idle the
        # suite for 30+ seconds.
        # cache_turbo_breaker_retry_after is set EXPLICITLY here (not left to
        # track cache_turbo_breaker_open automatically) -- an unset
        # breaker_retry_after inherits the ENCLOSING server block's
        # already-resolved default (30s, from breaker_open's OWN 30s default
        # at that level) rather than being derived from THIS location's
        # breaker_open, so leaving it unset with breaker_open 2s here would
        # read 30 instead of 2 (a pre-existing inheritance gap, reported
        # separately -- not what this fixture is testing). An explicit
        # directive is unaffected by that gap and is what this test verifies.
        location /o45/ {{
            cache_turbo                    o45z;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_breaker              on;
            cache_turbo_breaker_threshold    1;
            cache_turbo_breaker_window      60s;
            cache_turbo_breaker_open         2s;
            cache_turbo_breaker_retry_after  2s;
            cache_turbo_lock_timeout         2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        location = /_cache_o45 {{
            cache_turbo_admin    o45z;
            allow 127.0.0.1;
            deny all;
        }}

        # O4.5 negative control: identical shape to /o45/ (SAME threshold/
        # window/open, so only the breaker on|off flag itself differs -- a
        # mutation that ignores breaker_enable in breaker_should_consult()
        # would otherwise still be blocked by threshold/window and this
        # control would pass for the wrong reason). With the breaker off a
        # dead origin gets no fallback at all -- the origin hit count keeps
        # climbing (every request reaches it) rather than flatlining behind
        # an OPEN breaker.
        location /o45off/ {{
            cache_turbo                    o45offz;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_breaker              off;
            cache_turbo_breaker_threshold    1;
            cache_turbo_breaker_window      60s;
            cache_turbo_breaker_open         2s;
            cache_turbo_lock_timeout         2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # O4.5 / O4.2-f: header-filter recording-block pins (claims 1+2: a
        # 5xx records a failure, a cache-turbo HIT records nothing). Own
        # zone (o45hitz) so origin_failures here is never moved by /o45/'s
        # own trip. threshold=1/window=60s/open=30s -- same shape as the
        # other breaker fixtures; claim 1's drop DOES trip this zone's
        # breaker, which is why it runs after claim 2's HIT check.
        #
        # valid is 30s, NOT the 1s the sibling breaker fixtures use: claim 2
        # puts an _admin_stat round trip between the prime and the HIT fetch,
        # so a 1s window can expire on a loaded or ASan runner and the HIT
        # becomes a re-fetch -- failing on box speed rather than on module
        # behaviour, the same SUITE-4 trap the /ccignmr/ comment records.
        # Neither claim here needs a short TTL: /o45hit/dropme is never primed,
        # and the staleness step runs on /o45hitpos/, a different zone.
        location /o45hit/ {{
            cache_turbo                    o45hitz;
            cache_turbo_key                $uri;
            cache_turbo_valid              30s;
            cache_turbo_breaker              on;
            cache_turbo_breaker_threshold    1;
            cache_turbo_breaker_window      60s;
            cache_turbo_breaker_open        30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        location = /_cache_o45hit {{
            cache_turbo_admin    o45hitz;
            allow 127.0.0.1;
            deny all;
        }}

        # O4.5 / O4.2-f: POSITION-claim-only location (see the o45hitposz
        # zone comment above for why this is not on o45hitz). keep_stale
        # forever so the same key's expired entry can be pushed through the
        # SIE rewrite, masking a real origin 502 with a 200/stale body while
        # still needing to have recorded the 502 as a breaker failure.
        location /o45hitpos/ {{
            cache_turbo                    o45hitposz;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_keep_stale     forever;
            cache_turbo_breaker              on;
            cache_turbo_breaker_threshold    1;
            cache_turbo_breaker_window      60s;
            cache_turbo_breaker_open        30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        location = /_cache_o45hitpos {{
            cache_turbo_admin    o45hitposz;
            allow 127.0.0.1;
            deny all;
        }}

        # O4.2-f: a native proxy_cache HIT must not touch the breaker's
        # recording block at all (ctx is NULL/ctx->served on a HIT --
        # never a cache-turbo location, so the header filter never reaches
        # the record() call). Own proxy_cache zone (ctpo45, not ctpcon --
        # see the proxy_cache_path comment above); no cache_turbo directive
        # here at all, so no ctx and no breaker.
        location /o45natpc/ {{
            proxy_cache          ctpo45;
            proxy_cache_valid    200 5m;
            proxy_cache_key      $uri;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Negative control for /keepstale/: identical location, keep_stale off
        # (the default) -> an expired entry with a dead origin must surface the
        # error (502), not serve stale. Proves the positive result above is
        # actually caused by keep_stale, not some other widening.
        location /keepstaleoff/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_keep_stale off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Precedence test: both a response stale-if-error AND cache_turbo_keep_stale
        # are in play here. keep_stale is a generous 1h baseline; the response's
        # own stale-if-error=30 (via the "sieserve" request-suffix marker, same
        # origin convention as /sieserve/) must WIN -- sie_window = ttl + 30, not
        # ttl + 3600 and not max() of the two. Drives
        # test_keep_stale_loses_to_response_sie.
        location /keepstalewins/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_keep_stale 1h;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S3.1: a negative-cached 5xx must never overwrite a still-serveable
        # body (cache_turbo_valid 503 1m legitimately negative-caches errors,
        # but that must not let an error blob clobber a good 200 -- the
        # inverse of outage resilience). Short fresh/stale window (1s / x4=4s)
        # like /keepstale/ so the entry goes stale quickly; the 503 negative
        # cache rule is what a "cache negative responses too" config looks
        # like. Drives test_5xx_never_overwrites_cached_body.
        location /noclobber/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_valid    503 1m;
            cache_turbo_background_update off;
            cache_turbo_beta     100000;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # AUD-5XX-CTA: cache_turbo_bypass skips the LOOKUP *and* single-flight
        # but still permits storing, so it is the one path that can reach the
        # 5xx guard with NO earlier serialization point at all -- exactly the
        # reachability the check-then-act race needed. Negative-cache 503 so a
        # bypassed 5xx is actually eligible to be stored (a non-cacheable
        # status never reaches the guard). Drives test_5xx_cta_bypass_never_
        # overwrites_cached_body.
        location /cta5xx/ {{
            cache_turbo         main;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            cache_turbo_valid   503 1m;
            cache_turbo_bypass  $arg_nocache;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S2.3: no-reaper contract. keep_stale is a generous 1h -- an entry
        # here is way inside its keep-stale window at every point this test
        # checks it, so if the entry ever disappears on its own that proves a
        # time-based reaper exists (contract violation). The zone (ksevz,
        # 64k, the enforced minimum) is what actually reclaims memory: it only
        # holds a couple of these bodies, so flooding it with distinct keys
        # forces genuine LRU eviction and gives the test a second location to
        # observe the SAME key vanish for the CORRECT reason (max_size
        # pressure, not time).
        location /ksev/ {{
            cache_turbo             ksevz;
            cache_turbo_key         $uri;
            cache_turbo_valid       1s;
            cache_turbo_keep_stale  1h;
            add_header X-CT-Status  $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # background_update OFF (v8): the stale dice-winner regenerates INLINE
        # and serves the fresh body on that request (pre-v8 behaviour).
        location /noswr/ {{
            cache_turbo                   main;
            cache_turbo_key               $uri;
            cache_turbo_valid             2s;
            cache_turbo_beta              5000;
            cache_turbo_background_update off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # max_size = 4 bytes: origin body "gen-N\\n" is >4, so never cached
        location /big/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_max_size 4;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Q1 suppress-native: $cache_turbo_active reads 1 when engaged AND
        # cache_turbo_suppress_native is on. Echo it into a header so a test can
        # observe the value an operator would wire into proxy_no_cache.
        location /sup/ {{
            cache_turbo                 main;
            cache_turbo_key             $uri;
            cache_turbo_valid           30s;
            cache_turbo_suppress_native on;
            add_header X-CT-Active      $cache_turbo_active always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # suppress off (default): the variable is always 0, so the wiring is a
        # safe no-op until opted in.
        location /nosup/ {{
            cache_turbo            main;
            cache_turbo_key        $uri;
            cache_turbo_valid      30s;
            add_header X-CT-Active $cache_turbo_active always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # auto-classify: anon pages cache, dynamic surfaces skip. This used to
        # be `cache_turbo main auto;` (the generic union); `auto`/`generic` are
        # gone, so the backends are named explicitly -- which is the point.
        location /auto/ {{
            cache_turbo         main;
            cache_turbo_backend wordpress woocommerce joomla;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # auto-classify + suppress_native: an anon page engages cache-turbo
        # ($cache_turbo_active=1, native defers), but a request the preset
        # classifies as dynamic (login cookie / backend URI) is skipped -> NOT
        # engaged -> $cache_turbo_active=0 so a stacked native cache is free to
        # own that URL. Proves auto-skip forces the variable to 0 even with
        # suppress_native on.
        location /autosup/ {{
            cache_turbo                 main;
            cache_turbo_backend         wordpress;
            cache_turbo_key             $uri;
            cache_turbo_valid           30s;
            cache_turbo_suppress_native on;
            add_header X-CT-Active      $cache_turbo_active always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # auto-classify URI-prefix rule: r->uri starts with /wp-admin/ -> skip
        location /wp-admin/ {{
            cache_turbo         main;
            cache_turbo_backend wordpress;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # cache_turbo_backend woocommerce only: composes just that preset.
        # NOTE the key includes the query string: ?wc-ajax= rides on an ORDINARY
        # page URL, so this location is exactly the "cacheable page that an AJAX
        # call is layered onto" shape the wc-ajax arg rule has to catch.
        #
        # `woocommerce` alone here ALSO implies `wordpress` (resolved at parse):
        # the woo-cookie/arg rules are woo's own; the WP login-cookie skip and the
        # /wp-admin/ URI skip come from the implied wordpress preset. Composition
        # itself is now pinned in ci/t/preset-engine/composition.t; this fixture
        # location remains for test_woocommerce_wc_ajax below.
        location /woo/ {{
            cache_turbo         main;
            cache_turbo_backend woocommerce;
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # woo-only location mounted at /wooshop/: proves the IMPLIED wordpress
        # /wp-admin/ URI rule fires without `wordpress` being named. The prefix
        # rebases /wooshop/wp-admin/* onto /wp-admin/* for the preset matcher, so
        # a hit here would be the exact leak (cacheable wp-admin under woo-only).
        location /wooshop/ {{
            cache_turbo         main;
            cache_turbo_backend woocommerce;
            cache_turbo_backend_prefix /wooshop/;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # wordpress preset with the QUERY STRING in the key -- needed to tell
        # /wpq/x?s=foo apart from /wpq/x. This is where the ?s= (site search)
        # and ?preview= arg rules are exercised.
        location /wpq/ {{
            cache_turbo         main;
            cache_turbo_backend wordpress;
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # two backends stacked: both WP and Woo dynamic surfaces skip
        location /multi/ {{
            cache_turbo         main;
            cache_turbo_backend wordpress woocommerce;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # joomla URI-prefix rule: r->uri starts with /administrator/ -> skip
        location /administrator/ {{
            cache_turbo         main;
            cache_turbo_backend joomla;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # xenforo preset (opt-in; deliberately NOT part of generic/auto).
        # The preset's URI prefixes anchor at position 0 of r->uri, so /login
        # and /misc must be real ROOT locations to be exercised at all: a
        # /xf/login path would (correctly) never match. See docs/xenforo.md.
        location /login {{
            cache_turbo         main;
            cache_turbo_backend xenforo;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /misc {{
            cache_turbo         main;
            cache_turbo_backend xenforo;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # /api/ is the REST API: it authenticates on the XF-Api-Key HEADER, which
        # no cookie rule can see, so the preset bypasses it on the URI. Root
        # location for the same anchor-at-0 reason as /login and /misc above.
        location /api/ {{
            cache_turbo         main;
            cache_turbo_backend xenforo;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # xenforo cookie/arg rules are path-independent, so a prefixed location
        # exercises them: xf_user / xf_session_admin / xf_session bypass and the
        # _xfToken query arg bypasses, while the xf_style_* / xf_language_id
        # variant cookies must KEY (value-folded), not bypass and not collide.
        location /xf/ {{
            cache_turbo         main;
            cache_turbo_backend xenforo;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # smf routes every page through index.php?action=<route>, so its
        # dynamic surface is expressed as query-arg VALUES, not URI prefixes.
        # Arg rules are path-independent, so a prefixed location exercises them.
        location /smf/ {{
            cache_turbo         main;
            cache_turbo_backend smf;
            cache_turbo_key     $request_uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /mybb/ {{
            cache_turbo         main;
            cache_turbo_backend mybb;
            cache_turbo_key     $request_uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # redmine / opencart (2026-07-26 research pass). Both exist to prove a
        # guest-issued session cookie is NOT treated as a login signal -- the
        # trap that makes a preset bypass 100% of traffic and silently
        # disable the cache. The key must include $is_args$args so the
        # opencart arg-tier rows are reachable: with a bare $uri key every
        # ?route= variant collapses onto one entry and the test would pass for
        # the wrong reason.
        location /redmine/ {{
            cache_turbo         main;
            cache_turbo_backend redmine;
            cache_turbo_backend_prefix /redmine/;
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # opencart needs no prefix: it ships NO uris[] row at all (everything is
        # /index.php?route=), so the arg tier is what fires and it is
        # path-independent.
        location /opencart/ {{
            cache_turbo         main;
            cache_turbo_backend opencart;
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # A NAMED preset must pull in ONLY its own rules. `wordpress` here must
        # not react to /login, /user, /session, /index.php or another preset's
        # cookies -- those are other backends' surfaces and are perfectly
        # cacheable pages on a WordPress site. (This location used to be
        # `cache_turbo_backend generic;` and proved the same thing about the
        # union; the union is gone, the invariant is not.)
        location /gen/ {{
            cache_turbo         main;
            cache_turbo_backend wordpress;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ---- magento -------------------------------------------------------
        # URI prefixes anchor at position 0 -> ROOT locations.
        location /checkout {{
            cache_turbo         main;
            cache_turbo_backend magento;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /customer {{
            cache_turbo         main;
            cache_turbo_backend magento;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # Web API front names (app/code/Magento/Webapi/etc/di.xml). Header-
        # authenticated -> invisible to the cookie tier, so they need URI rules.
        # Root locations, or the fetch falls through to nginx's implicit 404 and
        # a "must bypass" assertion passes without the preset ever running.
        location /rest {{
            cache_turbo         main;
            cache_turbo_backend magento;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /soap {{
            cache_turbo         main;
            cache_turbo_backend magento;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # A catalog URL that merely SHARES the letters must still cache: the
        # prefix needs a '/' or '.' boundary after it, so /restaurant-supplies
        # is not /rest.
        location /restaurant-supplies {{
            cache_turbo         main;
            cache_turbo_backend magento;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # Cookie rules are path-independent. The catalog is the surface that MUST
        # stay cacheable -- including for guests carrying PHPSESSID / form_key /
        # private_content_version, every one of which Magento sets for anons.
        location /mg/ {{
            cache_turbo         main;
            cache_turbo_backend magento;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}


        # ---- require_header (explicit upstream store opt-in) ----------------
        # The gate INVERTS the store default here: nothing is captured unless the
        # origin affirms it. X-CT-Status is mandatory to test this at all -- every
        # refusal case (header absent / "no" / duplicated / empty) produces a
        # plain MISS, and a MISS has no x-cache, so "x-cache not in headers"
        # cannot tell a working gate from a gate that never runs.
        location /gql/ {{
            cache_turbo              main;
            cache_turbo_key          $uri;
            cache_turbo_valid        30s;
            cache_turbo_require_header X-GraphQL-Cacheable;
            add_header               X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # Same origin, NO gate: proves the refusals above come from the directive
        # and not from something else in the response (an unset gate must leave
        # the module's normal "cacheable unless vetoed" path untouched).
        location /nogql/ {{
            cache_turbo         main;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            add_header          X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # `none` overrides an inherited preset. The server-level directive below
        # arms wordpress for every location that does not say otherwise; this one
        # says otherwise, so /wp-admin/-style rules must NOT fire here.
        location /nonepreset/ {{
            cache_turbo         main;
            cache_turbo_backend none;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ---- discourse (ported to ci/t/preset-engine/arg-scanner.t and
        # ci/t/presets/discourse.t; kept here only as long as another Python
        # test in this file still references /dc/)
        # Cookie/arg rules are path-independent, so a prefixed location is fine:
        # _t bypasses, but the guest _forum_session and the theme_ids /
        # forced_color_mode variant cookies must NOT.
        location /dc/ {{
            cache_turbo         main;
            cache_turbo_backend discourse;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ---- phpbb --------------------------------------------------------
        # Every visitor gets phpBB's cookies; the preset therefore uses the
        # `_u != 1` value predicate rather than a name-presence rule.
        location /ucp.php {{
            cache_turbo         main;
            cache_turbo_backend phpbb;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /phpbb/ {{
            cache_turbo         main;
            cache_turbo_backend phpbb;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ---- vbulletin ----------------------------------------------------
        # The only preset wired to the NONEMPTY and EQ predicate ops (userid /
        # password non-empty, imloggedin == "yes"), and the only one whose key
        # cookie list is exercised here. $uri key so a key-cookie split is
        # attributable to the cookie and not to the path.
        location /vbull/ {{
            cache_turbo         main;
            cache_turbo_backend vbulletin;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ---- 2026 preset expansion --------------------------------------
        # Each app is mounted below a unique prefix. backend_prefix rebases
        # the preset's root-relative URI rules, so the same location exercises
        # cookie, query-arg and URI tiers without colliding with older tests'
        # /admin, /login and other root locations.
        location /ct-textpattern/ {{
            cache_turbo         main;
            cache_turbo_backend textpattern;
            cache_turbo_backend_prefix /ct-textpattern/;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-bludit/ {{
            cache_turbo         main;
            cache_turbo_backend bludit;
            cache_turbo_backend_prefix /ct-bludit/;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-spip/ {{
            cache_turbo         main;
            cache_turbo_backend spip;
            cache_turbo_backend_prefix /ct-spip/;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-bugzilla/ {{
            cache_turbo         main;
            cache_turbo_backend bugzilla;
            cache_turbo_backend_prefix /ct-bugzilla/;
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-mantis/ {{
            cache_turbo         main;
            cache_turbo_backend mantis;
            cache_turbo_backend_prefix /ct-mantis/;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-plone/ {{
            cache_turbo         main;
            cache_turbo_backend plone;
            cache_turbo_backend_prefix /ct-plone/;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-umbraco/ {{
            cache_turbo         main;
            cache_turbo_backend umbraco;
            cache_turbo_backend_prefix /ct-umbraco/;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-dotclear/ {{
            cache_turbo         main;
            cache_turbo_backend dotclear;
            cache_turbo_backend_prefix /ct-dotclear/;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-wikijs/ {{
            cache_turbo         main;
            cache_turbo_backend wikijs;
            cache_turbo_backend_prefix /ct-wikijs/;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-classicpress/ {{
            cache_turbo         main;
            cache_turbo_backend classicpress;
            cache_turbo_backend_prefix /ct-classicpress/;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-backdrop/ {{
            cache_turbo         main;
            cache_turbo_backend backdrop;
            cache_turbo_backend_prefix /ct-backdrop/;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ---- invision -----------------------------------------------------
        # Cookie/arg rules are path-independent, so a prefixed location
        # exercises them. $uri key for the same attribution reason as /vbull/.
        location /ips/ {{
            cache_turbo         main;
            cache_turbo_backend invision;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ---- header-auth REST surfaces (drupal /jsonapi, /oauth) -----------
        # Used by test_header_auth_rest_surfaces() -- both surfaces are
        # header-authenticated (bearer token) and structurally invisible to
        # the cookie tier; only the URI rule catches them. See
        # ci/t/presets/drupal.t for the drupal preset's own cookie/URI tests.
        location /jsonapi {{
            cache_turbo         main;
            cache_turbo_backend drupal;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /oauth {{
            cache_turbo         main;
            cache_turbo_backend drupal;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ---- internal-redirect regression (DOC-A1 / DOC-A2) ---------------
        # A PHP front controller: try_files sends every clean URL to
        # /ctir/index.php. After that internal redirect nginx has REPLACED
        # r->uri with /ctir/index.php, so both the default $uri-based key and
        # the preset URI rules see the front controller, never the original
        # route. /ctir/ reproduces the shape the published docs used to show.
        location /ctir/ {{
            try_files $uri /ctir/index.php;
        }}
        location = /ctir/index.php {{
            cache_turbo         main;
            cache_turbo_backend xenforo;
            cache_turbo_key     $host$uri$cache_turbo_normalized_args;
            cache_turbo_valid   30s;
            add_header          X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # AUD-DOC1. Third copy of the same front controller, guarded ONLY by
        # cache_turbo_bypass_uri. The directive matches r->uri, which the
        # internal redirect has already rewritten to the front controller, so
        # the prefix never matches and the private route is cached like any
        # other. Pinning it here keeps the documented blind spot honest.
        location /ctir-bu/ {{
            try_files $uri /ctir-bu/index.php;
        }}
        location = /ctir-bu/index.php {{
            cache_turbo            main;
            cache_turbo_key        $host$request_uri;
            cache_turbo_bypass_uri /ctir-bu/api/;
            cache_turbo_valid      30s;
            add_header             X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Same front controller, keyed the way the fixed docs now prescribe:
        # $request_uri survives the internal redirect, so distinct clean URLs
        # stay distinct and the map-driven private-route veto still fires.
        location /ctir-fixed/ {{
            try_files $uri /ctir-fixed/index.php;
        }}
        location = /ctir-fixed/index.php {{
            cache_turbo           main;
            cache_turbo_backend   xenforo;
            cache_turbo_key       $host$request_uri;
            cache_turbo_bypass    $ctir_private_route;
            cache_turbo_no_store  $ctir_private_route;
            cache_turbo_valid     30s;
            add_header            X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ---- CTXRDR: error_page internal redirect AFTER ctx exists --------
        # The /ctir* fixtures above redirect via try_files, which runs in the
        # REWRITE phase -- before the PRECONTENT access handler, so the module
        # only ever sees the post-redirect URI and ctx is built once. This pair
        # covers the other order: cache-turbo is enabled on BOTH the route that
        # 404s and the error_page target, so the access handler builds a ctx,
        # the origin 404s, error_page fires ngx_http_internal_redirect(), and
        # r->ctx is memzeroed mid-request while the first ctx's pool cleanups
        # (cold-winner unstub, blob release) and its embedded cold_wait_ev timer
        # remain registered on the still-live r->pool.
        #
        # Both locations emit the status/reason variables so the SECOND pass's
        # ctx is observable: the variable getters read r->ctx directly, so a
        # module that cached a ctx pointer across the redirect -- or that failed
        # to rebuild one -- shows up here rather than as a silent corruption.
        location /ctxrdr/ {{
            cache_turbo           main;
            cache_turbo_key       $host$request_uri;
            cache_turbo_valid     30s;
            error_page            404 = /ctxrdr-fallback/page;
            # Required: without it nginx passes the origin's 404 straight to the
            # client and error_page never fires, so the redirect under test
            # never happens at all.
            proxy_intercept_errors on;
            add_header            X-CT-Status $cache_turbo_status always;
            add_header            X-CT-Reason $cache_turbo_serve_reason always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ctxrdr-fallback/ {{
            cache_turbo           main;
            cache_turbo_key       $host$request_uri;
            cache_turbo_valid     30s;
            add_header            X-CT-Status $cache_turbo_status always;
            add_header            X-CT-Reason $cache_turbo_serve_reason always;
            # NOTE: the upstream path carries a marker UNIQUE to the fallback
            # leg. (Config is written encoding="ascii" -- keep this block
            # ASCII-only; a non-ASCII char here fails the whole suite at
            # config-write time, before a single test runs.)
            # Both ctxrdr locations strip their own prefix, so a bare
            # `proxy_pass .../` made the fallback fetch plain `/page` -- and
            # hits_for("ctxrdr-missing") then counted only the FIRST pass's 404,
            # never the fallback's origin contact. The "exactly one origin
            # contact" assertion was true for the wrong reason and would have
            # stayed 1 however many times the fallback hit the origin. Keep this
            # marker distinct from every other fixture's path.
            proxy_pass http://127.0.0.1:{origin_port}/ctxrdr-fb-;
        }}
        # Negative control for the CTXRDR test: same variables, but cache_turbo
        # is NOT enabled, so no ctx is ever created. Both variables must report
        # "-" here. Without this arm the CTXRDR assertions would pass equally
        # well against getters that answered from anything but r->ctx.
        location /ctxrdr-off/ {{
            add_header            X-CT-Status $cache_turbo_status always;
            add_header            X-CT-Reason $cache_turbo_serve_reason always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Q2 multi-buffer oversize: ~200 KB body, 1k cap -> mid-stream abort
        location /qbig/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_max_size 1k;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Q1: a location WITHOUT cache_turbo -> $cache_turbo_active must be "0"
        # (no ctx / disabled), proving the variable's defensive default.
        location /plain/ {{
            add_header X-CT-Active $cache_turbo_active always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Q1 E2E: cache_turbo_suppress_native on + the documented wiring ->
        # proxy_cache (ctpcon) must stay empty (cache-turbo owns caching).
        location /supcache/ {{
            cache_turbo                 main;
            cache_turbo_suppress_native on;
            cache_turbo_key             $uri;
            cache_turbo_valid           30s;
            proxy_cache                 ctpcon;
            proxy_cache_valid           200 5m;
            proxy_cache_key             $uri;
            proxy_no_cache              $cache_turbo_active;
            proxy_cache_bypass          $cache_turbo_active;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Q1 E2E control: suppress OFF -> $cache_turbo_active=0 -> the SAME
        # wiring is inert and proxy_cache (ctpcoff) stores normally.
        location /nosupcache/ {{
            cache_turbo                 main;
            cache_turbo_key             $uri;
            cache_turbo_valid           30s;
            proxy_cache                 ctpcoff;
            proxy_cache_valid           200 5m;
            proxy_cache_key             $uri;
            proxy_no_cache              $cache_turbo_active;
            proxy_cache_bypass          $cache_turbo_active;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # tiny zone to force LRU eviction (R6)
        location /e/ {{
            cache_turbo          tiny;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            add_header           X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S8: scan-resistant segmented LRU, ON. Own tiny zone so the scan below
        # cannot be perturbed by other tests sharing /e/.
        location /sr/ {{
            cache_turbo               srz;
            cache_turbo_key           $uri;
            cache_turbo_valid         300s;
            {sr_directive}
            add_header                X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S8: the SAME shape with the directive ABSENT -- the default-off
        # control. Any behavioural difference between /sr/ and /sroff/ is
        # attributable to the directive and nothing else.
        location /sroff/ {{
            cache_turbo          sroffz;
            cache_turbo_key      $uri;
            cache_turbo_valid    300s;
            add_header           X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S8: explicit `off` must behave identically to absent (not merely
        # parse). Separate zone again so it is independently measurable.
        location /srexpoff/ {{
            cache_turbo               srexpz;
            cache_turbo_key           $uri;
            cache_turbo_valid         300s;
            cache_turbo_scan_resistant off;
            add_header                X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # R6b: refresh-under-pressure. A tiny zone (so eviction churns) with a
        # short fresh window + aggressive beta + background_update, so a working
        # set larger than the zone is CONTINUOUSLY going stale and refreshing
        # (SWR store back into shm) at the same time other entries are being
        # evicted to make room. This overlaps the shm slab alloc/free/evict path
        # with the refresh-store path under concurrency -- the combination the
        # eviction-only (/e/, valid 30s never stale) and serve-under-eviction
        # (PERF-7) tests do not exercise. The value is under the sanitizer CI run
        # (asan job runs the full suite): a shm UAF / double-free / overflow in
        # store-under-eviction surfaces there. beta 5000 = refresh fires early in
        # the stale window; valid 1s keeps entries turning over fast.
        location /shmref/ {{
            cache_turbo               shmref;
            cache_turbo_key           $uri;
            cache_turbo_valid         2s;     # stale window opens at t+2s
            cache_turbo_beta          5000;   # aggressive: refresh fires early in stale
            cache_turbo_background_update on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # key normalize (v3-1): key is built from $cache_turbo_normalized_args
        # so reordered / tracking-laden query strings collapse to one slot
        location /n/ {{
            cache_turbo          main;
            cache_turbo_key      $uri$cache_turbo_normalized_args;
            cache_turbo_valid    30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # extra denylist patterns: exact "sid" + prefix "tmp_*", on top of the
        # built-in defaults (utm_*, fbclid, ...)
        location /ns/ {{
            cache_turbo          main;
            cache_turbo_key      $uri$cache_turbo_normalized_args;
            cache_turbo_valid    30s;
            cache_turbo_normalize_strip sid "tmp_*";
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # strip "*": every arg dropped, so all query strings share one slot
        location /na/ {{
            cache_turbo          main;
            cache_turbo_key      $uri$cache_turbo_normalized_args;
            cache_turbo_valid    30s;
            cache_turbo_normalize_strip "*";
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Vary-aware suffix (v3-4): a request that differs only by Accept-Encoding
        # class (br/gzip/identity) gets its own cache slot.
        location /ve/ {{
            cache_turbo          main;
            cache_turbo_key      $uri$cache_turbo_normalized_args;
            cache_turbo_valid    30s;
            cache_turbo_normalize_vary encoding;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # device class (mobile/desktop from User-Agent) gets its own slot
        location /vd/ {{
            cache_turbo          main;
            cache_turbo_key      $uri$cache_turbo_normalized_args;
            cache_turbo_valid    30s;
            cache_turbo_normalize_vary device;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # both buckets compose: encoding x device = distinct slots
        location /vb/ {{
            cache_turbo          main;
            cache_turbo_key      $uri$cache_turbo_normalized_args;
            cache_turbo_valid    30s;
            cache_turbo_normalize_vary encoding device;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # auto-Vary (v11 other half): the module reads the response Vary header
        # itself and splits on the named request header (safe whitelist only).
        # cache_turbo_key includes the query so each test's marker isolates.
        location /av/ {{
            cache_turbo          main;
            cache_turbo_key      $request_uri;
            cache_turbo_valid    30s;
            cache_turbo_auto_vary on;
            # X-CT-Status is the canary the primary-subtag share test asserts
            # on: "b1 == b2" alone is equally satisfied by two independent
            # origin misses that happen to return byte-identical bodies, so
            # the HIT status is what distinguishes a real shared slot.
            add_header           X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # auto-Vary with a SHORT fresh TTL so the variant (and its L1 vary marker)
        # go stale fast: a request after the fresh deadline but inside the stale
        # window must still resolve to the variant via the now-stale marker
        # (codex follow-up) and serve it stale, instead of falling back to the
        # base key and missing to origin.
        location /avs/ {{
            cache_turbo          main;
            cache_turbo_key      $request_uri;
            cache_turbo_valid    2s;
            cache_turbo_auto_vary on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # cache_turbo_valid 0 == "cache forever" (resolved to a long finite TTL):
        # the entry stays FRESH (a HIT, not instantly STALE) and survives the L2
        # round-trip, reconciling the documented "forever" contract.
        location /forever/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    0;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Raw-key migration (was cache_turbo_safe_key): an explicit
        # $scheme$host$request_uri key keeps the full raw query (no strip/sort),
        # so two distinct sessionid values get distinct entries instead of
        # aliasing onto one normalized key.
        location /safekey/ {{
            cache_turbo          main;
            cache_turbo_key      $scheme$host$request_uri;
            cache_turbo_valid    30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # COR-5 (L1-only): auto-Vary + PURGE with NO L2 backend. A PURGE of the
        # base URI must invalidate EVERY variant; with no enumerable L2 index the
        # module bumps the marker generation so old-generation variants are
        # orphaned and the next request for each axis value misses to origin.
        location /cor5l1/ {{
            cache_turbo          main;
            cache_turbo_key      $request_uri;
            cache_turbo_valid    30s;
            cache_turbo_auto_vary on;
            cache_turbo_purge    on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # auto-Vary OFF (default): the same response Vary header is ignored, so
        # two encodings collapse onto one slot (back-compat proof).
        location /avoff/ {{
            cache_turbo          main;
            cache_turbo_key      $request_uri;
            cache_turbo_valid    30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # presets (v3-2): one location per preset. Each overrides cache_turbo_valid
        # to 1s so the test runs fast; the only behavioural difference left is the
        # preset-supplied stale multiplier (conservative x2 -> serveable 2s,
        # balanced x4 -> 4s, aggressive x8 -> 8s). The explicit valid also proves
        # an explicit knob beats the preset's band value.
        location /pc/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_preset   conservative;
            cache_turbo_valid    1s;     # stale_mult=2 -> expires at 2s
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /pb/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_preset   balanced;
            cache_turbo_valid    1s;     # stale_mult=4 -> expires at 4s
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # H5: the aggressive band is stale_mult=8, but an explicit directive
        # must beat it -> 1 = no stale window at all, hard-expires at 1s.
        location /psm/ {{
            cache_turbo             main;
            cache_turbo_key         $uri;
            cache_turbo_preset      aggressive;
            cache_turbo_valid       1s;
            cache_turbo_stale_mult  1;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /pa/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_preset   aggressive;
            cache_turbo_valid    1s;     # stale_mult=8 -> expires at 8s
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # H3c band-column fixtures. Deliberately NOT reusing /pa/ and /pb/: those
        # carry `cache_turbo_valid 1s` for the stale_mult tests, and the min_uses
        # tests need several sequential requests to stay inside the fresh window.
        # 30s TTL keeps the gate the only variable.
        #
        # /pab/: aggressive band, NO directive -> band min_uses=2 is the only
        # thing that can arm the gate, so req1 skips and req2 stores.
        location /pab/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_preset   aggressive;
            cache_turbo_valid    30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # /pbb/: balanced (the DEFAULT band) -> min_uses=1, stores on req1.
        location /pbb/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_preset   balanced;
            cache_turbo_valid    30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # /pmu/: aggressive band (min_uses=2) + an explicit directive -> 1 wins,
        # so req2 is already a HIT.
        location /pmu/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_preset   aggressive;
            cache_turbo_valid    30s;
            cache_turbo_min_uses 1;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # micro preset: NO explicit cache_turbo_valid, so the band's own 1s fresh
        # TTL (stale_mult=2 -> serveable 2s) is what drives expiry. Distinguishes
        # micro (default valid 1s) from every other preset (default valid >= 30s).
        location /pm/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_preset   micro;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # live autotune (v4-3). /at/ + /atc/ share zone "at": a window of slow
        # misses drives the zone's beta verdict up; /at/ is balanced (band
        # [500,2000]) so it shows the verdict, /atc/ is conservative (band
        # [500,1000]) so it shows the SAME verdict re-clamped -- proving the
        # per-location band clamp. X-CT-Beta exposes the effective beta. /ato/ has
        # autotune OFF so it always shows the static preset beta regardless of the
        # zone verdict (off-by-default). The recompute cadence is a fixed 30s;
        # the tests force a recompute via the admin ?autotune=1 endpoint.
        location /at/ {{
            cache_turbo          at;
            cache_turbo_key      $uri;
            cache_turbo_autotune on;
            cache_turbo_background_update off;   # autotune test: inline regen (see /atch/)
            add_header           X-CT-Beta $cache_turbo_beta always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /atc/ {{
            cache_turbo          at;
            cache_turbo_key      $uri;
            cache_turbo_preset   conservative;
            cache_turbo_autotune on;
            cache_turbo_background_update off;   # autotune test: inline regen (see /atch/)
            add_header           X-CT-Beta $cache_turbo_beta always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ato/ {{
            cache_turbo          at;
            cache_turbo_key      $uri;
            cache_turbo_preset   balanced;
            add_header           X-CT-Beta $cache_turbo_beta always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # v4-4 load-adaptive stale widen. conservative (stale_mult 2) + valid 1s =
        # static serveable window 2s. A slow-miss window pumps the zone load factor
        # to the cap (4x); the probe entry, hard-expired by its STATIC 2s window, is
        # still STALE-serveable at t=3s because the load factor widened the
        # serveable stale span. bg-update ON (default) so losers serve stale.
        location /atl/ {{
            cache_turbo          atl;
            cache_turbo_key      $uri;
            cache_turbo_preset   conservative;
            cache_turbo_valid    1s;
            cache_turbo_autotune on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # autotune insufficient-data: a fresh zone with < MISSES_FLOOR traffic in
        # the window must NOT publish a verdict (autotuned_beta stays 0).
        location /ati/ {{
            cache_turbo          ati;
            cache_turbo_key      $uri;
            cache_turbo_autotune on;
            cache_turbo_background_update off;   # autotune test: inline regen (see /atch/)
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # autotune churn-disqualify: short TTL + short lock + aggressive beta so a
        # stale read reliably refreshes; the test drives refreshes >> misses so the
        # churn gate (refreshes/misses > 2) vetoes the otherwise-qualifying verdict.
        location /atch/ {{
            cache_turbo          atch;
            cache_turbo_key      $uri;
            cache_turbo_preset   aggressive;  # stale_mult 8 -> entry lives 8s, so a
                                              # skipped refresh cycle never expires
                                              # to a MISS (keeps churn ratio stable)
            cache_turbo_min_uses 1;           # H3c: the aggressive band is 2, but
                                              # this test measures the refresh/miss
                                              # churn ratio over 110 cold keys --
                                              # gating each key's first store would
                                              # double the miss count and change the
                                              # very ratio under test. Pin the
                                              # pre-H3c behaviour explicitly.
            cache_turbo_valid    1s;
            cache_turbo_beta     5000;        # static dice beta: refresh is certain
            cache_turbo_lock_ttl 1s;
            cache_turbo_autotune on;
            # bg-update OFF: this test drives a *flood* of stale re-reads (110 keys
            # x 4 cycles) purely to exercise the autotune churn gate; with SWR on
            # each would fire an async background-refresh subrequest, swamping a
            # single-process worker and leaking late origin hits into later tests'
            # exact-count assertions. Inline regen records cost/refreshes identically
            # for autotune, so this changes nothing the test measures.
            cache_turbo_background_update off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        location = /_cache_at {{
            cache_turbo_admin at;
            allow 127.0.0.1;
            deny all;
        }}
        location = /_cache_atl {{
            cache_turbo_admin atl;
            allow 127.0.0.1;
            deny all;
        }}
        location = /_cache_ati {{
            cache_turbo_admin ati;
            allow 127.0.0.1;
            deny all;
        }}
        location = /_cache_atch {{
            cache_turbo_admin atch;
            allow 127.0.0.1;
            deny all;
        }}
        location = /_cache_shmref {{
            cache_turbo_admin shmref;
            allow 127.0.0.1;
            deny all;
        }}

        # H7.3a: Prometheus breaker_opens_total/breaker_state coverage. Own
        # zone (h73z, not s71z -- see the zone declaration comment) and own
        # admin endpoint for the same reason /_cache_s71 exists: /_cache
        # reports `main`, which never sees this zone's breaker_opens.
        location /h73brk/ {{
            cache_turbo                    h73z;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location = /_cache_h73 {{
            cache_turbo_admin    h73z;
            allow 127.0.0.1;
            deny all;
        }}

        # uncached passthrough, lets us read the raw origin
        location /raw/ {{
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # admin endpoint for the "main" zone, localhost-only
        location = /_cache {{
            cache_turbo_admin main;
            allow 127.0.0.1;
            deny all;
        }}
        # same endpoint but reachable only from a (non-loopback) address we
        # can't be, to prove the deny path returns 403
        location = /_cache_denied {{
            cache_turbo_admin main;
            deny all;
        }}
    }}
}}
"""


class Nginx:
    def __init__(self, binary, module, root, port, origin_port, runner,
                 single_process, redis_port=None, redis_auth_port=None,
                 redis_password=None, redis_tls_port=None,
                 redis_tls_ca=None, memcached_port=None,
                 fault_injection=False,
                 redis_tls_untrusted_port=None,
                 redis_tls_expired_port=None) -> None:
        self.binary = binary
        self.module = module
        self.root = root
        self.port = port
        self.origin_port = origin_port
        self.runner_raw = runner
        self.runner = shlex.split(runner)
        self.single_process = single_process
        self.sanitizer = False          # set in main() from --sanitizer (CI-3)
        self.redis_port = redis_port
        self.redis_auth_port = redis_auth_port
        self.redis_password = redis_password
        self.redis_tls_port = redis_tls_port
        self.redis_tls_ca = redis_tls_ca
        self.memcached_port = memcached_port
        self.fault_injection = fault_injection
        self.redis_tls_untrusted_port = redis_tls_untrusted_port
        self.redis_tls_expired_port = redis_tls_expired_port
        self.process: subprocess.Popen | None = None
        self.output_path = root / "nginx-output.log"

    def write_config(self, sr_off: bool = False) -> None:
        workers = 1 if self.single_process else 4
        (self.root / "conf").mkdir(parents=True, exist_ok=True)
        (self.root / "logs").mkdir(parents=True, exist_ok=True)
        (self.root / "conf" / "nginx.conf").write_text(
            nginx_config(self.root, self.port, self.module,
                         self.origin_port, workers, self.redis_port,
                         self.redis_auth_port, self.redis_password,
                         self.redis_tls_port, self.redis_tls_ca,
                         self.memcached_port, self.fault_injection,
                         sr_off,
                         redis_tls_untrusted_port=self.redis_tls_untrusted_port,
                         redis_tls_expired_port=self.redis_tls_expired_port),
            encoding="ascii")

    def command(self, test: bool = False) -> list[str]:
        cmd = [str(self.binary), "-p", str(self.root),
               "-c", str(self.root / "conf" / "nginx.conf")]
        if test:
            cmd.append("-t")
        elif self.single_process:
            cmd.extend(["-g", "daemon off; master_process off;"])
        else:
            cmd.extend(["-g", "daemon off;"])
        return self.runner + cmd

    def config_test(self) -> None:
        r = subprocess.run(self.command(test=True), text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=20)
        if r.returncode != 0:
            raise RuntimeError(f"nginx -t failed:\n{r.stdout}")

    def start(self) -> None:
        self.write_config()
        out = self.output_path.open("a", encoding="utf-8")
        self.process = _track(subprocess.Popen(self.command(), text=True,
                                        stdout=out,
                                        stderr=subprocess.STDOUT))
        out.close()
        try:
            wait_port(self.port)
        except Exception:
            self.stop()
            raise

    def worker_pids(self) -> set[int]:
        """PIDs of the live worker processes (children of the master).

        Read from /proc rather than `ps` so it stays dependency-free. Returns an
        empty set in single-process mode, where there are no children at all.
        """
        if self.process is None:
            return set()
        try:
            children = (pathlib.Path("/proc") / str(self.process.pid) /
                        "task" / str(self.process.pid) / "children")
            return {int(p) for p in children.read_text().split()}
        except (OSError, ValueError):
            return set()

    def reload(self, sr_off: bool = False, timeout: float = 20.0) -> None:
        """Rewrite the config and drive a REAL `nginx -s reload`, then block
        until the new worker generation has actually taken over.

        !! Waiting is the whole point. `-s reload` only delivers SIGHUP and
        returns; the master then forks new workers and shuts the old ones down
        gracefully. A test that asserts immediately after the signal is racing a
        worker that may still be running the OLD configuration, which makes the
        assertion nondeterministic in exactly the direction that hides a bug.
        We therefore capture the worker PID set first and wait for a set that is
        both non-empty and fully disjoint from it -- old workers gone, new
        workers serving.

        Requires a master process; single-process mode has none and must skip.
        """
        if self.process is None:
            raise RuntimeError("reload() on a stopped nginx")
        if self.single_process:
            raise RuntimeError("reload() requires a master process "
                               "(not single_process mode)")

        before = self.worker_pids()
        self.write_config(sr_off=sr_off)

        # Fail on a bad config BEFORE signalling: a reload with a broken conf is
        # logged and ignored by the master, which would otherwise surface here as
        # a confusing "behaviour did not change" assertion failure instead of a
        # config error.
        self.config_test()

        r = subprocess.run(
            self.runner + [str(self.binary), "-p", str(self.root),
                           "-c", str(self.root / "conf" / "nginx.conf"),
                           "-s", "reload"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=20)
        if r.returncode != 0:
            raise RuntimeError(f"nginx -s reload failed:\n{r.stdout}")

        deadline = time.time() + timeout
        while time.time() < deadline:
            now = self.worker_pids()
            if now and not (now & before):
                # New generation is up. The listening socket is inherited, so the
                # port never closes; confirm it still answers before returning.
                wait_port(self.port)
                return
            time.sleep(0.1)

        raise RuntimeError(
            f"reload: workers did not turn over within {timeout}s "
            f"(before={sorted(before)}, now={sorted(self.worker_pids())})")

    def stop(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        rc = self.process.returncode
        self.process = None
        if rc not in (0, -signal.SIGTERM):
            out = (self.output_path.read_text(encoding="utf-8", errors="replace")
                   if self.output_path.exists() else "")
            raise RuntimeError(f"nginx exited with {rc}:\n{out}")

    def assert_clean_logs(self) -> None:
        paths = [self.output_path, self.root / "logs" / "error.log"]
        combined = "\n".join(
            p.read_text(encoding="utf-8", errors="replace")
            for p in paths if p.exists())
        for marker in SANITIZER_MARKERS:
            if marker == "ERROR SUMMARY:" and "ERROR SUMMARY: 0 errors" in combined:
                continue
            if marker in combined:
                raise AssertionError(f"runtime checker marker found: {marker}")
        fatal = [ln for ln in combined.splitlines()
                 if "[alert]" in ln or "[emerg]" in ln]
        if fatal:
            # DIAG: attribute any "open socket ... left in connection" leak to
            # the test that opened connection *NNNN. Purely informative — the
            # assertion still fires, it just names the culprit instead of
            # leaving a bare ordinal (see issues.md socket-flake entry).
            attribution = []
            for ln in fatal:
                m = re.search(r"\*(\d+) open socket", ln)
                if m:
                    attribution.append(_attribute_alert(int(m.group(1))))
            msg = "nginx logged fatal:\n" + "\n".join(fatal)
            if attribution:
                msg += ("\n\nsocket-leak attribution "
                        "(c->number cursor estimate):\n"
                        + "\n".join(attribution))
            raise AssertionError(msg)


# --------------------------------------------------------------------------- #
# Ephemeral Redis for the L2 (v2b) tests.
# --------------------------------------------------------------------------- #

def gen_tls_certs(dirpath: pathlib.Path) -> dict:
    """Generate a throwaway CA + a 127.0.0.1/localhost server cert for a TLS
    Redis. Returns {ca, cert, key} paths. Raises on any openssl failure."""
    dirpath.mkdir(parents=True, exist_ok=True)
    ca_key = dirpath / "ca.key"
    ca = dirpath / "ca.crt"
    key = dirpath / "redis.key"
    csr = dirpath / "redis.csr"
    crt = dirpath / "redis.crt"
    ext = dirpath / "redis.ext"
    ext.write_text("subjectAltName=IP:127.0.0.1,DNS:localhost\n")

    def run(*a):
        subprocess.run(a, check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=30)

    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(ca_key), "-out", str(ca), "-days", "1",
        "-subj", "/CN=ct-test-ca",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(csr), "-subj", "/CN=localhost")
    run("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca),
        "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(crt),
        "-days", "1", "-extfile", str(ext))
    return {"ca": str(ca), "cert": str(crt), "key": str(key),
            "ca_key": str(ca_key)}


def gen_tls_expired_cert(dirpath: pathlib.Path, ca_key: str, ca: str) -> dict:
    """Sign a server cert with an ALREADY-EXPIRED validity window (2020, well
    in the past), using the SAME trusted CA `gen_tls_certs` produced. Chain
    trust is fine (same CA); only the time-validity check should reject it.
    Isolates AUD-TLS1's "wrong CA" mode (gen_tls_certs called on a second,
    untrusted dir) from its "expired but chain-trusted" mode. Returns
    {ca, cert, key}. Raises on any openssl failure."""
    dirpath.mkdir(parents=True, exist_ok=True)
    key = dirpath / "redis.key"
    csr = dirpath / "redis.csr"
    crt = dirpath / "redis.crt"
    ext = dirpath / "redis.ext"
    ext.write_text("subjectAltName=IP:127.0.0.1,DNS:localhost\n")

    # `openssl x509 -req` only learned -not_before/-not_after in OpenSSL 3.2,
    # and CI runners still ship older builds -- using them here made the
    # fixture fail to generate and the whole redis_tls suite degrade. `openssl
    # ca -startdate/-enddate` has been supported for many major versions, so
    # the backdated window is portable. It needs a CA database, hence the
    # index/serial/config scaffolding below.
    index = dirpath / "index.txt"
    serial = dirpath / "serial"
    cnf = dirpath / "ca.cnf"
    index.write_text("")
    serial.write_text("01\n")
    cnf.write_text(
        "[ca]\n"
        "default_ca = CA_default\n"
        "[CA_default]\n"
        f"dir = {dirpath}\n"
        "database = $dir/index.txt\n"
        "serial = $dir/serial\n"
        "new_certs_dir = $dir\n"
        f"certificate = {ca}\n"
        f"private_key = {ca_key}\n"
        "default_md = sha256\n"
        "policy = policy_any\n"
        "email_in_dn = no\n"
        "rand_serial = no\n"
        "unique_subject = no\n"
        "[policy_any]\n"
        "commonName = supplied\n"
    )

    def run(*a):
        subprocess.run(a, check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=30)

    run("openssl", "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(csr), "-subj", "/CN=localhost")
    run("openssl", "ca", "-batch", "-config", str(cnf),
        "-in", str(csr), "-out", str(crt), "-notext",
        "-extfile", str(ext),
        "-startdate", "20200101000000Z", "-enddate", "20200102000000Z")
    return {"ca": ca, "cert": str(crt), "key": str(key)}


class RedisServer:
    def __init__(self, binary: pathlib.Path, root: pathlib.Path,
                 port: int, password: str | None = None,
                 tls_certs: dict | None = None) -> None:
        self.binary = binary
        self.root = root
        self.port = port
        self.password = password
        self.tls_certs = tls_certs
        self.process: subprocess.Popen[str] | None = None

    def start(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        args = [
            str(self.binary),
            "--bind", "127.0.0.1",
            "--save", "",
            "--appendonly", "no",
            "--dir", str(self.root),
        ]
        if self.tls_certs:
            # TLS-only listener: plaintext port off, tls-port on.
            args += [
                "--port", "0",
                "--tls-port", str(self.port),
                "--tls-cert-file", self.tls_certs["cert"],
                "--tls-key-file", self.tls_certs["key"],
                "--tls-ca-cert-file", self.tls_certs["ca"],
                "--tls-auth-clients", "no",
            ]
        else:
            args += ["--port", str(self.port)]
        if self.password:
            args += ["--requirepass", self.password]

        self.process = _track(subprocess.Popen(
            args, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT))
        wait_port(self.port)
        self.cli("FLUSHALL")

    def cli(self, *args: str) -> str:
        """Run a redis-cli command against this server; return stdout."""
        base = ["redis-cli", "-h", "127.0.0.1", "-p", str(self.port)]
        if self.tls_certs:
            base += ["--tls", "--cacert", self.tls_certs["ca"]]
        if self.password:
            base += ["-a", self.password, "--no-auth-warning"]
        r = subprocess.run(
            [*base, *args],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=10)
        return r.stdout.strip()

    def set_raw(self, key: str, value: bytes, px_ms: int) -> None:
        """SET key value PX px_ms over raw RESP — binary-safe, so a blob with
        embedded NULs/CRLF (which redis-cli argv cannot carry) lands intact."""
        args = [b"SET", key.encode(), value, b"PX", str(px_ms).encode()]
        cmd = b"*%d\r\n" % len(args)
        for a in args:
            cmd += b"$%d\r\n%s\r\n" % (len(a), a)
        with socket.create_connection(("127.0.0.1", self.port), 5) as s:
            s.sendall(cmd)
            if s.recv(64)[:1] != b"+":
                raise RuntimeError("raw SET not acknowledged")

    def get_raw(self, key: str) -> bytes | None:
        """GET key over raw RESP — binary-safe, so a blob with embedded NULs is
        returned intact (redis-cli text decoding would mangle it). Returns the
        value bytes, or None on a miss ($-1)."""
        args = [b"GET", key.encode()]
        cmd = b"*%d\r\n" % len(args)
        for a in args:
            cmd += b"$%d\r\n%s\r\n" % (len(a), a)
        with socket.create_connection(("127.0.0.1", self.port), 5) as s:
            s.sendall(cmd)
            s.settimeout(5)
            buf = b""
            # bulk reply: $<len>\r\n<payload>\r\n  (or $-1\r\n on miss)
            while b"\r\n" not in buf:
                buf += s.recv(4096)
            hdr_end = buf.index(b"\r\n")
            if buf[:1] != b"$":
                raise RuntimeError(f"unexpected GET reply: {buf[:32]!r}")
            n = int(buf[1:hdr_end])
            if n < 0:
                return None
            payload = buf[hdr_end + 2:]
            while len(payload) < n + 2:                # + trailing CRLF
                payload += s.recv(65536)
            return payload[:n]

    def stop(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=10)
        self.process = None

    def start_monitor(self) -> "RedisMonitor":
        """Open a raw MONITOR connection: Redis echoes every command any client
        executes against this instance, timestamped, as it runs. Used to prove a
        wire-level negative (e.g. AUTH/SELECT NOT resent on a reused connection)
        that a state-inspection query (EXISTS/PTTL/...) cannot show — those only
        prove the end state, not what was said on the wire to reach it."""
        return RedisMonitor(self)


class RedisMonitor:
    """Background reader of `MONITOR` output for one RedisServer. Requires its
    own raw socket (redis-cli MONITOR blocks the process), authenticating first
    if the server has a password. Collects the command name (first RESP token
    after the timestamp/db/addr preamble) of every command seen, so a caller can
    assert exact counts of e.g. AUTH / SELECT / GET / SET without parsing full
    MONITOR line syntax."""

    _CMD_RE = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')

    def __init__(self, redis: "RedisServer") -> None:
        self.redis = redis
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._lines: list[str] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def __enter__(self) -> "RedisMonitor":
        self._sock = socket.create_connection(("127.0.0.1", self.redis.port), 5)
        self._sock.settimeout(0.2)
        if self.redis.password:
            self._send(b"AUTH", self.redis.password.encode())
        self._send(b"MONITOR")
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        time.sleep(0.1)  # let MONITOR register before the caller issues traffic
        return self

    def _send(self, *args: bytes) -> None:
        cmd = b"*%d\r\n" % len(args)
        for a in args:
            cmd += b"$%d\r\n%s\r\n" % (len(a), a)
        assert self._sock is not None
        self._sock.sendall(cmd)
        # drain the one-line reply (+OK or the MONITOR banner)
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                if self._sock.recv(4096):
                    return
            except socket.timeout:
                continue

    def _run(self) -> None:
        buf = b""
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                chunk = self._sock.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            while b"\r\n" in buf:
                line, buf = buf.split(b"\r\n", 1)
                with self._lock:
                    self._lines.append(line.decode(errors="replace"))

    def commands_seen(self) -> list[str]:
        """Uppercased first-token command name of each MONITOR line captured so
        far (e.g. ['AUTH', 'SELECT', 'GET', ...]); the MONITOR connection's own
        AUTH is included by Redis too, so callers should checkpoint (clear) after
        __enter__ if the server has a password and that AUTH must not be counted."""
        with self._lock:
            lines = list(self._lines)
        out = []
        for ln in lines:
            m = self._CMD_RE.findall(ln)
            if m:
                out.append(m[0].upper())
        return out

    def checkpoint(self) -> None:
        """Discard everything captured so far (e.g. the monitor's own AUTH)."""
        with self._lock:
            self._lines.clear()

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)


class MemcachedServer:
    """A throwaway memcached instance for the v13 L2 tests. Talks the text
    protocol over a raw socket (no client library dependency), mirroring how the
    module's driver speaks to it."""

    def __init__(self, binary: pathlib.Path, port: int) -> None:
        self.binary = binary
        self.port = port
        self.process: subprocess.Popen[str] | None = None

    def start(self) -> None:
        self.process = _track(subprocess.Popen(
            [str(self.binary), "-l", "127.0.0.1", "-p", str(self.port),
             "-U", "0", "-m", "64"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT))
        wait_port(self.port)
        self.command(b"flush_all\r\n")

    def command(self, payload: bytes, recv: int = 65536) -> bytes:
        """Send a raw text-protocol command, return the (single recv) reply."""
        with socket.create_connection(("127.0.0.1", self.port), 5) as s:
            s.sendall(payload)
            s.settimeout(5)
            return s.recv(recv)

    def get(self, key: str) -> bytes | None:
        """Return the stored value bytes for key, or None on miss. Reads until
        the trailing END\\r\\n so a value spanning multiple TCP segments is whole."""
        with socket.create_connection(("127.0.0.1", self.port), 5) as s:
            s.sendall(b"get " + key.encode() + b"\r\n")
            s.settimeout(5)
            buf = b""
            while b"END\r\n" not in buf:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
        if buf.startswith(b"END\r\n"):
            return None
        # VALUE <key> <flags> <bytes>\r\n<data>\r\nEND\r\n
        hdr_end = buf.index(b"\r\n")
        nbytes = int(buf[:hdr_end].split()[3])
        data_start = hdr_end + 2
        return buf[data_start:data_start + nbytes]

    def exists(self, key: str) -> bool:
        return self.get(key) is not None

    def total_connections(self) -> int:
        """Value of memcached's `STAT total_connections` -- the running count of
        connections it has accepted since start. A keepalive pool that reuses
        connections drives far fewer new accepts than connect-per-op. Mirrors
        _redis_conns_received(); like it, the probe's OWN connection is counted
        (each caller opens one), so subtract a per-probe baseline, not compare
        raw totals."""
        reply = self.command(b"stats\r\n")
        for line in reply.split(b"\r\n"):
            parts = line.split()
            if len(parts) == 3 and parts[0] == b"STAT" \
                    and parts[1] == b"total_connections":
                return int(parts[2])
        raise RuntimeError("total_connections absent from memcached stats")

    def stop(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=10)
        self.process = None


class DirtyMemcached:
    """A DELIBERATELY MISBEHAVING fake memcached for the D-O2 clean-boundary test.

    Speaks just enough of the text protocol to answer get/set/delete/flush_all,
    but appends `trailer` bytes AFTER the framed reply (past END / STORED / the
    delete ack). A correct driver frames the reply, sees the extra trailing
    bytes, decides the stream is NOT at a clean boundary, and CLOSES the
    connection rather than returning it to the keepalive pool -- so the next op
    dials a fresh connection instead of resuming mid-reply. We count accepted
    connections: no pooling => roughly one accept per op.

    Threaded raw-socket server (no client library, mirrors MemcachedServer)."""

    def __init__(self, port: int, trailer: bytes = b"JUNKJUNK\r\n") -> None:
        self.port = port
        self.trailer = trailer
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._store: dict[bytes, bytes] = {}
        self._lock = threading.Lock()
        self._running = False
        self.accepts = 0

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.listen(64)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        wait_port(self.port)

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            with self._lock:
                self.accepts += 1
            threading.Thread(target=self._serve, args=(conn,),
                             daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        buf = b""
        try:
            conn.settimeout(10)
            while self._running:
                # A command is a CRLF-terminated line (plus a data block for set).
                while b"\r\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                line, _, rest = buf.partition(b"\r\n")
                buf = rest
                parts = line.split()
                if not parts:
                    continue
                cmd = parts[0]
                if cmd == b"set":
                    nbytes = int(parts[4])
                    while len(buf) < nbytes + 2:
                        chunk = conn.recv(4096)
                        if not chunk:
                            return
                        buf += chunk
                    data = buf[:nbytes]
                    buf = buf[nbytes + 2:]           # drop data + trailing CRLF
                    with self._lock:
                        self._store[parts[1]] = data
                    conn.sendall(b"STORED\r\n" + self.trailer)
                elif cmd == b"get":
                    with self._lock:
                        val = self._store.get(parts[1])
                    if val is None:
                        conn.sendall(b"END\r\n" + self.trailer)
                    else:
                        conn.sendall(b"VALUE " + parts[1] + b" 0 "
                                     + str(len(val)).encode() + b"\r\n" + val
                                     + b"\r\nEND\r\n" + self.trailer)
                elif cmd == b"delete":
                    with self._lock:
                        hit = self._store.pop(parts[1], None) is not None
                    conn.sendall((b"DELETED\r\n" if hit else b"NOT_FOUND\r\n")
                                 + self.trailer)
                elif cmd == b"flush_all":
                    with self._lock:
                        self._store.clear()
                    conn.sendall(b"OK\r\n")
                else:
                    conn.sendall(b"ERROR\r\n")
        except OSError:
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._running = False
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None


def l2_key(uri: str, prefix: str = "ct:") -> str:
    """Mirror the module's L2 key: prefix + hex of the 32-byte key hash. SEC-2:
    the key hash is SHA-256(cache_key) filling the whole 32-byte slot (64 hex);
    cache_turbo_key is $uri in the test config. (The module's no-SSL fallback is
    a double-MD5 fold, but the test build always has --with-http_ssl_module.)"""
    return prefix + hashlib.sha256(uri.encode()).hexdigest()


def lock_key(uri: str, prefix: str = "ct:") -> str:
    """Mirror the module's cross-node lock key: <prefix>lock:<hex key hash>."""
    return prefix + "lock:" + hashlib.sha256(uri.encode()).hexdigest()


def wait_for(predicate, timeout: float = 3.0, interval: float = 0.05) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def wait_for_l2(redis, key: str, expected: bytes, what: str = "",
                timeout: float = 2.0, interval: float = 0.02) -> None:
    """Assert that `key` holds exactly `expected` in L2, allowing a bounded
    wait for the value to land.

    This is an INSTRUMENT, not a fix. Three tests write an aged blob with
    set_raw() and immediately assert get_raw() agrees; on a shared CI Redis
    under load that read has intermittently disagreed. A bare `assert
    get_raw(key) == expected` cannot tell "never written" from "written late",
    so a red said nothing about which. This waits up to `timeout` and, on
    give-up, raises with the RAW observed value and the elapsed time -- which
    is what separates the two.

    Deliberately NOT a swallow: a wrong or absent value at the deadline still
    raises. Widening a wait until it always passes would disable the oracle
    ([[feedback-widening-shared-timeout-disables-oracle]]); the point here is
    to make the eventual red diagnosable, not to make it go away."""
    # monotonic, not time.time(): an NTP step on a CI box must not cut the wait
    # short or stretch it. The sleep is clamped to what is left of the deadline
    # so the wait cannot overrun `timeout` by up to a full interval.
    start = time.monotonic()
    got = None
    while True:
        got = redis.get_raw(key)
        if got == expected:
            return
        remaining = timeout - (time.monotonic() - start)
        if remaining <= 0:
            break
        time.sleep(min(interval, remaining))

    elapsed = time.monotonic() - start
    label = f" for {what}" if what else ""
    seen = "absent" if got is None else f"{len(got)} bytes"
    raise AssertionError(
        f"L2 value{label} did not match after {elapsed:.2f}s "
        f"(timeout {timeout:.2f}s): key={key!r}\n"
        f"  expected ({len(expected)} bytes): {expected!r}\n"
        f"  observed ({seen}): {got!r}\n"
        f"  This is the state at the LAST read, not a cause: absent means the "
        f"value was not there yet (never written, written later, or evicted), "
        f"and a differing value means the key held something else at that "
        f"instant. Compare the two blobs before picking a theory.")


def drain_origin(origin: Origin, settle: float = 0.6,
                 timeout: float = 10.0) -> None:
    """Wait until the origin stops receiving hits for `settle` seconds. v8's
    background_update fires async refresh subrequests that hit the origin AFTER
    the triggering request has returned; a bg-firing test must call this before
    returning so its async origin traffic does not pollute a later test's exact
    origin.hits assertion."""
    deadline = time.time() + timeout
    last = origin.hits
    stable_since = time.time()
    while time.time() < deadline:
        time.sleep(0.05)
        now = origin.hits
        if now != last:
            last = now
            stable_since = time.time()
        elif time.time() - stable_since >= settle:
            return


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #

def test_compressed_edge_identity_capture(ng: Nginx) -> None:
    """REGRESSION (2026-06-13 incident): cache_turbo behind a real compression
    filter must cache the IDENTITY body and let the downstream gzip filter
    re-encode per client, so a HIT never replays a coding the client did not
    accept (browser "Content Encoding Error").

    The /gz/ location runs the actual nginx gzip filter in front of the origin
    (gzip_proxied any + gzip_min_length 1 so even the tiny origin body is
    compressed). With the ngx_module_order load-order fix cache_turbo sits ABOVE
    gzip: it captures the uncompressed body, the entry is a single identity
    copy, and gzip compresses it for each client on MISS and HIT alike.

    Fails on the pre-fix build (cache_turbo below gzip -> stores gzip bytes +
    Content-Encoding: gzip -> replays gzip to the identity client). The Fix-B
    guard alone would make the entry a perpetual MISS, which the X-Cache=HIT
    assertion below would also catch — so this proves the real identity-capture
    path, not merely the refusal."""
    import gzip as _gzip

    def raw(ae: str):
        _bump_conn()
        conn = http.client.HTTPConnection("127.0.0.1", ng.port, timeout=HTTP_TIMEOUT)
        try:
            conn.request("GET", "/gz/page",
                         headers={"Accept-Encoding": ae, "Connection": "close"})
            r = conn.getresponse()
            data = r.read()
            return (r.status, data,
                    {k.lower(): v for k, v in r.getheaders()})
        finally:
            conn.close()

    def decode(data, ce):
        if ce == "gzip":
            return _gzip.decompress(data)
        assert ce in (None, "", "identity"), \
            f"unexpected Content-Encoding {ce!r}"
        return data

    # prime: gzip-capable client. MISS -> origin identity captured -> gzip
    # compresses on the way out.
    s0, d0, h0 = raw("gzip")
    assert s0 == 200, f"prime status {s0}"
    plain0 = decode(d0, h0.get("content-encoding"))

    # cross-encoding HIT: an identity-only client must get an UNencoded body from
    # the same cached entry, decoding to the same bytes.
    s1, d1, h1 = raw("identity")
    assert s1 == 200
    ce1 = h1.get("content-encoding")
    assert ce1 in (None, "", "identity"), \
        f"identity client got Content-Encoding={ce1!r} on HIT (encoding bug)"
    assert h1.get("x-cache") == "HIT", \
        f"identity request should HIT the identity entry, x-cache={h1.get('x-cache')}"
    assert decode(d1, ce1) == plain0, "HIT body (identity) differs from origin"

    # gzip client on a HIT: re-encoded gzip, decodes to the same bytes.
    s2, d2, h2 = raw("gzip")
    assert s2 == 200
    ce2 = h2.get("content-encoding")
    assert h2.get("x-cache") == "HIT", \
        f"second gzip request should HIT, x-cache={h2.get('x-cache')}"
    assert decode(d2, ce2) == plain0, "HIT body (gzip) differs from origin"


def test_miss_then_hit(ng: Nginx) -> None:
    """Basic: first request MISS (origin), second HIT (cached, same body)."""
    s1, b1, h1 = fetch(ng.port, "/c/hit")
    assert s1 == 200, f"miss status {s1}"
    assert "x-cache" not in h1, f"first req should be a miss, got {h1.get('x-cache')}"
    s2, b2, h2 = fetch(ng.port, "/c/hit")
    assert s2 == 200
    assert h2.get("x-cache") == "HIT", f"second req X-Cache={h2.get('x-cache')}"
    assert b1 == b2, f"HIT body differs: {b1!r} vs {b2!r}"


def test_surrogate_key_emit_on_miss_and_hit(ng: Nginx) -> None:
    """cache_turbo_surrogate_key on: BOTH the MISS (store) response and every
    later HIT carry the same Surrogate-Key header built from the deduped
    cache_turbo_tag list (SK-A1). A fronting CDN POP whose own copy expired
    refills from our HIT; an untagged hit would leave that edge object outside
    the tag purge. Works with NO cache_turbo_redis -- the emit is independent of
    the L2 tag index."""
    path = "/sk/page"

    s1, _b1, h1 = fetch(ng.port, path)
    assert s1 == 200, f"miss status {s1}"
    assert "x-cache" not in h1, f"first req should MISS, got {h1.get('x-cache')}"
    sk = h1.get("surrogate-key")
    assert sk is not None, "MISS response is missing the Surrogate-Key header"
    # tag list was "blog news blog" -> dedup -> two tags, order preserved.
    assert sk.split() == ["blog", "news"], \
        f"Surrogate-Key not the deduped tag set: {sk!r}"

    s2, _b2, h2 = fetch(ng.port, path)
    assert s2 == 200
    assert h2.get("x-cache") == "HIT", f"second req X-Cache={h2.get('x-cache')}"
    sk2 = h2.get("surrogate-key")
    assert sk2 is not None, \
        "HIT dropped Surrogate-Key -- a CDN refilling from this hit caches an " \
        "untagged object that a tag purge cannot reach (SK-A1)"
    assert sk2.split() == ["blog", "news"], \
        f"HIT Surrogate-Key differs from the MISS's: {sk2!r} vs {sk!r}"
    assert sk2.split() == sk.split(), "MISS and HIT keys must match exactly"

    # Exactly one header line -- the store-path skip must keep the generated key
    # out of the blob, or the hit would carry a duplicate.
    conn = http.client.HTTPConnection("127.0.0.1", ng.port, timeout=HTTP_TIMEOUT)
    try:
        conn.request("GET", path, headers={"Connection": "close"})
        resp = conn.getresponse()
        resp.read()
        sk_lines = [v for k, v in resp.getheaders()
                    if k.lower() == "surrogate-key"]
    finally:
        conn.close()
    assert len(sk_lines) == 1, \
        f"expected exactly one Surrogate-Key line on a HIT, got {sk_lines!r}"


def test_surrogate_key_off_by_default(ng: Nginx) -> None:
    """A cache_turbo_tag location WITHOUT cache_turbo_surrogate_key emits no
    Surrogate-Key header -- the directive gates the emit."""
    s1, _b1, h1 = fetch(ng.port, "/skoff/page")
    assert s1 == 200, f"miss status {s1}"
    assert "x-cache" not in h1, f"first req should MISS, got {h1.get('x-cache')}"
    assert "surrogate-key" not in h1, \
        f"surrogate_key OFF but header present: {h1.get('surrogate-key')!r}"


def test_surrogate_key_origin_header_survives_hit(ng: Nginx) -> None:
    """SK-A1, directive OFF: an origin-supplied Surrogate-Key is stored with the
    representation and replayed on the HIT. The store-path skip only applies to
    the key the module generates itself; dropping the origin's would hand a CDN
    an untagged edge object on every refill from our cache."""
    path = "/c/originsk-page"

    s1, _b1, h1 = fetch(ng.port, path)
    assert s1 == 200, f"miss status {s1}"
    assert "x-cache" not in h1, f"first req should MISS, got {h1.get('x-cache')}"
    assert h1.get("surrogate-key") == "origin-a origin-b", \
        f"origin Surrogate-Key mangled on MISS: {h1.get('surrogate-key')!r}"

    s2, _b2, h2 = fetch(ng.port, path)
    assert s2 == 200
    assert h2.get("x-cache") == "HIT", f"second req X-Cache={h2.get('x-cache')}"
    assert h2.get("surrogate-key") == "origin-a origin-b", \
        f"HIT dropped the origin Surrogate-Key: {h2.get('surrogate-key')!r}"


def test_surrogate_key_empty_tag_no_header(ng: Nginx) -> None:
    """surrogate_key on but the tag expression evaluates empty (no ?t= arg):
    no tags, so no Surrogate-Key header (and no empty-value header)."""
    s1, _b1, h1 = fetch(ng.port, "/skcap/page")
    assert s1 == 200, f"miss status {s1}"
    assert "surrogate-key" not in h1, \
        f"empty tag list should emit no header, got {h1.get('surrogate-key')!r}"


def test_surrogate_key_dedup_from_arg(ng: Nginx) -> None:
    """The emitted Surrogate-Key reflects the same dedup the tag tokeniser does:
    a value with a repeated tag emits each tag once."""
    s1, _b1, h1 = fetch(ng.port, "/skcap/page2?t=a,b,a,c,b")
    assert s1 == 200, f"miss status {s1}"
    sk = h1.get("surrogate-key")
    assert sk is not None, "MISS response is missing the Surrogate-Key header"
    assert sk.split() == ["a", "b", "c"], \
        f"Surrogate-Key not deduped in emit order: {sk!r}"


def test_post_passthrough_uncached(ng: Nginx, origin: Origin) -> None:
    """A POST through a cache_turbo location is a pure passthrough today (the
    method gate declines non-GET/HEAD before any cache work): every POST must
    reach the origin, the body must transit nginx intact (origin echoes its
    digest), and the GET entry for the same URI must be neither served to the
    POST nor polluted by it."""
    path = "/c/post-passthru"
    payload = b'{"query":"query P($id:ID!){product(id:$id){name}}"}'
    want = hashlib.sha256(payload).hexdigest()[:16]
    base = origin.hits_for("post-passthru")

    s1, b1, h1 = fetch(ng.port, path, method="POST", data=payload,
                       headers={"Content-Type": "application/json"})
    s2, b2, h2 = fetch(ng.port, path, method="POST", data=payload,
                       headers={"Content-Type": "application/json"})
    assert s1 == 200 and s2 == 200, f"POST status {s1}/{s2}"
    assert b1.startswith("post-") and b2.startswith("post-"), \
        f"origin do_POST body shape: {b1!r} / {b2!r}"
    # Both POSTs must carry the body intact -- checking only the first would
    # leave a second-request body corruption (buffering/park bug) invisible.
    for tag, b in (("first", b1), ("second", b2)):
        assert b.split(":")[1].strip() == want, \
            f"{tag} POST body mangled in transit: {b!r} want digest {want}"
    assert b1 != b2, f"identical POST bodies -> a POST was served from cache: {b1!r}"
    assert "x-cache" not in h1 and "x-cache" not in h2
    assert origin.hits_for("post-passthru") == base + 2, \
        "every POST must reach the origin"

    # The GET slot for the same URI is independent: the first GET must reach the
    # origin (positive proof, via the path-scoped hit counter -- NOT an
    # "x-cache absent" assert, which a plain MISS and a never-consulted cache
    # produce alike; see lessons.md) and return a fresh gen body rather than a
    # replayed POST body. The second GET is then a HIT.
    gbase = origin.hits_for("post-passthru")
    sg1, bg1, _ = fetch(ng.port, path)
    assert origin.hits_for("post-passthru") == gbase + 1, \
        "the first GET must reach the origin (no POST-primed entry to serve)"
    sg2, bg2, hg2 = fetch(ng.port, path)
    assert sg1 == 200 and sg2 == 200
    assert bg1.startswith("gen-"), \
        f"GET served a POST-shaped body -> POST polluted the GET entry: {bg1!r}"
    assert hg2.get("x-cache") == "HIT" and bg1 == bg2, \
        f"GET caching broken next to POSTs: {hg2.get('x-cache')} {bg1!r}/{bg2!r}"


def test_header_fidelity(ng: Nginx) -> None:
    """R2: Content-Type + arbitrary origin header survive a HIT byte-identical."""
    fetch(ng.port, "/c/hdr")                       # prime
    _, _, h = fetch(ng.port, "/c/hdr")             # HIT
    assert h.get("x-cache") == "HIT"
    assert h.get("content-type") == "application/json; charset=utf-8", \
        f"content-type lost: {h.get('content-type')}"
    assert h.get("x-backend") == "origin-42", \
        f"custom header lost: {h.get('x-backend')}"


def test_restore_allocation_failure_fails_closed(ng: Nginx,
                                                 origin: Origin) -> None:
    """Allocation failure while rebuilding a cached response must never emit a
    partial cached 200/3xx or fall through from a destructively reset SIE header
    list. The hidden directive exists only in ci/tools/ci-build.sh builds."""
    aborted_paths: list[str] = []

    def assert_failed_closed(path: str, forbidden_status: int,
                             forbidden_header: str | None = None) -> None:
        # Two outcomes are fail-closed and both are accepted: a deterministic
        # 500, or an abort before any byte of the header block reaches the
        # client. Every location here currently takes the abort path --
        # add_header()'s NGX_ERROR propagates out of the header filter, so
        # nginx tears the connection down instead of emitting a partial
        # response. That is the contract this test names ("must never emit a
        # partial cached 200/3xx"), so an abort is a PASS, not a skip.
        #
        # A bare `return` here used to swallow the abort entirely, which meant
        # the branch asserted nothing at all. Record it instead: the caller
        # asserts the whole set below, so a silent flip of every location to
        # some other status can no longer pass unnoticed.
        #
        # Deliberately NOT re-probed. `cache_turbo_test_restore_alloc_fail` is
        # a static loc-conf flag (module.c:512-516, merged at :12524), so a
        # second request to the same location aborts for exactly the same
        # reason as the first. A re-probe here cannot distinguish a one-off
        # truncation from the steady state, and asserting on it would look
        # like coverage while being unreachable.
        try:
            status, _, headers = fetch_raw(ng.port, path)
        except http.client.RemoteDisconnected:
            aborted_paths.append(path)
            return

        assert status == 500 and status != forbidden_status, \
            f"allocation failure returned unsafe status {status}: {headers}"
        if forbidden_header is not None:
            assert headers.get(forbidden_header) is None, \
                f"allocation failure leaked {forbidden_header}: {headers}"

    s0, _, _ = fetch_raw(ng.port, "/allocfail/bare-normal")
    assert s0 == 200, f"normal allocation-fault prime failed: {s0}"
    assert_failed_closed("/allocfail/bare-normal", 200, "x-cache")

    sr0, _, hr0 = fetch_raw(ng.port, "/allocfailst/redir")
    assert sr0 == 301 and hr0.get("location"), \
        f"redirect allocation-fault prime failed: {sr0} {hr0}"
    assert_failed_closed("/allocfailst/redir", 301, "location")

    ss0, bs0, _ = fetch_raw(ng.port, "/allocfailsie/sieserve-alloc")
    assert ss0 == 200 and bs0, f"SIE allocation-fault prime failed: {ss0}"
    time.sleep(4.6)  # fully expired, but inside stale-if-error=30
    origin.fail = True
    try:
        assert_failed_closed("/allocfailsie/sieserve-alloc", 503,
                             "x-cache")
    finally:
        origin.fail = False
        drain_origin(origin)

    # Pin the observed shape. All three locations abort today, and each abort
    # returned above without asserting anything -- so without this the test
    # passes unchanged if every one of them silently starts doing something
    # else. Both directions are real failures worth seeing: a location that
    # stops aborting takes the 500 branch above (and must satisfy it), while
    # this catches the set drifting as a whole.
    assert aborted_paths == ["/allocfail/bare-normal", "/allocfailst/redir",
                             "/allocfailsie/sieserve-alloc"], \
        f"allocation-failure abort set changed: {aborted_paths}"


def test_file_backed_delegate_never_stores(ng: Nginx,
                                            origin: Origin) -> None:
    """A file-backed (sendfile) response body cannot be captured from memory,
    so the body filter must abort capture and delegate the UNMODIFIED chain
    downstream -- the object is served correctly but never cached. The hidden
    cache_turbo_test_force_file_buf directive drives that branch
    deterministically (the real in_file trigger is directio/fs dependent). The
    directive exists only in ci/tools/ci-build.sh builds."""
    n0 = origin.hits
    s1, b1, h1 = fetch(ng.port, "/forcefile/asset")
    assert s1 == 200 and b1, f"forcefile prime failed: {s1}"
    assert h1.get("x-cache") != "HIT", \
        f"file-backed body must not HIT on first read: {h1.get('x-cache')}"

    s2, b2, h2 = fetch(ng.port, "/forcefile/asset")
    assert s2 == 200 and b2, f"file-backed second read failed: {s2}"
    assert h2.get("x-cache") != "HIT", \
        f"file-backed body must never store (delegate path): {h2.get('x-cache')}"
    # The counting origin returns a unique body per hit, so a HIT would replay
    # b1 byte-for-byte. Two distinct bodies prove both reads were served fresh
    # from the origin -- i.e. the delegate path stored nothing.
    assert b2 != b1, \
        "file-backed body identical across reads -> a stale copy was served"

    # Both reads reached the origin -> nothing was served from cache-turbo.
    assert origin.hits - n0 >= 2, \
        f"expected >=2 origin hits (no caching), got {origin.hits - n0}"


def test_suppress_native_variable(ng: Nginx) -> None:
    """Q1: $cache_turbo_active reads 1 on an engaged request when
    cache_turbo_suppress_native is on (so a stacked native cache can defer via
    proxy_no_cache), and 0 when the directive is off (default), even though
    cache-turbo is still caching the request."""
    # suppress on -> engaged request reports active=1 (miss and subsequent hit)
    _, _, h1 = fetch(ng.port, "/sup/x")
    assert h1.get("x-ct-active") == "1", \
        f"suppress on: expected X-CT-Active=1, got {h1.get('x-ct-active')}"
    _, _, h1b = fetch(ng.port, "/sup/x")
    assert h1b.get("x-cache") == "HIT", "second /sup/ read should HIT"
    assert h1b.get("x-ct-active") == "1", \
        f"suppress on (hit): expected 1, got {h1b.get('x-ct-active')}"
    # suppress off (default) -> variable is 0 although the entry is still cached
    _, _, h2 = fetch(ng.port, "/nosup/x")
    assert h2.get("x-ct-active") == "0", \
        f"suppress off: expected X-CT-Active=0, got {h2.get('x-ct-active')}"
    _, _, h2b = fetch(ng.port, "/nosup/x")
    assert h2b.get("x-cache") == "HIT", \
        "second /nosup/ read should HIT (still caching, var just reads 0)"


def test_auto_classify(ng: Nginx, origin: Origin) -> None:
    """Auto-classify (cache_turbo <zone> auto): a normal anonymous page is
    cached, but a request matching a dynamic surface of the generic preset —
    login/session cookie, backend URI prefix, or dynamic query arg — skips the
    cache entirely (origin every time, never an X-Cache HIT)."""
    # normal anon page: cacheable
    _, b1, _ = fetch(ng.port, "/auto/normal")
    _, b2, h2 = fetch(ng.port, "/auto/normal")
    assert h2.get("x-cache") == "HIT", \
        f"anon page should cache, got x-cache={h2.get('x-cache')}"
    assert b2 == b1, "cached body should be byte-identical"

    # logged-in cookie: never cached (#1 footgun — a request Cookie alone does
    # not block caching without auto-classify)
    ck = {"Cookie": "wordpress_logged_in_abc=deadbeef"}
    _, c1, hc1 = fetch(ng.port, "/auto/private", headers=ck)
    _, c2, hc2 = fetch(ng.port, "/auto/private", headers=ck)
    assert "x-cache" not in hc1 and "x-cache" not in hc2, \
        "logged-in cookie must skip the cache"
    assert c1 != c2, "logged-in requests must each reach the origin"

    # dynamic query arg ?preview=true: never cached
    _, p1, hp1 = fetch(ng.port, "/auto/post?preview=true")
    _, p2, hp2 = fetch(ng.port, "/auto/post?preview=true")
    assert "x-cache" not in hp1 and "x-cache" not in hp2, \
        "preview arg must skip the cache"
    assert p1 != p2, "preview requests must each reach the origin"

    # backend URI prefix (/wp-admin/): never cached
    _, _, ha1 = fetch(ng.port, "/wp-admin/index")
    _, _, ha2 = fetch(ng.port, "/wp-admin/index")
    assert "x-cache" not in ha1 and "x-cache" not in ha2, \
        "/wp-admin/ must skip the cache"
    drain_origin(origin)


def test_auto_classify_suppress_native_interaction(ng: Nginx, origin: Origin) -> None:
    """Q1 x auto-classify: on a suppress_native location, an anon page engages
    cache-turbo so $cache_turbo_active=1 (native cache defers), but an
    auto-classified dynamic request (login cookie) is skipped -> NOT engaged ->
    $cache_turbo_active=0, freeing a stacked native cache to own that URL.

    Guards the src comment at ngx_http_cache_turbo_module.c:2964 (auto-skip sets
    ct_active=0). A regression that left ct_active=1 on the skip path would make
    the variable report "1" and wrongly keep native suppressed on a page
    cache-turbo refuses to store -> that URL caches nowhere."""
    # anon page: engaged, native suppressed -> active=1, and it caches
    fetch(ng.port, "/autosup/normal")
    _, _, h = fetch(ng.port, "/autosup/normal")
    assert h.get("x-cache") == "HIT", \
        f"anon page should cache, got x-cache={h.get('x-cache')}"
    assert h.get("x-ct-active") == "1", \
        f"engaged anon page must report $cache_turbo_active=1, got {h.get('x-ct-active')}"

    # logged-in cookie: auto-classified dynamic -> skipped -> NOT engaged
    ck = {"Cookie": "wordpress_logged_in_abc=deadbeef"}
    _, d1, hd1 = fetch(ng.port, "/autosup/private", headers=ck)
    _, d2, hd2 = fetch(ng.port, "/autosup/private", headers=ck)
    assert "x-cache" not in hd1 and "x-cache" not in hd2, \
        "logged-in cookie must skip the cache even with suppress_native on"
    assert d1 != d2, "logged-in requests must each reach the origin"
    assert hd1.get("x-ct-active") == "0", \
        (f"auto-skipped dynamic request must report $cache_turbo_active=0 so a "
         f"stacked native cache is free, got {hd1.get('x-ct-active')}")
    drain_origin(origin)


def test_woocommerce_wc_ajax(ng: Nginx, origin: Origin) -> None:
    """?wc-ajax= is the one WooCommerce leak path that NO URI rule can close.

    WC's AJAX endpoints have no path of their own — get_endpoint() builds
    "currentpageurl?wc-ajax=name", so a cart-fragment call is a request to an
    ORDINARY, CACHEABLE page URL carrying a query arg. /cart, /checkout and
    /my-account all fail to match it. The response body is that shopper's cart
    HTML; store it and the next visitor is served someone else's cart.

    So: the same page URL must CACHE when plain, and BYPASS the moment wc-ajax
    appears. Both halves are asserted — a bypass-everything bug would pass the
    second assertion alone."""
    # The bare page is a normal cacheable page.
    fetch(ng.port, "/woo/shop-front")
    _, _, hp = fetch(ng.port, "/woo/shop-front")
    assert hp.get("x-cache") == "HIT", \
        f"woo: a plain shop page must cache, got {hp.get('x-cache')}"

    # The SAME page with ?wc-ajax= is a per-shopper cart fragment -> must bypass.
    for uri in ("/woo/shop-front?wc-ajax=get_refreshed_fragments",
                "/woo/shop-front?wc-ajax=update_order_review",
                "/woo/?wc-ajax=checkout"):
        _, _, h1 = fetch(ng.port, uri)
        _, _, h2 = fetch(ng.port, uri)
        assert "x-cache" not in h1 and "x-cache" not in h2, \
            (f"woo: {uri} is a per-shopper cart fragment on an ordinary page URL "
             "-- it must bypass or one shopper's cart is served to everyone")
    drain_origin(origin)


def test_header_auth_rest_surfaces(ng: Nginx, origin: Origin) -> None:
    """Header-authenticated REST surfaces must bypass on the URI/arg tier.

    These are structurally invisible to the cookie tier: an API client sends
    `Authorization: Bearer ...` and NO session cookie, so every cookie rule in
    every preset is blind to it. Only a URI or arg rule can see them, and only
    xenforo's /api/ was covered.

    The arms deliberately send NO Authorization header. The module has an
    Authorization storage floor, so a request that carries one would bypass
    storing for a reason that has nothing to do with the preset -- the
    assertion would pass with the rule removed. A cookie-less, header-less
    fetch is the only shape that actually tests the URI rule.

    WordPress ?rest_route= is the sharpest of these: it is not a fallback for
    /wp-json/, it is what /wp-json/ REWRITES TO. wp-includes/rest-api.php maps
    ^wp-json/(.*) -> index.php?rest_route=/$1, and rest_api_loaded() dispatches
    only when that query var is set. With plain permalinks the request never has
    a /wp-json/ path at all, so the URI rule saw nothing."""
    # Magento Web API front names: rest + soap.
    for uri in ("/rest/V1/customers/me", "/rest/V1/orders", "/soap/default"):
        fetch(ng.port, uri)
        _, _, h = fetch(ng.port, uri)
        assert "x-cache" not in h, \
            (f"magento {uri} is header-authenticated and invisible to the cookie "
             f"tier -- it must bypass on the URI rule, got {h.get('x-cache')}")

    # ...but a catalog URL that merely shares the letters must still cache. The
    # prefix requires a '/' or '.' boundary, so /restaurant-supplies is not /rest.
    fetch(ng.port, "/restaurant-supplies")
    _, _, hr = fetch(ng.port, "/restaurant-supplies")
    assert hr.get("x-cache") == "HIT", \
        ("/restaurant-supplies merely shares letters with /rest and must stay "
         f"cacheable (prefix needs a '/' or '.' boundary), got {hr.get('x-cache')}")

    # Drupal JSON:API (core, jsonapi.base_path) and simple_oauth.
    # /oauth/userinfo is the leak that justifies the prefix: a GET, authenticated
    # purely by bearer token, returning the token holder's profile.
    for uri in ("/jsonapi/node/article", "/oauth/userinfo", "/oauth/debug"):
        fetch(ng.port, uri)
        _, _, h = fetch(ng.port, uri)
        assert "x-cache" not in h, \
            (f"drupal {uri} is header-authenticated -- it must bypass on the URI "
             f"rule, got {h.get('x-cache')}")

    # WordPress ?rest_route= -- the same API as /wp-json/, addressed the other
    # way. This is the arm that fails if only the URI half is covered.
    for uri in ("/wpq/?rest_route=/wp/v2/users/me",
                "/wpq/index.php?rest_route=/wp/v2/posts",
                "/wpq/?p=1&rest_route=/wp/v2/settings"):
        fetch(ng.port, uri)
        _, _, h = fetch(ng.port, uri)
        assert "x-cache" not in h, \
            (f"{uri} IS the REST API -- /wp-json/ is a rewrite to this form, so "
             f"guarding only the path leaves it open, got {h.get('x-cache')}")
    drain_origin(origin)


def test_phpbb_preset(ng: Nginx, origin: Origin) -> None:
    """phpBB preset (docs/phpbb.md). URI + ?sid= rules, PLUS the cookie VALUE
    predicate <prefix>_u != 1.

    phpBB sets _u/_k/_sid for every non-bot visitor INCLUDING guests, so a
    presence matcher identifies nobody: an anon gets _u=1 (ANONYMOUS), a member
    gets _u=<user_id> (never 1 — ANONYMOUS is a reserved row). Only a VALUE test
    separates them. Until that existed the preset shipped no cookie rule and a
    logged-in member's page was cached and served to strangers unless the
    operator hand-wrote a bypass; this test now asserts that leak is closed.

    The name is matched by SUFFIX because the prefix is config('cookie_name'),
    an ACP setting (default "phpbb") that installers randomise — a literal-name
    rule stops firing on a renamed board, and a bypass that stops firing leaks.
    Verified against phpbb/phpbb: includes/constants.php (ANONYMOUS=1),
    phpbb/session.php session_create()/set_cookie()."""
    for uri in ("/ucp.php", "/ucp.php?mode=login"):
        _, _, h = fetch(ng.port, uri)
        assert "x-cache" not in h, f"{uri} must bypass on the phpbb preset"

    # ?sid= marks a session-propagated URL: bypass (also a key-poisoning vector).
    _, _, hs = fetch(ng.port, "/phpbb/viewtopic?sid=deadbeef")
    assert "x-cache" not in hs, "?sid= must bypass"

    # Guest cookies must NOT bypass — every anonymous phpBB visitor carries them.
    guest = {"Cookie": "phpbb3_sid=abc; phpbb3_u=1; phpbb3_k="}
    fetch(ng.port, "/phpbb/viewtopic-a", headers=guest)
    _, _, hg = fetch(ng.port, "/phpbb/viewtopic-a", headers=guest)
    assert hg.get("x-cache") == "HIT", \
        f"guest phpbb cookies must stay cacheable, got {hg.get('x-cache')}"

    # THE FIX (was the documented gap): a logged-in user carries <prefix>_u with
    # their user_id, never ANONYMOUS(=1). The value predicate reads it and
    # bypasses. Before this rule the member's page was cached and served to
    # strangers — a cross-user leak the docs told the operator to patch by hand.
    authed = {"Cookie": "phpbb3_sid=abc; phpbb3_u=42; phpbb3_k=beef"}
    fetch(ng.port, "/phpbb/viewtopic-b", headers=authed)
    _, _, ha = fetch(ng.port, "/phpbb/viewtopic-b", headers=authed)
    assert "x-cache" not in ha, \
        (f"logged-in phpbb user (_u=42 != ANONYMOUS 1) MUST bypass, got "
         f"{ha.get('x-cache')} — this is the cross-user leak the value "
         "predicate exists to close")

    # The cookie NAME PREFIX is an ACP setting (config 'cookie_name', default
    # "phpbb"), and installers randomise it. The predicate matches the name by
    # SUFFIX for exactly this reason: a literal-name rule silently stops firing
    # on a renamed board, and a bypass rule that stops firing LEAKS. Prove the
    # suffix match holds under an arbitrary prefix.
    for prefix in ("phpbb", "phpbb3", "myboard_xyz", "zz"):
        m = {"Cookie": f"{prefix}_sid=abc; {prefix}_u=7"}
        fetch(ng.port, f"/phpbb/vt-{prefix}", headers=m)
        _, _, hm = fetch(ng.port, f"/phpbb/vt-{prefix}", headers=m)
        assert "x-cache" not in hm, \
            (f"member with cookie prefix '{prefix}' must bypass — the name is "
             "matched by SUFFIX because the prefix is admin-configurable")

        g = {"Cookie": f"{prefix}_sid=abc; {prefix}_u=1"}
        fetch(ng.port, f"/phpbb/vg-{prefix}", headers=g)
        _, _, hgp = fetch(ng.port, f"/phpbb/vg-{prefix}", headers=g)
        assert hgp.get("x-cache") == "HIT", \
            f"guest (_u=1) with prefix '{prefix}' must stay cacheable"

    # Absent _u => no session => guest => cacheable (the predicate must have no
    # opinion when its cookie is missing, not bypass everything).
    none = {"Cookie": "other=1; unrelated=x"}
    fetch(ng.port, "/phpbb/viewtopic-c", headers=none)
    _, _, hn = fetch(ng.port, "/phpbb/viewtopic-c", headers=none)
    assert hn.get("x-cache") == "HIT", \
        f"no _u cookie at all must stay cacheable, got {hn.get('x-cache')}"

    # Unparseable => fail CLOSED to bypass. A bare "_u" with no '=' gives us no
    # value to test; guessing "guest" there would cache a possible member.
    bare = {"Cookie": "phpbb3_sid=abc; phpbb3_u"}
    fetch(ng.port, "/phpbb/viewtopic-d", headers=bare)
    _, _, hb = fetch(ng.port, "/phpbb/viewtopic-d", headers=bare)
    assert "x-cache" not in hb, \
        (f"valueless '_u' must fail closed (bypass), got {hb.get('x-cache')} — "
         "an unreadable cookie must never be assumed to be a guest")

    # "_u=10" must not satisfy "_u == 1": the compare is exact + length-checked,
    # not a prefix. A member with user_id 10 is a member.
    ten = {"Cookie": "phpbb3_u=10"}
    fetch(ng.port, "/phpbb/viewtopic-e", headers=ten)
    _, _, ht = fetch(ng.port, "/phpbb/viewtopic-e", headers=ten)
    assert "x-cache" not in ht, \
        f"_u=10 is user 10, not ANONYMOUS(1) — must bypass, got {ht.get('x-cache')}"

    # Empty value "_u=" (a cleared/reset cookie, distinct from the bare "_u" with
    # no '=' above): it reaches the value compare with a zero-length value. By the
    # letter of "!= 1" an empty string is a non-member => bypass; that is also the
    # safe reading for a malformed/cleared cookie (module.c:2532-2540). Exercises
    # the empty-value arm of the NE predicate the non-empty members above skip.
    empty = {"Cookie": "phpbb3_sid=abc; phpbb3_u="}
    fetch(ng.port, "/phpbb/viewtopic-f", headers=empty)
    _, _, he = fetch(ng.port, "/phpbb/viewtopic-f", headers=empty)
    assert "x-cache" not in he, \
        (f"empty '_u=' is not the guest literal '1' — must bypass (cleared/"
         f"malformed cookie, safe direction), got {he.get('x-cache')}")
    drain_origin(origin)



def test_redmine_key_arg_bypasses_without_cookie(ng: Nginx,
                                                 origin: Origin) -> None:
    """redmine preset must bypass `?key=` with NO cookie present.

    application_controller.rb authenticates `key` two ways, neither of which
    starts a session: as an Atom key (params[:format] == 'atom' && params[:key]
    -> User.find_by_atom_key) and as an API key (api_key_from_request when
    Setting.rest_api_enabled?). So ?key=<atom key> returns a private issue list
    with no cookie at all. A cookie-only preset would cache that under the
    public cache key and serve one user's private tracker to everyone -- the
    same hole ghost's ?uuid=/?key=/?gift= rows close.

    The negative control is the same path WITHOUT the arg: it must still cache,
    proving the bypass comes from the arg rule and not from the path being
    uncacheable anyway."""
    _, _, _h1 = fetch(ng.port, "/redmine/issues?key=abc123deadbeef")
    _, _, h2 = fetch(ng.port, "/redmine/issues?key=abc123deadbeef")
    assert "x-cache" not in h2, \
        (f"?key= MUST bypass with no cookie, got {h2.get('x-cache')} -- it "
         "authenticates via Atom/API key and returns private content")

    fetch(ng.port, "/redmine/issues")
    _, _, h3 = fetch(ng.port, "/redmine/issues")
    assert h3.get("x-cache") == "HIT", \
        (f"a public issue list with no key must still cache, got "
         f"{h3.get('x-cache')} -- if this is also a bypass the test above "
         "proves nothing about the arg rule")


def test_redmine_public_content_stays_cacheable(ng: Nginx,
                                                origin: Origin) -> None:
    """redmine must NOT bypass /projects, /issues, /news, /wiki.

    On an open tracker those are the main public content and the entire reason
    to put a cache in front of it. Public-vs-private there is a per-project
    ACL nginx cannot see; the cookie rule is what protects a logged-in view.
    A preset that bypassed them would be safe but pointless, so the rows are
    deliberately absent and that absence is pinned here.

    /admin and /my are asserted alongside as the positive half, so the test
    cannot pass by the preset simply doing nothing."""
    for uri in ("/redmine/projects/foo", "/redmine/issues",
                "/redmine/news", "/redmine/wiki/Main"):
        fetch(ng.port, uri)
        _, _, h = fetch(ng.port, uri)
        assert h.get("x-cache") == "HIT", \
            (f"{uri} must stay cacheable, got {h.get('x-cache')} -- public "
             "tracker content is why the cache is here")

    for uri in ("/redmine/admin", "/redmine/my/account", "/redmine/login"):
        fetch(ng.port, uri)
        _, _, h = fetch(ng.port, uri)
        assert "x-cache" not in h, \
            (f"{uri} MUST bypass, got {h.get('x-cache')}")


def test_cookie_pred_multiple_matching_cookies(ng: Nginx, origin: Origin) -> None:
    """A Cookie header can carry SEVERAL cookies matching one predicate's name
    suffix. Every one of them must be examined.

    phpBB keys on the suffix `_u` and the prefix is per-board (config
    'cookie_name'), so one browser visiting two boards on the same host sends
    `phpbb3_<a>_u` AND `phpbb3_<b>_u` in a single header. The evaluator used to
    return on the FIRST pair whose name matched, so a leading guest `_u=1`
    decided the whole request and masked a member `_u=42` sitting behind it --
    the member's page was cached and served to strangers. That is the same
    cross-user leak the value predicate exists to close, reachable again through
    a second cookie.

    Both orders are asserted: the reverse order always worked, so testing only
    that would pass with the bug still in place."""
    # Guest cookie FIRST, member second. This is the regression.
    masked = {"Cookie": "phpbb3_aaa_u=1; phpbb3_bbb_u=42"}
    fetch(ng.port, "/phpbb/multi-a", headers=masked)
    _, _, hm = fetch(ng.port, "/phpbb/multi-a", headers=masked)
    assert "x-cache" not in hm, \
        (f"a member `_u=42` behind a guest `_u=1` in the SAME Cookie header "
         f"must still bypass, got {hm.get('x-cache')} -- the scan stopped at "
         "the first name match and served a logged-in page from cache")

    # Member first: worked before the fix too, kept so the pair is symmetric.
    lead = {"Cookie": "phpbb3_bbb_u=42; phpbb3_aaa_u=1"}
    fetch(ng.port, "/phpbb/multi-b", headers=lead)
    _, _, hl = fetch(ng.port, "/phpbb/multi-b", headers=lead)
    assert "x-cache" not in hl, \
        f"member `_u=42` first must bypass, got {hl.get('x-cache')}"

    # Two guests must NOT become a bypass: `continue` means "no opinion", it
    # must not leak into "objection". Without this the fix would trade a leak
    # for a board-wide hit-rate collapse and nothing would catch it.
    guests = {"Cookie": "phpbb3_aaa_u=1; phpbb3_bbb_u=1"}
    fetch(ng.port, "/phpbb/multi-c", headers=guests)
    _, _, hg = fetch(ng.port, "/phpbb/multi-c", headers=guests)
    assert hg.get("x-cache") == "HIT", \
        (f"two guest `_u=1` cookies must stay cacheable, got "
         f"{hg.get('x-cache')} -- 'no opinion' must not become a bypass")


def _assert_new_preset_shape(
    ng: Nginx,
    root: str,
    cookie: str,
    dynamic_uri: str,
) -> None:
    """Pin the shared contract for a newly added preset.

    A plain public URL must still cache; a representative state cookie and a
    representative root-relative dynamic URI must bypass. The URI request is
    made below the test mount so this also covers backend_prefix rebasing.
    """
    public = f"/{root}/public"
    fetch(ng.port, public)
    status, _, hp = fetch(ng.port, public)
    assert status == 200, f"{root} public page returned {status}"
    assert hp.get("x-cache") == "HIT", \
        f"{root} anonymous public page must cache, got {hp.get('x-cache')}"

    member = f"/{root}/state-cookie"
    headers = {"Cookie": cookie}
    fetch(ng.port, member, headers=headers)
    status, _, hc = fetch(ng.port, member, headers=headers)
    assert status == 200, f"{root} cookie request returned {status}"
    assert "x-cache" not in hc, \
        f"{root} state cookie {cookie!r} must bypass, got {hc.get('x-cache')}"

    uri = f"/{root}/{dynamic_uri.lstrip('/')}"
    fetch(ng.port, uri)
    status, _, hu = fetch(ng.port, uri)
    assert status == 200, f"{root} dynamic URI returned {status}"
    assert "x-cache" not in hu, \
        f"{root} dynamic URI {dynamic_uri!r} must bypass, got {hu.get('x-cache')}"


def test_2026_preset_expansion(ng: Nginx, origin: Origin) -> None:
    """Source-audited CMS and issue-tracker presets added in 2026.

    Representative rules cover all nine registry rows and the three aliases.
    Extra assertions pin the suffix predicates, cookieless token auth, and
    current alternate cookie spellings that motivated the individual designs.
    """
    _assert_new_preset_shape(
        ng, "ct-textpattern", "txp_login_public=member", "textpattern/index.php"
    )
    _assert_new_preset_shape(
        ng, "ct-bludit", "__Secure-BLUDIT-KEY=session", "admin/dashboard"
    )
    _assert_new_preset_shape(
        ng, "ct-spip", "CUSTOM_session=member", "ecrire/"
    )
    _assert_new_preset_shape(
        ng, "ct-bugzilla", "Bugzilla_logincookie=member", "editusers.cgi"
    )
    _assert_new_preset_shape(
        ng, "ct-mantis", "ACME_STRING_COOKIE=member", "bug_report_page.php"
    )
    _assert_new_preset_shape(
        ng, "ct-plone", "__ac=member", "@@login"
    )
    _assert_new_preset_shape(
        ng, "ct-umbraco", "__Host-umbAccessToken-siteA=member", "umbraco/"
    )
    _assert_new_preset_shape(
        ng, "ct-dotclear", "dcxd_blog=session", "pagespreview/draft"
    )
    _assert_new_preset_shape(
        ng, "ct-wikijs", "jwt=token", "graphql"
    )
    _assert_new_preset_shape(
        ng, "ct-classicpress", "wordpress_logged_in_hash=member", "wp-admin/"
    )
    _assert_new_preset_shape(
        ng, "ct-backdrop", "SSESSabc=member", "user/login"
    )

    # SPIP's cookie prefix is configurable. Every presentation/state suffix is
    # intentionally prefix-agnostic and non-empty only.
    for i, cookie in enumerate((
        "site_admin=1",
        "site_lang=fr",
        "site_lang_ecrire=fr",
        "site_accepte_ajax=1",
    )):
        uri = f"/ct-spip/predicate-{i}"
        fetch(ng.port, uri, headers={"Cookie": cookie})
        status, _, h = fetch(ng.port, uri, headers={"Cookie": cookie})
        assert status == 200, f"SPIP predicate request returned {status}"
        assert "x-cache" not in h, \
            f"SPIP suffix cookie {cookie!r} must bypass, got {h.get('x-cache')}"

    # Empty suffix cookies are cleared state, not active identity/preferences.
    empty_spip = {"Cookie": "site_session=; site_lang="}
    fetch(ng.port, "/ct-spip/empty", headers=empty_spip)
    status, _, hs = fetch(ng.port, "/ct-spip/empty", headers=empty_spip)
    assert status == 200, f"empty SPIP-cookie request returned {status}"
    assert hs.get("x-cache") == "HIT", \
        f"empty SPIP state cookies must stay cacheable, got {hs.get('x-cache')}"

    # SPIP action/debug modes and Bugzilla query credential spellings can carry
    # dynamic or authenticated state with no cookie at all.
    for uri in (
        "/ct-spip/public?action=logout",
        "/ct-spip/public?var_mode=preview",
        "/ct-bugzilla/show_bug.cgi?id=1&Bugzilla_api_key=secret",
        "/ct-bugzilla/show_bug.cgi?id=1&api_key=secret",
        "/ct-bugzilla/show_bug.cgi?id=1&Bugzilla_api_token=secret",
        "/ct-bugzilla/show_bug.cgi?id=1&Bugzilla_token=secret",
        "/ct-bugzilla/show_bug.cgi?id=1&Bugzilla_login=user",
        "/ct-bugzilla/show_bug.cgi?id=1&token=secret",
        "/ct-bugzilla/rest/bug/1",
    ):
        fetch(ng.port, uri)
        status, _, h = fetch(ng.port, uri)
        assert status == 200, f"cookieless dynamic request returned {status}"
        assert "x-cache" not in h, \
            f"cookieless dynamic request {uri!r} must bypass, got {h.get('x-cache')}"

    # MantisBT's prefix is configurable and its anonymous form-token session is
    # PHPSESSID by default. Project/list/collapse state changes public HTML.
    for i, cookie in enumerate((
        "PROJECTX_PROJECT_COOKIE=7",
        "PROJECTX_VIEW_ALL_COOKIE=recent",
        "PROJECTX_BUG_LIST_COOKIE=filter",
        "PROJECTX_collapse_settings=1",
        "PHPSESSID=anonymous-form-session",
    )):
        uri = f"/ct-mantis/predicate-{i}"
        fetch(ng.port, uri, headers={"Cookie": cookie})
        status, _, h = fetch(ng.port, uri, headers={"Cookie": cookie})
        assert status == 200, f"MantisBT predicate request returned {status}"
        assert "x-cache" not in h, \
            f"MantisBT state cookie {cookie!r} must bypass, got {h.get('x-cache')}"

    # Remaining alternate/default cookie channels.
    for root, cookie in (
        ("ct-textpattern", "txp_login=admin"),
        ("ct-bludit", "BLUDITREMEMBERTOKEN=remembered"),
        ("ct-plone", "I18N_LANGUAGE=nl"),
        ("ct-plone", "_ZopeId=session"),
        ("ct-umbraco", ".AspNetCore.Identity.Application=member"),
        ("ct-umbraco", "UMB_PREVIEW=preview"),
        ("ct-umbraco", "UMB_SESSION=custom-state"),
        ("ct-dotclear", "dc_admin=remembered"),
        ("ct-dotclear", "dc_passwd=protected-post"),
        ("ct-wikijs", "connect.sid=oauth-session"),
        ("ct-wikijs", "loginRedirect=/private-page"),
    ):
        uri = f"/{root}/alternate-{cookie.split('=', 1)[0].replace('.', 'dot')}"
        fetch(ng.port, uri, headers={"Cookie": cookie})
        status, _, h = fetch(ng.port, uri, headers={"Cookie": cookie})
        assert status == 200, f"{root} alternate-cookie request returned {status}"
        assert "x-cache" not in h, \
            f"{root} alternate cookie {cookie!r} must bypass, got {h.get('x-cache')}"

    drain_origin(origin)


def test_internal_redirect_key_and_veto(ng: Nginx, origin: Origin) -> None:
    """Internal redirects replace r->uri -- regression for the 2026-07-26 docs
    audit (DOC-A1 BLOCKER, DOC-A2 MAJOR).

    A PHP front controller runs `try_files $uri /index.php`. Once nginx takes
    that internal redirect, r->uri IS /index.php: the original clean route is
    only still visible in $request_uri. Two consequences, both proven here:

    DOC-A1 -- with the module's DEFAULT $uri-based key, two unrelated clean
    URLs collapse onto the single key /ctir/index.php, so the second request is
    served the FIRST page's body. That is a cross-page hit inside one shared
    cache. This test pins the defect deliberately: it is the reason the
    published examples now say `cache_turbo_key $host$request_uri`. If the
    module default ever becomes original-path-based, the first assertion flips
    to MISS and this test must be revisited along with the docs guidance.

    DOC-A2 -- preset URI rules and cache_turbo_bypass_uri BOTH compare r->uri
    (ngx_http_cache_turbo_bypass_uri_match, module.c:4059), so a route-only
    guard for a private path silently stops matching after the redirect.
    cache_turbo_bypass_uri cannot be the fix -- it reads the same rewritten
    r->uri. The working pattern, which docs/xenforo.md prescribes, is a
    `map $request_uri` feeding cache_turbo_bypass + cache_turbo_no_store.
    XenForo's /api/ is the sharpest case: it authenticates with XF-Api-Key,
    not a preset cookie, so nothing else catches it.

    NEGATIVE CONTROL: the /ctir-fixed/ assertions must FAIL if the key reverts
    to $uri -- distinct routes would share one entry, so the second GET would
    report HIT and replay alpha's body instead of MISSing with its own. The
    origin answers every GET with a unique `gen-<n>` body, so body identity
    across two different routes is positive proof of a shared entry; asserting
    status alone would pass for free whenever both routes rendered alike."""
    # -- DOC-A1: default $uri key collapses distinct routes onto index.php --
    s1, b1, h1 = fetch(ng.port, "/ctir/alpha")
    assert s1 == 200 and h1.get("x-ct-status") == "MISS", \
        f"first clean URL should MISS, got {s1}/{h1.get('x-ct-status')}"

    # A DIFFERENT clean URL, same front controller. Under the $uri key this
    # hits the entry stored for /ctir/alpha.
    _, b2, h2 = fetch(ng.port, "/ctir/beta")
    assert h2.get("x-ct-status") == "HIT", \
        ("DOC-A1 regression: with the default $uri key both clean URLs key on "
         f"/ctir/index.php, so the 2nd route must HIT the 1st entry, got "
         f"{h2.get('x-ct-status')} -- if this now MISSes the module default key "
         "changed and the docs guidance must be revisited")
    assert b2 == b1, \
        ("DOC-A1 regression: /ctir/beta must be served ALPHA's cached body "
         f"under the $uri key, got {b2!r} vs {b1!r}")

    # -- DOC-A1 fixed: $request_uri keeps the routes distinct ---------------
    _, bf1, hf1 = fetch(ng.port, "/ctir-fixed/alpha")
    assert hf1.get("x-ct-status") == "MISS", \
        f"first fixed route should MISS, got {hf1.get('x-ct-status')}"

    _, bf2, hf2 = fetch(ng.port, "/ctir-fixed/beta")
    # THE discriminating assertion: MISS, not HIT. A revert to $uri makes this
    # a HIT replaying alpha's body -- exactly the defect being guarded.
    assert hf2.get("x-ct-status") == "MISS", \
        ("$host$request_uri must keep distinct clean URLs on distinct keys "
         f"across the internal redirect, got {hf2.get('x-ct-status')}")
    assert bf2 != bf1, \
        ("/ctir-fixed/beta must get its OWN origin body, not alpha's cached "
         f"one, got {bf2!r} == {bf1!r}")

    # Each fixed route caches independently on its own second request.
    _, ba, ha = fetch(ng.port, "/ctir-fixed/alpha")
    assert ha.get("x-ct-status") == "HIT" and ba == bf1, \
        f"fixed alpha should HIT its own entry, got {ha.get('x-ct-status')}/{ba!r}"

    # -- DOC-A2: route veto must survive the internal redirect --------------
    _, bp1, hp1 = fetch(ng.port, "/ctir-fixed/api/me")
    assert hp1.get("x-ct-status") == "BYPASS", \
        ("DOC-A2: the private /api/ route must BYPASS even though the internal "
         f"redirect rewrote r->uri to the front controller, got "
         f"{hp1.get('x-ct-status')}")

    # ... and must never have been STORED, not merely skipped on lookup: a
    # fresh origin body on every request is what proves nothing was cached.
    _, bp2, hp2 = fetch(ng.port, "/ctir-fixed/api/me")
    assert hp2.get("x-ct-status") == "BYPASS", \
        f"private route must BYPASS on every request, got {hp2.get('x-ct-status')}"
    assert bp2 != bp1, \
        ("private route must come from origin each time -- an identical body "
         f"means it was stored and replayed, got {bp2!r}")


def test_bypass_uri_inert_after_internal_redirect(ng: Nginx,
                                                  origin: Origin) -> None:
    """AUD-DOC1: cache_turbo_bypass_uri matches r->uri, so it stops guarding a
    route the moment a front controller rewrites r->uri -- the same blind spot
    DOC-A2 pins for the preset URI tier, on the tier operators are told to use
    for private paths.

    This asserts the CURRENT, intended behaviour rather than a defect: the
    matcher deliberately reads r->uri, and rebasing it onto $request_uri would
    change what every existing config matches. The value of the test is that
    the behaviour is now written down in two places that must agree -- here and
    in the directive's documentation -- so a later change to either is caught.

    /ctir-bu/ is guarded ONLY by cache_turbo_bypass_uri /ctir-bu/api/. If the
    directive fired, the route would BYPASS and every request would come from
    origin. It does not fire, so the second request is a HIT replaying the
    first response: a private page served from a shared cache, which is exactly
    why the docs now say a route-only guard is not enough behind a front
    controller."""
    s1, b1, h1 = fetch(ng.port, "/ctir-bu/api/me")
    assert s1 == 200, f"front-controller route did not answer 200: {s1}"
    assert h1.get("x-ct-status") != "BYPASS", \
        ("cache_turbo_bypass_uri matched a URI the internal redirect had "
         "already rewritten -- if this now BYPASSes, the matcher was changed "
         "to read the original path and docs/README.md plus the README "
         f"synopsis row must be updated with it (got {h1.get('x-ct-status')})")

    _, b2, h2 = fetch(ng.port, "/ctir-bu/api/me")
    assert h2.get("x-ct-status") == "HIT" and b2 == b1, \
        ("the unguarded private route must be cached and replayed -- that is "
         f"the documented blind spot (got {h2.get('x-ct-status')}, "
         f"{b2!r} vs {b1!r})")

    # Control: the directive is wired up and does work on a URI the redirect
    # leaves alone. Without this the assertions above pass just as well for a
    # cache_turbo_bypass_uri that is broken outright or spelled wrong.
    _, _, hc1 = fetch(ng.port, "/bu/panel")
    assert hc1.get("x-ct-status") == "BYPASS", \
        ("cache_turbo_bypass_uri does not match even without a redirect, so "
         f"the test above proves nothing: got {hc1.get('x-ct-status')}")


def test_ctx_survives_error_page_internal_redirect(ng: Nginx,
                                                   origin: Origin) -> None:
    """CTXRDR: an error_page internal redirect memzeros r->ctx MID-REQUEST,
    after the access handler has already built one. The module must treat the
    second pass as a fresh request and must not strand the first ctx's
    registered teardown.

    Why this shape and not the /ctir* ones: try_files redirects in the REWRITE
    phase, i.e. BEFORE the PRECONTENT access handler ever runs, so those tests
    only ever exercise a single ctx built on the post-redirect URI. error_page
    redirects off the ORIGIN's 404 -- after the access handler built ctx and
    after the header filter ran. ngx_http_internal_redirect() then does an
    unconditional `ngx_memzero(r->ctx, ...)` (ngx_http_core_module.c:2614). The
    one-module-preserving variant in special_response.c:547 is the
    filter_finalize path and does NOT apply here.

    What that makes safe, and what this pins:

    1. r->pool is NOT reset by the redirect, so the first ctx's pool cleanups
       (cold_cleanup's stub unstub, blob_cleanup's shm reference drop) and its
       EMBEDDED cold_wait_ev timer stay registered against memory that is still
       allocated. They key off the ctx pointer captured in cln->data, never off
       r->ctx, so dropping r->ctx cannot orphan them -- the cleanups still run
       at pool destroy and still see the right ctx.
    2. The second pass re-enters the access handler, finds r->ctx NULL, and
       pcallocs a FRESH ctx (module.c:4515). No state leaks across the two
       passes: the fallback must report its own outcome, not the 404 pass's.

    The variable getters read r->ctx directly, which is what makes pass 2's ctx
    observable from the wire at all."""
    # Pass 1 404s at the origin -> error_page -> internal redirect -> pass 2
    # serves the fallback. The client sees the fallback body under the 404's
    # status-code-preserving redirect.
    # THE oracle for "did pass 2 park?". Timing alone cannot carry this test:
    # `elapsed < 2.0` goes vacuous the moment cache_turbo_lock_timeout is
    # configured below 2s, and it is a proxy for the symptom rather than the
    # mechanism. lock_waits is bumped once per request that actually ENTERS
    # cold_wait(), which is precisely the thing CTXRDR must prevent, so an exact
    # "did not move" is both stronger and immune to a slow runner.
    waits0 = _admin_lock_waits(ng)

    t0 = time.monotonic()
    s1, b1, _ = fetch(ng.port, "/ctxrdr/ctxrdr-missing")
    elapsed1 = time.monotonic() - t0
    assert s1 == 200, \
        (f"error_page did not take the internal redirect (got {s1}); the "
         "fixture, not the module, is wrong -- the rest of this test would be "
         "vacuous")
    assert b1, "fallback served an empty body"

    # CTXRDR, the defect this test was written for. $request_uri does not change
    # across an internal redirect, so BOTH passes hash to the same key. Pass 1
    # won the cold-miss claim and planted a stub; the redirect then memzeroed
    # r->ctx, so pass 2's fresh ctx has cold_winner = 0 and used to read that
    # stub as another request's in-flight fill -- parking in cold_wait() for the
    # FULL cache_turbo_lock_timeout (5s by default) before giving up and
    # re-winning. It answered correctly, so only the clock showed it.
    #
    # None of the three header/body-filter unstub sites can prevent that: an
    # intercepted upstream error is finalized inside
    # ngx_http_upstream_intercept_errors() without traversing the output filter
    # chain, leaving only the pool cleanup, which runs at teardown -- long after
    # pass 2 has parked. The fix is _cold_adopt_own_stub(): on CLAIM_LOSER the
    # request looks for a stub an earlier ctx of ITSELF still owns and adopts it.
    #
    # Timing is the assertion because latency IS the symptom. The threshold is
    # far below the 5s timeout and far above a normal redirect (measured ~8ms),
    # so it cannot flake into passing on a slow runner the way a tight bound
    # would.
    # THE assertion. Not one request may enter cold_wait(): pass 2 adopting its
    # own stub is exactly the difference between "went straight to origin" and
    # "parked on itself for the full lock_timeout".
    assert _admin_lock_waits(ng) - waits0 == 0, \
        (f"lock_waits moved by {_admin_lock_waits(ng) - waits0}: the "
         "post-redirect pass PARKED on the cold-miss stub its OWN first pass "
         "planted. _cold_adopt_own_stub() should have adopted it on "
         "CLAIM_LOSER instead")

    # Timing is kept as a loose diagnostic only -- it is the client-visible
    # symptom and makes a failure obvious, but lock_waits above is what proves
    # the mechanism. Threshold far below the 5s timeout and far above a normal
    # redirect (~8ms) so it cannot flake on a slow runner.
    assert elapsed1 < 2.0, \
        (f"the post-redirect pass took {elapsed1:.2f}s: it parked on the "
         "cold-miss stub its OWN first pass planted and waited out "
         "cache_turbo_lock_timeout. _cold_adopt_own_stub() should have adopted "
         "it on CLAIM_LOSER instead")

    # One origin contact for the FALLBACK body, not two: adoption must make the
    # second pass the WINNER that goes to origin, not a waiter that eventually
    # times out and then also goes to origin.
    #
    # ⚠ Counted on the fallback's own upstream marker. The obvious spelling --
    # hits_for("ctxrdr-missing") -- observes only pass 1's 404, because the
    # fallback location proxies as /ctxrdr-fb-page; it would read 1 no matter
    # what the fallback leg did.
    assert origin.hits_for("ctxrdr-fb-") == 1, \
        ("the fallback leg hit the origin "
         f"{origin.hits_for('ctxrdr-fb-')} times, expected exactly 1")

    # The post-memzero ctx must have STORED, not merely answered. Note the key
    # is $host$request_uri and $request_uri is NOT rewritten by the redirect, so
    # the entry lands under the ORIGINAL /ctxrdr/ctxrdr-missing key -- repeating
    # that same request is what reads it back, not a direct fetch of the
    # rewritten /ctxrdr-fallback/page URI (a different key entirely).
    t1 = time.monotonic()
    s2, b2, h2 = fetch(ng.port, "/ctxrdr/ctxrdr-missing")
    elapsed2 = time.monotonic() - t1
    assert s2 == 200, f"second redirecting request failed: {s2}"
    assert h2.get("x-ct-status") == "HIT" and b2 == b1, \
        ("the ctx rebuilt after the r->ctx memzero did not store, so the "
         "adopted stub never became a real entry (got "
         f"{h2.get('x-ct-status')}, {b2!r} vs {b1!r})")
    assert h2.get("x-ct-reason") == "FRESH", \
        ("$cache_turbo_serve_reason reads r->ctx; a HIT must report FRESH, got "
         f"{h2.get('x-ct-reason')!r}")
    assert elapsed2 < 2.0, \
        f"the cached redirecting request took {elapsed2:.2f}s"

    # Serving that HIT cost no further origin work: still exactly one contact.
    assert origin.hits_for("ctxrdr-fb-") == 1, \
        ("the HIT went to the origin anyway: "
         f"{origin.hits_for('ctxrdr-fb-')} contacts, expected 1")

    # Negative control. The assertions above are only meaningful if the
    # variables are genuinely sourced from a per-request ctx that this fixture
    # can move. A location with no cache-turbo ctx at all must report "-": if
    # this returned MISS/HIT the getters would be answering from something
    # other than r->ctx and every assertion above would be reading a constant.
    _, _, hc = fetch(ng.port, "/ctxrdr-off/page")
    assert hc.get("x-ct-status") in (None, "-"), \
        ("$cache_turbo_status reports a value on a location where the module "
         f"never engaged, so it is not reading r->ctx: got "
         f"{hc.get('x-ct-status')!r}")
    # Both variables, not just the status one. The HIT above asserts
    # x-ct-reason == "FRESH", so $cache_turbo_serve_reason carries real weight
    # here; a getter answering a constant for the reason would sail through
    # every assertion in this test if only the status arm were controlled.
    assert hc.get("x-ct-reason") in (None, "-"), \
        ("$cache_turbo_serve_reason reports a value on a location where the "
         f"module never engaged, so it is not reading r->ctx: got "
         f"{hc.get('x-ct-reason')!r}")


def test_auto_classify_more(ng: Nginx, origin: Origin) -> None:
    """Auto-classify breadth: the search query arg (?s=), the comment_author_
    cookie, the joomla /administrator/ URI prefix, and a two-backend stack
    (wordpress woocommerce) where BOTH cookie families skip."""
    # ?s= search -> does NOT skip. This assertion is INVERTED: `s` was a
    # bare-name row in ct_wp_args and every site search bypassed. It bought no
    # safety (a logged-out visitor's results are anonymous-identical; a
    # logged-in editor is bypassed by wordpress_logged_in_ on the cookie tier)
    # and it removed miss-collapsing from the most expensive query WordPress
    # runs. Full coverage is in ci/t/presets/wordpress.t (TEST 8-9), which uses
    # a location whose key carries the query string; /auto/ keys on $uri alone,
    # so all that can be asserted here is that ?s= no longer classifies as
    # dynamic.
    fetch(ng.port, "/auto/results-s?s=widgets")
    _, _, hs2 = fetch(ng.port, "/auto/results-s?s=widgets")
    assert hs2.get("x-cache") == "HIT", \
        (f"?s= must no longer classify as dynamic, got {hs2.get('x-cache')}")

    # comment_author_ cookie -> skip
    cc = {"Cookie": "comment_author_email_x=foo%40bar"}
    _, _, hc1 = fetch(ng.port, "/auto/comment", headers=cc)
    _, _, hc2 = fetch(ng.port, "/auto/comment", headers=cc)
    assert "x-cache" not in hc1 and "x-cache" not in hc2, \
        "comment_author_ cookie must skip"

    # joomla /administrator/ URI prefix -> skip
    _, _, ha1 = fetch(ng.port, "/administrator/index.php")
    _, _, ha2 = fetch(ng.port, "/administrator/index.php")
    assert "x-cache" not in ha1 and "x-cache" not in ha2, \
        "/administrator/ must skip"

    # two backends stacked: a WP cookie AND a Woo cookie both skip on /multi/
    _, _, hm1 = fetch(ng.port, "/multi/a",
                      headers={"Cookie": "wordpress_logged_in_z=1"})
    assert "x-cache" not in hm1, "stacked WP cookie must skip on /multi/"
    _, _, hm2 = fetch(ng.port, "/multi/b",
                      headers={"Cookie": "woocommerce_cart_hash=z"})
    assert "x-cache" not in hm2, "stacked Woo cookie must skip on /multi/"
    # a plain anon page on the stacked location still caches
    fetch(ng.port, "/multi/plain")
    _, _, hm3 = fetch(ng.port, "/multi/plain")
    assert hm3.get("x-cache") == "HIT", \
        f"anon page on /multi/ should cache, got {hm3.get('x-cache')}"
    drain_origin(origin)


def test_q2_multibuffer_oversize(ng: Nginx, origin: Origin) -> None:
    """Q2: a ~200 KB response (streamed in several buffers) over a 1k max_size
    must early-abort capture mid-stream — never cached, body intact, no error,
    across repeats (the abort path runs each time)."""
    first = None
    for _ in range(3):
        s, b, h = fetch(ng.port, "/qbig/bigbody-media")
        assert s == 200, f"oversize multibuffer served {s}, expected 200"
        assert len(b) > 100000, f"body truncated: {len(b)} bytes"
        assert "x-cache" not in h, "multibuffer oversize must not be cached"
        if first is not None:
            assert b != first, "served a cached copy of an oversize body"
        first = b
    drain_origin(origin)


def test_suppress_native_inert_on_plain_location(ng: Nginx) -> None:
    """Q1: $cache_turbo_active is "0" on a location with no cache_turbo (no ctx
    / disabled) — the variable's defensive default, so wiring it into an
    unrelated location can never accidentally read 1."""
    _, _, h = fetch(ng.port, "/plain/x")
    assert h.get("x-ct-active") == "0", \
        f"plain location: expected X-CT-Active=0, got {h.get('x-ct-active')}"


def test_suppress_native_e2e_proxy_cache(ng: Nginx) -> None:
    """Q1 end-to-end: with cache_turbo_suppress_native on plus the documented
    proxy_no_cache/proxy_cache_bypass wiring, a stacked proxy_cache never writes
    (its on-disk cache dir stays empty). With suppress off the identical wiring
    is inert ($cache_turbo_active=0) and proxy_cache stores as usual. Proves the
    variable gates native caching for real, not just as a header value."""
    import os

    # proxy_cache writes go through nginx's cache-manager process, which is not
    # spawned under `master_process off`; the multi-process Runtime job covers
    # this end-to-end. Skip in single-process mode (the ASan run uses it).
    #
    # Also skip under sanitizers (CI-3 multi-worker ASan/UBSan smoke): this is the
    # only test that drives nginx's CORE proxy_cache file-WRITE path, and that path
    # trips a known nginx-core UBSan false positive
    # (src/http/ngx_http_file_cache.c: "null pointer passed as argument 2" — a
    # zero-length ngx_memcpy with a NULL src, harmless, same class as the OpenSSL
    # ASan baseline noise). It is nginx-core code, not cache-turbo; the plain
    # multi-worker Runtime job still exercises it fully without sanitizers.
    if ng.single_process or ng.sanitizer:
        return

    def file_count(d: pathlib.Path) -> int:
        return sum(len(files) for _, _, files in os.walk(d))

    on_dir = ng.root / "pcache_on"
    off_dir = ng.root / "pcache_off"

    # suppress ON: cache-turbo owns it; proxy_cache must stay empty.
    fetch(ng.port, "/supcache/a")
    fetch(ng.port, "/supcache/b")
    time.sleep(0.4)                       # let the cache manager settle
    n_on = file_count(on_dir)
    assert n_on == 0, \
        f"suppress on: proxy_cache wrote {n_on} files, expected 0 (native not suppressed)"

    # suppress OFF (control): the same wiring is inert, proxy_cache stores.
    fetch(ng.port, "/nosupcache/a")
    fetch(ng.port, "/nosupcache/b")
    time.sleep(0.4)
    n_off = file_count(off_dir)
    assert n_off > 0, \
        "suppress off: proxy_cache should have stored (wiring inert), but dir is empty"


def test_invalid_backend_name(ng: Nginx) -> None:
    """An unknown cache_turbo_backend value is rejected at config time."""
    bad = ng.root.parent / "bad-backend"
    (bad / "conf").mkdir(parents=True, exist_ok=True)
    (bad / "logs").mkdir(parents=True, exist_ok=True)
    cfg = nginx_config(bad, ng.port, ng.module, ng.origin_port, 1)
    cfg = cfg.replace("cache_turbo_backend woocommerce;",
                      "cache_turbo_backend bogus;")
    (bad / "conf" / "nginx.conf").write_text(cfg, encoding="ascii")
    cmd = ng.runner + [str(ng.binary), "-p", str(bad),
                       "-c", str(bad / "conf" / "nginx.conf"), "-t"]
    r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=20)
    assert r.returncode != 0, \
        f"invalid backend 'bogus' was accepted by nginx -t:\n{r.stdout}"
    assert "unknown cache_turbo_backend" in r.stdout, \
        f"missing/odd diagnostic for bad backend:\n{r.stdout}"


def _config_rejects(ng: Nginx, tag: str, old: str, new: str, want: str) -> None:
    """Swap `old`->`new` in the generated config and assert nginx -t FAILS with
    `want` in the diagnostic. Used for the removal tests below, where a silent
    accept is the failure mode we actually fear."""
    bad = ng.root.parent / tag
    (bad / "conf").mkdir(parents=True, exist_ok=True)
    (bad / "logs").mkdir(parents=True, exist_ok=True)
    cfg = nginx_config(bad, ng.port, ng.module, ng.origin_port, 1)
    assert old in cfg, f"{tag}: pattern to replace not found in config: {old!r}"
    cfg = cfg.replace(old, new, 1)
    (bad / "conf" / "nginx.conf").write_text(cfg, encoding="ascii")
    cmd = ng.runner + [str(ng.binary), "-p", str(bad),
                       "-c", str(bad / "conf" / "nginx.conf"), "-t"]
    r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=20)
    assert r.returncode != 0, \
        f"{tag}: config was ACCEPTED by nginx -t but must be rejected:\n{r.stdout}"
    assert want in r.stdout, \
        f"{tag}: missing/odd diagnostic (want {want!r}):\n{r.stdout}"


def test_invalid_cache_turbo_mode(ng: Nginx) -> None:
    """cache_turbo takes a zone name and nothing else. Any 2nd token is rejected
    (the `auto` shorthand is gone -- see test_auto_and_generic_are_removed)."""
    _config_rejects(ng, "bad-mode",
                    "cache_turbo         main;\n            cache_turbo_backend wordpress;",
                    "cache_turbo         main bogusmode;",
                    "invalid cache_turbo mode")


def test_auto_and_generic_are_removed(ng: Nginx) -> None:
    """The `generic`/`auto` preset union was removed because it was never a safe
    default: it never covered every backend, `woocommerce` in it left /wp-admin/
    cacheable unless stacked with `wordpress`, and `joomla` in it then shipped
    no cookie rule at all.

    All three dead spellings must be a HARD CONFIG ERROR, not a silent no-op.
    That distinction is the entire point: accepting the name and enabling nothing
    would leave an existing WordPress config with no preset active and quietly
    start caching /wp-admin/. nginx must refuse to start so the operator looks."""
    # cache_turbo_backend generic;
    _config_rejects(ng, "dead-generic", _BACKEND_LINE,
                    "cache_turbo_backend generic;", "has been removed")
    # cache_turbo_backend auto;
    _config_rejects(ng, "dead-backend-auto", _BACKEND_LINE,
                    "cache_turbo_backend auto;", "has been removed")
    # cache_turbo <zone> auto;  -- the old shorthand
    _config_rejects(ng, "dead-shorthand-auto",
                    "cache_turbo         main;\n            cache_turbo_backend wordpress;",
                    "cache_turbo         main auto;",
                    "no longer supported")


def _config_accepts(ng: Nginx, tag: str, old: str, new: str) -> None:
    """Swap `old`->`new` and assert nginx -t ACCEPTS the result."""
    good = ng.root.parent / tag
    (good / "conf").mkdir(parents=True, exist_ok=True)
    (good / "logs").mkdir(parents=True, exist_ok=True)
    cfg = nginx_config(good, ng.port, ng.module, ng.origin_port, 1)
    assert old in cfg, f"{tag}: pattern to replace not found: {old!r}"
    cfg = cfg.replace(old, new, 1)
    (good / "conf" / "nginx.conf").write_text(cfg, encoding="ascii")
    cmd = ng.runner + [str(ng.binary), "-p", str(good),
                       "-c", str(good / "conf" / "nginx.conf"), "-t"]
    r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=20)
    assert r.returncode == 0, \
        f"{tag}: config was REJECTED by nginx -t but must be accepted:\n{r.stdout}"


def _config_warns(ng: Nginx, tag: str, old: str, new: str, want: str) -> None:
    """Swap `old`->`new` and assert nginx -t both ACCEPTS the config (exit 0)
    AND prints `want` on stdout. For warn-not-reject checks (O4.4-d): a config
    that loads successfully today must keep loading, but the operator still
    needs to see the diagnostic."""
    warn = ng.root.parent / tag
    (warn / "conf").mkdir(parents=True, exist_ok=True)
    (warn / "logs").mkdir(parents=True, exist_ok=True)
    cfg = nginx_config(warn, ng.port, ng.module, ng.origin_port, 1)
    assert old in cfg, f"{tag}: pattern to replace not found: {old!r}"
    cfg = cfg.replace(old, new, 1)
    (warn / "conf" / "nginx.conf").write_text(cfg, encoding="ascii")
    cmd = ng.runner + [str(ng.binary), "-p", str(warn),
                       "-c", str(warn / "conf" / "nginx.conf"), "-t"]
    r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=20)
    assert r.returncode == 0, \
        f"{tag}: config was REJECTED by nginx -t but must still load:\n{r.stdout}"
    assert want in r.stdout, \
        f"{tag}: missing/odd diagnostic (want {want!r}):\n{r.stdout}"


def test_breaker_policy_divergence_warns(ng: Nginx) -> None:
    """O4.4-d: breaker STATE/counters are per-ZONE but the five breaker
    directives are per-LOCATION. Two sibling locations sharing one zone
    (`brkpolz`) with divergent EFFECTIVE breaker tuples (open=30s vs open=5m)
    must load successfully (WARN, not reject -- a hard reject would break
    configs that work today) and must print the divergence diagnostic added
    at merge_loc_conf just after the shm_zone inheritance block."""
    _config_warns(ng, "breaker-policy-diverge",
        "        location /forever/ {\n"
        "            cache_turbo          main;\n"
        "            cache_turbo_key      $uri;\n"
        "            cache_turbo_valid    0;\n"
        "            proxy_pass http://127.0.0.1:{origin_port}/;\n"
        "        }\n".replace("{origin_port}", str(ng.origin_port)),
        "        location /forever/ {\n"
        "            cache_turbo          main;\n"
        "            cache_turbo_key      $uri;\n"
        "            cache_turbo_valid    0;\n"
        "            proxy_pass http://127.0.0.1:%d/;\n"
        "        }\n"
        "\n"
        "        location /brkpolicy1/ {\n"
        "            cache_turbo                   brkpolz;\n"
        "            cache_turbo_key                $uri;\n"
        "            cache_turbo_valid              30s;\n"
        "            cache_turbo_breaker            on;\n"
        "            cache_turbo_breaker_threshold  3;\n"
        "            cache_turbo_breaker_window     10s;\n"
        "            cache_turbo_breaker_open       30s;\n"
        "            proxy_pass http://127.0.0.1:%d/;\n"
        "        }\n"
        "\n"
        "        location /brkpolicy2/ {\n"
        "            cache_turbo                   brkpolz;\n"
        "            cache_turbo_key                $uri;\n"
        "            cache_turbo_valid              30s;\n"
        "            cache_turbo_breaker            on;\n"
        "            cache_turbo_breaker_threshold  3;\n"
        "            cache_turbo_breaker_window     10s;\n"
        "            cache_turbo_breaker_open       5m;\n"
        "            proxy_pass http://127.0.0.1:%d/;\n"
        "        }\n"
        % (ng.origin_port, ng.origin_port, ng.origin_port),
        "circuit breaker")


def test_breaker_policy_identical_no_warning(ng: Nginx) -> None:
    """NEGATIVE CONTROL (a): two siblings on the same zone with an IDENTICAL
    effective breaker tuple must produce NO warning -- the divergence check
    must not fire unconditionally. See test_breaker_policy_divergence_warns
    for the positive arm; the always-true-mutation falsification (b) is
    manual (documented in the O4.4-d ledger), since it requires rebuilding
    the module with a deliberately broken comparison."""
    good = ng.root.parent / "breaker-policy-identical"
    (good / "conf").mkdir(parents=True, exist_ok=True)
    (good / "logs").mkdir(parents=True, exist_ok=True)
    cfg = nginx_config(good, ng.port, ng.module, ng.origin_port, 1)
    old = ("        location /forever/ {\n"
           "            cache_turbo          main;\n"
           "            cache_turbo_key      $uri;\n"
           "            cache_turbo_valid    0;\n"
           "            proxy_pass http://127.0.0.1:%d/;\n"
           "        }\n") % ng.origin_port
    assert old in cfg, "pattern to replace not found"
    new = (old +
        "\n"
        "        location /brkpolicy1/ {\n"
        "            cache_turbo                   brkpolz;\n"
        "            cache_turbo_key                $uri;\n"
        "            cache_turbo_valid              30s;\n"
        "            cache_turbo_breaker            on;\n"
        "            cache_turbo_breaker_threshold  3;\n"
        "            cache_turbo_breaker_window     10s;\n"
        "            cache_turbo_breaker_open       30s;\n"
        "            proxy_pass http://127.0.0.1:%d/;\n"
        "        }\n"
        "\n"
        "        location /brkpolicy2/ {\n"
        "            cache_turbo                   brkpolz;\n"
        "            cache_turbo_key                $uri;\n"
        "            cache_turbo_valid              30s;\n"
        "            cache_turbo_breaker            on;\n"
        "            cache_turbo_breaker_threshold  3;\n"
        "            cache_turbo_breaker_window     10s;\n"
        "            cache_turbo_breaker_open       30s;\n"
        "            proxy_pass http://127.0.0.1:%d/;\n"
        "        }\n"
        % (ng.origin_port, ng.origin_port))
    cfg = cfg.replace(old, new, 1)
    (good / "conf" / "nginx.conf").write_text(cfg, encoding="ascii")
    cmd = ng.runner + [str(ng.binary), "-p", str(good),
                       "-c", str(good / "conf" / "nginx.conf"), "-t"]
    r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=20)
    assert r.returncode == 0, \
        f"identical breaker tuples: config was REJECTED:\n{r.stdout}"
    assert "circuit breaker" not in r.stdout, \
        f"identical breaker tuples must NOT warn, but got:\n{r.stdout}"


def test_breaker_directives_accepted(ng: Nginx) -> None:
    """O4.4: the four breaker directives parse. Each is appended standalone
    after the zone's cache_turbo_valid line (present verbatim in every
    generated config) so the test does not depend on any one location block's
    exact directive set."""
    _config_accepts(ng, "breaker-flag-on",
                    "cache_turbo_valid    0;",
                    "cache_turbo_valid    0;\n"
                    "            cache_turbo_breaker on;")
    _config_accepts(ng, "breaker-flag-off",
                    "cache_turbo_valid    0;",
                    "cache_turbo_valid    0;\n"
                    "            cache_turbo_breaker off;")
    _config_accepts(ng, "breaker-threshold",
                    "cache_turbo_valid    0;",
                    "cache_turbo_valid    0;\n"
                    "            cache_turbo_breaker_threshold 5;")
    _config_accepts(ng, "breaker-window",
                    "cache_turbo_valid    0;",
                    "cache_turbo_valid    0;\n"
                    "            cache_turbo_breaker_window 30s;")
    _config_accepts(ng, "breaker-open-nonzero",
                    "cache_turbo_valid    0;",
                    "cache_turbo_valid    0;\n"
                    "            cache_turbo_breaker_open 15s;")
    _config_accepts(ng, "breaker-retry-after",
                    "cache_turbo_valid    0;",
                    "cache_turbo_valid    0;\n"
                    "            cache_turbo_breaker_retry_after 20s;")


def test_breaker_open_zero_rejected(ng: Nginx) -> None:
    """O4.3-a / O4.4 regression pin: `cache_turbo_breaker_open 0` MUST be a
    hard config error, not accepted as a disable. Every sibling breaker field
    treats 0 as inert/off; this one is the exception because
    ngx_http_cache_turbo_shm_breaker_state()'s timed reopen is guarded on
    `open_for > 0` -- with 0 an OPEN breaker would never promote a probe, and
    with no origin contact while OPEN, no success could ever close it either.
    The breaker would wedge OPEN until reload. See memory issues.md O4.3-a."""
    _config_rejects(ng, "breaker-open-zero",
                    "cache_turbo_valid    0;",
                    "cache_turbo_valid    0;\n"
                    "            cache_turbo_breaker_open 0;",
                    "must be greater than 0")


def test_breaker_arming_gated_on_breaker_enable(ng: Nginx, origin: Origin) -> None:
    """O4.4 wiring pin: cache_turbo_breaker off must be a genuine, independent
    off-switch black-box-observable end to end (arming call site through the
    pre-origin gate) -- a dead origin behind a disabled breaker must never be
    answered from a stale snapshot.

    ⚠ This end-to-end shape cannot isolate WHICH of the two should_consult()
    call sites (arming vs. the pre-origin gate) is doing the gating: the
    pre-origin gate alone already blocks BRK_ACT_SERVE when breaker_enable is
    off, regardless of whether arming itself is correctly gated -- verified by
    injecting a bare `breaker_threshold > 0` at the arming site alone (dropping
    should_consult() there) and observing this test still passes. Isolating
    the arming site specifically needs a white-box check (e.g. a debug counter
    or log line asserting brk_armed stayed 0), not a black-box HTTP fetch
    through both sites.

    /breakeron/ and /breakeroff/ are identical apart from the flag itself.

    threshold=1 means one failing response trips CLOSED -> OPEN, but that
    trip is recorded by the header filter AFTER the response is already
    built, so the failing request that does the tripping still gets the raw
    origin error itself; only the NEXT request finds the breaker OPEN at the
    pre-origin gate and can be served the fallback. Hence two dead-origin
    fetches per location below: the first trips (and is asserted to reach
    the dead origin, i.e. NOT 200), the second observes the tripped state."""
    for path in ("/breakeron/dead", "/breakeroff/dead"):
        s0, b0, _ = fetch(ng.port, path)
        assert s0 == 200, f"prime failed for {path}: {s0}"
        assert b0, f"prime returned an empty body for {path}"

    time.sleep(4.3)   # past fresh (1s) AND the x4 stale window (4s): L1-expired
    origin.fail = True
    try:
        s_trip, _, _ = fetch(ng.port, "/breakeron/dead")
        assert s_trip != 200, \
            (f"breaker ON: the tripping request itself was answered 200 -- "
             f"expected it to reach the (dead) origin and fail, got {s_trip}")

        s_on, _b_on, _ = fetch(ng.port, "/breakeron/dead")
        assert s_on == 200, \
            (f"breaker ON: expired entry + dead origin did not fall back to "
             f"the breaker's any-age snapshot after tripping, got {s_on}")

        s_off_trip, _, _ = fetch(ng.port, "/breakeroff/dead")
        assert s_off_trip != 200, \
            f"breaker OFF: tripping request unexpectedly 200: {s_off_trip}"

        s_off, _, _ = fetch(ng.port, "/breakeroff/dead")
        assert s_off != 200, \
            ("breaker OFF: a dead origin was still answered 200 from a stale "
             "snapshot -- cache_turbo_breaker off did not disable arming at "
             "the L1-expired call site")
    finally:
        origin.fail = False
        drain_origin(origin)


def test_breaker_counters(ng: Nginx, origin: Origin) -> None:
    """S7.1: breaker_serves counts responses actually delivered from the
    breaker's armed fallback (STALE-BREAKER), and origin_failures counts
    origin responses recorded as a failure by the breaker -- not every
    request through a breaker-enabled location.

    Same two-fetch trip sequence as test_breaker_arming_gated_on_breaker_enable
    (threshold=1, so the FIRST dead-origin request trips CLOSED->OPEN and
    still surfaces the raw origin failure itself; the SECOND finds the
    breaker OPEN and is served the fallback), but on the private s71z zone
    with its own admin endpoint so the deltas cannot be polluted by
    /breakeron/ or /brkion/, which have already tripped their own breakers by
    the time this runs in run_all()'s ordering.

    origin_failures must move on the FIRST (tripping) fetch -- that is the
    request whose 5xx status actually reaches ngx_http_cache_turbo_breaker_is_
    origin_failure() and feeds _breaker_record(). breaker_serves must NOT
    move on that fetch (nothing is armed/served from the breaker yet -- the
    origin's own error passes through) and MUST move on the second."""
    s0, b0, _ = fetch(ng.port, "/s71brk/dead")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    time.sleep(4.3)   # past fresh (1s) AND the x4 stale window (4s): L1-expired
    origin.fail = True
    try:
        of_before = _admin_stat(ng, "origin_failures", "/_cache_s71")
        bs_before = _admin_stat(ng, "breaker_serves", "/_cache_s71")

        s_trip, _, _ = fetch(ng.port, "/s71brk/dead")
        assert s_trip != 200, \
            (f"tripping request was answered 200 -- expected it to reach "
             f"the dead origin and fail, got {s_trip}")

        of_trip = _admin_stat(ng, "origin_failures", "/_cache_s71")
        bs_trip = _admin_stat(ng, "breaker_serves", "/_cache_s71")
        assert of_trip - of_before > 0, \
            "origin_failures did not move on the origin failure that tripped the breaker"
        assert bs_trip == bs_before, \
            (f"breaker_serves moved on the TRIPPING request, which surfaces "
             f"the raw origin error and serves nothing from the breaker -- "
             f"{bs_before} -> {bs_trip}")

        s_on, _, _ = fetch(ng.port, "/s71brk/dead")
        assert s_on == 200, \
            f"breaker OPEN did not fall back to the any-age snapshot, got {s_on}"

        bs_after = _admin_stat(ng, "breaker_serves", "/_cache_s71")
        assert bs_after - bs_trip > 0, \
            "breaker_serves did not move on the STALE-BREAKER fallback serve"
    finally:
        origin.fail = False
        drain_origin(origin)


def test_breaker_retry_after_auto_tracks_breaker_open(ng: Nginx, origin: Origin) -> None:
    """BRK-RA1 regression pin: cache_turbo_breaker_retry_after, left unset,
    must track the EFFECTIVE cache_turbo_breaker_open for that location, not
    the module-wide 30s default.

    The bug: ngx_conf_merge_sec_value(conf->breaker_retry_after,
    prev->breaker_retry_after, conf->breaker_open) only falls back to
    conf->breaker_open when prev->breaker_retry_after is itself UNSET. nginx
    merges the enclosing server{} loc_conf against http FIRST, before any
    location merge. Nothing in this config sets breaker_retry_after at
    server scope, so that level resolves to http's breaker_open default
    (30) -- NOT UNSET. Every child location that also leaves it unset (like
    /ra1/ here, breaker_open 2s) then inherits prev->breaker_retry_after ==
    30, not UNSET, so its own breaker_open is never consulted and the
    BREAKER-503 sends Retry-After: 30 instead of 2.

    Own zone (raz), same two-fetch trip shape as test_breaker_counters /
    test_serve_reason_variable (threshold=1: the first dead-origin fetch
    trips CLOSED->OPEN and still surfaces the raw origin failure; only the
    SECOND finds the breaker OPEN). /ra1/never is a COLD url -- never
    primed -- so once the breaker is OPEN it has no snapshot of any age and
    falls straight into ngx_http_cache_turbo_breaker_unavailable(), the
    local 503 whose Retry-After header is under test.

    /ra1exp/ is the positive control: identical shape, but with an EXPLICIT
    cache_turbo_breaker_retry_after 7s. That must still win -- proves the
    fix resolves the UNSET case lazily without disturbing the explicit
    path."""
    s0, b0, _ = fetch(ng.port, "/ra1/dead")
    assert s0 == 200 and b0, f"prime failed for /ra1/dead: {s0} {b0!r}"

    time.sleep(4.3)   # past fresh (1s) AND the x4 stale window (4s): L1-expired
    origin.fail = True
    try:
        s_trip, _, _ = fetch(ng.port, "/ra1/dead")
        assert s_trip != 200, \
            (f"tripping request was answered 200 -- expected it to reach "
             f"the dead origin and fail, got {s_trip}")

        s_503, _, h_503 = fetch(ng.port, "/ra1/never")
        assert s_503 == 503, \
            f"breaker OPEN + no cached copy should 503, got {s_503}"
        assert h_503.get("retry-after") == "2", \
            (f"auto-tracked Retry-After should equal this location's own "
             f"cache_turbo_breaker_open (2s), got "
             f"{h_503.get('retry-after')!r} -- BRK-RA1: breaker_retry_after "
             f"inherited the module-wide 30s default instead of tracking "
             f"the effective breaker_open")
    finally:
        origin.fail = False
        drain_origin(origin)

    # Positive control: explicit cache_turbo_breaker_retry_after still wins.
    s0e, b0e, _ = fetch(ng.port, "/ra1exp/dead")
    assert s0e == 200 and b0e, f"prime failed for /ra1exp/dead: {s0e} {b0e!r}"

    time.sleep(4.3)
    origin.fail = True
    try:
        s_trip_e, _, _ = fetch(ng.port, "/ra1exp/dead")
        assert s_trip_e != 200, \
            (f"tripping request was answered 200 -- expected it to reach "
             f"the dead origin and fail, got {s_trip_e}")

        s_503e, _, h_503e = fetch(ng.port, "/ra1exp/never")
        assert s_503e == 503, \
            f"breaker OPEN + no cached copy should 503, got {s_503e}"
        assert h_503e.get("retry-after") == "7", \
            (f"explicit cache_turbo_breaker_retry_after must win over the "
             f"derived default, got {h_503e.get('retry-after')!r}")
    finally:
        origin.fail = False
        drain_origin(origin)


def test_prometheus_breaker_metrics(ng: Nginx, origin: Origin) -> None:
    """H7.3a: cache_turbo_breaker_opens_total and cache_turbo_breaker_state
    are emitted on the Prometheus surface, not just the admin JSON.

    Own private zone (h73z) and admin endpoint (/_cache_h73), same shape as
    /s71brk/ + /_cache_s71 (test_breaker_counters above) -- NOT a reuse of
    s71z, because s71z's breaker is already OPEN by the time run_all() gets
    here (test_breaker_counters trips it and never resets it), which would
    make this test's own prime fetch fail before the assertions under test
    even run.

    Two claims:
      1. cache_turbo_breaker_opens_total{zone="h73z"} moves by exactly one
         on the tripping request (CLOSED -> OPEN, threshold=1).
      2. cache_turbo_breaker_state{zone="h73z"} reads the OPEN numeric value
         (NGX_HTTP_CACHE_TURBO_BREAKER_OPEN == 1, module.h) while OPEN, and
         is back to CLOSED (0) beforehand.
    """
    import re

    def _prom_int(body: str, metric: str, zone: str = "h73z") -> int:
        m = re.search(
            r'cache_turbo_%s\{zone="%s"\} (\d+)' % (re.escape(metric), zone),
            body)
        assert m, f"no {metric} sample for zone={zone}:\n{body[:400]}"
        return int(m.group(1))

    s0, b0, _ = fetch(ng.port, "/h73brk/prom")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    time.sleep(4.3)   # past fresh (1s) AND the x4 stale window (4s): L1-expired
    origin.fail = True
    try:
        _, prom_before, _ = fetch(ng.port, "/_cache_h73?format=prometheus")
        opens_before = _prom_int(prom_before, "breaker_opens_total")
        state_before = _prom_int(prom_before, "breaker_state")
        assert state_before == 0, (
            f"breaker_state should read CLOSED (0) before the trip, got "
            f"{state_before}")

        s_trip, _, _ = fetch(ng.port, "/h73brk/prom")
        assert s_trip != 200, \
            (f"tripping request was answered 200 -- expected it to reach "
             f"the dead origin and fail, got {s_trip}")

        _, prom_after, _ = fetch(ng.port, "/_cache_h73?format=prometheus")
        opens_after = _prom_int(prom_after, "breaker_opens_total")
        state_after = _prom_int(prom_after, "breaker_state")

        assert opens_after - opens_before == 1, (
            f"cache_turbo_breaker_opens_total did not move by exactly one "
            f"on the CLOSED->OPEN trip: {opens_before} -> {opens_after}")
        assert state_after == 1, (
            f"cache_turbo_breaker_state should report OPEN (1) once tripped, "
            f"got {state_after}")

        s_on, _, _ = fetch(ng.port, "/h73brk/prom")
        assert s_on == 200, \
            f"breaker OPEN did not fall back to the any-age snapshot, got {s_on}"
    finally:
        origin.fail = False
        drain_origin(origin)


# Response-header names arrive lower-cased from fetch()'s dict.
_ARMINGS_HDR = "x-cache-turbo-test-armings"


def _armings(hdrs: dict, where: str, site: str = "l1") -> int:
    """Pull ONE arming site's lifetime breaker-arming counter out of a
    response's headers (O4.4-i, TEST_FAULTS-only).

    The header carries both sites: ``l1=<n>,l2=<n>``. `site` selects which.
    They are separate counters on purpose -- a single total cannot pin either
    site, because the L1 site runs first on every request, so an L2 assertion
    against a shared counter passes on L1's bump and the L2 mutation stays
    green. That was measured, not assumed.

    Takes an ALREADY-FETCHED header dict on purpose: issuing an extra request
    just to read the counter perturbs the very state under test (a probe fetch
    re-primes the entry and resets the failure window, which made the tripping
    request below return 200 instead of reaching the dead origin).

    A missing header means the build lacks the counter, in which case every
    delta would read 0 and the test would pass while proving nothing -- so its
    absence is a hard failure, not a skip. Same for a site key that is not in
    the value: a format drift must fail loudly rather than silently read 0."""
    assert site in ("l1", "l2"), f"unknown arming site {site!r}"
    raw = hdrs.get(_ARMINGS_HDR)
    assert raw is not None, (
        f"{_ARMINGS_HDR} missing on {where} -- this build has no arming "
        f"counter, so the O4.4-i control cannot distinguish 'gated' from "
        f"'broken'")
    parts = dict(
        kv.split("=", 1) for kv in raw.split(",") if "=" in kv
    )
    assert site in parts, (
        f"{_ARMINGS_HDR} on {where} is {raw!r}, which carries no {site!r} "
        f"key -- the header format drifted and this assertion would silently "
        f"measure nothing")
    return int(parts[site])


def test_breaker_arming_sites_gated_white_box(ng: Nginx, origin: Origin) -> None:
    """O4.4-i: pin the L1 expired-entry ARMING call site specifically, which
    test_breaker_arming_gated_on_breaker_enable() provably cannot.

    ⚠ SCOPE: this pins the **L1** arming site only, and now says so in the
    counter it reads: the header carries `l1=<n>,l2=<n>` and this test asserts
    on the l1 field. The L2 site is pinned separately by
    test_breaker_l2_arming_site_gated_white_box() below.

    The per-site split is load-bearing, not tidiness. Against a single shared
    counter an L2 assertion passes on the L1 site's bump -- the L1 site runs
    first on every request -- so the L2 mutation stayed green. That was measured
    (mutation applied, rebuilt, test still PASSED), which is why the counter was
    split rather than the L2 test simply being added.

    Verified by mutation: reverting the L1 gate (module.c:5069) to a bare
    `breaker_threshold > 0` fails this test on the armed_off assertion, while
    the black-box test above still passes.

    That test is black-box, and the pre-origin gate alone blocks BRK_ACT_SERVE
    when the breaker is off -- so reverting an arming site to a bare
    `breaker_threshold > 0` (dropping should_consult() there) keeps it green.
    Verified in s138 by injecting exactly that mutation.

    This test reads the TEST_FAULTS-only arming counter instead, which is bumped
    INSIDE the should_consult() branch at each arming site. Two claims:

      1. breaker ON  + expired entry + dead origin => the counter MOVES.
         Without this the '0 armings' assertion below is vacuous: a counter that
         never moves satisfies it no matter how the sites are gated.
      2. breaker OFF + same conditions            => the counter does NOT move.
         This is the O4.4-c regression a bare threshold check reintroduces:
         `breaker off` would keep pinning blobs on the expired-entry path.

    /brkion/ and /brkioff/ share the dedicated `brkiz` zone (NOT `main`): this
    test leaves the breaker OPEN, which would make the black-box test's own
    tripping request get served the fallback rather than reach the dead origin.
    Since the two locations do share brkiz, the counter is zone-wide and every
    assertion below is a DELTA around that location's fetches, never an
    absolute."""
    base = {}
    for path in ("/brkion/dead", "/brkioff/dead"):
        s0, b0, h0 = fetch(ng.port, path)
        assert s0 == 200, f"prime failed for {path}: {s0}"
        assert b0, f"prime returned an empty body for {path}"
        base[path] = _armings(h0, f"prime {path}", site="l1")

    time.sleep(4.3)   # past fresh (1s) AND the x4 stale window (4s): L1-expired
    origin.fail = True
    try:
        # --- claim 1: breaker ON arms, so the counter must move ---------------
        s_trip, _, _ = fetch(ng.port, "/brkion/dead")
        assert s_trip != 200, \
            f"breaker ON: tripping request unexpectedly 200: {s_trip}"
        s_on, _, h_on = fetch(ng.port, "/brkion/dead")
        assert s_on == 200, \
            f"breaker ON: expected the any-age fallback after tripping, got {s_on}"
        armed_on = _armings(h_on, "breaker ON fallback", site="l1") - base["/brkion/dead"]
        assert armed_on > 0, (
            "breaker ON armed NOTHING at either call site (counter delta 0) -- "
            "either the arming sites no longer bump the counter or the fallback "
            "was served without arming; the 'breaker OFF arms nothing' "
            "assertion below would be vacuous, so fail here instead")

        # --- claim 2: breaker OFF must arm nothing ---------------------------
        # Baseline is the counter AFTER the breaker-ON phase, since both
        # locations share the `main` zone.
        before_off = _armings(h_on, "breaker ON fallback", site="l1")
        s_off_trip, _, _ = fetch(ng.port, "/brkioff/dead")
        assert s_off_trip != 200, \
            f"breaker OFF: tripping request unexpectedly 200: {s_off_trip}"
        s_off, _, h_off = fetch(ng.port, "/brkioff/dead")
        assert s_off != 200, \
            f"breaker OFF: dead origin answered 200 from a stale snapshot: {s_off}"
        armed_off = _armings(h_off, "breaker OFF error", site="l1") - before_off
        assert armed_off == 0, (
            f"breaker OFF armed {armed_off} time(s) at the L1 expired-entry "
            f"arming call site -- cache_turbo_breaker off must gate it through "
            f"breaker_should_consult(), not a bare breaker_threshold > 0 check. "
            f"With the breaker off this path keeps pinning blobs on every "
            f"request to a cold-ish key (O4.4-c/O4.4-i)")
    finally:
        origin.fail = False
        drain_origin(origin)


def test_breaker_l2_arming_site_gated_white_box(ng: Nginx, origin: Origin,
                                                redis: RedisServer) -> None:
    """O4.4-i (L2 half): pin the **L2** breaker-fallback ARMING call site.

    The sibling test above pins the L1 expired-entry site. This one pins the
    other arming site -- the branch that arms from an L2 blob when L1 has no
    copy (module.c ~5227, inside the `rem_stale <= 0` arm) -- and reaching it
    needs three conditions at once, each of which was established by
    measurement rather than assumed:

      1. **A separate counter.** The header reports `l1=<n>,l2=<n>` and this
         test asserts on `l2`. Against a single shared total the L1 site
         supplies the bump and the assertion would pass with the L2 gate broken
         -- measured on an earlier shared-counter version of this test.
      2. **`rem_stale <= 0` with the blob still in Redis.** The blob is aged in
         place (`created` rewritten, i64 @24) so `age > stale_ttl` and the L2
         branch's `rem_stale <= 0` precondition holds immediately, with no
         sleep. `keep_stale 300s` leaves `sie_ttl` wide, so the aged blob still
         carries a serve-on-error window and the fallback has something to arm.
      3. **L1 ABSENT, not expired.** This is the part three earlier fixture
         attempts got wrong. While an L1 copy exists AND its stamped `sie_ttl`
         window is open, the L1 SIE arm (module.c ~5122) runs BEFORE the L2 GET
         and the request is served STALE-IF-ERROR without ever entering the
         `rem_stale <= 0` branch -- so `l2` stays 0 whether the gate is right or
         wrong. And the L1 SIE window cannot be closed independently: the same
         `sie_window` feeds both `bhw.sie_ttl` (~7681) and the L2 key's
         `retain_ttl = max(stale_window, sie_window)` (~7695), and the blob is
         stamped once at store time, so "L2 object alive" and "L1 SIE window
         open" are the SAME condition by construction. No valid/keep_stale/
         stale_mult combination separates them -- do not look for one.
         The escape is to remove L1 entirely: `cache_turbo_purge on` on both
         locations, PURGE each key, then rewrite the (aged) blob back into
         Redis. PURGE is L2-aware and DELs the Redis key too (module.c ~1711),
         so the rewrite MUST come after the purge -- same ordering constraint as
         /sfgu/. LRU eviction via a filler loop was tried and rejected: it left
         the OFF key resident and is what made this half vacuous.

    The fixture serves 200 STALE-IF-ERROR / STALE-BREAKER rather than an error,
    so the STATUS is not the oracle here -- the per-site counter is. Both
    claims are therefore deltas on `l2`:

      1. breaker ON  => the l2 counter MOVES
      2. breaker OFF => the l2 counter does NOT move

    ⚠ A SECOND defect had to be fixed before claim 2 could fail at all, and it
    was in the module, not the fixture: `sie_rewrite()` (module.c ~6814)
    ngx_list_init()s `headers_out.headers` to make the snapshot's headers
    authoritative, which WIPES the arming header the header filter already
    stamped. Every STALE-IF-ERROR response therefore carried the snapshot's
    stored counter (0) while the live zone counter had moved -- measured: the
    filter logged l2=3 and l2=4 for the two /brkil2off/ requests while the
    client received `l1=0,l2=0`. The OFF fixture is served exactly that way, so
    the oracle read 0 no matter what the gate did. `sie_rewrite()` now re-stamps
    the header after restore_response. Anything else asserting on a counter
    header off a STALE-IF-ERROR response has the same exposure.

    Both halves are real controls. Mutation-verified: reducing the L2 arming
    gate (module.c ~5227) from `breaker_should_consult(clcf)` to a bare
    `clcf->breaker_threshold > 0` makes the claim-2 assertion FAIL
    ("breaker OFF armed 1 time(s) at the L2 arming call site"), and reverting it
    makes the test pass again.
    """
    base = {}
    blobs = {}
    for path in ("/brkil2on/dead", "/brkil2off/dead"):
        s0, b0, h0 = fetch(ng.port, path)
        assert s0 == 200, f"prime failed for {path}: {s0}"
        assert b0, f"prime returned an empty body for {path}"
        base[path] = _armings(h0, f"prime {path}", site="l2")

        key = l2_key(path, prefix="brkil2:")
        assert wait_for(lambda k=key: redis.cli("EXISTS", k) == "1"), \
            f"{path} never reached L2 -- nothing to arm the L2 site from"
        blob = redis.get_raw(key)
        assert blob is not None and len(blob) >= 44, \
            f"short/absent L2 blob for {path}: {blob!r}"
        _fresh_ttl, stale_ttl, sie_ttl = struct.unpack("<III", blob[32:44])
        assert sie_ttl > 60, (
            f"{path} fixture drifted: sie_ttl={sie_ttl}, expected > 60 from "
            f"keep_stale 300s. Without a wide sie window the aged blob has no "
            f"serve-on-error window and the breaker fallback arms nothing, "
            f"making claim 1 fail for a reason unrelated to gating.")
        blobs[path] = (key, blob, stale_ttl)

    # Make L1 ABSENT and leave L2 PRESENT-but-past-its-window. See condition 3
    # in the docstring: expiring L1 is not enough, because the L1 SIE arm
    # short-circuits the L2 GET, and the SIE window cannot be narrowed without
    # also dropping the L2 object. PURGE removes L1 outright; because PURGE is
    # L2-aware the Redis key goes with it, so the aged blob is written back
    # AFTERWARDS -- order matters, reversing it deletes the object under test.
    for path, (key, blob, stale_ttl) in blobs.items():
        s_p, b_p, _ = fetch_raw(ng.port, path, method="PURGE")
        assert s_p == 200, f"PURGE {path} -> {s_p}: {b_p}"
        aged = (blob[:24]
                + struct.pack("<q", int(time.time()) - (int(stale_ttl) + 60))
                + blob[32:])
        redis.set_raw(key, aged, 3_600_000)
        # PROVE the L2 blob survived the L1 drop. If it did not, both claims
        # would read l2 == 0 and claim 2 would be vacuous again.
        wait_for_l2(redis, key, aged, what=f"aged L2 blob for {path}")

    origin.fail = True
    try:
        # --- claim 1: breaker ON arms from L2, so the l2 counter must move ---
        s_trip, _, _ = fetch(ng.port, "/brkil2on/dead")
        assert s_trip == 200, (
            f"breaker ON: expected the L2 stale-if-error serve on the tripping "
            f"request, got {s_trip}")
        s_on, _, h_on = fetch(ng.port, "/brkil2on/dead")
        assert s_on == 200, \
            f"breaker ON: expected the L2 fallback after tripping, got {s_on}"
        armed_on = _armings(h_on, "breaker ON L2 fallback",
                            site="l2") - base["/brkil2on/dead"]
        assert armed_on > 0, (
            "breaker ON armed nothing at the L2 call site (l2 counter delta 0). "
            "Either the fallback came from L1 rather than L2 -- check that the "
            "PURGE above still drops the L1 copy -- or the aged L2 blob had "
            "already left Redis, or the site no longer bumps its counter. The "
            "'breaker OFF arms nothing' assertion below would be vacuous in "
            "every one of those cases, so fail here instead")

        # --- claim 2: breaker OFF must arm nothing at the L2 site ------------
        # This IS a control: /brkil2off/dead has no L1 copy (purged above) and a
        # live-but-past-window L2 blob, so the request DOES enter the
        # `rem_stale <= 0` branch where the L2 arming site lives. The only
        # reason `l2` must not move is `breaker_should_consult()` returning
        # false for `cache_turbo_breaker off`. Mutation-verified: reduce that
        # gate to a bare `clcf->breaker_threshold > 0` and this assertion fails.
        #
        # ⚠ The baseline is read from a /brkil2off/ RESPONSE, not carried over
        # from h_on: differencing across the ON phase produced a NEGATIVE delta
        # (brkil2z is small and shared), which is how that was found.
        #
        # ⚠ The L1 copy is RE-DROPPED between the two samples. The first OFF
        # request restores the L2 blob into L1 (the `rem_stale <= 0` branch both
        # serves and stores), so without this the MEASURED request would find an
        # L1 copy and never re-enter the L2 branch -- the same short-circuit that
        # made this half vacuous before. The re-drop is what keeps the measured
        # request on the branch under test.
        _, _, h_off0 = fetch(ng.port, "/brkil2off/dead")
        before_off = _armings(h_off0, "breaker OFF baseline", site="l2")
        okey, oblob, ostale = blobs["/brkil2off/dead"]
        s_p2, b_p2, _ = fetch_raw(ng.port, "/brkil2off/dead", method="PURGE")
        assert s_p2 == 200, f"re-PURGE /brkil2off/dead -> {s_p2}: {b_p2}"
        oaged = (oblob[:24]
                 + struct.pack("<q", int(time.time()) - (int(ostale) + 60))
                 + oblob[32:])
        redis.set_raw(okey, oaged, 3_600_000)
        wait_for_l2(redis, okey, oaged,
                    what="aged L2 blob for /brkil2off/dead after the re-drop")
        _, _, h_off = fetch(ng.port, "/brkil2off/dead")
        armed_off = _armings(h_off, "breaker OFF L2 error",
                             site="l2") - before_off

        assert armed_off == 0, (
            f"breaker OFF armed {armed_off} time(s) at the L2 arming call site "
            f"-- cache_turbo_breaker off must gate it through "
            f"breaker_should_consult(), not a bare breaker_threshold > 0 check "
            f"(O4.4-c/O4.4-i, L2 half)")
    finally:
        origin.fail = False
        drain_origin(origin)


def test_breaker_lifecycle_open_zero_contact_close(ng: Nginx, origin: Origin) -> None:
    """O4.5: the breaker STATE MACHINE end-to-end, not just its config/counter
    surfaces (existing test_*breaker* tests cover config-parse, arming gates,
    counters and Prometheus, but none drives CLOSED -> OPEN -> HALF_OPEN ->
    CLOSED for real).

    ⚠ SEMANTICS pinned here, not to be re-litigated: an OPEN breaker makes NO
    origin contact at all. There is no "one request per refresh cycle probes
    the origin" during OPEN -- the single probe is promoted only once
    cache_turbo_breaker_open has ELAPSED (ngx_http_cache_turbo_shm_breaker_
    state(), shm.c ~1424). See README.md's cache_turbo_breaker_open row.

    Four claims, in sequence on /o45/ (o45z, threshold=1, window=60s,
    open=2s):

      1. N (=1) origin failures trips the breaker OPEN.
      2. A CACHED key (/o45/o45cache, already armed by the priming fetch) still
         answers 200 while OPEN, with origin.hits_for("o45cache")
         UNCHANGED across the OPEN-window fetch -- proving zero origin
         contact, not just "some 200".
      3. A COLD key sharing the same zone (/o45/o45cold, never primed, so it has
         no snapshot to arm) gets 503 + a Retry-After header while OPEN,
         matching this location's explicit cache_turbo_breaker_retry_after
         (2s -- set explicitly rather than left to track breaker_open, see
         the fixture comment on /o45/: an unset breaker_retry_after inherits
         the ENCLOSING server{} context's already-resolved 30s default
         rather than being derived from this location's own breaker_open,
         a separate pre-existing gap reported to the ledger, not what this
         claim is testing).
      4. Origin restored + the probe promoted after breaker_open (2s) elapses
         CLOSES the breaker: the next fetch after the wait reaches the (now
         healthy) origin and origin.hits_for("o45cache") MOVES.
    """
    # NOTE: proxy_pass strips the /o45/ location prefix before the request
    # reaches the origin, so origin.hits_for() must be given the ORIGIN-side
    # needle (post-strip), not the client-facing path -- using the full
    # client path as the needle silently never matches anything, which
    # measured 0 the whole way through until this was caught by the trip
    # assertion below firing "did not actually reach the origin". Neither
    # needle collides with an existing fixture's URI (unlike bare
    # "cached"/"cold", which /cold/ already uses elsewhere in this file).
    cached_path = "/o45/o45cache"
    cold_path = "/o45/o45cold"
    cached_needle = "o45cache"
    cold_needle = "o45cold"

    # Prime /o45/o45cache only -- /o45/o45cold is deliberately NEVER primed (claim 3
    # needs a key with no armed snapshot at all once OPEN).
    s0, b0, _ = fetch(ng.port, cached_path)
    assert s0 == 200 and b0, f"prime failed for {cached_path}: {s0} {b0!r}"

    time.sleep(4.3)   # past fresh (1s) AND the x4 stale window (4s): L1-expired
    origin.fail = True
    try:
        hits_before_trip = origin.hits_for(cached_needle)

        # --- claim 1: the tripping request reaches the (now dead) origin ---
        s_trip, _, _ = fetch(ng.port, cached_path)
        assert s_trip != 200, (
            f"tripping request was answered 200 -- expected it to reach the "
            f"dead origin and fail, got {s_trip}")
        assert origin.hits_for(cached_needle) - hits_before_trip == 1, (
            "the tripping request did not actually reach the origin -- claim "
            "1 (N failures trips OPEN) would be vacuous without this")

        # --- claim 2: a cached key answers 200 with ZERO origin contact -----
        hits_before_open_serve = origin.hits_for(cached_needle)
        s_open, b_open, _ = fetch(ng.port, cached_path)
        assert s_open == 200, (
            f"breaker OPEN: cached key was not served from the any-age "
            f"snapshot, got {s_open}")
        assert b_open, "breaker OPEN serve returned an empty body"
        hits_after_open_serve = origin.hits_for(cached_needle)
        assert hits_after_open_serve == hits_before_open_serve, (
            f"breaker OPEN: origin.hits_for({cached_path!r}) moved "
            f"{hits_before_open_serve} -> {hits_after_open_serve} while "
            f"serving a cached key -- an OPEN breaker must make ZERO origin "
            f"contact, not just avoid surfacing the failure")

        # --- claim 3: a cold key gets 503 + Retry-After while OPEN ----------
        hits_before_cold = origin.hits_for(cold_needle)
        s_cold, _, h_cold = fetch(ng.port, cold_path)
        assert s_cold == 503, (
            f"breaker OPEN: cold key (no armed snapshot) expected 503, got "
            f"{s_cold}")
        assert origin.hits_for(cold_needle) == hits_before_cold, (
            "breaker OPEN: the cold-key 503 must not have reached the origin "
            "either")
        ra = h_cold.get("retry-after")
        assert ra is not None, (
            "breaker OPEN: cold-key 503 carries no Retry-After header -- "
            "expected the explicit cache_turbo_breaker_retry_after (2s)")
        assert ra == "2", (
            f"breaker OPEN: Retry-After should match the explicit "
            f"cache_turbo_breaker_retry_after (2), got {ra!r}")

        # --- claim 4: origin restored + probe after `open` elapses CLOSES --
        origin.fail = False
        time.sleep(2.3)   # past breaker_open (2s): the next request is the probe
        hits_before_probe = origin.hits_for(cached_needle)
        s_probe, b_probe, _ = fetch(ng.port, cached_path)
        assert s_probe == 200, (
            f"post-open-window probe: expected 200 from the now-healthy "
            f"origin, got {s_probe}")
        assert b_probe, "post-open-window probe returned an empty body"
        assert origin.hits_for(cached_needle) - hits_before_probe == 1, (
            "post-open-window probe did not reach the origin -- the breaker "
            "must promote exactly one request to the origin once "
            "breaker_open has elapsed, closing on success")

        # A second fetch right after must find the breaker CLOSED (normal
        # service resumed) rather than still routing through the fallback.
        #
        # The status alone cannot say that: a still-OPEN breaker serving the
        # armed any-age snapshot answers 200 too. Nor can an origin-hit delta
        # -- the probe above just re-stored this key and cache_turbo_valid is
        # 1s, so a CLOSED breaker legitimately answers from cache with zero
        # origin contact, and asserting a hit would fail on timing rather than
        # behaviour. The zone's own breaker_state is the discriminating read:
        # shm_stats() snapshots the word (shm.c:734) instead of going through
        # _breaker_state(), so unlike the request path it promotes nothing and
        # observing it cannot change what it reports.
        drain_origin(origin)
        s_confirm, _, _ = fetch(ng.port, cached_path)
        assert s_confirm == 200, (
            f"post-close confirm fetch: expected 200, got {s_confirm}")
        brk_state = _admin_str(ng, "breaker_state", "/_cache_o45")
        assert brk_state == "closed", (
            f"the successful probe must CLOSE the breaker, but the zone still "
            f"reports breaker_state={brk_state!r} -- a 200 here proves nothing "
            f"on its own, since an OPEN breaker serving the armed snapshot "
            f"answers 200 as well")
    finally:
        origin.fail = False
        drain_origin(origin)


def test_breaker_off_negative_control_origin_climbs(ng: Nginx, origin: Origin) -> None:
    """O4.5 MANDATORY negative control for the suite: with cache_turbo_breaker
    off (/o45off/, o45offz), a dead origin gets NO fallback at all -- every
    request keeps reaching it, so the origin hit count keeps CLIMBING rather
    than flatlining behind an OPEN breaker. This is the control that proves
    the zero-origin-contact result in test_breaker_lifecycle_open_zero_
    contact_close is actually caused by the breaker, not by keep_stale or some
    other widening: an identical shape with only the breaker flag flipped
    must show origin traffic continuing."""
    # See the O4.5 lifecycle test above for why the needle must survive the
    # /o45off/ proxy_pass prefix-strip and must not collide with an existing
    # fixture's URI ("probe" alone already belongs to /at/, /atc/, /atl/).
    path = "/o45off/o45offprobe"
    s0, b0, _ = fetch(ng.port, path)
    assert s0 == 200 and b0, f"prime failed for {path}: {s0} {b0!r}"

    time.sleep(4.3)   # past fresh (1s) AND the x4 stale window (4s): L1-expired
    origin.fail = True
    try:
        hits_before = origin.hits_for("o45offprobe")
        for _ in range(3):
            fetch(ng.port, path)
        hits_after = origin.hits_for("o45offprobe")
        assert hits_after - hits_before == 3, (
            f"breaker off: expected all 3 requests to reach the (dead) "
            f"origin (no breaker protection), but origin.hits_for("
            f"'o45offprobe') moved only {hits_after - hits_before}")
    finally:
        origin.fail = False
        drain_origin(origin)


def test_breaker_record_position_and_sense(ng: Nginx, origin: Origin) -> None:
    """O4.5 owns O4.2's declared test gap (O4.2-f): the header-filter
    recording block (module.c ~7201-7243) has no automated guard on either
    its POSITION (before the RFC-2 stale-if-error rewrite at ~7250) or the
    sense of its success argument (module.c passes `!is_failure`, i.e. a
    5xx origin status records a FAILURE, everything else a success).

    Claims 1+2 run on /o45hit/ (o45hitz, threshold=1/window=60s/open=30s).
    Claim 3 (position) runs on a SEPARATE location/zone, /o45hitpos/
    (o45hitposz, keep_stale forever) -- see the o45hitposz zone comment for
    why: threshold=1 means the failure each claim exercises trips that
    zone's breaker OPEN, and a shared zone would make the second claim to
    run fail for an unrelated reason (the pre-origin gate blocking all
    origin contact once OPEN), not because of an actual position/sense bug.

      1. An origin 5xx (drop -> 502) on a COLD key records a failure:
         origin_failures moves by exactly one, and the raw 502 surfaces
         (nothing armed yet to swap it for).
      2. A cache-turbo HIT (served from ctx->served, never reaching the
         recording block at all) records NOTHING: origin_failures does not
         move across a HIT.
      3. POSITION: recording happens BEFORE the SIE rewrite at ~7250, not
         after. Primes a key, lets it go stale (past cache_turbo_valid +
         the x4 stale window), then drops the origin on THAT key --
         keep_stale forever arms the SIE rewrite, which swaps the 502 for
         the stale body (client sees 200, body unchanged from the prime).
         origin_failures must STILL move by one: if recording ran after the
         rewrite instead of before, r->headers_out.status would already be
         the rewritten 200 by the time is_origin_failure() ran, and this
         delta would read 0 -- the exact regression a records-after-rewrite
         mutation produces.

    O4.2-f's own third claim ("a native proxy_cache HIT records nothing") is
    covered by test_breaker_record_native_proxy_cache_hit_no_record below,
    split out because it needs its own on-disk proxy_cache dir and the
    single/multi-process + sanitizer skip that test already carries."""
    hit_path = "/o45hit/x"
    cold_path = "/o45hit/dropme"
    stale_path = "/o45hitpos/staleme"

    # claim 2: prime + a genuine cache-turbo HIT (well within the 1s valid).
    s0, b0, _ = fetch(ng.port, hit_path)
    assert s0 == 200 and b0, f"prime failed for {hit_path}: {s0} {b0!r}"

    of_before_hit = _admin_stat(ng, "origin_failures", "/_cache_o45hit")
    s_hit, b_hit, _ = fetch(ng.port, hit_path)
    assert s_hit == 200 and b_hit == b0, (
        f"expected a cache-turbo HIT (identical body) for {hit_path}, got "
        f"status={s_hit} body-changed={b_hit != b0}")
    of_after_hit = _admin_stat(ng, "origin_failures", "/_cache_o45hit")
    assert of_after_hit == of_before_hit, (
        f"origin_failures moved {of_before_hit} -> {of_after_hit} across a "
        f"cache-turbo HIT -- the recording block must not run at all when "
        f"ctx->served short-circuits the header filter")

    # claim 1: drop the connection (502, transport-level failure -- a
    # different error class than the clean 503 `fail` mode) on a FRESH,
    # never-primed key, so the raw 502 has nothing to be swapped for and
    # must surface as-is.
    origin.drop = True
    try:
        of_before_fail = _admin_stat(ng, "origin_failures", "/_cache_o45hit")
        s_fail, _, _ = fetch(ng.port, cold_path)
        assert s_fail != 200, (
            f"expected the dropped-connection origin failure (502) to "
            f"surface, got {s_fail}")
        of_after_fail = _admin_stat(ng, "origin_failures", "/_cache_o45hit")
        assert of_after_fail - of_before_fail == 1, (
            f"origin_failures did not move by exactly one on a genuine "
            f"origin drop (502): {of_before_fail} -> {of_after_fail}")
    finally:
        origin.drop = False
        drain_origin(origin)

    # claim 3 (POSITION): on the SEPARATE o45hitposz zone/location so this
    # claim's own trip cannot be confused with (or blocked by) claim 1's.
    # Prime, let it go stale, then drop the origin on the SAME key --
    # keep_stale forever arms the SIE rewrite, so the client-visible
    # response becomes 200/unchanged-body even though the origin genuinely
    # answered (dropped to) a 502. origin_failures on o45hitposz must still
    # move, proving the record() call sees the ORIGINAL 502 status, not the
    # rewritten 200.
    s2, b2, _ = fetch(ng.port, stale_path)
    assert s2 == 200 and b2, f"prime failed for {stale_path}: {s2} {b2!r}"
    time.sleep(4.3)   # past fresh (1s) AND the x4 stale window (4s)
    origin.drop = True
    try:
        of_before_stale = _admin_stat(ng, "origin_failures", "/_cache_o45hitpos")
        s_stale, b_stale, _ = fetch(ng.port, stale_path)
        assert s_stale == 200 and b_stale == b2, (
            f"expected keep_stale to swap the dropped-connection 502 for "
            f"the stale body (unchanged from the prime), got status="
            f"{s_stale} body-changed={b_stale != b2} -- without this the "
            f"position claim below is not actually exercising the SIE "
            f"rewrite at all")
        of_after_stale = _admin_stat(ng, "origin_failures", "/_cache_o45hitpos")
        assert of_after_stale - of_before_stale == 1, (
            f"origin_failures did not move on a stale-serve that masked a "
            f"genuine origin 502 -- the recording block must run BEFORE "
            f"the SIE rewrite overwrites r->headers_out.status, not after: "
            f"{of_before_stale} -> {of_after_stale}")
    finally:
        origin.drop = False
        drain_origin(origin)


def test_breaker_record_native_proxy_cache_hit_no_record(ng: Nginx) -> None:
    """O4.2-f (third claim): a native `proxy_cache` HIT must record NOTHING
    on the breaker's origin_failures counter -- /o45natpc/ carries no
    cache_turbo directive at all, so the module never builds a ctx for it
    (ngx_http_get_module_ctx() returns NULL) and the header filter's very
    first line (`ctx == NULL || ctx->served`) returns before the recording
    block is ever reached, on both the MISS and every later HIT.

    Reads o45hitz's origin_failures as the observation point (o45hitz is
    never touched by /o45natpc/'s traffic at all -- there is no shared state
    between an uninstrumented location and a private zone -- so a delta of
    zero here is not a coincidence of an inert counter; it is the only
    counter this suite has that could have moved had /o45natpc/ somehow
    touched the breaker machinery, and it stays flat throughout).

    NEGATIVE CONTROL: manual, not an automated mutation, and documented as
    such rather than silently skipped (same precedent as
    test_breaker_policy_identical_no_warning's arm (b) elsewhere in this
    file). This claim is protected by TWO independent structural gates --
    ctx == NULL (no cache_turbo directive on this location at all) AND
    clcf->shm_zone == NULL (cache_turbo_zone never bound here either) -- so
    any single-line mutation that defeats one gate alone (e.g. dropping the
    ctx->served half of the early-return, tried and confirmed to still pass
    because the shm_zone gate independently blocks it) proves nothing; a
    mutation that defeats BOTH would deref a NULL ctx/shm_zone and crash
    rather than silently pass, which is not a meaningful control either.
    test_breaker_record_position_and_sense's sense (is_failure) and position
    (before/after the SIE rewrite) mutations, run against /o45hit/ +
    /o45hitpos/ above, exercise the SAME recording block this test relies on
    being unreachable -- so that block's mutation coverage is not skipped,
    just not re-proven a second time from this angle.

    Note on the MISS+HIT pair below: the HIT is a PRECONDITION (it makes the
    counter check interesting), not the claim, and it is advisory. Both gates
    above hold on a MISS as well, so a cache-visibility race on a loaded runner
    cannot invalidate the assertion -- see the comment at the poll."""
    if ng.single_process or ng.sanitizer:
        # Same core-nginx UBSan/ASan false-positive + cache-manager-process
        # skip as test_suppress_native_e2e_proxy_cache above.
        return

    path = "/o45natpc/y"
    of_before = _admin_stat(ng, "origin_failures", "/_cache_o45hit")

    s0, b0, _ = fetch(ng.port, path)
    assert s0 == 200 and b0, f"MISS failed for {path}: {s0} {b0!r}"

    # Second request: ideally a native proxy_cache HIT, which is what makes the
    # counter assertion below interesting rather than vacuous. Polled (not a
    # fixed sleep) because nginx writes the cache entry after the response
    # completes, so a loaded box can MISS again immediately afterwards.
    #
    # ADVISORY, NOT AN ASSERTION -- deliberately. The claim this test makes is
    # the origin_failures delta below, and that claim does NOT depend on
    # request 2 being a HIT: the header filter returns at
    # `ctx == NULL || ctx->served` (module.c:7122) and /o45natpc/ carries no
    # cache_turbo directive at all, so ngx_http_get_module_ctx() is NULL on
    # EVERY request here -- MISS and HIT alike -- and the recording block
    # (module.c:7234) is unreachable either way. A MISS therefore still
    # exercises the claim. Hard-failing on it cost three sessions chasing an
    # environment-dependent runner MISS that endangered nothing (see
    # lessons.md); a note is the right severity.
    #
    # Short budget on purpose: this is advisory, so a runner that is never
    # going to produce the HIT should not pay 5s to learn that.
    b1 = None
    for _ in range(10):
        s1, b1, _ = fetch(ng.port, path)
        if s1 == 200 and b1 == b0:
            break
        time.sleep(0.1)
    assert s1 == 200, (
        f"native proxy_cache request 2 for {path} must still be a healthy 200 "
        f"(HIT or MISS), got {s1} -- an error response would mean the origin "
        f"or the location itself broke, not a cache-visibility race")
    if b1 != b0:
        print(f"    note: {path} did not become a native proxy_cache HIT "
              f"within 1s (request 2 re-fetched from origin). Harmless here -- "
              f"the origin_failures claim below holds for a MISS too.",
              flush=True)

    of_after = _admin_stat(ng, "origin_failures", "/_cache_o45hit")
    assert of_after == of_before, (
        f"origin_failures moved {of_before} -> {of_after} across a native "
        f"proxy_cache MISS+HIT with no cache_turbo directive present at all "
        f"-- the breaker recording block must be unreachable without a ctx")


# The directive line the separator tests rewrite. Kept as one constant so a
# config reshuffle breaks these loudly (via the `old in cfg` assert) instead of
# silently skipping them.
_BACKEND_LINE = "cache_turbo_backend wordpress woocommerce joomla;"


def test_backend_separators(ng: Nginx) -> None:
    """Backends stack, and spaces and '|' are interchangeable separators. All of
    these must mean the same thing:

        cache_turbo_backend wordpress woocommerce;
        cache_turbo_backend wordpress|woocommerce;
        cache_turbo_backend wordpress | woocommerce;

    nginx's config lexer splits on whitespace, so `a|b` arrives as ONE token with
    a '|' inside while `a | b` arrives as THREE tokens -- the parser has to
    handle both, which is what this pins down."""
    for i, spec in enumerate([
        "wordpress",
        "wordpress woocommerce",
        "wordpress|woocommerce",
        "wordpress | woocommerce",
        "wordpress|woocommerce joomla",
        "mediawiki|drupal",
        "none",
        "wordpress|woocommerce|joomla|xenforo|discourse|phpbb|drupal|mediawiki"
        "|magento|ghost|wagtail|kirby|shopware6|typo3",
        "magento|ghost",
        "wagtail|kirby",
        "shopware6|typo3",
        "textpattern|bludit|spip|bugzilla|mantisbt|plone|umbraco|dotclear|wikijs",
        "mantis|classicpress|backdrop",
    ]):
        _config_accepts(ng, f"sep-ok-{i}", _BACKEND_LINE,
                        f"cache_turbo_backend {spec};")


def test_backend_malformed_pipes(ng: Nginx) -> None:
    """A stray '|' is a typo, and every form of it must be a config error.

    Both of these were silent-accept bugs during development, which is the
    dangerous direction: `wordpress|` parsed as just `wordpress` (the trailing
    empty slice was never examined), and a lone `|` resolved to ZERO backends --
    which leaves the mask at 0, which the loc-conf merge reads as "unset" and so
    quietly INHERITS the parent's preset. A directive that looks like it names a
    backend and silently does something else is exactly what must not ship."""
    for i, (spec, want) in enumerate([
        ("wordpress||woocommerce", "empty backend name"),
        ("|wordpress",             "empty backend name"),
        ("wordpress|",             "empty backend name"),   # trailing pipe
        ("|",                      "names no backend"),     # lone pipe
        ("| |",                    "names no backend"),
        ("bogus",                  "unknown cache_turbo_backend"),
        ("wordpress|bogus",        "unknown cache_turbo_backend"),
    ]):
        _config_rejects(ng, f"sep-bad-{i}", _BACKEND_LINE,
                        f"cache_turbo_backend {spec};", want)


def test_backend_none_is_exclusive(ng: Nginx) -> None:
    """`none` means "no preset here" and cannot be combined with a real backend --
    `none wordpress` is a contradiction, and silently letting one win is exactly
    the quiet surprise this directive exists to avoid."""
    for i, spec in enumerate(["none wordpress", "none|wordpress",
                              "wordpress|none", "none | mediawiki"]):
        _config_rejects(ng, f"none-plus-{i}", _BACKEND_LINE,
                        f"cache_turbo_backend {spec};", "cannot be combined")

    # Across SEPARATE directive lines in the same context. Each line passes the
    # per-invocation check on its own, but the COMBINED result is still
    # NONE|<preset>, which must still be rejected. Regression guard for A3
    # (audit 2026-07-21): the exclusivity check used to look at only this one
    # invocation's args and silently left NONE|WORDPRESS set. Without the fix
    # nginx -t accepts these two-line configs and _config_rejects fails on its
    # `returncode != 0` assert -- i.e. this loop is its own negative control.
    # `woocommerce` implies `wordpress`, so ("woocommerce","none") also exercises
    # the implies path folding into the combined mask.
    for i, (a, b) in enumerate([("none", "wordpress"),
                                ("wordpress", "none"),
                                ("none", "mediawiki|drupal"),
                                ("woocommerce", "none")]):
        _config_rejects(
            ng, f"none-2line-{i}", _BACKEND_LINE,
            f"cache_turbo_backend {a};\n"
            f"            cache_turbo_backend {b};",
            "cannot be combined")


def test_backend_none_overrides_inherited(ng: Nginx, origin: Origin) -> None:
    """`cache_turbo_backend none;` switches OFF a preset inherited from the
    server level.

    This is the gap `none` exists to fill. backend_presets uses 0 to mean "this
    location named no backend", which the loc-conf merge reads as "inherit the
    parent's" -- so before `none` there was no way to opt a single location out
    of a server-level preset. `none` sets a sentinel bit: non-zero (so nothing is
    inherited) but matching no registry row (so no rule fires).

    The server block arms `wordpress`, so /wp-admin/-shaped paths would normally
    bypass. Under `none` they must cache like any other page."""
    # A WordPress dynamic surface, in a location that said `none`: must CACHE.
    fetch(ng.port, "/nonepreset/wp-login.php")
    _, _, h = fetch(ng.port, "/nonepreset/wp-login.php")
    assert h.get("x-cache") == "HIT", \
        ("`none` must override the inherited wordpress preset, so this caches; "
         f"got {h.get('x-cache')} -- the preset is still firing")

    # And a WordPress auth cookie must not bypass either.
    wp = {"Cookie": "wordpress_logged_in_abc=deadbeef"}
    fetch(ng.port, "/nonepreset/page", headers=wp)
    _, _, hw = fetch(ng.port, "/nonepreset/page", headers=wp)
    assert hw.get("x-cache") == "HIT", \
        ("`none` must override the inherited wordpress cookie rule too; "
         f"got {hw.get('x-cache')}")
    drain_origin(origin)


def test_valid_status_rejects_304(ng: Nginx) -> None:
    """COR-12: a per-status cache_turbo_valid naming 304 (or 206 / 1xx) is a
    meaningless standalone cache entry and must be rejected at config time."""
    bad = ng.root.parent / "bad-status"
    (bad / "conf").mkdir(parents=True, exist_ok=True)
    (bad / "logs").mkdir(parents=True, exist_ok=True)
    cfg = nginx_config(bad, ng.port, ng.module, ng.origin_port, 1)
    cfg = cfg.replace("cache_turbo_valid    0;",
                      "cache_turbo_valid    0;\n"
                      "            cache_turbo_valid 304 1m;")
    (bad / "conf" / "nginx.conf").write_text(cfg, encoding="ascii")
    cmd = ng.runner + [str(ng.binary), "-p", str(bad),
                       "-c", str(bad / "conf" / "nginx.conf"), "-t"]
    r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=20)
    assert r.returncode != 0, \
        f"standalone 304 was accepted by nginx -t:\n{r.stdout}"
    assert "cannot be cached standalone" in r.stdout, \
        f"missing/odd diagnostic for 304 status:\n{r.stdout}"


def test_empty_l2_prefix_rejected(ng: Nginx) -> None:
    """An empty L2 prefix must fail nginx -t: Redis all-purge would otherwise
    become SCAN MATCH * and delete the selected database."""
    cases = []
    if ng.redis_port is not None:
        cases.append(("redis", "prefix=ct:", "prefix="))
    if ng.memcached_port is not None:
        cases.append(("memcached", "prefix=mc:", "prefix="))

    for name, old, new in cases:
        bad = ng.root.parent / f"bad-empty-{name}-prefix"
        (bad / "conf").mkdir(parents=True, exist_ok=True)
        (bad / "logs").mkdir(parents=True, exist_ok=True)
        cfg = nginx_config(
            bad, ng.port, ng.module, ng.origin_port, 1, ng.redis_port,
            ng.redis_auth_port, ng.redis_password, ng.redis_tls_port,
            ng.redis_tls_ca, ng.memcached_port)
        assert old in cfg, f"test fixture missing {old!r}"
        cfg = cfg.replace(old, new, 1)
        (bad / "conf" / "nginx.conf").write_text(cfg, encoding="ascii")
        cmd = ng.runner + [str(ng.binary), "-p", str(bad),
                           "-c", str(bad / "conf" / "nginx.conf"), "-t"]
        r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=20)
        assert r.returncode != 0, \
            f"empty {name} prefix was accepted by nginx -t:\n{r.stdout}"
        assert "empty prefix" in r.stdout.lower(), \
            f"missing empty-prefix diagnostic for {name}:\n{r.stdout}"


def _config_test_result(ng: Nginx, mutate) -> "subprocess.CompletedProcess[str]":
    """Render the full config, apply `mutate(cfg) -> cfg`, write it, and run
    nginx -t. Returns the CompletedProcess (returncode + combined stdout)."""
    bad = ng.root.parent / "cfgcheck"
    (bad / "conf").mkdir(parents=True, exist_ok=True)
    (bad / "logs").mkdir(parents=True, exist_ok=True)
    cfg = nginx_config(
        bad, ng.port, ng.module, ng.origin_port, 1, ng.redis_port,
        ng.redis_auth_port, ng.redis_password, ng.redis_tls_port,
        ng.redis_tls_ca, ng.memcached_port)
    cfg = mutate(cfg)
    (bad / "conf" / "nginx.conf").write_text(cfg, encoding="ascii")
    cmd = ng.runner + [str(ng.binary), "-p", str(bad),
                       "-c", str(bad / "conf" / "nginx.conf"), "-t"]
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=20)


def test_backend_prefix_rejected(ng: Nginx) -> None:
    """item 18: a malformed cache_turbo_backend_prefix must fail nginx -t. A
    value that does not match the deployed mount yields ZERO URI-rule coverage
    -- the exact silent failure the directive exists to end -- so it is rejected
    loudly instead of coerced into something that merely looks configured.
    Bare "/" is rejected too: it is a no-op that reads as configured."""
    anchor = "cache_turbo_backend_prefix /shop/;"
    for bad_value, why in (
        ("shop/",  "no leading slash"),
        ("/shop",  "no trailing slash"),
        ("/",      "bare root mount is a no-op"),
    ):
        def mutate(cfg: str, _v: str = bad_value) -> str:
            assert anchor in cfg, f"test fixture missing {anchor!r}"
            return cfg.replace(anchor,
                               f"cache_turbo_backend_prefix {_v};", 1)

        r = _config_test_result(ng, mutate)
        assert r.returncode != 0, \
            (f"cache_turbo_backend_prefix {bad_value!r} ({why}) was accepted by "
             f"nginx -t:\n{r.stdout}")
        assert "must begin and end" in r.stdout.lower(), \
            (f"missing backend_prefix diagnostic for {bad_value!r}:\n{r.stdout}")


def test_s8_scan_resistant_config_rejects(ng: Nginx) -> None:
    """S8 config-time rejects. Each arm has its OWN diagnostic, because a
    single "bad config" catch-all cannot tell an operator which mistake they
    made -- and because a shared message would let one arm pass on the other's
    error (the trap the H5/stale_mult tests recorded).

    protected_pct is range-checked by hand rather than via
    ngx_conf_set_num_slot precisely so `protected_pct=0` is an ERROR instead of
    being silently coerced to the default 80. Both H5 and H3(c) were bitten by
    that coerce-on-read trap; this test is what stops it recurring here."""
    anchor = "cache_turbo_scan_resistant on;"

    # 1. bad on/off token
    r = _config_test_result(
        ng, lambda c: c.replace(anchor, "cache_turbo_scan_resistant yes;", 1))
    assert r.returncode != 0, f"bad on/off token accepted:\n{r.stdout}"
    assert 'expected "on" or "off"' in r.stdout, \
        f"missing on/off diagnostic:\n{r.stdout}"

    # 2. protected_pct=0 -- must NOT be coerced to the default
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor, "cache_turbo_scan_resistant on protected_pct=0;", 1))
    assert r.returncode != 0, f"protected_pct=0 accepted:\n{r.stdout}"
    assert "out of range" in r.stdout, \
        f"missing protected_pct range diagnostic:\n{r.stdout}"

    # 3. protected_pct=100 -- upper bound is 99 (100 would mean "nothing may
    #    ever live in probation", i.e. no scan resistance at all)
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor, "cache_turbo_scan_resistant on protected_pct=100;", 1))
    assert r.returncode != 0, f"protected_pct=100 accepted:\n{r.stdout}"
    assert "out of range" in r.stdout, \
        f"missing protected_pct upper-bound diagnostic:\n{r.stdout}"

    # 4. non-numeric protected_pct -- a DISTINCT diagnostic from out-of-range.
    #    ngx_atoi has no sign handling, so a negative also lands here.
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor, "cache_turbo_scan_resistant on protected_pct=abc;", 1))
    assert r.returncode != 0, f"non-numeric protected_pct accepted:\n{r.stdout}"
    assert "bad protected_pct" in r.stdout, \
        f"missing bad-protected_pct diagnostic:\n{r.stdout}"

    # 5. unknown parameter
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor, "cache_turbo_scan_resistant on wat=1;", 1))
    assert r.returncode != 0, f"unknown parameter accepted:\n{r.stdout}"
    assert "unknown parameter" in r.stdout, \
        f"missing unknown-parameter diagnostic:\n{r.stdout}"

    # 6. protected_pct on `off` is inert config -- reject rather than store a
    #    value that can never be read.
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor, "cache_turbo_scan_resistant off protected_pct=50;", 1))
    assert r.returncode != 0, f"protected_pct on `off` accepted:\n{r.stdout}"
    assert "meaningless with" in r.stdout, \
        f"missing off+protected_pct diagnostic:\n{r.stdout}"

    # 7. duplicate directive
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor, anchor + "\n            " + anchor, 1))
    assert r.returncode != 0, f"duplicate directive accepted:\n{r.stdout}"
    assert "is duplicate" in r.stdout, \
        f"missing duplicate diagnostic:\n{r.stdout}"

    # 8. the pristine config must still pass, or every arm above is vacuous
    #    (a config broken for an unrelated reason fails all seven).
    r = _config_test_result(ng, lambda c: c)
    assert r.returncode == 0, \
        f"baseline config does not pass nginx -t:\n{r.stdout}"


def test_keepalive_cap_rejected(ng: Nginx) -> None:
    """STAB-5: an absurd cache_turbo_redis keepalive=N (the per-worker pool is
    N*sizeof(item)) is rejected at config time so the size_t multiply can't
    overflow into a short allocation the init loop then overruns."""
    if ng.redis_port is None:
        return
    anchor = "keepalive=8 keepalive_timeout=30s"
    r = _config_test_result(
        ng, lambda c: c.replace(anchor,
                                "keepalive=99999999 keepalive_timeout=30s", 1))
    assert r.returncode != 0, \
        f"oversized keepalive was accepted by nginx -t:\n{r.stdout}"
    assert "exceeds the maximum" in r.stdout, \
        f"missing keepalive-cap diagnostic:\n{r.stdout}"


def test_memcached_keepalive_invalid_rejected(ng: Nginx) -> None:
    """L14: cache_turbo_memcached keepalive=<bad> is rejected."""
    if ng.memcached_port is None:
        return
    def mutate(c):
        return c.replace(
            f"cache_turbo_memcached  127.0.0.1:{ng.memcached_port} prefix=mc: timeout=250ms;",
            f"cache_turbo_memcached  127.0.0.1:{ng.memcached_port} prefix=mc: timeout=250ms keepalive=abc;", 1)
    r = _config_test_result(ng, mutate)
    assert r.returncode != 0, \
        f"bad keepalive was accepted by nginx -t:\n{r.stdout}"
    assert "bad keepalive" in r.stdout, \
        f"missing bad-keepalive diagnostic:\n{r.stdout}"


def test_memcached_keepalive_cap_rejected(ng: Nginx) -> None:
    """L14: cache_turbo_memcached keepalive=N > max is rejected."""
    if ng.memcached_port is None:
        return
    def mutate(c):
        return c.replace(
            f"cache_turbo_memcached  127.0.0.1:{ng.memcached_port} prefix=mc: timeout=250ms;",
            f"cache_turbo_memcached  127.0.0.1:{ng.memcached_port} prefix=mc: timeout=250ms keepalive=99999999;", 1)
    r = _config_test_result(ng, mutate)
    assert r.returncode != 0, \
        f"oversized keepalive was accepted by nginx -t:\n{r.stdout}"
    assert "must be <=" in r.stdout, \
        f"missing keepalive-cap diagnostic:\n{r.stdout}"


def test_memcached_keepalive_timeout_invalid_rejected(ng: Nginx) -> None:
    """L14: cache_turbo_memcached keepalive_timeout=<bad> is rejected."""
    if ng.memcached_port is None:
        return
    def mutate(c):
        return c.replace(
            f"cache_turbo_memcached  127.0.0.1:{ng.memcached_port} prefix=mc: timeout=250ms;",
            f"cache_turbo_memcached  127.0.0.1:{ng.memcached_port} prefix=mc: timeout=250ms keepalive=8 keepalive_timeout=notatime;", 1)
    r = _config_test_result(ng, mutate)
    assert r.returncode != 0, \
        f"bad keepalive_timeout was accepted by nginx -t:\n{r.stdout}"
    assert "bad keepalive_timeout" in r.stdout, \
        f"missing bad-timeout diagnostic:\n{r.stdout}"


def test_valid_dup_status_warns(ng: Nginx) -> None:
    """COR-9: a second cache_turbo_valid rule for a status code is dead
    (status_ttl returns the first match). nginx -t loads but must warn."""
    r = _config_test_result(
        ng, lambda c: c.replace(
            "cache_turbo_valid    0;",
            "cache_turbo_valid    0;\n"
            "            cache_turbo_valid 404 1m;\n"
            "            cache_turbo_valid 404 2m;", 1))
    assert r.returncode == 0, \
        f"duplicate-status config unexpectedly failed nginx -t:\n{r.stdout}"
    assert "duplicate rule for status" in r.stdout, \
        f"missing duplicate-status warning:\n{r.stdout}"


def test_tag_without_l2_warns(ng: Nginx) -> None:
    """COR-0: cache_turbo_tag in a location with no Redis L2 is inert (tags live
    only in Redis). nginx -t loads but must warn it has no effect."""
    r = _config_test_result(
        ng, lambda c: c.replace(
            "cache_turbo_valid    0;",
            "cache_turbo_valid    0;\n"
            "            cache_turbo_tag      $arg_t;", 1))
    assert r.returncode == 0, \
        f"tag-without-L2 config unexpectedly failed nginx -t:\n{r.stdout}"
    assert "no effect here" in r.stdout, \
        f"missing tag-without-L2 warning:\n{r.stdout}"


def test_tag_without_l2_but_surrogate_key_no_warn(ng: Nginx) -> None:
    """COR-0 exception: cache_turbo_surrogate_key gives cache_turbo_tag a
    Redis-free consumer (downstream Surrogate-Key emission). The tag is then NOT
    inert, so the "no effect here" warning must be SUPPRESSED even with no L2 --
    otherwise a valid Redis-free CDN-sync config nags on every reload."""
    r = _config_test_result(
        ng, lambda c: c.replace(
            "cache_turbo_valid    0;",
            "cache_turbo_valid    0;\n"
            "            cache_turbo_tag      $arg_t;\n"
            "            cache_turbo_surrogate_key on;", 1))
    assert r.returncode == 0, \
        f"tag+surrogate_key config unexpectedly failed nginx -t:\n{r.stdout}"
    assert "no effect here" not in r.stdout, \
        f"tag-without-L2 warning must be suppressed when surrogate_key is on:\n{r.stdout}"


def test_cache_control_invalid_mode_rejected(ng: Nginx) -> None:
    """cache_turbo_cache_control takes respect|honor|ignore. Any other token is
    rejected at config time: the mode decides whether an origin's `private` /
    `no-store` is obeyed, so silently falling back to a default on a typo'd
    value would turn a storage floor off without any signal."""
    r = _config_test_result(
        ng, lambda c: c.replace(
            "cache_turbo_valid    0;",
            "cache_turbo_valid    0;\n"
            "            cache_turbo_cache_control respekt;", 1))
    assert r.returncode != 0, \
        f"invalid cache_control mode was accepted by nginx -t:\n{r.stdout}"
    assert "want respect|honor|ignore" in r.stdout, \
        f"missing/odd invalid-mode diagnostic:\n{r.stdout}"


def test_cache_control_duplicate_rejected(ng: Nginx) -> None:
    """Two cache_turbo_cache_control directives in one block is a config error,
    not last-wins. The two modes disagree about the storage floor, so guessing
    which the operator meant is worse than refusing to start."""
    r = _config_test_result(
        ng, lambda c: c.replace(
            "cache_turbo_valid    0;",
            "cache_turbo_valid    0;\n"
            "            cache_turbo_cache_control honor;\n"
            "            cache_turbo_cache_control ignore;", 1))
    assert r.returncode != 0, \
        f"duplicate cache_control was accepted by nginx -t:\n{r.stdout}"
    assert "is duplicate" in r.stdout, \
        f"missing duplicate-directive diagnostic:\n{r.stdout}"


def test_valid_status_rejects_out_of_range_code(ng: Nginx) -> None:
    """A cache_turbo_valid status code outside 100..599 is rejected. This is a
    DIFFERENT arm from the 1xx/206/304 refusal (test_valid_status_rejects_304):
    that one refuses valid-but-unstorable codes, this one refuses a value that
    is not an HTTP status at all -- e.g. a time typo'd into the code slot."""
    r = _config_test_result(
        ng, lambda c: c.replace(
            "cache_turbo_valid    0;",
            "cache_turbo_valid    0;\n"
            "            cache_turbo_valid 999 1m;", 1))
    assert r.returncode != 0, \
        f"out-of-range status code was accepted by nginx -t:\n{r.stdout}"
    assert "bad status code" in r.stdout, \
        f"missing/odd bad-status-code diagnostic:\n{r.stdout}"


def test_valid_rejects_bad_time(ng: Nginx) -> None:
    """The last cache_turbo_valid argument is always the time; an unparseable
    one is rejected rather than silently resolving to 0 (which the parser then
    promotes to cache-forever -- the worst possible reading of a typo)."""
    r = _config_test_result(
        ng, lambda c: c.replace(
            "cache_turbo_valid    0;",
            "cache_turbo_valid    0;\n"
            "            cache_turbo_valid 404 5x;", 1))
    assert r.returncode != 0, \
        f"bad valid time was accepted by nginx -t:\n{r.stdout}"
    assert "bad time" in r.stdout, \
        f"missing/odd bad-time diagnostic:\n{r.stdout}"


def test_require_header_rejects_invalid_name(ng: Nginx) -> None:
    """cache_turbo_require_header takes an RFC 9110 token. A non-token name can
    never match a real response header, so the store gate would silently never
    pass -- a cache that stores nothing, with no diagnostic. Rejected instead."""
    r = _config_test_result(
        ng, lambda c: c.replace(
            "cache_turbo_valid    0;",
            "cache_turbo_valid    0;\n"
            "            cache_turbo_require_header \"X-Bad:Name\";", 1))
    assert r.returncode != 0, \
        f"invalid require_header name was accepted by nginx -t:\n{r.stdout}"
    assert "invalid header name" in r.stdout, \
        f"missing/odd invalid-header-name diagnostic:\n{r.stdout}"


def test_require_header_duplicate_rejected(ng: Nginx) -> None:
    """Two cache_turbo_require_header directives in one block: the gate is a
    single name, so the second would be silently dropped and the operator would
    believe both headers were required."""
    r = _config_test_result(
        ng, lambda c: c.replace(
            "cache_turbo_valid    0;",
            "cache_turbo_valid    0;\n"
            "            cache_turbo_require_header X-One;\n"
            "            cache_turbo_require_header X-Two;", 1))
    assert r.returncode != 0, \
        f"duplicate require_header was accepted by nginx -t:\n{r.stdout}"
    assert "is duplicate" in r.stdout, \
        f"missing duplicate-directive diagnostic:\n{r.stdout}"


def test_redis_bad_db_rejected(ng: Nginx) -> None:
    """A non-numeric Redis db is rejected at config time rather than defaulting
    to db 0 -- silently sharing db 0 with another application's keys is exactly
    what an explicit db selector was written to prevent.

    Both arms are pinned because they are SEPARATE parser paths with separate
    diagnostics: the `db=N` trailing param and the `/N` DSN suffix. The rendered
    test config uses the param form, so the DSN arm is reached by rewriting a
    bare `host:port db=N` line into DSN form."""
    if ng.redis_port is None:
        return

    param_anchor = f"127.0.0.1:{ng.redis_port} db=1"
    assert param_anchor in nginx_config(
        ng.root, ng.port, ng.module, ng.origin_port, 1, ng.redis_port,
        ng.redis_auth_port, ng.redis_password, ng.redis_tls_port,
        ng.redis_tls_ca, ng.memcached_port), \
        f"test fixture missing anchor {param_anchor!r}"

    # arm 1: db= trailing param
    r = _config_test_result(
        ng, lambda c: c.replace(param_anchor,
                                f"127.0.0.1:{ng.redis_port} db=xy", 1))
    assert r.returncode != 0, \
        f"bad db= param was accepted by nginx -t:\n{r.stdout}"
    assert "bad db" in r.stdout, \
        f"missing/odd bad-db diagnostic:\n{r.stdout}"

    # arm 2: /N DSN suffix -- distinct code path, distinct message
    r = _config_test_result(
        ng, lambda c: c.replace(param_anchor,
                                f"redis://127.0.0.1:{ng.redis_port}/xy", 1))
    assert r.returncode != 0, \
        f"bad DSN db was accepted by nginx -t:\n{r.stdout}"
    assert "bad db in DSN" in r.stdout, \
        f"missing/odd bad-DSN-db diagnostic:\n{r.stdout}"


def test_redis_db_cap_rejected(ng: Nginx) -> None:
    """A syntactically valid but out-of-range db index is rejected at config
    time, both as the `db=N` param and as the `/N` DSN suffix.

    Distinct from test_redis_bad_db_rejected: that one refuses a value that is
    not a number at all; this one refuses a well-formed number that no Redis
    will accept. Redis ships `databases 16` (indices 0..15), so `db=99` used to
    pass `nginx -t` clean and then fail every L2 op at runtime on SELECT --
    silent until traffic. Both arms are pinned because they are separate parser
    paths with separate diagnostics."""
    if ng.redis_port is None:
        return

    param_anchor = f"127.0.0.1:{ng.redis_port} db=1"
    assert param_anchor in nginx_config(
        ng.root, ng.port, ng.module, ng.origin_port, 1, ng.redis_port,
        ng.redis_auth_port, ng.redis_password, ng.redis_tls_port,
        ng.redis_tls_ca, ng.memcached_port), \
        f"test fixture missing anchor {param_anchor!r}"

    # arm 1: db= trailing param
    r = _config_test_result(
        ng, lambda c: c.replace(param_anchor,
                                f"127.0.0.1:{ng.redis_port} db=99", 1))
    assert r.returncode != 0, \
        f"out-of-range db= param was accepted by nginx -t:\n{r.stdout}"
    assert "exceeds the maximum" in r.stdout, \
        f"missing/odd db-cap diagnostic:\n{r.stdout}"

    # arm 2: /N DSN suffix -- distinct code path, distinct message
    r = _config_test_result(
        ng, lambda c: c.replace(param_anchor,
                                f"redis://127.0.0.1:{ng.redis_port}/99", 1))
    assert r.returncode != 0, \
        f"out-of-range DSN db was accepted by nginx -t:\n{r.stdout}"
    assert "db in DSN" in r.stdout and "exceeds the maximum" in r.stdout, \
        f"missing/odd DSN-db-cap diagnostic:\n{r.stdout}"

    # the boundary itself must still be accepted -- a cap that rejects the
    # highest legal index would be an off-by-one that no bad-value test catches
    r = _config_test_result(
        ng, lambda c: c.replace(param_anchor,
                                f"127.0.0.1:{ng.redis_port} db=15", 1))
    assert r.returncode == 0, \
        f"db=15 (the highest legal index) was rejected:\n{r.stdout}"


def test_l2_prefix_charset_rejected(ng: Nginx) -> None:
    """AUD-MC1: an L2 key prefix carrying a control character, or long enough to
    push the composed key past the 250-byte memcached limit, is refused at
    config time -- on BOTH backends, which parse `prefix=` in separate
    functions.

    Only `prefix.len != 0` used to be checked. The module documents the composed
    L2 key as "printable, no spaces/control chars, <=250 bytes"
    (ngx_http_cache_turbo_memcached.c header), an invariant the digest half
    honoured and the operator-supplied half did not. memcached frames its
    commands by spaces and CRLF, so such a prefix corrupts the command and the
    location silently degrades to L1-only -- a config typo with no diagnostic.

    The last arm is what keeps the others from being vacuous: an ordinary
    prefix must still be accepted, or a validator that refused everything would
    satisfy every rejection assertion above while breaking the feature."""
    if ng.redis_port is None or ng.memcached_port is None:
        return

    redis_anchor = f"127.0.0.1:{ng.redis_port} db=1"
    mc_anchor = f"127.0.0.1:{ng.memcached_port} prefix=mc: timeout=250ms"
    cfg = nginx_config(
        ng.root, ng.port, ng.module, ng.origin_port, 1, ng.redis_port,
        ng.redis_auth_port, ng.redis_password, ng.redis_tls_port,
        ng.redis_tls_ca, ng.memcached_port)
    assert redis_anchor in cfg and mc_anchor in cfg, \
        "test fixture missing an anchor for one of the two L2 parsers"

    # arm 1: control byte, redis parser
    r = _config_test_result(
        ng, lambda c: c.replace(redis_anchor,
                                f"127.0.0.1:{ng.redis_port} prefix=ct\x01x:", 1))
    assert r.returncode != 0, \
        f"a control character in prefix= was accepted by nginx -t:\n{r.stdout}"
    assert "must be printable" in r.stdout, \
        f"missing/odd prefix-charset diagnostic:\n{r.stdout}"

    # arm 2: same byte, memcached parser -- separate function, separate message
    r = _config_test_result(
        ng, lambda c: c.replace(mc_anchor,
                                f"127.0.0.1:{ng.memcached_port} prefix=mc\x01:", 1))
    assert r.returncode != 0, \
        f"memcached accepted a control character in prefix=:\n{r.stdout}"
    assert "cache_turbo_memcached" in r.stdout and "must be printable" in r.stdout, \
        f"memcached prefix diagnostic did not name its own directive:\n{r.stdout}"

    # arm 3: length. 187 bytes leaves less than the 64 the module may append.
    long_prefix = "c" * 187
    r = _config_test_result(
        ng, lambda c: c.replace(mc_anchor,
                                f"127.0.0.1:{ng.memcached_port} prefix={long_prefix}", 1))
    assert r.returncode != 0, \
        f"an over-long prefix= was accepted by nginx -t:\n{r.stdout}"
    assert "at most" in r.stdout and "186" in r.stdout, \
        f"missing/odd prefix-length diagnostic:\n{r.stdout}"

    # arm 4: the boundary is usable, and an ordinary prefix still parses
    r = _config_test_result(
        ng, lambda c: c.replace(mc_anchor,
                                f"127.0.0.1:{ng.memcached_port} prefix={'c' * 186}", 1))
    assert r.returncode == 0, \
        f"a 186-byte prefix (the longest legal one) was rejected:\n{r.stdout}"


def test_max_size_not_cached(ng: Nginx) -> None:
    """Responses larger than cache_turbo_max_size are never cached (Q2: the
    body filter early-aborts capture the moment body_len crosses max_size, so
    the oversize blob is delegated to a stacked native cache instead of being
    fully copied into the request pool and discarded). Repeated reads must keep
    reaching the origin (no stale cached copy) and never surface an error."""
    fetch(ng.port, "/big/x")
    for _ in range(3):
        s, b, h = fetch(ng.port, "/big/x")
        assert s == 200, f"oversize delegate served {s}, expected live 200"
        assert b, "oversize response lost its body"
        assert "x-cache" not in h, "oversized response should not be cached"


def test_no_cache_set_cookie(ng: Nginx) -> None:
    """RFC 9111 floor: a Set-Cookie response is never stored (it carries
    per-client state) — repeated reads keep hitting the origin."""
    s1, b1, h1 = fetch(ng.port, "/cc/setcookie")
    assert s1 == 200 and "x-cache" not in h1, "first read should be a miss"
    _s2, b2, h2 = fetch(ng.port, "/cc/setcookie")
    assert "x-cache" not in h2, "Set-Cookie response must not be cached"
    assert b1 != b2, "both reads should have gone to the origin"


def test_no_cache_cc_private(ng: Nginx) -> None:
    """RFC 9111 floor: Cache-Control: private is not stored in a shared cache."""
    _, b1, h1 = fetch(ng.port, "/cc/ccprivate")
    assert "x-cache" not in h1
    _, b2, h2 = fetch(ng.port, "/cc/ccprivate")
    assert "x-cache" not in h2, "Cache-Control: private must not be cached"
    assert b1 != b2


def test_no_cache_cc_nostore(ng: Nginx) -> None:
    """RFC 9111 floor: Cache-Control: no-store is never stored."""
    _, b1, h1 = fetch(ng.port, "/cc/ccnostore")
    assert "x-cache" not in h1
    _, b2, h2 = fetch(ng.port, "/cc/ccnostore")
    assert "x-cache" not in h2, "Cache-Control: no-store must not be cached"
    assert b1 != b2


def test_no_cache_authorization(ng: Nginx) -> None:
    """RFC 9111 floor: a request carrying Authorization yields a per-user
    response that must not be stored in or served from the shared cache,
    including when an anonymous representation was already primed."""
    hdr = {"Authorization": "Bearer secrettoken"}

    # Prime an anonymous representation first. A store-only Authorization guard
    # misses this case and would replay the anonymous HIT to the credentialed
    # request.
    _, anon, _ = fetch(ng.port, "/c/authreq-primed")
    _, anon_hit, hp = fetch(ng.port, "/c/authreq-primed")
    assert hp.get("x-cache") == "HIT" and anon_hit == anon
    _, auth_body, ha = fetch(ng.port, "/c/authreq-primed", headers=hdr)
    assert "x-cache" not in ha, \
        "Authorization request was served a primed anonymous cache entry"
    assert auth_body != anon, "authorized request did not reach the origin"

    # A cold authorized request must also remain uncacheable.
    _, b1, h1 = fetch(ng.port, "/c/authreq-cold", headers=hdr)
    assert "x-cache" not in h1
    _, b2, h2 = fetch(ng.port, "/c/authreq-cold", headers=hdr)
    assert "x-cache" not in h2, "Authorization request must not be cached"
    assert b1 != b2


def test_default_key_varies_by_host(ng: Nginx) -> None:
    """Default key (no cache_turbo_key) is $host$request_uri: the same path
    under two Host headers must NOT collide (cross-vhost poisoning guard)."""
    s1, b1, h1 = fetch(ng.port, "/dk/hostvary", headers={"Host": "a.example"})
    assert s1 == 200 and "x-cache" not in h1, "first read should be a miss"
    _, b2, h2 = fetch(ng.port, "/dk/hostvary", headers={"Host": "a.example"})
    assert h2.get("x-cache") == "HIT" and b2 == b1, "same Host should HIT"
    _, b3, h3 = fetch(ng.port, "/dk/hostvary", headers={"Host": "b.example"})
    assert "x-cache" not in h3, "different Host must not collide"
    assert b3 != b1, "second Host served the first Host's cached body"


def test_admin_purge_post_with_body(ng: Nginx) -> None:
    """A purge POST carrying a request body must succeed (the handler discards
    the body) — otherwise the unread bytes would desync a keepalive socket."""
    import json
    fetch(ng.port, "/c/bodypurge")                     # miss -> cached
    _, _, h = fetch(ng.port, "/c/bodypurge")
    assert h.get("x-cache") == "HIT", "should be cached before purge"
    req = urllib.request.Request(
        f"http://127.0.0.1:{ng.port}/_cache?key=/c/bodypurge",
        data=b"x" * 256, method="POST",
        headers={"Connection": "close"})
    _bump_conn()
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
        assert r.status == 200, f"purge-with-body status {r.status}"
        assert json.loads(r.read())["purged"] == 1
    _, _, h2 = fetch(ng.port, "/c/bodypurge")
    assert "x-cache" not in h2, "entry should be gone after purge (a MISS)"


def test_default_key_normalizes(ng: Nginx) -> None:
    """The default key (no cache_turbo_key) is $host$uri$cache_turbo_normalized_args,
    so tracking params and the built-in sid/sessionid are stripped: a junk-laden
    URL shares the clean slot."""
    _, b1, h1 = fetch(ng.port, "/dk/norm?utm_source=x&sid=42&sessionid=abc")
    assert "x-cache" not in h1, "first should miss"
    _, b2, h2 = fetch(ng.port, "/dk/norm")
    assert h2.get("x-cache") == "HIT" and b2 == b1, \
        "default key should strip tracking + sid/sessionid to one slot"


def test_cache_redirect(ng: Nginx) -> None:
    """v6: a 301 (empty body) is cached and replayed with its Location intact."""
    s1, _, h1 = fetch_raw(ng.port, "/st/redir")
    assert s1 == 301 and "x-cache" not in h1, f"first 301 should miss: {s1} {h1}"
    loc1 = h1.get("location")
    s2, _, h2 = fetch_raw(ng.port, "/st/redir")
    assert s2 == 301 and h2.get("x-cache") == "HIT", \
        f"second 301 should be a HIT: {s2} {h2.get('x-cache')}"
    assert h2.get("location") == loc1, \
        f"Location not preserved on cached 301: {h2.get('location')} vs {loc1}"


def test_cache_negative_404(ng: Nginx) -> None:
    """v6: a 404 is cached (negative caching) — the body is preserved on HIT."""
    s1, b1, h1 = fetch_raw(ng.port, "/st/notfound")
    assert s1 == 404 and "x-cache" not in h1, f"first 404 should miss: {s1}"
    s2, b2, h2 = fetch_raw(ng.port, "/st/notfound")
    assert s2 == 404 and h2.get("x-cache") == "HIT", "second 404 should HIT"
    assert b1 == b2 and b2, f"404 body not preserved: {b1!r} vs {b2!r}"


def test_head_not_stored(ng: Nginx) -> None:
    """v6: a HEAD must never populate the cache as the GET entry — the following
    GET is still a MISS (and then caches normally)."""
    sh, _, hh = fetch_raw(ng.port, "/c/headonly", method="HEAD")
    assert sh == 200, f"HEAD status {sh}"
    assert "x-cache" not in hh, "HEAD should not be served from cache here"
    _, _, h1 = fetch_raw(ng.port, "/c/headonly", method="GET")
    assert "x-cache" not in h1, "GET after HEAD should still be a MISS"
    _, _, h2 = fetch_raw(ng.port, "/c/headonly", method="GET")
    assert h2.get("x-cache") == "HIT", "GET should cache normally after the HEAD"


def test_honor_cache_control(ng: Nginx) -> None:
    """v7: with cache_turbo_cache_control honor, the origin's max-age=1 shortens
    the fresh TTL below the configured 60s — so the entry is stale at ~2s."""
    _, _, h0 = fetch(ng.port, "/cc7/ttl1")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/cc7/ttl1")
    assert h1.get("x-cache") == "HIT", "second should be a fresh HIT (<1s)"
    time.sleep(2.0)                               # past max-age=1, within stale
    _, _, h2 = fetch(ng.port, "/cc7/ttl1")
    assert h2.get("x-cache") == "STALE", \
        ("honor_cache_control: entry should be STALE at 2s (max-age=1 < 60s), "
         f"got {h2.get('x-cache')}")


def test_honor_expires_absolute_ttl(ng: Nginx) -> None:
    """upstream_ttl ladder step 4 (module.c Expires branch): a response with NO
    Cache-Control/CDN-CC/Surrogate-Control, only an absolute Expires ~2s out,
    must derive its fresh TTL from Expires-minus-now — NOT from the configured
    cache_turbo_valid 60s (which would keep it fresh). STALE at ~3.5s (past the
    2s Expires window, staleness >=1s so the 1s-granularity check is unambiguous)
    proves the Expires arm set the window."""
    _, _, h0 = fetch(ng.port, "/cc7/expabs")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/cc7/expabs")
    assert h1.get("x-cache") == "HIT", "second should be a fresh HIT (<2s)"
    time.sleep(3.5)                               # past the 2s Expires, staleness >=1s
    _, _, h2 = fetch(ng.port, "/cc7/expabs")
    assert h2.get("x-cache") == "STALE", \
        ("Expires-derived TTL (~2s) must win over cache_turbo_valid 60s: "
         f"entry should be STALE at ~3.5s, got {h2.get('x-cache')}")


def test_cdn_cache_control_ttl_outranks_cache_control(ng: Nginx) -> None:
    """RFC 9213: CDN-Cache-Control sets the shared-cache TTL and must OUTRANK the
    browser-facing Cache-Control. Origin: CC max-age=60, CDN-CC max-age=1 (via the
    /cc7/ honor location). The entry must be STALE at ~2s (the 1s CDN TTL won),
    not fresh (which the 60s CC would give)."""
    _, _, h0 = fetch(ng.port, "/cc7/cdnttl")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/cc7/cdnttl")
    assert h1.get("x-cache") == "HIT", "second should be a fresh HIT (<1s)"
    time.sleep(2.0)                               # past CDN max-age=1, within stale
    _, _, h2 = fetch(ng.port, "/cc7/cdnttl")
    assert h2.get("x-cache") == "STALE", \
        ("CDN-Cache-Control max-age=1 must outrank Cache-Control max-age=60: "
         f"entry should be STALE at 2s, got {h2.get('x-cache')}")


def test_surrogate_control_ttl_outranks_cdn_and_cache_control(ng: Nginx) -> None:
    """RFC 9213: Surrogate-Control (Fastly/Akamai) is the highest-priority TTL
    source, above CDN-Cache-Control and Cache-Control. Origin: SC max-age=1,
    CDN-CC max-age=60, CC max-age=60. STALE at ~2s proves SC's 1s won."""
    _, _, h0 = fetch(ng.port, "/cc7/scttl")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/cc7/scttl")
    assert h1.get("x-cache") == "HIT", "second should be a fresh HIT (<1s)"
    time.sleep(2.0)
    _, _, h2 = fetch(ng.port, "/cc7/scttl")
    assert h2.get("x-cache") == "STALE", \
        ("Surrogate-Control max-age=1 must outrank CDN-CC=60 and CC=60: entry "
         f"should be STALE at 2s, got {h2.get('x-cache')}")


def test_surrogate_control_split_header_ttl(ng: Nginx) -> None:
    """AUD2-CC-TARGETED: Surrogate-Control split across TWO field-lines
    (/cc7/scsplit) -- stale-while-revalidate=30 on the first, max-age=1 on the
    SECOND. header_find() only sees the first occurrence; a single-line TTL
    read would miss max-age entirely and fall through to Cache-Control's 60s,
    caching far longer than Surrogate-Control authorized. STALE at ~2s proves
    the second SC line's max-age=1 won, not CC's 60s."""
    _, _, h0 = fetch(ng.port, "/cc7/scsplit")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/cc7/scsplit")
    assert h1.get("x-cache") == "HIT", "second should be a fresh HIT (<1s)"
    time.sleep(2.0)                               # past SC max-age=1 (2nd line)
    _, _, h2 = fetch(ng.port, "/cc7/scsplit")
    assert h2.get("x-cache") == "STALE", \
        ("Surrogate-Control max-age on a later field-line must not be ignored: "
         f"entry should be STALE at 2s (SC max-age=1), got {h2.get('x-cache')} "
         "(a single-line reader would wrongly stay fresh on CC max-age=60)")


def test_cdn_cache_control_split_header_ttl(ng: Nginx) -> None:
    """AUD2-CC-TARGETED: CDN-Cache-Control split across TWO field-lines
    (/cc7/cdnsplit) -- stale-while-revalidate=30 on the first, max-age=1 on the
    SECOND. Same defect as scsplit but for ladder arm 2. STALE at ~2s proves
    the second CDN-CC line's max-age=1 won over Cache-Control's 60s."""
    _, _, h0 = fetch(ng.port, "/cc7/cdnsplit")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/cc7/cdnsplit")
    assert h1.get("x-cache") == "HIT", "second should be a fresh HIT (<1s)"
    time.sleep(2.0)                               # past CDN-CC max-age=1 (2nd line)
    _, _, h2 = fetch(ng.port, "/cc7/cdnsplit")
    assert h2.get("x-cache") == "STALE", \
        ("CDN-Cache-Control max-age on a later field-line must not be ignored: "
         f"entry should be STALE at 2s (CDN-CC max-age=1), got "
         f"{h2.get('x-cache')} (a single-line reader would wrongly stay fresh "
         "on CC max-age=60)")


def test_cdn_cache_control_no_store_refuses(ng: Nginx) -> None:
    """RFC 9213: a targeted CDN-Cache-Control: no-store must veto the shared store
    even though plain Cache-Control (max-age=60) would permit it. The /cc7/ honor
    location reads both; the response must never become a HIT."""
    _, _, h0 = fetch(ng.port, "/cc7/cdnnostore")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/cc7/cdnnostore")
    assert "x-cache" not in h1, \
        ("CDN-Cache-Control: no-store must refuse the shared store despite "
         f"Cache-Control max-age=60, got X-Cache={h1.get('x-cache')}")


def test_targeted_cache_control_stripped_from_serve(ng: Nginx) -> None:
    """RFC 9213: the shared cache is the intended consumer of CDN-Cache-Control /
    Surrogate-Control, so they must be stripped before store and never replayed to
    a downstream client on a HIT (same as the Age strip). Origin sends both on a
    cacheable response; the cached HIT must carry neither."""
    _, _, h0 = fetch(ng.port, "/cc7/cdnstrip")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/cc7/cdnstrip")
    assert h1.get("x-cache") == "HIT", f"second should be a HIT, got {h1}"
    assert "cdn-cache-control" not in h1, \
        "CDN-Cache-Control must be stripped from the served HIT"
    assert "surrogate-control" not in h1, \
        "Surrogate-Control must be stripped from the served HIT"


def test_age_header(ng: Nginx) -> None:
    """RFC 9111 5.1: a cache HIT carries an Age header counting seconds since the
    representation was stored. It must grow with wall-clock age."""
    _, _, h0 = fetch(ng.port, "/c/age-test")
    assert "x-cache" not in h0, "first should miss"
    time.sleep(1.2)
    _, _, h1 = fetch(ng.port, "/c/age-test")
    assert h1.get("x-cache") == "HIT", f"second should be a HIT, got {h1}"
    assert "age" in h1, "cache HIT must carry an Age header"
    age = int(h1["age"])
    assert age >= 1, f"Age should be >=1s after a 1.2s wait, got {age}"


def test_must_revalidate_split_header(ng: Nginx) -> None:
    """AUD-CC-FIRST-LINE: same must-revalidate collapse as test_must_revalidate,
    but the origin (/ccsplit/, splitmrev marker) emits max-age and
    must-revalidate on TWO separate Cache-Control field-lines. HTTP allows a
    field to repeat across field-lines (RFC 9110 SS5.3), equivalent to one
    comma-joined line -- a reader that only inspects the first Cache-Control
    line would miss the must-revalidate token on the second and wrongly
    stale-serve past freshness."""
    _, _, h0 = fetch(ng.port, "/ccsplit/splitmrev")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/ccsplit/splitmrev")
    assert h1.get("x-cache") == "HIT", f"second should be a fresh HIT, got {h1}"
    time.sleep(2.0)                               # past max-age=1
    _, _, h2 = fetch(ng.port, "/ccsplit/splitmrev")
    assert h2.get("x-cache") != "STALE", \
        ("must-revalidate on a later Cache-Control field-line must NOT be "
         f"ignored, got {h2.get('x-cache')}")
    assert "x-cache" not in h2, \
        "must-revalidate (2nd field-line) should re-fetch from origin once stale"


def test_request_no_cache(ng: Nginx, origin: Origin) -> None:
    """RFC 9111 5.2.1.4: a request Cache-Control: no-cache skips the stored copy
    and revalidates at the origin (the fresh response still refreshes the entry).
    Pragma: no-cache behaves the same."""
    _, b0, _ = fetch(ng.port, "/c/nocache-req")            # miss -> origin
    _, _, h1 = fetch(ng.port, "/c/nocache-req")
    assert h1.get("x-cache") == "HIT", "entry should be primed"
    before = origin.hits
    _, b2, h2 = fetch(ng.port, "/c/nocache-req",
                      headers={"Cache-Control": "no-cache"})
    assert "x-cache" not in h2, \
        f"request no-cache must reach origin, got X-Cache={h2.get('x-cache')}"
    assert origin.hits == before + 1, "request no-cache must consult the origin"
    assert b2 != b0, "no-cache response should be a fresh origin generation"
    _, _, h3 = fetch(ng.port, "/c/nocache-req",
                     headers={"Pragma": "no-cache"})
    assert "x-cache" not in h3, "Pragma: no-cache must also reach the origin"


def test_must_revalidate(ng: Nginx) -> None:
    """RFC 9111: a must-revalidate response is served fresh until its deadline
    then re-fetched — never stale-served. Same setup as /cc7/ (which DOES stale-
    serve), proving the must-revalidate token collapses the stale window."""
    _, _, h0 = fetch(ng.port, "/mrev/mustrev")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/mrev/mustrev")
    assert h1.get("x-cache") == "HIT", f"second should be a fresh HIT, got {h1}"
    time.sleep(2.0)                               # past max-age=1
    _, _, h2 = fetch(ng.port, "/mrev/mustrev")
    assert h2.get("x-cache") != "STALE", \
        f"must-revalidate must NOT stale-serve past freshness, got {h2.get('x-cache')}"
    assert "x-cache" not in h2, \
        "must-revalidate should re-fetch from origin once stale"


def test_proxy_revalidate(ng: Nginx) -> None:
    """RFC 9111: proxy-revalidate is the shared-cache synonym of must-revalidate
    and MUST collapse the stale window identically. Exercises the OR-arm of
    response_must_revalidate (module.c:1142) that must-revalidate alone leaves
    uncovered. Same /mrev/ location, "proxyrev" origin arm emits
    "max-age=1, proxy-revalidate"."""
    _, _, h0 = fetch(ng.port, "/mrev/proxyrev")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/mrev/proxyrev")
    assert h1.get("x-cache") == "HIT", f"second should be a fresh HIT, got {h1}"
    time.sleep(2.0)                               # past max-age=1
    _, _, h2 = fetch(ng.port, "/mrev/proxyrev")
    assert h2.get("x-cache") != "STALE", \
        f"proxy-revalidate must NOT stale-serve past freshness, got {h2.get('x-cache')}"
    assert "x-cache" not in h2, \
        "proxy-revalidate should re-fetch from origin once stale"


def test_precise_maxage_token_parse(ng: Nginx) -> None:
    """Full-token Cache-Control parse: max-age=01000 is 1000s (cacheable), it must
    NOT trip the old substring 'max-age=0' uncacheable check; max-age=0 is still
    refused."""
    _, _, h0 = fetch(ng.port, "/cc/ccpad")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/cc/ccpad")
    assert h1.get("x-cache") == "HIT", \
        f"max-age=01000 must be cacheable (1000s), got X-Cache={h1.get('x-cache')}"

    fetch(ng.port, "/cc/ccmaxage0")                        # prime attempt
    _, _, h2 = fetch(ng.port, "/cc/ccmaxage0")
    assert "x-cache" not in h2, "max-age=0 must not be stored in a shared cache"


def test_ignore_cache_control_overrides_floor(ng: Nginx, origin: Origin) -> None:
    """cache_turbo_cache_control ignore makes the response Cache-Control floor
    a no-op: a max-age=0 response (the ccmaxage0 marker) that /cc/ refuses to
    store is STORED under /ccign/ and served as a HIT at cache_turbo_valid.
    Mirrors nginx `proxy_ignore_headers Cache-Control`. The Set-Cookie floor is
    unaffected (covered by the /cc/ccsetcookie case)."""
    fetch(ng.port, "/ccign/ccmaxage0")                     # prime (miss, stores)
    _, _, h = fetch(ng.port, "/ccign/ccmaxage0")
    assert h.get("x-cache") == "HIT", \
        ("ignore_cache_control must store a max-age=0 response and HIT; got "
         f"X-Cache={h.get('x-cache')}")


def test_ignore_cc_must_revalidate_keeps_stale_window(ng: Nginx,
                                                      origin: Origin) -> None:
    """cache_turbo_cache_control ignore must neutralise the WHOLE response
    Cache-Control, including the must-revalidate token that would otherwise
    collapse the stale window at store. The origin emits
    "max-age=1, must-revalidate"; under /ccignmr/ (ignore_cc on, valid 2s, default
    stale_mult 4 => 8s total serve life = 2s fresh + 6s stale) the entry must
    still be STALE-served at ~4s. Without the fix (must-revalidate parsed despite
    ignore_cc) the serve deadline collapses to the 2s fresh deadline and the 4s
    read is a hard miss to origin. Inverse of test_must_revalidate (the /mrev/
    honor_cc case).

    !! The 2s fresh TTL is deliberate and paired with the 4s sleep below; see
    the /ccignmr/ fixture comment. Do not shrink either one independently."""
    uri = "/ccignmr/mustrev"
    fetch(ng.port, uri)                                    # prime (miss, stores)
    _, _, h1 = fetch(ng.port, uri)
    assert h1.get("x-cache") == "HIT", \
        f"ignore_cc must store the must-revalidate response; got {h1.get('x-cache')}"
    time.sleep(4.0)                                        # past 2s fresh, < 8s deadline
    before = origin.hits
    _, _, h2 = fetch(ng.port, uri)
    assert h2.get("x-cache") == "STALE", \
        ("ignore_cc must keep the stale window (must-revalidate ignored): expected "
         f"STALE at 4s, got X-Cache={h2.get('x-cache')} — window was collapsed")
    assert origin.hits == before, \
        "stale serve under ignore_cc unexpectedly hit origin (window collapsed?)"


def test_hits_for_exact_beyond_ring_size(ng: Nginx, origin: Origin) -> None:
    """hits_for() must be an EXACT per-path count, not an approximation that
    degrades once a window spans more than 64 origin contacts.

    Origin._paths is a diagnostics-only ring hard-trimmed to the last 64
    entries (do_GET/do_POST: `if len(origin._paths) > 64: del
    origin._paths[:-64]`; do_HEAD counts but does not append) for
    _recent_memo_skips()/the SUITE-1 dump. Before
    hits_for() was backed by a real Counter, it summed that ring directly, so
    any window driving more than 64 TOTAL origin contacts (this path or any
    other -- the ring is global, not per-path) silently undercounted: the
    oldest hits on THIS path fall off the ring the moment other traffic pushes
    the ring past 64 entries.

    This drives 80 direct GETs at the origin on one unique path (bypassing
    nginx entirely -- we're proving a property of the Origin test double
    itself, not the module) inside one window, i.e. 16 more contacts than the
    ring can hold, and asserts the exact delta. Under the old ring-summing
    implementation the delta reads <= 64 (16 short); under the Counter it is
    exactly 80."""
    needle = "hitsforring-" + uuid.uuid4().hex[:8]
    path = f"/{needle}"
    base = origin.hits_for(needle)
    n_contacts = 80
    assert n_contacts > 64, "control requires more contacts than the ring holds"
    # Borrow the delay to zero: 80 serial GETs at the suite's 0.05s baseline
    # would add ~4s to every full-suite run, and nothing here depends on a
    # regeneration window. Restored via reset_delay() in the finally, NOT to a
    # hardcoded 0.0 -- see reset_delay()'s docstring for the SUITE-8 bug that
    # shipped from exactly that mistake.
    origin.delay = 0
    try:
        for _ in range(n_contacts):
            status, _, _ = fetch(origin.port, path)
            assert status == 200, f"origin direct GET failed: status={status}"
    finally:
        origin.reset_delay()
    delta = origin.hits_for(needle) - base
    assert delta == n_contacts, (
        f"hits_for({needle!r}) delta must be exact: expected {n_contacts}, got "
        f"{delta}. A delta <= 64 means hits_for() is summing the trimmed "
        "diagnostics ring instead of a real per-path counter.")


def test_valid_zero_is_forever(ng: Nginx, origin: Origin) -> None:
    """cache_turbo_valid 0 == "cache forever": the stored entry must stay FRESH
    (a HIT), not become instantly stale. Pre-fix a literal 0 fresh TTL made the
    very next request a STALE serve and broke L2; now it resolves to a long
    finite TTL and behaves as a normal long-lived HIT."""
    # Path-scoped, NOT origin.hits: the global counter sees every other test's
    # traffic (and async bg-refresh subrequests) landing between the base capture
    # and the assertion below, which fails an equality bound that has nothing to
    # do with this location. That is a real failure mode, not a hypothetical --
    # it took down the ASan multi-worker arm on 28ae802 (SUITE-3), the slowest arm
    # and so the one with the widest window. Same fix as test_206_never_cached and
    # test_honor_ttl_clamped_to_max directly below.
    #
    # /!\ The needle is in the FILENAME, not the location prefix. /forever/ uses
    # `proxy_pass http://.../;` WITH a trailing slash, so nginx strips the prefix
    # and the origin only ever sees "/forever-f" -- hits_for("/forever/") matches
    # nothing and the assertion fails with the entry behaving perfectly. Same trap
    # as the /l2sie/ fixture (s121). This is why ttlclamp works: its needle is the
    # filename too.
    base = origin.hits_for("forever-f")
    _, b0, h0 = fetch(ng.port, "/forever/forever-f")
    assert "x-cache" not in h0, "first should miss to origin"
    _, b1, h1 = fetch(ng.port, "/forever/forever-f")
    assert h1.get("x-cache") == "HIT", \
        f"valid 0 must serve a FRESH HIT, got X-Cache={h1.get('x-cache')}"
    assert b1 == b0, "HIT served a different body"
    time.sleep(2.0)
    _, b2, h2 = fetch(ng.port, "/forever/forever-f")
    assert h2.get("x-cache") == "HIT", \
        f"valid 0 must still be fresh after a delay, got X-Cache={h2.get('x-cache')}"
    assert b2 == b0, "the 'forever' entry served a different body after the delay"
    assert origin.hits_for("forever-f") == base + 1, \
        "a 'forever' entry must not re-hit the origin while fresh"


def test_honor_ttl_clamped_to_max(ng: Nginx, origin: Origin) -> None:
    """STAB-5 TTL clamp (module.c:4873): honor mode reads an unbounded upstream
    max-age (~3170 years, > TTL_MAX 0xFFFFFFFF). The clamp caps it before the
    uint32 fresh_ttl cast and the stale-window multiply; without the clamp those
    could overflow/wrap the fresh window to a small or instantly-stale value.
    Observable proof: the entry stays a FRESH HIT (no re-hit to origin) rather
    than going stale — a wrapped TTL would surface as a STALE serve here."""
    base = origin.hits_for("ttlclamp")           # path-scoped: immune to bg-refresh noise
    _, _b0, h0 = fetch(ng.port, "/cc7/ttlclamp")
    assert "x-cache" not in h0, "first should miss to origin"
    _, _b1, h1 = fetch(ng.port, "/cc7/ttlclamp")
    assert h1.get("x-cache") == "HIT", \
        f"clamped huge max-age must serve a FRESH HIT, got {h1.get('x-cache')}"
    time.sleep(2.0)
    _, _b2, h2 = fetch(ng.port, "/cc7/ttlclamp")
    assert h2.get("x-cache") == "HIT", \
        ("clamped max-age must still be fresh after a delay (no overflow-to-stale), "
         f"got {h2.get('x-cache')}")
    assert origin.hits_for("ttlclamp") == base + 1, \
        "a TTL_MAX-clamped entry must not re-hit the origin while fresh"


def test_vary_encoding_qvalue(ng: Nginx, origin: Origin) -> None:
    """Accept-Encoding is tokenised, not substring-matched: `gzip;q=0` (the client
    REFUSES gzip) must NOT bucket as gzip, while `gzip;q=0.001` still does. Pre-fix
    the substring scan re-keyed a never-gzip client onto a gzip body."""
    base = origin.hits
    _, bg, hg = fetch(ng.port, "/ve/q", headers={"Accept-Encoding": "gzip"})
    assert "x-cache" not in hg, "first (gzip) request should miss"
    # gzip;q=0 => client refuses gzip => identity bucket => SEPARATE slot (miss)
    _, bz, hz = fetch(ng.port, "/ve/q",
                      headers={"Accept-Encoding": "gzip;q=0"})
    assert "x-cache" not in hz, \
        f"gzip;q=0 must NOT hit the gzip slot, got X-Cache={hz.get('x-cache')}"
    assert bz != bg, "gzip;q=0 was served the gzip body"
    assert origin.hits == base + 2, "gzip and gzip;q=0 should be distinct slots"
    # a positive q (even tiny) is still gzip => HIT the original gzip slot
    _, bq, hq = fetch(ng.port, "/ve/q",
                      headers={"Accept-Encoding": "gzip;q=0.001"})
    assert hq.get("x-cache") == "HIT", \
        f"gzip;q=0.001 must HIT the gzip slot, got X-Cache={hq.get('x-cache')}"
    assert bq == bg, "gzip;q=0.001 should share the gzip slot"
    assert origin.hits == base + 2, "gzip;q=0.001 wrongly hit origin"


def test_auto_vary_unknown_axis_uncacheable(ng: Nginx, origin: Origin) -> None:
    """auto-Vary: a response `Vary: Accept-Charset` names an axis the whitelist
    cannot key on (and is not *, Cookie, or Authorization). It must force the
    response uncacheable rather than serve one representation for every value
    (RFC 9110 12.5.5)."""
    base = origin.hits_for("/u?v=cs")
    _, _, h0 = fetch(ng.port, "/av/u?v=cs")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/av/u?v=cs")
    assert "x-cache" not in h1, \
        f"Vary on an un-keyable axis must stay uncacheable, got {h1.get('x-cache')}"
    assert origin.hits_for("/u?v=cs") == base + 2, "un-keyable Vary axis was wrongly cached"


def test_auto_vary_stale_marker_reachable(ng: Nginx, origin: Origin) -> None:
    """auto-Vary: once the variant and its L1 vary marker go stale (but are still
    inside the stale window), a request must still resolve to the variant via the
    stale marker and serve it from cache — not fall back to the base key and miss
    to origin (codex follow-up)."""
    ae = {"Accept-Encoding": "gzip"}
    _, _, h0 = fetch(ng.port, "/avs/m?v=ae", headers=ae)
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/avs/m?v=ae", headers=ae)
    assert h1.get("x-cache") == "HIT", f"second should HIT, got {h1.get('x-cache')}"
    time.sleep(2.5)                          # past the 2s fresh TTL, inside stale
    _, _, h2 = fetch(ng.port, "/avs/m?v=ae", headers=ae)
    assert "x-cache" in h2, \
        ("a stale-but-serveable variant must stay reachable via its stale marker, "
         f"got X-Cache={h2.get('x-cache')} (base-key fallback missed to origin)")


def test_206_never_cached(ng: Nginx, origin: Origin) -> None:
    """206 Partial Content must never be cached: the key carries no Range, so a
    stored partial could be replayed for a different/whole range. Every request
    reaches the origin.

    Uses a unique URL ("partial" substring still triggers the 206 branch) and a
    path-scoped hit count so a prior test's async background_update refresh can
    bump the global origin counter without polluting this exact-count assert
    (the historical CI flake)."""
    url = "/c/partial-206flake"
    base = origin.hits_for("partial-206flake")
    s0, _, h0 = fetch(ng.port, url)
    assert s0 == 206, f"origin should answer 206, got {s0}"
    assert "x-cache" not in h0, "first 206 should miss"
    s1, _, h1 = fetch(ng.port, url)
    assert s1 == 206 and "x-cache" not in h1, \
        f"206 must never be cached, got X-Cache={h1.get('x-cache')}"
    assert origin.hits_for("partial-206flake") == base + 2, \
        "206 was wrongly served from cache"


def test_range_hit_matches_miss(ng: Nginx, origin: Origin) -> None:
    """AUD-RANGE1: r->allow_ranges was never set on the restore/HIT path, so a
    Range request against a cached (<= max_size) entry silently fell back to a
    full 200 instead of the 206 a MISS to the same Range-capable origin
    returns. Warm one URL (plain GET, MISS, stores), then Range-GET it (HIT)
    and compare against Range-GET-ing a NEVER-cached URL (a fresh MISS that
    reaches the Range-capable origin directly) -- status, Content-Range and
    body bytes must match."""
    range_hdr = {"Range": "bytes=0-99"}

    # MISS reference: a URL never requested before, fetched WITH the Range
    # header. cache-turbo has nothing cached for it, so this reaches the
    # Range-capable origin directly and its 206 is relayed verbatim.
    s_miss, b_miss, h_miss = fetch_raw(ng.port, "/range/rngsrc-miss",
                                       headers=range_hdr)
    assert s_miss == 206, f"MISS with Range should be 206, got {s_miss}"
    assert "x-cache" not in h_miss, f"reference fetch should not HIT: {h_miss}"
    assert h_miss.get("content-range"), "MISS 206 must carry Content-Range"

    # Warm a SEPARATE url with a plain GET (no Range) so it gets cached as a
    # normal 200, Accept-Ranges: bytes included (the origin always sends it).
    s0, _, h0 = fetch_raw(ng.port, "/range/rngsrc-warm")
    assert s0 == 200 and "x-cache" not in h0, f"prime should miss: {s0} {h0}"
    assert h0.get("accept-ranges") == "bytes", \
        f"origin should advertise Accept-Ranges: {h0}"

    # Now Range-GET the warmed URL: cache-turbo serves it from cache (HIT).
    s_hit, b_hit, h_hit = fetch_raw(ng.port, "/range/rngsrc-warm",
                                    headers=range_hdr)
    assert h_hit.get("x-cache") == "HIT", f"second fetch should HIT: {h_hit}"
    assert s_hit == 206, \
        f"a Range request against a cache-turbo HIT must answer 206 like a " \
        f"MISS does, got {s_hit} (Accept-Ranges was replayed but the range " \
        f"was not honoured)"
    assert s_hit == s_miss, f"HIT status {s_hit} != MISS status {s_miss}"
    assert h_hit.get("content-range") == h_miss.get("content-range"), \
        f"HIT Content-Range {h_hit.get('content-range')!r} != " \
        f"MISS Content-Range {h_miss.get('content-range')!r}"
    assert b_hit == b_miss, \
        f"HIT partial body {b_hit!r} != MISS partial body {b_miss!r}"
    assert len(b_hit) == 100, f"bytes=0-99 should be 100 bytes, got {len(b_hit)}"


def test_range_suffix_hit_matches_miss(ng: Nginx, origin: Origin) -> None:
    """AUD-RANGE1, suffix form. test_range_hit_matches_miss covers only the
    prefix form (bytes=0-99). A suffix range (bytes=-N = the LAST N bytes) takes
    a different path through core's range parser, and the module's allow_ranges
    permit at module.c:6563 is what lets core answer it at all on a HIT. Same
    HIT-must-equal-MISS oracle: warm one URL with a plain GET, then suffix-Range
    it (HIT) and compare against suffix-Range-ing a never-cached URL (MISS).

    The comparison is against a MISS rather than a hardcoded expectation on
    purpose -- it pins HIT to whatever core+origin genuinely do for a suffix
    range, so this cannot pass by both paths being wrong the same way."""
    range_hdr = {"Range": "bytes=-50"}

    s_miss, b_miss, h_miss = fetch_raw(ng.port, "/range/rngsrc-sfxmiss",
                                       headers=range_hdr)
    assert s_miss == 206, f"MISS with suffix Range should be 206, got {s_miss}"
    assert "x-cache" not in h_miss, f"reference fetch should not HIT: {h_miss}"

    s0, _, h0 = fetch_raw(ng.port, "/range/rngsrc-sfxwarm")
    assert s0 == 200 and "x-cache" not in h0, f"prime should miss: {s0} {h0}"

    s_hit, b_hit, h_hit = fetch_raw(ng.port, "/range/rngsrc-sfxwarm",
                                    headers=range_hdr)
    assert h_hit.get("x-cache") == "HIT", f"second fetch should HIT: {h_hit}"
    assert s_hit == 206, \
        f"a suffix Range against a HIT must answer 206 like a MISS does, " \
        f"got {s_hit}"
    assert h_hit.get("content-range") == h_miss.get("content-range"), \
        f"HIT Content-Range {h_hit.get('content-range')!r} != " \
        f"MISS Content-Range {h_miss.get('content-range')!r}"
    assert b_hit == b_miss, \
        f"HIT suffix body {b_hit!r} != MISS suffix body {b_miss!r}"
    # The LAST 50 bytes, not the first 50: a mis-sliced suffix that still
    # returned 50 bytes would pass a length-only assert.
    assert len(b_hit) == 50, f"bytes=-50 should be 50 bytes, got {len(b_hit)}"
    assert h_hit.get("content-range") == "bytes 150-199/200", \
        f"bytes=-50 of a 200-byte body is 150-199, got " \
        f"{h_hit.get('content-range')!r}"


def test_range_unsatisfiable_hit_matches_miss(ng: Nginx,
                                              origin: Origin) -> None:
    """A Range wholly past the end of a cached body must be refused with a real
    416 response.

    Found a live defect. ngx_http_cache_turbo_serve() did:

        if (ngx_http_send_header(r) != NGX_OK) { return NGX_ERROR; }

    but a header filter may return a STATUS CODE, not just NGX_OK/NGX_ERROR:
    ngx_http_range_header_filter answers an unsatisfiable Range with
    NGX_HTTP_RANGE_NOT_SATISFIABLE (416), expecting the caller to finalize it
    into a 416. Collapsing that into NGX_ERROR produced
    ngx_http_finalize_request(r, -1) -- observed as the connection being CLOSED
    WITH NO RESPONSE AT ALL, while the same request against a MISS answered
    normally. Fixed to mirror the core contract in ngx_http_upstream.c
    (`rc == NGX_ERROR || rc > NGX_OK` -> finalize with rc).

    ⚠ This does NOT compare HIT against MISS, unlike its sibling Range tests.
    The test origin ignores an unsatisfiable Range and answers 200 with the full
    body, so a MISS here is a FIXTURE artifact, not the contract -- asserting
    HIT == MISS would pin the module to the stub origin's behaviour. 416 is
    asserted directly because it is what RFC 9110 6.5.4 requires and what core
    produces once the return value is honoured."""
    # The rngsrc body is 200 bytes, so bytes=500-599 cannot be satisfied.
    range_hdr = {"Range": "bytes=500-599"}

    s0, _, h0 = fetch_raw(ng.port, "/range/rngsrc-unsatwarm")
    assert s0 == 200 and "x-cache" not in h0, f"prime should miss: {s0} {h0}"

    s_hit, b_hit, _ = fetch_raw(ng.port, "/range/rngsrc-unsatwarm",
                                headers=range_hdr)
    assert s_hit == 416, \
        f"an unsatisfiable Range against a cached entry must answer 416, got " \
        f"{s_hit} (before the send_header fix this was not a wrong status but " \
        f"NO RESPONSE -- the connection was closed mid-request)"
    assert "200" not in b_hit[:200] or "416" in b_hit, \
        f"416 body should be the range-not-satisfiable page, got {b_hit[:120]!r}"

    # The entry must still be intact and servable after the refusal: a 416 is a
    # client error, not a reason to drop or poison the cached representation.
    s_after, b_after, h_after = fetch_raw(ng.port, "/range/rngsrc-unsatwarm")
    assert s_after == 200 and h_after.get("x-cache") == "HIT", \
        f"the cached entry must survive a 416, got {s_after} {h_after}"
    assert len(b_after) == 200, \
        f"the cached body must be intact after a 416, got {len(b_after)} bytes"


def test_range_not_offered_on_304(ng: Nginx, origin: Origin) -> None:
    """AUD-RANGE1, the exclusion. module.c:6563 sets r->allow_ranges only for a
    200 serve with a known length, deliberately NOT for the conditional-304
    branch immediately above it (a 304 has no body to range over, and
    header_only is already set). Nothing asserted that exclusion, so a future
    edit moving the permit above the 304 branch would be silent.

    A 304 carrying Accept-Ranges would invite a client to issue a Range request
    against a representation this response never delivered."""
    # The rngcond marker makes the Range-capable origin branch emit an ETag, so
    # this one key is both range-capable and revalidatable.
    url = "/range/rngsrc-rngcond-k1"
    s0, _, h0 = fetch_raw(ng.port, url)
    assert s0 == 200 and "x-cache" not in h0, f"prime should miss: {s0} {h0}"
    etag = h0.get("etag")
    assert etag == '"rngetag"', \
        f"fixture is wrong, not the module: rngcond must emit an ETag, got " \
        f"{etag!r}"

    # Positive half first, and it must depend on the PERMIT, not on the blob.
    # Accept-Ranges is replayed from the stored headers (the origin sent it), so
    # asserting that header would pass even with module.c:6563 deleted --
    # measured: it survived that exact mutation. Issuing a real Range and
    # requiring 206 is what the permit actually gates.
    s_hit, b_hit, h_hit = fetch_raw(ng.port, url,
                                    headers={"Range": "bytes=0-9"})
    assert h_hit.get("x-cache") == "HIT", f"ranged fetch should HIT: {h_hit}"
    assert s_hit == 206, \
        f"a cached 200 must be range-servable (the permit at module.c:6563), " \
        f"got {s_hit}"
    assert len(b_hit) == 10, f"bytes=0-9 should be 10 bytes, got {len(b_hit)}"

    s304, b304, h304 = fetch_raw(ng.port, url,
                                 headers={"If-None-Match": etag})
    assert s304 == 304, f"conditional against a HIT should be 304, got {s304}"
    assert b304 == "", f"a 304 must carry no body, got {b304!r}"
    assert "content-range" not in h304, \
        f"a 304 must never carry Content-Range: {h304}"


def test_range_on_sie_serve(ng: Nginx, origin: Origin) -> None:
    """AUD-RANGE1 on the STALE-IF-ERROR path. r->allow_ranges is set inside
    ngx_http_cache_turbo_restore_response() (module.c:6563), and
    sie_rewrite() (module.c:7104) calls that same function to replay a snapshot
    when the origin errors -- so a serve-on-error response is range-capable by
    construction. Only the live-HIT path was ever tested.

    This matters because sie_rewrite() rebuilds headers_out from scratch
    (ngx_list_init at module.c:7090). A future change to that rebuild that
    dropped Accept-Ranges, or that reordered the restore so the permit no longer
    ran, would regress Range on exactly the path a client is most likely to be
    retrying against.

    Fixture: /rangesie/ keys carry both the rngsrc marker (Range-capable body)
    and the rngsie marker (stale-if-error=30), so the entry can fully expire and
    still be replayed when the origin then 5xxs."""
    url = "/rangesie/rngsrc-rngsie-k1"
    range_hdr = {"Range": "bytes=0-99"}

    s0, _, h0 = fetch_raw(ng.port, url)
    assert s0 == 200 and "x-cache" not in h0, f"prime failed: {s0} {h0}"

    time.sleep(4.6)     # past fresh (1s) AND the stale window (x4 = 4s)
    origin.fail = True
    try:
        s, b, h = fetch_raw(ng.port, url, headers=range_hdr)
        assert h.get("x-cache") == "STALE-IF-ERROR", \
            f"expected a serve-on-error replay, got x-cache={h.get('x-cache')} " \
            f"status={s} (the fixture, not the Range, is wrong)"
        assert s == 206, \
            f"a Range against a STALE-IF-ERROR serve must answer 206 like a " \
            f"HIT does, got {s} -- the client asked for a slice and got the " \
            f"whole body"
        assert h.get("content-range") == "bytes 0-99/200", \
            f"Content-Range on the SIE serve is {h.get('content-range')!r}, " \
            f"expected bytes 0-99/200"
        assert len(b) == 100, f"bytes=0-99 should be 100 bytes, got {len(b)}"
        assert b == "R" * 100, \
            f"the SIE serve returned the wrong 100 bytes: {b!r}"
    finally:
        origin.fail = False
        drain_origin(origin)


def test_safe_key_distinct_sessionids(ng: Nginx, origin: Origin) -> None:
    """Raw-key migration (was cache_turbo_safe_key): an explicit
    cache_turbo_key $scheme$host$request_uri keeps the full raw query, so two
    distinct sessionid values get DISTINCT cache entries instead of aliasing onto
    one normalized key (which could serve user A's page to user B). The same
    sessionid still HITs its own entry."""
    base = origin.hits
    _, ba, ha = fetch(ng.port, "/safekey/p?sessionid=AAA")
    assert "x-cache" not in ha, "first (sessionid=AAA) should miss"
    _, bb, hb = fetch(ng.port, "/safekey/p?sessionid=BBB")
    assert "x-cache" not in hb, \
        f"a different sessionid must NOT alias, got X-Cache={hb.get('x-cache')}"
    assert bb != ba, "two sessionids shared one cache entry (cross-user leak)"
    assert origin.hits == base + 2, "the two sessionids should each reach origin"
    _, ba2, ha2 = fetch(ng.port, "/safekey/p?sessionid=AAA")
    assert ha2.get("x-cache") == "HIT" and ba2 == ba, \
        "the same sessionid must HIT its own entry"



def test_conditional_inm_304(ng: Nginx, origin: Origin) -> None:
    """v11: a HIT whose stored ETag matches If-None-Match is answered 304 with no
    body, served from cache (the origin is not hit again)."""
    s0, _, h0 = fetch_raw(ng.port, "/cond/cond-inm")
    assert s0 == 200 and "x-cache" not in h0, f"prime should miss: {s0} {h0}"
    assert h0.get("etag") == '"v11etag"', f"etag not surfaced: {h0.get('etag')}"
    before = origin.hits_for("cond-inm")
    s1, b1, h1 = fetch_raw(ng.port, "/cond/cond-inm",
                           headers={"If-None-Match": '"v11etag"'})
    assert s1 == 304, f"matching If-None-Match should be 304, got {s1}"
    assert b1 == "", f"304 must have no body, got {b1!r}"
    assert h1.get("x-cache") == "HIT", f"304 should be a cache HIT: {h1}"
    assert origin.hits_for("cond-inm") == before, "304 must be served from cache, not origin"


def test_conditional_inm_list_short_first(ng: Nginx, origin: Origin) -> None:
    """COR-11: an If-None-Match LIST whose FIRST tag is shorter than the cached
    ETag must still match a later equal tag — the parser skips to the next comma
    instead of bailing on the whole header."""
    s0, _, h0 = fetch_raw(ng.port, "/cond/cond-list")
    assert s0 == 200 and h0.get("etag") == '"v11etag"', f"prime: {s0} {h0}"
    before = origin.hits_for("cond-list")
    s1, b1, h1 = fetch_raw(ng.port, "/cond/cond-list",
                           headers={"If-None-Match": '"x", "v11etag"'})
    assert s1 == 304, f"a later matching tag must 304, got {s1}"
    assert b1 == "", f"304 must have no body, got {b1!r}"
    assert h1.get("x-cache") == "HIT" and origin.hits_for("cond-list") == before, \
        "304 from the list must be served from cache"


def test_conditional_inm_star(ng: Nginx) -> None:
    """v11: If-None-Match: * matches any cached representation -> 304."""
    fetch_raw(ng.port, "/cond/cond-star")                          # prime
    s, b, h = fetch_raw(ng.port, "/cond/cond-star",
                        headers={"If-None-Match": "*"})
    assert s == 304 and b == "", f"INM '*' should be 304/no-body: {s} {b!r}"
    assert h.get("x-cache") == "HIT"


def test_conditional_inm_mismatch_full(ng: Nginx) -> None:
    """v11: a non-matching If-None-Match serves the full cached body (200 HIT)."""
    _, b0, _ = fetch_raw(ng.port, "/cond/cond-miss")               # prime
    s, b, h = fetch_raw(ng.port, "/cond/cond-miss",
                        headers={"If-None-Match": '"other"'})
    assert s == 200, f"non-matching INM should be 200, got {s}"
    assert b == b0 and b, f"full body expected on mismatch: {b!r} vs {b0!r}"
    assert h.get("x-cache") == "HIT"


def test_conditional_ims_304(ng: Nginx) -> None:
    """v11: If-Modified-Since later than the stored Last-Modified -> 304."""
    fetch_raw(ng.port, "/cond/cond-ims")                           # prime (LM=2015-10-21)
    s, b, h = fetch_raw(ng.port, "/cond/cond-ims",
                        headers={"If-Modified-Since":
                                 "Thu, 22 Oct 2015 07:28:00 GMT"})
    assert s == 304 and b == "", f"IMS-after-LM should be 304: {s} {b!r}"
    assert h.get("x-cache") == "HIT"


def test_conditional_ims_old_full(ng: Nginx) -> None:
    """v11: If-Modified-Since earlier than Last-Modified means the client's copy
    is stale -> serve the full body (200 HIT), not 304."""
    _, b0, _ = fetch_raw(ng.port, "/cond/cond-imsold")             # prime
    s, b, h = fetch_raw(ng.port, "/cond/cond-imsold",
                        headers={"If-Modified-Since":
                                 "Tue, 20 Oct 2015 07:28:00 GMT"})
    assert s == 200, f"IMS-before-LM should be 200, got {s}"
    assert b == b0 and b, "full body expected when client copy is older"
    assert h.get("x-cache") == "HIT"


def test_conditional_inm_beats_ims(ng: Nginx) -> None:
    """v11 / RFC 7232 precedence: when both are present, If-None-Match decides.
    A matching INM yields 304 even though the IMS is older than Last-Modified."""
    fetch_raw(ng.port, "/cond/cond-prec")                          # prime
    s, b, _ = fetch_raw(ng.port, "/cond/cond-prec",
                        headers={"If-None-Match": '"v11etag"',
                                 "If-Modified-Since":
                                 "Tue, 20 Oct 2015 07:28:00 GMT"})
    assert s == 304 and b == "", \
        f"INM match must win over older IMS (304 expected): {s} {b!r}"


def test_rfc6_stale_conditional_full(ng: Nginx, origin: Origin) -> None:
    """RFC-6: a 304 may only be answered from a FRESH entry. Once the entry is
    stale (served while a refresh is pending) a conditional request gets the
    full 200 body, never a 304 from an unvalidated stale copy.

    /condst/ has a 1s TTL (shared with test_rfc1_request_max_stale and
    test_p4_multi_directive_single_resolve, which sleep past it to exercise the
    STALE path deliberately - do not widen it here). The fresh-conditional leg
    below must be primed and read back before that 1s elapses; on a loaded CI
    runner the two requests can straddle the boundary and the entry goes stale
    before the "fresh" leg is evaluated. That is an expired test precondition,
    not a product defect - retry with a fresh cache key (so a stale prior
    attempt's entry is never misread as this attempt's result), bounded.

    KNOWN SENSITIVITY COST: a real "entries go stale too early" regression (a
    TTL-computation bug shortening the effective window) produces the SAME
    200 + x-cache: STALE signature as a lost race, so it now has to reproduce on
    all 3 attempts to fail the build instead of failing on the first. Each
    swallowed attempt therefore prints a note rather than retrying silently -
    a run that logs these repeatedly across an UNLOADED runner is a product
    signal, not flake, and must be investigated rather than shrugged off.
    """
    last_fresh_state = None
    for attempt in range(3):
        key = f"/condst/cond-x-{attempt}"
        s0, _, h0 = fetch_raw(ng.port, key)                         # prime, fresh 1s
        assert s0 == 200 and h0.get("etag") == '"v11etag"', f"prime: {s0} {h0}"
        # while still fresh, a matching INM is a 304 (the existing fresh behaviour)
        sf, bf, hf = fetch_raw(ng.port, key,
                               headers={"If-None-Match": '"v11etag"'})
        if sf == 200 and hf.get("x-cache") == "STALE":
            # setup raced its own 1s TTL before the fresh leg could be read;
            # not a product failure - re-prime under a new key and retry.
            # Printed, never silent: see KNOWN SENSITIVITY COST above.
            print(f"    note: {key} went stale before the fresh conditional leg "
                  f"(attempt {attempt + 1}, age={hf.get('age')}); re-priming",
                  flush=True)
            last_fresh_state = (sf, bf, hf)
            continue
        assert sf == 304 and bf == "" and hf.get("x-cache") == "HIT", \
            f"fresh conditional should 304: {sf} {bf!r} {hf}"
        break
    else:
        raise AssertionError(
            "harness-timing precondition: /condst/ entry kept going stale "
            f"before the fresh conditional leg could run (last: {last_fresh_state})"
        )

    time.sleep(1.4)                                                # now stale
    s1, b1, h1 = fetch_raw(ng.port, key,
                           headers={"If-None-Match": '"v11etag"'})
    assert s1 == 200, f"stale conditional must serve full body, not 304: {s1}"
    assert b1, "stale conditional must carry the full body"
    assert h1.get("x-cache") == "STALE", \
        f"stale serve expected (beta 1, no refresh): {h1.get('x-cache')}"


def test_rfc3_date_stable_across_hits(ng: Nginx) -> None:
    """RFC-3: the Date emitted for a cached representation is stable across hits
    (it does not advance to "now" on every request) and Age tracks elapsed time
    consistently with it."""
    fetch_raw(ng.port, "/cond/date")                               # prime (miss)
    _, _, ha = fetch_raw(ng.port, "/cond/date")                    # HIT A
    assert ha.get("x-cache") == "HIT", f"second read should be a HIT: {ha}"
    assert ha.get("date"), "a cached HIT must carry a Date"
    age_a = int(ha.get("age", "0"))
    time.sleep(1.4)
    _, _, hb = fetch_raw(ng.port, "/cond/date")                    # HIT B (later)
    assert hb.get("x-cache") == "HIT", f"third read should be a HIT: {hb}"
    assert hb.get("date") == ha.get("date"), \
        f"Date must be stable across hits: {ha.get('date')} -> {hb.get('date')}"
    assert int(hb.get("age", "0")) > age_a, \
        f"Age must advance while Date holds: {age_a} -> {hb.get('age')}"


def test_rfc1_only_if_cached_miss_504(ng: Nginx, origin: Origin) -> None:
    """RFC-1 (§5.2.1.7): only-if-cached on a key in neither L1 nor L2 returns
    504 Gateway Timeout and never contacts the origin."""
    before = origin.hits
    s, _, _ = fetch_raw(ng.port, "/cond/oic-miss",
                        headers={"Cache-Control": "only-if-cached"})
    assert s == 504, f"only-if-cached miss must be 504, got {s}"
    assert origin.hits == before, "only-if-cached must not reach the origin"


def test_rfc1_only_if_cached_hit(ng: Nginx, origin: Origin) -> None:
    """RFC-1: only-if-cached is satisfied by a cache HIT (no origin contact)."""
    fetch_raw(ng.port, "/cond/oic-hit")                            # prime
    before = origin.hits
    s, b, h = fetch_raw(ng.port, "/cond/oic-hit",
                        headers={"Cache-Control": "only-if-cached"})
    assert s == 200 and b, f"only-if-cached HIT should serve the body: {s} {b!r}"
    assert h.get("x-cache") == "HIT" and origin.hits == before, \
        "only-if-cached HIT must be served from cache"


def test_rfc1_request_no_store(ng: Nginx, origin: Origin) -> None:
    """RFC-1 (§5.2.1.5): a request Cache-Control: no-store runs to the origin and
    its response is NOT stored — a following plain GET still misses."""
    before = origin.hits_for("/rns")
    s, _, h = fetch_raw(ng.port, "/cond/rns",
                        headers={"Cache-Control": "no-store"})
    assert s == 200, f"no-store request should still serve 200: {s}"
    assert "x-cache" not in h, "a no-store request is an origin miss, not a HIT"
    assert origin.hits_for("/rns") == before + 1, "no-store must reach the origin"
    # nothing was stored: the next plain GET is itself a miss (origin hit again)
    _s2, _, h2 = fetch_raw(ng.port, "/cond/rns")
    assert "x-cache" not in h2 and origin.hits_for("/rns") == before + 2, \
        f"no-store response must not have been cached: {h2}"


def test_rfc1_request_max_age_zero_revalidates(ng: Nginx, origin: Origin) -> None:
    """RFC-1 (§5.2.1.1): a request max-age=0 (browser force-refresh) forces a
    revalidation — the cached entry is bypassed to the origin and refreshed."""
    fetch_raw(ng.port, "/cond/ma0")                                # prime
    _, _, hhit = fetch_raw(ng.port, "/cond/ma0")
    assert hhit.get("x-cache") == "HIT", "entry should be cached before refresh"
    before = origin.hits_for("/ma0")
    s, _, h = fetch_raw(ng.port, "/cond/ma0",
                        headers={"Cache-Control": "max-age=0"})
    assert s == 200, f"max-age=0 should still serve 200: {s}"
    assert "x-cache" not in h, "max-age=0 must revalidate at origin, not HIT"
    assert origin.hits_for("/ma0") == before + 1, "max-age=0 must reach the origin"


def test_rfc1_request_max_age_n(ng: Nginx, origin: Origin) -> None:
    """RFC-1 (§5.2.1.1): request max-age=N rejects an entry older than N seconds
    (revalidate at origin); a generous N still HITs the same entry."""
    fetch_raw(ng.port, "/cond/man")                                # prime
    time.sleep(2.2)
    before = origin.hits_for("/man")
    _s0, _, h0 = fetch_raw(ng.port, "/cond/man",
                          headers={"Cache-Control": "max-age=30"})
    assert h0.get("x-cache") == "HIT" and origin.hits_for("/man") == before, \
        f"max-age=30 on a ~2s entry should HIT: {h0}"
    s1, _, h1 = fetch_raw(ng.port, "/cond/man",
                          headers={"Cache-Control": "max-age=1"})
    assert s1 == 200 and "x-cache" not in h1, \
        f"max-age=1 on a ~2s entry must revalidate at origin: {h1}"
    assert origin.hits_for("/man") == before + 1, "tight max-age must reach the origin"


def test_rfc1_request_min_fresh(ng: Nginx, origin: Origin) -> None:
    """RFC-1 (§5.2.1.3): request min-fresh=N rejects an entry that will not stay
    fresh for at least N more seconds."""
    fetch_raw(ng.port, "/cond/mf")                                 # prime, fresh 30s
    before = origin.hits_for("/mf")
    _s0, _, h0 = fetch_raw(ng.port, "/cond/mf",
                          headers={"Cache-Control": "min-fresh=5"})
    assert h0.get("x-cache") == "HIT" and origin.hits_for("/mf") == before, \
        f"min-fresh=5 with ~30s left should HIT: {h0}"
    s1, _, h1 = fetch_raw(ng.port, "/cond/mf",
                          headers={"Cache-Control": "min-fresh=600"})
    assert s1 == 200 and "x-cache" not in h1, \
        f"min-fresh=600 with ~30s left must revalidate: {h1}"
    assert origin.hits_for("/mf") == before + 1, "unmet min-fresh must reach the origin"


def test_rfc1_request_max_stale(ng: Nginx, origin: Origin) -> None:
    """RFC-1 (§5.2.1.2): on a stale entry, a client sending max-age WITHOUT
    max-stale gets a revalidation; adding max-stale re-permits the stale serve."""
    fetch_raw(ng.port, "/condst/cond-ms")                          # prime, fresh 1s
    time.sleep(1.5)                                                # now stale
    before = origin.hits_for("/cond-ms")
    # max-stale present -> accept the stale copy (beta 1, no refresh)
    s0, b0, h0 = fetch_raw(ng.port, "/condst/cond-ms",
                           headers={"Cache-Control": "max-age=1, max-stale=30"})
    assert s0 == 200 and b0 and h0.get("x-cache") == "STALE", \
        f"max-stale must permit the stale serve: {s0} {h0}"
    assert origin.hits_for("/cond-ms") == before, "max-stale stale serve must not hit origin"
    # same tight max-age but NO max-stale -> no stale tolerance -> revalidate
    s1, _, h1 = fetch_raw(ng.port, "/condst/cond-ms",
                          headers={"Cache-Control": "max-age=1"})
    assert s1 == 200 and "x-cache" not in h1, \
        f"max-age without max-stale must revalidate a stale entry: {h1}"
    assert origin.hits_for("/cond-ms") == before + 1, "no-max-stale revalidation must hit origin"


def test_p4_multi_directive_single_resolve(ng: Nginx, origin: Origin) -> None:
    """P4: the request Cache-Control header is resolved ONCE per request and read
    by every RFC-1 predicate (revalidate / only-if-cached / no-store / freshness
    bounds), instead of each predicate re-scanning the header list. Prove the one
    resolve feeds MULTIPLE predicates by exercising two different ones:

    (a) no-store predicate: a cold request with `Cache-Control: no-store, max-age=99`
        must reach origin AND not store the response, so the next plain GET is a
        MISS (origin hit again). This drives req_no_store off the same resolve
        that also parsed the max-age bound.
    (b) max-stale predicate: `Cache-Control: no-store, max-stale=30` on a stale
        entry serves the stale copy (max-stale honoured off the same resolve)."""
    # (a) no-store on a fresh cold key: not stored -> second GET re-hits origin.
    before = origin.hits_for("/p4-nostore")
    s0, _, _h0 = fetch_raw(ng.port, "/condst/p4-nostore",
                          headers={"Cache-Control": "no-store, max-age=99"})
    assert s0 == 200 and origin.hits_for("/p4-nostore") == before + 1, \
        f"no-store request must reach origin: {s0} hits={origin.hits_for('/p4-nostore')}"
    s1, _, h1 = fetch_raw(ng.port, "/condst/p4-nostore")           # plain GET
    assert s1 == 200 and h1.get("x-cache") != "HIT" \
        and origin.hits_for("/p4-nostore") == before + 2, \
        f"no-store must have suppressed storage -> second GET MISSes: {h1}"

    # (b) max-stale half of a combined directive on a stale entry.
    fetch_raw(ng.port, "/condst/p4-multi")                         # prime, fresh 1s
    time.sleep(1.5)                                                # now stale
    before = origin.hits_for("/p4-multi")
    s2, b2, h2 = fetch_raw(ng.port, "/condst/p4-multi",
                           headers={"Cache-Control": "no-store, max-stale=30"})
    assert s2 == 200 and b2 and h2.get("x-cache") == "STALE", (
        f"max-stale half of the combined directive must permit the stale "
        f"serve: {s2} {h2}")
    assert origin.hits_for("/p4-multi") == before, "combined-directive stale serve must not hit origin"


def test_rfc2_swr_duration_extends_stale(ng: Nginx, origin: Origin) -> None:
    """RFC-2: a response stale-while-revalidate=10 extends the stale window past
    the cache_turbo_stale_mult default (which would expire the 1s entry at ~4s),
    so the copy is still STALE-serveable at ~5s."""
    fetch_raw(ng.port, "/swrdur/swrdur-x")                         # prime, fresh 1s
    time.sleep(5)                                                  # > default 4s window
    before = origin.hits_for("/swrdur-x")
    s, b, h = fetch_raw(ng.port, "/swrdur/swrdur-x")
    assert s == 200 and b, f"SWR-extended entry should still serve: {s}"
    assert h.get("x-cache") == "STALE", \
        f"stale-while-revalidate must keep it serveable past the default: {h}"
    assert origin.hits_for("/swrdur-x") == before, "SWR stale serve (beta 1) must not hit origin"


def test_purge_method(ng: Nginx) -> None:
    """v14: a PURGE request drops that URI's entry; the next GET is a MISS."""
    import json
    fetch(ng.port, "/pg/x")                          # miss -> cached
    _, _, h = fetch(ng.port, "/pg/x")
    assert h.get("x-cache") == "HIT", "should be cached before PURGE"
    s, b, _ = fetch_raw(ng.port, "/pg/x", method="PURGE")
    assert s == 200, f"PURGE status {s}"
    assert json.loads(b)["purged"] == 1, f"purge count: {b}"
    _, _, h2 = fetch(ng.port, "/pg/x")
    assert "x-cache" not in h2, "entry should be gone after PURGE (a MISS)"


def test_cor5_l1only_variant_purge(ng: Nginx, origin: Origin) -> None:
    """COR-5 (L1-only): a PURGE of an auto-Vary base URI must invalidate EVERY
    variant, not just the base key. With no L2 backend the module bumps the
    marker generation, orphaning every old-generation variant. Two language
    variants are primed (HIT), then one PURGE of the base must make BOTH miss."""
    import json
    en = {"Accept-Language": "en"}
    fr = {"Accept-Language": "fr"}
    # prime + confirm two distinct, independently-cached variants
    _, en0, _ = fetch(ng.port, "/cor5l1/p?v=al", headers=en)
    _, en1, he1 = fetch(ng.port, "/cor5l1/p?v=al", headers=en)
    assert he1.get("x-cache") == "HIT" and en1 == en0, "en variant should cache"
    _, fr0, _ = fetch(ng.port, "/cor5l1/p?v=al", headers=fr)
    _, fr1, hf1 = fetch(ng.port, "/cor5l1/p?v=al", headers=fr)
    assert hf1.get("x-cache") == "HIT" and fr1 == fr0, "fr variant should cache"
    assert fr0 != en0, "en and fr must be distinct variant slots"
    # one PURGE of the base URI (no Accept-Language => base key)
    s, b, _ = fetch_raw(ng.port, "/cor5l1/p?v=al", method="PURGE")
    assert s == 200, f"PURGE status {s}"
    assert json.loads(b)["purged"] >= 1, f"purge should report >=1: {b}"
    # BOTH variants must now miss to origin (new bodies)
    _, en2, he2 = fetch(ng.port, "/cor5l1/p?v=al", headers=en)
    assert "x-cache" not in he2 and en2 != en0, \
        f"en variant survived PURGE: X-Cache={he2.get('x-cache')} body={en2!r}"
    _, fr2, hf2 = fetch(ng.port, "/cor5l1/p?v=al", headers=fr)
    assert "x-cache" not in hf2 and fr2 != fr0, \
        f"fr variant survived PURGE: X-Cache={hf2.get('x-cache')} body={fr2!r}"


def test_cor5_l1only_variant_purge_gen_wrap(ng: Nginx, origin: Origin) -> None:
    """AUD-GEN1: the L1-only auto-Vary purge marker's generation is a
    one-byte counter (module.c marker_store). The 256th PURGE of the same
    base used to wrap the stored byte back to 0 -- the value ALSO used by a
    never-purged base -- so a variant purged exactly 256 times could resolve
    back to whatever was still resident under the pre-purge/never-purged
    key and resurrect as a live HIT. Runs the base through a real 256-purge
    cycle (the wrap boundary) and asserts the variant is still a genuine
    MISS afterward, not a resurrected stale HIT."""
    import json
    en = {"Accept-Language": "en"}
    # prime one variant so a marker (gen=0) exists for this base.
    _, en0, _ = fetch(ng.port, "/cor5l1/gen?v=al", headers=en)
    _, en1, he1 = fetch(ng.port, "/cor5l1/gen?v=al", headers=en)
    assert he1.get("x-cache") == "HIT" and en1 == en0, "en variant should cache"
    # 256 PURGEs: #1..#255 bump the marker through the normal (non-wrapping)
    # range; #256 is the wrap (256 & 0xFF == 0, the defect boundary).
    for i in range(1, 257):
        s, b, _ = fetch_raw(ng.port, "/cor5l1/gen?v=al", method="PURGE")
        assert s == 200, f"PURGE #{i} status {s}"
        # Only #1 has a live variant to drop; #2.. bump the marker generation
        # with nothing resident, so they legitimately report 0. Assert the
        # count is present and well-formed rather than `>= 0`, which no
        # response can fail.
        purged = json.loads(b)["purged"]
        if i == 1:
            assert purged >= 1, f"PURGE #1 should drop the primed variant: {b}"
    # post-wrap: the variant must be a genuine MISS (fresh origin body), never
    # a HIT on the pre-purge #1 body that AUD-GEN1's wrap would resurrect.
    _, en2, he2 = fetch(ng.port, "/cor5l1/gen?v=al", headers=en)
    assert "x-cache" not in he2, \
        (f"AUD-GEN1: variant resolved as a HIT immediately after the 256th "
         f"PURGE (marker generation wrap) -- X-Cache={he2.get('x-cache')}")
    assert en2 != en0, \
        "AUD-GEN1: post-wrap body matches the pre-purge #1 body -- purged " \
        "variant resurrected"


def test_cor5_redis_variant_purge(ng: Nginx, origin: Origin,
                                  redis: RedisServer) -> None:
    """COR-5 (Redis-backed): a PURGE of an auto-Vary base URI must drop every
    variant from BOTH tiers via the per-base variant-index set (SADD at store,
    SMEMBERS+DEL at purge). Two language variants are primed (HIT), then one
    PURGE of the base must make both miss to origin."""
    import json
    en = {"Accept-Language": "en"}
    fr = {"Accept-Language": "fr"}
    _, en0, _ = fetch(ng.port, "/cor5/p?v=al", headers=en)
    _, en1, he1 = fetch(ng.port, "/cor5/p?v=al", headers=en)
    assert he1.get("x-cache") == "HIT" and en1 == en0, "en variant should cache"
    _, fr0, _ = fetch(ng.port, "/cor5/p?v=al", headers=fr)
    _, fr1, hf1 = fetch(ng.port, "/cor5/p?v=al", headers=fr)
    assert hf1.get("x-cache") == "HIT" and fr1 == fr0, "fr variant should cache"
    assert fr0 != en0, "en and fr must be distinct variant slots"
    s, b, _ = fetch_raw(ng.port, "/cor5/p?v=al", method="PURGE")
    assert s == 200, f"PURGE status {s}"
    # the index held 2 variant members
    assert json.loads(b)["purged"] >= 2, f"purge should report >=2 variants: {b}"
    _, en2, he2 = fetch(ng.port, "/cor5/p?v=al", headers=en)
    assert "x-cache" not in he2 and en2 != en0, \
        f"en variant survived PURGE: X-Cache={he2.get('x-cache')} body={en2!r}"
    _, fr2, hf2 = fetch(ng.port, "/cor5/p?v=al", headers=fr)
    assert "x-cache" not in hf2 and fr2 != fr0, \
        f"fr variant survived PURGE: X-Cache={hf2.get('x-cache')} body={fr2!r}"


def test_cache_and_purge_respect_access_control(ng: Nginx) -> None:
    """A cached GET and PURGE must run after allow/deny. Both locations share
    one cache key, proving the denied request cannot serve or delete the entry
    that the allowed location primed."""
    key = f"acl-{time.time_ns()}"
    seed = f"/acl-seed/x?k={key}"
    denied = f"/acl-denied/x?k={key}"

    _, body, _ = fetch(ng.port, seed)
    _, hit_body, hh = fetch(ng.port, seed)
    assert hh.get("x-cache") == "HIT" and hit_body == body, \
        "failed to prime shared access-control test entry"

    s, _, hd = fetch(ng.port, denied)
    assert s == 403, f"denied cached GET returned {s}, expected 403"
    assert "x-cache" not in hd, "denied GET was served from cache"

    s, _, _ = fetch_raw(ng.port, denied, method="PURGE")
    assert s == 403, f"denied PURGE returned {s}, expected 403"

    _, body_after, ha = fetch(ng.port, seed)
    assert ha.get("x-cache") == "HIT" and body_after == body, \
        "denied PURGE deleted the protected cache entry"


def test_bypass(ng: Nginx) -> None:
    """v9: cache_turbo_bypass skips the lookup (forces origin) but still stores,
    so a bypassing request refreshes the entry."""
    _, b0, h0 = fetch(ng.port, "/bp/x")
    assert "x-cache" not in h0, "first should miss"
    _, b1, h1 = fetch(ng.port, "/bp/x")
    assert h1.get("x-cache") == "HIT" and b1 == b0, "second should HIT"
    # bypass: must go to origin (new body), not served from cache
    _, b2, h2 = fetch(ng.port, "/bp/x?nocache=1")
    assert "x-cache" not in h2, "bypass should not be served from cache"
    assert b2 != b1, "bypass should hit the origin (fresh body)"
    # the bypass refreshed the entry: a plain read now returns the bypass body
    _, b3, h3 = fetch(ng.port, "/bp/x")
    assert h3.get("x-cache") == "HIT" and b3 == b2, \
        "bypass should have refreshed the cached entry"


def test_bypass_uri(ng: Nginx) -> None:
    """v15: cache_turbo_bypass_uri gives a DIY user the preset segment-boundary
    URI matcher without a preset. A matching prefix bypasses (origin, never
    captured, X-CT-Status=BYPASS); a non-boundary continuation ("/bu/panel-x")
    does NOT match and caches normally; an unlisted URI caches. This is the gap
    a plain nginx `location` prefix cannot close (it anchors at position 0 and
    has no '/'-or-'.' boundary check)."""
    # exact segment match -> bypass
    _, _, h = fetch(ng.port, "/bu/panel")
    assert h.get("x-ct-status") == "BYPASS", \
        f"/bu/panel must bypass (exact segment), got {h.get('x-ct-status')}"
    # boundary continuation -> still bypass ("/bu/panel/sub", "/bu/panel.json")
    _, _, h = fetch(ng.port, "/bu/panel/sub")
    assert h.get("x-ct-status") == "BYPASS", \
        f"/bu/panel/sub must bypass (segment boundary '/'), got {h.get('x-ct-status')}"
    _, _, h = fetch(ng.port, "/bu/panel.json")
    assert h.get("x-ct-status") == "BYPASS", \
        f"/bu/panel.json must bypass (segment boundary '.'), got {h.get('x-ct-status')}"
    # trailing-slash needle: any continuation is inside the subtree
    _, _, h = fetch(ng.port, "/bu/admin/users")
    assert h.get("x-ct-status") == "BYPASS", \
        f"/bu/admin/users must bypass, got {h.get('x-ct-status')}"

    # NON-boundary continuation -> NOT a match -> caches. This is the whole point
    # of the segment matcher: "/bu/panel-x" is a different resource from "/bu/panel".
    _, _, h0 = fetch(ng.port, "/bu/panel-x")
    assert h0.get("x-ct-status") == "MISS", \
        f"/bu/panel-x must NOT match /bu/panel (letters continue), got {h0.get('x-ct-status')}"
    _, _, h1 = fetch(ng.port, "/bu/panel-x")
    assert h1.get("x-ct-status") == "HIT", \
        f"/bu/panel-x must cache (not bypassed), got {h1.get('x-ct-status')}"

    # an entirely unlisted URI caches normally
    _, _, h0 = fetch(ng.port, "/bu/public")
    assert h0.get("x-ct-status") == "MISS", "unlisted URI first fetch MISS"
    _, _, h1 = fetch(ng.port, "/bu/public")
    assert h1.get("x-ct-status") == "HIT", \
        f"unlisted /bu/public must cache, got {h1.get('x-ct-status')}"


def test_key_cookie(ng: Nginx) -> None:
    """v15: cache_turbo_key_cookie value-keys a cookie into the cache key for a
    DIY user, the same tier-3 engine the magento preset uses. Different values
    are different entries; the same value shares one; an absent cookie is its
    own anonymous bucket. EXACT-name match and all-Cookie-headers scan are the
    same anti-bucket-selection guarantees the preset carries."""
    seg_a = {"Cookie": "seg=aaaa1111bbbb2222"}
    _, ba1, _ = fetch(ng.port, "/kc/page", headers=seg_a)
    _, ba2, ha2 = fetch(ng.port, "/kc/page", headers=seg_a)
    assert ha2.get("x-ct-status") == "HIT" and ba1 == ba2, \
        "same seg value must key to its own entry and HIT"

    # a DIFFERENT value must not see A's body -- the value is in the KEY
    seg_b = {"Cookie": "seg=cccc3333dddd4444"}
    _, bb1, _ = fetch(ng.port, "/kc/page", headers=seg_b)
    assert bb1 != ba1, \
        "a different seg value was served another segment's body -- cross-user leak"

    # OVER-LONG values (> 256 bytes) collapse to ONE bucket, marked by the
    # reserved 0xffffffff length field and no value bytes. Two DIFFERENT
    # over-long values must therefore share an entry -- that is the cap doing
    # its job. The only requests in that bucket are other over-long ones.
    big_x = {"Cookie": "seg=" + ("x" * 300)}
    big_y = {"Cookie": "seg=" + ("y" * 400)}
    _, bx1, _ = fetch(ng.port, "/kc/page", headers=big_x)
    _, by1, hy1 = fetch(ng.port, "/kc/page", headers=big_y)
    assert hy1.get("x-ct-status") == "HIT" and by1 == bx1, \
        ("two distinct over-long key-cookie values must collapse to ONE bucket "
         f"-- otherwise the cap does not bound anything, got {hy1.get('x-ct-status')}")

    # ...but that bucket must be DISTINCT from the anonymous (absent-cookie)
    # one, or an over-long value poisons the entry every cookie-less visitor
    # reads. This is the assertion that fails if the cap is implemented by
    # simply dropping the fold.
    _, banon, _ = fetch(ng.port, "/kc/page")
    assert banon != bx1, \
        ("an over-long value must NOT land in the anonymous bucket -- dropping "
         "the fold instead of marking it poisons every cookie-less visitor")

    # ...and distinct from an in-range value's bucket.
    assert bx1 != ba1 and bx1 != bb1, \
        "the oversize bucket must not collide with an in-range segment's entry"

    # A value at exactly the cap is still folded VERBATIM -- the boundary is
    # inclusive, so a legitimate 256-byte fingerprint keeps its own entry.
    at_cap = {"Cookie": "seg=" + ("z" * 256)}
    _, bz1, _ = fetch(ng.port, "/kc/page", headers=at_cap)
    assert bz1 != bx1, \
        ("a value of exactly 256 bytes is at the cap, not over it -- it must "
         "still key to its own entry, not the oversize bucket")
    _, bb2, hb2 = fetch(ng.port, "/kc/page", headers=seg_b)
    assert hb2.get("x-ct-status") == "HIT" and bb2 == bb1, \
        "each seg value must warm and HIT its own entry"

    # the cookie-less anonymous entry is a third, separate bucket
    _, ban, _ = fetch(ng.port, "/kc/page")
    _, ban2, han2 = fetch(ng.port, "/kc/page")
    assert han2.get("x-ct-status") == "HIT" and ban2 == ban, "anonymous entry caches"
    assert ban != ba1 and ban != bb1, "anonymous is its own bucket, not a segment's"

    # EXACT-name: a cookie whose name merely ends with "seg" is a different
    # cookie and must not select seg's bucket.
    _, bd, _ = fetch(ng.port, "/kc/decoy",
                     headers={"Cookie": "notseg=aaaa1111bbbb2222"})
    _, bda, _ = fetch(ng.port, "/kc/decoy")
    assert bd == bda, \
        "notseg must not be read as seg -- exact-name keeps the bucket out of client hands"

    # ALL Cookie headers scanned: the real cookie hidden in a SECOND header must
    # key identically to the same cookie in one header (else attacker-chosen).
    _, bs, _ = fetch_dup(ng.port, "/kc/split",
                         [("Cookie", "other=x"),
                          ("Cookie", "seg=eeee5555ffff6666")])
    _, bs2, hs2 = fetch(ng.port, "/kc/split",
                        headers={"Cookie": "other=x; seg=eeee5555ffff6666"})
    assert hs2.get("x-ct-status") == "HIT" and bs2 == bs, \
        "a seg cookie in a second Cookie header must key identically"


def test_require_header(ng: Nginx) -> None:
    """PR-A: cache_turbo_require_header inverts the store default on a location
    from "cacheable unless vetoed" to "uncacheable unless the origin affirms
    it". Only the application can decide for an origin like GraphQL, which
    answers queries and mutations on the same URI+method and returns errors as
    HTTP 200. Every assert is on a POSITIVE X-CT-Status: each refusal case is a
    plain MISS, and a MISS carries no x-cache, so an absence assert here would
    pass even if the gate never ran."""
    # affirmative -> stored and served. "yes"/"1"/"on" each on their own URI so
    # one value's entry can never satisfy another's assert.
    for i, val in enumerate(("yes", "1", "on", "YES", "On")):
        p = f"/gql/ok{i}"
        _, b1, h1 = fetch(ng.port, p, headers={"X-Want-Cacheable": val})
        assert h1.get("x-ct-status") == "MISS", \
            f"cold fetch of {p} should be MISS, got {h1.get('x-ct-status')}"
        _, b2, h2 = fetch(ng.port, p, headers={"X-Want-Cacheable": val})
        assert h2.get("x-ct-status") == "HIT" and b2 == b1, \
            f"{val!r} is affirmative -> must store and HIT, got {h2.get('x-ct-status')}"
        # STRIPPED before store, asserted per value rather than once after the
        # loop: this cache is the header's intended consumer, and a HIT must not
        # replay the origin's internal store signal downstream. Checked inside
        # the loop so every affirmative proves its own strip -- a single assert
        # after the loop would silently only ever test the last value.
        assert "x-graphql-cacheable" not in {k.lower() for k in h2}, \
            f"{val!r}: the store opt-in header must be stripped, not replayed"

    # every non-affirmative value refuses the store -> the second fetch is a
    # fresh origin body, never a HIT. "note"/"1x"/"onward" specifically catch a
    # prefix compare that would read them as affirmative.
    # No "" case here: nginx drops an empty-valued response header in the proxy
    # layer, so it never reaches the gate at all -- an "" row would silently be
    # a second copy of the /gql/absent case below, not an empty-value test. The
    # gate's own len-based checks still refuse an empty value if one ever does
    # arrive (a non-proxy content phase, say); it just isn't reachable here.
    for i, val in enumerate(("no", "0", "note", "1x", "onward", "yes-but")):
        p = f"/gql/no{i}"
        _, b1, _ = fetch(ng.port, p, headers={"X-Want-Cacheable": val})
        _, b2, h2 = fetch(ng.port, p, headers={"X-Want-Cacheable": val})
        assert h2.get("x-ct-status") == "MISS" and b2 != b1, \
            f"{val!r} is not affirmative -> must never store, got {h2.get('x-ct-status')}"

    # Pins WHY there is no "" row above, on the ungated control location so the
    # proxy layer's own behaviour is what's observed: nginx does not forward an
    # empty-valued response header (the origin demonstrably sends
    # "X-GraphQL-Cacheable: "). If a future nginx starts forwarding it, this
    # fails and the "" case becomes worth testing on the gate directly.
    _, _, he = fetch(ng.port, "/nogql/empty", headers={"X-Want-Cacheable": ""})
    assert he.get("X-GraphQL-Cacheable") is None, \
        "nginx now forwards an empty-valued header -- add an empty-value case " \
        "to the refusal loop above, it is no longer just /gql/absent"

    # header ABSENT entirely -> refuse (the fail-closed default of the gate)
    _, ba1, _ = fetch(ng.port, "/gql/absent")
    _, ba2, ha2 = fetch(ng.port, "/gql/absent")
    assert ha2.get("x-ct-status") == "MISS" and ba2 != ba1, \
        "no opt-in header at all must refuse the store"

    # DUPLICATED + conflicting ("yes" and "no") -> ambiguous -> refuse, in BOTH
    # orders: the gate scans the whole headers_out list, so a first-match-wins
    # implementation would store the yes-first case and leak an uncacheable body.
    for order in ("yes|no", "no|yes"):
        p = f"/gql/dup{order.split('|')[0]}"
        _, bd1, _ = fetch(ng.port, p, headers={"X-Want-Cacheable": order})
        _, bd2, hd2 = fetch(ng.port, p, headers={"X-Want-Cacheable": order})
        assert hd2.get("x-ct-status") == "MISS" and bd2 != bd1, \
            f"conflicting duplicate opt-in ({order}) is ambiguous -> must refuse"

    # UNSET on a location => gate inert => the module's normal path is untouched.
    # Without this, a gate that refused everything everywhere would still pass
    # every refusal assert above.
    _, bn1, _ = fetch(ng.port, "/nogql/page")
    _, bn2, hn2 = fetch(ng.port, "/nogql/page")
    assert hn2.get("x-ct-status") == "HIT" and bn2 == bn1, \
        "an unset require_header must leave normal caching alone"


def test_status_variable(ng: Nginx) -> None:
    """$cache_turbo_status (echoed as X-CT-Status): MISS on the cold fetch,
    HIT on the second, BYPASS when a cache_turbo_bypass predicate trips. Also
    confirms the bypass bumped the cache_turbo_bypasses_total counter."""
    import re
    _, _, h0 = fetch(ng.port, "/ctstatus/s")
    assert h0.get("x-ct-status") == "MISS", \
        f"cold fetch should be MISS, got {h0.get('x-ct-status')}"
    _, _, h1 = fetch(ng.port, "/ctstatus/s")
    assert h1.get("x-ct-status") == "HIT", \
        f"second fetch should be HIT, got {h1.get('x-ct-status')}"

    _, b, _ = fetch(ng.port, "/_cache?format=prometheus")
    m = re.search(r'cache_turbo_bypasses_total\{zone="main"\} (\d+)', b)
    assert m, f"no bypasses_total sample:\n{b[:300]}"
    before = int(m.group(1))

    _, _, h2 = fetch(ng.port, "/ctstatus/s?nocache=1")
    assert h2.get("x-ct-status") == "BYPASS", \
        f"bypass fetch should be BYPASS, got {h2.get('x-ct-status')}"

    _, b2, _ = fetch(ng.port, "/_cache?format=prometheus")
    after = int(re.search(r'cache_turbo_bypasses_total\{zone="main"\} (\d+)',
                          b2).group(1))
    assert after == before + 1, \
        f"bypasses_total should increment on a bypass: {before} -> {after}"


def test_status_stale(ng: Nginx, origin: Origin) -> None:
    """$cache_turbo_status = STALE while serving a stale copy. /ctstale/ has
    beta 1 so the refresh dice ~never fires (the read stays a clean STALE serve
    rather than flipping to a fresh HIT). Locks the ST_STALE arm of the var."""
    fetch(ng.port, "/ctstale/s")                  # prime: MISS, fresh 1s
    time.sleep(1.3)                               # past fresh, within the 4s stale
    _, _, h = fetch(ng.port, "/ctstale/s")
    assert h.get("x-ct-status") == "STALE", \
        f"stale serve should report STALE, got {h.get('x-ct-status')}"
    drain_origin(origin)       # settle any async bg refresh before the next test


def test_status_expired(ng: Nginx, origin: Origin) -> None:
    """$cache_turbo_status = EXPIRED when a cached entry is found past its whole
    serveable window and refetched from origin — distinct from a cold MISS
    (which test_status_variable covers). Locks the ST_EXPIRED arm + the
    nginx-aligned semantics (EXPIRED != only-if-cached-504)."""
    fetch(ng.port, "/ctstale/e")                  # prime: MISS, fresh 1s, stale to 4s
    time.sleep(4.5)                               # past the entire 4s window
    _, _, h = fetch(ng.port, "/ctstale/e")
    assert h.get("x-ct-status") == "EXPIRED", \
        f"expired-refetch should report EXPIRED, got {h.get('x-ct-status')}"
    drain_origin(origin)


def test_serve_reason_variable(ng: Nginx, origin: Origin) -> None:
    """S7.2: $cache_turbo_serve_reason (echoed as X-CT-Reason) is the UNFOLDED
    per-request serve outcome. Drives all five values on the private sr72z
    zone, kept separate from s71z/brkiz/etc. so this test's own breaker
    priming (expects CLOSED, then trips it itself) is not polluted by another
    test's already-tripped breaker.

    FRESH  : /sr72/ second fetch, within the 1s fresh window.
    STALE  : /sr72/ third fetch, past fresh (1s) but within the x4=4s stale
             window (beta 1 keeps the refresh dice from firing, same
             discipline as test_status_stale).
    STALE-IF-ERROR : /sr72sie/ fully expired (past the 4s stale window) with
             the origin down; the "sieserve" request-suffix marker armed a
             serve-on-error snapshot on priming (same convention as
             test_sie_serve_on_error).
    STALE-BREAKER  : /sr72brk/dead, primed then origin killed. threshold=1
             means the FIRST dead-origin request trips CLOSED->OPEN and still
             surfaces the raw origin error (not a serve at all, so it does
             NOT report STALE-BREAKER); the SECOND request finds the breaker
             OPEN and is served the armed fallback -- that is the one this
             test asserts on (same two-fetch shape as test_breaker_counters).
    BREAKER-503    : /sr72brk/never -- NEVER primed, so once the breaker above
             is OPEN this key has no snapshot of any age and falls into
             ngx_http_cache_turbo_breaker_unavailable(), the local 503 that
             never touches the origin.
    """
    # FRESH
    fetch(ng.port, "/sr72/k1")                    # prime: MISS (SR_NONE, no
                                                    # unfolded reason for a cold
                                                    # miss -- not asserted here)
    _, _, h_fresh = fetch(ng.port, "/sr72/k1")
    assert h_fresh.get("x-ct-reason") == "FRESH", \
        f"fresh serve should report FRESH, got {h_fresh.get('x-ct-reason')}"

    # STALE
    time.sleep(1.3)                                # past fresh, within 4s stale
    _, _, h_stale = fetch(ng.port, "/sr72/k1")
    assert h_stale.get("x-ct-reason") == "STALE", \
        f"stale serve should report STALE, got {h_stale.get('x-ct-reason')}"
    drain_origin(origin)

    # STALE-IF-ERROR
    s0, b0, _ = fetch(ng.port, "/sr72sie/sieserve-k1")   # arms sie window
    assert s0 == 200 and b0, f"sie prime failed: {s0} {b0!r}"
    time.sleep(4.6)                                # past fresh (1s) + stale (4s)
    origin.fail = True
    try:
        s_sie, b_sie, h_sie = fetch(ng.port, "/sr72sie/sieserve-k1")
        assert s_sie == 200 and b_sie == b0, \
            f"SIE serve-on-error returned {s_sie} {b_sie!r}, expected stale 200 {b0!r}"
        assert h_sie.get("x-ct-reason") == "STALE-IF-ERROR", \
            (f"SIE serve should report STALE-IF-ERROR, got "
             f"{h_sie.get('x-ct-reason')}")
    finally:
        origin.fail = False
        drain_origin(origin)

    # STALE-BREAKER + BREAKER-503
    s_prime, b_prime, _ = fetch(ng.port, "/sr72brk/dead")
    assert s_prime == 200 and b_prime, f"breaker prime failed: {s_prime} {b_prime!r}"

    time.sleep(4.3)   # past fresh (1s) AND the x4 stale window (4s): L1-expired
    origin.fail = True
    try:
        s_trip, _, _ = fetch(ng.port, "/sr72brk/dead")
        assert s_trip != 200, \
            (f"tripping request was answered 200 -- expected it to reach "
             f"the dead origin and fail, got {s_trip}")

        s_brk, _, h_brk = fetch(ng.port, "/sr72brk/dead")
        assert s_brk == 200, \
            f"breaker OPEN did not fall back to the any-age snapshot, got {s_brk}"
        assert h_brk.get("x-ct-reason") == "STALE-BREAKER", \
            (f"breaker fallback serve should report STALE-BREAKER, got "
             f"{h_brk.get('x-ct-reason')}")

        s_503, _, h_503 = fetch(ng.port, "/sr72brk/never")
        assert s_503 == 503, \
            f"breaker OPEN + no cached copy should 503, got {s_503}"
        assert h_503.get("x-ct-reason") == "BREAKER-503", \
            (f"breaker refusal should report BREAKER-503, got "
             f"{h_503.get('x-ct-reason')}")
    finally:
        origin.fail = False
        drain_origin(origin)


def test_request_cc_serve_verdict_fresh(ng: Nginx, origin: Origin) -> None:
    """RFC-1 request Cache-Control against a FRESH entry (req_serve_verdict,
    module.c:1403-1409). A client's own max-age/min-fresh can refuse an entry
    the cache considers fresh: fresh_ok clears, no max-stale means stale_ok is
    also 0, so both serve paths are refused and the entry is revalidated
    (refetched from origin) instead of served HIT.

    The counting origin returns a unique body per hit, so a refetch yields a
    body distinct from the primed one — that difference is the proof the cache
    did NOT serve the stored copy."""
    # prime a fresh 30s entry, confirm the plain second read HITs
    _, base, _ = fetch(ng.port, "/reqcc/f")
    _, b2, h2 = fetch(ng.port, "/reqcc/f")
    assert h2.get("x-ct-status") == "HIT", \
        f"plain second read should HIT, got {h2.get('x-ct-status')}"
    assert b2 == base, "fresh HIT must replay the stored body"

    # max-age=0: client demands an entry no older than 0s. The 30s entry has
    # age>0 -> fresh_ok=0; no max-stale -> stale_ok=0 -> refused -> refetch.
    _, bm, hm = fetch(ng.port, "/reqcc/f",
                      headers={"Cache-Control": "max-age=0"})
    assert hm.get("x-ct-status") != "HIT", \
        f"max-age=0 must refuse the fresh HIT, got {hm.get('x-ct-status')}"
    assert bm != base, "max-age=0 must be revalidated from origin (new body)"

    # min-fresh=999: client wants >=999s of remaining freshness; the entry has
    # at most 30s left -> fresh_ok=0 -> refused -> refetch.
    fetch(ng.port, "/reqcc/g")
    fetch(ng.port, "/reqcc/g")   # ensure a fresh stored entry
    _, _, hg = fetch(ng.port, "/reqcc/g",
                      headers={"Cache-Control": "min-fresh=999"})
    assert hg.get("x-ct-status") != "HIT", \
        f"min-fresh=999 must refuse the 30s entry, got {hg.get('x-ct-status')}"

    # max-stale (bare) on a fresh entry still serves the fresh HIT (fresh_ok=1),
    # while exercising the bare-max-stale parse (req_max_stale_any). module.c:1367
    _, _, hs = fetch(ng.port, "/reqcc/f",
                     headers={"Cache-Control": "max-stale"})
    assert hs.get("x-ct-status") == "HIT", \
        f"bare max-stale must still serve the fresh HIT, got {hs.get('x-ct-status')}"
    drain_origin(origin)


def test_request_cc_serve_verdict_stale(ng: Nginx, origin: Origin) -> None:
    """RFC-1 request Cache-Control against a STALE entry (req_serve_verdict
    stale_ok arm, module.c:1411-1421). /reqccst/ has a 1s fresh window + the
    default 4x stale window and beta 1 (dice ~never), so after ~1.3s the entry
    is stale-but-serveable. The client's max-stale decides whether the cache may
    serve that stale copy."""
    # default (no request CC): a stale entry is served per cache policy (stale_ok
    # default arm, module.c:1421).
    fetch(ng.port, "/reqccst/a")
    time.sleep(1.3)
    _, _, hd = fetch(ng.port, "/reqccst/a")
    assert hd.get("x-ct-status") == "STALE", \
        f"default request must serve STALE, got {hd.get('x-ct-status')}"

    # max-stale=0: no staleness tolerated. staleness>0 -> stale_ok=0; no max-age
    # so fresh_ok stays 1 but the entry is not fresh -> refused -> refetch.
    # Sleep 2.3s (not 1.3s) so staleness = now-fresh_until is unambiguously >=1s:
    # ngx_time() has 1s granularity, and at ~0.3s past a 1s window the rounded
    # staleness can land on 0, making `staleness <= max_stale(0)` true and the
    # copy STALE-served (the 1s-granularity SWR flake class). 2.3s clears it.
    fetch(ng.port, "/reqccst/b")
    time.sleep(2.3)
    _, _, hz = fetch(ng.port, "/reqccst/b",
                     headers={"Cache-Control": "max-stale=0"})
    assert hz.get("x-ct-status") != "STALE", \
        f"max-stale=0 must refuse the stale copy, got {hz.get('x-ct-status')}"

    # max-stale=100: 100s of staleness tolerated; the ~0.3s-stale entry is well
    # within it -> stale_ok=1 -> STALE served (module.c:1416, valued branch).
    fetch(ng.port, "/reqccst/c")
    time.sleep(1.3)
    _, _, hp = fetch(ng.port, "/reqccst/c",
                     headers={"Cache-Control": "max-stale=100"})
    assert hp.get("x-ct-status") == "STALE", \
        f"max-stale=100 must permit the stale copy, got {hp.get('x-ct-status')}"

    # max-stale=abc: unparseable value falls back to "accept any staleness"
    # (req_max_stale_any, module.c:1375) -> STALE served.
    fetch(ng.port, "/reqccst/d")
    time.sleep(1.3)
    _, _, hu = fetch(ng.port, "/reqccst/d",
                     headers={"Cache-Control": "max-stale=abc"})
    assert hu.get("x-ct-status") == "STALE", \
        f"unparseable max-stale must be lenient (STALE), got {hu.get('x-ct-status')}"
    drain_origin(origin)


def test_cc_mode_inheritance_child_preset_overrides_parent_ignore(
        ng: Nginx, origin: Origin) -> None:
    """cc_mode (cache_turbo_cache_control) merge precedence: a child with a CMS
    backend preset (cc_mode defaults to honor) under a parent that set `ignore`
    must resolve to HONOR, not inherit the parent's ignore. honor respects the
    cacheability floor so the origin's `private` response is NOT cached at the
    child; the parent (ignore) DOES cache it. Differential proves the child did
    not inherit ignore (the old two-flag model would have cached the child too)."""
    # parent (ignore): the private floor is bypassed -> cached -> HIT on re-read
    fetch(ng.port, "/ccinh/ccprivate")
    _, _, hp = fetch(ng.port, "/ccinh/ccprivate")
    assert hp.get("x-cache") == "HIT", \
        f"parent ignore must cache a private response; got {hp.get('x-cache')}"
    # child (preset honor): the private floor is honored -> NOT cached -> no HIT
    fetch(ng.port, "/ccinh/wp/ccprivate")
    _, _, hc = fetch(ng.port, "/ccinh/wp/ccprivate")
    assert hc.get("x-cache") != "HIT", \
        ("child CMS-preset must resolve to honor (private NOT cached), not "
         f"inherit parent ignore; got X-Cache={hc.get('x-cache')}")


def test_no_store(ng: Nginx) -> None:
    """v9: cache_turbo_no_store keeps a flagged response out of the cache."""
    _, _, h1 = fetch(ng.port, "/nost/y?private=1")
    assert "x-cache" not in h1, "first should miss"
    _, _, h2 = fetch(ng.port, "/nost/y?private=1")
    assert "x-cache" not in h2, "no_store response must not be cached"
    # without the flag it caches normally (same $uri key)
    _, _, h3 = fetch(ng.port, "/nost/y")
    assert "x-cache" not in h3, "first un-flagged read is still a miss"
    _, _, h4 = fetch(ng.port, "/nost/y")
    assert h4.get("x-cache") == "HIT", "un-flagged response should cache"


def test_native_cache_headers_stripped(ng: Nginx) -> None:
    """When a native nginx cache (proxy_cache) sits behind us, its per-response
    Age / X-Cache-Status must NOT be frozen into our blob and replayed on every
    L1 hit. Our own X-Cache stays."""
    fetch(ng.port, "/c/nativecache")                   # prime (origin Age=123)
    _, _, h = fetch(ng.port, "/c/nativecache")         # HIT from shm
    assert h.get("x-cache") == "HIT", "should be an L1 hit"
    # The upstream's frozen Age:123 must not be replayed; we emit our OWN Age
    # (seconds since WE stored it, so small) computed in serve().
    assert "age" in h, "our own Age header should be present on a HIT"
    assert int(h["age"]) < 100, \
        f"upstream Age=123 leaked instead of our computed Age: {h.get('age')}"
    assert "x-cache-status" not in h, \
        f"upstream X-Cache-Status leaked: {h.get('x-cache-status')}"


def test_warm_rejects_traversal(ng: Nginx, origin: Origin) -> None:
    """AUD3-WARM-URI-NORM: ngx_http_subrequest() does not run
    ngx_http_parse_complex_uri() on a hand-built URI, so a percent-decoded
    "?url=" value that resolves to a ".." segment must be rejected before it
    ever reaches location matching -- otherwise "/%2e%2e/%2e%2e/etc/x" decodes
    to "/../../etc/x" and is matched un-normalized. The bad entry must simply
    not be warmed (warmed count excludes it); a comma-separated list with a
    good entry alongside it must still warm the good one."""
    import json
    good = "/c/warm-trav-ok"
    base = origin.hits_for("warm-trav-ok")
    s, b, _ = fetch(ng.port, "/_cache?url=/%2e%2e/%2e%2e/etc/x", method="POST")
    assert s == 200, f"warm status {s}"
    assert json.loads(b)["warmed"] == 0, \
        f"traversal url must not be warmed: {b}"

    # a bad entry alongside a good one must not kill the good one.
    s2, b2, _ = fetch(
        ng.port, f"/_cache?url=/%2e%2e/%2e%2e/etc/x,{good}", method="POST")
    assert s2 == 200, f"warm status {s2}"
    assert json.loads(b2)["warmed"] == 1, \
        f"good url in the same list must still warm: {b2}"
    assert wait_for(lambda: origin.hits_for("warm-trav-ok") == base + 1), \
        "the good warm subrequest never reached origin"


def test_warm_rejects_embedded_nul(ng: Nginx, origin: Origin) -> None:
    """AUD3-WARM-URI-NORM: a percent-decoded %00 produces an embedded NUL in
    sr->uri; downstream ngx_str_t-vs-C-string consumers (proxy_pass URI
    construction, $uri in a log format) would truncate at it. Reject and skip
    rather than warm."""
    import json
    s, b, _ = fetch(ng.port, "/_cache?url=/c/warm-nul%00trunc", method="POST")
    assert s == 200, f"warm status {s}"
    assert json.loads(b)["warmed"] == 0, \
        f"NUL-containing url must not be warmed: {b}"


def test_warm_normal_url_still_warms(ng: Nginx, origin: Origin) -> None:
    """AUD3-WARM-URI-NORM guard: the new URI-safety check must not over-reject
    an ordinary valid warm target. Same shape as test_warm_populates, kept
    separate so the traversal/NUL fix has its own positive control."""
    import json
    uri = "/c/warm-norm-ok"
    base = origin.hits_for("warm-norm-ok")
    s, b, _ = fetch(ng.port, f"/_cache?url={uri}", method="POST")
    assert s == 200, f"warm status {s}"
    assert json.loads(b)["warmed"] == 1, f"warmed count: {b}"
    assert wait_for(lambda: origin.hits_for("warm-norm-ok") == base + 1), \
        "warm subrequest never hit the origin"


def test_stale_serves_stale(ng: Nginx, origin: Origin) -> None:
    """R3: once fresh TTL passes, the cache serves the stale copy (not a miss),
    and a refresh eventually lands (the served body advances to a new gen)."""
    s0, b0, _ = fetch(ng.port, "/swr/serve")       # prime
    assert s0 == 200
    time.sleep(1.3)                                # now stale (fresh=1s)
    # first stale read: must still be 200 and the SAME (stale) body or a fresh
    # regenerated one — never an error, never empty.
    s1, b1, h1 = fetch(ng.port, "/swr/serve")
    assert s1 == 200 and b1, f"stale serve failed: {s1} {b1!r}"
    assert h1.get("x-cache") in ("STALE", None), \
        f"expected STALE or fresh-regen, got {h1.get('x-cache')}"
    # within the stale window the entry refreshes to a new generation
    deadline = time.time() + 2.0
    advanced = False
    while time.time() < deadline:
        _, b, h = fetch(ng.port, "/swr/serve")
        if b != b0 and h.get("x-cache") == "HIT":
            advanced = True
            break
        time.sleep(0.1)
    assert advanced, "stale entry never refreshed to a new generation"
    drain_origin(origin)       # v8: settle async bg refreshes before the next test


def test_single_flight(ng: Nginx, origin: Origin) -> None:
    """R4: a burst of readers on a stale key triggers far fewer origin regens
    than readers (single-flight), and never a per-reader stampede."""
    fetch(ng.port, "/swr/sf")                      # prime
    base = origin.hits
    time.sleep(1.3)                                # stale
    # Fire a burst; the hard lock + dice must collapse this to a handful of
    # origin regens, not one-per-reader. Poll a moment for in-flight refreshes.
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: fetch(ng.port, "/swr/sf"),
                                range(40)))
    assert {r[0] for r in results} == {200}, \
        f"stale burst returned {set(r[0] for r in results)}"
    time.sleep(0.5)
    regens = origin.hits - base
    # Single-flight property: nowhere near 40. A small number is fine (dice can
    # let a few through before the lock is visible across event-loop turns).
    assert regens <= 8, \
        f"single-flight failed: {regens} origin regens for 40 readers"
    drain_origin(origin)       # v8: settle async bg refreshes before the next test


def test_stale_if_error(ng: Nginx, origin: Origin) -> None:
    """v8: when an entry is stale and the background refresh hits a 5xx origin,
    the client keeps getting the stale copy — the error is never surfaced and
    the stale entry is not overwritten (stale-if-error)."""
    s0, b0, _ = fetch(ng.port, "/sie/x")           # prime: 200, cached fresh
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    base = origin.hits
    time.sleep(2.3)                                # past fresh (2s), inside the
                                                   # stale window (×4 = 8s)
    origin.fail = True
    try:
        for _ in range(8):
            s, b, h = fetch(ng.port, "/sie/x")
            assert s == 200, f"stale-if-error served {s}, expected stale 200"
            assert b == b0, f"served {b!r}, expected stale {b0!r}"
            assert h.get("x-cache") == "STALE", \
                f"expected STALE serve, got x-cache={h.get('x-cache')}"
            time.sleep(0.1)
        # the background refresh did reach the (failing) origin at least once.
        # bg-refresh is async; under a loaded (valgrind ×2) runner it can lag the
        # 0.8s serve loop, so poll to a generous deadline instead of asserting once.
        deadline = time.monotonic() + 5.0
        while origin.hits <= base and time.monotonic() < deadline:
            fetch(ng.port, "/sie/x")   # keep prodding the stale entry
            time.sleep(0.1)
        assert origin.hits > base, \
            "no background refresh reached the origin during the stale window"
    finally:
        origin.fail = False
        drain_origin(origin)   # settle the failing bg refreshes before next test


def test_stale_serves_stale_origin_hard_dead(ng: Nginx, origin: Origin) -> None:
    """Goal-2: serve-stale-on-dead-upstream. Within the stale window a read is
    answered from shm WITHOUT contacting the origin, so a hard upstream failure
    (connection dropped, not a clean 503) still yields a stale 200 — the error
    is never surfaced. This is the transport-level (502) counterpart to
    test_stale_if_error's clean-5xx case, and exercises the bg-refresh path
    against an origin that resets the connection.

    Boundary (intentional): this v8 path holds for the SWR window with
    background_update on (the default). A cold key, or background_update=off,
    surface the live origin error by design. A key already PAST its stale_until
    is no longer surfaced unconditionally — RFC-2 stale-if-error (CTB4) replays it
    when the response carried stale-if-error=N and now < created + sie_ttl (see
    test_sie_serve_on_error); without that window the expired entry still surfaces
    the error."""
    s0, b0, _ = fetch(ng.port, "/sie/x2")          # prime: 200, cached fresh
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    base = origin.hits
    time.sleep(2.3)                                # past fresh (2s), inside the
                                                   # stale window (×4 = 8s)
    origin.drop = True
    try:
        for _ in range(8):
            s, b, h = fetch(ng.port, "/sie/x2")
            assert s == 200, f"hard-dead origin served {s}, expected stale 200"
            assert b == b0, f"served {b!r}, expected stale {b0!r}"
            assert h.get("x-cache") == "STALE", \
                f"expected STALE serve, got x-cache={h.get('x-cache')}"
            time.sleep(0.1)
        # the background refresh did reach the dropped-connection origin. async +
        # loaded runner can lag the serve loop → poll to a deadline, not once.
        deadline = time.monotonic() + 5.0
        while origin.hits <= base and time.monotonic() < deadline:
            fetch(ng.port, "/sie/x2")
            time.sleep(0.1)
        assert origin.hits > base, \
            "no background refresh reached the origin during the stale window"
    finally:
        origin.drop = False
        drain_origin(origin)   # settle the failing bg refreshes before next test


def test_sie_serve_on_error(ng: Nginx, origin: Origin) -> None:
    """RFC-2 (CTB4) stale-if-error serve-on-error: a FULLY EXPIRED entry (past its
    stale window) whose blob carries a serve-on-error window (created + sie_ttl) is
    replayed when the origin revalidation returns 5xx — the error is replaced by
    the stale body with X-Cache: STALE-IF-ERROR. This is the past-stale_until case
    the v8 SWR path deliberately did NOT cover (see
    test_stale_serves_stale_origin_hard_dead).

    Negative control in the same test: a sibling key whose response carries NO
    stale-if-error has sie_ttl == 0, so the same expired-origin-5xx surfaces the
    error instead of serving stale."""
    # Positive: origin emits stale-if-error=30 (request suffix marker "sieserve").
    s0, b0, _ = fetch(ng.port, "/sieserve/sieserve-k1")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    # Negative control: no stale-if-error in the response (sie_ttl == 0).
    sn, bn, _ = fetch(ng.port, "/sieserve/plain-k1")
    assert sn == 200 and bn, f"control prime failed: {sn} {bn!r}"

    time.sleep(4.6)     # past fresh (1s) AND the stale window (x4 = 4s): expired
    origin.fail = True
    try:
        s, b, h = fetch(ng.port, "/sieserve/sieserve-k1")
        assert s == 200, f"SIE serve-on-error returned {s}, expected stale 200"
        assert b == b0, f"served {b!r}, expected stale {b0!r}"
        assert h.get("x-cache") == "STALE-IF-ERROR", \
            f"expected STALE-IF-ERROR, got x-cache={h.get('x-cache')}"

        # Negative control: no SIE window -> the 5xx is surfaced, not replaced.
        sc, _, hc = fetch(ng.port, "/sieserve/plain-k1")
        assert sc == 503, f"no-SIE expired entry served {sc}, expected origin 503"
        assert hc.get("x-cache") != "STALE-IF-ERROR", \
            "a no-SIE expired entry must not serve-on-error"
    finally:
        origin.fail = False
        drain_origin(origin)


def _errlog_window_start(ng: Nginx) -> int:
    """Byte offset into logs/error.log at the moment of the call, for
    bracketing a later grep to lines written strictly during this test's own
    window -- the pattern test_l2_negative_ttl_expires established (see the
    long comment above it) to avoid attributing a debug line emitted by an
    unrelated concurrent/earlier request to the wrong test.

    0 (file absent yet) is a legal starting offset, not an error -- the log is
    created lazily on first write."""
    log = ng.root / "logs" / "error.log"
    try:
        return log.stat().st_size
    except OSError:
        return 0


def _errlog_sie_unconsumed_in_window(ng: Nginx, start: int) -> list[int]:
    """AUD-SIE-BODY oracle: every `cache_turbo: test_sie_unconsumed=<N>` value
    logged strictly after byte offset `start`, in emission order.

    The module emits these at NOTICE, so they clear the harness's default log
    level with no TEST_CT_ERRLOG and no per-location debug error_log (see the
    long note in test_sie_serve_on_error_unbuffered for why debug is not an
    option here). Callers must still assert the list is non-empty before
    trusting any 0 in it: a missing line means the sie_serving block was never
    entered, or TEST_FAULTS was not compiled in -- not evidence of a fixed
    bug."""
    log = ng.root / "logs" / "error.log"
    try:
        with log.open("rb") as f:
            f.seek(start)
            tail = f.read()
    except OSError as exc:
        raise AssertionError(f"error.log unreadable: {exc}") from None
    text = tail.decode("utf-8", errors="replace")
    return [int(m) for m in
            re.findall(r"cache_turbo: test_sie_unconsumed=(\d+)", text)]


def test_sie_serve_on_error_unbuffered(ng: Nginx, origin: Origin) -> None:
    """AUD-SIE-BODY regression: same scenario as test_sie_serve_on_error (a
    fully expired /sieserve/-style entry replayed from its stale-if-error
    snapshot when the origin 5xxs) but through /siebuf/, which sets
    proxy_buffering off.

    A client-visible hang is the WRONG oracle for this bug: /siebuf/'s
    upstream has no keepalive pool, so ngx_http_upstream_finalize_request()
    unconditionally close()s the upstream connection on request teardown,
    which reclaims any stuck buffers as an OS side effect regardless of
    whether the module marked them consumed -- the request completes either
    way (proven: an earlier version of this test used a raw keep-alive socket
    with a bounded recv() timeout and did not reliably discriminate fix from
    revert). Only the module's INTERNAL buffer accounting differs, so this
    test asserts that directly via ctx->test_sie_unconsumed (TEST_FAULTS-only,
    see the field comment in ngx_http_cache_turbo_module.h): the count of
    incoming upstream buffers left with buf->pos != buf->last at the point the
    sie_serving block in the body filter returns, on both of its exits. With
    the fix this is always 0; reverting the two consume loops (pos = last /
    file_pos = file_last / sync = 1) leaves the discarded error-body buffers
    un-advanced and it is > 0.

    A response header cannot carry this value: by the time the body filter
    runs, ngx_http_next_header_filter() has already returned for this request
    (the sie_serving header-filter exit at :7807 calls it unconditionally,
    and nginx's header filter chain serializes r->headers_out.headers into
    the wire buffer synchronously with no postponement contract) -- a header
    stamped from the body filter would always read 0, which is the exact
    vacuous-pass shape this test must not have. Instead the module logs
    `cache_turbo: test_sie_unconsumed=<N>` at NOTICE level (not debug) and
    this test reads it out of logs/error.log, bracketed by byte offset so a
    line is provably attributable to this test's own triggering request and
    not a neighbour's.

    NOTICE, not ngx_log_debug1(), is deliberate. The line has to be readable
    at the harness's default level because CI never sets TEST_CT_ERRLOG, and
    the obvious alternative -- a location-scoped `error_log ... debug` on
    /siebuf/ -- kills the ASan job: debug logging in the proxy path trips a
    PRE-EXISTING UBSan null-pointer report in nginx core
    (src/core/ngx_string.c:586, "null pointer passed as argument 2"), and the
    sanitizer workflow runs with halt_on_error=1, so the worker aborts on the
    very first request. That reproduces on unmodified upstream code with a
    debug error_log added to the existing /sieserve/ location, so it is not
    this module's bug -- but it does make debug-level logging unusable inside
    a CI-visible fixture. The counter is TEST_FAULTS-only, so NOTICE costs
    production nothing.

    The origin's "sieserve-unbuf" marker (see Origin.do_GET) answers `fail`
    with an 8192-byte body written as two flushed chunks: a zero-length or
    single-recv error body leaves nothing behind for the sie_serving block to
    fail to consume, so the bug does not reproduce without it."""
    s0, b0, _ = fetch(ng.port, "/siebuf/sieserve-unbuf-k1")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    time.sleep(4.6)     # past fresh (1s) AND the stale window (x4 = 4s): expired
    origin.fail = True
    try:
        window_start = _errlog_window_start(ng)

        s, b, h = fetch(ng.port, "/siebuf/sieserve-unbuf-k1")
        assert s == 200, f"unbuffered SIE serve-on-error returned {s}"
        assert b == b0, f"served {b!r}, expected stale {b0!r}"
        assert h.get("x-cache") == "STALE-IF-ERROR", \
            f"expected STALE-IF-ERROR, got x-cache={h.get('x-cache')}"

        values = _errlog_sie_unconsumed_in_window(ng, window_start)
        assert values, (
            "no 'cache_turbo: test_sie_unconsumed=' line found in this "
            "request's error.log window -- the oracle line is MISSING, which "
            "must fail (never silently read as 0): either TEST_FAULTS is not "
            "actually compiled in, or the sie_serving block was not entered "
            "at all for this request")
        assert all(v == 0 for v in values), \
            (f"sie_serving left unconsumed upstream buffers on the fixed "
             f"build: test_sie_unconsumed values in window = {values} "
             f"(expected all 0)")
    finally:
        origin.fail = False
        drain_origin(origin)


def test_unbuf_streamed_store_and_hit(ng: Nginx) -> None:
    """proxy_buffering off coverage gap: ordinary capture/store + HIT serve
    when the origin body arrives as MANY flushed body-filter invocations
    instead of one coalesced chain. /siebuf/ only drives the SIE
    serve-on-error consume path; this proves the everyday store path is
    correct under the same multi-call streaming, exercising
    ctx->body_last append-cursor accumulation and last_buf detection across
    calls. A truncated or reordered capture must fail: assert full length
    AND byte-identity, not just non-empty."""
    s0, b0, h0 = fetch(ng.port, "/unbuf/unbuf-stream-k1")
    assert s0 == 200, f"prime fetch returned {s0}"
    assert "x-cache" not in h0, f"prime should MISS, got {h0.get('x-cache')}"
    assert len(b0) > 60000, f"prime body suspiciously short: {len(b0)} bytes"

    s1, b1, h1 = fetch(ng.port, "/unbuf/unbuf-stream-k1")
    assert s1 == 200, f"second fetch returned {s1}"
    assert h1.get("x-cache") == "HIT", \
        f"expected HIT after streamed store, got x-cache={h1.get('x-cache')}"
    assert len(b1) == len(b0), \
        f"HIT body length {len(b1)} != origin body length {len(b0)} " \
        f"-- streamed capture was truncated or padded"
    assert b1 == b0, "HIT body differs from the primed origin body byte-for-byte"


def test_unbuf_oversize_abort_mid_stream(ng: Nginx, origin: Origin) -> None:
    """proxy_buffering off + cache_turbo_max_size: the oversize origin body
    (~64 KiB, streamed as 16 flushed chunks) crosses the 8k cap on a LATER
    body-filter invocation, not the first buffer -- unlike test_max_size_not_
    cached's /big/ (single-buffer, buffered upstream). Delegation must still
    deliver the response COMPLETE and byte-correct to the client (no
    truncation), and the entry must never be cached."""
    s0, b0, h0 = fetch(ng.port, "/unbufbig/unbuf-big-k1")
    assert s0 == 200, f"oversize streamed fetch returned {s0}"
    assert "x-cache" not in h0, \
        f"oversize response must not be served from cache: {h0.get('x-cache')}"
    assert len(b0) > 60000, \
        f"oversize body truncated by the mid-stream abort: {len(b0)} bytes"
    assert b0.startswith("big-"), "oversize body missing its origin marker"
    assert b0.endswith("\n"), \
        "oversize body does not end cleanly -- looks truncated mid-chunk"
    # Every chunk, not just the length and the end markers: the delegated path
    # hands each buffer downstream individually, so a lost, duplicated or
    # reordered INTERIOR chunk is exactly the failure mode this test exists to
    # catch -- and a length-plus-first-and-last-marker assertion accepts all
    # three. `gen` is constant within one response, so the expected body is
    # reconstructible from the first chunk's generation.
    gen0 = b0.split("-")[1]
    expected0 = "".join(f"big-{gen0}-{i:02d}-" + "Z" * 4000 + "\n"
                        for i in range(16))
    assert b0 == expected0, \
        ("delegated oversize body is not the origin's byte stream -- a chunk "
         "was lost, duplicated or reordered mid-stream")

    # Re-fetch: must still be a live MISS (never cached), and origin must be
    # contacted again (distinct generation-tagged body).
    hits_before = origin.hits
    s1, b1, h1 = fetch(ng.port, "/unbufbig/unbuf-big-k1")
    assert s1 == 200, f"second oversize fetch returned {s1}"
    assert "x-cache" not in h1, \
        f"oversize entry must not have been cached: {h1.get('x-cache')}"
    assert origin.hits > hits_before, \
        "second fetch did not reach the origin -- oversize entry may have " \
        "been served from a cache after all"
    assert len(b1) == len(b0), \
        f"second oversize body length {len(b1)} != first {len(b0)}"
    gen1 = b1.split("-")[1]
    expected1 = "".join(f"big-{gen1}-{i:02d}-" + "Z" * 4000 + "\n"
                        for i in range(16))
    assert b1 == expected1, \
        ("second delegated oversize body is not the origin's byte stream -- a "
         "chunk was lost, duplicated or reordered mid-stream")


def test_sie_serves_counter(ng: Nginx, origin: Origin) -> None:
    """S7.1: sie_serves counts responses actually served from a stale-if-error
    snapshot -- ngx_http_cache_turbo_sie_rewrite() winning inside the header
    filter -- not every armed-SIE request or every 5xx origin response.

    Same fixture shape as test_sie_serve_on_error (a fully expired /sieserve/
    entry whose response carried stale-if-error=30, replayed with
    X-Cache: STALE-IF-ERROR when the origin then 5xxs), but reads the admin
    counter delta around the exact triggering fetch instead of only checking
    the header.

    Negative control (mandatory): the sibling /sieserve/plain-* key carries no
    stale-if-error window, so the same expired-origin-5xx sequence surfaces
    the origin's 503 directly (proven by test_sie_serve_on_error) instead of
    taking the sie_rewrite() path -- sie_serves must NOT move for it, proving
    the counter is pinned to the rewrite succeeding, not to "any 5xx on an
    expired SIE-eligible location"."""
    s0, b0, _ = fetch(ng.port, "/sieserve/sieserve-cnt-pos")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    sn0, bn0, _ = fetch(ng.port, "/sieserve/plain-cnt-neg")
    assert sn0 == 200 and bn0, f"control prime failed: {sn0} {bn0!r}"

    time.sleep(4.6)     # past fresh (1s) AND the stale window (x4 = 4s): expired
    origin.fail = True
    try:
        before = _admin_stat(ng, "sie_serves")

        s, _b, h = fetch(ng.port, "/sieserve/sieserve-cnt-pos")
        assert s == 200, f"SIE serve-on-error returned {s}, expected stale 200"
        assert h.get("x-cache") == "STALE-IF-ERROR", \
            f"expected STALE-IF-ERROR, got x-cache={h.get('x-cache')}"
        after_pos = _admin_stat(ng, "sie_serves")
        assert after_pos - before > 0, \
            "sie_serves did not move on an actual SIE serve-on-error"

        # Negative control: no SIE window on this key -> 503 surfaced directly,
        # no sie_rewrite() call, counter must stay put.
        sc, _, hc = fetch(ng.port, "/sieserve/plain-cnt-neg")
        assert sc == 503, f"no-SIE expired entry served {sc}, expected origin 503"
        assert hc.get("x-cache") != "STALE-IF-ERROR"
        after_neg = _admin_stat(ng, "sie_serves")
        assert after_neg == after_pos, \
            ("sie_serves moved on a plain 503 with no armed SIE snapshot -- "
             f"{after_pos} -> {after_neg}")
    finally:
        origin.fail = False
        drain_origin(origin)


def test_sie_origin_recovers_serves_fresh(ng: Nginx, origin: Origin) -> None:
    """RFC-2 serve-on-error must NOT hijack a SUCCESSFUL revalidation: when the
    expired entry's origin comes back 200, the client gets the FRESH new body and
    the entry is re-stored (the normal store path stays intact), not the stale
    snapshot."""
    s0, b0, _ = fetch(ng.port, "/sieserve/sieserve-k2")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    time.sleep(4.6)                                # fully expired
    s, b, h = fetch(ng.port, "/sieserve/sieserve-k2")
    assert s == 200, f"recovered origin served {s}, expected fresh 200"
    assert b != b0, f"served stale {b!r}, expected a fresh new gen"
    assert h.get("x-cache") != "STALE-IF-ERROR", \
        "a successful revalidation must not be a serve-on-error"
    # Re-stored fresh: an immediate re-read returns the same NEW body from cache.
    s2, b2, _ = fetch(ng.port, "/sieserve/sieserve-k2")
    assert s2 == 200 and b2 == b, "expected the fresh re-store to be re-served"


def test_keep_stale_serves_dead_origin(ng: Nginx, origin: Origin) -> None:
    """S2.2: cache_turbo_keep_stale is the origin-independent serve-on-error
    fallback (D-1 precedence table) when the response carries no
    stale-if-error of its own. /keepstale/ origin emits no Cache-Control at
    all, so without keep_stale a fully-expired entry would have sie_window==0
    and surface the dead origin's error. With keep_stale 1h, sie_window =
    ttl (1s) + 3600, comfortably covering the test's expiry window -> a hard
    connection-drop on a fully expired entry still serves the cached body with
    X-Cache: STALE-IF-ERROR.

    Negative control (MANDATORY, same origin behaviour, sibling location with
    cache_turbo_keep_stale off): the identical dead-origin request against
    /keepstaleoff/ must surface a 502 -- proving the 200 above is caused by
    keep_stale, not some other widening (SWR/stale_mult) leaking into the
    expired path."""
    s0, b0, _ = fetch(ng.port, "/keepstale/x")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    sn0, bn0, _ = fetch(ng.port, "/keepstaleoff/x")
    assert sn0 == 200 and bn0, f"control prime failed: {sn0} {bn0!r}"

    time.sleep(4.6)     # past fresh (1s) AND the stale window (x4 = 4s): expired
    origin.drop = True
    try:
        # Positive: keep_stale covers the outage -> stale body served.
        s, b, h = fetch(ng.port, "/keepstale/x")
        assert s == 200, f"keep_stale dead-origin served {s}, expected stale 200"
        assert b == b0, f"served {b!r}, expected stale {b0!r}"
        assert h.get("x-cache") == "STALE-IF-ERROR", \
            f"expected STALE-IF-ERROR, got x-cache={h.get('x-cache')}"

        # Negative control: keep_stale off -> no fallback window -> the dead
        # origin's connection-drop surfaces as 502, proven BY THIS ASSERTION.
        sc, _, hc = fetch(ng.port, "/keepstaleoff/x")
        assert sc == 502, \
            f"keep_stale off served {sc}, expected 502 (no serve-on-error window)"
        assert hc.get("x-cache") != "STALE-IF-ERROR", \
            "keep_stale off must not serve-on-error"
    finally:
        origin.drop = False
        drain_origin(origin)


def test_use_stale_http_404(ng: Nginx, origin: Origin) -> None:
    """S4.2: cache_turbo_use_stale selects WHICH upstream statuses fall back to
    a stale copy, replacing the hardcoded "any 5xx" trigger in the header
    filter. /usestale404/ names http_404 and nothing else.

    Four assertions, and the three negatives are the point (S4.1-b: the S4.1
    parse tests cannot observe the mask at all, so every mutation below survives
    them unchanged):

      1. 404 on /usestale404/ -> stale served. The mask read works and a
         non-5xx status can now trigger, which was impossible before S4.2.
      2. 503 on /usestale404/ -> surfaces as 503. Kills a mask read that
         triggers unconditionally, and kills "http_404 also sets the 5xx bits".
      3. 404 on /usestaledefault/ -> surfaces as 404. Kills a widened
         USE_STALE_DEFAULT and proves the merge default is not simply "all
         bits". This is the assertion that fails if UNSET-vs-0 merging breaks
         in the direction of over-triggering.
      4. 503 on /usestaledefault/ -> stale served. The default still reproduces
         the pre-S4.2 behaviour byte-for-byte; without this, dropping the 5xx
         bits from the default would read as a pass.

    Both locations carry keep_stale 1h, so the serve-on-error window itself is
    identical and the mask is the only variable."""
    s0, b0, _ = fetch(ng.port, "/usestale404/x")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    sd0, bd0, _ = fetch(ng.port, "/usestaledefault/x")
    assert sd0 == 200 and bd0, f"default-location prime failed: {sd0} {bd0!r}"

    time.sleep(4.6)     # past fresh (1s) AND the stale window (x4 = 4s): expired
    origin.fail = True
    try:
        # 1. named status triggers.
        origin.fail_status = 404
        s, b, h = fetch(ng.port, "/usestale404/x")
        assert s == 200, f"use_stale http_404 served {s}, expected stale 200"
        assert b == b0, f"served {b!r}, expected stale {b0!r}"
        assert h.get("x-cache") == "STALE-IF-ERROR", \
            f"expected STALE-IF-ERROR, got x-cache={h.get('x-cache')}"

        # A stale serve fires a background refresh subrequest, which hits the
        # (still failing) origin asynchronously. Settle it before the next
        # request: otherwise the following fetch races that in-flight refresh on
        # the shared keepalive connection and can time out rather than fail an
        # assertion. Same reason the keep_stale tests drain before returning.
        drain_origin(origin)

        # 2. an unnamed status does NOT trigger, even though it is a 5xx and
        #    would have triggered under the pre-S4.2 hardcoded condition.
        origin.fail_status = 503
        s2, _, h2 = fetch(ng.port, "/usestale404/x")
        assert s2 == 503, \
            f"use_stale http_404 served {s2} on a 503, expected the origin's 503"
        assert h2.get("x-cache") != "STALE-IF-ERROR", \
            "a status outside the mask must not serve-on-error"

        # 3. default mask does NOT cover 404.
        origin.fail_status = 404
        s3, _, h3 = fetch(ng.port, "/usestaledefault/x")
        assert s3 == 404, \
            f"default use_stale served {s3} on a 404, expected the origin's 404"
        assert h3.get("x-cache") != "STALE-IF-ERROR", \
            "the default mask must not serve-on-error for 404"

        # 4. default mask still covers 5xx exactly as it did before S4.2.
        origin.fail_status = 503
        s4, b4, h4 = fetch(ng.port, "/usestaledefault/x")
        assert s4 == 200, f"default use_stale served {s4} on a 503, expected stale 200"
        assert b4 == bd0, f"served {b4!r}, expected stale {bd0!r}"
        assert h4.get("x-cache") == "STALE-IF-ERROR", \
            f"expected STALE-IF-ERROR, got x-cache={h4.get('x-cache')}"
    finally:
        origin.fail = False
        origin.fail_status = 503
        drain_origin(origin)


def test_use_stale_any_5xx_bit(ng: Nginx, origin: Origin) -> None:
    """S4.2 / S4.1-b: pins the ANY_5XX bit, which no config token can set and
    which the parse tests cannot observe.

    USE_STALE_DEFAULT is the four named 5xx bits PLUS ANY_5XX, together
    reproducing "every 5xx" -- including the ones no bit names (506, 507, 508,
    510, 511). Drop ANY_5XX from the default and the four named bits still
    cover 500/502/503/504, so every other test in this file keeps passing while
    a 507 silently stops serving stale.

      - 507 on /usestaledefault/ -> stale served (ANY_5XX present in default).
      - 507 on /usestale500/ (mask = http_500 only) -> surfaces as 507. Proves
        the 507 above is caused by ANY_5XX specifically and not by the trigger
        falling back to a 5xx range check that ignores the mask."""
    s0, b0, _ = fetch(ng.port, "/usestaledefault/y")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    s500, b500, _ = fetch(ng.port, "/usestale500/y")
    assert s500 == 200 and b500, f"http_500-location prime failed: {s500} {b500!r}"

    time.sleep(4.6)     # fully expired
    origin.fail = True
    origin.fail_status = 507
    try:
        s, b, h = fetch(ng.port, "/usestaledefault/y")
        assert s == 200, \
            f"default use_stale served {s} on a 507, expected stale 200 (ANY_5XX)"
        assert b == b0, f"served {b!r}, expected stale {b0!r}"
        assert h.get("x-cache") == "STALE-IF-ERROR", \
            f"expected STALE-IF-ERROR, got x-cache={h.get('x-cache')}"

        # Stale serve -> background refresh against the failing origin; settle
        # it before the next request (see test_use_stale_http_404).
        drain_origin(origin)

        s2, _, h2 = fetch(ng.port, "/usestale500/y")
        assert s2 == 507, \
            f"use_stale http_500 served {s2} on a 507, expected the origin's 507"
        assert h2.get("x-cache") != "STALE-IF-ERROR", \
            "http_500 alone must not cover an unnamed 5xx"
    finally:
        origin.fail = False
        origin.fail_status = 503
        drain_origin(origin)


def test_use_stale_off(ng: Nginx, origin: Origin) -> None:
    """S4.2: `cache_turbo_use_stale off` means an EMPTY mask -- no status
    triggers a stale serve, including the 5xx the default covers.

    /usestaleoff/ carries keep_stale 1h exactly like /usestaledefault/, so the
    serve-on-error window is armed and identical; only the mask differs. A 503
    must therefore surface as 503 here while the same request against the
    default location serves stale. Without this, an `off` that merged as UNSET
    (i.e. silently fell back to the default) would look identical to a working
    `off` in every other test."""
    s0, b0, _ = fetch(ng.port, "/usestaleoff/z")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"
    sd0, bd0, _ = fetch(ng.port, "/usestaledefault/z")
    assert sd0 == 200 and bd0, f"default-location prime failed: {sd0} {bd0!r}"

    time.sleep(4.6)     # fully expired
    origin.fail = True
    try:
        s, _, h = fetch(ng.port, "/usestaleoff/z")
        assert s == 503, \
            f"use_stale off served {s} on a 503, expected the origin's 503"
        assert h.get("x-cache") != "STALE-IF-ERROR", \
            "use_stale off must never serve-on-error"

        # Same request, same window, default mask -> stale. Proves the 503
        # above is caused by `off` and not by a missing or short SIE window.
        s2, b2, h2 = fetch(ng.port, "/usestaledefault/z")
        assert s2 == 200, f"default use_stale served {s2}, expected stale 200"
        assert b2 == bd0, f"served {b2!r}, expected stale {bd0!r}"
        assert h2.get("x-cache") == "STALE-IF-ERROR", \
            f"expected STALE-IF-ERROR, got x-cache={h2.get('x-cache')}"
    finally:
        origin.fail = False
        drain_origin(origin)


def test_use_stale_403_429(ng: Nginx, origin: Origin) -> None:
    """S4.2: the remaining explicit non-5xx tokens. `cache_turbo_use_stale
    http_403 http_429` must trigger on both statuses it names and on nothing
    else -- in particular not on a 503, which the DEFAULT would have covered.

    This is the multi-token arm: it also proves the parser's accumulation
    across tokens reaches the trigger intact, which the S4.1 parse tests could
    only prove as far as `nginx -t`."""
    s0, b0, _ = fetch(ng.port, "/usestale403429/w")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    time.sleep(4.6)     # fully expired
    origin.fail = True
    try:
        for status in (403, 429):
            origin.fail_status = status
            s, b, h = fetch(ng.port, "/usestale403429/w")
            assert s == 200, \
                f"use_stale http_403 http_429 served {s} on a {status}, expected stale 200"
            assert b == b0, f"served {b!r} on a {status}, expected stale {b0!r}"
            assert h.get("x-cache") == "STALE-IF-ERROR", \
                f"expected STALE-IF-ERROR on {status}, got x-cache={h.get('x-cache')}"
            # Settle the background refresh this serve fired before the next
            # iteration reuses the connection (see test_use_stale_http_404).
            drain_origin(origin)

        # A 5xx is NOT in this mask, even though the default covers it.
        origin.fail_status = 503
        s2, _, h2 = fetch(ng.port, "/usestale403429/w")
        assert s2 == 503, \
            f"use_stale http_403 http_429 served {s2} on a 503, expected the origin's 503"
        assert h2.get("x-cache") != "STALE-IF-ERROR", \
            "a status outside the mask must not serve-on-error"
    finally:
        origin.fail = False
        origin.fail_status = 503
        drain_origin(origin)


def test_keep_stale_loses_to_response_sie(ng: Nginx, origin: Origin) -> None:
    """S2.2 / D-1: a HONORED response stale-if-error wins over
    cache_turbo_keep_stale when both are available -- NOT max(). /keepstalewins/
    has keep_stale 1h (3600s) configured; the "sieserve" request-suffix marker
    makes the origin emit stale-if-error=30 for this request, same convention as
    /sieserve/. If the precedence were max(), sie_window would be ttl+3600 and a
    request timed at ttl+~35s (well past the response SIE window but nowhere near
    the keep_stale window) would still serve stale. The correct precedence
    (response SIE wins outright, keep_stale is not consulted at all) makes that
    same request surface the dead origin's error instead."""
    s0, b0, _ = fetch(ng.port, "/keepstalewins/sieserve-p1")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    # Phase 1 -- inside the response's own SIE window (~31s). Serves stale.
    # NB this assertion is NOT the discriminating one: it passes identically
    # whether the precedence is "response SIE wins" (window ~31s) or a max()
    # bug (window ~3601s). It only establishes that a window exists at all.
    time.sleep(4.6)     # past fresh (1s) and stale_mult x4 (4s): fully expired
    origin.fail = True
    try:
        s, b, h = fetch(ng.port, "/keepstalewins/sieserve-p1")
        assert s == 200, f"within response-SIE window served {s}, expected 200"
        assert b == b0, f"served {b!r}, expected stale {b0!r}"
        assert h.get("x-cache") == "STALE-IF-ERROR", \
            f"expected STALE-IF-ERROR, got x-cache={h.get('x-cache')}"
    finally:
        origin.fail = False
        drain_origin(origin)

    # Phase 2 -- THE DISCRIMINATING ASSERTION. Past the response's own SIE
    # window (fresh 1s + sie 30s = ~31s) but far short of keep_stale's 3600s.
    # Correct precedence: sie_window ended at ~31s, keep_stale was never
    # consulted -> the dead origin surfaces as 502. Under a max() bug the
    # window would run to ~3601s and this would still serve a stale 200, so
    # this assertion is what fails if anyone "reconciles" the precedence into
    # a max(). Re-prime first: phase 1 left the entry untouched (a stale serve
    # does not re-store), so its absolute sie deadline is still ~31s from the
    # ORIGINAL store -- sleeping the remainder is what crosses it.
    time.sleep(27.0)    # ~31.6s total since the store: response SIE expired
    origin.fail = True
    try:
        s2, _, h2 = fetch(ng.port, "/keepstalewins/sieserve-p1")
        # 503 (not 502): origin.fail returns an upstream 503, which passes
        # through once no serve-on-error window covers the request.
        # origin.drop is the transport-level failure that yields 502.
        assert s2 == 503, (
            f"past the response stale-if-error window served {s2}, expected 503. "
            "A 200 here means keep_stale (3600s) widened the window the response "
            "had already scoped to 30s -- i.e. the precedence became max(), which "
            "D-1 explicitly rejects."
        )
        assert h2.get("x-cache") != "STALE-IF-ERROR", \
            "keep_stale must not extend a response-scoped stale-if-error window"
    finally:
        origin.fail = False
        drain_origin(origin)


def test_5xx_never_overwrites_cached_body(ng: Nginx, origin: Origin) -> None:
    """O6/S3.1: a legitimate negative-cache rule (cache_turbo_valid 503 1m)
    must never let an error blob overwrite a still-serveable good body -- the
    exact inverse of outage resilience. /noclobber/ has a 1s fresh TTL (x4 =
    4s stale window) plus `cache_turbo_valid 503 1m`, `background_update off`
    (the dice-winning reader regenerates INLINE/synchronously instead of
    firing a background subrequest -- deterministic, no async race to wait
    out) and a cranked `cache_turbo_beta 100000` so the very first stale-path
    request wins the refresh dice for certain (threshold saturates to
    guaranteed almost immediately after fresh_until, see
    ngx_http_cache_turbo_should_refresh's elapsed_frac*beta model).

    Sequence: warm with a 200, sleep past fresh_until (1s) but well inside
    the stale window (4s) -- entry is stale-but-serveable, exactly the case
    the guard predicate's `now < stale_until` branch protects. The dice
    winner goes straight to origin inline; origin answers a clean 503 (NOT
    origin.drop -- that is a transport-level 502, a different code path).
    That 503 is what `cache_turbo_valid 503 1m` would normally negative-cache
    -- clobbering the good entry without the guard. A second request right
    after must still see the ORIGINAL 200 body from cache. Once the origin
    recovers a 200 must still be served, though NOT necessarily the original
    body: the entry is past fresh_until, so a healthy refresh may legitimately
    replace it (the guard blocks ERROR stores, it does not freeze good ones)."""
    s0, b0, _ = fetch(ng.port, "/noclobber/x")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    time.sleep(2.5)     # past fresh (1s), well inside stale window (fresh+4=5s)
    origin.fail = True
    try:
        # The stale-but-serveable dice winner regenerates inline (background_
        # update off) and gets the origin's 503 back. Without the guard this
        # STORES the 503 into L1, clobbering the good body.
        s1, _, _ = fetch(ng.port, "/noclobber/x")
        assert s1 == 503, f"expected the origin's 503 to pass through, got {s1}"

        # THE DISCRIMINATING ASSERTION: a second request right after must
        # still see the ORIGINAL 200 body, not a cached 503. If the guard is
        # missing/disabled, the first request's 503 got stored and this
        # request is served straight from cache as a 503 with no body match.
        s2, b2, _ = fetch(ng.port, "/noclobber/x")
        assert s2 == 200, (
            f"second stale-path request got {s2}, expected 200 -- the prior "
            "503 was allowed to overwrite the cached body"
        )
        assert b2 == b0, f"served {b2!r}, expected original body {b0!r}"
    finally:
        origin.fail = False
        drain_origin(origin)

    # After the origin recovers, a 200 must be served -- either the retained
    # original or a fresh regeneration.
    #
    # ⚠ Deliberately NOT `b3 == b0`. The entry is past fresh_until, so once the
    # origin is healthy again a refresh legitimately stores a NEW body: that is
    # the cache working, not the guard failing. Asserting the original body
    # survives recovery would demand the entry never refresh again, and the
    # assertion DID fail that way (`gen-5356` != `gen-5354`) while the guard
    # itself was working correctly. The guard's contract is "an ERROR must not
    # replace a good body", never "a good body is frozen".
    s3, b3, _ = fetch(ng.port, "/noclobber/x")
    assert s3 == 200, f"post-recovery request got {s3}, expected 200"
    assert b3, "post-recovery served an empty body"


def test_5xx_cta_bypass_never_overwrites_cached_body(ng: Nginx,
                                                      origin: Origin) -> None:
    """AUD-5XX-CTA: the "refuse to overwrite a good cached body with an error
    status" guard used to be a separate check-then-act -- lock, lookup,
    decide `protect`, unlock, THEN store re-locked later. cache_turbo_bypass
    is the one path that skips BOTH the lookup and the single-flight claim
    while still permitting a store, so a bypassed request has no earlier
    serialization point at all and drives the guard's predicate and its write
    through two independent lock acquisitions -- exactly the window
    AUD-5XX-CTA closes by folding both into shm_store_if() under ONE lock.

    /cta5xx/ seeds a normal 200 (cacheable 30s), then every further request
    goes through ?nocache=1 (cache_turbo_bypass), which always reaches the
    origin and always attempts a store on the way back regardless of cache
    state. With the origin forced to answer 503 (negative-cacheable via
    `cache_turbo_valid 503 1m`), the guard must refuse to let that 503
    displace the still-fresh 200 seeded above. A subsequent NON-bypassed read
    must still return the original 200 body -- under the pre-fix bug the 503
    clobbers the entry and this read comes back as a cached 503 (or a
    mismatched body from a second store race)."""
    s0, b0, _ = fetch(ng.port, "/cta5xx/x")
    assert s0 == 200 and b0, f"prime failed: {s0} {b0!r}"

    origin.fail = True
    origin.fail_status = 503
    try:
        # Bypass: skips lookup + single-flight, still stores. This is the
        # store-path call that must be refused by the guard.
        s1, _, _ = fetch(ng.port, "/cta5xx/x?nocache=1")
        assert s1 == 503, \
            f"bypassed request should reach origin's 503, got {s1}"

        # A second bypass for good measure -- makes a single successful
        # refusal insufficient if the guard only holds up once.
        s1b, _, _ = fetch(ng.port, "/cta5xx/x?nocache=1")
        assert s1b == 503, \
            f"second bypassed request should also reach origin's 503, got {s1b}"
    finally:
        origin.fail = False
        drain_origin(origin)

    # THE DISCRIMINATING ASSERTION: a plain (non-bypass) read must still HIT
    # the original 200 body. Under the pre-fix check-then-act bug, the
    # bypassed store above overwrote the entry with the negative-cached 503,
    # and this read would come back 503 with an empty/mismatched body.
    s2, b2, h2 = fetch(ng.port, "/cta5xx/x")
    assert s2 == 200, (
        f"post-bypass plain read got {s2}, expected 200 -- the bypassed 5xx "
        "store was allowed to overwrite the cached body (AUD-5XX-CTA)"
    )
    assert b2 == b0, f"served {b2!r}, expected original body {b0!r}"
    assert h2.get("x-cache") == "HIT", \
        f"post-bypass plain read expected a cache HIT, got {h2.get('x-cache')!r}"


def test_keep_stale_no_reaper_lru_only_reclaim(ng: Nginx, origin: Origin) -> None:
    """S2.3 CONTRACT: an L1 node past its stale deadline but still inside its
    cache_turbo_keep_stale window is reclaimed ONLY by LRU/max_size pressure --
    there is no time-based reaper proactively evicting it. Verified against
    src/ngx_http_cache_turbo_shm.c: the only eviction path is
    ngx_http_cache_turbo_shm_evict_one(), called exclusively from
    ngx_http_cache_turbo_shm_alloc_evict() on an allocation failure inside
    store()/claim()/count_miss()/l2_neg_set(). No ngx_add_timer/event-driven
    sweep touches the LRU queues anywhere in the module. This is deliberate,
    not a gap -- do not "fix" it with a reaper.

    /ksev/ (zone ksevz, 8m->64k, the enforced minimum) has cache_turbo_valid 1s
    and cache_turbo_keep_stale 1h, so an entry is fresh for ~1s and then sits
    deep inside a 3600s keep-stale window for the rest of this test.

    Phase 1 (retention across an idle gap): prime one key, let it go stale,
    wait past the stale deadline with NOTHING else touching the zone, then
    kill the origin and confirm the key still serves a stale 200.

    ⚠ SCOPE OF THIS PHASE -- do not over-trust it. The idle gap is only ~2.3s,
    so it does NOT rule out a time-based reaper in general: any plausible
    sweep cadence (seconds to minutes) could hide inside this window and the
    assertion would still pass. What phase 1 actually proves is narrower and
    still worth having -- that an expired-but-inside-keep_stale node is
    RETAINED and SERVEABLE rather than dropped at its stale deadline, which is
    the behaviour keep_stale exists to provide. The real evidence for the
    no-reaper contract is the source read recorded in the first paragraph
    (there is no ngx_add_timer sweep to find), not this sleep. Lengthening the
    wait would buy very little and cost the suite real wall-clock; if you ever
    need the stronger claim, assert it against the source, not the clock.

    Phase 2 (discriminates "LRU is what DOES reclaim it"): with the same key
    still resident, flood the same tiny zone with enough distinct keys to
    force real max_size eviction. The original key must now be gone (a fresh
    MISS body, not the stale one) -- proving reclaim genuinely happens, just
    triggered by capacity pressure rather than a clock. Without this phase,
    phase 1 alone can't distinguish "no reaper" from "eviction is broken
    entirely"."""
    key = "/ksev/no-reaper"

    # Prime, then let TTL (1s) elapse so the entry is genuinely stale.
    s0, b0, h0 = fetch(ng.port, key)
    assert s0 == 200, f"prime {key} -> {s0}"
    assert h0.get("x-ct-status") == "MISS", f"prime not a MISS: {h0.get('x-ct-status')}"
    time.sleep(1.3)   # cross the 1s valid window -> now stale, deep in keep_stale

    # Nothing touches ksevz here. If a reaper swept expired-but-keep-stale
    # nodes on a timer, this idle gap is exactly where it would fire.
    time.sleep(1.0)

    origin.fail = True
    try:
        s1, b1, _ = fetch(ng.port, key)
        # A time-based reaper would have removed this node already, so the
        # request would MISS, hit the dead origin, and surface an error (503)
        # instead of serving the retained stale body.
        assert s1 == 200, (
            f"{key} returned {s1} with origin down after an idle wait -- "
            "expected a stale 200. A non-200 here means the entry was reaped "
            "by something other than LRU/max_size pressure, violating the "
            "no-reaper contract."
        )
        assert b1 == b0, (
            f"{key} body changed ({b0!r} -> {b1!r}) with origin down -- "
            "expected the SAME retained stale node, not a refill"
        )
    finally:
        origin.fail = False
        drain_origin(origin)

    # Phase 2: force real LRU/max_size eviction in the SAME tiny zone by
    # flooding it with enough distinct keys to overflow 64k. The original key
    # must be gone afterward -- reclaim happens, just via capacity, not time.
    for i in range(120):
        fetch(ng.port, f"/ksev/flood-{i}")

    s2, b2, h2 = fetch(ng.port, key)
    assert s2 == 200, f"post-flood {key} -> {s2}"
    assert h2.get("x-ct-status") == "MISS", (
        f"{key} still resident after flooding ksevz to capacity "
        f"(status={h2.get('x-ct-status')}) -- LRU/max_size pressure is "
        "supposed to be the actual reclaim mechanism; if it never evicts "
        "either, entries would accumulate in a keep_stale zone forever."
    )
    assert b2 != b0, (
        f"{key} served the SAME stale body ({b0!r}) after eviction pressure -- "
        "the old node should have been reclaimed and this should be a fresh refill"
    )


def test_background_update_off_regenerates_inline(ng: Nginx,
                                                  origin: Origin) -> None:
    """v8: cache_turbo_background_update off restores the pre-v8 winner — the
    stale dice-winner regenerates INLINE and serves the freshly regenerated body
    on that same request (live origin response, no X-Cache header), rather than
    serving stale and refreshing in the background."""
    s0, b0, _ = fetch(ng.port, "/noswr/x")         # prime
    assert s0 == 200 and b0
    time.sleep(2.3)                                # stale
    # aggressive beta -> a stale read wins the dice; bg-off -> it regenerates
    # inline and the response is the live origin body (no X-Cache), a NEW gen.
    deadline = time.time() + 3.0
    got_fresh_inline = False
    while time.time() < deadline:
        s, b, h = fetch(ng.port, "/noswr/x")
        assert s == 200
        if b != b0 and "x-cache" not in h:
            got_fresh_inline = True
            break
        time.sleep(0.1)
    assert got_fresh_inline, \
        "bg-off winner should serve a freshly regenerated body inline"


def _admin_lock_waits(ng: Nginx, path: str = "/_cache") -> int:
    """Default path reads zone `main`'s admin endpoint; pass path= for a
    private-zone endpoint like /_cache_s71 or /_cache_storefail so the
    lock_waits delta is not polluted by unrelated locations sharing `main`."""
    import json
    _, b, _ = fetch(ng.port, path)
    return int(json.loads(b).get("lock_waits", 0))


def _admin_stat(ng: Nginx, name: str, path: str = "/_cache") -> int:
    """S7.1: read one named counter off an admin JSON endpoint (default
    /_cache, zone `main`; pass path= for a private-zone endpoint like
    /_cache_s71). Generic sibling of _admin_lock_waits, used for the new
    sie_serves / breaker_serves / origin_failures fields so each test does
    not restate its own json.loads. A missing key reads 0 via .get(),
    matching the field's "not yet exercised" state -- the tests below never
    assert a bare presence check, only that a delta MOVES, so a build without
    the field would show a 0 delta and fail loudly rather than silently
    pass."""
    import json
    _, b, _ = fetch(ng.port, path)
    return int(json.loads(b).get(name, 0))


def _admin_str(ng: Nginx, name: str, path: str = "/_cache") -> str:
    """String-valued sibling of _admin_stat, for breaker_state (the only
    non-numeric field on the admin JSON). Deliberately defaults to "" rather
    than "closed" on a missing key: a build that stopped emitting the field
    must fail the assertion, not read as the state the caller hoped for."""
    import json
    _, b, _ = fetch(ng.port, path)
    return str(json.loads(b).get(name, ""))


def test_cold_single_flight(ng: Nginx, origin: Origin) -> None:
    """v10: a burst of first-hits on ONE virgin (never-cached) key collapses to a
    single origin fetch — the first request regenerates, the rest WAIT for the
    fill and then serve it, instead of every reader stampeding the origin."""
    uri = "/cold/sf"                               # never fetched before
    base = origin.hits
    waits0 = _admin_lock_waits(ng)

    # Rendezvous before the burst for the same reason as
    # test_l2_unserveable_giveup_still_single_flights: a reader that arrives
    # after the winner's fill lands takes the CLAIM_FRESH path and serves from
    # L1 without entering cold_wait(), so it never increments lock_waits. Left
    # unsynchronised, a staggered thread start can drive the delta to 0 while
    # the collapse itself was correct.
    readers = 40
    barrier = threading.Barrier(readers)

    def _burst_reader(_i: int) -> tuple[int, bytes, dict]:
        barrier.wait()
        return fetch(ng.port, uri)

    with concurrent.futures.ThreadPoolExecutor(max_workers=readers) as pool:
        results = list(pool.map(_burst_reader, range(readers)))
    assert {r[0] for r in results} == {200}, \
        f"cold burst returned {set(r[0] for r in results)}"
    # All readers must agree on one body (the single regenerated copy).
    bodies = {r[1] for r in results}
    assert len(bodies) == 1, f"cold burst served {len(bodies)} distinct bodies"
    regens = origin.hits - base
    assert regens <= 3, \
        f"cold single-flight failed: {regens} origin fetches for 40 readers"
    # The collapse must have happened via the wait path (not just lucky timing).
    assert _admin_lock_waits(ng) - waits0 > 0, \
        "no requests waited — single-flight did not engage"
    drain_origin(origin)


def test_cold_lock_off_stampedes(ng: Nginx, origin: Origin) -> None:
    """v10 gate: with cache_turbo_lock off, the same cold burst is NOT collapsed —
    far more than one reader reaches the origin (proves the lock is what coalesces,
    not some other serialisation)."""
    uri = "/coldoff/sf"
    base = origin.hits
    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
        results = list(pool.map(lambda _: fetch(ng.port, uri), range(40)))
    assert {r[0] for r in results} == {200}, \
        f"cold(off) burst returned {set(r[0] for r in results)}"
    regens = origin.hits - base
    assert regens > 3, \
        f"lock-off should stampede; only {regens} origin fetches for 40 readers"
    drain_origin(origin)


def test_store_failure_cleans_up_cold_stub(ng: Nginx, origin: Origin) -> None:
    """AUD-STORE-ERR-STUB: a failed store() must NOT leave ctx->cold_stored set,
    or the cold-miss winner's pool cleanup (armed only while !cold_stored) never
    runs and the stub it left behind blocks every waiter until lock_timeout.

    /storefail/ forces l1->store() to fail deterministically
    (cache_turbo_test_store_fail) on a virgin key. Request 1 is the cold-miss
    winner: its store fails, so with the bug (ctx->cold_stored set
    unconditionally) the winner's pool cleanup sees cold_stored=1, skips
    unstub(), and the stub is never reclaimed. Request 2 then finds that live
    stub and PARKS in cold_wait().

    The oracle is cache_turbo's own lock_waits counter, not wall-clock time.
    An earlier version of this test asserted `elapsed < 1.0` and passed against
    a deliberately reintroduced bug: with a short lock_ttl the leaked stub's
    lease is already expired by the time request 2 arrives, so claim() ADOPTS
    it (module.c:5942) instead of waiting, and the buggy build is just as fast
    as the fixed one. lock_waits increments at module.c:6003, on entry to
    cold_wait() -- exactly and only when a request parks on a stub that should
    not exist. lock_ttl is 30s here so the lease cannot expire out from under
    the assertion and turn a park into an adopt.

    /storefail/ binds its OWN zone (storefailz), not `main` -- `main` is
    shared by 166 other test locations, including test_cold_single_flight's
    40 deliberately-parking concurrent readers, and a straggler from that
    (or any other) test landing between this test's w0/w1 samples used to
    break the exact-equality assert on an unrelated build. Reading
    lock_waits off /_cache_storefail (storefailz's own admin endpoint)
    instead of /_cache (zone `main`) makes the delta observe only
    /storefail/'s own traffic, so the exact-equality assert is meaningful
    again.

    Fixed build: request 1's cleanup unstubs (store failed => cold_stored
    stays 0), request 2 claims a virgin key, lock_waits does not move.
    Buggy build: the stub survives with a live lease, request 2 parks,
    lock_waits increments."""
    uri = f"/storefail/stub-{time.time()}"

    w0 = _admin_lock_waits(ng, "/_cache_storefail")
    s1, b1, _ = fetch(ng.port, uri)
    assert s1 == 200 and b1, f"cold-miss winner (store forced to fail) failed: {s1}"

    s2, b2, _ = fetch(ng.port, uri)
    assert s2 == 200 and b2, f"second request after failed store got {s2}"
    w1 = _admin_lock_waits(ng, "/_cache_storefail")

    assert w1 == w0, (
        f"lock_waits moved {w0} -> {w1}: the second request parked in "
        "cold_wait() on the cold-miss stub left behind by the failed store "
        "(AUD-STORE-ERR-STUB: ctx->cold_stored was set even though store() "
        "returned NGX_ERROR, so the pool cleanup skipped unstub())")
    drain_origin(origin)


def _admin_l2_misses(ng: Nginx) -> int:
    import json
    _, b, _ = fetch(ng.port, "/_cache")
    return int(json.loads(b).get("l2_misses", 0))


def test_cross_node_winner_owner_token_preserved(ng: Nginx, origin: Origin,
                                                 redis: RedisServer) -> None:
    """AUD-NXLOCK-OWNER: the cross-node NX-lock resume path must hand
    cold_mark_winner() the SAME L1 owner token claim() issued before the park,
    not a literal 0.

    Mechanism: claim() at the top of the `if (clcf->lock)` block takes an L1
    lease (a stack local claim_owner, non-zero) before firing the cross-node
    Redis NX lock and parking (NGX_AGAIN). On resume (ctx->lock_done), the
    request is unconditionally a former CLAIM_WINNER -- an L1 lease WAS taken
    -- yet the pre-fix code passed a literal 0 to cold_mark_winner(), because
    the stack local does not survive the park/resume. shm_unstub() is a no-op
    when owner == 0 (ngx_http_cache_turbo_shm.c ~913), so a winner whose
    response turns out non-cacheable can never release its stub: the header
    filter's immediate unstub() (module.c ~7861) and the pool-cleanup backstop
    both pass owner=0 and both silently no-op, leaving the node `refreshing`
    with a lease nobody can ever match (CTXRDR-ADOPT-LEASE's owner identity
    check requires refresh_owner == owner, and 0 is rejected outright).

    Oracle: lock_waits (bumped only on ENTRY to cold_wait()), not wall clock.
    A leaked stub only delays a later request while the lease is still live;
    with a short lock_ttl the lease would simply expire and the next claim()
    would ADOPT the stub instead of parking, making a buggy build exactly as
    fast as a fixed one. /coldl2ns/ uses a 30s lock_ttl so that cannot happen
    inside this test's timeframe.

    Why the second probe is a SEPARATE, redis-less location and not a second
    /coldl2ns/ request: the cross-node Redis NX lock is deliberately never
    unlock()ed (module.c ~6015 -- unlocking early would re-open the fleet-wide
    dogpile window), so it stays SET for the full lock_ttl regardless of this
    bug. A second /coldl2ns/ request always parks on THAT lock, which would
    make lock_waits move on a fixed build too and give a vacuous test. The two
    locations share the `main` zone and a FIXED cache_turbo_key (not $uri), so
    they hash to the identical L1 node -- but /coldl2ns_probe/ has no L2
    backend configured, so its claim() can only ever see the shared L1 state
    and can never itself touch or park on Redis.

    /coldl2ns/ (cache_turbo_no_store $arg_private, lock default ON, L2-backed)
    makes the FIRST request for a virgin key a non-cacheable cross-node
    winner: it takes the L1 claim, fires+wins the uncontested NX lock, resumes
    with lock_result == NGX_OK, and its no_store response never reaches the
    body-filter store -- forcing the header-filter unstub() at ~7861 to be the
    ONLY thing that can release the L1 lease. A probe request against the SAME
    key on /coldl2ns_probe/ must then find the L1 stub already released
    (claim() sees `refreshing == 0` -> CLAIM_WINNER, straight to origin) and
    must NOT park in cold_wait(), because parking there is only reachable via
    CLAIM_LOSER, which requires the stub to still read `refreshing` -- exactly
    the leak this test targets."""
    key = "aud-nxlock-owner-probe"
    redis.cli("DEL", l2_key(key), lock_key(key))

    waits0 = _admin_lock_waits(ng)

    s1, _, h1 = fetch(ng.port, "/coldl2ns/owner?private=1")
    assert s1 == 200, f"cross-node winner status {s1}"
    assert "x-cache" not in h1, \
        f"no_store response must not be a HIT: {h1.get('x-cache')}"

    # The winner's own request must not have parked (it IS the winner).
    assert _admin_lock_waits(ng) - waits0 == 0, \
        (f"lock_waits moved by {_admin_lock_waits(ng) - waits0} on the winner's "
         "own request -- fixture defect, not the bug under test")

    # THE assertion. The probe location shares the L1 zone + key with the
    # winner above but has no L2 backend of its own, so it can only observe
    # -- never touch -- the shared L1 stub. If owner==0 leaked past unstub(),
    # the L1 node is still `refreshing` and this probe's claim() returns
    # CLAIM_LOSER, parking in cold_wait() and bumping lock_waits.
    s2, _, _ = fetch(ng.port, "/coldl2ns_probe/owner")
    assert s2 == 200, f"probe request status {s2}"
    assert _admin_lock_waits(ng) - waits0 == 0, \
        (f"lock_waits moved by {_admin_lock_waits(ng) - waits0}: the probe "
         "request for the same L1 key PARKED in cold_wait() instead of "
         "finding the L1 stub already released -- the cross-node resume path "
         "handed cold_mark_winner() owner=0 instead of the stashed L1 lease "
         "token (ctx->pending_l1_owner), so shm_unstub() no-opped and the "
         "lease leaked (AUD-NXLOCK-OWNER)")

    drain_origin(origin)


def test_l2_miss_counted_once_on_cold_park(ng: Nginx, origin: Origin) -> None:
    """metrics: a single cold miss on an L2-backed, lock-ON location parks TWICE
    (once on the async L2 GET, once on the v4-2 NX lock) and re-enters the access
    handler from the top on each resume. The l2_misses counter must rise by
    exactly 1 across the whole request, not once per re-entry — guarded by
    ctx->l2_miss_counted (issues.md 'l2_misses double-count on the cold path').
    /coldl2/ is L2-backed with cache_turbo_lock default ON, so a virgin key
    exercises both parks."""
    uri = "/coldl2/misscount"                      # virgin key, lock default ON
    misses0 = _admin_l2_misses(ng)
    s, _, h = fetch(ng.port, uri)
    assert s == 200, f"cold L2 fetch status {s}"
    assert "x-cache" not in h, \
        f"first cold fetch must reach origin, not HIT: {h.get('x-cache')}"
    delta = _admin_l2_misses(ng) - misses0
    assert delta == 1, \
        f"l2_misses rose by {delta}, expected exactly 1 (cold-path double-count)"
    drain_origin(origin)


def _admin_min_uses_skips(ng: Nginx, endpoint: str = "/_cache") -> int:
    """v15 count of stores skipped because the key was below min_uses.

    ⚠ Zone-global, exactly like l2_neg_skips (see _admin_l2_neg_skips): the
    admin handler emits ONE zone's stats, so `endpoint` must name the admin
    location bound to the zone under test. /_cache is `cache_turbo_admin main`,
    /_cache_l2negmu is `cache_turbo_admin l2negmuz`. Reading the wrong one
    yields a counter the location never writes, which turns an equality
    assertion permanently true -- the SUITE-1 defect, in its min_uses form.

    /minuses/ and /pmu/ still share `main` and still use `== N` equality
    asserts, so they remain mutually contending by construction: keep any new
    min_uses location OUT of `main`, or give it a private zone + endpoint."""
    import json
    _, b, _ = fetch(ng.port, endpoint)
    return int(json.loads(b).get("min_uses_skips", 0))


def test_min_uses(ng: Nginx, origin: Origin) -> None:
    """v15 cache_turbo_min_uses N: a response is cached only after its key has
    cold-missed N times. /minuses/ sets N=3 — the first two misses run to the
    origin without storing, the third stores, the fourth is a HIT served from
    cache. The min_uses_skips counter rises by exactly the two skipped misses."""
    uri = "/minuses/page1"                       # never fetched before
    base = origin.hits_for("/page1")
    skips0 = _admin_min_uses_skips(ng)

    # Below threshold: misses 1 and 2 both reach the origin, neither is cached.
    for i in (1, 2):
        s, _, h = fetch(ng.port, uri)
        assert s == 200, f"sub-threshold req{i} status {s}"
        assert "x-cache" not in h, \
            f"req{i} must NOT be a HIT (below min_uses): {h.get('x-cache')}"
    assert origin.hits_for("/page1") == base + 2, \
        f"both sub-threshold reqs must hit origin: {origin.hits_for('/page1') - base}"

    # The third miss reaches the threshold: THIS request stores (still served
    # from the origin, no X-Cache), so its body is what later HITs return.
    s, b3, h3 = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in h3, \
        "the threshold-reaching miss is served from origin, then stored"
    assert origin.hits_for("/page1") == base + 3, "the storing miss must reach the origin"

    # The fourth request is now a cache HIT — no further origin traffic.
    s, b4, h4 = fetch(ng.port, uri)
    assert h4.get("x-cache") == "HIT", f"req4 X-Cache={h4.get('x-cache')}"
    assert origin.hits_for("/page1") == base + 3, "req4 must be served from cache, not origin"
    assert b4 == b3, "the HIT body must match the response that was stored"

    # Exactly the two sub-threshold misses were skipped (origin, no store).
    assert _admin_min_uses_skips(ng) - skips0 == 2, \
        f"min_uses_skips delta {_admin_min_uses_skips(ng) - skips0} != 2"


def test_min_uses_off_by_default(ng: Nginx) -> None:
    """A location with no cache_turbo_min_uses stores on the first miss (the
    feature is off by default) — proving min_uses doesn't change the baseline."""
    s, _, h1 = fetch(ng.port, "/c/minuses-default")    # /c/ has no min_uses
    assert s == 200 and "x-cache" not in h1, "first miss must reach origin"
    s, _, h2 = fetch(ng.port, "/c/minuses-default")
    assert h2.get("x-cache") == "HIT", \
        f"second req must HIT (min_uses default 1): {h2.get('x-cache')}"


def test_min_uses_band_aggressive(ng: Nginx, origin: Origin) -> None:
    """H3c: the AGGRESSIVE band raises min_uses to 2, with NO directive present.

    This is the band column doing the work: /pab/ carries only
    `cache_turbo_preset aggressive`, so the gate can only be armed by the band's
    min_uses=2. The first miss must therefore go to the origin WITHOUT storing,
    and the second must also reach the origin (it is the one that stores), so
    the third is the first HIT.

    Contrast with min_uses=1, where request 2 would already be a HIT -- that
    single difference is what distinguishes 'the band value reached the runtime'
    from 'some caching happened'. Paired with test_min_uses_band_balanced_is_1,
    which runs the identical sequence against the default preset and DOES get a
    HIT on request 2; if the column were wired to every band, that test fails."""
    uri = "/pab/band-minuses"                    # never fetched before
    base = origin.hits
    skips0 = _admin_min_uses_skips(ng)

    # Request 1: below the band threshold -> origin, not stored.
    s, _, h1 = fetch(ng.port, uri)
    assert s == 200, f"req1 status {s}"
    assert "x-cache" not in h1, \
        f"req1 must not be a HIT: {h1.get('x-cache')}"

    # Request 2: reaches min_uses=2 -> served from origin, and THIS one stores.
    s, b2, h2 = fetch(ng.port, uri)
    assert s == 200, f"req2 status {s}"
    assert "x-cache" not in h2, \
        ("req2 must still be served from the origin under the aggressive band "
         f"(min_uses=2), got X-Cache={h2.get('x-cache')} -- the band's min_uses "
         "did not reach the runtime, i.e. the H3c column is not wired")
    assert origin.hits == base + 2, \
        f"both sub-threshold reqs must reach the origin: {origin.hits - base}"

    # Request 3: the entry stored on req2 is now serveable.
    s, b3, h3 = fetch(ng.port, uri)
    assert h3.get("x-cache") == "HIT", f"req3 X-Cache={h3.get('x-cache')}"
    assert origin.hits == base + 2, "req3 must come from cache, not the origin"
    assert b3 == b2, "the HIT body must match the response that was stored"

    # Exactly one sub-threshold miss was skipped (req1); req2 stored.
    assert _admin_min_uses_skips(ng) - skips0 == 1, \
        f"min_uses_skips delta {_admin_min_uses_skips(ng) - skips0} != 1"


def test_min_uses_band_balanced_is_1(ng: Nginx, origin: Origin) -> None:
    """H3c: BALANCED -- the DEFAULT preset -- keeps min_uses=1, so adding the
    band column changed no existing user's caching behaviour.

    /pbb/ is `cache_turbo_preset balanced` with no min_uses directive. Request 2
    must be a HIT, exactly as it was before H3c. This is the semver guard: if a
    later edit flips the BALANCED row to 2 (the change that was explicitly NOT
    signed off), this test fails rather than silently changing the first-request
    store behaviour for every default-preset deployment."""
    uri = "/pbb/band-minuses-default"            # never fetched before
    base = origin.hits_for("/band-minuses-default")

    s, _, h1 = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in h1, "first miss must reach the origin"

    s, _, h2 = fetch(ng.port, uri)
    assert h2.get("x-cache") == "HIT", \
        ("the balanced band must store on the FIRST miss (min_uses=1); got "
         f"X-Cache={h2.get('x-cache')} -- a band row other than aggressive was "
         "given min_uses > 1, which is a semver-visible default change")
    assert origin.hits_for("/band-minuses-default") == base + 1, "req2 must be served from cache"


def test_min_uses_directive_beats_band(ng: Nginx, origin: Origin) -> None:
    """H3c: an explicit cache_turbo_min_uses overrides the resolved preset band,
    the same raw/effective split as valid/beta/lock_ttl/stale_mult.

    /pmu/ is `cache_turbo_preset aggressive` (band min_uses=2) plus an explicit
    `cache_turbo_min_uses 1`. The directive must win, so request 2 is a HIT --
    whereas /pab/ (same preset, no directive) needs three requests to get one.
    Without the raw/effective wiring the band would win and req2 would miss."""
    uri = "/pmu/beats-band"                      # never fetched before
    base = origin.hits_for("/beats-band")

    s, _, h1 = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in h1, "first miss must reach the origin"

    s, _, h2 = fetch(ng.port, uri)
    assert h2.get("x-cache") == "HIT", \
        ("explicit cache_turbo_min_uses 1 must beat the aggressive band's 2, so "
         f"req2 is a HIT; got X-Cache={h2.get('x-cache')} -- the directive lost "
         "to the band, i.e. min_uses_raw is not resolving ahead of band->min_uses")
    assert origin.hits_for("/beats-band") == base + 1, "req2 must be served from cache"


def test_min_uses_rejects_out_of_range(ng: Nginx) -> None:
    """H3c: cache_turbo_min_uses is range-checked at config time.

    `0` is the arm that matters: merge_loc_conf used to coerce a value < 1 up to
    1, so accepting a literal 0 would silently mean "store on the first miss"
    rather than whatever the operator intended by it. Rejecting at parse keeps
    the directive honest -- the same lesson as stale_mult. Boundaries 1 and 32
    must stay accepted so an off-by-one range check fails here."""
    anchor = "cache_turbo_min_uses 3;"
    assert anchor in nginx_config(
        ng.root, ng.port, ng.module, ng.origin_port, 1, ng.redis_port,
        ng.redis_auth_port, ng.redis_password, ng.redis_tls_port,
        ng.redis_tls_ca, ng.memcached_port), \
        f"test fixture missing anchor {anchor!r}"

    # in-range-check arm: parses as a number, refused by the bounds
    for bad in ("0", "33"):
        r = _config_test_result(
            ng, lambda c, b=bad: c.replace(
                anchor, f"cache_turbo_min_uses {b};", 1))
        assert r.returncode != 0, \
            f"cache_turbo_min_uses {bad} was accepted by nginx -t:\n{r.stdout}"
        assert "out of range" in r.stdout, \
            f"missing/odd range diagnostic for {bad}:\n{r.stdout}"

    # parse arm: ngx_atoi has no sign handling, so a negative never reaches the
    # bounds check and surfaces as "bad value" -- rejected, different diagnostic.
    # Pinned separately so a later editor cannot collapse the two paths.
    for bad in ("-1", "abc"):
        r = _config_test_result(
            ng, lambda c, b=bad: c.replace(
                anchor, f"cache_turbo_min_uses {b};", 1))
        assert r.returncode != 0, \
            f"cache_turbo_min_uses {bad} was accepted by nginx -t:\n{r.stdout}"
        assert "bad value" in r.stdout, \
            f"missing/odd bad-value diagnostic for {bad}:\n{r.stdout}"

    # both boundaries stay legal
    for good in ("1", "32"):
        r = _config_test_result(
            ng, lambda c, g=good: c.replace(
                anchor, f"cache_turbo_min_uses {g};", 1))
        assert r.returncode == 0, \
            f"cache_turbo_min_uses {good} (a legal boundary) was rejected:\n{r.stdout}"


def _recent_memo_skips(ng: Nginx, limit: int = 8) -> str:
    """Tail the URIs most recently skipped by a negative memo, for diagnostics.

    Reads the module's own `L2 GET skipped by negative memo "<uri>"` debug line
    out of logs/error.log. Only produces anything when the harness ran with
    TEST_CT_ERRLOG=debug (see _errlog_level) -- otherwise those lines are below
    the log level and this returns a hint saying so.

    Diagnostic only: never assert on this. It exists so that a failure of a
    ZONE-GLOBAL counter assertion names the uri that actually bumped the
    counter, rather than leaving the reader to bisect the suite.
    """
    log = ng.root / "logs" / "error.log"
    try:
        text = log.read_text(errors="replace")
    except OSError as exc:
        return f"<error.log unreadable: {exc}>"
    hits = re.findall(r'L2 GET skipped by negative memo "([^"]*)"', text)
    if not hits:
        return ("<none logged -- re-run with TEST_CT_ERRLOG=debug>"
                if _errlog_level() != "debug" else "<none logged at debug>")
    return ", ".join(hits[-limit:])


def _admin_l2_neg_skips(ng: Nginx, endpoint: str = "/_cache") -> int:
    """L13: count of L2 GETs skipped by a live negative memo (admin stats).

    ⚠ `l2_neg_skips` is PER-ZONE (z->sh->l2_neg_skips) and the admin handler
    emits exactly ONE zone's stats, so `endpoint` must name the admin location
    bound to the zone the location under test uses -- /_cache is
    `cache_turbo_admin main`, /_cache_l2neg is `cache_turbo_admin l2negz`.
    Reading the wrong one yields a counter the test never writes, which turns
    an `== 0` assertion permanently true (SUITE-1)."""
    import json
    _, b, _ = fetch(ng.port, endpoint)
    return int(json.loads(b).get("l2_neg_skips", 0))


def test_l2_negative_ttl_skips_repeat_get(ng: Nginx, origin: Origin,
                                          redis: RedisServer) -> None:
    """L13: after an L2 GET misses, a memo makes the next cold request for the
    same key skip the round-trip entirely.

    This measures the thing that actually changed -- the number of Redis
    connections the module opens -- NOT merely that the response is still
    correct. A test asserting only status/body would pass with or without the
    memo (the L9 lesson: a perf change needs a test that observes the op count).

    /l2neg/ has no keepalive, so each L2 op is exactly one accepted connection,
    and its min_uses 4 keeps the key below the store threshold -- so both
    requests stay on the cold-miss path that consults L2, rather than the second
    becoming an L1 HIT that trivially avoids Redis for the wrong reason."""
    uri = f"/l2neg/nomemo-{time.time()}"

    # Request 1 primes the memo: a real L2 GET that misses. Measure it alone --
    # redis.cli() shells out and opens its OWN connection, so any bookkeeping
    # between two readings would be counted as module traffic.
    before = _redis_conns_received(redis)
    s1, _, _ = fetch(ng.port, uri)
    assert s1 == 200, f"req1 status {s1}"
    time.sleep(0.4)                       # let the write-through SET settle
    first = _redis_conns_received(redis) - before
    assert first >= 1, \
        f"req1 must actually consult L2 (Redis conns delta {first} < 1)"

    # Request 2 is inside the 3s window: the memo must suppress the GET. A
    # write-through SET may still occur, so assert strictly fewer ops, not zero.
    # /_cache_l2neg, not /_cache: /l2neg/ lives in the private `l2negz` zone and
    # l2_neg_skips is per-zone, so /_cache (bound to `main`) would report a
    # counter this location never touches -- making this `>= 1` permanently
    # FALSE rather than trivially true (SUITE-1).
    skips0 = _admin_l2_neg_skips(ng, "/_cache_l2neg")
    before = _redis_conns_received(redis)
    s2, _, _ = fetch(ng.port, uri)
    assert s2 == 200, f"req2 status {s2}"
    time.sleep(0.4)
    second = _redis_conns_received(redis) - before

    assert second < first, \
        (f"req2 opened {second} Redis connections vs req1's {first} -- the "
         "negative memo did not suppress the repeat L2 GET")
    assert _admin_l2_neg_skips(ng, "/_cache_l2neg") - skips0 >= 1, \
        ("l2_neg_skips did not rise: the request avoided Redis for some other "
         "reason than the memo, so this test is not measuring the memo")


def test_l2_negative_ttl_expires(ng: Nginx, origin: Origin,
                                 redis: RedisServer) -> None:
    """L13: the memo is a BOUNDED-staleness window, not a permanent off-switch.

    The whole coherence story for this feature is "the memo expires", so the
    expiry is the load-bearing assertion: once cache_turbo_l2_negative_ttl
    seconds pass, the next request must consult L2 for real again and pick up
    anything a peer stored meanwhile. Without expiry (or with the window sliding
    forward on every memoed request) L2 would stay switched off for a hot-but-
    absent key forever -- the exact failure the re-arm guard prevents."""
    # /l2neglife/ + a "ccnostore" URI: DEFAULT min_uses (1) so the full cold path
    # including claim() runs -- claim() is what marks the node `refreshing` and is
    # the mechanism the memo-masking bug rode on, so a location with a raised
    # min_uses cannot exercise it at all (see the location comment). The
    # uncacheable origin response is what keeps the key off the store path so
    # later requests do not turn into L1 HITs.
    uri = f"/l2neglife/ccnostore-expiry-{time.time()}"

    fetch(ng.port, uri)                   # arm the memo with a real GET
    time.sleep(0.4)

    skips0 = _admin_l2_neg_skips(ng, "/_cache_l2neglife")
    fetch(ng.port, uri)                   # inside the window: skipped
    assert _admin_l2_neg_skips(ng, "/_cache_l2neglife") - skips0 >= 1, \
        "the second request should have been memo-skipped (window is 3s)"

    # Keep requesting ACROSS the whole window. Each of these is memo-skipped, and
    # each is therefore a chance for a buggy build to re-stamp l2_neg_until from
    # a miss it only "knew about" because of the memo -- which would slide the
    # window forward indefinitely and never let the expiry below happen. A single
    # mid-window request cannot detect that: the window would slide by only the
    # sleep length and the final wait would still clear it.
    # Hammer the key for LONGER than the 3s window, faster than the window, so
    # every request lands while the memo is still live. In a correct build the
    # memo is armed once and expires 3s after that first REAL miss -- mid-burst
    # -- so the tail of this loop is already consulting L2 again. In a build
    # that re-arms from memoed misses, l2_neg_until is pushed forward by every
    # request and the memo never dies while traffic continues.
    #
    # The detection therefore has to happen DURING the burst, not after it:
    # once requests stop, even a slid window lapses within one TTL, so any
    # "sleep then check" ending would pass on both builds.
    # The memo was armed once, at the first real miss. It must therefore DIE
    # mid-burst, ~3s in, and every later request in the burst must consult L2 for
    # real. Record when skips stop rising: that is the memo's true death.
    #
    # This assertion is what makes the !l2_neg_skipped re-arm guard testable. It
    # was impossible before the L13-fix (memo lifetime collapsed to ~1 request, so
    # the window was re-armed from a REAL miss every time and a guard-removed
    # Measure the memo's lifetime by counting GET COMMANDS ON THE WIRE.
    #
    # ⚠ Neither of the obvious signals works here, and both were tried:
    #
    # 1. l2_neg_skips is NOT a per-request counter. It is bumped on the skip
    #    branch in the request handler, which only runs on a request's FIRST entry
    #    with !l2_done. Measured directly (2026-07-19) it rises exactly ONCE for a
    #    key and then stays flat for the whole window while the memo keeps
    #    declining every GET -- so "skips stopped rising" means "the first skip
    #    happened", not "the memo died". Existing assertions on it are all `>= 1`
    #    liveness checks, which is why the flatness never surfaced before.
    #
    # 2. Redis CONNECTION count cannot see it either: with the memo working a
    #    request does 0 GETs + 1 write-through SET, and with the memo dead it does
    #    1 GET + 0 SETs. Both are exactly one connection on a keepalive-less
    #    location, so the metric is blind to the thing under test.
    #
    # MONITOR is the instrument that distinguishes them -- the same reason the
    # keepalive tests use it: a wire-level negative that a state query cannot show.
    with redis.start_monitor() as mon:
        t_start = time.time()
        t_end = t_start + 5.0
        samples = []      # (elapsed, GET commands issued for that request)
        statuses = []
        # 0.3s pacing: ~17 requests over 5s, enough samples to locate the memo's
        # death inside a 3s window. The key never stores (uncacheable origin
        # response), so request count is not bounded by min_uses here.
        while time.time() < t_end:
            mon.checkpoint()
            _s, _b, hdrs = fetch(ng.port, uri)
            time.sleep(0.3)   # let the request's L2 ops reach the wire
            samples.append((time.time() - t_start,
                            mon.commands_seen().count("GET")))
            statuses.append((hdrs.get("x-cache") or hdrs.get("X-Cache") or "-"))

    # ⚠ GUARD: prove the burst stayed on the path under test before reading
    # anything into its L2 traffic. If the key gets STORED mid-burst, every later
    # request is a plain L1 HIT that issues no L2 GET -- which is indistinguishable
    # from "the memo is alive" by GET count alone, and would make this test pass
    # for entirely the wrong reason. That is exactly what happened on the original
    # /l2neg/ location (min_uses 4 < burst length); see the location comment.
    assert "HIT" not in statuses, (
        f"the key was CACHED during the burst (X-Cache sequence: {statuses}) -- "
        "later requests never reached the L2 path, so the GET counts below say "
        "nothing about the memo. Raise min_uses on this location above the "
        "request count.")

    # While the memo is live the module issues NO GET; once it expires, GETs
    # resume. The last silent sample marks the memo's death.
    quiet = [t for t, n in samples if n == 0]
    talked = [t for t, n in samples if n > 0]
    memo_lifetime = max(quiet) if quiet else 0.0

    assert quiet, (
        f"every request in the burst issued an L2 GET ({samples}) -- the memo "
        "never suppressed a single GET, so it is not working at all")

    # It must have lived a MEANINGFUL fraction of its 3s window, not ~1 request.
    # This is the direct regression test for the memo-lifetime defect: before the
    # L13-fix the memo covered about ONE request (~0.2s) instead of ~3s.
    assert memo_lifetime > 1.5, (
        f"the memo stopped suppressing L2 GETs after only {memo_lifetime:.1f}s of a "
        f"3s window (per-request GET counts: {samples}) -- it is being destroyed "
        "or masked early, so the feature is largely a no-op (CodeRabbit CR-A / "
        "Codex #4 on PR #77)")

    # ...and it must actually DIE inside the burst. A build that re-arms from
    # memoed misses slides l2_neg_until forward on every request, so L2 stays
    # switched off for a hot-but-absent key indefinitely. Detection has to happen
    # DURING the burst: once traffic stops, even a slid window lapses within one
    # TTL and a "sleep then check" ending would pass on both builds. This is the
    # assertion that finally makes the !l2_neg_skipped re-arm guard testable -- it
    # was impossible while the memo only survived ~1 request.
    assert talked, (
        f"no request in a 5s burst issued an L2 GET (per-request GET counts: "
        f"{samples}) -- the 3s memo never expired, so l2_neg_until is sliding "
        "forward on memoed misses and L2 is effectively disabled for this key "
        "(the !l2_neg_skipped re-arm guard is not working)")

    time.sleep(3.5)
    skips1 = _admin_l2_neg_skips(ng, "/_cache_l2neglife")
    before = _redis_conns_received(redis)
    s, _, _ = fetch(ng.port, uri)
    assert s == 200, f"post-expiry status {s}"
    time.sleep(0.4)
    # _redis_conns_received() opens its OWN redis-cli connection, counted in
    # Redis' total_connections_received. The `before` probe's connection cancels
    # (it is in both reads); THIS probe's does not, so it inflates the delta by
    # exactly 1. Subtract it -- otherwise `>= 1` can never fail even when nginx
    # opened ZERO L2 connections, i.e. the "memo never expires, L2 stays off"
    # bug this is meant to catch ([[feedback-negative-control-or-it-isnt-a-test]]).
    nginx_l2_conns = _redis_conns_received(redis) - before - 1

    assert nginx_l2_conns >= 1, \
        (f"after the memo expired the request opened {nginx_l2_conns} Redis "
         "connections -- the memo is not expiring, so L2 is effectively disabled "
         "for this key")
    assert _admin_l2_neg_skips(ng, "/_cache_l2neglife") - skips1 == 0, \
        ("an expired memo must not count as a skip"
         "\n  NOTE l2_neg_skips is per-zone and /l2neglife/ has a PRIVATE zone"
         " (l2neglifez, s128), read here via /_cache_l2neglife. It is the only"
         " location that can WRITE that counter, so a non-zero delta is this"
         " uri's own memo -- it cannot be a sibling memo test bleeding into the"
         " window, which is what this assertion used to fail on while"
         " /l2neglife/ and /l2negmu/ both sat in `main`."
         f"\n  recently skipped keys: {_recent_memo_skips(ng, limit=8)}"
         "\n  ⚠ That key list is tailed from the WHOLE error.log, not this"
         " assertion's window, so an unrelated uri in it may predate the test"
         " entirely -- a hint, not evidence. Re-run with TEST_CT_ERRLOG=debug.")


def test_l2_negative_ttl_with_min_uses(ng: Nginx, origin: Origin,
                                       redis: RedisServer) -> None:
    """L13: the memo and min_uses share ONE counter node, so they must not
    clobber each other.

    /l2negmu/ sets min_uses 3 plus a 3s memo. Both requests below stay BELOW the
    threshold, so each one both counts a min_uses skip and (after the first)
    consults the memo -- the two features writing to the same node on the same
    request, which is the state that would break if l2_neg_set overwrote
    miss_count or count_miss reset l2_neg_until.

    The threshold must exceed the request count: with min_uses 2 the second
    request PASSES the gate and stores, so it legitimately records no skip and
    the interaction never gets exercised."""
    uri = f"/l2negmu/shared-node-{time.time()}"

    fetch(ng.port, uri)                   # miss 1: arms memo, counts 1
    time.sleep(0.4)

    skips0 = _admin_l2_neg_skips(ng, "/_cache_l2negmu")
    mu0 = _admin_min_uses_skips(ng, "/_cache_l2negmu")

    s, _, _ = fetch(ng.port, uri)         # miss 2 within the window
    assert s == 200, f"req2 status {s}"

    assert _admin_l2_neg_skips(ng, "/_cache_l2negmu") - skips0 >= 1, \
        "the memo stopped working once min_uses shared the node"
    assert _admin_min_uses_skips(ng, "/_cache_l2negmu") - mu0 >= 1, \
        "min_uses stopped counting once the memo shared the node"


def test_l2_negative_ttl_not_armed_by_outage(ng: Nginx, origin: Origin,
                                             redis: RedisServer) -> None:
    """L13-fix (Codex #5): an L2 OUTAGE must not arm the negative memo.

    The memo asserts "L2 does not have this key". A failed round-trip does not
    establish that -- it establishes nothing. Arming on failure is fail-slow
    amplification: every failed GET arms a memo, the memos then suppress the very
    GETs that would notice L2 coming back, and the cache stays switched off for up
    to l2_negative_ttl PAST recovery.

    So: take Redis down, drive requests (each one a connect failure, formerly
    indistinguishable from a miss), bring it back, and require that the next
    request consults L2 for real. A build that memoes transport failures skips it
    instead, and l2_neg_skips rises.

    This is precisely the scenario 5/5 green CI could not see before: the suite
    never induced an L2 outage, so the defect passed every existing assertion."""
    uri = f"/l2negout/outage-{time.time()}"

    redis.stop()
    outage_start = time.monotonic()
    try:
        # Each request now fails to reach L2. Formerly every one of these armed a
        # memo asserting the key was absent.
        for _ in range(3):
            s, _, _ = fetch(ng.port, uri)
            assert s == 200, \
                f"request during L2 outage returned {s}; origin must still serve"
    finally:
        redis.start()

    # Redis is back. The next request MUST consult it -- that is how recovery is
    # noticed. Assert on the skip counter (did the memo suppress it?), not merely
    # on the status, which is 200 either way.
    skips0 = _admin_l2_neg_skips(ng, "/_cache_l2negout")
    s, _, _ = fetch(ng.port, uri)
    assert s == 200, f"post-recovery status {s}"
    elapsed = time.monotonic() - outage_start

    # ⚠ Codex MAJOR-1: delta == 0 is only EVIDENCE while a memo armed by the
    # outage would still be live. If the restart outran the memo, a build WITH
    # the arm-on-failure bug also reports 0 -- the assertion below would pass
    # for the wrong reason and this test would silently stop guarding anything.
    # /l2negout/ uses a 60s memo precisely so this cannot happen; if it ever
    # does, fail LOUDLY here rather than reporting a meaningless pass.
    assert elapsed < 30, (
        f"outage window + restart took {elapsed:.1f}s, which is close enough to "
        "/l2negout/'s 60s l2_negative_ttl that a memo armed by the outage could "
        "have expired on its own. The delta assertion below would then pass even "
        "with the bug present, so this run proves nothing -- treat it as "
        "INCONCLUSIVE and raise the memo, do not relax the check.")

    delta = _admin_l2_neg_skips(ng, "/_cache_l2negout") - skips0
    assert delta == 0, (
        "an L2 outage armed the negative memo: the post-recovery request was "
        "memo-skipped instead of re-consulting L2, so a transient outage keeps L2 "
        "switched off for up to l2_negative_ttl afterwards (Codex #5)"
        f"\n  l2_neg_skips delta={delta} (expected 0), this test's uri={uri}"
        f"\n  recently skipped keys: {_recent_memo_skips(ng, limit=8)}"
        "\n  NOTE l2_neg_skips is per-zone and /l2negout/ has a PRIVATE zone"
        " (l2negoutz), read here via /_cache_l2negout. /l2negout/ is the only"
        " location that can WRITE that counter (the admin location is bound to"
        " the same zone but only reads it), so a non-zero delta is this uri's"
        " own memo and cannot be another location bleeding into the window."
        "\n  ⚠ The key list above is tailed from the WHOLE error.log, not from"
        " this assertion's window, so an unrelated uri in it may predate the"
        " test entirely -- it is a hint, not evidence. Re-run with"
        " TEST_CT_ERRLOG=debug to populate it.")


def test_min_uses_counter_survives_uncacheable(ng: Nginx, origin: Origin,
                                               redis: RedisServer) -> None:
    """L13-fix (CodeRabbit CR-B): an uncacheable response must not reset the
    min_uses counter.

    unstub() frees the leftover cold-miss stub when a winner's response turns out
    non-cacheable. A min_uses counter node has the same body-less shape as that
    stub, so a shape-based predicate freed it too -- silently discarding the
    accumulated miss_count and restarting the threshold from zero. A key that is
    requested repeatedly would then never reach min_uses and never get cached.

    /l2negmu/ sets min_uses 3. The URI contains "ccnostore", which makes the test
    origin answer `Cache-Control: no-store` -- a genuinely uncacheable response,
    so every request runs the non-cacheable winner teardown in unstub(). Then
    assert the counter still climbs: the min_uses skips must stop once the
    threshold is crossed. If the counter were being reset by that teardown, every
    request would keep skipping forever."""
    uri = f"/l2negmu/ccnostore-{time.time()}"

    # Five requests against a min_uses 3 location. In a correct build the counter
    # survives each uncacheable teardown, crosses 3, and the LAST requests record
    # no further min_uses skip. In a resetting build every request skips.
    # 0.3s between requests: each uncacheable response runs the cold-miss teardown,
    # and the next request must not race the winner's unstub(). At 0.1s this test
    # intermittently hit a still-claimed stub and parked, timing the suite out on
    # roughly one run in three.
    #
    # !! The sleep is a NUISANCE REDUCER, not the thing that makes this safe, and
    # it never was: lock_ttl on /l2negmu/ is 1s, so a 0.3s gap still lands well
    # inside the previous request's claim window by construction. Parking here is
    # REACHABLE and expected -- count_miss() returns NGX_OK (not NGX_DECLINED) when
    # it finds a live stub, precisely so claim() can turn this request into a
    # waiter (shm.c, "Proceed so the caller's claim() makes this request a
    # waiter"). No concurrency is needed to get a waiter in this serial test.
    # What keeps that park from failing the test is cache_turbo_lock_timeout 2s
    # on the location, which bounds the park strictly under fetch()'s 5s client
    # timeout. Both were 5s until 2026-07-20, which is the real source of the
    # "1 in N" red on slow CI runners -- not the sleep, and not unstub().
    skips_seen = []
    for _ in range(5):
        mu0 = _admin_min_uses_skips(ng, "/_cache_l2negmu")
        s, _, _ = fetch(ng.port, uri)
        assert s == 200, f"status {s}"
        skips_seen.append(_admin_min_uses_skips(ng, "/_cache_l2negmu") - mu0)
        time.sleep(0.3)

    assert skips_seen[0] >= 1, (
        f"first request recorded no min_uses skip ({skips_seen}) -- min_uses is "
        "not gating this location, so this test is not measuring the counter")
    assert skips_seen[-1] == 0, (
        f"min_uses skips per request across 5 requests: {skips_seen}. The counter "
        "never crossed its threshold of 3, i.e. it is being reset by the "
        "uncacheable-response teardown in unstub() (CodeRabbit CR-B on PR #77)")


def test_l2_negative_ttl_rejects_out_of_range(ng: Nginx) -> None:
    """L13: cache_turbo_l2_negative_ttl is range-checked at config time.

    Unlike min_uses/stale_mult, `0` is LEGAL here and means off (it is the
    default, and merge does not coerce it), so 0 is pinned as accepted -- if a
    later edit copies the min_uses setter wholesale it would start rejecting the
    documented way to disable the feature, and this test catches that. 61 is
    rejected because the memo has no invalidation channel: the cap is what keeps
    a typo from disabling L2 for a long window."""
    anchor = "cache_turbo_l2_negative_ttl  3;"
    assert anchor in nginx_config(
        ng.root, ng.port, ng.module, ng.origin_port, 1, ng.redis_port,
        ng.redis_auth_port, ng.redis_password, ng.redis_tls_port,
        ng.redis_tls_ca, ng.memcached_port), \
        f"test fixture missing anchor {anchor!r}"

    # in-range-check arm: parses as a number, refused by the bounds
    for bad in ("61", "3600"):
        r = _config_test_result(
            ng, lambda c, b=bad: c.replace(
                anchor, f"cache_turbo_l2_negative_ttl {b};", 1))
        assert r.returncode != 0, \
            f"cache_turbo_l2_negative_ttl {bad} was accepted by nginx -t:\n{r.stdout}"
        assert "out of range" in r.stdout, \
            f"missing/odd range diagnostic for {bad}:\n{r.stdout}"

    # parse arm: ngx_atoi has no sign handling, so a negative surfaces as a
    # "bad value" rather than reaching the bounds check. Pinned separately so a
    # later editor cannot collapse the two diagnostics into one.
    for bad in ("-1", "abc"):
        r = _config_test_result(
            ng, lambda c, b=bad: c.replace(
                anchor, f"cache_turbo_l2_negative_ttl {b};", 1))
        assert r.returncode != 0, \
            f"cache_turbo_l2_negative_ttl {bad} was accepted by nginx -t:\n{r.stdout}"
        assert "bad value" in r.stdout, \
            f"missing/odd bad-value diagnostic for {bad}:\n{r.stdout}"

    # 0 (off, the default) and both real boundaries stay legal
    for good in ("0", "1", "60"):
        r = _config_test_result(
            ng, lambda c, g=good: c.replace(
                anchor, f"cache_turbo_l2_negative_ttl {g};", 1))
        assert r.returncode == 0, \
            (f"cache_turbo_l2_negative_ttl {good} (legal) was rejected:\n{r.stdout}")


def test_keep_stale_config_parse(ng: Nginx) -> None:
    """S2.1: cache_turbo_keep_stale <off|time|forever> -- PARSER ONLY, no
    runtime read yet (that is S2.2). Cover every accept/reject arm named in
    the plan: off, a plain time, forever, an invalid token, and a duplicate
    directive in one block. The negative control for each reject case is the
    literal expected diagnostic string, not merely a nonzero exit -- nginx -t
    failing for the WRONG reason would pass a bare-returncode assertion."""
    anchor = "cache_turbo_valid 30s;"
    assert anchor in nginx_config(
        ng.root, ng.port, ng.module, ng.origin_port, 1), \
        f"test fixture missing anchor {anchor!r}"

    # accept: off (the default spelling)
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor, anchor + "\n            cache_turbo_keep_stale off;", 1))
    assert r.returncode == 0, \
        f"cache_turbo_keep_stale off was rejected:\n{r.stdout}"

    # accept: bare 0 as a synonym for off (NOT forever -- see handler comment)
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor, anchor + "\n            cache_turbo_keep_stale 0;", 1))
    assert r.returncode == 0, \
        f"cache_turbo_keep_stale 0 was rejected:\n{r.stdout}"

    # accept: a plain time value
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor, anchor + "\n            cache_turbo_keep_stale 1h;", 1))
    assert r.returncode == 0, \
        f"cache_turbo_keep_stale 1h was rejected:\n{r.stdout}"

    # accept: forever
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor, anchor + "\n            cache_turbo_keep_stale forever;",
            1))
    assert r.returncode == 0, \
        f"cache_turbo_keep_stale forever was rejected:\n{r.stdout}"

    # reject: invalid token (neither off/forever nor a parseable time)
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor, anchor + "\n            cache_turbo_keep_stale bogus;",
            1))
    assert r.returncode != 0, \
        f"cache_turbo_keep_stale bogus was accepted by nginx -t:\n{r.stdout}"
    assert "bad value" in r.stdout, \
        f"missing/odd bad-value diagnostic:\n{r.stdout}"

    # reject: duplicate directive in the same block
    r = _config_test_result(
        ng, lambda c: c.replace(
            anchor,
            anchor
            + "\n            cache_turbo_keep_stale 1h;"
              "\n            cache_turbo_keep_stale 2h;",
            1))
    assert r.returncode != 0, \
        f"duplicate cache_turbo_keep_stale was accepted:\n{r.stdout}"
    assert "is duplicate" in r.stdout, \
        f"missing duplicate diagnostic:\n{r.stdout}"

    # negative control: the pristine (unmutated) config must still pass, or
    # every reject arm above is vacuous (a config broken for an unrelated
    # reason fails all of them regardless of this directive).
    r = _config_test_result(ng, lambda c: c)
    assert r.returncode == 0, \
        f"pristine config (no mutation) failed nginx -t:\n{r.stdout}"


def test_use_stale_config_parse(ng: Nginx) -> None:
    """S4.1: cache_turbo_use_stale <off|error|timeout|http_NNN...> --
    PARSER ONLY, no runtime read yet (that is S4.2). Cover every token
    individually, a multi-token combination, off, an invalid token, and a
    duplicate directive. Each reject case asserts the literal diagnostic
    string, not just a nonzero exit, so a config broken for the wrong reason
    cannot pass as "correctly rejected"."""
    anchor = "cache_turbo_valid 30s;"
    assert anchor in nginx_config(
        ng.root, ng.port, ng.module, ng.origin_port, 1), \
        f"test fixture missing anchor {anchor!r}"

    def with_directive(cfg: str, directive: str) -> str:
        assert anchor in cfg, f"test fixture missing {anchor!r}"
        return cfg.replace(anchor, anchor + "\n            " + directive, 1)

    # accept: each individual token
    for token in ("off", "error", "timeout", "http_403", "http_404",
                  "http_429", "http_500", "http_502", "http_503",
                  "http_504"):
        r = _config_test_result(
            ng, lambda c, _t=token: with_directive(
                c, f"cache_turbo_use_stale {_t};"))
        assert r.returncode == 0, \
            f"cache_turbo_use_stale {token} was rejected:\n{r.stdout}"

    # accept: multi-token combination
    r = _config_test_result(
        ng, lambda c: with_directive(
            c, "cache_turbo_use_stale error timeout http_404 http_500;"))
    assert r.returncode == 0, \
        f"multi-token cache_turbo_use_stale was rejected:\n{r.stdout}"

    # reject: off combined with another token
    r = _config_test_result(
        ng, lambda c: with_directive(c, "cache_turbo_use_stale off http_500;"))
    assert r.returncode != 0, \
        f"cache_turbo_use_stale off + http_500 was accepted:\n{r.stdout}"
    assert "cannot be combined" in r.stdout, \
        f"missing off-combination diagnostic:\n{r.stdout}"

    # reject: invalid token
    r = _config_test_result(
        ng, lambda c: with_directive(c, "cache_turbo_use_stale bogus;"))
    assert r.returncode != 0, \
        f"cache_turbo_use_stale bogus was accepted by nginx -t:\n{r.stdout}"
    assert "invalid value" in r.stdout, \
        f"missing invalid-value diagnostic:\n{r.stdout}"

    # reject: duplicate directive in the same block
    r = _config_test_result(
        ng, lambda c: with_directive(
            c,
            "cache_turbo_use_stale http_500;"
            "\n            cache_turbo_use_stale http_502;"))
    assert r.returncode != 0, \
        f"duplicate cache_turbo_use_stale was accepted:\n{r.stdout}"
    assert "is duplicate" in r.stdout, \
        f"missing duplicate diagnostic:\n{r.stdout}"

    # accept: server-level directive inherited by a location that does not
    # override it, and a location-level override alongside it. This is the
    # only part of the create/merge path observable from a config test.
    r = _config_test_result(
        ng, lambda c: with_directive(c, "cache_turbo_use_stale http_404;"))
    assert r.returncode == 0, \
        f"server-scope cache_turbo_use_stale was rejected:\n{r.stdout}"

    # reject: tokens are matched by exact bytes, so a case variant is not a
    # silently-accepted synonym.
    for bad in ("HTTP_500", "Off", "Error"):
        r = _config_test_result(
            ng, lambda c, _b=bad: with_directive(
                c, f"cache_turbo_use_stale {_b};"))
        assert r.returncode != 0, \
            f"cache_turbo_use_stale {bad} was accepted (case folding?):\n{r.stdout}"
        assert "invalid value" in r.stdout, \
            f"missing invalid-value diagnostic for {bad}:\n{r.stdout}"

    # negative control: the pristine (unmutated) config must still pass, or
    # every reject arm above is vacuous.
    r = _config_test_result(ng, lambda c: c)
    assert r.returncode == 0, \
        f"pristine config (no mutation) failed nginx -t:\n{r.stdout}"

    # ⚠ KNOWN COVERAGE GAP -- do not read this test as validating the mask.
    # Nothing reads clcf->use_stale yet (that is S4.2), so no config test can
    # observe the VALUE any token produces. These arms prove only that the
    # grammar accepts/rejects the right strings. Mutations that survive this
    # test unchanged: mapping every token to the same bit, swapping two token
    # bits, dropping ANY_5XX from USE_STALE_DEFAULT, or breaking the
    # UNSET-vs-0 merge. Those invariants become observable only once S4.2
    # gives the mask a behavioural effect, and the S4.2 tests -- not these --
    # are what must pin them down. See the S4.1 entry in issues.md.


def test_lru_eviction(ng: Nginx) -> None:
    """R6: with a tiny zone, old entries are evicted, not 500s."""
    # hammer many distinct keys through the tiny zone; must all 200, no errors
    for i in range(200):
        s, _, _ = fetch(ng.port, f"/e/{i}")
        assert s == 200, f"/e/{i} returned {s}"


def test_p1_coarse_lru_splice_keeps_hot_key_resident(ng: Nginx) -> None:
    """P1: the LRU head-splice on a HIT is coarse-gated (re-splice only when
    now - last_access >= 1s) so a key hammered many times per second does not
    re-write the shared LRU list every hit. The gate must NOT let a genuinely
    hot key drift toward the eviction tail: after being hammered fast and then
    surviving a burst of cold-key eviction churn, the hot key must still be
    resident (X-CT-Status HIT), proving the coarse splice still promotes it.

    Positive assertion on $cache_turbo_status (HIT), never header-absence -- a
    vanished status header would read as a pass otherwise. Sabotage check: if
    the coarse gate wrongly skipped ALL splices, the hot key would age to the
    LRU tail and the post-churn fetch would MISS."""
    import time
    hot = "/e/p1-hot"

    # Prime the hot key, then hammer it fast so almost every hit lands inside the
    # same 1s window and exercises the coarse-splice SKIP path (the whole point
    # of P1 -- these hits must NOT re-splice the LRU list).
    s, _, _ = fetch(ng.port, hot)
    assert s == 200, f"prime {hot} -> {s}"
    for _ in range(300):
        s, _, _ = fetch(ng.port, hot)
        assert s == 200, f"hot hammer {hot} -> {s}"

    # Cold-key churn in waves, each wave preceded by a real >1s gap then a hot
    # touch. The sleep is load-bearing: the coarse gate splices only when
    # now - last_access >= 1, and a new node starts at last_access = now, so
    # WITHOUT the gap fast-loopback re-touches would fall in the same time_t
    # second, skip every promotion, and the test could pass without ever
    # exercising the splice. With the gap each hot touch genuinely re-promotes.
    # /e/ is a tiny zone (R6: eviction at ~200 keys); each wave overflows it.
    for wave in range(3):
        time.sleep(1.2)                  # cross a 1s boundary -> splice fires
        s, _, _ = fetch(ng.port, hot)    # re-promote to LRU head
        assert s == 200, f"hot re-touch {hot} -> {s}"
        for i in range(250):
            fetch(ng.port, f"/e/p1-cold-{wave}-{i}")

    # The hot key was re-promoted before each eviction wave, so a correct coarse
    # splice kept it RESIDENT. The property under test is non-eviction, so both
    # HIT (still fresh) and STALE (present-but-expired; the many cold fetches +
    # 1.2s sleeps can push total runtime past /e/'s 30s valid window) prove the
    # node survived. A broken gate that skipped ALL splices would have aged it to
    # the LRU tail and evicted it -> the re-fetch would MISS (cold origin fill).
    s, _, h = fetch(ng.port, hot)
    assert s == 200, f"post-churn {hot} -> {s}"
    assert h.get("x-ct-status") in ("HIT", "STALE"), (
        f"hot key evicted despite promotion: X-CT-Status={h.get('x-ct-status')}")


def _s8_scan(ng: Nginx, prefix: str, tag: str, n: int = 400) -> None:
    """Walk n unique keys once each -- a crawler. Every one is a one-hit
    wonder, so under a segmented LRU they all stay in probation and can only
    evict each other."""
    for i in range(n):
        fetch(ng.port, f"{prefix}scan-{tag}-{i}")


def _s8_hot_status(ng: Nginx, prefix: str, tag: str) -> str:
    """Prime a hot key so it is PROTECTED-eligible, run a scan, then report the
    hot key's status. Promotion needs a SECOND hit, and the P1 coarse gate only
    splices when now - last_access >= 1s, so the two priming hits straddle a
    real 1s boundary. Without that sleep the second hit is swallowed by the
    gate, the node never promotes, and the test would measure nothing."""
    import time
    hot = f"{prefix}hot-{tag}"

    s, _, _ = fetch(ng.port, hot)                 # store (probation)
    assert s == 200, f"prime {hot} -> {s}"
    time.sleep(1.2)
    s, _, h = fetch(ng.port, hot)                 # 1st touch
    assert s == 200, f"touch1 {hot} -> {s}"
    assert h.get("x-ct-status") == "HIT", (
        f"priming touch1 should HIT: {h.get('x-ct-status')}")
    time.sleep(1.2)
    s, _, h = fetch(ng.port, hot)                 # 2nd touch -> PROMOTES
    assert s == 200, f"touch2 {hot} -> {s}"
    assert h.get("x-ct-status") == "HIT", (
        f"priming touch2 should HIT: {h.get('x-ct-status')}")

    _s8_scan(ng, prefix, tag)

    s, _, h = fetch(ng.port, hot)
    assert s == 200, f"post-scan {hot} -> {s}"
    return h.get("x-ct-status", "")


def test_s8_scan_resistant_keeps_hot_key(ng: Nginx) -> None:
    """S8 test 1 -- THE ACTUAL FIX. With cache_turbo_scan_resistant on, a key
    that was hit twice is PROTECTED, so a crawler walking a large unique
    keyspace through a small zone cannot evict it: every scan key is a one-hit
    wonder that never leaves PROBATION, and evict_one() takes probation tails
    first.

    Positive assertion on $cache_turbo_status (HIT), never header-absence.

    NEGATIVE CONTROL (verified by hand, see the PR body): with evict_one()
    reverted to the flat `ngx_queue_last(&z->sh->lru)` this assertion fails --
    the hot key is evicted by the scan and comes back MISS."""
    st = _s8_hot_status(ng, "/sr/", "on")
    assert st == "HIT", (
        f"S8: scan evicted the protected hot key (X-CT-Status={st}); "
        "promote-on-second-hit or the probation-first victim pick is broken")


def test_s8_default_off_is_unchanged(ng: Nginx) -> None:
    """S8 test 2 -- OFF BY DEFAULT, and off means genuinely unchanged.

    Same location shape, same zone size, same traffic, directive ABSENT. The
    flat LRU has no notion of protection, so the scan walks the hot key out of
    the zone exactly as it did before S8 and the post-scan fetch MISSes.

    This is the off-by-default regression guard: if a future edit ever makes
    segmentation apply unconditionally, this test flips to HIT and fails. It is
    also the inverse arm of test 1 -- the two together show the behavioural
    difference is caused by the directive and by nothing else, since the only
    difference between /sr/ and /sroff/ is that one line of config."""
    st = _s8_hot_status(ng, "/sroff/", "off")
    assert st == "MISS", (
        f"S8: default-off behaviour CHANGED (X-CT-Status={st}, expected MISS). "
        "Scan resistance must not apply unless cache_turbo_scan_resistant is on")


def test_s8_explicit_off_matches_absent(ng: Nginx) -> None:
    """S8: `cache_turbo_scan_resistant off` must be identical to omitting it --
    not merely accepted by the parser. Pins that `off` stores 0 rather than
    falling through to the default-on-when-present trap."""
    st = _s8_hot_status(ng, "/srexpoff/", "expoff")
    assert st == "MISS", (
        f"S8: explicit `off` did not match absent (X-CT-Status={st})")


def test_s8_reload_on_to_off_drains_protected(ng: Nginx) -> None:
    """S8 reload arm -- THE BUG CLASS THE SUITE COULD NOT REACH.

    Every other S8 test starts from a fresh zone, so an entry can only ever be
    PROTECTED under a config that is currently `on`. The interesting state is
    the one that only a reload can produce: a zone whose shared memory SURVIVES
    (init_zone inherits the live `sh`) being handed to a worker whose effective
    protected_pct is now 0. That is how the `on` -> `off` inherited-PROTECTED
    bug reached CI green -- it was unreachable by construction, not merely
    untested. (Found by CodeRabbit on PR #81; see lessons.md.)

    Sequence: promote a hot key to PROTECTED while `on`, reload the SAME zone to
    `off`, then touch the hot key (which must DEMOTE it to probation) and run a
    scan. With `off` genuinely restoring pre-S8 behaviour the scan walks the key
    out of the zone exactly as in test_s8_default_off_is_unchanged -> MISS.

    NEGATIVE CONTROL (required by TODO, verified by hand -- see the PR body):
    delete the `ctn->seg = ...SEG_PROBATION;` demote in
    ngx_http_cache_turbo_shm_touch_lru() (shm.c, the `protected_pct == 0` arm)
    and this test FAILS by its own assertion with X-CT-Status=HIT: the node
    stays on lru_protected across the reload and the scan cannot evict it.

    Skipped in single-process mode (`master_process off`), which has no master
    and therefore cannot reload at all -- the ASan run uses it.
    """
    if ng.single_process:
        return

    prefix, tag = "/sr/", "reload"
    hot = f"{prefix}hot-{tag}"

    # 1. Promote to PROTECTED while the directive is still `on`. Two touches,
    #    each straddling a real 1s boundary so the P1 coarse gate lets the
    #    splice through (the same priming _s8_hot_status does).
    s, _, _ = fetch(ng.port, hot)
    assert s == 200, f"prime {hot} -> {s}"
    for n in (1, 2):
        time.sleep(1.2)
        s, _, h = fetch(ng.port, hot)
        assert s == 200, f"touch{n} {hot} -> {s}"
        assert h.get("x-ct-status") == "HIT", (
            f"priming touch{n} should HIT: {h.get('x-ct-status')}")

    # 2. Prove the promotion actually took, BEFORE the reload. Without this the
    #    test could pass for the wrong reason: if priming silently failed the
    #    key would never be PROTECTED, the post-reload MISS would be trivially
    #    true, and the test would assert nothing about `off` at all.
    _s8_scan(ng, prefix, f"{tag}-pre")
    s, _, h = fetch(ng.port, hot)
    assert s == 200, f"pre-reload {hot} -> {s}"
    assert h.get("x-ct-status") == "HIT", (
        f"S8 reload: hot key was not PROTECTED before the reload "
        f"(X-CT-Status={h.get('x-ct-status')}); priming is broken, so the "
        "post-reload assertion below would prove nothing")

    try:
        # 3. The real reload: same zone, directive flipped to `off`.
        ng.reload(sr_off=True)

        # 4. Touch the surviving node under the new config. This is the demote:
        #    protected_pct is now 0, so touch_lru must move it back to
        #    probation. Straddle the 1s gate or the splice never runs.
        time.sleep(1.2)
        s, _, h = fetch(ng.port, hot)
        assert s == 200, f"post-reload touch {hot} -> {s}"
        assert h.get("x-ct-status") in ("HIT", "STALE"), (
            f"S8 reload: entry did not survive the reload at all "
            f"(X-CT-Status={h.get('x-ct-status')}); the zone was re-created "
            "rather than inherited, so this test is not measuring the "
            "inherited-state path it exists to cover")

        # 5. Now the scan must be able to evict it, exactly as it does in the
        #    never-was-on case.
        _s8_scan(ng, prefix, f"{tag}-post")
        s, _, h = fetch(ng.port, hot)
        assert s == 200, f"post-scan {hot} -> {s}"
        st = h.get("x-ct-status", "")
        assert st == "MISS", (
            f"S8 reload: `off` did not drain the inherited PROTECTED node "
            f"(X-CT-Status={st}, expected MISS). Turning scan resistance off "
            "must ACTIVELY DEMOTE nodes promoted while it was on, not merely "
            "decline to promote new ones -- the zone outlives the reload")
    finally:
        # Restore `on` for whatever runs next: the conf and the srz zone are
        # shared, and leaving the directive off would silently invert
        # test_s8_scan_resistant_keeps_hot_key if it ran after this one.
        ng.reload(sr_off=False)


def test_s8_scan_still_stores_and_evicts(ng: Nginx) -> None:
    """S8 test 4 -- the anti-hang / anti-wedge arm at the HTTP level.

    Drive far more unique keys through the scan-resistant zone than it can
    hold, so the protected segment fills, the cap demotes, and eviction must
    keep finding victims on BOTH queues. Every request must still complete with
    a 200: a zone that could not evict would fail stores (or, with the
    evict_one() hazard, wedge the worker holding the mutex and time this out).

    The C-level test pins the spin deterministically with a watchdog; this arm
    proves the same property through the real request path under real slab
    pressure, which is where a both-queues-consistency bug would actually
    surface."""
    for i in range(1500):
        s, _, _ = fetch(ng.port, f"/sr/churn-{i}")
        assert s == 200, f"/sr/churn-{i} returned {s} (store or eviction wedged)"

    # And the zone is still serving: a fresh key stores and then HITs, proving
    # eviction left the structure usable rather than merely not crashing.
    s, _, _ = fetch(ng.port, "/sr/after-churn")
    assert s == 200
    s, _, h = fetch(ng.port, "/sr/after-churn")
    assert s == 200 and h.get("x-ct-status") == "HIT", (
        f"zone unusable after churn: X-CT-Status={h.get('x-ct-status')}")


def test_perf7_zero_copy_serve_under_eviction(ng: Nginx) -> None:
    """PERF-7: a HIT serves the blob zero-copy DIRECTLY out of the shm slab
    (no per-hit copy into r->pool), holding a refcount on the buffer until the
    response drains. Hammer a working set far larger than the tiny zone in
    parallel so blobs are evicted/refreshed by one worker while other in-flight
    requests are still serving them. If the refcount is wrong (frees a buffer a
    serve still points into, or double-frees), the multi-worker ASan run trips a
    use-after-free / double-free here; the plain run still asserts no 5xx. Every
    request must succeed."""
    import random
    keys = 300                       # > what the 8m tiny zone holds (see R6)
    reqs = 4000
    for i in range(keys):            # prime, forcing continuous eviction
        fetch(ng.port, f"/e/p7-{i}")

    def hit(_: int) -> int:
        # STRESS_TIMEOUT, not the default: 4000 requests across 48 threads means
        # a descheduled worker can exceed the plain ceiling on a loaded runner
        # while the server is healthy. The assertion here is "HTTP 200", not
        # "answered within 5s".
        return fetch(ng.port, f"/e/p7-{random.randint(0, keys - 1)}",
                     timeout=STRESS_TIMEOUT)[0]

    with concurrent.futures.ThreadPoolExecutor(max_workers=48) as pool:
        codes = list(pool.map(hit, range(reqs)))
    bad = sorted({c for c in codes if c != 200})
    assert not bad, f"non-200 under serve/eviction churn: {bad}"


def test_shm_refresh_under_pressure(ng: Nginx) -> None:
    """R6b: refresh-store races with eviction under concurrency. The /shmref/
    location uses a tiny zone (8m) with a 1s fresh window + aggressive beta +
    background_update, so a working set far larger than the zone is
    CONTINUOUSLY going stale and refreshing (SWR store back into the shm slab)
    while OTHER entries are being evicted to make room. This overlaps the
    slab alloc/free/evict path with the refresh-store path -- the combination
    that neither the eviction-only test (/e/, valid 30s, never stale) nor the
    serve-under-eviction test (PERF-7, valid 30s, never refreshes) exercises.

    The high-value assertion is delivered by the sanitizer CI run (the asan job
    runs the full suite): a UAF / double-free / heap-overflow in store-under-
    eviction trips ASan/UBSan and aborts the worker, which this test observes as
    a 5xx or a dead server. The plain run asserts liveness + no corruption.

    NOT timing-fragile: it does not assert an exact regeneration count (the
    dice is ngx_time()-driven at 1s granularity and per-worker, so an exact
    count would flake under slow/sanitized runs). It asserts (a) every request
    succeeds, (b) the server is still alive and serving afterwards, and (c) the
    refresh machinery actually engaged at least once (refreshes counter > 0),
    so a run where nothing ever went stale -- which would silently cover
    nothing -- fails loudly instead of passing vacuously."""
    import json
    import random

    # A small HOT set stays resident in the zone across the 1s fresh window, so a
    # re-request after expiry lands on a stale-but-present entry and drives the
    # refresh-store path (which increments `refreshes` only for a stale HIT that
    # wins the dice -- an entry EVICTED before re-hit never refreshes, so a large
    # working set alone covers nothing). Interleaved COLD keys create the
    # concurrent slab eviction pressure, so refresh-store races with eviction --
    # the combination /e/ (never stale) and PERF-7 (never refreshes) miss.
    # Hot set is re-touched every wave so it stays MRU and survives eviction (it
    # must persist to go stale and drive refresh). The larger cold set overflows
    # the zone's ~key capacity and is evicted continuously, so slab evict runs
    # concurrently with the hot set's refresh-store. (A 16m zone holds a few
    # hundred of these small entries; R6 shows 8m evicting at ~200 keys, so cold
    # is sized well past that to guarantee churn without touching the MRU hot set.)
    hot = 40
    cold = 800                       # >> zone capacity -> continuous eviction
    reqs = 4000

    # refreshes counter baseline. Read the shmref zone's OWN admin endpoint --
    # /_cache is bound to zone "main" (cache_turbo_admin main), so it would
    # report main's counters, never shmref's, and the refresh assertion below
    # would read 0 forever regardless of what the module did.
    base = json.loads(fetch(ng.port, "/_cache_shmref")[1]).get("refreshes", 0)

    for i in range(hot):             # prime the hot set (must survive to go stale)
        s, _, _ = fetch(ng.port, f"/shmref/hot-{i}")
        assert s == 200, f"/shmref/hot-{i} prime returned {s}"

    # Sleep past fresh_until AND past the ngx_time() one-second-granularity dead
    # zone. The refresh dice threshold is elapsed/window * beta with elapsed in
    # whole seconds; at elapsed == 0 (the first ~1s after fresh_until) it is 0 and
    # the dice CANNOT fire whatever beta is (documented on test_lock_redis_outage
    # and the /atch/ churn test, which sleeps 2.7). fresh window is 2s; sleeping
    # 3.2s puts the hot set >= ~1.2s into the stale window, so elapsed >= 1s for
    # the entire hammer below and the dice fires from its first request.
    time.sleep(3.2)

    def hit(n: int) -> int:
        # ~70% hot (stale -> refresh), ~30% cold (fresh miss -> eviction churn),
        # so the refresh-store path and the slab evict path run concurrently.
        if n % 10 < 7:
            uri = f"/shmref/hot-{random.randint(0, hot - 1)}"
        else:
            uri = f"/shmref/cold-{random.randint(0, cold - 1)}"
        # STRESS_TIMEOUT, not the default -- see test_perf7_zero_copy_serve_
        # under_eviction. A slow read here is 48-thread scheduling contention,
        # not the module; the assertions are liveness + refreshes > base.
        return fetch(ng.port, uri, timeout=STRESS_TIMEOUT)[0]

    with concurrent.futures.ThreadPoolExecutor(max_workers=48) as pool:
        codes = list(pool.map(hit, range(reqs)))
    bad = sorted({c for c in codes if c != 200})
    assert not bad, f"non-200 under refresh/eviction churn: {bad}"

    # Server still alive and serving (an ASan abort in a worker would show here).
    s, body, _ = fetch(ng.port, "/_cache_shmref")
    assert s == 200, f"admin stats unreachable after churn: {s}"
    refreshes = json.loads(body).get("refreshes", 0)
    assert refreshes > base, \
        f"refresh path never engaged (refreshes {base} -> {refreshes}); " \
        "test covered no refresh-under-pressure"


def test_concurrent_hits_no_deadlock(ng: Nginx) -> None:
    """R1: many parallel HITs on one key do not serialise/deadlock."""
    fetch(ng.port, "/c/conc")                      # prime
    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(lambda _: fetch(ng.port, "/c/conc"),
                                range(500)))
    elapsed = time.time() - start
    assert all(r[0] == 200 for r in results), "some concurrent HITs failed"
    assert all(r[2].get("x-cache") == "HIT" for r in results), \
        "some concurrent reads were not HITs"
    # 500 cached HITs should be fast; serialising under a held lock would blow this.
    assert elapsed < 10, f"concurrent HITs took {elapsed:.1f}s (possible lock stall)"


def test_admin_stats(ng: Nginx) -> None:
    """GET /_cache returns JSON counters that reflect observed traffic."""
    import json
    fetch(ng.port, "/c/stat1")           # miss
    fetch(ng.port, "/c/stat1")           # hit
    s, b, h = fetch(ng.port, "/_cache")
    assert s == 200, f"admin stats status {s}"
    assert "application/json" in h.get("content-type", ""), h.get("content-type")
    data = json.loads(b)
    for field in ("hits", "misses", "stale_serves", "refreshes", "evictions"):
        assert field in data, f"stats missing {field}: {data}"
    assert data["hits"] >= 1 and data["misses"] >= 1, f"counters look wrong: {data}"


def test_admin_prometheus(ng: Nginx) -> None:
    """GET /_cache?format=prometheus renders the Prometheus text exposition
    format: right content-type, HELP/TYPE lines, zone-labelled samples."""
    import re
    fetch(ng.port, "/c/prom1")           # miss
    fetch(ng.port, "/c/prom1")           # hit -> hits_total >= 1
    s, b, h = fetch(ng.port, "/_cache?format=prometheus")
    assert s == 200, f"metrics status {s}"
    ct = h.get("content-type", "")
    assert "text/plain" in ct and "0.0.4" in ct, f"bad content-type: {ct}"
    for line in ("# TYPE cache_turbo_hits_total counter",
                 "# TYPE cache_turbo_misses_total counter",
                 "# TYPE cache_turbo_stale_serves_total counter",
                 "# TYPE cache_turbo_refreshes_total counter",
                 "# TYPE cache_turbo_evictions_total counter",
                 "# TYPE cache_turbo_l2_hits_total counter",
                 "# TYPE cache_turbo_l2_misses_total counter",
                 "# TYPE cache_turbo_lock_waits_total counter",
                 "# TYPE cache_turbo_min_uses_skips_total counter",
                 "# TYPE cache_turbo_l2_neg_skips_total counter",
                 "# TYPE cache_turbo_bypasses_total counter",
                 "# TYPE cache_turbo_regen_cost_ms gauge",
                 "# TYPE cache_turbo_autotuned_beta gauge"):
        assert line in b, f"metrics missing line: {line!r}"
    m = re.search(r'cache_turbo_hits_total\{zone="main"\} (\d+)', b)
    assert m, f"no zone-labelled hits sample:\n{b[:300]}"
    assert int(m.group(1)) >= 1, "hits_total should be >= 1"


def test_admin_purge_key(ng: Nginx) -> None:
    """POST /_cache?key=<uri> drops that entry; next read is a MISS again."""
    import json
    fetch(ng.port, "/c/purgeme")                       # miss -> cached
    _, _, h = fetch(ng.port, "/c/purgeme")
    assert h.get("x-cache") == "HIT", "should be cached before purge"
    # key is the cache_turbo_key for this location, which is $uri
    s, b, _ = fetch(ng.port, "/_cache?key=/c/purgeme", method="POST")
    assert s == 200, f"purge status {s}"
    assert json.loads(b)["purged"] == 1, f"purge count: {b}"
    _, _, h2 = fetch(ng.port, "/c/purgeme")
    assert "x-cache" not in h2, "entry should be gone after purge (a MISS)"


def test_admin_all_zero_does_not_purge(ng: Nginx) -> None:
    """COR-10: only the exact ?all=1 purges; ?all=0 (a typo) must NOT destroy the
    zone — the entry stays cached."""
    fetch(ng.port, "/c/azkeep")                        # miss -> cached
    _, _, h = fetch(ng.port, "/c/azkeep")
    assert h.get("x-cache") == "HIT", "should be cached before the ?all=0 attempt"
    fetch(ng.port, "/_cache?all=0", method="POST")     # must purge nothing
    _, _, h2 = fetch(ng.port, "/c/azkeep")
    assert h2.get("x-cache") == "HIT", "?all=0 wrongly purged the entry"


def test_admin_purge_all(ng: Nginx) -> None:
    """POST /_cache?all=1 empties the zone."""
    import json
    fetch(ng.port, "/c/a1")
    fetch(ng.port, "/c/a2")
    fetch(ng.port, "/c/a3")
    s, b, _ = fetch(ng.port, "/_cache?all=1", method="POST")
    assert s == 200, f"purge-all status {s}"
    assert json.loads(b)["purged"] >= 1, f"purge-all count: {b}"
    # everything is now a miss
    _, _, h = fetch(ng.port, "/c/a1")
    assert "x-cache" not in h, "purge-all should have emptied the zone"


def test_admin_gating(ng: Nginx) -> None:
    """A deny-all admin location returns 403 (gating works)."""
    s, _, _ = fetch(ng.port, "/_cache_denied")
    assert s == 403, f"deny-all admin returned {s}, expected 403"


def test_warm_populates(ng: Nginx, origin: Origin) -> None:
    """v3-3: POST /_cache?url=<u> fires a background subrequest that hits origin
    once and stores the result, so a never-before-fetched URL is a HIT on its
    first real visit — without that visit touching the origin again."""
    import json
    uri = "/c/warm-pop"
    base = origin.hits_for("warm-pop")
    s, b, _ = fetch(ng.port, f"/_cache?url={uri}", method="POST")
    assert s == 200, f"warm status {s}"
    assert json.loads(b)["warmed"] == 1, f"warmed count: {b}"
    # the bg subrequest reaching origin is our completion signal
    assert wait_for(lambda: origin.hits_for("warm-pop") == base + 1), \
        "warm subrequest never hit the origin"
    time.sleep(0.2)                     # let the store settle after the response
    after = origin.hits_for("warm-pop")
    # first real visit must be served from the warm-populated entry
    s2, _, h2 = fetch(ng.port, uri)
    assert s2 == 200
    assert h2.get("x-cache") == "HIT", \
        f"warm did not populate the cache (X-Cache={h2.get('x-cache')})"
    assert origin.hits_for("warm-pop") == after, \
        f"GET after warm hit the origin ({origin.hits_for('warm-pop')} vs {after})"


def test_warm_multi(ng: Nginx, origin: Origin) -> None:
    """v3-3: a comma-separated ?url=a,b warms both; both HIT afterwards."""
    import json
    a, b_uri = "/c/warm-m1", "/c/warm-m2"
    base = origin.hits_for("warm-m")
    s, body, _ = fetch(ng.port, f"/_cache?url={a},{b_uri}", method="POST")
    assert s == 200, f"warm-multi status {s}"
    assert json.loads(body)["warmed"] == 2, f"warmed count: {body}"
    assert wait_for(lambda: origin.hits_for("warm-m") == base + 2), \
        "both warm subrequests never reached origin"
    time.sleep(0.2)
    after = origin.hits_for("warm-m")
    for u in (a, b_uri):
        _, _, h = fetch(ng.port, u)
        assert h.get("x-cache") == "HIT", f"{u} not warmed (X-Cache={h.get('x-cache')})"
    assert origin.hits_for("warm-m") == after, "a warmed GET still hit origin"


def test_warm_no_url(ng: Nginx) -> None:
    """v3-3: POST /_cache with no recognised arg is a 400 with a JSON error."""
    import json
    s, b, h = fetch(ng.port, "/_cache", method="POST")
    assert s == 400, f"no-arg admin POST returned {s}, expected 400"
    assert "application/json" in h.get("content-type", ""), h.get("content-type")
    assert "error" in json.loads(b), f"expected an error body, got {b!r}"


def test_warm_strips_key_cookie(ng: Nginx, origin: Origin) -> None:
    """B-S4: a warm subrequest fetches ANONYMOUSLY even when the admin POST
    carries a segment/key cookie.

    ngx_http_subrequest copies headers_in shallowly, so the warm sr inherits the
    admin request's Cookie header. On a preset location (magento here) that would
    (a) fold X-Magento-Vary into the cache key -> the warmed body lands under a
    SEGMENTED key no cookieless visitor reaches (wasted warm), and (b) forward the
    cookie upstream -> the origin returns that segment's private body. warm_one
    now strips every Cookie from the sr, so both the key and the upstream request
    are the cookieless anonymous variant.

    Negative control: without the strip, (a) makes the cookieless GET below a MISS
    (asserted HIT), and (b) leaks the cookie into the served body (asserted absent).
    """
    import json
    uri = "/mg/ckecho-warm"
    seg = {"Cookie": "X-Magento-Vary=deadbeefdeadbeefdeadbeefdeadbeef"}
    base = origin.hits_for("ckecho-warm")
    s, b, _ = fetch(ng.port, f"/_cache?url={uri}", method="POST", headers=seg)
    assert s == 200, f"warm status: {s} {b!r}"
    assert json.loads(b)["warmed"] == 1, f"warm body: {b!r}"
    assert wait_for(lambda: origin.hits_for("ckecho-warm") == base + 1), \
        "warm subrequest never reached origin"
    time.sleep(0.2)                     # let the store settle
    after = origin.hits_for("ckecho-warm")

    # (a) the cookieless anonymous lookup HITs the warmed entry -> key went anon.
    s2, body2, h2 = fetch(ng.port, uri)          # no cookie
    assert s2 == 200
    assert h2.get("x-cache") == "HIT", \
        ("warm keyed to the X-Magento-Vary segment, not the anonymous bucket a "
         f"cookieless visitor looks up (X-Cache={h2.get('x-cache')})")
    assert origin.hits_for("ckecho-warm") == after, \
        f"the anonymous GET hit origin instead of the warm entry ({origin.hits_for('ckecho-warm')} vs {after})"

    # (b) the served (warm-stored) body proves the origin saw NO cookie -> no leak.
    assert "cookie=[none]" in body2, \
        f"warm forwarded the operator cookie to origin (leak): {body2!r}"
    assert "X-Magento-Vary" not in body2, \
        f"warm leaked the segment cookie into the anonymous entry: {body2!r}"


def test_l2_write_through(ng: Nginx, origin: Origin, redis: RedisServer) -> None:
    """P4: a store writes through to L2. After caching /l2/<k>, the blob is
    present in Redis under the expected key, carries a PX TTL, and contains the
    actual response body bytes."""
    uri = "/l2/store"
    redis.cli("DEL", l2_key(uri))
    s, body, h = fetch(ng.port, uri)               # miss -> origin -> store
    assert s == 200, f"l2 store status {s}"
    assert "x-cache" not in h, "first request should be a miss"

    key = l2_key(uri)
    # write-through is async/fire-and-forget; give it a moment to land
    assert wait_for(lambda: redis.cli("EXISTS", key) == "1"), \
        f"L2 key {key} never appeared in Redis"

    pttl = int(redis.cli("PTTL", key))
    # PX applied: a positive TTL no larger than the stale window (valid*4 = 120s)
    assert 0 < pttl <= 120_000, f"unexpected PTTL {pttl}"

    strlen = int(redis.cli("STRLEN", key))
    assert strlen > len(body), f"stored blob ({strlen}B) smaller than body"

    raw = redis.cli("--no-raw", "GET", key)
    assert "gen-" in raw, f"stored blob missing response body: {raw[:80]!r}"

    # L1 still serves the hit (L2 write-through must not disturb the hot path)
    _, b2, h2 = fetch(ng.port, uri)
    assert h2.get("x-cache") == "HIT" and b2 == body, "L1 hit broken after L2 set"


def _redis_conns_received(redis: RedisServer) -> int:
    """Redis' monotonic count of accepted client connections (INFO stats)."""
    for line in redis.cli("INFO", "stats").splitlines():
        if line.startswith("total_connections_received:"):
            return int(line.split(":", 1)[1])
    raise RuntimeError("total_connections_received absent from INFO stats")


def test_l2_keepalive_reuse(ng: Nginx, origin: Origin,
                            redis: RedisServer) -> None:
    """v15: the keepalive pool reuses Redis connections across L2 ops. A burst
    of distinct-URI misses opens one L2 GET + one L2 SET each. Under /l2ka/
    (keepalive=4) the pool reuses connections, so Redis accepts far fewer new
    connections than the same burst under /l2/ (no keepalive), where every op
    dials a fresh socket and closes it."""
    n = 60
    stamp = time.time()

    def burst(prefix: str) -> int:
        before = _redis_conns_received(redis)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            # 4 concurrent (<= pool cap) so reuse can dominate; unique keys so
            # every request is an L1+L2 miss (GET then write-through SET).
            list(ex.map(lambda i: fetch(ng.port, f"{prefix}ka-{stamp}-{i}"),
                        range(n)))
        # let the fire-and-forget SETs complete + pooled conns settle
        time.sleep(0.6)
        return _redis_conns_received(redis) - before

    off = burst("/l2/")      # no keepalive: ~2N fresh connections
    on = burst("/l2ka/")     # keepalive on: a small bounded number, then reuse

    assert off > n, f"no-keepalive baseline too low ({off}); expected > {n}"
    assert on * 2 < off, \
        f"keepalive did not cut Redis connection churn (on={on}, off={off})"

    # the pool keeps connections live: a subsequent op still hits + serves
    _, _, h = fetch(ng.port, f"/l2ka/ka-{stamp}-0")   # now an L1 HIT
    assert h.get("x-cache") == "HIT", "keepalive location broke the hot path"


def test_l2_keepalive_db_isolation(ng: Nginx, origin: Origin,
                                   redis: RedisServer) -> None:
    """Pooled Redis connections must not cross SELECT state. Alternate two
    locations sharing one address/pool but selecting DB 0 and DB 1; every key
    must land only in its configured database."""
    stamp = time.time_ns()

    for i in range(8):
        k0 = f"ka-db0-{stamp}-{i}"
        k1 = f"ka-db1-{stamp}-{i}"
        key0 = l2_key(k0, prefix="kais:")
        key1 = l2_key(k1, prefix="kais:")
        redis.cli("-n", "0", "DEL", key0, key1)
        redis.cli("-n", "1", "DEL", key0, key1)

        fetch(ng.port, f"/l2ka0/x?k={k0}")
        assert wait_for(
            # noqa: B023 -- late binding is safe here: wait_for consumes the
            # lambda before this iteration ends, so key0 cannot have been
            # rebound. Do not "fix" with a default arg; it would hide a real
            # deferred-closure bug if one is ever introduced below.
            lambda: redis.cli("-n", "0", "EXISTS", key0) == "1",  # noqa: B023
            timeout=4.0), f"DB 0 keepalive write missing for {k0}"
        assert redis.cli("-n", "1", "EXISTS", key0) == "0", \
            f"DB 0 key leaked into DB 1 through keepalive reuse: {k0}"

        fetch(ng.port, f"/l2ka1/x?k={k1}")
        assert wait_for(
            # noqa: B023 -- same as the DB 0 case above: consumed within the
            # iteration, so the late binding cannot observe a rebound key1.
            lambda: redis.cli("-n", "1", "EXISTS", key1) == "1",  # noqa: B023
            timeout=4.0), f"DB 1 keepalive write missing for {k1}"
        assert redis.cli("-n", "0", "EXISTS", key1) == "0", \
            f"DB 1 key leaked into DB 0 through keepalive reuse: {k1}"


def test_l2_cross_instance_fill(ng: Nginx, origin: Origin,
                                redis: RedisServer) -> None:
    """P2: an L1 miss fills from L2. A second, independent nginx with a cold L1
    but the same Redis serves the object another node cached, without hitting
    the origin again."""
    uri = "/l2/p2"
    redis.cli("DEL", l2_key(uri))

    # Instance A (the main server): cold -> origin -> writes L1 + L2
    s, body_a, ha = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in ha, "A should miss to origin first"
    assert wait_for(lambda: redis.cli("EXISTS", l2_key(uri)) == "1"), \
        "A never wrote the object to L2"
    drain_origin(origin)           # absorb any stray async bg before counting
    origin_after_a = origin.hits

    # Instance B: separate nginx, cold L1, same Redis + same origin
    b = Nginx(ng.binary, ng.module, ng.root.parent / "server-b",
              ng.port + PORT_OFFSETS["l2_cross_instance_fill_b"],
              ng.origin_port, ng.runner_raw,
              ng.single_process, ng.redis_port)
    b.write_config()
    b.config_test()
    b.start()
    try:
        s2, body_b, hb = fetch(b.port, uri)
        assert s2 == 200, f"B status {s2}"
        assert body_b == body_a, f"B body {body_b!r} != A body {body_a!r}"
        assert hb.get("x-cache") == "HIT", \
            f"B X-Cache={hb.get('x-cache')} (expected an L2-fill HIT)"
        if origin.hits != origin_after_a:
            recent = [(round(t, 2), p) for t, p in origin._paths[-15:]]
            raise AssertionError(
                f"origin was hit on the L2 fill ({origin.hits} vs "
                f"{origin_after_a}); recent origin paths: {recent}")

        # B now has it in L1 too: second read is a plain L1 HIT
        _, body_b2, hb2 = fetch(b.port, uri)
        assert hb2.get("x-cache") == "HIT" and body_b2 == body_a
        assert origin.hits == origin_after_a, "origin hit on B's L1 hit"

        time.sleep(0.2)
        b.stop()
        b.assert_clean_logs()
    finally:
        b.stop()


def make_ctb4_blob(body: bytes, status: int = 200,
                   headers: dict[str, str] | None = None,
                   created: int | None = None, fresh_ttl: int = 60,
                   stale_ttl: int = 240, sie_ttl: int = 0,
                   magic: int = 0x43544234,
                   version: int = 4) -> bytes:
    """Hand-build a CTB4 cache blob exactly as the module serialises it (STAB-4 +
    RFC-2: fixed 44-byte little-endian, padding-free header). Pass a wrong
    magic/version to exercise the validator's reject path. Wire layout (LE):
      u32 magic, u16 version, u16 flags, u32 status, u32 nheaders, u32 headers_len,
      u32 body_len, i64 created, u32 fresh_ttl, u32 stale_ttl, u32 sie_ttl."""
    headers = headers or {"Content-Type": "text/plain"}
    created = int(time.time()) if created is None else created
    hdr_block = b""
    nheaders = 0
    for name, value in headers.items():
        nb = name.encode()
        vb = value.encode()
        hdr_block += struct.pack("<I", len(nb)) + nb
        hdr_block += struct.pack("<I", len(vb)) + vb
        nheaders += 1
    head = struct.pack("<IHHIIIIqIII", magic, version, 0, status, nheaders,
                       len(hdr_block), len(body), created, fresh_ttl, stale_ttl,
                       sie_ttl)
    return head + hdr_block + body


def test_l2_dsn_auth_db(ng: Nginx, origin: Origin,
                        redis_auth: RedisServer) -> None:
    """v5 DSN: redis://:pass@host/2 drives an AUTH + SELECT preamble, then the
    write-through SET lands in the AUTHED instance's db 2."""
    fetch(ng.port, "/l2auth/k1")                   # miss -> store via preamble
    key = l2_key("/l2auth/k1")
    assert wait_for(lambda: redis_auth.cli("-n", "2", "EXISTS", key) == "1",
                    timeout=4.0), \
        "object not in authed redis db 2 (AUTH/SELECT preamble failed?)"
    _, _, h = fetch(ng.port, "/l2auth/k1")
    assert h.get("x-cache") == "HIT", "second read should be an L1 hit"


def test_l2_keepalive_no_auth_replay(ng: Nginx, origin: Origin,
                                     redis_auth: RedisServer) -> None:
    """Deferred enhancement: prove a pooled Redis connection does NOT replay the
    AUTH/SELECT preamble on reuse (ngx_http_cache_turbo_redis.c: op->reused skips
    ngx_http_cache_turbo_redis_preamble() entirely — see redis_launch()). A
    state-inspection assertion (EXISTS/PTTL) cannot show this: the object lands
    in the right db either way, whether or not the preamble ran on every op. Only
    a wire-level trace (Redis MONITOR) tells the difference between "no replay"
    and "replayed harmlessly by hitting the same already-authed session".

    /l2authka/ pairs the v5 AUTH+SELECT DSN with a keepalive pool. A burst of
    DISTINCT-URI misses each open one L2 GET + one L2 SET; with keepalive the
    same handful of pooled connections serve the whole burst, so the preamble
    runs once per connection ACTUALLY OPENED, never once per op.

    NOTE on what is (and is not) asserted. As of the per-fingerprint pool (v16)
    this location gets its OWN keepalive bucket, sized from its OWN keepalive=4,
    independent of any other location's cap and of test execution order (each
    distinct connection profile is bucketed separately -- ka_bucket() in
    ngx_http_cache_turbo_redis.c). So the configured cap IS now honoured. We
    still assert the ORDER-INDEPENDENT property rather than a magic number,
    because it is the stronger claim and is robust to worker count: the preamble
    count does not SCALE with the op count. A pool of any size >= 1 that skips
    the preamble on reuse yields auths << n; a preamble replayed on every op
    yields auths == n exactly. That gap is the property under test, and
    `auths < n` discriminates it soundly for any cap the bucket holds."""
    stamp = time.time_ns()
    n = 20

    with redis_auth.start_monitor() as mon:
        mon.checkpoint()          # drop the monitor connection's own AUTH
        for i in range(n):
            fetch(ng.port, f"/l2authka/auth-{stamp}-{i}")
        time.sleep(0.6)           # let fire-and-forget L2 SETs land
        cmds = mon.commands_seen()

    auths = cmds.count("AUTH")
    selects = cmds.count("SELECT")
    gets = cmds.count("GET")
    sets = cmds.count("SET")

    ops = gets + sets
    assert ops >= n, \
        f"burst did not reach redis as expected (GET={gets} SET={sets}, n={n})"

    # The preamble must have run at least once: a pooled conn is only exempt
    # because SOME earlier op authenticated it. Zero AUTH would mean the monitor
    # never saw the traffic (a broken harness), not a passing module.
    assert auths > 0 and selects > 0, \
        f"no preamble seen at all (AUTH={auths} SELECT={selects}) -- the " \
        f"monitor likely missed the burst; the test proves nothing"

    # THE property: the preamble is not replayed per-op. Replay-on-every-op is
    # AUTH == SELECT == ops (one preamble per GET and per SET). Skip-on-reuse is
    # one per connection opened -- a small constant, independent of `ops`. These
    # are far apart for any pool cap >= 1, so `< ops` needs no magic number and
    # holds whatever cap the process-global pool latched (see docstring).
    assert auths < ops, \
        f"AUTH replayed on reuse: {auths} AUTH for {ops} L2 ops -- the " \
        f"preamble count scales with op count, so pooled conns are " \
        f"re-authenticating instead of reusing an authed session"
    assert selects < ops, \
        f"SELECT replayed on reuse: {selects} SELECT for {ops} L2 ops -- the " \
        f"preamble count scales with op count, so pooled conns are " \
        f"re-SELECTing instead of reusing an already-SELECTed session"

    # the pooled channel still serves correctly after the burst
    _, _, h = fetch(ng.port, f"/l2authka/auth-{stamp}-0")
    assert h.get("x-cache") == "HIT", "keepalive+auth location broke the hot path"


def test_l2_db_select(ng: Nginx, origin: Origin,
                      redis: RedisServer) -> None:
    """SELECT-only preamble (db=1, no auth): the object lands in db 1, not 0."""
    fetch(ng.port, "/l2db/k1")
    key = l2_key("/l2db/k1")
    assert wait_for(lambda: redis.cli("-n", "1", "EXISTS", key) == "1",
                    timeout=4.0), "object not written to db 1 (SELECT preamble?)"
    assert redis.cli("-n", "0", "EXISTS", key) == "0", \
        "object leaked into db 0 — SELECT did not take effect"


def test_l2_tls(ng: Nginx, origin: Origin,
                redis_tls: RedisServer) -> None:
    """rediss:// with server-cert verification against the test CA: the
    write-through SET reaches the TLS redis over an encrypted connection."""
    fetch(ng.port, "/l2tls/k1")
    key = l2_key("/l2tls/k1")
    assert wait_for(lambda: redis_tls.cli("EXISTS", key) == "1", timeout=4.0), \
        "object not in TLS redis (handshake/verify failed?)"
    _, _, h = fetch(ng.port, "/l2tls/k1")
    assert h.get("x-cache") == "HIT", "second read should be an L1 hit"


def test_redis_tls_untrusted_ca_rejected(
        ng: Nginx, origin: Origin,
        redis_tls_untrusted: RedisServer) -> None:
    """AUD-TLS1: /l2tlsuntrusted/ trusts the SAME CA as /l2tls/, but this
    backend's cert is signed by a DIFFERENT CA. A working
    SSL_CTX_set_verify(PEER) must fail the handshake's chain check, so the
    fire-and-forget L2 write-through must NEVER land -- the key must stay
    absent no matter how long we wait. Before the fix, verify mode stays
    SSL_VERIFY_NONE (the ngx_ssl_trusted_certificate call only loads a store,
    it never flips the mode), the handshake succeeds anyway, and the key
    shows up -- so this assertion is exactly what should currently FAIL."""
    fetch(ng.port, "/l2tlsuntrusted/k1")
    key = l2_key("/l2tlsuntrusted/k1")
    assert not wait_for(
        lambda: redis_tls_untrusted.cli("EXISTS", key) == "1", timeout=2.0), \
        "L2 write-through reached a Redis whose cert chains to an UNTRUSTED " \
        "CA -- SSL_CTX_set_verify(PEER) is not being applied (AUD-TLS1)"


def test_redis_tls_expired_cert_rejected(
        ng: Nginx, origin: Origin,
        redis_tls_expired: RedisServer) -> None:
    """AUD-TLS1, second mode: /l2tlsexpired/ trusts the correct CA (chain
    trust is fine) but the leaf cert's own validity window is already
    expired. A working verify must still reject it via the standard OpenSSL
    time check. Same vacuous-guard failure mode as the untrusted-CA test."""
    fetch(ng.port, "/l2tlsexpired/k1")
    key = l2_key("/l2tlsexpired/k1")
    assert not wait_for(
        lambda: redis_tls_expired.cli("EXISTS", key) == "1", timeout=2.0), \
        "L2 write-through reached a Redis with an EXPIRED cert -- " \
        "verification is not actually checking anything (AUD-TLS1)"


def test_l2_tls_keepalive_reuse(ng: Nginx, origin: Origin,
                                redis_tls: RedisServer) -> None:
    """v15-2: the keepalive pool reuses TLS Redis connections across L2 ops, so
    a TLS handshake + AUTH/SELECT is paid once per pooled conn, not per op. A
    distinct-URI burst opens one L2 GET + one L2 SET each; under /l2tlska/
    (keepalive=4) Redis accepts far fewer new TLS connections than the same burst
    under /l2tls/ (no keepalive), where every op dials + handshakes a fresh
    socket. A passing TLS HIT after the burst proves the pooled (already-
    handshaked) channel still serves correctly."""
    n = 60
    stamp = time.time()

    def burst(prefix: str) -> int:
        before = _redis_conns_received(redis_tls)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            list(ex.map(lambda i: fetch(ng.port, f"{prefix}tka-{stamp}-{i}"),
                        range(n)))
        # let the fire-and-forget SETs complete + pooled conns settle
        time.sleep(0.6)
        return _redis_conns_received(redis_tls) - before

    off = burst("/l2tls/")     # no keepalive: ~2N fresh TLS connections
    on = burst("/l2tlska/")    # keepalive=4: a small bounded number, then reuse

    assert off > n, f"no-keepalive TLS baseline too low ({off}); expected > {n}"
    assert on * 2 < off, \
        f"TLS keepalive did not cut Redis connection churn (on={on}, off={off})"

    # the pool keeps the TLS channel live: a subsequent op still hits + serves
    _, _, h = fetch(ng.port, f"/l2tlska/tka-{stamp}-0")   # now an L1 HIT
    assert h.get("x-cache") == "HIT", "TLS keepalive location broke the hot path"


def test_l2_keepalive_per_profile_no_starvation(
        ng: Nginx, origin: Origin,
        redis: RedisServer, redis_tls: RedisServer) -> None:
    """v16 per-fingerprint pool: two mutually-unreusable connection profiles
    (plain /l2ka/ and TLS /l2tlska/, distinct sockaddr + tls bit) each keep their
    OWN keepalive bucket and reuse connections, neither starving the other.

    Before v16 the pool was one process-global struct with a single cap latched
    by whichever profile inited first; the loser's conns could saturate that one
    cap and shut the other profile out (documented in lessons.md: /l2tlska/ was
    deterministically starved under single-process ASan, worked around by summing
    both working sets into /l2ka/'s cap). With per-profile buckets that coupling
    is gone: each server sees its own bounded new-connection churn.

    We hammer BOTH profiles concurrently (interleaved so both are hot at once)
    and measure each Redis instance's total_connections_received independently
    (plain and TLS are separate servers on separate ports, so their counters do
    not mix). Each profile opening its working set once and then reusing means
    each counter stays well below the per-op ceiling. A starved profile would
    instead dial a fresh conn per op -> ~2N new connections on that server."""
    n = 40
    stamp = time.time_ns()

    plain_before = _redis_conns_received(redis)
    tls_before = _redis_conns_received(redis_tls)

    def hit(i: int) -> None:
        # interleave the two profiles so both pools are under load simultaneously
        if i % 2 == 0:
            fetch(ng.port, f"/l2ka/pp-{stamp}-{i}")
        else:
            fetch(ng.port, f"/l2tlska/pp-{stamp}-{i}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(hit, range(n)))
    time.sleep(0.6)   # let fire-and-forget L2 SETs + pool settle

    plain_new = _redis_conns_received(redis) - plain_before
    tls_new = _redis_conns_received(redis_tls) - tls_before

    ops_per_profile = n // 2                 # ~20 requests each -> ~2 L2 ops each

    # Each profile reuses: new conns stay a small bounded number (its own cap +
    # slack), far below one-per-op. If either were starved of pool slots it would
    # dial per op and land near ops_per_profile.
    assert 0 < plain_new < ops_per_profile, \
        f"plain profile did not keep its own pool (new conns={plain_new}, " \
        f"ops~={ops_per_profile}) -- starved by the TLS profile?"
    assert 0 < tls_new < ops_per_profile, \
        f"TLS profile did not keep its own pool (new conns={tls_new}, " \
        f"ops~={ops_per_profile}) -- starved by the plain profile?"

    # both channels still serve correctly after the concurrent load
    _, _, hp = fetch(ng.port, f"/l2ka/pp-{stamp}-0")
    assert hp.get("x-cache") == "HIT", "plain keepalive broke after mixed load"
    _, _, ht = fetch(ng.port, f"/l2tlska/pp-{stamp}-1")
    assert ht.get("x-cache") == "HIT", "TLS keepalive broke after mixed load"


def test_l2_purge_key_drops_l2(ng: Nginx, origin: Origin,
                               redis: RedisServer) -> None:
    """P6: a single-key admin purge on an L2-aware endpoint removes the entry
    from BOTH tiers, so it cannot be silently refilled from Redis."""
    uri = "/l2/purgekey"
    redis.cli("DEL", l2_key(uri))

    s, body_a, h = fetch(ng.port, uri)             # miss -> origin -> L1 + L2
    assert s == 200 and "x-cache" not in h, "prime should miss to origin"
    assert wait_for(lambda: redis.cli("EXISTS", l2_key(uri)) == "1"), \
        "write-through never reached L2"
    _, _, h2 = fetch(ng.port, uri)
    assert h2.get("x-cache") == "HIT", "should be an L1 hit before purge"

    # purge via the L2-aware admin endpoint
    s, b, _ = fetch(ng.port, f"/_cache_l2?key={uri}", method="POST")
    assert s == 200 and json.loads(b)["purged"] == 1, f"purge result: {s} {b}"

    # L2 entry must be gone (DEL fired); fire-and-forget, so allow a beat
    assert wait_for(lambda: redis.cli("EXISTS", l2_key(uri)) == "0"), \
        "admin purge did not DEL the entry from L2 (P6 regression)"

    # next read is a true miss to the origin (a NEW gen), not an L2 refill — and
    # it must NOT stall: purge clears the cross-node single-flight lock too, so the
    # cold-miss winner re-acquires the NX and goes straight to origin. Before the
    # fix a stale lock made it wait the full lock_timeout (~5s) = the V-HANG.
    origin_before = origin.hits
    t0 = time.monotonic()
    s, body_b, h3 = fetch(ng.port, uri)
    elapsed = time.monotonic() - t0
    assert s == 200 and "x-cache" not in h3, \
        f"post-purge read should miss to origin, got {h3.get('x-cache')}"
    assert elapsed < 2.0, \
        f"post-purge cold miss stalled {elapsed:.1f}s (stale single-flight lock?)"
    assert origin.hits == origin_before + 1, "origin was not consulted after purge"
    assert body_b != body_a, "post-purge body should be a fresh generation"


def test_l2_expired_consults_l2(ng: Nginx, origin: Origin,
                                redis: RedisServer) -> None:
    """P6: once the L1 copy is fully expired (past its stale window), a read
    consults L2 before the origin. Seed L2 with a fresh blob after L1 expires
    and prove the request serves it as a HIT without hitting the origin."""
    uri = "/l2e/expired"
    redis.cli("DEL", l2_key(uri))

    fetch(ng.port, uri)                            # prime: L1 (valid=1s) + L2
    time.sleep(4.3)                                # past stale_until (valid*4=4s)
    # both L1 and L2 are expired now; reseed ONLY L2 with a fresh, valid blob
    seeded = b"l2-seeded\n"
    blob = make_ctb4_blob(seeded, headers={"Content-Type": "text/plain"})
    redis.set_raw(l2_key(uri), blob, 60_000)       # binary-safe raw RESP SET
    assert redis.cli("EXISTS", l2_key(uri)) == "1", "failed to seed L2"

    origin_before = origin.hits
    s, body, h = fetch(ng.port, uri)
    assert s == 200, f"expired+L2 read status {s}"
    assert h.get("x-cache") == "HIT", \
        f"expired L1 should serve from L2 as HIT, got {h.get('x-cache')}"
    assert body == seeded.decode(), f"served body {body!r} != seeded L2 blob"
    assert origin.hits == origin_before, \
        "origin was hit even though L2 held a fresh copy (P6 regression)"


def test_l2_preserves_original_freshness(ng: Nginx, origin: Origin,
                                         redis: RedisServer) -> None:
    """An L2 hit restores remaining freshness instead of resetting the location
    TTL. Seed an already-stale object with one second left in its original
    stale window: first read is STALE, then it expires and the origin is used."""
    uri = "/l2e/original-lifetime"
    key = l2_key(uri)
    redis.cli("DEL", key, lock_key(uri))
    seeded = b"l2-aged\n"
    blob = make_ctb4_blob(
        seeded, created=int(time.time()) - 2, fresh_ttl=1, stale_ttl=4)
    redis.set_raw(key, blob, 60_000)

    origin_before = origin.hits
    s, body, h = fetch(ng.port, uri)
    assert s == 200 and body == seeded.decode()
    assert h.get("x-cache") == "STALE", \
        f"aged L2 object was re-promoted as {h.get('x-cache')}, expected STALE"
    assert origin.hits == origin_before, "stale L2 hit unexpectedly used origin"

    time.sleep(2.3)
    origin_before_expired = origin.hits_for("/original-lifetime")
    s, body2, h2 = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in h2, \
        f"expired L2 object was still served as {h2.get('x-cache')}"
    assert origin.hits_for("/original-lifetime") == origin_before_expired + 1, \
        "expired L2 object did not fall through to origin"
    assert body2 != seeded.decode()


def _wire_response(port: int, path: str) -> tuple[bytes, bytes]:
    """Read one response off the socket with no parsing client in between.
    Returns (raw_head, body).

    Header injection is a WIRE defect and http.client is the wrong instrument
    for it: it normalises the header block, and a value an attacker split into
    two lines comes back through .getheaders() looking exactly like a header the
    module chose to emit. The raw bytes are the only place the difference is
    visible."""
    _bump_conn()
    s = socket.create_connection(("127.0.0.1", port), timeout=HTTP_TIMEOUT)
    try:
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                  f"Connection: close\r\n\r\n".encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            rest += chunk
        return head, rest
    finally:
        s.close()


def test_l2_forged_blob_cannot_inject_headers(ng: Nginx, origin: Origin,
                                              redis: RedisServer) -> None:
    """AUD-BLOBE2E1: the AUD-HDR1 restore-side header gate is mutation-proven at
    the UNIT layer (ci/fuzz/fuzz_blob.c -DCT_BLOB_FIXTURES drives
    header_admissible()/blob_validate() directly). What that cannot show is the
    WIRING -- that restore_response() consults the gate on the LIVE serve path.

    Seed L2 with a blob carrying all four AUD-HDR1 primitives at once, then read
    it twice: the first read is the L2-fill serve, the second is the L1 HIT
    promoted from it. Both must be clean. Nothing here reimplements the gate;
    the assertions are on the bytes the client actually receives."""
    uri = "/l2e/forged-headers"
    key = l2_key(uri)
    redis.cli("DEL", key, lock_key(uri))

    seeded = b"forged-l2-body\n"
    blob = make_ctb4_blob(seeded, headers={
        # benign, and the POSITIVE CONTROL: it must SURVIVE. Without it a gate
        # that dropped every stored header -- or a serve that quietly fell
        # through to the origin -- would satisfy every assertion below.
        "Content-Type":       "text/plain",
        # 1. CR/LF in a value -> response splitting.
        "X-Split":            "ok\r\nInjected: yes",
        # 2. a header NAME that is not a token and carries its own CRLF.
        "X-Bad\r\nEvil:":     "1",
        # 3. Transfer-Encoding -> smuggling against a downstream proxy/CDN.
        "Transfer-Encoding":  "chunked",
        # 4. Set-Cookie -> session fixation from a poisoned cache entry.
        "Set-Cookie":         "sess=attacker",
    })
    redis.set_raw(key, blob, 60_000)
    assert redis.cli("EXISTS", key) == "1", "failed to seed the forged blob"

    origin_before = origin.hits

    def assert_clean(stage: str) -> bytes:
        head, body = _wire_response(ng.port, uri)
        low = head.lower()
        assert b"injected" not in low, \
            f"{stage}: CRLF in a stored header value SPLIT into a new response " \
            f"header -- restore_response() did not consult header_admissible()" \
            f"\n{head!r}"
        assert b"evil" not in low, \
            f"{stage}: a non-token stored header name reached the wire\n{head!r}"
        assert b"\nset-cookie:" not in low, \
            f"{stage}: Set-Cookie survived restore (session fixation); it is on " \
            f"the store-side skip list and restore must mirror it\n{head!r}"
        assert b"\ntransfer-encoding:" not in low, \
            f"{stage}: Transfer-Encoding survived restore (smuggling)\n{head!r}"
        # positive control -- the response really is the restored blob
        assert b"\ncontent-type: text/plain" in low, \
            f"{stage}: benign stored header did NOT survive, so the clean " \
            f"assertions above prove nothing\n{head!r}"
        assert body == seeded, \
            f"{stage}: served body {body!r} is not the seeded blob's body"
        return low

    # 1st read: no L1 entry exists, so this is the L2-fill serve.
    first = assert_clean("L2-fill serve")
    assert b"x-cache: hit" in first, \
        "seeded L2 object was not served from L2 -- this test never reached " \
        "the restore path at all"
    assert origin.hits == origin_before, \
        "origin was consulted, so the response is not the forged blob"

    # 2nd read: served from the L1 copy the fill above promoted. Same
    # restore_response() call site (module.c:6738) -- what this second stage
    # actually pins is that L1 holds the RAW forged blob and is re-filtered on
    # every serve, rather than caching a once-sanitised copy at fill time. A
    # future "filter once on the way in" optimisation would leave the first
    # stage green and break this one.
    # NOT covered here: the SIE-snapshot restore at module.c:7093, which is a
    # genuinely separate call site and still has no e2e forged-blob test.
    second = assert_clean("L1 HIT serve")
    assert b"x-cache: hit" in second, "second read should be an L1 HIT"
    assert origin.hits == origin_before, "L1 HIT unexpectedly used the origin"


def test_sie_forged_blob_cannot_inject_headers(ng: Nginx, origin: Origin,
                                               redis: RedisServer) -> None:
    """AUD-SIEBLOB1: test_l2_forged_blob_cannot_inject_headers pins the L2-fill
    and L1-HIT serve paths, both of which call
    ngx_http_cache_turbo_restore_response() from module.c:6738. There is a
    SECOND, genuinely separate call site at module.c:7093
    (ngx_http_cache_turbo_sie_rewrite(), the stale-if-error snapshot replay
    that fires when a fully-expired entry's origin revalidation returns a
    5xx) that was never driven with a forged blob -- so the header-admissible
    gate's wiring on THAT path was unproven at runtime.

    Seed L2 directly with a blob that is already past its serveable window
    (rem_stale <= 0) but still inside its stale-if-error window (RFC-2 CTB4
    sie_ttl), carrying the same AUD-HDR1 forged-header primitives as the L2
    test. With no L1 entry present, a read consults L2, finds the object
    EXPIRED, arms ctx->sie_snap from the L2 blob (the L2-arm branch, not the
    L1 one), and falls through to the origin -- which is forced to answer
    5xx, driving ngx_http_cache_turbo_sie_rewrite() -> restore_response()
    over the forged snapshot. Assertions are on the RAW WIRE BYTES, exactly
    like the L2 test."""
    uri = "/l2e/forged-sie-headers"
    key = l2_key(uri)
    redis.cli("DEL", key, lock_key(uri))

    seeded = b"forged-sie-body\n"
    now = int(time.time())
    blob = make_ctb4_blob(
        seeded,
        headers={
            # benign positive control -- must SURVIVE, see the L2 test for why.
            "Content-Type":       "text/plain",
            # 1. CR/LF in a value -> response splitting.
            "X-Split":            "ok\r\nInjected: yes",
            # 2. a header NAME that is not a token and carries its own CRLF.
            "X-Bad\r\nEvil:":     "1",
            # 3. Transfer-Encoding -> smuggling against a downstream proxy/CDN.
            "Transfer-Encoding":  "chunked",
            # 4. Set-Cookie -> session fixation from a poisoned cache entry.
            "Set-Cookie":         "sess=attacker",
        },
        # created far enough in the past that the object is already outside
        # its serveable window (rem_stale = stale_ttl - age <= 0)...
        created=now - 100,
        fresh_ttl=1,
        stale_ttl=10,
        # ...but sie_ttl still covers "now": now < created + sie_ttl.
        sie_ttl=300,
    )
    redis.set_raw(key, blob, 60_000)
    assert redis.cli("EXISTS", key) == "1", "failed to seed the forged SIE blob"

    origin_before = origin.hits_for("forged-sie-headers")
    origin.fail = True
    try:
        head, body = _wire_response(ng.port, uri)
        low = head.lower()
        assert b"injected" not in low, \
            f"SIE replay: CRLF in a stored header value SPLIT into a new " \
            f"response header -- ngx_http_cache_turbo_sie_rewrite() did not " \
            f"consult header_admissible() on the SIE snapshot path\n{head!r}"
        assert b"evil" not in low, \
            f"SIE replay: a non-token stored header name reached the wire " \
            f"on the SIE snapshot path\n{head!r}"
        assert b"\nset-cookie:" not in low, \
            f"SIE replay: Set-Cookie survived the SIE snapshot restore " \
            f"(session fixation)\n{head!r}"
        assert b"\ntransfer-encoding:" not in low, \
            f"SIE replay: Transfer-Encoding survived the SIE snapshot " \
            f"restore (smuggling)\n{head!r}"
        # positive control -- a truncated/short read cannot vacuously satisfy
        # the assertions above.
        assert b"\ncontent-type: text/plain" in low, \
            f"SIE replay: benign stored header did NOT survive, so the " \
            f"clean assertions above prove nothing\n{head!r}"
        assert b"x-cache: stale-if-error" in low, \
            "seeded blob was not replayed via the SIE snapshot path -- this " \
            f"test never reached ngx_http_cache_turbo_sie_rewrite() at all\n{head!r}"
        assert body == seeded, \
            f"SIE replay: served body {body!r} is not the seeded blob's body"
        assert origin.hits_for("forged-sie-headers") == origin_before + 1, \
            "the failing-origin revalidation was not actually consulted -- " \
            "this test would pass even without a real SIE rewrite"
    finally:
        origin.fail = False
        drain_origin(origin)


def test_l2_malformed_blob_rejected(ng: Nginx, origin: Origin,
                                    redis: RedisServer) -> None:
    """STAB-4: a malformed L2 blob must be fully validated and REJECTED before it
    is inserted into L1 (the old code stored first and only failed in serve(),
    poisoning the L1 slot). Each bad blob => a clean MISS to origin, a real body,
    and a subsequent request that is a legitimate HIT (no poisoned L1, no crash).
    The origin serves a dynamic gen-<n> body."""
    cases = {
        "wrong-magic":   make_ctb4_blob(b"x", magic=0x43544232),     # CTB2
        "wrong-version": make_ctb4_blob(b"x", version=2),
        # CTB3 (prior wire format): a stale on-disk blob from the pre-RFC-2 build
        # must miss-to-origin once (self-heal), not be parsed at a shifted layout.
        "old-ctb3":      make_ctb4_blob(b"x", magic=0x43544233, version=3),
        # valid magic+version but headers_len lies past the buffer end
        "hdrlen-overflow": (
            struct.pack("<IHHIIIIqIII", 0x43544234, 4, 0, 200, 1,
                        0xFFFF, 1, int(time.time()), 60, 240, 0) + b"\x01"),
        # body_len lies past the buffer end
        "bodylen-overflow": (
            struct.pack("<IHHIIIIqIII", 0x43544234, 4, 0, 200, 0,
                        0, 0xFFFF, int(time.time()), 60, 240, 0)),
    }

    for name, blob in cases.items():
        uri = f"/l2/bad-{name}"
        key = l2_key(uri)
        redis.cli("DEL", key, lock_key(uri))
        redis.set_raw(key, blob, 60_000)

        before = origin.hits_for("/bad-")
        s, body, h = fetch(ng.port, uri)
        assert s == 200, f"{name}: status {s}"
        assert body.startswith("gen-"), \
            f"{name}: served garbage body {body!r} from a malformed L2 blob"
        assert "x-cache" not in h, \
            f"{name}: malformed blob served as {h.get('x-cache')} (not a miss)"
        assert origin.hits_for("/bad-") == before + 1, \
            f"{name}: malformed blob did not fall through to origin"

        # Second read must succeed AND be a real HIT — the rejected blob must not
        # have poisoned L1, and the origin response is now legitimately cached.
        s2, body2, h2 = fetch(ng.port, uri)
        assert s2 == 200 and body2 == body and h2.get("x-cache") == "HIT", \
            f"{name}: L1 poisoned/uncacheable after reject (2nd read {s2}, " \
            f"x-cache={h2.get('x-cache')})"


def test_sie_ttl_stored_in_blob(ng: Nginx, origin: Origin,
                                redis: RedisServer) -> None:
    """RFC-2 (CTB4): a response Cache-Control: stale-if-error=N is recorded as an
    ABSOLUTE serve-on-error window (fresh_ttl + N) in the blob's sie_ttl field at
    wire offset 40. Origin under /siettl/ emits max-age=60, stale-if-error=30;
    cache_turbo_valid 60s (honor_cc off, so fresh_ttl is the location 60s), so the
    stored blob carries fresh_ttl=60 and sie_ttl=90. This locks the CTB4 wire
    format + the response_sie parse; the serve-on-error consumer of sie_ttl lands
    in a follow-up."""
    # proxy_pass strips the /siettl/ location prefix, so the origin marker must
    # ride the request SUFFIX (origin sees /siettl-k1, not /k1).
    uri = "/siettl/siettl-k1"
    key = l2_key(uri)
    redis.cli("DEL", key)
    fetch(ng.port, uri)                            # miss -> store L1 + L2
    assert wait_for(lambda: redis.cli("EXISTS", key) == "1"), \
        "object never written to L2"

    blob = redis.get_raw(key)
    assert blob is not None and len(blob) >= 44, f"short/absent blob: {blob!r}"
    magic, version = struct.unpack("<IH", blob[:6])
    assert magic == 0x43544234, f"blob magic {magic:#x} != CTB4 (0x43544234)"
    assert version == 4, f"blob version {version} != 4"
    fresh_ttl, stale_ttl, sie_ttl = struct.unpack("<III", blob[32:44])
    assert fresh_ttl == 60, f"fresh_ttl {fresh_ttl} != 60 (location valid)"
    assert sie_ttl == 90, f"sie_ttl {sie_ttl} != fresh_ttl+30 (90)"
    assert stale_ttl >= fresh_ttl, \
        f"stale_ttl {stale_ttl} < fresh_ttl {fresh_ttl}"

    # A response WITHOUT stale-if-error carries sie_ttl == 0 (no serve-on-error
    # window beyond the normal stale window).
    uri2 = "/l2e/no-sie"
    key2 = l2_key(uri2)
    redis.cli("DEL", key2)
    fetch(ng.port, uri2)
    assert wait_for(lambda: redis.cli("EXISTS", key2) == "1"), \
        "control object never written to L2"
    blob2 = redis.get_raw(key2)
    assert blob2 is not None and len(blob2) >= 44
    (sie_ttl2,) = struct.unpack("<I", blob2[40:44])
    assert sie_ttl2 == 0, f"sie_ttl {sie_ttl2} != 0 for a no-SIE response"


def test_l2_retain_ttl_covers_sie(ng: Nginx, origin: Origin,
                                  redis: RedisServer) -> None:
    """S1.2: the L2 key's own retention (PX) must cover max(stale_window,
    sie_window), not stale_window alone. /l2sie/ sets stale_mult=1 (stale_window
    == fresh_ttl == 1s) and origin emits stale-if-error=3600 (sie_ttl = 3601s).
    Before the fix, retain_ttl was computed as stale_ttl(fresh_ttl, stale_mult)
    -- 1s here -- so the L2 key would already be gone (or close to it) by the
    time an origin failure past 1s needs to serve it from L2, even though the
    blob's own sie_ttl field says the object should still be servable. Negative
    control: reverting the retain_ttl fix in ngx_http_cache_turbo_module.c
    (passing stale_ttl(ttl, stale_mult) again instead of max(stale_window,
    sie_window)) makes this PTTL assertion fail (~1000ms instead of >3000s)."""
    uri = "/l2sie/l2sie-k1"
    key = l2_key(uri)
    redis.cli("DEL", key)
    fetch(ng.port, uri)                            # miss -> store L1 + L2
    assert wait_for(lambda: redis.cli("EXISTS", key) == "1"), \
        "object never written to L2"

    pttl = int(redis.cli("PTTL", key))
    # sie_ttl = fresh_ttl(1) + 3600 = 3601s; allow generous slack for test
    # wall-clock but stay far above the pre-fix ~1000ms stale_window truncation.
    assert pttl > 3000_000, \
        f"L2 key PTTL {pttl}ms truncated to stale_window, not covering " \
        f"stale-if-error window (expected >3,000,000ms, i.e. close to 3601s)"


def test_l2_sie_serve_survives_l1_purge(ng: Nginx, origin: Origin,
                                        redis: RedisServer) -> None:
    """S1.2 (behavioural complement to test_l2_retain_ttl_covers_sie, which only
    asserts the Redis PTTL): prove a user actually gets served during an origin
    outage once L1 is gone. Reuses the /l2sie/ marker (max-age=1,
    cache_turbo_stale_mult 1, origin stale-if-error=3600) -- a 3600s SIE window
    is far past this test's runtime, so it also satisfies the plan's "sleep past
    the stale window; ... within stale-if-error=30" shape without a fragile 30s
    sleep budget.

    Sequence: prime L1+L2 -> sleep past the 1s stale window (L1 now expired) ->
    purge L1 ONLY via the non-L2-aware /_cache admin endpoint (zone "main" has
    no cache_turbo_redis directive, so this purge cannot reach Redis) -> the L2
    key must still exist -> origin.fail = True -> a read must still get a 200
    with X-Cache: STALE-IF-ERROR, served out of L2.

    Negative control: revert S1.2 (retain_ttl back to stale_ttl(ttl,
    stale_mult) instead of max(stale_window, sie_window)) and the L2 key is
    already gone by the time of the purge/origin-fail step -> 502."""
    import json
    uri = "/l2sie/l2sie-sie1"
    key = l2_key(uri)
    redis.cli("DEL", key)

    s0, body0, h0 = fetch(ng.port, uri)            # miss -> store L1 + L2
    assert s0 == 200 and "x-cache" not in h0, "prime should miss to origin"
    assert wait_for(lambda: redis.cli("EXISTS", key) == "1"), \
        "object never written to L2"

    time.sleep(1.3)                                # past the 1s stale window

    # L1-only purge: /_cache (zone "main") has no cache_turbo_redis directive,
    # so it cannot touch the L2 key -- only the L1 slot is dropped.
    s, b, _ = fetch(ng.port, f"/_cache?key={uri}", method="POST")
    assert s == 200 and json.loads(b)["purged"] == 1, f"L1 purge result: {s} {b}"
    assert redis.cli("EXISTS", key) == "1", \
        "L1-only purge must not have deleted the L2 key (test setup broken)"

    origin.fail = True
    try:
        s2, body2, h2 = fetch(ng.port, uri)
        assert s2 == 200, \
            f"origin down + L1 purged should still serve 200 from L2, got {s2}"
        assert h2.get("x-cache") == "STALE-IF-ERROR", \
            f"expected X-Cache: STALE-IF-ERROR from L2, got {h2.get('x-cache')}"
        assert body2 == body0, \
            f"served {body2!r}, expected the original primed body {body0!r}"
    finally:
        origin.fail = False
        drain_origin(origin)


def test_l2_stale_refetch_does_not_stall_on_lock(ng: Nginx, origin: Origin,
                                                 redis: RedisServer) -> None:
    """V-HANG-2: a request that finds an entry past its stored stale window must
    go to the origin PROMPTLY, not sit in the cold-miss wait loop until the
    cross-node NX lock expires.

    The trap: the winner takes `SET <prefix>lock:<hex> NX PX <lock_ttl*1000>`
    (default 5s) and it is released ONLY by PX expiry -- `unlock` is
    deliberately NULL (module.h), because an early unlock would re-open the
    dogpile window. That is fine as long as waiters can serve the fill. But
    /l2sie/ sets cache_turbo_stale_mult 1, so stale_window == fresh_ttl == 1s:
    ~1s after the winner stores, the object is UNSERVEABLE while its lock is
    still alive for ~4s more. Every request in that gap lost the NX, entered
    ngx_http_cache_turbo_cold_wait(), re-polled L2 every 100ms
    (LOCK_POLL_MS), got the same unserveable blob back each time, and only
    reached the origin after the full lock_timeout (default 5000ms).

    That is a ~5s user-visible stall on a healthy origin with a healthy cache.
    It also made test_l2_sie_serve_survives_l1_purge look like a flaky timeout,
    because HTTP_TIMEOUT is also 5s -- the client lost that dead heat.

    ⚠ ASSERT ON WALL-CLOCK, not just status. With the bug present this request
    still returns 200, just ~5.05s later, so a status-only assertion passes
    with the bug fully restored.

    Negative control: revert the `ctx->l2_present_unserveable` give-up in
    cold_wait (module.c) -- e.g. `if (0 && ctx->waiting && ...)` -- and the
    elapsed assertion below fails at ~5.0s while every other assertion here
    still passes."""
    uri = "/l2sie/l2sie-nostall"
    key = l2_key(uri)
    redis.cli("DEL", key)

    s0, _, _ = fetch(ng.port, uri)              # miss -> store L1 + L2, takes NX
    assert s0 == 200, f"prime should reach origin, got {s0}"
    assert wait_for(lambda: redis.cli("EXISTS", key) == "1"), \
        "object never written to L2"

    # Past the 1s stale window but well inside the 5s lock PX: the exact gap
    # where the winner's lock is still held and its object is unserveable.
    time.sleep(1.3)

    # sleep() only guarantees a LOWER bound. If the box stalls long enough for
    # the 5s lock PX to expire before the fetch below, the request no longer
    # meets a held lock and the test passes without exercising the window it
    # exists to cover. Assert the lock is still alive, with enough margin left
    # that a stall could not be mistaken for a healthy sub-2s response.
    lock_pttl = int(redis.cli("PTTL", lock_key(uri)))
    assert lock_pttl > 2000, (
        f"cross-node lock has only {lock_pttl}ms left (or is gone: -2). The "
        f"unserveable-object/held-lock window has already closed, so this run "
        f"would not exercise V-HANG-2 at all.")

    t0 = time.time()
    s1, _, _ = fetch(ng.port, uri)
    elapsed = time.time() - t0

    assert s1 == 200, f"stale refetch should serve 200 from origin, got {s1}"
    # lock_timeout defaults to 5000ms; the stall was the FULL window. A healthy
    # refetch is ~50ms here, so 2s is far above real latency and far below the
    # 5s bug -- it cannot pass with the give-up removed.
    assert elapsed < 2.0, (
        f"stale refetch took {elapsed:.2f}s -- it stalled in the cold-miss wait "
        f"loop waiting out the cross-node NX lock (V-HANG-2). Expected <2s; "
        f"the bug parks for the full lock_timeout (~5s).")

    drain_origin(origin)


def test_l2_unserveable_giveup_still_single_flights(
        ng: Nginx, origin: Origin, redis: RedisServer) -> None:
    """V-HANG-2 guard rail: the give-up must not defeat cold-miss single-flight.

    The V-HANG-2 fix lets a cold-miss waiter stop parking once it sees the key
    PRESENT in L2 but past its stored stale window -- the fill it was waiting
    for has already landed, so further polling only burns lock_timeout.

    ⚠ That inference is valid ONLY on a cold-wait RE-POLL. The set site
    (module.c, the L2-hit-but-expired branch) fires on ANY L2 lookup, including
    the very first one. If the give-up is gated on `ctx->waiting`, it guards
    nothing: cold_wait() sets `waiting = 1` a few lines ABOVE the check, so it
    is unconditionally true on first entry too. A CLAIM_LOSER then reads the
    same expired blob on its FIRST pass -- before the winner has written
    anything -- gives up immediately, and goes straight to the origin. Every
    loser in a burst does the same, so the whole burst stampedes.

    Hence the real gate is `ctx->wait_polled`, set at the park site only after
    the timer is armed.

    ⚠ It deliberately does NOT reuse /l2sie/. That location sets
    cache_turbo_valid 1s, so a regenerated entry is stale again within the
    burst and 40 origin fetches is CORRECT behaviour there -- verified by
    running this exact burst against stock: identical counts (40 regens, 40
    lock_waits). A stampede assertion on /l2sie/ would fail on fixed and stock
    alike and prove nothing.

    /sfgu/ instead has fresh_ttl 30s with stale_mult 1, so once the primed entry
    is unserveable, any regen stays fresh for the whole burst -- every extra
    origin fetch is then a genuine single-flight failure. The entry is aged by
    rewriting the blob's `created` field (i64 at offset 24) rather than by
    sleeping 30s.

    Negative control: relax the gate back to `ctx->waiting` in cold_wait
    (module.c) and the `regens` assertion below fails, while
    test_l2_stale_refetch_does_not_stall_on_lock above still passes -- the two
    tests pin opposite edges of the same branch."""
    uri = "/sfgu/sfgu-k1"
    key = l2_key(uri)
    redis.cli("DEL", key)

    s0, _, _ = fetch(ng.port, uri)              # miss -> store L1 + L2, takes NX
    assert s0 == 200, f"prime should reach origin, got {s0}"
    assert wait_for(lambda: redis.cli("EXISTS", key) == "1"), \
        "object never written to L2"

    # Age the L2 blob past its stale window WITHOUT waiting for it: rewrite
    # `created` (i64 @24) to 60s ago. fresh_ttl is 30 and stale_mult 1 makes
    # stale_ttl 30, so the object is now PRESENT-but-UNSERVEABLE -- exactly the
    # state that arms l2_present_unserveable on the very first L2 lookup.
    blob = redis.get_raw(key)
    assert blob is not None and len(blob) >= 44, f"short/absent blob: {blob!r}"
    fresh_ttl, stale_ttl, _sie = struct.unpack("<III", blob[32:44])
    assert fresh_ttl == 30 and stale_ttl == 30, (
        f"/sfgu/ fixture drifted: fresh_ttl={fresh_ttl} stale_ttl={stale_ttl}, "
        f"expected 30/30 (valid 30s + stale_mult 1). Without stale_ttl == "
        f"fresh_ttl the aged blob is still serveable and this test is vacuous.")

    # ⚠ ORDER MATTERS. PURGE is L2-aware -- it DELETEs the Redis key too -- so
    # the L1 drop has to happen BEFORE the aged blob is written, or the setup
    # deletes the very object under test and the burst sees a plain cold miss.
    s_p, b_p, _ = fetch_raw(ng.port, uri, method="PURGE")
    assert s_p == 200, f"PURGE status {s_p}: {b_p}"
    aged = blob[:24] + struct.pack("<q", int(time.time()) - 60) + blob[32:]
    redis.set_raw(key, aged, 3_600_000)
    wait_for_l2(redis, key, aged, what="aged blob for /sfgu/ give-up")

    base = origin.hits
    waits0 = _admin_lock_waits(ng)

    # ⚠ PRECONDITION, not decoration. The lock_waits assert at the end of this
    # test is a LIVENESS proxy ("someone actually parked"), and it is only
    # meaningful while the winner's origin fetch is still in flight when the
    # stragglers arrive. With an INSTANT origin the winner fills L1 first, the
    # rest take CLAIM_FRESH without ever entering cold_wait(), and the delta
    # decays toward 0 -- a test-harness artefact that looks exactly like a
    # single-flight defect (SUITE-8).
    #
    # Measured on this burst, pinned to 2 cores: delay=0.05 gives a lock_waits
    # delta of 39/39/39, delay=0.0 gives 39/23/8 -- same regens==1 (the module
    # is correct either way), but the margin erodes to near-zero. CI's slower
    # single-process ASan arm is where 8 becomes 0.
    #
    # This tripped because the autotune tests upstream in run_all() borrow
    # origin.delay and used to restore it to a hardcoded 0.0 instead of the
    # suite baseline. Origin.reset_delay() now restores the real default; this
    # assert makes a regression of that fail HERE, loudly, instead of showing up
    # as a rare unexplained flake in the assertion below.
    assert origin.delay > 0, (
        f"origin.delay is {origin.delay}: an instant origin leaves no "
        f"regeneration window for the losers to park in, making the lock_waits "
        f"liveness assert below vacuous. An upstream test borrowed origin.delay "
        f"and did not restore it via origin.reset_delay().")

    # All 40 readers rendezvous at the barrier before hitting the key, so they
    # reach the cold-miss claim inside the same window. Without this the burst
    # can legitimately produce ZERO waiters: a regen here stays fresh for 30s,
    # so once the winner's fill lands in L1 every later reader takes the
    # CLAIM_FRESH path (module.c) and serves from L1 *without entering
    # cold_wait()* -- the only site that increments lock_waits. On a loaded
    # runner, thread start-up is staggered enough for the winner to finish
    # before any other thread reaches the claim, leaving regens == 1 (a correct
    # collapse) but the lock_waits delta at 0 -- failing the liveness assert
    # below for a race in the test rather than a defect in the module.
    readers = 40
    barrier = threading.Barrier(readers)

    def _burst_reader(_i: int) -> tuple[int, bytes, dict]:
        barrier.wait()
        return fetch(ng.port, uri)

    with concurrent.futures.ThreadPoolExecutor(max_workers=readers) as pool:
        results = list(pool.map(_burst_reader, range(readers)))

    assert {r[0] for r in results} == {200}, \
        f"expired-L2 burst returned {set(r[0] for r in results)}"

    # A regen here stays fresh for 30s, so after the first one every other
    # reader can be served: extra origin fetches are genuine single-flight
    # failures, not re-expiry. The give-up may still legitimately cost a few
    # (a waiter that re-polls and finds the blob unserveable regenerates), so
    # the bound is loose -- but with the gate wrongly on ctx->waiting all 40
    # bypass the wait loop and reach the origin.
    regens = origin.hits - base
    assert regens <= 5, (
        f"expired-L2 burst stampeded: {regens} origin fetches for 40 readers. "
        f"The V-HANG-2 give-up fired on the FIRST pass instead of on a re-poll, "
        f"so every cold-miss loser bypassed the wait loop.")

    # ...and it must collapse VIA the wait path, not by luck: at least one
    # request has to have actually parked. Without this the assertion above
    # could pass on a run where the requests merely serialised.
    assert _admin_lock_waits(ng) - waits0 > 0, \
        "no requests waited — single-flight did not engage on the expired-L2 burst"

    drain_origin(origin)


def _errlog_l2_promote_rc_in_window(ng: Nginx, start: int) -> list[int]:
    """AUD-L2-PROMOTE-RACE oracle: every `cache_turbo: test_l2_promote_rc=<N>`
    value logged strictly after byte offset `start`, in emission order. NGX_OK
    is 0 and NGX_DECLINED is -5 in nginx's ngx_int_t space, so this also
    accepts a leading '-'. Mirrors _errlog_sie_unconsumed_in_window's
    window-bracketing discipline exactly (see that function's docstring for
    why: attributing a debug/notice line to the wrong concurrent request is
    the failure mode this guards against)."""
    log = ng.root / "logs" / "error.log"
    try:
        with log.open("rb") as f:
            f.seek(start)
            tail = f.read()
    except OSError as exc:
        raise AssertionError(f"error.log unreadable: {exc}") from None
    text = tail.decode("utf-8", errors="replace")
    return [int(m) for m in
            re.findall(r"cache_turbo: test_l2_promote_rc=(-?\d+)", text)]


def test_l2_promote_race_never_overwrites_newer_l1_entry(
        ng: Nginx, origin: Origin, redis: RedisServer) -> None:
    """AUD-L2-PROMOTE-RACE: the L2 GET is async -- it parks the request (zone
    mutex NOT held) and resumes it when the redis reply lands. On resume, the
    pre-fix code promoted the L2 blob into L1 unconditionally, so a slow L2
    reply could overwrite a NEWER origin response that landed in L1 while the
    first request was parked. store_if(..., STORE_IF_NEWER) closes that by
    deciding "is the resident entry newer?" and writing under ONE lock hold.

    WHY NOT A PLAIN BLACK-BOX TIMING RACE: the actual window this fix closes
    is the gap between the resumed handler's own (already-unlocked) L1
    re-check and its store_if() call -- pure CPU, no I/O, no yield point in
    between (confirmed: firing a concurrent write any time before the L2
    reply arrives is simply seen by that SAME re-check on resume and short-
    circuits the promote call entirely, producing "L1 HIT (fresh)" and never
    reaching the vulnerable line -- that dead end was tried and measured
    before landing on this design). No amount of delaying the L2 GET itself
    (redis DEBUG SLEEP, a slow origin, etc.) can widen a gap with no yield
    point in it. cache_turbo_test_l2_promote_hold_ms (TEST_FAULTS-only, module.c
    ~L2-promote site) blocks the CURRENT worker for a bounded, deterministic
    window at EXACTLY that gap via a plain ngx_msleep -- it stalls only this
    worker's own event loop, so with 4 workers configured a concurrent
    request lands on a different worker and is unaffected.

    Two-part oracle, matching the item's explicit requirement to distinguish
    "declined" from "never reached": the NOTICE-level `test_l2_promote_rc=`
    line (module.c, right after the store_if() call, inside TEST_FAULTS) is
    asserted PRESENT (an absent line fails, never reads as anything) and
    equal to NGX_DECLINED. A black-box read of the final L1 body is used
    alongside it, since it is independently reachable here (unlike the
    unconsumed-buffer case _errlog_sie_unconsumed_in_window's sibling
    docstring explains): the body proves the DECLINED promote was correct
    behaviour (the newer entry, not the stale L2 blob, is what gets served),
    while the log line proves the guarded branch, specifically, is what
    produced it -- a passing body check with an absent/wrong log line would
    mean the assertion is passing for an unrelated reason and must fail.

    Sequence:
      1. Seed L2 (only) with body A by writing it through the module on a
         throwaway URI sharing /l2promo/'s config, then copying the raw blob
         bytes into THIS test's key via redis.set_raw() -- keeps the exact
         on-wire blob format (module-produced) while leaving /l2promo/x's own
         L1 slot virgin, so the very first real read of it is a guaranteed
         cold L1 miss that must consult L2.
      2. Fire the L2-bound read in the background; it parks on the L2 GET,
         resumes, and -- because /l2promo/ sets
         cache_turbo_test_l2_promote_hold_ms -- blocks its own worker for
         2000ms immediately before the promote decision.
      3. While it is held, fire the bypass read on the SAME key (never
         touches redis, reaches origin fast, stores body B into L1 via a
         plain unconditional store() -- on a different nginx worker).
      4. The held worker wakes, decides (L1 now holds B, newer than the L2
         blob) and must DECLINE the promote. A follow-up plain read must
         still see body B, never body A; the NOTICE line must read
         NGX_DECLINED.

    Skipped in single-process mode (the ASan single-process job), which runs
    `workers = 1`. Step 3 requires the concurrent bypass write to land on a
    DIFFERENT worker while this one is inside its ngx_msleep; with one worker
    that write cannot be serviced until the hold expires, by which point the
    promote has already been decided against an L1 slot that still holds
    nothing newer -- the promote is then correctly allowed and the oracle
    reads NGX_OK. That is the harness losing the race setup, not the fix
    regressing, so asserting it here would be asserting a property this
    configuration cannot express. The multi-worker Runtime and ASan
    multi-worker jobs both exercise it for real."""
    if ng.single_process:
        return

    uri = "/l2promo/x"
    seed_uri = "/l2promo/seed-for-x"
    key = l2_key(uri)
    redis.cli("DEL", key)

    # Produce a module-correct blob for body A on a THROWAWAY key (own L2
    # slot), then copy its raw bytes into uri's L2 slot directly -- this
    # leaves /l2promo/x's L1 completely virgin (never touched), which is what
    # forces the first real read of it through the cold-L1-miss -> L2-consult
    # path rather than serving a live L1 HIT.
    s0, bodyA, _ = fetch(ng.port, seed_uri)
    assert s0 == 200 and bodyA, f"seed prime failed: {s0} {bodyA!r}"
    seed_key = l2_key(seed_uri)
    assert wait_for(lambda: redis.cli("EXISTS", seed_key) == "1"), \
        "seed body never reached L2"
    blobA = redis.get_raw(seed_key)
    assert blobA is not None, "could not read back the seed L2 blob"

    # AGE the blob's `created` stamp (u64 LE at byte offset 24, per
    # ngx_http_cache_turbo_blob_hdr_write / blob_validate -- no checksum
    # covers the header, so a direct byte patch is safe and does not need to
    # re-derive anything else) by 25s BEFORE seeding it into L2. This is what
    # makes STORE_IF_NEWER's comparison unambiguous regardless of scheduling
    # jitter: the promoted blob's remaining freshness (rem_fresh = fresh_ttl -
    # age) is forced to ~5s while the bypass write's fresh_until (anchored
    # fresh, cache_turbo_valid 30s from ITS OWN write time) is ~30s out -- a
    # >20s margin, immune to any sub-second timing wobble. Without this the
    # seed and the bypass write land within a few hundred ms of each other
    # (both use the same 30s TTL), so "is the resident entry newer" turns on
    # exactly the race's own jitter and the assertion flakes both ways
    # (measured: NGX_OK observed on an unaged blob in ~2 of 5 runs).
    assert len(blobA) >= 32, f"seed blob too short to carry a header: {blobA!r}"
    created = int.from_bytes(blobA[24:32], "little")
    aged_created = created - 25
    blobA = blobA[:24] + aged_created.to_bytes(8, "little") + blobA[32:]

    redis.set_raw(key, blobA, 30_000)
    wait_for_l2(redis, key, blobA, what="L2 seed for /l2promo/x")

    window_start = _errlog_window_start(ng)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        # Parked read: /l2promo/x's L1 slot is virgin, so this is a
        # guaranteed cold L1 miss -> L2 GET -> resume -> held for 2000ms
        # (cache_turbo_test_l2_promote_hold_ms) right before the promote
        # decision.
        held_fut = pool.submit(fetch, ng.port, uri)

        # Give the held request time to actually park on L2, resume, and
        # enter the hold -- comfortably under the 2000ms hold itself (wide
        # margin against redis round-trip / scheduler jitter on a loaded CI
        # box), so the bypass write below reliably lands INSIDE the window.
        time.sleep(0.5)

        # Concurrent newer write: bypass never touches redis or the hold
        # (different code path entirely), so it proceeds immediately on
        # whichever worker picks it up -- almost certainly a different one
        # from the held request, since that worker's event loop is blocked.
        s_bp, bodyB, _h_bp = fetch(ng.port, uri + "?nocache=1")
        assert s_bp == 200 and bodyB, f"bypass write failed: {s_bp} {bodyB!r}"
        assert bodyB != bodyA, \
            "bypass must hit the origin for a fresh body, not replay bodyA"

        s_held, _b_held, _h_held = held_fut.result(timeout=10)

    assert s_held == 200, f"held L2 read returned {s_held}, expected 200"

    # Oracle part 1: the NOTICE line must be PRESENT and read NGX_DECLINED.
    # Absent is a FAIL, never read as 0/NGX_OK -- see the docstring on why an
    # absent line cannot be trusted as "the guard passed".
    rcs = _errlog_l2_promote_rc_in_window(ng, window_start)
    assert rcs, (
        "no 'cache_turbo: test_l2_promote_rc=' line found in this request's "
        "error.log window -- the oracle line is MISSING, which must fail "
        "(never silently read as declined): either TEST_FAULTS is not "
        "actually compiled in, or the L2-promote branch was never entered "
        "for this request")
    NGX_DECLINED = -5
    assert all(v == NGX_DECLINED for v in rcs), (
        f"L2 promote was not declined: test_l2_promote_rc values in window = "
        f"{rcs} (NGX_DECLINED == {NGX_DECLINED}) -- the race was not closed, "
        f"a slow L2 reply was allowed to promote over a newer L1 entry")

    # Oracle part 2 (black-box, reachable here unlike the SIE-buffer case):
    # a follow-up plain read must see bodyB (the newer L1 entry), never
    # bodyA (the stale L2 blob). Under the pre-fix bug this comes back with
    # bodyA instead -- exactly the race AUD-L2-PROMOTE-RACE exists to close.
    s_final, b_final, _h_final = fetch(ng.port, uri)
    assert s_final == 200, f"final read returned {s_final}, expected 200"
    assert b_final == bodyB, (
        f"final L1 body was overwritten by the slow L2 promote: "
        f"got {b_final!r}, expected the newer bypass body {bodyB!r} "
        f"(bodyA was {bodyA!r})"
    )


def test_request_cc_serve_verdict_l2(ng: Nginx, origin: Origin,
                                     redis: RedisServer) -> None:
    """C-S5-a: RFC-1 request Cache-Control serve verdict evaluated on the L2
    (Redis) arm at module.c:5296, NOT the L1 site at :4813 the existing
    /reqcc/ + /reqccst/ tests exercise (neither location there carries
    cache_turbo_redis, so the L2 branch has zero runtime coverage otherwise).

    An L2 entry can be younger than the L1 copy (a peer refreshed it), so its
    own age (bh.created / bh.fresh_ttl) has to be re-verdicted independently.

    PURGE on /reqccl2/ is L2-AWARE (it DELs the Redis key too, see
    ngx_http_cache_turbo_purge_request / module.c:1711), so it cannot be used
    to drop L1 while leaving L2 populated -- it empties both. Instead: prime,
    capture the stored blob's raw bytes via GET, PURGE to clear both tiers,
    then write the SAME blob bytes back into L2 only via raw SET (mirrors the
    /sfgu/ precedent's "aged blob written directly to L2" technique). L1 is
    now empty and L2 holds the object, so any read is forced through the L2
    verdict at module.c:5296.

    Two-sided: a Cache-Control bound the L2 entry FAILS must revalidate at
    origin (req_reval, observable as a body change / non-HIT status); a
    request that does not conflict must still serve the stored L2 copy."""
    uri = "/reqccl2/reqccl2-k1"
    key = l2_key(uri)
    redis.cli("DEL", key)

    # prime: miss -> stored in both L1 and L2
    s0, base, _ = fetch(ng.port, uri)
    assert s0 == 200, f"prime should reach origin, got {s0}"
    assert wait_for(lambda: redis.cli("EXISTS", key) == "1"), \
        "object never written to L2"
    blob = redis.get_raw(key)
    assert blob is not None and len(blob) >= 44, f"short/absent blob: {blob!r}"

    def _drop_l1_keep_l2() -> None:
        """PURGE clears L1 AND L2 (module.c:1711); re-write the captured blob
        straight into L2 afterwards so only L1 stays empty.

        ⚠ The PURGE-side L2 DEL is FIRE-AND-FORGET: the 200 is written from the
        L1 count and does not await Redis (see the purge completion comment,
        "L2 deletions are fire-and-forget and not reflected in {"purged":N}").
        So the DEL can land AFTER our set_raw() and delete the very blob under
        test -- an unrecoverable loss that wait_for_l2() below can only report
        as `observed (absent): None`, never wait out. Observed as an ASan
        single-process red on run 31464424090. Wait for the DEL to be OBSERVED
        (key gone) before writing, so the two operations cannot interleave."""
        s_p, b_p, _ = fetch_raw(ng.port, uri, method="PURGE")
        assert s_p == 200, f"PURGE status {s_p}: {b_p}"
        assert wait_for(lambda: redis.cli("EXISTS", key) == "0"), \
            "PURGE's fire-and-forget L2 DEL never landed; writing the blob " \
            "back now would race it and could be deleted after the fact"
        redis.set_raw(key, blob, 3_600_000)
        wait_for_l2(redis, key, blob,
                    what="L2 restore after PURGE on /reqccl2/")

    _drop_l1_keep_l2()

    # plain read (no request Cache-Control): must still be served from the
    # stored L2 copy -- proves the passing/no-bound arm fills L1 from L2
    # rather than always refetching.
    s1, b1, h1 = fetch(ng.port, uri)
    assert s1 == 200 and b1 == base, \
        f"plain re-read after L1 drop should replay the L2-stored body, " \
        f"got status={s1} body_changed={b1 != base}"
    assert h1.get("x-ct-status") in ("HIT", "STALE"), \
        f"plain re-read should be served from L2 (HIT/STALE), got " \
        f"{h1.get('x-ct-status')}"

    # drop L1 again (the read above refilled it) so the next read is also
    # forced through the L2 verdict.
    _drop_l1_keep_l2()

    # min-fresh=999: client wants >=999s of remaining freshness. NOTE: this
    # (not max-age=0) is the correct failing bound here -- max-age=0 is
    # intercepted unconditionally by ngx_http_cache_turbo_request_revalidate()
    # at module.c:4473, BEFORE the L1 lookup even runs, so it never reaches
    # the L2 verdict site at :5296 at all (confirmed via error.log: it logs
    # "request no-cache -> origin (revalidate)", not an L2 verdict line). The
    # L2 entry has at most 30s of remaining freshness -> l2_fresh_ok=0; no
    # max-stale -> l2_stale_ok=0 -> req_reval=1 -> refetch from origin instead
    # of serving the rejected L2 copy.
    s2, b2, h2 = fetch(ng.port, uri,
                       headers={"Cache-Control": "min-fresh=999"})
    assert s2 == 200, f"revalidated read should still be 200, got {s2}"
    assert b2 != base, \
        "min-fresh=999 must revalidate the L2 copy at origin (new body), " \
        "not replay the rejected stored blob"
    assert h2.get("x-ct-status") != "HIT", \
        f"min-fresh=999 must refuse the L2-served HIT, got " \
        f"{h2.get('x-ct-status')}"

    drain_origin(origin)


def tag_key(name: str, prefix: str = "ct:") -> str:
    """Mirror the module's tag-set key: <prefix>tag:<name>."""
    return f"{prefix}tag:{name}"


def test_l2_tag_truncation_warns(ng: Nginx, origin: Origin,
                                 redis: RedisServer) -> None:
    """MAX_TAGS (16) is a deliberate DoS bound -- the tag value is
    upstream-controlled, and each tag costs its own Redis op, so an unbounded list
    would let one response fire a connection storm (PERF-2). The bound stays.

    But hitting it SILENTLY is a correctness trap, and a real one: a Magento
    category page emits one cat_p_<id> tag PER PRODUCT, so a 40-product page
    overflows 16 and the tags past the cap are never indexed. A later purge of one
    of those tags then does NOT invalidate the page -- the operator gets stale
    content with no signal anywhere. This pins the WARNING that makes the
    truncation diagnosable.

    Asserted positively (see lessons.md): we require the warning TEXT to appear,
    and we require it NOT to appear for an exactly-at-the-cap value -- a warning
    that always fires is as useless as one that never does."""
    logf = ng.root / "logs" / "error.log"

    def log_text() -> str:
        return (logf.read_text(encoding="utf-8", errors="replace")
                if logf.exists() else "")

    # Exactly 16 tags -- at the cap, nothing dropped, must NOT warn. Append a
    # trailing separator so this also exercises the "skip trailing separators
    # before deciding s < e" arm -- without it, a value ending right after the
    # 16th tag never reaches that code path and the arm goes unexercised.
    before = len(log_text())
    at_cap = ",".join(f"t{i}" for i in range(16)) + ", "
    fetch(ng.port, f"/l2tcap/at-cap?t={at_cap}")
    time.sleep(0.3)
    new = log_text()[before:]
    assert "tag list truncated" not in new, \
        ("a value with exactly MAX_TAGS tags drops nothing and must NOT warn -- "
         "a warning that always fires teaches the operator to ignore it")

    # 17 tags -- one over. The 17th is silently unindexed, so it MUST warn.
    before = len(log_text())
    over = ",".join(f"x{i}" for i in range(17))
    fetch(ng.port, f"/l2tcap/over-cap?t={over}")
    time.sleep(0.3)
    new = log_text()[before:]
    assert "tag list truncated" in new, \
        ("17 tags overflow the 16-tag cap: the 17th is NOT indexed and a purge of "
         "it will NOT invalidate the entry. That must be logged, or the operator "
         "sees stale content with no signal. Missing warning in:\n" + new[-800:])
    assert "/l2tcap/over-cap" in new, \
        "the truncation warning must name the URI it dropped tags for"

    # And the dropped tag really is absent from the index -- the warning is not
    # cosmetic, it is reporting a real loss of purgeability.
    assert redis.cli("EXISTS", tag_key("x16")) == "0", \
        "the 17th tag must not be indexed (it is past the cap)"
    assert redis.cli("EXISTS", tag_key("x0")) == "1", \
        "tags within the cap must still be indexed"
    drain_origin(origin)


def test_l2_tag_add_on_store(ng: Nginx, origin: Origin,
                             redis: RedisServer) -> None:
    """v2c: a tagged store SADDs the object's L2 key into every tag set named by
    cache_turbo_tag, and bounds the set's lifetime with an EXPIRE."""
    redis.cli("DEL", tag_key("blog"), tag_key("news"))
    uri = "/l2t/article"
    s, _, h = fetch(ng.port, uri)                  # miss -> origin -> store+tag
    assert s == 200 and "x-cache" not in h, "tagged prime should miss to origin"

    okey = l2_key(uri)
    # SADD is fire-and-forget; let it land
    assert wait_for(lambda: redis.cli("SISMEMBER", tag_key("blog"), okey) == "1"), \
        "object key never joined tag set 'blog'"
    assert redis.cli("SISMEMBER", tag_key("news"), okey) == "1", \
        "object key missing from second tag set 'news'"
    # EXPIRE applied to the tag set (bounded lifetime)
    pttl = int(redis.cli("PTTL", tag_key("blog")))
    assert pttl > 0, f"tag set has no TTL (PTTL={pttl})"


def test_l2_tag_purge(ng: Nginx, origin: Origin, redis: RedisServer) -> None:
    """P4: purge-by-tag drops every tagged object from BOTH tiers and removes
    the tag set. Two objects share tag 'news'; one POST clears them all."""
    redis.cli("DEL", tag_key("blog"), tag_key("news"))
    u1, u2 = "/l2t/p1", "/l2t/p2"
    body1, body2 = {}, {}
    for u, store in ((u1, body1), (u2, body2)):
        _, b, _ = fetch(ng.port, u)                # miss -> origin -> store+tag
        store["body"] = b
        _, _, h = fetch(ng.port, u)
        assert h.get("x-cache") == "HIT", f"{u} should be cached (L1) before purge"
    assert wait_for(lambda: redis.cli("SCARD", tag_key("news")) == "2"), \
        "both objects should be in tag set 'news'"

    s, b, _ = fetch(ng.port, "/_cache_l2?tag=news", method="POST")
    assert s == 200, f"tag purge status {s}"
    assert json.loads(b)["purged"] == 2, f"expected 2 purged, got {b}"

    # both objects gone from L2, and the tag set itself deleted
    assert wait_for(lambda: redis.cli("EXISTS", l2_key(u1)) == "0"
                    and redis.cli("EXISTS", l2_key(u2)) == "0"), \
        "tagged objects not removed from L2"
    assert wait_for(lambda: redis.cli("EXISTS", tag_key("news")) == "0"), \
        "emptied tag set was not deleted"

    # both gone from L1: next reads miss to a fresh origin generation, and must
    # not stall — tag purge clears each member's single-flight lock too (V-HANG).
    origin_before = origin.hits
    t0 = time.monotonic()
    _, nb1, h1 = fetch(ng.port, u1)
    _, nb2, h2 = fetch(ng.port, u2)
    elapsed = time.monotonic() - t0
    assert "x-cache" not in h1 and "x-cache" not in h2, \
        "tagged objects should be a MISS in L1 after purge"
    assert elapsed < 2.0, \
        f"post-tag-purge cold misses stalled {elapsed:.1f}s (stale lock?)"
    assert origin.hits == origin_before + 2, "both reads should reach origin"
    assert nb1 != body1["body"] and nb2 != body2["body"], \
        "post-purge bodies should be fresh generations"


def test_l2_tag_purge_large(ng: Nginx, origin: Origin,
                            redis: RedisServer) -> None:
    """STAB-3 + PERF-1/2: a tag set with enough members that the SMEMBERS reply
    spans multiple recv()s (>16 KiB), and whose purge drops every member across
    both tiers. Pre-PERF this fired ~2N fire-and-forget DEL connections at once
    and exhausted worker_connections; now the purge collects all keys into ONE
    pipelined UNLINK connection, so the whole set is deleted cleanly. Asserts
    both the framed member count (STAB-3) and full cross-tier deletion (PERF)."""
    # ⚠ The tag SADD is fire-and-forget, so the PRECEDING test's trailing
    # /l2t/p1 + /l2t/p2 cold misses (test_l2_tag_purge) can still have their
    # re-tagging SADDs in flight when we get here. DELeting once races them: a
    # straggler lands after the DEL and this test counts 351 instead of 350.
    # Drain to a stable empty state first -- DEL, then confirm it STAYS empty
    # across a settle window -- so the count below is only our own members.
    def _drained() -> bool:
        # Re-DEL each poll so a straggler that lands between our DEL and our
        # read is absorbed rather than merely detected, then require the set to
        # STAY empty across a settle window before we trust it.
        redis.cli("DEL", tag_key("blog"), tag_key("news"))
        time.sleep(0.25)
        return redis.cli("SCARD", tag_key("news")) == "0"

    assert wait_for(_drained, timeout=10.0), \
        (f"tag set 'news' never drained before priming; a previous test's "
         f"fire-and-forget SADD is still landing after 10s "
         f"(SCARD={redis.cli('SCARD', tag_key('news'))})")

    n = 350                                        # ~25 KiB SMEMBERS reply
    for i in range(n):
        s, _, _ = fetch(ng.port, f"/l2t/big-{i}")  # miss -> store + tag
        assert s == 200, f"prime /l2t/big-{i} status {s}"
    assert wait_for(lambda: redis.cli("SCARD", tag_key("news")) == str(n),
                    timeout=10.0), \
        f"expected {n} members in 'news', got {redis.cli('SCARD', tag_key('news'))}"

    s, b, _ = fetch(ng.port, "/_cache_l2?tag=news", method="POST")
    assert s == 200, f"large tag purge status {s}"
    # STAB-3: the whole multi-recv SMEMBERS array was framed + parsed once.
    assert json.loads(b)["purged"] == n, f"expected {n} purged, got {b}"
    # PERF-1/2: the pipelined UNLINK dropped every member + the tag set itself.
    assert wait_for(lambda: redis.cli("EXISTS", tag_key("news")) == "0",
                    timeout=10.0), "emptied tag set survived the large purge"
    assert wait_for(lambda: redis.cli("EXISTS", l2_key("/l2t/big-0")) == "0"
                    and redis.cli("EXISTS", l2_key(f"/l2t/big-{n-1}")) == "0",
                    timeout=10.0), "purged members survived in L2"


def test_l2_tag_cap_and_dedup(ng: Nginx, origin: Origin,
                              redis: RedisServer) -> None:
    """PERF-2: the upstream-controlled cache_turbo_tag value is bounded. A
    request naming more than MAX_TAGS (16) distinct tags indexes only the first
    16; duplicate tags in one value are SADD'd once (idempotent + no extra
    connection). Guards against a hostile origin fanning out unbounded SADDs."""
    obj = l2_key("/l2tcap/x")
    # 30 distinct tags -> only the first 16 should index the object.
    tags = ",".join(f"cap{i}" for i in range(30))
    for i in range(30):
        redis.cli("DEL", tag_key(f"cap{i}"))
    s, _, _ = fetch(ng.port, f"/l2tcap/x?t={tags}")
    assert s == 200, f"cap prime status {s}"
    assert wait_for(lambda: redis.cli("SISMEMBER", tag_key("cap0"), obj) == "1"), \
        "first tag was not indexed"
    indexed = sum(1 for i in range(30)
                  if redis.cli("SISMEMBER", tag_key(f"cap{i}"), obj) == "1")
    assert indexed == 16, f"expected exactly 16 tags indexed (cap), got {indexed}"

    # dedup: the same tag repeated still yields one membership.
    obj2 = l2_key("/l2tcap/y")
    redis.cli("DEL", tag_key("dup"))
    s, _, _ = fetch(ng.port, "/l2tcap/y?t=dup,dup,dup,dup")
    assert s == 200
    assert wait_for(lambda: redis.cli("SISMEMBER", tag_key("dup"), obj2) == "1"), \
        "deduped tag was not indexed"
    assert redis.cli("SCARD", tag_key("dup")) == "1", \
        "duplicate tag produced more than one membership"


def test_l2_tag_purge_arg_validation(ng: Nginx, origin: Origin,
                                     redis: RedisServer) -> None:
    """AUD-TAG1: the ?tag= purge argument is taken raw from ngx_http_arg with
    no length/charset check of its own, unlike cache_turbo_tag's own tokeniser
    (test_l2_tag_cap_and_dedup et al) which caps each tag at MAX_TAG_LEN (128)
    and splits on space/tab/comma/CR/LF. The purge arg must mirror those SAME
    rules so a purge request can never even ask about a byte string the
    tokeniser could not have produced as a tag.

    ngx_http_arg does not URL-decode, and a literal space/tab/CR/LF in the
    request-target is invalid HTTP grammar -- nginx's own core parser 400s the
    request before it ever reaches our handler (verified: a raw socket sending
    '?tag=news<TAB>blog' gets nginx's stock text/html 400 page, not our JSON
    error body). So those bytes can never actually reach ngx_http_arg; the
    check against them is defense-in-depth against a DISTANT parser rather
    than something a live request can exercise, exactly like the ledger's
    note on the plain space case. Comma is the one separator byte that IS
    valid in a request-target and reaches ngx_http_arg intact, so it is what
    proves the charset check fires for real; length is proven directly since
    an over-long ASCII tag is ordinary, well-formed HTTP. Rejections take the
    existing bad-input shape for this handler: 400 with a JSON {"error": ...}
    body (see the sibling 'requires cache_turbo_redis' 400 a few lines above
    the validation)."""
    # over-length: 129 bytes, one past MAX_TAG_LEN (128).
    s, b, _ = fetch(ng.port, f"/_cache_l2?tag={'a' * 129}", method="POST")
    assert s == 400, f"129-byte tag should be rejected, got {s}: {b}"
    assert "invalid tag" in json.loads(b)["error"], \
        f"expected an 'invalid tag' error for an over-length tag, got {b}"

    # exactly at the cap (128 bytes) must NOT be rejected by the length check
    # -- proves the check is > not >=. (Backend absent path already covered by
    # the 'requires cache_turbo_redis' test elsewhere; this only needs to get
    # past the length gate, so any redis-backed status other than the
    # over-length 400 proves it.)
    s, b, _ = fetch(ng.port, f"/_cache_l2?tag={'b' * 128}", method="POST")
    assert s == 200, f"exactly-128-byte tag should pass validation, got {s}: {b}"

    # comma: a real, unencoded query byte that reaches ngx_http_arg intact.
    s, b, _ = fetch(ng.port, "/_cache_l2?tag=news,blog", method="POST")
    assert s == 400, f"comma in tag should be rejected, got {s}: {b}"
    assert "invalid tag" in json.loads(b)["error"], \
        f"expected an 'invalid tag' error for a comma-bearing tag, got {b}"

    # Positive control: an ordinary legitimate tag purges exactly as before --
    # proves the new check does not over-reject real traffic. /l2tcap/ takes
    # its tag from $arg_t so a custom tag name can be primed here.
    redis.cli("DEL", tag_key("valtest"))
    path = "/l2tcap/valtest-obj"
    fetch(ng.port, f"{path}?t=valtest")               # miss -> origin -> store+tag
    obj = l2_key(path)
    assert wait_for(lambda: redis.cli("SISMEMBER", tag_key("valtest"),
                                       obj) == "1"), \
        "object never joined tag set 'valtest'"
    s, b, _ = fetch(ng.port, "/_cache_l2?tag=valtest", method="POST")
    assert s == 200, f"legitimate tag purge should succeed, got {s}: {b}"
    assert json.loads(b)["purged"] == 1, f"expected 1 purged, got {b}"
    assert wait_for(lambda: redis.cli("EXISTS", tag_key("valtest")) == "0"), \
        "legitimate tag purge should still remove the tag set"


def test_l2_tag_add_batched_one_op(ng: Nginx, origin: Origin,
                                   redis: RedisServer) -> None:
    """L9: a store naming N tags indexes them in ONE pipelined Redis op, not N.

    /l2tcap/ carries no keepalive=, so every op dials a fresh socket and Redis'
    total_connections_received tracks the op count directly. A 12-tag store
    costs 1 SET + 1 batched tag op; before L9 it cost 1 SET + 12 tag ops, so
    the pre-L9 tree fails this by roughly an order of magnitude.

    Membership is asserted too: batching must not lose a tag (the existing
    cap/dedup tests would pass either way, since they only check membership)."""
    ntags = 12
    stamp = time.time()
    uri = f"/l2tcap/batch-{stamp}"
    obj = l2_key(uri)
    tags = [f"b{stamp}-{i}" for i in range(ntags)]
    for t in tags:
        redis.cli("DEL", tag_key(t))

    # NOTE: redis.cli() shells out to redis-cli and opens its OWN connection
    # per call, so NOTHING may touch redis between the two _redis_conns_received
    # readings -- a SISMEMBER poll inside the window counts as module traffic
    # and inflates the result. Measure the fetch alone; verify membership after.
    before = _redis_conns_received(redis)
    s, _, _ = fetch(ng.port, f"{uri}?t={','.join(tags)}")
    assert s == 200, f"batch prime status {s}"
    time.sleep(0.6)          # let the fire-and-forget ops settle
    conns = _redis_conns_received(redis) - before

    # every tag must still be indexed -- batching must not drop one
    assert wait_for(lambda: all(
        redis.cli("SISMEMBER", tag_key(t), obj) == "1" for t in tags)), \
        "batched tag_add did not index every tag"

    # 1 GET (miss) + 1 SET (write-through) + 1 batched tag op = ~3. Allow slack
    # for retries/probes but stay far below the pre-L9 1 + 1 + ntags.
    assert conns < ntags, \
        f"tag_add was not batched: {conns} connections for {ntags} tags " \
        f"(pre-L9 cost ~{ntags + 2}; batched should be ~3)"


def _spawn_node(ng: Nginx, name: str, port_offset: int) -> Nginx:
    """Start a second, independent nginx (own root, same Redis + origin) so a
    cross-node test can observe two cache instances sharing one L2."""
    b = Nginx(ng.binary, ng.module, ng.root.parent / name,
              ng.port + port_offset, ng.origin_port, ng.runner_raw,
              ng.single_process, ng.redis_port)
    b.write_config()
    b.config_test()
    b.start()
    return b


def test_multinode_lock(ng: Nginx, origin: Origin, redis: RedisServer) -> None:
    """v4-2: two nginx nodes sharing one Redis collapse a stale-key refresh to a
    SINGLE origin regen via the cross-node SET NX PX lock. Without the lock both
    nodes' dice would each reach origin (== 2)."""
    uri = "/lock/mn"
    redis.cli("DEL", l2_key(uri), lock_key(uri))

    # Node A primes the key: origin -> L1_A + L2 fresh.
    sa, body_a, ha = fetch(ng.port, uri)
    assert sa == 200 and "x-cache" not in ha, "A should miss to origin first"
    assert wait_for(lambda: redis.cli("EXISTS", l2_key(uri)) == "1"), \
        "A never wrote the object to L2"

    b = _spawn_node(ng, "server-mn", 6)
    try:
        # Node B fills its L1 from the shared L2 (HIT, no origin) -> both hold it.
        sb, body_b, hb = fetch(b.port, uri)
        assert sb == 200 and body_b == body_a, "B should L2-fill A's body"
        assert hb.get("x-cache") == "HIT", \
            f"B fill X-Cache={hb.get('x-cache')} (expected an L2-fill HIT)"

        # Wait until the entry is stale on BOTH nodes. Each node's L1 is fresh
        # for valid=2s from its own store; B stored its copy last (~now), so a
        # 2.5s sleep puts both past fresh yet well inside the 8s stale window.
        time.sleep(2.5)                            # stale on both, still < 8s
        drain_origin(origin)       # absorb any stray async bg before counting
        base = origin.hits

        # Hammer both nodes through the stale window. The dice fires a refresh on
        # at least one; the NX lock lets exactly one node reach origin.
        deadline = time.time() + 1.5
        while time.time() < deadline:
            fetch(ng.port, uri)
            fetch(b.port, uri)
            time.sleep(0.05)
        time.sleep(0.4)                            # let any in-flight regen land

        regens = origin.hits - base
        assert regens == 1, \
            f"cross-node single-flight failed: {regens} origin regens (want 1)"

        time.sleep(0.2)
        b.stop()
        b.assert_clean_logs()
    finally:
        b.stop()
        drain_origin(origin)   # v8: settle async bg refreshes before next test


def test_lock_self_heal(ng: Nginx, origin: Origin, redis: RedisServer) -> None:
    """v4-2: a held cross-node lock (a peer mid-regen) makes other nodes serve
    stale without piling on origin; once the lock PX-expires (the peer 'died'
    before storing) a node re-acquires it and regenerates EXACTLY once. Uses the
    short-lock_ttl /lockh/ location so the node's own per-box L1 refresh lock
    (also lock_ttl) clears in step with the cross-node lock.

    NB: losing the NX still arms this node's local refresh_lock_until for
    lock_ttl, so the self-heal cannot fire until BOTH the peer's PX and this
    node's local lock have expired — the foreign PX is set a touch longer than
    lock_ttl so it is the gating one."""
    uri = "/lockh/heal"
    redis.cli("DEL", l2_key(uri), lock_key(uri))

    s, _body_a, h = fetch(ng.port, uri)             # prime -> origin -> L1 + L2
    assert s == 200 and "x-cache" not in h, "prime should miss to origin"
    assert wait_for(lambda: redis.cli("EXISTS", l2_key(uri)) == "1"), \
        "prime never wrote L2"

    time.sleep(2.4)                                # now stale (fresh=2s)

    # A peer node 'holds' the regen lock (set now that the key is stale, PX 2500
    # > lock_ttl 2000), then crashes — the lock is freed only by PX expiry.
    redis.cli("SET", lock_key(uri), "peer-node", "PX", "2500")
    drain_origin(origin)           # absorb any stray async bg before counting
    base = origin.hits

    # Phase 1 — lock held by the peer: refresh attempts lose the NX, so reads
    # serve stale and origin is NOT hit. Short, well inside the 2.5s PX.
    for _ in range(6):
        s, _, _ = fetch(ng.port, uri)
        assert s == 200, f"stale read status {s}"
        time.sleep(0.05)
    assert origin.hits == base, \
        f"origin was hit while the lock was held by a peer ({origin.hits - base})"

    # Phase 2 — let the peer's lock PX-expire (and with it, past this node's own
    # 2s local lock), then read: a node self-heals by acquiring the freed NX and
    # regenerating exactly once. Still inside the 8s stale window.
    assert wait_for(lambda: redis.cli("EXISTS", lock_key(uri)) == "0",
                    timeout=4.0), "foreign lock never PX-expired"
    deadline = time.time() + 1.5
    heal_before = origin.hits_for("heal")
    while time.time() < deadline and origin.hits_for("heal") == heal_before:
        fetch(ng.port, uri)
        time.sleep(0.05)
    time.sleep(0.4)

    regens = origin.hits_for("heal") - heal_before
    if regens != 1:
        recent = [(round(t, 2), p) for t, p in origin._paths[-15:]]
        raise AssertionError(
            f"self-heal: want exactly 1 regen after lock expiry, got {regens}; "
            f"recent origin paths: {recent}")
    drain_origin(origin)       # v8: settle async bg refreshes before the next test


def test_lock_redis_outage_fallback(ng: Nginx, origin: Origin,
                                    redis: RedisServer) -> None:
    """Deferred enhancement: deterministic mid-flight Redis outage coverage for
    the lock NGX_ERROR fallback (ngx_http_cache_turbo_module.c ~3166-3206). When
    the cross-node SET NX PX lock channel itself fails (Redis down, not merely
    "peer holds the lock" == NGX_DECLINED), the module must NOT treat that the
    same as a peer holding the lock (which would serve stale forever with no
    regen) — it degrades to per-box single-flight and regenerates locally, since
    `ctx->lock_result == NGX_OK || ctx->lock_result == NGX_ERROR` both fall into
    the "we own the regen" branch, only NGX_DECLINED (genuine peer-holds) serves
    stale without regenerating.

    This is a REAL, distinct branch from test_lock_self_heal (which exercises a
    PEER holding a live lock that later PX-expires — NGX_DECLINED then NGX_OK).
    Here the lock channel never even completes: Redis is stopped between the
    prime and the stale read, so the NX attempt itself gets ECONNREFUSED
    (immediate, deterministic — no timeout hang, since this is a plain TCP
    connect failure, not a slow-loris). Uses /lock/ (cache_turbo_lock off
    isolates the stale-path NX under test, same as test_multinode_lock).

    Readers are BARRIER-SYNCHRONISED and concurrent, which is what makes the
    single-flight claim provable. A sequential hammer loop could not: each fetch
    completes before the next begins, so even a COLLAPSED single-flight yields
    one regen — the first reader's refresh fills L1, and every later read is a
    plain fresh hit that never reaches the dice. Such a test passes with the
    mechanism it claims to test removed. Only readers that are all inside the
    SAME regeneration window (origin delay = 50ms) can distinguish "one reader
    regenerates and the rest ride the claim" from "each reader regenerates".

    Latency is asserted PER REQUEST, not aggregated over the loop: an aggregate
    bound hides one multi-second stall inside a budget sized for the whole burst,
    and a stall is exactly what the NGX_ERROR path would produce if it waited on
    the dead lock channel instead of failing fast.

    Two harness constraints that are easy to get wrong (both cost a debug round):

    1. `slug`, not `uri`, is what the origin counter matches. proxy_pass strips
       the /lock/ prefix, so the origin logs "/<slug>" -- `hits_for(uri)` would
       match NOTHING and read 0 regens forever, which is indistinguishable from
       the canary's genuine failure signature. Scope on the slug, which is unique
       per run (so the count is immune to another test's async bg traffic, per
       the drain_origin boundary lesson) AND is what actually lands in the log.
    2. The refresh dice is driven by ngx_time(), which has ONE-SECOND
       granularity (swr.c: `elapsed = now - fresh_until`, threshold =
       elapsed/window * beta). At elapsed == 0 the threshold is 0 and the dice
       CANNOT fire, whatever beta is. sleep(2.4) puts the first read ~0.4s past
       fresh_until, i.e. still elapsed == 0 for up to ~0.6s more; the barrier
       burst then rides the wait_for below rather than assuming an instant regen.
       Do not "optimise" the wait_for into a fixed short sleep -- a burst that
       lands entirely inside elapsed == 0 legitimately produces zero regens until
       the clock ticks."""
    slug = f"redis-outage-{time.time_ns()}"
    uri = f"/lock/{slug}"
    redis.cli("DEL", l2_key(uri), lock_key(uri))

    s, _body_a, h = fetch(ng.port, uri)             # prime -> origin -> L1 + L2
    assert s == 200 and "x-cache" not in h, "prime should miss to origin"
    assert wait_for(lambda: redis.cli("EXISTS", l2_key(uri)) == "1"), \
        "prime never wrote L2"

    time.sleep(2.4)                                # now stale (fresh=2s)

    # Simulate the outage: Redis goes away mid-flight, AFTER the prime succeeded
    # and BEFORE any refresh's lock NX is attempted. Every subsequent lock
    # attempt on this key fails at connect(), i.e. NGX_ERROR, never NGX_DECLINED.
    redis.stop()
    try:
        drain_origin(origin)           # absorb any stray async bg before counting
        base = origin.hits_for(slug)

        # All readers rendezvous at the barrier, then hit the stale key at once.
        # beta=5000 makes the dice fire on the first of them; the rest arrive
        # while that regen is still in flight (origin delay 50ms), so they can
        # only be absorbed by the single-flight claim -- not by an already-filled
        # L1. Losing Redis for the lock must not (a) hang a request, (b) serve
        # stale forever with zero regen, or (c) regen once per reader (that would
        # mean single-flight collapsed entirely, not "degraded to per-box").
        readers = 24
        barrier = threading.Barrier(readers)

        def _reader(_i: int) -> tuple[int, float]:
            barrier.wait()
            t = time.monotonic()
            st, _, _ = fetch(ng.port, uri)
            return st, time.monotonic() - t

        with concurrent.futures.ThreadPoolExecutor(max_workers=readers) as pool:
            results = list(pool.map(_reader, range(readers)))

        bad = [st for st, _ in results if st != 200]
        assert not bad, f"stale reads during redis outage returned {set(bad)}"

        # PER-REQUEST latency: no single reader may park on the dead lock
        # channel. The NGX_ERROR path is a connect() refusal (immediate), and a
        # loser rides the local claim and is served stale at once -- neither
        # waits on Redis. The real failure mode this guards is a lock_timeout
        # park (~5s, the V-HANG class), so the bound is generous enough to
        # survive valgrind/slow-CI scheduling while still catching that stall.
        worst = max(d for _, d in results)
        assert worst < 3.0, \
            f"a stale read during the redis outage stalled {worst:.1f}s -- the " \
            f"NGX_ERROR lock path parked instead of failing fast " \
            f"(latencies: {sorted(round(d, 2) for _, d in results)})"

        # 5s literal, NOT HTTP_TIMEOUT. This is a semantic deadline -- "the
        # NGX_ERROR fallback regenerated at all" -- not a socket read ceiling,
        # and the two only ever coincided numerically. Borrowing the client
        # timeout meant any future widening of it would silently grant a broken
        # fallback path more time to look correct.
        assert wait_for(
            lambda: origin.hits_for(slug) > base, timeout=5.0), \
            "lock NGX_ERROR fallback failed: 0 origin regens during a redis " \
            "outage -- the NGX_ERROR lock channel was treated like a peer " \
            "holding the lock (NGX_DECLINED), so the key is stuck stale forever"
        drain_origin(origin)           # let every in-flight regen land + settle

        regens = origin.hits_for(slug) - base
        # Path-scoped (hits_for), so another test's async bg traffic cannot
        # inflate this. Upper bound allows the multi-worker debug build: the
        # claim is per-WORKER shm state, so up to one regen per worker can race
        # in before the claim is visible -- but 24 readers collapsing to a small
        # constant is still categorically "single-flight held", whereas a
        # collapse reads ~24.
        assert regens <= 4, \
            f"lock NGX_ERROR fallback failed: {regens} origin regens from " \
            f"{readers} concurrent stale readers during a redis outage (want a " \
            f"small constant -- per-box single-flight degrade; ~{readers} means " \
            f"single-flight collapsed entirely)"
    finally:
        redis.start()                  # restore for cleanup / assert_clean_logs
        drain_origin(origin)


def test_cold_single_flight_cross_node(ng: Nginx, origin: Origin,
                                       redis: RedisServer) -> None:
    """v10 cross-node: two nodes sharing one Redis collapse a CONCURRENT cold
    burst to ~1 origin fetch. The node that wins the SET NX PX regenerates and
    write-throughs to L2; the other node's local winner loses the NX and waits
    for that L2 fill instead of going to origin too."""
    uri = "/coldl2/sf"
    redis.cli("DEL", l2_key(uri), lock_key(uri))

    b = _spawn_node(ng, "server-cold", 7)
    try:
        base = origin.hits
        ports = [ng.port, b.port]
        # 40 concurrent first-hits split across both cold nodes.
        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
            results = list(pool.map(
                lambda i: fetch(ports[i % 2], uri), range(40)))
        assert {r[0] for r in results} == {200}, \
            f"cross-node cold burst returned {set(r[0] for r in results)}"
        bodies = {r[1] for r in results}
        assert len(bodies) == 1, \
            f"cross-node cold burst served {len(bodies)} distinct bodies"
        time.sleep(0.4)                            # let any in-flight regen land
        regens = origin.hits - base
        # One node regenerates; the other L2-fills. Allow a little slack for the
        # NX-resolution window across two event loops.
        assert regens <= 3, \
            f"cross-node cold single-flight failed: {regens} origin fetches"
        time.sleep(0.2)
        b.stop()
        b.assert_clean_logs()
    finally:
        b.stop()
        drain_origin(origin)


def test_purge_all_clears_l2(ng: Nginx, origin: Origin,
                             redis: RedisServer) -> None:
    """v4-2: POST ?all=1 on an L2-aware admin endpoint clears the whole L2
    keyspace (SCAN MATCH <prefix>* + DEL), so a purged object cannot be refilled
    from Redis on the next miss. Pre-v4-2 ?all=1 emptied L1 only."""
    uri = "/l2/purgeall"
    redis.cli("DEL", l2_key(uri))

    s, body_a, h = fetch(ng.port, uri)             # miss -> origin -> L1 + L2
    assert s == 200 and "x-cache" not in h, "prime should miss to origin"
    assert wait_for(lambda: redis.cli("EXISTS", l2_key(uri)) == "1"), \
        "write-through never reached L2"
    _, _, h2 = fetch(ng.port, uri)
    assert h2.get("x-cache") == "HIT", "should be an L1 hit before purge"

    # all-purge via the L2-aware admin endpoint
    s, b, _ = fetch(ng.port, "/_cache_l2?all=1", method="POST")
    assert s == 200 and "purged" in json.loads(b), f"all-purge result: {s} {b}"

    # the L2 entry must actually be gone (SCAN+DEL fired, fire-and-forget)
    assert wait_for(lambda: redis.cli("EXISTS", l2_key(uri)) == "0"), \
        "?all=1 did not clear the entry from L2 (v4-2 regression)"

    # next read is a true miss to a NEW origin generation, not an L2 refill
    origin_before = origin.hits_for("purgeall")
    s, body_b, h3 = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in h3, \
        f"post-all-purge read should miss to origin, got {h3.get('x-cache')}"
    assert origin.hits_for("purgeall") == origin_before + 1, \
        "origin was not consulted after all-purge (L2 still served)"
    assert body_b != body_a, "post-purge body should be a fresh generation"


def test_purge_all_escapes_redis_prefix_glob(ng: Nginx,
                                             redis: RedisServer) -> None:
    """SCAN MATCH must treat glob metacharacters in the configured prefix
    literally. Purging prefix 'ct*:' deletes 'ct*:owned' but not 'ctX:foreign'."""
    owned = f"ct*:owned:{time.time_ns()}"
    foreign = owned.replace("ct*:", "ctX:", 1)
    redis.cli("-n", "0", "SET", owned, "owned")
    redis.cli("-n", "0", "SET", foreign, "foreign")

    s, b, _ = fetch(ng.port, "/_cache_l2glob?all=1", method="POST")
    assert s == 200 and "purged" in json.loads(b), \
        f"glob-prefix all-purge failed: {s} {b}"

    # !! The 200 does NOT mean the keys are gone yet. The SCAN loop hands each
    # page to redis_del_many(), which opens its OWN connection and pipelines
    # UNLINKs fire-and-forget (redis.c: launch(..., read_drain)); the SCAN loop
    # never waits for those replies, and smembers_finish() emits this response
    # as soon as the CURSOR completes. So an UNLINK can still be in flight here.
    # Asserting EXISTS immediately is a race that only loses on a slow build --
    # which is why it went red under ASan (instrumented nginx is ~10-20x slower)
    # while passing every plain run. Poll for absence instead of sampling once.
    assert wait_for(lambda: redis.cli("-n", "0", "EXISTS", owned) == "0",
                    timeout=10.0), \
        "literal glob-prefix key was not purged (waited 10s after the 200)"

    # !! `owned` disappearing does NOT mean the purge has finished. del_many()
    # runs ONCE PER SCAN PAGE (redis.c:2584), each opening its own connection,
    # and there is no completion ordering between them. With the escaping defect
    # restored, `ct*:*` can put `owned` and `foreign` on DIFFERENT pages -- so a
    # single EXISTS sample here can observe foreign==1 simply because the page
    # that would delete it has an UNLINK still in flight, and the cleanup DEL
    # below then erases the evidence. That is a green run with the regression
    # present, which is the exact failure mode this whole PR exists to remove.
    #
    # So assert the forbidden transition NEVER happens across a drain window
    # wider than the 250ms redis op timeout, rather than sampling once.
    assert not wait_for(lambda: redis.cli("-n", "0", "EXISTS", foreign) == "0",
                        timeout=1.5), \
        "glob prefix widened SCAN and deleted an unrelated key"
    redis.cli("-n", "0", "DEL", foreign)


def _scan_fill(redis: RedisServer, n: int, tag: str) -> None:
    """Pipeline n `ctscan:` keys onto one socket. One redis-cli per key would
    be ~n process spawns; the SCAN-walk tests need thousands of keys, so the
    SETs go out as a single RESP pipeline and only the reply count is checked."""
    with socket.create_connection(("127.0.0.1", redis.port), 5) as s:
        s.settimeout(20)
        # The scan endpoints are configured with db=7; this raw socket starts on
        # db 0, so it must SELECT the same db or the walk sees nothing.
        s.sendall(b"*2\r\n$6\r\nSELECT\r\n$1\r\n7\r\n")
        if not s.recv(4096).startswith(b"+OK"):
            raise RuntimeError("redis SELECT 7 failed")
        # Chunked, and each chunk's replies are drained before the next is sent:
        # one giant sendall() can deadlock against a peer that stops reading
        # once ITS output buffer to us is full.
        for base in range(0, n, 500):
            batch = range(base, min(base + 500, n))
            cmd = bytearray()
            for i in batch:
                args = (b"SET", f"ctscan:{tag}:{i}".encode(), b"v",
                        b"EX", b"300")
                cmd += b"*%d\r\n" % len(args)
                for a in args:
                    cmd += b"$%d\r\n%s\r\n" % (len(a), a)
            s.sendall(cmd)
            buf = b""
            while buf.count(b"\r\n") < len(batch):
                chunk = s.recv(65536)
                if not chunk:
                    raise RuntimeError("redis closed mid-pipeline")
                buf += chunk


def _scan_purge(ng: Nginx, loc: str) -> tuple[int, dict]:
    """POST an ?all=1 all-purge at `loc` and return (status, parsed JSON)."""
    s, b, _ = fetch(ng.port, f"{loc}?all=1", method="POST")
    return s, json.loads(b)


def test_scan_walk_pool_is_o1_in_pages(ng: Nginx, redis: RedisServer) -> None:
    """AUD-SCAN1 (a): the SCAN-based L2 all-purge must hold a CONSTANT amount of
    memory regardless of how many SCAN pages the walk takes.

    read_scan drove the whole cursor loop off ONE op pool: every page allocated
    a fresh keys array, a rebuilt SCAN command and (on a big reply) a doubled
    receive buffer out of it, and `op->rlen = 0` reset only the LENGTH -- nothing
    was released until the walk ended. A large keyspace therefore grew the worker
    monotonically for the whole purge.

    The oracle is `scan_pool_blocks` (TEST_FAULTS-only): the live pool blocks the
    walk still holds when it finishes. Two purges of the SAME keyspace shape, one
    short walk and one an order of magnitude longer, must report the same figure.
    Asserting an absolute number would be brittle across pool tunings and
    NGX_DEBUG_PALLOC builds; asserting that it does not TRACK page count is the
    actual property, and it is the one that fails when the per-page pool is
    removed (blocks then rise by at least one large block per page).

    No test drove a multi-page SCAN walk at all before this one -- the archived
    purge tests all fit inside a single COUNT 256 page."""
    # FLUSHDB, not a KEYS/DEL sweep: deleting keys leaves the db's hash table
    # sized for the biggest fill it ever held, and SCAN COUNT walks BUCKETS, so
    # a stale oversized table makes a 5-key walk span many pages.
    redis.cli("-n", "7", "FLUSHDB")

    _scan_fill(redis, 300, "small")
    s, small = _scan_purge(ng, "/_cache_scanwalk")
    assert s == 200, f"short walk should complete: {s} {small}"
    assert "l2" not in small, f"short walk reported incomplete: {small}"

    _scan_fill(redis, 6000, "big")
    s, big = _scan_purge(ng, "/_cache_scanwalk")
    assert s == 200, f"long walk should complete: {s} {big}"
    assert "l2" not in big, f"long walk reported incomplete: {big}"

    # The comparison is only meaningful if the two walks really differ in
    # length. Without this the blocks assertion is vacuous: two one-page walks
    # hold the same memory whether or not the pool is rotated.
    assert big["scan_pages"] >= small["scan_pages"] + 8, \
        f"the two walks were not different lengths: {small} vs {big}"

    # +2 of slack, not 0: the reply buffer is only re-grown on a page whose
    # reply exceeds 4 pagesize, so the two walks can legitimately differ by a
    # block or two. Pre-fix the gap is >= one block PER EXTRA PAGE.
    assert big["scan_pool_blocks"] <= small["scan_pool_blocks"] + 2, \
        ("AUD-SCAN1: walk memory tracks page count -- "
         f"{small['scan_pages']} pages held {small['scan_pool_blocks']} blocks, "
         f"{big['scan_pages']} pages held {big['scan_pool_blocks']}")


def test_all_purge_reports_l2_unavailable_when_backend_is_down(
        ng: Nginx, redis: RedisServer) -> None:
    """AUD-PURGE-HONESTY1: an all-purge whose L2 walk never STARTS must not
    answer a bare success.

    scan_del returning NGX_ERROR (connect refused, L2 never reached) used to
    fall through to the synchronous 200 {"purged":<L1 count>} -- on the wire
    that is indistinguishable from a purge that emptied both tiers. An operator
    purging before a config rollout reads 200 and believes L2 is empty; it is
    entirely intact. Same dishonesty class as AUD-SCAN1, which #174 fixed for
    the walk that STARTS and ends early. Contract chosen 2026-08-01: 500 plus an
    explicit "l2":"unavailable" -- non-2xx like the incomplete walk, a distinct
    value because nothing was walked at all.

    Two claims, and the first keeps the second from being vacuous:

      1. NEGATIVE CONTROL -- the SAME request shape against a LIVE L2
         (/_cache_scanwalk) answers 200 with no "l2" key. An endpoint that
         reported unavailable unconditionally would satisfy claim 2 while
         breaking every healthy purge.
      2. Against the dead backend the reply is 500 AND carries
         "l2":"unavailable". Asserting only "not 200" would pass on any
         unrelated error path (a 404 from a misspelled location, a 400 from a
         rejected arg), so both status and field are pinned.

    "purged" must still be present and numeric in the failure body: L1 really
    was purged, and dropping the count would understate what happened."""
    # 1. control: identical request shape, live backend
    redis.cli("-n", "7", "FLUSHDB")
    _scan_fill(redis, 5, "down-ctrl")
    s_ok, ok = _scan_purge(ng, "/_cache_scanwalk")
    assert s_ok == 200, f"control purge against a LIVE L2 failed: {s_ok} {ok}"
    assert "l2" not in ok, f"control purge reported an L2 problem: {ok}"
    redis.cli("-n", "7", "FLUSHDB")

    # 2. the claim: L2 down, nothing walked
    s, down = _scan_purge(ng, "/_cache_scandown")
    assert s == 500, \
        f"purge with L2 down must not report success: {s} {down}"
    assert down.get("l2") == "unavailable", \
        f"purge with L2 down did not disclose the L2 state: {down}"
    # "unavailable" must mean literally nothing was walked -- if a page had been
    # consumed, part of L2 WOULD be purged and "incomplete" is the honest word.
    assert down.get("scan_pages") == 0, \
        f"reported unavailable after walking pages: {down}"
    assert isinstance(down.get("purged"), int), \
        f"failure body dropped the L1 purge count: {down}"


def test_scan_walk_page_cap_reports_incomplete(ng: Nginx,
                                               redis: RedisServer) -> None:
    """AUD-SCAN1 (b): read_scan used to terminate ONLY on cursor "0". A backend
    that never returns it (broken, hostile, or simply a keyspace larger than the
    walk can finish) looped forever -- the per-page read timeout does not bound
    the walk, because each page's write re-arms the timer.

    The walk is now capped. Two claims, and the first is what keeps the second
    from being vacuous:

      1. NEGATIVE CONTROL -- a keyspace that fits inside the cap completes
         normally at the SAME endpoint (200, no "l2" key). A cap that fired on
         every purge would satisfy claim 2 while destroying the feature.
      2. Past the cap the request FINALIZES (no hang) and reports the purge as
         INCOMPLETE with a non-2xx status -- never as a success. Silently
         truncating and answering 200 would trade the memory bug for a
         correctness bug: the operator is told L2 is empty when it is not."""
    # FLUSHDB, not a KEYS/DEL sweep: deleting keys leaves the db's hash table
    # sized for the biggest fill it ever held, and SCAN COUNT walks BUCKETS, so
    # a stale oversized table makes a 5-key walk span many pages.
    redis.cli("-n", "7", "FLUSHDB")

    # 1. under the cap -> ordinary completion
    _scan_fill(redis, 5, "cap-ok")
    s, ok = _scan_purge(ng, "/_cache_scancap")
    assert s == 200, f"a walk inside the cap must complete: {s} {ok}"
    assert "l2" not in ok, f"cap fired on a one-page walk: {ok}"

    # 2. past the cap -> abandoned, reported INCOMPLETE
    _scan_fill(redis, 6000, "cap-over")
    s, over = _scan_purge(ng, "/_cache_scancap")
    assert s == 500, f"an abandoned purge must not report success: {s} {over}"
    assert over.get("l2") == "incomplete" and over.get("reason") == "page-cap", \
        f"abandoned purge did not report the page cap: {over}"
    assert over["scan_pages"] == 2, \
        f"walk did not stop AT the cap (2 pages): {over}"

    # The abandoned walk must have left L2 partially populated -- that is the
    # state the INCOMPLETE report exists to disclose. If everything were gone,
    # the report would be describing a purge that actually finished.
    assert int(redis.cli("-n", "7", "EVAL",
                         "return #redis.call('KEYS','ctscan:*')",
                         "0") or 0) > 0, \
        "cap-abandoned purge somehow emptied the keyspace"

    redis.cli("-n", "7", "FLUSHDB")


def test_normalize_arg_order(ng: Nginx, origin: Origin) -> None:
    """v3-1: ?b=2&a=1 and ?a=1&b=2 normalize to one cache slot — the reordered
    second request is a HIT serving the first body, origin hit exactly once."""
    base = origin.hits_for("/order")
    s1, b1, h1 = fetch(ng.port, "/n/order?b=2&a=1")
    assert s1 == 200 and "x-cache" not in h1, "first request should miss to origin"
    _s2, b2, h2 = fetch(ng.port, "/n/order?a=1&b=2")
    assert h2.get("x-cache") == "HIT", \
        f"reordered args should HIT, got X-Cache={h2.get('x-cache')}"
    assert b2 == b1, "reordered request served a different body"
    assert origin.hits_for("/order") == base + 1, \
        f"origin hit {origin.hits_for('/order') - base} times (args not normalized to one key)"


def test_normalize_strips_tracking(ng: Nginx, origin: Origin) -> None:
    """Built-in denylist: utm_* and fbclid are dropped, so ?p=1&utm_source=x&
    fbclid=y collapses onto the same slot as a bare ?p=1."""
    base = origin.hits_for("/track")
    _, b1, h1 = fetch(ng.port, "/n/track?p=1")
    assert "x-cache" not in h1, "prime should miss to origin"
    _, b2, h2 = fetch(ng.port, "/n/track?p=1&utm_source=news&utm_medium=cpc&fbclid=z")
    assert h2.get("x-cache") == "HIT", \
        f"tracking-only diff should HIT, got X-Cache={h2.get('x-cache')}"
    assert b2 == b1, "tracking-laden request served a different body"
    assert origin.hits_for("/track") == base + 1, "tracking params were not stripped from the key"


def test_normalize_strip_custom(ng: Nginx, origin: Origin) -> None:
    """cache_turbo_normalize_strip adds exact ("sid") and prefix ("tmp_*")
    patterns on top of the defaults; a request differing only in those HITs."""
    base = origin.hits
    _, b1, h1 = fetch(ng.port, "/ns/page?keep=1")
    assert "x-cache" not in h1, "prime should miss to origin"
    _, b2, h2 = fetch(ng.port, "/ns/page?sid=abc&keep=1&tmp_foo=9&utm_source=x")
    assert h2.get("x-cache") == "HIT", \
        f"custom-stripped diff should HIT, got X-Cache={h2.get('x-cache')}"
    assert b2 == b1, "custom-stripped request served a different body"
    assert origin.hits == base + 1, "custom strip patterns not applied"


def test_normalize_strip_all(ng: Nginx, origin: Origin) -> None:
    """cache_turbo_normalize_strip "*" drops EVERY arg (a bare '*' is a
    zero-length prefix that matches every name), so wholly different query
    strings on the same path share one cache slot."""
    base = origin.hits
    _, b1, h1 = fetch(ng.port, "/na/x?anything=1&here=2")
    assert "x-cache" not in h1, "prime should miss to origin"
    _, b2, h2 = fetch(ng.port, "/na/x?totally=different&set=ofargs")
    assert h2.get("x-cache") == "HIT", \
        f"strip_all should collapse all args to one slot, got {h2.get('x-cache')}"
    assert b2 == b1, "strip_all served a different body"
    assert origin.hits == base + 1, "strip_all did not drop all args"


def test_normalize_distinct_args_differ(ng: Nginx, origin: Origin) -> None:
    """Guard against over-normalizing: a meaningful arg difference (a=1 vs a=2)
    must remain two distinct cache slots, not collapse to one."""
    base = origin.hits_for("/distinct")
    _, b1, h1 = fetch(ng.port, "/n/distinct?a=1")
    assert "x-cache" not in h1, "first should miss"
    _, b2, h2 = fetch(ng.port, "/n/distinct?a=2")
    assert "x-cache" not in h2, \
        f"a different value must MISS, got X-Cache={h2.get('x-cache')}"
    assert b2 != b1, "distinct args wrongly served the same cached body"
    assert origin.hits_for("/distinct") == base + 2, "both distinct args should reach origin"


# UA strings whose device class is unambiguous for the substring matcher.
_UA_MOBILE = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
              "AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1")
_UA_DESKTOP = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
               "Chrome/124.0 Safari/537.36")


def test_normalize_vary_encoding(ng: Nginx, origin: Origin) -> None:
    """v3-4: cache_turbo_normalize_vary encoding splits the key by Accept-Encoding
    CLASS (br/gzip/identity). br and gzip get separate slots (each its own origin
    fetch); two br requests share one slot. The raw header still collapses to the
    class, so 'br, deflate' HITs the 'br' entry."""
    base = origin.hits
    _, b1, h1 = fetch(ng.port, "/ve/p", headers={"Accept-Encoding": "br"})
    assert "x-cache" not in h1, "first (br) request should miss to origin"
    _, b2, h2 = fetch(ng.port, "/ve/p", headers={"Accept-Encoding": "gzip"})
    assert "x-cache" not in h2, \
        f"gzip must be a separate slot from br, got X-Cache={h2.get('x-cache')}"
    assert b2 != b1, "gzip slot served the br body"
    assert origin.hits == base + 2, "br and gzip should each reach origin once"
    _, b3, h3 = fetch(ng.port, "/ve/p", headers={"Accept-Encoding": "br, deflate"})
    assert h3.get("x-cache") == "HIT", \
        f"second br request should HIT, got X-Cache={h3.get('x-cache')}"
    assert b3 == b1, "two br requests must share one slot"
    assert origin.hits == base + 2, "second br request wrongly hit origin"


def test_normalize_vary_device(ng: Nginx, origin: Origin) -> None:
    """v3-4: cache_turbo_normalize_vary device splits the key by User-Agent device
    class (mobile/desktop). A mobile and a desktop UA get separate slots; a second
    mobile UA (different mobile token) shares the mobile slot."""
    base = origin.hits
    _, b1, h1 = fetch(ng.port, "/vd/p", headers={"User-Agent": _UA_MOBILE})
    assert "x-cache" not in h1, "first (mobile) request should miss to origin"
    _, b2, h2 = fetch(ng.port, "/vd/p", headers={"User-Agent": _UA_DESKTOP})
    assert "x-cache" not in h2, \
        f"desktop must be a separate slot from mobile, got {h2.get('x-cache')}"
    assert b2 != b1, "desktop slot served the mobile body"
    assert origin.hits == base + 2, "mobile and desktop should each reach origin"
    # a different mobile UA (Android) still classes as mobile -> HIT the slot
    _, b3, h3 = fetch(ng.port, "/vd/p",
                      headers={"User-Agent": "Mozilla/5.0 (Linux; Android 13) Mobile"})
    assert h3.get("x-cache") == "HIT", \
        f"second mobile UA should HIT the mobile slot, got {h3.get('x-cache')}"
    assert b3 == b1, "two mobile UAs must share one slot"
    assert origin.hits == base + 2, "second mobile request wrongly hit origin"


def test_normalize_vary_both(ng: Nginx, origin: Origin) -> None:
    """v3-4: encoding and device compose — (br,mobile) and (gzip,desktop) are two
    distinct slots, and each repeats as a HIT of its own slot."""
    base = origin.hits
    br_mob = {"Accept-Encoding": "br", "User-Agent": _UA_MOBILE}
    gz_desk = {"Accept-Encoding": "gzip", "User-Agent": _UA_DESKTOP}
    _, b1, h1 = fetch(ng.port, "/vb/p", headers=br_mob)
    assert "x-cache" not in h1, "(br,mobile) should miss"
    _, b2, h2 = fetch(ng.port, "/vb/p", headers=gz_desk)
    assert "x-cache" not in h2, \
        f"(gzip,desktop) must be its own slot, got {h2.get('x-cache')}"
    assert b2 != b1, "(gzip,desktop) served the (br,mobile) body"
    assert origin.hits == base + 2, "both compose-buckets should reach origin"
    _, b3, h3 = fetch(ng.port, "/vb/p", headers=br_mob)
    assert h3.get("x-cache") == "HIT" and b3 == b1, "(br,mobile) repeat should HIT"
    _, b4, h4 = fetch(ng.port, "/vb/p", headers=gz_desk)
    assert h4.get("x-cache") == "HIT" and b4 == b2, "(gzip,desktop) repeat should HIT"
    assert origin.hits == base + 2, "compose-bucket repeats wrongly hit origin"


def test_normalize_vary_off_by_default(ng: Nginx, origin: Origin) -> None:
    """v3-4 regression guard: WITHOUT cache_turbo_normalize_vary (location /n/),
    differing Accept-Encoding and User-Agent must NOT split the key — the v3-1
    normalized key is byte-identical, so the second request HITs the first slot."""
    base = origin.hits_for("/voff")
    _, b1, h1 = fetch(ng.port, "/n/voff",
                      headers={"Accept-Encoding": "br", "User-Agent": _UA_MOBILE})
    assert "x-cache" not in h1, "prime should miss to origin"
    _, b2, h2 = fetch(ng.port, "/n/voff",
                      headers={"Accept-Encoding": "gzip", "User-Agent": _UA_DESKTOP})
    assert h2.get("x-cache") == "HIT", \
        ("vary off: differing encoding/device must still HIT one slot, "
         f"got X-Cache={h2.get('x-cache')}")
    assert b2 == b1, "vary off served a different body (key wrongly split)"
    assert origin.hits_for("/voff") == base + 1, "vary off must keep one slot regardless of headers"


def test_normalize_vary_encoding_zstd(ng: Nginx, origin: Origin) -> None:
    """v4-3 (issues V6): the encoding bucket ranks zstd ABOVE br — we ship
    http-zstd, which serves zstd whenever the client advertises it (winning over
    brotli/gzip). So zstd / br / gzip are three distinct slots, two zstd requests
    share one, and a zstd-only client never reads the identity slot. 'zstd, br'
    collapses to the zstd class (HITs the zstd entry, not br)."""
    base = origin.hits
    _, bz, hz = fetch(ng.port, "/ve/z", headers={"Accept-Encoding": "zstd"})
    assert "x-cache" not in hz, "first (zstd) request should miss to origin"
    _, bb, hb = fetch(ng.port, "/ve/z", headers={"Accept-Encoding": "br"})
    assert "x-cache" not in hb, \
        f"br must be a separate slot from zstd, got X-Cache={hb.get('x-cache')}"
    _, bg, hg = fetch(ng.port, "/ve/z", headers={"Accept-Encoding": "gzip"})
    assert "x-cache" not in hg, \
        f"gzip must be a separate slot, got X-Cache={hg.get('x-cache')}"
    assert len({bz, bb, bg}) == 3, "zstd/br/gzip must be three distinct slots"
    assert origin.hits == base + 3, "zstd/br/gzip should each reach origin once"

    # identity client (no Accept-Encoding) must not read the zstd entry
    _, bi, hi = fetch(ng.port, "/ve/z")
    assert "x-cache" not in hi, \
        f"zstd-only entry must not serve an identity client, got {hi.get('x-cache')}"
    assert bi not in (bz, bb, bg), "identity slot served an encoded-class body"

    # two zstd share one slot; 'zstd, br' collapses to the zstd class
    _, bz2, hz2 = fetch(ng.port, "/ve/z", headers={"Accept-Encoding": "zstd, br"})
    assert hz2.get("x-cache") == "HIT", \
        f"second zstd request should HIT the zstd slot, got X-Cache={hz2.get('x-cache')}"
    assert bz2 == bz, "two zstd requests must share one slot"


def test_invalid_normalize_vary_token(ng: Nginx) -> None:
    """v3-4: an unknown cache_turbo_normalize_vary token is rejected at config
    time (nginx -t fails) with a clear message, not silently ignored."""
    bad = ng.root.parent / "bad-vary"
    (bad / "conf").mkdir(parents=True, exist_ok=True)
    (bad / "logs").mkdir(parents=True, exist_ok=True)
    cfg = nginx_config(bad, ng.port, ng.module, ng.origin_port, 1)
    cfg = cfg.replace("cache_turbo_normalize_vary encoding;",
                      "cache_turbo_normalize_vary bogus;")
    (bad / "conf" / "nginx.conf").write_text(cfg, encoding="ascii")
    cmd = ng.runner + [str(ng.binary), "-p", str(bad),
                       "-c", str(bad / "conf" / "nginx.conf"), "-t"]
    r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=20)
    assert r.returncode != 0, \
        f"invalid vary token 'bogus' was accepted by nginx -t:\n{r.stdout}"
    assert "invalid cache_turbo_normalize_vary" in r.stdout, \
        f"missing/odd diagnostic for bad vary token:\n{r.stdout}"


def test_auto_vary_encoding(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary: a response `Vary: Accept-Encoding` makes the module split
    by the Accept-Encoding class automatically (no operator config). Same class
    collapses onto one slot; a different class is a distinct slot."""
    base = origin.hits
    p = "/av/enc?v=ae"
    _, b1, _ = fetch(ng.port, p, {"Accept-Encoding": "gzip"})  # cold -> origin
    _, b2, _ = fetch(ng.port, p, {"Accept-Encoding": "gzip"})  # marker -> HIT
    assert b1 == b2, (b1, b2)
    _, b3, _ = fetch(ng.port, p, {"Accept-Encoding": "br"})    # new variant
    _, b4, _ = fetch(ng.port, p, {"Accept-Encoding": "br"})    # HIT
    assert b3 == b4, (b3, b4)
    assert b1 != b3, ("gzip and br shared a slot", b1, b3)
    _, b5, _ = fetch(ng.port, p, {"Accept-Encoding": "gzip"})  # still its slot
    assert b5 == b1, (b5, b1)
    assert origin.hits - base == 2, origin.hits - base


def test_auto_vary_encoding_same_class_shares(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary: two Accept-Encoding headers in the same bucket (gzip and
    'gzip, deflate' both classify gzip) share one slot -> one origin hit."""
    base = origin.hits_for("/encsame?v=ae")
    p = "/av/encsame?v=ae"
    _, b1, _ = fetch(ng.port, p, {"Accept-Encoding": "gzip"})
    _, b2, _ = fetch(ng.port, p, {"Accept-Encoding": "gzip, deflate"})
    assert b1 == b2, (b1, b2)
    assert origin.hits_for("/encsame?v=ae") - base == 1, origin.hits_for("/encsame?v=ae") - base


def test_auto_vary_device(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary: `Vary: User-Agent` splits by the coarse device class."""
    base = origin.hits_for("/dev?v=ua")
    p = "/av/dev?v=ua"
    mob = {"User-Agent": "Mozilla/5.0 (iPhone; CPU) Mobile"}
    dsk = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
    _, m1, _ = fetch(ng.port, p, mob)
    _, m2, _ = fetch(ng.port, p, mob)
    _, d1, _ = fetch(ng.port, p, dsk)
    _, d2, _ = fetch(ng.port, p, dsk)
    assert m1 == m2 and d1 == d2, (m1, m2, d1, d2)
    assert m1 != d1, ("mobile and desktop shared a slot", m1, d1)
    assert origin.hits_for("/dev?v=ua") - base == 2, origin.hits_for("/dev?v=ua") - base


def test_auto_vary_language(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary: `Vary: Accept-Language` splits by the LANG axis class
    (S7: primary-subtag class, not the raw header)."""
    base = origin.hits_for("/lang?v=al")
    p = "/av/lang?v=al"
    _, e1, _ = fetch(ng.port, p, {"Accept-Language": "en"})
    _, e2, _ = fetch(ng.port, p, {"Accept-Language": "en"})
    _, f1, _ = fetch(ng.port, p, {"Accept-Language": "fr"})
    assert e1 == e2, (e1, e2)
    assert e1 != f1, ("en and fr shared a slot", e1, f1)
    assert origin.hits_for("/lang?v=al") - base == 2, origin.hits_for("/lang?v=al") - base


def test_auto_vary_language_primary_subtag_shares(ng: Nginx,
                                                    origin: Origin) -> None:
    """S7: LANG folds to the primary-subtag CLASS, so `en-US,en;q=0.9` and
    `en-GB,en;q=0.8` -- distinct raw headers, same primary subtag `en` -- now
    SHARE one slot -> a single origin hit. This is the actual fix: before S7
    the raw fold gave each browser locale string its own variant, blowing up
    the keyspace on an i18n site for representations that are byte-identical.
    Canary: $cache_turbo_status (echoed as X-CT-Status) is HIT on the second
    request, not just "body matches"."""
    base = origin.hits_for("/langshare?v=al")
    p = "/av/langshare?v=al"
    s1, b1, h1 = fetch(ng.port, p, {"Accept-Language": "en-US,en;q=0.9"})
    s2, b2, h2 = fetch(ng.port, p, {"Accept-Language": "en-GB,en;q=0.8"})
    assert s1 == 200 and s2 == 200, (s1, s2)
    assert b1 == b2, ("en-US and en-GB did not share a slot", b1, b2)
    # The canary the docstring promises. Body identity alone is equally
    # satisfied by two independent origin misses returning the same bytes;
    # only the HIT proves en-GB landed on the slot en-US filled.
    assert h1.get("x-ct-status") == "MISS", \
        f"en-US should prime the 'en' class slot, got {h1.get('x-ct-status')}"
    assert h2.get("x-ct-status") == "HIT", \
        ("en-GB must HIT the slot en-US filled, not re-fetch an identical body",
         h2.get("x-ct-status"))
    assert origin.hits_for("/langshare?v=al") - base == 1, \
        ("en-US and en-GB should fold to one 'en' class -> one origin hit",
         origin.hits_for("/langshare?v=al") - base)


def test_auto_vary_language_different_primary_splits(ng: Nginx,
                                                       origin: Origin) -> None:
    """S7 negative guard: `en` and `de` are DIFFERENT primary subtags and must
    still SPLIT into distinct slots -- proves the fold isn't over-collapsing
    everything to one class."""
    base = origin.hits_for("/langsplit?v=al")
    p = "/av/langsplit?v=al"
    _, en1, _ = fetch(ng.port, p, {"Accept-Language": "en-US,en;q=0.9"})
    _, en2, _ = fetch(ng.port, p, {"Accept-Language": "en-GB,en;q=0.8"})
    _, de1, _ = fetch(ng.port, p, {"Accept-Language": "de-DE,de;q=0.9"})
    assert en1 == en2, ("en variants should still share", en1, en2)
    assert en1 != de1, ("en and de shared a slot", en1, de1)
    assert origin.hits_for("/langsplit?v=al") - base == 2, origin.hits_for("/langsplit?v=al") - base


def test_auto_vary_language_absent_splits_from_class(ng: Nginx,
                                                       origin: Origin) -> None:
    """S7: an absent Accept-Language header folds to its OWN empty class "" --
    it must still split from a present `en` header, not collide with it (the
    empty class is skip-shaped but must NOT be skipped: skipping the axis
    would collide a present-but-empty header with an absent one)."""
    base = origin.hits_for("/langabsent?v=al")
    p = "/av/langabsent?v=al"
    s1, absent1, _h1 = fetch(ng.port, p)  # no Accept-Language header at all
    s2, absent2, _h2 = fetch(ng.port, p)
    s3, en1, _h3 = fetch(ng.port, p, {"Accept-Language": "en-US,en;q=0.9"})
    assert s1 == 200 and s2 == 200 and s3 == 200, (s1, s2, s3)
    assert absent1 == absent2, ("absent header should share its own slot",
                                 absent1, absent2)
    assert absent1 != en1, ("absent Accept-Language shared a slot with 'en'",
                             absent1, en1)
    assert origin.hits_for("/langabsent?v=al") - base == 2, origin.hits_for("/langabsent?v=al") - base


def test_auto_vary_origin(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary: `Vary: Origin` splits by the raw Origin header value.
    ORIGIN is a CORS security boundary and is NEVER class-folded (S7 touches
    LANG only) -- two distinct Origins must still split into distinct slots."""
    base = origin.hits_for("/org?v=or")
    p = "/av/org?v=or"
    _, a1, _ = fetch(ng.port, p, {"Origin": "https://a.example"})
    _, a2, _ = fetch(ng.port, p, {"Origin": "https://a.example"})
    _, c1, _ = fetch(ng.port, p, {"Origin": "https://b.example"})
    assert a1 == a2, (a1, a2)
    assert a1 != c1, ("two Origins shared a slot", a1, c1)
    assert origin.hits_for("/org?v=or") - base == 2, origin.hits_for("/org?v=or") - base


def test_auto_vary_origin_not_class_folded(ng: Nginx, origin: Origin) -> None:
    """S7 regression guard: ORIGIN must stay RAW and is NEVER class-folded like
    LANG. Two distinct origins that share the same first 8 bytes (the LANG fold
    length, NGX_HTTP_CACHE_TURBO_LANG_CLASS_MAX) and the same "scheme + first
    label up to a '-'" shape -- i.e. exactly what a primary-subtag-style fold
    would collapse -- must still split into distinct slots and cause TWO
    origin hits. If ORIGIN were ever folded the way LANG is (cut at a
    delimiter, lowercase, cap at 8 bytes), these two would collide into one
    slot: both start with the identical 8-byte prefix "https://" and share the
    same leading label "a-one" / "a-two" up to a hyphen-cut point that overlaps
    ("a"), so a class-fold bug reusing the lang-style cut would alias them.
    Folding https://a-one.example with https://a-two.example would serve one
    origin's CORS headers to the other -- a real security bug, not just a
    cache-efficiency regression."""
    base = origin.hits_for("/orgnofold?v=or")
    p = "/av/orgnofold?v=or"
    o1 = "https://a-one.example"
    o2 = "https://a-two.example"
    s1, b1, _h1 = fetch(ng.port, p, {"Origin": o1})
    s2, b2, _h2 = fetch(ng.port, p, {"Origin": o1})
    s3, b3, _h3 = fetch(ng.port, p, {"Origin": o2})
    assert s1 == 200 and s2 == 200 and s3 == 200, (s1, s2, s3)
    assert b1 == b2, ("same Origin should share a slot", b1, b2)
    assert b1 != b3, (
        "ORIGIN got class-folded -- two distinct origins sharing an 8-byte "
        "prefix collapsed onto one slot; this is a CORS cross-origin leak",
        b1, b3)
    assert origin.hits_for("/orgnofold?v=or") - base == 2, (
        "ORIGIN must stay raw: two distinct origins => two origin hits, "
        "not one folded class", origin.hits_for("/orgnofold?v=or") - base)


def test_auto_vary_star_uncacheable(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary: `Vary: *` is uncacheable -> every request hits origin."""
    base = origin.hits_for("/star?v=star")
    p = "/av/star?v=star"
    _, b1, _ = fetch(ng.port, p)
    _, b2, _ = fetch(ng.port, p)
    assert b1 != b2, ("Vary: * was cached", b1, b2)
    assert origin.hits_for("/star?v=star") - base == 2, origin.hits_for("/star?v=star") - base


def test_auto_vary_cookie_uncacheable(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary: `Vary: Cookie` is refused (per-user) -> not cached."""
    base = origin.hits_for("/ck?v=ck")
    p = "/av/ck?v=ck"
    _, b1, _ = fetch(ng.port, p)
    _, b2, _ = fetch(ng.port, p)
    assert b1 != b2, ("Vary: Cookie was cached", b1, b2)
    assert origin.hits_for("/ck?v=ck") - base == 2, origin.hits_for("/ck?v=ck") - base


def test_auto_vary_mixed_refused_wins(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary: `Vary: Accept-Encoding, Cookie` -> the refused Cookie axis
    wins over the safe encoding axis, so the response is not cached at all."""
    base = origin.hits_for("/mix?v=mix")
    p = "/av/mix?v=mix"
    _, b1, _ = fetch(ng.port, p, {"Accept-Encoding": "gzip"})
    _, b2, _ = fetch(ng.port, p, {"Accept-Encoding": "gzip"})
    assert b1 != b2, ("mixed safe+refused Vary was cached", b1, b2)
    assert origin.hits_for("/mix?v=mix") - base == 2, origin.hits_for("/mix?v=mix") - base


def test_auto_vary_off_ignores_vary(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary off by default: the response Vary header is ignored, so two
    different Accept-Encodings collapse onto one slot (back-compat)."""
    base = origin.hits
    p = "/avoff/enc?v=ae"
    _, b1, _ = fetch(ng.port, p, {"Accept-Encoding": "gzip"})
    _, b2, _ = fetch(ng.port, p, {"Accept-Encoding": "br"})
    assert b1 == b2, ("auto_vary off still split by Vary", b1, b2)
    assert origin.hits - base == 1, origin.hits - base


def test_preset_window_differs(ng: Nginx, origin: Origin) -> None:
    """v3-2: a preset sets the stale-window multiplier. With cache_turbo_valid
    pinned to 1s on both locations, the only difference is the preset: the
    conservative band (x2) makes the entry serveable for 2s, the aggressive band
    (x8) for 8s. At t=3s the conservative copy is hard-expired (a MISS, re-fetch)
    while the aggressive copy is still serveable as stale. This asserts the
    PRESET'S effect, not its stored value, and proves the band reaches the
    runtime stale math (stale_mult threaded through shm_store)."""
    fetch(ng.port, "/pc/win")                          # prime conservative
    # H3c: the aggressive band is min_uses=2, so the FIRST request to a cold key
    # under /pa/ is gated to the origin without storing. Prime twice -- the
    # second request is the one that actually stores the entry whose stale
    # window this test measures. (Conservative is min_uses=1, one prime is
    # enough.) Without this the aggressive arm has nothing cached at t=3s and
    # the STALE assertion below fails for a reason unrelated to stale_mult.
    fetch(ng.port, "/pa/win")                          # aggressive: gated miss
    fetch(ng.port, "/pa/win")                          # aggressive: stores
    time.sleep(3.0)                                     # cons expired, aggr stale

    # conservative: past stale_until -> a true MISS (no X-Cache, hits origin)
    sc, _, hc = fetch(ng.port, "/pc/win")
    assert sc == 200, f"conservative re-read status {sc}"
    assert "x-cache" not in hc, \
        ("conservative (stale_mult=2) should hard-expire by t=3s and MISS, "
         f"got X-Cache={hc.get('x-cache')}")

    # aggressive: still within its 8s window. Burst so single-flight forces the
    # losers to serve stale (the lone dice-winner may regenerate); at least one
    # STALE proves the entry is still serveable, i.e. the wider band took effect.
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: fetch(ng.port, "/pa/win"), range(16)))
    assert {r[0] for r in results} == {200}, \
        f"aggressive stale burst returned {set(r[0] for r in results)}"
    assert any(h.get("x-cache") == "STALE" for _, _, h in results), \
        ("aggressive (stale_mult=8) should still serve STALE at t=3s; "
         "got " + repr(sorted(str(h.get('x-cache')) for _, _, h in results)))
    drain_origin(origin)       # v8: settle async bg refreshes before the next test


def test_stale_mult_directive_beats_preset(ng: Nginx, origin: Origin) -> None:
    """H5: an explicit cache_turbo_stale_mult overrides the resolved preset's
    band multiplier, the same way cache_turbo_valid/_beta/_lock_ttl already do.

    /psm/ carries `cache_turbo_preset aggressive` (band stale_mult=8) plus
    `cache_turbo_stale_mult 1`. The paired assertion is what makes this
    load-bearing: /pa/ is the SAME preset and the SAME 1s fresh TTL and is
    still serveable as STALE at t=3s, so if the directive were ignored /psm/
    would behave identically. It must instead hard-expire and MISS -- proving
    the raw value reached the runtime stale math and beat the band, not merely
    that some window exists."""
    # H3c: both locations resolve the aggressive band, whose min_uses is 2, so
    # the first request to each cold key is gated to the origin without storing.
    # Prime twice -- the second request is the one that stores the entry whose
    # stale window this test measures. This is admission, orthogonal to the
    # stale_mult precedence under test.
    fetch(ng.port, "/psm/win")                         # gated miss
    fetch(ng.port, "/psm/win")                         # prime (stores)
    fetch(ng.port, "/pa/win2")                         # gated miss
    fetch(ng.port, "/pa/win2")                         # control prime (stores)
    time.sleep(3.0)

    # directive wins: stale_mult=1 -> stale_until == fresh_until -> hard MISS
    s, _, h = fetch(ng.port, "/psm/win")
    assert s == 200, f"stale_mult=1 re-read status {s}"
    assert "x-cache" not in h, \
        ("explicit cache_turbo_stale_mult 1 should hard-expire at 1s and MISS, "
         f"got X-Cache={h.get('x-cache')} -- the directive lost to the "
         "aggressive band (stale_mult=8), i.e. the raw/effective split is "
         "not wired")

    # control: same preset, no directive -> the band's 8s window still applies,
    # so the difference above is attributable to the directive alone.
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: fetch(ng.port, "/pa/win2"), range(16)))
    assert any(h.get("x-cache") == "STALE" for _, _, h in results), \
        ("control /pa/ (aggressive band, no directive) should still serve "
         "STALE at t=3s; got "
         + repr(sorted(str(h.get('x-cache')) for _, _, h in results)))
    drain_origin(origin)


def test_stale_mult_rejects_out_of_range(ng: Nginx) -> None:
    """H5: cache_turbo_stale_mult is range-checked at config time.

    `0` is the arm that matters: ngx_http_cache_turbo_stale_ttl() coerces a
    non-positive multiplier back to the BALANCED default of 4, so accepting a
    literal 0 would silently give the operator a 4x stale window instead of the
    "no stale window" they asked for. Rejecting it at parse is what keeps the
    directive honest. The boundaries 1 and 8 must still be accepted, so an
    off-by-one range check fails here rather than passing unnoticed."""
    anchor = "cache_turbo_stale_mult  1;"
    assert anchor in nginx_config(
        ng.root, ng.port, ng.module, ng.origin_port, 1, ng.redis_port,
        ng.redis_auth_port, ng.redis_password, ng.redis_tls_port,
        ng.redis_tls_ca, ng.memcached_port), \
        f"test fixture missing anchor {anchor!r}"

    # in-range-check arm: parses fine as a number, refused by the bounds
    for bad in ("0", "9"):
        r = _config_test_result(
            ng, lambda c, b=bad: c.replace(
                anchor, f"cache_turbo_stale_mult  {b};", 1))
        assert r.returncode != 0, \
            f"cache_turbo_stale_mult {bad} was accepted by nginx -t:\n{r.stdout}"
        assert "out of range" in r.stdout, \
            f"missing/odd range diagnostic for {bad}:\n{r.stdout}"

    # parse arm: ngx_atoi has no sign handling, so a negative never reaches the
    # bounds check and surfaces as "bad value" -- still rejected, different
    # diagnostic. Pinned so the two paths can't be collapsed by a later editor.
    for bad in ("-1", "abc"):
        r = _config_test_result(
            ng, lambda c, b=bad: c.replace(
                anchor, f"cache_turbo_stale_mult  {b};", 1))
        assert r.returncode != 0, \
            f"cache_turbo_stale_mult {bad} was accepted by nginx -t:\n{r.stdout}"
        assert "bad value" in r.stdout, \
            f"missing/odd bad-value diagnostic for {bad}:\n{r.stdout}"

    # both boundaries stay legal
    for good in ("1", "8"):
        r = _config_test_result(
            ng, lambda c, g=good: c.replace(
                anchor, f"cache_turbo_stale_mult  {g};", 1))
        assert r.returncode == 0, \
            f"cache_turbo_stale_mult {good} (a legal boundary) was rejected:\n{r.stdout}"


def test_preset_micro_default_ttl(ng: Nginx, origin: Origin) -> None:
    """micro preset: with NO explicit cache_turbo_valid the band's own 1s fresh
    TTL takes effect (stale_mult=2 -> entry hard-expires at ~2s). An immediate
    re-read is a fresh HIT; by t=3s the entry is gone and the next read MISSes.
    A >=30s default (any other preset's band) would still HIT at t=3s, so this
    proves micro's 1s default-valid band reaches the runtime freshness math
    without an explicit knob."""
    sc, _, hc = fetch(ng.port, "/pm/win")              # prime (MISS, no X-Cache)
    assert sc == 200 and "x-cache" not in hc, \
        f"micro prime should be a MISS, got {sc} X-Cache={hc.get('x-cache')}"

    sc, _, hc = fetch(ng.port, "/pm/win")              # immediate -> fresh HIT
    assert sc == 200 and hc.get("x-cache") == "HIT", \
        ("micro within its 1s fresh window should HIT, got "
         f"{sc} X-Cache={hc.get('x-cache')}")

    time.sleep(3.0)                                     # past fresh+stale (~2s)
    sc, _, hc = fetch(ng.port, "/pm/win")
    assert sc == 200, f"micro re-read status {sc}"
    assert "x-cache" not in hc, \
        ("micro (default valid 1s, stale_mult=2) should hard-expire by t=3s and "
         f"MISS; a >=30s default would still HIT. Got X-Cache={hc.get('x-cache')}")
    drain_origin(origin)       # settle any async bg refresh before the next test


def test_invalid_preset_name(ng: Nginx) -> None:
    """v3-2: an unknown cache_turbo_preset value is rejected at config time
    (nginx -t fails) with a clear message, not silently ignored."""
    bad = ng.root.parent / "bad-preset"
    (bad / "conf").mkdir(parents=True, exist_ok=True)
    (bad / "logs").mkdir(parents=True, exist_ok=True)
    cfg = nginx_config(bad, ng.port, ng.module, ng.origin_port, 1)
    cfg = cfg.replace("cache_turbo_preset   conservative;",
                      "cache_turbo_preset   bogus;")
    (bad / "conf" / "nginx.conf").write_text(cfg, encoding="ascii")
    cmd = ng.runner + [str(ng.binary), "-p", str(bad),
                       "-c", str(bad / "conf" / "nginx.conf"), "-t"]
    r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=20)
    assert r.returncode != 0, \
        f"invalid preset 'bogus' was accepted by nginx -t:\n{r.stdout}"
    assert "invalid cache_turbo_preset" in r.stdout, \
        f"missing/odd diagnostic for bad preset:\n{r.stdout}"


# --------------------------------------------------------------------------- #
# Live autotune within preset bands (v4-3)
# --------------------------------------------------------------------------- #

def _fire_misses(ng: Nginx, prefix: str, n: int) -> None:
    """Fire n distinct-key GETs concurrently so a window fills fast. Re-calling
    with the same prefix re-reads the same keys (refreshes, not misses)."""
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=16) as ex:
        list(ex.map(lambda i: fetch(ng.port, f"{prefix}{i}"), range(n)))


# A forced recompute (admin ?autotune=1) windows over everything since the last
# recompute and returns the stats incl. the fresh verdict. The autotune locations
# use a huge interval so the throttled per-request recompute fires only on the
# seed (snapshotting ~0) and never splits the measured window — the force does the
# real measurement, making these tests independent of wall-clock timing.

def _autotune_force(ng: Nginx, admin: str) -> dict:
    import json
    s, b, _ = fetch(ng.port, f"{admin}?autotune=1")
    assert s == 200, f"{admin}?autotune=1 status {s}"
    return json.loads(b)


def test_autotune_raises_beta_within_band(ng: Nginx, origin: Origin) -> None:
    """A window of slow misses makes the zone autotune its beta UP from the live
    miss-cost (beta = cost_ms/20, ×1000). The verdict is published per-zone (admin
    autotuned_beta) and re-clamped to each location's preset band ($cache_turbo_beta):
    balanced /at/ [500,2000] shows the verdict, conservative /atc/ [500,1000] shows
    it capped at its band max and strictly lower."""
    origin.delay = 0.04          # ~40ms regen -> target beta ~ 40*1000/20 = 2000
    try:
        fetch(ng.port, "/at/seed")               # first request snapshots ~0
        _fire_misses(ng, "/at/k", 110)           # 110 distinct slow misses
        st = _autotune_force(ng, "/_cache_at")   # recompute over the whole window

        assert 25 <= st["cost_ms"] <= 200, f"cost not measured sanely: {st}"
        beta = st["autotuned_beta"]
        assert 1500 <= beta <= 3000, f"autotuned beta not raised: {st}"

        _, _, hb = fetch(ng.port, "/at/probe")
        _, _, hc = fetch(ng.port, "/atc/probe")
        bal = int(hb["x-ct-beta"])
        con = int(hc["x-ct-beta"])
        assert bal == max(500, min(beta, 2000)), \
            f"balanced effective beta {bal} not clamped to its band from {beta}"
        assert con == max(500, min(beta, 1000)), \
            f"conservative effective beta {con} not clamped to its band from {beta}"
        assert con < bal, f"conservative ({con}) should be below balanced ({bal})"
    finally:
        origin.reset_delay()
        drain_origin(origin)   # v8: settle async bg refreshes before next test


def test_autotune_load_factor_under_load(ng: Nginx, origin: Origin) -> None:
    """v4-4: the same slow-miss window that raises beta also publishes a LOAD
    FACTOR (×1000) the request path uses to widen the stale window + lock_ttl.
    load = clamp(1000, cost_ms×100, 4000); a ~40ms regen saturates it at the 4000
    cap. A subsequent high-hit-rate window (not under load) snaps it back to the
    1000 baseline — proving the factor adapts down, not just up."""
    origin.delay = 0.04          # ~40ms regen -> cost×100 >= 4000 -> capped
    try:
        fetch(ng.port, "/at/lseed")              # snapshot the window start
        _fire_misses(ng, "/at/lk", 110)          # 110 distinct slow misses
        st = _autotune_force(ng, "/_cache_at")
        assert 25 <= st["cost_ms"] <= 500, f"cost not measured sanely: {st}"
        load = st["autotuned_load"]
        # cost_ms >= 40 (a real 40ms sleep) => cost×100 >= 4000 => hits the cap.
        assert load == 4000, \
            f"load factor should saturate at the 4000 cap for a ~40ms origin: {st}"
    finally:
        origin.reset_delay()
        drain_origin(origin)

    # Snap-back: a window dominated by HITS (few misses, hit-rate >= 95%) does not
    # qualify as under-load, so the verdict republishes the 1000 baseline. Uses a
    # hit-heavy window (not a fast-miss one) so it is robust under ASan timing.
    fetch(ng.port, "/at/hot")                    # prime (1 miss)
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(lambda _: fetch(ng.port, "/at/hot"), range(130)))   # 130 hits
    st2 = _autotune_force(ng, "/_cache_at")
    assert st2["autotuned_load"] == 1000, \
        f"load factor did not snap back to baseline on a non-load window: {st2}"


def test_autotune_load_widens_stale_window(ng: Nginx, origin: Origin) -> None:
    """v4-4 behaviour: with the zone load factor pumped to the cap, an entry that
    is hard-expired by its STATIC stale window (conservative ×2: fresh 1s + stale
    1s = serveable 2s) is still STALE-serveable at t=3s, because the load factor
    widened the serveable stale span (fresh window is NOT touched). Mirror of
    test_preset_window_differs, but here the wider window comes from live load, not
    a preset."""
    origin.delay = 0.04
    try:
        fetch(ng.port, "/atl/seed")
        _fire_misses(ng, "/atl/k", 110)          # pump the zone load factor
        st = _autotune_force(ng, "/_cache_atl")
        assert st["autotuned_load"] >= 2000, f"load not pumped: {st}"
        origin.delay = 0.0   # deliberate, NOT a restore: the probe prime must be
                             # instant so it lands well inside the 1s fresh window.
                             # The finally below does the real restore.
        fetch(ng.port, "/atl/probe")             # prime the probe (fresh 1s)
    finally:
        origin.reset_delay()

    time.sleep(3.0)                              # past static 2s, within widened ~5s

    # Burst so single-flight forces losers to serve stale (the dice winner may
    # regenerate); at least one STALE proves the load-widened window held.
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        res = list(pool.map(lambda _: fetch(ng.port, "/atl/probe"), range(16)))
    assert {r[0] for r in res} == {200}, \
        f"load-widen stale burst returned {set(r[0] for r in res)}"
    assert any(h.get("x-cache") == "STALE" for _, _, h in res), \
        ("load-widened stale window should still serve STALE at t=3s (a static "
         "conservative ×2 window would hard-expire and MISS); got "
         + repr(sorted({h.get("x-cache") for _, _, h in res})))
    drain_origin(origin)


def test_autotune_off_by_default(ng: Nginx) -> None:
    """A location WITHOUT cache_turbo_autotune ignores the zone's live verdict and
    always reports its static preset beta (balanced = 1000), even though /ato/
    shares the zone /at/ just autotuned up."""
    _, _, h = fetch(ng.port, "/ato/x")
    assert int(h["x-ct-beta"]) == 1000, \
        f"autotune-off location should show static beta 1000, got {h.get('x-ct-beta')}"


def test_autotune_insufficient_data(ng: Nginx, origin: Origin) -> None:
    """Below MISSES_FLOOR (100) traffic in a window, no verdict is published — the
    fresh zone's autotuned_beta stays 0 (fall back to preset)."""
    origin.delay = 0.04
    try:
        fetch(ng.port, "/ati/seed")              # first request snapshots ~0
        _fire_misses(ng, "/ati/k", 10)           # only 10 < floor
        st = _autotune_force(ng, "/_cache_ati")  # recompute: thin window -> no verdict
        assert st["autotuned_beta"] == 0, f"thin data wrongly tuned: {st}"
    finally:
        origin.reset_delay()
        drain_origin(origin)   # v8: settle async bg refreshes before next test


def test_autotune_churn_disqualifies(ng: Nginx, origin: Origin) -> None:
    """A refresh-dominated window (refreshes/misses > 2) is vetoed by the churn gate
    even though cost+hit-rate would otherwise qualify (cf. test_autotune_raises_*),
    so no verdict is published (autotuned_beta stays 0). The /atch/ location uses an
    aggressive preset (8s entry life), 1s TTL + 1s lock + beta 5.0 so a stale read
    deep in the window certainly refreshes; re-reading the 110 keys for 4 cycles
    drives well over 220 refreshes (> 2x the 110 cold misses) with margin even when
    valgrind slows a cycle. One forced recompute windows the whole run."""
    origin.delay = 0.012         # ~12ms >= COST_MOD (10ms): cost would qualify
    try:
        fetch(ng.port, "/atch/seed")             # first request snapshots ~0
        _fire_misses(ng, "/atch/k", 110)         # 110 cold misses (floor + low hit-rate)
        for _ in range(4):                        # 4 stale refresh cycles
            time.sleep(2.7)                       # past fresh + lock, deep in stale
            _fire_misses(ng, "/atch/k", 110)      # same keys -> refreshes, not misses

        st = _autotune_force(ng, "/_cache_atch")  # recompute over the whole window
        assert st["refreshes"] > 2 * max(1, st["misses"]), \
            f"setup failed to drive churn ratio > 2: {st}"
        assert st["autotuned_beta"] == 0, \
            f"churn-heavy window should be vetoed, got {st}"
    finally:
        origin.reset_delay()
        drain_origin(origin)   # v8: settle async bg refreshes before next test


# --------------------------------------------------------------------------- #
# v13 memcached L2 backend
# --------------------------------------------------------------------------- #

def test_l2_memcached_write_through(ng: Nginx, origin: Origin,
                                    mc: MemcachedServer) -> None:
    """v13: a store under /mc/ writes through to memcached. After caching, the
    blob is present under the mc: key and contains the response body bytes, and
    the L1 hot path still serves the HIT byte-identically."""
    uri = "/mc/store"
    key = l2_key(uri, prefix="mc:")
    mc.command(b"delete " + key.encode() + b"\r\n")

    s, body, h = fetch(ng.port, uri)               # miss -> origin -> store
    assert s == 200, f"mc store status {s}"
    assert "x-cache" not in h, "first request should be a miss"

    # write-through is async/fire-and-forget; give it a moment to land
    assert wait_for(lambda: mc.exists(key)), \
        f"L2 key {key} never appeared in memcached"
    stored = mc.get(key)
    assert stored is not None and len(stored) > len(body), \
        f"stored blob ({len(stored or b'')}B) smaller than body"
    assert b"gen-" in stored, "stored blob missing response body"

    # L1 still serves the hit (write-through must not disturb the hot path)
    _, b2, h2 = fetch(ng.port, uri)
    assert h2.get("x-cache") == "HIT" and b2 == body, "L1 hit broken after L2 set"


def test_l2_memcached_cross_instance_fill(ng: Nginx, origin: Origin,
                                          mc: MemcachedServer) -> None:
    """v13: an L1 miss fills from memcached. A second, independent nginx with a
    cold L1 but the same memcached serves the object the first node cached,
    without hitting the origin again."""
    uri = "/mc/p2"
    key = l2_key(uri, prefix="mc:")
    mc.command(b"delete " + key.encode() + b"\r\n")

    # Instance A: cold -> origin -> writes L1 + L2
    s, body_a, ha = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in ha, "A should miss to origin first"
    assert wait_for(lambda: mc.exists(key)), "A never wrote the object to L2"
    drain_origin(origin)
    origin_after_a = origin.hits

    # Instance B: separate nginx, cold L1, same memcached + same origin
    b = Nginx(ng.binary, ng.module, ng.root.parent / "server-b-mc",
              ng.port + PORT_OFFSETS["l2_memcached_cross_instance_fill_b"],
              ng.origin_port, ng.runner_raw,
              ng.single_process, memcached_port=ng.memcached_port)
    b.write_config()
    b.config_test()
    b.start()
    try:
        s2, body_b, hb = fetch(b.port, uri)
        assert s2 == 200, f"B status {s2}"
        assert body_b == body_a, f"B body {body_b!r} != A body {body_a!r}"
        assert hb.get("x-cache") == "HIT", \
            f"B X-Cache={hb.get('x-cache')} (expected an L2-fill HIT)"
        assert origin.hits == origin_after_a, \
            f"origin was hit on the L2 fill ({origin.hits} vs {origin_after_a})"

        # B now has it in L1 too: second read is a plain L1 HIT
        _, body_b2, hb2 = fetch(b.port, uri)
        assert hb2.get("x-cache") == "HIT" and body_b2 == body_a
        assert origin.hits == origin_after_a, "origin hit on B's L1 hit"

        time.sleep(0.2)
        b.stop()
        b.assert_clean_logs()
    finally:
        b.stop()


def test_l2_memcached_purge_key_drops_l2(ng: Nginx, origin: Origin,
                                         mc: MemcachedServer) -> None:
    """v13: a single-key purge on the memcached-aware admin endpoint also deletes
    the entry from memcached (not just L1), so the next miss cannot be silently
    refilled from L2."""
    uri = "/mc/purgekey"
    key = l2_key(uri, prefix="mc:")
    mc.command(b"delete " + key.encode() + b"\r\n")

    s, body_a, h = fetch(ng.port, uri)             # miss -> origin -> L1 + L2
    assert s == 200 and "x-cache" not in h, "prime should miss to origin"
    assert wait_for(lambda: mc.exists(key)), "write-through never reached L2"

    # purge the key via the memcached-aware admin endpoint
    s, _, _ = fetch(ng.port, f"/_cache_mc?key={uri}", method="POST")
    assert s == 200, f"purge status {s}"

    # the L2 entry must actually be gone (fire-and-forget delete)
    assert wait_for(lambda: not mc.exists(key)), \
        "single-key purge did not drop the entry from memcached"

    # next read misses to a fresh origin generation, not an L2 refill
    origin_before = origin.hits
    s, body_b, h3 = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in h3, \
        f"post-purge read should miss to origin, got {h3.get('x-cache')}"
    assert origin.hits == origin_before + 1, \
        "origin not consulted after purge (L2 still served)"
    assert body_b != body_a, "post-purge body should be a fresh generation"


def test_l2_backend_inheritance_child_redis_over_parent_memcached(
        ng: Nginx, origin: Origin, redis: RedisServer,
        mc: MemcachedServer) -> None:
    """Precedence regression (bug FIXED 2026-06-12): a child location naming
    cache_turbo_redis, enclosed by a parent naming cache_turbo_memcached, must
    drive its OWN address with the Redis backend — not inherit the parent's
    memcached=1 at merge (which would select the memcached driver for a redis://
    address). The redis directive pins memcached=0 for this reason; this locks it.

    Assertion: a store under the child writes through to REDIS (ct: key) and NOT
    to memcached (mc: key). If the fix regressed, the blob would land in memcached
    (parent's inherited backend) and the Redis key would never appear."""
    uri = "/mcinh/child/store"
    r_key = l2_key(uri, prefix="ct:")   # where it must land (child = Redis)
    m_key = l2_key(uri, prefix="mc:")   # where it must NOT land (parent memcached)
    redis.cli("DEL", r_key)
    mc.command(b"delete " + m_key.encode() + b"\r\n")

    s, _body, h = fetch(ng.port, uri)               # miss -> origin -> store
    assert s == 200, f"child store status {s}"
    assert "x-cache" not in h, "first request should be a miss"

    # write-through is async; the child's own (Redis) backend must receive it
    assert wait_for(lambda: redis.cli("EXISTS", r_key) == "1"), \
        f"child cache_turbo_redis store never reached Redis ({r_key}) — the child " \
        "likely inherited the parent's memcached backend (precedence regression)"
    # and the parent's memcached backend must stay untouched by the child
    assert not mc.exists(m_key), \
        f"child store leaked into the parent's memcached backend ({m_key})"

    # sanity: the parent location itself still uses memcached (not poisoned by
    # the child's redis override the other way around)
    puri = "/mcinh/parent-x"
    pm_key = l2_key(puri, prefix="mc:")
    pr_key = l2_key(puri, prefix="ct:")
    redis.cli("DEL", pr_key)
    mc.command(b"delete " + pm_key.encode() + b"\r\n")
    ps, _, ph = fetch(ng.port, puri)
    assert ps == 200 and "x-cache" not in ph, "parent prime should miss"
    assert wait_for(lambda: mc.exists(pm_key)), \
        "parent cache_turbo_memcached store never reached memcached"
    assert redis.cli("EXISTS", pr_key) == "0", \
        "parent store leaked into Redis (backend identity crossed)"


def test_mc_keepalive_reuse(ng: Nginx, origin: Origin,
                            mc: MemcachedServer) -> None:
    """D-O1 primary crash path: a memcached L2 op GET-pools its connection, and
    the very next op (the write-through SET) REUSES it, then re-pools it. Before
    the fix, mc_connect's reuse branch left op->peer.name NULL, so the SET's
    re-pool (op_done -> ka_save, which dereferences op->peer.name) SIGSEGV'd the
    worker on a plain L1 miss. This exercises that exact GET-pool -> SET-reuse
    -> re-pool cycle across a burst and proves (a) the worker survives it and
    (b) the pool actually reuses connections (few new accepts vs connect-per-op).

    /mcka/ has keepalive=4; /mc/ connects per op. We measure memcached's accept
    count across an identical burst on each and assert the pool cut the churn --
    the same connect-per-op vs reuse contrast the Redis test_l2_keepalive_reuse
    makes, but on the driver the fix touched.
    """
    n = 40
    stamp = time.time()

    def burst(prefix: str) -> int:
        # each probe opens one stats connection; subtract it so we count only
        # nginx's accepts, not our own measurement conns (mirrors the redis test)
        before = mc.total_connections() - 1
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            list(ex.map(lambda i: fetch(ng.port, f"{prefix}reuse-{stamp}-{i}"),
                        range(n)))
        time.sleep(0.6)   # let fire-and-forget SETs finish + conns settle
        return mc.total_connections() - 1 - before

    workers_before = ng.worker_pids()

    off = burst("/mc/")      # connect-per-op memcached location: ~2N accepts
    on = burst("/mcka/")     # keepalive on: a small bounded number, then reuse

    # The worker must have survived the GET-pool -> SET-reuse -> re-pool cycle.
    if not ng.single_process:
        assert ng.worker_pids() == workers_before, (
            "worker PID set changed during a keepalive reuse burst -- a worker "
            "crashed (D-O1 NULL op->peer.name on the mc_connect reuse path)")

    assert off > n, f"connect-per-op baseline too low ({off}); expected > {n}"
    assert on * 2 < off, \
        f"memcached keepalive did not cut connection churn (on={on}, off={off})"

    # pool kept a live conn: a subsequent op still hits + serves
    _, _, h = fetch(ng.port, f"/mcka/reuse-{stamp}-0")   # now an L1 HIT
    assert h.get("x-cache") == "HIT", "keepalive location broke the hot path"


def test_mc_keepalive_zero_does_not_drain_pool(ng: Nginx, origin: Origin,
                                               mc: MemcachedServer) -> None:
    """MC-A2: a location with keepalive=0 must neither borrow from nor drain the
    pool a DIFFERENT location filled for the SAME memcached peer. /mcka/ has
    keepalive=4 and /mcka0/ points at the same address with keepalive=0.

    Prime /mcka/ so idle sockets sit in the pool, run a burst through /mcka0/,
    then run a burst through /mcka/ again. If the zero location borrowed pooled
    sockets it would close each one after its op (ka_save refuses to re-pool at
    keepalive=0), so the second /mcka/ burst would have to re-dial and its accept
    count would jump to the connect-per-op level. With the fix the zero location
    dials its own connections and /mcka/'s pool is untouched."""
    n = 12
    stamp = time.time()

    def burst(prefix: str, tag: str) -> int:
        before = mc.total_connections() - 1
        for i in range(n):
            fetch(ng.port, f"{prefix}drain-{tag}-{stamp}-{i}")
        time.sleep(0.6)          # let fire-and-forget SETs settle
        return mc.total_connections() - 1 - before

    workers_before = ng.worker_pids()

    burst("/mcka/", "prime")             # fill the pool
    zero = burst("/mcka0/", "zero")      # keepalive=0: fresh conn per op
    warm = burst("/mcka/", "warm")       # pool must still be warm

    if not ng.single_process:
        assert ng.worker_pids() == workers_before, \
            "worker crashed during the mixed keepalive=0 / keepalive=4 burst"

    assert zero >= 2 * n - 2, \
        f"keepalive=0 location did not dial per op (accepts={zero}, ops={n})"
    # The pool holds 4 idle sockets. If /mcka0/ borrowed them it closed each one
    # after its op (ka_save refuses to re-pool at keepalive=0), so the warm burst
    # must re-dial the whole pool. Untouched, the warm burst reuses what is
    # already pooled and opens (almost) nothing.
    assert warm <= 1, (
        "the keepalive=0 location drained the shared peer's pool: the warm "
        f"burst re-dialled {warm} connection(s) (zero={zero}, ops={n})")


def test_mc_keepalive_idle_timeout_drops(ng: Nginx, origin: Origin,
                                         mc: MemcachedServer) -> None:
    """D-O1 idle-timer branch of mc_ka_close_handler (ev->timedout): a pooled
    memcached connection left idle past keepalive_timeout must be dropped by the
    timer handler, not leak or crash the worker. /mckashort/ has a 1s idle
    timeout. Prime a pooled conn, wait past it, and assert the worker survives
    and the next op still serves (re-dialing a fresh conn transparently).

    The peer-event branch is covered by test_mc_keepalive_server_close_survives;
    this covers the timedout branch the server-close test never reaches."""
    uri = "/mckashort/idle"
    key = l2_key(uri, prefix="mcks:")
    mc.command(b"delete " + key.encode() + b"\r\n")

    s, body, _ = fetch(ng.port, uri)
    assert s == 200, "prime should miss to origin"
    assert wait_for(lambda: mc.exists(key)), \
        "write-through never reached memcached (no conn to pool)"

    workers_before = ng.worker_pids()

    # Idle timeout is 1s; wait comfortably past it so the read timer fires and
    # mc_ka_close_handler drops the pooled slot via the ev->timedout path.
    time.sleep(2.0)

    if not ng.single_process:
        assert ng.worker_pids() == workers_before, (
            "worker PID set changed while a pooled conn idle-timed-out -- the "
            "idle-timer close handler crashed (D-O1 timedout branch)")

    # A fresh op re-dials transparently and still serves from L1.
    s2, body2, h2 = fetch(ng.port, uri)
    assert s2 == 200 and h2.get("x-cache") == "HIT" and body2 == body, \
        "worker no longer serves the L1 hit after the pooled conn idle-timeout"


def test_mc_dirty_reply_not_pooled(ng: Nginx, origin: Origin) -> None:
    """D-O2: a memcached reply that does not end at a clean protocol boundary
    (trailing junk past END / STORED) must NOT be returned to the keepalive pool.
    The connection is closed instead, so a later reuse can never resume in the
    middle of a stale reply and desync the stream.

    /mcdirty/ (keepalive=4) points at a fake memcached that appends garbage after
    every framed reply. We drive a burst of DISTINCT cold keys -- each is an L1
    miss -> memcached GET (miss) -> origin -> L1 store + write-through memcached
    SET, i.e. two memcached ops per key. With the clean gate, every one of those
    connections is closed (the reply had trailing bytes), so the fake sees about
    one accept per op. The pre-fix driver pooled those unclean connections and
    reused them, collapsing the accept count far below the op count.

    Negative control (PROVEN by reverting op->clean + its gate in the driver and
    rebuilding the .so): dirty conns get pooled -> `accepts` drops ~10x -> the
    assertion below fires. The worker-PID check also catches a crash on the
    unclean path."""
    dirty = DirtyMemcached(ng.port + PORT_OFFSETS["mc_dirty_reply"])
    dirty.start()
    try:
        n = 30
        stamp = time.time()
        workers_before = ng.worker_pids()

        def one(i: int) -> int:
            s, _, _ = fetch(ng.port, f"/mcdirty/d-{stamp}-{i}")
            return s

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            statuses = list(ex.map(one, range(n)))
        time.sleep(0.6)   # let fire-and-forget SETs land + connections settle

        assert all(s == 200 for s in statuses), \
            f"a /mcdirty/ request failed (worker wedged on an unclean conn?): {statuses}"

        if not ng.single_process:
            assert ng.worker_pids() == workers_before, (
                "worker PID set changed during the dirty-reply burst -- a worker "
                "crashed handling an unclean memcached connection (D-O2)")

        # ~2N ops, each on its own fresh connection when the clean gate closes the
        # unclean ones. `>= n` sits ~2x under the pooled-none expectation (~2N) and
        # well above the reuse case (~pool size). Generous slack for scheduling.
        assert dirty.accepts >= n, (
            f"dirty memcached connections were reused ({dirty.accepts} accepts for "
            f"{n} cold keys / ~{2 * n} ops) -- an unclean reply was pooled (D-O2)")
    finally:
        dirty.stop()


def test_mc_keepalive_server_close_survives(ng: Nginx, origin: Origin,
                                            mc: MemcachedServer) -> None:
    """D-O1: an idle memcached keepalive connection whose server drops it must
    NOT crash the worker.

    The /mcka/ location runs the memcached L2 backend with a keepalive pool.
    After a write-through SET the driver parks the connection idle in the pool.
    When the memcached server then closes that idle connection, epoll wakes
    c->read; the pooled slot must carry a close-on-readable handler that drops
    it. The driver used to leave c->read->handler == NULL there, so the wakeup
    dereferenced NULL and SIGSEGV'd the worker. We detect a crash by watching
    the worker PID set: a segfaulting worker is replaced by the master, so the
    set changes; a healthy worker keeps its PID and keeps serving the L1 hit.

    Multi-worker mode only (single_process has no worker to lose + no PID set).
    """
    if ng.single_process:
        return

    uri = "/mcka/keepme"
    key = l2_key(uri, prefix="mck:")
    mc.command(b"delete " + key.encode() + b"\r\n")

    # Miss -> origin -> L1 + write-through SET. The SET op pools its connection
    # idle when it finishes (op_done -> ka_save).
    s, body, h = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in h, "prime should miss to origin"
    assert wait_for(lambda: mc.exists(key)), \
        "write-through never reached memcached (no conn to pool)"

    workers_before = ng.worker_pids()
    assert workers_before, "expected at least one worker in multi-process mode"

    # Server drops every connection, including the idle pooled one. This is what
    # wakes the pooled conn's read event on the worker.
    mc.stop()

    # Give epoll a moment to deliver the readable/closed event to the worker and
    # run its handler. On the unpatched (NULL-handler) driver the worker would
    # SIGSEGV here and the master would fork a replacement with a new PID.
    deadline = time.time() + 2.0
    while time.time() < deadline:
        if ng.worker_pids() != workers_before:
            break
        time.sleep(0.05)

    assert ng.worker_pids() == workers_before, (
        "worker PID set changed after the memcached server dropped an idle "
        "pooled connection -- a worker crashed (D-O1 NULL close handler)")

    # And the worker is still healthy: the already-cached object still serves
    # from L1 without the (now dead) memcached backend.
    s2, body2, h2 = fetch(ng.port, uri)
    assert s2 == 200 and h2.get("x-cache") == "HIT" and body2 == body, \
        "worker no longer serves the L1 hit after the pooled-conn close event"


def run_all(ng: Nginx, origin: Origin,
            redis: RedisServer | None = None,
            redis_auth: RedisServer | None = None,
            redis_tls: RedisServer | None = None,
            mc: MemcachedServer | None = None,
            redis_tls_untrusted: RedisServer | None = None,
            redis_tls_expired: RedisServer | None = None) -> None:
    test_miss_then_hit(ng)
    test_surrogate_key_emit_on_miss_and_hit(ng)
    if redis is not None:
        # /skoff/ carries a cache_turbo_redis (its tag needs the L2 consumer to
        # keep the COR-0 warning quiet), so it only exists in a Redis run.
        test_surrogate_key_off_by_default(ng)
    test_surrogate_key_origin_header_survives_hit(ng)
    test_surrogate_key_empty_tag_no_header(ng)
    test_surrogate_key_dedup_from_arg(ng)
    test_post_passthrough_uncached(ng, origin)
    test_compressed_edge_identity_capture(ng)
    test_header_fidelity(ng)
    if ng.fault_injection:
        test_restore_allocation_failure_fails_closed(ng, origin)
        test_file_backed_delegate_never_stores(ng, origin)
        test_store_failure_cleans_up_cold_stub(ng, origin)
    test_max_size_not_cached(ng)
    test_suppress_native_variable(ng)
    test_auto_classify(ng, origin)
    test_auto_classify_suppress_native_interaction(ng, origin)
    test_woocommerce_wc_ajax(ng, origin)
    test_header_auth_rest_surfaces(ng, origin)
    test_phpbb_preset(ng, origin)
    test_redmine_key_arg_bypasses_without_cookie(ng, origin)
    test_redmine_public_content_stays_cacheable(ng, origin)
    test_cookie_pred_multiple_matching_cookies(ng, origin)
    test_2026_preset_expansion(ng, origin)
    test_internal_redirect_key_and_veto(ng, origin)
    test_auto_classify_more(ng, origin)
    test_q2_multibuffer_oversize(ng, origin)
    test_suppress_native_inert_on_plain_location(ng)
    test_suppress_native_e2e_proxy_cache(ng)
    test_invalid_backend_name(ng)
    test_invalid_cache_turbo_mode(ng)
    test_auto_and_generic_are_removed(ng)
    test_breaker_directives_accepted(ng)                     # O4.4
    test_breaker_policy_divergence_warns(ng)                 # O4.4-d
    test_breaker_policy_identical_no_warning(ng)              # O4.4-d
    test_breaker_open_zero_rejected(ng)                      # O4.4 / O4.3-a
    test_breaker_arming_gated_on_breaker_enable(ng, origin)  # O4.4
    test_breaker_counters(ng, origin)                        # S7.1 breaker_serves/origin_failures
    test_breaker_retry_after_auto_tracks_breaker_open(ng, origin)  # BRK-RA1
    test_prometheus_breaker_metrics(ng, origin)               # H7.3a breaker_opens_total/breaker_state on prometheus
    test_breaker_arming_sites_gated_white_box(ng, origin)    # O4.4-i (L1)
    if redis is not None:
        # O4.4-i (L2). Needs a real Redis: without an L2 backend the L2 arming
        # path never executes and every delta reads 0, so the test would pass
        # while proving nothing. Guarded rather than unconditional for that
        # reason -- a no-Redis run must SKIP it, not fake it.
        test_breaker_l2_arming_site_gated_white_box(ng, origin, redis)
    test_breaker_lifecycle_open_zero_contact_close(ng, origin)  # O4.5
    test_breaker_off_negative_control_origin_climbs(ng, origin)  # O4.5
    test_breaker_record_position_and_sense(ng, origin)          # O4.5 / O4.2-f
    test_breaker_record_native_proxy_cache_hit_no_record(ng)    # O4.2-f
    test_backend_separators(ng)
    test_backend_malformed_pipes(ng)
    test_backend_none_is_exclusive(ng)
    test_backend_none_overrides_inherited(ng, origin)
    test_valid_status_rejects_304(ng)
    test_empty_l2_prefix_rejected(ng)
    test_backend_prefix_rejected(ng)
    test_keepalive_cap_rejected(ng)
    test_s8_scan_resistant_config_rejects(ng)
    test_keep_stale_config_parse(ng)                        # S2.1
    test_use_stale_config_parse(ng)                         # S4.1
    test_memcached_keepalive_invalid_rejected(ng)
    test_memcached_keepalive_cap_rejected(ng)
    test_memcached_keepalive_timeout_invalid_rejected(ng)
    test_valid_dup_status_warns(ng)
    test_tag_without_l2_warns(ng)
    test_tag_without_l2_but_surrogate_key_no_warn(ng)
    test_cache_control_invalid_mode_rejected(ng)
    test_cache_control_duplicate_rejected(ng)
    test_valid_status_rejects_out_of_range_code(ng)
    test_valid_rejects_bad_time(ng)
    test_require_header_rejects_invalid_name(ng)
    test_require_header_duplicate_rejected(ng)
    test_redis_bad_db_rejected(ng)
    test_redis_db_cap_rejected(ng)
    test_l2_prefix_charset_rejected(ng)
    test_no_cache_set_cookie(ng)
    test_no_cache_cc_private(ng)
    test_no_cache_cc_nostore(ng)
    test_no_cache_authorization(ng)
    test_default_key_varies_by_host(ng)
    test_default_key_normalizes(ng)
    test_cache_redirect(ng)
    test_cache_negative_404(ng)
    test_head_not_stored(ng)
    test_honor_cache_control(ng)
    test_honor_expires_absolute_ttl(ng)                    # upstream_ttl Expires arm
    test_cdn_cache_control_ttl_outranks_cache_control(ng)   # RFC 9213
    test_surrogate_control_ttl_outranks_cdn_and_cache_control(ng)  # RFC 9213
    test_surrogate_control_split_header_ttl(ng)             # AUD2-CC-TARGETED
    test_cdn_cache_control_split_header_ttl(ng)             # AUD2-CC-TARGETED
    test_cdn_cache_control_no_store_refuses(ng)             # RFC 9213
    test_targeted_cache_control_stripped_from_serve(ng)     # RFC 9213
    test_age_header(ng)
    test_request_no_cache(ng, origin)
    test_must_revalidate(ng)
    test_must_revalidate_split_header(ng)
    test_proxy_revalidate(ng)
    test_precise_maxage_token_parse(ng)
    test_ignore_cache_control_overrides_floor(ng, origin)
    test_ignore_cc_must_revalidate_keeps_stale_window(ng, origin)
    test_hits_for_exact_beyond_ring_size(ng, origin)        # A1: hits_for() Counter
    test_valid_zero_is_forever(ng, origin)
    test_honor_ttl_clamped_to_max(ng, origin)              # STAB-5 TTL clamp
    test_vary_encoding_qvalue(ng, origin)
    test_auto_vary_unknown_axis_uncacheable(ng, origin)
    test_auto_vary_stale_marker_reachable(ng, origin)
    test_206_never_cached(ng, origin)
    test_range_hit_matches_miss(ng, origin)
    test_range_suffix_hit_matches_miss(ng, origin)
    test_range_unsatisfiable_hit_matches_miss(ng, origin)
    test_range_not_offered_on_304(ng, origin)
    test_range_on_sie_serve(ng, origin)
    test_safe_key_distinct_sessionids(ng, origin)
    test_conditional_inm_304(ng, origin)
    test_conditional_inm_list_short_first(ng, origin)
    test_conditional_inm_star(ng)
    test_conditional_inm_mismatch_full(ng)
    test_conditional_ims_304(ng)
    test_conditional_ims_old_full(ng)
    test_conditional_inm_beats_ims(ng)
    test_rfc6_stale_conditional_full(ng, origin)
    test_rfc3_date_stable_across_hits(ng)
    test_rfc1_only_if_cached_miss_504(ng, origin)
    test_rfc1_only_if_cached_hit(ng, origin)
    test_rfc1_request_no_store(ng, origin)
    test_rfc1_request_max_age_zero_revalidates(ng, origin)
    test_rfc1_request_max_age_n(ng, origin)
    test_rfc1_request_min_fresh(ng, origin)
    test_rfc1_request_max_stale(ng, origin)
    test_p4_multi_directive_single_resolve(ng, origin)
    test_rfc2_swr_duration_extends_stale(ng, origin)
    test_purge_method(ng)
    test_cor5_l1only_variant_purge(ng, origin)
    test_cor5_l1only_variant_purge_gen_wrap(ng, origin)
    test_cache_and_purge_respect_access_control(ng)
    test_bypass(ng)
    test_bypass_uri(ng)
    test_bypass_uri_inert_after_internal_redirect(ng, origin)
    test_ctx_survives_error_page_internal_redirect(ng, origin)
    test_require_header(ng)
    test_key_cookie(ng)
    test_status_variable(ng)
    test_status_stale(ng, origin)
    test_status_expired(ng, origin)
    test_serve_reason_variable(ng, origin)                   # S7.2 unfolded serve reason
    test_request_cc_serve_verdict_fresh(ng, origin)
    test_request_cc_serve_verdict_stale(ng, origin)
    test_cc_mode_inheritance_child_preset_overrides_parent_ignore(ng, origin)
    test_no_store(ng)
    test_native_cache_headers_stripped(ng)
    test_admin_purge_post_with_body(ng)
    test_concurrent_hits_no_deadlock(ng)
    test_lru_eviction(ng)
    test_p1_coarse_lru_splice_keeps_hot_key_resident(ng)
    test_s8_scan_resistant_keeps_hot_key(ng)
    test_s8_default_off_is_unchanged(ng)
    test_s8_explicit_off_matches_absent(ng)
    test_s8_reload_on_to_off_drains_protected(ng)
    test_s8_scan_still_stores_and_evicts(ng)
    test_admin_stats(ng)
    test_admin_prometheus(ng)
    test_admin_purge_key(ng)
    test_admin_gating(ng)
    test_warm_populates(ng, origin)
    test_warm_multi(ng, origin)
    test_warm_no_url(ng)
    test_warm_strips_key_cookie(ng, origin)
    test_warm_rejects_traversal(ng, origin)
    test_warm_rejects_embedded_nul(ng, origin)
    test_warm_normal_url_still_warms(ng, origin)
    test_stale_serves_stale(ng, origin)
    test_single_flight(ng, origin)
    test_cold_single_flight(ng, origin)
    test_cold_lock_off_stampedes(ng, origin)
    test_min_uses(ng, origin)
    test_min_uses_off_by_default(ng)
    test_min_uses_band_aggressive(ng, origin)
    test_min_uses_band_balanced_is_1(ng, origin)
    test_min_uses_directive_beats_band(ng, origin)
    test_min_uses_rejects_out_of_range(ng)
    test_stale_if_error(ng, origin)
    test_stale_serves_stale_origin_hard_dead(ng, origin)
    test_sie_serve_on_error(ng, origin)                     # RFC-2 CTB4 serve-on-error
    test_sie_serve_on_error_unbuffered(ng, origin)          # AUD-SIE-BODY proxy_buffering off
    test_unbuf_streamed_store_and_hit(ng)                   # UNBUF streamed store + HIT round-trip
    test_unbuf_oversize_abort_mid_stream(ng, origin)        # UNBUF oversize mid-stream abort
    test_sie_serves_counter(ng, origin)                     # S7.1 sie_serves counter
    test_sie_origin_recovers_serves_fresh(ng, origin)       # RFC-2 success not hijacked
    test_keep_stale_serves_dead_origin(ng, origin)          # S2.2 keep_stale fallback
    test_keep_stale_loses_to_response_sie(ng, origin)       # S2.2 / D-1 precedence
    test_use_stale_http_404(ng, origin)                     # S4.2 mask selects trigger
    test_use_stale_any_5xx_bit(ng, origin)                  # S4.2 ANY_5XX bit
    test_use_stale_off(ng, origin)                          # S4.2 off = empty mask
    test_use_stale_403_429(ng, origin)                      # S4.2 non-5xx tokens
    test_keep_stale_no_reaper_lru_only_reclaim(ng, origin)  # S2.3 no-reaper contract
    test_5xx_never_overwrites_cached_body(ng, origin)       # O6/S3.1 5xx-never-clobbers
    test_5xx_cta_bypass_never_overwrites_cached_body(ng, origin)  # AUD-5XX-CTA
    test_background_update_off_regenerates_inline(ng, origin)
    test_normalize_arg_order(ng, origin)
    test_normalize_strips_tracking(ng, origin)
    test_normalize_strip_custom(ng, origin)
    test_normalize_strip_all(ng, origin)
    test_normalize_distinct_args_differ(ng, origin)
    test_normalize_vary_encoding(ng, origin)
    test_normalize_vary_device(ng, origin)
    test_normalize_vary_both(ng, origin)
    test_normalize_vary_off_by_default(ng, origin)
    test_normalize_vary_encoding_zstd(ng, origin)
    test_invalid_normalize_vary_token(ng)
    test_auto_vary_encoding(ng, origin)
    test_auto_vary_encoding_same_class_shares(ng, origin)
    test_auto_vary_device(ng, origin)
    test_auto_vary_language(ng, origin)
    test_auto_vary_language_primary_subtag_shares(ng, origin)
    test_auto_vary_language_different_primary_splits(ng, origin)
    test_auto_vary_language_absent_splits_from_class(ng, origin)
    test_auto_vary_origin(ng, origin)
    test_auto_vary_origin_not_class_folded(ng, origin)
    test_auto_vary_star_uncacheable(ng, origin)
    test_auto_vary_cookie_uncacheable(ng, origin)
    test_auto_vary_mixed_refused_wins(ng, origin)
    test_auto_vary_off_ignores_vary(ng, origin)
    test_preset_window_differs(ng, origin)
    test_stale_mult_directive_beats_preset(ng, origin)
    test_stale_mult_rejects_out_of_range(ng)
    test_preset_micro_default_ttl(ng, origin)
    test_invalid_preset_name(ng)
    test_autotune_raises_beta_within_band(ng, origin)
    test_autotune_load_factor_under_load(ng, origin)
    test_autotune_load_widens_stale_window(ng, origin)
    test_autotune_off_by_default(ng)
    test_autotune_insufficient_data(ng, origin)
    test_autotune_churn_disqualifies(ng, origin)
    if redis is not None:
        test_l2_write_through(ng, origin, redis)
        test_l2_negative_ttl_skips_repeat_get(ng, origin, redis)   # L13
        test_l2_negative_ttl_expires(ng, origin, redis)            # L13
        test_l2_negative_ttl_with_min_uses(ng, origin, redis)      # L13
        test_l2_negative_ttl_not_armed_by_outage(ng, origin, redis)  # L13-fix #5
        test_min_uses_counter_survives_uncacheable(ng, origin, redis)  # L13-fix CR-B
        # config-reject arm: no redis fixture needed, but its config anchor only
        # exists when the redis locations are emitted, so it lives in here too
        test_l2_negative_ttl_rejects_out_of_range(ng)              # L13
        test_l2_keepalive_reuse(ng, origin, redis)
        test_l2_keepalive_db_isolation(ng, origin, redis)
        test_l2_cross_instance_fill(ng, origin, redis)
        test_l2_purge_key_drops_l2(ng, origin, redis)
        test_l2_expired_consults_l2(ng, origin, redis)
        test_request_cc_serve_verdict_l2(ng, origin, redis)  # C-S5-a L2 verdict arm
        test_l2_promote_race_never_overwrites_newer_l1_entry(
            ng, origin, redis)                          # AUD-L2-PROMOTE-RACE
        test_l2_preserves_original_freshness(ng, origin, redis)
        test_l2_malformed_blob_rejected(ng, origin, redis)  # STAB-4 validate
        test_l2_forged_blob_cannot_inject_headers(ng, origin, redis)   # AUD-BLOBE2E1
        test_sie_forged_blob_cannot_inject_headers(ng, origin, redis)  # AUD-SIEBLOB1
        test_sie_ttl_stored_in_blob(ng, origin, redis)      # RFC-2 CTB4 sie_ttl
        test_l2_retain_ttl_covers_sie(ng, origin, redis)    # S1.2 retain_ttl
        test_l2_sie_serve_survives_l1_purge(ng, origin, redis)  # S1.2 e2e serve
        test_l2_stale_refetch_does_not_stall_on_lock(ng, origin, redis)  # V-HANG-2
        test_l2_unserveable_giveup_still_single_flights(ng, origin, redis)
        test_l2_tag_add_on_store(ng, origin, redis)
        test_l2_tag_truncation_warns(ng, origin, redis)
        test_l2_tag_purge(ng, origin, redis)
        test_l2_tag_purge_large(ng, origin, redis)  # STAB-3 + PERF-1/2 pipeline
        test_l2_tag_purge_arg_validation(ng, origin, redis)  # AUD-TAG1
        test_l2_tag_cap_and_dedup(ng, origin, redis)  # PERF-2 tag cap/dedup
        test_l2_tag_add_batched_one_op(ng, origin, redis)  # L9 one op for N tags
        test_cor5_redis_variant_purge(ng, origin, redis)  # COR-5 variant index
        test_multinode_lock(ng, origin, redis)
        test_lock_self_heal(ng, origin, redis)
        test_cold_single_flight_cross_node(ng, origin, redis)
        test_cross_node_winner_owner_token_preserved(ng, origin, redis)  # AUD-NXLOCK-OWNER
        test_l2_miss_counted_once_on_cold_park(ng, origin)  # double-count guard
        test_l2_db_select(ng, origin, redis)         # SELECT-only preamble
        # AUD-SCAN1: multi-page SCAN walks. Own ctscan: prefix, and they clean up
        # after themselves, so they must stay AHEAD of the two all-purge tests
        # below (the last of which deliberately empties L2).
        test_scan_walk_pool_is_o1_in_pages(ng, redis)
        test_scan_walk_page_cap_reports_incomplete(ng, redis)
        # AUD-PURGE-HONESTY1: shares the ctscan: prefix for its control leg, so
        # it belongs in this group and ahead of the all-purge tests below.
        test_all_purge_reports_l2_unavailable_when_backend_is_down(ng, redis)
        test_purge_all_escapes_redis_prefix_glob(ng, redis)
        test_purge_all_clears_l2(ng, origin, redis)  # last L2: empties L2
        test_lock_redis_outage_fallback(ng, origin, redis)  # NGX_ERROR lock fallback (stops/restarts redis)
    if redis_auth is not None:
        test_l2_dsn_auth_db(ng, origin, redis_auth)  # AUTH+SELECT preamble
        test_l2_keepalive_no_auth_replay(ng, origin, redis_auth)  # no replay on reuse
    if redis_tls is not None:
        test_l2_tls(ng, origin, redis_tls)           # rediss:// + verify
        test_l2_tls_keepalive_reuse(ng, origin, redis_tls)  # v15-2 TLS pool
        if redis is not None:
            # v16: plain + TLS profiles each keep their own keepalive bucket
            test_l2_keepalive_per_profile_no_starvation(
                ng, origin, redis, redis_tls)
    if redis_tls_untrusted is not None:
        test_redis_tls_untrusted_ca_rejected(ng, origin, redis_tls_untrusted)
    if redis_tls_expired is not None:
        test_redis_tls_expired_cert_rejected(ng, origin, redis_tls_expired)
    if mc is not None:
        test_l2_memcached_write_through(ng, origin, mc)        # v13
        test_l2_memcached_cross_instance_fill(ng, origin, mc)  # v13
        test_l2_memcached_purge_key_drops_l2(ng, origin, mc)   # v13
        if redis is not None:
            # child redis over parent memcached — precedence regression lock
            test_l2_backend_inheritance_child_redis_over_parent_memcached(
                ng, origin, redis, mc)
        test_mc_keepalive_reuse(ng, origin, mc)            # D-O1 reuse+re-pool
        test_mc_keepalive_zero_does_not_drain_pool(ng, origin, mc)  # MC-A2
        test_mc_keepalive_idle_timeout_drops(ng, origin, mc)  # D-O1 timedout br
        test_mc_dirty_reply_not_pooled(ng, origin)         # D-O2 clean-gate
        # D-O1 idle-pool close: MUST be last mc test — it stops the mc server.
        test_mc_keepalive_server_close_survives(ng, origin, mc)
    # PERF-7 zero-copy serve stress: run LAST among L1 tests — its 48-thread /
    # 4000-request eviction churn keeps the workers busy, so placing it before a
    # timing-sensitive test (e.g. stale-if-error's ~0.8s bg-refresh window) can
    # starve that window under the slow ASan build. Here it can't perturb others.
    test_perf7_zero_copy_serve_under_eviction(ng)
    test_shm_refresh_under_pressure(ng)
    test_admin_all_zero_does_not_purge(ng)
    test_admin_purge_all(ng)   # last: it empties the zone


def main() -> int:
    args = parse_args()
    binary = pathlib.Path(args.nginx_binary).resolve()
    module = pathlib.Path(args.module).resolve() if args.module else None
    if not binary.exists():
        raise FileNotFoundError(binary)
    if module is not None and not module.exists():
        raise FileNotFoundError(module)

    _check_port_registry(PORT_OFFSETS)

    origin_port = args.port + PORT_OFFSETS["origin"]
    redis_port = args.port + PORT_OFFSETS["redis"] if args.redis_server else None
    redis_auth_port = (
        args.port + PORT_OFFSETS["redis_auth"] if args.redis_server else None)
    redis_tls_port = (
        args.port + PORT_OFFSETS["redis_tls"] if args.redis_server else None)
    memcached_port = (
        args.port + PORT_OFFSETS["memcached"] if args.memcached_server else None)
    # mc_dirty_reply (+25) is claimed here too: test_mc_dirty_reply_not_pooled()
    # stands up its DirtyMemcached on `ng.port + PORT_OFFSETS["mc_dirty_reply"]`,
    # a call site nowhere near this block. See PORT_OFFSETS above -- that is
    # the registry a new fixture must check before picking an offset.
    redis_tls_untrusted_port = (
        args.port + PORT_OFFSETS["redis_tls_untrusted"] if args.redis_server else None)
    redis_tls_expired_port = (
        args.port + PORT_OFFSETS["redis_tls_expired"] if args.redis_server else None)
    redis_password = "ctsecret"
    # AUD-TESTFIX1: a fixture whose CLI flag was passed (--redis-server,
    # --memcached-server) must fail the run if it cannot start -- redis.start()
    # and mc.start() already raise uncaught, which is correct, leave them
    # alone. TLS is the one sub-fixture allowed to stay best-effort (needs a
    # TLS-capable redis-server build + working openssl), but "best-effort"
    # must never mean *silent*: every skip prints a loud, grep-able line and
    # is counted here so CI can assert the fixture set it asked for actually
    # came up instead of quietly losing ~80 L2/TLS tests off the running total.
    fixture_skips: list[str] = []

    def _skip(name: str, reason: str) -> None:
        line = f"FIXTURE SKIPPED: {name} ({reason})"
        print(line, flush=True)
        fixture_skips.append(name)

    with tempfile.TemporaryDirectory(prefix="cache-turbo-ci-") as tmp:
        root = pathlib.Path(tmp)
        origin = Origin(origin_port, delay=0.05)
        redis = redis_auth = redis_tls = mc = None
        redis_tls_untrusted = redis_tls_expired = None
        tls_certs = None
        if args.memcached_server:
            mc = MemcachedServer(pathlib.Path(args.memcached_server),
                                 memcached_port)
        if args.redis_server:
            rbin = pathlib.Path(args.redis_server)
            redis = RedisServer(rbin, root / "redis", redis_port)
            redis_auth = RedisServer(rbin, root / "redis-auth", redis_auth_port,
                                     password=redis_password)
            # TLS is best-effort: needs a TLS-capable redis + openssl. If either
            # is missing, skip the rediss:// tests rather than failing the
            # suite -- but loudly (see fixture_skips above).
            try:
                tls_certs = gen_tls_certs(root / "redis-tls-certs")
                redis_tls = RedisServer(rbin, root / "redis-tls", redis_tls_port,
                                        tls_certs=tls_certs)
                # AUD-TLS1 negative fixtures: a second, untrusted CA + an
                # expired-but-chain-trusted cert. Best-effort alongside the
                # base TLS fixture -- same openssl/redis-server dependency.
                untrusted_certs = gen_tls_certs(root / "redis-tls-untrusted-certs")
                redis_tls_untrusted = RedisServer(
                    rbin, root / "redis-tls-untrusted", redis_tls_untrusted_port,
                    tls_certs=untrusted_certs)
                expired_certs = gen_tls_expired_cert(
                    root / "redis-tls-expired-certs",
                    tls_certs["ca_key"], tls_certs["ca"])
                redis_tls_expired = RedisServer(
                    rbin, root / "redis-tls-expired", redis_tls_expired_port,
                    tls_certs=expired_certs)
            except (OSError, subprocess.SubprocessError) as e:
                _skip("redis_tls", f"cert/build generation failed: {e}")
                redis_tls = redis_tls_untrusted = redis_tls_expired = None
                tls_certs = None

        ng = Nginx(binary, module, root / "server", args.port, origin_port,
                   args.runner, args.single_process, redis_port,
                   redis_auth_port=redis_auth_port if redis_auth else None,
                   redis_password=redis_password,
                   redis_tls_port=redis_tls_port if redis_tls else None,
                   redis_tls_ca=(tls_certs or {}).get("ca"),
                   memcached_port=memcached_port if mc else None,
                   fault_injection=args.fault_injection,
                   redis_tls_untrusted_port=(
                       redis_tls_untrusted_port if redis_tls_untrusted else None),
                   redis_tls_expired_port=(
                       redis_tls_expired_port if redis_tls_expired else None))
        ng.sanitizer = args.sanitizer

        try:
            origin.start()
            if redis is not None:
                redis.start()
            if redis_auth is not None:
                redis_auth.start()
            if redis_tls is not None:
                redis_tls, redis_tls_untrusted, redis_tls_expired = (
                    _start_tls_fixtures(
                        redis_tls, redis_tls_untrusted, redis_tls_expired,
                        _skip))
            if mc is not None:
                mc.start()
            ng.write_config()
            ng.config_test()
            ng.start()
            _instrument(origin)   # DIAG: socket-flake attribution
            run_all(ng, origin, redis, redis_auth, redis_tls, mc,
                    redis_tls_untrusted, redis_tls_expired)
            time.sleep(0.2)
            ng.stop()
            ng.assert_clean_logs()
        finally:
            ng.stop()
            if redis is not None:
                redis.stop()
            if redis_auth is not None:
                redis_auth.stop()
            if redis_tls is not None:
                redis_tls.stop()
            if redis_tls_untrusted is not None:
                redis_tls_untrusted.stop()
            if redis_tls_expired is not None:
                redis_tls_expired.stop()
            if mc is not None:
                mc.stop()
            origin.stop()

        if fixture_skips:
            print(f"FIXTURE SUMMARY: {len(fixture_skips)} skipped: "
                  f"{', '.join(fixture_skips)}", flush=True)

    print("OK: miss/hit, POST passthrough uncached (origin do_POST harness), "
          "header fidelity, max_size, "
          "cacheability floor (Set-Cookie/CC-private/CC-no-store/Authorization "
          "not cached), default-key Host split, "
          "per-status caching (301/404 cached, HEAD not stored), "
          "honor upstream Cache-Control, "
          "Expires-only absolute TTL (upstream_ttl step 4), "
          "RFC 9213 targeted cache-control (CDN-CC/Surrogate-Control TTL "
          "precedence + no-store veto + stripped from serve), "
          "valid 0 = forever (fresh HIT, not instant-stale), "
          "TTL clamp to TTL_MAX (huge upstream max-age stays fresh, no overflow), "
          "Accept-Encoding q-value (gzip;q=0 != gzip bucket), "
          "auto-Vary unknown-axis uncacheable, "
          "auto-Vary stale-marker still reachable, 206 never cached, "
          "raw-key distinct sessionids (explicit request_uri key), "
          "conditional 304 (v11: If-None-Match/*/mismatch, "
          "If-Modified-Since fresh/stale, INM-beats-IMS precedence), "
          "PURGE method, COR-5 auto-Vary variant purge (L1-only gen-bump), "
          "bypass + no_store, DIY bypass_uri (v15: segment-boundary + subdir + "
          "non-boundary caches), backend_prefix malformed value rejected "
          "(item 18), DIY key_cookie (v15: value-keyed entries + anon "
          "bucket + exact-name + split-header + oversize values collapse to one "
          "bucket distinct from anon and from in-range, 256 still verbatim), "
          "$cache_turbo_status (MISS/HIT/BYPASS + bypasses counter, "
          "STALE serve, EXPIRED refetch), "
          "RFC-1 request Cache-Control serve verdict (fresh: max-age=0/min-fresh "
          "refuse fresh HIT + revalidate, bare max-stale still serves fresh; "
          "stale: default serves STALE, max-stale=0 refuses, max-stale=N/"
          "unparseable permit stale), "
          "cc_mode inheritance (child preset honor "
          "overrides parent ignore), "
          "native-cache headers stripped, "
          "admin purge w/ body, "
          "concurrency (R1), prometheus metrics (incl L2 hit/miss), "
          "default-key normalization, "
          "LRU eviction (R6), S8 scan-resistant segmented LRU (protected hot key survives a scan; default-off and explicit-off both still evict it; churn stores+evicts without wedging; config rejects; on->off across a REAL reload drains inherited PROTECTED nodes), refresh-under-pressure (R6b), "
          "stale serve (R3), single-flight (R4), "
          "cold-miss single-flight (v10: per-box collapse + lock-off stampede), "
          "min_uses (v15: cache after N misses + off-by-default; "
          "H3c: aggressive band=2, balanced band stays 1, directive beats band, "
          "range-checked), "
          "stale-if-error (v8), "
          "keep_stale (S2.2: serves a dead origin with no response "
          "stale-if-error, off surfaces the error; response stale-if-error "
          "wins over keep_stale, not max(); S2.3: no time-based reaper, "
          "LRU/max_size is the only reclaim), "
          "background_update off (v8 inline regen), "
          "admin stats/purge/gating, warm (v3-3: populates/multi/no-url), "
          "key normalize (v3-1: order/tracking/"
          "custom-strip/strip-all/distinct), "
          "vary suffix (v3-4: encoding/device/both/off-by-default, "
          "zstd>br bucket (V6), invalid-token rejected), "
          "auto-Vary (v11: encoding/same-class/device/language/origin split, "
          "Vary:*/Cookie/mixed-refused uncacheable, off-by-default ignores Vary), "
          "presets (v3-2: conservative/aggressive stale-window differ, "
          "explicit cache_turbo_stale_mult beats the band + range-rejects, "
          "invalid-name rejected), "
          "cookie predicate multi-match (guest cookie must not mask a member "
          "in the same header, both orders, two-guests still cacheable), "
          "2026 preset expansion (textpattern/bludit/spip/bugzilla/mantisbt/"
          "plone/umbraco/dotclear/wikijs: public HIT + state-cookie/URI/arg "
          "BYPASS, custom "
          "cookie-prefix predicates, backend_prefix rebasing; mantis/"
          "classicpress/backdrop aliases), "
          "header-auth REST surfaces (magento /rest+/soap, drupal /jsonapi+"
          "/oauth, wp ?rest_route=, /restaurant-supplies still cached), "
          "config maxima/warns (STAB-5 keepalive cap rejected, COR-9 dup-status "
          "warn, COR-0 tag-without-L2 warn), "
          "config-time rejects (cache_control bad-mode/duplicate, valid "
          "out-of-range code/bad time, require_header non-token/duplicate, "
          "redis DSN bad db, redis db out-of-range cap both arms), "
          "autotune (v4-3: raises beta within band/off-by-default/"
          "insufficient-data/churn-disqualify)"
          + (", L2 write-through (P4), "
             "L2 negative memo (L13: skips the repeat GET, expires, "
             "coexists with min_uses, range-checked incl. 0=off, "
             "survives its full window, NOT armed by an L2 outage, "
             "min_uses counter survives uncacheable teardown), "
             "keepalive pool reuse (v15), "
             "malformed L2 blob rejected pre-L1 (STAB-4), "
             "L2 cross-instance fill (P2), "
             "L2-aware key purge (P6), expired-L1 consults L2 (P6), "
             "tag index add (v2c), tag purge both tiers (P4), "
             "COR-5 Redis variant-index purge (both tiers), "
             "multi-node dogpile lock (v4-2 SET NX PX), lock self-heal (v4-2), "
             "cold-miss cross-node single-flight (v10), "
             "?all=1 clears L2 (v4-2 SCAN+DEL), "
             "DSN SELECT-db preamble (v5)"
             if redis_port else "")
          + (", DSN AUTH+SELECT preamble (v5)" if redis_auth else "")
          + (", rediss:// TLS + verify (v5), TLS keepalive reuse (v15-2)"
             + (", per-profile keepalive no-starvation (v16)" if redis_port else "")
             if redis_tls else "")
          + (", memcached L2 (v13: write-through, cross-instance fill, "
             "key purge)" if memcached_port else "")
          + (", backend-inheritance (child redis over parent memcached)"
             if (memcached_port and redis_port) else "")
          + (", alloc-fault fails-closed, file-backed sendfile delegate "
             "never stores" if ng.fault_injection else ""))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
