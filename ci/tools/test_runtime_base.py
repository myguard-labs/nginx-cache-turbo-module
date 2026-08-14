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
                if "midbody-mismatch" in self.path:
                    # S231-SIE-MIDBODY framing test: a body deliberately a
                    # DIFFERENT length than the already-primed snapshot for
                    # the same cache key ($uri excludes the query string this
                    # marker rides in on, so it does not create a new key).
                    # Content-Length below is correctly the length of THIS
                    # body -- that is the framing the client is told to
                    # expect, and the module's rescue must decline once the
                    # snapshot cannot match it. See
                    # test_sie_midbody_rescue_declines_on_length_mismatch.
                    body = f"gen-{n}-mismatch-longer-body\n".encode()
                else:
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
                if "sieshort" in self.path:
                    # Same convention as "sieserve" below, but a SHORT
                    # stale-if-error window so a test that only needs to cross
                    # the sie deadline (not exercise the full 30s) doesn't have
                    # to sleep 27s+ to get there. cache_turbo_valid (1s) sets
                    # the fresh TTL; sie_ttl = 1 + 5 = 6s -- deliberately past
                    # the location's own stale window (stale_mult default 4 =>
                    # 4s), so phase 1 of the discriminating test still lands
                    # inside the SIE window rather than the ordinary stale
                    # window. Drives test_keep_stale_loses_to_response_sie.
                    self.send_header("Cache-Control", "stale-if-error=5")
                elif "sieserve" in self.path:
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

        # S231-L2-BACKOFF (TLS follow-up): same untrusted-CA backend as
        # /l2tlsuntrusted/ above, but with connect_backoff armed. Every
        # request's TLS handshake fails cert verification -- a TERMINAL
        # handshake failure, not a TCP connect refusal -- so this proves the
        # backoff also arms off the TLS path, not just a plain-TCP connect()
        # error. cache_turbo_lock off for the same reason as /l2backoff/: one
        # L2 attempt per request, exact counter deltas.
        location /l2tlsbackoff/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 1s;
            cache_turbo_lock  off;
            cache_turbo_redis rediss://127.0.0.1:{redis_tls_untrusted_port}/0 tls_ca={redis_tls_ca} tls_name=localhost prefix=ctbotls: connect_backoff=5000ms;
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
            # S231-DEFAULTS: pinned off. retain_ttl = max(stale_window,
            # sie_window) folds keep_stale's window into the L2 (Redis) PTTL
            # (module.c ~7705) -- left at the new 24h default,
            # test_l2_write_through's PTTL bound (<=120s, i.e. valid*4) would
            # fail because the stored blob would carry a ~24h TTL instead.
            cache_turbo_keep_stale off;
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
            cache_turbo_stale_mult 1;
            # S231-DEFAULTS: pinned off. keep_stale widens the blob's sie_ttl
            # field the same way a response stale-if-error does (module.c
            # ~7705, S2.2) -- left at the new 24h default,
            # test_sie_ttl_stored_in_blob's "no stale-if-error header -> sie_ttl
            # == 0" negative control would fail (sie_ttl would carry
            # fresh_ttl+86400 instead).
            cache_turbo_keep_stale off;
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

        # S231-L2-SCANTIME. /_cache_scandeadline sets scan_deadline=1ms -- far
        # below any real page round-trip over TCP, so a walk spanning 2+ pages
        # is deterministically past it by the second page boundary (no timing
        # band: 1ms is chosen to be unmeetable, not "usually enough"). The page
        # cap stays at its production value so only the deadline can explain an
        # abort at scan_pages < the cap. /_cache_scandeadlineoff is the negative
        # control: same location shape, scan_deadline=0 (disabled), so a walk
        # spanning the same number of pages must complete normally.
        location = /_cache_scandeadline {{
            cache_turbo_admin    main;
            cache_turbo_redis    127.0.0.1:{redis_port} db=7 prefix=ctscan: timeout=2s scan_deadline=1ms;
            allow 127.0.0.1;
            deny all;
        }}

        location = /_cache_scandeadlineoff {{
            cache_turbo_admin    main;
            cache_turbo_redis    127.0.0.1:{redis_port} db=7 prefix=ctscan: timeout=2s scan_deadline=0;
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

        # S231-L2-BACKOFF: per-worker L2 connect backoff. Same dead peer as
        # /_cache_scandown (redis_dead offset, never bound -> every connect
        # is refused), but wired to a normal GET/miss location so it goes
        # through ngx_http_cache_turbo_redis_get -> launch(), the fail-fast
        # choke point, not the admin scan path.
        #
        # /l2backoff/ arms a 5s window: request 1 pays the real refused
        # connect() (the ordinary per-request path), request 2 must fail
        # fast on the SAME worker without another connect attempt. Both are
        # indistinguishable from the client's perspective (both a plain L2
        # miss -> origin serve) -- the oracle is the X-Cache-Turbo-Test-L2-
        # Backoff counter (TEST_FAULTS-only), never response equality.
        # cache_turbo_lock off: this location's job is purely to exercise the
        # L2 connect path, not the cold-miss cross-node NX lock. With locking
        # on, a dead L2 peer makes every miss retry through the cold-miss
        # WAIT poll (module.c's cold_wait_ev/cold_wait_timeout), which was
        # measured to leave a timer armed past its owning request's response
        # in a way that can outlive a since-closed keepalive connection and
        # crash the worker on shutdown (pre-existing race, unrelated to L2
        # backoff, ledgered in issues.md). Locking off avoids that path
        # entirely and is irrelevant to what this fixture tests.
        location /l2backoff/ {{
            cache_turbo                    main;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_lock               off;
            cache_turbo_redis              127.0.0.1:{port + PORT_OFFSETS["redis_dead"]} prefix=ctbo: timeout=250ms connect_backoff=5000ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Negative control: connect_backoff=0 (disabled) against the SAME
        # dead peer -- every request must pay its own connect failure, so the
        # counter never moves no matter how many requests land back to back.
        # Same cache_turbo_lock off reasoning as /l2backoff/ above.
        location /l2backoffoff/ {{
            cache_turbo                    main;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_lock               off;
            cache_turbo_redis              127.0.0.1:{port + PORT_OFFSETS["redis_dead"]} prefix=ctboo: timeout=250ms connect_backoff=0;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-COLDWAIT-UAF repro: live redis (cache_turbo_lock default ON),
        # short lock_timeout so the 100ms cold_wait poll fires repeatedly
        # against LOSER requests parked behind a same-key cross-node NX
        # lock while the winner regenerates from a deliberately slow
        # origin. This is the fixture that reproduces the cold-wait poll
        # timer double-free (issues.md "cold-wait poll timer double-frees
        # the request"): a loser's kept-alive connection is aborted by the
        # client WHILE parked in cold_wait, independently of the poll
        # timer; nginx's own connection-close path can finalize+free `r`
        # before the already-armed cold_wait_ev fires via
        # ngx_event_expire_timers(), which then calls
        # ngx_http_cache_turbo_cold_wait_timeout() -> ...
        # -> ngx_http_finalize_request() a second time on freed memory.
        location /coldwaituaf/ {{
            cache_turbo                    main;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_lock_timeout        2s;
            cache_turbo_redis              127.0.0.1:{redis_port} prefix=ctcw: timeout=250ms;
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

        # S231-L2-BACKOFF, memcached side. Same dead-peer/cache_turbo_lock off
        # shape as /l2backoff/ above (redis_dead offset -- never bound, plain
        # TCP refuse works identically for either driver's connect()).
        location /mcbackoff/ {{
            cache_turbo            main;
            cache_turbo_key        $uri;
            cache_turbo_valid      1s;
            cache_turbo_lock       off;
            cache_turbo_memcached  127.0.0.1:{port + PORT_OFFSETS["redis_dead"]} prefix=mcbo: timeout=250ms connect_backoff=5000ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
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
            cache_turbo_stale_mult              1;
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

        # S231-SIE-MIDBODY: same short fresh/stale window + "sieserve" marker
        # convention as /sieserve/ so a warmed key gets a serve-on-error
        # snapshot armed (sie_armed), but the fault fires in the BODY filter
        # instead of driving the origin to a real 5xx -- cache_turbo_test_
        # midbody_abort treats the first arriving body buffer as a mid-body
        # origin death regardless of what status the origin actually sent.
        # This is the header-filter trigger's blind spot: that trigger only
        # ever sees r->headers_out.status, and a mid-body death arrives with
        # headers already serialised as a normal 200. Drives
        # test_sie_midbody_rescue.
        location /midbody/ {{
            cache_turbo                  main;
            cache_turbo_key              $uri;
            cache_turbo_valid            1s;
            cache_turbo_stale_mult       1;
            cache_turbo_keep_stale       off;
            cache_turbo_test_midbody_abort on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-SIE-MIDBODY negative control: identical fault directive, but
        # NO stale-if-error window ever gets armed (no "sieserve" marker in
        # the key, so sie_armed stays 0 for every request). Proves the fault
        # cannot fabricate a body out of nothing -- with nothing armed the
        # rescue's own `ctx->sie_armed` guard must refuse it and the
        # (truncated-by-the-fault) response must pass through unchanged.
        location /midbodycold/ {{
            cache_turbo                  main;
            cache_turbo_key              $uri;
            cache_turbo_valid            30s;
            cache_turbo_test_midbody_abort on;
            proxy_pass http://127.0.0.1:{origin_port}/;
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
    # /breakeron/ and /breakeroff/'s own zone (S231-DEFAULTS) -- see the
    # comment on /breakeron/ below for why this can no longer share `main`.
    cache_turbo_zone name=brkonoffz 16m;
    # S231-DEFAULTS: own zone for /brkdefault/ (compiled-in shipped-default
    # breaker), same reasoning as brkiz above -- tripping it must not perturb
    # /breakeron/'s state on `main`.
    cache_turbo_zone name=brkdefz 16m;
    # S232-BYPASS-STALE: own zone for /bstale/, same isolation reasoning as
    # brkiz -- tripping the breaker there must not perturb any other location.
    cache_turbo_zone name=bstalez 16m;
    # S232-BYPASS-STALE: a SECOND zone for the tests that must run against a
    # CLOSED breaker. breaker_open is 30s, so a test that trips /bstale/ leaves
    # that zone's breaker OPEN far longer than the suite takes to reach the
    # next test -- sharing one zone made the no-trip controls 503 on a breaker
    # someone else tripped, measuring nothing about their own subject.
    cache_turbo_zone name=bstalecz 16m;
    # S232-BYPASS-STALE: a THIRD zone for the never-primed control, which trips
    # its own breaker. It cannot share bstalez: the feature test trips that one
    # and breaker_open holds it OPEN for 30s, so this test's own priming
    # request would 503 on someone else's breaker before it measured anything.
    cache_turbo_zone name=bstalenz 16m;
    # S232-BYPASS-STALE: a FOURTH zone for the safety control, which also trips
    # its own breaker. Every bypass-stale test that trips one needs a private
    # zone: breaker_open holds the state OPEN for 30s, far longer than the gap
    # between two tests, so a shared zone makes the SECOND test 503 on the
    # FIRST test's breaker before it can prime.
    cache_turbo_zone name=bstalesz 16m;
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
    cache_turbo_zone name=s231ncz 16m;   # S231-NOCACHE-OUTAGE (breaker gets tripped OPEN)
    cache_turbo_zone name=s231nccz 16m;  # S231-NOCACHE-OUTAGE negative control (breaker CLOSED)
    cache_turbo_zone name=s231ncvz 16m;  # S231-NOCACHE-OUTAGE ordering (auto-Vary)
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
    # S231-EVICT-BLIND: private tiny zone (64k == enforced minimum, same
    # reasoning as srz/ksevz above -- a handful of unique keys genuinely
    # overflow it and force real eviction) with its own breaker, so tripping
    # it OPEN and filling the zone cannot perturb any other zone's breaker
    # state or LRU contents.
    cache_turbo_zone name=evblindz 64k;
    # S231-PERF-MISSLOCKS: private zone for /mmulock/'s concurrent min_uses +
    # cache_turbo_lock race (a second worker claiming the key between what
    # used to be count_miss()'s and claim()'s separate mutex acquisitions).
    # NOT `main` -- min_uses_skips and lock_waits are zone-global counters and
    # `main` already carries traffic from 166+ other locations by the time
    # this runs, so a delta-based assert here needs its own zone + admin
    # endpoint for the same reason storefailz does.
    cache_turbo_zone name=mmulockz 16m;

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
        # shape as /sieserve/ (1s fresh, stale_mult 1 -> 1s stale window, fully
        # expired by ~1.3s) but with the rngsrc+rngsie markers so the stored
        # blob is Range-capable AND carries stale-if-error=30. Drives
        # test_range_on_sie_serve.
        location /rangesie/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 1s;
            cache_turbo_stale_mult 1;
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

        # RFC-2 stale-if-error serve-on-error (CTB4). Short fresh (1s, stale_mult
        # 1 -> 1s stale window, fully expired by ~1.3s). The origin emits
        # stale-if-error=30 ONLY when the request suffix carries the "sieserve"
        # marker (proxy_pass strips the /sieserve/ prefix), so a /sieserve/sieserve-*
        # key gets a serve-on-error window and a /sieserve/plain-* key does NOT.
        # The plain-* key is the negative control: an expired entry with no SIE
        # window must surface the origin error. Drives test_sie_serve_on_error.
        location /sieserve/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_stale_mult 1;
            # S231-DEFAULTS: pinned off. The no-SIE negative controls here
            # (test_sie_serve_on_error, test_sie_serves_counter) rely on a
            # PLAIN expired entry surfacing the origin's 503 directly -- left
            # at the new 24h default, cache_turbo_keep_stale would serve it
            # stale via S2.2 instead and make those negative controls vacuous.
            cache_turbo_keep_stale off;
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
            cache_turbo_stale_mult 1;
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
        # Short fresh (1s) / stale (stale_mult 1 -> 1s) window like /sieserve/ so
        # the entry is fully expired quickly. Drives test_keep_stale_serves_dead_origin.
        location /keepstale/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_stale_mult 1;
            cache_turbo_keep_stale 1h;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-DEFAULTS: NO cache_turbo_keep_stale directive at all -- proves
        # the compiled-in merge default is 24h, not just that `24h;` works
        # when written out explicitly (every /keepstale*/ location above opts
        # in explicitly). Same short fresh/stale shape as /keepstale/ (1s
        # fresh, stale_mult 1 -> 1s stale window) so a dead-origin fetch
        # against a fully expired entry isolates the shipped default rather
        # than the explicit 1h window. Drives
        # test_keep_stale_shipped_default_serves_dead_origin.
        location /ksdefault/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_stale_mult 1;
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
            cache_turbo_stale_mult 1;
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
            cache_turbo_stale_mult 1;
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
            cache_turbo_stale_mult 1;
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
            cache_turbo_stale_mult 1;
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
            cache_turbo_stale_mult 1;
            cache_turbo_keep_stale 1h;
            cache_turbo_use_stale http_403 http_429;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # O4.4: the circuit breaker's own on/off switch (cache_turbo_breaker),
        # independent of the threshold/window off-switches the config-parse
        # tests already cover. NO keep_stale/use_stale window here on purpose:
        # once the entry is past its stale window (1s fresh, stale_mult 1 -> 1s
        # stale) the ONLY thing that can still answer a dead origin with a cached body is
        # the breaker's own any-age fallback (call site 1 in
        # ngx_http_cache_turbo_access_handler) -- so this isolates that call
        # site's routing through breaker_should_consult() rather than
        # overlapping RFC-2/keep_stale, which have their own coverage above.
        # Drives test_breaker_arming_gated_on_breaker_enable. Own zone
        # (brkonoffz), not `main`: S231-DEFAULTS made breaker_enable/
        # threshold/window shipped-on by default, so `main`'s ~120+ other
        # locations (which set no breaker directives at all) now pick up the
        # compiled-in defaults (5/10s) -- sharing `main` here would make this
        # location's deliberately-fast explicit tuple (threshold=1/window=60s,
        # chosen to trip on a single request) diverge from that ambient
        # default and trip the O4.4-d policy-divergence warning on every
        # config load. /breakeroff/ shares brkonoffz with this location (they
        # need to compare against each other, not against `main`).
        location /breakeron/ {{
            cache_turbo                    brkonoffz;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_stale_mult          1;
            # keep_stale is ALSO on by default now (S231-DEFAULTS, 24h) and
            # would mask the dead origin behind S2.2's serve-on-error
            # fallback before the tripping request ever reached it -- off
            # here so this isolates the breaker call site alone.
            cache_turbo_keep_stale          off;
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
        # armed or consulted. keep_stale off for the same reason as
        # /breakeron/ above (S231-DEFAULTS): it would otherwise mask the
        # dead origin via S2.2 regardless of the breaker flag, making this
        # negative control vacuous.
        location /breakeroff/ {{
            cache_turbo                    brkonoffz;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_stale_mult          1;
            cache_turbo_keep_stale          off;
            cache_turbo_breaker             off;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-DEFAULTS: NO cache_turbo_breaker/threshold/window directives at
        # all -- proves the compiled-in merge defaults are breaker_enable=1,
        # breaker_threshold=5, breaker_window=10s, not just that `on;
        # threshold 1; window 60s;` works when written out explicitly (every
        # /breaker*/ location above opts in explicitly). Own zone so tripping
        # it here cannot perturb /breakeron/'s counters on `main`. threshold=5
        # means five failing responses are needed to trip CLOSED -> OPEN (vs.
        # threshold=1 on /breakeron/), so the test below drives five tripping
        # fetches before the sixth observes the tripped state. Drives
        # test_breaker_shipped_default_trips_and_serves_stale.
        location /brkdefault/ {{
            cache_turbo             brkdefz;
            cache_turbo_key         $uri;
            cache_turbo_valid       1s;
            cache_turbo_stale_mult  1;
            cache_turbo_lock_timeout 2s;
            # keep_stale is now ALSO on by default (S231-DEFAULTS, 24h) and
            # would mask a dead origin behind S2.2's serve-on-error fallback
            # before the breaker ever gets a chance to trip -- explicitly off
            # here so this location isolates the breaker default alone.
            cache_turbo_keep_stale  off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S232-BYPASS-STALE. /bstale/api/ is opted in to breaker-only storage;
        # /bstale/plain/ is NOT, and is the negative control proving the
        # directive is scoped rather than blanket. threshold=1 so a single dead
        # -origin request trips CLOSED -> OPEN. keep_stale off for the same
        # reason as /brkdefault/: it would answer from the stale entry before
        # the breaker could trip, masking what these tests measure.
        location /bstale/ {{
            cache_turbo             bstalez;
            cache_turbo_key         $uri;
            cache_turbo_valid       1s;
            cache_turbo_stale_mult  1;
            cache_turbo_keep_stale  off;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            cache_turbo_bypass_stale_uri  /bstale/api;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S232-BYPASS-STALE, safety control. Own zone + own breaker to trip,
        # for the same 30s-open-window reason as /bstalen/ below.
        location /bstales/ {{
            cache_turbo             bstalesz;
            cache_turbo_key         $uri;
            cache_turbo_valid       1s;
            cache_turbo_stale_mult  1;
            cache_turbo_keep_stale  off;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            cache_turbo_bypass_stale_uri  /bstales/api;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S232-BYPASS-STALE, never-primed control. Its own zone + its own
        # breaker to trip, so it never races the feature test's 30s open window.
        location /bstalen/ {{
            cache_turbo             bstalenz;
            cache_turbo_key         $uri;
            cache_turbo_valid       1s;
            cache_turbo_stale_mult  1;
            cache_turbo_keep_stale  off;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            cache_turbo_bypass_stale_uri  /bstalen/api;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S232-BYPASS-STALE, CLOSED-breaker half. Same directives as /bstale/
        # but on its own zone and with the breaker left at its default (never
        # tripped here), so the normal-path and scope controls measure their
        # own subject rather than a breaker some earlier test opened.
        location /bstalec/ {{
            cache_turbo             bstalecz;
            cache_turbo_key         $uri;
            cache_turbo_valid       1s;
            cache_turbo_stale_mult  1;
            cache_turbo_keep_stale  off;
            cache_turbo_bypass_stale_uri  /bstalec/api;
            add_header              X-CT-Status $cache_turbo_status always;
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
            cache_turbo_keep_stale         off;  # S231-DEFAULTS: isolate dead-origin arming from the 24h keep_stale default
            cache_turbo_stale_mult          1;
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
            cache_turbo_keep_stale         off;  # S231-DEFAULTS: isolate dead-origin arming from the 24h keep_stale default
            cache_turbo_stale_mult          1;
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
            # S231-DEFAULTS: pinned off explicitly. This location does not
            # exercise the breaker; left at the (now shipped-on) default it
            # would diverge from /sr72brk/'s deliberately fast explicit tuple
            # (threshold=1/window=60s) on this shared zone and trip the
            # O4.4-d policy-divergence warning on every config load.
            cache_turbo_breaker off;
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
            cache_turbo_stale_mult 1;
            # S231-DEFAULTS: see /sr72/ above -- same reason, pinned off.
            cache_turbo_breaker off;
            add_header         X-CT-Reason $cache_turbo_serve_reason always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S7.2: $cache_turbo_serve_reason coverage, STALE-BREAKER + BREAKER-503
        # arms. Same shape as /s71brk/ (1s fresh, stale_mult 1 -> 1s stale,
        # threshold=1) but on sr72z: the /dead key gets primed then trips the breaker OPEN, the
        # /never key is NEVER primed so once the breaker is OPEN it has no
        # armed copy at all and falls into breaker_unavailable() (BREAKER-503).
        # Drives test_serve_reason_variable.
        location /sr72brk/ {{
            cache_turbo                    sr72z;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_keep_stale         off;  # S231-DEFAULTS: isolate dead-origin arming from the 24h keep_stale default
            cache_turbo_stale_mult          1;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            add_header         X-CT-Reason $cache_turbo_serve_reason always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-NOCACHE-OUTAGE: private zone for the "honour cache instead of a
        # client's Cache-Control: no-cache while the origin is known down" gate
        # (:4749 in ngx_http_cache_turbo_module.c). Own zone (s231ncz), not
        # sr72z/brkiz/s71z/etc: this location primes then trips ITS OWN breaker
        # OPEN, which must not perturb any other test's CLOSED-breaker
        # expectations on a shared zone. threshold=1/stale_mult=1/keep_stale off
        # mirror /sr72brk/'s fast-trip shape. Drives
        # test_nocache_breaker_open_honours_cache and
        # test_nocache_breaker_closed_still_revalidates (negative control).
        location /s231nc/ {{
            cache_turbo                    s231ncz;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_keep_stale         off;  # isolate from the 24h keep_stale default
            cache_turbo_stale_mult          1;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            add_header         X-CT-Reason $cache_turbo_serve_reason always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-NOCACHE-OUTAGE negative control: identical shape to /s231nc/ but
        # on its OWN zone (s231nccz) that is NEVER tripped -- proves the fix
        # only kicks in while the breaker is actually OPEN, not unconditionally.
        # Drives test_nocache_breaker_closed_still_revalidates. Also carries
        # the only-if-cached-out-of-scope regression pin
        # (test_nocache_only_if_cached_still_504), since that arm is unaffected
        # by breaker state either way and needs no tripping.
        location /s231ncc/ {{
            cache_turbo                    s231nccz;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_keep_stale         off;
            cache_turbo_stale_mult          1;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            add_header         X-CT-Reason $cache_turbo_serve_reason always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-NOCACHE-OUTAGE ordering-hazard regression: same breaker shape as
        # /s231nc/ but with auto-Vary on, on its OWN zone (s231ncvz) so tripping
        # this breaker cannot perturb /s231nc/'s. The gate at :4749 runs BEFORE
        # ngx_http_cache_turbo_vary_resolve() (:4762) -- falling through on a
        # breaker-OPEN no-cache request must still resolve the variant key
        # before the cache lookup below it runs, or a varying URL would probe
        # the BASE key and silently serve the wrong (or no) variant. Drives
        # test_nocache_breaker_open_varying_url_serves_correct_variant.
        location /s231ncv/ {{
            cache_turbo                    s231ncvz;
            cache_turbo_key                $request_uri;
            cache_turbo_valid               30s;
            cache_turbo_auto_vary           on;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            add_header         X-CT-Reason $cache_turbo_serve_reason always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-NOCACHE-OUTAGE ordering-hazard breaker trigger: SAME zone
        # (s231ncvz) as /s231ncv/ above -- the breaker STATE is per-zone, so
        # tripping it here also flips /s231ncv/'s view of the breaker -- but a
        # SHORT cache_turbo_valid (1s) of its own, distinct from /s231ncv/'s
        # 30s. This lets the tripping key (/dead) expire and trip fast while
        # the gzip/br variants primed on /s231ncv/ stay comfortably fresh for
        # the whole sequence. Drives
        # test_nocache_breaker_open_varying_url_serves_correct_variant.
        location /s231ncvbrk/ {{
            cache_turbo                    s231ncvz;
            cache_turbo_key                $request_uri;
            cache_turbo_valid               1s;
            cache_turbo_keep_stale         off;
            cache_turbo_stale_mult          1;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
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
            cache_turbo_keep_stale         off;  # S231-DEFAULTS: isolate dead-origin arming from the 24h keep_stale default
            cache_turbo_stale_mult          1;
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
            cache_turbo_keep_stale         off;  # S231-DEFAULTS: isolate dead-origin arming from the 24h keep_stale default
            cache_turbo_stale_mult          1;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open        2s;
            cache_turbo_breaker_retry_after 7s;
            cache_turbo_lock_timeout        2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S7.1: breaker_serves / origin_failures counter coverage. Same shape
        # as /breakeron/ (1s fresh, stale_mult 1 -> 1s stale, threshold=1) but on its own
        # zone (s71z) so the admin JSON delta is not polluted by /breakeron/'s
        # or /brkion/'s already-tripped breaker. Drives test_breaker_counters.
        location /s71brk/ {{
            cache_turbo                    s71z;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_keep_stale         off;  # S231-DEFAULTS: isolate dead-origin arming from the 24h keep_stale default
            cache_turbo_stale_mult          1;
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
        # tripped (same 1s-fresh/stale_mult-1-1s-stale/threshold=1 shape as /s71brk/) so
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
            cache_turbo_keep_stale         off;  # S231-DEFAULTS: isolate dead-origin arming from the 24h keep_stale default
            cache_turbo_stale_mult           1;
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
            cache_turbo_keep_stale         off;  # S231-DEFAULTS: isolate dead-origin arming from the 24h keep_stale default
            cache_turbo_stale_mult           1;
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
            cache_turbo_keep_stale         off;  # S231-DEFAULTS: isolate dead-origin arming from the 24h keep_stale default
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
            cache_turbo_stale_mult          1;
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
        # (explicit -- S231-DEFAULTS made 24h the default, so this is no
        # longer "the default", it is an opt-out) -> an expired entry with a
        # dead origin must surface the error (502), not serve stale. Proves
        # the positive result above is actually caused by keep_stale, not
        # some other widening.
        location /keepstaleoff/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_stale_mult 1;
            cache_turbo_keep_stale off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Precedence test: both a response stale-if-error AND cache_turbo_keep_stale
        # are in play here. keep_stale is a generous 1h baseline; the response's
        # own stale-if-error=5 (via the "sieshort" request-suffix marker -- a
        # short-window sibling of the "sieserve" convention used by /sieserve/)
        # must WIN -- sie_window = ttl + 5, not ttl + 3600 and not max() of the
        # two. Drives test_keep_stale_loses_to_response_sie.
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
        # inverse of outage resilience). Short fresh/stale window (1s / x4=4s,
        # default stale_mult) so the entry goes stale quickly; the 503 negative
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

        # S231-PERF-AUTOCLASSIFY negative control: the presets below had no
        # dedicated runtime-test location at all before this change, so their
        # cookie needles were exercised only by the fuzz corpus (crash safety)
        # and never asserted classified-dynamic here. Added to prove the
        # first-byte prefilter cannot make a needle unreachable -- see
        # test_cookie_prefilter_negative_control().
        location /ct-drupal/ {{
            cache_turbo         main;
            cache_turbo_backend drupal;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-mediawiki/ {{
            cache_turbo         main;
            cache_turbo_backend mediawiki;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-ghost/ {{
            cache_turbo         main;
            cache_turbo_backend ghost;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-wagtail/ {{
            cache_turbo         main;
            cache_turbo_backend wagtail;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-kirby/ {{
            cache_turbo         main;
            cache_turbo_backend kirby;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-typo3/ {{
            cache_turbo         main;
            cache_turbo_backend typo3;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-vanilla/ {{
            cache_turbo         main;
            cache_turbo_backend vanilla;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-punbb/ {{
            cache_turbo         main;
            cache_turbo_backend punbb;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-phorum/ {{
            cache_turbo         main;
            cache_turbo_backend phorum;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-yabb/ {{
            cache_turbo         main;
            cache_turbo_backend yabb;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-flarum/ {{
            cache_turbo         main;
            cache_turbo_backend flarum;
            cache_turbo_key     $uri;
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

        # S231-PERF-AUTOCLASSIFY (args half) negative control: ghost/mediawiki/
        # yabb have non-empty args[] rows but no dedicated arg-classification
        # location elsewhere in this config. $uri$is_args$args in the key so
        # distinct query strings do not collapse onto one cache entry.
        location /ct-ghost-args/ {{
            cache_turbo         main;
            cache_turbo_backend ghost;
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-mediawiki-args/ {{
            cache_turbo         main;
            cache_turbo_backend mediawiki;
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-yabb-args/ {{
            cache_turbo         main;
            cache_turbo_backend yabb;
            cache_turbo_key     $uri$is_args$args;
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

        # S231-EVICT-BLIND: private tiny zone (evblindz, 64k) + own breaker
        # (threshold=1, same trip shape as /s71brk/). proxy_pass is the bare
        # origin root (not /sieserve/) so callers choose per-key whether the
        # upstream response carries a stale-if-error window: /evblind/sieserve/*
        # gets one (fresh=1s + stale-if-error=30 -> sie_ttl=31s from creation,
        # SIE-live for the whole test), /evblind/_trip_plain does not, which is
        # what lets the trip fetch surface the origin's raw failure instead of
        # a 200 STALE-IF-ERROR replay. Drives test_evict_blind_second_chance:
        # fills the zone while the breaker is OPEN (must still store, never
        # ENOMEM/store failure) and pins that a live-SIE entry survives
        # exactly one eviction pass, not every pass.
        location /evblind/ {{
            cache_turbo                     evblindz;
            cache_turbo_key                 $uri;
            cache_turbo_valid               1s;
            cache_turbo_keep_stale          off;  # S231-DEFAULTS: isolate dead-origin arming from the 24h keep_stale default, same as /s71brk/
            cache_turbo_stale_mult          1;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window      10s;
            cache_turbo_breaker_open        30s;
            add_header                      X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        location = /_cache_evblind {{
            cache_turbo_admin    evblindz;
            allow 127.0.0.1;
            deny all;
        }}

        # S231-PERF-MISSLOCKS: min_uses > 1 AND cache_turbo_lock on (the
        # default) TOGETHER -- the exact combination the merged resolve_miss()
        # path covers. lock_ttl left short so a losing waiter does not have to
        # wait long, and lock_timeout is generous so a slow CI runner cannot
        # make a genuine waiter give up and stampede the origin, which would
        # look like a correctness failure but would only be scheduling noise.
        location /mmulock/ {{
            cache_turbo               mmulockz;
            cache_turbo_key           $uri;
            cache_turbo_valid         30s;
            cache_turbo_min_uses      3;
            cache_turbo_lock          on;
            cache_turbo_lock_ttl      2s;
            cache_turbo_lock_timeout  5s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        location = /_cache_mmulock {{
            cache_turbo_admin    mmulockz;
            allow 127.0.0.1;
            deny all;
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

        # auto-Vary explicitly OFF (S231-VARY: no longer the shipped default --
        # see /avdefault/ below for that): the same response Vary header is
        # ignored, so two encodings collapse onto one slot (back-compat proof
        # for an operator who opts back out).
        location /avoff/ {{
            cache_turbo          main;
            cache_turbo_key      $request_uri;
            cache_turbo_valid    30s;
            cache_turbo_auto_vary off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-VARY: NO cache_turbo_auto_vary directive at all -- this is the
        # only location that proves the *compiled-in* default rather than an
        # explicit `on;` (every /av/ location above opts in explicitly). Must
        # behave exactly like /av/: safe axes split, Vary: Cookie is refused.
        location /avdefault/ {{
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
            cache_turbo_keep_stale         off;  # S231-DEFAULTS: isolate dead-origin arming from the 24h keep_stale default
            cache_turbo_stale_mult          1;
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


def wait_for_l2_absent(redis, key: str, what: str = "",
                       timeout: float = 2.0, interval: float = 0.02) -> None:
    """Wait until `key` is GONE from L2, then return.

    The counterpart to wait_for_l2 below, and the ordering primitive a test
    needs between an L2-aware PURGE and a set_raw() that writes the key back.

    PURGE returning 200 means the module ACCEPTED the purge, not that the Redis
    DEL has already been executed. A test that PURGEs and immediately
    set_raw()s the same key is racing the module: when the DEL lands late it
    deletes the blob the test just wrote, and the failure surfaces at the NEXT
    read as "the value I wrote is absent" -- which reads as Redis latency and
    was mis-ledgered as exactly that three times.

    Waiting for absence first makes the write unambiguously the last operation
    on the key. Deliberately NOT a swallow: a key still present at the deadline
    raises, because that means the purge genuinely did not happen and the test
    that follows would be testing the wrong object
    ([[feedback-widening-shared-timeout-disables-oracle]])."""
    start = time.monotonic()
    while True:
        if redis.get_raw(key) is None:
            return
        remaining = timeout - (time.monotonic() - start)
        if remaining <= 0:
            break
        time.sleep(min(interval, remaining))

    elapsed = time.monotonic() - start
    label = f" for {what}" if what else ""
    raise AssertionError(
        f"L2 key{label} still present {elapsed:.2f}s after PURGE returned 200 "
        f"(timeout {timeout:.2f}s): key={key!r}\n"
        f"  The module accepted the purge but the Redis DEL never landed, so "
        f"anything written to this key now may still be deleted afterwards.")


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


# ---------------------------------------------------------------------------
# Shared test helpers (MAINT-T1).
#
# These were interleaved with the tests before the split, but each is used
# from more than one area module. They live here rather than in an area so
# the areas stay independent of each other -- an area importing an area
# would be an import cycle, since the dependencies run both ways.
# ---------------------------------------------------------------------------

# The directive line the separator tests rewrite. Kept as one constant so a
# config reshuffle breaks these loudly (via the `old in cfg` assert) instead of
# silently skipping them.
_BACKEND_LINE = "cache_turbo_backend wordpress woocommerce joomla;"


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


def _fetch_keepalive(conn: http.client.HTTPConnection, path: str,
                      headers: dict | None = None):
    """GET on an ALREADY-OPEN HTTPConnection, without closing it. nginx pins
    every request on one accepted TCP connection to whichever worker accepted
    it, so this is what makes a same-worker request sequence possible against
    the harness's 4-worker default (fetch() sends `Connection: close` and
    opens a fresh socket per call, which round-robins across workers and
    cannot pin anything -- measured: two ordinary fetch() calls landed on
    different worker PIDs, so a second call's fail-fast state was for a
    worker the first call never touched).

    `headers`, if given, are merged with the mandatory keep-alive header
    (caller's values win on collision)."""
    req_headers = {"Connection": "keep-alive"}
    if headers:
        req_headers.update(headers)
    conn.request("GET", path, headers=req_headers)
    resp = conn.getresponse()
    body = resp.read().decode("utf-8", "replace")
    return (resp.status, body, {k.lower(): v for k, v in resp.getheaders()})


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


def _admin_lock_waits(ng: Nginx, path: str = "/_cache") -> int:
    """Default path reads zone `main`'s admin endpoint; pass path= for a
    private-zone endpoint like /_cache_s71 or /_cache_storefail so the
    lock_waits delta is not polluted by unrelated locations sharing `main`."""
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
    _, b, _ = fetch(ng.port, path)
    return int(json.loads(b).get(name, 0))


def _admin_str(ng: Nginx, name: str, path: str = "/_cache") -> str:
    """String-valued sibling of _admin_stat, for breaker_state (the only
    non-numeric field on the admin JSON). Deliberately defaults to "" rather
    than "closed" on a missing key: a build that stopped emitting the field
    must fail the assertion, not read as the state the caller hoped for."""
    _, b, _ = fetch(ng.port, path)
    return str(json.loads(b).get(name, ""))


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
    _, b, _ = fetch(ng.port, endpoint)
    return int(json.loads(b).get("min_uses_skips", 0))


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


# Response-header names arrive lower-cased from fetch()'s dict.
_ARMINGS_HDR = "x-cache-turbo-test-armings"
_BACKOFF_HDR = "x-cache-turbo-test-l2-backoff"

def _backoff_skips(hdrs: dict, where: str, driver: str = "redis") -> int:
    """Pull ONE driver's lifetime L2-connect-backoff fail-fast counter out of
    a response's headers (S231-L2-BACKOFF, TEST_FAULTS-only).

    Mirrors _armings() above: the header carries both drivers as
    `redis=<n>,memcached=<n>` so an assertion on one driver cannot be
    satisfied by the other driver's counter moving. A missing header or
    missing key is a hard failure, not a skip -- same reasoning as _armings:
    its absence would make every delta read 0 and the test would pass while
    proving nothing."""
    assert driver in ("redis", "memcached"), f"unknown backoff driver {driver!r}"
    raw = hdrs.get(_BACKOFF_HDR)
    assert raw is not None, (
        f"{_BACKOFF_HDR} missing on {where} -- this build has no backoff "
        f"counter, so the S231-L2-BACKOFF control cannot distinguish "
        f"'fail-fast fired' from 'never checked'")
    parts = dict(
        kv.split("=", 1) for kv in raw.split(",") if "=" in kv
    )
    assert driver in parts, (
        f"{_BACKOFF_HDR} on {where} is {raw!r}, which carries no {driver!r} "
        f"key -- the header format drifted and this assertion would silently "
        f"measure nothing")
    return int(parts[driver])


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


def _redis_conns_received(redis: RedisServer) -> int:
    """Redis' monotonic count of accepted client connections (INFO stats)."""
    for line in redis.cli("INFO", "stats").splitlines():
        if line.startswith("total_connections_received:"):
            return int(line.split(":", 1)[1])
    raise RuntimeError("total_connections_received absent from INFO stats")


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
