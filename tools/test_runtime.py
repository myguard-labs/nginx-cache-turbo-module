#!/usr/bin/env python3
"""End-to-end tests for ngx_http_cache_turbo_module.

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
import concurrent.futures
import email.utils
import hashlib
import http.client
import http.server
import json
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


def wait_port(port: int, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.25):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"port 127.0.0.1:{port} never came up")


def fetch(port: int, path: str, headers: dict | None = None,
          method: str | None = None, data: bytes | None = None):
    """Return (status, body_str, response_headers_dict). `data` sends a request
    body (method must be given explicitly; urllib would otherwise silently flip
    a GET into a POST the moment data is set)."""
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
        with urllib.request.urlopen(req, timeout=5) as r:
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
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
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
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
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
        self.fail = False          # when True, every GET answers 503 (v8 SIE)
        self.drop = False          # when True, every GET drops the connection
                                   # with no response (transport-level failure:
                                   # nginx sees a 502, a different error class
                                   # than the clean 503 `fail` mode — Goal-2
                                   # hard-dead-upstream coverage)
        self._n = 0
        self._paths: list[tuple[float, str]] = []   # DEBUG: (time, path) log
        self._lock = threading.Lock()
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def hits(self) -> int:
        with self._lock:
            return self._n

    def hits_for(self, needle: str) -> int:
        """Count origin GETs whose path contains `needle`. Path-scoped, so a
        test using a unique URL is immune to other tests' async bg-refresh
        traffic bumping the global `hits` counter between its base capture and
        its assertion (the test_206_never_cached deflake)."""
        with self._lock:
            return sum(1 for _, p in self._paths if needle in p)

    def start(self) -> None:
        origin = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_HEAD(self):  # noqa: N802
                # A HEAD must reach the origin (no body); the module must NOT
                # store it as the GET entry.
                with origin._lock:
                    origin._n += 1
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
                if origin.drop:
                    self.close_connection = True
                    return
                if origin.fail:
                    self.send_response(503)
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
                    self.send_response(503)
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


def nginx_config(root: pathlib.Path, port: int, module: pathlib.Path | None,
                 origin_port: int, workers: int,
                 redis_port: int | None = None,
                 redis_auth_port: int | None = None,
                 redis_password: str | None = None,
                 redis_tls_port: int | None = None,
                 redis_tls_ca: str | None = None,
                 memcached_port: int | None = None,
                 fault_injection: bool = False) -> str:
    """Build the generated nginx.conf for the test server.

    !! ASCII ONLY -- everything returned here, INCLUDING COMMENTS, is written
    with encoding="ascii" (see Nginx.write_config). A single non-ASCII byte
    anywhere in this function (a stray arrow, dash, or warning sign pasted into
    a location comment) raises UnicodeEncodeError before a single test runs, and
    the traceback points at write_text, not at the comment you added. Use "!!",
    "->" and plain hyphens.
    """
    load = f"load_module {module};\n" if module else ""

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
            cache_turbo                  main;
            cache_turbo_key              $uri;
            cache_turbo_valid            30s;
            cache_turbo_min_uses         4;
            cache_turbo_l2_negative_ttl  3;
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
            cache_turbo                  main;
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
            cache_turbo                  main;
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

        # admin endpoint that is itself L2-aware: a single-key purge here must
        # also DEL the entry from Redis (P6), not just drop L1.
        location = /_cache_l2 {{
            cache_turbo_admin    main;
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
        # by tools/ci-build.sh and are absent from production/package builds.
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
"""

    # Root-anchored punbb URI rows, one prefix location each (see the comment at
    # the use site for why this is not a single regex location).
    punbb_root_locs = "".join(f"""
        location /{s}.php {{
            cache_turbo         main;
            cache_turbo_backend punbb;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}""" for s in ("edit", "delete", "moderate", "profile", "register",
                       "userlist", "search"))

    return f"""{load}worker_processes {workers};
pid {root}/nginx.pid;
error_log {root}/logs/error.log notice;

events {{ worker_connections 512; }}

http {{
    access_log off;

    cache_turbo_zone name=main 16m;
    cache_turbo_zone name=tiny 8m;   # small zone for eviction test (R6)
    cache_turbo_zone name=shmref 16m; # refresh-under-pressure (R6b)
    cache_turbo_zone name=at 16m;    # autotune raise/clamp/off (v4-3)
    cache_turbo_zone name=atl 16m;   # autotune load-adaptive stale widen (v4-4)
    cache_turbo_zone name=ati 16m;   # autotune insufficient-data (v4-3)
    cache_turbo_zone name=atch 16m;  # autotune churn-disqualify (v4-3)
    cache_turbo_zone name=ka0 8m;    # Redis keepalive DB-isolation test
    cache_turbo_zone name=ka1 8m;    # Redis keepalive DB-isolation test

    # Q1 end-to-end: stacked native proxy_cache, one zone per suppress mode, so
    # a test can prove cache_turbo_suppress_native actually keeps the native
    # cache empty (vs the inert default where proxy_cache stores normally).
    proxy_cache_path {root}/pcache_on  keys_zone=ctpcon:1m  levels=1:2
                     inactive=10m max_size=64m;
    proxy_cache_path {root}/pcache_off keys_zone=ctpcoff:1m levels=1:2
                     inactive=10m max_size=64m;

    server {{
        listen 127.0.0.1:{port};
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

        # ignore_cc vs must-revalidate: cache_turbo_cache_control ignore must
        # make the ENTIRE response Cache-Control inert, not just the cacheability
        # floor. The origin emits "max-age=1, must-revalidate"; without ignore
        # the must-revalidate token collapses the stale window (like /mrev/), but
        # with ignore the window stays valid*stale_mult (1s*4), so at ~2s
        # the entry is still STALE-served, not a hard miss. fresh = valid 1s
        # (ignore forces honor off). beta 1 ~never rolls a refresh, so the
        # stale read is a clean STALE serve (no dice regen polluting origin).
        location /ccignmr/ {{
            cache_turbo               main;
            cache_turbo_key           $uri;
            cache_turbo_valid         1s;
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
        location /woo/ {{
            cache_turbo         main;
            cache_turbo_backend woocommerce;
            cache_turbo_key     $uri$is_args$args;
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

        # joomla public content: where the joomla_remember_me_ cookie rule and the
        # unmatchable md5 session cookie are exercised.
        location /jm/ {{
            cache_turbo         main;
            cache_turbo_backend joomla;
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
        # yabb is the same shape as smf -- one YaBB.pl entry script dispatching
        # on ?action=<route> -- so it too is exercised from a prefixed location.
        location /yabb/ {{
            cache_turbo         main;
            cache_turbo_backend yabb;
            cache_turbo_key     $request_uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # phorum is a flat top-level-script app: its URI rules are real root
        # paths, so they must be root locations to be exercised at all.
        location /admin.php {{
            cache_turbo         main;
            cache_turbo_backend phorum;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # file.php is phorum's permission-checked attachment download. Same
        # reason as above: the row anchors at byte 0, so only a root location
        # exercises it.
        location /file.php {{
            cache_turbo         main;
            cache_turbo_backend phorum;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # punbb's URI rules are root scripts too, so each needs its own root
        # location. userlist.php is here on purpose: the preset deliberately
        # does NOT list it, so it is the negative control. Written as prefix
        # locations rather than one regex -- the CI nginx is built without PCRE
        # and rejects a regex location outright.
        {punbb_root_locs}

        # Forum presets whose cookie rules were corrected after the docs
        # deep-research pass (punbb / vanilla / phorum). Their cookie rules are
        # path-independent, so a prefixed location exercises them; the URI rules
        # anchor at position 0 and are not what these locations test.
        location /punbb/ {{
            cache_turbo         main;
            cache_turbo_backend punbb;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /vanilla/ {{
            cache_turbo         main;
            cache_turbo_backend vanilla;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /phorum/ {{
            cache_turbo         main;
            cache_turbo_backend phorum;
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

        # ---- ghost ---------------------------------------------------------
        location /ghost/ {{
            cache_turbo         main;
            cache_turbo_backend ghost;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # The public blog: must cache for anonymous readers. Also where the
        # ?uuid=/?key= cookieless member auth is exercised.
        location /blog/ {{
            cache_turbo         main;
            cache_turbo_backend ghost;
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ---- wagtail -------------------------------------------------------
        # URI prefixes anchor at position 0 -> ROOT locations. Every "must
        # bypass" URI needs a REAL location: without one, nginx's implicit 404
        # also carries no x-cache header and the assertion would pass for free.
        location /admin/ {{
            cache_turbo         main;
            cache_turbo_backend wagtail;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /django-admin/ {{
            cache_turbo         main;
            cache_turbo_backend wagtail;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # Permission-checked (serve_view enforces per-collection privacy).
        location /documents/ {{
            cache_turbo         main;
            cache_turbo_backend wagtail;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # The public site + /search/. Both MUST stay cacheable for anonymous
        # readers -- including a guest carrying csrftoken, which Django hands to
        # anyone who renders a form. /search/ is dynamic but anonymous-identical,
        # so bypassing it would be a pure hit-rate loss.
        location /wt/ {{
            cache_turbo         main;
            cache_turbo_backend wagtail;
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /search/ {{
            cache_turbo         main;
            cache_turbo_backend wagtail;
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ---- kirby ---------------------------------------------------------
        location /panel {{
            cache_turbo         main;
            cache_turbo_backend kirby;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # Segment-boundary matcher proof: "/panel" must NOT swallow an unrelated
        # public path that merely shares the prefix. "/panels-and-doors" is a
        # different path segment (next byte is 's', not '/' or '.') so it must
        # CACHE. Without the boundary check the bare prefix test bypassed it.
        location /panels-and-doors {{
            cache_turbo         main;
            cache_turbo_backend kirby;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # The flat-file public site: the whole point of the preset. Must cache.
        # /media/ is NOT a preset URI (static assets, no permission view) so it
        # must cache too -- asserting that guards against someone "helpfully"
        # adding it later.
        location /kb/ {{
            cache_turbo         main;
            cache_turbo_backend kirby;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /media/ {{
            cache_turbo         main;
            cache_turbo_backend kirby;
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

        # ---- shopware6 -----------------------------------------------------
        # Preset URI bypasses. Each needs a REAL location: a URI with no location
        # gets nginx's implicit 404, which carries no x-cache, so a "must bypass"
        # assert would pass for free and prove nothing.
        # X-CT-Status makes BYPASS a positive signal -- "x-cache is absent" is not
        # proof the URI rule fired, because a plain first-request MISS has no
        # x-cache either. Without this header a preset with an EMPTY uri list
        # would still pass the bypass asserts below.
        location /account {{
            cache_turbo         main;
            cache_turbo_backend shopware6;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            add_header          X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /store-api {{
            cache_turbo         main;
            cache_turbo_backend shopware6;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            add_header          X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # The storefront: sw-cache-hash is VALUE-KEYED here, never bypassed.
        # X-CT-Status is what lets the transition-race test tell "the Set-Cookie
        # floor REFUSED the store" (MISS) apart from "bypassed for some other
        # reason" (BYPASS) -- a bare != HIT cannot distinguish them.
        location /sw/ {{
            cache_turbo         main;
            cache_turbo_backend shopware6;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            add_header          X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ---- typo3 ---------------------------------------------------------
        location /typo3 {{
            cache_turbo         main;
            cache_turbo_backend typo3;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # Segment-boundary proof: /typo3 must not swallow a public page that
        # merely shares the prefix.
        location /typo3-guide {{
            cache_turbo         main;
            cache_turbo_backend typo3;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # X-CT-Status makes the bypass a POSITIVE signal. Asserting only that
        # x-cache is ABSENT is not enough: any unrelated reason to not cache also
        # removes x-cache, so such a test passes even when the cookie rule was
        # never consulted (a dropped cookie literal then goes undetected -- this
        # exact hole let a sabotage canary through during development).
        location /t3/ {{
            cache_turbo         main;
            cache_turbo_backend typo3;
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

        # ---- discourse ----------------------------------------------------
        # URI prefixes anchor at position 0, so these must be ROOT locations.
        location /session {{
            cache_turbo         main;
            cache_turbo_backend discourse;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /u/ {{
            cache_turbo         main;
            cache_turbo_backend discourse;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
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
        # Ships NO cookie rule (all three phpBB cookies are set for guests and
        # the matcher has no value predicate). URI + ?sid= only.
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

        # ---- drupal -------------------------------------------------------
        # Ships NO cookie rule (SESS would substring-match PHPSESSID/JSESSIONID).
        location /user {{
            cache_turbo         main;
            cache_turbo_backend drupal;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # /admin is a preset URI rule too and needs its own ROOT location, or a
        # fetch of /admin/config falls through to nginx's implicit 404 -- which
        # carries no x-cache header either, so a "must bypass" assertion would
        # pass without the preset ever running.
        location /admin {{
            cache_turbo         main;
            cache_turbo_backend drupal;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
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
        location /dr/ {{
            cache_turbo         main;
            cache_turbo_backend drupal;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ---- mediawiki ----------------------------------------------------
        location /index.php {{
            cache_turbo         main;
            cache_turbo_backend mediawiki;
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # /wiki/ is the CACHEABLE read path -- proves the preset does not just
        # bypass the whole wiki. Cookie + arg rules exercised from here.
        location /wiki/ {{
            cache_turbo         main;
            cache_turbo_backend mediawiki;
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   30s;
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
                 fault_injection=False) -> None:
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
        self.process: subprocess.Popen | None = None
        self.output_path = root / "nginx-output.log"

    def write_config(self) -> None:
        workers = 1 if self.single_process else 4
        (self.root / "conf").mkdir(parents=True, exist_ok=True)
        (self.root / "logs").mkdir(parents=True, exist_ok=True)
        (self.root / "conf" / "nginx.conf").write_text(
            nginx_config(self.root, self.port, self.module,
                         self.origin_port, workers, self.redis_port,
                         self.redis_auth_port, self.redis_password,
                         self.redis_tls_port, self.redis_tls_ca,
                         self.memcached_port, self.fault_injection),
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
            raise AssertionError("nginx logged fatal:\n" + "\n".join(fatal))


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
    return {"ca": str(ca), "cert": str(crt), "key": str(key)}


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

    def stop(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=10)
        self.process = None


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
        conn = http.client.HTTPConnection("127.0.0.1", ng.port, timeout=5)
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
    list. The hidden directive exists only in tools/ci-build.sh builds."""
    def assert_failed_closed(path: str, forbidden_status: int,
                             forbidden_header: str | None = None) -> None:
        try:
            status, _, headers = fetch_raw(ng.port, path)
        except http.client.RemoteDisconnected:
            return  # nginx aborted before sending any partial header block
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


def test_file_backed_delegate_never_stores(ng: Nginx,
                                            origin: Origin) -> None:
    """A file-backed (sendfile) response body cannot be captured from memory,
    so the body filter must abort capture and delegate the UNMODIFIED chain
    downstream -- the object is served correctly but never cached. The hidden
    cache_turbo_test_force_file_buf directive drives that branch
    deterministically (the real in_file trigger is directio/fs dependent). The
    directive exists only in tools/ci-build.sh builds."""
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


def test_auto_backend_composition(ng: Nginx, origin: Origin) -> None:
    """cache_turbo_backend composes only the named presets: a woocommerce-only
    location skips on a woo session cookie but NOT on a wordpress login cookie
    (which that preset does not know about), so the WP-cookie page still caches
    — proving the presets are selective, not a blanket union."""
    woo = {"Cookie": "woocommerce_cart_hash=abc123"}
    _, _, hw1 = fetch(ng.port, "/woo/cartpage", headers=woo)
    _, _, hw2 = fetch(ng.port, "/woo/cartpage", headers=woo)
    assert "x-cache" not in hw1 and "x-cache" not in hw2, \
        "woo session cookie must skip on the woocommerce backend"

    wp = {"Cookie": "wordpress_logged_in_x=1"}
    fetch(ng.port, "/woo/wppage", headers=wp)
    _, _, hp2 = fetch(ng.port, "/woo/wppage", headers=wp)
    assert hp2.get("x-cache") == "HIT", \
        f"woo backend should ignore a WP cookie and cache, got {hp2.get('x-cache')}"
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


def test_wordpress_search_and_preview(ng: Nginx, origin: Origin) -> None:
    """WordPress ?s= (site search) must CACHE; ?preview= must BYPASS.

    The search assertion is INVERTED from what the preset used to ship. `s` was
    a bare-name arg rule, so every site search bypassed. That bought nothing: a
    logged-out visitor's results are ANONYMOUS-IDENTICAL (everyone searching
    "foo" gets the same page), and a logged-in editor whose results include
    drafts is already bypassed by wordpress_logged_in_ on the cookie tier.

    It was also the wrong direction on load. A bypass returns NGX_DECLINED
    before the single-flight lock, so a bypassed request gets no miss-collapsing
    -- a ?s= flood put 100% of its load on the origin, uncollapsed, on the most
    expensive query WordPress runs. ct_wagtail_* (/search/ absent) and the
    mediawiki registry's refusal of a blanket action= rule already argued this
    case; the WordPress row was the outlier.

    ?preview= is asserted in the same test because it is the OTHER arg row, and
    the failure mode of "fix search by emptying ct_wp_args" is that preview goes
    with it. A preview renders an unpublished revision."""
    # Search results are shared across logged-out visitors -> must cache.
    for uri in ("/wpq/index?s=foo", "/wpq/index?s=hello+world", "/wpq/?s=x"):
        fetch(ng.port, uri)
        _, _, hs = fetch(ng.port, uri)
        assert hs.get("x-cache") == "HIT", \
            (f"{uri} is an anonymous-identical search result and must cache -- "
             f"bypassing it is a hit-rate loss AND an uncollapsed origin flood, "
             f"got {hs.get('x-cache')}")

    # Distinct search terms must not collide (the key carries the query string).
    _, b1, _ = fetch(ng.port, "/wpq/index?s=alpha")
    _, b2, _ = fetch(ng.port, "/wpq/index?s=beta")
    assert b1 != b2, "distinct ?s= terms must not share a cache entry"

    # A logged-in editor's search DOES include drafts -- the cookie tier is what
    # covers that, and it must still fire on a search URL.
    ed = {"Cookie": "wordpress_logged_in_abc123=alice|1|deadbeef"}
    fetch(ng.port, "/wpq/index?s=draft", headers=ed)
    _, _, he = fetch(ng.port, "/wpq/index?s=draft", headers=ed)
    assert "x-cache" not in he, \
        ("a logged-in editor's search may include drafts and private posts -- "
         f"wordpress_logged_in_ must bypass it, got {he.get('x-cache')}")

    # ?preview= renders an unpublished revision -> must never be stored.
    for uri in ("/wpq/post-1?preview=true", "/wpq/post-1?p=9&preview=true"):
        fetch(ng.port, uri)
        _, _, hp = fetch(ng.port, uri)
        assert "x-cache" not in hp, \
            (f"{uri} renders an UNPUBLISHED revision and must bypass, got "
             f"{hp.get('x-cache')}")
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


def test_xenforo_preset(ng: Nginx, origin: Origin) -> None:
    """XenForo preset (docs/xenforo.md).

    xf_session MUST BYPASS, and that assertion is INVERTED from the original
    preset on purpose. It is the regression guard for a real cross-user leak.

    STOCK XF2 HAS NO LOGIN-ONLY COOKIE. xf_user is the REMEMBER-ME cookie only
    (completeLogin() mints it inside `if ($remember)`, and "Stay logged in" is
    unticked by default), so an ordinary member who just types their password
    carries ONLY xf_session. This test used to assert that xf_session "must stay
    cacheable" -- which meant that member's authenticated page was stored and
    served to strangers. Bypassing on xf_session is the only cookie-only fix; it
    costs hit rate (XF's session is lazy, so clean guests still cache, but a guest
    who logs out / trips 2FA / hits a captcha acquires one) and that is the trade.

    Do not "optimise" xf_session back out. That is the leak."""
    # URI prefixes (root locations — the prefixes anchor at position 0). /api/ is
    # the REST API: it auths on the XF-Api-Key HEADER, invisible to every cookie
    # rule, so a shared cache keyed on URL alone would serve one API client's
    # private response to the next. It MUST bypass on the URI.
    for uri in ("/login", "/misc/style", "/api/threads/1/"):
        _, _, h = fetch(ng.port, uri)
        assert "x-cache" not in h, f"{uri} must bypass on the xenforo preset"

    # _xfToken is XF's CSRF token as a query arg (logout link, style-variation
    # switcher). Its value is per-session, so any GET carrying it is per-user and
    # must never be cached or served across visitors. (arg rules are
    # path-independent, so the /xf/ prefix exercises them.)
    _, _, ht1 = fetch(ng.port, "/xf/thread-tok?_xfToken=1650000000,abcdef")
    _, _, ht2 = fetch(ng.port, "/xf/thread-tok?_xfToken=1650000000,abcdef")
    assert "x-cache" not in ht1 and "x-cache" not in ht2, \
        "a GET carrying _xfToken must bypass -- the CSRF token is per-session"

    # Every auth signal bypasses. xf_session is here because it is the ONLY cookie
    # an ordinary (non-remember-me) login carries; xf_lscxf_logged_in is the
    # LiteSpeed plugin's true login-only cookie, present only if that plugin runs.
    for ck in ("xf_user=1234%2Cabcdef", "xf_session_admin=deadbeef",
               "xf_session=membersess123", "xf_lscxf_logged_in=1"):
        _, _, h1 = fetch(ng.port, "/xf/thread-a", headers={"Cookie": ck})
        _, _, h2 = fetch(ng.port, "/xf/thread-a", headers={"Cookie": ck})
        assert "x-cache" not in h1 and "x-cache" not in h2, \
            (f"cookie {ck.split('=')[0]} must bypass -- a session-only login "
             "carries xf_session and NOTHING else, so caching it leaks")

    # A cookieless guest still caches. This is what stops the xf_session rule from
    # being a blanket hit-rate zero: XF's session is LAZY, so a clean first-time
    # visitor who stores nothing in it is issued no cookie at all.
    fetch(ng.port, "/xf/thread-b")
    _, _, hg = fetch(ng.port, "/xf/thread-b")
    assert hg.get("x-cache") == "HIT", \
        f"a cookieless XF guest must still cache, got {hg.get('x-cache')}"

    # Presentation variants are VALUE-KEYED (tier-3 key_cookies), not bypassed and
    # not presence-keyed: xf_style_id (multi-style board), xf_style_variation
    # (XF 2.3 light/dark within a style) and xf_language_id. Each is a SHARED
    # variant -- everyone on dark theme sees the same page -- so it must cache,
    # repeat-hit its OWN entry, and NOT collide with a different value.
    for name in ("xf_style_variation", "xf_style_id", "xf_language_id"):
        va = {"Cookie": f"{name}=aaaa"}
        _, ba1, _ = fetch(ng.port, f"/xf/variant-{name}", headers=va)
        _, ba2, hs = fetch(ng.port, f"/xf/variant-{name}", headers=va)
        assert hs.get("x-cache") == "HIT" and ba1 == ba2, \
            f"{name} must be KEYED and repeat-hit its own entry, got {hs.get('x-cache')}"
        # A different value must not be served the first value's cached body.
        vb = {"Cookie": f"{name}=bbbb"}
        _, bb1, _ = fetch(ng.port, f"/xf/variant-{name}", headers=vb)
        assert bb1 != ba1, \
            f"{name}: a different value was served another variant's cached body"
        _, bb2, hb = fetch(ng.port, f"/xf/variant-{name}", headers=vb)
        assert hb.get("x-cache") == "HIT" and bb2 == bb1, \
            f"{name}: each value must warm and hit its OWN entry"

    # EVERY declared key cookie is folded, not just the first one present.
    # The preset declares xf_style_id, xf_style_variation and xf_language_id;
    # if the key stopped at the first match, two requests that agree on
    # xf_style_id and differ on xf_language_id would share ONE entry -- a
    # German reader served the English page, and the same cookie the operator
    # asked to vary on silently ignored. Hold the earlier cookie fixed and vary
    # only the later one.
    both_en = {"Cookie": "xf_style_id=7; xf_language_id=en"}
    both_de = {"Cookie": "xf_style_id=7; xf_language_id=de"}
    _, b_en, _ = fetch(ng.port, "/xf/multikey", headers=both_en)
    _, _, h_en = fetch(ng.port, "/xf/multikey", headers=both_en)
    assert h_en.get("x-cache") == "HIT", \
        f"the multi-cookie combination must warm its own entry, got {h_en.get('x-cache')}"
    _, b_de, h_de = fetch(ng.port, "/xf/multikey", headers=both_de)
    assert h_de.get("x-cache") != "HIT" and b_de != b_en, \
        ("a second key cookie behind the first one is not folded into the key: "
         f"xf_language_id=de was served the =en entry ({h_de.get('x-cache')})")
    _, b_de2, h_de2 = fetch(ng.port, "/xf/multikey", headers=both_de)
    assert h_de2.get("x-cache") == "HIT" and b_de2 == b_de, \
        "each key-cookie combination must warm and hit its OWN entry"

    # Symmetrically, varying only the EARLIER cookie must still split, so the
    # fold cannot be reduced to "the last cookie wins" either.
    other_style = {"Cookie": "xf_style_id=9; xf_language_id=en"}
    _, b_o, h_o = fetch(ng.port, "/xf/multikey", headers=other_style)
    assert h_o.get("x-cache") != "HIT" and b_o != b_en, \
        "a different xf_style_id at the same language must key to its own entry"
    drain_origin(origin)


def test_xenforo_not_in_generic(ng: Nginx, origin: Origin) -> None:
    """xenforo is opt-in and must NOT be folded into generic/auto: its URIs
    (/login, /register, /contact, /misc) are generic English words that a
    non-forum site can legitimately serve as cacheable pages. A `generic`
    location must therefore still cache them, and must ignore xf_ cookies."""
    fetch(ng.port, "/gen/login")
    _, _, h = fetch(ng.port, "/gen/login")
    assert h.get("x-cache") == "HIT", \
        f"generic must NOT pull in the xenforo URI rules, got {h.get('x-cache')}"

    xf = {"Cookie": "xf_user=1234%2Cabcdef"}
    fetch(ng.port, "/gen/page", headers=xf)
    _, _, hx = fetch(ng.port, "/gen/page", headers=xf)
    assert hx.get("x-cache") == "HIT", \
        f"generic must NOT pull in the xenforo cookie rules, got {hx.get('x-cache')}"
    drain_origin(origin)


def test_discourse_preset(ng: Nginx, origin: Origin) -> None:
    """Discourse preset (docs/discourse.md). `_t` is the auth token and bypasses.
    `_forum_session` is the Rails session cookie that Discourse hands to EVERY
    visitor including guests, and theme_ids/forced_color_mode are presentation
    variants — all three must keep caching. Bypassing on _forum_session would be
    the xf_session mistake again: it would drop all guest traffic out of the
    cache, which is a performance bug, not a safety one."""
    _, _, h = fetch(ng.port, "/session")
    assert "x-cache" not in h, "/session must bypass on the discourse preset"

    # /u/ (public profiles) is NO LONGER a bypass rule: profiles are anon-
    # identical and Discourse's own anon cache caches them, so they must cache.
    fetch(ng.port, "/u/someone")
    _, _, hu = fetch(ng.port, "/u/someone")
    assert hu.get("x-cache") == "HIT", \
        f"/u/ public profile must cache now, got {hu.get('x-cache')}"

    # Auth token bypasses on an otherwise cacheable page.
    tok = {"Cookie": "_t=abc123deadbeef"}
    _, _, h1 = fetch(ng.port, "/dc/topic-a", headers=tok)
    _, _, h2 = fetch(ng.port, "/dc/topic-a", headers=tok)
    assert "x-cache" not in h1 and "x-cache" not in h2, "_t must bypass"

    # Guest Rails session must NOT bypass.
    guest = {"Cookie": "_forum_session=guestsess123"}
    fetch(ng.port, "/dc/topic-b", headers=guest)
    _, _, hg = fetch(ng.port, "/dc/topic-b", headers=guest)
    assert hg.get("x-cache") == "HIT", \
        f"guest _forum_session must stay cacheable, got {hg.get('x-cache')}"

    # Theme / colour-mode variants must NOT bypass (they belong in the key).
    var = {"Cookie": "theme_ids=2; forced_color_mode=dark"}
    fetch(ng.port, "/dc/topic-c", headers=var)
    _, _, hv = fetch(ng.port, "/dc/topic-c", headers=var)
    assert hv.get("x-cache") == "HIT", \
        f"theme_ids/forced_color_mode must stay cacheable, got {hv.get('x-cache')}"

    # API args bypass.
    _, _, ha = fetch(ng.port, "/dc/topic-d?api_key=deadbeef")
    assert "x-cache" not in ha, "?api_key= must bypass"
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


def test_punbb_cookie_name_default(ng: Nginx, origin: Origin) -> None:
    """punbb preset must fire on the PunBB 1.4.x default cookie name.

    The row originally matched only `punbb_cookie`, the 1.2-era default. PunBB
    1.4.x names the auth cookie `$cookie_name` from config.php, which falls
    back to `forum_cookie` and which the installer randomises to
    `forum_cookie_<random>`. On a stock 1.4 board the preset therefore never
    matched and logged-in members were served cached guest pages. Both names
    are matched now; the substring also covers the randomised variant.
    Verified against punbb/punbb tag 1.4.4 (include/common.php,
    admin/install.php)."""
    for i, cookie in enumerate(("forum_cookie=NDJ8YWJj",
                                "forum_cookie_9f3a1c=NDJ8YWJj",
                                "punbb_cookie=NDJ8YWJj")):
        uri = f"/punbb/topic-{i}"
        m = {"Cookie": cookie}
        fetch(ng.port, uri, headers=m)
        _, _, h = fetch(ng.port, uri, headers=m)
        assert "x-cache" not in h, \
            (f"a PunBB member carrying '{cookie}' MUST bypass, got "
             f"{h.get('x-cache')} -- matching only the 1.2-era punbb_cookie "
             "served cached guest pages to members on a stock 1.4 board")


def test_vanilla_guest_cookies_stay_cacheable(ng: Nginx,
                                              origin: Origin) -> None:
    """vanilla preset must match `Vanilla=`, not the bare `Vanilla` prefix.

    Vanilla derives several GUEST-issued cookie names from the same
    Garden.Cookie.Name prefix: `Vanilla-tk` (CSRF transient key) and
    `Vanilla-Vv` (visit tracker). A bare-prefix rule matched those and served
    BYPASS to every returning anonymous visitor, leaving the cache to answer
    only cookie-less first hits and crawlers -- the guest-issued-cookie trap
    the preset registry's own header comment forbids. The `=` anchors on the
    identity cookie's delimiter instead.

    Both directions are asserted: the guest cookies must stay cacheable AND the
    real identity cookie must still bypass. Do not drop the `=`."""
    guest = {"Cookie": "Vanilla-Vv=1; Vanilla-tk=1650000000.abcdef"}
    fetch(ng.port, "/vanilla/discussion-a", headers=guest)
    _, _, hg = fetch(ng.port, "/vanilla/discussion-a", headers=guest)
    assert hg.get("x-cache") == "HIT", \
        (f"a returning GUEST carrying only Vanilla-tk / Vanilla-Vv must stay "
         f"cacheable, got {hg.get('x-cache')} -- both are issued to everyone")

    authed = {"Cookie": "Vanilla-Vv=1; Vanilla=abc.signed.payload"}
    fetch(ng.port, "/vanilla/discussion-b", headers=authed)
    _, _, ha = fetch(ng.port, "/vanilla/discussion-b", headers=authed)
    assert "x-cache" not in ha, \
        (f"a logged-in Vanilla member (identity cookie Vanilla=) MUST bypass, "
         f"got {ha.get('x-cache')}")


def test_phorum_admin_session_cookie(ng: Nginx, origin: Origin) -> None:
    """phorum preset must match the real admin cookie `phorum_admin_session`.

    The row shipped a stale `phorum_admin_session_v5` literal; the PHP constant
    (PHORUM_SESSION_ADMIN, include/api/user.php) has no `_v5` suffix, so a pure
    admin-session cookie never matched by name. Live impact was nil because
    /admin.php bypasses by URI, but the literal was wrong. Verified against
    Phorum Core v6.0.3. The member session cookies are asserted alongside it so
    a future edit cannot quietly drop one."""
    for i, cookie in enumerate(("phorum_admin_session=42:deadbeef",
                                "phorum_session_v5=42:deadbeef",
                                "phorum_session_st=42:cafebabe")):
        uri = f"/phorum/read-{i}"
        m = {"Cookie": cookie}
        fetch(ng.port, uri, headers=m)
        _, _, h = fetch(ng.port, uri, headers=m)
        assert "x-cache" not in h, \
            (f"a Phorum session cookie '{cookie}' MUST bypass, got "
             f"{h.get('x-cache')}")

    # phorum_tmp_cookie is a guest-issued cookie-support probe with no identity
    # value -- matching it would be a pure hit-rate loss. It must NOT bypass.
    guest = {"Cookie": "phorum_tmp_cookie=1"}
    fetch(ng.port, "/phorum/read-guest", headers=guest)
    _, _, hg = fetch(ng.port, "/phorum/read-guest", headers=guest)
    assert hg.get("x-cache") == "HIT", \
        (f"phorum_tmp_cookie is guest-issued and must stay cacheable, got "
         f"{hg.get('x-cache')}")


def test_punbb_phorum_uri_rules(ng: Nginx, origin: Origin) -> None:
    """The punbb and phorum URI rows must match the scripts those projects
    actually ship, with no cookie present.

    Both presets were written from a docs pass rather than from the source
    trees. punbb was missing every member/mutating script except login/post
    (edit, delete, moderate, profile, register all cached), and phorum was
    missing file.php -- the attachment download, which authorises per request
    through the file_storage API, so a cached response replays one member's
    attachment to everyone who later asks for the same file id.

    Every arm fetches twice on purpose: a bypass and a first-time MISS both
    answer without an x-cache header, so a single fetch passes with the row
    still absent. Only a bypass is still header-less on the second request.

    userlist.php and search.php are the negative controls. Both are
    guest-reachable read surfaces that the preset deliberately does NOT list, so
    they pin that these rows are per-script and not a blanket "any root .php
    bypasses" -- an over-broad edit that made them all bypass would still pass
    every arm above. search.php is asserted separately from userlist.php because
    it is the one a future editor is most likely to add: it is slow, and slow
    reads as dynamic. It is not. It is the endpoint that benefits MOST from
    being cached."""
    for uri in ("/edit.php?id=1", "/delete.php?id=1", "/moderate.php?fid=2",
                "/profile.php?id=42", "/register.php"):
        fetch(ng.port, uri)
        _, _, h = fetch(ng.port, uri)
        assert "x-cache" not in h, \
            (f"{uri} is a PunBB member/mutating script and must bypass on the "
             f"punbb preset with no cookie present, got {h.get('x-cache')}")

    fetch(ng.port, "/file.php?file=7")
    _, _, hf = fetch(ng.port, "/file.php?file=7")
    assert "x-cache" not in hf, \
        (f"/file.php is Phorum's permission-checked attachment download and "
         f"must bypass -- caching it replays one member's attachment to every "
         f"later requester of the same id, got {hf.get('x-cache')}")

    for uri in ("/userlist.php", "/search.php?action=search&keywords=nginx"):
        fetch(ng.port, uri)
        _, _, hu = fetch(ng.port, uri)
        assert hu.get("x-cache") == "HIT", \
            (f"{uri} is a public PunBB read surface that the preset does not "
             f"list and must stay cacheable, got {hu.get('x-cache')}")
    drain_origin(origin)


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


def test_vbulletin_preset(ng: Nginx, origin: Origin) -> None:
    """vBulletin preset: the NONEMPTY and EQ predicate ops, and the key cookies.

    This preset is the only one wired to NONEMPTY (`userid`, `password`) and EQ
    (`imloggedin` == "yes"), so it is the only runtime coverage those two arms
    get. Names are matched by SUFFIX because the `bb_` prefix is an admin
    setting (Cookie and HTTP Header Options).

    bb_lastvisit / bb_lastactivity are deliberately NOT key cookies: they are
    per-visit timestamps, so keying on them gives every visitor a private entry
    their own next request invalidates, and lets any client mint unlimited keys
    to force eviction. Only bb_language is keyed."""
    # Guest: session hash is issued to everyone, must not bypass.
    guest = {"Cookie": "bb_sessionhash=abc; bb_lastvisit=1721300000"}
    fetch(ng.port, "/vbull/forum", headers=guest)
    _, _, hg = fetch(ng.port, "/vbull/forum", headers=guest)
    assert hg.get("x-cache") == "HIT", \
        f"vbulletin guest must stay cacheable, got {hg.get('x-cache')}"

    # NONEMPTY arm: a non-empty userid/password is a logged-in member.
    for i, ck in enumerate(("bb_userid=42", "bb_password=deadbeef")):
        m = {"Cookie": f"bb_sessionhash=abc; {ck}"}
        fetch(ng.port, f"/vbull/member-{i}", headers=m)
        _, _, hm = fetch(ng.port, f"/vbull/member-{i}", headers=m)
        assert "x-cache" not in hm, \
            f"vbulletin member ({ck}) must bypass, got {hm.get('x-cache')}"

    # NONEMPTY arm, EMPTY value: a cleared cookie is a logged-OUT visitor and
    # must stay cacheable, or every logged-out member kills the hit rate.
    empt = {"Cookie": "bb_sessionhash=abc; bb_userid=; bb_password="}
    fetch(ng.port, "/vbull/emptied", headers=empt)
    _, _, he = fetch(ng.port, "/vbull/emptied", headers=empt)
    assert he.get("x-cache") == "HIT", \
        f"empty bb_userid is logged-out and must cache, got {he.get('x-cache')}"

    # NONEMPTY arm across TWO matching cookies, empty one first: the empty pair
    # must not end the scan and hide the populated one behind it.
    twin = {"Cookie": "bb_userid=; other_userid=42"}
    fetch(ng.port, "/vbull/twin", headers=twin)
    _, _, ht = fetch(ng.port, "/vbull/twin", headers=twin)
    assert "x-cache" not in ht, \
        (f"a populated `userid` behind an empty one must still bypass, got "
         f"{ht.get('x-cache')}")

    # EQ arm: imloggedin == "yes" bypasses; any other value does not.
    yes = {"Cookie": "bb_sessionhash=abc; bb_imloggedin=yes"}
    fetch(ng.port, "/vbull/imlogged", headers=yes)
    _, _, hy = fetch(ng.port, "/vbull/imlogged", headers=yes)
    assert "x-cache" not in hy, \
        f"bb_imloggedin=yes must bypass, got {hy.get('x-cache')}"

    no = {"Cookie": "bb_sessionhash=abc; bb_imloggedin=no"}
    fetch(ng.port, "/vbull/imlogged-no", headers=no)
    _, _, hn = fetch(ng.port, "/vbull/imlogged-no", headers=no)
    assert hn.get("x-cache") == "HIT", \
        f"bb_imloggedin=no is not the EQ literal and must cache, got {hn.get('x-cache')}"

    # EQ arm across TWO matching cookies, the non-matching one first: a value
    # that is not the literal must not end the scan and hide the "yes" behind
    # it. Guards the same regression as the NONEMPTY twin above, for the EQ arm.
    eq_twin = {"Cookie": "bb_imloggedin=no; other_imloggedin=yes"}
    fetch(ng.port, "/vbull/imlogged-twin", headers=eq_twin)
    _, _, h_eq_twin = fetch(ng.port, "/vbull/imlogged-twin", headers=eq_twin)
    assert "x-cache" not in h_eq_twin, \
        (f"an `imloggedin=yes` behind a non-matching one must still bypass, "
         f"got {h_eq_twin.get('x-cache')}")

    # Key cookie: bb_language splits the entry (two languages, same URL, two
    # buckets -- the second language must NOT read the first one's entry).
    en = {"Cookie": "bb_language=en"}
    de = {"Cookie": "bb_language=de"}
    fetch(ng.port, "/vbull/keyed", headers=en)
    _, _, h_en = fetch(ng.port, "/vbull/keyed", headers=en)
    assert h_en.get("x-cache") == "HIT", "same bb_language must hit its bucket"
    _, _, h_de = fetch(ng.port, "/vbull/keyed", headers=de)
    assert h_de.get("x-cache") != "HIT", \
        (f"a different bb_language must key to its own entry, got "
         f"{h_de.get('x-cache')} -- the language cookie is not folded into "
         "the key")

    # bb_lastvisit must NOT be keyed: two different timestamps on the same URL
    # must share one entry. If this fails the preset is minting an entry per
    # request and the zone is a free eviction target.
    v1 = {"Cookie": "bb_lastvisit=1721300000"}
    v2 = {"Cookie": "bb_lastvisit=1721399999"}
    fetch(ng.port, "/vbull/unkeyed", headers=v1)
    _, _, h_v1 = fetch(ng.port, "/vbull/unkeyed", headers=v1)
    assert h_v1.get("x-cache") == "HIT", "bb_lastvisit bucket must warm"
    _, _, h_v2 = fetch(ng.port, "/vbull/unkeyed", headers=v2)
    assert h_v2.get("x-cache") == "HIT", \
        (f"a different bb_lastvisit must reuse the SAME entry, got "
         f"{h_v2.get('x-cache')} -- per-visit timestamps must not be key "
         "cookies or every request mints its own entry")


def test_invision_preset(ng: Nginx, origin: Origin) -> None:
    """Invision: the _loggedIn bypass, the cosmetic key cookies, and the device
    fingerprint that must NOT be one.

    ips4_device_key is a per-device remember-me token. Keying on it would give
    every visitor a private entry nobody else can hit and let any client mint
    unlimited keys to force eviction -- the same failure bb_lastvisit had on the
    vBulletin preset.

    Note what the device-key case can and cannot prove. The registry listed the
    cookie under a camelCase name (`ips4_deviceKey`) that EXACT key-cookie
    matching never matched, so these requests were already unkeyed and this
    assertion passes both before and after the row was dropped. It is not a
    regression test for the removal; it is the guard against the tempting wrong
    repair -- correcting the spelling to `ips4_device_key` -- which would key
    every device separately and which this test would then fail."""
    # Guest with the ordinary session cookie: issued to everyone, must cache.
    guest = {"Cookie": "ips4_IPSSessionFront=abc"}
    fetch(ng.port, "/ips/topic", headers=guest)
    _, _, hg = fetch(ng.port, "/ips/topic", headers=guest)
    assert hg.get("x-cache") == "HIT", \
        f"an IPS guest session must stay cacheable, got {hg.get('x-cache')}"

    # _loggedIn is matched by SUFFIX, because the ips4_ prefix is admin-
    # configurable (Overriding Default Cookie Options). The stock name alone
    # would pass under an exact-name matcher too, so a renamed board is the
    # case that actually pins the suffix rule.
    for i, ck in enumerate(("ips4_loggedIn=1", "custom_loggedIn=1")):
        memb = {"Cookie": f"ips4_IPSSessionFront=abc; {ck}"}
        fetch(ng.port, f"/ips/member-{i}", headers=memb)
        _, _, hm = fetch(ng.port, f"/ips/member-{i}", headers=memb)
        assert "x-cache" not in hm, \
            f"a logged-in IPS member ({ck}) must bypass, got {hm.get('x-cache')}"

    # Cosmetic key cookie: two themes, same URL, two entries.
    ta = {"Cookie": "ips4_theme=1"}
    tb = {"Cookie": "ips4_theme=2"}
    _, ba, _ = fetch(ng.port, "/ips/keyed", headers=ta)
    _, _, h_ta = fetch(ng.port, "/ips/keyed", headers=ta)
    assert h_ta.get("x-cache") == "HIT", "the same ips4_theme must hit its bucket"
    _, bb, h_tb = fetch(ng.port, "/ips/keyed", headers=tb)
    assert h_tb.get("x-cache") != "HIT", \
        f"a different ips4_theme must not read the first theme's entry, got {h_tb.get('x-cache')}"
    assert bb != ba, \
        "a different ips4_theme was served the first theme's cached body"

    # The device fingerprint must NOT be keyed: two devices, one entry.
    d1 = {"Cookie": "ips4_device_key=aaaaaaaaaaaaaaaa"}
    d2 = {"Cookie": "ips4_device_key=bbbbbbbbbbbbbbbb"}
    fetch(ng.port, "/ips/unkeyed", headers=d1)
    _, _, h_d1 = fetch(ng.port, "/ips/unkeyed", headers=d1)
    assert h_d1.get("x-cache") == "HIT", "the device-key bucket must warm"
    _, _, h_d2 = fetch(ng.port, "/ips/unkeyed", headers=d2)
    assert h_d2.get("x-cache") == "HIT", \
        (f"a different ips4_device_key must reuse the SAME entry, got "
         f"{h_d2.get('x-cache')} -- a per-device fingerprint must not be a key "
         "cookie or every device mints its own entry")
    drain_origin(origin)


def test_mybb_preset(ng: Nginx, origin: Origin) -> None:
    """MyBB: the `user`-SUFFIX bypass, the EXACT-match key cookies, and the
    asymmetry between the two that must not be 'fixed'.

    MyBB prepends an ACP-settable `cookieprefix` (default empty) to every
    hardcoded base name, so a reconfigured board sends `<prefix>mybbuser` and
    `<prefix>mybbtheme`. The bypass rule survives that because it matches the
    `user` suffix. The key cookies deliberately do NOT: they are matched by
    exact wire name, so a prefixed board silently stops varying on theme.

    That asymmetry is the point of this test. Making the key cookies suffix-
    matched too is the obvious-looking repair and it is wrong: key cookies
    select which entry a request lands in, so a loose match lets any client
    fold a cookie of its own naming into the key and land on another visitor's
    bucket -- while the origin, which ignores the unknown name, returns the
    default variant to be stored there. A predicate's loose match costs a
    bypass; a key's loose match hands out bucket selection."""
    # sid is issued to every visitor including guests -- must stay cacheable.
    guest = {"Cookie": "sid=abc123"}
    fetch(ng.port, "/mybb/index.php", headers=guest)
    _, _, hg = fetch(ng.port, "/mybb/index.php", headers=guest)
    assert hg.get("x-cache") == "HIT", \
        f"a MyBB guest session (sid) must stay cacheable, got {hg.get('x-cache')}"

    # The login cookie bypasses, and keeps bypassing under a board prefix --
    # that is what the suffix rule buys. The prefixed arm is the one that fails
    # if anyone tightens the predicate to an exact name.
    for i, ck in enumerate(("mybbuser=42_loginkey", "boardxmybbuser=42_loginkey")):
        memb = {"Cookie": f"sid=abc123; {ck}"}
        fetch(ng.port, f"/mybb/member-{i}.php", headers=memb)
        _, _, hm = fetch(ng.port, f"/mybb/member-{i}.php", headers=memb)
        assert "x-cache" not in hm, \
            f"a logged-in MyBB member ({ck}) must bypass, got {hm.get('x-cache')}"

    # The key cookie folds under its exact name: two themes, two entries.
    ta, tb = {"Cookie": "mybbtheme=1"}, {"Cookie": "mybbtheme=2"}
    _, ba, _ = fetch(ng.port, "/mybb/keyed.php", headers=ta)
    _, _, h_ta = fetch(ng.port, "/mybb/keyed.php", headers=ta)
    assert h_ta.get("x-cache") == "HIT", "the same mybbtheme must hit its bucket"
    _, bb, h_tb = fetch(ng.port, "/mybb/keyed.php", headers=tb)
    assert h_tb.get("x-cache") != "HIT", \
        f"a different mybbtheme must not read the first theme's entry, got {h_tb.get('x-cache')}"
    assert bb != ba, "a different mybbtheme was served the first theme's cached body"

    # THE PIN. A cookie merely ENDING in the key-cookie name must not fold, so
    # it cannot steer bucket selection: a request carrying only
    # `evilmybbtheme` keys identically to one carrying no theme cookie at all,
    # and therefore reads the entry the no-cookie request just warmed.
    fetch(ng.port, "/mybb/unsteerable.php")
    _, _, h_base = fetch(ng.port, "/mybb/unsteerable.php")
    assert h_base.get("x-cache") == "HIT", "the no-cookie bucket must warm"
    _, _, h_evil = fetch(ng.port, "/mybb/unsteerable.php",
                         headers={"Cookie": "evilmybbtheme=1"})
    assert h_evil.get("x-cache") == "HIT", \
        (f"a cookie merely ending in 'mybbtheme' must NOT fold into the key, got "
         f"{h_evil.get('x-cache')} -- suffix-matching a KEY cookie lets a client "
         "pick which entry it lands on; the prefixed-board remedy is an operator "
         "cache_turbo_key_cookie, not a loose match here")
    drain_origin(origin)


def test_yabb_preset(ng: Nginx, origin: Origin) -> None:
    """YaBB: the Y2* cookie triple bypasses, and every mutating ?action= route
    does too -- including logout.

    Logout is the row this test exists for. A cached logout response is served
    without the request ever reaching LogInOut.pl, so the
    UpdateCookie("delete") that terminates the session never runs: the member
    is shown a logged-out page while their Y2Sess-* cookie stays valid. The
    registry listed login/login2 but not logout, so a logout arriving WITHOUT
    the cookie triple (a stale tab, a link followed after the cookies expired,
    or any client that drops them) was cacheable.

    The cookie-triple arm is not a substitute for it: a request carrying
    Y2User-* bypasses on the cookie rule alone and would pass with the args row
    still missing, so the args arms are deliberately cookie-less."""
    # The random per-install numeric suffix is what the substring rule exists
    # for -- use a non-stock one so an exact-name matcher would fail here.
    memb = {"Cookie": "Y2User-91827=alice; Y2Sess-91827=deadbeef"}
    fetch(ng.port, "/yabb/YaBB.pl?num=17", headers=memb)
    _, _, hm = fetch(ng.port, "/yabb/YaBB.pl?num=17", headers=memb)
    assert "x-cache" not in hm, \
        f"a YaBB member (Y2User-<rand>) must bypass, got {hm.get('x-cache')}"

    # Mutating/authenticated routes must bypass on the ARG alone, with no
    # cookie present. Fetch twice: a bypass and a first-time MISS are
    # indistinguishable on one fetch (both lack x-cache), and only the bypass
    # still lacks it on the second.
    for q in ("action=logout", "action=login", "action=post", "action=admin",
              "action=pm"):
        uri = f"/yabb/YaBB.pl?{q}"
        fetch(ng.port, uri)
        _, _, h = fetch(ng.port, uri)
        assert "x-cache" not in h, \
            (f"?{q} must bypass on the yabb preset with no cookie present, got "
             f"{h.get('x-cache')}")

    # YaBB writes multi-argument URLs with ';', and the arg it dispatches on is
    # rarely first -- the form the scanner was added for. Still a bypass.
    uri = "/yabb/YaBB.pl?num=17;action=logout"
    fetch(ng.port, uri)
    _, _, h_semi = fetch(ng.port, uri)
    assert "x-cache" not in h_semi, \
        (f"?num=17;action=logout must bypass -- ';' is a YaBB query separator "
         f"and the action is not the first argument, got {h_semi.get('x-cache')}")

    # A plain thread read carries no action at all and must stay cacheable;
    # this is what a bare-arg-NAME match would have broken.
    for uri in ("/yabb/YaBB.pl?num=17;start=15", "/yabb/YaBB.pl?action=recent"):
        fetch(ng.port, uri)
        _, _, h_ok = fetch(ng.port, uri)
        assert h_ok.get("x-cache") == "HIT", \
            (f"{uri} is an ordinary read and must stay cacheable, got "
             f"{h_ok.get('x-cache')}")
    drain_origin(origin)


def test_preset_arg_value_predicate(ng: Nginx) -> None:
    """Preset query-arg rules written as `name=value` must match the VALUE.

    The single-entry-script forums (SMF, MyBB, YaBB, Invision) route every page
    through one `action` / `do` argument, so the argument NAME carries the
    ordinary read routes too. The classifier originally looked every args entry
    up as a bare argument name, which meant `action=login` was searched for as
    an argument literally called "action=login" and never matched anything --
    login, PM and moderation routes stayed cacheable. Matching on the name
    alone is not the fix either: it would bypass the whole board.

    So both halves are asserted. A listed value bypasses; an unlisted value on
    the SAME argument name still caches."""
    # A listed route value must bypass. Fetch TWICE: a bypassed response and an
    # ordinary first-time MISS both come back with no x-cache header, so a
    # single fetch cannot tell them apart and would pass even with the rule
    # removed. Only a bypass keeps the header absent on the SECOND request --
    # a mere MISS would have been stored and would answer HIT.
    for i, q in enumerate(("action=login", "action=admin", "action=pm")):
        uri = f"/smf/index.php?{q}&t={i}"
        fetch(ng.port, uri)
        _, _, h = fetch(ng.port, uri)
        assert "x-cache" not in h, \
            (f"?{q} must bypass on the smf preset (still no x-cache on the "
             f"second request), got {h.get('x-cache')}")

    # An UNLISTED value on the same argument name is an ordinary read and must
    # stay cacheable -- this is what a bare-name match would have broken.
    for q in ("action=display", "action=recent"):
        uri = f"/smf/index.php?{q}"
        fetch(ng.port, uri)
        _, _, h = fetch(ng.port, uri)
        assert h.get("x-cache") == "HIT", \
            (f"?{q} is an ordinary read route and must stay cacheable, got "
             f"{h.get('x-cache')} -- matching the bare arg NAME bypasses the "
             "entire board")


def test_preset_arg_scanner(ng: Nginx, origin: Origin) -> None:
    """The preset arg scanner must percent-decode, split on ';', and look past
    the first occurrence of a name.

    All three of these were fail-OPEN with core nginx's ngx_http_arg():

      * ngx_http_arg splits only on '&'. SMF and YaBB build nearly every
        multi-argument URL with ';' ("?u=42;action=login"), so everything after
        the first argument was invisible and those presets' arg rows matched
        nothing on a real board URL.
      * ngx_http_arg does not percent-decode. PHP routes "%61ction=log%69n"
        exactly like "action=login", so an encoded login URL was cached.
      * ngx_http_arg returns the FIRST occurrence and stops. PHP's $_GET keeps
        the LAST, so a harmless value prefixed onto the real one
        ("?action=display&action=login") hid the dynamic route.

    Each case is fetched TWICE for the same reason as the value-predicate test:
    a bypass and a first-time MISS are indistinguishable on one request, so a
    single fetch would pass with the scanner removed."""
    bypass_cases = (
        ("u=42;action=login", "';' is a query separator for SMF/YaBB"),
        ("%61ction=login", "the argument NAME may be percent-encoded"),
        ("action=log%69n", "the argument VALUE may be percent-encoded"),
        ("action=display&action=login", "a later occurrence still counts"),
        ("board=1;u=42;action=pm", "the match may be the LAST of several"),
    )
    for i, (q, why) in enumerate(bypass_cases):
        uri = f"/smf/index.php?{q}&n={i}"
        fetch(ng.port, uri)
        _, _, h = fetch(ng.port, uri)
        assert "x-cache" not in h, \
            (f"?{q} must bypass on the smf preset ({why}), got "
             f"{h.get('x-cache')}")

    # The negative half. Decoding and ';'-splitting must not turn an ordinary
    # read route into a bypass, or the scanner has simply un-cached the board.
    for q in ("u=42;action=display", "action=%64isplay", "actionx=login"):
        uri = f"/smf/index.php?{q}"
        fetch(ng.port, uri)
        _, _, h = fetch(ng.port, uri)
        assert h.get("x-cache") == "HIT", \
            (f"?{q} is an ordinary read route and must stay cacheable, got "
             f"{h.get('x-cache')}")

    # PHP's key mangling. php_register_variable_ex() rewrites '.' and ' ' to
    # '_' when it builds a $_GET key, so "?.xfToken=" reaches XenForo as
    # "_xfToken" -- the exact argument name the preset bypasses on, and a
    # percent-decoding-only matcher misses every alias. A literal '+' is a
    # space in form encoding and mangles the same way. The fold is applied to
    # every preset, not only the PHP ones: on Discourse (Rack, which does not
    # mangle) it can only ever cost an unnecessary bypass, which is the safe
    # direction, so the discourse arms below pin the uniform behaviour.
    for uri in ("/xf/thread-mangle?%2ExfToken=1650000000,abcdef",
                "/xf/thread-mangle2?+xfToken=1650000000,abcdef",
                "/dc/topic-mangle?api%2Ekey=deadbeef",
                "/dc/topic-mangle2?api%20username=admin"):
        fetch(ng.port, uri)
        _, _, h = fetch(ng.port, uri)
        assert "x-cache" not in h, \
            (f"{uri} must bypass -- PHP folds '.', ' ' and a literal '+' in an "
             f"argument NAME to '_', got {h.get('x-cache')}")

    # ...but the mangling is a NAME rule only, and PHP leaves values alone.
    # An unrelated name that merely contains the fold characters must not
    # suddenly match, or every preset with an underscore in an arg row starts
    # bypassing traffic it has no business seeing.
    for uri in ("/xf/thread-nomangle?x.xfToken=1", "/dc/topic-nomangle?api.keyx=1"):
        fetch(ng.port, uri)
        _, _, h = fetch(ng.port, uri)
        assert h.get("x-cache") == "HIT", \
            (f"{uri} matches no preset argument and must stay cacheable, got "
             f"{h.get('x-cache')}")

    drain_origin(origin)


def test_phorum_uri_rules_anchor_at_root(ng: Nginx, origin: Origin) -> None:
    """phorum URI rules must carry a leading slash.

    r->uri always begins with '/', and the preset's URI rules are prefixes
    anchored at position 0, so a rule written as "admin.php" can never match
    "/admin.php". The row shipped all eleven script names unslashed, which left
    the admin, login, posting and moderation routes cacheable."""
    _, _, h = fetch(ng.port, "/admin.php")
    assert "x-cache" not in h, \
        (f"/admin.php must bypass on the phorum preset, got {h.get('x-cache')} "
         "-- the URI rules are anchored at position 0 and need a leading slash")


def test_joomla_preset(ng: Nginx, origin: Origin) -> None:
    """Joomla preset (docs/joomla.md). joomla_remember_me_ is the ONE Joomla
    cookie that passes both tests: it is a fixed PREFIX ('joomla_remember_me_' .
    getShortHashedUserAgent() -- the per-install part is the suffix) and it is set
    only for an authenticated user.

    THE PARTIAL-GUARD HALF IS ASSERTED TOO, and it matters more than the positive
    one: a normally-logged-in frontend user (who did NOT tick "Remember Me")
    carries only the session cookie, whose NAME is md5($secret . $session_name) --
    a per-install hash with no fixed substring. That user is INVISIBLE to this
    matcher, by construction. The test pins that reality so nobody reads the
    presence of a cookie rule as "joomla is handled" -- it is not, and the docs
    tell the operator to add their own cache_turbo_bypass."""
    # The remember-me cookie is auth-only -> bypass.
    rm = {"Cookie": "joomla_remember_me_9f8e7d6c=abc123"}
    _, _, h1 = fetch(ng.port, "/jm/article-a", headers=rm)
    _, _, h2 = fetch(ng.port, "/jm/article-a", headers=rm)
    assert "x-cache" not in h1 and "x-cache" not in h2, \
        "joomla_remember_me_ is auth-only and must bypass"

    # THE GAP, asserted on purpose: the md5-named session cookie is unmatchable,
    # so a normally-logged-in user still caches. This is a KNOWN limitation, not a
    # regression -- if a future change makes this bypass, the preset got better and
    # this assertion should be revisited deliberately, not deleted in passing.
    sess = {"Cookie": "b1946ac92492d2347c6235b4d2611184=sessvalue"}
    fetch(ng.port, "/jm/article-b", headers=sess)
    _, _, hs = fetch(ng.port, "/jm/article-b", headers=sess)
    assert hs.get("x-cache") == "HIT", \
        ("joomla's md5-named session cookie is unmatchable by a substring rule, so "
         "it still caches -- the operator MUST add their own cache_turbo_bypass. "
         f"got {hs.get('x-cache')}")

    # /administrator/ still bypasses.
    _, _, ha = fetch(ng.port, "/administrator/index.php")
    assert "x-cache" not in ha, "/administrator/ must bypass"
    drain_origin(origin)


def test_drupal_preset(ng: Nginx, origin: Origin) -> None:
    """Drupal preset (docs/drupal.md).

    The SESS cookie rule is a LEAK FIX and its assertions are INVERTED from the
    original preset. This test used to assert that PHPSESSID must stay cacheable,
    with a comment reading "If someone adds SESS, this fails" -- i.e. it encoded
    the bug as a guarantee.

    The bug: the preset shipped NO cookie rule, on the belief that anonymous
    Drupal users never get a session cookie. False. Drupal opens a session for an
    ANONYMOUS user as soon as anything writes to $_SESSION -- core's own
    NoSessionOpen docblock names the cases (a status message from a form submit,
    cart contents). A logged-in user carries the same SESS<hash> shape, so with
    no cookie rule an authenticated response could be stored and served on.

    The accepted cost: "SESS" is a substring of PHPSESSID and JSESSIONID, so a
    co-hosted PHP/Java app's session cookie also bypasses. That is a HIT-RATE
    loss on the other app, never a leak -- and it does not justify leaking here."""
    for uri in ("/user", "/user/1/edit", "/admin/config"):
        _, _, h = fetch(ng.port, uri)
        assert "x-cache" not in h, f"{uri} must bypass on the drupal preset"

    # The session cookie must bypass -- both the plain and the TLS (SSESS) form.
    # The hash is per-install, so "SESS" as a substring is the only shippable rule.
    for ck in ("SESS1a2b3c4d5e6f=authsession", "SSESSdeadbeefcafe=authsession"):
        _, _, h1 = fetch(ng.port, "/dr/node-a", headers={"Cookie": ck})
        _, _, h2 = fetch(ng.port, "/dr/node-a", headers={"Cookie": ck})
        assert "x-cache" not in h1 and "x-cache" not in h2, \
            (f"drupal: {ck.split('=')[0]} must bypass -- a logged-in user carries "
             "this shape and caching it serves their page to strangers")

    # The known, accepted collision: PHPSESSID contains "SESS", so it bypasses too.
    # Asserted explicitly so the trade-off is visible and cannot regress silently.
    php = {"Cookie": "PHPSESSID=abc123"}
    _, _, hp1 = fetch(ng.port, "/dr/node-b", headers=php)
    _, _, hp2 = fetch(ng.port, "/dr/node-b", headers=php)
    assert "x-cache" not in hp1 and "x-cache" not in hp2, \
        ("drupal: PHPSESSID collides with the SESS substring and bypasses. This is "
         "the ACCEPTED cost of closing the anon-session leak -- a hit-rate loss on "
         f"a co-hosted PHP app, never a leak. got {hp2.get('x-cache')}")

    # A cookieless anonymous reader still caches -- the preset is not a blanket
    # bypass, which is the whole point of it existing.
    fetch(ng.port, "/dr/node-c")
    _, _, hc = fetch(ng.port, "/dr/node-c")
    assert hc.get("x-cache") == "HIT", \
        f"drupal: a cookieless anonymous reader must cache, got {hc.get('x-cache')}"
    drain_origin(origin)


def test_mediawiki_preset(ng: Nginx, origin: Origin) -> None:
    """MediaWiki preset (docs/mediawiki.md). The identity cookies have no stable
    prefix ($wgCookiePrefix defaults to the DB NAME), so the preset matches the
    CamelCase suffixes UserID= / UserName=. The dynamic surface is in query args,
    not paths: /wiki/<Title> is the cacheable read path.

    The negative half matters as much as the positive one: action=raw,
    action=history, diff= and oldid= are deterministic, shared and hot — they
    must stay CACHEABLE. Bypassing them is a measurable hit-rate loss, which is
    why a blanket "presence of action= => bypass" rule was rejected.

    THE PRESET HAS NO URI RULES. It used to bypass /index.php, /load.php and
    /api.php; all three were wrong. On a stock wiki $wgArticlePath is
    /index.php?title=Foo, so /index.php IS the article read path — that rule
    bypassed 100% of article reads. /load.php (ResourceLoader) and /api.php are
    the hottest cacheable objects on the site; Wikimedia's VCL ring-fences them
    against being made private, by ticket number (T102898, T113007)."""
    # /index.php IS the article path on a stock wiki -- it must CACHE, not bypass.
    # This assertion is inverted from the original preset on purpose: it is the
    # regression guard for the worst rule the registry ever shipped.
    fetch(ng.port, "/index.php?title=Foo")
    _, _, h = fetch(ng.port, "/index.php?title=Foo")
    assert h.get("x-cache") == "HIT", \
        ("/index.php?title= is the ARTICLE READ PATH on a stock wiki "
         f"($wgArticlePath) -- it must cache, got {h.get('x-cache')}")

    # VisualEditor is always dynamic.
    _, _, hv = fetch(ng.port, "/wiki/Foo?veaction=edit")
    assert "x-cache" not in hv, "?veaction= must bypass"

    # Identity cookies bypass, whatever the site's $wgCookiePrefix happens to be.
    # Token and _session are what UPSTREAM keys on -- getVaryCookies() verbatim:
    # "Vary on token and session because those are the real authn determiners.
    #  UserID and UserName don't matter without those."
    # The _session assertion is INVERTED from the original preset, which asserted
    # it must stay cacheable. Bypassing a session-carrying guest costs hits; NOT
    # bypassing a session-carrying member leaks.
    for ck in ("mywikiToken=deadbeef", "mywiki_session=abc123", "mywikiUserID=42"):
        _, _, h1 = fetch(ng.port, "/wiki/Article-a", headers={"Cookie": ck})
        _, _, h2 = fetch(ng.port, "/wiki/Article-a", headers={"Cookie": ck})
        assert "x-cache" not in h1 and "x-cache" not in h2, \
            f"cookie {ck.split('=')[0]} must bypass -- upstream calls it an authn determiner"

    # UserName must NOT bypass. unpersistSession() deliberately does NOT clear it
    # on logout (it pre-fills the login form), so EVERY visitor who has ever logged
    # in keeps sending it forever -- long after they are an ordinary anonymous
    # reader. Bypassing on it is a permanent hit-rate loss with zero safety gain.
    exlogin = {"Cookie": "mywikiUserName=Bob"}
    fetch(ng.port, "/wiki/Article-b", headers=exlogin)
    _, _, hn = fetch(ng.port, "/wiki/Article-b", headers=exlogin)
    assert hn.get("x-cache") == "HIT", \
        ("mywikiUserName survives logout (login-form pre-fill), so an ex-member "
         f"reading anonymously must still cache, got {hn.get('x-cache')}")

    # Every MUTATING core action must bypass on the ARG alone, with no cookie
    # present. ct_mw_args used to hold only veaction/returnto while the registry
    # comment claimed "Only the MUTATING actions are listed" -- there was no
    # action= row of any kind. Fetch twice: a bypass and a first-time MISS are
    # indistinguishable on one fetch (both lack x-cache), and only the bypass
    # still lacks it on the second.
    #
    # A logged-in actor is already covered by the cookie rule, and MediaWiki's
    # own floor covers the anonymous case (mCdnMaxage stays 0 for anything that
    # is not a ViewAction or a purgeable URL, so sendCacheControl() emits
    # `private`). These arms are cookie-less and do not rely on that floor: the
    # origin here sends no Cache-Control at all, which is precisely the
    # `cache_turbo_cache_control ignore` shape the rows exist for.
    for act in ("edit", "submit", "delete", "protect", "unprotect", "purge",
                "rollback", "revert", "watch", "unwatch", "markpatrolled",
                "mcrundo", "mcrrestore"):
        uri = f"/wiki/Article-m?action={act}"
        fetch(ng.port, uri)
        _, _, hm = fetch(ng.port, uri)
        assert "x-cache" not in hm, \
            (f"?action={act} is a mutating MediaWiki core action and must "
             f"bypass with no cookie present, got {hm.get('x-cache')}")

    # MediaWiki writes ?title=Foo&action=edit -- the action is not the first
    # argument. Percent-encoded too: PHP routes ?%61ction=edit identically.
    for uri in ("/index.php?title=Foo&action=edit",
                "/index.php?title=Foo&%61ction=delete"):
        fetch(ng.port, uri)
        _, _, hp = fetch(ng.port, uri)
        assert "x-cache" not in hp, \
            (f"{uri} must bypass -- the action is not the first argument and "
             f"may be percent-encoded, got {hp.get('x-cache')}")

    # The read path and the deliberately-cacheable args must all still cache.
    # action=render/info/credits are the rows a future editor is most likely to
    # add by reflex when extending the mutating list -- they are core actions
    # sitting right beside the ones above in CORE_ACTIONS, and they are hot,
    # deterministic and shared. Pinning them here is what makes the list a
    # decision rather than an accident.
    for uri in ("/wiki/Article-c",
                "/wiki/Article-c?action=raw",
                "/wiki/Article-c?action=history",
                "/wiki/Article-c?action=render",
                "/wiki/Article-c?action=info",
                "/wiki/Article-c?action=credits",
                "/wiki/Article-c?action=view",
                "/wiki/Article-c?oldid=12345",
                "/wiki/Article-c?diff=12345"):
        fetch(ng.port, uri)
        _, _, hc = fetch(ng.port, uri)
        assert hc.get("x-cache") == "HIT", \
            (f"{uri} must stay cacheable (deterministic + shared); bypassing it "
             f"is a hit-rate loss, got {hc.get('x-cache')}")
    drain_origin(origin)


def test_magento_preset(ng: Nginx, origin: Origin) -> None:
    """Magento 2 preset (docs/magento.md).

    X-Magento-Vary is VALUE-KEYED, not bypassed -- exactly as Magento's own
    reference VCL does it (vcl_hash: hash_data of the regsub'd cookie) and as
    Magento's built-in PHP FPC does it (Identifier.php folds COOKIE_VARY_STRING
    into the cache id). The cookie is a SEGMENT FINGERPRINT (sha256 over
    {customer_group, customer_logged_in, store, currency}), not an identity: many
    visitors legitimately share one value, and Magento's private-content JS keeps
    the cart OUT of the cached HTML.

    Bypassing on it (what this preset used to do) was safe but sent every
    non-default ANONYMOUS visitor -- a guest in a second currency, a second store
    view -- to the origin with no private data at all. Presence-KEYING would be
    the actual leak (it collapses guest-EUR + wholesale + logged-in-retail into
    one bucket); value-keying is neither."""
    for uri in ("/checkout", "/checkout/cart", "/customer/account"):
        _, _, h = fetch(ng.port, uri)
        assert "x-cache" not in h, f"{uri} must bypass on the magento preset"

    # VALUE-KEYED: same vary value hits its own entry ...
    v_a = {"Cookie": "X-Magento-Vary=9f2a4c1e8b7d6f5a4c3b2a1908070605"}
    _, b1, h1 = fetch(ng.port, "/mg/product-a", headers=v_a)
    _, b2, h2 = fetch(ng.port, "/mg/product-a", headers=v_a)
    assert h2.get("x-cache") == "HIT", \
        ("X-Magento-Vary must be KEYED, not bypassed -- a segment repeats and "
         f"must hit its own entry; got {h2.get('x-cache')}")
    assert b1 == b2, "same vary value must serve the same cached body"

    # ... and a DIFFERENT value must NOT see it. This is the leak the old
    # presence-keying rejection was worried about, and it is the whole point of
    # keying on the VALUE.
    v_b = {"Cookie": "X-Magento-Vary=0000111122223333444455556666777"}
    _, b3, h3 = fetch(ng.port, "/mg/product-a", headers=v_b)
    assert b3 != b1, \
        ("magento: a DIFFERENT X-Magento-Vary value was served another "
         "segment's cached body -- this is a cross-user leak")
    _, b4, h4 = fetch(ng.port, "/mg/product-a", headers=v_b)
    assert h4.get("x-cache") == "HIT" and b4 == b3, \
        "each vary value must warm and hit its OWN entry"

    # The anonymous (no cookie) entry is a third, separate bucket -- and must not
    # be the one a segmented visitor sees.
    _, ba, _ = fetch(ng.port, "/mg/product-a")
    _, ba2, ha2 = fetch(ng.port, "/mg/product-a")
    assert ha2.get("x-cache") == "HIT", "anonymous catalog must cache"
    assert ba2 == ba and ba != b1 and ba != b3, \
        "the cookie-less anonymous entry must be its own bucket"

    # ALL Cookie headers are collected. A client may split its cookies over
    # several Cookie headers; if only the first were scanned, an attacker could
    # hide the real cookie in a second header and CHOOSE which bucket to read.
    _, bs, _ = fetch_dup(ng.port, "/mg/split",
                         [("Cookie", "PHPSESSID=abc"),
                          ("Cookie", "X-Magento-Vary=aaaa1111bbbb2222")])
    _, bs2, hs2 = fetch(ng.port, "/mg/split",
                        headers={"Cookie":
                                 "PHPSESSID=abc; X-Magento-Vary=aaaa1111bbbb2222"})
    assert hs2.get("x-cache") == "HIT" and bs2 == bs, \
        ("a cookie in a SECOND Cookie header must key identically to the same "
         "cookie folded into one header -- else the bucket is attacker-chosen")

    # A cookie whose name merely ENDS WITH ours is a different cookie. Keying is
    # EXACT-name (unlike the tier-2 predicate engine, which matches by suffix):
    # a loose match here would let an attacker-chosen cookie select the bucket.
    _, bd, _ = fetch(ng.port, "/mg/decoy",
                     headers={"Cookie": "NOT-X-Magento-Vary=aaaa1111bbbb2222"})
    _, banon, _ = fetch(ng.port, "/mg/decoy")
    assert bd == banon, \
        ("NOT-X-Magento-Vary must not be read as X-Magento-Vary -- an exact "
         "name match is what keeps the bucket out of the client's hands")

    # THE TRANSITION RACE. The request carries NO vary cookie, so it keys to the
    # ANONYMOUS entry -- and the response ESTABLISHES the segment. Storing that
    # body under the anonymous key poisons it for every anonymous visitor.
    # Upstream's VCL refuses exactly this (beresp.uncacheable).
    #
    # We inherit the refusal from the UNCONDITIONAL Set-Cookie floor: the
    # establishing response carries a Set-Cookie and is never stored. This test
    # therefore pins the BEHAVIOUR, not a magento-specific code path -- and it is
    # the reason the floor may not be made optional. If someone adds a
    # "cache Set-Cookie responses" knob, this assertion is what fails.
    for _ in range(2):
        _, _, ht = fetch(ng.port, "/mg/mgvary-page")
    assert ht.get("x-cache") != "HIT", \
        ("a response that SETS X-Magento-Vary on a cookie-less request must not "
         "be stored under the anonymous key -- that poisons the shared entry")

    # THE HIT RATE: every one of these is set for ANONYMOUS visitors. All must
    # keep caching. A regression here is a silent 0%-hit-rate catalog.
    for name, ck in (
        ("PHPSESSID",               "PHPSESSID=abc123"),
        ("form_key",                "form_key=deadbeef"),
        ("private_content_version", "private_content_version=1a2b3c"),
        ("mage-cache-sessid",       "mage-cache-sessid=true"),
        ("section_data_ids",        "section_data_ids=%7B%22cart%22%3A1%7D"),
        ("all of them together",    "PHPSESSID=abc; form_key=def; "
                                    "private_content_version=1a2b; "
                                    "mage-cache-sessid=true; mage-messages=hi"),
    ):
        uri = f"/mg/cat-{name.split()[0]}"
        fetch(ng.port, uri, headers={"Cookie": ck})
        _, _, hg = fetch(ng.port, uri, headers={"Cookie": ck})
        assert hg.get("x-cache") == "HIT", \
            (f"magento: {name} is set for ANONYMOUS visitors and must stay "
             f"cacheable -- bypassing on it zeroes the catalog hit rate; "
             f"got {hg.get('x-cache')}")
    drain_origin(origin)


def test_shopware6_preset(ng: Nginx, origin: Origin) -> None:
    """Shopware 6 preset (docs/shopware6.md).

    sw-cache-hash is VALUE-KEYED, not bypassed -- the same shape as magento, and
    Shopware's own Varnish config does exactly this (hash_data("+context=" +
    cookie.get("sw-cache-hash"))). The value is a segment fingerprint:
    CacheHeadersService::buildCacheHash() folds {rule_ids, version_id,
    currency_id, tax_state, logged_in_state} into it.

    Bypassing on presence would be WRONG: isCacheHashRequired() sets the cookie
    for a logged-in customer OR a guest with a filled cart OR a guest on a
    non-default currency. Bypass would ship every cart-holding guest to the
    origin for nothing -- the cart is not in the cached HTML.

    Shopware is unusually strict about the anonymous case: when the hash is not
    required it does not merely omit the cookie, it DELETES a stale one."""
    # Asserted POSITIVELY: X-CT-Status == BYPASS proves the URI rule fired. An
    # "x-cache is absent" assert would also pass on a plain MISS, so an empty URI
    # list would sail straight through it.
    for uri in ("/account", "/account/login", "/store-api/product"):
        _, _, h = fetch(ng.port, uri)
        assert h.get("x-ct-status") == "BYPASS", \
            (f"shopware6: {uri} must BYPASS; got X-CT-Status={h.get('x-ct-status')}"
             f" -- if this is MISS, the URI is not in ct_shopware6_uris and a "
             f"private page is being cached")
        assert "x-cache" not in h, f"shopware6: {uri} must not serve from cache"

    # VALUE-KEYED: one segment repeats and hits its OWN entry.
    v_a = {"Cookie": "sw-cache-hash=b1946ac92492d2347c6235b4d2611184"}
    _, b1, _ = fetch(ng.port, "/sw/product-a", headers=v_a)
    _, b2, h2 = fetch(ng.port, "/sw/product-a", headers=v_a)
    assert h2.get("x-cache") == "HIT", \
        ("sw-cache-hash must be KEYED, not bypassed -- a repeating segment must "
         f"hit its own entry; got {h2.get('x-cache')}")
    assert b1 == b2, "same cache-hash must serve the same cached body"

    # A DIFFERENT hash must NOT see it. logged_in_state is folded INTO the value,
    # so this is precisely the logged-in-vs-guest separation.
    v_b = {"Cookie": "sw-cache-hash=591785b794601e212b260e25925636fd"}
    _, b3, _ = fetch(ng.port, "/sw/product-a", headers=v_b)
    assert b3 != b1, \
        ("shopware6: a DIFFERENT sw-cache-hash was served another segment's "
         "cached body -- this is a cross-user leak")
    _, b4, h4 = fetch(ng.port, "/sw/product-a", headers=v_b)
    assert h4.get("x-cache") == "HIT" and b4 == b3, \
        "each cache-hash must warm and hit its OWN entry"

    # The cookie-less anonymous visitor is a third bucket -- and it is the COMMON
    # one, because Shopware actively clears the cookie for anon+empty-cart.
    _, ba, _ = fetch(ng.port, "/sw/product-a")
    _, ba2, ha2 = fetch(ng.port, "/sw/product-a")
    assert ha2.get("x-cache") == "HIT", "anonymous storefront must cache"
    assert ba2 == ba and ba != b1 and ba != b3, \
        "the cookie-less anonymous entry must be its own bucket"

    # ALL Cookie headers are collected -- else the bucket is attacker-chosen.
    _, bs, _ = fetch_dup(ng.port, "/sw/split",
                         [("Cookie", "session-=abc"),
                          ("Cookie", "sw-cache-hash=aaaa1111bbbb2222")])
    _, bs2, hs2 = fetch(ng.port, "/sw/split",
                        headers={"Cookie":
                                 "session-=abc; sw-cache-hash=aaaa1111bbbb2222"})
    assert hs2.get("x-cache") == "HIT" and bs2 == bs, \
        ("a cookie in a SECOND Cookie header must key identically to the same "
         "cookie folded into one header")

    # EXACT name match: a cookie that merely ends with ours is a different cookie.
    _, bd, _ = fetch(ng.port, "/sw/decoy",
                     headers={"Cookie": "NOT-sw-cache-hash=aaaa1111bbbb2222"})
    _, banon, _ = fetch(ng.port, "/sw/decoy")
    assert bd == banon, \
        ("NOT-sw-cache-hash must not be read as sw-cache-hash -- an exact name "
         "match is what keeps the bucket out of the client's hands")

    # THE TRANSITION RACE -- the most important assertion here. The request carries
    # NO sw-cache-hash (so it keys to the ANONYMOUS entry) and the response
    # ESTABLISHES the segment. Storing that body under the anonymous key poisons it
    # for every anonymous visitor. Refused by the unconditional Set-Cookie floor.
    #
    # Asserted POSITIVELY and in the direction of the actual leak. A bare
    # `!= "HIT"` proves nothing: it is satisfied by any unrelated reason to not
    # cache, and it never checks the thing that would actually be poisoned.
    # We pin three separate facts:
    #   1. X-CT-Status is MISS, not BYPASS -- the request WAS a cache candidate
    #      (cache-turbo engaged, no URI/cookie bypass) and the STORE is what got
    #      refused. If the floor were removed this would read HIT on pass 2.
    #   2. It never becomes a HIT, however many times it is fetched.
    #   3. The anonymous bucket is UNCONTAMINATED: a later cookie-less reader of
    #      the same URI must not be served the segment-establishing body.
    n_before = origin.hits_for("swhash-page")
    bodies = []
    for _ in range(3):
        _, bt, ht = fetch(ng.port, "/sw/swhash-page")
        bodies.append(bt)
        assert ht.get("x-cache") != "HIT", \
            ("a response that SETS sw-cache-hash on a cookie-less request must "
             "not be stored under the anonymous key -- that poisons the shared "
             "entry for every anonymous visitor")
        assert ht.get("x-ct-status") == "MISS", \
            ("the transition-race response must be a MISS whose STORE is refused "
             "by the Set-Cookie floor, not a BYPASS; got X-CT-Status="
             f"{ht.get('x-ct-status')} -- a BYPASS here would mean this test is "
             "passing for the wrong reason and no longer guards the floor")
    assert origin.hits_for("swhash-page") - n_before == 3, \
        ("every request must reach the origin -- a frozen origin count means the "
         "Set-Cookie response WAS stored and is being replayed to anonymous "
         "visitors")
    assert len(set(bodies)) == 3, \
        ("each fetch must get a fresh origin body -- identical bodies mean the "
         "segment-establishing response was cached and served to a subsequent "
         "anonymous visitor, which is the poisoning this floor exists to refuse")

    # sw-states must NOT bypass. It was removed in Shopware 6.8, and a bypass rule
    # on it would zero the storefront hit rate on <=6.7 (where it rides along with
    # sw-cache-hash on every segmented request). Asserted POSITIVELY via
    # X-CT-Status: a plain `x-cache == HIT` assert cannot fail here, because
    # shopware6 ships no bypass-cookie list at all -- it would pass just as well
    # with the cookie named zzz-nonsense, so it would guard nothing.
    _, _, hs1 = fetch(ng.port, "/sw/states",
                      headers={"Cookie": "sw-states=logged-in"})
    assert hs1.get("x-ct-status") == "MISS", \
        ("shopware6: sw-states must not be a BYPASS rule (it was removed in 6.8);"
         f" got X-CT-Status={hs1.get('x-ct-status')}")
    _, _, hs2 = fetch(ng.port, "/sw/states",
                      headers={"Cookie": "sw-states=logged-in"})
    assert hs2.get("x-cache") == "HIT", \
        ("shopware6: a request carrying only sw-states must still CACHE; got "
         f"{hs2.get('x-cache')}")
    drain_origin(origin)


def test_typo3_preset(ng: Nginx, origin: Origin) -> None:
    """TYPO3 preset (docs/typo3.md).

    Lazy sessions, and deliberately so: FrontendUserAuthentication overrides
    $dontSetCookie to TRUE (:155), against the base class default of false, and
    flips it back only in createUserSession()/regenerateSessionId(). So an
    anonymous reader of a public page is issued NO cookie -- upstream chose this
    to make the frontend cacheable.

    fe_typo_user is the FE login cookie; be_typo_user is the backend one and is
    NOT redundant -- an editor previewing the frontend carries only the BE cookie
    and is served hidden/scheduled records. Caching that publishes unpublished
    content."""
    _, _, h = fetch(ng.port, "/typo3/module/web/layout")
    assert "x-cache" not in h, "typo3: /typo3/... backend must bypass"
    _, _, hp = fetch(ng.port, "/typo3")
    assert "x-cache" not in hp, "typo3: exact /typo3 must bypass"

    # Segment-boundary matcher: /typo3 must not swallow a public page.
    fetch(ng.port, "/typo3-guide")
    _, _, hb = fetch(ng.port, "/typo3-guide")
    assert hb.get("x-cache") == "HIT", \
        ("typo3: /typo3-guide must cache (not swallowed by /typo3), got "
         f"{hb.get('x-cache')}")

    # Both identity cookies bypass -- asserted POSITIVELY via $cache_turbo_status.
    # "x-cache is absent" is NOT sufficient: an unrelated uncacheable response has
    # no x-cache either, so an absence-only assert stays green even if the cookie
    # literal is dropped from the preset entirely. X-CT-Status == BYPASS proves the
    # cookie rule actually fired.
    for ck in ("fe_typo_user=abc123", "be_typo_user=def456",
               "fe_typo_user=abc123; be_typo_user=def456"):
        _, _, hc = fetch(ng.port, "/t3/page", headers={"Cookie": ck})
        assert hc.get("x-ct-status") == "BYPASS", \
            (f"typo3: the cookie rule must BYPASS (Cookie: {ck}); got "
             f"X-CT-Status={hc.get('x-ct-status')} -- if this is MISS, the cookie "
             f"literal is not in ct_typo3_cookies and logged-in pages get CACHED")
        assert "x-cache" not in hc, f"typo3: must not serve from cache ({ck})"

    # The anonymous reader -- the whole point of the preset -- must cache.
    fetch(ng.port, "/t3/page")
    _, _, ha = fetch(ng.port, "/t3/page")
    assert ha.get("x-cache") == "HIT", \
        f"typo3: an anonymous reader must cache, got {ha.get('x-cache')}"
    drain_origin(origin)


def test_ghost_preset(ng: Nginx, origin: Origin) -> None:
    """Ghost preset (docs/ghost.md).

    The public blog is a genuinely shared anonymous surface, which is what makes
    it worth caching. Note it is NOT true that a member sees the same HTML as a
    guest on a public post -- `@member` is injected into the template context
    unconditionally, so {{#if @member}} changes the markup of a fully public post.
    The cookie bypass is what keeps this correct; it is load-bearing.

    The query-arg rules are LOAD-BEARING too: each one authenticates or unlocks
    with NO cookie, so the cookie rule cannot catch them. authMemberByUuid()
    authenticates a member purely from ?uuid=&key=; ?gift= serves UNLOCKED GATED
    content to a caller with no member cookie at all. Without these rules a
    member-authenticated (or paid) response could be stored and served to
    strangers. That is the sharp edge of this preset."""
    # Admin SPA / API bypasses.
    _, _, h = fetch(ng.port, "/ghost/api/admin/site")
    assert "x-cache" not in h, "/ghost/ must bypass"

    # Members session cookie bypasses (covers the .sig cookie via substring too).
    for ck in ("ghost-members-ssr=abc123", "ghost-members-ssr.sig=deadbeef",
               "ghost-admin-api-session=cafe"):
        _, _, h1 = fetch(ng.port, "/blog/post-a", headers={"Cookie": ck})
        _, _, h2 = fetch(ng.port, "/blog/post-a", headers={"Cookie": ck})
        assert "x-cache" not in h1 and "x-cache" not in h2, \
            f"ghost: {ck.split('=')[0]} must bypass"

    # COOKIELESS MEMBER AUTH: ?uuid=&key= authenticates a member with no cookie at
    # all. If these do not bypass, a member's page gets stored and served to the
    # public. This is the sharp edge of the Ghost preset.
    for uri in ("/blog/post-b?uuid=abc-123&key=deadbeef",
                "/blog/post-b?token=magiclink123",
                "/blog/post-b?gift=abc123"):
        _, _, hu = fetch(ng.port, uri)
        assert "x-cache" not in hu, \
            (f"ghost: {uri} authenticates a member (or unlocks gated content) via "
             "the QUERY STRING with no cookie -- it must bypass or a member/paid "
             "response is served to strangers")

    # An anonymous reader must cache -- Ghost sets no cookie for one, which is the
    # property that makes this preset worth shipping at all.
    fetch(ng.port, "/blog/post-c")
    _, _, ha = fetch(ng.port, "/blog/post-c")
    assert ha.get("x-cache") == "HIT", \
        f"ghost: an anonymous blog reader must cache, got {ha.get('x-cache')}"
    drain_origin(origin)


def test_wagtail_preset(ng: Nginx, origin: Origin) -> None:
    """Wagtail preset (docs/wagtail.md).

    The first preset whose auth cookie belongs to the FRAMEWORK, not the app:
    Wagtail ships no cookie of its own and rides Django's `sessionid`. That is only
    safe because Django's SessionMiddleware saves the cookie ONLY when the session
    is non-empty AND modified -- so a logged-out reader of a public page gets no
    cookie at all. (Laravel has no such check and cookies every guest, which is why
    there is no statamic/october/laravel preset. See docs/frameworks.md.)

    The two assertions that matter pull in opposite directions:
      - `sessionid` must bypass          (or a logged-in editor is served from cache)
      - `csrftoken` must NOT bypass      (or the hit rate goes to zero)
    Django hands csrftoken to any anonymous visitor who renders a form, so treating
    it as a login signal is the classic way to build a cache that caches nothing."""
    # Admin surfaces bypass. Each has a real location -- an implicit 404 carries no
    # x-cache header either, and would pass this assertion for free.
    for uri in ("/admin/pages/", "/django-admin/auth/user/"):
        _, _, h = fetch(ng.port, uri)
        assert "x-cache" not in h, f"wagtail: {uri} must bypass"

    # /documents/ is permission-checked: WAGTAILDOCS_SERVE_METHOD defaults to
    # serve_view, a Django view enforcing per-collection privacy. A private
    # document fetched by an authorised user must never be stored and replayed.
    _, _, hd = fetch(ng.port, "/documents/3/private-contract.pdf")
    assert "x-cache" not in hd, \
        ("wagtail: /documents/ is permission-checked (serve_view) -- it must bypass "
         "or a private document is served to strangers")

    # The logged-in editor: sessionid must bypass, on a URL a guest can also fetch.
    for ck in ("sessionid=abc123", "sessionid=abc123; csrftoken=xyz"):
        _, _, h1 = fetch(ng.port, "/wt/about", headers={"Cookie": ck})
        _, _, h2 = fetch(ng.port, "/wt/about", headers={"Cookie": ck})
        assert "x-cache" not in h1 and "x-cache" not in h2, \
            f"wagtail: sessionid must bypass (Cookie: {ck})"

    # THE INVERTED ONE. csrftoken is issued to ANONYMOUS visitors by Django, so it
    # must NOT bypass. If a future edit adds it to the cookie list, the preset still
    # "looks" correct -- it just silently stops caching. Fail loudly instead.
    fetch(ng.port, "/wt/pricing", headers={"Cookie": "csrftoken=xyz"})
    _, _, hc = fetch(ng.port, "/wt/pricing", headers={"Cookie": "csrftoken=xyz"})
    assert hc.get("x-cache") == "HIT", \
        ("wagtail: csrftoken is set for ANONYMOUS visitors and must keep caching -- "
         f"bypassing it would zero the hit rate, got {hc.get('x-cache')}")

    # Anonymous reader of the public site caches. This is the whole point.
    fetch(ng.port, "/wt/home")
    _, _, ha = fetch(ng.port, "/wt/home")
    assert ha.get("x-cache") == "HIT", \
        f"wagtail: an anonymous reader must cache, got {ha.get('x-cache')}"

    # /search/ is deliberately NOT a preset URI: dynamic, but anonymous-IDENTICAL,
    # so it is shared and hot. Bypassing it would be a pure hit-rate loss with no
    # safety gain (same reasoning that keeps a blanket action= out of mediawiki).
    fetch(ng.port, "/search/?q=nginx")
    _, _, hs = fetch(ng.port, "/search/?q=nginx")
    assert hs.get("x-cache") == "HIT", \
        ("wagtail: /search/ is anonymous-identical and must stay cacheable, got "
         f"{hs.get('x-cache')}")
    drain_origin(origin)


def test_kirby_preset(ng: Nginx, origin: Origin) -> None:
    """Kirby preset (docs/kirby.md).

    The best-shaped traffic of any preset here -- a flat-file site is almost
    entirely public pages identical for every logged-out visitor.

    kirby_session is a stable literal (session.cookieName) AND is not issued to
    anonymous visitors: Kirby creates a session only when something is stored in
    it. Stable + not-guest-issued is the pair every rejected candidate failed
    (Grav's grav-site-<hash> is guest-issued AND per-install; Craft's
    CraftSessionId is stable but handed to everyone).

    THE ONE CONDITION FAILS SAFE: Kirby's csrf() helper creates a session cookie,
    so a page with a contact/search form issues kirby_session to guests and stops
    caching. That costs HITS; it never leaks -- the error direction is
    bypass-a-guest, not serve-a-member's-page. Precisely inverted from Flarum,
    whose no-remember-me logins carry only the guest-issued flarum_session, which
    is why Flarum is rejected outright."""
    # Panel (admin) bypasses -- both the exact prefix and a sub-path.
    _, _, h = fetch(ng.port, "/panel/pages")
    assert "x-cache" not in h, "kirby: /panel/... must bypass"
    _, _, hp = fetch(ng.port, "/panel")
    assert "x-cache" not in hp, "kirby: exact /panel must bypass"

    # SEGMENT BOUNDARY: /panels-and-doors shares the /panel prefix but is a
    # different path segment, so it must CACHE, not bypass. Guards the boundary
    # matcher against regressing to a bare prefix test.
    fetch(ng.port, "/panels-and-doors")
    _, _, hb = fetch(ng.port, "/panels-and-doors")
    assert hb.get("x-cache") == "HIT", \
        f"kirby: /panels-and-doors must cache (not swallowed by /panel), got {hb.get('x-cache')}"

    # The logged-in Panel user / frontend member: kirby_session must bypass.
    for ck in ("kirby_session=abc123",):
        _, _, h1 = fetch(ng.port, "/kb/about", headers={"Cookie": ck})
        _, _, h2 = fetch(ng.port, "/kb/about", headers={"Cookie": ck})
        assert "x-cache" not in h1 and "x-cache" not in h2, \
            f"kirby: kirby_session must bypass (Cookie: {ck})"

    # Anonymous reader of the flat-file site caches -- Kirby issues no cookie to
    # one, which is the property that makes this preset shippable.
    fetch(ng.port, "/kb/home")
    _, _, ha = fetch(ng.port, "/kb/home")
    assert ha.get("x-cache") == "HIT", \
        f"kirby: an anonymous reader must cache, got {ha.get('x-cache')}"

    # /media/ is deliberately NOT a preset URI. Kirby serves assets from
    # /media/<hash>/ with no per-request permission view, so it is static content
    # that SHOULD cache -- bypassing it would be a self-inflicted wound. Assert it
    # caches so nobody "helpfully" adds the prefix later.
    fetch(ng.port, "/media/pages/home/logo.svg")
    _, _, hm = fetch(ng.port, "/media/pages/home/logo.svg")
    assert hm.get("x-cache") == "HIT", \
        ("kirby: /media/ is static with no permission view and must stay cacheable, "
         f"got {hm.get('x-cache')}")
    drain_origin(origin)


def test_new_presets_not_in_generic(ng: Nginx, origin: Origin) -> None:
    """None of the opt-in presets may be folded into generic/auto. Their URIs are
    generic English words (/login, /user, /admin, /session, /posts) that an
    unrelated site legitimately serves as cacheable pages, so a `generic`
    location must still cache them and must ignore their cookies."""
    for uri in ("/gen/user", "/gen/admin", "/gen/session", "/gen/index.php"):
        fetch(ng.port, uri)
        _, _, h = fetch(ng.port, uri)
        assert h.get("x-cache") == "HIT", \
            f"generic must NOT pull in the opt-in URI rules ({uri}), got {h.get('x-cache')}"

    # Distinct URIs per cookie: the key is $uri, so reusing one path would let
    # the second cookie HIT on the first one's entry and pass for free.
    for i, ck in enumerate(("_t=abc123", "mywikiUserID=42")):
        uri = f"/gen/page-{i}"
        fetch(ng.port, uri, headers={"Cookie": ck})
        _, _, hx = fetch(ng.port, uri, headers={"Cookie": ck})
        assert hx.get("x-cache") == "HIT", \
            f"generic must NOT pull in the opt-in cookie rule {ck}, got {hx.get('x-cache')}"
    drain_origin(origin)


def test_auto_classify_more(ng: Nginx, origin: Origin) -> None:
    """Auto-classify breadth: the search query arg (?s=), the comment_author_
    cookie, the joomla /administrator/ URI prefix, and a two-backend stack
    (wordpress woocommerce) where BOTH cookie families skip."""
    # ?s= search -> does NOT skip. This assertion is INVERTED: `s` was a
    # bare-name row in ct_wp_args and every site search bypassed. It bought no
    # safety (a logged-out visitor's results are anonymous-identical; a
    # logged-in editor is bypassed by wordpress_logged_in_ on the cookie tier)
    # and it removed miss-collapsing from the most expensive query WordPress
    # runs. Full coverage is in test_wordpress_search_and_preview, which uses a
    # location whose key carries the query string; /auto/ keys on $uri alone, so
    # all that can be asserted here is that ?s= no longer classifies as dynamic.
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
    cacheable unless stacked with `wordpress`, and `joomla` in it shipped no
    cookie rule at all.

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
    s2, b2, h2 = fetch(ng.port, "/cc/setcookie")
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
    with urllib.request.urlopen(req, timeout=5) as r:
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
    "max-age=1, must-revalidate"; under /ccignmr/ (ignore_cc on, valid 1s, default
    stale_mult 4 => 4s stale window) the entry must still be STALE-served at ~2s.
    Without the fix (must-revalidate parsed despite ignore_cc) the window collapses
    to 1s and the 2s read is a hard miss to origin. Inverse of
    test_must_revalidate_collapses_stale (the /mrev/ honor_cc case)."""
    uri = "/ccignmr/mustrev"
    fetch(ng.port, uri)                                    # prime (miss, stores)
    _, _, h1 = fetch(ng.port, uri)
    assert h1.get("x-cache") == "HIT", \
        f"ignore_cc must store the must-revalidate response; got {h1.get('x-cache')}"
    time.sleep(2.0)                                        # past 1s fresh, < 4s stale
    before = origin.hits
    _, _, h2 = fetch(ng.port, uri)
    assert h2.get("x-cache") == "STALE", \
        ("ignore_cc must keep the stale window (must-revalidate ignored): expected "
         f"STALE at 2s, got X-Cache={h2.get('x-cache')} — window was collapsed")
    assert origin.hits == before, \
        "stale serve under ignore_cc unexpectedly hit origin (window collapsed?)"


def test_valid_zero_is_forever(ng: Nginx, origin: Origin) -> None:
    """cache_turbo_valid 0 == "cache forever": the stored entry must stay FRESH
    (a HIT), not become instantly stale. Pre-fix a literal 0 fresh TTL made the
    very next request a STALE serve and broke L2; now it resolves to a long
    finite TTL and behaves as a normal long-lived HIT."""
    base = origin.hits
    _, b0, h0 = fetch(ng.port, "/forever/f")
    assert "x-cache" not in h0, "first should miss to origin"
    _, b1, h1 = fetch(ng.port, "/forever/f")
    assert h1.get("x-cache") == "HIT", \
        f"valid 0 must serve a FRESH HIT, got X-Cache={h1.get('x-cache')}"
    assert b1 == b0, "HIT served a different body"
    time.sleep(2.0)
    _, b2, h2 = fetch(ng.port, "/forever/f")
    assert h2.get("x-cache") == "HIT", \
        f"valid 0 must still be fresh after a delay, got X-Cache={h2.get('x-cache')}"
    assert origin.hits == base + 1, \
        "a 'forever' entry must not re-hit the origin while fresh"


def test_honor_ttl_clamped_to_max(ng: Nginx, origin: Origin) -> None:
    """STAB-5 TTL clamp (module.c:4873): honor mode reads an unbounded upstream
    max-age (~3170 years, > TTL_MAX 0xFFFFFFFF). The clamp caps it before the
    uint32 fresh_ttl cast and the stale-window multiply; without the clamp those
    could overflow/wrap the fresh window to a small or instantly-stale value.
    Observable proof: the entry stays a FRESH HIT (no re-hit to origin) rather
    than going stale — a wrapped TTL would surface as a STALE serve here."""
    base = origin.hits_for("ttlclamp")           # path-scoped: immune to bg-refresh noise
    _, b0, h0 = fetch(ng.port, "/cc7/ttlclamp")
    assert "x-cache" not in h0, "first should miss to origin"
    _, b1, h1 = fetch(ng.port, "/cc7/ttlclamp")
    assert h1.get("x-cache") == "HIT", \
        f"clamped huge max-age must serve a FRESH HIT, got {h1.get('x-cache')}"
    time.sleep(2.0)
    _, b2, h2 = fetch(ng.port, "/cc7/ttlclamp")
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
    base = origin.hits
    _, _, h0 = fetch(ng.port, "/av/u?v=cs")
    assert "x-cache" not in h0, "first should miss"
    _, _, h1 = fetch(ng.port, "/av/u?v=cs")
    assert "x-cache" not in h1, \
        f"Vary on an un-keyable axis must stay uncacheable, got {h1.get('x-cache')}"
    assert origin.hits == base + 2, "un-keyable Vary axis was wrongly cached"


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
    before = origin.hits
    s1, b1, h1 = fetch_raw(ng.port, "/cond/cond-inm",
                           headers={"If-None-Match": '"v11etag"'})
    assert s1 == 304, f"matching If-None-Match should be 304, got {s1}"
    assert b1 == "", f"304 must have no body, got {b1!r}"
    assert h1.get("x-cache") == "HIT", f"304 should be a cache HIT: {h1}"
    assert origin.hits == before, "304 must be served from cache, not origin"


def test_conditional_inm_list_short_first(ng: Nginx, origin: Origin) -> None:
    """COR-11: an If-None-Match LIST whose FIRST tag is shorter than the cached
    ETag must still match a later equal tag — the parser skips to the next comma
    instead of bailing on the whole header."""
    s0, _, h0 = fetch_raw(ng.port, "/cond/cond-list")
    assert s0 == 200 and h0.get("etag") == '"v11etag"', f"prime: {s0} {h0}"
    before = origin.hits
    s1, b1, h1 = fetch_raw(ng.port, "/cond/cond-list",
                           headers={"If-None-Match": '"x", "v11etag"'})
    assert s1 == 304, f"a later matching tag must 304, got {s1}"
    assert b1 == "", f"304 must have no body, got {b1!r}"
    assert h1.get("x-cache") == "HIT" and origin.hits == before, \
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
    full 200 body, never a 304 from an unvalidated stale copy."""
    s0, _, h0 = fetch_raw(ng.port, "/condst/cond-x")                    # prime, fresh 1s
    assert s0 == 200 and h0.get("etag") == '"v11etag"', f"prime: {s0} {h0}"
    # while still fresh, a matching INM is a 304 (the existing fresh behaviour)
    sf, bf, hf = fetch_raw(ng.port, "/condst/cond-x",
                           headers={"If-None-Match": '"v11etag"'})
    assert sf == 304 and bf == "" and hf.get("x-cache") == "HIT", \
        f"fresh conditional should 304: {sf} {bf!r} {hf}"
    time.sleep(1.4)                                                # now stale
    s1, b1, h1 = fetch_raw(ng.port, "/condst/cond-x",
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
    before = origin.hits
    s, _, h = fetch_raw(ng.port, "/cond/rns",
                        headers={"Cache-Control": "no-store"})
    assert s == 200, f"no-store request should still serve 200: {s}"
    assert "x-cache" not in h, "a no-store request is an origin miss, not a HIT"
    assert origin.hits == before + 1, "no-store must reach the origin"
    # nothing was stored: the next plain GET is itself a miss (origin hit again)
    s2, _, h2 = fetch_raw(ng.port, "/cond/rns")
    assert "x-cache" not in h2 and origin.hits == before + 2, \
        f"no-store response must not have been cached: {h2}"


def test_rfc1_request_max_age_zero_revalidates(ng: Nginx, origin: Origin) -> None:
    """RFC-1 (§5.2.1.1): a request max-age=0 (browser force-refresh) forces a
    revalidation — the cached entry is bypassed to the origin and refreshed."""
    fetch_raw(ng.port, "/cond/ma0")                                # prime
    _, _, hhit = fetch_raw(ng.port, "/cond/ma0")
    assert hhit.get("x-cache") == "HIT", "entry should be cached before refresh"
    before = origin.hits
    s, _, h = fetch_raw(ng.port, "/cond/ma0",
                        headers={"Cache-Control": "max-age=0"})
    assert s == 200, f"max-age=0 should still serve 200: {s}"
    assert "x-cache" not in h, "max-age=0 must revalidate at origin, not HIT"
    assert origin.hits == before + 1, "max-age=0 must reach the origin"


def test_rfc1_request_max_age_n(ng: Nginx, origin: Origin) -> None:
    """RFC-1 (§5.2.1.1): request max-age=N rejects an entry older than N seconds
    (revalidate at origin); a generous N still HITs the same entry."""
    fetch_raw(ng.port, "/cond/man")                                # prime
    time.sleep(2.2)
    before = origin.hits
    s0, _, h0 = fetch_raw(ng.port, "/cond/man",
                          headers={"Cache-Control": "max-age=30"})
    assert h0.get("x-cache") == "HIT" and origin.hits == before, \
        f"max-age=30 on a ~2s entry should HIT: {h0}"
    s1, _, h1 = fetch_raw(ng.port, "/cond/man",
                          headers={"Cache-Control": "max-age=1"})
    assert s1 == 200 and "x-cache" not in h1, \
        f"max-age=1 on a ~2s entry must revalidate at origin: {h1}"
    assert origin.hits == before + 1, "tight max-age must reach the origin"


def test_rfc1_request_min_fresh(ng: Nginx, origin: Origin) -> None:
    """RFC-1 (§5.2.1.3): request min-fresh=N rejects an entry that will not stay
    fresh for at least N more seconds."""
    fetch_raw(ng.port, "/cond/mf")                                 # prime, fresh 30s
    before = origin.hits
    s0, _, h0 = fetch_raw(ng.port, "/cond/mf",
                          headers={"Cache-Control": "min-fresh=5"})
    assert h0.get("x-cache") == "HIT" and origin.hits == before, \
        f"min-fresh=5 with ~30s left should HIT: {h0}"
    s1, _, h1 = fetch_raw(ng.port, "/cond/mf",
                          headers={"Cache-Control": "min-fresh=600"})
    assert s1 == 200 and "x-cache" not in h1, \
        f"min-fresh=600 with ~30s left must revalidate: {h1}"
    assert origin.hits == before + 1, "unmet min-fresh must reach the origin"


def test_rfc1_request_max_stale(ng: Nginx, origin: Origin) -> None:
    """RFC-1 (§5.2.1.2): on a stale entry, a client sending max-age WITHOUT
    max-stale gets a revalidation; adding max-stale re-permits the stale serve."""
    fetch_raw(ng.port, "/condst/cond-ms")                          # prime, fresh 1s
    time.sleep(1.5)                                                # now stale
    before = origin.hits
    # max-stale present -> accept the stale copy (beta 1, no refresh)
    s0, b0, h0 = fetch_raw(ng.port, "/condst/cond-ms",
                           headers={"Cache-Control": "max-age=1, max-stale=30"})
    assert s0 == 200 and b0 and h0.get("x-cache") == "STALE", \
        f"max-stale must permit the stale serve: {s0} {h0}"
    assert origin.hits == before, "max-stale stale serve must not hit origin"
    # same tight max-age but NO max-stale -> no stale tolerance -> revalidate
    s1, _, h1 = fetch_raw(ng.port, "/condst/cond-ms",
                          headers={"Cache-Control": "max-age=1"})
    assert s1 == 200 and "x-cache" not in h1, \
        f"max-age without max-stale must revalidate a stale entry: {h1}"
    assert origin.hits == before + 1, "no-max-stale revalidation must hit origin"


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
    before = origin.hits
    s0, _, h0 = fetch_raw(ng.port, "/condst/p4-nostore",
                          headers={"Cache-Control": "no-store, max-age=99"})
    assert s0 == 200 and origin.hits == before + 1, \
        f"no-store request must reach origin: {s0} hits={origin.hits}"
    s1, _, h1 = fetch_raw(ng.port, "/condst/p4-nostore")           # plain GET
    assert s1 == 200 and h1.get("x-cache") != "HIT" \
        and origin.hits == before + 2, \
        f"no-store must have suppressed storage -> second GET MISSes: {h1}"

    # (b) max-stale half of a combined directive on a stale entry.
    fetch_raw(ng.port, "/condst/p4-multi")                         # prime, fresh 1s
    time.sleep(1.5)                                                # now stale
    before = origin.hits
    s2, b2, h2 = fetch_raw(ng.port, "/condst/p4-multi",
                           headers={"Cache-Control": "no-store, max-stale=30"})
    assert s2 == 200 and b2 and h2.get("x-cache") == "STALE", (
        f"max-stale half of the combined directive must permit the stale "
        f"serve: {s2} {h2}")
    assert origin.hits == before, "combined-directive stale serve must not hit origin"


def test_rfc2_swr_duration_extends_stale(ng: Nginx, origin: Origin) -> None:
    """RFC-2: a response stale-while-revalidate=10 extends the stale window past
    the cache_turbo_stale_mult default (which would expire the 1s entry at ~4s),
    so the copy is still STALE-serveable at ~5s."""
    fetch_raw(ng.port, "/swrdur/swrdur-x")                         # prime, fresh 1s
    time.sleep(5)                                                  # > default 4s window
    before = origin.hits
    s, b, h = fetch_raw(ng.port, "/swrdur/swrdur-x")
    assert s == 200 and b, f"SWR-extended entry should still serve: {s}"
    assert h.get("x-cache") == "STALE", \
        f"stale-while-revalidate must keep it serveable past the default: {h}"
    assert origin.hits == before, "SWR stale serve (beta 1) must not hit origin"


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


def test_backend_prefix_subdir(ng: Nginx) -> None:
    """item 18: preset uris[] are anchored at byte 0, so a subdirectory install
    matches no URI rule and its admin surface is cacheable.
    cache_turbo_backend_prefix rebases r->uri onto the mount before the preset
    URI tier runs. Asserts the fix, the bug it fixes (control location), that a
    URI outside the mount does NOT inherit the app's rules, and that the
    segment-boundary semantics survive the rebase."""
    # THE BUG, still live on a location without the directive. If this ever
    # reads BYPASS, the fix landed somewhere global and the /shop/ assertions
    # below prove nothing.
    _, _, h0 = fetch(ng.port, "/noshop/wp-admin/")
    assert h0.get("x-ct-status") == "MISS", \
        ("/noshop/wp-admin/ must still be cacheable without the directive -- "
         f"otherwise this test cannot prove the fix, got {h0.get('x-ct-status')}")
    _, _, h1 = fetch(ng.port, "/noshop/wp-admin/")
    assert h1.get("x-ct-status") == "HIT", \
        ("/noshop/wp-admin/ must CACHE without the directive (the item-18 bug) "
         f"-- got {h1.get('x-ct-status')}")

    # THE FIX: same path under the mount, with the directive -> preset URI rule
    # matches after the rebase -> bypass.
    _, _, h = fetch(ng.port, "/shop/wp-admin/")
    assert h.get("x-ct-status") == "BYPASS", \
        ("/shop/wp-admin/ must bypass: cache_turbo_backend_prefix rebases it to "
         f"/wp-admin/ so the wordpress preset rule matches, got {h.get('x-ct-status')}")

    # a second rebased needle, to prove the rebase is not special-cased to one rule
    _, _, h = fetch(ng.port, "/shop/wp-login.php")
    assert h.get("x-ct-status") == "BYPASS", \
        f"/shop/wp-login.php must bypass after rebase, got {h.get('x-ct-status')}"

    # OUTSIDE the mount: backend_prefix is /shop/ but the URI starts with
    # /elsewhere/, so the rebase must not fire. A misconfigured mount leaves the
    # URI alone rather than force-matching -- it degrades to today's behaviour.
    _, _, h0 = fetch(ng.port, "/elsewhere/wp-admin/")
    assert h0.get("x-ct-status") == "MISS", \
        ("a URI outside the configured mount must not be rebased, got "
         f"{h0.get('x-ct-status')}")
    _, _, h1 = fetch(ng.port, "/elsewhere/wp-admin/")
    assert h1.get("x-ct-status") == "HIT", \
        ("an unrebased URI keeps today's (buggy-by-design) caching behaviour, "
         f"got {h1.get('x-ct-status')}")

    # BOUNDARY survives the rebase: "/shop/wp-adminfoo" rebases to
    # "/wp-adminfoo", where the byte after the needle is a letter -> no match.
    _, _, h0 = fetch(ng.port, "/shop/wp-adminfoo")
    assert h0.get("x-ct-status") == "MISS", \
        ("/shop/wp-adminfoo must NOT match /wp-admin/ after rebase (letters "
         f"continue past the needle), got {h0.get('x-ct-status')}")
    _, _, h1 = fetch(ng.port, "/shop/wp-adminfoo")
    assert h1.get("x-ct-status") == "HIT", \
        f"/shop/wp-adminfoo must cache (not bypassed), got {h1.get('x-ct-status')}"

    # a normal page under the mount still caches -- the rebase must not turn the
    # whole mounted subtree into a bypass.
    _, _, h0 = fetch(ng.port, "/shop/about")
    assert h0.get("x-ct-status") == "MISS", "mounted normal page first fetch MISS"
    _, _, h1 = fetch(ng.port, "/shop/about")
    assert h1.get("x-ct-status") == "HIT", \
        f"/shop/about must cache, got {h1.get('x-ct-status')}"


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


def _admin_lock_waits(ng: Nginx) -> int:
    import json
    _, b, _ = fetch(ng.port, "/_cache")
    return int(json.loads(b).get("lock_waits", 0))


def test_cold_single_flight(ng: Nginx, origin: Origin) -> None:
    """v10: a burst of first-hits on ONE virgin (never-cached) key collapses to a
    single origin fetch — the first request regenerates, the rest WAIT for the
    fill and then serve it, instead of every reader stampeding the origin."""
    uri = "/cold/sf"                               # never fetched before
    base = origin.hits
    waits0 = _admin_lock_waits(ng)
    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
        results = list(pool.map(lambda _: fetch(ng.port, uri), range(40)))
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


def _admin_l2_misses(ng: Nginx) -> int:
    import json
    _, b, _ = fetch(ng.port, "/_cache")
    return int(json.loads(b).get("l2_misses", 0))


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


def _admin_min_uses_skips(ng: Nginx) -> int:
    import json
    _, b, _ = fetch(ng.port, "/_cache")
    return int(json.loads(b).get("min_uses_skips", 0))


def test_min_uses(ng: Nginx, origin: Origin) -> None:
    """v15 cache_turbo_min_uses N: a response is cached only after its key has
    cold-missed N times. /minuses/ sets N=3 — the first two misses run to the
    origin without storing, the third stores, the fourth is a HIT served from
    cache. The min_uses_skips counter rises by exactly the two skipped misses."""
    uri = "/minuses/page1"                       # never fetched before
    base = origin.hits
    skips0 = _admin_min_uses_skips(ng)

    # Below threshold: misses 1 and 2 both reach the origin, neither is cached.
    for i in (1, 2):
        s, _, h = fetch(ng.port, uri)
        assert s == 200, f"sub-threshold req{i} status {s}"
        assert "x-cache" not in h, \
            f"req{i} must NOT be a HIT (below min_uses): {h.get('x-cache')}"
    assert origin.hits == base + 2, \
        f"both sub-threshold reqs must hit origin: {origin.hits - base}"

    # The third miss reaches the threshold: THIS request stores (still served
    # from the origin, no X-Cache), so its body is what later HITs return.
    s, b3, h3 = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in h3, \
        "the threshold-reaching miss is served from origin, then stored"
    assert origin.hits == base + 3, "the storing miss must reach the origin"

    # The fourth request is now a cache HIT — no further origin traffic.
    s, b4, h4 = fetch(ng.port, uri)
    assert h4.get("x-cache") == "HIT", f"req4 X-Cache={h4.get('x-cache')}"
    assert origin.hits == base + 3, "req4 must be served from cache, not origin"
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
    base = origin.hits

    s, _, h1 = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in h1, "first miss must reach the origin"

    s, _, h2 = fetch(ng.port, uri)
    assert h2.get("x-cache") == "HIT", \
        ("the balanced band must store on the FIRST miss (min_uses=1); got "
         f"X-Cache={h2.get('x-cache')} -- a band row other than aggressive was "
         "given min_uses > 1, which is a semver-visible default change")
    assert origin.hits == base + 1, "req2 must be served from cache"


def test_min_uses_directive_beats_band(ng: Nginx, origin: Origin) -> None:
    """H3c: an explicit cache_turbo_min_uses overrides the resolved preset band,
    the same raw/effective split as valid/beta/lock_ttl/stale_mult.

    /pmu/ is `cache_turbo_preset aggressive` (band min_uses=2) plus an explicit
    `cache_turbo_min_uses 1`. The directive must win, so request 2 is a HIT --
    whereas /pab/ (same preset, no directive) needs three requests to get one.
    Without the raw/effective wiring the band would win and req2 would miss."""
    uri = "/pmu/beats-band"                      # never fetched before
    base = origin.hits

    s, _, h1 = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in h1, "first miss must reach the origin"

    s, _, h2 = fetch(ng.port, uri)
    assert h2.get("x-cache") == "HIT", \
        ("explicit cache_turbo_min_uses 1 must beat the aggressive band's 2, so "
         f"req2 is a HIT; got X-Cache={h2.get('x-cache')} -- the directive lost "
         "to the band, i.e. min_uses_raw is not resolving ahead of band->min_uses")
    assert origin.hits == base + 1, "req2 must be served from cache"


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


def _admin_l2_neg_skips(ng: Nginx) -> int:
    """L13: count of L2 GETs skipped by a live negative memo (admin stats)."""
    import json
    _, b, _ = fetch(ng.port, "/_cache")
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
    skips0 = _admin_l2_neg_skips(ng)
    before = _redis_conns_received(redis)
    s2, _, _ = fetch(ng.port, uri)
    assert s2 == 200, f"req2 status {s2}"
    time.sleep(0.4)
    second = _redis_conns_received(redis) - before

    assert second < first, \
        (f"req2 opened {second} Redis connections vs req1's {first} -- the "
         "negative memo did not suppress the repeat L2 GET")
    assert _admin_l2_neg_skips(ng) - skips0 >= 1, \
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

    skips0 = _admin_l2_neg_skips(ng)
    fetch(ng.port, uri)                   # inside the window: skipped
    assert _admin_l2_neg_skips(ng) - skips0 >= 1, \
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
    skips1 = _admin_l2_neg_skips(ng)
    before = _redis_conns_received(redis)
    s, _, _ = fetch(ng.port, uri)
    assert s == 200, f"post-expiry status {s}"
    time.sleep(0.4)
    after = _redis_conns_received(redis) - before

    assert after >= 1, \
        (f"after the memo expired the request opened {after} Redis connections "
         "-- the memo is not expiring, so L2 is effectively disabled for this key")
    assert _admin_l2_neg_skips(ng) - skips1 == 0, \
        "an expired memo must not count as a skip"


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

    skips0 = _admin_l2_neg_skips(ng)
    mu0 = _admin_min_uses_skips(ng)

    s, _, h = fetch(ng.port, uri)         # miss 2 within the window
    assert s == 200, f"req2 status {s}"

    assert _admin_l2_neg_skips(ng) - skips0 >= 1, \
        "the memo stopped working once min_uses shared the node"
    assert _admin_min_uses_skips(ng) - mu0 >= 1, \
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
    uri = f"/l2neg/outage-{time.time()}"

    redis.stop()
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
    skips0 = _admin_l2_neg_skips(ng)
    s, _, _ = fetch(ng.port, uri)
    assert s == 200, f"post-recovery status {s}"

    assert _admin_l2_neg_skips(ng) - skips0 == 0, (
        "an L2 outage armed the negative memo: the post-recovery request was "
        "memo-skipped instead of re-consulting L2, so a transient outage keeps L2 "
        "switched off for up to l2_negative_ttl afterwards (Codex #5)")


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
        mu0 = _admin_min_uses_skips(ng)
        s, _, _ = fetch(ng.port, uri)
        assert s == 200, f"status {s}"
        skips_seen.append(_admin_min_uses_skips(ng) - mu0)
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
        return fetch(ng.port, f"/e/p7-{random.randint(0, keys - 1)}")[0]

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
        return fetch(ng.port, uri)[0]

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
                 "# TYPE cache_turbo_l2_hits_total counter",
                 "# TYPE cache_turbo_l2_misses_total counter",
                 "# TYPE cache_turbo_min_uses_skips_total counter",
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
    base = origin.hits
    s, b, _ = fetch(ng.port, f"/_cache?url={uri}", method="POST")
    assert s == 200, f"warm status {s}"
    assert json.loads(b)["warmed"] == 1, f"warmed count: {b}"
    # the bg subrequest reaching origin is our completion signal
    assert wait_for(lambda: origin.hits == base + 1), \
        "warm subrequest never hit the origin"
    time.sleep(0.2)                     # let the store settle after the response
    after = origin.hits
    # first real visit must be served from the warm-populated entry
    s2, _, h2 = fetch(ng.port, uri)
    assert s2 == 200
    assert h2.get("x-cache") == "HIT", \
        f"warm did not populate the cache (X-Cache={h2.get('x-cache')})"
    assert origin.hits == after, \
        f"GET after warm hit the origin ({origin.hits} vs {after})"


def test_warm_multi(ng: Nginx, origin: Origin) -> None:
    """v3-3: a comma-separated ?url=a,b warms both; both HIT afterwards."""
    import json
    a, b_uri = "/c/warm-m1", "/c/warm-m2"
    base = origin.hits
    s, body, _ = fetch(ng.port, f"/_cache?url={a},{b_uri}", method="POST")
    assert s == 200, f"warm-multi status {s}"
    assert json.loads(body)["warmed"] == 2, f"warmed count: {body}"
    assert wait_for(lambda: origin.hits == base + 2), \
        "both warm subrequests never reached origin"
    time.sleep(0.2)
    after = origin.hits
    for u in (a, b_uri):
        _, _, h = fetch(ng.port, u)
        assert h.get("x-cache") == "HIT", f"{u} not warmed (X-Cache={h.get('x-cache')})"
    assert origin.hits == after, "a warmed GET still hit origin"


def test_warm_no_url(ng: Nginx) -> None:
    """v3-3: POST /_cache with no recognised arg is a 400 with a JSON error."""
    import json
    s, b, h = fetch(ng.port, "/_cache", method="POST")
    assert s == 400, f"no-arg admin POST returned {s}, expected 400"
    assert "application/json" in h.get("content-type", ""), h.get("content-type")
    assert "error" in json.loads(b), f"expected an error body, got {b!r}"


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
            lambda: redis.cli("-n", "0", "EXISTS", key0) == "1",
            timeout=4.0), f"DB 0 keepalive write missing for {k0}"
        assert redis.cli("-n", "1", "EXISTS", key0) == "0", \
            f"DB 0 key leaked into DB 1 through keepalive reuse: {k0}"

        fetch(ng.port, f"/l2ka1/x?k={k1}")
        assert wait_for(
            lambda: redis.cli("-n", "1", "EXISTS", key1) == "1",
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
              ng.port + 5, ng.origin_port, ng.runner_raw,
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
    s, body2, h2 = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in h2, \
        f"expired L2 object was still served as {h2.get('x-cache')}"
    assert origin.hits == origin_before + 1, \
        "expired L2 object did not fall through to origin"
    assert body2 != seeded.decode()


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

        before = origin.hits
        s, body, h = fetch(ng.port, uri)
        assert s == 200, f"{name}: status {s}"
        assert body.startswith("gen-"), \
            f"{name}: served garbage body {body!r} from a malformed L2 blob"
        assert "x-cache" not in h, \
            f"{name}: malformed blob served as {h.get('x-cache')} (not a miss)"
        assert origin.hits == before + 1, \
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

    # Exactly 16 tags -- at the cap, nothing dropped, must NOT warn.
    before = len(log_text())
    at_cap = ",".join(f"t{i}" for i in range(16))
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
    redis.cli("DEL", tag_key("blog"), tag_key("news"))
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

    s, body_a, h = fetch(ng.port, uri)             # prime -> origin -> L1 + L2
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
    while time.time() < deadline and origin.hits == base:
        fetch(ng.port, uri)
        time.sleep(0.05)
    time.sleep(0.4)

    regens = origin.hits - base
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

    s, body_a, h = fetch(ng.port, uri)             # prime -> origin -> L1 + L2
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
    origin_before = origin.hits
    s, body_b, h3 = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in h3, \
        f"post-all-purge read should miss to origin, got {h3.get('x-cache')}"
    assert origin.hits == origin_before + 1, \
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
    assert redis.cli("-n", "0", "EXISTS", owned) == "0", \
        "literal glob-prefix key was not purged"
    assert redis.cli("-n", "0", "EXISTS", foreign) == "1", \
        "glob prefix widened SCAN and deleted an unrelated key"
    redis.cli("-n", "0", "DEL", foreign)


def test_normalize_arg_order(ng: Nginx, origin: Origin) -> None:
    """v3-1: ?b=2&a=1 and ?a=1&b=2 normalize to one cache slot — the reordered
    second request is a HIT serving the first body, origin hit exactly once."""
    base = origin.hits
    s1, b1, h1 = fetch(ng.port, "/n/order?b=2&a=1")
    assert s1 == 200 and "x-cache" not in h1, "first request should miss to origin"
    s2, b2, h2 = fetch(ng.port, "/n/order?a=1&b=2")
    assert h2.get("x-cache") == "HIT", \
        f"reordered args should HIT, got X-Cache={h2.get('x-cache')}"
    assert b2 == b1, "reordered request served a different body"
    assert origin.hits == base + 1, \
        f"origin hit {origin.hits - base} times (args not normalized to one key)"


def test_normalize_strips_tracking(ng: Nginx, origin: Origin) -> None:
    """Built-in denylist: utm_* and fbclid are dropped, so ?p=1&utm_source=x&
    fbclid=y collapses onto the same slot as a bare ?p=1."""
    base = origin.hits
    _, b1, h1 = fetch(ng.port, "/n/track?p=1")
    assert "x-cache" not in h1, "prime should miss to origin"
    _, b2, h2 = fetch(ng.port, "/n/track?p=1&utm_source=news&utm_medium=cpc&fbclid=z")
    assert h2.get("x-cache") == "HIT", \
        f"tracking-only diff should HIT, got X-Cache={h2.get('x-cache')}"
    assert b2 == b1, "tracking-laden request served a different body"
    assert origin.hits == base + 1, "tracking params were not stripped from the key"


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
    base = origin.hits
    _, b1, h1 = fetch(ng.port, "/n/distinct?a=1")
    assert "x-cache" not in h1, "first should miss"
    _, b2, h2 = fetch(ng.port, "/n/distinct?a=2")
    assert "x-cache" not in h2, \
        f"a different value must MISS, got X-Cache={h2.get('x-cache')}"
    assert b2 != b1, "distinct args wrongly served the same cached body"
    assert origin.hits == base + 2, "both distinct args should reach origin"


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
    base = origin.hits
    _, b1, h1 = fetch(ng.port, "/n/voff",
                      headers={"Accept-Encoding": "br", "User-Agent": _UA_MOBILE})
    assert "x-cache" not in h1, "prime should miss to origin"
    _, b2, h2 = fetch(ng.port, "/n/voff",
                      headers={"Accept-Encoding": "gzip", "User-Agent": _UA_DESKTOP})
    assert h2.get("x-cache") == "HIT", \
        ("vary off: differing encoding/device must still HIT one slot, "
         f"got X-Cache={h2.get('x-cache')}")
    assert b2 == b1, "vary off served a different body (key wrongly split)"
    assert origin.hits == base + 1, "vary off must keep one slot regardless of headers"


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
    base = origin.hits
    p = "/av/encsame?v=ae"
    _, b1, _ = fetch(ng.port, p, {"Accept-Encoding": "gzip"})
    _, b2, _ = fetch(ng.port, p, {"Accept-Encoding": "gzip, deflate"})
    assert b1 == b2, (b1, b2)
    assert origin.hits - base == 1, origin.hits - base


def test_auto_vary_device(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary: `Vary: User-Agent` splits by the coarse device class."""
    base = origin.hits
    p = "/av/dev?v=ua"
    mob = {"User-Agent": "Mozilla/5.0 (iPhone; CPU) Mobile"}
    dsk = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
    _, m1, _ = fetch(ng.port, p, mob)
    _, m2, _ = fetch(ng.port, p, mob)
    _, d1, _ = fetch(ng.port, p, dsk)
    _, d2, _ = fetch(ng.port, p, dsk)
    assert m1 == m2 and d1 == d2, (m1, m2, d1, d2)
    assert m1 != d1, ("mobile and desktop shared a slot", m1, d1)
    assert origin.hits - base == 2, origin.hits - base


def test_auto_vary_language(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary: `Vary: Accept-Language` splits by the LANG axis class
    (S7: primary-subtag class, not the raw header)."""
    base = origin.hits
    p = "/av/lang?v=al"
    _, e1, _ = fetch(ng.port, p, {"Accept-Language": "en"})
    _, e2, _ = fetch(ng.port, p, {"Accept-Language": "en"})
    _, f1, _ = fetch(ng.port, p, {"Accept-Language": "fr"})
    assert e1 == e2, (e1, e2)
    assert e1 != f1, ("en and fr shared a slot", e1, f1)
    assert origin.hits - base == 2, origin.hits - base


def test_auto_vary_language_primary_subtag_shares(ng: Nginx,
                                                    origin: Origin) -> None:
    """S7: LANG folds to the primary-subtag CLASS, so `en-US,en;q=0.9` and
    `en-GB,en;q=0.8` -- distinct raw headers, same primary subtag `en` -- now
    SHARE one slot -> a single origin hit. This is the actual fix: before S7
    the raw fold gave each browser locale string its own variant, blowing up
    the keyspace on an i18n site for representations that are byte-identical.
    Canary: $cache_turbo_status (echoed as X-CT-Status) is HIT on the second
    request, not just "body matches"."""
    base = origin.hits
    p = "/av/langshare?v=al"
    s1, b1, h1 = fetch(ng.port, p, {"Accept-Language": "en-US,en;q=0.9"})
    s2, b2, h2 = fetch(ng.port, p, {"Accept-Language": "en-GB,en;q=0.8"})
    assert s1 == 200 and s2 == 200, (s1, s2)
    assert b1 == b2, ("en-US and en-GB did not share a slot", b1, b2)
    assert origin.hits - base == 1, \
        ("en-US and en-GB should fold to one 'en' class -> one origin hit",
         origin.hits - base)


def test_auto_vary_language_different_primary_splits(ng: Nginx,
                                                       origin: Origin) -> None:
    """S7 negative guard: `en` and `de` are DIFFERENT primary subtags and must
    still SPLIT into distinct slots -- proves the fold isn't over-collapsing
    everything to one class."""
    base = origin.hits
    p = "/av/langsplit?v=al"
    _, en1, _ = fetch(ng.port, p, {"Accept-Language": "en-US,en;q=0.9"})
    _, en2, _ = fetch(ng.port, p, {"Accept-Language": "en-GB,en;q=0.8"})
    _, de1, _ = fetch(ng.port, p, {"Accept-Language": "de-DE,de;q=0.9"})
    assert en1 == en2, ("en variants should still share", en1, en2)
    assert en1 != de1, ("en and de shared a slot", en1, de1)
    assert origin.hits - base == 2, origin.hits - base


def test_auto_vary_language_absent_splits_from_class(ng: Nginx,
                                                       origin: Origin) -> None:
    """S7: an absent Accept-Language header folds to its OWN empty class "" --
    it must still split from a present `en` header, not collide with it (the
    empty class is skip-shaped but must NOT be skipped: skipping the axis
    would collide a present-but-empty header with an absent one)."""
    base = origin.hits
    p = "/av/langabsent?v=al"
    s1, absent1, h1 = fetch(ng.port, p)  # no Accept-Language header at all
    s2, absent2, h2 = fetch(ng.port, p)
    s3, en1, h3 = fetch(ng.port, p, {"Accept-Language": "en-US,en;q=0.9"})
    assert s1 == 200 and s2 == 200 and s3 == 200, (s1, s2, s3)
    assert absent1 == absent2, ("absent header should share its own slot",
                                 absent1, absent2)
    assert absent1 != en1, ("absent Accept-Language shared a slot with 'en'",
                             absent1, en1)
    assert origin.hits - base == 2, origin.hits - base


def test_auto_vary_origin(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary: `Vary: Origin` splits by the raw Origin header value.
    ORIGIN is a CORS security boundary and is NEVER class-folded (S7 touches
    LANG only) -- two distinct Origins must still split into distinct slots."""
    base = origin.hits
    p = "/av/org?v=or"
    _, a1, _ = fetch(ng.port, p, {"Origin": "https://a.example"})
    _, a2, _ = fetch(ng.port, p, {"Origin": "https://a.example"})
    _, c1, _ = fetch(ng.port, p, {"Origin": "https://b.example"})
    assert a1 == a2, (a1, a2)
    assert a1 != c1, ("two Origins shared a slot", a1, c1)
    assert origin.hits - base == 2, origin.hits - base


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
    base = origin.hits
    p = "/av/orgnofold?v=or"
    o1 = "https://a-one.example"
    o2 = "https://a-two.example"
    s1, b1, h1 = fetch(ng.port, p, {"Origin": o1})
    s2, b2, h2 = fetch(ng.port, p, {"Origin": o1})
    s3, b3, h3 = fetch(ng.port, p, {"Origin": o2})
    assert s1 == 200 and s2 == 200 and s3 == 200, (s1, s2, s3)
    assert b1 == b2, ("same Origin should share a slot", b1, b2)
    assert b1 != b3, (
        "ORIGIN got class-folded -- two distinct origins sharing an 8-byte "
        "prefix collapsed onto one slot; this is a CORS cross-origin leak",
        b1, b3)
    assert origin.hits - base == 2, (
        "ORIGIN must stay raw: two distinct origins => two origin hits, "
        "not one folded class", origin.hits - base)


def test_auto_vary_star_uncacheable(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary: `Vary: *` is uncacheable -> every request hits origin."""
    base = origin.hits
    p = "/av/star?v=star"
    _, b1, _ = fetch(ng.port, p)
    _, b2, _ = fetch(ng.port, p)
    assert b1 != b2, ("Vary: * was cached", b1, b2)
    assert origin.hits - base == 2, origin.hits - base


def test_auto_vary_cookie_uncacheable(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary: `Vary: Cookie` is refused (per-user) -> not cached."""
    base = origin.hits
    p = "/av/ck?v=ck"
    _, b1, _ = fetch(ng.port, p)
    _, b2, _ = fetch(ng.port, p)
    assert b1 != b2, ("Vary: Cookie was cached", b1, b2)
    assert origin.hits - base == 2, origin.hits - base


def test_auto_vary_mixed_refused_wins(ng: Nginx, origin: Origin) -> None:
    """v11 auto-Vary: `Vary: Accept-Encoding, Cookie` -> the refused Cookie axis
    wins over the safe encoding axis, so the response is not cached at all."""
    base = origin.hits
    p = "/av/mix?v=mix"
    _, b1, _ = fetch(ng.port, p, {"Accept-Encoding": "gzip"})
    _, b2, _ = fetch(ng.port, p, {"Accept-Encoding": "gzip"})
    assert b1 != b2, ("mixed safe+refused Vary was cached", b1, b2)
    assert origin.hits - base == 2, origin.hits - base


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
        origin.delay = 0.0
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
        origin.delay = 0.0
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
        origin.delay = 0.0
        fetch(ng.port, "/atl/probe")             # prime the probe (fresh 1s)
    finally:
        origin.delay = 0.0

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
        origin.delay = 0.0
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
        origin.delay = 0.0
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
              ng.port + 6, ng.origin_port, ng.runner_raw,
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

    s, body, h = fetch(ng.port, uri)               # miss -> origin -> store
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


def run_all(ng: Nginx, origin: Origin,
            redis: RedisServer | None = None,
            redis_auth: RedisServer | None = None,
            redis_tls: RedisServer | None = None,
            mc: MemcachedServer | None = None) -> None:
    test_miss_then_hit(ng)
    test_post_passthrough_uncached(ng, origin)
    test_compressed_edge_identity_capture(ng)
    test_header_fidelity(ng)
    if ng.fault_injection:
        test_restore_allocation_failure_fails_closed(ng, origin)
        test_file_backed_delegate_never_stores(ng, origin)
    test_max_size_not_cached(ng)
    test_suppress_native_variable(ng)
    test_auto_classify(ng, origin)
    test_auto_classify_suppress_native_interaction(ng, origin)
    test_auto_backend_composition(ng, origin)
    test_woocommerce_wc_ajax(ng, origin)
    test_wordpress_search_and_preview(ng, origin)
    test_header_auth_rest_surfaces(ng, origin)
    test_xenforo_preset(ng, origin)
    test_xenforo_not_in_generic(ng, origin)
    test_discourse_preset(ng, origin)
    test_phpbb_preset(ng, origin)
    test_punbb_cookie_name_default(ng, origin)
    test_vanilla_guest_cookies_stay_cacheable(ng, origin)
    test_phorum_admin_session_cookie(ng, origin)
    test_punbb_phorum_uri_rules(ng, origin)
    test_preset_arg_value_predicate(ng)
    test_preset_arg_scanner(ng, origin)
    test_cookie_pred_multiple_matching_cookies(ng, origin)
    test_vbulletin_preset(ng, origin)
    test_invision_preset(ng, origin)
    test_mybb_preset(ng, origin)
    test_yabb_preset(ng, origin)
    test_phorum_uri_rules_anchor_at_root(ng, origin)
    test_joomla_preset(ng, origin)
    test_drupal_preset(ng, origin)
    test_mediawiki_preset(ng, origin)
    test_magento_preset(ng, origin)
    test_ghost_preset(ng, origin)
    test_wagtail_preset(ng, origin)
    test_kirby_preset(ng, origin)
    test_shopware6_preset(ng, origin)
    test_typo3_preset(ng, origin)
    test_new_presets_not_in_generic(ng, origin)
    test_auto_classify_more(ng, origin)
    test_q2_multibuffer_oversize(ng, origin)
    test_suppress_native_inert_on_plain_location(ng)
    test_suppress_native_e2e_proxy_cache(ng)
    test_invalid_backend_name(ng)
    test_invalid_cache_turbo_mode(ng)
    test_auto_and_generic_are_removed(ng)
    test_backend_separators(ng)
    test_backend_malformed_pipes(ng)
    test_backend_none_is_exclusive(ng)
    test_backend_none_overrides_inherited(ng, origin)
    test_valid_status_rejects_304(ng)
    test_empty_l2_prefix_rejected(ng)
    test_backend_prefix_rejected(ng)
    test_keepalive_cap_rejected(ng)
    test_memcached_keepalive_invalid_rejected(ng)
    test_memcached_keepalive_cap_rejected(ng)
    test_memcached_keepalive_timeout_invalid_rejected(ng)
    test_valid_dup_status_warns(ng)
    test_tag_without_l2_warns(ng)
    test_cache_control_invalid_mode_rejected(ng)
    test_cache_control_duplicate_rejected(ng)
    test_valid_status_rejects_out_of_range_code(ng)
    test_valid_rejects_bad_time(ng)
    test_require_header_rejects_invalid_name(ng)
    test_require_header_duplicate_rejected(ng)
    test_redis_bad_db_rejected(ng)
    test_redis_db_cap_rejected(ng)
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
    test_cdn_cache_control_no_store_refuses(ng)             # RFC 9213
    test_targeted_cache_control_stripped_from_serve(ng)     # RFC 9213
    test_age_header(ng)
    test_request_no_cache(ng, origin)
    test_must_revalidate(ng)
    test_proxy_revalidate(ng)
    test_precise_maxage_token_parse(ng)
    test_ignore_cache_control_overrides_floor(ng, origin)
    test_ignore_cc_must_revalidate_keeps_stale_window(ng, origin)
    test_valid_zero_is_forever(ng, origin)
    test_honor_ttl_clamped_to_max(ng, origin)              # STAB-5 TTL clamp
    test_vary_encoding_qvalue(ng, origin)
    test_auto_vary_unknown_axis_uncacheable(ng, origin)
    test_auto_vary_stale_marker_reachable(ng, origin)
    test_206_never_cached(ng, origin)
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
    test_cache_and_purge_respect_access_control(ng)
    test_bypass(ng)
    test_bypass_uri(ng)
    test_backend_prefix_subdir(ng)
    test_require_header(ng)
    test_key_cookie(ng)
    test_status_variable(ng)
    test_status_stale(ng, origin)
    test_status_expired(ng, origin)
    test_request_cc_serve_verdict_fresh(ng, origin)
    test_request_cc_serve_verdict_stale(ng, origin)
    test_cc_mode_inheritance_child_preset_overrides_parent_ignore(ng, origin)
    test_no_store(ng)
    test_native_cache_headers_stripped(ng)
    test_admin_purge_post_with_body(ng)
    test_concurrent_hits_no_deadlock(ng)
    test_lru_eviction(ng)
    test_p1_coarse_lru_splice_keeps_hot_key_resident(ng)
    test_admin_stats(ng)
    test_admin_prometheus(ng)
    test_admin_purge_key(ng)
    test_admin_gating(ng)
    test_warm_populates(ng, origin)
    test_warm_multi(ng, origin)
    test_warm_no_url(ng)
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
    test_sie_origin_recovers_serves_fresh(ng, origin)       # RFC-2 success not hijacked
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
        test_l2_preserves_original_freshness(ng, origin, redis)
        test_l2_malformed_blob_rejected(ng, origin, redis)  # STAB-4 validate
        test_sie_ttl_stored_in_blob(ng, origin, redis)      # RFC-2 CTB4 sie_ttl
        test_l2_tag_add_on_store(ng, origin, redis)
        test_l2_tag_truncation_warns(ng, origin, redis)
        test_l2_tag_purge(ng, origin, redis)
        test_l2_tag_purge_large(ng, origin, redis)  # STAB-3 + PERF-1/2 pipeline
        test_l2_tag_cap_and_dedup(ng, origin, redis)  # PERF-2 tag cap/dedup
        test_l2_tag_add_batched_one_op(ng, origin, redis)  # L9 one op for N tags
        test_cor5_redis_variant_purge(ng, origin, redis)  # COR-5 variant index
        test_multinode_lock(ng, origin, redis)
        test_lock_self_heal(ng, origin, redis)
        test_cold_single_flight_cross_node(ng, origin, redis)
        test_l2_miss_counted_once_on_cold_park(ng, origin)  # double-count guard
        test_l2_db_select(ng, origin, redis)         # SELECT-only preamble
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
    if mc is not None:
        test_l2_memcached_write_through(ng, origin, mc)        # v13
        test_l2_memcached_cross_instance_fill(ng, origin, mc)  # v13
        test_l2_memcached_purge_key_drops_l2(ng, origin, mc)   # v13
        if redis is not None:
            # child redis over parent memcached — precedence regression lock
            test_l2_backend_inheritance_child_redis_over_parent_memcached(
                ng, origin, redis, mc)
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

    origin_port = args.port + 11
    redis_port = args.port + 21 if args.redis_server else None
    redis_auth_port = args.port + 22 if args.redis_server else None
    redis_tls_port = args.port + 23 if args.redis_server else None
    memcached_port = args.port + 24 if args.memcached_server else None
    redis_password = "ctsecret"
    with tempfile.TemporaryDirectory(prefix="cache-turbo-ci-") as tmp:
        root = pathlib.Path(tmp)
        origin = Origin(origin_port, delay=0.05)
        redis = redis_auth = redis_tls = mc = None
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
            # is missing, skip the rediss:// test rather than failing the suite.
            try:
                tls_certs = gen_tls_certs(root / "redis-tls-certs")
                redis_tls = RedisServer(rbin, root / "redis-tls", redis_tls_port,
                                        tls_certs=tls_certs)
            except (OSError, subprocess.SubprocessError):
                redis_tls = None
                tls_certs = None

        ng = Nginx(binary, module, root / "server", args.port, origin_port,
                   args.runner, args.single_process, redis_port,
                   redis_auth_port=redis_auth_port if redis_auth else None,
                   redis_password=redis_password,
                   redis_tls_port=redis_tls_port if redis_tls else None,
                   redis_tls_ca=(tls_certs or {}).get("ca"),
                   memcached_port=memcached_port if mc else None,
                   fault_injection=args.fault_injection)
        ng.sanitizer = args.sanitizer

        try:
            origin.start()
            if redis is not None:
                redis.start()
            if redis_auth is not None:
                redis_auth.start()
            if redis_tls is not None:
                try:
                    redis_tls.start()
                except Exception:
                    redis_tls = None        # TLS redis refused to start: skip
            if mc is not None:
                mc.start()
            ng.write_config()
            ng.config_test()
            ng.start()
            run_all(ng, origin, redis, redis_auth, redis_tls, mc)
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
            if mc is not None:
                mc.stop()
            origin.stop()

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
          "non-boundary caches), backend_prefix subdir installs (item 18: "
          "rebased preset URI rules + control location proves the bug + "
          "unrebased outside mount + boundary survives rebase + malformed "
          "rejected), DIY key_cookie (v15: value-keyed entries + anon "
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
          "LRU eviction (R6), refresh-under-pressure (R6b), "
          "stale serve (R3), single-flight (R4), "
          "cold-miss single-flight (v10: per-box collapse + lock-off stampede), "
          "min_uses (v15: cache after N misses + off-by-default; "
          "H3c: aggressive band=2, balanced band stays 1, directive beats band, "
          "range-checked), "
          "stale-if-error (v8), background_update off (v8 inline regen), "
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
          "preset arg scanner (';' separator, percent-decoded name and value, "
          "later occurrence, PHP '.'/' '/'+' key mangling, read routes still "
          "cached), "
          "vbulletin preset (NONEMPTY/EQ arms, empty value logged-out, "
          "bb_language keyed, bb_lastvisit NOT keyed), "
          "invision preset (_loggedIn suffix bypass, ips4_theme keyed, "
          "ips4_device_key NOT keyed), "
          "mybb preset (user-suffix bypass survives cookieprefix, mybbtheme keyed exactly, look-alike cookie cannot steer buckets), "
          "yabb preset (Y2* triple bypass, action=logout/login/post/admin/pm "
          "bypass cookie-less, ';'-separated logout, plain reads cached), "
          "header-auth REST surfaces (magento /rest+/soap, drupal /jsonapi+"
          "/oauth, wp ?rest_route=, /restaurant-supplies still cached), "
          "wordpress preset (?s= search CACHES incl. distinct terms, "
          "logged-in editor search bypasses on cookie, ?preview= bypasses), "
          "mediawiki preset (13 mutating core actions bypass cookie-less, "
          "encoded/non-first action, render/info/credits/view stay cached), "
          "punbb/phorum URI rows (edit/delete/moderate/profile/register bypass, "
          "phorum file.php attachment bypass, userlist.php/search.php stay "
          "cached), "
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
