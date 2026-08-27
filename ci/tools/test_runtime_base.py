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

import origin as _origin_module

# Origin imported early so _conn_cursor() and fetch*() can use it before the
# late re-export at the module level.
from origin import (
    Origin,
    _bump_conn,
    wait_port,
)

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


def config_check_env() -> dict[str, str]:
    """Environment for a short-lived `nginx -t` (or the config-parse phase of
    `-s reload`) subprocess -- everywhere this module invokes nginx WITHOUT
    starting the long-running server under test.

    nginx's main() always calls ngx_init_cycle() to parse the config before
    branching on ngx_test_config / ngx_signal, and BOTH of those branches
    return straight out of main() (src/core/nginx.c) without ever calling
    ngx_destroy_pool() on the cycle it just built -- unlike a master/worker
    exit, which does (ngx_process_cycle.c). LeakSanitizer therefore reports
    the ENTIRE config parse -- nginx core, OpenSSL's one-time init, and this
    module's own config-time allocations (e.g. cookie_ac_prepare's
    Aho-Corasick table) -- as leaked on every single `-t`/`-s` invocation.
    Root-caused and confirmed (0 Direct / all Indirect, every stack rooted in
    main -> ngx_init_cycle -> ngx_conf_parse) in
    memory/labs/nginx-cache-turbo-module/issues.md, SRV-ASAN-ABORT-L2-XFILL:
    that is upstream shutdown behaviour on this one code path, not a leak a
    module can fix or a bug to chase.

    Scoping detect_leaks=0 to just these short-lived processes -- instead of
    for the whole suite -- is what lets the actual long-running server (which
    DOES destroy its pools on exit) run with real leak detection ON. Do not
    "fix" this with an LSan suppression file: leak:ngx_create_pool and
    leak:main were both tried and DISPROVEN by negative control -- LSan
    matches a suppression against ANY frame on the allocation stack, and both
    entries are broad enough to also hide a genuine leak in this module's own
    long-running allocations.

    detect_leaks=0 is appended LAST: ASan's flag parser takes the last
    occurrence of a repeated key, so this always wins over whatever
    detect_leaks the caller's environment (a workflow env: block, this
    process's own ASAN_OPTIONS) set for the real server run."""
    env = dict(os.environ)
    opts = env.get("ASAN_OPTIONS", "")
    env["ASAN_OPTIONS"] = f"{opts}:detect_leaks=0" if opts else "detect_leaks=0"
    return env


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





# (name, cum_before, cum_after) per instrumented test, where cum tracks
# c->number = client accepts + upstream connects. Populated by _instrument().
_SPANS: list[tuple[str, int, int]] = []
_ORIGIN_REF: Origin | None = None

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
    return _origin_module._NGX_CLIENT_CONNS + origin_hits


def _instrument(origin: Origin) -> None:
    """Wrap every module-level test_* function so each records the c->number
    cursor before and after it runs. Nested test_* calls just produce nested
    spans; the narrowest span that brackets an alert is the most specific
    attribution. Idempotent-safe: called once from main() before run_all."""
    global _ORIGIN_REF
    _ORIGIN_REF = origin
    import inspect

    def _wrap(name, fn):
        def _runner(*a, **kw):
            before = _conn_cursor()
            _write_breadcrumb(f"{name} {before}")
            try:
                return fn(*a, **kw)
            finally:
                _SPANS.append((name, before, _conn_cursor()))
                _write_breadcrumb(f"DONE {name}")
        _runner._ct_instrumented = True   # type: ignore[attr-defined]
        return _runner

    # MAINT-T1: the tests no longer live in THIS module's globals(), so
    # instrumenting only globals() would wrap nothing at all and disable the
    # breadcrumb/attribution machinery without a word. Wrap in each area
    # module, then rebind the same wrapper in the facade -- run_all() resolves
    # test names against the facade's globals, so an area-only rebind would
    # leave run_all() calling the unwrapped originals.
    targets = [m for n, m in sys.modules.items()
               if m is not None and (n == "test_runtime" or n.startswith("areas."))]
    wrapped: dict[str, object] = {}
    for _mod in targets:
        _g = vars(_mod)
        for _name, _fn in list(_g.items()):
            if not (_name.startswith("test_") and inspect.isfunction(_fn)):
                continue
            if getattr(_fn, "_ct_instrumented", False):
                wrapped.setdefault(_name, _fn)     # already wrapped: keep it
                continue
            if _name not in wrapped:
                wrapped[_name] = _wrap(_name, _fn)
            _g[_name] = wrapped[_name]


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
# Origin, _bump_conn, wait_port, and _origin_module imported at module top
# (MAINT-T3: moved to origin.py). Re-exported for consuming modules.
# --------------------------------------------------------------------------- #

# MAINT-T2: nginx_config() moved to its own module (a 3.8k-line template, not
# test logic). Re-exported here (not via `import *`) so the area modules'
# `from test_runtime_base import *` chain keeps resolving the bare name --
# star-import does not chain transitively through this module.
from nginx_config import (  # re-exported for the areas; F401 via ruff.toml
    PORT_OFFSETS,
    _errlog_level,
    nginx_config,
)


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
        # config_check_env(): a bare `-t` exits without destroying the cycle
        # pool it just built, so under detect_leaks=1 this reports the entire
        # config parse as leaked -- see the function's docstring.
        r = subprocess.run(self.command(test=True), text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=20, env=config_check_env())
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

        # This client-side `-s reload` invocation re-parses the whole config
        # via its own ngx_init_cycle() (to locate the running master) and then
        # exits via ngx_signal_process() -- the same exit-without-destroying-
        # the-cycle-pool path as `-t`, so it needs the same scoped env.
        r = subprocess.run(
            self.runner + [str(self.binary), "-p", str(self.root),
                           "-c", str(self.root / "conf" / "nginx.conf"),
                           "-s", "reload"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=20, env=config_check_env())
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

    def start_monitor(self) -> RedisMonitor:
        """Open a raw MONITOR connection: Redis echoes every command any client
        executes against this instance, timestamped, as it runs. Used to prove a
        wire-level negative (e.g. AUTH/SELECT NOT resent on a reused connection)
        that a state-inspection query (EXISTS/PTTL/...) cannot show — those only
        prove the end state, not what was said on the wire to reach it."""
        return RedisMonitor(self)


class DirtyRedis:
    """A fake Redis that appends a partial RESP frame after every reply.

    GET returns a nil bulk and writes return ``+OK``; both carry one trailing
    ``+`` byte. A correct keepalive driver consumes an exact frame boundary and
    closes these connections. ``accepts`` makes accidental pooling observable.
    """

    def __init__(self, port: int) -> None:
        self.port = port
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._lock = threading.Lock()
        self.accepts = 0

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.listen(32)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        wait_port(self.port)

    @staticmethod
    def _pop_command(buf: bytes) -> tuple[bytes, bytes] | None:
        """Return (command name, remaining bytes) for one complete RESP array."""
        line_end = buf.find(b"\r\n")
        if line_end < 0 or not buf.startswith(b"*"):
            return None
        try:
            count = int(buf[1:line_end])
        except ValueError:
            return None
        pos = line_end + 2
        command = b""
        for i in range(count):
            if pos >= len(buf) or buf[pos:pos + 1] != b"$":
                return None
            line_end = buf.find(b"\r\n", pos)
            if line_end < 0:
                return None
            try:
                length = int(buf[pos + 1:line_end])
            except ValueError:
                return None
            pos = line_end + 2
            if length < 0 or len(buf) - pos < length + 2:
                return None
            if buf[pos + length:pos + length + 2] != b"\r\n":
                return None
            if i == 0:
                command = buf[pos:pos + length].upper()
            pos += length + 2
        return command, buf[pos:]

    def _accept_loop(self) -> None:
        sock = self._sock
        assert sock is not None
        while self._running:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            with self._lock:
                self.accepts += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        buf = b""
        try:
            conn.settimeout(10)
            while self._running:
                parsed = self._pop_command(buf)
                while parsed is None:
                    chunk = conn.recv(65536)
                    if not chunk:
                        return
                    buf += chunk
                    parsed = self._pop_command(buf)
                command, buf = parsed
                reply = b"$-1\r\n+" if command == b"GET" else b"+OK\r\n+"
                conn.sendall(reply)
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


class RedisMonitor:
    """Background reader of `MONITOR` output for one RedisServer. Requires its
    own raw socket (redis-cli MONITOR blocks the process), authenticating first
    if the server has a password. Collects the command name (first RESP token
    after the timestamp/db/addr preamble) of every command seen, so a caller can
    assert exact counts of e.g. AUTH / SELECT / GET / SET without parsing full
    MONITOR line syntax."""

    _CMD_RE = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')

    def __init__(self, redis: RedisServer) -> None:
        self.redis = redis
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._lines: list[str] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def __enter__(self) -> RedisMonitor:
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
            except TimeoutError:
                continue

    def _run(self) -> None:
        buf = b""
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                chunk = self._sock.recv(65536)
            except TimeoutError:
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
            # shutdown() BEFORE close(): the accept thread is parked in
            # accept() holding its own reference to this socket, and on Linux
            # close() alone does not reliably wake it -- the listening fd then
            # stays open in the kernel until that thread happens to exit, so
            # the port keeps showing LISTEN and the next bind() gets
            # EADDRINUSE no matter how long it retries. shutdown() forces the
            # blocked accept() to return immediately.
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None


class DropReplyMemcached:
    """A fake peer that reads one complete memcached command, then closes.

    The successful client-side send followed by a replyless EOF is the ordering
    that proves connect backoff stays armed until a real reply byte arrives.
    ``commands`` excludes the readiness probe, which connects without sending.
    """

    def __init__(self, port: int) -> None:
        self.port = port
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._lock = threading.Lock()
        self.commands = 0

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.listen(16)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        wait_port(self.port)

    def _accept_loop(self) -> None:
        sock = self._sock
        assert sock is not None
        while self._running:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            threading.Thread(target=self._drop_after_command, args=(conn,),
                             daemon=True).start()

    def _drop_after_command(self, conn: socket.socket) -> None:
        buf = b""
        try:
            conn.settimeout(5)
            while b"\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            with self._lock:
                self.commands += 1
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


# FLAKE-ASAN-TIMING-BAND: three unrelated tests (test_cross_node_won_stale_body,
# test_concurrent_hits_no_deadlock, test_cdn_cache_control_split_header_ttl /
# test_must_revalidate_split_header) intermittently fail ONLY under ASan, with
# zero sanitizer output -- a functional/timing failure, not a memory defect. A
# rerun of the same SHA flips it to green. ASan slows the module enough that
# fixed wall-clock bands become marginal on a loaded runner; the fix is not a
# wider band (that would silently disable the oracle on a NORMAL build too,
# see [[feedback-widening-shared-timeout-disables-oracle]]) but a band that
# scales ONLY when a sanitizer is actually instrumenting this run.
#
# .github/workflows/asan.yml sets ASAN_OPTIONS in the env of both runtime
# steps and no other workflow does, so its presence in os.environ is a
# reliable, already-existing signal that needs no workflow change.
# Kept modest (not larger): test_l2_stale_refetch_does_not_stall_on_lock
# asserts a request completes well UNDER the 5s lock_timeout bug window
# (budget 2.0s today) -- a factor that pushes 2.0*factor past 5.0 would start
# colliding with that bug signal instead of just absorbing ASan slowdown.
ASAN_TIME_SCALE = 2.0


def sanitizer_time_scale() -> float:
    """Return the wall-clock multiplier for this run: ASAN_TIME_SCALE under a
    sanitizer build (ASAN_OPTIONS present in the environment), 1.0 otherwise.

    Applied inside wait_for()/wait_for_l2()/wait_for_l2_absent() so every call
    site benefits without touching call sites, including ones that pass an
    explicit timeout= -- the scaling happens on the value AFTER the caller's
    default/explicit timeout is resolved, so both are covered identically.
    Call sites that assert elapsed wall-clock directly (not via wait_for) must
    scale their own comparison constant through this same function; grep
    ASAN_TIME_SCALE for the existing call sites.

    Non-ASan effective bands are unchanged byte-for-byte: this returns exactly
    1.0 when ASAN_OPTIONS is unset, so `timeout * sanitizer_time_scale() ==
    timeout`."""
    return ASAN_TIME_SCALE if "ASAN_OPTIONS" in os.environ else 1.0


def wait_for(predicate, timeout: float = 3.0, interval: float = 0.05) -> bool:
    deadline = time.time() + timeout * sanitizer_time_scale()
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
    ([[feedback-widening-shared-timeout-disables-oracle]]).

    `timeout` is scaled by sanitizer_time_scale() -- 1.0 outside a sanitizer
    build, so the non-ASan deadline is unchanged."""
    timeout = timeout * sanitizer_time_scale()
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
    to make the eventual red diagnosable, not to make it go away.

    `timeout` is scaled by sanitizer_time_scale() -- 1.0 outside a sanitizer
    build, so the non-ASan deadline is unchanged."""
    timeout = timeout * sanitizer_time_scale()
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


def _config_test_result(ng: Nginx, mutate, *, expect_unchanged: bool = False) -> subprocess.CompletedProcess[str]:
    """Render the full config, apply `mutate(cfg) -> cfg`, write it, and run
    nginx -t. Returns the CompletedProcess (returncode + combined stdout).

    By default, asserts that mutate produces a change to the config, to guard
    against silently no-op mutators that would make the test vacuous (never
    validating an actual mutation). Pass expect_unchanged=True only for a
    deliberate identity/positive-control check, which asserts the opposite:
    that the config is genuinely unchanged."""
    bad = ng.root.parent / "cfgcheck"
    (bad / "conf").mkdir(parents=True, exist_ok=True)
    (bad / "logs").mkdir(parents=True, exist_ok=True)
    cfg = nginx_config(
        bad, ng.port, ng.module, ng.origin_port, 1, ng.redis_port,
        ng.redis_auth_port, ng.redis_password, ng.redis_tls_port,
        ng.redis_tls_ca, ng.memcached_port)
    cfg_before = cfg
    cfg = mutate(cfg)
    if expect_unchanged:
        assert cfg == cfg_before, \
            "mutator unexpectedly changed config when identity mutation was expected"
    else:
        assert cfg != cfg_before, \
            "mutator produced no change: test would be vacuous (never validates a mutation)"
    (bad / "conf" / "nginx.conf").write_text(cfg, encoding="ascii")
    cmd = ng.runner + [str(ng.binary), "-p", str(bad),
                       "-c", str(bad / "conf" / "nginx.conf"), "-t"]
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=20,
                          env=config_check_env())


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
                       stderr=subprocess.STDOUT, timeout=20,
                       env=config_check_env())
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
                       stderr=subprocess.STDOUT, timeout=20,
                       env=config_check_env())
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


#: CTB5 role tags (src/ngx_http_cache_turbo_internal.h NGX_HTTP_CACHE_TURBO_HROLE_*).
CTB5_HROLE = {
    "content-type": 1,
    "etag": 2,
    "last-modified": 3,
}
CTB5_DATE_LEN = 29


def ctb5_date(created: int) -> bytes:
    """The exact 29 bytes ngx_http_time() renders for `created` -- what
    blob_hdr_write() now stores and restore memcpy's out as the Date header."""
    return time.strftime("%a, %d %b %Y %H:%M:%S GMT",
                         time.gmtime(created)).encode("ascii")


def make_ctb5_blob(body: bytes, status: int = 200,
                   headers: dict[str, str] | None = None,
                   created: int | None = None, fresh_ttl: int = 60,
                   stale_ttl: int = 240, sie_ttl: int = 0,
                   magic: int = 0x43544235,
                   version: int = 5, flags: int = 0,
                   date_field: bytes | None = None,
                   date_len: int | None = None,
                   role_of: "dict[str, int] | None" = None) -> bytes:
    """Hand-build a CTB5 cache blob exactly as the module serialises it (STAB-4 +
    RFC-2 + PERF-AUD2-02/03: fixed 76-byte little-endian, padding-free header).
    Pass a wrong magic/version to exercise the validator's reject path. Wire
    layout (LE):
      u32 magic, u16 version, u16 flags, u32 status, u32 nheaders, u32 headers_len,
      u32 body_len, i64 created, u32 fresh_ttl, u32 stale_ttl, u32 sie_ttl,
      u8 date_len, u8[29] date, u8[2] reserved
    followed by nheaders TLV entries of { u8 role, u32 nlen, name, u32 vlen, value }.

    `flags` writes the BLOBF_* u16 at offset 6. It defaults to 0 (no bits),
    which is what every pre-P4-3 caller assumed. Pass BLOBF_HDRS_VETTED
    (0x0020) to FORGE the "these headers were already vetted" claim an L2
    writer would most want to make -- the module must strip it at L2 ingress
    and re-run header_admissible() anyway.

    `date_field` / `date_len` override the rendered Date field and its length
    byte independently, so a test can forge exactly the shapes the validator
    must reject (short field, over-long length byte, CR/LF or NUL in the
    value). `role_of` overrides a header's role tag by lower-cased name, for
    the out-of-range-tag rejection test."""
    headers = headers or {"Content-Type": "text/plain"}
    created = int(time.time()) if created is None else created
    role_of = role_of or {}
    hdr_block = b""
    nheaders = 0
    for name, value in headers.items():
        nb = name.encode()
        vb = value.encode()
        role = role_of.get(name.lower(),
                           CTB5_HROLE.get(name.lower(), 0))
        hdr_block += bytes([role & 0xFF])
        hdr_block += struct.pack("<I", len(nb)) + nb
        hdr_block += struct.pack("<I", len(vb)) + vb
        nheaders += 1
    dfield = ctb5_date(created) if date_field is None else date_field
    dfield = dfield[:CTB5_DATE_LEN].ljust(CTB5_DATE_LEN, b"\x00")
    dlen = CTB5_DATE_LEN if date_len is None else date_len
    head = struct.pack("<IHHIIIIqIII", magic, version, flags, status, nheaders,
                       len(hdr_block), len(body), created, fresh_ttl, stale_ttl,
                       sie_ttl)
    head += bytes([dlen & 0xFF]) + dfield + b"\x00\x00"
    return head + hdr_block + body
