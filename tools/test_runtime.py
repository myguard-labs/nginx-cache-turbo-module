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
import concurrent.futures
import hashlib
import http.server
import json
import pathlib
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
    parser.add_argument("--port", type=int, default=18880)
    parser.add_argument("--redis-server")  # accepted; used by v2 L2 tests
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
          method: str | None = None):
    """Return (status, body_str, response_headers_dict)."""
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        headers={"Connection": "close", **(headers or {})},
        method=method,
    )
    if method in ("POST", "PUT", "DELETE"):
        req.data = b""
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            body = r.read().decode("utf-8", "replace")
            return r.status, body, {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        return exc.code, body, {k.lower(): v for k, v in exc.headers.items()}


# --------------------------------------------------------------------------- #
# Counting origin: every GET returns a unique body and bumps a hit counter.
# --------------------------------------------------------------------------- #

class Origin:
    def __init__(self, port: int, delay: float = 0.0) -> None:
        self.port = port
        self.delay = delay
        self._n = 0
        self._lock = threading.Lock()
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def hits(self) -> int:
        with self._lock:
            return self._n

    def start(self) -> None:
        origin = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if origin.delay:
                    time.sleep(origin.delay)
                with origin._lock:
                    origin._n += 1
                    n = origin._n
                body = f"gen-{n}\n".encode()
                self.send_response(200)
                self.send_header("Content-Type",
                                 "application/json; charset=utf-8")
                self.send_header("X-Backend", "origin-42")
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
                 redis_port: int | None = None) -> str:
    load = f"load_module {module};\n" if module else ""

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

        # L2 with a short fresh TTL so the L1 copy expires in-test (stale window
        # = valid*4 = 4s), exercising the expired-L1 -> consult-L2 path (P6).
        location /l2e/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
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

        # cross-node dogpile (v4-2): fresh TTL 2s -> stale_until = valid*4 = 8s,
        # a wide window so both lock tests have timing slack; aggressive beta so
        # a stale read reliably rolls a refresh; lock_ttl 5s = the Redis SET NX
        # PX hold (long enough to cap a multinode burst, short enough to model a
        # crashed peer's lock self-healing by PX expiry).
        location /lock/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    2s;     # stale window: serveable until t+8s
            cache_turbo_beta     5000;   # aggressive: refresh likely while stale
            cache_turbo_lock_ttl 5s;     # cross-node NX PX = 5000ms
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
"""

    return f"""{load}worker_processes {workers};
pid {root}/nginx.pid;
error_log {root}/logs/error.log notice;

events {{ worker_connections 512; }}

http {{
    access_log off;

    cache_turbo_zone name=main 16m;
    cache_turbo_zone name=tiny 8m;   # small zone for eviction test (R6)

    server {{
        listen 127.0.0.1:{port};
{redis_loc}

        # standard 30s-fresh cache
        location /c/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_max_size 1m;
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

        # max_size = 4 bytes: origin body "gen-N\\n" is >4, so never cached
        location /big/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_max_size 4;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # tiny zone to force LRU eviction (R6)
        location /e/ {{
            cache_turbo          tiny;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
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

        # strip_all: every arg dropped, so all query strings share one slot
        location /na/ {{
            cache_turbo          main;
            cache_turbo_key      $uri$cache_turbo_normalized_args;
            cache_turbo_valid    30s;
            cache_turbo_normalize_strip_all on;
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
        location /pa/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_preset   aggressive;
            cache_turbo_valid    1s;     # stale_mult=8 -> expires at 8s
            proxy_pass http://127.0.0.1:{origin_port}/;
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
                 single_process, redis_port=None) -> None:
        self.binary = binary
        self.module = module
        self.root = root
        self.port = port
        self.origin_port = origin_port
        self.runner_raw = runner
        self.runner = shlex.split(runner)
        self.single_process = single_process
        self.redis_port = redis_port
        self.process: subprocess.Popen | None = None
        self.output_path = root / "nginx-output.log"

    def write_config(self) -> None:
        workers = 1 if self.single_process else 4
        (self.root / "conf").mkdir(parents=True, exist_ok=True)
        (self.root / "logs").mkdir(parents=True, exist_ok=True)
        (self.root / "conf" / "nginx.conf").write_text(
            nginx_config(self.root, self.port, self.module,
                         self.origin_port, workers, self.redis_port),
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
        self.process = subprocess.Popen(self.command(), text=True,
                                        stdout=out, stderr=subprocess.STDOUT)
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

class RedisServer:
    def __init__(self, binary: pathlib.Path, root: pathlib.Path,
                 port: int) -> None:
        self.binary = binary
        self.root = root
        self.port = port
        self.process: subprocess.Popen[str] | None = None

    def start(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.process = subprocess.Popen(
            [
                str(self.binary),
                "--bind", "127.0.0.1",
                "--port", str(self.port),
                "--save", "",
                "--appendonly", "no",
                "--dir", str(self.root),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        wait_port(self.port)
        self.cli("FLUSHALL")

    def cli(self, *args: str) -> str:
        """Run a redis-cli command against this server; return stdout."""
        r = subprocess.run(
            ["redis-cli", "-h", "127.0.0.1", "-p", str(self.port), *args],
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

    def stop(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=10)
        self.process = None


def l2_key(uri: str, prefix: str = "ct:") -> str:
    """Mirror the module's L2 key: prefix + hex of the 32-byte key hash. The
    key hash is md5(cache_key) widened into 32 bytes (upper 16 stay zero), and
    cache_turbo_key is $uri in the test config."""
    return prefix + hashlib.md5(uri.encode()).hexdigest() + "0" * 32


def lock_key(uri: str, prefix: str = "ct:") -> str:
    """Mirror the module's cross-node lock key: <prefix>lock:<hex key hash>."""
    return prefix + "lock:" + hashlib.md5(uri.encode()).hexdigest() + "0" * 32


def wait_for(predicate, timeout: float = 3.0, interval: float = 0.05) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #

def test_miss_then_hit(ng: Nginx) -> None:
    """Basic: first request MISS (origin), second HIT (cached, same body)."""
    before = None
    s1, b1, h1 = fetch(ng.port, "/c/hit")
    assert s1 == 200, f"miss status {s1}"
    assert "x-cache" not in h1, f"first req should be a miss, got {h1.get('x-cache')}"
    s2, b2, h2 = fetch(ng.port, "/c/hit")
    assert s2 == 200
    assert h2.get("x-cache") == "HIT", f"second req X-Cache={h2.get('x-cache')}"
    assert b1 == b2, f"HIT body differs: {b1!r} vs {b2!r}"


def test_header_fidelity(ng: Nginx) -> None:
    """R2: Content-Type + arbitrary origin header survive a HIT byte-identical."""
    fetch(ng.port, "/c/hdr")                       # prime
    _, _, h = fetch(ng.port, "/c/hdr")             # HIT
    assert h.get("x-cache") == "HIT"
    assert h.get("content-type") == "application/json; charset=utf-8", \
        f"content-type lost: {h.get('content-type')}"
    assert h.get("x-backend") == "origin-42", \
        f"custom header lost: {h.get('x-backend')}"


def test_max_size_not_cached(ng: Nginx) -> None:
    """Responses larger than cache_turbo_max_size are never cached."""
    fetch(ng.port, "/big/x")
    _, _, h = fetch(ng.port, "/big/x")
    assert "x-cache" not in h, "oversized response should not be cached"


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


def test_lru_eviction(ng: Nginx) -> None:
    """R6: with a tiny zone, old entries are evicted, not 500s."""
    # hammer many distinct keys through the tiny zone; must all 200, no errors
    for i in range(200):
        s, _, _ = fetch(ng.port, f"/e/{i}")
        assert s == 200, f"/e/{i} returned {s}"


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


def test_admin_purge_all(ng: Nginx) -> None:
    """POST /_cache?all=1 empties the zone."""
    import json
    fetch(ng.port, "/c/a1"); fetch(ng.port, "/c/a2"); fetch(ng.port, "/c/a3")
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


def make_ctb1_blob(body: bytes, status: int = 200,
                   headers: dict[str, str] | None = None) -> bytes:
    """Hand-build a CTB1 cache blob exactly as the module serialises it
    (ngx_http_cache_turbo_blob_hdr_t + name/value pairs + body, all native
    little-endian uint32). Lets a test seed L2 directly with a valid object."""
    headers = headers or {"Content-Type": "text/plain"}
    hdr_block = b""
    nheaders = 0
    for name, value in headers.items():
        nb = name.encode()
        vb = value.encode()
        hdr_block += struct.pack("<I", len(nb)) + nb
        hdr_block += struct.pack("<I", len(vb)) + vb
        nheaders += 1
    magic = 0x43544231
    head = struct.pack("<IIIII", magic, nheaders, len(hdr_block),
                       len(body), status)
    return head + hdr_block + body


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

    # next read is a true miss to the origin (a NEW gen), not an L2 refill
    origin_before = origin.hits
    s, body_b, h3 = fetch(ng.port, uri)
    assert s == 200 and "x-cache" not in h3, \
        f"post-purge read should miss to origin, got {h3.get('x-cache')}"
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
    blob = make_ctb1_blob(seeded, headers={"Content-Type": "text/plain"})
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


def tag_key(name: str, prefix: str = "ct:") -> str:
    """Mirror the module's tag-set key: <prefix>tag:<name>."""
    return f"{prefix}tag:{name}"


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

    s, b, _ = fetch(ng.port, f"/_cache_l2?tag=news", method="POST")
    assert s == 200, f"tag purge status {s}"
    assert json.loads(b)["purged"] == 2, f"expected 2 purged, got {b}"

    # both objects gone from L2, and the tag set itself deleted
    assert wait_for(lambda: redis.cli("EXISTS", l2_key(u1)) == "0"
                    and redis.cli("EXISTS", l2_key(u2)) == "0"), \
        "tagged objects not removed from L2"
    assert wait_for(lambda: redis.cli("EXISTS", tag_key("news")) == "0"), \
        "emptied tag set was not deleted"

    # both gone from L1: next reads miss to a fresh origin generation
    origin_before = origin.hits
    _, nb1, h1 = fetch(ng.port, u1)
    _, nb2, h2 = fetch(ng.port, u2)
    assert "x-cache" not in h1 and "x-cache" not in h2, \
        "tagged objects should be a MISS in L1 after purge"
    assert origin.hits == origin_before + 2, "both reads should reach origin"
    assert nb1 != body1["body"] and nb2 != body2["body"], \
        "post-purge bodies should be fresh generations"


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
    assert regens == 1, \
        f"self-heal: want exactly 1 regen after lock expiry, got {regens}"


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
    """cache_turbo_normalize_strip_all drops EVERY arg, so wholly different query
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


def test_preset_window_differs(ng: Nginx, origin: Origin) -> None:
    """v3-2: a preset sets the stale-window multiplier. With cache_turbo_valid
    pinned to 1s on both locations, the only difference is the preset: the
    conservative band (x2) makes the entry serveable for 2s, the aggressive band
    (x8) for 8s. At t=3s the conservative copy is hard-expired (a MISS, re-fetch)
    while the aggressive copy is still serveable as stale. This asserts the
    PRESET'S effect, not its stored value, and proves the band reaches the
    runtime stale math (stale_mult threaded through shm_store)."""
    fetch(ng.port, "/pc/win")                          # prime conservative
    fetch(ng.port, "/pa/win")                          # prime aggressive
    time.sleep(3.0)                                     # cons expired, aggr stale

    # conservative: past stale_until -> a true MISS (no X-Cache, hits origin)
    sc, bc, hc = fetch(ng.port, "/pc/win")
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
         "got " + repr(sorted({h.get('x-cache') for _, _, h in results})))


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


def run_all(ng: Nginx, origin: Origin,
            redis: RedisServer | None = None) -> None:
    test_miss_then_hit(ng)
    test_header_fidelity(ng)
    test_max_size_not_cached(ng)
    test_concurrent_hits_no_deadlock(ng)
    test_lru_eviction(ng)
    test_admin_stats(ng)
    test_admin_purge_key(ng)
    test_admin_gating(ng)
    test_warm_populates(ng, origin)
    test_warm_multi(ng, origin)
    test_warm_no_url(ng)
    test_stale_serves_stale(ng, origin)
    test_single_flight(ng, origin)
    test_normalize_arg_order(ng, origin)
    test_normalize_strips_tracking(ng, origin)
    test_normalize_strip_custom(ng, origin)
    test_normalize_strip_all(ng, origin)
    test_normalize_distinct_args_differ(ng, origin)
    test_normalize_vary_encoding(ng, origin)
    test_normalize_vary_device(ng, origin)
    test_normalize_vary_both(ng, origin)
    test_normalize_vary_off_by_default(ng, origin)
    test_invalid_normalize_vary_token(ng)
    test_preset_window_differs(ng, origin)
    test_invalid_preset_name(ng)
    if redis is not None:
        test_l2_write_through(ng, origin, redis)
        test_l2_cross_instance_fill(ng, origin, redis)
        test_l2_purge_key_drops_l2(ng, origin, redis)
        test_l2_expired_consults_l2(ng, origin, redis)
        test_l2_tag_add_on_store(ng, origin, redis)
        test_l2_tag_purge(ng, origin, redis)
        test_multinode_lock(ng, origin, redis)
        test_lock_self_heal(ng, origin, redis)
        test_purge_all_clears_l2(ng, origin, redis)  # last L2: empties L2
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
    with tempfile.TemporaryDirectory(prefix="cache-turbo-ci-") as tmp:
        root = pathlib.Path(tmp)
        origin = Origin(origin_port, delay=0.05)
        redis = None
        if args.redis_server:
            redis = RedisServer(pathlib.Path(args.redis_server),
                                root / "redis", redis_port)
        ng = Nginx(binary, module, root / "server", args.port, origin_port,
                   args.runner, args.single_process, redis_port)
        ng.write_config()
        ng.config_test()
        try:
            origin.start()
            if redis is not None:
                redis.start()
            ng.start()
            run_all(ng, origin, redis)
            time.sleep(0.2)
            ng.stop()
            ng.assert_clean_logs()
        finally:
            ng.stop()
            if redis is not None:
                redis.stop()
            origin.stop()

    print("OK: miss/hit, header fidelity, max_size, concurrency (R1), "
          "LRU eviction (R6), stale serve (R3), single-flight (R4), "
          "admin stats/purge/gating, warm (v3-3: populates/multi/no-url), "
          "key normalize (v3-1: order/tracking/"
          "custom-strip/strip-all/distinct), "
          "vary suffix (v3-4: encoding/device/both/off-by-default, "
          "invalid-token rejected), "
          "presets (v3-2: conservative/aggressive stale-window differ, "
          "invalid-name rejected)"
          + (", L2 write-through (P4), L2 cross-instance fill (P2), "
             "L2-aware key purge (P6), expired-L1 consults L2 (P6), "
             "tag index add (v2c), tag purge both tiers (P4), "
             "multi-node dogpile lock (v4-2 SET NX PX), lock self-heal (v4-2), "
             "?all=1 clears L2 (v4-2 SCAN+DEL)"
             if redis_port else ""))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
