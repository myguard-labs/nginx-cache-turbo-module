"""Origin HTTP mock server for cache-turbo test harness."""

from __future__ import annotations

import collections
import email.utils
import hashlib
import http.server
import socket
import threading
import time

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


# --------------------------------------------------------------------------- #
# Counting origin: every GET returns a unique body and bumps a hit counter.
# --------------------------------------------------------------------------- #


class _OriginHTTPServer(http.server.ThreadingHTTPServer):
    """ThreadingHTTPServer with enlarged listen backlog for stress tests.

    Default backlog (5) overflows under 48-thread tests with ~30% cold misses
    that each open a new connection, surfacing as upstream 502s in the harness.
    Raise request_queue_size to 128 to accommodate concurrent connection bursts.
    """
    request_queue_size = 128


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
        # (method, path)-keyed companion to _path_hits -- hits_for() stays
        # method-blind (391 existing tests depend on that), this is purely
        # additive for tests that need to prove a specific METHOD reached a
        # specific path. Incremented under the same _lock, in the same three
        # places as _path_hits, so it is exact.
        self._method_hits: collections.Counter[tuple[str, str]] = collections.Counter()
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

    def hits_for_method(self, method: str, needle: str) -> int:
        """Like hits_for(), but scoped to one HTTP method -- backed by
        `_method_hits`, a (method, path)-keyed Counter incremented under
        `_lock` beside `_path_hits` in do_GET/do_HEAD/do_POST. Additive only:
        hits_for()'s existing method-blind semantics and callers are
        untouched. Use this when a test must prove a specific method (not
        just "some request") reached a path -- e.g. that a HEAD-only URL was
        never subsequently fetched with GET."""
        with self._lock:
            return sum(c for (m, p), c in self._method_hits.items()
                       if m == method and needle in p)

    def start(self) -> None:
        origin = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_HEAD(self):
                # A HEAD must reach the origin (no body); the module must NOT
                # store it as the GET entry.
                with origin._lock:
                    origin._n += 1
                    origin._path_hits[self.path] += 1
                    origin._method_hits[("HEAD", self.path)] += 1
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_POST(self):
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
                    origin._method_hits[("POST", self.path)] += 1
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

            def _get_handle_hard_failure(self, n: int) -> bool:
                """origin.drop / origin.fail early-return cases. Returns True
                if a complete response was written (caller must stop), False
                to fall through to the marker-driven special cases."""
                # Hard upstream failure (Goal-2): drop the connection with no
                # response so nginx's upstream sees a transport error (502),
                # exercising a different error class than the clean 503 `fail`
                # mode. The hit is already counted above (proves the bg refresh
                # reached the origin); serving stale must not depend on it.
                if origin.drop:
                    self.close_connection = True
                    return True
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
                        return True
                    self.send_response(origin.fail_status)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return True
                return False

            def _get_handle_rngsrc(self) -> None:
                """AUD-RANGE1: a real Range-capable origin (e.g. a static
                file server) that both advertises Accept-Ranges: bytes AND
                honours an incoming Range header with a genuine 206 +
                Content-Range + sliced body. Body is well over 100 bytes so
                bytes=0-99 is a true partial slice, not the whole response.
                Used to prove a cache-turbo HIT answers Range identically to
                a MISS. Writes a complete response; caller returns after."""
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

            def _get_handle_special_cases(self, n: int) -> tuple[bool, bytes | None]:
                """Marker-driven special-case responses (ctxrdr-missing,
                precompressed, partial, rngsrc, redir, notfound, bigbody,
                chainbig, unbuf-stream, unbuf-big, ckecho) plus the midbody-mismatch body
                computation.
                Returns (True, None) if a complete response was written
                (caller must stop), or (False, body) with the body for the
                common 200 path to send."""
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
                    return True, None
                # P0-1: a response that arrives ALREADY Content-Encoding'd (the
                # origin pre-compressed it, or -- defense-in-depth -- cache_turbo
                # somehow ended up below a compressor). The module's body filter
                # only ever captures the IDENTITY body, so a coding-specific one
                # must never be stored (see response_encoded()'s own comment in
                # ngx_http_cache_turbo_vary.c). The gzip magic bytes are enough to
                # exercise the gate; the module never inflates or validates the
                # body, it only reads the header.
                # P1-1: the negative control for the Accept-Encoding vary-axis
                # collapse. Same pre-encoded body as "precompressed" above, but
                # ALSO advertises `Vary: Accept-Encoding` so a test can prove the
                # module still partitions by encoding class when the origin's
                # body genuinely is coding-specific -- collapse must only apply
                # when response_encoded() is false.
                if "precompressed-vary" in self.path:
                    body = b"\x1f\x8b" + f"prevary-{n}\n".encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Encoding", "gzip")
                    self.send_header("Vary", "Accept-Encoding")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    try:
                        self.wfile.write(body)
                    except BrokenPipeError:
                        pass
                    return True, None
                if "precompressed" in self.path:
                    body = b"\x1f\x8b" + f"pre-{n}\n".encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Encoding", "gzip")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    try:
                        self.wfile.write(body)
                    except BrokenPipeError:
                        pass
                    return True, None
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
                    return True, None
                # AUD-RANGE1: a real Range-capable origin (e.g. a static file
                # server) that both advertises Accept-Ranges: bytes AND honours
                # an incoming Range header with a genuine 206 + Content-Range +
                # sliced body. Body is well over 100 bytes so bytes=0-99 is a
                # true partial slice, not the whole response. Used to prove a
                # cache-turbo HIT answers Range identically to a MISS.
                if "rngsrc" in self.path:
                    self._get_handle_rngsrc()
                    return True, None
                # Per-status caching markers (v6): redirects + negative responses.
                if "redir" in self.path:
                    self.send_response(301)
                    self.send_header("Location", f"/dest-{n}")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return True, None
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
                    return True, None
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
                    return True, None
                if "chainbig" in self.path:
                    # P4-5: a LARGE, CACHEABLE, deterministic body used to
                    # exercise the multi-buf zero-copy serve chain in
                    # ngx_http_cache_turbo_serve(). Three properties are all
                    # load-bearing:
                    #
                    #   * SIZE -- 320000 bytes is ~9.8 x the 32 KB slice size,
                    #     so the served chain is ~10 bufs and the body crosses
                    #     many chunk boundaries including a final PARTIAL one
                    #     (320000 % 32768 = 6656). An exact multiple would hide
                    #     an off-by-one in the tail slice.
                    #
                    #   * POSITION-DEPENDENT CONTENT -- every 16-byte record
                    #     encodes its own offset. A run of identical bytes
                    #     (like the `bigbody` marker above) is byte-identical
                    #     under a duplicated, dropped or reordered chunk, so it
                    #     could not detect the exact failure modes chaining
                    #     introduces. This body can.
                    #
                    #   * CACHEABLE -- an explicit max-age, because the whole
                    #     point is to compare a stored HIT against the origin
                    #     MISS. `bigbody` sends no Cache-Control and is used
                    #     for the oversize-abort path instead.
                    #
                    # The body is IDENTICAL on every origin contact (no gen-N
                    # prefix) precisely so a HIT and a MISS can be compared for
                    # byte equality; the test distinguishes them by X-Cache,
                    # not by content.
                    body = b"".join(
                        b"%015d\n" % off
                        for off in range(0, 320000, 16))
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Cache-Control", "public, max-age=60")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    try:
                        self.wfile.write(body)
                    except BrokenPipeError:
                        pass
                    return True, None
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
                    return True, None
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
                    return True, None
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
                    return True, None
                if "hdrecho" in self.path:
                    # ADMIN-WARM-AUTH-FORWARD: echo every header whose presence
                    # distinguishes an allowlist rebuild from inherited admin
                    # headers. Fake credential values stay test-local; the
                    # response is later served from cache so the follow-up also
                    # proves the warm was eligible for anonymous storage.
                    def header(name):
                        return self.headers.get(name) or "none"

                    body = (
                        f"gen-{n} "
                        f"host=[{header('Host')}] "
                        f"ua=[{header('User-Agent')}] "
                        f"auth=[{header('Authorization')}] "
                        f"proxy-auth=[{header('Proxy-Authorization')}] "
                        f"cookie=[{header('Cookie')}] "
                        f"admin-token=[{header('X-Admin-Token')}]\n"
                    ).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    try:
                        self.wfile.write(body)
                    except BrokenPipeError:
                        pass
                    return True, None
                if "vldechonone" in self.path:
                    # P1-4 negative control: echo received If-None-Match /
                    # If-Modified-Since like "vldecho" below, but emit NO
                    # ETag/Last-Modified -- the stored entry then has neither
                    # validator, so a later background refresh must stay an
                    # unconditional GET (both echoed values read "none").
                    # Checked BEFORE the plain "vldecho" substring match below
                    # (this path contains it) so the negative-control marker
                    # is actually reachable.
                    inm = self.headers.get("If-None-Match") or "none"
                    ims = self.headers.get("If-Modified-Since") or "none"
                    body = f"gen-{n} inm=[{inm}] ims=[{ims}]\n".encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    try:
                        self.wfile.write(body)
                    except BrokenPipeError:
                        pass
                    return True, None
                if "vld304" in self.path:
                    # P1-4 safety probe: behave like a REAL conditional origin
                    # -- answer 304 (no body) whenever the request carries the
                    # matching If-None-Match, else 200 with the validator. This
                    # is what a background refresh actually meets in production
                    # once P1-4 injects validators, and it is the case that
                    # decides whether injection ALONE is safe: the stored entry
                    # must survive a 304 refresh unchanged, still be served, and
                    # still be correct. (Reusing the stored body ON the 304 --
                    # freshening -- is the separate row P5-4.)
                    if self.headers.get("If-None-Match") == '"vld304etag"':
                        self.send_response(304)
                        self.send_header("ETag", '"vld304etag"')
                        self.end_headers()
                        return True, None
                    body = f"gen-{n} vld304\n".encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("ETag", '"vld304etag"')
                    self.end_headers()
                    try:
                        self.wfile.write(body)
                    except BrokenPipeError:
                        pass
                    return True, None
                if "vldecho" in self.path:
                    # P1-4: echo the received If-None-Match / If-Modified-Since
                    # so a test can prove a background-refresh subrequest
                    # carried the entry's stored validators upstream (instead
                    # of an unconditional GET every stale cycle). Always
                    # answers 200 with a fresh body/generation like the plain
                    # path -- this marker only needs the REQUEST headers it
                    # received, never a 304 (304-freshening is a separate,
                    # deliberately unimplemented row, P5-4).
                    inm = self.headers.get("If-None-Match") or "none"
                    ims = self.headers.get("If-Modified-Since") or "none"
                    body = f"gen-{n} inm=[{inm}] ims=[{ims}]\n".encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    # Stable validators (same convention as "cond") so the
                    # PRIMING response stores an ETag + Last-Modified for the
                    # later background refresh to read back and inject.
                    self.send_header("ETag", '"vldechoetag"')
                    self.send_header("Last-Modified",
                                     "Wed, 21 Oct 2015 07:28:00 GMT")
                    self.end_headers()
                    try:
                        self.wfile.write(body)
                    except BrokenPipeError:
                        pass
                    return True, None
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
                return False, body

            def _get_send_common_status_headers(self, n: int) -> None:
                """Decorate the shared 200 response: X-Backend/X-GraphQL echo
                headers, per-status Set-Cookie/Surrogate-Key markers."""
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
                want_expires = self.headers.get("X-Want-Expires")
                if want_expires is not None:
                    self.send_header("Expires", want_expires)
                # Path-marker-driven response headers, so a test can drive the
                # RFC 9111 shared-cache floor (these responses must NOT be
                # stored). The marker is matched in the path so $uri keying still
                # collapses repeated requests onto one slot.
                if "setcookie" in self.path:
                    self.send_header("Set-Cookie", "sess=abc; Path=/")
                # P5-8 named Set-Cookie ignore-list fixtures. Each emits a
                # DIFFERENT shape of Set-Cookie so one test can pin one
                # behaviour. Checked before the generic "setcookie" marker below
                # would be reached only by substring luck, so every name here is
                # deliberately distinct from it.
                if "p58listed" in self.path:
                    # Exactly one Set-Cookie, on the configured ignore list.
                    self.send_header("Set-Cookie",
                                     "_ga=GA1.2.99; Path=/; Max-Age=63072000")
                if "p58multi" in self.path:
                    # SEVERAL Set-Cookie fields, EVERY one on the list. nginx
                    # hands these to the module as separate header entries, so
                    # this is the case that proves the walk checks all of them
                    # rather than just the first.
                    self.send_header("Set-Cookie", "_ga=GA1.2.99; Path=/")
                    self.send_header("Set-Cookie", "ab_bucket=B; Path=/")
                if "p58mixed" in self.path:
                    # THE assertion that matters: two listed cookies with ONE
                    # unlisted cookie among them. A guard that stops at the first
                    # Set-Cookie, or that ORs instead of ANDs, stores this.
                    self.send_header("Set-Cookie", "_ga=GA1.2.99; Path=/")
                    self.send_header("Set-Cookie", "sessionid=deadbeef; Path=/; HttpOnly")
                    self.send_header("Set-Cookie", "ab_bucket=B; Path=/")
                if "p58noeq" in self.path:
                    # Malformed: no '=' at all, so no cookie-pair. Fail closed.
                    self.send_header("Set-Cookie", "justjunk; Path=/")
                if "p58emptyname" in self.path:
                    # Empty cookie name. RFC 6265 does not define it and clients
                    # disagree; fail closed.
                    self.send_header("Set-Cookie", "=GA1.2.99; Path=/")
                if "p58attrname" in self.path:
                    # An UNLISTED cookie whose ATTRIBUTES contain a listed name.
                    # A substring search, or a request-Cookie-grammar parser that
                    # treats "; " as a pair separator, matches "_ga" here and
                    # wrongly stores a real session cookie.
                    self.send_header("Set-Cookie",
                                     "sessionid=deadbeef; Path=/_ga; Domain=_ga")
                if "p58quoted" in self.path:
                    # Quoted name: not a token, so unparseable. Fail closed.
                    self.send_header("Set-Cookie", '"_ga"=GA1.2.99; Path=/')
                if "p58spacedname" in self.path:
                    # Embedded space in the name. Fail closed.
                    self.send_header("Set-Cookie", "_g a=GA1.2.99; Path=/")
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

            def _get_send_cache_control_headers(self) -> None:
                """Decorate the shared 200 response with the Cache-Control /
                CDN-Cache-Control / Surrogate-Control / Expires / ETag /
                Last-Modified TTL-ladder markers."""
                if "ccprivate" in self.path:
                    self.send_header("Cache-Control", "private, max-age=60")
                if "ccnostore" in self.path:
                    self.send_header("Cache-Control", "no-store")
                if "ccpublic" in self.path:
                    # P3-4: bare `public` -- an RFC 9111 SS3.5 shared-cache
                    # reuse authorisation with NO max-age, so the entry's TTL
                    # still comes from cache_turbo_valid and this marker only
                    # exercises the SS3.5 permission, nothing else.
                    self.send_header("Cache-Control", "public")
                if "manyhdr" in self.path:
                    # R4-1: nginx sizes r->headers_out.headers at 20 entries
                    # per ngx_list_t part, so >20 stored headers force the list
                    # to SPILL into a second part. The store path's admissibility
                    # verdict cache indexes its bitmap positionally across that
                    # part boundary, and an off-by-one in the part transition
                    # would misalign the measure and emit walks -- silently
                    # dropping or admitting the wrong header. Emit enough to
                    # cross the boundary twice, each with a distinct value so a
                    # shifted verdict shows up as a wrong/missing value, not
                    # just a wrong count. One skip-listed header (Age) is mixed
                    # in so the bitmap is not uniformly 1s: a broken index that
                    # happened to read a neighbouring set bit would still pass
                    # an all-admissible fixture.
                    for _i in range(45):
                        self.send_header(f"X-Many-{_i:02d}", f"v-{_i:02d}")
                    self.send_header("Age", "123")
                if "nativecache" in self.path:
                    # mimic a native nginx cache (proxy_cache) sitting behind us
                    self.send_header("Age", "123")
                    self.send_header("X-Cache-Status", "HIT")
                if "ttl1" in self.path:
                    # upstream-declared 1s freshness (v7 honor_cache_control)
                    self.send_header("Cache-Control", "public, max-age=1")
                if "mustrev" in self.path:
                    # RFC 9111 must-revalidate: fresh, then NO stale serving.
                    # TEST-MICROTTL-ORACLE (2026-08-23): was max-age=1. A
                    # must-revalidate entry never shows an intermediate STALE
                    # state (unlike ordinary stale-serving) -- past the
                    # deadline it collapses straight back to an origin
                    # revalidate, which is observationally IDENTICAL to "was
                    # never stored". So (unlike the /cc7/ honor tests) there is
                    # no HIT-or-STALE relaxation available here: proving
                    # "stored and still fresh" genuinely requires the
                    # immediate re-read to land inside the fresh window, with
                    # zero explicit wait. 4s (instead of 1s) gives that live
                    # round trip real margin under a slow sanitizer build; see
                    # test_must_revalidate. This marker is ALSO reached by
                    # /ccignmr/mustrev (both /mrev/ and /ccignmr/ proxy_pass
                    # with a trailing "/", which strips the location prefix,
                    # so the origin sees the same "/mustrev" path either way
                    # and cannot distinguish the two consumers by path) --
                    # that is harmless because /ccignmr/ uses
                    # cache_turbo_cache_control ignore and derives its window
                    # from cache_turbo_valid, never from this header's value.
                    self.send_header("Cache-Control",
                                     "max-age=4, must-revalidate")
                if "proxyrev" in self.path:
                    # RFC 9111 proxy-revalidate: the shared-cache synonym of
                    # must-revalidate. Same window collapse (response_must_revalidate
                    # OR-arm) and same TEST-MICROTTL-ORACLE widening as "mustrev"
                    # above (proxyrev has no /ccignmr/-style second consumer, so
                    # no path scoping is needed here).
                    self.send_header("Cache-Control",
                                     "max-age=4, proxy-revalidate")
                if "splitmrev" in self.path:
                    # AUD-CC-FIRST-LINE: HTTP allows a header field to be split
                    # across multiple field-lines (RFC 9110 SS5.3), equivalent to
                    # one line with the values comma-joined in order. Emit TWO
                    # separate Cache-Control lines -- max-age on the first,
                    # must-revalidate on the SECOND -- so a reader that only
                    # inspects the first occurrence would miss must-revalidate
                    # entirely and stale-serve past freshness. TEST-MICROTTL-ORACLE:
                    # max-age widened 1 -> 4 for the same reason as "mustrev" above.
                    self.send_header("Cache-Control", "max-age=4")
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

            def _get_send_vary_headers(self) -> None:
                """Decorate the shared 200 response with auto-Vary markers.

                (v11 other half): emit a response Vary driven by a query
                marker so a test can prove the module splits (or refuses)
                by the named request header. The body is the global gen-N, so
                a new origin hit == a distinct body == a distinct variant
                slot."""
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
                if "v=acc" in self.path:
                    # P3-3: Accept is a common real-world Vary axis the built-in
                    # whitelist has no bit for. On /av/ (no vary_ignore) this must
                    # be refused like v=cs; on /avi/ (cache_turbo_vary_ignore
                    # Accept) it must be dropped before the refusal check and
                    # stay cacheable.
                    self.send_header("Vary", "Accept")

            def do_GET(self):
                if origin.delay:
                    time.sleep(origin.delay)
                with origin._lock:
                    origin._n += 1
                    n = origin._n
                    origin._paths.append((time.time(), self.path))
                    if len(origin._paths) > 64:        # ring: diagnostics only
                        del origin._paths[:-64]
                    origin._path_hits[self.path] += 1
                    origin._method_hits[("GET", self.path)] += 1
                if self._get_handle_hard_failure(n):
                    return
                handled, body = self._get_handle_special_cases(n)
                if handled:
                    return
                self.send_response(200)
                self.send_header("Content-Type",
                                 "application/json; charset=utf-8")
                self._get_send_common_status_headers(n)
                self._get_send_cache_control_headers()
                self._get_send_vary_headers()
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except BrokenPipeError:
                    pass

            def log_message(self, *a):  # silence
                pass

        self._server = _OriginHTTPServer(
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
