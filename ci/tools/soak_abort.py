#!/usr/bin/env python3
"""Abort-mix helpers for ci/tools/soak.sh (ABORT=1 mode).

Subcommands (all bind/connect 127.0.0.1):

  origin <port>                       slow-able 80 KB text/css origin
  kv <port> [delay_s]                 RESP fake Redis with a per-GET delay, so a
                                      request parks on L2 long enough to be hit
  stress <h1> <h2> <secs> [kv]  the client mix (kv: gate on its GET count); exit 1 on any failure

Why a fake KV and not redis-server: a real Redis answers in microseconds, so a
request is almost never parked when the client's abort lands. The delay is the
point -- it holds requests parked while 24 workers reset/close/poke them.

The client mix is the CT-RESUME-FINALIZE-UAF stress (HTTP/1 RST, FIN; HTTP/2
RST_STREAM, connection close; clean clients, primed and fresh keys) plus the
CT-PARKED-REENTRY stimulus: a keep-alive connection whose receive window is
tiny gets a response larger than the send buffer (so nginx's send blocks and
the connection's write event goes active), is read to the end, and the next
request on it -- the one that parks -- is then poked, reset or left alone.

Failure conditions the client itself reports: a clean client that gets no
complete 200 within its deadline (a request nobody answers), and a server-side
socket still ESTABLISHED or CLOSE_WAIT on the edge ports after the clients are
gone and the keep-alive timeout has passed (a held connection).
"""

import asyncio
import http.server
import os
import pathlib
import random
import socket
import struct
import sys
import threading
import time
import urllib.request

WORKERS = 24
CLEAN_DEADLINE = 15.0
HELD_DEADLINE = 12.0


def _body() -> bytes:
    return b"font-data-" * 8192


# --------------------------------------------------------------------------- #
# origin
# --------------------------------------------------------------------------- #


def run_origin(port: int) -> None:
    body = _body()
    delay = float(os.environ.get("ODELAY", "0"))

    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            time.sleep(delay)
            self.send_response(200)
            self.send_header("Content-Type", "text/css")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "public, max-age=60")
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                pass

        def log_message(self, *a):
            pass

        def handle(self):
            try:
                super().handle()
            except OSError:
                pass

    http.server.ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()


# --------------------------------------------------------------------------- #
# fake Redis
# --------------------------------------------------------------------------- #


def _parse(buf: bytes):
    out, i = [], 0
    while i < len(buf) and buf[i : i + 1] == b"*":
        e = buf.find(b"\r\n", i)
        if e < 0:
            break
        n = int(buf[i + 1 : e])
        j, args, ok = e + 2, [], True
        for _ in range(n):
            e = buf.find(b"\r\n", j)
            if e < 0:
                ok = False
                break
            ln = int(buf[j + 1 : e])
            j = e + 2
            if len(buf) < j + ln + 2:
                ok = False
                break
            args.append(buf[j : j + ln])
            j += ln + 2
        if not ok:
            break
        out.append(args)
        i = j
    return out, buf[i:]


def run_kv(port: int, delay: float) -> None:
    store: dict[bytes, bytes] = {}
    gets = [0]  # GETs received and held for `delay`, read back via SOAKGETS

    async def handle(r, w):
        buf = b""
        try:
            while True:
                d = await r.read(1 << 20)
                if not d:
                    break
                buf += d
                cmds, buf = _parse(buf)
                for a in cmds:
                    c = a[0].upper()
                    if c == b"GET":
                        # Count on receipt: a GET still sleeping at the final
                        # snapshot was received in the worker phase.
                        gets[0] += 1
                        await asyncio.sleep(delay)
                        v = store.get(a[1])
                        w.write(
                            b"$-1\r\n" if v is None else b"$%d\r\n%s\r\n" % (len(v), v)
                        )
                    elif c == b"SET":
                        store[a[1]] = a[2]
                        w.write(b"+OK\r\n")
                    elif c == b"SOAKGETS":
                        w.write(b":%d\r\n" % gets[0])
                    elif c in (b"SADD", b"DEL", b"EXPIRE", b"PEXPIRE", b"SREM"):
                        w.write(b":1\r\n")
                    else:
                        w.write(b"+OK\r\n")
                await w.drain()
        except Exception:
            pass
        finally:
            w.close()

    async def main():
        srv = await asyncio.start_server(handle, "127.0.0.1", port)
        async with srv:
            await srv.serve_forever()

    asyncio.run(main())


# --------------------------------------------------------------------------- #
# client mix
# --------------------------------------------------------------------------- #


def _fr(t, fl, sid, p):
    return struct.pack(">I", len(p))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + p


def _lit(i, v):
    return bytes([i]) + bytes([len(v)]) + v


def _h2_headers(path):
    # :method GET, :scheme http, :path literal, :authority "t", accept-encoding
    return (
        b"\x82\x86"
        + _lit(4, path.encode())
        + _lit(1, b"t")
        + bytes([0x0F, 0x01, 4])
        + b"zstd"
    )


H2_PREFACE = (
    b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    + _fr(4, 0, 0, struct.pack(">HI", 4, 1 << 20))  # INITIAL_WINDOW_SIZE
    + _fr(8, 0, 0, struct.pack(">I", 1 << 20))
)  # conn WINDOW_UPDATE


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.count: dict[str, int] = {}
        self.failures: list[str] = []

    def hit(self, k):
        with self.lock:
            self.count[k] = self.count.get(k, 0) + 1

    def fail(self, msg):
        with self.lock:
            self.failures.append(msg)


def _path(primed: bool) -> str:
    if primed:
        return f"/p{random.randint(0, 39)}"
    return f"/new{random.randint(0, 10**6)}"


def _pick() -> str:
    return _path(random.random() < 0.8)


def _h1_request(path: str, close: bool = True) -> bytes:
    conn = "Connection: close\r\n" if close else ""
    return (
        f"GET {path} HTTP/1.1\r\nHost: t\r\nAccept-Encoding: zstd\r\n{conn}\r\n"
    ).encode()


def _chunked_len(buf: bytes):
    """Decode a chunked body held in `buf`. Returns (state, n): state is
    "done" (terminal chunk and the blank line after the trailers seen, n =
    decoded body length), "more" (valid so far, incomplete) or "bad"."""
    i, total = 0, 0
    while True:
        e = buf.find(b"\r\n", i)
        if e < 0:
            return ("bad", 0) if len(buf) - i > 4096 else ("more", 0)
        try:
            size = int(buf[i:e].split(b";", 1)[0].strip(), 16)
        except ValueError:
            return "bad", 0
        if size < 0:
            return "bad", 0
        i = e + 2
        if size == 0:
            # trailers, then the empty line that ends the message
            while True:
                e = buf.find(b"\r\n", i)
                if e < 0:
                    return "more", 0
                if e == i:
                    return "done", total
                i = e + 2
        if len(buf) < i + size + 2:
            return "more", 0
        if buf[i + size : i + size + 2] != b"\r\n":
            return "bad", 0
        total += size
        i += size + 2


def _h1_framing(head: bytes):
    """(content_length or None, is_chunked) from a response head."""
    n = None
    chunked = False
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        k = k.strip().lower()
        if k == b"content-length":
            n = int(v)
        if k == b"transfer-encoding" and b"chunked" in v.lower():
            chunked = True
    return n, chunked


def _read_h1_response(s: socket.socket, deadline: float):
    """(status, body_len), or None when the response is not provably complete:
    EOF/timeout before the whole body arrived, a malformed chunk stream, or a
    200 with neither Content-Length nor chunked framing (close-delimited, so
    a truncated body is indistinguishable from a whole one). `deadline` is
    the TOTAL time allowed, not a per-recv() timeout."""
    end = time.monotonic() + deadline

    def recv() -> bytes | None:
        left = end - time.monotonic()
        if left <= 0:
            return None
        s.settimeout(left)
        return s.recv(65536) or None

    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            d = recv()
            if d is None:
                return None
            buf += d
        head, _, rest = buf.partition(b"\r\n\r\n")
        status = int(head.split(b" ", 2)[1])
        n, chunked = _h1_framing(head)
        if chunked:
            while True:
                state, got = _chunked_len(rest)
                if state == "done":
                    return status, got
                if state == "bad":
                    return None
                d = recv()
                if d is None:
                    return None
                rest += d
        if n is None:
            # No framing: the end of the body is only the connection close.
            return None if status == 200 else (status, len(rest))
        got = len(rest)
        while got < n:
            d = recv()
            if d is None:
                return None
            got += len(d)
        return status, got
    except (OSError, ValueError, IndexError):
        return None


def _clean_h1(st: Stats, h1: int, path: str):
    s = socket.create_connection(("127.0.0.1", h1))
    try:
        s.sendall(_h1_request(path))
        r = _read_h1_response(s, CLEAN_DEADLINE)
    finally:
        s.close()
    if r is None or r[0] != 200:
        st.fail(f"clean h1 {path}: no complete 200 within {CLEAN_DEADLINE}s ({r})")
    else:
        st.hit("clean_h1_ok")


def _h2_read_until_end(s: socket.socket, sid: int, deadline: float) -> bool:
    end = time.time() + deadline
    buf = b""
    while time.time() < end:
        s.settimeout(max(0.1, end - time.time()))
        try:
            d = s.recv(65536)
        except OSError:
            return False
        if not d:
            return False
        buf += d
        while len(buf) >= 9:
            ln = int.from_bytes(buf[:3], "big")
            if len(buf) < 9 + ln:
                break
            t, fl = buf[3], buf[4]
            fsid = int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF
            buf = buf[9 + ln :]
            if t == 4 and not fl & 1:
                s.sendall(_fr(4, 1, 0, b""))
            if t == 7:  # GOAWAY
                return False
            if t == 3 and fsid == sid:  # RST_STREAM from the server
                return False
            if fsid == sid and t in (0, 1) and fl & 1:
                return True
    return False


def _clean_h2(st: Stats, h2: int, path: str):
    s = socket.create_connection(("127.0.0.1", h2))
    try:
        s.sendall(H2_PREFACE + _fr(1, 5, 1, _h2_headers(path)))
        ok = _h2_read_until_end(s, 1, CLEAN_DEADLINE)
    finally:
        s.close()
    if not ok:
        st.fail(f"clean h2 {path}: stream not completed within {CLEAN_DEADLINE}s")
    else:
        st.hit("clean_h2_ok")


def _abort_h1(st: Stats, h1: int, mode: str):
    s = socket.create_connection(("127.0.0.1", h1))
    s.sendall(_h1_request(_pick()))
    time.sleep(random.uniform(0, 0.2))
    if mode == "rst":
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()
    st.hit(f"h1_{mode}")


def _abort_h2(st: Stats, h2: int, mode: str):
    s = socket.create_connection(("127.0.0.1", h2))
    s.sendall(H2_PREFACE)
    sid = 1
    for _ in range(random.randint(1, 4)):
        s.sendall(_fr(1, 5, sid, _h2_headers(_pick())))
        sid += 2
    time.sleep(random.uniform(0, 0.2))
    if mode == "rst_stream":
        for x in range(1, sid, 2):
            s.sendall(_fr(3, 0, x, struct.pack(">I", 8)))
        time.sleep(0.05)
    s.close()
    st.hit(f"h2_{mode}")


def _wmem_max() -> int:
    try:
        return int(pathlib.Path("/proc/sys/net/ipv4/tcp_wmem").read_text().split()[2])
    except (OSError, IndexError, ValueError):
        return 4194304


def _poke_client(st: Stats, h1: int, arm: str):
    """Blocked-send warm-up, then the parking request poked / reset / left."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)  # before connect()
    try:
        s.settimeout(30)
        s.connect(("127.0.0.1", h1))
        s.sendall(b"GET /_ab_big HTTP/1.1\r\nHost: t\r\n\r\n")
        time.sleep(0.3)  # let nginx's send block
        r = _read_h1_response(s, 30)
        if r is None or r[0] != 200:
            st.fail(f"poke warm-up: no complete 200 ({r})")
            return
        s.sendall(_h1_request(_pick()))
        time.sleep(random.uniform(0.02, 0.08))  # the request is parked now
        if arm == "poke":
            s.sendall(b"\r\n")
            time.sleep(random.uniform(0, 0.1))
        elif arm == "rst":
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        elif arm == "clean":
            # Left alone: read the parked answer to a complete 200.
            r = _read_h1_response(s, CLEAN_DEADLINE)
            if r is None or r[0] != 200:
                st.fail(f"poke_clean: parked request got no complete 200 ({r})")
                return
        st.hit(f"poke_{arm}")
    except OSError:
        st.hit("poke_oserror")
    finally:
        s.close()


def _worker(st: Stats, h1: int, h2: int, until: float):
    kinds = [
        "h1_rst",
        "h1_rst",
        "h1_fin",
        "h1_fin",
        "h2_rst_stream",
        "h2_close",
        "clean_h1",
        "clean_h2",
        "poke_poke",
        "poke_rst",
        "poke_clean",
    ]
    while time.time() < until:
        k = random.choice(kinds)
        try:
            if k.startswith("h1_"):
                _abort_h1(st, h1, k[3:])
            elif k.startswith("h2_"):
                _abort_h2(st, h2, k[3:])
            elif k == "clean_h1":
                _clean_h1(st, h1, _pick())
            elif k == "clean_h2":
                _clean_h2(st, h2, _pick())
            else:
                _poke_client(st, h1, k[5:])
        except OSError:
            st.hit("oserror")  # a refused/reset connection is not a verdict
        except Exception as exc:  # a parse error means nginx sent garbage
            # Record it and keep the thread alive: a thread that died quietly
            # would leave st.failures empty and thin the load.
            st.fail(f"{k}: client raised {exc!r}")


# /proc/net/tcp st column. Every client here ends with close() (a FIN) or an
# RST. A socket nginx still holds after the client's FIN is CLOSE_WAIT, not
# ESTABLISHED, so both count as held.
_HELD_STATES = {"01": "ESTABLISHED", "08": "CLOSE_WAIT"}


def _held_to(ports) -> list[str]:
    """Server-side ESTABLISHED or CLOSE_WAIT sockets whose local port is one of
    `ports`: connections nginx has not closed."""
    want = {f"{p:04X}" for p in ports}
    rows = []
    for f in ("/proc/net/tcp",):
        try:
            lines = pathlib.Path(f).read_text().splitlines()[1:]
        except OSError:
            continue
        for ln in lines:
            cols = ln.split()
            if cols[3] in _HELD_STATES and cols[1].split(":")[1] in want:
                rows.append(f"{_HELD_STATES[cols[3]]} {ln.strip()}")
    return rows


def _l2_lookups(h1: int) -> int | None:
    """l2_hits + l2_misses from the edge's Prometheus page; None if unreadable.
    Every L2 lookup parks the request, so a rise across the worker phase means a
    worker request parked."""
    url = f"http://127.0.0.1:{h1}/_ct?format=prometheus"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310
            text = resp.read().decode("ascii", "replace")
    except (OSError, ValueError):
        return None
    total = 0
    seen = False
    for line in text.splitlines():
        if line.startswith(("cache_turbo_l2_hits_total", "cache_turbo_l2_misses_total")):
            try:
                total += int(float(line.split()[-1]))
            except (IndexError, ValueError):
                return None
            seen = True
    return total if seen else None


def _kv_gets(kv: int) -> int | None:
    """GETs the fake KV has received and delayed so far; None if unreachable."""
    try:
        with socket.create_connection(("127.0.0.1", kv), timeout=5) as c:
            c.sendall(b"*1\r\n$8\r\nSOAKGETS\r\n")
            line = b""
            while not line.endswith(b"\r\n"):
                d = c.recv(64)
                if not d:
                    return None
                line += d
        return int(line[1:-2]) if line[:1] == b":" else None
    except (OSError, ValueError):
        return None


def run_stress(h1: int, h2: int, secs: float, kv: int | None = None) -> int:
    st = Stats()
    # Prime the hot keys so "primed" means a stored (L1/L2) entry, not a miss.
    for i in range(40):
        try:
            _clean_h1(st, h1, f"/p{i}")
        except OSError as e:
            st.fail(f"prime /p{i}: {e}")
    # Engagement is measured over the worker phase only: priming goes through
    # L2 itself, so a counter read after the run is positive even when no
    # worker request ever parked.
    lookups_before = _l2_lookups(h1)
    kv_before = _kv_gets(kv) if kv is not None else None
    until = time.time() + secs
    ts = [
        threading.Thread(target=_worker, args=(st, h1, h2, until))
        for _ in range(WORKERS)
    ]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    lookups_after = _l2_lookups(h1)
    if lookups_before is None or lookups_after is None:
        st.fail(f"engagement: L2 counters unreadable ({lookups_before}, {lookups_after})")
    elif lookups_after <= lookups_before:
        st.fail(
            f"engagement: no L2 lookup during the worker phase "
            f"({lookups_before} -> {lookups_after}), so no worker request parked"
        )
    else:
        st.count["l2_lookups_worker_phase"] = lookups_after - lookups_before
    # The L2 counters above also count GETs that fail fast after an async
    # connect, so they cannot prove the KV saw and delayed a GET. The KV's own
    # count can.
    if kv is not None:
        kv_after = _kv_gets(kv)
        if kv_before is None or kv_after is None:
            st.fail(
                f"engagement: fake KV GET count unreadable ({kv_before}, {kv_after})"
            )
        elif kv_after <= kv_before:
            st.fail(
                "engagement: the fake KV received no GET during the worker phase "
                f"({kv_before} -> {kv_after}), so no worker request parked on it"
            )
        else:
            st.count["kv_gets_worker_phase"] = kv_after - kv_before
    # Held sockets: the clients are all gone; nginx must have closed its side.
    end = time.time() + HELD_DEADLINE
    held = _held_to((h1, h2))
    while held and time.time() < end:
        time.sleep(0.5)
        held = _held_to((h1, h2))
    if held:
        st.fail(
            f"{len(held)} server-side socket(s) still ESTABLISHED or CLOSE_WAIT "
            f"{HELD_DEADLINE}s after the last client closed: {held[:3]}"
        )
    if not (st.count.get("clean_h1_ok") and st.count.get("clean_h2_ok")):
        st.fail(f"engagement: clean clients never completed ({st.count})")
    print(
        "soak-abort clients:", " ".join(f"{k}={v}" for k, v in sorted(st.count.items()))
    )
    for m in st.failures[:20]:
        print("FAIL:", m)
    return 1 if st.failures else 0


def main(argv) -> int:
    if len(argv) >= 3 and argv[1] == "origin":
        run_origin(int(argv[2]))
    elif len(argv) >= 3 and argv[1] == "kv":
        run_kv(int(argv[2]), float(argv[3]) if len(argv) > 3 else 0.1)
    elif len(argv) in (5, 6) and argv[1] == "stress":
        return run_stress(
            int(argv[2]),
            int(argv[3]),
            float(argv[4]),
            int(argv[5]) if len(argv) == 6 else None,
        )
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
