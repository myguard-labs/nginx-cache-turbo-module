#!/usr/bin/env python3
r"""Equivalence control for hostile_peer: real Redis vs replayed Redis.

The existing L2 store / hit / purge smoke tests run UNMODIFIED, through
run_named.py's fixture stack, with the plain `redis` fixture swapped for either

  capture  a recording proxy in front of a real redis-server: every command
           and the real reply are saved to a JSON fixture; or
  replay   a hostile_peer.Peer that answers from that fixture and runs no
           redis-server at all.

Both modes then drive the same tests, so a replay pass shows the peer is
indistinguishable from real Redis for the traffic those tests generate.

Capture (writes ci/fixtures/hostile_peer/l2_smoke_redis.json):

    python3 ci/tools/hostile_peer_equiv.py capture \
        --fixture ci/fixtures/hostile_peer/l2_smoke_redis.json -- \
        --nginx-binary .build/nginx-X/objs/nginx --port 19240 \
        --redis-server /usr/bin/redis-server NAME...

Replay (same tests, same assertions, no redis-server behind it):

    python3 ci/tools/hostile_peer_equiv.py replay \
        --fixture ci/fixtures/hostile_peer/l2_smoke_redis.json -- \
        --nginx-binary ... --port 19240 --redis-server /usr/bin/redis-server NAME...

`replay --corrupt-bulk-len` declares every replayed bulk reply one byte longer
than its payload: a negative control that must make the smoke tests fail.
(--redis-server is still passed: the AUTH/TLS fixtures stay real.)

Replay model.  A reply is looked up by (verb, first-argument key) and the
number of mutating commands already seen for that key (its epoch), taking the
newest recorded epoch <= the current one.  That reproduces "EXISTS is 0, then 1
after the SET lands" without depending on how often a test polls.  Values the
tests themselves wrote are not replayed from a stale capture: when the recorded
GET reply equalled the last SET value (or STRLEN its length), the replay
answers with the last value SET on that key in THIS run (the CTB5 blob carries
an absolute creation time, so a verbatim old copy would read as expired).
A command with no recorded reply gets an error reply and fails the run.
"""

from __future__ import annotations

import argparse
import base64
import json
import pathlib
import socket
import sys
import threading

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import hostile_peer as hp  # noqa: E402

READ_ONLY = {b"GET", b"EXISTS", b"PTTL", b"TTL", b"STRLEN", b"PING", b"SCAN",
             b"SSCAN", b"SMEMBERS", b"TYPE", b"MGET", b"INFO", b"SCARD",
             b"DBSIZE", b"KEYS"}


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _bulk(b: bytes) -> bytes:
    return b"$%d\r\n%s\r\n" % (len(b), b)


def read_reply(sock: socket.socket, buf: bytearray) -> bytes:
    """Read exactly one RESP2 reply (nested arrays included) off `sock`."""
    def fill(n: int) -> None:
        while len(buf) < n:
            d = sock.recv(65536)
            if not d:
                raise EOFError("upstream closed")
            buf.extend(d)

    def line(pos: int) -> int:
        while True:
            i = buf.find(b"\r\n", pos)
            if i >= 0:
                return i
            fill(len(buf) + 1)

    def parse(pos: int) -> int:
        i = line(pos)
        kind, rest = buf[pos:pos + 1], bytes(buf[pos + 1:i])
        if kind in (b"+", b"-", b":"):
            return i + 2
        n = int(rest)
        if kind == b"$":
            if n < 0:
                return i + 2
            fill(i + 2 + n + 2)
            return i + 2 + n + 2
        if kind == b"*":
            pos = i + 2
            for _ in range(max(n, 0)):
                pos = parse(pos)
            return pos
        raise ValueError(f"unknown RESP type {kind!r}")

    end = parse(0)
    out = bytes(buf[:end])
    del buf[:end]
    return out


def _key(cmd: hp.Command) -> bytes:
    return cmd.args[1] if len(cmd.args) > 1 else b""


class Capture:
    """Responder that forwards to a real redis and records each exchange."""

    def __init__(self, upstream_port: int) -> None:
        self.sock = socket.create_connection(("127.0.0.1", upstream_port), 5)
        self.buf = bytearray()
        self.lock = threading.Lock()
        self.epoch: dict[bytes, int] = {}
        self.last_set: dict[bytes, bytes] = {}
        self.entries: list[dict] = []

    def __call__(self, cmd: hp.Command) -> hp.Step:
        raw = b"*%d\r\n" % len(cmd.args) + b"".join(_bulk(a) for a in cmd.args)
        verb, key = cmd.args[0].upper(), _key(cmd)
        with self.lock:
            self.sock.sendall(raw)
            reply = read_reply(self.sock, self.buf)
            ep = self.epoch.get(key, 0)
            echo = None
            last = self.last_set.get(key)
            if last is not None and verb == b"GET" and reply == _bulk(last):
                echo = "bulk"
            elif last is not None and verb == b"STRLEN" \
                    and reply == b":%d\r\n" % len(last):
                echo = "len"
            self.entries.append({"verb": verb.decode(), "target": _b64(key),
                                 "epoch": ep, "reply": _b64(reply),
                                 "echo": echo})
            if verb not in READ_ONLY:
                self.epoch[key] = ep + 1
                if verb == b"SET" and len(cmd.args) > 2:
                    self.last_set[key] = cmd.args[2]
        return hp.Step(reply=reply)

    def save(self, path: pathlib.Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"entries": self.entries}, indent=1) + "\n")


class Replay:
    """Responder that answers from a saved capture."""

    def __init__(self, path: pathlib.Path, corrupt_bulk_len: bool = False):
        self.table: dict[tuple[bytes, bytes], dict[int, dict]] = {}
        for e in json.loads(path.read_text())["entries"]:
            slot = self.table.setdefault(
                (e["verb"].encode(), base64.b64decode(e["target"])), {})
            slot[e["epoch"]] = {"reply": base64.b64decode(e["reply"]),
                                "echo": e["echo"]}
        self.corrupt = corrupt_bulk_len
        self.lock = threading.Lock()
        self.epoch: dict[bytes, int] = {}
        self.last_set: dict[bytes, bytes] = {}
        self.misses: list[bytes] = []

    def __call__(self, cmd: hp.Command) -> hp.Step:
        verb, key = cmd.args[0].upper(), _key(cmd)
        with self.lock:
            ep = self.epoch.get(key, 0)
            slot = self.table.get((verb, key))
            if verb not in READ_ONLY:
                self.epoch[key] = ep + 1
                if verb == b"SET" and len(cmd.args) > 2:
                    self.last_set[key] = cmd.args[2]
            if not slot:
                self.misses.append(cmd.line)
                return hp.Step(reply=b"-ERR hostile_peer replay: no recorded "
                                     b"reply\r\n")
            use = max((e for e in slot if e <= ep), default=min(slot))
            rec = slot[use]
            reply = rec["reply"]
            last = self.last_set.get(key)
            if rec["echo"] == "bulk" and last is not None:
                reply = _bulk(last)
            elif rec["echo"] == "len" and last is not None:
                reply = b":%d\r\n" % len(last)
        if self.corrupt and reply[:1] == b"$" and reply[:3] != b"$-1":
            hdr, _, body = reply.partition(b"\r\n")
            reply = b"$%d\r\n%s" % (int(hdr[1:]) + 1, body)
        return hp.Step(reply=reply)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    ap.add_argument("mode", choices=("capture", "replay"))
    ap.add_argument("--fixture", required=True, type=pathlib.Path)
    ap.add_argument("--corrupt-bulk-len", action="store_true")
    argv = sys.argv[1:]
    cut = argv.index("--") if "--" in argv else len(argv)
    a = ap.parse_args(argv[:cut])
    rest = argv[cut + 1:]
    if a.corrupt_bulk_len and a.mode != "replay":
        ap.error("--corrupt-bulk-len needs replay")

    import run_named
    T = run_named.T
    real_cls = T.RedisServer
    state: dict[str, object] = {}

    class Fronted(real_cls):  # type: ignore[misc, valid-type]
        def start(self) -> None:
            front = self.port
            if a.mode == "capture":
                self.port = _free_port()
                super().start()                  # real redis on a side port
                cap = Capture(self.port)
                state["cap"] = cap
                peer = hp.Peer(responder=cap, port=front)
            else:
                rep = Replay(a.fixture, a.corrupt_bulk_len)
                state["rep"] = rep
                peer = hp.Peer(responder=rep, on_exhausted=hp.CLOSE, port=front)
            state["peer"] = peer
            peer.start()
            self.port = front
            self.cli("FLUSHALL")

        def stop(self) -> None:
            peer = state.pop("peer", None)
            if isinstance(peer, hp.Peer):
                peer.stop()
            super().stop()

    def factory(binary, root, port, password=None, tls_certs=None):
        if password is None and tls_certs is None and root.name == "redis":
            return Fronted(binary, root, port)
        return real_cls(binary, root, port, password=password,
                        tls_certs=tls_certs)

    T.RedisServer = factory
    sys.argv = ["run_named.py", *rest]
    rc = run_named.main()
    if a.mode == "capture":
        cap = state.get("cap")
        assert isinstance(cap, Capture)
        cap.save(a.fixture)
        print(f"captured {len(cap.entries)} exchanges -> {a.fixture}")
    else:
        rep = state.get("rep")
        assert isinstance(rep, Replay)
        print(f"replay misses: {len(rep.misses)}")
        for m in rep.misses:
            print("  no recorded reply for:", m[:80])
        if rep.misses and rc == 0:
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
