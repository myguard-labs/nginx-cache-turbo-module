"""Self-tests: replay model of ci/tools/hostile_peer_equiv.py."""

import base64
import json
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import hostile_peer as hp  # noqa: E402
import hostile_peer_equiv as eq  # noqa: E402


def entry(verb: str, key: bytes, epoch: int, reply: bytes,
          echo: str | None = None) -> dict:
    b = base64.b64encode
    return {"verb": verb, "target": b(key).decode(), "epoch": epoch,
            "reply": b(reply).decode(), "echo": echo}


def cmd(*args: bytes) -> hp.Command:
    return hp.Command(0, args)


def make_replay(tmp_path: Path, entries: list[dict],
                corrupt: bool = False) -> eq.Replay:
    f = tmp_path / "f.json"
    f.write_text(json.dumps({"entries": entries}))
    return eq.Replay(f, corrupt)


def test_read_reply_frames_nested_and_split() -> None:
    a, b = socket.socketpair()
    try:
        raw = b"*2\r\n$3\r\nabc\r\n*1\r\n:7\r\n"
        b.sendall(raw[:9])
        b.sendall(raw[9:] + b"+NEXT\r\n")
        buf = bytearray()
        assert eq.read_reply(a, buf) == raw
        assert eq.read_reply(a, buf) == b"+NEXT\r\n"
        b.sendall(b"$-1\r\n")
        assert eq.read_reply(a, buf) == b"$-1\r\n"
    finally:
        a.close()
        b.close()


def test_replay_epoch_selects_reply_by_mutation_count(tmp_path: Path) -> None:
    r = make_replay(tmp_path, [
        entry("EXISTS", b"k", 1, b":0\r\n"),
        entry("EXISTS", b"k", 2, b":1\r\n"),
        entry("DEL", b"k", 0, b":0\r\n"),
        entry("SET", b"k", 1, b"+OK\r\n"),
    ])
    assert r(cmd(b"DEL", b"k")).reply == b":0\r\n"
    assert r(cmd(b"EXISTS", b"k")).reply == b":0\r\n"
    assert r(cmd(b"EXISTS", b"k")).reply == b":0\r\n"     # polling is free
    assert r(cmd(b"SET", b"k", b"v")).reply == b"+OK\r\n"
    assert r(cmd(b"EXISTS", b"k")).reply == b":1\r\n"
    assert r.misses == []


def test_replay_echoes_last_set_value(tmp_path: Path) -> None:
    r = make_replay(tmp_path, [
        entry("SET", b"k", 0, b"+OK\r\n"),
        entry("GET", b"k", 1, b"$3\r\nold\r\n", "bulk"),
        entry("STRLEN", b"k", 1, b":3\r\n", "len"),
    ])
    r(cmd(b"SET", b"k", b"fresh!"))
    assert r(cmd(b"GET", b"k")).reply == b"$6\r\nfresh!\r\n"
    assert r(cmd(b"STRLEN", b"k")).reply == b":6\r\n"


def test_replay_unrecorded_command_is_a_miss(tmp_path: Path) -> None:
    r = make_replay(tmp_path, [])
    assert r(cmd(b"GET", b"nope")).reply.startswith(b"-ERR")
    assert r.misses == [b"GET nope"]


def test_corrupt_bulk_len_changes_only_bulk_header(tmp_path: Path) -> None:
    ents = [entry("GET", b"k", 0, b"$3\r\nabc\r\n"),
            entry("GET", b"n", 0, b"$-1\r\n"),
            entry("EXISTS", b"k", 0, b":1\r\n")]
    r = make_replay(tmp_path, ents, corrupt=True)
    assert r(cmd(b"GET", b"k")).reply == b"$4\r\nabc\r\n"
    assert r(cmd(b"GET", b"n")).reply == b"$-1\r\n"
    assert r(cmd(b"EXISTS", b"k")).reply == b":1\r\n"
