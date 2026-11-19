"""Self-tests: every primitive of ci/tools/hostile_peer.py."""

import socket
import sys
import tempfile
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import hostile_peer as hp  # noqa: E402
from hostile_peer import Peer, Step  # noqa: E402


def resp(*args: bytes) -> bytes:
    out = b"*%d\r\n" % len(args)
    for a in args:
        out += b"$%d\r\n%s\r\n" % (len(a), a)
    return out


def dial(peer: Peer) -> socket.socket:
    if peer.unix_path:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(peer.unix_path)
        return s
    return socket.create_connection(("127.0.0.1", peer.port), 3)


def recv_all(s: socket.socket) -> bytes:
    """Read until EOF; a reset counts as the end with whatever arrived."""
    buf = b""
    while True:
        try:
            d = s.recv(4096)
        except ConnectionResetError:
            return buf + b"<RST>"
        if not d:
            return buf
        buf += d


def test_reply_bytes_verbatim_and_prefix_match() -> None:
    with Peer([[Step(expect=b"GET ct:", reply=b"$3\r\nabc\r\n")]]) as p:
        with dial(p) as s:
            s.sendall(resp(b"get", b"ct:key"))
            assert s.recv(64) == b"$3\r\nabc\r\n"
        assert p.mismatches == []


def test_prefix_mismatch_recorded_and_closes() -> None:
    with Peer([[Step(expect=b"SET ", reply=b"+OK\r\n")]]) as p:
        with dial(p) as s:
            s.sendall(resp(b"GET", b"k"))
            assert recv_all(s) == b""       # closed without the reply
        (idx, want, got), = p.mismatches
        assert (idx, want, got.args) == (0, b"SET ", (b"GET", b"k"))


def test_mismatch_ignore_still_replies() -> None:
    step = Step(expect=b"SET ", reply=b"+OK\r\n", on_mismatch="ignore")
    with Peer([[step]]) as p, dial(p) as s:
        s.sendall(resp(b"GET", b"k"))
        assert s.recv(16) == b"+OK\r\n"
        assert len(p.mismatches) == 1


def test_chunking_with_per_chunk_delay() -> None:
    # Byte content and pacing only: TCP does not preserve write boundaries, so
    # chunk sizes are asserted at the send side (test_send_chunk_boundaries).
    reply = b"$10\r\n0123456789\r\n"
    with Peer([[Step(reply=reply, chunk=4, delay=0.05)]]) as p, dial(p) as s:
        t0 = time.monotonic()
        s.sendall(resp(b"GET", b"k"))
        s.settimeout(3)
        got = b""
        while len(got) < len(reply):
            d = s.recv(4096)
            assert d
            got += d
        elapsed = time.monotonic() - t0
    assert got == reply
    # 17 bytes / 4 = 5 chunks, each preceded by 50 ms
    assert elapsed >= 0.2


class _RecSock:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.at: list[float] = []

    def sendall(self, b: bytes) -> None:
        self.sent.append(bytes(b))
        self.at.append(time.monotonic())


def recv_n(s: socket.socket, n: int) -> bytes:
    """Read exactly n bytes of the stream (a recv may return part of a reply
    or several replies at once)."""
    buf = b""
    while len(buf) < n:
        d = s.recv(n - len(buf))
        assert d, f"EOF after {len(buf)} of {n} bytes"
        buf += d
    return buf


def test_send_chunk_boundaries() -> None:
    reply = b"$10\r\n0123456789\r\n"
    p = Peer([[]])
    rec = _RecSock()
    assert p._send(rec, Step(reply=reply, chunk=4))        # type: ignore[arg-type]
    assert [len(c) for c in rec.sent] == [4, 4, 4, 4, 1]
    assert b"".join(rec.sent) == reply
    one = _RecSock()
    assert p._send(one, Step(reply=reply))                 # type: ignore[arg-type]
    assert one.sent == [reply]


def test_late_unsolicited_bytes_after_delay() -> None:
    rec = _RecSock()
    p = Peer([[]])
    assert p._send(rec, Step(reply=b"+OK\r\n", late=b"$-1\r\n",  # type: ignore[arg-type]
                             late_delay=0.15))
    assert rec.sent == [b"+OK\r\n", b"$-1\r\n"]   # reply first, late separately
    # The delay sits BETWEEN the two writes (not before the first one).
    assert rec.at[1] - rec.at[0] >= 0.15
    none = _RecSock()
    assert p._send(none, Step(reply=b"+OK\r\n"))     # type: ignore[arg-type]
    assert none.sent == [b"+OK\r\n"]                 # no late write by default
    with pytest.raises(ValueError):
        Step(late=b"x", late_delay=-1)
    with Peer([[Step(reply=b"+OK\r\n", late=b":1\r\n", late_delay=0.1)]]) as q, \
            dial(q) as s:
        s.sendall(resp(b"SET", b"k", b"v"))
        s.settimeout(3)
        # Stream read: a recv may return both replies, or part of the first.
        assert recv_n(s, 9) == b"+OK\r\n:1\r\n"


def test_late_gap_check_catches_a_delay_before_the_first_write() -> None:
    """Negative control: the total-elapsed assertion the test used to make
    passes for a sender that sleeps 150 ms and then writes both replies back
    to back; the inter-write gap check does not."""
    reg = _RecSock()
    t0 = time.monotonic()
    time.sleep(0.15)                      # regressed: delay before reply 1
    reg.sendall(b"+OK\r\n")
    reg.sendall(b"$-1\r\n")
    assert time.monotonic() - t0 >= 0.15           # old oracle: passes
    assert reg.at[1] - reg.at[0] < 0.15            # new oracle: fails it


def test_negative_data_length_rejected() -> None:
    rd = hp._Reader(None)                                  # type: ignore[arg-type]
    rd.buf = b"abc"
    with pytest.raises(hp._ProtocolError):
        rd.exact(-2)
    assert rd.buf == b"abc"
    assert rd.exact(0) == b""                              # zero stays valid
    with Peer([[Step(reply=b"+OK\r\n")]]) as p, dial(p) as s:
        s.sendall(b"*1\r\n$-2\r\nPING\r\n")
        assert recv_all(s) in (b"", b"<RST>")              # closed, no reply
        assert p.wait_for_closed(1)
        assert p.commands() == []
    with Peer([[Step(reply=b"STORED\r\n")]], proto="memcached") as p, dial(p) as s:
        s.sendall(b"set k 0 0 -2\r\nhi\r\n")
        assert recv_all(s) in (b"", b"<RST>")
        assert p.wait_for_closed(1)
        assert p.commands() == []
    with Peer([[Step(reply=b"+OK\r\n")]]) as p, dial(p) as s:   # $0 valid
        s.sendall(b"*1\r\n$0\r\n\r\n")
        assert s.recv(16) == b"+OK\r\n"


def test_responder_valueerror_recorded_in_errors() -> None:
    def respond(_cmd: hp.Command) -> Step | None:
        raise ValueError("responder bug")
    with Peer(responder=respond) as p, dial(p) as s:
        s.sendall(resp(b"PING"))
        assert recv_all(s) in (b"", b"<RST>")
        assert p.wait_for_closed(1)
        assert len(p.errors) == 1 and isinstance(p.errors[0], ValueError)
        assert not isinstance(p.errors[0], hp._ProtocolError)


def test_malformed_client_input_is_silent() -> None:
    for payload in (b"*1\r\n$-2\r\nPING\r\n", b"*x\r\n", b"*1\r\n$zz\r\n",
                    b"*1\r\n+OK\r\n"):
        with Peer([[Step(reply=b"+OK\r\n")]]) as p, dial(p) as s:
            s.sendall(payload)
            assert recv_all(s) in (b"", b"<RST>")
            assert p.wait_for_closed(1)
            assert p.errors == []


def test_bad_script_selection_still_closes_connection() -> None:
    def boom(_i: int) -> list[Step]:
        raise RuntimeError("selector")

    for peer in (Peer(boom), Peer([])):
        with peer as p, dial(p) as s:
            assert p.wait_for_closed(1)
            assert recv_all(s) in (b"", b"<RST>")
            assert p.connections[0].closed is not None
            assert p._socks == set()
            assert len(p.errors) == 1


def test_close_after_reply() -> None:
    with Peer([[Step(reply=b"+OK\r\n", then=hp.CLOSE)]]) as p, dial(p) as s:
        s.sendall(resp(b"PING"))
        assert recv_all(s) == b"+OK\r\n"
        assert p.wait_for_closed(1)


def test_truncated_reply_then_close() -> None:
    with Peer([[Step(reply=b"$10\r\nabc", then=hp.CLOSE)]]) as p, dial(p) as s:
        s.sendall(resp(b"GET", b"k"))
        assert recv_all(s) == b"$10\r\nabc"


def test_rst_after_reply() -> None:
    with Peer([[Step(reply=b"+OK\r\n", then=hp.RST)]]) as p, dial(p) as s:
        s.sendall(resp(b"PING"))
        out = recv_all(s)
    assert out in (b"<RST>", b"+OK\r\n<RST>")     # reset, never a clean EOF


def test_never_reply_holds_connection_open() -> None:
    with Peer([[Step(never=True)]]) as p, dial(p) as s:
        s.sendall(resp(b"GET", b"k"))
        s.settimeout(0.4)
        with pytest.raises(TimeoutError):
            s.recv(16)
        assert p.commands()[0].args == (b"GET", b"k")
        assert not p.wait_for_closed(1, timeout=0.2)  # still open


def test_half_close_then_connection_keeps_reading() -> None:
    steps = [Step(reply=b"+A\r\n", then=hp.HALF_CLOSE),
             Step(reply=b"+B\r\n")]
    with Peer([steps]) as p, dial(p) as s:
        s.sendall(resp(b"X"))
        s.settimeout(3)
        assert s.recv(16) == b"+A\r\n"
        assert s.recv(16) == b""                      # FIN from the peer
        s.sendall(resp(b"Y"))                         # our write side is open
        assert p.wait_for_commands(2)
        assert p.commands()[1].args == (b"Y",)


def test_script_exhausted_closes_and_none_keeps_open() -> None:
    with Peer([[Step(reply=b"+1\r\n")]]) as p, dial(p) as s:
        s.sendall(resp(b"A"))
        assert s.recv(16) == b"+1\r\n"
        s.sendall(resp(b"B"))
        assert recv_all(s) == b""
    with Peer([[]], on_exhausted=hp.NONE) as p, dial(p) as s:
        s.sendall(resp(b"A"))
        s.settimeout(0.3)
        with pytest.raises(TimeoutError):
            s.recv(16)


def test_unix_socket() -> None:
    with tempfile.TemporaryDirectory() as d:
        path = str(Path(d) / "peer.sock")
        with Peer([[Step(reply=b"+OK\r\n")]], unix_path=path) as p:
            assert p.address == path
            with dial(p) as s:
                s.sendall(resp(b"PING"))
                assert s.recv(16) == b"+OK\r\n"


def test_caller_given_and_ephemeral_port() -> None:
    with Peer([[]]) as p:
        assert p.port > 0
        free = p.port
    with Peer([[Step(reply=b"+OK\r\n")]], port=free) as p2, dial(p2) as s:
        assert p2.port == free
        s.sendall(resp(b"PING"))
        assert s.recv(16) == b"+OK\r\n"


def test_records_connections_and_commands_thread_safely() -> None:
    scripts = [[Step(reply=b"+OK\r\n")] * 2, [Step(reply=b"+OK\r\n")]]
    with Peer(scripts) as p:
        a, b = dial(p), dial(p)
        a.sendall(resp(b"SET", b"k", b"v\r\nx"))      # binary-safe argument
        a.recv(16)
        b.sendall(resp(b"DEL", b"k"))
        b.recv(16)
        a.sendall(b"PING\r\n")                        # inline command
        a.recv(16)
        a.close()
        b.close()
        assert p.wait_for_closed(2)
        assert p.accepted == 2
        recs = p.connections
        assert [c.args for c in recs[0].commands] == \
            [(b"SET", b"k", b"v\r\nx"), (b"PING",)]
        assert [c.args for c in recs[1].commands] == [(b"DEL", b"k")]
        assert [c.conn for c in p.commands()] == [0, 0, 1]


def test_script_selector_callable_per_connection() -> None:
    def pick(i: int) -> list[Step]:
        return [Step(reply=b"+%d\r\n" % i)]
    with Peer(pick) as p:
        for want in (b"+0\r\n", b"+1\r\n"):
            with dial(p) as s:
                s.sendall(resp(b"X"))
                assert s.recv(16) == want


def test_responder_mode() -> None:
    def respond(cmd: hp.Command) -> Step | None:
        return Step(reply=b":%d\r\n" % len(cmd.args))
    with Peer(responder=respond) as p, dial(p) as s:
        s.sendall(resp(b"A", b"B", b"C"))
        assert s.recv(16) == b":3\r\n"


def test_memcached_lines_and_data_block() -> None:
    steps = [Step(expect=b"SET k", reply=b"STORED\r\n"),
             Step(expect=b"get k", reply=b"VALUE k 0 2\r\nhi\r\nEND\r\n")]
    with Peer([steps], proto="memcached") as p, dial(p) as s:
        s.sendall(b"set k 0 0 5\r\nab\r\nc\r\n")      # data holds CRLF
        assert s.recv(16) == b"STORED\r\n"
        s.sendall(b"get k\r\n")
        assert s.recv(64) == b"VALUE k 0 2\r\nhi\r\nEND\r\n"
        cmds = p.commands()
        assert cmds[0].data == b"ab\r\nc" and cmds[1].data is None
        assert p.mismatches == []


def test_stop_unblocks_held_connection_and_is_idempotent() -> None:
    p = Peer([[Step(never=True)]]).start()
    s = dial(p)
    s.sendall(resp(b"GET", b"k"))
    assert p.wait_for_commands(1)
    p.stop()
    p.stop()
    s.settimeout(3)
    assert recv_all(s) in (b"", b"<RST>")
    s.close()


def test_invalid_construction_rejected() -> None:
    with pytest.raises(ValueError):
        Step(then="explode")
    with pytest.raises(ValueError):
        Step(chunk=-1)
    with pytest.raises(ValueError):
        Peer()
    with pytest.raises(ValueError):
        Peer([[]], proto="http")


def test_unix_socket_file_removed_so_path_is_reusable() -> None:
    with tempfile.TemporaryDirectory() as d:
        path = str(Path(d) / "peer.sock")
        for _ in range(2):
            with Peer([[Step(reply=b"+OK\r\n")]], unix_path=path) as p:
                with dial(p) as s:
                    s.sendall(resp(b"PING"))
                    assert s.recv(16) == b"+OK\r\n"
            assert not Path(path).exists()


def test_responder_mismatch_index_is_command_ordinal() -> None:
    with Peer(responder=lambda c: Step(expect=b"SET ", reply=b"+OK\r\n",
                                       on_mismatch="ignore")) as p:
        with dial(p) as s:
            s.sendall(resp(b"SET", b"k", b"v"))
            s.recv(16)
            s.sendall(resp(b"GET", b"k"))
            s.recv(16)
        assert [m[0] for m in p.mismatches] == [1]
