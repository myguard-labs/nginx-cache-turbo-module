#!/usr/bin/env python3
"""Exercise the real legacy parser's wire-order guard, without a module loaded.

This complements HARD-R2's cache/origin oracles. Requests use the same literal
HPACK encoder and raw client, but require a PROTOCOL_ERROR stream reset for the
new ordering guard. Valid requests must finish with the complete static body.
"""

import argparse
import itertools
import json
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from areas import hostile_http2 as h2


def cases() -> list[tuple[str, tuple[bytes, ...], str]]:
    """Return valid permutations, ignored/special fields and split-block cases."""
    base = tuple(h2.base("/"))
    rows: list[tuple[str, tuple[bytes, ...], str]] = [
        (f"permutation-{i}", (h2.header_block(order + (("x-a", "1"),)),), "ok")
        for i, order in enumerate(itertools.permutations(base))
    ]
    for name, value in [
        ("x-a", "1"),
        ("x_bad", "ignored"),
        ("cookie", "a=1"),
        ("content-length", "0"),
    ]:
        regular = ((name, value),)
        rows.append((f"ordered-{name}", (h2.header_block(base + regular),), "ok"))
        rows.append(
            (
                f"late-path-{name}",
                (h2.header_block(base[:3] + regular + base[3:]),),
                "order",
            )
        )
    # Host replaces :authority on a valid request. Supplying both is rejected
    # before a later field can exercise the ordering guard on nginx 1.22.1.
    host_base = tuple(field for field in base if field[0] != ":authority")
    host = (("host", h2.HOST),)
    rows.append(("ordered-host", (h2.header_block(host_base + host),), "ok"))
    rows.append(
        (
            "late-path-host",
            (h2.header_block(host_base[:2] + host + host_base[2:]),),
            "order",
        )
    )
    # An indexed regular field bypasses literal-name parsing, but not ordering.
    prefix = h2.header_block(base[:3]) + b"\x90"  # RFC 7541 static index 16
    tail = h2.header_block(base[3:])
    rows.append(("late-path-indexed", (prefix + tail,), "order"))
    regular = h2.header_block((("x-a", "1"),))
    prefix = h2.header_block(base[:3]) + regular
    for name, split in [
        ("between-fields", len(prefix)),
        ("inside-regular", len(prefix) - 3),
        ("inside-pseudo", len(prefix) + 4),
    ]:
        block = prefix + tail
        rows.append((f"continuation-{name}", (block[:split], block[split:]), "order"))
    # Multiple CONTINUATIONs, including a split regular field and pseudo field.
    block = prefix + tail
    rows.append(
        (
            "continuation-many",
            (
                block[:2],
                block[2 : len(prefix) - 1],
                block[len(prefix) - 1 : len(prefix) + 4],
                block[len(prefix) + 4 :],
            ),
            "order",
        )
    )
    good = h2.header_block(base + (("cookie", "a=1"),))
    rows.append(("continuation-valid", (good[:2], good[2:-1], good[-1:]), "ok"))
    for name, fields in [
        ("duplicate-path", base + ((":path", "/other"),)),
        ("unknown-pseudo", base + ((":foo", "bar"),)),
        ("uppercase-name", base + (("X-Foo", "bar"),)),
    ]:
        rows.append((name, (h2.header_block(fields),), "reject"))
    # Each required pseudo-header can be the first forbidden late field.
    for name, value in base[:3]:
        fields = tuple(field for field in base if field[0] != name)
        fields += (("x-a", "1"), (name, value))
        rows.append((f"late-{name[1:]}", (h2.header_block(fields),), "order"))
    return rows


def send_request(conn: h2.H2Conn, sid: int, chunks: tuple[bytes, ...]) -> None:
    """Keep actual frame boundaries, including partial HPACK strings."""
    conn.streams[sid] = h2.Stream()
    for i, chunk in enumerate(chunks):
        kind = h2.HEADERS if i == 0 else h2.CONTINUATION
        flags = h2.FLAG_END_STREAM if i == 0 else 0
        if i == len(chunks) - 1:
            flags |= h2.FLAG_END_HEADERS
        assert conn.send(h2.frame(kind, flags, sid, chunk)), "request send failed"


def observe(conn: h2.H2Conn, sid: int, expect: str) -> dict:
    """Require complete success or the specific stream-local ordering error."""
    stream = conn.wait(sid, 3)
    conn.quiet(h2.QUIET_S)
    result = {
        "status": stream.status,
        "rst": stream.rst,
        "goaway": conn.goaway,
        "ended": stream.ended,
        "body_hex": stream.body.hex(),
    }
    if expect == "order":
        ok = stream.rst == 1 and conn.goaway is None
    elif expect == "ok":
        ok = (
            stream.status == 200
            and stream.ended
            and stream.body == b"ok\n"
            and stream.rst is None
            and conn.goaway is None
        )
    else:
        ok = stream.rst is not None or stream.status >= 400
    result["pass"] = ok
    return result


def check(port: int) -> list[dict]:
    """Check independent requests and stream isolation on a shared connection."""
    results = []
    for name, chunks, expect in cases():
        conn = h2.H2Conn(port)
        try:
            send_request(conn, 1, chunks)
            results.append({"case": name, **observe(conn, 1, expect)})
        finally:
            conn.close()
    conn = h2.H2Conn(port)
    try:
        good = (h2.header_block(tuple(h2.base("/")) + (("x-a", "1"),)),)
        bad = next(chunks for name, chunks, _ in cases() if name == "late-path-x-a")
        # Keep two complete requests in flight so one stream's regular-field
        # state cannot reject another stream's leading pseudo-headers.
        send_request(conn, 1, good)
        send_request(conn, 3, good)
        results.append({"case": "parallel-stream", **observe(conn, 3, "ok")})
        results.append({"case": "first-stream", **observe(conn, 1, "ok")})
        send_request(conn, 5, bad)
        results.append({"case": "bad-stream", **observe(conn, 5, "order")})
        send_request(conn, 7, good)
        results.append({"case": "after-reset-stream", **observe(conn, 7, "ok")})
    finally:
        conn.close()
    return results


def run(binary: Path, port: int) -> list[dict]:
    """Own one isolated nginx process and always reap it before returning."""
    with tempfile.TemporaryDirectory(prefix="legacy-http2-order-") as name:
        root = Path(name)
        (root / "logs").mkdir()
        config = root / "nginx.conf"
        config.write_text(
            f"worker_processes 1; pid {root}/nginx.pid;\n"
            f"error_log {root}/logs/error.log info;\n"
            "events { worker_connections 128; }\n"
            "http { access_log off; server { "
            f"listen 127.0.0.1:{port} http2; server_name {h2.HOST}; "
            'location / { return 200 "ok\\n"; } } }\n',
            encoding="utf-8",
        )
        with (
            (root / "process.log").open("wb") as log,
            subprocess.Popen(
                [
                    str(binary.resolve()),
                    "-p",
                    str(root),
                    "-c",
                    str(config),
                    "-g",
                    "daemon off;",
                ],
                stdout=log,
                stderr=log,
            ) as proc,
        ):
            try:
                for _ in range(100):
                    if proc.poll() is not None:
                        detail = (root / "process.log").read_text()
                        raise RuntimeError(
                            f"selected nginx exited before listener readiness\n{detail}"
                        )
                    try:
                        owned_pid = (root / "nginx.pid").read_text().strip()
                    except (OSError, UnicodeError):
                        owned_pid = ""
                    if owned_pid != str(proc.pid):
                        time.sleep(0.05)
                        continue
                    try:
                        with socket.create_connection(("127.0.0.1", port), 0.1):
                            break
                    except OSError:
                        time.sleep(0.05)
                else:
                    raise RuntimeError("legacy HTTP/2 listener did not start")
                results = check(port)
                if proc.poll() is not None:
                    detail = (root / "process.log").read_text()
                    raise RuntimeError(
                        f"selected nginx exited during protocol checks\n{detail}"
                    )
                return results
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


def main() -> None:
    """Report all controls before failing on any parser divergence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx-binary", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    results = run(args.nginx_binary, args.port)
    print(json.dumps(results, indent=2), flush=True)
    failed = [row for row in results if not row["pass"]]
    assert not failed, f"legacy HTTP/2 ordering controls: {failed}"
    print(f"legacy HTTP/2 ordering controls: {len(results)} passed")


if __name__ == "__main__":
    main()
