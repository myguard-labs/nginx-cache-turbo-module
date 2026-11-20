"""Exact legacy admission and focused protocol control contracts."""

import hashlib
import importlib.util
import subprocess
import sys
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ci/tools"))

CHECK_SPEC = importlib.util.spec_from_file_location(
    "check_legacy_http2_order", ROOT / "ci/tools/check_legacy_http2_order.py"
)
assert CHECK_SPEC is not None and CHECK_SPEC.loader is not None
checker = importlib.util.module_from_spec(CHECK_SPEC)
CHECK_SPEC.loader.exec_module(checker)

SPEC = importlib.util.spec_from_file_location(
    "legacy_http2_order", ROOT / "ci/tools/legacy_http2_order.py"
)
assert SPEC is not None and SPEC.loader is not None
legacy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(legacy)


class FakeProcess:
    """Minimal controllable Popen context for listener-ownership tests."""

    pid = 4321

    def __init__(self, polls):
        self._polls = iter(polls)
        self._last_poll = None
        self.terminated = False

    def __enter__(self):
        return self

    def __exit__(self, _kind, _value, _traceback):
        return False

    def poll(self):
        self._last_poll = next(self._polls, self._last_poll)
        return self._last_poll

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return 0

    def kill(self):
        raise AssertionError("graceful fake-process reap unexpectedly timed out")


@pytest.fixture(name="runtime")
def runtime_harness(tmp_path, monkeypatch):
    """Install a network-free fake runtime and return its controls."""

    def install(*, pid_text=None, polls=(None,), results=None):
        process = FakeProcess(polls)
        if pid_text is not None:
            (tmp_path / "nginx.pid").write_text(pid_text, encoding="utf-8")
        listener = Mock(return_value=nullcontext())
        checked = [] if results is None else results
        monkeypatch.setattr(
            checker.tempfile,
            "TemporaryDirectory",
            lambda **_kwargs: nullcontext(str(tmp_path)),
        )
        monkeypatch.setattr(checker.subprocess, "Popen", lambda *_args, **_kwargs: process)
        monkeypatch.setattr(checker.socket, "create_connection", listener)
        monkeypatch.setattr(checker.time, "sleep", lambda _delay: None)
        monkeypatch.setattr(checker, "check", lambda _port: checked)
        return process, listener, checked

    return install


@pytest.fixture(name="tree")
def source_tree(tmp_path, monkeypatch):
    sources = {}
    patches = []
    for name in legacy.SOURCES:
        old, new = b"before\nold\nafter\n", b"before\nnew\nafter\n"
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(old)
        target.chmod(0o640)
        sources[name] = (
            hashlib.sha256(old).hexdigest(),
            hashlib.sha256(new).hexdigest(),
        )
        patches.append(
            f"--- a/{name}\n+++ b/{name}\n"
            "@@ -1,3 +1,3 @@\n before\n-old\n+new\n after\n"
        )
    patch = tmp_path / "change.patch"
    patch.write_text("".join(patches))
    monkeypatch.setattr(legacy, "PATCH", patch)
    monkeypatch.setattr(legacy, "SOURCES", sources)
    return tmp_path, patch


def test_apply_idempotence_and_modes(tree):
    root, _patch = tree
    assert legacy.apply(root) == "applied"
    targets = [root / name for name in legacy.SOURCES]
    assert all(p.read_bytes() == b"before\nnew\nafter\n" for p in targets)
    assert all(p.stat().st_mode & 0o777 == 0o640 for p in targets)
    stamps = [p.stat().st_mtime_ns for p in targets]
    assert legacy.apply(root) == "already patched"
    assert [p.stat().st_mtime_ns for p in targets] == stamps
    assert not list(root.glob(".legacy-http2-*"))


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("content", [b"", b"drift\n", b"before\nnew\nafter\n"])
def test_reject_drift_or_mixed_pair_without_writes(tree, index, content):
    root, _patch = tree
    targets = [root / name for name in legacy.SOURCES]
    targets[index].write_bytes(content)
    before = [p.read_bytes() for p in targets]
    with pytest.raises(ValueError, match="source checksum mismatch"):
        legacy.apply(root)
    assert [p.read_bytes() for p in targets] == before


@pytest.mark.parametrize("bad", ["not a patch\n", "partial", "result"])
def test_patch_failure_does_not_publish_either_file(tree, bad):
    root, patch = tree
    text = patch.read_text()
    if bad == "partial":
        # First file applies, second hunk fails in the private scratch tree.
        text = text[: text.rindex("-old")] + text[text.rindex("-old") :].replace(
            "-old", "-absent"
        )
    elif bad == "result":
        text = text[: text.rindex("+new")] + text[text.rindex("+new") :].replace(
            "+new", "+wrong"
        )
    else:
        text = bad
    patch.write_text(text)
    with pytest.raises(ValueError, match="patch failed|patched checksum mismatch"):
        legacy.apply(root)
    assert all(
        (root / p).read_bytes() == b"before\nold\nafter\n" for p in legacy.SOURCES
    )
    assert not list(root.glob(".legacy-http2-*"))


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("kind", ["missing", "symlink"])
def test_reject_nonregular_sources(tree, index, kind):
    root, _patch = tree
    target = root / list(legacy.SOURCES)[index]
    target.unlink()
    outside = root / "outside"
    outside.write_bytes(b"before\nold\nafter\n")
    if kind == "symlink":
        target.symlink_to(outside)
    with pytest.raises(ValueError, match="regular file"):
        legacy.apply(root)
    assert outside.read_bytes() == b"before\nold\nafter\n"


def test_missing_patch_tool_keeps_sources(tree, monkeypatch):
    root, _patch = tree
    monkeypatch.setenv("PATH", "")
    with pytest.raises(FileNotFoundError):
        legacy.apply(root)
    assert all(
        (root / p).read_bytes() == b"before\nold\nafter\n" for p in legacy.SOURCES
    )


@pytest.mark.parametrize(
    "flavor,version,expected",
    [
        ("nginx", "1.22.1", 1),
        ("nginx", "1.31.3", 0),
        ("nginx", "1.30.4", 0),
        ("angie", "1.22.1", 0),
    ],
)
def test_build_is_version_and_flavor_limited(flavor, version, expected):
    text = (ROOT / "ci/tools/ci-build.sh").read_text()
    start = text.index('if [ "$FLAVOR" = nginx ] && [ "$VERSION" = 1.22.1 ]; then')
    snippet = text[start : text.index("\nfi", start) + 3]
    result = subprocess.run(
        [
            "bash",
            "-c",
            'python3() { printf "%s\\n" "$1"; }; '
            "MODULE_DIR=/module; ROOT=/build; DIR=nginx; "
            f"FLAVOR={flavor}; VERSION={version}; " + snippet,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.splitlines().count(
        "/module/ci/tools/legacy_http2_order.py"
    ) == expected


def test_runtime_control_inventory():
    rows = checker.cases()
    names = [name for name, _chunks, _expect in rows]
    assert len(names) == len(set(names))
    assert sum(name.startswith("permutation-") for name in names) == 24
    assert "late-path-x_bad" in names and "late-path-cookie" in names
    assert "late-path-host" in names and "ordered-host" in names
    assert "late-path-indexed" in names and "continuation-many" in names
    assert {"late-method", "late-scheme", "late-authority"} <= set(names)
    assert all(chunks and all(chunks) for _name, chunks, _expect in rows)


@pytest.mark.parametrize(
    "rst,goaway,eof,expect,want",
    [
        (1, None, False, "order", True),
        (1, None, True, "order", False),
        (None, None, False, "order", False),
        (2, None, False, "order", False),
        (1, 1, False, "order", False),
        (None, None, False, "ok", True),
        (None, None, True, "ok", False),
        (1, None, False, "ok", False),
    ],
)
def test_order_oracle_requires_open_stream_protocol_error(
    rst, goaway, eof, expect, want
):
    stream = checker.h2.Stream(status=200, body=b"ok\n", ended=True, rst=rst)
    connection = SimpleNamespace(
        goaway=goaway,
        eof=eof,
        wait=lambda _sid, _bound: stream,
        quiet=lambda _bound: None,
    )
    assert checker.observe(connection, 1, expect)["pass"] is want


def test_order_oracle_observes_delayed_connection_error():
    stream = checker.h2.Stream(ended=True, rst=1)
    connection = SimpleNamespace(
        goaway=None, eof=False, wait=lambda _sid, _bound: stream
    )

    def delayed_goaway(_bound):
        connection.goaway = 1

    connection.quiet = delayed_goaway
    assert checker.observe(connection, 1, "order")["pass"] is False


def test_order_oracle_observes_delayed_connection_close():
    stream = checker.h2.Stream(ended=True, rst=1)
    connection = SimpleNamespace(
        goaway=None, eof=False, wait=lambda _sid, _bound: stream
    )

    def delayed_eof(_bound):
        connection.eof = True

    connection.quiet = delayed_eof
    assert checker.observe(connection, 1, "order")["pass"] is False


def test_run_rejects_connectable_wrong_listener_without_owned_pid(runtime):
    process, listener, _results = runtime()

    with pytest.raises(RuntimeError, match="listener did not start"):
        checker.run(Path("nginx"), 18443)

    listener.assert_not_called()
    assert process.terminated


def test_run_accepts_owned_pid_and_listener(runtime):
    expected = [{"case": "positive", "pass": True}]
    process, listener, results = runtime(pid_text="4321\n", results=expected)

    assert checker.run(Path("nginx"), 18443) is results

    listener.assert_called_once_with(("127.0.0.1", 18443), 0.1)
    assert process.terminated


@pytest.mark.parametrize("pid_text", ["1234\n", "not-a-pid\n", "\n"])
def test_run_rejects_wrong_stale_or_malformed_pid(runtime, pid_text):
    process, listener, _results = runtime(pid_text=pid_text)

    with pytest.raises(RuntimeError, match="listener did not start"):
        checker.run(Path("nginx"), 18443)

    listener.assert_not_called()
    assert process.terminated


def test_run_rejects_selected_child_early_exit(runtime):
    process, listener, _results = runtime(polls=(23,))

    with pytest.raises(RuntimeError, match="exited before listener readiness"):
        checker.run(Path("nginx"), 18443)

    listener.assert_not_called()
    assert process.terminated


def test_run_rejects_selected_child_exit_after_protocol_checks(runtime):
    process, listener, _results = runtime(pid_text="4321\n", polls=(None, 23))

    with pytest.raises(RuntimeError, match="exited during protocol checks"):
        checker.run(Path("nginx"), 18443)

    listener.assert_called_once_with(("127.0.0.1", 18443), 0.1)
    assert process.terminated
