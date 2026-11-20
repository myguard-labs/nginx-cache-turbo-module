"""Legacy build admission is exact, atomic, idempotent, and version limited."""

import hashlib
import importlib.util
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "legacy_tls_errors", ROOT / "ci/tools/legacy_tls_errors.py")
assert SPEC is not None and SPEC.loader is not None
legacy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(legacy)


@pytest.fixture(name="tree")
def source_tree(tmp_path, monkeypatch):
    # The helper's admission logic uses small independent source identities;
    # ci-build also tests the actual classifier from the pinned nginx source.
    old, new = b"before\nold\nafter\n", b"before\nnew\nafter\n"
    target = tmp_path / legacy.SOURCE
    target.parent.mkdir(parents=True)
    target.write_bytes(old)
    target.chmod(0o640)
    patch = tmp_path / "change.patch"
    patch.write_text("--- a/src/event/ngx_event_openssl.c\n"
                     "+++ b/src/event/ngx_event_openssl.c\n"
                     "@@ -1,3 +1,3 @@\n before\n-old\n+new\n after\n")
    monkeypatch.setattr(legacy, "PATCH", patch)
    monkeypatch.setattr(legacy, "PRISTINE_SHA256", hashlib.sha256(old).hexdigest())
    monkeypatch.setattr(legacy, "PATCHED_SHA256", hashlib.sha256(new).hexdigest())
    return tmp_path, target, old, new, patch


def test_apply_and_idempotent_cache(tree):
    root, target, _old, new, _patch = tree
    assert legacy.apply(root) == "applied"
    assert target.read_bytes() == new
    assert target.stat().st_mode & 0o777 == 0o640
    stamp = target.stat().st_mtime_ns
    assert legacy.apply(root) == "already patched"
    assert target.stat().st_mtime_ns == stamp
    assert not list(root.glob(".legacy-tls-*"))


@pytest.mark.parametrize("content", [b"", b"before\nold\nafter", b"drift\n"])
def test_reject_source_drift_without_writes(tree, content):
    root, target, _old, _new, _patch = tree
    target.write_bytes(content)
    with pytest.raises(ValueError, match="source checksum mismatch"):
        legacy.apply(root)
    assert target.read_bytes() == content


@pytest.mark.parametrize("content", [
    "not a patch\n", "--- a/missing\n+++ b/missing\n@@ -1 +1 @@\n-x\n+y\n",
])
def test_bad_patch_never_changes_source(tree, content):
    root, target, old, _new, patch = tree
    patch.write_text(content)
    with pytest.raises(ValueError, match="patch failed"):
        legacy.apply(root)
    assert target.read_bytes() == old
    assert not list(root.glob(".legacy-tls-*"))


def test_wrong_patch_result_never_published(tree):
    root, target, old, _new, patch = tree
    patch.write_text(patch.read_text().replace("+new\n", "+other\n"))
    with pytest.raises(ValueError, match="patched checksum mismatch"):
        legacy.apply(root)
    assert target.read_bytes() == old


def test_reject_missing_source(tree):
    root, target, _old, _new, _patch = tree
    target.unlink()
    with pytest.raises(ValueError, match="regular file"):
        legacy.apply(root)


def test_reject_symlink_source(tree):
    root, target, old, _new, _patch = tree
    outside = root / "outside"
    outside.write_bytes(old)
    target.unlink()
    target.symlink_to(outside)
    with pytest.raises(ValueError, match="regular file"):
        legacy.apply(root)
    assert outside.read_bytes() == old


def test_missing_patch_tool_does_not_change_source(tree, monkeypatch):
    root, target, old, _new, _patch = tree
    monkeypatch.setenv("PATH", "")
    with pytest.raises(FileNotFoundError):
        legacy.apply(root)
    assert target.read_bytes() == old


@pytest.mark.parametrize("flavor,version,expected", [
    ("nginx", "1.22.1", 2), ("nginx", "1.31.3", 0),
    ("nginx", "1.30.4", 0), ("angie", "1.22.1", 0),
])
def test_build_invocation_is_version_and_flavor_limited(flavor, version, expected):
    text = (ROOT / "ci/tools/ci-build.sh").read_text()
    start = text.index('if [ "$FLAVOR" = nginx ] && [ "$VERSION" = 1.22.1 ]; then')
    snippet = text[start:text.index("\nfi", start) + 3]
    result = subprocess.run(
        ["bash", "-c", 'python3() { printf "%s\\n" "$1"; }; '
         'MODULE_DIR=/module; ROOT=/build; DIR=nginx; '
         f"FLAVOR={flavor}; VERSION={version}; " + snippet],
        capture_output=True, text=True, check=True,
    )
    tls_calls = [line for line in result.stdout.splitlines()
                 if "legacy_tls_errors.py" in line]
    assert tls_calls == [
        "/module/ci/tools/legacy_tls_errors.py",
        "/module/ci/tools/check_legacy_tls_errors.py",
    ][:expected]
