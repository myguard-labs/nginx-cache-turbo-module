#!/usr/bin/env python3
"""Apply the pinned peer-error compatibility patch to a legacy CI source tree.

nginx 1.22.1 predates two OpenSSL peer record errors. Keep their classification
consistent with other malformed peer records, without changing any TLS I/O.
Only ci-build.sh's exact nginx/1.22.1 branch invokes this helper.
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SOURCE = Path("src/event/ngx_event_openssl.c")
PATCH = Path(__file__).resolve().parents[1] / "patches/nginx-1.22.1-peer-tls-errors.patch"
PRISTINE_SHA256 = "5d3b88f7e2b93692878847c2737b5cfe4fa65c56e2b73ab180d563400649c6ca"
PATCHED_SHA256 = "cb2e1352d057c54cadbb6303da1f6098251c7d5beb0d1c710fbdf3efd2ddb781"


def apply(source_root: Path) -> str:
    """Recognize the exact cached result or atomically patch pristine source."""
    target = source_root / SOURCE
    if target.is_symlink() or not target.is_file():
        raise ValueError("legacy TLS source must be a regular file")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    if digest == PATCHED_SHA256:
        return "already patched"
    if digest != PRISTINE_SHA256:
        raise ValueError("legacy TLS source checksum mismatch; refusing source drift")

    # Patch only a private copy: a bad patch must never leave a partial source.
    with tempfile.TemporaryDirectory(prefix=".legacy-tls-", dir=source_root) as name:
        scratch = Path(name)
        staged = scratch / SOURCE
        staged.parent.mkdir(parents=True)
        shutil.copy2(target, staged)
        result = subprocess.run(
            ["patch", "--batch", "--fuzz=0", "--no-backup-if-mismatch",
             "--reject-file=-", "-p1", "--input", str(PATCH)],
            cwd=scratch, capture_output=True, text=True, check=False,
        )
        if result.returncode:
            raise ValueError("legacy TLS patch failed: " + result.stdout + result.stderr)
        if hashlib.sha256(staged.read_bytes()).hexdigest() != PATCHED_SHA256:
            raise ValueError("legacy TLS patched checksum mismatch")
        os.replace(staged, target)
    return "applied"


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: legacy_tls_errors.py SOURCE_ROOT", file=sys.stderr)
        return 2
    try:
        verdict = apply(Path(sys.argv[1]))
    except (OSError, ValueError) as exc:
        print(f"legacy TLS compatibility patch: {exc}", file=sys.stderr)
        return 1
    print(f"legacy TLS compatibility patch: {verdict}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
