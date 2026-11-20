#!/usr/bin/env python3
"""Apply only the exact nginx 1.22.1 HTTP/2 ordering correction for CI builds.

The stream owns a monotonic pseudo-only -> regular-seen bit. Completed regular
fields set it before ignored/special-field handling; subsequent pseudo-headers
terminate that stream with PROTOCOL_ERROR. CONTINUATION never resets the bit,
and new streams start zeroed by ngx_pcalloc. No new allocation or lock is needed.
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PATCH = Path(__file__).resolve().parents[1] / "patches/nginx-1.22.1-http2-order.patch"
SOURCES = {
    Path("src/http/v2/ngx_http_v2.c"): (
        "6f90665d6ebe08f26ede2d7984364192109d043be281e16dc3f51d7e7c506096",
        "6ba8c078ddcaf02e882c047ed989aef57a46e921da9b8fafdac6faebb9ea5732",
    ),
    Path("src/http/v2/ngx_http_v2.h"): (
        "e01c646e35078afba0bba884498842a231be7d35e3f98e202aedfa95f51772f0",
        "cd896adc59871bec1f34a70c4f2eaa465e754218bad314ffa56b72ec104f1412",
    ),
}


def apply(source_root: Path) -> str:
    """Admit both exact sources before patching; publish only validated files.

    Each replacement is atomic. An interrupted publication leaves a mixed pair
    which is rejected on the next build, rather than admitted as a cached result.
    """
    digests = []
    for name in SOURCES:
        target = source_root / name
        if target.is_symlink() or not target.is_file():
            raise ValueError("legacy HTTP/2 source must be a regular file")
        digests.append(hashlib.sha256(target.read_bytes()).hexdigest())
    if digests == [pins[1] for pins in SOURCES.values()]:
        return "already patched"
    if digests != [pins[0] for pins in SOURCES.values()]:
        raise ValueError(
            "legacy HTTP/2 source checksum mismatch; refusing source drift"
        )

    with tempfile.TemporaryDirectory(
        prefix=".legacy-http2-", dir=source_root
    ) as scratch_name:
        scratch = Path(scratch_name)
        for source in SOURCES:
            staged = scratch / source
            staged.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_root / source, staged)
        result = subprocess.run(
            [
                "patch",
                "--batch",
                "--fuzz=0",
                "--no-backup-if-mismatch",
                "--reject-file=-",
                "-p1",
                "--input",
                str(PATCH),
            ],
            cwd=scratch,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            raise ValueError(
                "legacy HTTP/2 patch failed: " + result.stdout + result.stderr
            )
        for source, pins in SOURCES.items():
            if hashlib.sha256((scratch / source).read_bytes()).hexdigest() != pins[1]:
                raise ValueError("legacy HTTP/2 patched checksum mismatch")
        for source in SOURCES:
            os.replace(scratch / source, source_root / source)
    return "applied"


def main() -> int:
    """Expose a failing build step for unknown or partially patched sources."""
    if len(sys.argv) != 2:
        print("usage: legacy_http2_order.py SOURCE_ROOT", file=sys.stderr)
        return 2
    try:
        verdict = apply(Path(sys.argv[1]))
    except (OSError, ValueError) as exc:
        print(f"legacy HTTP/2 compatibility patch: {exc}", file=sys.stderr)
        return 1
    print(f"legacy HTTP/2 compatibility patch: {verdict}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
