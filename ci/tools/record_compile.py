# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Record make's compiler argv without interception; merge after build success.

CT_COMPILE_COMMANDS_DIR is a fresh caller-owned directory. Separate fragments
avoid locks between parallel make jobs. ccache remains in the executed command,
but its launcher prefix is omitted from the database consumed by the scanners.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def record(argv: list[str]) -> int:
    """Execute the unchanged command, then record successful C compilations."""
    if not argv:
        raise ValueError("missing compiler command")
    directory = Path(os.environ["CT_COMPILE_COMMANDS_DIR"])
    if not directory.is_dir():
        raise ValueError("capture directory does not exist")
    result = subprocess.run(argv, check=False)
    if result.returncode:
        return result.returncode if result.returncode > 0 else 128 - result.returncode
    # This is the one launcher ci-build.sh adds. Keep compiler flags verbatim.
    arguments = argv[1:] if Path(argv[0]).name == "ccache" else argv
    if "-c" in arguments:
        for arg in arguments[1:]:
            source = Path(arg)
            if source.suffix == ".c" and source.is_file():
                entry = {
                    "directory": str(Path.cwd()),
                    "file": str(source.resolve()),
                    "arguments": arguments,
                }
                # The workflow EXIT trap owns fragment cleanup after merge.
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    suffix=".json",
                    dir=directory,
                    delete=False,
                    encoding="utf-8",
                ) as fragment:
                    json.dump(entry, fragment)
    return 0


def merge(directory: str, output: str) -> int:
    """Publish only a complete, nonempty set of successful compiler records."""
    entries = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(Path(directory).glob("*.json"))
    ]
    if not entries:
        raise ValueError("no C compile commands captured")
    entries.sort(key=lambda entry: (entry["file"], entry["arguments"]))
    Path(output).write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    return 0


def main() -> int:
    try:
        if sys.argv[1:2] == ["--merge"]:
            if len(sys.argv) != 4:
                raise ValueError("usage: record_compile.py --merge DIR OUTPUT")
            return merge(*sys.argv[2:])
        return record(sys.argv[1:])
    except (OSError, ValueError, KeyError) as error:
        print(f"compile capture: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
