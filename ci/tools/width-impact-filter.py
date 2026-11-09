#!/usr/bin/env python3
"""Report whether the 32-bit unit subset must run for a PR."""
import subprocess
import sys


def main():
    if len(sys.argv) != 2 or not sys.argv[1]:
        print("true")
        return
    result = subprocess.run(
        ["git", "diff", "--name-only", "-z", "--no-renames", sys.argv[1] + "...HEAD", "--"],
        stdout=subprocess.PIPE,
        check=True,
    )
    paths = result.stdout.split(b"\0")
    prefixes = (b"src/", b"ci/", b".github/workflows/")
    print(str(any(path.startswith(prefixes) for path in paths)).lower())


if __name__ == "__main__":
    main()
