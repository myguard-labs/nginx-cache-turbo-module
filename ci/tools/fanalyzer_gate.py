#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Replay all module compilations and compare selected GCC diagnostics exactly."""

import collections
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

OPTIONS = {
    "-Wanalyzer-use-after-free",
    "-Wanalyzer-double-free",
    "-Wanalyzer-null-dereference",
    "-Wanalyzer-deref-before-check",
}
DIAGNOSTIC = re.compile(r"^(.*?):(\d+):(\d+): warning: (.+) \[(-Wanalyzer-[\w-]+)\]$")


def key(option, path, line, column, message):
    return (option, path, line, column, message)


def baseline(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise TypeError("baseline must be a list")
    result = collections.Counter()
    for row in data:
        if not isinstance(row, dict) or set(row) != {
            "option",
            "path",
            "line",
            "column",
            "message",
            "count",
        }:
            raise ValueError("malformed baseline record")
        option, name, line, col, message, count = (
            row[k] for k in ("option", "path", "line", "column", "message", "count")
        )
        if (
            option not in OPTIONS
            or not isinstance(name, str)
            or not re.fullmatch(r"src/[^/]+\.c", name)
            or type(line) is not int
            or line < 1
            or type(col) is not int
            or col < 1
            or not isinstance(message, str)
            or not message
            or type(count) is not int
            or count < 1
        ):
            raise ValueError("invalid baseline record")
        item = key(option, name, line, col, message)
        if item in result:
            raise ValueError("duplicate baseline record")
        result[item] = count
    return result


def diagnostics(output, root, directory):
    result = collections.Counter()
    for line in output.splitlines():
        if not any(option in line for option in OPTIONS):
            continue
        match = DIAGNOSTIC.fullmatch(line)
        if not match or match.group(5) not in OPTIONS:
            raise ValueError(f"malformed selected diagnostic: {line}")
        name, lineno, col, message, option = match.groups()
        path = Path(name)
        path = (path if path.is_absolute() else directory / path).resolve()
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError as error:
            raise ValueError(f"diagnostic outside source root: {path}") from error
        if not re.fullmatch(r"src/[^/]+\.c", relative) or not path.is_file():
            raise ValueError(f"invalid diagnostic source: {relative}")
        if int(lineno) < 1 or int(col) < 1:
            raise ValueError("invalid diagnostic position")
        result[key(option, relative, int(lineno), int(col), message)] += 1
    return result


def run(root, db_path, baseline_path):
    root = root.resolve()
    allowed = baseline(baseline_path)
    sources = set((root / "src").glob("*.c"))
    if not sources:
        raise ValueError("no module sources")
    if any(root / item[1] not in sources for item in allowed):
        raise ValueError("baseline refers to a missing source")
    data = json.loads(db_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise TypeError("invalid compilation database")
    entries = {}
    for entry in data:
        directory = Path(entry["directory"])
        source = (directory / entry["file"]).resolve()
        if source in sources:
            if source in entries:
                raise ValueError(f"duplicate compilation entry: {source}")
            args = entry.get("arguments") or shlex.split(entry["command"])
            if (
                not isinstance(args, list)
                or not args
                or not all(isinstance(a, str) for a in args)
            ):
                raise ValueError("invalid compilation arguments")
            if not any((directory / arg).resolve() == source for arg in args[1:]):
                raise ValueError(f"compile arguments omit source: {source}")
            entries[source] = (directory, args)
    if set(entries) != sources:
        raise ValueError("compilation database does not cover all module sources")
    environment = dict(os.environ, LC_ALL="C")
    version = subprocess.run(
        ["gcc", "--version"],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    ).stdout.splitlines()[0]
    print(
        f"compiler: {version}\ncompile database sha256: {hashlib.sha256(db_path.read_bytes()).hexdigest()}",
        flush=True,
    )
    found = collections.Counter()
    with tempfile.TemporaryDirectory() as scratch:
        for source in sorted(sources):
            directory, args = entries[source]
            filtered = []
            skip = False
            for arg in args[1:]:
                if skip:
                    skip = False
                elif arg == "-o":
                    skip = True
                elif arg == "-Werror":
                    continue
                elif arg.startswith("-Werror="):
                    filtered.append("-W" + arg[len("-Werror=") :])
                elif arg != "-c":
                    filtered.append(arg)
            if skip or "-fsyntax-only" in filtered or "-w" in filtered:
                raise ValueError("invalid replay flags")
            object_path = Path(scratch) / "out.o"
            object_path.unlink(missing_ok=True)
            cmd = [
                "gcc",
                "-c",
                *filtered,
                "-fanalyzer",
                "-Wno-error",
                "-fdiagnostics-color=never",
                "-fdiagnostics-show-option",
                *sorted(OPTIONS),
                *("-Wno-error=" + option[2:] for option in sorted(OPTIONS)),
                "-o",
                str(object_path),
            ]
            proc = subprocess.run(
                cmd,
                cwd=directory,
                capture_output=True,
                text=True,
                check=False,
                env=environment,
            )
            print(f"--- {source.name} ---\n{proc.stdout}{proc.stderr}", flush=True)
            if proc.returncode:
                raise ValueError(
                    f"compiler replay failed for {source.name}: {proc.returncode}"
                )
            if not object_path.is_file():
                raise ValueError(f"compiler produced no object for {source.name}")
            found.update(diagnostics(proc.stdout + proc.stderr, root, directory))
    for item, count in sorted(found.items()):
        print(
            f"{'known' if count <= allowed[item] else 'new'}: {item} count={count} baseline={allowed[item]}"
        )
    if found - allowed:
        return 1
    print(f"analysis completed: {len(sources)} sources")
    return 0


def main():
    try:
        root = Path(sys.argv[1]).resolve()
        return run(root, Path(sys.argv[2]), Path(sys.argv[3]))
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        IndexError,
        subprocess.SubprocessError,
    ) as error:
        print(f"fanalyzer gate: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
