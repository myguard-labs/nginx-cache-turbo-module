#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Gate: no new conversion/shadow/VLA/fallthrough/cast-qual warnings in parser files.

  warning_baseline_gate.py <root> <compile_commands.json> <baseline.json>
  warning_baseline_gate.py --update <root> <compile_commands.json> <baseline.json>

Each parser file is recompiled with the argv recorded for the real module build
(ci/tools/record_compile.py), under every compiler in COMPILERS, with
-Wconversion -Wsign-conversion -Wshadow -Wvla -Wimplicit-fallthrough
-Wcast-qual added. Diagnostics located in src/ are counted per
(compiler, translation unit, diagnostic file, option, message). Line and
column numbers are NOT part of the key, so unrelated edits that only move a
known warning do not churn the baseline.

A key whose count rises, or a key that is not in the baseline, FAILS (exit 1)
and is printed as "new: <compiler> <file> <option>: <message>". A key whose
count drops passes and prints "fixed:"; lower the baseline with --update.
Exit 2 is a broken replay (compile error, missing compiler, missing database
entry, or a compiler major version that differs from the baseline's: warning
sets are version specific, so regenerate on the CI image).

Known limit: counting is per message text, so fixing one warning and adding a
different-site warning with an identical message in the same file nets to zero.
"""

import collections
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

FILES = tuple(
    f"src/ngx_http_cache_turbo_{name}.c"
    for name in (
        "redis",
        "memcached",
        "blob",
        "match",
        "vary",
        "purge",
        "admin",
        "filters",
    )
)
COMPILERS = ("gcc", "clang")
WARNING_FLAGS = (
    "-Wconversion",
    "-Wsign-conversion",
    "-Wshadow",
    "-Wvla",
    "-Wimplicit-fallthrough",
    "-Wcast-qual",
)
DIAGNOSTIC = re.compile(
    r"^(?P<path>[^\s:][^:]*):(?P<line>\d+):(?P<col>\d+): warning: "
    r"(?P<msg>.*?)(?: \[(?P<opt>-W[\w+=-]+)\])?$"
)
ERROR = re.compile(r":\d+:\d+: (?:fatal )?error: ")
VERSION = re.compile(r"(\d+)\.\d+(?:\.\d+)?")
ENTRY_KEYS = {"compiler", "file", "source", "option", "message", "count"}


def compiler_version(name, env):
    first = subprocess.run(
        [name, "--version"], check=True, capture_output=True, text=True, env=env
    ).stdout.splitlines()[0]
    match = VERSION.search(first)
    if not match:
        raise ValueError(f"cannot parse {name} version: {first}")
    return first, int(match.group(1))


def replay_args(args, compiler):
    """Recorded argv minus compiler, -c, -o, -Werror*; plus the warning set."""
    out = []
    skip = False
    for arg in args[1:]:
        if skip:
            skip = False
        elif arg == "-o":
            skip = True
        elif arg == "-c" or arg == "-Werror" or arg.startswith("-Werror="):
            continue
        else:
            out.append(arg)
    if skip or "-fsyntax-only" in out or "-w" in out:
        raise ValueError("invalid replay flags")
    extra = ["-Wno-unknown-warning-option", "-Wno-unused-command-line-argument"]
    return [
        compiler,
        "-c",
        *out,
        *WARNING_FLAGS,
        "-Wno-error",
        "-fdiagnostics-color=never",
        "-fdiagnostics-show-option",
        *(extra if compiler == "clang" else []),
    ]


def load_entries(root, db_path):
    data = json.loads(db_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise TypeError("invalid compilation database")
    wanted = {(root / name).resolve(): name for name in FILES}
    missing = [name for name in FILES if not (root / name).is_file()]
    if missing:
        raise ValueError(f"parser file missing: {missing[0]}")
    entries = {}
    for entry in data:
        directory = Path(entry["directory"])
        source = (directory / entry["file"]).resolve()
        if source not in wanted:
            continue
        args = entry.get("arguments") or shlex.split(entry["command"])
        if not args or not all(isinstance(a, str) for a in args):
            raise ValueError("invalid compilation arguments")
        if wanted[source] in entries:
            raise ValueError(f"duplicate compilation entry: {wanted[source]}")
        entries[wanted[source]] = (directory, args)
    absent = [name for name in FILES if name not in entries]
    if absent:
        raise ValueError(f"no compilation database entry for {absent[0]}")
    return entries


def parse(output, root, directory, compiler, tu):
    found = collections.Counter()
    for line in output.splitlines():
        match = DIAGNOSTIC.match(line)
        if not match:
            continue
        path = Path(match.group("path"))
        path = (path if path.is_absolute() else directory / path).resolve()
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            continue  # nginx core header: not ours to baseline
        if not re.fullmatch(r"src/[^/]+\.(?:c|h)", relative):
            continue
        found[
            (compiler, tu, relative, match.group("opt") or "none", match.group("msg"))
        ] += 1
    return found


def collect(root, entries, env):
    found = collections.Counter()
    versions = {}
    for compiler in COMPILERS:
        try:
            versions[compiler] = compiler_version(compiler, env)
        except (OSError, subprocess.CalledProcessError) as error:
            raise ValueError(f"{compiler} unavailable: {error}") from error
    with tempfile.TemporaryDirectory() as scratch:
        for compiler in COMPILERS:
            for tu in FILES:
                directory, args = entries[tu]
                obj = Path(scratch) / "out.o"
                obj.unlink(missing_ok=True)
                proc = subprocess.run(
                    [*replay_args(args, compiler), "-o", str(obj)],
                    cwd=directory,
                    capture_output=True,
                    text=True,
                    check=False,
                    env=env,
                )
                text = proc.stdout + proc.stderr
                if proc.returncode or ERROR.search(text) or not obj.is_file():
                    raise ValueError(
                        f"{compiler} replay failed for {tu} "
                        f"(rc={proc.returncode}):\n{text[-2000:]}"
                    )
                found.update(parse(text, root, directory, compiler, tu))
    return found, versions


def write_baseline(path, found, versions):
    per_file = {compiler: {tu: 0 for tu in FILES} for compiler in COMPILERS}
    for (compiler, tu, _src, _opt, _msg), count in found.items():
        per_file[compiler][tu] += count
    doc = {
        "compilers": {
            c: {"version": versions[c][0], "major": versions[c][1]} for c in COMPILERS
        },
        "per_file_counts": per_file,
        "entries": [
            {
                "compiler": c,
                "file": tu,
                "source": src,
                "option": opt,
                "message": msg,
                "count": count,
            }
            for (c, tu, src, opt, msg), count in sorted(found.items())
        ],
    }
    path.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")


def read_baseline(path):
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or set(doc) != {
        "compilers",
        "per_file_counts",
        "entries",
    }:
        raise ValueError("malformed baseline")
    allowed = collections.Counter()
    totals = {c: {tu: 0 for tu in FILES} for c in COMPILERS}
    for row in doc["entries"]:
        if not isinstance(row, dict) or set(row) != ENTRY_KEYS:
            raise ValueError("malformed baseline record")
        if (
            row["compiler"] not in COMPILERS
            or row["file"] not in FILES
            or not isinstance(row["source"], str)
            or not isinstance(row["option"], str)
            or not isinstance(row["message"], str)
            or type(row["count"]) is not int
            or row["count"] < 1
        ):
            raise ValueError("invalid baseline record")
        item = (
            row["compiler"],
            row["file"],
            row["source"],
            row["option"],
            row["message"],
        )
        if item in allowed:
            raise ValueError("duplicate baseline record")
        allowed[item] = row["count"]
        totals[row["compiler"]][row["file"]] += row["count"]
    if doc["per_file_counts"] != totals:
        raise ValueError("per_file_counts disagrees with entries")
    return doc["compilers"], allowed


def run(root, db_path, baseline_path, update=False):
    root = root.resolve()
    env = dict(os.environ, LC_ALL="C")
    entries = load_entries(root, db_path)
    found, versions = collect(root, entries, env)
    for compiler in COMPILERS:
        print(f"compiler: {versions[compiler][0]}", flush=True)
    if update:
        write_baseline(baseline_path, found, versions)
        print(f"baseline written: {sum(found.values())} warnings")
        return 0
    recorded, allowed = read_baseline(baseline_path)
    for compiler in COMPILERS:
        if recorded.get(compiler, {}).get("major") != versions[compiler][1]:
            raise ValueError(
                f"{compiler} major {versions[compiler][1]} differs from baseline "
                f"{recorded.get(compiler)}: regenerate with --update on the CI image"
            )
    status = 0
    for item in sorted(found.keys() | allowed.keys()):
        count, base = found[item], allowed[item]
        compiler, tu, src, opt, msg = item
        where = tu if src == tu else f"{tu} (via {src})"
        if count > base:
            status = 1
            print(f"new: {compiler} {where} {opt}: {msg} count={count} baseline={base}")
        elif count < base:
            print(
                f"fixed: {compiler} {where} {opt}: {msg} count={count} "
                f"baseline={base} (lower the baseline with --update)"
            )
    total = sum(found.values())
    print(
        f"{'FAIL' if status else 'ok'}: {total} warnings "
        f"(baseline {sum(allowed.values())}) over {len(FILES)} files x "
        f"{len(COMPILERS)} compilers"
    )
    return status


def main(argv):
    update = argv[:1] == ["--update"]
    args = argv[1:] if update else argv
    if len(args) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        return run(Path(args[0]), Path(args[1]), Path(args[2]), update)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        IndexError,
        subprocess.SubprocessError,
    ) as error:
        print(f"warning baseline gate: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
