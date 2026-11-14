#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Mandatory sizeof-pointer decisions using libclang's canonical C types.

ast-grep supplies byte locations, including unparenthesized sizeof. libclang
resolves declarations, typedefs, arrays and lexical scope in configured nginx
translation units. A parse error or an uncovered location is uncertainty (2),
never a safe-copy verdict. No source rewriting or guessed nginx typedefs.

Uses the stable clang-c API shipped alongside clang; no Python bindings needed.
NGX_SRC_TREE follows the carve-init gate: configured tree, .build auto-discovery,
or explicit '-' for self-contained test inputs. Headers use real includers.
"""

from __future__ import annotations

import ctypes as ct
import ctypes.util
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

RULE = "c-memcpy-sizeof-pointer"
CANDIDATES = """id: sizeof-pointer-candidate
language: c
severity: warning
rule:
  any:
    - pattern: $FN($DST, $SRC, sizeof($VALUE))
    - pattern: $FN($DST, $SRC, sizeof $VALUE)
constraints:
  FN:
    regex: ^(memcpy|memmove|ngx_memcpy)$
  VALUE:
    kind: identifier
"""


class Uncertain(Exception):
    """The mandatory check cannot establish a semantic verdict."""


class CXString(ct.Structure):
    _fields_ = [("data", ct.c_void_p), ("flags", ct.c_uint)]


class CXCursor(ct.Structure):
    _fields_ = [("kind", ct.c_uint), ("xdata", ct.c_int), ("data", ct.c_void_p * 3)]


class CXType(ct.Structure):
    _fields_ = [("kind", ct.c_uint), ("data", ct.c_void_p * 2)]


class CXLocation(ct.Structure):
    _fields_ = [("data", ct.c_void_p * 2), ("offset", ct.c_uint)]


class Clang:
    """Only the public clang-c calls needed to query one expression's type."""

    def __init__(self, compiler):
        probe = subprocess.run(
            [compiler, "-print-file-name=libclang.so.1"],
            capture_output=True, text=True, check=True,
        )
        library = probe.stdout.strip()
        if not Path(library).is_file():
            # Runtime packages can expose only a versioned SONAME, with no
            # development symlink in clang's library search path.
            version = subprocess.run(
                [compiler, "-dumpversion"], capture_output=True, text=True, check=True,
            ).stdout.strip().split(".")[0]
            if not version.isdecimal():
                raise Uncertain(f"{compiler}: cannot determine libclang major version")
            library = ctypes.util.find_library(f"clang-{version}")
        if not library:
            raise Uncertain(f"{compiler}: libclang missing; install matching libclang runtime")
        self.lib = ct.CDLL(library)
        signatures = {
            "createIndex": (ct.c_void_p, [ct.c_int, ct.c_int]),
            "disposeIndex": (None, [ct.c_void_p]),
            "parseTranslationUnit": (ct.c_void_p, [ct.c_void_p, ct.c_char_p,
                ct.POINTER(ct.c_char_p), ct.c_int, ct.c_void_p, ct.c_uint, ct.c_uint]),
            "disposeTranslationUnit": (None, [ct.c_void_p]),
            "getNumDiagnostics": (ct.c_uint, [ct.c_void_p]),
            "getDiagnostic": (ct.c_void_p, [ct.c_void_p, ct.c_uint]),
            "getDiagnosticSeverity": (ct.c_uint, [ct.c_void_p]),
            "getDiagnosticSpelling": (CXString, [ct.c_void_p]),
            "disposeDiagnostic": (None, [ct.c_void_p]),
            "getCString": (ct.c_char_p, [CXString]),
            "disposeString": (None, [CXString]),
            "getFile": (ct.c_void_p, [ct.c_void_p, ct.c_char_p]),
            "getLocationForOffset": (CXLocation, [ct.c_void_p, ct.c_void_p, ct.c_uint]),
            "getCursor": (CXCursor, [ct.c_void_p, CXLocation]),
            "getCursorType": (CXType, [CXCursor]),
            "getCanonicalType": (CXType, [CXType]),
            "getCursorReferenced": (CXCursor, [CXCursor]),
            "getCursorSemanticParent": (CXCursor, [CXCursor]),
            "Cursor_getNumArguments": (ct.c_int, [CXCursor]),
            "Cursor_getArgument": (CXCursor, [CXCursor, ct.c_uint]),
            "equalCursors": (ct.c_uint, [CXCursor, CXCursor]),
            "getArgType": (CXType, [CXType, ct.c_uint]),
        }
        for name, (result, args) in signatures.items():
            fn = getattr(self.lib, f"clang_{name}")
            fn.restype, fn.argtypes = result, args
        self.index = self.lib.clang_createIndex(0, 0)
        if not self.index:
            raise Uncertain("libclang could not create an index")

    def close(self):
        self.lib.clang_disposeIndex(self.index)

    def inspect(self, source, args, candidates):
        """Return candidate-index/type-kind pairs and relevant parse errors."""
        encoded = [os.fsencode(a) for a in args]
        argv = (ct.c_char_p * len(encoded))(*encoded)
        tu = self.lib.clang_parseTranslationUnit(
            self.index, os.fsencode(source), argv, len(encoded), None, 0, 0,
        )
        if not tu:
            raise Uncertain(f"libclang could not parse {source}")
        try:
            relevant = []
            for i, candidate in enumerate(candidates):
                file = self.lib.clang_getFile(tu, os.fsencode(candidate["path"]))
                if file:
                    relevant.append((i, candidate, file))
            if not relevant:
                return {}, []
            errors = []
            for i in range(self.lib.clang_getNumDiagnostics(tu)):
                diagnostic = self.lib.clang_getDiagnostic(tu, i)
                try:
                    if self.lib.clang_getDiagnosticSeverity(diagnostic) >= 3:
                        spelling = self.lib.clang_getDiagnosticSpelling(diagnostic)
                        try:
                            errors.append(self.lib.clang_getCString(spelling).decode())
                        finally:
                            self.lib.clang_disposeString(spelling)
                finally:
                    self.lib.clang_disposeDiagnostic(diagnostic)
            if errors:
                return {}, [f"{source}: {e}" for e in errors]
            kinds = {}
            for i, candidate, file in relevant:
                location = self.lib.clang_getLocationForOffset(tu, file, candidate["offset"])
                cursor = self.lib.clang_getCursor(tu, location)
                # CXCursor_DeclRefExpr: a sizeof identifier must resolve to the
                # expression itself, not a containing call or macro expansion.
                if cursor.kind != 101:
                    continue
                type_ = self.lib.clang_getCursorType(cursor)
                declaration = self.lib.clang_getCursorReferenced(cursor)
                if declaration.kind == 10:  # CXCursor_ParmDecl
                    # libclang preserves an array parameter's written array
                    # type on its DeclRefExpr. The function type carries C's
                    # adjusted pointer type, which is what sizeof measures.
                    parent = self.lib.clang_getCursorSemanticParent(declaration)
                    for position in range(self.lib.clang_Cursor_getNumArguments(parent)):
                        parameter = self.lib.clang_Cursor_getArgument(parent, position)
                        if self.lib.clang_equalCursors(parameter, declaration):
                            type_ = self.lib.clang_getArgType(
                                self.lib.clang_getCanonicalType(
                                    self.lib.clang_getCursorType(parent)
                                ), position,
                            )
                            break
                    else:
                        continue
                kind = self.lib.clang_getCanonicalType(type_).kind
                # Invalid/unexposed types cannot establish scalar safety.
                if kind not in (0, 1):
                    kinds[i] = kind
            return kinds, []
        finally:
            self.lib.clang_disposeTranslationUnit(tu)


def include_args():
    """Read the configured include set, as the module's carve-init gate does."""
    configured = os.environ.get("NGX_SRC_TREE")
    if configured == "-":
        return []
    trees = [Path(configured)] if configured else list(Path(".build").glob("nginx-*/"))
    usable = [t for t in trees if (t / "objs/Makefile").is_file()
              and (t / "src/core/ngx_config.h").is_file()]
    if not usable:
        raise Uncertain("no configured nginx tree; set NGX_SRC_TREE (as for carve-init)")
    tree = max(usable, key=lambda t: (t / "objs/Makefile").stat().st_mtime).resolve()
    makefile = (tree / "objs/Makefile").read_text()
    match = re.search(r"^ALL_INCS =((?:[^\n]*\\\n)*[^\n]*)", makefile, re.M)
    if not match:
        raise Uncertain(f"{tree}: ALL_INCS missing")
    words = shlex.split(match[1].replace("\\\n", " "))
    args = []
    i = 0
    while i < len(words):
        word = words[i]
        if word == "-I" and i + 1 < len(words):
            i += 1
            args.extend(["-I", str((tree / words[i]).resolve())])
        elif word.startswith("-I") and len(word) > 2:
            args.extend(["-I", str((tree / word[2:]).resolve())])
        else:
            raise Uncertain(f"{tree}: unsupported ALL_INCS entry {word!r}")
        i += 1
    if not args:
        raise Uncertain(f"{tree}: ALL_INCS empty")
    return [*args, "-I", str(Path("src").resolve())]


def candidates_for(files):
    scan = subprocess.run(
        ["ast-grep", "scan", "--inline-rules", CANDIDATES, "--json=compact", *files],
        capture_output=True, text=True, check=False,
    )
    if scan.returncode != 0:
        raise Uncertain(f"candidate scan failed ({scan.returncode}): {scan.stderr.strip()}")
    result = []
    for hit in json.loads(scan.stdout):
        operand = hit["metaVariables"]["single"]["VALUE"]
        result.append({"path": Path(hit["file"]).resolve(),
                       "offset": operand["range"]["byteOffset"]["start"],
                       "line": operand["range"]["start"]["line"] + 1,
                       "name": operand["text"]})
    return result


def check(files):
    candidates = candidates_for(files)
    if not candidates:
        print(f"{RULE}: no sizeof-identifier copy lengths")
        return 0
    args = include_args()
    # Headers are never guessed into standalone TUs. Examine actual module
    # includers, including when a commit changes only a header. A header without
    # a usable includer leaves its candidates unresolved and fails closed.
    sources = {Path(f).resolve() for f in files if Path(f).suffix == ".c"}
    if any(Path(f).suffix == ".h" for f in files):
        sources.update(p.resolve() for p in Path("src").glob("*.c"))
    clang = Clang(os.environ.get("SIZEOF_POINTER_CLANG", "clang"))
    resolved, pointers, errors = set(), set(), []
    try:
        for source in sorted(sources):
            for config in ([], ["-DNGX_HTTP_CACHE_TURBO_TEST_FAULTS=1"]):
                kinds, parse_errors = clang.inspect(str(source), [*args, *config], candidates)
                errors.extend(parse_errors)
                resolved.update(kinds)
                # CXType_Pointer / CXType_BlockPointer, canonicalized by clang.
                pointers.update(i for i, kind in kinds.items() if kind in (101, 102))
    finally:
        clang.close()
    for i in sorted(pointers):
        c = candidates[i]
        print(f"{c['path']}:{c['line']}: error[{RULE}]: sizeof({c['name']}) is pointer width")
    missing = set(range(len(candidates))) - resolved
    if errors or missing:
        for error in errors[:5]:
            print(f"{RULE}: uncertainty: {error}", file=sys.stderr)
        for i in sorted(missing):
            c = candidates[i]
            print(f"{c['path']}:{c['line']}: {RULE}: uncertainty: type of {c['name']} unresolved",
                  file=sys.stderr)
        return 2
    print(f"{RULE}: {len(candidates)} length operand(s) resolved using canonical C types")
    return int(bool(pointers))


def main(argv):
    if not argv:
        print(f"{RULE}: uncertainty: no input files", file=sys.stderr)
        return 2
    try:
        return check(argv)
    except (Uncertain, OSError, ValueError, KeyError, TypeError,
            AttributeError, subprocess.SubprocessError) as error:
        print(f"{RULE}: uncertainty: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
