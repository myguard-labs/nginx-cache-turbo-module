#!/usr/bin/env python3
"""Baseline gate for the project-owned ast-grep rules in ci/ast-grep-local/.

Runs `ast-grep scan` over src/ with ci/ast-grep-local/sgconfig.yml and compares
the hits with ci/ast-grep-local/baseline.tsv (rule, file:line, matched text).

Policy (strict, both directions):
  new     a hit with no baseline entry               -> fail
  stale   a baseline entry whose hit is gone         -> fail ("fixed, remove it")
  moved   same rule+file+text, different line number -> fail, reported as a move
          (refresh the baseline) rather than as a new+stale pair
HARD-B4 empties the baseline; until then any src/ edit that shifts a baselined
line must refresh it with `--update`, which keeps the diff reviewable.

Usage: check_baseline.py [--update]
  Exit: 0 match, 1 drift found by a complete scan, 2 cannot run (ast-grep
  failed or skipped a src/ C file or could not list a src/ directory, a
  malformed hit row, baseline unreadable/unparsable/unwritable/malformed;
  --update then leaves baseline.tsv untouched).
"""

import collections
import contextlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
BASELINE = HERE / "baseline.tsv"
HEADER = "# rule\tfile:line\tmatched text (tabs/newlines collapsed)\n"


SUMMARY_RE = re.compile(r"scannedFileCount=(\d+),skippedFileCount=(\d+)")
C_SUFFIXES = (".c", ".h")  # the extensions ast-grep maps to its C language


ENTITY_FILE_RE = re.compile(r"^sg: entity\|file\|(.+): language=", re.MULTILINE)


def _unscanned_c_files(repo, target, scanned):
    """Non-empty C files under target that ast-grep did not scan.

    `scanned` is the set of repo-relative paths from `--inspect entity`
    (0.44.1 and 0.51.0 list every scanned file there and omit skipped ones).
    A zero-byte file is legitimately skipped (no content, so no hits); a
    whitespace-only file is scanned, so it appears in `scanned` and never
    masks anything. Hidden files/dirs are not visited by ast-grep and are
    pruned like it does; a gitignored non-empty C file fails closed.
    """
    root = pathlib.Path(repo)
    missing = []

    def _fail(exc):
        raise RuntimeError(f"cannot list source directory: {exc}") from exc

    for dirpath, dirs, files in os.walk(root / target, onerror=_fail):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for name in files:
            if not name.endswith(C_SUFFIXES) or name.startswith("."):
                continue
            path = pathlib.Path(dirpath, name)
            rel = path.relative_to(root).as_posix()
            try:
                empty = path.stat().st_size == 0
            except OSError:
                empty = False
            if rel not in scanned and not empty:
                missing.append(rel)
    return sorted(missing)


def scan(repo=REPO, config=None, target="src"):
    """Return sorted [(rule, file, line, text)] for `target` under `repo`.

    Raises RuntimeError unless the scan provably covered every C file:
    ast-grep exits 0 for warning-severity hits (1 only for error severity,
    6/8 for a bad config/rule), prints a JSON array, and skips unreadable,
    non-UTF-8 or oversized files silently, so every non-empty C file under
    target must appear in the `--inspect entity` list of scanned files.
    """
    exe = shutil.which("ast-grep")
    if exe is None:
        raise RuntimeError("ast-grep not found on PATH")
    cfg = config or HERE / "sgconfig.yml"
    proc = subprocess.run(
        [exe, "scan", "-c", str(cfg), "--json=compact", "--inspect", "entity", target],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    # These rules are warnings: a successful scan exits 0 whatever it finds.
    if proc.returncode != 0:
        raise RuntimeError(f"ast-grep scan rc={proc.returncode}: {proc.stderr[-400:]}")
    try:
        hits = json.loads(proc.stdout)
    except ValueError as exc:
        raise RuntimeError(f"unparsable ast-grep output: {exc}") from exc
    if not isinstance(hits, list):
        raise RuntimeError("ast-grep output is not a JSON array")  # noqa: TRY004
    summary = SUMMARY_RE.search(proc.stderr)
    if summary is None:
        raise RuntimeError("ast-grep printed no scan summary; coverage unknown")
    scanned = set(ENTITY_FILE_RE.findall(proc.stderr))
    missing = _unscanned_c_files(repo, target, scanned)
    if missing:
        raise RuntimeError(
            f"ast-grep did not scan {len(missing)} non-empty C file(s) (unreadable, "
            f"non-UTF-8 or oversized): {', '.join(missing[:5])}"
        )
    return sorted(_hit_row(h) for h in hits)


def _hit_row(h):
    """(rule, file, line, text) from one ast-grep JSON hit; RuntimeError if malformed."""
    try:
        text, rule, file = h["text"], h["ruleId"], h["file"]
        line = h["range"]["start"]["line"]
    except (KeyError, TypeError) as exc:
        raise RuntimeError(f"malformed ast-grep hit {h!r}: missing {exc}") from exc
    if (
        not all(isinstance(v, str) for v in (text, rule, file))
        or not rule
        or not file
        or isinstance(line, bool)
        or not isinstance(line, int)
        or line < 0
    ):
        raise RuntimeError(f"malformed ast-grep hit: {h!r}")
    return (rule, file, line + 1, " ".join(text.split()))


def load_baseline(path=None):
    entries = []
    for raw in pathlib.Path(path or BASELINE).read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.startswith("#"):
            continue
        rule, loc, text = raw.split("\t", 2)
        file, sep, line = loc.rpartition(":")
        if not rule or not sep or not file or not line.isascii() or not line.isdigit():
            raise ValueError(f"malformed baseline location {loc!r}")
        if int(line) < 1:
            raise ValueError(f"baseline line must be positive: {loc!r}")
        entries.append((rule, file, int(line), text))
    return sorted(entries)


def format_baseline(entries):
    return HEADER + "".join(f"{r}\t{f}:{ln}\t{t}\n" for r, f, ln, t in sorted(entries))


def diff(baseline, actual):
    """Return (new, stale, moved); moved = [(base_entry, actual_entry)]."""
    base = collections.Counter(baseline)
    act = collections.Counter(actual)
    stale = list((base - act).elements())
    new = list((act - base).elements())
    moved = []
    for s in list(stale):
        for n in list(new):
            if s[:2] == n[:2] and s[3] == n[3]:
                moved.append((s, n))
                stale.remove(s)
                new.remove(n)
                break
    return new, stale, moved


def report(new, stale, moved):
    lines = []
    for r, f, ln, t in new:
        lines.append(f"NEW (unbaselined) {r} {f}:{ln}: {t}")
    for (r, f, old, t), (_, _, now, _) in moved:
        lines.append(f"MOVED {r} {f}: line {old} -> {now}: {t}  (run --update)")
    for r, f, ln, t in stale:
        lines.append(
            f"STALE (baselined hit gone) {r} {f}:{ln}: {t}  (fixed? run --update)"
        )
    return lines


def _write_atomic(path, text):
    """Write via a temp file in the same directory, then os.replace."""
    path = pathlib.Path(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def main(argv):
    try:
        actual = scan()
        if "--update" in argv:
            _write_atomic(BASELINE, format_baseline(actual))
            print(f"baseline updated: {len(actual)} hit(s)")
            return 0
        baseline = load_baseline()
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"check_baseline: cannot run: {exc}", file=sys.stderr)
        return 2
    new, stale, moved = diff(baseline, actual)
    lines = report(new, stale, moved)
    if lines:
        print("\n".join(lines), file=sys.stderr)
        return 1
    print(f"ast-grep-local baseline ok: {len(actual)} baselined hit(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
