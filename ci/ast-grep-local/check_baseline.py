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
  failed or skipped a src/ C file, baseline unreadable/unparsable/unwritable;
  --update then leaves baseline.tsv untouched).
"""

import collections
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
BASELINE = HERE / "baseline.tsv"
HEADER = "# rule\tfile:line\tmatched text (tabs/newlines collapsed)\n"


SUMMARY_RE = re.compile(r"scannedFileCount=(\d+),skippedFileCount=(\d+)")
C_SUFFIXES = (".c", ".h")  # the extensions ast-grep maps to its C language


def _is_blank(path):
    """True for a file ast-grep legitimately skips (no content, so no hits)."""
    try:
        return not path.read_bytes().strip()
    except OSError:
        return False


def _blank_c_files(root):
    return sum(
        1
        for dirpath, _dirs, files in os.walk(root)
        for name in files
        if name.endswith(C_SUFFIXES) and _is_blank(pathlib.Path(dirpath, name))
    )


def scan(repo=REPO, config=None, target="src"):
    """Return sorted [(rule, file, line, text)] for `target` under `repo`.

    Raises RuntimeError unless the scan provably covered every C file:
    ast-grep exits 0 for warning-severity hits (1 only for error severity,
    6/8 for a bad config/rule), prints a JSON array, and skips unreadable,
    non-UTF-8 or oversized files silently, so the summary's skippedFileCount
    must not exceed the number of blank files (which have no hits to miss).
    """
    exe = shutil.which("ast-grep")
    if exe is None:
        raise RuntimeError("ast-grep not found on PATH")
    cfg = config or HERE / "sgconfig.yml"
    proc = subprocess.run(
        [exe, "scan", "-c", str(cfg), "--json=compact", "--inspect", "summary", target],
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
    skipped = int(summary.group(2))
    blank = _blank_c_files(pathlib.Path(repo) / target)
    if skipped > blank:
        raise RuntimeError(
            f"ast-grep skipped {skipped} C file(s) but only {blank} are blank: "
            "an unreadable, non-UTF-8 or oversized file under "
            f"{target}/ was not scanned"
        )
    out = []
    for h in hits:
        text = " ".join(h["text"].split())
        out.append((h["ruleId"], h["file"], h["range"]["start"]["line"] + 1, text))
    return sorted(out)


def load_baseline(path=None):
    entries = []
    for raw in pathlib.Path(path or BASELINE).read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.startswith("#"):
            continue
        rule, loc, text = raw.split("\t", 2)
        file, _, line = loc.rpartition(":")
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


def main(argv):
    try:
        actual = scan()
        if "--update" in argv:
            BASELINE.write_text(format_baseline(actual), encoding="utf-8")
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
