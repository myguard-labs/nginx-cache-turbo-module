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

Usage: check_baseline.py [--update]     Exit: 0 match, 1 drift, 2 cannot run.
"""

import collections
import json
import pathlib
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
BASELINE = HERE / "baseline.tsv"
HEADER = "# rule\tfile:line\tmatched text (tabs/newlines collapsed)\n"


def scan(repo=REPO, config=None, target="src"):
    """Return sorted [(rule, file, line, text)] for `target` under `repo`."""
    exe = shutil.which("ast-grep")
    if exe is None:
        raise RuntimeError("ast-grep not found on PATH")
    cfg = config or HERE / "sgconfig.yml"
    proc = subprocess.run(
        [exe, "scan", "-c", str(cfg), "--json=compact", target],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    # rc 0 = clean, 1 = an error-severity hit; these rules are warnings, so
    # anything else (or unparsable output) is "could not run", not a verdict.
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"ast-grep scan rc={proc.returncode}: {proc.stderr[-400:]}")
    try:
        hits = json.loads(proc.stdout or "[]")
    except ValueError as exc:
        raise RuntimeError(f"unparsable ast-grep output: {exc}") from exc
    out = []
    for h in hits:
        text = " ".join(h["text"].split())
        out.append((h["ruleId"], h["file"], h["range"]["start"]["line"] + 1, text))
    return sorted(out)


def load_baseline(path=BASELINE):
    entries = []
    for raw in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
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
    except RuntimeError as exc:
        print(f"check_baseline: cannot run: {exc}", file=sys.stderr)
        return 2
    if "--update" in argv:
        BASELINE.write_text(format_baseline(actual), encoding="utf-8")
        print(f"baseline updated: {len(actual)} hit(s)")
        return 0
    new, stale, moved = diff(load_baseline(), actual)
    lines = report(new, stale, moved)
    if lines:
        print("\n".join(lines), file=sys.stderr)
        return 1
    print(f"ast-grep-local baseline ok: {len(actual)} baselined hit(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
