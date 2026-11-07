#!/usr/bin/env python3
"""Fail CI if a test_*() in ci/tools/test_runtime.py is defined but never
invoked from run_all() (CI-REG1).

test_l2_forged_blob_cannot_inject_headers shipped in PR #178 defined at
test_runtime.py:13517 with no call site: run_all() never invoked it, so the
security gate it was written to prove had never executed in CI. This is the
SECOND time this file has shipped tests that are defined, collected (by
py_compile / import) and executed zero times while the suite still exits 0
(first occurrence: five tests, 2026-07-26). Prose guidance in the CI skill did
not stop the repeat, so this check is mechanical: parse the file with `ast`
(not regex -- a regex call-site scanner misses attribute calls, conditional
calls, calls split across lines, etc. and produces a false green, which is
worse than not having the lint) and diff "defined" against "reachable from
run_all()".

Reachability is NOT just run_all()'s own body: if run_all ever grows a call
to a helper function that itself calls test_*() (a "run_group"-style
wrapper), those calls must count too, or a refactor that introduces such a
helper silently blinds this lint back to zero. So this walks run_all()'s
body for calls to test_* names directly, AND recursively follows any
non-test_* function call made from within run_all() (or from an
already-followed helper) into that function's body, collecting further
test_* calls found there. As of 2026-08-01 run_all() has no such helper --
every test_*() call is direct -- but the lint does not assume that stays true.

The suite is being split per test area (MAINT-T1), so "the file" is now a
package: the ci/tools/test_runtime.py facade plus every ci/tools/areas/*.py.
This lint therefore parses ALL of them into ONE symbol table before resolving
reachability -- a single-file parse would see a facade holding run_all() and
almost no test_* definitions and report a triumphant "OK" over a suite it can
no longer see. That is the exact false green the paragraph above calls worse
than not having the lint, so the file set is discovered, counted and REPORTED
on every run: if the areas package is expected and missing, this fails loudly
instead of quietly measuring less.

Note the reachability BFS still resolves only bare-Name calls (test_foo(ng)),
not attribute calls (areas.l2.test_foo(ng)). That is deliberate and matches
the facade design: the facade star-imports each area module, so every test is
a bare name in run_all()'s scope. A future refactor to namespaced calls would
have to teach called_names() about ast.Attribute FIRST -- until then such a
call is unreachable here and the test reports as an orphan, which is the safe
direction to fail.

Second check (BP-D1, abort-arm coverage): every site in ci/park-sites.tsv
must have an arm for each of the five abort shapes (ABORT_SHAPES). The mapping
is mechanical, see park_arm_matrix(). A (site, shape) pair with no arm must be
listed in ci/park-arms-missing.tsv; the baseline can only shrink -- a listed
pair whose arm now exists, or whose site is gone, fails as stale.

Third check (CT-HOOK-AREA-FAULT-ONLY-TESTS): delegated to lint-fault-gate.py,
which fails when a pre-commit @area map entry would run a test that run_all()
calls only under `if ng.fault_injection:` without the selector's capability
gate. Skipped (with a note) when the facade's repo has no precommit map.

Usage: ci/tools/lint-orphan-tests.py [path-to-test_runtime.py]
Exit 0 + "OK" line on a clean run, exit 1 naming every orphaned test on a
regression.
"""
from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

# Explicit opt-out list for tests that are deliberately never called from
# run_all() -- e.g. a manual/exploratory harness kept in-tree for a human to
# invoke directly. Each entry needs a comment saying WHY it's here. Do not
# add a test to this list just to make the lint pass; an orphan found that
# isn't already explained here is a real regression -- report it, don't
# silence it.
ALLOWED_ORPHANS: set[str] = set((
    # (none as of 2026-08-01)
))


def defined_tests(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    out: dict[str, ast.FunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            out[node.name] = node
    return out


def called_names(node: ast.AST) -> set[str]:
    """Every bare-name function call made directly inside `node`'s body
    (not walking into nested FunctionDefs -- callers are resolved by the
    reachability BFS below, not by flattening everything up front)."""
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child is not node:
            continue  # a nested def's body is that def's own scope
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
            names.add(child.func.id)
    return names


def reachable_tests_from_run_all(
    run_all: ast.FunctionDef, all_funcs: dict[str, ast.FunctionDef]
) -> set[str]:
    """BFS over run_all()'s call graph. Any test_* name reached, directly or
    through a chain of plain function calls, counts as invoked.

    Takes no ast.Module: the walk is driven entirely by run_all plus the
    merged symbol table, which is what makes it correct across a multi-file
    suite. It previously accepted a `tree` it never read, and the caller now
    parses several -- passing the loop's last tree would have looked
    meaningful while silently being "whichever area module sorted last".
    """
    reached_tests: set[str] = set()
    seen_helpers: set[str] = set()
    frontier = [run_all]
    while frontier:
        fn = frontier.pop()
        for name in called_names(fn):
            if name.startswith("test_"):
                reached_tests.add(name)
            elif name in all_funcs and name not in seen_helpers and all_funcs[name] is not fn:
                seen_helpers.add(name)
                frontier.append(all_funcs[name])
    return reached_tests


def suite_files(facade: Path) -> list[Path]:
    """The facade plus every area module, sorted for a stable report.

    The areas package is optional only because this lint has to keep working
    on the pre-split tree (and so MAINT-T0 could land, and be verified against
    a known-good 326/326, BEFORE any test moved). Once ci/tools/areas/ exists
    every .py in it is mandatory input: a module that fails to parse is an
    error, never a silently skipped file.
    """
    files = [facade]
    areas = facade.parent / "areas"
    if areas.is_dir():
        files.extend(sorted(p for p in areas.glob("*.py")
                            if p.name != "__init__.py"))
    return files


class SuiteParseError(Exception):
    """A suite file could not be read or parsed.

    Raised rather than returned so the load phase cannot be accidentally
    continued past a file it failed on: a partial symbol table is what makes
    this lint claim things about tests it never saw.
    """


def load_suite(
    paths: list[Path],
) -> tuple[dict[str, ast.FunctionDef], dict[str, ast.FunctionDef], dict[str, Path]]:
    """Parse every suite file into ONE merged symbol table.

    Returns (tests, all_funcs, origin): the test_* defs, every def by name for
    the reachability walk, and which file each test came from so an orphan is
    reported at its real location rather than the facade's.
    """
    tests: dict[str, ast.FunctionDef] = {}
    all_funcs: dict[str, ast.FunctionDef] = {}
    origin: dict[str, Path] = {}
    for path in paths:
        try:
            tree = ast.parse(path.read_text(), filename=str(path))
        except (OSError, SyntaxError) as exc:
            raise SuiteParseError(
                f"{path}: cannot parse ({exc}) -- refusing to report on a "
                "partially-read suite") from exc
        for name, fn in defined_tests(tree).items():
            tests[name] = fn
            origin[name] = path
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                all_funcs[node.name] = node
    return tests, all_funcs, origin


# --- BP-D1: abort-arm coverage matrix ------------------------------------- #
#
# Mapping method (derived from names only, never from test bodies):
#  * site token: the park-sites.tsv `abort_tests` column lists tests named
#    test_l2_abort_<token>_<shape>_<phase>; <token> is the part between
#    "test_l2_abort_" and the first shape word (names with token "fixture" are
#    the shared fixture-park smoke test, not a per-site token).
#  * shape arm: a reachable test_l2_abort_<token>_<shape>_* exists, with
#    <shape> in ABORT_SHAPES' name stems.
#  * blocked-send-then-poke: the re-entry family test_l2_reentry_<rtoken>_poke
#    (run_reentry_test(..., "poke")); <rtoken> equals the site token except for
#    POKE_TOKEN_ALIAS, where the re-entry rig drives the walk through another
#    name (the "purge_walk" rig PURGEs and parks in redis_sscan).
ABORT_SHAPES: dict[str, str] = {
    "http1_fin": "HTTP/1 FIN",
    "http1_rst": "HTTP/1 RST",
    "h2_rst_stream": "HTTP/2 RST_STREAM",
    "h2_close": "HTTP/2 close",
    "poke": "blocked-send-then-poke",
}
POKE_TOKEN_ALIAS: dict[str, str] = {"sscan_walk": "purge_walk"}
_TOKEN_RE = re.compile(
    r"^test_l2_abort_(?P<tok>.+?)_(?:http1_(?:rst|fin)|h2_(?:rst_stream|close)"
    r"|clean|parks)(?:_|$)")


def site_tokens(abort_tests: str) -> set[str]:
    toks = set()
    for name in filter(None, (t.strip() for t in abort_tests.split(","))):
        m = _TOKEN_RE.match(name)
        if m and m.group("tok") != "fixture":
            toks.add(m.group("tok"))
    return toks


def read_tsv(path: Path) -> list[list[str]]:
    rows = []
    for line in path.read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            rows.append(line.split("\t"))
    return rows


def park_arm_matrix(
    sites: list[list[str]], reached: set[str]
) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    """Return (covered, missing) sets of (function, shape) pairs.
    A site whose abort_tests give no token covers nothing (all shapes missing)."""
    covered: set[tuple[str, str]] = set()
    missing: set[tuple[str, str]] = set()
    for row in sites[1:]:  # row 0 is the header
        func = row[1]
        toks = site_tokens(row[5] if len(row) > 5 else "")
        for shape in ABORT_SHAPES:
            if shape == "poke":
                rtoks = {POKE_TOKEN_ALIAS.get(t, t) for t in toks}
                names = {f"test_l2_reentry_{t}_poke" for t in rtoks}
                hit = any(n in reached for n in names)
            else:
                hit = any(n.startswith(f"test_l2_abort_{t}_{shape}_")
                          for t in toks for n in reached)
            (covered if hit else missing).add((func, shape))
    return covered, missing


def read_baseline(base_p: Path) -> tuple[set[tuple[str, str]], bool]:
    """Parse the baseline; returns (pairs, ok)."""
    pairs: set[tuple[str, str]] = set()
    ok = True
    for row in read_tsv(base_p):
        if len(row) != 2 or row[1] not in ABORT_SHAPES:
            print(f"lint-orphan-tests: {base_p}: bad baseline line {row!r} "
                  f"(want <function><TAB><{'|'.join(ABORT_SHAPES)}>)",
                  file=sys.stderr)
            ok = False
        else:
            pairs.add((row[0], row[1]))
    return pairs, ok


def check_park_arms(facade: Path, reached: set[str]) -> int:
    ci_dir = facade.parent.parent
    try:
        sites = read_tsv(ci_dir / "park-sites.tsv")
        baseline, ok = read_baseline(ci_dir / "park-arms-missing.tsv")
    except OSError as exc:
        print(f"lint-orphan-tests: {exc}", file=sys.stderr)
        return 1
    if len(sites) < 2:
        print("lint-orphan-tests: park-sites.tsv: no park sites -- refusing "
              "a vacuous arm check", file=sys.stderr)
        return 1
    covered, missing = park_arm_matrix(sites, reached)
    for func, shape in sorted(missing - baseline):
        print(f"lint-orphan-tests: park-sites.tsv: {func} has no "
              f"'{shape}' abort arm ({ABORT_SHAPES[shape]}) -- add the arm; "
              "do not extend the baseline", file=sys.stderr)
        ok = False
    for func, shape in sorted(baseline - missing):
        print(f"lint-orphan-tests: park-arms-missing.tsv: stale entry {func} "
              f"{shape} (the arm exists or the site is gone) -- delete the "
              "line", file=sys.stderr)
        ok = False
    if ok:
        print(f"lint-orphan-tests: park arms OK ({len(sites) - 1} sites x "
              f"{len(ABORT_SHAPES)} shapes: {len(covered)} covered, "
              f"{len(missing & baseline)} in baseline)")
    return 0 if ok else 1


def check_fault_gate(facade: Path) -> int:
    root = facade.resolve().parent.parent.parent
    if not (root / "ci/tools/precommit-test-map.tsv").is_file():
        print(f"lint-orphan-tests: fault-gate check skipped: no precommit map "
              f"under {root}")
        return 0
    return subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parent / "lint-fault-gate.py"),
         "--root", str(root)], check=False).returncode


def main() -> int:
    facade = Path(sys.argv[1] if len(sys.argv) > 1 else "ci/tools/test_runtime.py")
    paths = suite_files(facade)

    try:
        tests, all_funcs, origin = load_suite(paths)
    except SuiteParseError as exc:
        print(f"lint-orphan-tests: {exc}", file=sys.stderr)
        return 1

    run_all = all_funcs.get("run_all")
    if run_all is None:
        print(f"lint-orphan-tests: {facade}: no run_all() found in "
              f"{len(paths)} suite file(s) -- refusing to report OK on a "
              "suite this lint cannot parse", file=sys.stderr)
        return 1

    # Sanity gates on the INPUT, before any orphan arithmetic. Both conditions
    # below are structurally impossible in a healthy suite, and both are what a
    # vanished/renamed areas/ package looks like from in here: the facade still
    # parses, run_all() still calls names, but the definitions are gone. Without
    # these the lint prints "0 test_* defined ... 326 reachable" and exits 0 --
    # a green over a suite it can no longer see, i.e. precisely the false green
    # this file's docstring calls worse than having no lint at all.
    if not tests:
        print(f"lint-orphan-tests: {facade}: no test_* defined in "
              f"{len(paths)} suite file(s) -- the suite cannot be empty, so "
              "this is a lost/renamed area package or a wrong path argument, "
              "not a clean run", file=sys.stderr)
        return 1

    reached = reachable_tests_from_run_all(run_all, all_funcs)

    # run_all() calling a test_* name that nothing defines. Orphan arithmetic
    # is a set DIFFERENCE, so these subtract out silently and a partially-lost
    # area package (say areas/l2.py deleted, the rest intact) reads as a clean
    # run with a smaller total. Catch it on the count, not on eyeballing the
    # OK line.
    phantom = sorted(reached - set(tests))
    if phantom:
        for name in phantom:
            print(f"lint-orphan-tests: {facade}: run_all() calls '{name}' but "
                  "no such test_* is defined in the suite -- a deleted or "
                  "renamed area module, or a typo'd call site",
                  file=sys.stderr)
        return 1

    orphans = sorted(set(tests) - reached - ALLOWED_ORPHANS)
    stale_allow = sorted(ALLOWED_ORPHANS - set(tests))

    status = 0
    if stale_allow:
        for name in stale_allow:
            print(f"lint-orphan-tests: {facade}: ALLOWED_ORPHANS lists "
                  f"'{name}' but no such test_* is defined any more -- "
                  "remove the stale opt-out entry", file=sys.stderr)
        status = 1

    if orphans:
        for name in orphans:
            where = origin[name]
            lineno = tests[name].lineno
            print(f"lint-orphan-tests: {where}:{lineno}: '{name}' is defined "
                  "but never called from run_all() (or a helper it calls) -- "
                  "the test never executes in CI. Call it from run_all(), or "
                  "add it to ALLOWED_ORPHANS with a comment saying why it's "
                  "deliberately manual-only.", file=sys.stderr)
        status = 1

    if status == 0:
        # The file count is part of the verdict, not decoration: it is what
        # makes "the areas package vanished and I am now linting a facade"
        # visible in the CI log instead of reading as a normal green.
        print(f"lint-orphan-tests: OK ({len(tests)} test_* defined across "
              f"{len(paths)} file(s), {len(reached)} reachable from "
              f"run_all(), {len(ALLOWED_ORPHANS)} explicit opt-outs)")

    return max(status, check_park_arms(facade, reached),
               check_fault_gate(facade))


if __name__ == "__main__":
    raise SystemExit(main())
