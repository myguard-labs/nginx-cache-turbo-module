#!/usr/bin/env bash
# ci/linter/lint-astgrep-essentials.sh -- the FULL ast-grep essentials pack.
#
# lint-astgrep.sh runs the C/C++ slice vendored under ci/ast-grep/ and blocks on
# five promoted rules. This checker runs the whole upstream pack
# (labs/ast-grep-essentials, every language it covers) and blocks on the pack's
# own severity: any finding of severity `error` fails; warning and info are
# printed for the files being checked and never block.
#
# Scope: staged files in hook mode, every tracked file in LINT_MODE=all, or the
# explicit file list run-all.sh passes. Fixtures under ci/linter/fixtures/ are
# deliberately wrong and are skipped unless named explicitly.
#
# Pack root: $AST_GREP_ESSENTIALS, default /opt/myguard/labs/ast-grep-essentials
# (CI checks out myguard-labs/ast-grep-essentials at AST_GREP_ESSENTIALS_SHA from
# .github/versions.env). A root without sgconfig.yml is exit 2 ("could not run"),
# like a missing tool: a gate that passes because its ruleset is absent checks
# nothing.
#
# Env:   AST_GREP_ESSENTIALS=<dir>   pack root
#        LINT_MODE=staged|all
#        ESSENTIALS_ADVISORY=1       print errors as errors but exit 0 (a local
#                                    triage aid; neither CI nor the hook sets it)
#        ESSENTIALS_MAX_ADVISORY=N   advisory lines printed per run (default 40)
# Usage: ci/linter/lint-astgrep-essentials.sh [files...]
# Exit:  0 no error-severity finding, 1 an error-severity finding,
#        2 ast-grep/python3 missing, pack root unusable, or ast-grep failed.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

# Extensions of every language the pack's rules/ directories cover.
EXT_RE='\.(sh|bash|c|h|cc|cpp|cxx|hpp|cs|go|html|htm|java|js|mjs|cjs|jsx|kt|kts|lua|php|phtml|ps1|psm1|py|rb|rs|scala|swift|ts|tsx)$'

lint_files_into FILES "$EXT_RE" "$@"
if [ "$#" -eq 0 ]; then
    kept=()
    for f in "${FILES[@]}"; do
        [[ "$f" == ci/linter/fixtures/* ]] || kept+=("$f")
    done
    FILES=("${kept[@]+"${kept[@]}"}")
fi
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-astgrep-essentials: no files of a covered language"; exit 0; }

need ast-grep "see ci/linter/install-linters.sh (pinned upstream binary)"
need python3 "apt-get install python3"

ROOT_E="${AST_GREP_ESSENTIALS:-/opt/myguard/labs/ast-grep-essentials}"
[ -f "$ROOT_E/sgconfig.yml" ] \
    || die "ast-grep essentials pack not found at $ROOT_E (set AST_GREP_ESSENTIALS; CI checks it out at the pinned SHA)"

echo "lint-astgrep-essentials: ${#FILES[@]} file(s)"

out="$(mktemp "${TMPDIR:-/tmp}/essentials.XXXXXX")"
trap 'rm -f "$out"' EXIT

# lib.sh sets errexit; capture the status instead of dying on rc 1.
rc=0
ast-grep scan -c "$ROOT_E/sgconfig.yml" --json=stream "${FILES[@]}" > "$out" || rc=$?
# 0 clean/warnings only, 1 an error-severity rule fired. Anything else is
# ast-grep failing to run, which is "could not run", not a verdict.
case "$rc" in
    0|1) ;;
    *) die "ast-grep exited $rc -- could not run (config error?), not a verdict" ;;
esac

ADVISORY="${ESSENTIALS_ADVISORY:-}" MAXADV="${ESSENTIALS_MAX_ADVISORY:-40}" \
SHOW_ADV="$([ "${LINT_MODE:-all}" = all ] && [ "$#" -eq 0 ] && echo 0 || echo 1)" \
python3 -I - "$out" "$rc" <<'PY' || exit $?
import json, os, sys

path, rc = sys.argv[1], int(sys.argv[2])
errors, other = [], []
with open(path, encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        # A stream that stops parsing is "could not run" (2), never a finding (1).
        try:
            d = json.loads(line)
            row = (d["file"], d["range"]["start"]["line"] + 1, d["ruleId"],
                   d.get("severity", ""), " ".join(d.get("message", "").split()))
        except (ValueError, KeyError, TypeError) as e:
            print(f"ERROR: cannot parse ast-grep stream: {e!r}", file=sys.stderr)
            sys.exit(2)
        (errors if row[3] == "error" else other).append(row)

# ast-grep says "error found" (rc 1) and the parsed stream must agree, or the
# verdict rests on a parse that stopped matching.
if (rc == 1) != bool(errors):
    print(f"ERROR: ast-grep rc={rc} but {len(errors)} error finding(s) parsed", file=sys.stderr)
    sys.exit(2)

show = os.environ["SHOW_ADV"] == "1"
limit = int(os.environ["MAXADV"])
if show:
    shown = [r for r in other if r[3] in ("warning", "info")]
    for f, ln, rid, sev, msg in shown[:limit]:
        print(f"  {sev}: {f}:{ln}: [{rid}] {msg[:100]}")
    if len(shown) > limit:
        print(f"  ... {len(shown) - limit} more advisory finding(s) not shown")
else:
    print(f"  {len(other)} advisory (warning/info) finding(s) not listed in whole-tree mode")
for f, ln, rid, sev, msg in errors:
    print(f"{f}:{ln}: error[{rid}]: {msg[:160]}")
if errors:
    adv = os.environ.get("ADVISORY")
    print(f"lint-astgrep-essentials: {len(errors)} error-severity finding(s)"
          + (" -- ADVISORY, not blocking (ESSENTIALS_ADVISORY set)" if adv else ""))
    sys.exit(0 if adv else 1)
PY
