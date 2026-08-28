#!/usr/bin/env bash
# ci/linter/lib.sh -- shared helpers for the ci/linter/lint-*.sh scripts.
#
# Sourced, never executed. Provides:
#   repo_root            absolute path of the checkout
#   lint_files <regex>   emit the file list to lint, one per line. Honours
#                        LINT_MODE:
#                          staged (default in the git hook) -- staged files only
#                          all                              -- every tracked file
#                        and an explicit file list passed in "$@" by run-all.sh.
#   lint_files_into <array> <regex> [files...]
#                        load lint_files output without losing its exit status
#   need <tool> <hint>   hard-fail with an install hint when a linter is absent
#   say / warn / die     consistent output
#
# Missing tools are a HARD FAILURE, never a silent skip: a gate that quietly
# disappears when its tool is uninstalled reports green while checking nothing.
# Run ci/linter/install-linters.sh to get them all.

set -euo pipefail

repo_root() { git rev-parse --show-toplevel; }

say()  { printf '  %s\n' "$*"; }
warn() { printf '  WARN: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 2; }

need() {
    command -v "$1" >/dev/null 2>&1 && return 0
    die "$1 not found. Install it: $2   (or run ci/linter/install-linters.sh)"
}

# Paths never linted: byte-exact fuzz inputs, vendored trees, build output.
#
# `(^|/)vendor/` and not `^ci/vendor/`: vendored code is not confined to one
# directory any more -- ci/ast-grep/rules/vendor/ holds CodeRabbit's pack, and
# tools/vendor-astgrep-rules.py rewrites that tree wholesale on every refresh.
# Linting a tree we regenerate produces findings nobody may fix: the upstream
# misspelling in string-view-temporary-string-cpp.yml and yamllint's
# indentation complaints are theirs, and a hand-edit is reverted by the next
# vendor run. Same regex shape as the
# top-level exclude in .pre-commit-config.yaml, so the hook and these scripts
# select the same files.
LINT_EXCLUDE_RE='^ci/fuzz/corpus/|^ci/fuzz/regressions/|(^|/)vendor/|(^|/)objs/|(^|/)\.build/|(^|/)node_modules/|(^|/)\.venv/'

# lint_files <match-regex> [explicit files...]
lint_files() {
    local match_re="$1"; shift
    local list f match_rc
    if [ "$#" -gt 0 ]; then
        list=$(printf '%s\n' "$@")
    elif [ "${LINT_MODE:-all}" = "staged" ]; then
        list=$(git diff --cached --name-only --diff-filter=ACMR) || die "git diff --cached failed"
    else
        list=$(git ls-files) || die "git ls-files failed"
    fi

    # Validate once even when the list is empty. Bash reports an invalid ERE as
    # status 2, which must not collapse into an ordinary miss.
    if [[ "" =~ $match_re ]]; then
        match_rc=0
    else
        # shellcheck disable=SC2319  # the condition status distinguishes miss from invalid ERE
        match_rc=$?
    fi
    [ "$match_rc" -ne 2 ] || die "invalid lint file regex: $match_re"

    while IFS= read -r f; do
        [ -n "$f" ] || continue
        if [[ "$f" =~ $LINT_EXCLUDE_RE ]]; then
            continue
        fi
        if [[ "$f" =~ $match_re ]]; then
            if [ -f "$f" ]; then
                printf '%s\n' "$f"
            fi
        fi
    done <<< "$list"
}

# lint_files_into <array-name> <match-regex> [explicit files...]
#
# `mapfile -t FILES < <(lint_files ...)` observes mapfile's status, not the
# producer's. A failed git command can therefore look exactly like a legitimate
# empty selection. Capture the list, check the producer, then load it.
lint_files_into() {
    local array_name="$1" match_re="$2" list
    shift 2

    [[ "$array_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] \
        || die "invalid lint file-list array name: $array_name"

    if list="$(lint_files "$match_re" "$@")"; then
        :
    else
        die "file-list producer failed"
    fi

    if [ -n "$list" ]; then
        mapfile -t "$array_name" <<< "$list"
    else
        mapfile -t "$array_name" < /dev/null
    fi
}
