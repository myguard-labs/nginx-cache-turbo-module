#!/usr/bin/env bash
# ci/linter/lib.sh -- shared helpers for the ci/linter/lint-*.sh scripts.
#
# Sourced, never executed. Provides:
#   repo_root            absolute path of the checkout
#   lint_files <regex>   emit the file list to lint, NUL-delimited. Honours
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

# _lint_emit_file <match-regex> <path>
_lint_emit_file() {
    local match_re="$1" f="$2"
    if [[ "$f" =~ $LINT_EXCLUDE_RE ]]; then
        return 0
    fi
    if [[ "$f" =~ $match_re ]] && [ -f "$f" ]; then
        printf '%s\0' "$f"
    fi
}

# lint_files <match-regex> [explicit files...]
lint_files() {
    local match_re="$1"; shift
    local f match_rc
    local -a git_cmd source_status

    # Validate once even when the list is empty. Bash reports an invalid ERE as
    # status 2, which must not collapse into an ordinary miss.
    if [[ "" =~ $match_re ]]; then
        match_rc=0
    else
        # shellcheck disable=SC2319  # the condition status distinguishes miss from invalid ERE
        match_rc=$?
    fi
    [ "$match_rc" -ne 2 ] || die "invalid lint file regex: $match_re"

    if [ "$#" -gt 0 ]; then
        for f in "$@"; do
            _lint_emit_file "$match_re" "$f"
        done
        return 0
    fi

    if [ "${LINT_MODE:-all}" = "staged" ]; then
        git_cmd=(git diff --cached --name-only --diff-filter=ACMR -z)
    else
        git_cmd=(git ls-files -z)
    fi

    # This runs inside lint_files_into's coprocess, so toggling errexit cannot
    # affect the caller. Capture both pipeline statuses before any other command
    # overwrites PIPESTATUS: a Git failure after a valid prefix must stay red.
    set +e
    "${git_cmd[@]}" | while IFS= read -r -d '' f; do
        _lint_emit_file "$match_re" "$f"
    done
    source_status=("${PIPESTATUS[@]}")
    set -e

    [ "${source_status[0]}" -eq 0 ] || die "Git file-list producer failed"
    [ "${source_status[1]}" -eq 0 ] || die "file-list filter failed"
}

# lint_files_into <array-name> <match-regex> [explicit files...]
#
# `mapfile < <(lint_files ...)` observes mapfile's status, not the producer's.
# A failed git command can therefore look exactly like a legitimate empty
# selection. Keep the NUL stream on a pipe, then wait for its producer.
lint_files_into() {
    local array_name="$1" match_re="$2"
    local coproc_in_fd coproc_out_fd element_ref item load_rc
    local producer_fd producer_pid producer_rc read_rc
    local index=0
    shift 2

    [[ "$array_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] \
        || die "invalid lint file-list array name: $array_name"

    # The handshake prevents a fast producer from exiting while its Bash-owned
    # coproc FD is still being promoted to an ordinary shell FD. Named coproc
    # descriptors can disappear as soon as the child exits; the duplicate is
    # owned by this shell until explicitly closed below.
    coproc LINT_FILES_SOURCE {
        IFS= read -r _lint_start || exit 2
        lint_files "$match_re" "$@"
    }
    producer_pid=$!
    if exec {producer_fd}<&"${LINT_FILES_SOURCE[0]}"; then
        :
    else
        coproc_in_fd="${LINT_FILES_SOURCE[1]}"
        exec {coproc_in_fd}>&-
        wait "$producer_pid" || true
        die "could not duplicate lint file-list pipe"
    fi
    coproc_out_fd="${LINT_FILES_SOURCE[0]}"
    coproc_in_fd="${LINT_FILES_SOURCE[1]}"
    exec {coproc_out_fd}<&-
    if printf '.\n' >&"$coproc_in_fd"; then
        :
    else
        exec {coproc_in_fd}>&-
        exec {producer_fd}<&-
        wait "$producer_pid" || true
        die "could not start lint file-list producer"
    fi
    exec {coproc_in_fd}>&-

    # Bash 4.3 has read -d and printf -v array elements, but mapfile did not
    # gain -d until 4.4. Clear through mapfile's older interface, then decode
    # each NUL record without raising run-all.sh's documented Bash floor.
    mapfile -t "$array_name" < /dev/null
    load_rc=0
    while :; do
        item=""
        if IFS= read -r -d '' item <&"$producer_fd"; then
            read_rc=0
        else
            # shellcheck disable=SC2319  # read status distinguishes EOF from a record
            read_rc=$?
        fi
        if [ "$read_rc" -ne 0 ]; then
            # read -d returns nonzero for both clean EOF and an unterminated
            # tail, but assigns the partial tail in the latter case.
            [ -z "$item" ] || load_rc=2
            break
        fi
        printf -v element_ref '%s[%s]' "$array_name" "$index"
        if ! printf -v "$element_ref" '%s' "$item"; then
            load_rc=2
            break
        fi
        index=$((index + 1))
    done
    exec {producer_fd}<&-

    if wait "$producer_pid"; then
        producer_rc=0
    else
        # shellcheck disable=SC2319  # wait status is the lint_files status
        producer_rc=$?
    fi

    if [ "$producer_rc" -ne 0 ]; then
        mapfile -t "$array_name" < /dev/null
        return "$producer_rc"
    fi
    if [ "$load_rc" -ne 0 ]; then
        mapfile -t "$array_name" < /dev/null
        die "could not load lint file list"
    fi
}
