#!/usr/bin/env bash
# ci/linter/lint-sh.sh -- shellcheck over every *.sh / *.bash in the tree.
#
# -S warning, not info: the info tier (SC2015, SC2086 in safe positions) fires
# on existing build scripts and would land this gate red on arrival, which only
# teaches everyone to --no-verify. Same floor as the shellcheck the actionlint
# hook runs inside `run:` blocks (SHELLCHECK_OPTS=-Swarning), so an SC2164 is
# not ignored in a .sh file while blocking in a workflow.
#
# Usage: ci/linter/lint-sh.sh [files...]   Env: LINT_MODE=staged|all
# Extend: raise to -S info only together with a pass that fixes the backlog.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

# .githooks/* has no extension but is bash; an unchecked commit hook is the
# one script whose bug silently disables every other check here.
mapfile -t FILES < <(lint_files '\.(sh|bash)$|^\.githooks/' "$@")

# The nginx addon `config` decides which src/*.c are compiled into the module, so
# a typo there silently drops a translation unit from the build -- exactly the
# class this gate exists to catch -- but it matched neither pattern above and was
# read by no checker at all (GATE-CONFIG-UNLINTED).
#
# Checked separately, and NOT simply added to FILES, for two reasons:
#   -s sh    it is sourced by nginx's POSIX-sh configure, not run as bash.
#   -e ...   SC2154/SC2034 are false positives here BY CONSTRUCTION and cannot be
#            fixed in this file. auto/modules:1313 sets ngx_addon_dir as a loop
#            variable and then dot-sources this file into that scope (:1327), and
#            auto/module reads ngx_module_type/_name/_srcs/_deps back out. Both
#            sides of every flagged variable live across a `.` source boundary
#            that the checker cannot follow, so it sees reads with no assignment
#            and assignments with no reads.
# Suppressing them beats leaving the file unchecked: everything else -- quoting,
# SC2164, typos in real logic -- is still enforced. Adding it WITHOUT -e would
# land the gate red on arrival for findings wrong by inspection, which is how a
# checker teaches everyone --no-verify.
mapfile -t CONFIG_FILES < <(lint_files '(^|/)config$' "$@")

if [ "${#FILES[@]}" -eq 0 ] && [ "${#CONFIG_FILES[@]}" -eq 0 ]; then
    echo "lint-sh: no shell files to check"
    exit 0
fi

need shellcheck "apt-get install shellcheck"

if [ "${#FILES[@]}" -gt 0 ]; then
    echo "lint-sh: ${#FILES[@]} file(s)"
    shellcheck -S warning -x "${FILES[@]}"
fi

if [ "${#CONFIG_FILES[@]}" -gt 0 ]; then
    echo "lint-sh: ${#CONFIG_FILES[@]} nginx addon config file(s)"
    shellcheck -S warning -s sh -e SC2154,SC2034 "${CONFIG_FILES[@]}"
fi

say "clean"
