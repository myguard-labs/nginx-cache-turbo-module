#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/tools/versions-env.sh -- validate .github/versions.env, then source it.
#
#   . ci/tools/versions-env.sh
#   load_versions_env .github/versions.env
#
# WHY THIS IS A FUNCTION AND NOT THREE COPIES. `.github/versions.env` is
# `source`d, so any line in it that is not a KEY=value pin is EXECUTED as shell.
# The check that prevents that lived inline in ci/tools/ci-build.sh, whose
# comment claimed the "same rule enforced in both consumers" -- and then
# ci/tools/coverage.sh became a third consumer and sourced the file with no
# check at all. A rule that has to be re-typed at each call site is a rule that
# is one new caller away from not holding, and the comment asserting otherwise
# is what makes it hard to notice.
#
# The pattern is deliberately narrow: versions and digests only. A pin never
# needs a space, a quote, a `$`, or a backtick, so anything containing one is
# either a mistake or an injection, and both should stop the build.
#
# Extend: widening the character class is a security decision, not a
# convenience one -- if a future pin needs another character, add exactly that
# character and say why here.

load_versions_env() {
    local file="${1:?load_versions_env: no file given}"
    local line

    if [ ! -f "$file" ]; then
        echo "FATAL: $file not found (run from the module root)" >&2
        return 1
    fi

    # `|| [ -n "$line" ]` so a final line with no trailing newline is still
    # checked rather than silently skipped -- which would be a hole exactly at
    # the end of the file, where an appended line lands.
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            '' | \#*) continue ;;
        esac
        if ! printf '%s' "$line" | grep -qE '^[A-Za-z_][A-Za-z0-9_]*=[A-Za-z0-9._-]*$'; then
            echo "FATAL: malformed line in $file: $line" >&2
            return 1
        fi
    done < "$file"

    # shellcheck source=/dev/null
    . "$file"
}
