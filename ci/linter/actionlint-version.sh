#!/usr/bin/env bash
# Shared pin for the installer and the workflow linter.
ACTIONLINT_VERSION=1.7.7

actionlint_version_ok() {
    local output
    if ! output="$(actionlint -version 2>/dev/null)"; then
        echo "actionlint: missing or version command failed" >&2
        return 1
    fi
    if [ "${output%%$'\n'*}" != "$ACTIONLINT_VERSION" ]; then
        echo "actionlint: expected version $ACTIONLINT_VERSION" >&2
        return 1
    fi
}
