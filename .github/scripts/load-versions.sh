#!/usr/bin/env bash
# sync-sha: 462e9069e36fdcc1b860fafbb677ecb3a53d04f555eba1744d096d529ade5cda
# Load the checked-in version pins into a GitHub Actions job environment.
set -euo pipefail

file=.github/versions.env
[ -f "$file" ] || { echo "::error::$file not found" >&2; exit 1; }
[ -n "${GITHUB_ENV:-}" ] || { echo "::error::GITHUB_ENV is unset" >&2; exit 1; }
while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    if ! printf '%s' "$line" | grep -qE '^[A-Z][A-Z0-9_]*=[0-9a-f.]+$'; then
        echo "::error::malformed version pin: $line" >&2
        exit 1
    fi
    printf '%s\n' "$line" >> "$GITHUB_ENV"
done < "$file"
