#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
# Positive and negative controls for the shared versions.env loader.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=ci/tools/versions-env.sh
. "$ROOT/ci/tools/versions-env.sh"

load_versions_env "$ROOT/.github/versions.env"

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
# shellcheck disable=SC2016  # literal command substitution is the attack input
printf 'NGINX_VERSION=1.2.3\nNGINX_VERSION_SHA256=$(false)\n' > "$TMP"
if load_versions_env "$TMP" >/dev/null 2>&1; then
    echo "versions loader accepted executable shell syntax" >&2
    exit 1
fi

# shellcheck disable=SC2016  # literal unterminated attack input
printf 'NGINX_VERSION=$(false)' > "$TMP"
if load_versions_env "$TMP" >/dev/null 2>&1; then
    echo "versions loader accepted malformed unterminated syntax" >&2
    exit 1
fi

printf 'PATH=.' > "$TMP"
if load_versions_env "$TMP" >/dev/null 2>&1; then
    echo "versions loader accepted an unsupported shell-control name" >&2
    exit 1
fi

printf 'NGINX_VERSION=abc-1.2' > "$TMP"
load_versions_env "$TMP"
[ "$NGINX_VERSION" = 'abc-1.2' ] || {
    echo "versions loader skipped the final unterminated pin" >&2
    exit 1
}

echo "versions loader: valid pins accepted, syntax and names constrained"
