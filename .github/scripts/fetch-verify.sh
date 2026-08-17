#!/usr/bin/env bash
# sync-sha: dab59fae650dad38322b39941831076ea9dd85e11c4fd697c9494a237495a0c7
# Download one upstream archive and verify its pinned SHA-256.
set -euo pipefail

url="${1:?usage: fetch-verify.sh URL SHA256 OUTFILE}"
want="${2:?missing expected sha256}"
out="${3:?missing output path}"
if [ ! -f "$out" ] || [ "$want" = - ] || [ "$(sha256sum "$out" | cut -d' ' -f1)" != "$want" ]; then
    curl -fSL --retry 3 --retry-delay 2 --connect-timeout 30 --max-time 300 -o "$out" "$url"
fi
got="$(sha256sum "$out" | cut -d' ' -f1)"
if [ "$want" = - ]; then
    printf '%s  %s\n' "$got" "$out"
elif [ "$got" != "$want" ]; then
    echo "::error::sha256 mismatch for $url (expected $want, got $got)" >&2
    exit 1
else
    printf 'sha256 verified: %s\n' "$out"
fi
