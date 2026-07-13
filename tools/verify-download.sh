#!/usr/bin/env bash
# Verify a downloaded CI input against the repository's pinned SHA-256 manifest.

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 FILE" >&2
    exit 2
fi

file=$1
name=${file##*/}
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
manifest="$script_dir/ci-checksums.sha256"

if [ ! -f "$file" ]; then
    echo "download does not exist: $file" >&2
    exit 1
fi

expected=$(awk -v name="$name" '
    $0 !~ /^#/ && $2 == name { print $1; found++ }
    END { if (found != 1) exit 1 }
' "$manifest") || {
    echo "no unique pinned checksum for $name" >&2
    exit 1
}

actual=$(sha256sum -- "$file")
actual=${actual%% *}
if [ "$actual" != "$expected" ]; then
    echo "checksum mismatch for $name" >&2
    echo "expected: $expected" >&2
    echo "actual:   $actual" >&2
    exit 1
fi

printf 'verified %s (%s)\n' "$name" "$actual"
