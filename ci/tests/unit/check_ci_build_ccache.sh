#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
# The ci-build.sh compiler selection: ccache on -> `ccache cc`, CT_NO_CCACHE=1
# or no ccache -> plain `cc`. CodeQL's build tracer needs the plain compiler even
# on a runner that has ccache installed (a ccache hit hides the compile).
#
# The block is extracted from the shipped script and evaluated against a stub
# PATH, so a change to the real selection logic flows straight into this test.
# Negative control: dropping the CT_NO_CCACHE condition from the extracted block
# must turn the "flag set -> cc" arm red.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="$ROOT/ci/tools/ci-build.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# From the CC default through the closing fi of the ccache if/else.
awk '/^CC="\$\{CC:-cc\}"/ {on=1} on {print} on && /^fi$/ {exit}' "$SCRIPT" >"$TMP/block.sh"
if ! [ -s "$TMP/block.sh" ] || ! grep -q 'WITH_CC=' "$TMP/block.sh"; then
    echo "could not extract the compiler-selection block from ci-build.sh" >&2
    exit 1
fi

mkdir -p "$TMP/with" "$TMP/without"
printf '#!/bin/sh\nexit 0\n' >"$TMP/with/ccache"
chmod +x "$TMP/with/ccache"
# The "absent" arm gets a PATH directory with no ccache in it.
BASH_BIN="$(command -v bash)"

pick() { # pick <block-file> <path> [VAR=val ...] -> WITH_CC
    local blk="$1" p="$2"
    shift 2
    # shellcheck disable=SC2016  # $1/$WITH_CC expand in the child shell
    env -i PATH="$p" "$@" "$BASH_BIN" -c 'set -euo pipefail; . "$1"; printf "%s" "$WITH_CC"' _ "$blk"
}

fail=0
expect() { # expect <label> <want> <got>
    if [ "$2" = "$3" ]; then
        echo "ok   $1: '$3'"
    else
        echo "FAIL $1: want '$2', got '$3'" >&2
        fail=1
    fi
}

expect "ccache present, flag unset" "ccache cc" "$(pick "$TMP/block.sh" "$TMP/with")"
expect "ccache present, CT_NO_CCACHE=1" "cc" "$(pick "$TMP/block.sh" "$TMP/with" CT_NO_CCACHE=1)"
expect "ccache present, CT_NO_CCACHE=0" "ccache cc" "$(pick "$TMP/block.sh" "$TMP/with" CT_NO_CCACHE=0)"
expect "ccache present, CC=clang" "ccache clang" "$(pick "$TMP/block.sh" "$TMP/with" CC=clang)"
expect "ccache absent" "cc" "$(pick "$TMP/block.sh" "$TMP/without")"

# Negative control: the mutant ignores the flag, so the flag arm must differ.
# shellcheck disable=SC2016  # literal pattern, not an expansion
sed 's/\[ "\${CT_NO_CCACHE:-}" != 1 \] && //' "$TMP/block.sh" >"$TMP/mutant.sh"
if cmp -s "$TMP/block.sh" "$TMP/mutant.sh"; then
    echo "FAIL negative control: mutation did not change the block" >&2
    fail=1
elif [ "$(pick "$TMP/mutant.sh" "$TMP/with" CT_NO_CCACHE=1)" = "cc" ]; then
    echo "FAIL negative control: mutant still honoured the flag" >&2
    fail=1
else
    echo "ok   negative control: mutant ignoring the flag picks ccache"
fi

exit "$fail"
