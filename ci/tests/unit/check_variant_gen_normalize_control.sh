#!/usr/bin/env bash
# Prove a direct wide generation cannot diverge from its one-byte marker form.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CC="${CC:-cc}"
TMP_DIR="$(mktemp -d)"
OUT="$TMP_DIR/control.out"

restore() {
    CTRL_VARIANT_NO_GEN_NORMALIZE=0 \
        bash "$DIR/extract_variant_hash.sh" >/dev/null
    rm -rf "$TMP_DIR"
}
trap restore EXIT

CTRL_VARIANT_NO_GEN_NORMALIZE=1 \
    bash "$DIR/extract_variant_hash.sh" >/dev/null

"$CC" -g -O0 -Wall -Wextra -Werror -Wno-unused-parameter \
    "$DIR/test_variant_gen.c" -o "$TMP_DIR/test_variant_gen" -lssl -lcrypto

set +e
"$TMP_DIR/test_variant_gen" >"$OUT" 2>&1
status=$?
set -e

if [ "$status" -eq 0 ]; then
    echo "✗ missing generation normalization survived its negative control" >&2
    exit 1
fi
if ! grep -qF \
    'direct generation 256 must normalize to persisted generation 0' \
    "$OUT"; then
    echo "✗ generation mutation missed its exact boundary assertion" >&2
    tail -20 "$OUT" >&2
    exit 1
fi

echo "✓ missing generation mask fails the exact gen-256 boundary assertion"
