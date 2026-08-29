#!/usr/bin/env bash
# Prove the barrier race rejects an unconditional post-marker-failure purge.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CC="${CC:-cc}"
TMP_DIR="$(mktemp -d)"
OUT="$TMP_DIR/control.out"

restore() {
	CTRL_MARKER_ROLLBACK_UNCONDITIONAL=0 \
		bash "$DIR/extract_marker_rollback.sh" >/dev/null
	rm -rf "$TMP_DIR"
}
trap restore EXIT

CTRL_MARKER_ROLLBACK_UNCONDITIONAL=1 \
	bash "$DIR/extract_marker_rollback.sh" >/dev/null

"$CC" -g -O0 -Wall -Wextra -Werror -Wno-unused-parameter -pthread \
	-I"$DIR" \
	"$DIR/test_marker_rollback.c" -o "$TMP_DIR/test_marker_rollback"

set +e
"$TMP_DIR/test_marker_rollback" >"$OUT" 2>&1
status=$?
set -e

if [ "$status" -eq 0 ]; then
	echo "✗ unconditional marker rollback survived its negative control" >&2
	exit 1
fi
if ! grep -qF \
	"concurrent replacement B must survive A's rollback" "$OUT"; then
	echo "✗ unconditional rollback missed the replacement-survival assertion" >&2
	tail -20 "$OUT" >&2
	exit 1
fi

echo "✓ unconditional marker rollback fails replacement-survival assertion"
