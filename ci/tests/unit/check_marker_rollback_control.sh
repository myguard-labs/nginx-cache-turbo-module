#!/usr/bin/env bash
# Prove the barrier race rejects an unconditional post-marker-failure purge.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CC="${CC:-cc}"
TMP_DIR="$(mktemp -d)"
OUT="$TMP_DIR/control.out"

restore() {
	CTRL_MARKER_ROLLBACK_UNCONDITIONAL=0 CTRL_MARKER_ROLLBACK_NO_WARN=0 \
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

CTRL_MARKER_ROLLBACK_UNCONDITIONAL=0 CTRL_MARKER_ROLLBACK_NO_WARN=1 \
	bash "$DIR/extract_marker_rollback.sh" >/dev/null

"$CC" -g -O0 -Wall -Wextra -Werror -Wno-unused-parameter -pthread \
	-I"$DIR" \
	"$DIR/test_marker_rollback.c" -o "$TMP_DIR/test_marker_rollback_no_warn"

set +e
"$TMP_DIR/test_marker_rollback_no_warn" >"$OUT" 2>&1
status=$?
set -e

if [ "$status" -eq 0 ]; then
	echo "✗ missing rollback warning survived its negative control" >&2
	exit 1
fi
if ! grep -qF \
	"successful unsafe-variant rollback must emit exactly one warning" \
	"$OUT"; then
	echo "✗ missing rollback warning missed its exact assertion" >&2
	tail -20 "$OUT" >&2
	exit 1
fi
for state_assertion in \
	"isolated failed marker store must remove A's unsafe variant" \
	"isolated rollback must release A's pinned token exactly once"; do
	if grep -qF "$state_assertion" "$OUT"; then
		echo "✗ warning-only mutation also changed rollback state" >&2
		tail -20 "$OUT" >&2
		exit 1
	fi
done

echo "✓ log-only rollback mutation fails logging while state assertions pass"
