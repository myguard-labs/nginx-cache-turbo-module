#!/usr/bin/env bash
# Prove the retry counter rejects double-counting the current upstream attempt.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CC="${CC:-cc}"
TMP_DIR="$(mktemp -d)"
OUT="$TMP_DIR/control.out"

restore() {
	bash "$DIR/extract_breaker_retry.sh" >/dev/null
	rm -rf "$TMP_DIR"
}
trap restore EXIT

CTRL_BREAKER_RETRY_INCLUDE_CURRENT=1 \
	bash "$DIR/extract_breaker_retry.sh" >/dev/null
"$CC" -g -O0 -Wall -Wextra -Werror -I"$DIR" \
	"$DIR/test_breaker_retry.c" -o "$TMP_DIR/test_breaker_retry"

set +e
"$TMP_DIR/test_breaker_retry" >"$OUT" 2>&1
status=$?
set -e

if [ "$status" -eq 0 ]; then
	echo "✗ include-current breaker mutation survived its negative control" >&2
	exit 1
fi
if ! grep -qF \
	"the final/current attempt must be excluded from retry failures" "$OUT"; then
	echo "✗ include-current mutation missed its exact assertion" >&2
	tail -20 "$OUT" >&2
	exit 1
fi

echo "✓ include-current breaker mutation fails the current-attempt assertion"
