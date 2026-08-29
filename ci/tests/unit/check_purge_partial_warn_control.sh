#!/usr/bin/env bash
# Prove a post-delete generation-store failure remains operator-visible.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CC="${CC:-cc}"
TMP_DIR="$(mktemp -d)"
OUT="$TMP_DIR/control.out"

restore() {
	CTRL_PURGE_NO_PARTIAL_WARN=0 \
		bash "$DIR/extract_purge_digest_order.sh" >/dev/null
	rm -rf "$TMP_DIR"
}
trap restore EXIT

CTRL_PURGE_NO_PARTIAL_WARN=1 \
	bash "$DIR/extract_purge_digest_order.sh" >/dev/null

"$CC" -g -O0 -Wall -Wextra -Werror -Wno-unused-parameter \
	"$DIR/test_purge_digest_order.c" -o "$TMP_DIR/test_purge_digest_order"

set +e
"$TMP_DIR/test_purge_digest_order" >"$OUT" 2>&1
status=$?
set -e

if [ "$status" -eq 0 ]; then
	echo "✗ missing partial-purge warning survived its negative control" >&2
	exit 1
fi
if ! grep -qF \
	"partial purge failure must emit exactly one warning" "$OUT"; then
	echo "✗ missing partial-purge warning missed its exact assertion" >&2
	tail -20 "$OUT" >&2
	exit 1
fi

echo "✓ missing partial-purge warning fails its exact logging assertion"
