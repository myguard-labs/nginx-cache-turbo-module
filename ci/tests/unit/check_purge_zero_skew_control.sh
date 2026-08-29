#!/usr/bin/env bash
# Prove purge-all cannot infer queue emptiness from a zero entry-count budget.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$DIR/../../.." && pwd)"
NGINX_VERSION="${NGINX_VERSION:-1.31.3}"
NGINX_SRC="${NGINX_SRC:-$REPO/.build/nginx-$NGINX_VERSION/src}"
NGINX_OBJS="${NGINX_OBJS:-$REPO/.build/nginx-$NGINX_VERSION/objs}"
CC="${CC:-cc}"
TMP_DIR="$(mktemp -d)"
OUT="$TMP_DIR/control.out"

restore() {
    CTRL_PURGE_SKIP_ZERO_CHECK=0 bash "$DIR/extract_shm.sh" >/dev/null
    rm -rf "$TMP_DIR"
}
trap restore EXIT

CTRL_PURGE_SKIP_ZERO_CHECK=1 bash "$DIR/extract_shm.sh" >/dev/null

CFLAGS=(-O1 -g -std=c99 -Wall -Wextra -Werror -Wno-unused-parameter)
NGX_INCS=(-I"$NGINX_SRC/core" -I"$NGINX_SRC/event"
          -I"$NGINX_SRC/os/unix" -I"$NGINX_OBJS")

"$CC" "${CFLAGS[@]}" "${NGX_INCS[@]}" \
    -c "$NGINX_SRC/core/ngx_rbtree.c" -o "$TMP_DIR/ngx_rbtree.o"
"$CC" "${CFLAGS[@]}" -pthread -I"$DIR" \
    -c "$DIR/test_shm_state.c" -o "$TMP_DIR/test_shm_state.o"
"$CC" -pthread "$TMP_DIR/test_shm_state.o" "$TMP_DIR/ngx_rbtree.o" \
    -o "$TMP_DIR/test_shm_state"

set +e
"$TMP_DIR/test_shm_state" >"$OUT" 2>&1
status=$?
set -e

if [ "$status" -eq 0 ]; then
    echo "✗ missing zero-budget observation survived its negative control" >&2
    exit 1
fi
if grep -qF 'HANG:' "$OUT"; then
    echo "✗ zero-budget observation mutation only tripped a watchdog" >&2
    tail -20 "$OUT" >&2
    exit 1
fi
if ! grep -qF \
    'zero snapshot with resident queue must report purge-all incomplete' \
    "$OUT"; then
    echo "✗ zero-budget mutation missed its exact result assertion" >&2
    tail -40 "$OUT" >&2
    exit 1
fi

echo "✓ missing zero-budget observation fails the exact skew assertion"
