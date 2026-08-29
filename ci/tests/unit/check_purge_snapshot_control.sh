#!/usr/bin/env bash
# Prove the concurrent-refill test rejects snapshot-less purge-all behavior by
# exact assertions, not merely because either thread happens to hang.
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
    CTRL_PURGE_NO_SNAPSHOT=0 bash "$DIR/extract_shm.sh" >/dev/null
    rm -rf "$TMP_DIR"
}
trap restore EXIT

CTRL_PURGE_NO_SNAPSHOT=1 bash "$DIR/extract_shm.sh" >/dev/null

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
    echo "✗ snapshot-less purge mutation survived its negative control" >&2
    exit 1
fi
if grep -qF 'HANG:' "$OUT"; then
    echo "✗ snapshot-less purge mutation only tripped the hang watchdog" >&2
    tail -20 "$OUT" >&2
    exit 1
fi
for expected in \
    'concurrent refill must report purge-all as incomplete' \
    'purge-all must consume exactly its finite start-of-call budget' \
    'the concurrent refill must remain resident after the snapshot ends'; do
    if ! grep -qF "$expected" "$OUT"; then
        echo "✗ snapshot-less mutation missed assertion: $expected" >&2
        tail -40 "$OUT" >&2
        exit 1
    fi
done

echo "✓ snapshot-less purge mutation fails exact overlap/result assertions"
