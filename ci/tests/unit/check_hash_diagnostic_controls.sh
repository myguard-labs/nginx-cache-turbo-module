#!/usr/bin/env bash
# Each hash diagnostic constructor must fail its own runnable assertion if its
# mismatch guard or increment is disarmed in the extracted production slice.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$DIR/../../.." && pwd)"
if [ -z "${NGINX_VERSION:-}" ] && [ -f "$REPO/.github/versions.env" ]; then
    NGINX_VERSION=$(sed -n 's/^NGINX_VERSION=//p' "$REPO/.github/versions.env" | head -1)
fi
NGINX_VERSION="${NGINX_VERSION:-1.31.3}"
NGINX_SRC="${NGINX_SRC:-$REPO/.build/nginx-$NGINX_VERSION/src}"
NGINX_OBJS="${NGINX_OBJS:-$REPO/.build/nginx-$NGINX_VERSION/objs}"
CC="${CC:-cc}"
TMP_DIR="$(mktemp -d)"
OUT="$TMP_DIR/control.out"

restore() {
    CTRL_HASH_DIAG_MUTATION='' bash "$DIR/extract_shm.sh" >/dev/null
    rm -rf "$TMP_DIR"
}
trap restore EXIT

owners=(ngx_http_cache_turbo_shm_store_locked
        ngx_http_cache_turbo_shm_claim_locked
        ngx_http_cache_turbo_shm_count_miss_locked
        ngx_http_cache_turbo_shm_l2_neg_set)
declare -A assertion=(
    [ngx_http_cache_turbo_shm_store_locked]='store_locked() constructor did not report hash mismatch'
    [ngx_http_cache_turbo_shm_claim_locked]='claim() constructor did not report hash mismatch'
    [ngx_http_cache_turbo_shm_count_miss_locked]='a hash not matching ngx_crc32_short(key_hash, 32) did not increment test_hash_crc32_mismatch'
    [ngx_http_cache_turbo_shm_l2_neg_set]='l2_neg_set() constructor did not report hash mismatch'
)
for owner in "${owners[@]}"; do
    for kind in guard increment; do
        CTRL_HASH_DIAG_MUTATION="$owner:$kind" bash "$DIR/extract_shm.sh" >/dev/null
        "$CC" -O1 -g -std=c99 -Wall -Wextra -Werror -Wno-unused-parameter \
            -I"$NGINX_SRC/core" -I"$NGINX_SRC/event" -I"$NGINX_SRC/os/unix" \
            -I"$NGINX_OBJS" -c "$NGINX_SRC/core/ngx_rbtree.c" -o "$TMP_DIR/rbtree.o"
        "$CC" -O1 -g -std=c99 -Wall -Wextra -Werror -Wno-unused-parameter \
            -pthread -I"$DIR" -c "$DIR/test_shm_state.c" -o "$TMP_DIR/test.o"
        "$CC" -pthread "$TMP_DIR/test.o" "$TMP_DIR/rbtree.o" -o "$TMP_DIR/test"
        set +e
        "$TMP_DIR/test" >"$OUT" 2>&1
        status=$?
        set -e
        if [ "$status" -eq 0 ] || ! grep -qF "${assertion[$owner]}" "$OUT"; then
            echo "✗ $owner $kind mutation survived its constructor assertion" >&2
            tail -40 "$OUT" >&2
            exit 1
        fi
        echo "✓ $owner $kind mutation fails its constructor assertion"
    done
done
