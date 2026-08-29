#!/usr/bin/env bash
# Extract the real admin whole-zone purge helper and dispatcher so error
# responses cannot fall through to the dispatcher's common 200 reply.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$DIR/../../../src/ngx_http_cache_turbo_admin.c"
OUT="$DIR/generated_admin_purge_all.inc"

awk '
    /^static ngx_int_t$/ { pending = 1; buf = $0 ORS; next }
    pending && /^ngx_http_cache_turbo_(all_purge_(reply|complete)|admin_purge_(all|dispatch))\(/ {
        capture = 1; pending = 0; printf "%s", buf; print; next
    }
    pending { pending = 0; buf = "" }
    capture {
        print
        if ($0 == "}") { capture = 0 }
    }
' "$SRC" >"$OUT"

for fn in \
	ngx_http_cache_turbo_all_purge_reply \
	ngx_http_cache_turbo_all_purge_complete \
	ngx_http_cache_turbo_admin_purge_all \
	ngx_http_cache_turbo_admin_purge_dispatch; do
	if ! grep -qF "$fn(" "$OUT"; then
		echo "✗ failed to extract $fn from $SRC" >&2
		rm -f "$OUT"
		exit 1
	fi
done

echo "✓ extracted admin purge-all reply/callback/helper/dispatcher → $(basename "$OUT")"
