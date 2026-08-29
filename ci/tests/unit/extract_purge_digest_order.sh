#!/usr/bin/env bash
# Extract the real PURGE request + auto-Vary helper so digest preflight ordering
# is tested against production code rather than a mirrored state machine.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$DIR/../../../src/ngx_http_cache_turbo_purge.c"
OUT="$DIR/generated_purge_digest_order.inc"

awk '
    /^(static )?ngx_int_t$/ { pending = 1; buf = $0 ORS; next }
    pending && /^ngx_http_cache_turbo_purge_(auto_vary|request)\(/ {
        capture = 1; pending = 0; printf "%s", buf; print; next
    }
    pending { pending = 0; buf = "" }
    capture {
        print
        if ($0 == "}") { capture = 0 }
    }
' "$SRC" >"$OUT"

for fn in ngx_http_cache_turbo_purge_auto_vary \
	ngx_http_cache_turbo_purge_request; do
	if ! grep -qF "$fn(" "$OUT"; then
		echo "✗ failed to extract $fn from $SRC" >&2
		rm -f "$OUT"
		exit 1
	fi
done

# Falsifiable partial-purge diagnostic control: the generation-store failure
# occurs after the base delete, so suppressing only its warning must trip the
# exact operator-visible contract assertion.
if [ "${CTRL_PURGE_NO_PARTIAL_WARN:-0}" = 1 ]; then
	warn_line='        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,'
	if [ "$(grep -cF "$warn_line" "$OUT")" -ne 1 ]; then
		echo "✗ partial-purge warning mutation could not find its production log" >&2
		rm -f "$OUT"
		exit 1
	fi
	sed -i \
		's/        ngx_log_error(NGX_LOG_WARN/        if (0) ngx_log_error(NGX_LOG_WARN/' \
		"$OUT"
fi

echo "✓ extracted PURGE digest-order path → $(basename "$OUT")"
