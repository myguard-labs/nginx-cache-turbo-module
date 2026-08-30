#!/usr/bin/env bash
# Extract the production breaker retry-attempt counter with source attribution.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$DIR/../../../src/ngx_http_cache_turbo_module.c"
SRC_CANON="$(realpath "$SRC")"
OUT="$DIR/generated_breaker_retry.inc"

awk -v source_name="$SRC_CANON" '
    $0 == "ngx_uint_t" { pending = 1; start = NR; buf = $0 ORS; next }
    pending && /^ngx_http_cache_turbo_breaker_retry_failures\(/ {
        capture = 1
        pending = 0
        printf "#line %d \"%s\"\n", start, source_name
        printf "%s", buf
        print
        next
    }
    pending { pending = 0; buf = "" }
    capture {
        print
        if ($0 == "}") { capture = 0; exit }
    }
' "$SRC" >"$OUT"

if ! grep -qF 'ngx_http_cache_turbo_breaker_retry_failures(' "$OUT"; then
	echo "✗ failed to extract breaker retry counter from $SRC" >&2
	rm -f "$OUT"
	exit 1
fi

# Falsifiable control: including the final state double-counts the response
# already handled by the caller. The exact current-attempt assertion must fail.
if [ "${CTRL_BREAKER_RETRY_INCLUDE_CURRENT:-0}" = 1 ]; then
	line='    n     = r->upstream_states->nelts - 1; /* exclude the final/current attempt */'
	if [ "$(grep -cF "$line" "$OUT")" -ne 1 ]; then
		echo "✗ breaker retry mutation did not find its loop bound" >&2
		rm -f "$OUT"
		exit 1
	fi
	sed -i 's/r->upstream_states->nelts - 1/r->upstream_states->nelts/' "$OUT"
fi

echo "✓ extracted breaker retry counter → $(basename "$OUT")"
