#!/usr/bin/env bash
# Extract the production compare-and-delete and body-filter rollback helpers.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHM_SRC="$DIR/../../../src/ngx_http_cache_turbo_shm.c"
FILTER_SRC="$DIR/../../../src/ngx_http_cache_turbo_filters.c"
OUT="$DIR/generated_marker_rollback.inc"

extract_function() {
	file="$1"
	type="$2"
	name="$3"

	awk -v type="$type" -v name="$name" '
        $0 == type { pending = 1; buf = $0 ORS; next }
        pending && $0 ~ "^" name "\\(" {
            capture = 1; pending = 0; printf "%s", buf; print; next
        }
        pending { pending = 0; buf = "" }
        capture {
            print
            if ($0 == "}") { capture = 0; exit }
        }
    ' "$file"
}

extract_function "$SHM_SRC" 'ngx_int_t' \
	'ngx_http_cache_turbo_shm_purge_if_blob' >"$OUT"
printf '\n' >>"$OUT"
extract_function "$FILTER_SRC" 'static void' \
	'ngx_http_cache_turbo_body_filter_rollback_store' >>"$OUT"

for symbol in \
	ngx_http_cache_turbo_shm_purge_if_blob \
	ngx_http_cache_turbo_body_filter_rollback_store; do
	if ! grep -qF "$symbol(" "$OUT"; then
		echo "✗ failed to extract $symbol" >&2
		rm -f "$OUT"
		exit 1
	fi
done

# Pin the caller contract as well as the extracted helpers: the marker-failure
# arm must pass the token into the compare-and-delete rollback, and the store
# call must request that token.  Otherwise the helper test could stay green
# while production silently stopped using it.
failure_arm=$(sed -n \
	'/if (ngx_http_cache_turbo_body_filter_varidx_store/,/return NGX_DECLINED;/p' \
	"$FILTER_SRC")
if ! grep -qF 'ngx_http_cache_turbo_body_filter_rollback_store' \
	<<<"$failure_arm"; then
	echo "✗ marker failure no longer invokes compare-and-delete rollback" >&2
	rm -f "$OUT"
	exit 1
fi
if grep -qF 'purge_key' <<<"$failure_arm"; then
	echo "✗ marker failure regressed to unconditional purge_key" >&2
	rm -f "$OUT"
	exit 1
fi

store_call=$(sed -n \
	'/if (ngx_http_cache_turbo_body_filter_store/,/== NGX_DECLINED)/p' \
	"$FILTER_SRC")
if ! grep -qF '&stored_data' <<<"$store_call"; then
	echo "✗ auto-Vary store no longer requests its pinned rollback token" >&2
	rm -f "$OUT"
	exit 1
fi

# Both ordinary and conditional shm stores must acquire the identity token
# while still holding the mutex and publish that exact blob pointer.  Missing
# the acquire reopens slab-address ABA; missing the out-write makes rollback a
# no-op.  Check both wrappers independently so one cannot mask drift in the
# other.
for store_name in \
	ngx_http_cache_turbo_shm_store \
	ngx_http_cache_turbo_shm_store_if; do
	store_body=$(extract_function "$SHM_SRC" 'ngx_int_t' "$store_name")
	if ! grep -qF 'ngx_http_cache_turbo_blob_acquire(written->data);' \
		<<<"$store_body" \
		|| ! grep -qF '*stored_data = written->data;' <<<"$store_body"; then
		echo "✗ $store_name no longer pins/publishes the exact stored blob" >&2
		rm -f "$OUT"
		exit 1
	fi
done

# Falsifiable control: remove only the identity comparison from the generated
# slice.  The barrier race must then delete B and fail its exact assertion.
if [ "${CTRL_MARKER_ROLLBACK_UNCONDITIONAL:-0}" = 1 ]; then
	line='    if (ctn == NULL || ctn->data != stored_data) {'
	if [ "$(grep -cF "$line" "$OUT")" -ne 1 ]; then
		echo "✗ unconditional-rollback mutation could not find compare" >&2
		rm -f "$OUT"
		exit 1
	fi
	sed -i \
		's/if (ctn == NULL || ctn->data != stored_data)/if (ctn == NULL)/' \
		"$OUT"
fi

# The isolated rollback is an operator-visible partial-store event.  Removing
# only the warning must fail the exact logging assertion without changing the
# compare-and-delete behavior.
if [ "${CTRL_MARKER_ROLLBACK_NO_WARN:-0}" = 1 ]; then
	line='    if (clcf->l1->purge_if_blob(z, store_key, hash, stored_data) > 0) {'
	if [ "$(grep -cF "$line" "$OUT")" -ne 1 ]; then
		echo "✗ rollback-warning mutation could not find its production branch" >&2
		rm -f "$OUT"
		exit 1
	fi
	sed -i \
		's/if (clcf->l1->purge_if_blob(z, store_key, hash, stored_data) > 0)/if (0 \&\& clcf->l1->purge_if_blob(z, store_key, hash, stored_data) > 0)/' \
		"$OUT"
fi

echo "✓ extracted marker rollback helpers → $(basename "$OUT")"
