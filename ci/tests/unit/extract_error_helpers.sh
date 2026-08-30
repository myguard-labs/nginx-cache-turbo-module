#!/usr/bin/env bash
# Extract real terminal-error compositions from admin, memcached, and Redis.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(realpath "$DIR/../../../src")"
ADMIN_SRC="$SRC_DIR/ngx_http_cache_turbo_admin.c"
MC_SRC="$SRC_DIR/ngx_http_cache_turbo_memcached.c"
REDIS_SRC="$SRC_DIR/ngx_http_cache_turbo_redis.c"
OUT="$DIR/generated_error_helpers.inc"

extract_function() {
	file="$1"
	type="$2"
	name="$3"

	awk -v source_name="$file" -v type="$type" -v name="$name" '
        $0 == type { pending = 1; start = NR; buf = $0 ORS; next }
        pending && $0 ~ "^" name "\\(" {
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
    ' "$file"
}

{
	extract_function "$ADMIN_SRC" 'static ngx_int_t' \
		'ngx_http_cache_turbo_warm_file_prereq_error'
	printf '\n'
	extract_function "$ADMIN_SRC" 'static ngx_int_t' \
		'ngx_http_cache_turbo_warm_file_schedule_error'
	printf '\n'
	for fn in \
		ngx_http_cache_turbo_mc_backoff_fail \
		ngx_http_cache_turbo_mc_write \
		ngx_http_cache_turbo_mc_read_drain \
		ngx_http_cache_turbo_mc_get_finish \
		ngx_http_cache_turbo_mc_op_fail; do
		extract_function "$MC_SRC" 'static void' "$fn"
		printf '\n'
	done
	for fn in \
		ngx_http_cache_turbo_redis_backoff_fail \
		ngx_http_cache_turbo_redis_read_drain \
		ngx_http_cache_turbo_redis_read_smembers \
		ngx_http_cache_turbo_redis_smembers_finish \
		ngx_http_cache_turbo_redis_get_finish \
		ngx_http_cache_turbo_redis_lock_finish \
		ngx_http_cache_turbo_redis_op_fail; do
		extract_function "$REDIS_SRC" 'static void' "$fn"
		printf '\n'
	done
	printf '#line 1 "%s"\n' "$DIR/test_error_helpers.c"
} >"$OUT"

for symbol in \
	ngx_http_cache_turbo_warm_file_prereq_error \
	ngx_http_cache_turbo_warm_file_schedule_error \
	ngx_http_cache_turbo_mc_backoff_fail \
	ngx_http_cache_turbo_mc_write \
	ngx_http_cache_turbo_mc_read_drain \
	ngx_http_cache_turbo_mc_get_finish \
	ngx_http_cache_turbo_mc_op_fail \
	ngx_http_cache_turbo_redis_backoff_fail \
	ngx_http_cache_turbo_redis_read_drain \
	ngx_http_cache_turbo_redis_read_smembers \
	ngx_http_cache_turbo_redis_smembers_finish \
	ngx_http_cache_turbo_redis_get_finish \
	ngx_http_cache_turbo_redis_lock_finish \
	ngx_http_cache_turbo_redis_op_fail; do
	if ! grep -qF "$symbol(" "$OUT"; then
		echo "✗ failed to extract $symbol" >&2
		rm -f "$OUT"
		exit 1
	fi
done

mutate_exact() {
	from="$1"
	to="$2"
	label="$3"
	escaped_to="${to//&/\\&}"

	if [ "$(grep -cF "$from" "$OUT")" -ne 1 ]; then
		echo "✗ $label mutation did not find exactly one production site" >&2
		rm -f "$OUT"
		exit 1
	fi
	sed -i "s|$from|$escaped_to|" "$OUT"
}

mutate_function_exact() {
	name="$1"
	from="$2"
	to="$3"
	label="$4"
	escaped_to="${to//&/\\&}"
	body=$(sed -n "/^${name}(/,/^}/p" "$OUT")

	if [ "$(grep -cF "$from" <<<"$body")" -ne 1 ]; then
		echo "✗ $label mutation did not find exactly one site in $name" >&2
		rm -f "$OUT"
		exit 1
	fi
	sed -i "/^${name}(/,/^}/ s|$from|$escaped_to|" "$OUT"
}

mutate_function_block_exact() {
	name="$1"
	marker="$2"
	from="$3"
	to="$4"
	label="$5"
	escaped_to="${to//&/\\&}"
	body=$(sed -n "/^${name}(/,/^}/p" "$OUT")
	block=$(sed -n "/$marker/,/return;/p" <<<"$body")

	if [ "$(grep -cF "$from" <<<"$block")" -ne 1 ]; then
		echo "✗ $label mutation did not find exactly one site" >&2
		rm -f "$OUT"
		exit 1
	fi
	sed -i "/^${name}(/,/^}/ { /$marker/,/return;/ s|$from|$escaped_to|; }" \
		"$OUT"
}

if [ "${CTRL_ERROR_HELPERS_WARM_STATUS:-0}" = 1 ]; then
	mutate_exact \
		'ngx_http_cache_turbo_send_json(r, NGX_HTTP_INTERNAL_SERVER_ERROR,' \
		'ngx_http_cache_turbo_send_json(r, NGX_HTTP_OK,' 'warm status'
fi

if [ "${CTRL_ERROR_HELPERS_WARM_BODY:-0}" = 1 ]; then
	mutate_exact 'and have an available/default thread pool' \
		'or have an available/default thread pool' 'warm body'
fi

if [ "${CTRL_ERROR_HELPERS_MC_CONSUME:-0}" = 1 ]; then
	mutate_function_exact ngx_http_cache_turbo_mc_backoff_fail \
		'op->unconnected = 0;' 'op->unconnected = 1;' \
		'memcached consume-once'
fi

if [ "${CTRL_ERROR_HELPERS_MC_WRITE_PREARM:-0}" = 1 ]; then
	target='                      "cache_turbo: memcached write timed out");'
	if [ "$(grep -cF "$target" "$OUT")" -ne 1 ]; then
		echo '✗ memcached write-prearm mutation lost its timeout site' >&2
		exit 1
	fi
	sed -i "/cache_turbo: memcached write timed out/a\\
        ngx_http_cache_turbo_mc_backoff_arm(\&op->clcf->redis_addr,\\
            op->clcf->redis_connect_backoff);" "$OUT"
fi

if [ "${CTRL_ERROR_HELPERS_MC_RESULT:-0}" = 1 ]; then
	mutate_function_exact ngx_http_cache_turbo_mc_op_fail \
		'ngx_http_cache_turbo_mc_get_finish(op, NGX_ERROR, NULL, 0);' \
		'ngx_http_cache_turbo_mc_get_finish(op, NGX_OK, NULL, 0);' \
		'memcached GET result'
fi

if [ "${CTRL_ERROR_HELPERS_MC_CALLBACK:-0}" = 1 ]; then
	mutate_function_exact ngx_http_cache_turbo_mc_op_fail \
		'if (op->request)' 'if (0 && op->request)' \
		'memcached completion callback'
fi

if [ "${CTRL_ERROR_HELPERS_MC_DRAIN_FAIL:-0}" = 1 ]; then
	mutate_function_block_exact ngx_http_cache_turbo_mc_read_drain \
		'if (n == NGX_ERROR || n == 0) {' \
		'ngx_http_cache_turbo_mc_backoff_fail(op);' '(void) op;' \
		'memcached read-drain failure ownership'
fi

if [ "${CTRL_ERROR_HELPERS_REDIS_CONSUME:-0}" = 1 ]; then
	mutate_function_exact ngx_http_cache_turbo_redis_backoff_fail \
		'op->unconnected = 0;' 'op->unconnected = 1;' 'Redis consume-once'
fi

if [ "${CTRL_ERROR_HELPERS_REDIS_SMEMBERS_FAIL:-0}" = 1 ]; then
	mutate_function_exact ngx_http_cache_turbo_redis_smembers_finish \
		'ngx_http_cache_turbo_redis_backoff_fail(op);' '(void) op;' \
		'Redis SMEMBERS zero-byte failure'
fi

if [ "${CTRL_ERROR_HELPERS_REDIS_DRAIN_CLEAR:-0}" = 1 ]; then
	mutate_function_exact ngx_http_cache_turbo_redis_read_drain \
		'op->unconnected = 0;' 'op->unconnected = 1;' \
		'Redis drain first-byte clear'
fi

echo "✓ extracted terminal error compositions → $(basename "$OUT")"
