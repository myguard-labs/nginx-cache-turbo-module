#!/usr/bin/env bash
# Extract real terminal-error compositions from admin, memcached, and Redis.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(realpath "$DIR/../../../src")"
ADMIN_SRC="$SRC_DIR/ngx_http_cache_turbo_admin.c"
MC_SRC="$SRC_DIR/ngx_http_cache_turbo_memcached.c"
REDIS_SRC="$SRC_DIR/ngx_http_cache_turbo_redis.c"
PURGE_SRC="$SRC_DIR/ngx_http_cache_turbo_purge.c"
HDR_SRC="$SRC_DIR/ngx_http_cache_turbo_module.h"
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

# CT-SSCAN-TERMINATE-LEAK: lift a struct definition VERBATIM out of the real
# header, rather than hand-copying its fields into the shim. The completion
# under test reads the await token and the tagpurge, and a hand-copied struct
# that drifts from the real one is precisely the divergence these extractions
# exist to rule out.
extract_struct() {
	file="$1"
	end="$2"

	awk -v source_name="$file" -v end="$end" '
        /^typedef struct/ { start = NR; buf = $0 ORS; next }
        start { buf = buf $0 ORS }
        $0 ~ ("^\\} " end ";$") {
            printf "#line %d \"%s\"\n", start, source_name
            printf "%s", buf
            exit
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
	# CT-SSCAN-TERMINATE-LEAK: the real tagpurge and await-token definitions,
	# lifted verbatim from the header. The awaited UNLINK's completion in
	# purge.c is extracted below and reads both; copying their fields by hand
	# would let the mock drift from production silently.
	extract_struct "$HDR_SRC" 'ngx_http_cache_turbo_tagpurge_t'
	printf '\n'
	extract_struct "$HDR_SRC" 'ngx_http_cache_turbo_tagpurge_await_t'
	printf '\n'
	# TODO-UNLINK-REPLY-WINDOW: walk_suspend is the API a page callback uses to
	# park its walk, and the suspension assertions drive read_sscan through it.
	# Non-static and ngx_int_t, so it needs its own extraction.
	extract_function "$REDIS_SRC" 'ngx_int_t' \
		ngx_http_cache_turbo_redis_walk_suspend
	printf '\n'
	# CT-SSCAN-TERMINATE-LEAK: the shared connection disarm. static ngx_int_t,
	# so it needs its own extraction, and it must precede walk_detach and
	# walk_finish, both of which call it.
	extract_function "$REDIS_SRC" 'static ngx_int_t' \
		ngx_http_cache_turbo_redis_walk_disarm_conn
	printf '\n'
	for fn in \
		ngx_http_cache_turbo_redis_backoff_fail \
		ngx_http_cache_turbo_redis_read_drain \
		ngx_http_cache_turbo_redis_walk_detach \
		ngx_http_cache_turbo_redis_sscan_advance \
		ngx_http_cache_turbo_redis_sscan_resume \
		ngx_http_cache_turbo_redis_read_sscan \
		ngx_http_cache_turbo_redis_walk_finish \
		ngx_http_cache_turbo_redis_get_finish \
		ngx_http_cache_turbo_redis_lock_finish \
		ngx_http_cache_turbo_redis_op_fail; do
		extract_function "$REDIS_SRC" 'static void' "$fn"
		printf '\n'
	done
	# CT-SSCAN-TERMINATE-LEAK: the awaited UNLINK's completion and the r->pool
	# cleanup that neutralizes it. Extracted AFTER sscan_resume, which the
	# completion's request-is-gone arm now calls through the token's mirrored
	# continuation -- the deferred teardown walk_detach hands off to.
	#
	# page_settle is NOT extracted: it walks the member array and issues the
	# SREM, needing the whole L2 surface, and the arm under test returns
	# before reaching it. The test file supplies a counting stub instead.
	for fn in \
		ngx_http_cache_turbo_tag_purge_page_unlinked \
		ngx_http_cache_turbo_tag_purge_await_gone; do
		extract_function "$PURGE_SRC" 'static void' "$fn"
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
	ngx_http_cache_turbo_redis_walk_detach \
	ngx_http_cache_turbo_redis_walk_disarm_conn \
	ngx_http_cache_turbo_redis_sscan_advance \
	ngx_http_cache_turbo_redis_sscan_resume \
	ngx_http_cache_turbo_redis_walk_suspend \
	ngx_http_cache_turbo_redis_read_sscan \
	ngx_http_cache_turbo_redis_walk_finish \
	ngx_http_cache_turbo_redis_get_finish \
	ngx_http_cache_turbo_redis_lock_finish \
	ngx_http_cache_turbo_redis_op_fail \
	ngx_http_cache_turbo_tag_purge_page_unlinked \
	ngx_http_cache_turbo_tag_purge_await_gone; do
	if ! grep -qF "$symbol(" "$OUT"; then
		echo "✗ failed to extract $symbol" >&2
		rm -f "$OUT"
		exit 1
	fi
done

for struct_name in \
	ngx_http_cache_turbo_tagpurge_t \
	ngx_http_cache_turbo_tagpurge_await_t; do
	if ! grep -qF "} $struct_name;" "$OUT"; then
		echo "✗ failed to extract struct $struct_name" >&2
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
	mutate_function_exact ngx_http_cache_turbo_warm_file_prereq_error \
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
	mutate_function_exact ngx_http_cache_turbo_redis_walk_finish \
		'ngx_http_cache_turbo_redis_backoff_fail(op);' '(void) op;' \
		'Redis walk-finish zero-byte failure'
fi

if [ "${CTRL_ERROR_HELPERS_REDIS_DRAIN_CLEAR:-0}" = 1 ]; then
	mutate_function_exact ngx_http_cache_turbo_redis_read_drain \
		'op->unconnected = 0;' 'op->unconnected = 1;' \
		'Redis drain first-byte clear'
fi

# CT-SSCAN-TERMINATE-LEAK controls. The detached teardown is a GUARD with five
# distinct exits, and each gets its own mutation: covering only the primary one
# is not coverage of the guard.
#
#   DETACH_REQUEST  - walk_detach must CLEAR op->request (the dangling pointer)
#   DETACH_TEARDOWN - walk_detach's unsuspended arm must reach op_done
#   DETACH_DEFER    - walk_detach's SUSPENDED arm must NOT tear down inline
#   FINISH_DETACHED - walk_finish's detached guard must skip cb + finalize
#   RESUME_DETACHED - sscan_resume's detached arm must op_done, not walk_finish
#
# Mutations compile the whole guard OFF (`0 &&`) or neutralize the statement,
# rather than substituting a constant, so no variable becomes unused and
# -Werror stays satisfied.
if [ "${CTRL_ERROR_HELPERS_REDIS_DETACH_REQUEST:-0}" = 1 ]; then
	mutate_function_exact ngx_http_cache_turbo_redis_walk_detach \
		'op->request = NULL;' '(void) 0;' 'Redis detach clears op->request'
fi

if [ "${CTRL_ERROR_HELPERS_REDIS_DETACH_TEARDOWN:-0}" = 1 ]; then
	mutate_function_exact ngx_http_cache_turbo_redis_walk_detach \
		'ngx_http_cache_turbo_redis_op_done(op);' '(void) op;' \
		'Redis detach unsuspended teardown'
fi

if [ "${CTRL_ERROR_HELPERS_REDIS_DETACH_DEFER:-0}" = 1 ]; then
	mutate_function_exact ngx_http_cache_turbo_redis_walk_detach \
		'if (op->suspended) {' 'if (0 && op->suspended) {' \
		'Redis detach defers a suspended walk'
fi

if [ "${CTRL_ERROR_HELPERS_REDIS_FINISH_DETACHED:-0}" = 1 ]; then
	mutate_function_exact ngx_http_cache_turbo_redis_walk_finish \
		'if (op->detached) {' 'if (0 && op->detached) {' \
		'Redis walk-finish detached guard'
fi

if [ "${CTRL_ERROR_HELPERS_REDIS_RESUME_DETACHED:-0}" = 1 ]; then
	mutate_function_exact ngx_http_cache_turbo_redis_sscan_resume \
		'if (op->detached) {' 'if (0 && op->detached) {' \
		'Redis sscan-resume detached arm'
fi

# GRIND-C7 controls. read_sscan's `suspended` entry guard is what makes a
# stray event on an UNDISARMABLE suspended connection inert. It has three
# distinct behaviours and each gets its own mutation:
#
#   SUSPENDED_GUARD   - the guard must exist at all: without it a stray read
#                       event falls into walk_finish, which destroys op->pool
#                       under the in-flight UNLINK completion
#   SUSPENDED_TIMEOUT - the guard's timeout arm must CONSUME rev->timedout and
#                       record resume_doomed, not drop the timeout silently
#   SUSPENDED_DOOM    - the guard's timeout arm must DOOM the walk: an expired
#                       read deadline must not let the resume advance
#
# Mutations compile the guard (or its arm) OFF rather than substituting a
# constant, so no variable becomes unused and -Werror stays satisfied.
if [ "${CTRL_ERROR_HELPERS_REDIS_SUSPENDED_GUARD:-0}" = 1 ]; then
	mutate_function_exact ngx_http_cache_turbo_redis_read_sscan \
		'if (op->suspended) {' 'if (0 && op->suspended) {' \
		'Redis SSCAN suspended-walk entry guard'
fi

if [ "${CTRL_ERROR_HELPERS_REDIS_SUSPENDED_TIMEOUT:-0}" = 1 ]; then
	mutate_function_exact ngx_http_cache_turbo_redis_read_sscan \
		'rev->timedout = 0;' '(void) rev;' \
		'Redis SSCAN suspended-walk timeout consume'
fi

if [ "${CTRL_ERROR_HELPERS_REDIS_SUSPENDED_DOOM:-0}" = 1 ]; then
	mutate_function_block_exact ngx_http_cache_turbo_redis_read_sscan \
		'if (op->suspended) {' \
		'op->resume_doomed = 1;' '(void) op;' \
		'Redis SSCAN suspended-walk timeout doom'
fi

# CT-SSCAN-TERMINATE-LEAK (round 3) controls. walk_detach's SUSPENDED arm tears
# down nothing and defers the walk's whole teardown to its continuation, which
# a terminated request can only reach through the mirror in the await token.
# That mirror is a THREE-part contract and each part gets its own mutation:
#
#   AWAIT_RESUME  - the !alive arm must RUN the mirrored continuation. Without
#                   it the deferred op_done never happens: the leak, back in
#                   full, living inside the fix for it.
#   AWAIT_CONSUME - the !alive arm must CONSUME the mirror. Leaving it set is a
#                   second op_done, double-destroying the walk op's pool.
#   AWAIT_LIVE    - the LIVE arm must consume the mirror too. The two arms are
#                   mutually exclusive and exactly one teardown may survive.
#
# Mutations neutralize the statement or compile the call out rather than
# substituting a constant, so no variable becomes unused and -Werror stays
# satisfied.
if [ "${CTRL_ERROR_HELPERS_AWAIT_RESUME:-0}" = 1 ]; then
	mutate_function_block_exact ngx_http_cache_turbo_tag_purge_page_unlinked \
		'if (!aw->alive) {' \
		'resume(rdata, NGX_ERROR);' '(void) rdata;' \
		'terminated await runs the deferred teardown'
fi

if [ "${CTRL_ERROR_HELPERS_AWAIT_CONSUME:-0}" = 1 ]; then
	mutate_function_block_exact ngx_http_cache_turbo_tag_purge_page_unlinked \
		'if (!aw->alive) {' \
		'aw->resume = NULL;' '(void) 0;' \
		'terminated await consumes its continuation mirror'
fi

if [ "${CTRL_ERROR_HELPERS_AWAIT_LIVE:-0}" = 1 ]; then
	# The live arm is delimited by its own unique marker (tp = aw->tp, which
	# only that arm can execute) through the settle call, so the mutation
	# cannot land on the !alive arm's identically-spelled statement.
	mutate_function_block_exact ngx_http_cache_turbo_tag_purge_page_unlinked \
		'tp = aw->tp;' \
		'aw->resume = NULL;' '(void) 0;' \
		'live await consumes its continuation mirror'
fi

if [ "${CTRL_ERROR_HELPERS_REDIS_EXACT_FRAME:-0}" = 1 ]; then
	mutate_function_exact ngx_http_cache_turbo_redis_read_sscan \
		'next != op->rbuf + op->rlen' '0' \
		'Redis SSCAN exact-frame gate'
fi

echo "✓ extracted terminal error compositions → $(basename "$OUT")"
