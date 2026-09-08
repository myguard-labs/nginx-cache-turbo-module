#!/usr/bin/env bash
# Prove each terminal-error composition rejects its contract-breaking mutant.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CC="${CC:-cc}"
TMP_DIR="$(mktemp -d)"
OUT="$TMP_DIR/control.out"

restore() {
	bash "$DIR/extract_error_helpers.sh" >/dev/null
	rm -rf "$TMP_DIR"
}
trap restore EXIT

run_mutant() {
	control="$1"
	expected="$2"
	label="$3"

	env "$control=1" bash "$DIR/extract_error_helpers.sh" >/dev/null
	"$CC" -g -O0 -Wall -Wextra -Werror -I"$DIR" \
		"$DIR/test_error_helpers.c" -o "$TMP_DIR/test_error_helpers"

	set +e
	"$TMP_DIR/test_error_helpers" >"$OUT" 2>&1
	status=$?
	set -e

	if [ "$status" -eq 0 ]; then
		echo "✗ $label mutation survived its negative control" >&2
		exit 1
	fi
	if ! grep -qF "$expected" "$OUT"; then
		echo "✗ $label mutation missed assertion: $expected" >&2
		tail -30 "$OUT" >&2
		exit 1
	fi

	echo "✓ $label mutation fails its exact assertion"
}

run_mutant CTRL_ERROR_HELPERS_WARM_STATUS \
	'warm prerequisite response must use HTTP 500' 'warm status'
run_mutant CTRL_ERROR_HELPERS_WARM_BODY \
	'warm prerequisite response body must retain its exact JSON contract' \
	'warm response body'
run_mutant CTRL_ERROR_HELPERS_MC_CONSUME \
	'memcached op_fail -> real get_finish must arm exactly once' \
	'memcached consume-once'
run_mutant CTRL_ERROR_HELPERS_MC_WRITE_PREARM \
	'memcached write timeout composition must arm exactly once' \
	'memcached write pre-arm'
run_mutant CTRL_ERROR_HELPERS_MC_RESULT \
	'memcached failed GET must publish exact error completion state' \
	'memcached GET result'
run_mutant CTRL_ERROR_HELPERS_MC_CALLBACK \
	'memcached failed GET must publish exact error completion state' \
	'memcached completion callback'
run_mutant CTRL_ERROR_HELPERS_MC_DRAIN_FAIL \
	'memcached drain zero-byte failure must arm once and consume state' \
	'memcached read-drain failure ownership'
run_mutant CTRL_ERROR_HELPERS_REDIS_CONSUME \
	'Redis op_fail -> real get_finish must arm exactly once' \
	'Redis consume-once'
run_mutant CTRL_ERROR_HELPERS_REDIS_SMEMBERS_FAIL \
	'Redis SSCAN zero-byte fill failure must arm exactly once' \
	'Redis walk-finish zero-byte failure'
run_mutant CTRL_ERROR_HELPERS_REDIS_DRAIN_CLEAR \
	'Redis drain first reply byte must clear, never arm, backoff state' \
	'Redis drain first-byte clear'
run_mutant CTRL_ERROR_HELPERS_REDIS_DETACH_REQUEST \
	'the request-teardown cleanup must CLEAR op->request' \
	'Redis detach clears op->request'
run_mutant CTRL_ERROR_HELPERS_REDIS_DETACH_TEARDOWN \
	'an UNSUSPENDED detached walk must reach op_done exactly once' \
	'Redis detach unsuspended teardown'
run_mutant CTRL_ERROR_HELPERS_REDIS_DETACH_DEFER \
	'a SUSPENDED detached walk must NOT be torn down inline' \
	'Redis detach defers a suspended walk'
run_mutant CTRL_ERROR_HELPERS_REDIS_FINISH_DETACHED \
	'walk_finish on a DETACHED walk must not call the page callback' \
	'Redis walk-finish detached guard'
# The discriminating assertion, not the op_done count: with the detached arm
# compiled out, an advance that cannot build its next page still falls into
# walk_finish and reaches op_done once. scan_pages is what separates them.
run_mutant CTRL_ERROR_HELPERS_REDIS_RESUME_DETACHED \
	"a DETACHED walk's resume must NOT enter sscan_advance" \
	'Redis sscan-resume detached arm'
run_mutant CTRL_ERROR_HELPERS_REDIS_EXACT_FRAME \
	'SSCAN must reject trailing RESP bytes before parsing' \
	'Redis SSCAN exact-frame gate'

# GRIND-C7: the `suspended` entry guard. The discriminating assertion for the
# guard itself is ngx_test_members_calls -- walk_finish runs the TERMINAL
# callback before op_done, and reaching that callback is what a stray event on
# a parked walk must never do.
run_mutant CTRL_ERROR_HELPERS_REDIS_SUSPENDED_GUARD \
	'a READ event on a SUSPENDED walk must not reach walk_finish' \
	'Redis SSCAN suspended-walk entry guard'
run_mutant CTRL_ERROR_HELPERS_REDIS_SUSPENDED_TIMEOUT \
	'a TIMEOUT on a SUSPENDED walk must CONSUME the flag' \
	'Redis SSCAN suspended-walk timeout consume'
run_mutant CTRL_ERROR_HELPERS_REDIS_SUSPENDED_DOOM \
	'a TIMEOUT on a SUSPENDED walk must record the doom' \
	'Redis SSCAN suspended-walk timeout doom'

# CT-SSCAN-TERMINATE-LEAK (round 3): the mirrored continuation. Each assertion
# named here is a COUNT of continuation invocations -- 0 is the leak, 2 is a
# double teardown of the walk op's pool -- so neither the guarded nor the
# unguarded path can satisfy it vacuously.
run_mutant CTRL_ERROR_HELPERS_AWAIT_RESUME \
	'must run the walk'"'"'s mirrored continuation EXACTLY ONCE' \
	'terminated await runs the deferred teardown'
run_mutant CTRL_ERROR_HELPERS_AWAIT_CONSUME \
	'a second completion must not run the continuation again' \
	'terminated await consumes its continuation mirror'
run_mutant CTRL_ERROR_HELPERS_AWAIT_LIVE \
	'the live arm must consume the token'"'"'s mirror too' \
	'live await consumes its continuation mirror'

# GRIND-C7 (re-arm): the assertion named here is ngx_test_add_event_calls -- a
# count of GENUINE ngx_add_event registrations. The shim's
# ngx_handle_read_event is ported verbatim from nginx's `!active && !ready`
# gate, so neither mutant can satisfy it vacuously: with `ready` left stale the
# gate is false and the count stays 0.
run_mutant CTRL_ERROR_HELPERS_REDIS_RESUME_READY_CLEAR \
	'a resumed walk must genuinely RE-REGISTER its read event' \
	'Redis sscan-advance clears stale read readiness'
run_mutant CTRL_ERROR_HELPERS_REDIS_RESUME_REARM \
	'a resumed walk must genuinely RE-REGISTER its read event' \
	'Redis sscan-advance re-arms the read event'
