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
	'Redis SMEMBERS zero-byte fill failure must arm exactly once' \
	'Redis SMEMBERS zero-byte failure'
run_mutant CTRL_ERROR_HELPERS_REDIS_DRAIN_CLEAR \
	'Redis drain first reply byte must clear, never arm, backoff state' \
	'Redis drain first-byte clear'
