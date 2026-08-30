#!/usr/bin/env bash
# Partial producer output must fail the inventory gates, never look clean.
set -euo pipefail

root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"

cat >"$tmp/bin/find" <<'EOF'
#!/usr/bin/env bash
case " $* " in
    *' .github/workflows '*) printf '%s\0' .github/workflows/build-test.yml ;;
    *'/ci/prober-scenarios '*) printf '%s\0' alloc-per-request ;;
    *) printf '%s\0' unexpected ;;
esac
exit 1
EOF
chmod +x "$tmp/bin/find"

assert_partial_fails() {
	local name="$1" success="$2" out status
	shift 2
	set +e
	out="$(env PATH="$tmp/bin:$PATH" "$@" 2>&1)"
	status=$?
	set -e
	if [ "$status" -ne 2 ]; then
		printf '%s: partial producer expected exit 2, got %s: %s\n' \
			"$name" "$status" "$out" >&2
		exit 1
	fi
	if grep -qF -- "$success" <<<"$out"; then
		printf '%s: partial producer printed success text: %s\n' "$name" "$out" >&2
		exit 1
	fi
}

assert_partial_fails 'lint-ci-ports' 'lint-ci-ports: OK' \
	bash "$root/ci/tools/lint-ci-ports.sh"
assert_partial_fails 'testkit scenario inventory' 'scenarios and host guard verified' \
	bash "$root/ci/tests/unit/check_testkit_contract.sh" "$root"

printf 'producer status controls: partial inventories exit 2 without success text\n'
