#!/usr/bin/env bash
# Prove testkit-stage's source inventory cannot bless a partial find result.
set -euo pipefail

root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Extract the live helper rather than copying it: the control must exercise the
# exact producer-status path testkit-stage uses after its build completes.
sed -n '/^newest_of() {/,/^}/p' "$root/ci/tools/testkit-stage.sh" >"$tmp/newest_of.sh"
grep -q '^newest_of() {' "$tmp/newest_of.sh" || {
	echo 'stage inventory control: could not extract newest_of' >&2
	exit 1
}

mkdir -p "$tmp/bin" "$tmp/src"
printf 'int source;\n' >"$tmp/src/one.c"
cat >"$tmp/bin/find" <<'EOF'
#!/usr/bin/env bash
printf '%s\0' "${FIND_PARTIAL_PATH:?}"
exit 1
EOF
chmod +x "$tmp/bin/find"

set +e
# shellcheck disable=SC2016  # $1/$2 are deliberately evaluated by child bash.
out="$(env PATH="$tmp/bin:$PATH" FIND_PARTIAL_PATH="$tmp/src/one.c" \
	bash -c '. "$1"; newest_of 1 "$2"' _ "$tmp/newest_of.sh" "$tmp/src" 2>&1)"
status=$?
set -e
if [ "$status" -ne 2 ]; then
	printf 'stage inventory control: partial producer expected exit 2, got %s: %s\n' \
		"$status" "$out" >&2
	exit 1
fi
if [ -n "$out" ]; then
	printf 'stage inventory control: partial producer printed success text: %s\n' "$out" >&2
	exit 1
fi

out="$(bash -c '. "$1"; newest_of 1 "$2"' _ "$tmp/newest_of.sh" "$tmp/src")"
case "$out" in
*" $tmp/src/one.c") ;;
*)
	printf 'stage inventory control: successful inventory changed output: %s\n' "$out" >&2
	exit 1
	;;
esac

# The caller must clear an inherited error status before a successful first
# inventory. Exercise that state with the live helper, and pin the reset next
# to the live command substitution so this cannot become a test-only property.
if ! awk '
    /^ct_ref="\$\(newest_of 1 / {
        found = 1
        if (previous != "unset newest_rc") bad = 1
        exit
    }
    /^[[:space:]]*$/ { next }
    { previous = $0 }
    END { exit !found || bad }
' "$root/ci/tools/testkit-stage.sh"; then
	printf '%s\n' 'stage inventory control: first inventory must clear inherited newest_rc' >&2
	exit 1
fi
out="$(bash -c '
	. "$1"
	newest_rc=2
	unset newest_rc
	ct_ref="$(newest_of 1 "$2")" || newest_rc=$?
	[ "${newest_rc:-0}" -eq 0 ] || exit 2
	printf "%s\\n" "$ct_ref"
' _ "$tmp/newest_of.sh" "$tmp/src")"
case "$out" in
*" $tmp/src/one.c") ;;
*)
	printf 'stage inventory control: inherited newest_rc poisoned successful inventory: %s\n' "$out" >&2
	exit 1
	;;
esac
printf 'stage inventory control: partial producer is exit 2; normal discovery retained\n'
