#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
tmp=""

# shellcheck disable=SC1091
source "$ROOT/ci/tools/testkit-scenarios.sh"
# shellcheck disable=SC1091
source "$ROOT/ci/tools/testkit-host-guard.sh"

fail() {
    printf 'testkit contract: %s\n' "$*" >&2
    exit 1
}

declare -A seen=()
for scenario in "${TESTKIT_SCENARIOS_ALL[@]}"; do
    [ -z "${seen[$scenario]:-}" ] || fail "duplicate scenario: $scenario"
    seen[$scenario]=1
    if [ "$scenario" != consumer-cache-turbo ]; then
        [ -d "$ROOT/ci/prober-scenarios/$scenario" ] || \
            fail "listed local scenario is missing: $scenario"
    fi
done

# Materialise before consuming: the exit status of a process substitution is
# mapfile/read's, not find's. A directory walk that writes one real scenario
# and then fails must be a gate error (2), never a partial clean inventory.
# NUL records preserve a scenario path exactly through discovery and sorting.
inventory_dir="$(mktemp -d)" || {
    printf 'testkit contract: cannot create scenario inventory directory\n' >&2
    exit 2
}
trap 'rm -rf "$inventory_dir" "${tmp:-}"' EXIT
inventory_raw="$inventory_dir/scenarios.raw"
inventory_sorted="$inventory_dir/scenarios.sorted"
if ! find "$ROOT/ci/prober-scenarios" -mindepth 1 -maxdepth 1 -type d \
    -printf '%f\0' >"$inventory_raw"; then
    printf 'testkit contract: scenario inventory failed -- refusing partial result\n' >&2
    exit 2
fi
if ! LC_ALL=C sort -z "$inventory_raw" >"$inventory_sorted"; then
    printf 'testkit contract: scenario inventory sort failed -- refusing partial result\n' >&2
    exit 2
fi
while IFS= read -r -d '' scenario; do
    [ -n "${seen[$scenario]:-}" ] || fail "unlisted local scenario: $scenario"
done <"$inventory_sorted"

for lane_name in PLAIN SANITIZED VALGRIND ANGIE; do
    lane_var="TESTKIT_SCENARIOS_${lane_name}[@]"
    lane=("${!lane_var}")
    for scenario in "${lane[@]}"; do
        [ -n "${seen[$scenario]:-}" ] || \
            fail "$lane_name lane names unknown scenario: $scenario"
    done
done

tmp="$(mktemp -d)"
mkdir -p "$tmp/1" "$tmp/2" "$tmp/3" "$tmp/4" "$tmp/5"
printf '/usr/bin/pbuilder\0--build\0' >"$tmp/1/cmdline"
printf '/usr/bin/perl\0/usr/bin/dpkg-buildpackage\0-b\0' >"$tmp/2/cmdline"
printf '/bin/bash\0/usr/sbin/pbuilder\0--build\0' >"$tmp/3/cmdline"
printf '/usr/bin/bash\0-c\0watch pbuilder and dpkg-buildpackage\0' >"$tmp/4/cmdline"
printf '/usr/bin/echo\0pbuilder\0' >"$tmp/5/cmdline"

TESTKIT_PROC_ROOT="$tmp"
export TESTKIT_PROC_ROOT
testkit_package_build_running || fail "real package build was not detected"
rm -rf "$tmp/1" "$tmp/2" "$tmp/3"
if testkit_package_build_running; then
    fail "prose mentioning a package build was treated as a live build"
fi
TESTKIT_PROC_ROOT="$tmp/missing"
export TESTKIT_PROC_ROOT
guard_rc=0
testkit_package_build_running || guard_rc=$?
[ "$guard_rc" -eq 2 ] || fail "uninspectable process root did not fail closed"
mkdir -p "$tmp/empty/6"
: >"$tmp/empty/6/cmdline"
TESTKIT_PROC_ROOT="$tmp/empty"
export TESTKIT_PROC_ROOT
guard_rc=0
testkit_package_build_running || guard_rc=$?
[ "$guard_rc" -eq 2 ] || fail "empty process data did not fail closed"
mkdir -p "$tmp/unreadable/7"
printf '/usr/bin/echo\0' >"$tmp/unreadable/7/cmdline"
chmod 000 "$tmp/unreadable/7/cmdline"
guard_rc=0
if [ "$(id -u)" -eq 0 ]; then
    command -v setpriv >/dev/null 2>&1 || \
        fail "setpriv is required to test unreadable process data as root"
    cp "$ROOT/ci/tools/testkit-host-guard.sh" "$tmp/host-guard.sh"
    chmod 755 "$tmp" "$tmp/unreadable" "$tmp/unreadable/7"
    # $1 belongs to the child shell, not this script.
    # shellcheck disable=SC2016
    setpriv --reuid=65534 --regid=65534 --clear-groups \
        env TESTKIT_PROC_ROOT="$tmp/unreadable" \
        bash -c '. "$1"; testkit_package_build_running' _ \
        "$tmp/host-guard.sh" || guard_rc=$?
else
    TESTKIT_PROC_ROOT="$tmp/unreadable"
    export TESTKIT_PROC_ROOT
    testkit_package_build_running || guard_rc=$?
fi
[ "$guard_rc" -eq 2 ] || fail "unreadable process data did not fail closed"
chmod 600 "$tmp/unreadable/7/cmdline"

for path in \
    src/ngx_http_cache_turbo_module.c \
    ci/prober-scenarios/reload-cycle/driver.sh \
    ci/tools/testkit-scenarios.sh \
    .github/workflows/ci-deep.yml; do
    printf '%s\n' "$path" | "$ROOT/ci/tools/testkit-impact-filter.sh" || \
        fail "testkit impact filter missed: $path"
done
for path in \
    README.md \
    ci/tools/test_runtime.py \
    ci/tools/testkit-run.sh.backup \
    .github/workflows/ci.yml.backup \
    docs/design.md; do
    if printf '%s\n' "$path" | "$ROOT/ci/tools/testkit-impact-filter.sh"; then
        fail "testkit impact filter overmatched: $path"
    fi
done

printf 'testkit contract: %d scenarios and host guard verified\n' \
    "${#TESTKIT_SCENARIOS_ALL[@]}"
