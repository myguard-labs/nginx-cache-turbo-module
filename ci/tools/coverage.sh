#!/usr/bin/env bash
#
# Measure gcov line+branch coverage of the cache-turbo MODULE sources by
# running the full runtime suite against a gcov-instrumented nginx.
#
#   ci/tools/coverage.sh [flavor] [version]
#     flavor : nginx | angie   (default nginx)
#     version: upstream version (default .github/versions.env NGINX_VERSION)
#
# Steps:
#   1. ci-build.sh <flavor> <version> coverage  -> instrumented .so + binary,
#      .gcno emitted under objs/addon/src/.
#   2. run test_runtime.py (the full suite: L2 redis+memcached + fault
#      injection) against that binary. nginx flushes .gcda on graceful SIGTERM
#      exit, so every worker's arcs land next to the .gcno.
#   3. gcovr over objs/addon/src, filtered to the module's own src/ tree only
#      (nginx core objects are instrumented too but are not our coverage target).
#
# Env:
#   COVERAGE_FAIL_UNDER  - if set, gcovr exits non-zero below this line %.
#                          Unset by default: this is a REPORT, not a gate (the
#                          repo policy is meaningful tests over a % threshold,
#                          see feedback-coverage-badge-vs-test-integrity). CI
#                          uploads the HTML/summary; it does not fail on a number.
#   REDIS_SERVER / MEMCACHED_SERVER - binary paths (default /usr/bin/...).
#   COVERAGE_OUT         - output dir (default coverage-report under the module).
#   TESTKIT_ROOT         - when set, also stage nginx-module-testkit coverage,
#                          run the canonical scenario matrix, and publish
#                          prober-only plus merged runtime+prober reports.
#   TEST_BASE_PORT       - base port handed to test_runtime.py --port (default
#                          18880, the suite's own default). CI sets this to a
#                          band exclusive to the coverage job so it cannot
#                          collide with another runtime-bearing job on the
#                          same shared self-hosted runner (AUD-CIPORT1).
#
set -euo pipefail

if ! command -v gcovr >/dev/null 2>&1; then
    echo "coverage: gcovr is required" >&2
    exit 2
fi
GCOVR_MAJOR="$(gcovr --version | awk 'NR == 1 { split($2, v, "."); print v[1] }')"
if [ -z "$GCOVR_MAJOR" ] || [ "$GCOVR_MAJOR" -lt 7 ]; then
    echo "coverage: gcovr >= 7 is required for GCC 14 gcov output" >&2
    exit 2
fi

FLAVOR="${1:-nginx}"
if [ -f .github/versions.env ]; then
    # shellcheck disable=SC1091
    source .github/versions.env
fi
VERSION="${2:-${NGINX_VERSION:-1.31.1}}"
MODULE_DIR="$PWD"
ROOT="${BUILD_ROOT:-$PWD/.build}"
DIR="${FLAVOR}-${VERSION}"
OBJDIR="$ROOT/$DIR/objs"
ADDON="$OBJDIR/addon/src"
OUT="${COVERAGE_OUT:-$MODULE_DIR/coverage-report}"
REDIS_SERVER="${REDIS_SERVER:-/usr/bin/redis-server}"
MEMCACHED_SERVER="${MEMCACHED_SERVER:-/usr/bin/memcached}"
TEST_BASE_PORT="${TEST_BASE_PORT:-18880}"

# 1. instrumented build
bash "$MODULE_DIR/ci/tools/ci-build.sh" "$FLAVOR" "$VERSION" coverage

if [ ! -d "$ADDON" ]; then
    echo "coverage: no instrumented module objects at $ADDON" >&2
    exit 1
fi

# Fresh counters: drop any .gcda from a previous run so the report reflects
# THIS suite only.
find "$ADDON" -name '*.gcda' -delete 2>/dev/null || true

# 2. run the full runtime suite against the instrumented binary. Faults on so
# the fault-injection paths are exercised and counted. TEST_NGINX_TIMEOUT must
# be generous or clean tests "fail" on slow instrumented seeding.
export TEST_NGINX_TIMEOUT="${TEST_NGINX_TIMEOUT:-30}"
python3 "$MODULE_DIR/ci/tools/test_runtime.py" \
    --nginx-binary "$OBJDIR/$([ "$FLAVOR" = angie ] && echo angie || echo nginx)" \
    --module "$OBJDIR/ngx_http_cache_turbo_module.so" \
    --redis-server "$REDIS_SERVER" \
    --memcached-server "$MEMCACHED_SERVER" \
    --port "$TEST_BASE_PORT" \
    --fault-injection

# 2b. extracted production-slice unit tests cover boundary/error paths the HTTP
# suite cannot drive deterministically. COVERAGE=1 emits their instrumented
# objects under ci/tests/unit, separate from the booted-nginx object tree.
UNIT_DIR="$MODULE_DIR/ci/tests/unit"
# Fresh unit counters: drop any .gcda from a previous run so the unit report
# reflects THIS run only.
find "$UNIT_DIR" -name '*.gcda' -delete 2>/dev/null || true
COVERAGE=1 bash "$UNIT_DIR/run.sh"

# 3. report. Filter to the module's own sources; branch coverage included.
#
# The instrumented build also emits .gcda for every nginx CORE object (they
# link the same --coverage runtime). gcovr walks ALL of them and errors on the
# core sources because they live under the unpacked nginx tree, not our root
# ("Cannot open source file src/core/ngx_palloc.c"). We only care about the
# module's six objects under addon/src, so:
#   addon/src as a positional path    restricts the object scan to those,
#   --object-directory addon/src      resolves their notes/data files,
#       spelled the portable way ON PURPOSE: the --gcov-object-directory alias
#       only exists on gcovr >= 7.0, and ci-deep.yml installs gcovr unpinned
#       from apt. On an older runner the long spelling is an unknown flag and
#       the report dies; --object-directory is accepted by both.
#   --filter src/                      restricts the report to our sources,
#   --gcov-ignore-errors=all           tolerates gcov's "cannot open source"
#       on the nginx HEADERS the module includes (ngx_string.h, etc. — pulled
#       into every module .gcda). Without it gcovr discards the WHOLE datafile
#       on a single unresolved header and silently drops module.c/redis.c/
#       memcached.c from the report (=all keeps them; module sources still
#       resolve fine against $MODULE_DIR/src).
mkdir -p "$OUT"
GCOVR_ARGS=(
    "$ADDON"
    --root "$MODULE_DIR"
    --filter "$MODULE_DIR/src/"
    --object-directory "$ADDON"
    --gcov-ignore-errors=all
    --merge-mode-functions=merge-use-line-min
    --branches
    --decisions
    --print-summary
    --html-details "$OUT/index.html"
    --xml "$OUT/coverage.xml"
    --txt "$OUT/coverage.txt"
    --json-pretty
    --json "$OUT/coverage.json"
)
if [ -n "${COVERAGE_FAIL_UNDER:-}" ]; then
    GCOVR_ARGS+=(--fail-under-line "$COVERAGE_FAIL_UNDER")
fi

gcovr "${GCOVR_ARGS[@]}"
echo "coverage: suite report written to $OUT (index.html, coverage.xml, coverage.txt)"

# 2c. extracted-unit report. The positional search path is intentional:
# --object-directory helps gcov resolve files but does not restrict its scan.
# Filtering to src/ excludes the test drivers and shims.
UNIT_OUT="$OUT/unit"
mkdir -p "$UNIT_OUT"
gcovr \
    "$UNIT_DIR" \
    --root "$MODULE_DIR" \
    --filter "$MODULE_DIR/src/" \
    --object-directory "$UNIT_DIR" \
    --gcov-ignore-errors=all \
    --merge-mode-functions=merge-use-line-min \
    --branches \
    --decisions \
    --print-summary \
    --html-details "$UNIT_OUT/index.html" \
    --xml "$UNIT_OUT/coverage.xml" \
    --txt "$UNIT_OUT/coverage.txt" \
    --json-pretty \
    --json "$UNIT_OUT/coverage.json"
python3 - "$UNIT_OUT/coverage.json" <<'PY'
import json
import sys

required = {
    "ngx_http_cache_turbo_warm_file_prereq_error",
    "ngx_http_cache_turbo_mc_op_fail",
}
data = json.load(open(sys.argv[1], encoding="utf-8"))
covered = {
    function["name"]
    for source in data["files"]
    for function in source.get("functions", [])
    if function.get("execution_count", 0) > 0
}
missing = sorted(required - covered)
if missing:
    raise SystemExit("coverage: extracted unit functions missing: " + ", ".join(missing))
PY
echo "coverage: extracted-unit report written to $UNIT_OUT"

# 4. Optional nginx-module-testkit profile. CI supplies TESTKIT_ROOT from its
# pinned sibling checkout. Keep the raw profiles separate so a reviewer can
# tell which harness reaches a function, then merge their tracefiles to expose
# functions missed by BOTH suites instead of comparing two percentages by eye.
if [ -n "${TESTKIT_ROOT:-}" ]; then
    TESTKIT_ROOT="$(cd "$TESTKIT_ROOT" && pwd)"
    export TESTKIT_ROOT

    bash "$MODULE_DIR/ci/tools/testkit-stage.sh" \
        --flavor "$FLAVOR" --version "$VERSION" --coverage

    TESTKIT_ADDON="$ROOT/${FLAVOR}-${VERSION}-testkit-coverage/objs/addon/src"
    find "$TESTKIT_ADDON" -name '*.gcda' -delete 2>/dev/null || true

    # shellcheck disable=SC1091
    source "$MODULE_DIR/ci/tools/testkit-scenarios.sh"
    bash "$MODULE_DIR/ci/tools/testkit-run.sh" \
        --flavor "$FLAVOR" --version "$VERSION" --coverage \
        --port "$TEST_BASE_PORT" -- "${TESTKIT_SCENARIOS_ALL[@]}"

    TESTKIT_OUT="$OUT/testkit"
    mkdir -p "$TESTKIT_OUT"
    gcovr \
        "$TESTKIT_ADDON" \
        --root "$MODULE_DIR" \
        --filter "$MODULE_DIR/src/" \
        --object-directory "$TESTKIT_ADDON" \
        --gcov-ignore-errors=all \
        --merge-mode-functions=merge-use-line-min \
        --branches \
        --decisions \
        --print-summary \
        --html-details "$TESTKIT_OUT/index.html" \
        --xml "$TESTKIT_OUT/coverage.xml" \
        --txt "$TESTKIT_OUT/coverage.txt" \
        --json-pretty \
        --json "$TESTKIT_OUT/coverage.json"

    COMBINED_OUT="$OUT/combined"
    mkdir -p "$COMBINED_OUT"
    gcovr \
        --root "$MODULE_DIR" \
        --add-tracefile "$OUT/coverage.json" \
        --add-tracefile "$TESTKIT_OUT/coverage.json" \
        --add-tracefile "$UNIT_OUT/coverage.json" \
        --merge-mode-functions=merge-use-line-min \
        --branches \
        --decisions \
        --print-summary \
        --html-details "$COMBINED_OUT/index.html" \
        --xml "$COMBINED_OUT/coverage.xml" \
        --txt "$COMBINED_OUT/coverage.txt" \
        --json-pretty \
        --json "$COMBINED_OUT/coverage.json"
    echo "coverage: testkit and runtime + testkit + unit reports written under $TESTKIT_OUT and $COMBINED_OUT"
fi
