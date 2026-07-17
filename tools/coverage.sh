#!/usr/bin/env bash
#
# Measure gcov line+branch coverage of the cache-turbo MODULE sources by
# running the full runtime suite against a gcov-instrumented nginx.
#
#   tools/coverage.sh [flavor] [version]
#     flavor : nginx | angie   (default nginx)
#     version: upstream version (default 1.31.1)
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
#
set -euo pipefail

FLAVOR="${1:-nginx}"
VERSION="${2:-1.31.1}"
MODULE_DIR="$PWD"
ROOT="${BUILD_ROOT:-$PWD/.build}"
DIR="${FLAVOR}-${VERSION}"
OBJDIR="$ROOT/$DIR/objs"
ADDON="$OBJDIR/addon/src"
OUT="${COVERAGE_OUT:-$MODULE_DIR/coverage-report}"
REDIS_SERVER="${REDIS_SERVER:-/usr/bin/redis-server}"
MEMCACHED_SERVER="${MEMCACHED_SERVER:-/usr/bin/memcached}"

# 1. instrumented build
bash "$MODULE_DIR/tools/ci-build.sh" "$FLAVOR" "$VERSION" coverage

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
python3 "$MODULE_DIR/tools/test_runtime.py" \
    --nginx-binary "$OBJDIR/$([ "$FLAVOR" = angie ] && echo angie || echo nginx)" \
    --module "$OBJDIR/ngx_http_cache_turbo_module.so" \
    --redis-server "$REDIS_SERVER" \
    --memcached-server "$MEMCACHED_SERVER" \
    --fault-injection

# 2b. pure-math unit tests. They cover the SWR/autotune boundary branches the
# HTTP suite structurally cannot reach (TTL overflow clamp, forever-TTL, band
# fallback, beta/load clamps, data-sufficiency floor, refresh-dice both ways).
# The driver #includes swr.c + autotune.c verbatim, compiles as a single TU
# under tests/unit, and (COVERAGE=1) emits its own instrumented objects there —
# so its arcs are NOT in the addon/src datafiles the main report scans below.
# We therefore publish a SEPARATE unit report for those two sources (2c) so the
# swr/autotune gains show up in the uploaded artifact, not just in the gate.
UNIT_DIR="$MODULE_DIR/tests/unit"
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
#   --gcov-object-directory addon/src  restricts the object scan to those,
#   --filter src/                      restricts the report to our sources,
#   --gcov-ignore-errors=all           tolerates gcov's "cannot open source"
#       on the nginx HEADERS the module includes (ngx_string.h, etc. — pulled
#       into every module .gcda). Without it gcovr discards the WHOLE datafile
#       on a single unresolved header and silently drops module.c/redis.c/
#       memcached.c from the report (=all keeps them; module sources still
#       resolve fine against $MODULE_DIR/src).
mkdir -p "$OUT"
GCOVR_ARGS=(
    --root "$MODULE_DIR"
    --filter "$MODULE_DIR/src/"
    --gcov-object-directory "$ADDON"
    --gcov-ignore-errors=all
    --branches
    --decisions
    --print-summary
    --html-details "$OUT/index.html"
    --xml "$OUT/coverage.xml"
    --txt "$OUT/coverage.txt"
)
if [ -n "${COVERAGE_FAIL_UNDER:-}" ]; then
    GCOVR_ARGS+=(--fail-under-line "$COVERAGE_FAIL_UNDER")
fi

gcovr "${GCOVR_ARGS[@]}"
echo "coverage: suite report written to $OUT (index.html, coverage.xml, coverage.txt)"

# 2c. unit-test report for the swr/autotune math. The unit driver's .gcda live
# under tests/unit (single-TU #include build), covering the boundary branches
# the HTTP suite cannot reach. Publish it as a separate report under $OUT/unit
# so the artifact carries the full swr/autotune numbers, not only the gate pass.
# Filter to just those two sources; the datafile also holds test_math.c arcs we
# do not report on. gcov-ignore-errors=all for the same header-resolution reason
# as the suite report above.
UNIT_OUT="$OUT/unit"
mkdir -p "$UNIT_OUT"
gcovr \
    --root "$MODULE_DIR" \
    --filter "$MODULE_DIR/src/ngx_http_cache_turbo_swr.c" \
    --filter "$MODULE_DIR/src/ngx_http_cache_turbo_autotune.c" \
    --gcov-object-directory "$UNIT_DIR" \
    --gcov-ignore-errors=all \
    --branches \
    --decisions \
    --print-summary \
    --html-details "$UNIT_OUT/index.html" \
    --xml "$UNIT_OUT/coverage.xml" \
    --txt "$UNIT_OUT/coverage.txt"
echo "coverage: unit (swr/autotune) report written to $UNIT_OUT"
