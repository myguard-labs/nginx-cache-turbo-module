#!/usr/bin/env bash
#
# Run the cache-turbo prober rules against a probe-enabled build.
#
#   t/prober/run.sh [flavor] [version]
#     flavor : nginx (default) | angie
#     version: source version; must match what tools/ci-build.sh fetched
#
# The engine lives in t/harness (nginx-test-harness) and knows nothing about
# cache-turbo: this only supplies the four things that are cache-turbo's --
# which .so to look in, which directive proves the harness build, and where
# the conf and rules are. Everything else (boot, teardown, TAP, the delta
# engine, the pid oracle, the error-log scrape) is the harness's.
#
# Cache-turbo consumes the harness in ZERO-HOOK mode: no zone_render, no
# fault_set, no module-specific probe C at all beyond the HTTP surface in
# ngx_http_cache_turbo_module.c. The rules therefore assert only on the
# harness's generic document.
#
# The build must have been made with TEST_HARNESS=1, otherwise
# cache_turbo_probe does not exist and the config fails to load; the harness
# checks for that up front by inspecting the binary rather than letting it
# surface as a confusing connect error.
set -euo pipefail

cd "$(dirname "$0")"

HERE="$PWD"

if [ ! -x ../harness/prober/run.sh ]; then
    echo "Bail out! t/harness is empty -- run: git submodule update --init"
    exit 1
fi

# The harness resolves conf/rules relative to its own directory, so both are
# passed as absolute paths out of this one.
export PROBER_MODULE="ngx_http_cache_turbo_module.so"
export PROBER_DIRECTIVE="cache_turbo_probe"
export PROBER_CONF="$HERE/conf/prober.conf"
export PROBER_RULES="$HERE/rules/*.rule"
export PROBER_ROOT="$(cd ../.. && pwd)"

# Own default port: the harness default (18099) is also every other
# consumer's default, and a stale or concurrently-running consumer on the
# same box answers this prober's requests convincingly enough to fail every
# case with 404s instead of a loud bind error on OUR side.
export PROBER_PORT="${PROBER_PORT:-18119}"

# NOT setting PROBER_ALLOW_LOG: no rule here arms a fault (zero-hook mode has
# no fault_set), so nothing is expected in the error log at alert/crit/emerg
# and the harness's default gate stays fully armed.

exec ../harness/prober/run.sh "$@"
