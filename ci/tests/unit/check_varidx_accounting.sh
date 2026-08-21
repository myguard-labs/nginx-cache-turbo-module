#!/usr/bin/env bash
#
# c-1: the PURGE reply's "complete":false honesty field (purge.c) depends on
# ngx_http_cache_turbo_zone_sh(z)->varidx_drops / ->varidx_reissues actually
# moving in a PRODUCTION build -- not only under
# -DNGX_HTTP_CACHE_TURBO_TEST_FAULTS=1, which is what every CI runtime test
# builds with. A prior version of this fix left both ngx_atomic_fetch_add()
# increments wrapped in
# "#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) && NGX_HTTP_CACHE_TURBO_TEST_FAULTS",
# so pending_at_launch (purge.c) was always 0 and "complete":false could never
# fire outside a TEST_FAULTS build -- every real deployment. The runtime test
# suite could not catch this: it only ever builds WITH TEST_FAULTS, so the
# increments it exercises are always present regardless of whether the #if
# guard around them is correct.
#
# This runs the ACTUAL COMPILER (cpp), not a source grep, against the two call
# sites with TEST_FAULTS undefined -- the same condition every real deployment
# builds under -- and fails if the increment line was preprocessed away.
#
# MUTATION THIS CATCHES: re-wrapping either
#   (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->varidx_drops, 1);    (filters.c)
#   (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->varidx_reissues, 1); (access.c)
# in a TEST_FAULTS #if (or deleting it outright) makes that line vanish from
# the preprocessed output below and this script exits 1.
#
# P4-2-s3b: ngx_http_cache_turbo_zone_sh(z) is a macro that expands (in the
# PREPROCESSED output this script greps) to
# "ngx_http_cache_turbo_zone_stripe(z)->sh" -- a function-call resolver, not a
# bare field -- so the match below is anchored on that expansion, not on the
# pre-seam "z->sh" spelling.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$DIR/../../.." && pwd)"
NGINX_VERSION="${NGINX_VERSION:-1.31.1}"
NGINX_SRC="${NGINX_SRC:-$REPO/.build/nginx-$NGINX_VERSION/src}"
NGINX_OBJS="${NGINX_OBJS:-$REPO/.build/nginx-$NGINX_VERSION/objs}"

if [ ! -d "$NGINX_SRC" ]; then
    echo "SKIP: no extracted nginx source at $NGINX_SRC" \
         "(NGINX_VERSION=$NGINX_VERSION) -- run the module build first" >&2
    exit 0
fi

INCS="-I$NGINX_SRC/core -I$NGINX_SRC/event -I$NGINX_SRC/event/modules \
      -I$NGINX_SRC/event/quic -I$NGINX_SRC/os/unix -I$NGINX_OBJS \
      -I$NGINX_SRC/http -I$NGINX_SRC/http/modules"

check_site() {
    local src="$1" field="$2" label="$3"
    local pp
    # shellcheck disable=SC2086
    pp="$(cc $INCS -E "$REPO/src/$src" 2>/dev/null)" \
        || { echo "FAIL: preprocessing $src failed" >&2; exit 1; }
    # ngx_atomic_fetch_add() is itself a macro (expands to
    # __sync_fetch_and_add on this platform) -- match on the field name next
    # to a fetch-add call in the PREPROCESSED output, not the unexpanded
    # source spelling, since that is what the compiler actually emits code
    # for. grep -E rather than -F: the macro expansion may not match the
    # source's exact call syntax across platforms/compilers.
    if ! grep -qE "(ngx_atomic_fetch_add|__sync_fetch_and_add)\(&\(?ngx_http_cache_turbo_zone_stripe\(z\)->sh\)?->${field}, *1\)" <<<"$pp"; then
        echo "FAIL: $label increment is NOT present in a non-TEST_FAULTS" \
             "preprocess of $src -- the PURGE \"complete\":false field can" \
             "never fire in a production build. Looked for an unconditional" \
             "fetch-add on ngx_http_cache_turbo_zone_sh(z)->${field}" \
             "(expands to ngx_http_cache_turbo_zone_stripe(z)->sh->${field})." >&2
        exit 1
    fi
    echo "ok: $label increment survives a non-TEST_FAULTS build of $src"
}

check_site ngx_http_cache_turbo_filters.c varidx_drops 'varidx_drops'
check_site ngx_http_cache_turbo_access.c varidx_reissues 'varidx_reissues'

echo "OK: varidx drop/reissue accounting is unconditional (production-reachable)"
