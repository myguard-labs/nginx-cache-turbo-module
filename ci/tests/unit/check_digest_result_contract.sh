#!/usr/bin/env bash
# Digest-derived keys are an integrity boundary.  GCC/Clang's
# warn_unused_result catches a bare discarded call; this gate pins those
# annotations and rejects the explicit `(void)` escape hatch too.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$DIR/../../.." && pwd)"
MODULE_H="$REPO/src/ngx_http_cache_turbo_module.h"
INTERNAL_H="$REPO/src/ngx_http_cache_turbo_internal.h"

if ! grep -qF '#define NGX_HTTP_CACHE_TURBO_MUST_CHECK  __attribute__((warn_unused_result))' \
    "$MODULE_H"
then
    echo "✗ NGX_HTTP_CACHE_TURBO_MUST_CHECK lost warn_unused_result" >&2
    exit 1
fi

check_decl() {
    fn="$1"
    header="$2"

    if ! sed -n "/ngx_int_t ${fn}(/,/;/p" "$header" \
        | grep -qF 'NGX_HTTP_CACHE_TURBO_MUST_CHECK'
    then
        echo "✗ $fn lost its must-check result contract" >&2
        exit 1
    fi
}

check_decl ngx_http_cache_turbo_digest "$MODULE_H"
for fn in \
    ngx_http_cache_turbo_digest_final \
    ngx_http_cache_turbo_vary_prepare \
    ngx_http_cache_turbo_vary_apply \
    ngx_http_cache_turbo_variant_hash \
    ngx_http_cache_turbo_marker_hash \
    ngx_http_cache_turbo_marker_store \
    ngx_http_cache_turbo_variant_index_name
do
    check_decl "$fn" "$INTERNAL_H"
done

if ! grep -B1 -F 'ngx_http_cache_turbo_vary_prepare_lazy(' "$INTERNAL_H" \
    | grep -qF 'NGX_HTTP_CACHE_TURBO_MUST_CHECK'
then
    echo "✗ ngx_http_cache_turbo_vary_prepare_lazy lost its must-check contract" >&2
    exit 1
fi

if rg -n -U '\(void\)[[:space:]]+ngx_http_cache_turbo_(digest|digest_final|vary_prepare(_lazy)?|vary_apply|variant_hash|marker_hash|marker_store|variant_index_name)\(' \
    "$REPO/src" --glob '*.[ch]'
then
    echo "✗ digest-derived return explicitly discarded; propagate failure" >&2
    exit 1
fi

echo "✓ digest-derived key results are must-check and never void-discarded"
