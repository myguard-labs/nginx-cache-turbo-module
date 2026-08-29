#!/usr/bin/env bash
#
# Build + run the cache-turbo pure-math unit tests. Fast, hermetic, no nginx.
#
#   ci/tests/unit/run.sh            # build with warnings-as-errors + run
#   COVERAGE=1 ci/tests/unit/run.sh # also instrument (--coverage) so a caller can
#                                # gcov ../../src/ngx_http_cache_turbo_{swr,
#                                # autotune}.c afterwards
#
# The driver #includes the shipped src units verbatim, so a prod change to the
# math flows straight into the test. check_constants.sh guards the one thing the
# shim duplicates (the fixed-point constants) against drift from module.h.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CC="${CC:-cc}"
CFLAGS="-g -O0 -Wall -Wextra -Werror -I$DIR"

bash "$DIR/check_constants.sh"

if [ "${COVERAGE:-0}" = 1 ]; then
    CFLAGS="$CFLAGS --coverage"
fi

# shellcheck disable=SC2086
"$CC" $CFLAGS "$DIR/test_math.c" -o "$DIR/test_math"
"$DIR/test_math"

# --- Cache-Control delta-seconds exact grammar ----------------------------
# Exercise the REAL request/response parser: quote-aware token iteration,
# quoted and bare deltas, the signed boundary, saturating overflow, and
# malformed values that must be rejected.
bash "$DIR/extract_cc_delta.sh"
# shellcheck disable=SC2086
"$CC" $CFLAGS "$DIR/test_cc_delta.c" -o "$DIR/test_cc_delta"
"$DIR/test_cc_delta"

# --- auto-Vary purge generation wrap (AUD-GEN1) ----------------------------
# Pure-math mirror of marker_store/variant_hash's gen write/truncate/fold --
# see the header comment in test_vary_gen.c for why a mirror, not a #include.
# shellcheck disable=SC2086
"$CC" $CFLAGS "$DIR/test_vary_gen.c" -o "$DIR/test_vary_gen"
"$DIR/test_vary_gen"

# --- auto-Vary Accept-Encoding axis collapse (P1-1) -------------------------
# Pure-math mirror of classify_vary_classify_token()'s Accept-Encoding arm --
# see the header comment in test_vary_encoding_collapse.c for why this is the
# only place the response_encoded()==1 case can be proven at all (the
# capture gate refuses that response end-to-end before the bit ever matters).
# shellcheck disable=SC2086
"$CC" $CFLAGS "$DIR/test_vary_encoding_collapse.c" -o "$DIR/test_vary_encoding_collapse"
"$DIR/test_vary_encoding_collapse"

# --- the same claim, against the REAL variant_hash (AUD-GEN1) --------------
# test_vary_gen.c above mirrors the arithmetic; this one links the production
# function, sliced verbatim out of src/ by extract_variant_hash.sh, so drift
# between the mirror and the shipped code cannot pass unnoticed. The extractor
# also fails the build if the gen fold is guarded on `gen` again.
bash "$DIR/extract_variant_hash.sh"
# shellcheck disable=SC2086
"$CC" $CFLAGS "$DIR/test_variant_gen.c" -o "$DIR/test_variant_gen" -lssl -lcrypto
"$DIR/test_variant_gen"

# --- cache-key fold, single-allocation (S231-PERF-KEYFOLD) -----------------
# Pins the digest of known multi-part / empty-value / oversize keys against
# the byte-framing contract (0x1f tag + 4B name-len + 4B val-len + name +
# value), against the REAL fold_size/fold_append/fold_all sliced out of
# src/ by extract_key_fold.sh. Byte-identity here is what proves the
# single-allocation fold did not change the stored cache key.
bash "$DIR/extract_key_fold.sh"
# shellcheck disable=SC2086
"$CC" $CFLAGS "$DIR/test_key_fold.c" -o "$DIR/test_key_fold" -lssl -lcrypto
"$DIR/test_key_fold"

# --- open-coded query-token sort, byte-identity vs ngx_sort (R3-2) --------
# The sort's output IS the cache key, so replacing ngx_sort() (which
# malloc/free'd a 16-byte scratch slot per request on the key path) with an
# open-coded insertion sort using a stack temp must not move a single element.
# Differentially compares the REAL loop, sliced verbatim out of src/ by
# extract_tok_sort.sh, against a verbatim ngx_sort() replica on adversarial and
# randomized inputs -- comparing ngx_str_t FIELDS, so a stability regression
# (same bytes, different source offset) is caught too.
bash "$DIR/extract_tok_sort.sh"
# shellcheck disable=SC2086
"$CC" $CFLAGS "$DIR/test_tok_sort.c" -o "$DIR/test_tok_sort"
"$DIR/test_tok_sort"

# --- auto-Vary marker fast-path magic/version gate (P1-6) ------------------
# Mirror of the old blob_validate()-gated read vs. the new cheap
# magic+version+length gate in ngx_http_cache_turbo_vary_apply() -- proves
# the fast path accepts a superset containing every real marker shape (legacy
# 1-byte and current 2-byte) with byte-identical (bits, gen), and that a
# truncated / bad-magic / bad-version marker is still rejected by both. See
# the header comment in test_vary_marker_fastpath.c for the divergence proof.
# shellcheck disable=SC2086
"$CC" $CFLAGS "$DIR/test_vary_marker_fastpath.c" -o "$DIR/test_vary_marker_fastpath"
"$DIR/test_vary_marker_fastpath"

# --- EVP digest failure path (AUD-DIGEST-ZERO) ----------------------------
# Unit test for the fail-closed digest handling. Tests that EVP failures are
# propagated to callers instead of silently producing all-zero keys.
# shellcheck disable=SC2086
"$CC" $CFLAGS "$DIR/test_digest_fail.c" -o "$DIR/test_digest_fail" -lssl -lcrypto
"$DIR/test_digest_fail"

# --- cached EVP_MD_fetch() byte-identity (C0, PLAN-hitpath-2026-08-23.md) --
# The digest is the cache key (including the L2 wire key), so the new
# worker-persistent EVP_MD_fetch() path must be byte-identical to the old
# per-call EVP_sha256() path. Pins the REAL production digest_init/_update/
# _final/_digest (sliced verbatim by extract_digest.sh) against independently
# computed SHA-256 vectors, and against each other via the
# ngx_http_cache_turbo_test_fetch_md_fail fault knob.
bash "$DIR/extract_digest.sh"
# shellcheck disable=SC2086
"$CC" $CFLAGS "$DIR/test_digest.c" -o "$DIR/test_digest" -lssl -lcrypto
"$DIR/test_digest"

FUZZ_DIR="$DIR/../../fuzz"
BLOB_CC="${BLOB_CC:-clang}"
if command -v "$BLOB_CC" >/dev/null 2>&1; then
    # --- Redis GET RESP exact-boundary fixtures --------------------------
    # The production parser is extracted verbatim. Pin malformed payload
    # delimiters and trailing partial replies so neither can become a HIT or
    # make a keepalive connection look clean again.
    echo "--- Redis RESP exact-boundary fixtures (ASan/UBSan) ---"
    bash "$FUZZ_DIR/extract_parser.sh"
    "$BLOB_CC" -g -O1 -fsanitize=address,undefined \
        -DNGX_HTTP_CACHE_TURBO_RESP_FIXTURES=1 -I"$FUZZ_DIR" \
        "$FUZZ_DIR/fuzz_resp_parser.c" -o "$DIR/resp_parser_fixtures"
    "$DIR/resp_parser_fixtures"

    # --- bounded/fail-closed auto-classification fixtures -----------------
    # Exercise the Cookie cap/work oracle and arg allocation-failure branch
    # against the same extracted production code as fuzz_auto_classify.
    echo "--- auto-classify bounded-work fixtures (ASan/UBSan) ---"
    bash "$FUZZ_DIR/extract_auto_classify.sh"
    "$BLOB_CC" -g -O1 -fsanitize=address,undefined \
        -DNGX_HTTP_CACHE_TURBO_AUTO_FIXTURES=1 -I"$FUZZ_DIR" \
        "$FUZZ_DIR/fuzz_auto_classify.c" -o "$DIR/auto_classify_fixtures"
    "$DIR/auto_classify_fixtures"

    # --- L2 blob deserializer fixtures (AUD-HDR1 / AUD-FUZZ1) ------------
    # One fixture per header-injection primitive, driven through the same
    # oracle ci/fuzz/fuzz_blob.c gives the fuzzer.
    echo "--- L2 blob deserializer fixtures (ASan/UBSan) ---"
    bash "$FUZZ_DIR/build_blob_fixtures.sh" "$BLOB_CC" "$DIR/blob_fixtures" \
        -g -O1 -fsanitize=address,undefined
    "$DIR/blob_fixtures"
else
    # Not a silent skip: these fixtures are the only deterministic guards on
    # the two sanitizer-backed paths, so a runner without clang is visible.
    echo "::warning::clang not found — auto-classify/L2 fixtures NOT run"
fi

# --- stripe resolver arithmetic at a FORCED N > 1 (P4-2-s3b/s3c) ----------
# NGX_HTTP_CACHE_TURBO_STRIPES is pinned at 1, and at N == 1 `anything % 1 == 0`
# -- so on the shipped module a resolver that ignores its key, inverts its
# modulo, or is a copy of the zone-wide one is INDISTINGUISHABLE from a correct
# one, and every runtime test stays green. This compiles the PRODUCTION
# resolver bodies (sliced by extract_stripe_resolver.sh, never mirrored) at a
# forced N of 8 and 7, where the arithmetic is finally observable. Hermetic:
# no nginx tree, so it runs in the Validation job too.
bash "$DIR/extract_stripe_resolver.sh"
# shellcheck disable=SC2086
"$CC" $CFLAGS "$DIR/test_stripe_resolver.c" -o "$DIR/test_stripe_resolver"
"$DIR/test_stripe_resolver"

# --- shm node state machine (CR-A / CR-B guards) --------------------------
# Unlike the pure-math tests these link nginx's real ngx_rbtree.c, so they need
# a CONFIGURED nginx source tree (objs/ngx_auto_config.h exists only after
# ./configure). Where there isn't one, skip with a notice rather than fail --
# the Validation job runs before any nginx build.
#
# ⚠ SKIPPING IS ONLY SAFE BECAUSE A JOB THAT HAS THE TREE ALSO RUNS THIS.
# If the only caller were a tree-less job this would silently test nothing,
# which is the exact failure mode these tests exist to prevent. Keep the
# build-test "Runtime" job (which has the configured tree) calling run.sh.
# Default to the CENTRAL pin, never a literal. A hardcoded fallback here silently
# drifts from .github/versions.env every time the pin moves, and the drift is
# invisible: a LOCAL run then looks for a tree that does not exist, SKIPS, and
# still exits 0 -- the precise "green that proves nothing" this file warns about
# two paragraphs up. (CI was unaffected: build-test.yml passes NGINX_VERSION
# explicitly. It was local runs that quietly tested nothing.)
if [ -z "${NGINX_VERSION:-}" ] && [ -f "$DIR/../../../.github/versions.env" ]; then
    NGINX_VERSION=$(sed -n 's/^NGINX_VERSION=//p' \
                        "$DIR/../../../.github/versions.env" | head -1)
fi
NGINX_VERSION="${NGINX_VERSION:-1.31.3}"
NGX_SRC="${NGX_SRC:-$DIR/../../../.build/nginx-$NGINX_VERSION}"

# Honour the Makefile's own variable names if the caller set them. These are
# passed to make as command-line args below, which override the environment --
# so without reading them here a caller pointing this script at a custom tree
# (following the Makefile, or the pattern in build-test.yml) would be silently
# ignored in favour of the .build default.
NGINX_SRC="${NGINX_SRC:-$NGX_SRC/src}"
NGINX_OBJS="${NGINX_OBJS:-$NGX_SRC/objs}"

if [ -f "$NGINX_OBJS/ngx_auto_config.h" ]; then
    echo "--- shm node state machine (ASan/UBSan) ---"
    make -C "$DIR" --no-print-directory check \
        NGINX_VERSION="$NGINX_VERSION" \
        NGINX_SRC="$NGINX_SRC" \
        NGINX_OBJS="$NGINX_OBJS"

    # --- c-1: varidx drop/reissue accounting is production-reachable -------
    # The PURGE reply's "complete":false honesty field depends on
    # z->sh->varidx_drops/varidx_reissues actually moving OUTSIDE a
    # NGX_HTTP_CACHE_TURBO_TEST_FAULTS build. Every runtime test above
    # (including this one) builds WITH TEST_FAULTS, so none of them can
    # catch the increments being wrapped back into that #if -- this
    # preprocesses the two call sites with TEST_FAULTS undefined instead.
    echo "--- varidx drop/reissue accounting (non-TEST_FAULTS preprocess) ---"
    NGINX_VERSION="$NGINX_VERSION" NGINX_SRC="$NGINX_SRC" NGINX_OBJS="$NGINX_OBJS" \
        bash "$DIR/check_varidx_accounting.sh"
else
    echo "--- shm node state machine: SKIPPED (no configured nginx tree at" \
         "$NGINX_OBJS) ---"
    echo "    build one with ci/tools/ci-build.sh, or run ci/tests/unit/make check" \
         "with NGINX_SRC/NGINX_OBJS set."
fi
