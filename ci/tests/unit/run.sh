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

# --- auto-Vary purge generation wrap (AUD-GEN1) ----------------------------
# Pure-math mirror of marker_store/variant_hash's gen write/truncate/fold --
# see the header comment in test_vary_gen.c for why a mirror, not a #include.
# shellcheck disable=SC2086
"$CC" $CFLAGS "$DIR/test_vary_gen.c" -o "$DIR/test_vary_gen"
"$DIR/test_vary_gen"

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

# --- EVP digest failure path (AUD-DIGEST-ZERO) ----------------------------
# Unit test for the fail-closed digest handling. Tests that EVP failures are
# propagated to callers instead of silently producing all-zero keys.
# shellcheck disable=SC2086
"$CC" $CFLAGS "$DIR/test_digest_fail.c" -o "$DIR/test_digest_fail" -lssl -lcrypto
"$DIR/test_digest_fail"

# --- L2 blob deserializer fixtures (AUD-HDR1 / AUD-FUZZ1) -----------------
# Deterministic, hermetic (no nginx tree, no libFuzzer engine): one fixture per
# header-injection primitive, driven through the SAME oracle ci/fuzz/fuzz_blob.c
# gives the fuzzer. Built here rather than only in the fuzzing workflow so the
# guards are checked on every PR — fuzzing.yml is path-filtered to ci/fuzz/**
# and would not run at all on a change that only touches src/.
echo "--- L2 blob deserializer fixtures (ASan/UBSan) ---"
FUZZ_DIR="$DIR/../../fuzz"
BLOB_CC="${BLOB_CC:-clang}"
if command -v "$BLOB_CC" >/dev/null 2>&1; then
    bash "$FUZZ_DIR/build_blob_fixtures.sh" "$BLOB_CC" "$DIR/blob_fixtures" \
        -g -O1 -fsanitize=address,undefined
    "$DIR/blob_fixtures"
else
    # Not a silent skip: these fixtures are the only guard on the restore-side
    # header filter, so a runner without clang must be visible in the log.
    echo "::warning::clang not found — L2 blob fixtures NOT run"
fi

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
NGINX_VERSION="${NGINX_VERSION:-1.31.1}"
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
else
    echo "--- shm node state machine: SKIPPED (no configured nginx tree at" \
         "$NGINX_OBJS) ---"
    echo "    build one with ci/tools/ci-build.sh, or run ci/tests/unit/make check" \
         "with NGINX_SRC/NGINX_OBJS set."
fi
