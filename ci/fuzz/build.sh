#!/usr/bin/env bash
#
# Build the cache-turbo libFuzzer targets.
# Usage: ci/fuzz/build.sh [output-dir-or-binary]
#
#   - no arg      : build every registered target into ci/fuzz/
#   - a directory : build every registered target into that dir
#   - a file path : build ONLY the RESP-reply target to that path
#                   (back-compat for the CI step that passes an explicit
#                   fuzz_resp_parser output name)
#
# Requires clang with libFuzzer (clang >= 6). CFLAGS/CC overridable for
# OSS-Fuzz / ClusterFuzzLite, which pass their own sanitizer flags.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CC="${CC:-clang}"

# ccache the fuzz-target compiles when available (auto-detected on PATH), so the
# CI ccache cache persisted by .github/actions/build-cache covers these too. Not
# wrapped under OSS-Fuzz (it sets its own CC/engine and drives its own caching).
# Content-keyed so a mismatch can only miss, never serve a wrong object.
if [ -z "${LIB_FUZZING_ENGINE:-}" ] && command -v ccache >/dev/null 2>&1 \
    && [ "${CC#ccache }" = "$CC" ]; then
    CC="ccache $CC"
    export CCACHE_COMPILERCHECK=content
fi

# OSS-Fuzz sets $LIB_FUZZING_ENGINE and its own $CFLAGS; honour them.
ENGINE="${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}"
CFLAGS="${CFLAGS:--g -O1 -fsanitize=address,undefined -fno-sanitize-recover=undefined}"

build_one() {
    local src="$1" out="$2"
    # CC may be "ccache clang" and CFLAGS/ENGINE are flag lists: all must word-split.
    # shellcheck disable=SC2086
    $CC $CFLAGS $ENGINE -I"$FUZZ_DIR" "$FUZZ_DIR/$src" -o "$out"
    echo "✓ built fuzz target: $out"
}

build_auto_classify_empty_smoke() {
    local out="$1"
    # The smoke has its own main(), so it deliberately omits libFuzzer's engine
    # while retaining this script's ASan/UBSan CFLAGS.
    # shellcheck disable=SC2086
    $CC $CFLAGS -I"$FUZZ_DIR" "$FUZZ_DIR/test_auto_classify_empty.c" -o "$out"
    echo "✓ built auto-classify empty-cookie smoke: $out"
}

# Target list comes from the registry (ci/fuzz/targets.tsv); targets.sh validates
# every row (missing source/corpus/dict/extractor fails naming the row).
# shellcheck source=ci/fuzz/targets.sh
. "$FUZZ_DIR/targets.sh"
ROWS="$(targets_rows)" || { echo "❌ fuzz target registry invalid" >&2; exit 1; }

ARG="${1:-}"
if [ -n "$ARG" ] && [ ! -d "$ARG" ]; then
    # Explicit single-file output path -> RESP-reply target only (CI compat).
    built=0
    while IFS=$'\t' read -r name src _corpus _dict extract; do
        [ "$name" = fuzz_resp_parser ] || continue
        bash "$FUZZ_DIR/$extract"
        build_one "$src" "$ARG"
        built=1
    done <<<"$ROWS"
    # A registry without the RESP row would otherwise exit 0 without writing
    # $ARG, and the caller would run a stale binary.
    if [ "$built" -ne 1 ]; then
        echo "❌ fuzz target registry has no fuzz_resp_parser row; nothing built to $ARG" >&2
        exit 1
    fi
else
    DIR="${ARG:-$FUZZ_DIR}"
    while IFS=$'\t' read -r name src _corpus _dict extract; do
        bash "$FUZZ_DIR/$extract"
        build_one "$src" "$DIR/$name"
    done <<<"$ROWS"
    build_auto_classify_empty_smoke "$DIR/auto_classify_empty_smoke"
    # Deterministic per-primitive fixture binary from the SAME source: no
    # libFuzzer engine, its own main(). This is what the unit gate runs, so the
    # AUD-HDR1 fixtures are checked on every PR, not only in the fuzz job.
    # Shared with ci/tests/unit/run.sh so the pinned flags cannot drift apart.
    # shellcheck disable=SC2086
    bash "$FUZZ_DIR/build_blob_fixtures.sh" "$CC" "$DIR/fuzz_blob_fixtures" $CFLAGS
fi
