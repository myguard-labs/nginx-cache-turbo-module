#!/usr/bin/env bash
#
# Build the cache-turbo libFuzzer targets.
# Usage: ci/fuzz/build.sh [output-dir-or-binary]
#
#   - no arg      : build both targets into ci/fuzz/
#   - a directory : build both targets into that dir
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

ARG="${1:-}"
if [ -n "$ARG" ] && [ ! -d "$ARG" ]; then
    # Explicit single-file output path -> RESP-reply target only (CI compat).
    bash "$FUZZ_DIR/extract_parser.sh"
    build_one fuzz_resp_parser.c "$ARG"
else
    DIR="${ARG:-$FUZZ_DIR}"
    bash "$FUZZ_DIR/extract_parser.sh"
    build_one fuzz_resp_parser.c "$DIR/fuzz_resp_parser"
    bash "$FUZZ_DIR/extract_norm_args.sh"
    build_one fuzz_norm_args.c "$DIR/fuzz_norm_args"
    bash "$FUZZ_DIR/extract_mc_parser.sh"
    build_one fuzz_mc_parser.c "$DIR/fuzz_mc_parser"
    bash "$FUZZ_DIR/extract_auto_classify.sh"
    build_one fuzz_auto_classify.c "$DIR/fuzz_auto_classify"
fi
