#!/usr/bin/env bash
#
# Build the deterministic L2 blob fixture binary (AUD-HDR1 / AUD-FUZZ1).
#
# Usage: ci/fuzz/build_blob_fixtures.sh <compiler> <output-path> [base-flags...]
#
#   compiler    : may be a multi-word command ("ccache clang"); it is word-split.
#   output-path : where the fixture binary is written.
#   base-flags  : the caller's own optimisation/sanitizer flags, word-split.
#
# Two callers build this same binary from the same source with independently
# maintained flags: ci/fuzz/build.sh (libFuzzer job, $CC/$CFLAGS overridable by
# OSS-Fuzz) and ci/tests/unit/run.sh (per-PR unit gate, $BLOB_CC). They differ
# legitimately in compiler and base flags, which is why those are parameters.
#
# What must NOT drift is pinned here rather than left to the caller:
#
#   -fno-sanitize-recover=undefined  UBSan must abort, not log-and-continue.
#                                    Without it a fixture that trips UB still
#                                    exits 0 and the gate reports success.
#   -DCT_BLOB_FIXTURES               selects fuzz_blob.c's own main() instead of
#                                    the libFuzzer entry point.
#   extract_blob.sh                  re-slices the deserializer out of src/ so
#                                    the fixtures can never test a stale copy.
#
# This binary is the only guard on the restore-side header filter, so a flag
# lost in one of the two call sites silently removes that coverage.

set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <compiler> <output-path> [base-flags...]" >&2
    exit 2
fi

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BLOB_CC="$1"
OUT="$2"
shift 2

bash "$FUZZ_DIR/extract_blob.sh"

# BLOB_CC may be "ccache clang" and "$@" is a flag list: both must word-split.
# shellcheck disable=SC2086
$BLOB_CC "$@" -fno-sanitize-recover=undefined -DCT_BLOB_FIXTURES \
    -I"$FUZZ_DIR" "$FUZZ_DIR/fuzz_blob.c" -o "$OUT"

echo "✓ built fixture binary: $OUT"
