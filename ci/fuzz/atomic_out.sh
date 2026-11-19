# shellcheck shell=bash
#
# Sourced by the extract_*.sh slicers. Build the generated include in
# same-directory scratch files and publish it with one rename, so a concurrent
# build never reads a truncated include and two concurrent runs never share a
# scratch name. Requires $OUT to be set before fuzz_atomic_begin is called.
#
#   fuzz_atomic_begin    create $TMP_OUT (the include under construction) and
#                        $TMP_PART (per-slice scratch); an EXIT trap removes
#                        both on every exit path, success included
#   fuzz_atomic_publish  mv $TMP_OUT over $OUT (same directory, so the rename
#                        is atomic); call last, after every validation
#
# A failing slicer never calls publish, and once fuzz_atomic_begin has run any
# non-zero exit also removes $OUT (a failure before begin, e.g. a missing
# source, leaves it as the slicer's own checks dictate). A slicer must not set
# its own EXIT trap after sourcing this: begin owns it.

TMP_OUT=""
TMP_PART=""

fuzz_atomic_cleanup() {
    local rc=$?
    rm -f "$TMP_OUT" "$TMP_PART"
    # Fail closed on any unexpected abort (an awk or mktemp error under set -e)
    # too, as the slicers' "removed on any failure" contract promises.
    if [ "$rc" -ne 0 ]; then
        rm -f "$OUT"
    fi
}

fuzz_atomic_begin() {
    trap fuzz_atomic_cleanup EXIT
    TMP_OUT=$(mktemp "$OUT.tmp.XXXXXX")
    TMP_PART=$(mktemp "$OUT.part.XXXXXX")
}

fuzz_atomic_publish() {
    # mktemp creates 0600; restore the mode a plain `> "$OUT"` would have had.
    chmod "$(printf '%03o' $((0666 & ~$(umask))))" "$TMP_OUT"
    mv -f "$TMP_OUT" "$OUT"
    # Published: later failures (extract_parser.sh runs another slicer next)
    # must not take the finished include away.
    rm -f "$TMP_PART"
    trap - EXIT
}
