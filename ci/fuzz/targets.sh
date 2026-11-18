#!/usr/bin/env bash
#
# Single reader/validator of the fuzz target registry ci/fuzz/targets.tsv.
# Consumers: ci/fuzz/build.sh, ci/fuzz/run-concurrent.sh and the static.yml /
# ci-deep.yml fuzz steps. A target added to the registry is therefore built,
# replayed on every PR and long-fuzzed in Deep with no other edit.
#
# Registry: tab-separated, first line is a header. Columns:
#   name  source  corpus  dict  extract
# source and extract are files in ci/fuzz/; corpus is a directory there; dict is
# a file there or "-" for none; extract is the slicer script run before the build.
#
# Usage: ci/fuzz/targets.sh <cmd> [arg]
#   validate        check every row; exit 1 naming the first bad row
#   names           one target name per line
#   specs [part]    name:corpus:dict lines (run-concurrent.sh spec); part is
#                   all (default), a (first ceil(n/2) rows) or b (the rest)
#   rows            name<TAB>source<TAB>corpus<TAB>dict<TAB>extract (dict "-" if none;
#                   a tab-IFS read would collapse an empty field)
# Env: FUZZ_TARGETS_TSV overrides the registry path (tests).
set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY="${FUZZ_TARGETS_TSV:-$FUZZ_DIR/targets.tsv}"

# targets_rows: validated, normalised rows on stdout; errors on stderr, rc 1.
targets_rows() {
    [ -f "$REGISTRY" ] || {
        echo "targets: registry not found: $REGISTRY" >&2
        return 1
    }
    local line n=0 rc=0 name source corpus dict extract rest seen=" "
    while IFS= read -r line || [ -n "$line" ]; do
        n=$((n + 1))
        line="${line%$'\r'}"
        [ "$n" -eq 1 ] && [ "${line%%$'\t'*}" = "name" ] && continue
        [ -z "$line" ] && continue
        case "$line" in '#'*) continue ;; esac
        local tabs="${line//[^$'\t']/}"
        if [ "${#tabs}" -ne 4 ]; then
            echo "targets: row at line $n needs 5 tab-separated columns, got $((${#tabs} + 1)): $line" >&2
            rc=1
            continue
        fi
        name="${line%%$'\t'*}"
        rest="${line#*$'\t'}"
        source="${rest%%$'\t'*}"
        rest="${rest#*$'\t'}"
        corpus="${rest%%$'\t'*}"
        rest="${rest#*$'\t'}"
        dict="${rest%%$'\t'*}"
        extract="${rest#*$'\t'}"
        case "$name" in
        fuzz_[a-z0-9_]*) ;;
        *)
            echo "targets: row at line $n has an invalid or empty name '$name' (want fuzz_<...>): $line" >&2
            rc=1
            continue
            ;;
        esac
        case "$seen" in *" $name "*)
            echo "targets: row '$name' (line $n) is a duplicate" >&2
            rc=1
            continue
            ;;
        esac
        seen="$seen$name "
        if [ -z "$source" ] || [ ! -f "$FUZZ_DIR/$source" ]; then
            echo "targets: row '$name' (line $n): harness source '$source' not found in $FUZZ_DIR" >&2
            rc=1
            continue
        fi
        if [ -z "$corpus" ] || [ ! -d "$FUZZ_DIR/$corpus" ]; then
            echo "targets: row '$name' (line $n): corpus dir '$corpus' not found in $FUZZ_DIR" >&2
            rc=1
            continue
        fi
        [ -n "$dict" ] || {
            echo "targets: row '$name' (line $n): dict is empty (use - for none)" >&2
            rc=1
            continue
        }
        if [ "$dict" != "-" ] && [ ! -f "$FUZZ_DIR/$dict" ]; then
            echo "targets: row '$name' (line $n): dict '$dict' not found in $FUZZ_DIR" >&2
            rc=1
            continue
        fi
        if [ -z "$extract" ] || [ ! -f "$FUZZ_DIR/$extract" ]; then
            echo "targets: row '$name' (line $n): extract script '$extract' not found in $FUZZ_DIR" >&2
            rc=1
            continue
        fi
        printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$source" "$corpus" "$dict" "$extract"
    done <"$REGISTRY"
    if [ "$rc" -eq 0 ] && [ "$seen" = " " ]; then
        echo "targets: registry $REGISTRY has no targets" >&2
        return 1
    fi
    return "$rc"
}

targets_specs() {
    local part="${1:-all}" rows total i=0 half name _s corpus dict _e
    rows="$(targets_rows)" || return 1
    total="$(printf '%s\n' "$rows" | wc -l)"
    half=$(((total + 1) / 2))
    while IFS=$'\t' read -r name _s corpus dict _e; do
        i=$((i + 1))
        [ "$dict" = "-" ] && dict=""
        case "$part" in
        a) [ "$i" -le "$half" ] || continue ;;
        b) [ "$i" -gt "$half" ] || continue ;;
        all) ;;
        *)
            echo "targets: unknown part '$part' (all|a|b)" >&2
            return 2
            ;;
        esac
        printf '%s:%s:%s\n' "$name" "$corpus" "$dict"
    done <<<"$rows"
}

targets_main() {
    case "${1:-}" in
    validate) targets_rows >/dev/null ;;
    names) targets_rows | cut -f1 ;;
    specs) targets_specs "${2:-all}" ;;
    rows) targets_rows ;;
    *)
        echo "usage: targets.sh validate|names|specs [all|a|b]|rows" >&2
        return 2
        ;;
    esac
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    targets_main "$@"
fi
