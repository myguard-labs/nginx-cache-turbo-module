#!/usr/bin/env bash
# Host guards shared by testkit staging and their hermetic controls.

testkit_package_build_running() {
    local proc_root="${TESTKIT_PROC_ROOT:-/proc}"
    local cmdline argv0 argv1 scanned=0 target

    [ -d "$proc_root" ] || return 2

    for cmdline in "$proc_root"/[0-9]*/cmdline; do
        [ -e "$cmdline" ] || continue
        [ -r "$cmdline" ] || return 2
        argv0=""
        argv1=""
        {
            IFS= read -r -d '' argv0 || true
            IFS= read -r -d '' argv1 || true
        } <"$cmdline"
        [ -n "$argv0" ] || continue
        scanned=1
        target="${argv0##*/}"
        case "$target" in
            pbuilder|dpkg-buildpackage) return 0 ;;
        esac
        # The kernel exposes shebang scripts as interpreter + script. Inspect
        # only argv[1] for known interpreters: later arguments may contain
        # arbitrary prose (the false positive this guard replaces).
        case "$target" in
            bash|dash|sh|perl)
                case "${argv1##*/}" in
                    pbuilder|dpkg-buildpackage) return 0 ;;
                esac
                ;;
        esac
    done
    [ "$scanned" -eq 1 ] || return 2
    return 1
}
