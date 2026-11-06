#!/usr/bin/env bash
#
# Re-enable UBSan checks on the MODULE's objects in a configured nginx tree.
#   asan-module-reinstrument.sh <objs/Makefile> <checks>
#     checks: comma list passed to -fsanitize=, e.g. alignment,nonnull-attribute
#
# ci-build.sh's asan mode turns some UBSan checks off build-wide
# (-fno-sanitize=... in --with-cc-opt) because nginx CORE trips them as benign
# false positives: alignment for the HTTP/2 ngx_http_v2_write_uint32 frame
# writes, nonnull-attribute for the --with-debug memcpy(NULL, 0) in
# src/core/ngx_string.c. nginx applies --with-cc-opt to every object, so those
# exclusions also blinded the module's own code -- e.g.
# test_l2_restore_href_array_alignment_ubsan depends on UBSan alignment to
# catch a misaligned refs[] access in module source.
#
# This rewrites only the compile recipes of objs/addon/* targets (the
# --add-module sources) to append -fsanitize=<checks> after $(CFLAGS). The
# later flag wins for both gcc and clang, so module objects get the checks back
# while core objects keep the exclusion. -fno-sanitize-recover=undefined from
# CFLAGS already covers these checks, so a module hit stays fatal.
#
# Fails closed: if the Makefile has no addon objects, or any addon compile
# recipe cannot be rewritten (an nginx Makefile format change), it exits
# non-zero instead of silently leaving the module unchecked. Idempotent.

set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <objs/Makefile> <checks>" >&2
    exit 2
fi
makefile="$1"
checks="$2"
case "$checks" in
    ''|*[!a-z,-]*)
        echo "asan-module-reinstrument: bad check list: '$checks'" >&2
        exit 2
        ;;
esac
[ -f "$makefile" ] || { echo "asan-module-reinstrument: no $makefile" >&2; exit 2; }

flag="-fsanitize=$checks"
tmp="$makefile.reinstrument.$$"
count="$tmp.count"
trap 'rm -f "$tmp" "$count"' EXIT

# A target block starts at "objs/addon/....o:" and ends at the first blank
# line. Inside it, the single "$(CC) -c $(CFLAGS)" recipe line gets the flag.
# The END block writes "<targets> <rewritten>" to $count for the guard below.
awk -v flag="$flag" -v count="$count" '
    /^objs\/addon\/[^:]*\.o:/ { in_addon = 1; targets++; done_this = 0 }
    /^$/ { in_addon = 0 }
    in_addon && !done_this && /^\t\$\(CC\) -c \$\(CFLAGS\)/ {
        if (index($0, " " flag " ") == 0) {
            sub(/\$\(CFLAGS\)/, "$(CFLAGS) " flag)
        }
        rewritten++
        done_this = 1
    }
    { print }
    END { printf "%d %d\n", targets, rewritten > count }
' "$makefile" > "$tmp"

read -r targets rewritten < "$count"
rm -f "$count"

if [ "$targets" -eq 0 ]; then
    echo "asan-module-reinstrument: no objs/addon/*.o targets in $makefile" >&2
    exit 1
fi
if [ "$rewritten" -ne "$targets" ]; then
    echo "asan-module-reinstrument: rewrote $rewritten of $targets addon" \
        "compile recipes in $makefile (nginx Makefile format changed?)" >&2
    exit 1
fi

mv "$tmp" "$makefile"
trap - EXIT
printf 'asan-module-reinstrument: %s on %d addon objects\n' "$flag" "$targets"
