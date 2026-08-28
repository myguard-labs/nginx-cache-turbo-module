#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Enforce that every ngx_http_cache_turbo_shctx_t member is explicitly
# initialised at zone carve (CARVE-INIT).
#
# WHY THIS CANNOT BE A RUNTIME TEST. The shctx is carved once per zone by a
# single ngx_slab_alloc() in ngx_http_cache_turbo_shm_init_zone(), which does
# NOT zero its return -- but on the fresh-carve path the slab arena is backed
# by freshly mapped anonymous memory, which the kernel hands over already
# zeroed. So an omitted initialiser reads 0 anyway, every test passes, and the
# omission is invisible from the outside. The correctness of ~70 counters,
# gauges and token sources therefore rests on an allocator property that
# nothing in the module asserts and that one ngx_slab_calloc free-list reuse
# would end. That is a structural invariant, so it needs a structural gate --
# the same shape of argument as lint-stripe-seam.sh, which is likewise
# invisible at today's N==1.
#
# The audit that prompted this (2026-08) was performed by eye and named five
# missing fields. Re-running it mechanically found EIGHT: markers, bg_inflight
# and owner_seq had been missed by the same reading that produced the list.
# owner_seq is the one that would have hurt -- claim() issues ++owner_seq as a
# never-reused single-flight token, and a garbage start can collide with a
# recycled node's stale refresh_owner. That miss rate is the case for this file
# existing: the manual pass is not reliable at this member count.
#
# THIS IS A PARSER, NOT A LEXER. The member harvest and the initialiser harvest
# were previously a hand-written awk lexer over the two files. Five consecutive
# review rounds each found a Major defect in the fix from the round before, and
# every one of them lived in the lexical model rather than in the invariant:
# a block comment that opened an initialiser window and never closed it, a line
# continuation inside a `//` comment, a bitfield width that made a member
# vanish from the gate entirely, a parenthesised declarator whose name is not
# the last token, CRLF records that defeated the phase-2 splice, and a prefix
# __attribute__ that deleted the member name. Each fix was correct; each grew a
# new surface, because a lexer approximating C is an open-ended set of shapes
# and the gate is only as good as the shapes someone thought of.
#
# clang is not an approximation. It performs translation phases 1-8 exactly, so
# line splicing, CRLF, comments, string and char literals, trigraphs, digraphs,
# attributes in any position, bitfields, macros and every declarator form are
# handled by the same code that compiles the module. The whole class is closed
# by construction rather than one shape at a time.
#
# THE COST is that this gate now needs a CONFIGURED nginx tree to parse
# against, because the header only makes sense with nginx's own headers around
# it. `configure` alone is enough -- no compilation, about three seconds -- and
# if no tree can be found this script exits 2 LOUDLY. A parser that cannot
# parse must never look like a clean gate; that is the single property the
# whole design rests on.
#
# BOTH CONFIGURATIONS ARE CHECKED. Four members sit behind
# `#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS)` and so do their carve stores.
# The old lexer skipped `#` lines and harvested every member unconditionally;
# it happened to agree, but only by being blind to both halves at once. A
# parser sees exactly one configuration per run, so the gate runs once per
# configuration and each must be self-consistent -- which additionally catches
# a member added under the guard whose store was added outside it.
#
# Usage: ci/tools/lint-carve-init.sh   (no arguments; the invariant spans a
#                                       fixed pair of files)
#   Env: NGX_SRC_TREE  a configured nginx tree to parse against; otherwise the
#                      trees under .build/ are searched.
#        CARVE_INIT_CLANG  clang to use (default: clang).
#        CARVE_INIT_CONFIGS  `both` (default) or `default` for the production
#                      configuration only; the selftest fixtures use the
#                      latter because none of them is TEST_FAULTS-sensitive.
# Exit:  0 clean, 1 a member has no initialiser, 2 could not run.

set -euo pipefail

# ../.. -- the REPO ROOT. This script lives in ci/tools/, so one climb lands in
# ci/, where the paths below match nothing. lint-shm-lock.sh spent months
# vacuously green on exactly that mistake; the guards below make an empty scan
# exit 2 rather than report ok.
cd "$(dirname "$0")/../.."

HDR=src/ngx_http_cache_turbo_module.h
SRC=src/ngx_http_cache_turbo_shm.c
AST=ci/tools/carve_init_ast.py

for f in "$HDR" "$SRC" "$AST"; do
    [ -f "$f" ] || {
        echo "lint-carve-init: $f missing -- refusing to report ok on an empty scan" >&2
        exit 2
    }
done

CLANG="${CARVE_INIT_CLANG:-clang}"
command -v "$CLANG" >/dev/null 2>&1 || {
    echo "lint-carve-init: $CLANG not found. This gate parses the real C, so it" >&2
    echo "      cannot fall back to a text scan -- that is the lexer this check" >&2
    echo "      was rewritten to retire. Install clang (ci/linter/install-linters.sh)." >&2
    exit 2
}

CONFIGS="${CARVE_INIT_CONFIGS:-both}"
case "$CONFIGS" in
    both|default) ;;
    *)
        echo "lint-carve-init: invalid CARVE_INIT_CONFIGS=$CONFIGS" >&2
        echo "      Expected 'both' or 'default'; refusing to skip a configuration." >&2
        exit 2
        ;;
esac

# --- locate a configured nginx tree ------------------------------------------
#
# A usable tree needs BOTH objs/Makefile (written by `configure`, and what
# carries ALL_INCS) and nginx's own sources, because the include paths in
# ALL_INCS are relative to the tree root and resolve to src/core and friends.
# Testing only for the Makefile is not enough: ci-build.sh leaves per-mode
# variant directories under .build/ that hold an objs/ and nothing else, and
# one of those is usually the NEWEST match. Selecting it produced a parse that
# failed on ngx_config.h -- a confusing error a long way from its cause.
#
# A tree that has been configured but never compiled is entirely sufficient,
# which is what keeps this affordable in a validation job that does not build.
tree_usable() {
    # Explicit if/return rather than an `&&`-list: `set -e` does not apply to a
    # bare `&&`-list, so the list form leaves the second test's failure
    # unenforced in some callers and, as the last command of a branch, can
    # become the enclosing compound's status.
    if [ ! -f "$1/objs/Makefile" ]; then
        return 1
    fi
    if [ ! -f "$1/src/core/ngx_config.h" ]; then
        return 1
    fi
    return 0
}

find_tree() {
    if [ -n "${NGX_SRC_TREE:-}" ]; then
        tree_usable "$NGX_SRC_TREE" || return 1
        printf '%s\n' "$NGX_SRC_TREE"
        return 0
    fi
    # Newest first, so a refreshed tree wins over a stale one. A glob cannot
    # order by mtime, and iterating `ls` output breaks on paths with spaces --
    # so the candidates come from a glob (safe) and the newest usable one is
    # chosen by comparing with `-nt` (no parsing at all).
    local d best=""
    for d in .build/nginx-*/; do
        d="${d%/}"
        [ -d "$d" ] || continue          # no match: the glob stayed literal
        tree_usable "$d" || continue
        if [ -z "$best" ] || [ "$d/objs/Makefile" -nt "$best/objs/Makefile" ]; then
            best="$d"
        fi
    done
    [ -n "$best" ] || return 1
    printf '%s\n' "$best"
}

# NGX_SRC_TREE=- means "this source is self-contained; parse it with no include
# set at all". That is exactly true of the selftest fixtures, which declare
# every type and object they use so they can exercise the harvest without a
# configured nginx anywhere on the machine. It is deliberately an explicit
# opt-in and never a fallback: silently parsing the REAL header without nginx's
# headers would fail, and any code path that turned that failure into a pass
# would be the silent-green this rewrite exists to eliminate.
SELF_CONTAINED=0
if [ "${NGX_SRC_TREE:-}" = "-" ]; then
    SELF_CONTAINED=1
fi

INCS=""
if [ "$SELF_CONTAINED" -eq 0 ]; then
    TREE="$(find_tree)" || {
        echo "lint-carve-init: no CONFIGURED nginx tree found." >&2
        echo "      This gate parses ${HDR} with clang against nginx's real include" >&2
        echo "      set, so it needs a tree where ./configure has run. It does NOT" >&2
        echo "      need one that has been compiled." >&2
        echo "      Point NGX_SRC_TREE at one, or run: bash ci/tools/ci-build.sh nginx <version>" >&2
        echo "      Refusing to report ok: a parser that cannot parse is not a clean gate." >&2
        exit 2
    }

    # ALL_INCS is MULTI-LINE -- backslash-continued across ten or so lines. A
    # `head -1` here drops `-I objs`, and the parse then dies on
    # ngx_auto_headers.h with an error that looks like a broken header rather
    # than a truncated include path. The sed range runs from the assignment to
    # the first line NOT ending in a backslash, which is exactly the
    # continuation the Makefile writes.
    INCS="$(sed -n '/^ALL_INCS =/,/[^\\]$/p' "$TREE/objs/Makefile" \
            | sed 's/^ALL_INCS =//; s/\\$//' | tr '\n' ' ')"
    if [ -z "${INCS// /}" ]; then
        echo "lint-carve-init: could not read ALL_INCS from $TREE/objs/Makefile --" >&2
        echo "      refusing to guess at the include set." >&2
        exit 2
    fi
fi

# Everything the command line refers to is resolved to an absolute path FIRST.
# The include paths in ALL_INCS are relative to the nginx tree ROOT, so the
# parse has to run from there, and a relative path would silently re-anchor
# against the tree once the subshell changes directory -- the failure mode that
# makes `-I objs` land somewhere harmless-looking and the parse die on an
# unrelated header.
MODULE_SRC="$PWD/src"
ABS_SRC="$PWD/$SRC"
ABS_AST="$PWD/$AST"
if [ "$SELF_CONTAINED" -eq 1 ]; then
    RUN_DIR="$PWD"
else
    RUN_DIR="$(cd "$TREE" && pwd)"
fi

run_config() {  # run_config <label> [extra clang args...]
    local label="$1"; shift
    local out status
    if [ "$SELF_CONTAINED" -eq 1 ]; then
        out="$(cd "$RUN_DIR" && python3 "$ABS_AST" "$CLANG" "$ABS_SRC" "$@" 2>&1)"
    else
        # CARVE_INIT_PIN_COUNT=1 only ever runs against the REAL module header
        # (never the self-contained selftest fixture, which declares a
        # same-named struct of two or three members on purpose): it asserts
        # the shctx member count read off the AST matches
        # EXPECTED_MEMBER_COUNT in carve_init_ast.py exactly, which is the
        # compensating control for AST-shape drift across clang majors --
        # collect_initialised() fails closed when a member vanishes from the
        # INITIALISER harvest, but nothing else catches one vanishing from the
        # MEMBER harvest itself.
        # shellcheck disable=SC2086  # INCS is a deliberate word-split arg list
        out="$(cd "$RUN_DIR" && CARVE_INIT_PIN_COUNT=1 python3 "$ABS_AST" "$CLANG" \
            "$ABS_SRC" "$@" $INCS -I "$MODULE_SRC" 2>&1)"
    fi
    status=$?
    printf '%s\n' "$out" | sed "s/^/[$label] /"
    return $status
}

# The production configuration and the TEST_FAULTS configuration are DIFFERENT
# translation units with different member sets, and each must be internally
# consistent. Both run before either verdict is reported, so a header carrying
# two independent omissions takes one round-trip rather than two.
#
# Exit 2 DOMINATES exit 1. "Could not run" and "ran and found a missing
# initialiser" are different answers and the caller acts on them differently:
# collapsing every non-zero status into 1 would report a parse failure as a
# finding, sending the reader to look for a member that was never checked.
rc=0
merge_rc() {  # merge_rc <status>
    [ "$1" -eq 0 ] && return
    if [ "$1" -eq 2 ] || [ "$rc" -eq 2 ]; then rc=2; else rc=1; fi
}

run_config "default" || merge_rc $?

# CARVE_INIT_CONFIGS=default runs the production configuration only. The
# selftest fixtures set it: none of them mentions TEST_FAULTS, so for those the
# second parse is duplicated work -- 75 rows x an extra clang invocation, which
# is most of the suite's runtime. It is NOT a way to skip a configuration on
# the real tree, where both must be checked and the default runs both.
if [ "$CONFIGS" = "both" ]; then
    run_config "test-faults" -DNGX_HTTP_CACHE_TURBO_TEST_FAULTS=1 || merge_rc $?
fi

exit "$rc"
