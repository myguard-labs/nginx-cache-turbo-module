#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Enforce that every ngx_http_cache_turbo_shctx_t member is explicitly
# initialised at zone carve (CARVE-INIT).
#
# WHY THIS CANNOT BE A RUNTIME TEST. The shctx is carved once per zone by a
# single ngx_slab_alloc() in ngx_http_cache_turbo_shm_init_zone(), which
# does NOT zero
# its return -- but on the fresh-carve path the slab arena is backed by freshly
# mapped anonymous memory, which the kernel hands over already zeroed. So an
# omitted initialiser reads 0 anyway, every test passes, and the omission is
# invisible from the outside. The correctness of ~70 counters, gauges and
# token sources therefore rests on an allocator property that nothing in the
# module asserts and that one ngx_slab_calloc free-list reuse would end. That
# is a structural invariant, so it needs a structural gate -- the same shape of
# argument as lint-stripe-seam.sh, which is likewise invisible at today's N==1.
#
# The audit that prompted this (2026-08) was performed by eye and named five
# missing fields. Re-running it mechanically found EIGHT: markers, bg_inflight
# and owner_seq had been missed by the same reading that produced the list.
# owner_seq is the one that would have hurt -- claim() issues ++owner_seq as a
# never-reused single-flight token, and a garbage start can collide with a
# recycled node's stale refresh_owner. That miss rate is the case for this
# file existing: the manual pass is not reliable at this member count.
#
# WHAT IT CHECKS. Every member declared in ngx_http_cache_turbo_shctx_t must
# appear as an `sh->NAME =` assignment inside the carve block of
# ngx_http_cache_turbo_shm_init_zone().
# Explicit padding members (_pad*) are exempt: they are layout, never read.
#
# Usage: ci/tools/lint-carve-init.sh   (no arguments; the invariant spans a
#                                       fixed pair of files)
# Exit:  0 clean, 1 a member has no initialiser, 2 could not run.

set -euo pipefail

# ../.. -- the REPO ROOT. This script lives in ci/tools/, so one climb lands in
# ci/, where the paths below match nothing. lint-shm-lock.sh spent months
# vacuously green on exactly that mistake; the guards below make an empty scan
# exit 2 rather than report ok.
cd "$(dirname "$0")/../.."

HDR=src/ngx_http_cache_turbo_module.h
SRC=src/ngx_http_cache_turbo_shm.c

# Debian /usr/bin/awk is mawk (ci/tools/install-requirements.sh documents this),
# and mawk has no 4-argument split() -- it dies at PARSE time, before a single
# line is read, so the failure is a syntax error rather than a wrong answer.
# ubuntu-latest ships gawk, but lint.yml allows a self-hosted POOL and the
# commit hook runs on developer machines, so neither can be assumed. The
# separator tracking that needed the 4th argument is gone (statements are split
# by hand below), but pin gawk when it exists anyway: this script relies on
# nothing else gawk-only, and the pin costs nothing.
if command -v gawk >/dev/null 2>&1; then
    AWK="gawk"
else
    # shellcheck disable=SC2209  # a program NAME, not a command substitution
    AWK="awk"
fi

# --- 0. strip comments and literals ------------------------------------------
#
# EVERY pass below parses the output of this function, never a raw file.
#
# A comment or a string is not code, and any pass that reads it as code can be
# steered by ordinary prose. The bug that forced this: a block comment naming an
# initialiser helper and carrying no `;` --
#
#     /* the LRU is set up by ngx_queue_init( further down */
#
# -- opened the INIT_HELPERS window and never closed it, crediting every pure
# read for the rest of the carve block as an initialisation. A `;` or a `{`
# inside a string literal misleads the statement splitter and the brace-depth
# tracker the same way. Rather than patch the one pass that was exploited, both
# passes now consume stripped text only, so the whole class is closed at once.
#
# Replacement is BLANK-PRESERVING at line granularity: comment bodies become
# spaces and string bodies become a single-space placeholder, so line numbers,
# line count and statement structure survive. Handles multi-line block comments
# (state carries across lines), line comments, "strings" and char literals,
# backslash escapes inside both, and never treats a quote inside a comment or a
# comment marker inside a string as its own thing.
#
# TRANSLATION PHASE 2 IS DONE FIRST, AND SEPARATELY. A physical line ending in
# a backslash is spliced onto the next one BEFORE any lexing happens, which is
# what the C standard actually specifies (phase 2 runs before phase 3 forms
# comments and tokens). Handling the carry inside the lexer instead means
# handling it once per state -- line comment, block comment, string, char
# literal, plain code -- and the bug that forced this rewrite was exactly one
# of those states being missed:
#
#     // note \
#     ngx_queue_init(&st->sh->misses)
#
# is ONE line comment in C. Lexing line-at-a-time terminated it at the first
# end-of-line and fed the second physical line to both passes as live code,
# which -- because the INIT_HELPERS window is sticky until a `;` -- could
# credit an arbitrary RUN of members from a single comment. Splicing first
# closes that for every state at once, including the ones nobody has written
# an exploit for yet: continued string literals, continued macro bodies and
# ordinary declarations wrapped across physical lines.
#
# An EVEN number of trailing backslashes does NOT continue: the last one is
# itself escaped. The count is taken on the RAW physical line, before lexing,
# because phase 2 precedes phase 3 -- a trailing backslash splices even inside
# a comment or a string, which is the whole point.
#
# Line count is preserved by emitting the spliced group's stripped text on the
# LAST physical line of the group and blanks for the ones before it. The
# alternative -- redistributing the text back across the original column
# offsets -- would let a construct be cut in half again at exactly the
# boundaries phase 2 exists to erase. Keeping the logical line whole is what
# lets a wrapped declaration or a wrapped helper call parse as the single
# statement it is; the diagnostics depend only on line NUMBERS remaining
# aligned, which they do.
strip_code() {
    "$AWK" '
        # --- phase 2: splice line continuations -----------------------------
        # `pend` holds the spliced logical line so far; `held` counts the
        # physical lines already folded into it, each of which owes a blank.
        function trailing_backslashes(s,   k) {
            k = 0
            while (k < length(s) && substr(s, length(s) - k, 1) == "\\") k++
            return k
        }
        BEGIN { inblock = 0; pend = ""; held = 0 }
        {
            raw = $0
            if (trailing_backslashes(raw) % 2 == 1) {
                # drop the splicing backslash itself, exactly as phase 2 does
                pend = pend substr(raw, 1, length(raw) - 1)
                held++
                next
            }
            line = pend raw
            pend = ""
            # --- phase 3: comments and literals -----------------------------
            out = ""
            i = 1
            n = length(line)
            while (i <= n) {
                c = substr(line, i, 1)
                d = substr(line, i, 2)
                if (inblock) {
                    if (d == "*/") { inblock = 0; out = out "  "; i += 2 }
                    else           { out = out " "; i++ }
                    continue
                }
                if (d == "/*") { inblock = 1; out = out "  "; i += 2; continue }
                if (d == "//") { break }
                if (c == "\"" || c == "'"'"'") {
                    q = c
                    i++
                    while (i <= n) {
                        e = substr(line, i, 1)
                        if (e == "\\") { i += 2; continue }
                        if (e == q) { i++; break }
                        i++
                    }
                    # one placeholder space: the literal is gone, the token
                    # separation it provided is not.
                    out = out " "
                    continue
                }
                out = out c
                i++
            }
            # one blank per physical line folded in, then the logical line
            while (held > 0) { print ""; held-- }
            print out
        }
        END {
            # A file whose LAST line ends in a backslash has an unterminated
            # splice. Emitting nothing would silently swallow the line; emit
            # what was accumulated so the member or store on it is still seen,
            # and keep the line count exact.
            if (held > 0 || pend != "") {
                while (held > 1) { print ""; held-- }
                print pend
            }
        }
    ' "$1"
}

for f in "$HDR" "$SRC"; do
    [ -f "$f" ] || {
        echo "lint-carve-init: $f missing -- refusing to report ok on an empty scan" >&2
        exit 2
    }
done

# --- 1. the declared members -------------------------------------------------
#
# Delimited by the struct's own opening and closing lines rather than fixed line
# numbers, so the check follows the struct as the header is edited. Comment
# bodies are dropped first (a `*`-prefixed continuation line can otherwise end
# in `;` and read as a declaration), then any line ending in `;` at one level of
# brace nesting is a member and its name is the last identifier before the `;`,
# past any array bound or __attribute__.
#
# Both delimiters are REQUIRED to have matched. An awk that only sets `inside`
# on the opener runs to end-of-file when the closing line changes spelling, and
# harvests the members of every struct that follows -- reporting a screenful of
# bogus names as "uninitialised" (exit 1) instead of admitting it could not
# parse (exit 2). Caught by mutation: renaming the closing typedef produced a
# 190-name failure list naming fields of unrelated structs.
members="$(strip_code "$HDR" | "$AWK" '
    # Split a declaration into declarators on TOP-LEVEL commas only. A comma
    # inside parens (a function-pointer parameter list) or brackets is part of
    # one declarator, not a separator between two.
    function split_declarators(s, arr,   i, ch, depth, cur, k) {
        depth = 0; cur = ""; k = 0
        for (i = 1; i <= length(s); i++) {
            ch = substr(s, i, 1)
            if (ch == "(" || ch == "[") depth++
            else if (ch == ")" || ch == "]") { if (depth > 0) depth-- }
            if (ch == "," && depth == 0) { arr[++k] = cur; cur = ""; continue }
            cur = cur ch
        }
        arr[++k] = cur
        return k
    }
    /^typedef struct ngx_http_cache_turbo_shctx_s \{/ { inside = 1; opened = 1; next }
    inside && /^\} ngx_http_cache_turbo_shctx_t;/     { inside = 0; closed = 1 }
    /^\}/ && inside && !closed                        { unterminated = 1 }
    !inside { next }
    /^[[:space:]]*#/   { next }        # preprocessor
    {
        line = $0
        # Comments and literals are already gone (strip_code), so no comment
        # handling belongs here -- a second, weaker stripper at this level is
        # exactly how the block-comment hole got in.
        #
        # Brace depth. The header comment claims one level of nesting, but
        # nothing enforced it: the members of a nested anonymous union or
        # struct were harvested as if they were top-level, demanding
        # `sh->inner = ...` stores for names that are not reachable that way.
        # That is an UNSATISFIABLE gate -- CI red on correct code, the worst
        # failure mode a linter has. Depth is now tracked, and any nesting is
        # refused LOUDLY rather than answered wrongly.
        opens = gsub(/\{/, "{", line)
        closes = gsub(/\}/, "}", line)
        if (depth > 0 || opens > closes) {
            nested = 1
        }
        depth += opens - closes
        if (depth < 0) depth = 0
        if (nested) next
        if (line !~ /;/) next
        sub(/;.*/, "", line)
        sub(/__attribute__.*/, "", line)
        # Capture the base type of the declaration BEFORE the array bound is
        # stripped: the _pad* exemption below must be able to prove a member is
        # genuinely `u_char NAME[...]` layout filler and not merely named like
        # it. `raw` keeps the array bracket the name-parse discards.
        raw = line
        gsub(/^[[:space:]]+/, "", raw)
        is_uchar_base = (raw ~ /^u_char[[:space:]]/)
        gsub(/[[:space:]]+$/, "", line)
        # A declaration may carry several declarators: `ngx_uint_t a, b;`.
        # Taking only the last identifier would hide every earlier name from
        # the gate permanently, so split on ',' and take the last identifier of
        # EACH declarator. Latent when written (the struct has no comma
        # declarators today); fixed so adding one cannot silently open a hole.
        #
        # The split is DEPTH-AWARE. A plain split on "," cuts a function
        # pointer parameter list in half -- `void (*cb)(void *, int);` becomes
        # `void (*cb)(void *` and ` int)` and neither half parses -- so commas
        # nested inside parens or brackets are not declarator separators.
        #
        # The array-bound test is PER-DECLARATOR, not per-line. `u_char
        # _pad_a[8], _pad_b;` has an array base type and a scalar second
        # declarator; testing the line as a whole would stamp "padok" onto
        # _pad_b and silently exempt a member nothing proves is filler --
        # reopening, along this axis, the exact hole the type check closes.
        ndecl = split_declarators(line, decls)
        for (d = 1; d <= ndecl; d++) {
            piece = decls[d]
            # A parenthesised or pointer declarator is not layout filler even
            # with a bracket: `u_char (*_pad_pa)[8];` is an 8-byte POINTER.
            had_bracket = (piece ~ /\[[^]]*\]/ && piece !~ /[(*]/)
            # Array bounds are stripped in a LOOP. A single sub() removes one
            # bound only, so `ngx_uint_t m[2][3];` kept a `[3]` on the token,
            # failed the identifier test and hit the catch-all -- exit 2, CI
            # red, on ordinary C the header does not use today but plausibly
            # will. A false FAIL on correct code is the second-worst outcome
            # this checker has.
            while (piece ~ /\[[^]]*\]/) sub(/\[[^]]*\]/, "", piece)
            # Bitfield width. `unsigned degraded:1` otherwise leaves the token
            # as `degraded:1`, which fails the identifier test below and used
            # to be DISCARDED -- the member vanished from the gate entirely and
            # no initialiser was ever demanded for it. The width is not part of
            # the name, so strip it; the catch-all below then guarantees that
            # any OTHER unparsed declarator form fails loudly instead of
            # disappearing the same way.
            sub(/:[[:space:]]*[0-9]+[[:space:]]*$/, "", piece)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", piece)
            if (piece == "") continue
            # A PARENTHESISED DECLARATOR holds the name inside the parens, and
            # everything after the closing paren is a suffix -- a function
            # pointer parameter list, an array bound -- not part of the name.
            # `void (*cb)(void *);` flattened with gsub(/[()]/) produced
            # `void *cb void`, whose last token is `void`: the catch-all fired
            # and turned CI red. Parse the parenthesised group FIRST and keep
            # only what is inside it, so the name is read from where C puts it.
            # Repeat, because the group can nest: `void (*(*f)(int))(void);`.
            while (match(piece, /\([^()]*\)/)) {
                inner = substr(piece, RSTART + 1, RLENGTH - 2)
                # A parameter list -- the group that FOLLOWS the declarator --
                # contributes no name. The declarator group is the one holding
                # a `*` or a bare identifier that is not itself a type list;
                # taking the group only when the text before it is not already
                # a complete declarator keeps the two apart.
                if (inner ~ /\*/ || RSTART == 1) {
                    piece = inner
                } else {
                    # Not a declarator group. Excise the group and KEEP BOTH
                    # SIDES: a trailing parameter list leaves the name on the
                    # left, but an ATTRIBUTE MACRO sits BETWEEN the type and
                    # the name -- `ngx_uint_t NGX_ALIGNED(64) slot;` -- and
                    # truncating to the left there throws the name away and
                    # harvests `NGX_ALIGNED` instead. Excision handles both:
                    # the parameter list leaves trailing whitespace that the
                    # name parse ignores, and the attribute macro leaves the
                    # macro name as one more leading token before `slot`.
                    piece = substr(piece, 1, RSTART - 1) " " \
                            substr(piece, RSTART + RLENGTH)
                }
                while (piece ~ /\[[^]]*\]/) sub(/\[[^]]*\]/, "", piece)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", piece)
            }
            n = split(piece, parts, /[[:space:]*]+/)
            if (n == 0) continue
            name = parts[n]
            # An ATTRIBUTE MACRO between the type and the name -- `ngx_uint_t
            # NGX_ALIGNED(64) slot;` -- is removed by the parameter-list branch
            # above, so the name is still the last token. A macro-TYPED member
            # (`NGX_ATOMIC_T counter;`) needs nothing special: the type is just
            # another leading token.
            if (name ~ /^[A-Za-z_][A-Za-z0-9_]*$/) {
                # Tag pad-eligibility onto the name so the exemption is a
                # TYPE decision, not a name-prefix one.
                if (is_uchar_base && had_bracket) print name "\tpadok"
                else                             print name "\t-"
            } else {
                # CATCH-ALL. A declarator this pass cannot parse is never
                # dropped. Silently discarding one removes the member from the
                # world of the gate -- nothing demands an initialiser, the
                # count still looks plausible, and the report reads exactly
                # like a passing gate. That is the whole failure class this
                # checker exists to catch, so an unrecognised form is a hard
                # error naming the text it could not parse. Every future
                # declarator shape lands here loudly rather than invisibly.
                print "ERR:unparsed-declarator:" piece > "/dev/stderr"
                bad_declarator = 1
            }
        }
    }
    END {
        if (!opened) { print "ERR:no-opening-line" > "/dev/stderr"; exit 3 }
        if (!closed) { print "ERR:no-closing-line" > "/dev/stderr"; exit 3 }
        if (unterminated) { print "ERR:unterminated" > "/dev/stderr"; exit 3 }
        if (nested) { print "ERR:nested-aggregate" > "/dev/stderr"; exit 4 }
        if (bad_declarator) { print "ERR:unparsed-declarator" > "/dev/stderr"; exit 5 }
    }
' | sort -u)" || harvest_rc=$?
# The awk END block distinguishes its refusals by exit status so each one can
# name its own cause. Without this they collapse into one "could not delimit"
# message that sends the reader to the wrong place entirely.
case "${harvest_rc:-0}" in
    0) ;;
    4)
        echo "lint-carve-init: ngx_http_cache_turbo_shctx_t contains a NESTED struct/union. This checker harvests top-level members only, and harvesting a nested member as if it were top-level would demand an 'sh->NAME =' store that cannot exist -- an unsatisfiable gate. Teach this script the nesting, or flatten the declaration." >&2
        exit 2
        ;;
    5)
        echo "lint-carve-init: a declarator in ngx_http_cache_turbo_shctx_t could not be parsed (see ERR:unparsed-declarator above). It is NOT being skipped: a dropped member is one nothing ever demands an initialiser for, which is the silent-green hole this checker exists to close. Teach this script the form, or spell the member conventionally." >&2
        exit 2
        ;;
    *)
        echo "lint-carve-init: could not delimit ngx_http_cache_turbo_shctx_t in $HDR -- its opening 'typedef struct ngx_http_cache_turbo_shctx_s {' or closing '} ngx_http_cache_turbo_shctx_t;' line has changed. Refusing to guess at the member set." >&2
        exit 2
        ;;
esac

if [ -z "$members" ]; then
    echo "lint-carve-init: parsed ZERO members from $HDR -- refusing to report ok on an empty scan" >&2
    exit 2
fi

# $members rows are "NAME<TAB>padok|-". Keep the tagged list for the exemption
# decision below and derive a bare-name list for counting.
member_names="$(printf '%s\n' "$members" | cut -f1)"

# --- 2. the members the carve block initialises ------------------------------
#
# Bounded to the CARVE BLOCK, not the whole function: an `sh->x = ...` store
# anywhere else in the file -- and, critically, anywhere else in this same
# function -- must not count as carve initialisation.
#
# The window opens at the `st->sh = ngx_slab_alloc(` line and closes at the
# first column-0 `}`. It deliberately does NOT open at the function's opening
# line, because ngx_http_cache_turbo_shm_init_zone() has two early-return
# branches ABOVE the slab alloc -- the `octx` reload inherit and the
# `shm.exists` branch -- each of which legitimately stores `st->sh->admission`.
# A window starting at the function opener swallows both, so a member
# initialised ONLY in a reload branch would satisfy the gate. That placement is
# exactly what the FAIL message below tells the developer not to do: it never
# runs on a fresh carve, and on reload it overwrites inherited live state.
# Caught by the agent review of this commit, reproduced by mutation.
#
# TWO accepted forms, because the block legitimately uses both:
#   assignment       st->sh->hits = 0;
#   initialiser call ngx_rbtree_init(&st->sh->rbtree, ...) / ngx_queue_init(&st->sh->lru)
# The second is matched on `&...sh->NAME` -- passing a member's address to an
# init helper is how the rbtree, its sentinel and the two queue heads are set
# up, and treating those as uninitialised would make the gate unsatisfiable.
# Note this deliberately does not try to prove the callee initialises what it
# is handed; that is beyond a textual gate. It proves the member was not
# FORGOTTEN, which is the failure class here.
# Calls that genuinely initialise what they are handed. A member set up by a
# helper NOT named here reads as uninitialised, so adding a new initialiser
# helper to the carve block means adding it here too -- the FAIL message says so.
INIT_HELPERS='(^|[^A-Za-z0-9_])(ngx_rbtree_init|ngx_queue_init|ngx_memzero|ngx_rbtree_sentinel_init)[[:space:]]*[(]'

# The carve target, spelled once. Every harvest below anchors on this literal
# text rather than on a bare `sh->` suffix. An unanchored suffix match credits
# ANY object that happens to end in `sh->` -- `ngx_queue_init(&other->sh->x)`
# initialises a different struct entirely, and used to satisfy this gate for
# the shctx member of the same name. Both the assignment harvest and the
# address-of harvest had that hole; both are anchored now.
CARVE_OBJ='st->sh->'

inits="$(strip_code "$SRC" | "$AWK" -v INIT_HELPERS="$INIT_HELPERS" -v OBJ="$CARVE_OBJ" '
    # the carve block starts at the slab alloc, NOT at the function opener --
    # see the comment above. Track the function too, so a same-named store in
    # a LATER function cannot reopen the window.
    /^ngx_http_cache_turbo_shm_init_zone\(/ { infn = 1; depth = 0 }
    infn && /st->sh[[:space:]]*=[[:space:]]*ngx_slab_alloc\(/ { inside = 1 }
    # The function ends where its braces BALANCE, not at the first column-0 `}`.
    # A column-0 brace occurs inside the function whenever an #if-gated or
    # macro-introduced block closes at column 0, and closing the window there
    # truncated the scan -- every member initialised after that point read as
    # forgotten. A false FAIL on correct code, and the header already carries
    # preprocessor lines inside the struct, so the shape is not hypothetical.
    # Comments and literals are stripped upstream, so no brace counted here can
    # come from prose or from a string.
    infn {
        bl = $0
        opens = gsub(/\{/, "{", bl)
        bl2 = $0
        closes = gsub(/\}/, "}", bl2)
        depth += opens - closes
        if (depth <= 0 && seen_open) { inside = 0; infn = 0; next }
        if (opens > 0) seen_open = 1
    }
    !inside { next }
    {
        line = $0
        # assignment form
        rest = line
        # `[^-+*/%&|^<>!=]=[^=]` so a compound assignment (+=, |=, &=, ...) is
        # NOT read as carve initialisation -- it mutates a value that must
        # already exist. Latent when written: zero compound assigns in the
        # carve block today.
        # Anchored on the literal carve target (OBJ), not on a bare `sh->`
        # suffix: `other->sh->hits = 0` must not credit the shctx member.
        # The trailing `[...]` / `.field` / `->field` run lets an AGGREGATE
        # member be initialised element-wise: `sh->stripes[0].x = 0` names
        # `stripes`, which is the member the header declares. Without it an
        # array or nested-struct member is unsatisfiable -- no spelling of an
        # element-wise store would ever satisfy the gate, so correct code
        # turns CI red. Latent today (every array member in the struct is an
        # exempt u_char pad), fixed so adding one cannot break the build.
        while (match(rest, OBJ "[A-Za-z_][A-Za-z0-9_]*([[][^]]*[]]|[.][A-Za-z_][A-Za-z0-9_]*|->[A-Za-z_][A-Za-z0-9_]*)*[[:space:]]*[^-+*/%&|^<>!=[:space:]]?=[^=]")) {
            s = substr(rest, RSTART + length(OBJ), RLENGTH - length(OBJ))
            # keep only the FIRST identifier -- the member the header declares
            sub(/[^A-Za-z0-9_].*/, "", s)
            sub(/[[:space:]]*=.*/, "", s)
            # A preceding identifier character means OBJ matched the tail of a
            # longer name; anchoring is only real if the left edge is checked.
            pre = (RSTART > 1) ? substr(rest, RSTART - 1, 1) : " "
            if (pre !~ /[A-Za-z0-9_>.]/) print s
            rest = substr(rest, RSTART + RLENGTH)
        }
        # Address-of form (initialiser call). Taking the address of a member
        # proves nothing on its own -- `memcmp(&st->sh->misses, ...)` is a pure
        # READ and used to satisfy this gate, a silent-green false negative.
        # Only a call that actually initialises what it is handed counts, so
        # the address-of harvest is scoped to the argument list of a call named
        # in INIT_HELPERS.
        #
        # Scoped to the CALL, not the line: `ngx_queue_init(&sh->lru),
        # memcmp(&sh->foo, ...)` puts an allowlisted call and a pure read on
        # one line, and a line-level test would count `foo`. Each statement is
        # split out, then only the text from an allowlisted call name to the
        # end of that statement is harvested.
        # The window is STICKY across lines. A call whose argument list wraps
        # puts its `&sh->NAME` args on a continuation line that contains no
        # allowlisted name; a per-line test skips that line and reports the
        # members forgotten -- a false FAIL on correct code, which is worse
        # than the read it was closing. `in_helper` stays set from the call
        # name until the statement-terminating `;`.
        # Statements are split by hand rather than with a 4-argument split().
        # The 4th argument is a gawk extension: on mawk -- which is the Debian
        # /usr/bin/awk, per ci/tools/install-requirements.sh -- the script dies
        # at PARSE time, before reading a line, so the checker does not run at
        # all on a self-hosted runner or a developer machine. Walking the line
        # needs no extension and tracks the separator exactly the same way.
        srest = line
        while (length(srest) > 0) {
            sc = index(srest, ";")
            if (sc > 0) { stmt = substr(srest, 1, sc - 1); srest = substr(srest, sc + 1); term = 1 }
            else        { stmt = srest; srest = ""; term = 0 }

            if (match(stmt, INIT_HELPERS)) {
                in_helper = 1
                stmt = substr(stmt, RSTART)
            }
            if (in_helper) {
                # Anchored on OBJ, same reason as the assignment harvest above:
                # the old pattern matched any `...sh->NAME` and then stripped
                # everything up to `sh->`, so `&other->sh->owner_seq` was
                # credited to the carved struct.
                rest = stmt
                while (match(rest, "&" OBJ "[A-Za-z_][A-Za-z0-9_]*")) {
                    s = substr(rest, RSTART + 1 + length(OBJ), RLENGTH - 1 - length(OBJ))
                    print s
                    rest = substr(rest, RSTART + RLENGTH)
                }
            }
            # a `;` closed this statement -- the helper window ends with it
            if (term) in_helper = 0
        }
    }
' | sort -u)"

if [ -z "$inits" ]; then
    echo "lint-carve-init: parsed ZERO initialisers from $SRC -- shm_init_zone's signature or brace style must have changed; this checker cannot report ok on an empty scan" >&2
    exit 2
fi

# --- 3. the difference -------------------------------------------------------
#
# _pad* members are explicit layout filler. Nothing reads them, so they are the
# one class that legitimately needs no store.
#
# The exemption is a TYPE decision, not a name-prefix one. A member is exempt
# only when it is BOTH named _pad* AND declared `u_char NAME[...]` -- the
# harvest above tags that as "padok". Prefix alone was a silent-green hole: an
# `ngx_uint_t _pad_but_real` that something actually reads was exempted and the
# gate reported ok, which is the exact failure class this checker exists to
# catch. A _pad*-named member of any other type is now a FAIL, not an exemption.
missing=""
mistyped_pad=""
while IFS="$(printf '\t')" read -r m tag; do
    [ -n "$m" ] || continue
    case "$m" in
        _pad*)
            if [ "$tag" = "padok" ]; then
                continue
            fi
            mistyped_pad="$mistyped_pad $m"
            ;;
    esac
    printf '%s\n' "$inits" | grep -qx -- "$m" || missing="$missing $m"
done <<EOF
$members
EOF

# Both lists are reported before exiting. Bailing on the first one makes a
# header with a mistyped pad AND a forgotten member take two round-trips: fix
# the pad, re-run, discover an unrelated second failure.
fail=0

if [ -n "$mistyped_pad" ]; then
    fail=1
    echo "FAIL: member(s) named _pad* but NOT declared 'u_char NAME[...]':" >&2
    for m in $mistyped_pad; do
        echo "        $m" >&2
    done
    echo "      The _pad* exemption covers layout filler only. It requires the" >&2
    echo "      literal spelling 'u_char NAME[...]'; a pointer or a parenthesised" >&2
    echo "      declarator is not filler. Either declare it as a u_char array, or" >&2
    echo "      rename it and initialise it at the carve." >&2
fi

if [ -n "$missing" ]; then
    fail=1
    echo "FAIL: ngx_http_cache_turbo_shctx_t member(s) never initialised at zone carve:" >&2
    for m in $missing; do
        echo "        $m" >&2
    done
    echo "      ngx_slab_alloc() does not zero. Add an 'st->sh->NAME = ...;' to the" >&2
    echo "      carve block in ngx_http_cache_turbo_shm_init_zone() ($SRC)." >&2
    echo "      If NAME is instead set up by an initialiser helper taking its" >&2
    echo "      address, add that helper to INIT_HELPERS in this script." >&2
    echo "      Do NOT add it to the shm.exists reload branch: that path deliberately" >&2
    echo "      inherits live state across a SIGHUP and zeroing there would wipe it." >&2
fi

if [ "$fail" -eq 1 ]; then
    exit 1
fi

n_checked="$(printf '%s\n' "$member_names" | grep -vc '^_pad' || true)"
echo "ok: all $n_checked shctx members initialised at zone carve (CARVE-INIT)"
