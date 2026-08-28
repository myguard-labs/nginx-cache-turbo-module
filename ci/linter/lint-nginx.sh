#!/usr/bin/env bash
# ci/linter/lint-nginx.sh -- nginx-specific source conventions for src/*.[ch].
#
# What no generic C linter knows: an nginx module must use the nginx allocator,
# the nginx string/number helpers and the nginx source style, because it is
# compiled into a worker with a pool-based lifetime and a shared coding
# standard. flawfinder/cppcheck/semgrep all pass code that leaks a malloc()
# into a request pool or calls atoi() on attacker input.
#
# Checks (each one line per finding, "file:line: rule: text"):
#   libc-alloc   malloc/calloc/realloc/free      -> ngx_palloc/ngx_pcalloc/ngx_pfree
#   libc-str     strcpy/strcat/sprintf/strncpy   -> ngx_cpymem/ngx_snprintf
#   libc-num     atoi/atol/strtol on request data -> ngx_atoi/ngx_atoof
#   libc-io      bare printf/fprintf(stderr)     -> ngx_log_error
#   tabs         hard tab in source              -> nginx style is 4 spaces
#   width        line >80 columns                -> nginx style limit
#   trailing     trailing whitespace
#   include      .c must include ngx_config.h before ngx_core.h
#
# Suppress a single justified line with a trailing  /* NOLINT-nginx */ .
# Suppressing a whole rule is not supported on purpose: the exception belongs
# next to the code that needs it, where review can see the reason.
#
# Usage: ci/linter/lint-nginx.sh [files...]   Env: LINT_MODE=staged|all
# Extend: add a rule as one more `rule <name> <regex> <message>` call.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

lint_files_into FILES '^src/.*\.[ch]$' "$@"
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-nginx: no C files to check"; exit 0; }

echo "lint-nginx: ${#FILES[@]} file(s)"
rc=0

# rule <name> <ere> <message> -- report every matching line not marked NOLINT.
rule() {
    local name="$1" re="$2" msg="$3" hits
    hits=$(grep -nE "$re" "${FILES[@]}" 2>/dev/null | grep -v 'NOLINT-nginx' || true)
    [ -n "$hits" ] || return 0
    printf '%s\n' "$hits" | sed "s/^/  /; s/$/    [$name: $msg]/"
    rc=1
}

# rule_advisory <name> <ere> <message> -- identical to rule(), except it does
# NOT set rc. Used where a convention is real and worth showing but the
# pre-existing backlog is too large to block on today (see `width` below). The
# findings are printed, so the tail cannot quietly grow unnoticed; what changes
# is only whether the commit is refused.
rule_advisory() {
    local name="$1" re="$2" msg="$3" hits n
    hits=$(grep -nE "$re" "${FILES[@]}" 2>/dev/null | grep -v 'NOLINT-nginx' || true)
    [ -n "$hits" ] || return 0
    n=$(printf '%s\n' "$hits" | wc -l)
    printf '%s\n' "$hits" | sed "s/^/  /; s/\$/    [$name: $msg]/"
    printf '  note: %s advisory %s finding(s) -- reported, not blocking\n' "$n" "$name"
}

rule libc-alloc '(^|[^_[:alnum:]])(malloc|calloc|realloc|free)[[:space:]]*\(' \
     'use ngx_palloc/ngx_pcalloc/ngx_pfree'
rule libc-str   '(^|[^_[:alnum:]])(strcpy|strcat|sprintf|strncpy|strncat)[[:space:]]*\(' \
     'use ngx_cpymem/ngx_snprintf'
rule libc-num   '(^|[^_[:alnum:]])(atoi|atol|strtol|strtoul)[[:space:]]*\(' \
     'use ngx_atoi/ngx_atoof'
rule libc-io    '(^|[^_[:alnum:]])(printf|fprintf|perror)[[:space:]]*\(' \
     'use ngx_log_error/ngx_conf_log_error'
rule tabs       $'\t' 'nginx style is 4 spaces, no hard tabs'
rule trailing   '[[:space:]]+$' 'trailing whitespace'
# RETARGET (adoption step 32). The skeleton gates every line at 80 columns.
# Measured on this module 2026-08-10: 928 of 21842 lines in src/ exceed 80
# (711 in comments, 217 in code), p95=80, p99=82, max=167 -- so the module does
# follow the convention, with a long tail this repo's CI has never gated
# (nothing in .pre-commit-config.yaml or .github/workflows/ ever checked C line
# width).
#
# The gate is NOT weakened to the observed value and the 928 are NOT
# suppressed: `width` still reports every one of them, so the tail stays
# visible. It is demoted to advisory-with-a-ceiling instead:
#
#   - >80  reported, does not block  -- 928 pre-existing lines, and reformatting
#          them is a whole-module rewrite, which this adoption is explicitly not
#          ("you are moving CI, not rewriting the module").
#   - >167 BLOCKS                    -- the ceiling, set one column above the
#          longest line that exists today, so it is enforceable on arrival and
#          the tail cannot get worse.
#
# Why 167 and not 100: the over-100 tail is 16 lines, and 15 of them are
# Prometheus `# HELP` text (module.c:10911-10950) or flag-macro comments
# (module.h:159-160) -- single string literals whose content IS the exported
# metric help text. Splitting them either changes the emitted output or hides
# it across concatenations, so a 100-column ceiling would demand a behavioural
# edit to satisfy a style rule. Per the adoption rules a gate is left at the
# honest value with the reason named rather than being met by rewriting the
# module; the observed max is 167 (module.c:10926).
#
# This is deliberately NOT "lower the gate to the observed value and call it
# clean": the 80-column rule above still reports all 928, so the real
# convention stays visible. 167 only pins the worst case so it cannot grow.
# Recorded in adoption-findings.md: bringing the 928 to 80 columns, and the 16
# to 100, is a follow-up for the module's maintainers, not for the CI rollout.
# Lower WIDTH_BLOCK_AT as that backlog is worked off.
WIDTH_BLOCK_AT=167
rule_advisory width '^.{81,}$' 'nginx style limit is 80 columns (advisory)'
rule width_hard  "^.{$((WIDTH_BLOCK_AT + 1)),}\$" \
     "over ${WIDTH_BLOCK_AT} columns -- hard ceiling, split the line"

for f in "${FILES[@]}"; do
    case "$f" in
      *.c)
        # ngx_config.h defines the feature macros every later nginx header
        # reads; including ngx_core.h first silently changes the build. Look at
        # the FIRST ngx_ include, not a fixed head -N window: these files open
        # with a long licence/design comment that would push the includes out
        # of any window and make the check vacuous.
        # Angle brackets only: a local "ngx_http_<mod>_*.h" is this module's
        # own header and carries its own ngx_config.h include -- matching it
        # here reported every well-formed file.
        # RETARGET (adoption step 32): consider the first ngx_ include of EITHER
        # spelling, not just the angle-bracket one. Every .c in this module
        # opens with "ngx_http_cache_turbo_module.h", whose own line 18 is
        # <ngx_config.h> -- so the ordering contract is satisfied, and looking
        # only at <...> reported the first angle include AFTER it
        # (<ngx_event_openssl.h>) as a violation. Both hits were false: the
        # skeleton's own .c files include <ngx_config.h> directly, so its
        # narrower check never met this shape.
        #
        # A local header that does NOT lead with ngx_config.h is still caught:
        # the recursion below follows the first local include one level, which
        # is where this module's convention puts it.
        first_ngx=$(grep -nE '^[[:space:]]*#[[:space:]]*include[[:space:]]*[<"]ngx_' "$f" | head -1 || true)
        case "$first_ngx" in
          *'"'*)
            # Leading local ngx_ header: the contract moves to that header.
            local_h="src/$(printf '%s' "$first_ngx" | sed -E 's/.*"([^"]+)".*/\1/')"
            if [ -f "$local_h" ] \
               && grep -nE '^[[:space:]]*#[[:space:]]*include[[:space:]]*<ngx_' "$local_h" \
                  | head -1 | grep -q 'ngx_config\.h'; then
                first_ngx=""
            fi ;;
        esac
        if [ -n "$first_ngx" ] && ! printf '%s' "$first_ngx" | grep -q 'ngx_config\.h'; then
            printf '  %s:    [include: ngx_config.h must be the first ngx_ include]\n' \
                   "$f:${first_ngx%%:*}"
            rc=1
        fi ;;
    esac
done

if [ "$rc" -eq 0 ]; then say "clean"; fi
exit "$rc"
